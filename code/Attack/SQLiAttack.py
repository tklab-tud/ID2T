# Created by Aidmar
"""
ATutor 2.2.1 SQL Injection / Remote Code Execution

This module exploits a SQL Injection vulnerability and an authentication weakness vulnerability in ATutor. This essentially
means an attacker can bypass authentication and reach the administrator's interface where they can upload malicious code.

more info:
https://www.rapid7.com/db/modules/exploit/multi/http/atutor_sqli

"""


import logging
import math
from operator import itemgetter
import operator
from random import randint, uniform

from lea import Lea

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.utils import RawPcapReader
from scapy.layers.inet import IP, Ether, TCP, RandShort
#from scapy.all import *


class SQLiAttack(BaseAttack.BaseAttack):
    # Metasploit default packet rate
    maxDefaultPPS = 55
    minDefaultPPS = 5
    # HTTP port
    http_port = 80
    # Metasploit experiments show this range of ports
    minDefaultPort = 30000
    maxDefaultPort = 50000

    def __init__(self, statistics, pcap_file_path):
        """
        Creates a new instance of the SQLi Attack.

        :param statistics: A reference to the statistics class.
        """
        # Initialize attack
        super(SQLiAttack, self).__init__(statistics, "SQLi Attack", "Injects a SQLi attack'",
                                        "Resource Exhaustion")

        # Define allowed parameters and their type
        self.supported_params = {
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.TARGET_HOST: ParameterTypes.TYPE_DOMAIN,
            #Param.TARGET_URI: ParameterTypes.TYPE_URI,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT
        }

        # PARAMETERS: initialize with default utilsvalues
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list):
            most_used_ip_address = most_used_ip_address[0]
        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))
        #self.add_param_value(Param.TARGET_URI, "/")
        self.add_param_value(Param.TARGET_HOST, "www.hackme.com")
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        self.add_param_value(Param.PACKETS_PER_SECOND,self.maxDefaultPPS)

        # victim configuration
        # consider that the destination has port 80 opened
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)

        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)

    def generate_attack_pcap(self):
        def update_timestamp(timestamp, pps, maxdelay):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            return timestamp + uniform(1 / pps, maxdelay)

        # Aidmar
        def getIntervalPPS(complement_interval_pps, timestamp):
            """
            Gets the packet rate (pps) in specific time interval.

            :return: the corresponding packet rate for packet rate (pps) .
            """
            for row in complement_interval_pps:
                if timestamp <= row[0]:
                    return row[1]
            return complement_interval_pps[-1][1]  # in case the timstamp > capture max timestamp

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # TO-DO: find better pkt rate
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 30, 5 / pps: 15, 10 / pps: 3})

        # Aidmar - calculate complement packet rates of BG traffic per interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Initialize parameters
        packets = []
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        ip_source = self.get_param_value(Param.IP_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        target_host = self.get_param_value(Param.TARGET_HOST)
        target_uri = "/" #self.get_param_value(Param.TARGET_URI)

        # Aidmar - check ip.src == ip.dst
        if ip_source == ip_destination:
            print("\nERROR: Invalid IP addresses; source IP is the same as destination IP: " + ip_source + ".")
            import sys
            sys.exit(0)

        path_attack_pcap = None
        minDelay, maxDelay = self.get_reply_delay(ip_destination)

        # Set TTL based on TTL distribution of IP address
        source_ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(source_ttl_dist) > 0:
            source_ttl_prob_dict = Lea.fromValFreqsDict(source_ttl_dist)
            source_ttl_value = source_ttl_prob_dict.random()
        else:
            source_ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

        destination_ttl_dist = self.statistics.get_ttl_distribution(ip_destination)
        if len(destination_ttl_dist) > 0:
            destination_ttl_prob_dict = Lea.fromValFreqsDict(destination_ttl_dist)
            destination_ttl_value = destination_ttl_prob_dict.random()
        else:
            destination_ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

        # Inject SQLi Attack
        # Read SQLi Attack pcap file
        orig_ip_dst = None
        exploit_raw_packets = RawPcapReader("resources/ATutorSQLi.pcap")

        port_source = randint(self.minDefaultPort,self.maxDefaultPort) # experiments show this range of ports

        # Random TCP sequence numbers
        global attacker_seq
        attacker_seq = randint(1000, 50000)
        global victim_seq
        victim_seq = randint(1000, 50000)

        for pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload
            str_tcp_seg = str(tcp_pkt.payload)

            # Clean payloads
            eth_frame.payload = b''
            ip_pkt.payload = b''
            tcp_pkt.payload = b''

            if pkt_num == 0:
                prev_orig_port_source = tcp_pkt.getfieldval("sport")
                orig_ip_dst = ip_pkt.getfieldval("dst")  # victim IP


            if tcp_pkt.getfieldval("dport") == 80 or tcp_pkt.getfieldval("sport") == 80:
                # Attacker --> vicitm
                if ip_pkt.getfieldval("dst") == orig_ip_dst: # victim IP

                    # There are 363 TCP connections with different source ports, for each of them we generate random port
                    if tcp_pkt.getfieldval("sport") != prev_orig_port_source and tcp_pkt.getfieldval("dport") != 4444:
                        port_source = randint(self.minDefaultPort, self.maxDefaultPort)
                        prev_orig_port_source = tcp_pkt.getfieldval("sport")
                        # New connection, new random TCP sequence numbers
                        attacker_seq = randint(1000, 50000)
                        victim_seq = randint(1000, 50000)
                        # First packet in a connection has ACK = 0
                        tcp_pkt.setfieldval("ack", 0)

                    # Ether
                    eth_frame.setfieldval("src", mac_source)
                    eth_frame.setfieldval("dst", mac_destination)
                    # IP
                    ip_pkt.setfieldval("src", ip_source)
                    ip_pkt.setfieldval("dst", ip_destination)
                    ip_pkt.setfieldval("ttl", source_ttl_value)
                    # TCP
                    tcp_pkt.setfieldval("sport",port_source)

                    if len(str_tcp_seg) > 0:
                        # convert payload bytes to str => str = "b'..\\r\\n..'"
                        str_tcp_seg = str_tcp_seg[2:-1]
                        str_tcp_seg = str_tcp_seg.replace('/ATutor', target_uri)
                        str_tcp_seg = str_tcp_seg.replace(orig_ip_dst, target_host)
                        str_tcp_seg = str_tcp_seg.replace("\\n", "\n")
                        str_tcp_seg = str_tcp_seg.replace("\\r", "\r")
                        str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                        str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                    # TCP Seq, Ack
                    if tcp_pkt.getfieldval("ack") != 0:
                        tcp_pkt.setfieldval("ack", victim_seq)
                    tcp_pkt.setfieldval("seq", attacker_seq)
                    if not (tcp_pkt.getfieldval("flags") == 16 and len(str_tcp_seg) == 0):  # flags=A:
                        attacker_seq += max(len(str_tcp_seg), 1)

                    new_pkt = (eth_frame / ip_pkt/ tcp_pkt / str_tcp_seg)
                    new_pkt.time = timestamp_next_pkt

                    maxdelay = randomdelay.random()
                    pps = max(getIntervalPPS(complement_interval_pps, timestamp_next_pkt), self.minDefaultPPS)
                    timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)

                # Victim --> attacker
                else:
                    # Ether
                    eth_frame.setfieldval("src", mac_destination)
                    eth_frame.setfieldval("dst", mac_source)
                    # IP
                    ip_pkt.setfieldval("src", ip_destination)
                    ip_pkt.setfieldval("dst", ip_source)
                    ip_pkt.setfieldval("ttl", destination_ttl_value)
                    # TCP
                    tcp_pkt.setfieldval("dport", port_source)

                    if len(str_tcp_seg) > 0:
                        # convert payload bytes to str => str = "b'..\\r\\n..'"
                        str_tcp_seg = str_tcp_seg[2:-1]
                        str_tcp_seg = str_tcp_seg.replace('/ATutor', target_uri)
                        str_tcp_seg = str_tcp_seg.replace(orig_ip_dst, target_host)
                        str_tcp_seg = str_tcp_seg.replace("\\n", "\n")
                        str_tcp_seg = str_tcp_seg.replace("\\r", "\r")
                        str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                        str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                    # TCP Seq, ACK
                    tcp_pkt.setfieldval("ack", attacker_seq)
                    tcp_pkt.setfieldval("seq", victim_seq)
                    strLen = len(str_tcp_seg)
                    if not (tcp_pkt.getfieldval("flags") == 16 and strLen == 0):  # flags=A:
                        victim_seq += max(strLen, 1)

                    new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_tcp_seg)
                    timestamp_next_pkt = timestamp_next_pkt + uniform(minDelay, 2 * maxDelay)
                    new_pkt.time = timestamp_next_pkt

            # The last connection
            else:
                # New connection, new random TCP sequence numbers
                attacker_seq = randint(1000, 50000)
                victim_seq = randint(1000, 50000)
                # First packet in a connection has ACK = 0
                tcp_pkt.setfieldval("ack", 0)
                #port_source = randint(self.minDefaultPort, self.maxDefaultPort)

                # Attacker --> vicitm
                if ip_pkt.getfieldval("dst") == orig_ip_dst:  # victim IP
                    # Ether
                    eth_frame.setfieldval("src", mac_source)
                    eth_frame.setfieldval("dst", mac_destination)
                    # IP
                    ip_pkt.setfieldval("src", ip_source)
                    ip_pkt.setfieldval("dst", ip_destination)
                    ip_pkt.setfieldval("ttl", source_ttl_value)
                    # TCP
                    #tcp_pkt.setfieldval("sport", port_source)

                    if len(str_tcp_seg) > 0:
                        # convert payload bytes to str => str = "b'..\\r\\n..'"
                        str_tcp_seg = str_tcp_seg[2:-1]
                        str_tcp_seg = str_tcp_seg.replace('/ATutor', target_uri)
                        str_tcp_seg = str_tcp_seg.replace(orig_ip_dst, target_host)
                        str_tcp_seg = str_tcp_seg.replace("\\n", "\n")
                        str_tcp_seg = str_tcp_seg.replace("\\r", "\r")
                        str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                        str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                    # TCP Seq, Ack
                    if tcp_pkt.getfieldval("ack") != 0:
                        tcp_pkt.setfieldval("ack", victim_seq)
                    tcp_pkt.setfieldval("seq", attacker_seq)
                    if not (tcp_pkt.getfieldval("flags") == 16 and len(str_tcp_seg) == 0):  # flags=A:
                        attacker_seq += max(len(str_tcp_seg), 1)

                    new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_tcp_seg)
                    new_pkt.time = timestamp_next_pkt

                    maxdelay = randomdelay.random()
                    pps = max(getIntervalPPS(complement_interval_pps, timestamp_next_pkt), self.minDefaultPPS)
                    timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)

                # Victim --> attacker
                else:
                    # Ether
                    eth_frame.setfieldval("src", mac_destination)
                    eth_frame.setfieldval("dst", mac_source)
                    # IP
                    ip_pkt.setfieldval("src", ip_destination)
                    ip_pkt.setfieldval("dst", ip_source)
                    ip_pkt.setfieldval("ttl", destination_ttl_value)
                    # TCP
                    #tcp_pkt.setfieldval("dport", port_source)

                    if len(str_tcp_seg) > 0:
                        # convert payload bytes to str => str = "b'..\\r\\n..'"
                        str_tcp_seg = str_tcp_seg[2:-1]
                        str_tcp_seg = str_tcp_seg.replace('/ATutor', target_uri)
                        str_tcp_seg = str_tcp_seg.replace(orig_ip_dst, target_host)
                        str_tcp_seg = str_tcp_seg.replace("\\n", "\n")
                        str_tcp_seg = str_tcp_seg.replace("\\r", "\r")
                        str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                        str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                    # TCP Seq, ACK
                    tcp_pkt.setfieldval("ack", attacker_seq)
                    tcp_pkt.setfieldval("seq", victim_seq)
                    strLen = len(str_tcp_seg)
                    if not (tcp_pkt.getfieldval("flags") == 16 and strLen == 0):  # flags=A:
                        victim_seq += max(strLen, 1)

                    new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_tcp_seg)
                    timestamp_next_pkt = timestamp_next_pkt + uniform(minDelay, 2 * maxDelay)
                    new_pkt.time = timestamp_next_pkt

            packets.append(new_pkt)

        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = packets[0].time
        self.attack_end_utime = packets[-1].time

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return pkt_num + 1, path_attack_pcap