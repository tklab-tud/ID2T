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
            Param.TARGET_HOST: ParameterTypes.TYPE_URI,
            Param.TARGET_URI: ParameterTypes.TYPE_URI,
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
        self.add_param_value(Param.TARGET_URI, "/")
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
        target_uri = self.get_param_value(Param.TARGET_URI)

        # Aidmar - check ip.src == ip.dst
        if ip_source == ip_destination:
            print("\nERROR: Invalid IP addresses; source IP is the same as destination IP: " + ip_source + ".")
            import sys
            sys.exit(0)

        path_attack_pcap = None
        replyDelay = self.get_reply_delay(ip_destination)

        # Inject SQLi Attack
        # Read SQLi Attack pcap file
        orig_ip_dst = None
        exploit_raw_packets = RawPcapReader("ATutorSQLi.pcap")

        port_source = randint(self.minDefaultPort,self.maxDefaultPort) # experiments show this range of ports

        for pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload
            str_http_pkt = str(tcp_pkt.payload)

            if pkt_num == 0:
                prev_orig_port_source = tcp_pkt.getfieldval("sport")
                if tcp_pkt.getfieldval("dport") == self.http_port:
                    orig_ip_dst = ip_pkt.getfieldval("dst") # victim IP

            # Request
            if ip_pkt.getfieldval("dst") == orig_ip_dst: # victim IP

                # There are 363 TCP connections with different source ports, for each of them we generate random port
                if tcp_pkt.getfieldval("sport") != prev_orig_port_source:
                    port_source = randint(self.minDefaultPort, self.maxDefaultPort)
                    prev_orig_port_source = tcp_pkt.getfieldval("sport")

                # Ether
                eth_frame.setfieldval("src", mac_source)
                eth_frame.setfieldval("dst", mac_destination)
                # IP
                ip_pkt.setfieldval("src", ip_source)
                ip_pkt.setfieldval("dst", ip_destination)
                # TCP
                tcp_pkt.setfieldval("sport",port_source)

                eth_frame.payload = b''
                ip_pkt.payload = b''
                tcp_pkt.payload = b''

                if len(str_http_pkt) > 0:
                    # convert payload bytes to str => str = "b'..\\r\\n..'"
                    str_http_pkt = str_http_pkt[2:-1]
                    str_http_pkt = str_http_pkt.replace('/ATutor', target_uri)
                    str_http_pkt = str_http_pkt.replace(orig_ip_dst, target_host)
                    str_http_pkt = str_http_pkt.replace("\\n", "\n")
                    str_http_pkt = str_http_pkt.replace("\\r", "\r")
                    str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                    str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                new_pkt = (eth_frame / ip_pkt/ tcp_pkt / str_http_pkt)
                new_pkt.time = timestamp_next_pkt

                maxdelay = randomdelay.random()
                pps = self.minDefaultPPS if getIntervalPPS(complement_interval_pps, timestamp_next_pkt) is None else max(
                    getIntervalPPS(complement_interval_pps, timestamp_next_pkt), self.minDefaultPPS)
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
            # Reply
            else:
                # Ether
                eth_frame.setfieldval("src", mac_destination)
                eth_frame.setfieldval("dst", mac_source)
                # IP
                ip_pkt.setfieldval("src", ip_destination)
                ip_pkt.setfieldval("dst", ip_source)
                # TCP
                tcp_pkt.setfieldval("dport", port_source)

                eth_frame.payload = b''
                ip_pkt.payload = b''
                tcp_pkt.payload = b''

                if len(str_http_pkt) > 0:
                    # convert payload bytes to str => str = "b'..\\r\\n..'"
                    str_http_pkt = str_http_pkt[2:-1]
                    str_http_pkt = str_http_pkt.replace('/ATutor', target_uri)
                    str_http_pkt = str_http_pkt.replace(orig_ip_dst, target_host)
                    str_http_pkt = str_http_pkt.replace("\\n", "\n")
                    str_http_pkt = str_http_pkt.replace("\\r", "\r")
                    str_tcp_seg = str_tcp_seg.replace("\\t", "\t")
                    str_tcp_seg = str_tcp_seg.replace("\\\'", "\'")

                new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_http_pkt)
                timestamp_next_pkt = timestamp_next_pkt + uniform(replyDelay, 2 * replyDelay)
                new_pkt.time = timestamp_next_pkt

            packets.append(new_pkt)

        # TO-DO: Last connection, victim start a connection from port 4444.

        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = packets[0].time
        self.attack_end_utime = packets[-1].time

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return pkt_num + 1, path_attack_pcap