import logging
import random

from lea import Lea
from scapy.layers.inet import Ether
from scapy.utils import RawPcapReader

import ID2TLib.Utility as Util
from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8


class SQLiAttack(BaseAttack.BaseAttack):
    template_attack_pcap_path = Util.RESOURCE_DIR + "ATutorSQLi.pcap"
    # HTTP port
    http_port = 80
    # Metasploit experiments show this range of ports
    minDefaultPort = 30000
    maxDefaultPort = 50000

    def __init__(self):
        """
        Creates a new instance of the SQLi Attack.

        """
        # Initialize attack
        super(SQLiAttack, self).__init__("SQLi Attack", "Injects a SQLi attack'",
                                        "Privilege elevation")

        # Define allowed parameters and their type
        self.supported_params.update({
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.PORT_DESTINATION: ParameterTypes.TYPE_PORT,
            Param.TARGET_HOST: ParameterTypes.TYPE_DOMAIN,
            #Param.TARGET_URI: ParameterTypes.TYPE_URI,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT
        })

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.
        """

        # PARAMETERS: initialize with default utilsvalues
        # (values are overwritten if user specifies them)
        # Attacker configuration
        most_used_ip_address = self.statistics.get_most_used_ip_address()

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        # Victim configuration
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)
        self.add_param_value(Param.PORT_DESTINATION, self.http_port)
        # self.add_param_value(Param.TARGET_URI, "/")
        self.add_param_value(Param.TARGET_HOST, "www.hackme.com")

        # Attack configuration
        self.add_param_value(Param.INJECT_AFTER_PACKET, random.randint(0, self.statistics.get_packet_count()))
        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)

    def generate_attack_pcap(self):
        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)

        # Calculate complement packet rates of BG traffic per interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Initialize parameters
        packets = []
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        ip_source = self.get_param_value(Param.IP_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        port_destination = self.get_param_value(Param.PORT_DESTINATION)

        target_host = self.get_param_value(Param.TARGET_HOST)
        target_uri = "/"  # self.get_param_value(Param.TARGET_URI)

        # Check ip.src == ip.dst
        self.ip_src_dst_equal_check(ip_source, ip_destination)

        path_attack_pcap = None

        # Set TTL based on TTL distribution of IP address
        source_ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(source_ttl_dist) > 0:
            source_ttl_prob_dict = Lea.fromValFreqsDict(source_ttl_dist)
            source_ttl_value = source_ttl_prob_dict.random()
        else:
            source_ttl_value = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(ttlValue)"))

        destination_ttl_dist = self.statistics.get_ttl_distribution(ip_destination)
        if len(destination_ttl_dist) > 0:
            destination_ttl_prob_dict = Lea.fromValFreqsDict(destination_ttl_dist)
            destination_ttl_value = destination_ttl_prob_dict.random()
        else:
            destination_ttl_value = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(ttlValue)"))

        # Inject SQLi Attack
        # Read SQLi Attack pcap file
        orig_ip_dst = None
        exploit_raw_packets = RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times, inter_arrival_time_dist = self.get_inter_arrival_time(exploit_raw_packets,True)
        timeSteps = Lea.fromValFreqsDict(inter_arrival_time_dist)
        exploit_raw_packets.close()
        exploit_raw_packets = RawPcapReader(self.template_attack_pcap_path)

        port_source = random.randint(self.minDefaultPort,self.maxDefaultPort) # experiments show this range of ports

        # Random TCP sequence numbers
        global attacker_seq
        attacker_seq = random.randint(1000, 50000)
        global victim_seq
        victim_seq = random.randint(1000, 50000)

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

            # TODO: sometimes results in ERROR: Invalid IP addresses; source IP is the same as destination IP
            # TODO: so far only for the joomla pcap, fixed by specifying inject_after-pkt parameter
            # Attacker --> vicitm
            if ip_pkt.getfieldval("dst") == orig_ip_dst:  # victim IP

                # There are 363 TCP connections with different source ports, for each of them we generate random port
                if tcp_pkt.getfieldval("sport") != prev_orig_port_source and tcp_pkt.getfieldval("dport") != 4444:
                    port_source = random.randint(self.minDefaultPort, self.maxDefaultPort)
                    prev_orig_port_source = tcp_pkt.getfieldval("sport")
                    # New connection, new random TCP sequence numbers
                    attacker_seq = random.randint(1000, 50000)
                    victim_seq = random.randint(1000, 50000)
                    # First packet in a connection has ACK = 0
                    tcp_pkt.setfieldval("ack", 0)

                # Last connection
                elif tcp_pkt.getfieldval("dport") != 80 and tcp_pkt.getfieldval("sport") != 80:
                    # New connection, new random TCP sequence numbers
                    attacker_seq = random.randint(1000, 50000)
                    victim_seq = random.randint(1000, 50000)
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

                # Regular connection
                if tcp_pkt.getfieldval("dport") == 80 or tcp_pkt.getfieldval("sport") == 80:
                    tcp_pkt.setfieldval("sport",port_source)
                    tcp_pkt.setfieldval("dport", port_destination)

                str_tcp_seg = self.modify_http_header(str_tcp_seg, '/ATutor', target_uri, orig_ip_dst, target_host)

                # TCP Seq, Ack
                if tcp_pkt.getfieldval("ack") != 0:
                    tcp_pkt.setfieldval("ack", victim_seq)
                tcp_pkt.setfieldval("seq", attacker_seq)
                if not (tcp_pkt.getfieldval("flags") == 16 and len(str_tcp_seg) == 0):  # flags=A:
                    attacker_seq += max(len(str_tcp_seg), 1)

                new_pkt = (eth_frame / ip_pkt/ tcp_pkt / str_tcp_seg)
                new_pkt.time = timestamp_next_pkt

                pps = max(Util.get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps) + float(timeSteps.random())

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

                # Regular connection
                if tcp_pkt.getfieldval("dport") == 80 or tcp_pkt.getfieldval("sport") == 80:
                    tcp_pkt.setfieldval("dport", port_source)
                    tcp_pkt.setfieldval("sport", port_destination)

                str_tcp_seg = self.modify_http_header(str_tcp_seg, '/ATutor', target_uri, orig_ip_dst, target_host)

                # TCP Seq, ACK
                tcp_pkt.setfieldval("ack", attacker_seq)
                tcp_pkt.setfieldval("seq", victim_seq)
                strLen = len(str_tcp_seg)
                if not (tcp_pkt.getfieldval("flags") == 16 and strLen == 0):  # flags=A:
                    victim_seq += max(strLen, 1)

                new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_tcp_seg)
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps) + float(timeSteps.random())
                new_pkt.time = timestamp_next_pkt

            packets.append(new_pkt)

        exploit_raw_packets.close()
        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = packets[0].time
        self.attack_end_utime = packets[-1].time

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return pkt_num + 1, path_attack_pcap
