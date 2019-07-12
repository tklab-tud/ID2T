import logging
import random as rnd

import lea
import scapy.layers.inet as inet
import scapy.utils

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

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

        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_DESTINATION: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.PORT_DESTINATION: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.TARGET_HOST: atkParam.ParameterTypes.TYPE_DOMAIN,
            # atkParam.Parameter.TARGET_URI: atkParam.ParameterTypes.TYPE_URI,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT
        })

    def init_param(self, param: atkParam.Parameter) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # Attacker configuration
        if param == atkParam.Parameter.IP_SOURCE:
            value = self.statistics.get_most_used_ip_address()
        elif param == atkParam.Parameter.MAC_SOURCE:
            ip_src = self.get_param_value(atkParam.Parameter.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        # Victim configuration
        elif param == atkParam.Parameter.IP_DESTINATION:
            ip_src = self.get_param_value(atkParam.Parameter.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_src])
        elif param == atkParam.Parameter.MAC_DESTINATION:
            ip_dst = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == atkParam.Parameter.PORT_DESTINATION:
            value = self.http_port
        # self.add_param_value(atkParam.Parameter.TARGET_URI, "/")
        elif param == atkParam.Parameter.TARGET_HOST:
            value = "www.hackme.com"
        # Attack configuration
        elif param == atkParam.Parameter.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        elif param == atkParam.Parameter.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        # Timestamp
        timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)

        # Initialize parameters
        mac_source = self.get_param_value(atkParam.Parameter.MAC_SOURCE)
        ip_source = self.get_param_value(atkParam.Parameter.IP_SOURCE)
        if isinstance(ip_source, list):
            ip_source = ip_source[0]
        mac_destination = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)
        ip_destination = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
        if isinstance(ip_destination, list):
            ip_destination = ip_destination[0]
        port_destination = self.get_param_value(atkParam.Parameter.PORT_DESTINATION)

        target_host = self.get_param_value(atkParam.Parameter.TARGET_HOST)
        target_uri = "/"  # self.get_param_value(atkParam.Parameter.TARGET_URI)

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source, ip_destination)

        # Set TTL based on TTL distribution of IP address
        source_ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(source_ttl_dist) > 0:
            source_ttl_prob_dict = lea.Lea.fromValFreqsDict(source_ttl_dist)
            source_ttl_value = source_ttl_prob_dict.random()
        else:
            source_ttl_value = Util.handle_most_used_outputs(self.statistics.get_most_used_ttl_value())

        destination_ttl_dist = self.statistics.get_ttl_distribution(ip_destination)
        if len(destination_ttl_dist) > 0:
            destination_ttl_prob_dict = lea.Lea.fromValFreqsDict(destination_ttl_dist)
            destination_ttl_value = destination_ttl_prob_dict.random()
        else:
            destination_ttl_value = Util.handle_most_used_outputs(
                self.statistics.get_most_used_ttl_value())

        # Inject SQLi Attack
        # Read SQLi Attack pcap file
        orig_ip_dst = None
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times, inter_arrival_time_dist = self.get_inter_arrival_time(exploit_raw_packets, True)
        time_steps = lea.Lea.fromValFreqsDict(inter_arrival_time_dist)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)

        port_source = rnd.randint(self.minDefaultPort, self.maxDefaultPort)  # experiments show this range of ports

        # Random TCP sequence numbers
        global attacker_seq
        attacker_seq = rnd.randint(1000, 50000)
        global victim_seq
        victim_seq = rnd.randint(1000, 50000)

        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload
            str_tcp_seg = str(tcp_pkt.payload)

            # Clean payloads
            eth_frame.payload = b''
            ip_pkt.payload = b''
            tcp_pkt.payload = b''

            # FIXME: no getfieldval in class bytes
            if self.pkt_num == 0:
                prev_orig_port_source = tcp_pkt.getfieldval("sport")
                orig_ip_dst = ip_pkt.getfieldval("dst")  # victim IP

            # Last connection
            if tcp_pkt.getfieldval("dport") != 80 and tcp_pkt.getfieldval("sport") != 80:
                # New connection, new random TCP sequence numbers
                attacker_seq = rnd.randint(1000, 50000)
                victim_seq = rnd.randint(1000, 50000)
                # First packet in a connection has ACK = 0
                tcp_pkt.setfieldval("ack", 0)

            # Attacker --> vicitm
            if ip_pkt.getfieldval("dst") == orig_ip_dst:  # victim IP

                # There are 363 TCP connections with different source ports, for each of them we generate random port
                if tcp_pkt.getfieldval("sport") != prev_orig_port_source and tcp_pkt.getfieldval("dport") != 4444 \
                        and (tcp_pkt.getfieldval("dport") == 80 or tcp_pkt.getfieldval("sport") == 80):
                    port_source = rnd.randint(self.minDefaultPort, self.maxDefaultPort)
                    prev_orig_port_source = tcp_pkt.getfieldval("sport")
                    # New connection, new random TCP sequence numbers
                    attacker_seq = rnd.randint(1000, 50000)
                    victim_seq = rnd.randint(1000, 50000)
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
                    tcp_pkt.setfieldval("sport", port_source)
                    tcp_pkt.setfieldval("dport", port_destination)

                str_tcp_seg = self.modify_http_header(str_tcp_seg, '/ATutor', target_uri, orig_ip_dst, target_host)

                # TCP Seq, Ack
                if tcp_pkt.getfieldval("ack") != 0:
                    tcp_pkt.setfieldval("ack", victim_seq)
                tcp_pkt.setfieldval("seq", attacker_seq)
                if not (tcp_pkt.getfieldval("flags") == 16 and len(str_tcp_seg) == 0):  # flags=A:
                    attacker_seq += max(len(str_tcp_seg), 1)

                new_pkt = (eth_frame / ip_pkt / tcp_pkt / str_tcp_seg)
                new_pkt.time = timestamp_next_pkt

                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + float(time_steps.random())

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
                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + float(time_steps.random())
                new_pkt.time = timestamp_next_pkt

            self.add_packet(new_pkt, ip_source, ip_destination)

        exploit_raw_packets.close()

    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = self.packets[0].time
        self.attack_end_utime = self.packets[-1].time

        if len(self.packets) > 0:
            self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
            self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)

        # return self.packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.pkt_num + 1, self.path_attack_pcap
