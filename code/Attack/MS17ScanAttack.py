import logging
import random as rnd

import lea
import scapy.layers.inet as inet
import scapy.utils

import Attack.BaseAttack as BaseAttack
import Attack.ParameterTypes as Types
import ID2TLib.SMBLib as SMBLib
import ID2TLib.Utility as Util

from Attack.Parameter import Parameter

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class MS17ScanAttack(BaseAttack.BaseAttack):
    MAC_SOURCE = 'mac.src'
    IP_SOURCE = 'ip.src'
    PORT_SOURCE = 'port.src'
    MAC_DESTINATION = 'mac.dst'
    IP_DESTINATION = 'ip.dst'
    PORT_DESTINATION = 'port.dst'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'
    INJECT_AFTER_PACKET = 'inject.after-pkt'
    PACKETS_PER_SECOND = 'packets.per-second'

    template_scan_pcap_path = Util.RESOURCE_DIR + "Win7_eternalblue_scan.pcap"
    # Empirical values from Metasploit experiments
    minDefaultPort = 30000
    maxDefaultPort = 50000
    last_conn_dst_port = 4444

    def __init__(self):
        """
        Creates a new instance of the EternalBlue Exploit.
        """
        # Initialize attack
        super(MS17ScanAttack, self).__init__("MS17ScanAttack", "Injects a MS17 scan'",
                                             "Scanning/Probing")

        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, Types.MACAddress()),
            Parameter(self.IP_SOURCE, Types.IPAddress()),
            Parameter(self.PORT_SOURCE, Types.Port()),
            Parameter(self.MAC_DESTINATION, Types.MACAddress()),
            Parameter(self.IP_DESTINATION, Types.IPAddress()),
            Parameter(self.PORT_DESTINATION, Types.Port()),
            Parameter(self.PACKETS_PER_SECOND, Types.Float())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # Victim configuration
        if param == self.IP_DESTINATION:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == self.PORT_DESTINATION:
            value = SMBLib.smb_port
        # Attacker configuration
        elif param == self.IP_SOURCE:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_dst])
        elif param == self.MAC_SOURCE:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        elif param == self.PORT_SOURCE:
            value = rnd.randint(self.minDefaultPort, self.maxDefaultPort)
        # Attack configuration
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        # Timestamp
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

        # Initialize parameters
        mac_source = self.get_param_value(self.MAC_SOURCE)
        ip_source = self.get_param_value(self.IP_SOURCE)
        port_source = self.get_param_value(self.PORT_SOURCE)
        mac_destination = self.get_param_value(self.MAC_DESTINATION)
        ip_destination = self.get_param_value(self.IP_DESTINATION)
        port_destination = self.get_param_value(self.PORT_DESTINATION)

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

        # Set Window Size based on Window Size distribution of IP address
        source_win_dist = self.statistics.get_win_distribution(ip_source)
        if len(source_win_dist) > 0:
            source_win_prob_dict = lea.Lea.fromValFreqsDict(source_win_dist)
        else:
            source_win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            source_win_prob_dict = lea.Lea.fromValFreqsDict(source_win_dist)

        destination_win_dist = self.statistics.get_win_distribution(ip_destination)
        if len(destination_win_dist) > 0:
            destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)
        else:
            destination_win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)

        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())
        if not mss_value:
            mss_value = 1465

        # Scan (MS17)
        # Read Win7_eternalblue_scan pcap file
        orig_ip_dst = None
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)

        source_origin_wins, destination_origin_wins = {}, {}

        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload

            if self.pkt_num == 0:
                if tcp_pkt.getfieldval("dport") == SMBLib.smb_port:
                    orig_ip_dst = ip_pkt.getfieldval("dst")  # victim IP

            # Request
            if ip_pkt.getfieldval("dst") == orig_ip_dst:  # victim IP
                # Ether
                eth_frame.setfieldval("src", mac_source)
                eth_frame.setfieldval("dst", mac_destination)
                # IP
                ip_pkt.setfieldval("src", ip_source)
                ip_pkt.setfieldval("dst", ip_destination)
                ip_pkt.setfieldval("ttl", source_ttl_value)
                # TCP
                tcp_pkt.setfieldval("sport", port_source)
                tcp_pkt.setfieldval("dport", port_destination)
                # Window Size (mapping)
                source_origin_win = tcp_pkt.getfieldval("window")
                if source_origin_win not in source_origin_wins:
                    source_origin_wins[source_origin_win] = source_win_prob_dict.random()
                new_win = source_origin_wins[source_origin_win]
                tcp_pkt.setfieldval("window", new_win)
                # MSS
                tcp_options = tcp_pkt.getfieldval("options")
                if tcp_options:
                    if tcp_options[0][0] == "MSS":
                        tcp_options[0] = ("MSS", mss_value)
                        tcp_pkt.setfieldval("options", tcp_options)

                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt

                # FIXME: double check inter_arrival_times calculation
                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + inter_arrival_times[
                    self.pkt_num]  # float(timeSteps.random())
            # Reply
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
                tcp_pkt.setfieldval("sport", port_destination)
                # Window Size
                destination_origin_win = tcp_pkt.getfieldval("window")
                if destination_origin_win not in destination_origin_wins:
                    destination_origin_wins[destination_origin_win] = destination_win_prob_dict.random()
                new_win = destination_origin_wins[destination_origin_win]
                tcp_pkt.setfieldval("window", new_win)
                # MSS
                tcp_options = tcp_pkt.getfieldval("options")
                if tcp_options:
                    if tcp_options[0][0] == "MSS":
                        tcp_options[0] = ("MSS", mss_value)
                        tcp_pkt.setfieldval("options", tcp_options)

                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                # FIXME: double check inter_arrival_times calculation
                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + inter_arrival_times[
                    self.pkt_num]  # + float(timeSteps.random())
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

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.pkt_num + 1, self.path_attack_pcap
