import logging
import random as rnd
import lea
import scapy.layers.inet as inet
import scapy.utils
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Port

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class DrupalScan(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    minDefaultPort = 30000
    maxDefaultPort = 50000
    template_scan_pcap_path = Util.RESOURCE_DIR + "drupal_version_enumeration_scan.pcap"

    """
    Creates a new instance of the Drupal Scan
    """
    def __init__(self):
        # Initialize attack
        super(DrupalScan, self).__init__("DrupalScanAttack", "Injects a Drupal Scan'",
                                             "Scanning/Probing")
        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PACKETS_PER_SECOND, Float())
        ])

    """
    Initialize a parameter with its default values specified in this attack
    :param param: parameter, which should be initialized
    :return: True if initialization was successful, False if not
    """
    def init_param(self, param: str) -> bool:
        value = None
        # Victim configuration
        if param == self.IP_DESTINATION:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
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

    """
    Creates the attack packets
    """
    def generate_attack_packets(self):

        # Timestamp
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

        # Initialize parameters
        mac_source = self.get_param_value(self.MAC_SOURCE)
        ip_source = self.get_param_value(self.IP_SOURCE)
        port_source = self.get_param_value(self.PORT_SOURCE)
        mac_destination = self.get_param_value(self.MAC_DESTINATION)
        ip_destination = self.get_param_value(self.IP_DESTINATION)

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

        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)

        source_origin_wins, destination_origin_wins = {}, {}
        use_original_source_ports = False

        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload
            victim_ip = '172.19.0.3'
            intermediary_ip = '172.19.0.2'

            # Request (Attacker, Intermediary -> Victim)
            if ip_pkt.getfieldval("dst") == victim_ip:
                # Ether
                eth_frame.setfieldval("src", mac_source)
                eth_frame.setfieldval("dst", mac_destination)
                # IP: ip.src can be either Attacker or Intermediary
                if ip_pkt.getfieldval("src") != intermediary_ip:
                   ip_pkt.setfieldval("src", ip_source)
                ip_pkt.setfieldval("dst", ip_destination)
                ip_pkt.setfieldval("ttl", source_ttl_value)
                # when first tcp stream ends: use source_ports from pcap
                if (tcp_pkt.getfieldval("ack") == 0 and self.pkt_num > 0):
                    use_original_source_ports = True
                # TCP
                if ip_pkt.getfieldval("src") != intermediary_ip and (use_original_source_ports == False or self.pkt_num == 97 or 
                                                                     self.pkt_num == 98 or self.pkt_num == 545 or 
                                                                     self.pkt_num == 549 or self.pkt_num == 558 or 
                                                                     self.pkt_num == 687 or self.pkt_num == 694):
                    tcp_pkt.setfieldval("sport", port_source)
                # Window Size (mapping)
                source_origin_win = tcp_pkt.getfieldval("window")
                if source_origin_win not in source_origin_wins:
                    while True: 
                        source_win_rand_pick = source_win_prob_dict.random()
                        if source_win_rand_pick != 0: 
                            break
                    source_origin_wins[source_origin_win] = source_win_rand_pick
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

                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + inter_arrival_times[self.pkt_num]

            # Reply (Victim -> Attacker, Intermediary)
            else:
                # Ether
                eth_frame.setfieldval("src", mac_destination)
                eth_frame.setfieldval("dst", mac_source)
                # IP: Only one kind of ip.source
                ip_pkt.setfieldval("src", ip_destination)
                # IP: ip.dst can be either Intermediary or Attacker
                if ip_pkt.getfieldval("dst") != intermediary_ip:
                    ip_pkt.setfieldval("dst", ip_source)
                ip_pkt.setfieldval("ttl", destination_ttl_value)
                # TCP
                if ip_pkt.getfieldval("dst") != intermediary_ip and (use_original_source_ports == False or self.pkt_num == 96 or
                                                                     self.pkt_num == 99 or self.pkt_num == 541 or 
                                                                     self.pkt_num == 551 or self.pkt_num == 557 or 
                                                                     self.pkt_num == 693):
                    tcp_pkt.setfieldval("dport", port_source)
                # Window Size
                destination_origin_win = tcp_pkt.getfieldval("window")
                if destination_origin_win not in destination_origin_wins:
                    while True:
                        destination_win_rand_pick = destination_win_prob_dict.random()
                        if destination_win_rand_pick != 0:
                            break
                    destination_origin_wins[destination_origin_win] = destination_win_rand_pick
                new_win = destination_origin_wins[destination_origin_win]
                tcp_pkt.setfieldval("window", new_win)
                # MSS
                tcp_options = tcp_pkt.getfieldval("options")
                if tcp_options:
                    if tcp_options[0][0] == "MSS":
                        tcp_options[0] = ("MSS", mss_value)
                        tcp_pkt.setfieldval("options", tcp_options)

                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp() + inter_arrival_times[self.pkt_num]
                new_pkt.time = timestamp_next_pkt

            self.add_packet(new_pkt, ip_source, ip_destination)

        exploit_raw_packets.close()

    """
    Creates a pcap containing the attack packets.
    :return: The location of the generated pcap file.
    """
    def generate_attack_pcap(self):
        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = self.packets[0].time
        self.attack_end_utime = self.packets[-1].time

        if len(self.packets) > 0:
            self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
            self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.pkt_num + 1, self.path_attack_pcap