import logging
import random as rnd

from scapy.all import *
import lea
import scapy.layers.inet as inet
import scapy.utils
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Port, Boolean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
load_layer("http")


class WinHTTPSysAttack(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    PORT_DESTINATION = 'port.dst'
    SUCCESSFUL_ATTACK = 'successful.attack'

    template_attack_pcap_path_fail = Util.RESOURCE_DIR + "Win_HTTP_Sys_fail.pcap"
    template_attack_pcap_path_success = Util.RESOURCE_DIR + "Win_HTTP_Sys_success.pcap"

    def __init__(self):
        """
        Creates a new instance of the WinHTTPSys.
        """
        # Initialize attack
        super(WinHTTPSysAttack, self).__init__("WinHTTPSys Exploit", "Injects a WinHTTPSys exploit'",
                                                 "Denial-of-service")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_DESTINATION, Port()),
            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.SUCCESSFUL_ATTACK, Boolean())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with a default value specified in the specific attack.
        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # Victim configuration
        if param == self.IP_DESTINATION:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if not ip_dst:
                return False
            value = self.get_mac_address(ip_dst)
        # Attacker configuration
        elif param == self.IP_SOURCE:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if not ip_dst:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_dst])
        elif param == self.MAC_SOURCE:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if not ip_src:
                return False
            value = self.get_mac_address(ip_src)
        elif param == self.PORT_SOURCE:
            value = self.get_unique_random_ephemeral_port()
        elif param == self.PORT_DESTINATION:
            value = 80
        # Attack configuration
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        elif param == self.SUCCESSFUL_ATTACK:
            value = False
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
        successful_attack = self.get_param_value(self.SUCCESSFUL_ATTACK)

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

        source_origin_wins, destination_origin_wins = {}, {}

        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())
        if not mss_value:
            mss_value = 1465

        if successful_attack:
            exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path_success)
            inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
            exploit_raw_packets.close()
            exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path_success)
        else: 
            exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path_fail)
            inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
            exploit_raw_packets.close()
            exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path_fail)

        arrival_time = 0
        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload       
            tcp_pkt = ip_pkt.payload
            victim_ip = '192.168.0.69'
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]

            # Request
            if ip_pkt.getfieldval("dst") == victim_ip:
                # New conversation: port_source value updated
                if (tcp_pkt.getfieldval("ack") == 0 and self.pkt_num > 0):
                    port_source = self.get_unique_random_ephemeral_port()
                    port_destination = 80
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
                # Window Size
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

                new_pkt = new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

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
                tcp_pkt.setfieldval("sport", port_destination)
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

                new_pkt = new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

            self.add_packet(new_pkt, ip_source, ip_destination)


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
        return len(self.packets), self.path_attack_pcap