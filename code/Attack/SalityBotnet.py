import logging
import random as rnd
import lea
from scapy.layers.inet import TCP
import scapy.layers.inet as inet
import scapy.utils
import lea
from scapy.layers.inet import TCP
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SalityBotnet(BaseAttack.BaseAttack):
    template_attack_pcap_path = Util.RESOURCE_DIR + "/../resources/sality_botnet.pcap"

    def __init__(self):
        """
        Creates a new instance of the Sality botnet.
        """
        # Initialize attack
        super(SalityBotnet, self).__init__("Sality Botnet", "Injects an Sality botnet'", "Botnet")
        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PACKETS_PER_SECOND, Float())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        if param == self.IP_SOURCE:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_SOURCE:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        elif param == self.INJECT_AFTER_PACKET:
            self.add_param_value(self.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
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
        self.statistics.get_ip_addresses()
        subnet_mask = "255.255.255.0"
        ip_dns_server = self.get_unique_random_ipv4_from_ip_network(ip_source, subnet_mask)
        mac_dns_server = self.generate_random_mac_address()
        ttl_map, origin_wins = {}, {}

        # Set Window Size based on Window Size distribution of IP address
        win_dist = self.statistics.get_win_distribution(ip_source)
        if len(win_dist) > 0:
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
        else:
            win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)

        # Set Window Size based on Window Size distribution of IP address
        win_dist = self.statistics.get_win_distribution(ip_source)
        if len(win_dist) > 0:
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
        else:
            win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
        origin_wins = {}
        ttl_map = {}

        # Bot original config in the template PCAP
        origin_mac_src, origin_mac_dns_server = "08:00:27:e5:d7:b0", "52:54:00:12:35:02"
        origin_ip_src, origin_ip_dns_server = "10.0.2.15", "10.0.2.2"
        ip_map = {origin_ip_src: ip_source, origin_ip_dns_server: ip_dns_server}
        mac_map = {origin_mac_src: mac_source, origin_mac_dns_server: mac_dns_server}

        arrival_time = 0
        # Inject Sality botnet
        # Read sality_botnet pcap file
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        
        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            ip_payload = ip_pkt.payload
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]

            # Setting randomized mappings for source IP addresses
            if ip_pkt.getfieldval("src") not in ip_map:
                ip_map[ip_pkt.getfieldval("src")] =  self.statistics.get_random_ip_address(1, list(ip_map.values()))
                ip_pkt.setfieldval("src", ip_map[ip_pkt.getfieldval("src")])
            else:
                ip_pkt.setfieldval("src", ip_map[ip_pkt.getfieldval("src")])

            # Setting randomized mappings for destination IP addresses
            if ip_pkt.getfieldval("dst") not in ip_map:
                ip_map[ip_pkt.getfieldval("dst")] =  self.statistics.get_random_ip_address(1, list(ip_map.values()))
                ip_pkt.setfieldval("dst", ip_map[ip_pkt.getfieldval("dst")])
            else: 
                ip_pkt.setfieldval("dst", ip_map[ip_pkt.getfieldval("dst")])  

            # Setting randomized mappings for source mac addresses
            if eth_frame.getfieldval("src") not in mac_map:
                mac_map[eth_frame.getfieldval("src")] =  self.generate_random_mac_address()
                eth_frame.setfieldval("src", mac_map[eth_frame.getfieldval("src")])
            else:
                eth_frame.setfieldval("src", mac_map[eth_frame.getfieldval("src")])

            # Setting randomized mappings for destination mac addresses
            if eth_frame.getfieldval("dst") not in mac_map:
                mac_map[eth_frame.getfieldval("dst")] =  self.generate_random_mac_address()
                eth_frame.setfieldval("dst", mac_map[eth_frame.getfieldval("dst")])
            else: 
                eth_frame.setfieldval("dst", mac_map[eth_frame.getfieldval("dst")])    
            
            # If a packet contains a TCP window size
            # this value for the packet is set based on picking a value from 'win_prob_dict' at random. 
            if ip_pkt.haslayer(TCP):
                origin_win = ip_payload.getfieldval("window")
                if origin_win not in origin_wins:
                    while True:
                        win_rand_pick = win_prob_dict.random()
                        if win_rand_pick != 0:
                                break
                    origin_wins[origin_win] = win_rand_pick
                new_win = origin_wins[origin_win]
                ip_payload.setfieldval("window", new_win)

            # Settig randomized mappings for TTL values
            if ip_pkt.getfieldval("ttl") not in ttl_map:
                source_ttl = self.statistics.get_most_used_ttl(ip_pkt.getfieldval("src"))
                if not source_ttl:
                    source_ttl = self.statistics.process_db_query("SELECT ttlValue FROM ip_ttl;")
                    if isinstance(source_ttl, list):
                        source_ttl = rnd.choice(source_ttl)
                ttl_map[ip_pkt.getfieldval("ttl")] = source_ttl
            ip_pkt.setfieldval("ttl", ttl_map[ip_pkt.getfieldval("ttl")])

            # Window mapping on TCP layer
            if ip_pkt.haslayer(TCP):
                origin_win = ip_payload.getfieldval("window")
                if origin_win not in origin_wins:
                    while True:
                        win_rand_pick = win_prob_dict.random()
                        if win_rand_pick != 0:
                                break
                    origin_wins[origin_win] = win_rand_pick
                new_win = origin_wins[origin_win]
                ip_payload.setfieldval("window", new_win)

            # Generate packet 
            new_pkt = (eth_frame / ip_pkt / ip_payload)
            new_pkt.time = timestamp_next_pkt + arrival_time
            timestamp_next_pkt = self.timestamp_controller.next_timestamp()
            self.add_packet(new_pkt, ip_source, ip_dns_server)

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