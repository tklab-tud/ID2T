import logging
import random as rnd
import lea
import scapy.utils
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
import scapy.layers.inet as inet
from scapy.layers.inet import TCP
import Attack.BaseAttack as BaseAttack
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Boolean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class EmotetBotnet(BaseAttack.BaseAttack):
    SPAM_BOT_ACTIVITY = 'spam_bot_activity'

    template_attack_pcap_path_default = Util.RESOURCE_DIR + "emotet_botnet/emotet_traffic_with_spambot.pcap"
    template_attack_pcap_path_no_spambot = Util.RESOURCE_DIR + "emotet_botnet/emotet_traffic.pcap"
    template_attack_pcap_path = ""


    def __init__(self):
        """
        Creates a new instance of the Emotet botnet.
        """
        # Initialize attack
        super(EmotetBotnet, self).__init__("Emotet Botnet", "Injects an Emotet botnet'", "Botnet")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.SPAM_BOT_ACTIVITY, Boolean())
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
        # Attack configuration
        elif param == self.INJECT_AFTER_PACKET:
            self.add_param_value(self.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.SPAM_BOT_ACTIVITY:
            value = True
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
        spam_bot_activity = self.get_param_value(self.SPAM_BOT_ACTIVITY)
        # Select IP for DNS server from background traffic
        ip_dns_server = self.statistics.process_db_query(
            "SELECT ipAddress FROM ip_protocols WHERE protocolName='DNS' AND protocolCount=(SELECT MAX(protocolCount) "
            "FROM ip_protocols WHERE protocolName='DNS');")
        ip_dns_server = Util.handle_most_used_outputs(ip_dns_server)
        if not ip_dns_server or ip_source == ip_dns_server:
            ip_dns_server = self.statistics.get_random_ip_address()
        mac_dns_server = self.statistics.get_mac_address(ip_dns_server)
        # Set Window Size based on Window Size distribution of IP address
        win_dist = self.statistics.get_win_distribution(ip_source)
        if len(win_dist) > 0:
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
        else:
            win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
        origin_wins = {}
        ttl_map = {}

        origin_mac_src_1 = "00:08:02:1c:47:ae"
        origin_mac_dns_server_1 = "20:e5:2a:b6:93:f1"
        # final mapping of mac values
        mac_map = {origin_mac_src_1: mac_source, origin_mac_dns_server_1: mac_dns_server}

        origin_ip_src_1 = "10.1.5.101"
        origin_ip_dns_server_1 = "10.1.5.1"
        dll_retrieval_ip_1 = "185.225.36.38"
        dll_retrieval_ip_2 = "144.217.79.200"
        icmp_ip_1 = "213.146.212.41"
        icmp_ip_2 = "213.146.212.2"

        # initial mapping of values for resulting pcap
        # a number of IP addresses are preserved for final pcap to preserve key characteristics
        ip_map = {origin_ip_src_1: ip_source, origin_ip_dns_server_1: ip_dns_server,
            dll_retrieval_ip_1: dll_retrieval_ip_1, dll_retrieval_ip_2: dll_retrieval_ip_2,
            icmp_ip_1: icmp_ip_1, icmp_ip_2:icmp_ip_2}

        dns_port, tls_port, browser_port, ssdp_port = 53, 442, 138, 1900
        c2_tcp_port_1, c2_tcp_port_2, c2_tcp_port_3 = 80, 8080, 7080
        spam_bot_port_1, spam_bot_port_2, spam_bot_port_3 = 25, 465, 587

        c2_traffic_port_map = {dns_port: dns_port, tls_port:tls_port, browser_port: browser_port, 
                               ssdp_port: ssdp_port, c2_tcp_port_1: c2_tcp_port_1, 
                               c2_tcp_port_2: c2_tcp_port_2, c2_tcp_port_3: c2_tcp_port_3, 
                               spam_bot_port_1: spam_bot_port_1, spam_bot_port_2: spam_bot_port_2, 
                               spam_bot_port_3: spam_bot_port_3}

        if(spam_bot_activity):
            self.template_attack_pcap_path = self.template_attack_pcap_path_default
        else:
            self.template_attack_pcap_path = self.template_attack_pcap_path_no_spam_bot

        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)

        arrival_time = 0
        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            ip_payload = ip_pkt.payload
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]

            # MAC mapping on Ether level
            if eth_frame.getfieldval("src") in mac_map:
                eth_frame.setfieldval("src", mac_map[eth_frame.getfieldval("src")])
            if eth_frame.getfieldval("dst") in mac_map:
                eth_frame.setfieldval("dst", mac_map[eth_frame.getfieldval("dst")])
            # TTL mapping on IP level
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

            # Setting randomized mappings for source IP addresses
            if ip_pkt.getfieldval("src") not in ip_map:
                ip_map[ip_payload.getfieldval("src")] =  self.statistics.get_random_ip_address(1, list(ip_map.values()))
                ip_pkt.setfieldval("src", ip_map[ip_pkt.getfieldval("src")])
            else:
                ip_pkt.setfieldval("src", ip_map[ip_pkt.getfieldval("src")])

            # Setting randomized mappings for destination IP addresses
            if ip_pkt.getfieldval("dst") not in ip_map:
                ip_map[ip_pkt.getfieldval("dst")] =  self.statistics.get_random_ip_address(1, list(ip_map.values()))
                ip_pkt.setfieldval("dst", ip_map[ip_pkt.getfieldval("dst")])
            else: 
                ip_pkt.setfieldval("dst", ip_map[ip_pkt.getfieldval("dst")])                  

            # Setting randomized mappings for source port values
            if ip_payload.getfieldval("sport") not in c2_traffic_port_map:
                c2_traffic_port_map[ip_payload.getfieldval("sport")] =  self.get_unique_random_ephemeral_port()
                ip_payload.setfieldval("sport", c2_traffic_port_map[ip_payload.getfieldval("sport")])
            else:
                ip_payload.setfieldval("sport", c2_traffic_port_map[ip_payload.getfieldval("sport")])

            # Setting randomized mappings for destination port values
            if ip_payload.getfieldval("dport") not in c2_traffic_port_map:
                c2_traffic_port_map[ip_payload.getfieldval("dport")] =  self.get_unique_random_ephemeral_port()
                ip_payload.setfieldval("dport", c2_traffic_port_map[ip_payload.getfieldval("dport")])
            else: 
                ip_payload.setfieldval("dport", c2_traffic_port_map[ip_payload.getfieldval("dport")])                       

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