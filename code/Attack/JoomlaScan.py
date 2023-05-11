import logging
import random as rnd

import lea
import scapy.layers.inet as inet
import scapy.utils

import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util

from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Port

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class JoomlaScan(BaseAttack.BaseAttack):
    PORT_DESTINATION = 'port.dst'
    MY_SQL_PORT = 3306
    ATTACKER_IP = '172.18.0.1' 
    VICTIM_IP = '172.18.0.3'
    MYSQL_DB_IP = '172.18.0.2'
    template_scan_pcap_path = Util.RESOURCE_DIR + "JoomlaScan.pcap"

    """
    Creates a new instance of the Joomla Scan
    """
    def __init__(self):
        # Initialize attack
        super(JoomlaScan, self).__init__("JoomlaScanAttack", "Injects a Joomla Scan'",
                                             "Scanning/Probing")
        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_DESTINATION, Port()),
            Parameter(self.PACKETS_PER_SECOND, Float())
        ])

    """
    Initialize a parameter with its default values specified in this attack.

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
        elif param == self.PORT_DESTINATION:
            value = 80 # HTTP
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
        # Attack configuration
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        if value is None:
            return False
        return self.add_param_value(param, value)


    """
    Generate SQL convo parameters 
    """
    def generate_sql_param(self): 
        ip_addresses_in_use = self.statistics.get_ip_addresses()
        ip_attakcer = self.get_param_value(self.IP_DESTINATION) # attacker ip 
        subnet_mask = "255.255.255.0"
        ip_sql = self.get_unique_random_ipv4_from_ip_network(ip_attakcer, subnet_mask,ip_addresses_in_use)
        mac_sql = self.generate_random_mac_address() 
        return mac_sql, ip_sql

    """
    Creates the attack packets
    """
    def generate_attack_packets(self):

# Timestamp
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

        # Initialize parameters
        mac_source = self.get_param_value(self.MAC_SOURCE)
        ip_source = self.get_param_value(self.IP_SOURCE)
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
        source_win_prob_dict = self.get_window_distribution(ip_source)
        destination_win_prob_dict = self.get_window_distribution(ip_destination)

        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())
        if not mss_value:
            mss_value = 1465

        # Communication is between server & its db 
        mac_sql, ip_sql = self.generate_sql_param()

        arrival_time = 0
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_scan_pcap_path)

        source_origin_wins, destination_origin_wins = {}, {}
        ephemeral_ports = {}
        reserved_ports = {self.MY_SQL_PORT,port_destination}

        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload
            tcp_pkt = ip_pkt.payload
            ep, ephemeral_ports = self.generate_ephemeral_ports(tcp_pkt,ephemeral_ports,reserved_ports)
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]

            # Request (Attacker, -> Victim)
            if ip_pkt.getfieldval("src") == self.ATTACKER_IP:
                # set src values 
                eth_frame.setfieldval("src", mac_source)         
                ip_pkt.setfieldval("src", ip_source)
                tcp_pkt.setfieldval("sport", ep)
                ip_pkt.setfieldval("ttl", source_ttl_value)
                # set dst values 
                eth_frame.setfieldval("dst", mac_destination)      
                ip_pkt.setfieldval("dst", ip_destination)
                tcp_pkt.setfieldval("dport", port_destination)
                
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


            # Request (DB ->  Victim/WebApp)
            elif ip_pkt.getfieldval("src") == self.MYSQL_DB_IP:
                
                # set src values 
                eth_frame.setfieldval("src", mac_sql)         
                ip_pkt.setfieldval("src", ip_sql)
                tcp_pkt.setfieldval("sport", self.MY_SQL_PORT)  
                
                # set dst values
                eth_frame.setfieldval("dst", mac_destination)      
                ip_pkt.setfieldval("dst", ip_destination)
                tcp_pkt.setfieldval("dport", ep) 
                

            # Reply (Victim -> Attacker or DB)
            else:
                # set victim src values 
                eth_frame.setfieldval("src", mac_destination)         
                ip_pkt.setfieldval("src", ip_destination)
               
                # We do not affect the window size & MSS values for internal traffic to DB
                if ip_pkt.getfieldval("dst") == self.MYSQL_DB_IP:
                    # set dst values (victim -> db)
                    eth_frame.setfieldval("dst", mac_sql)         
                    ip_pkt.setfieldval("dst", ip_sql)
                    tcp_pkt.setfieldval("sport", ep)  
                    tcp_pkt.setfieldval("dport", self.MY_SQL_PORT) 
                    
                else:# (victim -> attack)
                    # set dst values (victim -> attack)
                    eth_frame.setfieldval("dst", mac_source)
                    ip_pkt.setfieldval("dst", ip_source)
                    ip_pkt.setfieldval("ttl", destination_ttl_value)
                    tcp_pkt.setfieldval("sport",  port_destination)
                    tcp_pkt.setfieldval("dport", ep)
                    
                    # Window Size (mapping)
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
                
            # Generate packet 
            new_pkt = (eth_frame / ip_pkt / tcp_pkt)
            new_pkt.time = timestamp_next_pkt + arrival_time
            timestamp_next_pkt = self.timestamp_controller.next_timestamp()
        
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