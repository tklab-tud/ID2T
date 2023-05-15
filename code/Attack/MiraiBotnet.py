import logging
import random as rnd
import lea
import scapy.utils
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
import scapy.layers.inet as inet
import Attack.BaseAttack as BaseAttack
from Attack.Parameter import Parameter, MACAddress, Float, String, IPAddress, Port
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class MiraiBotnet(BaseAttack.BaseAttack):
    PORT_DESTINATION = 'port.dst'
    HTTP_FLOOD_TARGET = 'http.flood.target.ip'
    LOADER_SERVER = 'loader.server.ip'
    CNC_SERVER = 'cnc.server.ip'
    PORT_SOURCE = 'port.src'

    ATTACKER_BOTNET_IP = '172.20.0.1'
    LOADER_SERVER_IP = '49.182.192.4'
    CNC_SERVER_IP = '42.123.199.32'
    VICTIM_IP = '172.20.0.5'
    HTTP_FLOOD_TARGET_IP = '49.193.198.24'
    INIT_PORT = 46662
    HTTP_PORT = 80
    FTP_PORT = 23
    LOADER_PORT = 23
    template_attack_pcap_path = Util.RESOURCE_DIR + "mirai_botnet.pcap"

    def __init__(self):
        """
        Creates a new instance of the Mirai botnet.
        """
        # Initialize attack
        super(MiraiBotnet, self).__init__("Mirai Botnet", "Injects a Mirai botnet'", "Botnet")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),            
            Parameter(self.PORT_DESTINATION, Port()),
            Parameter(self.LOADER_SERVER, String()),
            Parameter(self.CNC_SERVER, String()),
            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.HTTP_FLOOD_TARGET, String())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.
        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        if param == self.IP_DESTINATION:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if not ip_dst:
                return False
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
            value = self.get_unique_random_ephemeral_port()
        elif param == self.PORT_DESTINATION:
            value = self.FTP_PORT
        elif param == self.INJECT_AFTER_PACKET:
            self.add_param_value(self.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.LOADER_SERVER:
            value = self.LOADER_SERVER_IP
        elif param == self.CNC_SERVER:
            value = self.CNC_SERVER_IP
        elif param == self.HTTP_FLOOD_TARGET:
            ip_src = self.get_param_value(self.IP_SOURCE)
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_src is None or ip_dst is None:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_src,ip_dst])
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
        mac_destination = self.get_param_value(self.MAC_DESTINATION)
        ip_source = self.get_param_value(self.IP_SOURCE)
        ip_destination = self.get_param_value(self.IP_DESTINATION)
        http_flood_target = self.get_param_value(self.HTTP_FLOOD_TARGET)
        port_source = self.get_param_value(self.PORT_SOURCE)
        port_destination = self.get_param_value(self.PORT_DESTINATION)
        # LOADER values    
        loader_server_mac =  self.generate_random_mac_address()  
        loader_server_ip = self.get_param_value(self.LOADER_SERVER) 
        victim_loader_ep_port = self.get_unique_random_ephemeral_port()
        # CNC values
        mac_cnc_server = self.generate_random_mac_address()  
        ip_cnc_server = self.get_param_value(self.CNC_SERVER)

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
        destination_win_prob_dict = self.get_window_distribution( ip_destination)

        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())
        if not mss_value:
            mss_value = 1465

        arrival_time = 0
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        source_origin_wins, destination_origin_wins = {}, {}
        ephemeral_ports = {self.INIT_PORT:port_source}
        reserved_ports = { self.HTTP_PORT,self.FTP_PORT, port_source, port_destination}


        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload       
            tcp_pkt = ip_pkt.payload      
            ep, ephemeral_ports = self.generate_ephemeral_ports(tcp_pkt,ephemeral_ports,reserved_ports)
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]
            arrival_time = 0
            
            # Request (ATTACKER BOT -> VICTIM)
            if ip_pkt.getfieldval("src") == self.ATTACKER_BOTNET_IP: 
                # Ether
                eth_frame.setfieldval("src", mac_source)
                eth_frame.setfieldval("dst", mac_destination)
                # IP
                ip_pkt.setfieldval("src", ip_source)
                ip_pkt.setfieldval("dst", ip_destination)
                ip_pkt.setfieldval("ttl", source_ttl_value)
                # TCP
                tcp_pkt.setfieldval("sport", ep)
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

            # LOADER_SERVER OR CNC_SERVER -> VICTIM
            elif ip_pkt.getfieldval("src") == self.CNC_SERVER_IP or ip_pkt.getfieldval("src") == self.LOADER_SERVER_IP:
                # set dst values
                eth_frame.setfieldval("dst", mac_destination)
                ip_pkt.setfieldval("dst", ip_destination)
                if ip_pkt.getfieldval("src") == self.CNC_SERVER_IP:
                    eth_frame.setfieldval("src", mac_cnc_server)
                    ip_pkt.setfieldval("src", ip_cnc_server)
                    tcp_pkt.setfieldval("dport", ep)
                else: 
                    eth_frame.setfieldval("src", loader_server_mac)
                    ip_pkt.setfieldval("src", loader_server_ip)
                    tcp_pkt.setfieldval("dport", victim_loader_ep_port)

            # Reply (VICTIM -> ATTACKER, LDAP_SERVER, DNS, HTTP_FLOODING_TARGET)
            elif ip_pkt.getfieldval("src")  == self.VICTIM_IP:
                # set sources 
                eth_frame.setfieldval("src", mac_destination)
                ip_pkt.setfieldval("src", ip_destination)
                ip_pkt.setfieldval("ttl", destination_ttl_value)

                if ip_pkt.getfieldval("dst") == self.CNC_SERVER_IP:
                    # set src 
                    tcp_pkt.setfieldval("sport", ep) 
                    # set dst 
                    eth_frame.setfieldval("dst", mac_cnc_server)
                    ip_pkt.setfieldval("dst", ip_cnc_server)
                
                elif ip_pkt.getfieldval("dst") == self.LOADER_SERVER_IP:
                    # set src 
                    tcp_pkt.setfieldval("sport", victim_loader_ep_port) 
                    # set dst 
                    eth_frame.setfieldval("dst", loader_server_mac)
                    ip_pkt.setfieldval("dst", loader_server_ip)   

                elif ip_pkt.getfieldval("dst") == self.ATTACKER_BOTNET_IP:
                    # set src 
                    eth_frame.setfieldval("dst", mac_source)
                    ip_pkt.setfieldval("dst", ip_source)
                    tcp_pkt.setfieldval("sport", port_destination)
                    # set dst 
                    tcp_pkt.setfieldval("dport", ep) 
                elif ip_pkt.getfieldval("dst") == self.HTTP_FLOOD_TARGET_IP:
                    ip_pkt.setfieldval("dst", http_flood_target)

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
            
            # Generate packet 
            self.update_ip_packet_len_and_checksums(ip_pkt)
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
