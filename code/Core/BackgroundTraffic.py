import logging

from scapy.all import *
import scapy.layers.inet as inet
import scapy.utils
import os
import tempfile
from scapy.layers.inet import TCP
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
load_layer("http")
class BackgroundTraffic: 

    def __init__(self, pcap_dest_path):
        self.pcap_dest_path = pcap_dest_path
        self.packets = []

    class WinHTTPSysExploit: 

        def __init__(self, pcap_dest_path):
            self.pcap_dest_path = pcap_dest_path
            self.packets = []

        def locate_final_attack_packet(self):
            """
            Locates malicious attack packet and the IP address of its receiver after 
            injection of attack packets for the attack: WinHttpSysExploit.
            :return the IP address of the victim, the packet number for the malicious packet.
            """
            input_pcap_raw_packets = scapy.utils.RawPcapReader(self.pcap_dest_path)
            victim_ip = ''
            final_attack_packet = 0
            accept_encoding_for_malicious_attack_packet = "Accept-Encoding: AAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&AA&**AAAAAAAAAAAAAAAAAAAA**A,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAA,****************************AAAAAA, *, ,"
            http_port = 80
            payload_size = 476
            for pkt_num, pkt in enumerate(input_pcap_raw_packets): 
                eth_frame = inet.Ether(pkt[0])
                ip_pkt = eth_frame.payload       
                ip_payload = ip_pkt.payload
                http_pkt = ip_payload.payload
                str_tcp_seg = str(ip_payload.payload)

                if http_pkt and ip_payload.haslayer(TCP) and ip_payload.getfieldval("dport") == http_port and len(str_tcp_seg) == payload_size:
                    payload = http_pkt[Raw].load.decode()
                    http_pkt[Raw].load = payload
                    if accept_encoding_for_malicious_attack_packet in payload:
                        final_attack_packet = pkt_num + 1
                        victim_ip = ip_pkt.getfieldval("dst")
                        return self.modify_background_traffic(victim_ip, final_attack_packet)

        def modify_background_traffic(self, victim_ip, final_attack_packet):
            """
            Deletes all activity the IP address of the victim after having received 
            the malicious attack packet.
            :return updated pcap file.
            """
            input_pcap_raw_packets = scapy.utils.RawPcapReader(self.pcap_dest_path)
            for pkt_num, pkt in enumerate(input_pcap_raw_packets):
                eth_frame = inet.Ether(pkt[0])
                ip_pkt = eth_frame.payload
                ip_payload = ip_pkt.payload
                http_pkt = ip_payload.payload
                if http_pkt: 
                    ip_src = ip_pkt.getfieldval("src")
                    ip_dst = ip_pkt.getfieldval("dst")
                    if pkt_num < final_attack_packet:
                        new_pkt = new_pkt = (eth_frame / ip_pkt / ip_payload)
                        self.packets.append(new_pkt)
                    if pkt_num > final_attack_packet and ip_src != victim_ip and ip_dst != victim_ip:
                        new_pkt = new_pkt = (eth_frame / ip_pkt / ip_payload)
                        self.packets.append(new_pkt)
                else: 
                    if pkt_num < final_attack_packet: 
                        new_pkt = new_pkt = (eth_frame / ip_pkt / ip_payload)
                        self.packets.append(new_pkt)
            input_pcap_raw_packets.close()
            if len(self.packets) > 0:
                self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
                self.path_attack_pcap = self.overwrite_destination_pcap(self.packets, False, self.pcap_dest_path)
            return len(self.packets)


        def overwrite_destination_pcap(self, packets: list, append_flag: bool, destination_path: str):
            """
            Writes the packets into a PCAP file with a destination path.
            :return: The path of the written PCAP file.
            """

            # Determine destination path
            if os.path.exists(destination_path):
                destination = destination_path
            else:
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
                destination = temp_file.name

            # Write packets into pcap file
            pktdump = scapy.utils.PcapWriter(destination, append=append_flag)
            pktdump.write(packets)

            # Store pcap path and close file objects
            pktdump.close()
            return destination