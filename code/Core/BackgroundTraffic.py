import logging

from scapy.all import *
import scapy.layers.inet as inet
import scapy.utils
import os
import tempfile
from scapy.layers.inet import IP
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

        def get_temp_attack_details(self, attacks_pcap_path): 
            """
            Retreieves relevant details from attack

            :return IP address of the victim, timestamp for malicious packet, boolean (indicating whether background traffic should be modified)
            """
            input_pcap_raw_packets = scapy.utils.RawPcapReader(attacks_pcap_path)
            victim_ip = ''
            timestamp_for_malicious_packet = 0
            background_manipulation = True
            for pkt_num, pkt in enumerate(input_pcap_raw_packets):
                eth_frame = inet.Ether(pkt[0])
                pkt_metadata = pkt[1]
                ip_pkt = eth_frame.payload
                if pkt_num == 12: 
                    victim_ip = ip_pkt.getfieldval("dst")
                    timestamp_for_malicious_packet = pkt_metadata.sec + pkt_metadata.usec / 1e6
                if pkt_num == 13: 
                    background_manipulation = False
            return victim_ip, timestamp_for_malicious_packet, background_manipulation

        def modify_background_traffic(self, victim_ip, timestamp_for_malicious_packet):
            """
            Deletes all activity the IP address of the victim after having received 
            the malicious attack packet.

            :return updated pcap file.
            """
            input_pcap_raw_packets = scapy.utils.RawPcapReader(self.pcap_dest_path)
            for _, pkt in enumerate(input_pcap_raw_packets):
                eth_frame = inet.Ether(pkt[0])
                pkt_metadata = pkt[1]
                ip_pkt = eth_frame.payload
                ip_payload = ip_pkt.payload
                timestamp = pkt_metadata.sec + pkt_metadata.usec / 1e6

                is_victim_ip = True
                if eth_frame.haslayer(IP): 
                    ip_src = ip_pkt.getfieldval("src")
                    ip_dst = ip_pkt.getfieldval("dst")
                    is_victim_ip = ip_src == victim_ip or ip_dst == victim_ip
                if timestamp <= timestamp_for_malicious_packet or (timestamp > timestamp_for_malicious_packet and not is_victim_ip):
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