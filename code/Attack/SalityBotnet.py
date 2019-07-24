import logging
import random as rnd

import scapy.layers.inet as inet
import scapy.utils

import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

from Attack.AttackParameters import ParameterTypes as ParamTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class SalityBotnet(BaseAttack.BaseAttack):
    MAC_SOURCE = 'mac.src'
    IP_SOURCE = 'ip.src'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'
    INJECT_AFTER_PACKET = 'inject.after-pkt'
    PACKETS_PER_SECOND = 'packets.per-second'

    template_attack_pcap_path = Util.RESOURCE_DIR + "/../resources/sality_botnet.pcap"

    def __init__(self):
        """
        Creates a new instance of the Sality botnet.
        """
        # Initialize attack
        super(SalityBotnet, self).__init__("Sality Botnet", "Injects an Sality botnet'",
                                           "Botnet")

        self.pkt_num = 0
        self.path_attack_pcap = None

        # Define allowed parameters and their type
        self.supported_params.update({
            self.MAC_SOURCE: ParamTypes.TYPE_MAC_ADDRESS,
            self.IP_SOURCE: ParamTypes.TYPE_IP_ADDRESS,
            self.INJECT_AT_TIMESTAMP: ParamTypes.TYPE_FLOAT,
            self.INJECT_AFTER_PACKET: ParamTypes.TYPE_PACKET_POSITION,
            self.PACKETS_PER_SECOND: ParamTypes.TYPE_FLOAT
        })

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

        # Pick a DNS server from the background traffic
        ip_dns_server = self.statistics.process_db_query(
            "SELECT ipAddress FROM ip_protocols WHERE protocolName='DNS' AND protocolCount=(SELECT MAX(protocolCount) "
            "FROM ip_protocols WHERE protocolName='DNS');")
        ip_dns_server = Util.handle_most_used_outputs(ip_dns_server)
        if not ip_dns_server or ip_source == ip_dns_server:
            ip_dns_server = self.statistics.get_random_ip_address()
        mac_dns_server = self.statistics.get_mac_address(ip_dns_server)

        # Bot original config in the template PCAP
        origin_mac_src = "08:00:27:e5:d7:b0"
        origin_ip_src = "10.0.2.15"

        origin_mac_dns_server = "52:54:00:12:35:02"
        origin_ip_dns_server = "10.0.2.2"

        ttl_map = {}

        ip_map = {origin_ip_src: ip_source, origin_ip_dns_server: ip_dns_server}
        mac_map = {origin_mac_src: mac_source, origin_mac_dns_server: mac_dns_server}

        # Inject Sality botnet
        # Read sality_botnet pcap file
        exploit_raw_packets = scapy.utils.RawPcapReader(self.template_attack_pcap_path)

        for self.pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])
            ip_pkt = eth_frame.payload

            # Ether
            if eth_frame.getfieldval("src") in mac_map:
                eth_frame.setfieldval("src", mac_map[eth_frame.getfieldval("src")])
            if eth_frame.getfieldval("dst") in mac_map:
                eth_frame.setfieldval("dst", mac_map[eth_frame.getfieldval("dst")])

            # IP
            if ip_pkt.getfieldval("src") in ip_map:
                ip_pkt.setfieldval("src", ip_map[ip_pkt.getfieldval("src")])
            if ip_pkt.getfieldval("dst") in ip_map:
                ip_pkt.setfieldval("dst", ip_map[ip_pkt.getfieldval("dst")])

            # TTL
            if ip_pkt.getfieldval("ttl") not in ttl_map:
                source_ttl = self.statistics.get_most_used_ttl(ip_pkt.getfieldval("src"))
                if not source_ttl:
                    source_ttl = self.statistics.process_db_query("SELECT ttlValue FROM ip_ttl;")
                    if isinstance(source_ttl, list):
                        source_ttl = rnd.choice(source_ttl)
                ttl_map[ip_pkt.getfieldval("ttl")] = source_ttl
            ip_pkt.setfieldval("ttl", ttl_map[ip_pkt.getfieldval("ttl")])

            new_pkt = (eth_frame / ip_pkt)
            new_pkt.time = timestamp_next_pkt

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
