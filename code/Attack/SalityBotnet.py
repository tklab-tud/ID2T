import logging

from random import randint, choice
from scapy.utils import RawPcapReader
from scapy.layers.inet import Ether

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
import ID2TLib.Utility as Util

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8


class SalityBotnet(BaseAttack.BaseAttack):
    template_attack_pcap_path = Util.RESOURCE_DIR + "/../resources/sality_botnet.pcap"

    def __init__(self):
        """
        Creates a new instance of the Sality botnet.

        """
        # Initialize attack
        super(SalityBotnet, self).__init__("Sality Botnet", "Injects an Sality botnet'",
                                        "Botnet")

        # Define allowed parameters and their type
        self.supported_params.update({
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT
        })

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.

        :param statistics: Reference to a statistics object.
        """
        # PARAMETERS: initialize with default utilsvalues
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        # Attack configuration
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)

    def generate_attack_pcap(self):

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)

        pps = self.get_param_value(Param.PACKETS_PER_SECOND)

        # Calculate complement packet rates of BG traffic per interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Initialize parameters
        packets = []
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        ip_source = self.get_param_value(Param.IP_SOURCE)

        # Pick a DNS server from the background traffic
        ip_dns_server = self.statistics.process_db_query("SELECT ipAddress FROM ip_protocols WHERE protocolName='DNS' AND protocolCount=(SELECT MAX(protocolCount) FROM ip_protocols WHERE protocolName='DNS');")
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

        ip_map = {origin_ip_src : ip_source, origin_ip_dns_server: ip_dns_server}
        mac_map = {origin_mac_src : mac_source, origin_mac_dns_server: mac_dns_server}

        path_attack_pcap = None

        # Inject Sality botnet
        # Read sality_botnet pcap file
        exploit_raw_packets = RawPcapReader(self.template_attack_pcap_path)

        for pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = Ether(pkt[0])
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

            ## TTL
            if ip_pkt.getfieldval("ttl") not in ttl_map:
                source_ttl = self.statistics.get_most_used_ttl(ip_pkt.getfieldval("src"))
                if not source_ttl:
                    source_ttl = self.statistics.process_db_query("SELECT ttlValue FROM ip_ttl;")
                    if isinstance(source_ttl, list):
                        source_ttl = choice(source_ttl)
                ttl_map[ip_pkt.getfieldval("ttl")] = source_ttl
            ip_pkt.setfieldval("ttl", ttl_map[ip_pkt.getfieldval("ttl")])

            new_pkt = (eth_frame / ip_pkt)
            new_pkt.time = timestamp_next_pkt

            pps = max(Util.get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
            timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps)

            packets.append(new_pkt)

        exploit_raw_packets.close()
        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = packets[0].time
        self.attack_end_utime = packets[-1].time

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return pkt_num + 1, path_attack_pcap