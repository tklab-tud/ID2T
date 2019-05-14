import logging
import random as rnd
import typing

import scapy.layers.inet as inet

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util
import ID2TLib.Memcached as Memcd

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class MemcrashedSpooferAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the "Memcrashed" Memcached amplification attack.
        """
        # Initialize attack
        super(MemcrashedSpooferAttack, self).__init__("Memcrashed Attack (Spoofer side)",
                                               "Injects the spoofer-side of a Memcached amplification attack",
                                               "Resource Exhaustion")

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_DESTINATION: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.IP_VICTIM: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.ATTACK_DURATION: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE
        })

    def init_params(self) -> None:
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.
        """
        # By default, the most used IP is the attacker
        most_used_ip = self.statistics.get_most_used_ip_address()
        self.add_param_value(atkParam.Parameter.IP_SOURCE, most_used_ip)
        self.add_param_value(atkParam.Parameter.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip))

        # Target (i.e. amplifier) is a random public IP
        self.add_param_value(atkParam.Parameter.IP_DESTINATION, self.generate_random_ipv4_address('A'))
        self.add_param_value(atkParam.Parameter.MAC_DESTINATION, self.generate_random_mac_address())

        # IP of the victim which is supposed to get hit by the amplified attack
        self.add_param_value(atkParam.Parameter.IP_VICTIM, self.generate_random_ipv4_address('A'))

        self.add_param_value(atkParam.Parameter.PACKETS_PER_SECOND, (self.statistics.get_pps_sent(most_used_ip) +
                             self.statistics.get_pps_received(most_used_ip)) / 2)
        self.add_param_value(atkParam.Parameter.ATTACK_DURATION, rnd.randint(5, 30))
        self.add_param_value(atkParam.Parameter.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))

    def generate_attack_packets(self) -> None:
        ip_attacker = self.get_param_value(atkParam.Parameter.IP_SOURCE)
        mac_attacker = self.get_param_value(atkParam.Parameter.MAC_SOURCE)
        ip_amplifier = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
        mac_amplifier = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)
        ip_victim = self.get_param_value(atkParam.Parameter.IP_VICTIM)

        timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
        self.attack_start_utime = timestamp_next_pkt

        attack_duration = self.get_param_value(atkParam.Parameter.ATTACK_DURATION)
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
