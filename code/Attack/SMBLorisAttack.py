import logging
import random as rnd

import scapy.layers.inet as inet
from scapy.layers.netbios import NBTSession

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.SMBLib as SMBLib
import ID2TLib.Utility as Util

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class SMBLorisAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the SMBLorisAttack.
        """
        # Initialize attack
        super(SMBLorisAttack, self).__init__("SMBLoris Attack", "Injects an SMBLoris (D)DoS Attack",
                                             "Resource Exhaustion")

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.MAC_DESTINATION: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.ATTACK_DURATION: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE,
            atkParam.Parameter.NUMBER_ATTACKERS: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE
        })

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.
        """

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()

        # The most used IP class in background traffic
        most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
        num_attackers = rnd.randint(1, 16)
        source_ip = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)

        self.add_param_value(atkParam.Parameter.IP_SOURCE, source_ip)
        self.add_param_value(atkParam.Parameter.MAC_SOURCE, self.generate_random_mac_address(num_attackers))

        random_ip_address = self.statistics.get_random_ip_address()
        # ip-dst should be valid and not equal to ip.src
        while not self.is_valid_ip_address(random_ip_address) or random_ip_address == source_ip:
            random_ip_address = self.statistics.get_random_ip_address()

        self.add_param_value(atkParam.Parameter.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(atkParam.Parameter.MAC_DESTINATION, destination_mac)
        self.add_param_value(atkParam.Parameter.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(atkParam.Parameter.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))
        self.add_param_value(atkParam.Parameter.ATTACK_DURATION, 30)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        pps = self.get_param_value(atkParam.Parameter.PACKETS_PER_SECOND)

        # Timestamp
        first_timestamp = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = first_timestamp

        # Initialize parameters
        self.packets = []
        ip_destination = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
        mac_destination = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(atkParam.Parameter.NUMBER_ATTACKERS)
        # user supplied atkParam.Parameter.NUMBER_ATTACKERS
        if (num_attackers is not None) and (num_attackers is not 0):
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            # Create random attackers based on user input atkParam.Parameter.NUMBER_ATTACKERS
            ip_source = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply atkParam.Parameter.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source = self.get_param_value(atkParam.Parameter.IP_SOURCE)
            mac_source = self.get_param_value(atkParam.Parameter.MAC_SOURCE)

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
        self.ip_src_dst_equal_check(ip_source_list, ip_destination)

        # Get MSS, TTL and Window size value for destination IP
        destination_mss_value, destination_ttl_value, destination_win_value = self.get_ip_data(ip_destination)

        min_delay, max_delay = self.get_reply_delay(ip_destination)

        attack_duration = self.get_param_value(atkParam.Parameter.ATTACK_DURATION)
        attack_ends_time = first_timestamp + attack_duration

        victim_pps = pps * num_attackers

        for attacker in range(num_attackers):
            # Get MSS, TTL and Window size value for source IP(attacker)
            source_mss_value, source_ttl_value, source_win_value = self.get_ip_data(ip_source_list[attacker])

            attacker_seq = rnd.randint(1000, 50000)
            victim_seq = rnd.randint(1000, 50000)

            sport = 1025

            # Timestamps of first self.packets shouldn't be exactly the same to look more realistic
            timestamp_next_pkt = rnd.uniform(first_timestamp, Util.update_timestamp(first_timestamp, pps))

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
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, victim_pps, min_delay)
                self.packets.append(syn)

                # response from victim (server)
                synack_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                                      window=destination_win_value, options=[('MSS', destination_mss_value)])
                victim_seq += 1
                synack = (victim_ether / victim_ip / synack_tcp)
                synack.time = timestamp_next_pkt
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps, min_delay)
                self.packets.append(synack)

                # acknowledgement from attacker (client)
                ack_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq, flags='A',
                                   window=source_win_value, options=[('MSS', source_mss_value)])
                ack = (attacker_ether / attacker_ip / ack_tcp)
                ack.time = timestamp_next_pkt
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps)
                self.packets.append(ack)

                # send NBT session header paket with maximum LENGTH-field
                req_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq, flags='AP',
                                   window=source_win_value, options=[('MSS', source_mss_value)])
                req_payload = NBTSession(TYPE=0x00, LENGTH=0x1FFFF)

                attacker_seq += len(req_payload)
                req = (attacker_ether / attacker_ip / req_tcp / req_payload)
                req.time = timestamp_next_pkt
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, victim_pps, min_delay)
                self.packets.append(req)

                # final ack from victim (server)
                last_ack_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='A',
                                        window=destination_win_value, options=[('MSS', destination_mss_value)])
                last_ack = (victim_ether / victim_ip / last_ack_tcp)
                last_ack.time = timestamp_next_pkt
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps, min_delay)
                self.packets.append(last_ack)

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
