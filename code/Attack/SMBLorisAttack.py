import logging

from random import randint, uniform
from lea import Lea
from scapy.layers.inet import IP, Ether, TCP
from scapy.layers.netbios import NBTSession

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
from ID2TLib.Utility import update_timestamp
from ID2TLib.SMBLib import smb_port

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
        self.supported_params = {
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.ATTACK_DURATION: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.NUMBER_ATTACKERS: ParameterTypes.TYPE_INTEGER_POSITIVE
        }

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.

        :param statistics: Reference to a statistics object.
        """
        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list):
            most_used_ip_address = most_used_ip_address[0]

        # The most used IP class in background traffic
        most_used_ip_class = self.statistics.process_db_query("most_used(ipClass)")
        num_attackers = randint(1, 16)
        source_ip = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)

        self.add_param_value(Param.IP_SOURCE, source_ip)
        self.add_param_value(Param.MAC_SOURCE, self.generate_random_mac_address(num_attackers))

        random_ip_address = self.statistics.get_random_ip_address()
        # ip-dst should be valid and not equal to ip.src
        while not self.is_valid_ip_address(random_ip_address) or random_ip_address == source_ip:
            random_ip_address = self.statistics.get_random_ip_address()

        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)
        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        self.add_param_value(Param.ATTACK_DURATION, 30)

    def generate_attack_pcap(self):
        def get_ip_data(ip_address: str):
            """
            :param ip_address: the ip of which (packet-)data shall be returned
            :return: MSS, TTL and Window Size values of the given IP
            """
            # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
            mss_dist = self.statistics.get_mss_distribution(ip_address)
            if len(mss_dist) > 0:
                mss_prob_dict = Lea.fromValFreqsDict(mss_dist)
                mss_value = mss_prob_dict.random()
            else:
                mss_value = self.statistics.process_db_query("most_used(mssValue)")

            # Set TTL based on TTL distribution of IP address
            ttl_dist = self.statistics.get_ttl_distribution(ip_address)
            if len(ttl_dist) > 0:
                ttl_prob_dict = Lea.fromValFreqsDict(ttl_dist)
                ttl_value = ttl_prob_dict.random()
            else:
                ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

            # Set Window Size based on Window Size distribution of IP address
            win_dist = self.statistics.get_win_distribution(ip_address)
            if len(win_dist) > 0:
                win_prob_dict = Lea.fromValFreqsDict(win_dist)
                win_value = win_prob_dict.random()
            else:
                win_value = self.statistics.process_db_query("most_used(winSize)")

            return mss_value, ttl_value, win_value

        pps = self.get_param_value(Param.PACKETS_PER_SECOND)

        # Timestamp
        first_timestamp = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = first_timestamp

        # Initialize parameters
        packets = []
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(Param.NUMBER_ATTACKERS)
        if (num_attackers is not None) and (num_attackers is not 0):  # user supplied Param.NUMBER_ATTACKERS
            # The most used IP class in background traffic
            most_used_ip_class = self.statistics.process_db_query("most_used(ipClass)")
            # Create random attackers based on user input Param.NUMBER_ATTACKERS
            ip_source = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply Param.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source = self.get_param_value(Param.IP_SOURCE)
            mac_source = self.get_param_value(Param.MAC_SOURCE)

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
        destination_mss_value, destination_ttl_value, destination_win_value = get_ip_data(ip_destination)

        minDelay,maxDelay = self.get_reply_delay(ip_destination)

        attack_duration = self.get_param_value(Param.ATTACK_DURATION)
        attack_ends_time = first_timestamp + attack_duration

        victim_pps = pps*num_attackers

        for attacker in range(num_attackers):
            # Get MSS, TTL and Window size value for source IP(attacker)
            source_mss_value, source_ttl_value, source_win_value = get_ip_data(ip_source_list[attacker])

            attacker_seq = randint(1000, 50000)
            victim_seq = randint(1000, 50000)

            sport = 1025

            # Timestamps of first packets shouldn't be exactly the same to look more realistic
            timestamp_next_pkt = uniform(first_timestamp, update_timestamp(first_timestamp, pps))

            while timestamp_next_pkt <= attack_ends_time:
                # Establish TCP connection
                if sport > 65535:
                    sport = 1025

                # prepare reusable Ethernet- and IP-headers
                attacker_ether = Ether(src=mac_source_list[attacker], dst=mac_destination)
                attacker_ip = IP(src=ip_source_list[attacker], dst=ip_destination, ttl=source_ttl_value, flags='DF')
                victim_ether = Ether(src=mac_destination, dst=mac_source_list[attacker])
                victim_ip = IP(src=ip_destination, dst=ip_source_list[attacker], ttl=destination_ttl_value, flags='DF')

                # connection request from attacker (client)
                syn_tcp = TCP(sport=sport, dport=smb_port, window=source_win_value, flags='S',
                              seq=attacker_seq, options=[('MSS', source_mss_value)])
                attacker_seq += 1
                syn = (attacker_ether / attacker_ip / syn_tcp)
                syn.time = timestamp_next_pkt
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, victim_pps, minDelay)
                packets.append(syn)

                # response from victim (server)
                synack_tcp = TCP(sport=smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                                 window=destination_win_value, options=[('MSS', destination_mss_value)])
                victim_seq += 1
                synack = (victim_ether / victim_ip / synack_tcp)
                synack.time = timestamp_next_pkt
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
                packets.append(synack)

                # acknowledgement from attacker (client)
                ack_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq, flags='A',
                              window=source_win_value, options=[('MSS', source_mss_value)])
                ack = (attacker_ether / attacker_ip / ack_tcp)
                ack.time = timestamp_next_pkt
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps)
                packets.append(ack)

                # send NBT session header paket with maximum LENGTH-field
                req_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq, flags='AP',
                              window=source_win_value, options=[('MSS', source_mss_value)])
                req_payload = NBTSession(TYPE=0x00, LENGTH=0x1FFFF)

                attacker_seq += len(req_payload)
                req = (attacker_ether / attacker_ip / req_tcp / req_payload)
                req.time = timestamp_next_pkt
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, victim_pps, minDelay)
                packets.append(req)

                # final ack from victim (server)
                last_ack_tcp = TCP(sport=smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='A',
                                   window=destination_win_value, options=[('MSS', destination_mss_value)])
                last_ack = (victim_ether / victim_ip / last_ack_tcp)
                last_ack.time = timestamp_next_pkt
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
                packets.append(last_ack)

                sport += 1

        # store end time of attack
        self.attack_end_utime = packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(packets), pcap_path
