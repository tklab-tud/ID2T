import logging
import csv

from random import shuffle, randint, choice, uniform

from lea import Lea

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP
from scapy.layers.netbios import NBTSession

# Resources:
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/dos/smb/smb_loris.rb
# https://samsclass.info/124/proj14/smbl.htm
# https://gist.githubusercontent.com/marcan/6a2d14b0e3eaa5de1795a763fb58641e/raw/565befecf4d9a4a27248d027a90b6e3e5994b5b6/smbloris.c
# http://smbloris.com/

class SMBLorisAttack(BaseAttack.BaseAttack):
    # SMB port
    smb_port = 445

    def __init__(self):
        """
        Creates a new instance of the SMBLorisAttack.

        """
        # Initialize attack
        super(SMBLorisAttack, self).__init__("SMBLoris Attack", "Injects an SMBLoris DoS Attack",
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
            Param.ATTACK_DURATION: ParameterTypes.TYPE_INTEGER_POSITIVE
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

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        random_ip_address = self.statistics.get_random_ip_address()
        # ip-dst should be valid and not equal to ip.src
        while not self.is_valid_ip_address(random_ip_address) or random_ip_address==most_used_ip_address:
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
        def update_timestamp(timestamp, pps, delay=0):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            if delay == 0:
                # Calculate request timestamp
                # To imitate the bursty behavior of traffic
                randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 20, 5 / pps: 7, 10 / pps: 3})
                return timestamp + uniform(1/pps ,  randomdelay.random())
            else:
                # Calculate reply timestamp
                randomdelay = Lea.fromValFreqsDict({2*delay: 70, 3*delay: 20, 5*delay: 7, 10*delay: 3})
                return timestamp + uniform(1 / pps + delay,  1 / pps + randomdelay.random())

        def getIntervalPPS(complement_interval_pps, timestamp):
            """
            Gets the packet rate (pps) for a specific time interval.

            :param complement_interval_pps: an array of tuples (the last timestamp in the interval, the packet rate in the crresponding interval).
            :param timestamp: the timestamp at which the packet rate is required.
            :return: the corresponding packet rate (pps) .
            """
            for row in complement_interval_pps:
                if timestamp<=row[0]:
                    return row[1]
            return complement_interval_pps[-1][1] # in case the timstamp > capture max timestamp

        def getIpData(ip_address: str):
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

        mac_source = self.get_param_value(Param.MAC_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)

        # Calculate complement packet rates of the background traffic for each interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt
        timestamp_prv_reply, timestamp_confirm = 0,0

        # Initialize parameters
        packets = []
        ip_source = self.get_param_value(Param.IP_SOURCE)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)

        # Check ip.src == ip.dst
        self.ip_src_dst_equal_check(ip_source, ip_destination)

        # Get MSS, TTL and Window size value for source and destination IP
        source_mss_value, source_ttl_value, source_win_value = getIpData(ip_source)
        destination_mss_value, destination_ttl_value, destination_win_value = getIpData(ip_destination)

        minDelay,maxDelay = self.get_reply_delay(ip_destination)

        attack_duration = self.get_param_value(Param.ATTACK_DURATION)
        attack_ends_time = timestamp_next_pkt + attack_duration

        sport = 1025

        attacker_seq = randint(1000, 50000)
        victim_seq = randint(1000, 50000)

        # FIXME: Improve timestamp generation
        while timestamp_next_pkt <= attack_ends_time:
            # Establish TCP connection
            if sport > 65535:
                sport = 1025

            # prepare reusable Ethernet- and IP-headers
            attacker_ether = Ether(src=mac_source, dst=mac_destination)
            attacker_ip = IP(src=ip_source, dst=ip_destination, ttl=source_ttl_value, flags='DF')
            victim_ether = Ether(src=mac_destination, dst=mac_source)
            victim_ip = IP(src=ip_destination, dst=ip_source, ttl=destination_ttl_value, flags='DF')

            # connection request from attacker (client)
            syn_tcp = TCP(sport=sport, dport=self.smb_port, window=source_win_value, flags='S',
                          seq=attacker_seq, options=[('MSS', source_mss_value)])
            attacker_seq += 1
            syn = (attacker_ether / attacker_ip / syn_tcp)
            syn.time = timestamp_next_pkt
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
            packets.append(syn)

            # response from victim (server)
            synack_tcp = TCP(sport=self.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                             window=destination_win_value, options=[('MSS', destination_mss_value)])
            victim_seq += 1
            synack = (victim_ether / victim_ip / synack_tcp)
            synack.time = timestamp_next_pkt
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
            packets.append(synack)

            # acknowledgement from attacker (client)
            ack_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq, flags='A',
                          window=source_win_value, options=[('MSS', source_mss_value)])
            ack = (attacker_ether / attacker_ip / ack_tcp)
            ack.time = timestamp_next_pkt
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
            packets.append(ack)

            # send NBT session header paket with maximum LENGTH-field
            req_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq, flags='AP',
                          window=source_win_value, options=[('MSS', source_mss_value)])
            req_payload = NBTSession(TYPE=0x00, LENGTH=0x1FFFF)

            attacker_seq += len(req_payload)
            req = (attacker_ether / attacker_ip / req_tcp / req_payload)
            req.time = timestamp_next_pkt
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
            packets.append(req)

            # final ack from victim (server)
            last_ack_tcp = TCP(sport=self.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='A',
                               window=destination_win_value, options=[('MSS', destination_mss_value)])
            last_ack = (victim_ether / victim_ip / last_ack_tcp)
            last_ack.time = timestamp_next_pkt
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, minDelay)
            packets.append(last_ack)

            sport += 1

            # FIXME: RST?

        # store end time of attack
        self.attack_end_utime = packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(packets), pcap_path
