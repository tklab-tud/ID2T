import collections as col
import logging
import random as rnd

import lea
import scapy.layers.inet as inet
import scipy.stats as stats

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class DDoSAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the DDoS attack.
        """
        # Initialize attack
        super(DDoSAttack, self).__init__("DDoS Attack", "Injects a DDoS attack'",
                                         "Resource Exhaustion")

        self.last_packet = None
        self.total_pkt_num = 0

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.PORT_SOURCE: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.MAC_DESTINATION: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.PORT_DESTINATION: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.NUMBER_ATTACKERS: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE,
            atkParam.Parameter.ATTACK_DURATION: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE,
            atkParam.Parameter.VICTIM_BUFFER: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE
        })

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.
        """
        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        self.add_param_value(atkParam.Parameter.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))
        # attacker configuration
        num_attackers = rnd.randint(1, 16)
        # The most used IP class in background traffic
        most_used_ip_class = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(ipClass)"))

        self.add_param_value(atkParam.Parameter.IP_SOURCE,
                             self.generate_random_ipv4_address(most_used_ip_class, num_attackers))
        self.add_param_value(atkParam.Parameter.MAC_SOURCE, self.generate_random_mac_address(num_attackers))
        self.add_param_value(atkParam.Parameter.PORT_SOURCE, str(inet.RandShort()))
        self.add_param_value(atkParam.Parameter.PACKETS_PER_SECOND, 0)
        self.add_param_value(atkParam.Parameter.ATTACK_DURATION, rnd.randint(5, 30))

        # victim configuration
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(atkParam.Parameter.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(atkParam.Parameter.MAC_DESTINATION, destination_mac)
        self.add_param_value(atkParam.Parameter.VICTIM_BUFFER, rnd.randint(1000, 10000))

    def generate_attack_packets(self):
        buffer_size = 1000

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(atkParam.Parameter.NUMBER_ATTACKERS)
        if num_attackers is not None:  # user supplied atkParam.Parameter.NUMBER_ATTACKERS
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(ipClass)"))
            # Create random attackers based on user input atkParam.Parameter.NUMBER_ATTACKERS
            ip_source_list = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source_list = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply atkParam.Parameter.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source_list = self.get_param_value(atkParam.Parameter.IP_SOURCE)
            mac_source_list = self.get_param_value(atkParam.Parameter.MAC_SOURCE)
            num_attackers = len(ip_source_list)

        # Initialize parameters
        self.packets = col.deque(maxlen=buffer_size)
        # FIXME: why is port_source_list never used?
        port_source_list = self.get_param_value(atkParam.Parameter.PORT_SOURCE)
        mac_destination = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)
        ip_destination = self.get_param_value(atkParam.Parameter.IP_DESTINATION)

        most_used_ip_address = self.statistics.get_most_used_ip_address()
        pps = self.get_param_value(atkParam.Parameter.PACKETS_PER_SECOND)
        if pps == 0:
            result = self.statistics.process_db_query(
                "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + ip_destination + "';")
            if result is not None and not 0:
                pps = num_attackers * result
            else:
                result = self.statistics.process_db_query(
                    "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + most_used_ip_address + "';")
                pps = num_attackers * result

        # Calculate complement packet rates of the background traffic for each interval
        attacker_pps = pps / num_attackers
        complement_interval_attacker_pps = self.statistics.calculate_complement_packet_rates(attacker_pps)

        # Check ip.src == ip.dst
        self.ip_src_dst_equal_check(ip_source_list, ip_destination)

        port_destination = self.get_param_value(atkParam.Parameter.PORT_DESTINATION)
        if not port_destination:  # user did not define port_dest
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination +
                "' AND portCount==(SELECT MAX(portCount) FROM ip_ports WHERE portDirection='in' AND ipAddress='" +
                ip_destination + "');")
        if not port_destination:  # no port was retrieved
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM (SELECT portNumber, SUM(portCount) as occ FROM ip_ports WHERE "
                "portDirection='in' GROUP BY portNumber ORDER BY occ DESC) WHERE occ=(SELECT SUM(portCount) "
                "FROM ip_ports WHERE portDirection='in' GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT 1);")
        if not port_destination:
            port_destination = max(1, int(inet.RandShort()))

        port_destination = Util.handle_most_used_outputs(port_destination)

        # FIXME: why are attacker_port_mapping and attacker_ttl_mapping never used?
        attacker_port_mapping = {}
        attacker_ttl_mapping = {}

        # Gamma distribution parameters derived from MAWI 13.8G dataset
        alpha, loc, beta = (2.3261710235, -0.188306914406, 44.4853123884)
        # FIXME: why is gd never used?
        gd = stats.gamma.rvs(alpha, loc=loc, scale=beta, size=len(ip_source_list))

        self.path_attack_pcap = None

        timestamp_prv_reply, timestamp_confirm = 0, 0
        min_delay, max_delay = self.get_reply_delay(ip_destination)
        victim_buffer = self.get_param_value(atkParam.Parameter.VICTIM_BUFFER)

        attack_duration = self.get_param_value(atkParam.Parameter.ATTACK_DURATION)
        pkts_num = int(pps * attack_duration)

        source_win_sizes = self.statistics.get_rnd_win_size(pkts_num)

        destination_win_dist = self.statistics.get_win_distribution(ip_destination)
        if len(destination_win_dist) > 0:
            destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)
            destination_win_value = destination_win_prob_dict.random()
        else:
            destination_win_value = self.statistics.process_db_query("most_used(winSize)")

        destination_win_value = Util.handle_most_used_outputs(destination_win_value)

        # MSS that was used by IP destination in background traffic
        mss_dst = self.statistics.get_most_used_mss(ip_destination)
        if mss_dst is None:
            mss_dst = self.statistics.process_db_query("most_used(mssValue)")

        mss_dst = Util.handle_most_used_outputs(mss_dst)

        replies_count = 0
        self.total_pkt_num = 0
        # For each attacker, generate his own packets, then merge all packets
        for attacker in range(num_attackers):
            # Timestamp
            timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
            attack_ends_time = timestamp_next_pkt + attack_duration
            timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, attacker_pps)
            attacker_pkts_num = int(pkts_num / num_attackers) + rnd.randint(0, 100)
            for pkt_num in range(attacker_pkts_num):
                # Stop the attack when it exceeds the duration
                if timestamp_next_pkt > attack_ends_time:
                    break
                # Build request package
                # Select one IP address and its corresponding MAC address
                (ip_source, mac_source) = Util.get_nth_random_element(ip_source_list, mac_source_list)
                # Determine source port
                (port_source, ttl_value) = Util.get_attacker_config(ip_source_list, ip_source)
                request_ether = inet.Ether(dst=mac_destination, src=mac_source)
                request_ip = inet.IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
                # Random win size for each packet
                source_win_size = rnd.choice(source_win_sizes)
                request_tcp = inet.TCP(sport=port_source, dport=port_destination, flags='S', ack=0,
                                       window=source_win_size)

                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp_next_pkt
                # Append request
                self.packets.append(request)
                self.total_pkt_num += 1

                # Build reply package
                if replies_count <= victim_buffer:
                    reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                    reply_ip = inet.IP(src=ip_destination, dst=ip_source, flags='DF')
                    reply_tcp = inet.TCP(sport=port_destination, dport=port_source, seq=0, ack=1, flags='SA',
                                         window=destination_win_value, options=[('MSS', mss_dst)])
                    reply = (reply_ether / reply_ip / reply_tcp)

                    timestamp_reply = Util.update_timestamp(timestamp_next_pkt, attacker_pps, min_delay)
                    while timestamp_reply <= timestamp_prv_reply:
                        timestamp_reply = Util.update_timestamp(timestamp_prv_reply, attacker_pps, min_delay)
                    timestamp_prv_reply = timestamp_reply

                    reply.time = timestamp_reply
                    self.packets.append(reply)
                    replies_count += 1
                    self.total_pkt_num += 1

                attacker_pps = max(Util.get_interval_pps(complement_interval_attacker_pps, timestamp_next_pkt),
                                   (pps / num_attackers) / 2)
                timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, attacker_pps)

                # Store timestamp of first packet (for attack label)
                if self.total_pkt_num <= 2:
                    self.attack_start_utime = self.packets[0].time
                elif pkt_num % buffer_size == 0:  # every 1000 packets write them to the pcap file (append)
                    self.last_packet = self.packets[-1]
                    self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
                    self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)
                    self.packets = []

    def generate_attack_pcap(self):
        if len(self.packets) > 0:
            self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
            self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)

        # Store timestamp of last packet
        self.attack_end_utime = self.last_packet.time

        # Return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.total_pkt_num, self.path_attack_pcap
