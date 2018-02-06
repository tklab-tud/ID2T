import logging

from random import randint, choice
from lea import Lea
from collections import deque
from scipy.stats import gamma
from scapy.layers.inet import IP, Ether, TCP, RandShort

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
from ID2TLib.Utility import update_timestamp, get_interval_pps, get_nth_random_element, index_increment, \
    handle_most_used_outputs

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

        # Define allowed parameters and their type
        self.supported_params = {
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.PORT_SOURCE: ParameterTypes.TYPE_PORT,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.PORT_DESTINATION: ParameterTypes.TYPE_PORT,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.NUMBER_ATTACKERS: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.ATTACK_DURATION: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.VICTIM_BUFFER: ParameterTypes.TYPE_INTEGER_POSITIVE
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
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        # attacker configuration
        num_attackers = randint(1, 16)
        # The most used IP class in background traffic
        most_used_ip_class = self.statistics.process_db_query("most_used(ipClass)")
        if isinstance(most_used_ip_class, list):
            most_used_ip_class.sort()
            most_used_ip_class = most_used_ip_class[0]

        self.add_param_value(Param.IP_SOURCE, self.generate_random_ipv4_address(most_used_ip_class, num_attackers))
        self.add_param_value(Param.MAC_SOURCE, self.generate_random_mac_address(num_attackers))
        self.add_param_value(Param.PORT_SOURCE, str(RandShort()))
        self.add_param_value(Param.PACKETS_PER_SECOND, 0)
        self.add_param_value(Param.ATTACK_DURATION, randint(5,30))

        # victim configuration
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)
        self.add_param_value(Param.VICTIM_BUFFER, randint(1000,10000))

    def generate_attack_pcap(self):
        def get_attacker_config(ipAddress: str):
            """
            Returns the attacker configuration depending on the IP address, this includes the port for the next
            attacking packet and the previously used (fixed) TTL value.
            :param ipAddress: The IP address of the attacker
            :return: A tuple consisting of (port, ttlValue)
            """
            # Determine port
            port = attacker_port_mapping.get(ipAddress)
            if port is not None:  # use next port
                next_port = attacker_port_mapping.get(ipAddress) + 1
                if next_port > (2 ** 16 - 1):
                    next_port = 1
            else:  # generate starting port
                next_port = RandShort()
            attacker_port_mapping[ipAddress] = next_port
            # Determine TTL value
            ttl = attacker_ttl_mapping.get(ipAddress)
            if ttl is None:  # determine TTL value
                is_invalid = True
                pos = ip_source_list.index(ipAddress)
                pos_max = len(gd)
                while is_invalid:
                    ttl = int(round(gd[pos]))
                    if 0 < ttl < 256:  # validity check
                        is_invalid = False
                    else:
                        pos = index_increment(pos, pos_max)
                attacker_ttl_mapping[ipAddress] = ttl
            # return port and TTL
            return next_port, ttl
        BUFFER_SIZE = 1000

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(Param.NUMBER_ATTACKERS)
        if num_attackers is not None:  # user supplied Param.NUMBER_ATTACKERS
            # The most used IP class in background traffic
            most_used_ip_class = handle_most_used_outputs(self.statistics.process_db_query("most_used(ipClass)"))
            # Create random attackers based on user input Param.NUMBER_ATTACKERS
            ip_source_list = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source_list = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply Param.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source_list = self.get_param_value(Param.IP_SOURCE)
            mac_source_list = self.get_param_value(Param.MAC_SOURCE)
            num_attackers = len(ip_source_list)

        # Initialize parameters
        packets = deque(maxlen=BUFFER_SIZE)
        port_source_list = self.get_param_value(Param.PORT_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)

        most_used_ip_address = self.statistics.get_most_used_ip_address()
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        if pps == 0:
            result = self.statistics.process_db_query("SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='"+ip_destination+"';")
            if result is not None and not 0:
                pps = num_attackers * result
            else:
                result = self.statistics.process_db_query("SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='"+most_used_ip_address+"';")
                pps = num_attackers * result

        # Calculate complement packet rates of the background traffic for each interval
        attacker_pps = pps / num_attackers
        complement_interval_attacker_pps = self.statistics.calculate_complement_packet_rates(attacker_pps)

        # Check ip.src == ip.dst
        self.ip_src_dst_equal_check(ip_source_list, ip_destination)

        port_destination = self.get_param_value(Param.PORT_DESTINATION)
        if not port_destination:  # user did not define port_dest
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination + "' AND portCount==(SELECT MAX(portCount) FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination + "');")
        if not port_destination:  # no port was retrieved
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM (SELECT portNumber, SUM(portCount) as occ FROM ip_ports WHERE portDirection='in' GROUP BY portNumber ORDER BY occ DESC) WHERE occ=(SELECT SUM(portCount) FROM ip_ports WHERE portDirection='in' GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT 1);")
        if not port_destination:
            port_destination = max(1, str(RandShort()))

        port_destination = handle_most_used_outputs(port_destination)

        attacker_port_mapping = {}
        attacker_ttl_mapping = {}

        # Gamma distribution parameters derived from MAWI 13.8G dataset
        alpha, loc, beta = (2.3261710235, -0.188306914406, 44.4853123884)
        gd = gamma.rvs(alpha, loc=loc, scale=beta, size=len(ip_source_list))

        path_attack_pcap = None

        timestamp_prv_reply, timestamp_confirm = 0, 0
        minDelay, maxDelay = self.get_reply_delay(ip_destination)
        victim_buffer = self.get_param_value(Param.VICTIM_BUFFER)

        attack_duration = self.get_param_value(Param.ATTACK_DURATION)
        pkts_num = int(pps * attack_duration)

        source_win_sizes = self.statistics.process_db_query(
                "SELECT DISTINCT winSize FROM tcp_win ORDER BY RANDOM() LIMIT "+str(pkts_num)+";")

        destination_win_dist = self.statistics.get_win_distribution(ip_destination)
        if len(destination_win_dist) > 0:
            destination_win_prob_dict = Lea.fromValFreqsDict(destination_win_dist)
            destination_win_value = destination_win_prob_dict.random()
        else:
            destination_win_value = self.statistics.process_db_query("most_used(winSize)")

        destination_win_value = handle_most_used_outputs(destination_win_value)

        # MSS that was used by IP destination in background traffic
        mss_dst = self.statistics.get_most_used_mss(ip_destination)
        if mss_dst is None:
            mss_dst = self.statistics.process_db_query("most_used(mssValue)")

        mss_dst = handle_most_used_outputs(mss_dst)

        replies_count = 0
        total_pkt_num = 0
        # For each attacker, generate his own packets, then merge all packets
        for attacker in range(num_attackers):
            # Timestamp
            timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
            attack_ends_time = timestamp_next_pkt + attack_duration
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, attacker_pps)
            attacker_pkts_num = int(pkts_num / num_attackers) + randint(0,100)
            for pkt_num in range(attacker_pkts_num):
                # Stop the attack when it exceeds the duration
                if timestamp_next_pkt > attack_ends_time:
                    break
                # Build request package
                # Select one IP address and its corresponding MAC address
                (ip_source, mac_source) = get_nth_random_element(ip_source_list, mac_source_list)
                # Determine source port
                (port_source, ttl_value) = get_attacker_config(ip_source)
                request_ether = Ether(dst=mac_destination, src=mac_source)
                request_ip = IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
                # Random win size for each packet
                source_win_size = choice(source_win_sizes)
                request_tcp = TCP(sport=port_source, dport=port_destination, flags='S', ack=0, window=source_win_size)

                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp_next_pkt
                # Append request
                packets.append(request)
                total_pkt_num +=1

                # Build reply package
                if replies_count <= victim_buffer:
                    reply_ether = Ether(src=mac_destination, dst=mac_source)
                    reply_ip = IP(src=ip_destination, dst=ip_source, flags='DF')
                    reply_tcp = TCP(sport=port_destination, dport=port_source, seq=0, ack=1, flags='SA', window=destination_win_value,options=[('MSS', mss_dst)])
                    reply = (reply_ether / reply_ip / reply_tcp)

                    timestamp_reply = update_timestamp(timestamp_next_pkt, attacker_pps, minDelay)
                    while (timestamp_reply <= timestamp_prv_reply):
                        timestamp_reply = update_timestamp(timestamp_prv_reply, attacker_pps, minDelay)
                    timestamp_prv_reply = timestamp_reply

                    reply.time = timestamp_reply
                    packets.append(reply)
                    replies_count+=1
                    total_pkt_num += 1

                attacker_pps = max(get_interval_pps(complement_interval_attacker_pps, timestamp_next_pkt), (pps / num_attackers) / 2)
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, attacker_pps)

                # Store timestamp of first packet (for attack label)
                if total_pkt_num <= 2 :
                    self.attack_start_utime = packets[0].time
                elif pkt_num % BUFFER_SIZE == 0: # every 1000 packets write them to the pcap file (append)
                    last_packet = packets[-1]
                    packets = sorted(packets, key=lambda pkt: pkt.time)
                    path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                    packets = []

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # Store timestamp of last packet
        self.attack_end_utime = last_packet.time

        # Return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return total_pkt_num , path_attack_pcap