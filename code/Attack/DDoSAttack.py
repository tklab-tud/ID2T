import logging
from random import randint, uniform

#Aidmar
import numpy as np

from lea import Lea
from scipy.stats import gamma

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP, RandShort
from collections import deque


class DDoSAttack(BaseAttack.BaseAttack):
    # Aidmar - Metasploit DoS default PPS
    maxDefaultPPS = 1400
    minDefaultPPS = 400
    # TO-DO: justify the values
    minDefaultBuffer = 1000
    maxDefaultBuffer = 2000

    def __init__(self, statistics, pcap_file_path):
        """
        Creates a new instance of the DDoS attack.

        :param statistics: A reference to the statistics class.
        """
        # Initialize attack
        super(DDoSAttack, self).__init__(statistics, "DDoS Attack", "Injects a DDoS attack'",
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
            # Aidmar - use attack duration instead
            #Param.PACKETS_LIMIT: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.NUMBER_ATTACKERS: ParameterTypes.TYPE_INTEGER_POSITIVE,
            # Aidmar
            Param.ATTACK_DURATION: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.VICTIM_BUFFER: ParameterTypes.TYPE_INTEGER_POSITIVE
        }

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)

        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        # attacker configuration
        num_attackers = randint(1, 16)
        # Aidmar
        # The most used IP class in background traffic
        most_used_ip_class = self.statistics.process_db_query("most_used(ipClass)")

        self.add_param_value(Param.IP_SOURCE, self.generate_random_ipv4_address(most_used_ip_class, num_attackers))
        self.add_param_value(Param.MAC_SOURCE, self.generate_random_mac_address(num_attackers))
        self.add_param_value(Param.PORT_SOURCE, str(RandShort()))
        # Aidmar
        #self.add_param_value(Param.PACKETS_PER_SECOND, randint(1, 64))
        self.add_param_value(Param.PACKETS_PER_SECOND, randint(self.minDefaultPPS, self.maxDefaultPPS))
        self.add_param_value(Param.ATTACK_DURATION, randint(5,30))

        # victim configuration
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)

        # Aidmar
        self.add_param_value(Param.VICTIM_BUFFER, randint(self.minDefaultBuffer,self.maxDefaultBuffer))
        # Aidmar - comment out
        """
        port_destination = self.statistics.process_db_query(
            "SELECT portNumber FROM ip_ports WHERE portDirection='in' ORDER BY RANDOM() LIMIT 1;")
        if port_destination is None:
            port_destination = str(RandShort())
        self.add_param_value(Param.PORT_DESTINATION, port_destination)
        """
        # Aidmar
        #self.add_param_value(Param.PACKETS_LIMIT, randint(1000, 5000))

    def generate_attack_pcap(self):
        def update_timestamp(timestamp, pps, maxdelay):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            return timestamp + uniform(0.1 / pps, maxdelay)

        def get_nth_random_element(*element_list):
            """
            Returns the n-th element of every list from an arbitrary number of given lists.
            For example, list1 contains IP addresses, list 2 contains MAC addresses. Use of this function ensures that
            the n-th IP address uses always the n-th MAC address.
            :param element_list: An arbitrary number of lists.
            :return: A tuple of the n-th element of every list.
            """
            range_max = min([len(x) for x in element_list])
            if range_max > 0: range_max -= 1
            n = randint(0, range_max)
            return tuple(x[n] for x in element_list)

        def index_increment(number: int, max: int):
            if number + 1 < max:
                return number + 1
            else:
                return 0

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
            # Create random attackers based on user input Param.NUMBER_ATTACKERS
            # Aidmar
            # The most used IP class in background traffic
            most_used_ip_class = self.statistics.process_db_query("most_used(ipClass)")

            ip_source_list = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source_list = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply Param.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source_list = self.get_param_value(Param.IP_SOURCE)
            mac_source_list = self.get_param_value(Param.MAC_SOURCE)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 30, 5 / pps: 15, 10 / pps: 3})

        # Initialize parameters
        packets = deque(maxlen=BUFFER_SIZE)
        port_source_list = self.get_param_value(Param.PORT_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        port_destination = self.get_param_value(Param.PORT_DESTINATION)

        # Aidmar
        if not port_destination:  # user did not define port_dest
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination + "' ORDER BY portCount DESC LIMIT 1;")
        if not port_destination:  # no port was retrieved
            port_destination = self.statistics.process_db_query(
                "SELECT portNumber FROM ip_ports WHERE portDirection='in' GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT 1;")
        if not port_destination:
            port_destination = max(1, str(RandShort()))

        attacker_port_mapping = {}
        attacker_ttl_mapping = {}

        # Gamma distribution parameters derived from MAWI 13.8G dataset
        alpha, loc, beta = (2.3261710235, -0.188306914406, 44.4853123884)
        gd = gamma.rvs(alpha, loc=loc, scale=beta, size=len(ip_source_list))

        path_attack_pcap = None

        # Aidmar
        replies = []
        replyDelay = self.get_reply_delay(ip_destination)
        victim_buffer = self.get_param_value(Param.VICTIM_BUFFER)

        # Aidmar
        #for pkt_num in range(self.get_param_value(Param.PACKETS_LIMIT)):
        attack_duration = self.get_param_value(Param.ATTACK_DURATION)
        pkts_num = int(pps * attack_duration)
        for pkt_num in range(pkts_num):
            # Build request package
            # Select one IP address and its corresponding MAC address
            (ip_source, mac_source) = get_nth_random_element(ip_source_list, mac_source_list)
            # Determine source port
            (port_source, ttl_value) = get_attacker_config(ip_source)
            maxdelay = randomdelay.random()
            request_ether = Ether(dst=mac_destination, src=mac_source)

            # TO-DO: move it out of the loop. Aidmar - check ip.src == ip.dst
            if ip_source == ip_destination:
                print("\nERROR: Invalid IP addresses; source IP is the same as destination IP: " + ip_source + ".")
                import sys
                sys.exit(0)

            request_ip = IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
            # Aidmar - random win size for each packet
            # request_tcp = TCP(sport=port_source, dport=port_destination, flags='S', ack=0)
            # TO-DO: move it out of the loop
            win_size = self.statistics.process_db_query(
                "SELECT winSize FROM tcp_syn_win ORDER BY RANDOM() LIMIT 1;")
            request_tcp = TCP(sport=port_source, dport=port_destination, flags='S', ack=0, window=win_size)

            request = (request_ether / request_ip / request_tcp)
            request.time = timestamp_next_pkt

            # Build reply package
            # Aidmar
            if len(replies) <= victim_buffer:
                reply_ether = Ether(src=mac_destination, dst=mac_source)
                reply_ip = IP(src=ip_destination, dst=ip_source, flags='DF')
                reply_tcp = TCP(sport=port_destination, dport=port_source, seq=0, ack=1, flags='SA', window=29200)  # ,
                # options=[('MSS', mss_dst)])
                reply = (reply_ether / reply_ip / reply_tcp)

                # TO-DO: justify the values
                timestamp_reply = timestamp_next_pkt + uniform(replyDelay, 2 * replyDelay)

                if len(replies) > 0:
                    last_reply_timestamp = replies[-1].time
                    while timestamp_reply <= last_reply_timestamp:
                        timestamp_reply = timestamp_reply + uniform(replyDelay, 2 * replyDelay)

                reply.time = timestamp_reply
                replies.append(reply)

            # Aidmar
            # Append reply
            if replies:
                while timestamp_next_pkt >= replies[0].time:
                    packets.append(replies[0])
                    replies.remove(replies[0])
                    if len(replies) == 0:
                        break

            # Append request
            packets.append(request)

            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)

            # Store timestamp of first packet (for attack label)
            if pkt_num == 1:
                self.attack_start_utime = packets[0].time
            elif pkt_num % BUFFER_SIZE == 0: # every 1000 packets write them to the pcap file (append)
                last_packet = packets[-1]
                packets = sorted(packets, key=lambda pkt: pkt.time)
                path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                packets = []

            # Requests are sent all, send all replies
            if pkt_num == pkts_num-1:
                for reply in replies:
                    packets.append(reply)

        if len(packets) > 0:
            packets = sorted(packets, key=lambda pkt: pkt.time)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)

        # Store timestamp of last packet
        self.attack_end_utime = last_packet.time

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return pkt_num + 1, path_attack_pcap