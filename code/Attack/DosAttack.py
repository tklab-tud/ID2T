import logging
from random import randint, choice, uniform
from lea import Lea
from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP, RandShort
from collections import deque


class DosAttack(BaseAttack.BaseAttack):
    def __init__(self, statistics, pcap_file_path):
        """
        Creates a new instance of the PortscanAttack.

        :param statistics: A reference to the statistics class.
        """
        # Initialize attack
        super(DosAttack, self).__init__(statistics, "DoS Attack", "Injects a DoS attack'",
                                        "Resource Exhaustion")

        # Define allowed parameters and their type
        self.supported_params = {
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.PORT_SOURCE: ParameterTypes.TYPE_PORT,
            Param.PORT_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.PORT_DESTINATION: ParameterTypes.TYPE_PORT,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.PACKETS_LIMIT: ParameterTypes.TYPE_INTEGER_POSITIVE
        }

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list): most_used_ip_address = most_used_ip_address[0]
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))
        # sender configuration
        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))
        self.add_param_value(Param.PORT_SOURCE, str(RandShort()))
        self.add_param_value(Param.PORT_SOURCE_RANDOMIZE, False)
        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        # receiver configuration
        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        self.add_param_value(Param.MAC_DESTINATION, self.statistics.get_mac_address(random_ip_address))
        self.add_param_value(Param.PORT_DESTINATION, '80')
        self.add_param_value(Param.PACKETS_LIMIT, randint(10, 1000))

    def get_packets(self):
        def update_timestamp(timestamp, pps, maxdelay):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            return timestamp + uniform(0.1 / pps, maxdelay)

        def get_nth_random_element(*element_list):
            """

            :param element_list:
            :return:
            """
            range_max = min([len(x) for x in element_list])
            if range_max > 0: range_max -= 1
            n = randint(0, range_max)
            return tuple(x[n] for x in element_list)

        BUFFER_SIZE_PACKETS = self.get_param_value(Param.PACKETS_LIMIT)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 30, 5 / pps: 15, 10 / pps: 3})

        # Initialize parameters
        packets = deque(maxlen=BUFFER_SIZE_PACKETS)
        # packets = []
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        ip_source = self.get_param_value(Param.IP_SOURCE)
        port_source = self.get_param_value(Param.PORT_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        port_destination = self.get_param_value(Param.PORT_DESTINATION)

        # Set TTL based on TTL distribution of IP address
        ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(ttl_dist) > 0:
            ttl_prob_dict = Lea.fromValFreqsDict(ttl_dist)
            ttl_value = ttl_prob_dict.random()
        else:
            ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

        # MSS (Maximum Segment Size) for Ethernet. Allowed values [536,1500]
        mss = self.statistics.get_mss(ip_destination)

        for pkt_num in range(self.get_param_value(Param.PACKETS_LIMIT)):
            # Determine source port
            if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
                cur_port_source = RandShort()
            elif isinstance(port_source, list):
                cur_port_source = choice(port_source)
            else:
                cur_port_source = port_source

            maxdelay = randomdelay.random()

            request_ether = Ether(dst=mac_destination, src=mac_source)
            request_ip = IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
            request_tcp = TCP(sport=cur_port_source, dport=port_destination, flags='S', ack=0)

            request = (request_ether / request_ip / request_tcp)
            request.time = timestamp_next_pkt
            packets.append(request)

            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)

        self.attack_end_utime = request.time

        # return packets sorted by packet time_sec_start
        return sorted(packets, key=lambda pkt: pkt.time)
