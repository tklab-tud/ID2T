import logging
from random import shuffle, randint, choice, uniform

from lea import Lea

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP


class PortscanAttack(BaseAttack.BaseAttack):
    def __init__(self, statistics, pcap_file_path):
        """
        Creates a new instance of the PortscanAttack.

        :param statistics: A reference to the statistics class.
        """
        # Initialize attack
        super(PortscanAttack, self).__init__(statistics, "Portscan Attack", "Injects a nmap 'regular scan'",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params = {
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.PORT_SOURCE: ParameterTypes.TYPE_PORT,
            Param.PORT_DESTINATION: ParameterTypes.TYPE_PORT,
            Param.PORT_OPEN: ParameterTypes.TYPE_PORT,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PORT_DEST_SHUFFLE: ParameterTypes.TYPE_BOOLEAN,
            Param.PORT_ORDER_DESC: ParameterTypes.TYPE_BOOLEAN,
            Param.IP_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.PORT_SOURCE_RANDOM: ParameterTypes.TYPE_BOOLEAN}

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list):
            most_used_ip_address = most_used_ip_address[0]

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.IP_SOURCE_RANDOMIZE, 'False')
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        random_ip_address = self.statistics.get_random_ip_address()
        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        self.add_param_value(Param.MAC_DESTINATION, self.statistics.get_mac_address(random_ip_address))

        self.add_param_value(Param.PORT_DESTINATION, '0-1023,1720,1900,8080')
        self.add_param_value(Param.PORT_OPEN, '8080,9232,9233')
        self.add_param_value(Param.PORT_DEST_SHUFFLE, 'False')
        self.add_param_value(Param.PORT_ORDER_DESC, 'False')

        self.add_param_value(Param.PORT_SOURCE, '8542')
        self.add_param_value(Param.PORT_SOURCE_RANDOM, 'False')

        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))

    def get_packets(self):
        def update_timestamp(timestamp, pps, maxdelay):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            return timestamp + uniform(0.1 / pps, maxdelay)

        # Determine ports
        dest_ports = self.get_param_value(Param.PORT_DESTINATION)
        if self.get_param_value(Param.PORT_ORDER_DESC):
            dest_ports.reverse()
        elif self.get_param_value(Param.PORT_DEST_SHUFFLE):
            shuffle(dest_ports)
        if self.get_param_value(Param.PORT_SOURCE_RANDOM):
            sport = randint(0, 65535)
        else:
            sport = self.get_param_value(Param.PORT_SOURCE)

        # Get TTL distribution
        # keys = list(self.statistics.get_ttl_distribution().vals()
        # values = list(self.statistics.get_ttl_distribution().pmf())
        # TTL_samples = numpy.random.choice(keys, size=len(dest_ports), replace=True, dport=values)
        ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        self.attack_start_utime = timestamp_next_pkt  # store start time of attack
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 30, 5 / pps: 15, 10 / pps: 3})
        maxdelay = randomdelay.random()

        # Initialize parameters
        packets = []
        ip_source = self.get_param_value(Param.IP_SOURCE)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)

        # MSS (Maximum Segment Size) for Ethernet. Allowed values [536,1500]
        mss = self.statistics.get_mss(ip_destination)

        for dport in dest_ports:
            # Parameters changing each iteration
            if self.get_param_value(Param.IP_SOURCE_RANDOMIZE) and isinstance(ip_source, list):
                ip_source = choice(ip_source)

            # 1) Build request package
            request_ether = Ether(src=mac_source, dst=mac_destination)
            request_ip = IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
            request_tcp = TCP(sport=sport, dport=dport)
            request = (request_ether / request_ip / request_tcp)
            # first packet uses timestamp provided by attack parameter Param.INJECT_AT_TIMESTAMP
            if len(packets) > 0:
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
            request.time = timestamp_next_pkt
            packets.append(request)

            # 2) Build reply package
            reply_ether = Ether(src=mac_destination, dst=mac_source)
            reply_ip = IP(src=ip_destination, dst=ip_source, flags='DF')

            if dport in self.get_param_value(Param.PORT_OPEN):  # destination port is OPEN
                # target answers
                if mss is None:
                    reply_tcp = TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=29200)
                else:
                    reply_tcp = TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=29200,
                                    options=[('MSS', mss)])
                # reply_tcp.time = time_sec_start + random.uniform(0.00005, 0.00013)
                reply = (reply_ether / reply_ip / reply_tcp)
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
                reply.time = timestamp_next_pkt
                packets.append(reply)

                # requester confirms
                confirm_ether = request_ether
                confirm_ip = request_ip
                confirm_tcp = TCP(sport=sport, dport=dport, seq=1, window=0, flags='R')
                reply = (confirm_ether / confirm_ip / confirm_tcp)
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
                reply.time = timestamp_next_pkt
                packets.append(reply)

                # else:  # destination port is NOT OPEN -> no reply is sent by target
                #     reply_tcp = TCP(sport=dport, dport=sport, flags='RA', seq=1, ack=1, window=0)
                #     # reply_tcp.time = time_sec_start + random.uniform(0.00005, 0.00013)
                #     reply = (reply_ether / reply_ip / reply_tcp)
                #     timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
                #     reply.time = timestamp_next_pkt
                #     packets.append(reply)

        # store end time of attack
        self.attack_end_utime = reply.time

        # return packets sorted by packet time_sec_start
        return sorted(packets, key=lambda pkt: pkt.time)
