import logging
import random as rnd

import lea
import scapy.layers.inet as inet

import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

from Attack.Parameter.Types import ParameterTypes as ParamTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class DDoSAttack(BaseAttack.BaseAttack):
    IP_SOURCE = 'ip.src'
    MAC_SOURCE = 'mac.src'
    PORT_SOURCE = 'port.src'
    IP_DESTINATION = 'ip.dst'
    MAC_DESTINATION = 'mac.dst'
    PORT_DESTINATION = 'port.dst'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'
    INJECT_AFTER_PACKET = 'inject.after-pkt'
    PACKETS_PER_SECOND = 'packets.per-second'
    NUMBER_ATTACKERS = 'attackers.count'
    ATTACK_DURATION = 'attack.duration'
    VICTIM_BUFFER = 'victim.buffer'
    LATENCY_MAX = 'latency.max'

    def __init__(self):
        """
        Creates a new instance of the DDoS attack.
        """
        # Initialize attack
        super(DDoSAttack, self).__init__("DDoS Attack", "Injects a DDoS attack'",
                                         "Resource Exhaustion")

        self.total_pkt_num = 0
        self.default_port = 0

        # Define allowed parameters and their type
        self.supported_params.update({
            self.IP_SOURCE: ParamTypes.TYPE_IP_ADDRESS,
            self.MAC_SOURCE: ParamTypes.TYPE_MAC_ADDRESS,
            self.PORT_SOURCE: ParamTypes.TYPE_PORT,
            self.IP_DESTINATION: ParamTypes.TYPE_IP_ADDRESS,
            self.MAC_DESTINATION: ParamTypes.TYPE_MAC_ADDRESS,
            self.PORT_DESTINATION: ParamTypes.TYPE_PORT,
            self.INJECT_AT_TIMESTAMP: ParamTypes.TYPE_FLOAT,
            self.INJECT_AFTER_PACKET: ParamTypes.TYPE_PACKET_POSITION,
            self.PACKETS_PER_SECOND: ParamTypes.TYPE_FLOAT,
            self.NUMBER_ATTACKERS: ParamTypes.TYPE_INTEGER_POSITIVE,
            self.ATTACK_DURATION: ParamTypes.TYPE_INTEGER_POSITIVE,
            self.VICTIM_BUFFER: ParamTypes.TYPE_INTEGER_POSITIVE,
            self.LATENCY_MAX: ParamTypes.TYPE_FLOAT
        })

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        if param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        # attacker configuration
        elif param == self.NUMBER_ATTACKERS:
            # FIXME
            value = rnd.randint(1, 16)
        elif param == self.IP_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if not num_attackers:
                return False
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            value = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
        elif param == self.MAC_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if not num_attackers:
                return False
            value = self.generate_random_mac_address(num_attackers)
        elif param == self.PORT_SOURCE:
            self.default_port = int(inet.RandShort())
            value = self.default_port
        elif param == self.PACKETS_PER_SECOND:
            value = 0.0
        elif param == self.ATTACK_DURATION:
            value = rnd.randint(5, 30)
        # victim configuration
        elif param == self.IP_DESTINATION:
            value = self.statistics.get_random_ip_address()
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if not ip_dst:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == self.VICTIM_BUFFER:
            value = rnd.randint(1000, 10000)
        elif param == self.LATENCY_MAX:
            value = 0
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)

        # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
        # if user supplied any values for those params
        ip_source_list = self.get_param_value(self.IP_SOURCE)
        mac_source_list = self.get_param_value(self.MAC_SOURCE)

        # Make sure IPs and MACs are lists
        if not isinstance(ip_source_list, list):
            ip_source_list = [ip_source_list]

        if not isinstance(mac_source_list, list):
            mac_source_list = [mac_source_list]

        if (num_attackers is not None) and (num_attackers is not 0):
            # user supplied self.NUMBER_ATTACKERS
            num_rnd_ips = num_attackers - len(ip_source_list)
            num_rnd_macs = num_attackers - len(mac_source_list)
            if num_rnd_ips:
                # The most used IP class in background traffic
                most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
                # Create random attackers based on user input self.NUMBER_ATTACKERS
                ip_source_list.extend(self.generate_random_ipv4_address(most_used_ip_class, num_rnd_ips))
            if num_rnd_macs:
                mac_source_list.extend(self.generate_random_mac_address(num_rnd_macs))

        # Generate MACs for each IP that has no corresponding MAC yet
        if (num_attackers is None) or (num_attackers is 0):
            if len(ip_source_list) > len(mac_source_list):
                mac_source_list.extend(self.generate_random_mac_address(len(ip_source_list)-len(mac_source_list)))
            num_attackers = min(len(ip_source_list), len(mac_source_list))

        # Initialize parameters
        port_source_list = self.get_param_value(self.PORT_SOURCE)
        if not isinstance(port_source_list, list):
            port_source_list = [port_source_list]
        mac_destination = self.get_param_value(self.MAC_DESTINATION)
        ip_destination = self.get_param_value(self.IP_DESTINATION)

        most_used_ip_address = self.statistics.get_most_used_ip_address()
        pps = self.get_param_value(self.PACKETS_PER_SECOND)
        if pps == 0:
            result = self.statistics.process_db_query(
                "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + ip_destination + "';")
            if result is not None and result != 0:
                pps = num_attackers * result
            else:
                result = self.statistics.process_db_query(
                    "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + most_used_ip_address + "';")
                pps = num_attackers * result

        # Calculate complement packet rates of the background traffic for each interval
        attacker_pps = pps / num_attackers
        #complement_interval_attacker_pps = self.statistics.calculate_complement_packet_rates(attacker_pps)

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source_list, ip_destination)

        port_destination = self.get_param_value(self.PORT_DESTINATION)
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

        self.path_attack_pcap = None

        victim_buffer = self.get_param_value(self.VICTIM_BUFFER)

        attack_duration = self.get_param_value(self.ATTACK_DURATION)
        pkts_num = int(pps * attack_duration)

        source_win_sizes = self.statistics.get_rnd_win_size(pkts_num)

        destination_win_dist = self.statistics.get_win_distribution(ip_destination)
        if len(destination_win_dist) > 0:
            destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)
            destination_win_value = destination_win_prob_dict.random()
        else:
            destination_win_value = self.statistics.get_most_used_win_size()

        destination_win_value = Util.handle_most_used_outputs(destination_win_value)

        # MSS that was used by IP destination in background traffic
        mss_dst = self.statistics.get_most_used_mss(ip_destination)
        if mss_dst is None:
            mss_dst = self.statistics.get_most_used_mss_value()

        mss_dst = Util.handle_most_used_outputs(mss_dst)

        # check user defined latency
        latency_limit = None
        latency_max = self.get_param_value(self.LATENCY_MAX)
        if latency_max != 0:
            latency_limit = latency_max

        # Stores triples of (timestamp, source_id, destination_id) for each timestamp.
        # Victim has id=0. Attacker tuple does not need to specify the destination because it's always the victim.
        timestamps_tuples = []
        # For each attacker(id), stores the current source-ports of SYN-packets
        # which still have to be acknowledged by the victim, as a "FIFO" for each attacker
        previous_attacker_port = []
        replies_count = 0
        already_used_pkts = 0
        sum_diff = 0

        self.attack_start_utime = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        self.timestamp_controller.set_pps(attacker_pps)
        attack_ends_time = self.timestamp_controller.get_timestamp() + attack_duration

        # For each attacker, generate his own packets, then merge all packets
        for attacker in range(num_attackers):
            # set latency limit to either the minimal latency occurring in the pcap, the default or the user specified limit
            # get minimal and maximal latency found in the pcap
            if not latency_limit:
                min_latency, max_latency = self.get_reply_latency(ip_source_list[attacker], ip_destination)
                latency_limit = min_latency

            # Initialize empty port "FIFO" for current attacker
            previous_attacker_port.append([])
            # Calculate timestamp of first SYN-packet of attacker
            timestamp_next_pkt = self.timestamp_controller.reset_timestamp()
            if attacker != 0:
                timestamp_next_pkt = rnd.uniform(timestamp_next_pkt,
                                                 self.timestamp_controller.next_timestamp(latency=latency_limit))
            # calculate each attackers packet count without exceeding the total number of attackers
            attacker_pkts_num = 0
            if already_used_pkts < pkts_num:
                random_offset = rnd.randint(0, int(pkts_num / num_attackers / 2))
                if attacker == num_attackers-1:
                    random_offset = 0
                attacker_pkts_num = int((pkts_num - already_used_pkts) / (num_attackers - attacker)) + random_offset
                already_used_pkts += attacker_pkts_num
                # each attacker gets a different pps according to his pkt count offset
                ratio = float(attacker_pkts_num) / float(pkts_num)
                attacker_pps = pps * ratio
                self.timestamp_controller.set_pps(attacker_pps)

            for pkt_num in range(attacker_pkts_num):
                # Count attack packets that exceed the attack duration
                if timestamp_next_pkt > attack_ends_time:
                    diff = timestamp_next_pkt-attack_ends_time
                    sum_diff += diff
                    self.exceeding_packets += 1

                # Add timestamp of attacker SYN-packet. Attacker tuples do not need to specify destination
                timestamps_tuples.append((timestamp_next_pkt, attacker+1))

                # Calculate timestamp of victim ACK-packet
                timestamp_reply = self.timestamp_controller.next_timestamp(latency=latency_limit)

                # Add timestamp of victim ACK-packet(victim always has id=0)
                timestamps_tuples.append((timestamp_reply, 0, attacker+1))

                # Calculate timestamp for next attacker SYN-packet
                self.timestamp_controller.set_timestamp(timestamp_next_pkt)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

        # Sort timestamp-triples according to their timestamps in ascending order
        timestamps_tuples.sort(key=lambda tmstmp: tmstmp[0])
        self.attack_start_utime = timestamps_tuples[0][0]

        # For each triple, generate packet
        for timestamp in timestamps_tuples:
            # tuple layout: [timestamp, attacker_id]

            # If current current triple is an attacker
            if timestamp[1] != 0:

                attacker_id = timestamp[1]-1
                # Build request package
                # Select one IP address and its corresponding MAC address
                ip_source = ip_source_list[attacker_id]
                mac_source = mac_source_list[attacker_id]

                # Determine source port
                (port_source, ttl_value) = Util.get_attacker_config(ip_source_list, ip_source)

                # If source ports were specified by the user, get random port from specified ports
                if port_source_list[0] != self.default_port:
                    port_source = rnd.choice(port_source_list)

                # Push port of current attacker SYN-packet into port "FIFO" of the current attacker
                # only if victim can still respond, otherwise, memory is wasted
                if replies_count <= victim_buffer:
                    previous_attacker_port[attacker_id].insert(0, port_source)

                request_ether = inet.Ether(dst=mac_destination, src=mac_source)
                request_ip = inet.IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
                # Random win size for each packet
                source_win_size = rnd.choice(source_win_sizes)
                request_tcp = inet.TCP(sport=port_source, dport=port_destination, flags='S', ack=0,
                                       window=source_win_size)

                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp[0]

                pkt = request

            # If current triple is the victim
            elif replies_count <= victim_buffer:
                # Build reply package
                attacker_id = timestamp[2]-1
                ip_source = ip_source_list[attacker_id]

                reply_ether = inet.Ether(src=mac_destination, dst=mac_source_list[attacker_id])
                reply_ip = inet.IP(src=ip_destination, dst=ip_source, flags='DF')
                # Pop port from attacker's port "FIFO" into destination port
                reply_tcp = inet.TCP(sport=port_destination, dport=previous_attacker_port[attacker_id].pop(), seq=0,
                                     ack=1, flags='SA', window=destination_win_value, options=[('MSS', mss_dst)])
                reply = (reply_ether / reply_ip / reply_tcp)

                reply.time = timestamp[0]

                pkt = reply
            else:
                continue

            result = self.add_packet(pkt, ip_source, ip_destination)

            if result == 1:
                replies_count += 1

            if self.buffer_full():
                self.flush_packets()

    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        if len(self.packets) > 0:
            self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
            self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)
            self.last_packet = self.packets[-1]

        # Store timestamp of last packet
        self.attack_end_utime = self.last_packet.time

        # Return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.total_pkt_num, self.path_attack_pcap
