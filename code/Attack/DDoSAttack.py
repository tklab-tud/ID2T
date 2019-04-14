import collections as col
import logging
import random as rnd

import lea
import scapy.layers.inet as inet

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
        self.default_port = 0

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
            atkParam.Parameter.VICTIM_BUFFER: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE,
            atkParam.Parameter.BANDWIDTH_MAX: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.BANDWIDTH_MIN_LOCAL: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.BANDWIDTH_MIN_PUBLIC: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.LATENCY_MAX: atkParam.ParameterTypes.TYPE_FLOAT
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
        most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())

        self.add_param_value(atkParam.Parameter.IP_SOURCE,
                             self.generate_random_ipv4_address(most_used_ip_class, num_attackers))
        self.add_param_value(atkParam.Parameter.MAC_SOURCE, self.generate_random_mac_address(num_attackers))
        self.default_port = int(inet.RandShort())
        self.add_param_value(atkParam.Parameter.PORT_SOURCE, self.default_port)
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

        self.add_param_value(atkParam.Parameter.BANDWIDTH_MAX, 0)
        self.add_param_value(atkParam.Parameter.BANDWIDTH_MIN_LOCAL, 0)
        self.add_param_value(atkParam.Parameter.BANDWIDTH_MIN_PUBLIC, 0)
        self.add_param_value(atkParam.Parameter.LATENCY_MAX, 0)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        buffer_size = 1000

        # Determine source IP and MAC address
        num_attackers = self.get_param_value(atkParam.Parameter.NUMBER_ATTACKERS)
        if (num_attackers is not None) and (num_attackers is not 0):
            # user supplied atkParam.Parameter.NUMBER_ATTACKERS
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            # Create random attackers based on user input atkParam.Parameter.NUMBER_ATTACKERS
            ip_source_list = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)
            mac_source_list = self.generate_random_mac_address(num_attackers)
        else:  # user did not supply atkParam.Parameter.NUMBER_ATTACKS
            # use default values for IP_SOURCE/MAC_SOURCE or overwritten values
            # if user supplied any values for those params
            ip_source_list = self.get_param_value(atkParam.Parameter.IP_SOURCE)
            mac_source_list = self.get_param_value(atkParam.Parameter.MAC_SOURCE)

        # Make sure IPs and MACs are lists
        if not isinstance(ip_source_list, list):
            ip_source_list = [ip_source_list]

        if not isinstance(mac_source_list, list):
            mac_source_list = [mac_source_list]

        # Generate MACs for each IP that has no corresponding MAC yet
        if (num_attackers is None) or (num_attackers is 0):
            if len(ip_source_list) > len(mac_source_list):
                mac_source_list.extend(self.generate_random_mac_address(len(ip_source_list)-len(mac_source_list)))
            num_attackers = min(len(ip_source_list), len(mac_source_list))

        # Initialize parameters
        self.packets = col.deque(maxlen=buffer_size)

        port_source_list = self.get_param_value(atkParam.Parameter.PORT_SOURCE)
        if not isinstance(port_source_list, list):
            port_source_list = [port_source_list]
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
        #complement_interval_attacker_pps = self.statistics.calculate_complement_packet_rates(attacker_pps)

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source_list, ip_destination)

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

        self.path_attack_pcap = None

        victim_buffer = self.get_param_value(atkParam.Parameter.VICTIM_BUFFER)

        attack_duration = self.get_param_value(atkParam.Parameter.ATTACK_DURATION)
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

        # get user defined bandwidth
        bandwidth_max = self.get_param_value(atkParam.Parameter.BANDWIDTH_MAX)
        bandwidth_min_local = self.get_param_value(atkParam.Parameter.BANDWIDTH_MIN_LOCAL)
        bandwidth_min_public = self.get_param_value(atkParam.Parameter.BANDWIDTH_MIN_PUBLIC)

        # check user defined latency
        latency_limit = None
        latency_max = self.get_param_value(atkParam.Parameter.LATENCY_MAX)
        if latency_max != 0:
            latency_limit = latency_max

        # Stores triples of (timestamp, source_id, destination_id) for each timestamp.
        # Victim has id=0. Attacker tuple does not need to specify the destination because it's always the victim.
        timestamps_tuples = []
        # For each attacker(id), stores the current source-ports of SYN-packets
        # which still have to be acknowledged by the victim, as a "FIFO" for each attacker
        previous_attacker_port = []
        replies_count = 0
        self.total_pkt_num = 0
        already_used_pkts = 0
        sum_diff = 0

        self.attack_start_utime = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
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

        sent_bytes = 0
        previous_interval = 0
        full_interval = None
        reply = None

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
            else:

                # Build reply package
                if replies_count <= victim_buffer:
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

            bytes = len(pkt)

            remaining_bytes, current_interval = self.get_remaining_bandwidth(pkt.time, ip_source, ip_destination,
                                                                             bandwidth_max, bandwidth_min_local,
                                                                             bandwidth_min_public)
            if previous_interval != current_interval:
                sent_bytes = 0

            previous_interval = current_interval

            if current_interval != full_interval:
                remaining_bytes *= 1000
                remaining_bytes -= sent_bytes

                if remaining_bytes >= bytes:
                    sent_bytes += bytes
                    self.packets.append(pkt)
                    self.total_pkt_num += 1
                    if pkt == reply:
                        replies_count += 1
                else:
                    print("Warning: generated attack packets exceeded bandwidth. Packets in interval {} "
                          "were omitted.".format(current_interval))
                    full_interval = current_interval

            # every 1000 packets write them to the pcap file (append)
            if (self.total_pkt_num > 0) and (self.total_pkt_num % buffer_size == 0) and (len(self.packets) > 0):
                self.last_packet = self.packets[-1]
                self.attack_end_utime = self.last_packet.time
                self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
                self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)
                self.packets = []

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
