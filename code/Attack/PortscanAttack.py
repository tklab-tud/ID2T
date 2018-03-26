import logging
import random as rnd

import lea
import scapy.layers.inet as inet

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class PortscanAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the PortscanAttack.
        This Attack injects TCP Syn Requests into the pcap and simulate related response to the output pcap.
        """
        # Initialize attack
        super(PortscanAttack, self).__init__("Portscan Attack", "Injects a nmap 'regular scan'",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.PORT_SOURCE: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.PORT_DESTINATION: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.PORT_OPEN: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.MAC_DESTINATION: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.PORT_DEST_SHUFFLE: atkParam.ParameterTypes.TYPE_BOOLEAN,
            atkParam.Parameter.PORT_DEST_ORDER_DESC: atkParam.ParameterTypes.TYPE_BOOLEAN,
            atkParam.Parameter.IP_SOURCE_RANDOMIZE: atkParam.ParameterTypes.TYPE_BOOLEAN,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.PORT_SOURCE_RANDOMIZE: atkParam.ParameterTypes.TYPE_BOOLEAN
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

        self.add_param_value(atkParam.Parameter.IP_SOURCE, most_used_ip_address)
        self.add_param_value(atkParam.Parameter.IP_SOURCE_RANDOMIZE, 'False')
        self.add_param_value(atkParam.Parameter.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        random_ip_address = self.statistics.get_random_ip_address()
        # ip.dst should be valid and not equal to ip.src
        while not self.is_valid_ip_address(random_ip_address) or random_ip_address == most_used_ip_address:
            random_ip_address = self.statistics.get_random_ip_address()

        self.add_param_value(atkParam.Parameter.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(atkParam.Parameter.MAC_DESTINATION, destination_mac)
        self.add_param_value(atkParam.Parameter.PORT_DESTINATION, self.get_ports_from_nmap_service_dst(1000))
        self.add_param_value(atkParam.Parameter.PORT_OPEN, '1')
        self.add_param_value(atkParam.Parameter.PORT_DEST_SHUFFLE, 'False')
        self.add_param_value(atkParam.Parameter.PORT_DEST_ORDER_DESC, 'False')
        self.add_param_value(atkParam.Parameter.PORT_SOURCE, rnd.randint(1024, 65535))
        self.add_param_value(atkParam.Parameter.PORT_SOURCE_RANDOMIZE, 'False')
        self.add_param_value(atkParam.Parameter.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(atkParam.Parameter.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        mac_source = self.get_param_value(atkParam.Parameter.MAC_SOURCE)
        mac_destination = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)
        pps = self.get_param_value(atkParam.Parameter.PACKETS_PER_SECOND)

        # Calculate complement packet rates of the background traffic for each interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Determine ports
        dest_ports = self.get_param_value(atkParam.Parameter.PORT_DESTINATION)
        if self.get_param_value(atkParam.Parameter.PORT_DEST_ORDER_DESC):
            dest_ports.reverse()
        elif self.get_param_value(atkParam.Parameter.PORT_DEST_SHUFFLE):
            rnd.shuffle(dest_ports)
        if self.get_param_value(atkParam.Parameter.PORT_SOURCE_RANDOMIZE):
            # FIXME: why is sport never used?
            sport = rnd.randint(1, 65535)
        else:
            sport = self.get_param_value(atkParam.Parameter.PORT_SOURCE)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt
        timestamp_prv_reply, timestamp_confirm = 0, 0

        # Initialize parameters
        self.packets = []
        ip_source = self.get_param_value(atkParam.Parameter.IP_SOURCE)
        if isinstance(ip_source, list):
            ip_source = ip_source[0]
        ip_destination = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
        if isinstance(ip_destination, list):
            ip_destination = ip_destination[0]

        # Check ip.src == ip.dst
        self.ip_src_dst_equal_check(ip_source, ip_destination)

        # Select open ports
        ports_open = self.get_param_value(atkParam.Parameter.PORT_OPEN)
        if ports_open == 1:  # user did not specify open ports
            # the ports that were already used by ip.dst (direction in) in the background traffic are open ports
            ports_used_by_ip_dst = self.statistics.process_db_query(
                "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination + "'")
            if ports_used_by_ip_dst:
                ports_open = ports_used_by_ip_dst
            else:  # if no ports were retrieved from database
                # Take open ports from nmap-service file
                # ports_temp = self.get_ports_from_nmap_service_dst(100)
                # ports_open = ports_temp[0:rnd.randint(1,10)]
                # OR take open ports from the most used ports in traffic statistics
                ports_open = self.statistics.process_db_query(
                    "SELECT portNumber FROM ip_ports GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT " + str(
                        rnd.randint(1, 10)))
        # in case of one open port, convert ports_open to array
        if not isinstance(ports_open, list):
            ports_open = [ports_open]

        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        source_mss_dist = self.statistics.get_mss_distribution(ip_source)
        if len(source_mss_dist) > 0:
            source_mss_prob_dict = lea.Lea.fromValFreqsDict(source_mss_dist)
            source_mss_value = source_mss_prob_dict.random()
        else:
            source_mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())
        destination_mss_dist = self.statistics.get_mss_distribution(ip_destination)
        if len(destination_mss_dist) > 0:
            destination_mss_prob_dict = lea.Lea.fromValFreqsDict(destination_mss_dist)
            destination_mss_value = destination_mss_prob_dict.random()
        else:
            destination_mss_value = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())

        # Set TTL based on TTL distribution of IP address
        source_ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(source_ttl_dist) > 0:
            source_ttl_prob_dict = lea.Lea.fromValFreqsDict(source_ttl_dist)
            source_ttl_value = source_ttl_prob_dict.random()
        else:
            source_ttl_value = Util.handle_most_used_outputs(self.statistics.get_most_used_ttl_value())
        destination_ttl_dist = self.statistics.get_ttl_distribution(ip_destination)
        if len(destination_ttl_dist) > 0:
            destination_ttl_prob_dict = lea.Lea.fromValFreqsDict(destination_ttl_dist)
            destination_ttl_value = destination_ttl_prob_dict.random()
        else:
            destination_ttl_value = Util.handle_most_used_outputs(self.statistics.get_most_used_ttl_value())

        # Set Window Size based on Window Size distribution of IP address
        source_win_dist = self.statistics.get_win_distribution(ip_source)
        if len(source_win_dist) > 0:
            source_win_prob_dict = lea.Lea.fromValFreqsDict(source_win_dist)
            source_win_value = source_win_prob_dict.random()
        else:
            source_win_value = Util.handle_most_used_outputs(self.statistics.get_most_used_win_size())
        destination_win_dist = self.statistics.get_win_distribution(ip_destination)
        if len(destination_win_dist) > 0:
            destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)
            destination_win_value = destination_win_prob_dict.random()
        else:
            destination_win_value = Util.handle_most_used_outputs(self.statistics.get_most_used_win_size())

        min_delay, max_delay = self.get_reply_delay(ip_destination)

        for dport in dest_ports:
            # Parameters changing each iteration
            if self.get_param_value(atkParam.Parameter.IP_SOURCE_RANDOMIZE) and isinstance(ip_source, list):
                ip_source = rnd.choice(ip_source)

            # 1) Build request package
            request_ether = inet.Ether(src=mac_source, dst=mac_destination)
            request_ip = inet.IP(src=ip_source, dst=ip_destination, ttl=source_ttl_value)

            # Random src port for each packet
            sport = rnd.randint(1, 65535)

            request_tcp = inet.TCP(sport=sport, dport=dport, window=source_win_value, flags='S',
                                   options=[('MSS', source_mss_value)])

            request = (request_ether / request_ip / request_tcp)

            request.time = timestamp_next_pkt
            # Append request
            self.packets.append(request)

            # 2) Build reply (for open ports) package
            if dport in ports_open:  # destination port is OPEN
                reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                reply_ip = inet.IP(src=ip_destination, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                reply_tcp = inet.TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=destination_win_value,
                                     options=[('MSS', destination_mss_value)])
                reply = (reply_ether / reply_ip / reply_tcp)

                timestamp_reply = Util.update_timestamp(timestamp_next_pkt, pps, min_delay)
                while timestamp_reply <= timestamp_prv_reply:
                    timestamp_reply = Util.update_timestamp(timestamp_prv_reply, pps, min_delay)
                timestamp_prv_reply = timestamp_reply

                reply.time = timestamp_reply
                self.packets.append(reply)

                # requester confirms
                confirm_ether = request_ether
                confirm_ip = request_ip
                confirm_tcp = inet.TCP(sport=sport, dport=dport, seq=1, window=0, flags='R')
                confirm = (confirm_ether / confirm_ip / confirm_tcp)
                timestamp_confirm = Util.update_timestamp(timestamp_reply, pps, min_delay)
                confirm.time = timestamp_confirm
                self.packets.append(confirm)

                # else: destination port is NOT OPEN -> no reply is sent by target

            pps = max(Util.get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
            timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps)

    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        # store end time of attack
        self.attack_end_utime = self.packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(self.packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(self.packets), pcap_path
