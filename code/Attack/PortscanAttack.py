import logging
import random as rnd

import lea
import scapy.layers.inet as inet

import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes as ParamTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class PortscanAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the PortscanAttack.
        This attack injects TCP Syn-requests and respective responses into the output pcap file.
        """
        # Initialize attack
        super(PortscanAttack, self).__init__("Portscan Attack", "Injects a nmap 'regular scan'",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params.update({
            Param.IP_SOURCE: ParamTypes.TYPE_IP_ADDRESS,
            Param.IP_DESTINATION: ParamTypes.TYPE_IP_ADDRESS,
            Param.PORT_SOURCE: ParamTypes.TYPE_PORT,
            Param.PORT_DESTINATION: ParamTypes.TYPE_PORT,
            Param.PORT_OPEN: ParamTypes.TYPE_PORT,
            Param.MAC_SOURCE: ParamTypes.TYPE_MAC_ADDRESS,
            Param.MAC_DESTINATION: ParamTypes.TYPE_MAC_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParamTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParamTypes.TYPE_PACKET_POSITION,
            Param.PORT_DEST_SHUFFLE: ParamTypes.TYPE_BOOLEAN,
            Param.PORT_DEST_ORDER_DESC: ParamTypes.TYPE_BOOLEAN,
            Param.IP_SOURCE_RANDOMIZE: ParamTypes.TYPE_BOOLEAN,
            Param.PACKETS_PER_SECOND: ParamTypes.TYPE_FLOAT,
            Param.PORT_SOURCE_RANDOMIZE: ParamTypes.TYPE_BOOLEAN
        })

    def init_param(self, param: Param) -> bool:
        """
        Initialize a parameter with a default value specified in the specific attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        if param == Param.IP_SOURCE:
            value = self.statistics.get_most_used_ip_address()
        elif param == Param.IP_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == Param.MAC_SOURCE:
            ip_src = self.get_param_value(Param.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        elif param == Param.IP_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == Param.IP_DESTINATION:
            ip_src = self.get_param_value(Param.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_src])
        elif param == Param.MAC_DESTINATION:
            ip_dst = self.get_param_value(Param.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == Param.PORT_DESTINATION:
            value = self.get_ports_from_nmap_service_dst(1000)
        elif param == Param.PORT_OPEN:
            value = '1'
        elif param == Param.PORT_DEST_SHUFFLE:
            value = 'False'
        elif param == Param.PORT_DEST_ORDER_DESC:
            value = 'False'
        elif param == Param.PORT_SOURCE:
            value = rnd.randint(1024, 65535)
        elif param == Param.PORT_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == Param.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == Param.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)

        # Determine ports
        dest_ports = self.get_param_value(Param.PORT_DESTINATION)
        if self.get_param_value(Param.PORT_DEST_ORDER_DESC):
            dest_ports.reverse()
        elif self.get_param_value(Param.PORT_DEST_SHUFFLE):
            rnd.shuffle(dest_ports)
        if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
            # FIXME: why is sport never used?
            sport = rnd.randint(1, 65535)
        else:
            sport = self.get_param_value(Param.PORT_SOURCE)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt

        # Initialize parameters
        ip_source = self.get_param_value(Param.IP_SOURCE)
        if isinstance(ip_source, list):
            ip_source = ip_source[0]
        ip_destination = self.get_param_value(Param.IP_DESTINATION)
        if not isinstance(ip_destination, list):
            ip_destination = [ip_destination]

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source, ip_destination)

        for ip in ip_destination:
            # Select open ports
            ports_open = self.get_param_value(Param.PORT_OPEN)
            if ports_open == 1:  # user did not specify open ports
                # the ports that were already used by ip.dst (direction in) in the background traffic are open ports
                ports_used_by_ip_dst = self.statistics.process_db_query(
                    "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip + "'")
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
            destination_mss_dist = self.statistics.get_mss_distribution(ip)
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
            destination_ttl_dist = self.statistics.get_ttl_distribution(ip)
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
            destination_win_dist = self.statistics.get_win_distribution(ip)
            if len(destination_win_dist) > 0:
                destination_win_prob_dict = lea.Lea.fromValFreqsDict(destination_win_dist)
                destination_win_value = destination_win_prob_dict.random()
            else:
                destination_win_value = Util.handle_most_used_outputs(self.statistics.get_most_used_win_size())

            min_delay, max_delay = self.get_reply_latency(ip_source, ip)

            for dport in dest_ports:
                # Parameters changing each iteration
                if self.get_param_value(Param.IP_SOURCE_RANDOMIZE) and isinstance(ip_source, list):
                    ip_source = rnd.choice(ip_source)

                # 1) Build request package
                request_ether = inet.Ether(src=mac_source, dst=mac_destination)
                request_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value)

                # Random src port for each packet
                sport = rnd.randint(1, 65535)

                request_tcp = inet.TCP(sport=sport, dport=dport, window=source_win_value, flags='S',
                                       options=[('MSS', source_mss_value)])

                request = (request_ether / request_ip / request_tcp)

                request.time = timestamp_next_pkt
                # Append request
                self.add_packet(request, ip_source, ip)

                # 2) Build reply (for open ports) package
                if dport in ports_open:  # destination port is OPEN
                    reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                    reply_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = inet.TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=destination_win_value,
                                         options=[('MSS', destination_mss_value)])
                    reply = (reply_ether / reply_ip / reply_tcp)

                    timestamp_reply = self.timestamp_controller.next_timestamp(latency=min_delay)

                    reply.time = timestamp_reply
                    self.add_packet(reply, ip_source, ip)

                    # requester confirms
                    confirm_ether = request_ether
                    confirm_ip = request_ip
                    confirm_tcp = inet.TCP(sport=sport, dport=dport, seq=1, window=0, flags='R')
                    confirm = (confirm_ether / confirm_ip / confirm_tcp)
                    self.timestamp_controller.set_timestamp(timestamp_reply)
                    timestamp_confirm = self.timestamp_controller.next_timestamp(latency=min_delay)
                    confirm.time = timestamp_confirm
                    self.add_packet(confirm, ip_source, ip)

                    # else: destination port is NOT OPEN -> no reply is sent by target

                self.timestamp_controller.set_timestamp(timestamp_next_pkt)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

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
