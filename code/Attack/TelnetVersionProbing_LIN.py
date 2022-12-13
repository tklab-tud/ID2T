import logging
import random as rnd

import lea
import scapy.layers.inet as inet

import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util

from Attack.Parameter import Parameter, Boolean, Float, IPAddress, MACAddress, Port

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8

WSCALE = 7

SRV_PAYLOAD_1 = bytes.fromhex('fffd18fffd20fffd23fffd27')
SRV_PAYLOAD_2 = bytes.fromhex('fffb03fffd01fffd1ffffb05fffd21')
SRV_PAYLOAD_3 = bytes.fromhex('fffb01')
SRV_PAYLOAD_4 = bytes.fromhex('5562756e74752032322e30342e31204c54530d0a76626f78206c6f67696e3a20')

CLI_PAYLOAD_1 = bytes.fromhex('fffc18')
CLI_PAYLOAD_2 = bytes.fromhex('fffc20fffc23fffc27')
CLI_PAYLOAD_3 = bytes.fromhex('fffd03')
CLI_PAYLOAD_4 = bytes.fromhex('fffc01fffc1ffffe05fffc21')
CLI_PAYLOAD_5 = bytes.fromhex('fffe01')

class TelnetVersionProbing_LIN(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    PORT_DESTINATION = 'port.dst'
    PORT_OPEN = 'port.open'
    PORT_DEST_SHUFFLE = 'port.dst.shuffle'
    PORT_DEST_ORDER_DESC = 'port.dst.order-desc'
    IP_SOURCE_RANDOMIZE = 'ip.src.shuffle'
    PORT_SOURCE_RANDOMIZE = 'port.src.shuffle'

    def __init__(self):
        """
        Creates a new instance of the Telnet Version Probing.
        This attack injects Metasploit telnet_scanner packets and respective responses into the output pcap file.
        """
        # Initialize attack
        super(TelnetVersionProbing_LIN, self).__init__("TelnetVersionProbing_LIN", "Injects a metasploit 'telnet_scanner' probing",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.PORT_SOURCE, Port()),
            Parameter(self.PORT_DESTINATION, Port()),
            Parameter(self.PORT_OPEN, Port()),
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.PORT_DEST_SHUFFLE, Boolean()),
            Parameter(self.PORT_DEST_ORDER_DESC, Boolean()),
            Parameter(self.IP_SOURCE_RANDOMIZE, Boolean()),
            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.PORT_SOURCE_RANDOMIZE, Boolean())
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with a default value specified in the specific attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        if param == self.IP_SOURCE:
            value = self.statistics.get_most_used_ip_address()
        elif param == self.IP_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == self.MAC_SOURCE:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.get_mac_address(ip_src)
        elif param == self.IP_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == self.IP_DESTINATION:
            ip_src = self.get_param_value(self.IP_SOURCE)
            if ip_src is None:
                return False
            value = self.statistics.get_random_ip_address(ips=[ip_src])
        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if ip_dst is None:
                return False
            value = self.get_mac_address(ip_dst)
        elif param == self.PORT_DESTINATION:
            value = self.get_ports_from_nmap_service_dst(1000)
        elif param == self.PORT_OPEN:
            value = '1'
        elif param == self.PORT_DEST_SHUFFLE:
            value = 'False'
        elif param == self.PORT_DEST_ORDER_DESC:
            value = 'False'
        elif param == self.PORT_SOURCE:
            value = rnd.randint(1024, 65535)
        elif param == self.PORT_SOURCE_RANDOMIZE:
            value = 'False'
        elif param == self.PACKETS_PER_SECOND:
            value = self.statistics.get_most_used_pps()
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        mac_source = self.get_param_value(self.MAC_SOURCE)
        mac_destination = self.get_param_value(self.MAC_DESTINATION)

        # Determine ports
        dport = 23
        if self.get_param_value(self.PORT_SOURCE_RANDOMIZE):
            # FIXME: why is sport never used?
            sport = rnd.randint(1, 65535)
        else:
            sport = self.get_param_value(self.PORT_SOURCE)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt

        # Initialize parameters
        ip_source = self.get_param_value(self.IP_SOURCE)
        if isinstance(ip_source, list):
            ip_source = ip_source[0]
        ip_destination = self.get_param_value(self.IP_DESTINATION)
        if not isinstance(ip_destination, list):
            ip_destination = [ip_destination]

        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_source, ip_destination)

        for ip in ip_destination:
            # Select open ports
            ports_open = self.get_param_value(self.PORT_OPEN)
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

            # Parameters changing each iteration
            if self.get_param_value(self.IP_SOURCE_RANDOMIZE) and isinstance(ip_source, list):
                ip_source = rnd.choice(ip_source)

            src_starting_seq = rnd.getrandbits(32)
            dst_starting_seq = rnd.getrandbits(32)
            src_tsval = rnd.getrandbits(32)
            dst_tsval = rnd.getrandbits(32)
            
            src_seq = src_starting_seq
            src_ack = 0

            dst_seq = dst_starting_seq
            dst_ack = 0

            # 1) Build request package
            request_ether = inet.Ether(src=mac_source, dst=mac_destination)
            request_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value)

            # Random src port for each packet
            sport = rnd.randint(1, 65535)
            
            # SYN
            request_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, window=source_win_value, flags='S', 
                            options=[('MSS', source_mss_value), ('SAckOK', ''),
                                        ('Timestamp', (src_tsval, 0)), ('NOP', ''), ('WScale', WSCALE)])

            request = (request_ether / request_ip / request_tcp)

            request.time = timestamp_next_pkt
            # Append request
            self.add_packet(request, ip_source, ip)

            dst_ack = src_seq +1

            # 2) Build reply (for closed ports) package
            if dport not in ports_open:  # destination port is CLOSED
                # RST, ACK
                reject_ether = inet.Ether(src=mac_destination, dst=mac_source)
                reject_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                reject_tcp = inet.TCP(sport=dport, dport=sport, seq=0, ack=dst_ack, flags='RA', window=0)
                reject = (reject_ether / reject_ip / reject_tcp)

                reject.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(reject, ip, ip_source)
                
            else:
                # SYN/ACK
                reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                reply_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                reply_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='SA', window=destination_win_value,
                            options=[('MSS', destination_mss_value), ('SAckOK', ''), ('Timestamp', (dst_tsval, src_tsval)), ('NOP', ''), ('WScale', WSCALE)])
                reply = (reply_ether / reply_ip / reply_tcp)

                reply.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(reply, ip, ip_source)

                
                #ACK
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                src_seq += 1
                src_ack = dst_seq +1

                confirm_ether = inet.Ether(src=mac_source, dst=mac_destination)
                confirm_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                confirm_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='A', window=source_win_value, 
                                options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                confirm = (confirm_ether / confirm_ip / confirm_tcp)

                confirm.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(confirm, ip_source, ip)


                # TELNET #1 server -> client
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                dst_seq += 1
                dst_ack = src_seq
                telnet1_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet1_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet1_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet1 = (telnet1_ether / telnet1_ip / telnet1_tcp)
                
                telnet1.add_payload(SRV_PAYLOAD_1)
                dst_seq += len(SRV_PAYLOAD_1)

                telnet1.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet1, ip, ip_source)
                
                

                #ACK
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                telnet1_ack_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet1_ack_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet1_ack_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='A', window=source_win_value, 
                                 options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet1_ack = (telnet1_ack_ether / telnet1_ack_ip / telnet1_ack_tcp)

                telnet1_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(telnet1_ack, ip_source, ip)

                # TELNET #2 client -> server
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                telnet2_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet2_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet2_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet2 = (telnet2_ether / telnet2_ip / telnet2_tcp)
                
                telnet2.add_payload(CLI_PAYLOAD_1)
                src_seq += len(CLI_PAYLOAD_1)

                telnet2.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet2, ip_source, ip)

                #ACK
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet2_ack_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet2_ack_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet2_ack_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='A', window=source_win_value, 
                                 options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet2_ack = (telnet2_ack_ether / telnet2_ack_ip / telnet2_ack_tcp)

                telnet2_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(telnet2_ack, ip_source, ip)


                # TELNET #3 client -> server
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                telnet3_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet3_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet3_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet3 = (telnet3_ether / telnet3_ip / telnet3_tcp)
                
                telnet3.add_payload(CLI_PAYLOAD_2)
                src_seq += len(CLI_PAYLOAD_2)

                telnet3.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet3, ip_source, ip)

                #ACK server -> client
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                dst_ack = src_seq
                telnet3_ack_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet3_ack_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet3_ack_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='A', window=destination_win_value, 
                                 options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet3_ack = (telnet3_ack_ether / telnet3_ack_ip / telnet3_ack_tcp)

                telnet3_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(telnet3_ack, ip, ip_source)

                # TELNET #4 server -> client
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet4_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet4_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet4_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet4 = (telnet4_ether / telnet4_ip / telnet4_tcp)
                
                telnet4.add_payload(SRV_PAYLOAD_2)
                dst_seq += len(SRV_PAYLOAD_2)

                telnet4.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet4, ip, ip_source)
                
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))

                # TELNET #5 client -> server
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                telnet5_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet5_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet5_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet5 = (telnet5_ether / telnet5_ip / telnet5_tcp)
                
                telnet5.add_payload(CLI_PAYLOAD_3)
                src_seq += len(CLI_PAYLOAD_3)

                telnet5.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet5, ip_source, ip)

                #ACK server -> client
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet5_ack_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet5_ack_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet5_ack_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='A', window=destination_win_value, 
                                 options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet5_ack = (telnet5_ack_ether / telnet5_ack_ip / telnet5_ack_tcp)

                telnet5_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(telnet5_ack, ip_source, ip)

                # TELNET #6 client -> server
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                telnet6_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet6_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet6_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet6 = (telnet6_ether / telnet6_ip / telnet6_tcp)
                
                telnet6.add_payload(CLI_PAYLOAD_4)
                src_seq += len(CLI_PAYLOAD_4)

                telnet6.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet6, ip_source, ip)

                #ACK server -> client
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet6_ack_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet6_ack_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet6_ack_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='A', window=destination_win_value, 
                                 options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet6_ack = (telnet6_ack_ether / telnet6_ack_ip / telnet6_ack_tcp)

                telnet6_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)
                self.add_packet(telnet6_ack, ip_source, ip)

                # TELNET #7 server -> client
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet7_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet7_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet7_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet7 = (telnet7_ether / telnet7_ip / telnet7_tcp)
                
                telnet7.add_payload(SRV_PAYLOAD_3)
                dst_seq += len(SRV_PAYLOAD_3)

                telnet7.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet7, ip, ip_source)
                
                # TELNET #8 client -> server
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                src_ack = dst_seq
                telnet8_ether = inet.Ether(src=mac_source, dst=mac_destination)
                telnet8_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                telnet8_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                telnet8 = (telnet8_ether / telnet8_ip / telnet8_tcp)
                
                telnet8.add_payload(CLI_PAYLOAD_5)
                src_seq += len(CLI_PAYLOAD_5)

                telnet8.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet8, ip_source, ip)

                # TELNET #9 server -> client
                dst_ack = src_seq
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                telnet9_ether = inet.Ether(src=mac_destination, dst=mac_source)
                telnet9_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                telnet9_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='PA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                telnet9 = (telnet9_ether / telnet9_ip / telnet9_tcp)
                
                telnet9.add_payload(SRV_PAYLOAD_4)
                dst_seq += len(SRV_PAYLOAD_4)

                telnet9.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(telnet9, ip, ip_source)
                
                # FIN/ACK client -> server
                src_ack = dst_seq
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                finack1_ether = inet.Ether(src=mac_source, dst=mac_destination)
                finack1_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                finack1_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='FA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                finack1 = (finack1_ether / finack1_ip / finack1_tcp)
                
                finack1.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(finack1, ip_source, ip)                

                # FIN/ACK server -> client
                dst_ack = src_seq +1
                dst_tsval = int(dst_tsval + rnd.uniform(min_delay, max_delay))
                finack2_ether = inet.Ether(src=mac_destination, dst=mac_source)
                finack2_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                finack2_tcp = inet.TCP(sport=dport, dport=sport, seq=dst_seq, ack=dst_ack, flags='FA', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (dst_tsval, src_tsval))])
                finack2 = (finack2_ether / finack2_ip / finack2_tcp)
                
                finack2.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(finack2, ip, ip_source)
                
                #ACK client -> server
                src_seq += 1
                src_ack = dst_seq +1
                src_tsval = int(src_tsval + rnd.uniform(min_delay, max_delay))
                finack2_ack_ether = inet.Ether(src=mac_source, dst=mac_destination)
                finack2_ack_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                finack2_ack_tcp = inet.TCP(sport=sport, dport=dport, seq=src_seq, ack=src_ack, flags='A', window=destination_win_value,
                            options=[('NOP', ''), ('NOP', ''), ('Timestamp', (src_tsval, dst_tsval))])
                finack2_ack = (finack2_ack_ether / finack2_ack_ip / finack2_ack_tcp)
                
                finack2_ack.time = self.timestamp_controller.next_timestamp(latency=min_delay)

                self.add_packet(finack2_ack, ip_source, ip)

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
