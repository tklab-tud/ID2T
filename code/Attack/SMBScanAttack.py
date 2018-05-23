import logging
import random as rnd

import scapy.layers.inet as inet
from scapy.layers.smb import *

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.SMB2 as SMB2
import ID2TLib.SMBLib as SMBLib
import ID2TLib.Utility as Util

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


class SMBScanAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the SMBScanAttack.
        This Attack injects TCP Syn Requests to the port 445 of several ips and related response into the output
        pcap file.
        If port 445 is open, it will simulate and inject the SMB Protocol Negotiation too.
        """
        # Initialize attack
        super(SMBScanAttack, self).__init__("SmbScan Attack", "Injects an SMB scan",
                                            "Scanning/Probing")

        self.host_os = Util.get_rnd_os()

        # Define allowed parameters and their type
        self.supported_params.update({
            atkParam.Parameter.IP_SOURCE: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.IP_DESTINATION: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.TARGET_COUNT: atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE,
            atkParam.Parameter.HOSTING_PERCENTAGE: atkParam.ParameterTypes.TYPE_PERCENTAGE,
            atkParam.Parameter.PORT_SOURCE: atkParam.ParameterTypes.TYPE_PORT,
            atkParam.Parameter.MAC_SOURCE: atkParam.ParameterTypes.TYPE_MAC_ADDRESS,
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.INJECT_AFTER_PACKET: atkParam.ParameterTypes.TYPE_PACKET_POSITION,
            atkParam.Parameter.IP_SOURCE_RANDOMIZE: atkParam.ParameterTypes.TYPE_BOOLEAN,
            atkParam.Parameter.PACKETS_PER_SECOND: atkParam.ParameterTypes.TYPE_FLOAT,
            atkParam.Parameter.PORT_SOURCE_RANDOMIZE: atkParam.ParameterTypes.TYPE_BOOLEAN,
            atkParam.Parameter.HOSTING_IP: atkParam.ParameterTypes.TYPE_IP_ADDRESS,
            atkParam.Parameter.HOSTING_VERSION: atkParam.ParameterTypes.TYPE_STRING,
            atkParam.Parameter.SOURCE_PLATFORM: atkParam.ParameterTypes.TYPE_STRING,
            atkParam.Parameter.PROTOCOL_VERSION: atkParam.ParameterTypes.TYPE_STRING
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

        self.add_param_value(atkParam.Parameter.TARGET_COUNT, 200)
        self.add_param_value(atkParam.Parameter.IP_DESTINATION, "1.1.1.1")

        self.add_param_value(atkParam.Parameter.PORT_SOURCE, rnd.randint(1024, 65535))
        self.add_param_value(atkParam.Parameter.PORT_SOURCE_RANDOMIZE, 'True')
        self.add_param_value(atkParam.Parameter.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(atkParam.Parameter.INJECT_AFTER_PACKET, rnd.randint(0, self.statistics.get_packet_count()))

        self.add_param_value(atkParam.Parameter.HOSTING_PERCENTAGE, 0.5)
        self.add_param_value(atkParam.Parameter.HOSTING_IP, "1.1.1.1")
        self.add_param_value(atkParam.Parameter.HOSTING_VERSION, SMBLib.get_smb_version(platform=self.host_os))
        self.add_param_value(atkParam.Parameter.SOURCE_PLATFORM, Util.get_rnd_os())
        self.add_param_value(atkParam.Parameter.PROTOCOL_VERSION, "1")

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """

        pps = self.get_param_value(atkParam.Parameter.PACKETS_PER_SECOND)

        # Calculate complement packet rates of the background traffic for each interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt
        timestamp_prv_reply, timestamp_confirm = 0, 0

        # Initialize parameters
        ip_source = self.get_param_value(atkParam.Parameter.IP_SOURCE)

        dest_ip_count = self.get_param_value(atkParam.Parameter.TARGET_COUNT)
        ip_addr_count = self.statistics.get_ip_address_count()
        if ip_addr_count < dest_ip_count + 1:
            dest_ip_count = ip_addr_count

        # Check for user defined target IP addresses
        ip_destinations = self.get_param_value(atkParam.Parameter.IP_DESTINATION)
        if isinstance(ip_destinations, list):
            dest_ip_count = dest_ip_count - len(ip_destinations)
        elif ip_destinations is not "1.1.1.1":
            dest_ip_count = dest_ip_count - 1
            ip_destinations = [ip_destinations]
        else:
            ip_destinations = []

        # Take random targets from pcap
        rnd_ips = self.statistics.get_random_ip_address(dest_ip_count)
        if not isinstance(rnd_ips, list):
            rnd_ips = [rnd_ips]
        ip_destinations = ip_destinations + rnd_ips

        # Make sure the source IP is not part of targets
        if ip_source in ip_destinations and isinstance(ip_destinations, list):
            ip_destinations.remove(ip_source)
        self.add_param_value(atkParam.Parameter.IP_DESTINATION, ip_destinations)

        ip_destinations = self.get_param_value(atkParam.Parameter.IP_DESTINATION)

        # Calculate the amount of IP addresses which are hosting SMB
        host_percentage = self.get_param_value(atkParam.Parameter.HOSTING_PERCENTAGE)
        rnd_ip_count = len(ip_destinations) * host_percentage

        # Check for user defined IP addresses which are hosting SMB
        hosting_ip = self.get_param_value(atkParam.Parameter.HOSTING_IP)
        if isinstance(hosting_ip, list):
            rnd_ip_count = rnd_ip_count - len(hosting_ip)
        elif hosting_ip is not "1.1.1.1":
            rnd_ip_count = rnd_ip_count - 1
            hosting_ip = [hosting_ip]
        else:
            hosting_ip = []

        hosting_ip = hosting_ip + ip_destinations[:int(rnd_ip_count)]
        self.add_param_value(atkParam.Parameter.HOSTING_IP, hosting_ip)

        # Shuffle targets
        rnd.shuffle(ip_destinations)

        # FIXME: Handle mac addresses correctly
        mac_source = self.get_param_value(atkParam.Parameter.MAC_SOURCE)
        mac_dest = self.get_param_value(atkParam.Parameter.MAC_DESTINATION)

        # Check smb version
        smb_version = self.get_param_value(atkParam.Parameter.PROTOCOL_VERSION)
        if smb_version not in SMBLib.smb_versions:
            SMBLib.invalid_smb_version(smb_version)
        hosting_version = self.get_param_value(atkParam.Parameter.HOSTING_VERSION)
        if hosting_version not in SMBLib.smb_versions:
            SMBLib.invalid_smb_version(hosting_version)
        # Check source platform
        src_platform = self.get_param_value(atkParam.Parameter.SOURCE_PLATFORM).lower()
        self.packets = []

        # randomize source ports according to platform, if specified
        if self.get_param_value(atkParam.Parameter.PORT_SOURCE_RANDOMIZE):
            sport = Util.generate_source_port_from_platform(src_platform)
        else:
            sport = self.get_param_value(atkParam.Parameter.PORT_SOURCE)

        # No destination IP was specified, but a destination MAC was specified, generate IP that fits MAC
        if isinstance(ip_destinations, list) and isinstance(mac_dest, str):
            ip_destinations = self.statistics.get_ip_address_from_mac(mac_dest)
            if len(ip_destinations) == 0:
                ip_destinations = self.generate_random_ipv4_address("Unknown", 1)
            # Check ip.src == ip.dst
            self.ip_src_dst_equal_check(ip_source, ip_destinations)

        ip_dests = []
        if isinstance(ip_destinations, list):
            ip_dests = ip_destinations
        else:
            ip_dests.append(ip_destinations)

        if isinstance(ip_dests, list):
            rnd.shuffle(ip_dests)

        # Randomize source IP, if specified
        if self.get_param_value(atkParam.Parameter.IP_SOURCE_RANDOMIZE):
            ip_source = self.generate_random_ipv4_address("Unknown", 1)
            while ip_source in ip_dests:
                ip_source = self.generate_random_ipv4_address("Unknown", 1)
            mac_source = self.statistics.get_mac_address(str(ip_source))
            if len(mac_source) == 0:
                mac_source = self.generate_random_mac_address()

        # Get MSS, TTL and Window size value for source IP
        source_mss_value, source_ttl_value, source_win_value = self.get_ip_data(ip_source)

        for ip in ip_dests:

            if ip != ip_source:

                # Get destination Mac Address
                mac_destination = self.statistics.get_mac_address(str(ip))
                if len(mac_destination) == 0:
                    if isinstance(mac_dest, str):
                        if len(self.statistics.get_ip_address_from_mac(mac_dest)) != 0:
                            ip = self.statistics.get_ip_address_from_mac(mac_dest)
                            self.ip_src_dst_equal_check(ip_source, ip)

                        mac_destination = mac_dest

                    else:
                        mac_destination = self.generate_random_mac_address()

                # Get MSS, TTL and Window size value for destination IP
                destination_mss_value, destination_ttl_value, destination_win_value = self.get_ip_data(ip)

                min_delay, max_delay = self.get_reply_delay(ip)

                # New connection, new random TCP sequence numbers
                attacker_seq = rnd.randint(1000, 50000)
                victim_seq = rnd.randint(1000, 50000)

                # Randomize source port for each connection if specified
                if self.get_param_value(atkParam.Parameter.PORT_SOURCE_RANDOMIZE):
                    sport = Util.generate_source_port_from_platform(src_platform, sport)

                # 1) Build request package
                request_ether = inet.Ether(src=mac_source, dst=mac_destination)
                request_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                request_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, window=source_win_value, flags='S',
                                       seq=attacker_seq, options=[('MSS', source_mss_value)])
                attacker_seq += 1
                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp_next_pkt

                # Append request
                self.packets.append(request)

                # Update timestamp for next package
                timestamp_reply = Util.update_timestamp(timestamp_next_pkt, pps, min_delay)
                while timestamp_reply <= timestamp_prv_reply:
                    timestamp_reply = Util.update_timestamp(timestamp_prv_reply, pps, min_delay)
                timestamp_prv_reply = timestamp_reply

                if ip in hosting_ip:

                    # 2) Build TCP packages for ip that hosts SMB

                    # destination sends SYN, ACK
                    reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                    reply_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                         flags='SA',
                                         window=destination_win_value, options=[('MSS', destination_mss_value)])
                    victim_seq += 1
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    self.packets.append(reply)

                    # requester confirms, ACK
                    confirm_ether = request_ether
                    confirm_ip = request_ip
                    confirm_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq,
                                           window=source_win_value, flags='A')
                    confirm = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = Util.update_timestamp(timestamp_reply, pps, min_delay)
                    confirm.time = timestamp_confirm
                    self.packets.append(confirm)

                    # 3) Build SMB Negotiation packets
                    smb_mid = rnd.randint(1, 65535)
                    smb_pid = rnd.randint(1, 65535)
                    smb_req_tail_arr = []
                    smb_req_tail_size = 0

                    # select dialects based on smb version
                    if smb_version is "1":
                        smb_req_dialects = SMBLib.smb_dialects[0:6]
                    else:
                        smb_req_dialects = SMBLib.smb_dialects
                    if len(smb_req_dialects) == 0:
                        smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail())
                        smb_req_tail_size = len(SMBNegociate_Protocol_Request_Tail())
                    else:
                        for dia in smb_req_dialects:
                            smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail(BufferData=dia))
                            smb_req_tail_size += len(SMBNegociate_Protocol_Request_Tail(BufferData=dia))

                    # Creation of SMB Negotiate Protocol Request packet
                    smb_req_head = SMBNegociate_Protocol_Request_Header(Flags2=0x2801, PID=smb_pid, MID=smb_mid,
                                                                        ByteCount=smb_req_tail_size)
                    smb_req_length = len(smb_req_head) + smb_req_tail_size
                    smb_req_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_req_length)
                    smb_req_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, flags='PA', seq=attacker_seq,
                                           ack=victim_seq)
                    smb_req_ip = inet.IP(src=ip_source, dst=ip, ttl=source_ttl_value)
                    smb_req_ether = inet.Ether(src=mac_source, dst=mac_destination)
                    attacker_seq += len(smb_req_net_bio) + len(smb_req_head) + smb_req_tail_size

                    smb_req_combined = (smb_req_ether / smb_req_ip / smb_req_tcp / smb_req_net_bio / smb_req_head)

                    for i in range(0, len(smb_req_tail_arr)):
                        smb_req_combined = smb_req_combined / smb_req_tail_arr[i]

                    timestamp_smb_req = Util.update_timestamp(timestamp_confirm, pps, min_delay)
                    smb_req_combined.time = timestamp_smb_req
                    self.packets.append(smb_req_combined)

                    # destination confirms SMB request package
                    reply_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                         window=destination_win_value, flags='A')
                    confirm_smb_req = (reply_ether / reply_ip / reply_tcp)
                    timestamp_reply = Util.update_timestamp(timestamp_smb_req, pps, min_delay)
                    confirm_smb_req.time = timestamp_reply
                    self.packets.append(confirm_smb_req)

                    # smb response package
                    first_timestamp = time.mktime(time.strptime(self.statistics.get_pcap_timestamp_start()[:19],
                                                                "%Y-%m-%d %H:%M:%S"))
                    server_guid, security_blob, capabilities, data_size, server_start_time =\
                        SMBLib.get_smb_platform_data(self.host_os, first_timestamp)

                    timestamp_smb_rsp = Util.update_timestamp(timestamp_reply, pps, min_delay)
                    diff = timestamp_smb_rsp - timestamp_smb_req
                    begin = Util.get_filetime_format(timestamp_smb_req + diff * 0.1)
                    end = Util.get_filetime_format(timestamp_smb_rsp - diff * 0.1)
                    system_time = rnd.randint(begin, end)

                    # Creation of SMB Negotiate Protocol Response packets
                    if smb_version is not "1" and hosting_version is not "1":
                        smb_rsp_packet = SMB2.SMB2_SYNC_Header(Flags=1)
                        smb_rsp_negotiate_body =\
                            SMB2.SMB2_Negotiate_Protocol_Response(DialectRevision=0x02ff, SecurityBufferOffset=124,
                                                                  SecurityBufferLength=len(security_blob),
                                                                  SecurityBlob=security_blob, Capabilities=capabilities,
                                                                  MaxTransactSize=data_size, MaxReadSize=data_size,
                                                                  MaxWriteSize=data_size, SystemTime=system_time,
                                                                  ServerStartTime=server_start_time,
                                                                  ServerGuid=server_guid)
                        smb_rsp_length = len(smb_rsp_packet) + len(smb_rsp_negotiate_body)
                    else:
                        smb_rsp_packet =\
                            SMBNegociate_Protocol_Response_Advanced_Security(Start="\xffSMB", PID=smb_pid, MID=smb_mid,
                                                                             DialectIndex=5, SecurityBlob=security_blob)
                        smb_rsp_length = len(smb_rsp_packet)
                    smb_rsp_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_rsp_length)
                    smb_rsp_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, flags='PA', seq=victim_seq,
                                           ack=attacker_seq)
                    smb_rsp_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value)
                    smb_rsp_ether = inet.Ether(src=mac_destination, dst=mac_source)
                    victim_seq += len(smb_rsp_net_bio) + len(smb_rsp_packet)
                    if smb_version is not "1" and hosting_version is not "1":
                        victim_seq += len(smb_rsp_negotiate_body)

                    smb_rsp_combined = (smb_rsp_ether / smb_rsp_ip / smb_rsp_tcp / smb_rsp_net_bio / smb_rsp_packet)
                    if smb_version is not "1" and hosting_version is not "1":
                        smb_rsp_combined = (smb_rsp_combined / smb_rsp_negotiate_body)

                    smb_rsp_combined.time = timestamp_smb_rsp
                    self.packets.append(smb_rsp_combined)

                    # source confirms SMB response package
                    confirm_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq,
                                           window=source_win_value, flags='A')
                    confirm_smb_res = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = Util.update_timestamp(timestamp_smb_rsp, pps, min_delay)
                    confirm_smb_res.time = timestamp_confirm
                    self.packets.append(confirm_smb_res)

                    # attacker sends FIN ACK
                    confirm_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq,
                                           window=source_win_value, flags='FA')
                    source_fin_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_src_fin_ack = Util.update_timestamp(timestamp_confirm, pps, min_delay)
                    source_fin_ack.time = timestamp_src_fin_ack
                    attacker_seq += 1
                    self.packets.append(source_fin_ack)

                    # victim sends FIN ACK
                    reply_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                         window=destination_win_value, flags='FA')
                    destination_fin_ack = (reply_ether / reply_ip / reply_tcp)
                    timestamp_dest_fin_ack = Util.update_timestamp(timestamp_src_fin_ack, pps, min_delay)
                    victim_seq += 1
                    destination_fin_ack.time = timestamp_dest_fin_ack
                    self.packets.append(destination_fin_ack)

                    # source sends final ACK
                    confirm_tcp = inet.TCP(sport=sport, dport=SMBLib.smb_port, seq=attacker_seq, ack=victim_seq,
                                           window=source_win_value, flags='A')
                    final_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_final_ack = Util.update_timestamp(timestamp_dest_fin_ack, pps, min_delay)
                    final_ack.time = timestamp_final_ack
                    self.packets.append(final_ack)

                else:
                    # Build RST package
                    reply_ether = inet.Ether(src=mac_destination, dst=mac_source)
                    reply_ip = inet.IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = inet.TCP(sport=SMBLib.smb_port, dport=sport, seq=0, ack=attacker_seq, flags='RA',
                                         window=destination_win_value, options=[('MSS', destination_mss_value)])
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    self.packets.append(reply)

            pps = max(Util.get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
            timestamp_next_pkt = Util.update_timestamp(timestamp_next_pkt, pps)

    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        # store end time of attack
        self.attack_end_utime = self.packets[-1].time

        # write attack self.packets to pcap
        pcap_path = self.write_attack_pcap(sorted(self.packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(self.packets), pcap_path
