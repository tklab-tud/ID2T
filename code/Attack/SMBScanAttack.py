import logging

from random import shuffle, randint
from lea import Lea
from scapy.layers.inet import IP, Ether, TCP
from scapy.layers.smb import *
from scapy.layers.netbios import *

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
from ID2TLib.SMB2 import *
from ID2TLib.Utility import update_timestamp, get_interval_pps, get_ip_range,\
    generate_source_port_from_platform, get_filetime_format, handle_most_used_outputs
import ID2TLib.Utility
from ID2TLib.SMBLib import smb_port, smb_versions, smb_dialects, get_smb_version, get_smb_platform_data,\
    invalid_smb_version

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8


class SMBScanAttack(BaseAttack.BaseAttack):

    def __init__(self):
        """
        Creates a new instance of the SMBScanAttack.

        """
        # Initialize attack
        super(SMBScanAttack, self).__init__("SmbScan Attack", "Injects an SMB scan",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params.update({
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.PORT_SOURCE: ParameterTypes.TYPE_PORT,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.IP_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.PORT_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN,
            Param.HOSTING_IP: ParameterTypes.TYPE_IP_ADDRESS,
            Param.HOSTING_VERSION: ParameterTypes.TYPE_STRING,
            Param.SOURCE_PLATFORM: ParameterTypes.TYPE_STRING,
            Param.PROTOCOL_VERSION: ParameterTypes.TYPE_STRING,
            Param.IP_DESTINATION_END: ParameterTypes.TYPE_IP_ADDRESS
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

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.IP_SOURCE_RANDOMIZE, 'False')
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        all_ips = self.statistics.get_ip_addresses()
        if not isinstance(all_ips, list):
            ip_destinations = []
            ip_destinations.append(all_ips)
        else:
            ip_destinations = all_ips
        self.add_param_value(Param.IP_DESTINATION, ip_destinations)
        destination_mac = []
        for ip in ip_destinations:
            destination_mac.append(self.statistics.get_mac_address(str(ip)))
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)
        self.add_param_value(Param.PORT_SOURCE, randint(1024, 65535))
        self.add_param_value(Param.PORT_SOURCE_RANDOMIZE, 'True')
        self.add_param_value(Param.PACKETS_PER_SECOND,
                             (self.statistics.get_pps_sent(most_used_ip_address) +
                              self.statistics.get_pps_received(most_used_ip_address)) / 2)
        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))

        rnd_ip_count = self.statistics.get_ip_address_count()//2
        self.add_param_value(Param.HOSTING_IP, self.statistics.get_random_ip_address(rnd_ip_count))
        self.host_os = ID2TLib.Utility.get_rnd_os()
        self.add_param_value(Param.HOSTING_VERSION, get_smb_version(platform=self.host_os))
        self.add_param_value(Param.SOURCE_PLATFORM, ID2TLib.Utility.get_rnd_os())
        self.add_param_value(Param.PROTOCOL_VERSION, "1")
        self.add_param_value(Param.IP_DESTINATION_END, "0.0.0.0")

    def generate_attack_pcap(self):

        pps = self.get_param_value(Param.PACKETS_PER_SECOND)

        # Calculate complement packet rates of the background traffic for each interval
        complement_interval_pps = self.statistics.calculate_complement_packet_rates(pps)


        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt
        timestamp_prv_reply, timestamp_confirm = 0,0

        # Initialize parameters
        ip_source = self.get_param_value(Param.IP_SOURCE)
        ip_destinations = self.get_param_value(Param.IP_DESTINATION)
        hosting_ip = self.get_param_value(Param.HOSTING_IP)
        ip_range_end = self.get_param_value(Param.IP_DESTINATION_END)
        mac_source = self.get_param_value(Param.MAC_SOURCE)
        mac_dest = self.get_param_value(Param.MAC_DESTINATION)

        # Check smb version
        smb_version = self.get_param_value(Param.PROTOCOL_VERSION)
        if smb_version not in smb_versions:
            invalid_smb_version(smb_version)
        hosting_version = self.get_param_value(Param.HOSTING_VERSION)
        if hosting_version not in smb_versions:
            invalid_smb_version(hosting_version)
        # Check source platform
        src_platform = self.get_param_value(Param.SOURCE_PLATFORM).lower()
        packets = []

        # randomize source ports according to platform, if specified
        if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
            sport = generate_source_port_from_platform(src_platform)
        else:
            sport = self.get_param_value(Param.PORT_SOURCE)

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

        # Generate IPs of destination IP range, if specified
        if ip_range_end != "0.0.0.0":
            ip_dests = get_ip_range(ip_dests[0], ip_range_end)
            shuffle(ip_dests)

        # Randomize source IP, if specified
        if self.get_param_value(Param.IP_SOURCE_RANDOMIZE):
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

                minDelay, maxDelay = self.get_reply_delay(ip)

                # New connection, new random TCP sequence numbers
                attacker_seq = randint(1000, 50000)
                victim_seq = randint(1000, 50000)

                # Randomize source port for each connection if specified
                if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
                    sport = generate_source_port_from_platform(src_platform, sport)

                # 1) Build request package
                request_ether = Ether(src=mac_source, dst=mac_destination)
                request_ip = IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                request_tcp = TCP(sport=sport, dport=smb_port, window=source_win_value, flags='S',
                                  seq=attacker_seq, options=[('MSS', source_mss_value)])
                attacker_seq += 1
                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp_next_pkt

                # Append request
                packets.append(request)

                # Update timestamp for next package
                timestamp_reply = update_timestamp(timestamp_next_pkt, pps, minDelay)
                while (timestamp_reply <= timestamp_prv_reply):
                    timestamp_reply = update_timestamp(timestamp_prv_reply, pps, minDelay)
                timestamp_prv_reply = timestamp_reply

                if ip in hosting_ip:

                    # 2) Build TCP packages for ip that hosts SMB

                    # destination sends SYN, ACK
                    reply_ether = Ether(src=mac_destination, dst=mac_source)
                    reply_ip = IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = TCP(sport=smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                                    window=destination_win_value, options=[('MSS', destination_mss_value)])
                    victim_seq += 1
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    packets.append(reply)

                    # requester confirms, ACK
                    confirm_ether = request_ether
                    confirm_ip = request_ip
                    confirm_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    confirm = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = update_timestamp(timestamp_reply, pps, minDelay)
                    confirm.time = timestamp_confirm
                    packets.append(confirm)

                    smb_MID = randint(1, 65535)
                    smb_PID = randint(1, 65535)
                    smb_req_tail_arr = []
                    smb_req_tail_size = 0

                    # select dialects based on smb version
                    if smb_version is "1":
                        smb_req_dialects = smb_dialects[0:6]
                    else:
                        smb_req_dialects = smb_dialects
                    if len(smb_req_dialects) == 0:
                        smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail())
                        smb_req_tail_size = len(SMBNegociate_Protocol_Request_Tail())
                    else:
                        for dia in smb_req_dialects:
                            smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail(BufferData = dia))
                            smb_req_tail_size += len(SMBNegociate_Protocol_Request_Tail(BufferData = dia))

                    smb_req_head = SMBNegociate_Protocol_Request_Header\
                        (Flags2=0x2801, PID=smb_PID, MID=smb_MID, ByteCount=smb_req_tail_size)
                    smb_req_length = len(smb_req_head) + smb_req_tail_size
                    smb_req_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_req_length)
                    smb_req_tcp = TCP(sport=sport, dport=smb_port, flags='PA', seq=attacker_seq, ack=victim_seq)
                    smb_req_ip = IP(src=ip_source, dst=ip, ttl=source_ttl_value)
                    smb_req_ether = Ether(src=mac_source, dst=mac_destination)
                    attacker_seq += len(smb_req_net_bio) + len(smb_req_head) + smb_req_tail_size

                    smb_req_combined = (smb_req_ether / smb_req_ip / smb_req_tcp / smb_req_net_bio / smb_req_head)

                    for i in range(0 , len(smb_req_tail_arr)):
                        smb_req_combined = smb_req_combined / smb_req_tail_arr[i]

                    timestamp_smb_req = update_timestamp(timestamp_confirm, pps, minDelay)
                    smb_req_combined.time = timestamp_smb_req
                    packets.append(smb_req_combined)

                    # destination confirms SMB request package
                    reply_tcp = TCP(sport=smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                    window=destination_win_value, flags='A')
                    confirm_smb_req = (reply_ether / reply_ip / reply_tcp)
                    timestamp_reply = update_timestamp(timestamp_smb_req, pps, minDelay)
                    confirm_smb_req.time = timestamp_reply
                    packets.append(confirm_smb_req)

                    # smb response package
                    first_timestamp = time.mktime(time.strptime(self.statistics.get_pcap_timestamp_start()[:19],
                                                                "%Y-%m-%d %H:%M:%S"))
                    server_Guid, security_blob, capabilities, data_size, server_start_time = get_smb_platform_data\
                        (self.host_os, first_timestamp)

                    timestamp_smb_rsp = update_timestamp(timestamp_reply, pps, minDelay)
                    diff = timestamp_smb_rsp - timestamp_smb_req
                    begin = get_filetime_format(timestamp_smb_req+diff*0.1)
                    end = get_filetime_format(timestamp_smb_rsp-diff*0.1)
                    system_time = randint(begin, end)

                    if smb_version is not "1" and hosting_version is not "1":
                        smb_rsp_paket = SMB2_SYNC_Header(Flags = 1)
                        smb_rsp_negotiate_body = SMB2_Negotiate_Protocol_Response\
                            (DialectRevision=0x02ff, SecurityBufferOffset=124, SecurityBufferLength=len(security_blob),
                             SecurityBlob=security_blob, Capabilities=capabilities, MaxTransactSize=data_size,
                             MaxReadSize=data_size, MaxWriteSize=data_size, SystemTime=system_time,
                             ServerStartTime=server_start_time, ServerGuid=server_Guid)
                        smb_rsp_length = len(smb_rsp_paket) + len(smb_rsp_negotiate_body)
                    else:
                        smb_rsp_paket = SMBNegociate_Protocol_Response_Advanced_Security\
                            (Start="\xffSMB", PID=smb_PID, MID=smb_MID, DialectIndex=5, SecurityBlob=security_blob)
                        smb_rsp_length = len(smb_rsp_paket)
                    smb_rsp_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_rsp_length)
                    smb_rsp_tcp = TCP(sport=smb_port, dport=sport, flags='PA', seq=victim_seq, ack=attacker_seq)
                    smb_rsp_ip = IP(src=ip, dst=ip_source, ttl=destination_ttl_value)
                    smb_rsp_ether = Ether(src=mac_destination, dst=mac_source)
                    victim_seq += len(smb_rsp_net_bio) + len(smb_rsp_paket)
                    if smb_version is not "1"and hosting_version is not "1":
                        victim_seq += len(smb_rsp_negotiate_body)

                    smb_rsp_combined = (smb_rsp_ether / smb_rsp_ip / smb_rsp_tcp / smb_rsp_net_bio / smb_rsp_paket)
                    if smb_version is not "1"and hosting_version is not "1":
                        smb_rsp_combined = (smb_rsp_combined / smb_rsp_negotiate_body)

                    smb_rsp_combined.time = timestamp_smb_rsp
                    packets.append(smb_rsp_combined)


                    # source confirms SMB response package
                    confirm_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    confirm_smb_res = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = update_timestamp(timestamp_smb_rsp, pps, minDelay)
                    confirm_smb_res.time = timestamp_confirm
                    packets.append(confirm_smb_res)

                    # attacker sends FIN ACK
                    confirm_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='FA')
                    source_fin_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_src_fin_ack = update_timestamp(timestamp_confirm, pps, minDelay)
                    source_fin_ack.time = timestamp_src_fin_ack
                    attacker_seq += 1
                    packets.append(source_fin_ack)

                    # victim sends FIN ACK
                    reply_tcp = TCP(sport=smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                    window=destination_win_value, flags='FA')
                    destination_fin_ack = (reply_ether / reply_ip / reply_tcp)
                    timestamp_dest_fin_ack = update_timestamp(timestamp_src_fin_ack, pps, minDelay)
                    victim_seq += 1
                    destination_fin_ack.time = timestamp_dest_fin_ack
                    packets.append(destination_fin_ack)

                    # source sends final ACK
                    confirm_tcp = TCP(sport=sport, dport=smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    final_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_final_ack = update_timestamp(timestamp_dest_fin_ack, pps, minDelay)
                    final_ack.time = timestamp_final_ack
                    packets.append(final_ack)

                else:
                    # Build RST package
                    reply_ether = Ether(src=mac_destination, dst=mac_source)
                    reply_ip = IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = TCP(sport=smb_port, dport=sport, seq=0, ack=attacker_seq, flags='RA',
                                    window=destination_win_value, options=[('MSS', destination_mss_value)])
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    packets.append(reply)

            pps = max(get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps)

        # store end time of attack
        self.attack_end_utime = packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(packets), pcap_path
