import logging

from random import shuffle, randint, choice, uniform

from lea import Lea

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
from ID2TLib.smb2 import *


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP
from scapy.layers.smb import *
from scapy.layers.netbios import *

class SmbScanAttack(BaseAttack.BaseAttack):
    platforms = {"win7", "win10", "winxp", "win8.1", "macos", "linux", "win8", "winvista", "winnt", "win2000"}
    # SMB port
    smb_port = 445
    # SMB versions
    smb_versions = {"1", "2.0", "2.1", "3.0", "3.0.2", "3.1.1"}
    smb_versions_per_win = {'win7': "2.1", 'win10': "3.1.1", 'winxp': "1", 'win8.1': "3.0.2", 'win8': "3.0",
                            'winvista': "2.0", 'winnt': "1", "win2000": "1"}
    smb_versions_per_samba = {'3.6': "2.0", '4.0': "2.1", '4.1': "3.0", '4.3': "3.1.1"}
    # SMB dialects
    smb_dialects = ["PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1",
                    "NT LM 0.12", "SMB 2.002", "SMB 2.???"]

    def __init__(self):
        """
        Creates a new instance of the SmbScanAttack.

        """
        # Initialize attack
        super(SmbScanAttack, self).__init__("SmbScan Attack", "Injects an SMB scan",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params = {
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
        }

    def init_params(self):
        """
        Initialize the parameters of this attack using the user supplied command line parameters.
        Use the provided statistics to calculate default parameters and to process user
        supplied queries.

        :param statistics: Reference to a statistics object.
        """
        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list):
            most_used_ip_address = most_used_ip_address[0]

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
        # FIXME: MAYBE REMOVE/CHANGE THIS MAC STUFF
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

        rnd_ip_count = self.statistics.get_ip_address_count()/2
        self.add_param_value(Param.HOSTING_IP, self.statistics.get_random_ip_address(rnd_ip_count))
        self.add_param_value(Param.HOSTING_VERSION, self.get_rnd_smb_version())
        self.add_param_value(Param.SOURCE_PLATFORM, self.get_rnd_os())
        self.add_param_value(Param.PROTOCOL_VERSION, "1")
        self.add_param_value(Param.IP_DESTINATION_END, "0.0.0.0")

    def get_rnd_os(self):
        os_dist = Lea.fromValFreqsDict({"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94,
                                       "linux": 3.38, "win8": 1.35, "winvista": 0.46, "winnt": 0.31})
        return os_dist.random()

    def get_rnd_smb_version(self):
        os = self.get_rnd_os()
        if os is "linux":
            return random.choice(list(self.smb_versions_per_samba.values()))
        elif os is "macos":
            # TODO: figure out macOS smb version(s)
            return random.choice(list(self.smb_versions))
        else:
            return self.smb_versions_per_win[os]

    @property
    def generate_attack_pcap(self):
        def update_timestamp(timestamp, pps, delay=0):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            if delay == 0:
                # Calculate request timestamp
                # To imitate the bursty behavior of traffic
                randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 20, 5 / pps: 7, 10 / pps: 3})
                return timestamp + uniform(1/pps ,  randomdelay.random())
            else:
                # Calculate reply timestamp
                randomdelay = Lea.fromValFreqsDict({2*delay: 70, 3*delay: 20, 5*delay: 7, 10*delay: 3})
                return timestamp + uniform(1 / pps + delay,  1 / pps + randomdelay.random())

        def getIntervalPPS(complement_interval_pps, timestamp):
            """
            Gets the packet rate (pps) for a specific time interval.

            :param complement_interval_pps: an array of tuples (the last timestamp in the interval, the packet rate in the crresponding interval).
            :param timestamp: the timestamp at which the packet rate is required.
            :return: the corresponding packet rate (pps) .
            """
            for row in complement_interval_pps:
                if timestamp<=row[0]:
                    return row[1]
            return complement_interval_pps[-1][1] # in case the timstamp > capture max timestamp

        def getIpData(ip_address: str):
            """
            :param ip_address: the ip of which (packet-)data shall be returned
            :return: MSS, TTL and Window Size values of the given IP
            """
            # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
            mss_dist = self.statistics.get_mss_distribution(ip_address)
            if len(mss_dist) > 0:
                mss_prob_dict = Lea.fromValFreqsDict(mss_dist)
                mss_value = mss_prob_dict.random()
            else:
                mss_value = self.statistics.process_db_query("most_used(mssValue)")

            # Set TTL based on TTL distribution of IP address
            ttl_dist = self.statistics.get_ttl_distribution(ip_address)
            if len(ttl_dist) > 0:
                ttl_prob_dict = Lea.fromValFreqsDict(ttl_dist)
                ttl_value = ttl_prob_dict.random()
            else:
                ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

            # Set Window Size based on Window Size distribution of IP address
            win_dist = self.statistics.get_win_distribution(ip_address)
            if len(win_dist) > 0:
                win_prob_dict = Lea.fromValFreqsDict(win_dist)
                win_value = win_prob_dict.random()
            else:
                win_value = self.statistics.process_db_query("most_used(winSize)")

            return mss_value, ttl_value, win_value

        def getIpRange(start_ip: str, end_ip: str):
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            ips = []

            if start < end:
                while start <= end:
                    ips.append(start.exploded)
                    start = start+1
            elif start > end:
                while start >= end:
                    ips.append(start.exploded)
                    start = start-1
            else:
                ips.append(start_ip)

            return ips

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
        def invalid_verison(version: str):
            print("\nInvalid smb version: " + version +
                  "\nPlease select one of the following versions: 1, 2.0, 2.1, 3.0, 3.0.2, 3.1.1")
            # FIXME: useful error code
            exit(-1)
        smb_version = self.get_param_value(Param.PROTOCOL_VERSION)
        if smb_version not in self.smb_versions:
            invalid_verison(smb_version)
        hosting_version = self.get_param_value(Param.HOSTING_VERSION)
        if hosting_version not in self.smb_versions:
            invalid_verison(hosting_version)
        # Check source platform
        src_platform = self.get_param_value(Param.SOURCE_PLATFORM).lower()
        if src_platform not in self.platforms:
            print("\nInvalid source platform: " + src_platform + ". Selecting random platform as source platform.")
            src_platform = self.get_rnd_os()
        packets = []

        # randomize source ports according to platform, if specified
        if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
            if src_platform in {"winnt", "winxp", "win2000"}:
                sport = randint(1024, 5000)
            elif src_platform == "linux":
                sport = randint(32768, 61000)
            else:
                sport = randint(49152, 65535)

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
            ip_dests = getIpRange(ip_dests[0], ip_range_end)
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
        source_mss_value, source_ttl_value, source_win_value = getIpData(ip_source)

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
                destination_mss_value, destination_ttl_value, destination_win_value = getIpData(ip)

                minDelay, maxDelay = self.get_reply_delay(ip)

                # New connection, new random TCP sequence numbers
                attacker_seq = randint(1000, 50000)
                victim_seq = randint(1000, 50000)

                # Randomize source port for each connection if specified
                if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
                    if src_platform == "linux":
                        sport = randint(32768, 61000)
                    else:
                        sport = sport+1

                # 1) Build request package
                request_ether = Ether(src=mac_source, dst=mac_destination)
                request_ip = IP(src=ip_source, dst=ip, ttl=source_ttl_value, flags='DF')
                request_tcp = TCP(sport=sport, dport=self.smb_port, window=source_win_value, flags='S',
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
                    reply_tcp = TCP(sport=self.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq, flags='SA',
                                    window=destination_win_value,
                                    options=[('MSS', destination_mss_value)])
                    victim_seq += 1
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    packets.append(reply)

                    # requester confirms, ACK
                    confirm_ether = request_ether
                    confirm_ip = request_ip
                    confirm_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    confirm = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = update_timestamp(timestamp_reply, pps, minDelay)
                    confirm.time = timestamp_confirm
                    packets.append(confirm)

                    # INSERT SMB-REQUEST PACKAGE HERE
                    # FIXME: CHECK FOR PROTOCOL VERSION?
                    smb_MID = randint(1, 65535)
                    smb_PID = randint(1, 65535)
                    smb_req_tail_arr = []
                    smb_req_tail_size = 0

                    # select dialects based on smb version
                    if smb_version is "1":
                        smb_req_dialects = self.smb_dialects[0:6]
                    else:
                        smb_req_dialects = self.smb_dialects
                    if len(smb_req_dialects) == 0:
                        smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail())
                        smb_req_tail_size = len(SMBNegociate_Protocol_Request_Tail())
                    else:
                        for dia in smb_req_dialects:
                            smb_req_tail_arr.append(SMBNegociate_Protocol_Request_Tail(BufferData = dia))
                            smb_req_tail_size += len(SMBNegociate_Protocol_Request_Tail(BufferData = dia))

                    smb_req_head = SMBNegociate_Protocol_Request_Header(Flags2=0x2801, PID=smb_PID, MID=smb_MID,
                                                                        ByteCount=smb_req_tail_size)
                    smb_req_length = len(smb_req_head) + smb_req_tail_size
                    smb_req_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_req_length)
                    smb_req_tcp = TCP(sport=sport, dport=self.smb_port, flags='PA', seq=attacker_seq, ack=victim_seq)
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
                    reply_tcp = TCP(sport=self.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                    window=destination_win_value, flags='A')
                    confirm_smb_req = (reply_ether / reply_ip / reply_tcp)
                    timestamp_reply = update_timestamp(timestamp_smb_req, pps, minDelay)
                    confirm_smb_req.time = timestamp_reply
                    packets.append(confirm_smb_req)

                    # smb response package
                    if smb_version is not "1" and hosting_version is not "1":
                        smb_rsp_paket = SMB2_SYNC_Header(Flags = 1)
                        smb_rsp_negotiate_body = SMB2_Negotiate_Protocol_Response(DialectRevision=0x02ff)
                        smb_rsp_length = len(smb_rsp_paket) + len(smb_rsp_negotiate_body)
                    else:
                        smb_rsp_paket = SMBNegociate_Protocol_Response_No_Security_No_Key(Start="\xffSMB" , PID=smb_PID,
                                                                                          MID=smb_MID, DialectIndex=5)
                        smb_rsp_length = len(smb_rsp_paket)
                    smb_rsp_net_bio = NBTSession(TYPE=0x00, LENGTH=smb_rsp_length)
                    smb_rsp_tcp = TCP(sport=self.smb_port, dport=sport, flags='PA', seq=victim_seq, ack=attacker_seq)
                    smb_rsp_ip = IP(src=ip, dst=ip_source, ttl=destination_ttl_value)
                    smb_rsp_ether = Ether(src=mac_destination, dst=mac_source)
                    victim_seq += len(smb_rsp_net_bio) + len(smb_rsp_paket)
                    if smb_version is not "1"and hosting_version is not "1":
                        victim_seq += len(smb_rsp_negotiate_body)

                    smb_rsp_combined = (smb_rsp_ether / smb_rsp_ip / smb_rsp_tcp / smb_rsp_net_bio / smb_rsp_paket)
                    if smb_version is not "1"and hosting_version is not "1":
                        smb_rsp_combined = (smb_rsp_combined / smb_rsp_negotiate_body)

                    timestamp_smb_rsp = update_timestamp(timestamp_reply, pps, minDelay)
                    smb_rsp_combined.time = timestamp_smb_rsp
                    packets.append(smb_rsp_combined)


                    # source confirms SMB response package
                    confirm_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    confirm_smb_res = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_confirm = update_timestamp(timestamp_smb_rsp, pps, minDelay)
                    confirm_smb_res.time = timestamp_confirm
                    packets.append(confirm_smb_res)

                    # attacker sends FIN ACK
                    confirm_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='FA')
                    source_fin_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_src_fin_ack = update_timestamp(timestamp_confirm, pps, minDelay)
                    source_fin_ack.time = timestamp_src_fin_ack
                    attacker_seq += 1
                    packets.append(source_fin_ack)

                    # victim sends FIN ACK
                    reply_tcp = TCP(sport=self.smb_port, dport=sport, seq=victim_seq, ack=attacker_seq,
                                    window=destination_win_value, flags='FA')
                    destination_fin_ack = (reply_ether / reply_ip / reply_tcp)
                    timestamp_dest_fin_ack = update_timestamp(timestamp_src_fin_ack, pps, minDelay)
                    victim_seq += 1
                    destination_fin_ack.time = timestamp_dest_fin_ack
                    packets.append(destination_fin_ack)

                    # source sends final ACK
                    confirm_tcp = TCP(sport=sport, dport=self.smb_port, seq=attacker_seq, ack=victim_seq,
                                      window=source_win_value, flags='A')
                    final_ack = (confirm_ether / confirm_ip / confirm_tcp)
                    timestamp_final_ack = update_timestamp(timestamp_dest_fin_ack, pps, minDelay)
                    final_ack.time = timestamp_final_ack
                    packets.append(final_ack)

                else:
                    # Build RST package
                    reply_ether = Ether(src=mac_destination, dst=mac_source)
                    reply_ip = IP(src=ip, dst=ip_source, ttl=destination_ttl_value, flags='DF')
                    reply_tcp = TCP(sport=self.smb_port, dport=sport, seq=0, ack=attacker_seq, flags='RA',
                                    window=destination_win_value, options=[('MSS', destination_mss_value)])
                    reply = (reply_ether / reply_ip / reply_tcp)
                    reply.time = timestamp_reply
                    packets.append(reply)

            pps = max(getIntervalPPS(complement_interval_pps, timestamp_next_pkt), 10)
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps)

        # store end time of attack
        self.attack_end_utime = packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(packets), pcap_path
