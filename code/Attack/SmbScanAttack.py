import logging

from random import shuffle, randint, choice, uniform
from datetime import datetime, timedelta, tzinfo
from calendar import timegm
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
    # SMB security blobs
    security_blob_windows = "\x60\x82\x01\x3c\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x82\x01\x30" \
                            "\x30\x82\x01\x2c\xa0\x1a\x30\x18\x06\x0a\x2b\x06\x01\x04\x01\x82" \
                            "\x37\x02\x02\x1e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" \
                            "\xa2\x82\x01\x0c\x04\x82\x01\x08\x4e\x45\x47\x4f\x45\x58\x54\x53" \
                            "\x01\x00\x00\x00\x00\x00\x00\x00\x60\x00\x00\x00\x70\x00\x00\x00" \
                            "\xbc\x84\x03\x97\x6f\x80\x3b\x81\xa6\x45\x1b\x05\x92\x39\xde\x3d" \
                            "\xd6\x91\x85\x49\x8a\xd0\x3b\x58\x87\x99\xb4\x98\xdf\xa6\x1d\x73" \
                            "\x3b\x57\xbf\x05\x63\x5e\x30\xea\xa8\xd8\xd8\x45\xba\x80\x52\xa5" \
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x00\x00\x01\x00\x00\x00" \
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x33\x53\x0d\xea\xf9\x0d\x4d" \
                            "\xb2\xec\x4a\xe3\x78\x6e\xc3\x08\x4e\x45\x47\x4f\x45\x58\x54\x53" \
                            "\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x98\x00\x00\x00" \
                            "\xbc\x84\x03\x97\x6f\x80\x3b\x81\xa6\x45\x1b\x05\x92\x39\xde\x3d" \
                            "\x5c\x33\x53\x0d\xea\xf9\x0d\x4d\xb2\xec\x4a\xe3\x78\x6e\xc3\x08" \
                            "\x40\x00\x00\x00\x58\x00\x00\x00\x30\x56\xa0\x54\x30\x52\x30\x27" \
                            "\x80\x25\x30\x23\x31\x21\x30\x1f\x06\x03\x55\x04\x03\x13\x18\x54" \
                            "\x6f\x6b\x65\x6e\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x50\x75\x62" \
                            "\x6c\x69\x63\x20\x4b\x65\x79\x30\x27\x80\x25\x30\x23\x31\x21\x30" \
                            "\x1f\x06\x03\x55\x04\x03\x13\x18\x54\x6f\x6b\x65\x6e\x20\x53\x69" \
                            "\x67\x6e\x69\x6e\x67\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79"
    security_blob_ubuntu = "\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e" \
                           "\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa3\x2a" \
                           "\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\x64\x65\x66\x69\x6e\x65" \
                           "\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6c\x65" \
                           "\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65"
    security_blob_macos =   "\x60\x7e\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x74\x30\x72\xa0\x44" \
                            "\x30\x42\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x06\x09\x2a" \
                            "\x86\x48\x86\xf7\x12\x01\x02\x02\x06\x06\x2a\x85\x70\x2b\x0e\x03" \
                            "\x06\x06\x2b\x06\x01\x05\x05\x0e\x06\x0a\x2b\x06\x01\x04\x01\x82" \
                            "\x37\x02\x02\x0a\x06\x06\x2b\x05\x01\x05\x02\x07\x06\x06\x2b\x06" \
                            "\x01\x05\x02\x05\xa3\x2a\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f" \
                            "\x64\x65\x66\x69\x6e\x65\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31" \
                            "\x37\x38\x40\x70\x6c\x65\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65"


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
        self.host_os = self.get_rnd_os()
        self.add_param_value(Param.HOSTING_VERSION, self.get_smb_version(self.host_os))
        self.add_param_value(Param.SOURCE_PLATFORM, self.get_rnd_os())
        self.add_param_value(Param.PROTOCOL_VERSION, "1")
        self.add_param_value(Param.IP_DESTINATION_END, "0.0.0.0")

    def get_rnd_os(self):
        os_dist = Lea.fromValFreqsDict({"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94,
                                       "linux": 3.38, "win8": 1.35, "winvista": 0.46, "winnt": 0.31})
        return os_dist.random()

    def get_smb_version(self, os: str):
        if os is "linux":
            return random.choice(list(self.smb_versions_per_samba.values()))
        elif os is "macos":
            # TODO: figure out macOS smb version(s)
            return random.choice(list(self.smb_versions))
        else:
            return self.smb_versions_per_win[os]

    def get_rnd_smb_version(self):
        os = self.get_rnd_os()
        return self.get_smb_version(os)

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

        def checkPlatform(platform: str):
            if platform not in self.platforms:
                print("\nERROR: Invalid platform: " + platform + "." +
                      "\n Please select one of the following platforms: ", self.platforms)
                exit(1)

        def generateSourcePortFromPlatform(platform: str, previousPort=0):
            checkPlatform(platform)
            if platform in {"winnt", "winxp", "win2000"}:
                if (previousPort == 0) or (previousPort+1 > 5000):
                    return randint(1024, 5000)
                else:
                    return previousPort+1
            elif platform == "linux":
                return randint(32768, 61000)
            else:
                if (previousPort == 0) or (previousPort+1 > 65535):
                    return randint(49152, 65535)
                else:
                    return previousPort+1

        # FIXME: rework copy-pasted code
        # source: http://reliablybroken.com/b/2009/09/working-with-active-directory-filetime-values-in-python/
        # WORK IN PROGRESS
        def get_filetime_format(timestamp):
            EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
            HUNDREDS_OF_NANOSECONDS = 10000000
            boot_datetime = datetime.fromtimestamp(timestamp)
            if (boot_datetime.tzinfo is None) or (boot_datetime.tzinfo.utcoffset(boot_datetime) is None):
                boot_datetime = boot_datetime.replace(tzinfo=boot_datetime.tzname())
            boot_filetime = EPOCH_AS_FILETIME + (timegm(boot_datetime.timetuple()) * HUNDREDS_OF_NANOSECONDS)
            return boot_filetime + (boot_datetime.microsecond * 10)

        def get_rnd_boot_time(timestamp, platform="winxp"):
            checkPlatform(platform)
            # FIXME: create probability distribution for each OS
            if platform is "linux":
                # four years
                timestamp -= randint(0, 126144000)
            if platform is "macOS":
                # three months
                timestamp -= randint(0, 7884000)
            else:
                # one month
                timestamp -= randint(0, 2678400)
            return get_filetime_format(timestamp)

        def getSmbPlatformData(platform: str, timestamp=time.time()):
            checkPlatform(platform)
            if platform == "linux":
                blob = self.security_blob_ubuntu
                capabilities = 0x5
                dataSize = 0x800000
                serverStartTime = 0
            elif platform == "macos":
                blob = self.security_blob_macos
                capabilities = 0x6
                dataSize = 0x400000
                serverStartTime = 0
            else:
                blob = self.security_blob_windows
                capabilities = 0x7
                dataSize = 0x100000
                serverStartTime = get_rnd_boot_time(timestamp)
            return blob, capabilities, dataSize, serverStartTime


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
        def invalid_version(version: str):
            print("\nInvalid smb version: " + version +
                  "\nPlease select one of the following versions: ", self.smb_versions)
            exit(1)
        smb_version = self.get_param_value(Param.PROTOCOL_VERSION)
        if smb_version not in self.smb_versions:
            invalid_version(smb_version)
        hosting_version = self.get_param_value(Param.HOSTING_VERSION)
        if hosting_version not in self.smb_versions:
            invalid_version(hosting_version)
        # Check source platform
        src_platform = self.get_param_value(Param.SOURCE_PLATFORM).lower()
        packets = []

        # randomize source ports according to platform, if specified
        if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
            sport = generateSourcePortFromPlatform(src_platform)
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
                    sport = generateSourcePortFromPlatform(src_platform, sport)

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
                                    window=destination_win_value, options=[('MSS', destination_mss_value)])
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

                    smb_req_head = SMBNegociate_Protocol_Request_Header\
                        (Flags2=0x2801, PID=smb_PID, MID=smb_MID, ByteCount=smb_req_tail_size)
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
                    timestamp_smb_rsp = update_timestamp(timestamp_reply, pps, minDelay)

                    security_blob, capabilities, dataSize, serverStartTime = getSmbPlatformData\
                        (self.host_os, time.mktime(time.strptime(self.statistics.get_pcap_timestamp_start()[:19],
                                                                 "%Y-%m-%d %H:%M:%S")))
                    diff = timestamp_smb_rsp - timestamp_smb_req
                    begin = get_filetime_format(timestamp_smb_req+diff*0.1)
                    end = get_filetime_format(timestamp_smb_rsp-diff*0.1)
                    systemtime = randint(begin, end)

                    if smb_version is not "1" and hosting_version is not "1":
                        smb_rsp_paket = SMB2_SYNC_Header(Flags = 1)
                        smb_rsp_negotiate_body = SMB2_Negotiate_Protocol_Response\
                            (DialectRevision=0x02ff, SecurityBufferOffset=124, SecurityBufferLength=len(security_blob),
                             SecurityBlob=security_blob, Capabilities=capabilities, MaxTransactSize=dataSize,
                             MaxReadSize=dataSize, MaxWriteSize=dataSize, SystemTime=systemtime,
                             ServerStartTime=serverStartTime)
                        smb_rsp_length = len(smb_rsp_paket) + len(smb_rsp_negotiate_body)
                    else:
                        smb_rsp_paket = SMBNegociate_Protocol_Response_Advanced_Security\
                            (Start="\xffSMB", PID=smb_PID, MID=smb_MID, DialectIndex=5, SecurityBlob=security_blob)
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
