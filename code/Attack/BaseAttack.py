import abc
import csv
import hashlib
import ipaddress
import os
import random
import random as rnd
import re
import socket
import sys
import tempfile
import time
import collections
import typing as t

import Lib.libpcapreader as pr
import lea
import numpy as np
import scapy.layers.inet as inet
import scapy.utils

import Lib.Utility as Util
import Core.Statistics as Statistics
import Core.TimestampController as tc
import Core.BandwidthController as bc

from Attack.Parameter import Parameter, Float, IntegerLimited


class BaseAttack(metaclass=abc.ABCMeta):
    """
    Abstract base class for all attack classes. Provides basic functionalities, like parameter validation.
    """

    #For AttackController
    # TODO: get rid of this
    ATTACK_DURATION = 'attack.duration'

    # General SRC and DST parameters
    IP_SOURCE = 'ip.src'
    IP_DESTINATION = 'ip.dst'
    MAC_SOURCE = 'mac.src'
    MAC_DESTINATION = 'mac.dst'

    # For TimestampController
    PACKETS_PER_SECOND = 'packets.per-second'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'
    INJECT_AFTER_PACKET = 'inject.after-pkt'

    # For BandwidthController
    BANDWIDTH_MAX = 'bandwidth.max'
    BANDWIDTH_MIN_LOCAL = 'bandwidth.min.local'
    BANDWIDTH_MIN_PUBLIC = 'bandwidth.min.public'

    ValuePair = collections.namedtuple('ValuePair', ['value', 'user_specified'])

    def __init__(self, name, description, attack_type):
        """
        To be called within the individual attack class to initialize the required parameters.

        :param name: The name of the attack class.
        :param description: A short description of the attack.
        :param attack_type: The type the attack belongs to, like probing/scanning, malware.
        """
        # Reference to statistics class
        self.statistics = Statistics.Statistics(None)

        try:
            # get_reply_delay
            self.all_min_latencies = self.statistics.process_db_query("SELECT minDelay FROM conv_statistics LIMIT 500;")
            self.all_max_latencies = self.statistics.process_db_query("SELECT maxDelay FROM conv_statistics LIMIT 500;")
            self.most_used_mss_value = self.statistics.get_most_used_mss_value()
            self.most_used_ttl_value = self.statistics.get_most_used_ttl_value()
            self.most_used_win_size = self.statistics.get_most_used_win_size()
            pkt_count = self.statistics.get_packet_count()
        except AttributeError:
            self.all_min_latencies = 0
            self.all_max_latencies = 0
            self.most_used_mss_value = 0
            self.most_used_ttl_value = 0
            self.most_used_win_size = 0
            pkt_count = 0

            # Class fields
        self.attack_name = name
        self.attack_description = description
        self.attack_type = attack_type
        self.params = [Parameter(self.INJECT_AT_TIMESTAMP, Float()),
                       Parameter(self.INJECT_AFTER_PACKET, IntegerLimited([0, pkt_count])),
                       Parameter(self.BANDWIDTH_MAX, Float()),
                       Parameter(self.BANDWIDTH_MIN_LOCAL, Float()),
                       Parameter(self.BANDWIDTH_MIN_PUBLIC, Float())]
        self.attack_start_utime = 0
        self.attack_end_utime = 0
        self.start_time = 0
        self.finish_time = 0
        self.packets = []
        self.total_pkt_num = 0
        self.exceeding_packets = 0
        self.path_attack_pcap = ""
        self.timestamp_controller = None
        self.bandwidth_controller = None
        self.last_packet = None
        self.full_interval = None
        self.previous_interval = 0
        self.sent_bytes = 0
        self.interval_count = 0
        self.buffer_size = 1000
        #self.packets = collections.deque(maxlen=self.buffer_size)

    def update_params(self, params):
        for new_param in params:
            index = None
            for old_param in self.params:
                if new_param.name == old_param.name:
                    index = self.params.index(old_param)
                    break
            if index is not None:
                self.params[index] = new_param
            else:
                self.params.append(new_param)

    def init_mutual_params(self):
        self.add_param_value(self.BANDWIDTH_MAX, 0)
        self.add_param_value(self.BANDWIDTH_MIN_LOCAL, 0)
        self.add_param_value(self.BANDWIDTH_MIN_PUBLIC, 0)

    def init_objects(self):
        timestamp = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        packet = self.get_param_value(self.INJECT_AFTER_PACKET)

        if timestamp is None:
            ts = pr.pcap_processor(self.statistics.pcap_filepath, "False", Util.RESOURCE_DIR, "").get_timestamp_mu_sec(int(packet))
            timestamp = (ts / 1000000)
            self.add_param_value(self.INJECT_AT_TIMESTAMP, timestamp)

        self.timestamp_controller = tc.TimestampController(self.get_param_value(self.INJECT_AT_TIMESTAMP),
                                                           self.get_param_value(self.PACKETS_PER_SECOND))
        self.bandwidth_controller = bc.BandwidthController(self.get_param_value(self.BANDWIDTH_MAX),
                                                           self.get_param_value(self.BANDWIDTH_MIN_LOCAL),
                                                           self.get_param_value(self.BANDWIDTH_MIN_PUBLIC),
                                                           self.statistics)

    def init_params(self):
        """
        Initialize all required parameters taking into account user supplied values. If no value is supplied,
        or if a user defined query is supplied, use a statistics object to do the calculations.
        A call to this function requires a call to 'set_statistics' first.
        """
        params_to_init = []
        for param in self.params:
            params_to_init.append(param.name)
        skipped = {}
        while len(params_to_init) != 0:
            param = params_to_init.pop(0)
            result = self.init_param(param)
            if result is False:
                val = 0
                if param in skipped.keys():
                    val = skipped[param]
                    if val > 1:
                        continue
                params_to_init.append(param)
                skipped.update({param: val+1})

    @abc.abstractmethod
    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with a default value specified in the specific attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        pass

    @abc.abstractmethod
    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        pass

    @abc.abstractmethod
    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """
        pass

    #########################################
    # HELPER METHODS
    #########################################

    @staticmethod
    def set_seed(seed):
        """
        :param seed: The random seed to be set.
        """
        seed_final = None
        if isinstance(seed, int):
            seed_final = seed
        elif isinstance(seed, str):
            if seed.isdigit():
                seed_final = int(seed)
            else:
                hashed_seed = hashlib.sha1(seed.encode()).digest()
                seed_final = int.from_bytes(hashed_seed, byteorder="little")

        if seed_final:
            random.seed(seed_final)
            np.random.seed(seed_final & 0xFFFFFFFF)

    def set_start_time(self) -> None:
        """
        Set the current time as global starting time.
        """
        self.start_time = time.time()

    def set_finish_time(self) -> None:
        """
        Set the current time as global finishing time.
        """
        self.finish_time = time.time()

    def get_packet_generation_time(self) -> float:
        """
        :return difference between starting and finishing time.
        """
        return self.finish_time - self.start_time

    def add_param_value(self, param, value, user_specified: bool = False) -> bool:
        """
        Adds the pair param : value to the dictionary of attack parameters. Prints and error message and skips the
        parameter if the validation fails.

        :param param: Name of the parameter that we wish to modify.
        :param value: The value we wish to assign to the specified parameter.
        :param user_specified: Whether the value was specified by the user (or left default)
        :return: None.
        """

        # by default no param is valid
        is_valid = False

        # get AttackParameters instance associated with param
        # for default values assigned in attack classes, like Parameter.PORT_OPEN
        if isinstance(param, str):
            param_name = param
        else:
            print("WARNING: Invalid attack parameter ({}). Ignoring.".format(param))
            return False

        if not user_specified and self.param_user_defined(param_name):
            return False

        # Verify validity of given value with respect to parameter type
        index = self.get_param_index(param_name)
        if index is None:
            print('WARNING: Parameter not available (\'{}\'). Ignoring'.format(str(param_name)))

        # a comma-separated lists must be split first
        if isinstance(value, str) and "," in value:
            if "'" in value:
                value = value.replace("'", "")
            value = value.replace(" ", "")
            value = value.split(",")

        # catch source IP = destination IP
        if (param_name == self.IP_SOURCE
            and self.param_equals(self.IP_DESTINATION, value)) \
                or (param_name == self.IP_DESTINATION
                    and self.param_equals(self.IP_SOURCE, value)):
            print("ERROR: Value " + str(value) + " of Parameter " + str(param_name) +
                  " can not be used for both source and destination. Generating random IP.")
            value = self.statistics.get_random_ip_address(ips=[value])

        # add value if validation was successful
        self.params[index].user_specified = user_specified
        self.params[index].value = value

        if self.params[index].value == value:
            is_valid = True

        return is_valid

    def get_param_value(self, param: str):
        """
        Returns the parameter value for a given parameter.

        :param param: The parameter whose value is wanted.
        :return: The parameter's value.
        """
        parameter = None
        for elem in self.params:
            if elem.name == param:
                return elem.value
        return None

    def get_param_index(self, param: str):
        """
        Returns index of parameter or None if not in list.

        :param param: name of the parameter
        :return: index of the parameter or None if not in list
        """
        i = None
        for elem in self.params:
            if elem.name == param:
                i = self.params.index(elem)
                break
        return i

    def param_exists(self, param_name: str) -> bool:
        """
        Returns whether the parameter value is specified.

        :param param_name: The parameter to look for.
        :return: True if the parameter is already specified, False if not.
        """
        index = self.get_param_index(param_name)
        return index is not None and self.params[index].value is not None

    def param_user_defined(self, param_name: str) -> bool:
        """
        Returns whether the parameter value was specified by the user or a given parameter.

        :param param_name: The parameter whose user-specified flag is wanted.
        :return: The parameter's user-specified flag.
        """
        index = self.get_param_index(param_name)
        return index is not None and self.params[index].user_specified

    def param_equals(self, param_name: str, value) -> bool:
        """
        Returns whether the parameter value equals the given value.

        :param param_name: The parameter to compare.
        :param value: The value to compare to.
        :return: True if the parameter is equal to the value, False if not.
        """
        param_value = self.get_param_value(param_name)
        return param_value is not None and param_value == value

    def check_parameters(self):
        """
        Checks whether all parameter values are defined. If a value is not defined, the application is terminated.
        However, this should not happen as all attack should define default parameter values.
        """
        # parameters which do not require default values
        non_obligatory_params = ['inject.after-pkt', 'number.attackers']
        for param in self.params:
            # checks whether all params have assigned values, INJECT_AFTER_PACKET must not be considered because the
            # timestamp derived from it is set to Parameter.INJECT_AT_TIMESTAMP
            if param.value is None and param.name not in non_obligatory_params:
                print("\033[91mERROR: Attack '" + self.attack_name + "' does not define the parameter '" +
                      str(param.name) + "'.\n The attack must define default values for all parameters."
                      + "\n Cannot continue attack generation.\033[0m")
                sys.exit(-1)

    def write_attack_pcap(self, packets: list, append_flag: bool = False, destination_path: str = None):
        """
        Writes the attack's packets into a PCAP file with a temporary filename.

        :return: The path of the written PCAP file.
        """
        # Only check params initially when attack generation starts
        if append_flag is False and destination_path is None:
            # Check if all req. parameters are set
            self.check_parameters()

        # Determine destination path
        if destination_path is not None and os.path.exists(destination_path):
            destination = destination_path
        else:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
            destination = temp_file.name

        # Write packets into pcap file
        pktdump = scapy.utils.PcapWriter(destination, append=append_flag)
        pktdump.write(packets)

        # Store pcap path and close file objects
        pktdump.close()

        return destination

    def get_reply_latency(self, ip_src, ip_dst, default: int=0, mode: str=None):
        """
        Gets the minimum and the maximum reply latency for all the connections of a specific IP.

        :param ip_src: The source IP for which to retrieve the reply latency.
        :param ip_dst: The destination IP for which to retrieve the reply latency.
        :param default: The default value to return if no latency could be calculated.
        :param mode: either "local" or "public"
        :return minimum and maximum latency
        """
        if not mode:
            mode = Util.get_network_mode(ip_src, ip_dst)
        minimum = {"local": 900, "public": 3000}

        if default != 0:
            minimum[mode] = default

        result = self.statistics.process_db_query\
                ("SELECT minLatency, maxLatency FROM ip_statistics WHERE ipAddress in ('{0}, {1}');".
                 format(ip_src, ip_dst))

        min_latency = minimum[mode]
        max_latency = minimum[mode]

        for ip in result:
            # retrieve minimum latency
            if ip[0]:
                retrieved = ip[0]
            else:
                retrieved = np.median(self.all_min_latencies)
            min_latency = min(min_latency, retrieved)

            # retrieve maximum latency
            if ip[1]:
                retrieved = ip[1]
            else:
                retrieved = np.median(self.all_max_latencies)
            max_latency = min(max_latency, retrieved)

        min_latency = int(min_latency) * 10 ** -6  # convert from micro to seconds
        max_latency = int(max_latency) * 10 ** -6
        return min_latency, max_latency

    def get_intermediate_timestamp(self, divisor: int=2, factor: int=1) -> int:
        """
        Calculates a timestamp, which lays within the input pcap.
        By default a timestamp in the middle of the pcap.

        :param divisor: The number of intervals in which the pcap length should be divided.
        :param factor: The number of the interval from which to get the timestamp.
        :return: The calculated timestamp.
        """
        start = Util.get_timestamp_from_datetime_str(self.statistics.get_pcap_timestamp_start())
        end = Util.get_timestamp_from_datetime_str(self.statistics.get_pcap_timestamp_end())
        if factor > divisor:
            print("Error: timestamp out of range (factor > divisor)")
            return start
        return start + ((end - start) / divisor) * factor

    def add_packet(self, pkt, ip_source, ip_destination):
        """

        :param pkt: the packet, which should be added to the packets list
        :param ip_source: the source IP
        :param ip_destination: the destination IP
        :return: 0 if request packet, 1 if reply packet, or 2 if packet was not added to packets
        """
        bytes = len(pkt)

        remaining_bytes, current_interval = \
            self.bandwidth_controller.get_remaining_bandwidth(pkt.time, ip_source, ip_destination)
        if self.previous_interval != current_interval:
            self.sent_bytes = 0
            self.interval_count += 1

        self.previous_interval = current_interval

        if current_interval != self.full_interval:
            remaining_bytes *= 1000
            remaining_bytes -= self.sent_bytes

            if remaining_bytes >= bytes:
                self.sent_bytes += bytes
                self.packets.append(pkt)
                self.total_pkt_num += 1
                if pkt['IP'].dst == ip_source:
                    return 1
                return 0
            else:
                print("Warning: generated attack packets exceeded bandwidth. Packets in interval {} "
                      "were omitted.".format(self.interval_count))
                self.full_interval = current_interval
                return 2

    def buffer_full(self):
        return (self.total_pkt_num > 0) and (self.total_pkt_num % self.buffer_size == 0) and (len(self.packets) > 0)

    def flush_packets(self):
        self.last_packet = self.packets[-1]
        self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
        self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)
        self.reset_packets()

    def reset_packets(self):
        self.packets = []

    @staticmethod
    def packets_to_convs(exploit_raw_packets):
        """
           Classifies a bunch of packets to conversations groups. A conversation is a set of packets go between host A
           (IP,port) to host B (IP,port)

           :param exploit_raw_packets: A set of packets contains several conversations.
           :return conversations: A set of arrays, each array contains the packet of specific conversation
           :return orderList_conversations: An array contains the conversations ids (IP_A,port_A, IP_b,port_B) in the
           order they appeared in the original packets.
           """
        conversations = {}
        order_list_conversations = []
        for pkt_num, pkt in enumerate(exploit_raw_packets):
            eth_frame = inet.Ether(pkt[0])

            ip_pkt = eth_frame.payload
            ip_dst = ip_pkt.getfieldval("dst")
            ip_src = ip_pkt.getfieldval("src")

            tcp_pkt = ip_pkt.payload
            port_dst = tcp_pkt.getfieldval("dport")
            port_src = tcp_pkt.getfieldval("sport")

            conv_req = (ip_src, port_src, ip_dst, port_dst)
            conv_rep = (ip_dst, port_dst, ip_src, port_src)
            if conv_req not in conversations and conv_rep not in conversations:
                pkt_list = [pkt]
                conversations[conv_req] = pkt_list
                # Order list of conv
                order_list_conversations.append(conv_req)
            else:
                if conv_req in conversations:
                    pkt_list = conversations[conv_req]
                    pkt_list.append(pkt)
                    conversations[conv_req] = pkt_list
                else:
                    pkt_list = conversations[conv_rep]
                    pkt_list.append(pkt)
                    conversations[conv_rep] = pkt_list
        return conversations, order_list_conversations

    @staticmethod
    def is_valid_ip_address(addr):
        """
        Checks if the IP address family is supported.

        :param addr: IP address to be checked.
        :return: Boolean
        """
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False

    @staticmethod
    def ip_src_dst_catch_equal(ip_source, ip_destination):
        """
        Exits if ip src and ip dst are equal or have an intersection.

        :param ip_source: source IP address.
        :param ip_destination: destination IP address.
        """
        if BaseAttack.ip_src_dst_equal_check(ip_source, ip_destination):
            print("ERROR: Invalid IP addresses; source IP is the same as destination IP: " + str(ip_destination) + ".")
            sys.exit(-1)

    @staticmethod
    def ip_src_dst_equal_check(ip_source, ip_destination):
        """
        Checks if the source IP and destination IP are equal.

        :param ip_source: source IP address.
        :param ip_destination: destination IP address.
        :return True if ip src and ip dst are equal or have an intersection. False if otherwise.
        """
        equal = False
        if isinstance(ip_source, list) and isinstance(ip_destination, list):
            for ip in ip_source:
                if ip in ip_destination:
                    equal = True
        elif isinstance(ip_source, list):
            if ip_destination in ip_source:
                equal = True
        elif isinstance(ip_destination, list):
            if ip_source in ip_destination:
                equal = True
        else:
            if ip_source == ip_destination:
                equal = True
        return equal

    @staticmethod
    def get_inter_arrival_time(packets, distribution: bool = False):
        """
        Gets the inter-arrival times array and its distribution of a set of packets.

        :param packets: the packets to extract their inter-arrival time.
        :param distribution: build distribution dictionary or not
        :return inter_arrival_times: array of the inter-arrival times
        :return dict: the inter-arrival time distribution as a histogram {inter-arrival time:frequency}
        """
        inter_arrival_times = []
        prvs_pkt_time = 0
        for index, pkt in enumerate(packets):
            timestamp = pkt[1].sec + pkt[1].usec / 10 ** 6

            if index == 0:
                prvs_pkt_time = timestamp
                inter_arrival_times.append(0)
            else:
                inter_arrival_times.append(timestamp - prvs_pkt_time)
                prvs_pkt_time = timestamp

        if distribution:
            # Build a distribution dictionary
            freq, values = np.histogram(inter_arrival_times, bins=20)
            dist_dict = {}
            for i, val in enumerate(values):
                if i < len(freq):
                    dist_dict[str(val)] = freq[i]
            return inter_arrival_times, dist_dict
        else:
            return inter_arrival_times

    @staticmethod
    def clean_white_spaces(str_param):
        """
        Delete extra backslash from white spaces. This function is used to process the payload of packets.

        :param str_param: the payload to be processed.
        """
        str_param = str_param.replace("\\n", "\n")
        str_param = str_param.replace("\\r", "\r")
        str_param = str_param.replace("\\t", "\t")
        str_param = str_param.replace("\\\'", "\'")
        return str_param

    def modify_http_header(self, str_tcp_seg, orig_target_uri, target_uri, orig_ip_dst, target_host):
        """
        Substitute the URI and HOST in a HTTP header with new values.

        :param str_tcp_seg: the payload to be processed.
        :param orig_target_uri: old URI
        :param target_uri: new URI
        :param orig_ip_dst: old host
        :param target_host: new host
        """
        if len(str_tcp_seg) > 0:
            # convert payload bytes to str => str = "b'..\\r\\n..'"
            str_tcp_seg = str_tcp_seg[2:-1]
            str_tcp_seg = str_tcp_seg.replace(orig_target_uri, target_uri)
            str_tcp_seg = str_tcp_seg.replace(orig_ip_dst, target_host)
            str_tcp_seg = self.clean_white_spaces(str_tcp_seg)
        return str_tcp_seg

    def get_ip_data(self, ip_address: str):
        """
        :param ip_address: the ip of which (packet-)data shall be returned
        :return: MSS, TTL and Window Size values of the given IP
        """
        # Set MSS (Maximum Segment Size) based on MSS distribution of IP address
        mss_dist = self.statistics.get_mss_distribution(ip_address)
        if len(mss_dist) > 0:
            mss_prob_dict = lea.Lea.fromValFreqsDict(mss_dist)
            mss_value = mss_prob_dict.random()
        else:
            mss_value = Util.handle_most_used_outputs(self.most_used_mss_value)

        # Set TTL based on TTL distribution of IP address
        ttl_dist = self.statistics.get_ttl_distribution(ip_address)
        if len(ttl_dist) > 0:
            ttl_prob_dict = lea.Lea.fromValFreqsDict(ttl_dist)
            ttl_value = ttl_prob_dict.random()
        else:
            ttl_value = Util.handle_most_used_outputs(self.most_used_ttl_value)

        # Set Window Size based on Window Size distribution of IP address
        win_dist = self.statistics.get_win_distribution(ip_address)
        if len(win_dist) > 0:
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
            win_value = win_prob_dict.random()
        else:
            win_value = Util.handle_most_used_outputs(self.most_used_win_size)

        return mss_value, ttl_value, win_value

    #########################################
    # RANDOM IP/MAC ADDRESS GENERATORS
    #########################################

    @staticmethod
    def generate_random_ipv4_address(ip_class, n: int = 1):
        # TODO: document ip_class
        """
        Generates n random IPv4 addresses.

        :param ip_class:
        :param n: The number of IP addresses to be generated
        :return: A single IP address, or if n>1, a list of IP addresses
        """

        def is_invalid(ip_address_param: ipaddress.IPv4Address):
            """
            TODO FILL ME
            :param ip_address_param:
            :return:
            """
            return ip_address_param.is_multicast or ip_address_param.is_unspecified or ip_address_param.is_loopback or \
                   ip_address_param.is_link_local or ip_address_param.is_reserved or ip_address_param.is_private

        # Generate a random IP from specific class
        def generate_address(ip_class_param):
            """
            TODO FILL ME
            :param ip_class_param:
            :return:
            """
            if ip_class_param == "Unknown":
                return ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1))
            else:
                # For DDoS attack, we do not generate private IPs
                if "private" in ip_class_param:
                    ip_class_param = ip_class_param[0]  # convert A-private to A
                ip_classes_byte1 = {"A": {1, 126}, "B": {128, 191}, "C": {192, 223}, "D": {224, 239}, "E": {240, 254}}
                temp = list(ip_classes_byte1[ip_class_param])
                min_b1 = temp[0]
                max_b1 = temp[1]
                b1 = random.randint(min_b1, max_b1)
                b2 = random.randint(1, 255)
                b3 = random.randint(1, 255)
                b4 = random.randint(1, 255)

                ip_address = ipaddress.IPv4Address(str(b1) + "." + str(b2) + "." + str(b3) + "." + str(b4))

            return ip_address

        ip_addresses = []
        for i in range(0, n):
            address = generate_address(ip_class)
            while is_invalid(address):
                address = generate_address(ip_class)
            ip_addresses.append(str(address))

        if n == 1:
            return ip_addresses[0]
        else:
            return ip_addresses

    @staticmethod
    def generate_random_ipv6_address(n: int = 1):
        """
        Generates n random IPv6 addresses.

        :param n: The number of IP addresses to be generated
        :return: A single IP address, or if n>1, a list of IP addresses
        """

        def is_invalid(ip_address: ipaddress.IPv6Address):
            """
            TODO FILL ME
            :param ip_address:
            :return:
            """
            return ip_address.is_multicast or ip_address.is_unspecified or ip_address.is_loopback or \
                   ip_address.is_link_local or ip_address.is_private or ip_address.is_reserved

        def generate_address():
            """
            TODO FILL ME
            :return:
            """
            return ipaddress.IPv6Address(random.randint(0, 2 ** 128 - 1))

        ip_addresses = []
        for i in range(0, n):
            address = generate_address()
            while is_invalid(address):
                address = generate_address()
            ip_addresses.append(str(address))

        if n == 1:
            return ip_addresses[0]
        else:
            return ip_addresses
        

    @staticmethod
    def get_unique_random_ipv4_from_ip_network(ip_address, subnet_mask, arg_chosen_ips=set()):
        """
        Generate a unique random IPv4 address within the specified IP network.

        Args:
            ip_network (str): The IP network in CIDR notation from which to generate the random IPv4 address.
            chosen_ips (set): A set of IPv4 addresses (as strings) that have already been chosen, to ensure uniqueness.

        Returns:
            str: A unique random IPv4 address within the specified IP network.
        """

        def get_ip_network(ip_address, subnet_mask):
            """
            Get the IP network in CIDR notation from an IPv4 address and a subnet mask.

            Args:
                ip_address (str): The IPv4 address in string format (e.g., "192.168.1.1").
                subnet_mask (str): The subnet mask in string format (e.g., "255.255.255.0").

            Returns:
                str: The IP network in CIDR notation (e.g., "192.168.1.0/24").
            """
            ipv4_address = ipaddress.IPv4Address(ip_address)
            ipv4_netmask = ipaddress.IPv4Address(subnet_mask)
            network_prefix = ipaddress.IPv4Network(f"{ipv4_address}/{ipv4_netmask}", strict=False)
            return str(network_prefix.network_address) + '/' + str(network_prefix.prefixlen)


        def is_invalid(ip_address_param: ipaddress.IPv4Address):
            """
            Check if generated IPv4Address is valid 
            NOTE: Private values are allowed  
            Args:
                ip_address_param (str): The IPv4Address to check for validity.
            Returns:
                bool: True when value is invalid .
            """
            return ip_address_param.is_multicast or ip_address_param.is_unspecified or ip_address_param.is_loopback or \
                ip_address_param.is_link_local or ip_address_param.is_reserved

        ip_network = get_ip_network(ip_address,subnet_mask)
        network = ipaddress.IPv4Network(ip_network, strict=False)
        in_use_ips_in_network = [ip for ip in arg_chosen_ips if ip!= '' and ipaddress.ip_address(ip) in network]
        in_use_ips_in_network = set(in_use_ips_in_network)
        available_ips = network.num_addresses - 2  # Excluding network and broadcast addresses
        if len(in_use_ips_in_network) >= available_ips:
            raise ValueError("No more unique IPs available in the specified range: {}".format(ip_network))
        while True:
            random_ip = network.network_address + random.randint(1, available_ips)
            random_ip_str = str(random_ip)

            if random_ip_str not in in_use_ips_in_network and not is_invalid(random_ip):
                in_use_ips_in_network.add(random_ip_str)
                return random_ip_str

    """
    Generates a unique random ephemeral port for a conversation with respect to direction & reserved_ports. 
    If ephemeral port for original port then the belonging (previously generataed ) ephemeral port is returned.   
     Args:
        tcp_pkt (Packet): Given TCP packet .
        ephemeral_ports (dict): A dictionary of ephemeral ports in use, keyed by the original port.
        reserved_ports (set): A set of reserved ports that should not be used for ephemeral ports.


    Returns:
        tuple: A tuple containing the new unique random ephemeral port and the updated ephemeral_ports dictionary.
    """
    def generate_ephemeral_ports(self,tcp_pkt, ephemeral_ports, reserved_ports):
        ep = tcp_pkt.getfieldval("sport")
        if ep in reserved_ports:   
            ep = tcp_pkt.getfieldval("dport")
            
        if ep not in ephemeral_ports: 
            ephemeral_ports[ep] = self.get_unique_random_ephemeral_port(chosen_ports=ephemeral_ports) 
        
        return ephemeral_ports[ep], ephemeral_ports


    """
    Generates a unique random ephemeral port.
    NOTE: Default values are based on Linux ephemeral port range. 
     Args:
        min_value (int): The lower bound (inclusive) of the ephemeral port range.
        max_value (int): The upper bound (inclusive) of the ephemeral port range.
        chosen_ints (set): A set of integers that have already been chosen, to ensure uniqueness.

    Returns:
        int: A unique random ephemeral port within the specified range.
    """
    @staticmethod    
    def get_unique_random_ephemeral_port(min_value=32768, max_value=61000, chosen_ports=set()):
        if(isinstance(chosen_ports,dict)):
            chosen_ports = chosen_ports.values() # check for unique values.    
        while True:
            random_int = rnd.randint(min_value, max_value) 
            if random_int not in chosen_ports:
                return random_int


    def update_seq_ack(self,tcp_pkt, payload_diff: int, source_dir: bool):
        '''
        This function updates the TCP packet's sequence (seq) or acknowledgment (ack) number based
        on the payload length difference and the direction of the packet.
        Args:
            tcp_pkt (scapy.layers.inet.TCP): the TCP packet.
            payload_diff (int): The difference in payload length after the update.
            source_dir (bool): If True, the function updates the sequence number (source direction).
                               If False, it updates the acknowledgment number (destination direction).
        '''
        seq = tcp_pkt.getfieldval("seq")
        ack = tcp_pkt.getfieldval("ack")
        
        if source_dir:
            tcp_pkt.setfieldval("seq", seq + payload_diff)
        else:  
            tcp_pkt.setfieldval("ack", ack + payload_diff)
        
    def update_ip_packet_len_and_checksums(self,ip_pkt):
        """
        This function updates the IP packet length and resets the IP and TCP checksums.
        Args:
            ip_pkt (scapy.layers.inet.IP): The IP packet whose length and checksums need to be updated.
        """
        ip_pkt.len = len(ip_pkt)
        ip_pkt.chksum = None
        ip_pkt.payload.chksum = None

    
    def get_window_distribution(self, ip_address):
        """
        This function retrieves the window size distribution for a given IP address. If no distribution is 
        found, it retrieves the distribution for the most used IP address. If still no distribution is found, it 
        retrieves the distribution for the IP with the most unique window sizes.

        :param ip_address: the IP address for which the window size distribution is to be retrieved.
        :return: A dictionary mapping window sizes to their counts for the selected IP.
        """

        ip_address_win_dist = self.statistics.get_win_distribution(ip_address)

        if not ip_address_win_dist:
            print("Warning: No window distribution found for the given IP. Retrieving for the most used IP...")
            ip_address_win_dist = self.statistics.get_win_distribution(self.statistics.get_most_used_ip_address())
            
        if not ip_address_win_dist:
            print("Warning: No window distribution found for the most used IP. Retrieving for the IP with most unique window sizes...")
            ip_address_win_dist = self.statistics.get_win_distribution_for_ip_with_win_sizes()

        if ip_address_win_dist:
            ip_address_win_prob_dict = lea.Lea.fromValFreqsDict(ip_address_win_dist)
            return ip_address_win_prob_dict
        else:
            print("Warning: No window distribution found. Using values from the attack script")
            return
    

    def generate_sql_victim_conv_param(self,ip_destination, subnet_mask="255.255.255.0"):
        """
        Generate mac & ip address for conv between sql and server  
        """ 
        ip_addresses_in_use = self.statistics.get_ip_addresses()
        ip_sql = self.get_unique_random_ipv4_from_ip_network(ip_destination, subnet_mask,ip_addresses_in_use)
        mac_sql = self.generate_random_mac_address() 
        return mac_sql, ip_sql

    """
    Generates a unique random ephemeral port.
    NOTE: Default values are based on Linux ephemeral port range. 
     Args:
        min_value (int): The lower bound (inclusive) of the ephemeral port range.
        max_value (int): The upper bound (inclusive) of the ephemeral port range.
        chosen_ports (set): A set of ports that have already been chosen, to ensure uniqueness.

    Returns:
        int: A unique random ephemeral port within the specified range.
    """
    @staticmethod    
    def get_unique_random_ephemeral_port(min_value=32768, max_value=61000, chosen_ports=set()):
        if(isinstance(chosen_ports,dict)):
            chosen_ports = chosen_ports.values() # check for unique values.    
        while True:
            random_int = rnd.randint(min_value, max_value) 
            if random_int not in chosen_ports:
                return random_int


    def get_mac_address(self, ip_address):
        """
        Get mac address to ip address, otherwise generate a random one.

        :param ip_address: the ip address for which the mac address is required
        :return: a mac address corresponding to the ip or a randomly generated one
        """
        if isinstance(ip_address, list):
            mac = list(self.statistics.get_mac_addresses(ip_address).values())
        else:
            mac = self.statistics.get_mac_address(ip_address)
        if not mac:
            mac = self.generate_random_mac_address()
        return mac

    @staticmethod
    def generate_random_mac_address(n: int = 1):
        """
        Generates n random MAC addresses.

        :param n: The number of MAC addresses to be generated.
        :return: A single MAC address, or if n>1, a list of MAC addresses
        """

        def is_invalid(address_param: str):
            first_octet = int(address_param[0:2], 16)
            is_multicast_address = bool(first_octet & 0b01)
            is_locally_administered = bool(first_octet & 0b10)
            return is_multicast_address or is_locally_administered

        def generate_address():
            # FIXME: cleanup
            mac = [random.randint(0x00, 0xff) for i in range(0, 6)]
            return ':'.join(map(lambda x: "%02x" % x, mac))

        mac_addresses = []
        for i in range(0, n):
            address = generate_address()
            while is_invalid(address):
                address = generate_address()
            mac_addresses.append(address)

        if n == 1:
            return mac_addresses[0]
        else:
            return mac_addresses

    @staticmethod
    def get_ports_from_nmap_service_dst(ports_num):
        """
        Read the most ports_num frequently open ports from nmap-service-tcp file to be used in the port scan.

        :return: Ports numbers to be used as default destination ports or default open ports in the port scan.
        """
        ports_dst = []
        file = open(Util.RESOURCE_DIR + 'nmap-services-tcp.csv', 'rt')
        spamreader = csv.reader(file, delimiter=',')
        for count in range(ports_num):
            # escape first row (header)
            next(spamreader)
            # save ports numbers
            ports_dst.append(next(spamreader)[0])
        file.close()
        # rnd.shuffle ports numbers partially
        if ports_num == 1000:  # used for port.dst
            # FIXME: cleanup
            temp_array = [[0 for i in range(10)] for i in range(100)]
            port_dst_shuffled = []
            for count in range(0, 10):
                temp_array[count] = ports_dst[count * 100:(count + 1) * 100]
                rnd.shuffle(temp_array[count])
                port_dst_shuffled += temp_array[count]
        else:  # used for port.open
            rnd.shuffle(ports_dst)
            port_dst_shuffled = ports_dst
        return port_dst_shuffled
