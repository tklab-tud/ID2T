import abc
import csv
import hashlib
import ipaddress
import math
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

import ID2TLib.libpcapreader as pr
import lea
import numpy as np
import scapy.layers.inet as inet
import scapy.utils

import Attack.AttackParameters as atkParam
import ID2TLib.Utility as Util


class BaseAttack(metaclass=abc.ABCMeta):
    """
    Abstract base class for all attack classes. Provides basic functionalities, like parameter validation.
    """

    ValuePair = collections.namedtuple('ValuePair', ['value', 'user_specified'])

    def __init__(self, name, description, attack_type):
        """
        To be called within the individual attack class to initialize the required parameters.

        :param name: The name of the attack class.
        :param description: A short description of the attack.
        :param attack_type: The type the attack belongs to, like probing/scanning, malware.
        """
        # Reference to statistics class
        self.statistics = None

        # Class fields
        self.attack_name = name
        self.attack_description = description
        self.attack_type = attack_type
        self.params = {}
        self.supported_params = {}
        self.attack_start_utime = 0
        self.attack_end_utime = 0
        self.start_time = 0
        self.finish_time = 0
        self.packets = []
        self.path_attack_pcap = ""

    def set_statistics(self, statistics):
        """
        Specify the statistics object that will be used to calculate the parameters of this attack.
        The statistics are used to calculate default parameters and to process user supplied
        queries.

        :param statistics: Reference to a statistics object.
        """
        self.statistics = statistics

    @abc.abstractmethod
    def init_params(self):
        """
        Initialize all required parameters taking into account user supplied values. If no value is supplied,
        or if a user defined query is supplied, use a statistics object to do the calculations.
        A call to this function requires a call to 'set_statistics' first.
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

    ################################################
    # HELPER VALIDATION METHODS
    # Used to validate the given parameter values
    ################################################

    @staticmethod
    def _is_mac_address(mac_address: t.Union[str, t.List[str]]) -> bool:
        """
        Verifies if the given string is a valid MAC address.
        Accepts the formats 00:80:41:ae:fd:7e and 00-80-41-ae-fd-7e.

        :param mac_address: The MAC address as string.
        :return: True if the MAC address is valid, otherwise False.
        """
        pattern = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', re.MULTILINE)
        if isinstance(mac_address, list):
            for mac in mac_address:
                if re.match(pattern, mac) is None:
                    return False
        else:
            if re.match(pattern, mac_address) is None:
                return False

        return True

    @staticmethod
    def _is_ip_address(ip_address: t.Union[str, t.List[str]]) -> t.Tuple[bool, t.Union[str, t.List[str]]]:
        """
        Verifies that the given string or list of IP addresses (strings) is a valid IPv4/IPv6 address.
        Accepts comma-separated lists of IP addresses, like "192.169.178.1, 192.168.178.2"

        :param ip_address: The IP address(es) as list of strings, comma-separated or dash-separated string.
        :return: True if all IP addresses are valid, otherwise False. And a list of IP addresses as string.
        """

        def append_ips(ip_address_input: t.List[str]) -> t.Tuple[bool, t.List[str]]:
            """
            Recursive appending function to handle lists and ranges of IP addresses.

            :param ip_address_input: The IP address(es) as list of strings, comma-separated or dash-separated string.
            :return: List of all given IP addresses.
            """
            ip_list = []
            is_valid = True
            for ip in ip_address_input:
                if '-' in ip:
                    ip_range = ip.split('-')
                    ip_range = Util.get_ip_range(ip_range[0], ip_range[1])
                    is_valid, ips = append_ips(ip_range)
                    ip_list.extend(ips)
                else:
                    try:
                        ipaddress.ip_address(ip)
                        ip_list.append(ip)
                    except ValueError:
                        return False, ip_list
            return is_valid, ip_list

        # a comma-separated list of IP addresses must be split first
        if isinstance(ip_address, str):
            ip_address = ip_address.split(',')

        result, ip_address_output = append_ips(ip_address)

        if len(ip_address_output) == 1:
            return result, ip_address_output[0]
        else:
            return result, ip_address_output

    @staticmethod
    def _is_port(ports_input: t.Union[t.List[str], t.List[int], str, int])\
            -> t.Union[bool, t.Tuple[bool, t.List[t.Union[int, str]]]]:
        """
        Verifies if the given value is a valid port. Accepts port ranges, like 80-90, 80..99, 80...99.

        :param ports_input: The port number as int or string.
        :return: True if the port number is valid, otherwise False. If a single port or a comma-separated list of ports
        was given, a list of int is returned. If a port range was given, the range is resolved
        and a list of int is returned.
        """

        def _is_invalid_port(num: int) -> bool:
            """
            Checks whether the port number is invalid.

            :param num: The port number as int.
            :return: True if the port number is invalid, otherwise False.
            """
            return num < 1 or num > 65535

        if ports_input is None or ports_input is "":
            return False

        if isinstance(ports_input, str):
            ports_input = ports_input.replace(' ', '').split(',')
        elif isinstance(ports_input, int):
            ports_input = [ports_input]
        elif len(ports_input) is 0:
            return False

        ports_output = []

        for port_entry in ports_input:
            if isinstance(port_entry, int):
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            # TODO: validate last condition
            elif isinstance(port_entry, str) and port_entry.isdigit():
                # port_entry describes a single port
                port_entry = int(port_entry)
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            elif '-' in port_entry or '..' in port_entry:
                # port_entry describes a port range
                # allowed format: '1-49151', '1..49151', '1...49151'
                match = re.match(r'^([0-9]{1,5})(?:-|\.{2,3})([0-9]{1,5})$', str(port_entry))
                # check validity of port range
                # and create list of ports derived from given start and end port
                (port_start, port_end) = int(match.group(1)), int(match.group(2))
                if _is_invalid_port(port_start) or _is_invalid_port(port_end):
                    return False
                else:
                    ports_list = [i for i in range(port_start, port_end + 1)]
                # append ports at ports_output list
                ports_output += ports_list

        if len(ports_output) == 1:
            return True, ports_output[0]
        else:
            return True, ports_output

    @staticmethod
    def _is_timestamp(timestamp: str) -> bool:
        """
        Checks whether the given value is in a valid timestamp format. The accepted format is:
        YYYY-MM-DD h:m:s, whereas h, m, s may be one or two digits.

        :param timestamp: The timestamp to be checked.
        :return: True if the timestamp is valid, otherwise False.
        """
        is_valid = re.match(r'[0-9]{4}(?:-[0-9]{1,2}){2} (?:[0-9]{1,2}:){2}[0-9]{1,2}', timestamp)
        return is_valid is not None

    @staticmethod
    def _is_boolean(value):
        """
        Checks whether the given value (string or bool) is a boolean. Strings are valid booleans if they are in:
        {y, yes, t, true, on, 1, n, no, f, false, off, 0}.

        :param value: The value to be checked.
        :return: True if the value is a boolean, otherwise false. And the casted boolean.
        """
        # If value is already a boolean
        if isinstance(value, bool):
            return True, value

        # If value is a string
        # True values are y, yes, t, true, on and 1;
        # False values are n, no, f, false, off and 0.
        # Raises ValueError if value is anything else.
        try:
            import distutils.core
            import distutils.util
            value = bool(distutils.util.strtobool(value.lower()))
            is_bool = True
        except ValueError:
            is_bool = False
        return is_bool, value

    @staticmethod
    def _is_float(value):
        """
        Checks whether the given value is a float.

        :param value: The value to be checked.
        :return: True if the value is a float, otherwise False. And the casted float.
        """
        try:
            value = float(value)
            return True, value
        except ValueError:
            return False, value

    @staticmethod
    def _is_domain(val: str) -> bool:
        """
        Verifies that the given string is a valid URI.

        :param val: The URI as string.
        :return: True if URI is valid, otherwise False.
        """
        domain = re.match(r'^(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$', val)
        return domain is not None

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

    def add_param_value(self, param, value, user_specified: bool = True) -> None:
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
        if isinstance(param, atkParam.Parameter):
            param_name = param
        # for values given by user input, like port.open
        else:
            # Get Enum key of given string identifier
            param_name = atkParam.Parameter(param)

        # Get parameter type of attack's required_params
        param_type = self.supported_params.get(param_name)

        # Verify validity of given value with respect to parameter type
        if param_type is None:
            print('Parameter ' + str(param_name) + ' not available for chosen attack. Skipping parameter.')

        # If value is query -> get value from database
        elif param_name != atkParam.Parameter.INTERVAL_SELECT_STRATEGY and self.statistics.is_query(value):
            value = self.statistics.process_db_query(value, False)
            if value is not None and value is not "":
                is_valid = True
            else:
                print('Error in given parameter value: ' + str(value) + '. Data could not be retrieved.')

        # Validate parameter depending on parameter's type
        elif param_type == atkParam.ParameterTypes.TYPE_IP_ADDRESS:
            is_valid, value = self._is_ip_address(value)
        elif param_type == atkParam.ParameterTypes.TYPE_PORT:
            is_valid, value = self._is_port(value)
        elif param_type == atkParam.ParameterTypes.TYPE_MAC_ADDRESS:
            is_valid = self._is_mac_address(value)
        elif param_type == atkParam.ParameterTypes.TYPE_INTEGER_POSITIVE:
            if isinstance(value, int) and int(value) >= 0:
                is_valid = True
            elif isinstance(value, str) and value.isdigit() and int(value) >= 0:
                is_valid = True
                value = int(value)
        elif param_type == atkParam.ParameterTypes.TYPE_STRING:
            if isinstance(value, str):
                is_valid = True
        elif param_type == atkParam.ParameterTypes.TYPE_FLOAT:
            is_valid, value = self._is_float(value)
            # this is required to avoid that the timestamp's microseconds of the first attack packet is '000000'
            # but microseconds are only chosen randomly if the given parameter does not already specify it
            # e.g. inject.at-timestamp=123456.987654 -> is not changed
            # e.g. inject.at-timestamp=123456 -> is changed to: 123456.[random digits]
            if param_name == atkParam.Parameter.INJECT_AT_TIMESTAMP and is_valid and ((value - int(value)) == 0):
                value = value + random.uniform(0, 0.999999)
        elif param_type == atkParam.ParameterTypes.TYPE_TIMESTAMP:
            is_valid = self._is_timestamp(value)
        elif param_type == atkParam.ParameterTypes.TYPE_BOOLEAN:
            is_valid, value = self._is_boolean(value)
        elif param_type == atkParam.ParameterTypes.TYPE_PACKET_POSITION:
            # This function call is valid only if there is a statistics object available.
            if self.statistics is None:
                print('Error: Statistics-dependent attack parameter added without setting a statistics object first.')
                exit(1)

            ts = pr.pcap_processor(self.statistics.pcap_filepath, "False").get_timestamp_mu_sec(int(value))
            if 0 <= int(value) <= self.statistics.get_packet_count() and ts >= 0:
                is_valid = True
                param_name = atkParam.Parameter.INJECT_AT_TIMESTAMP
                value = (ts / 1000000)  # convert microseconds from getTimestampMuSec into seconds
        elif param_type == atkParam.ParameterTypes.TYPE_DOMAIN:
            is_valid = self._is_domain(value)
        elif param_type == atkParam.ParameterTypes.TYPE_FILEPATH:
            is_valid = os.path.isfile(value)
        elif param_type == atkParam.ParameterTypes.TYPE_PERCENTAGE:
            is_valid_float, value = self._is_float(value)
            if is_valid_float:
                is_valid = 0 <= value <= 1
            else:
                is_valid = False
        elif param_type == atkParam.ParameterTypes.TYPE_PADDING:
            if isinstance(value, int):
                is_valid = 0 <= value <= 100
            elif isinstance(value, str) and value.isdigit():
                value = int(value)
                is_valid = 0 <= value <= 100
        elif param_type == atkParam.ParameterTypes.TYPE_INTERVAL_SELECT_STRAT:
            is_valid = value in {"random", "optimal", "custom"}

        # add value iff validation was successful
        if is_valid:
            self.params[param_name] = self.ValuePair(value, user_specified)
        else:
            print("ERROR: Parameter " + str(param) + " or parameter value " + str(value) +
                  " not valid. Skipping parameter.")

    def get_param_value(self, param: atkParam.Parameter):
        """
        Returns the parameter value for a given parameter.

        :param param: The parameter whose value is wanted.
        :return: The parameter's value.
        """
        parameter = self.params.get(param)
        if parameter is not None:
            return parameter.value
        else:
            return None

    def get_param_user_specified(self, param: atkParam.Parameter) -> bool:
        """
        Returns whether the parameter value was specified by the user for a given parameter.

        :param param: The parameter whose user-specified flag is wanted.
        :return: The parameter's user-specified flag.
        """
        parameter = self.params.get(param)
        if parameter is not None:
            return parameter.user_specified
        else:
            return False

    def check_parameters(self):
        """
        Checks whether all parameter values are defined. If a value is not defined, the application is terminated.
        However, this should not happen as all attack should define default parameter values.
        """
        # parameters which do not require default values
        non_obligatory_params = [atkParam.Parameter.INJECT_AFTER_PACKET, atkParam.Parameter.NUMBER_ATTACKERS]
        for param, param_type in self.supported_params.items():
            # checks whether all params have assigned values, INJECT_AFTER_PACKET must not be considered because the
            # timestamp derived from it is set to Parameter.INJECT_AT_TIMESTAMP
            if param not in self.params.keys() and param not in non_obligatory_params:
                print("\033[91mCRITICAL ERROR: Attack '" + self.attack_name + "' does not define the parameter '" +
                      str(param) + "'.\n The attack must define default values for all parameters."
                      + "\n Cannot continue attack generation.\033[0m")
                import sys
                sys.exit(0)

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

    def get_reply_delay(self, ip_dst, default=2000):
        """
           Gets the minimum and the maximum reply delay for all the connections of a specific IP.

           :param ip_dst: The IP to reterive its reply delay.
           :param default: The default value to return if no delay could be fount. If < 0 raise an exception instead
           :return minDelay: minimum delay
           :return maxDelay: maximum delay

           """
        result = self.statistics.process_db_query(
            "SELECT AVG(minDelay), AVG(maxDelay) FROM conv_statistics WHERE ipAddressB='" + ip_dst + "';")
        if result[0][0] and result[0][1]:
            min_delay = result[0][0]
            max_delay = result[0][1]
        else:
            all_min_delays = self.statistics.process_db_query("SELECT minDelay FROM conv_statistics LIMIT 500;")
            min_delay = np.median(all_min_delays)
            all_max_delays = self.statistics.process_db_query("SELECT maxDelay FROM conv_statistics LIMIT 500;")
            max_delay = np.median(all_max_delays)

            if math.isnan(min_delay):  # max_delay is nan too then
                if default < 0:
                    raise ValueError("Could not calculate min/max_delay")

                min_delay = default
                max_delay = default

        min_delay = int(min_delay) * 10 ** -6  # convert from micro to seconds
        max_delay = int(max_delay) * 10 ** -6
        return min_delay, max_delay

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
    def ip_src_dst_equal_check(ip_source, ip_destination):
        """
        Checks if the source IP and destination IP are equal.

        :param ip_source: source IP address.
        :param ip_destination: destination IP address.
        """
        equal = False
        if isinstance(ip_source, list):
            if ip_destination in ip_source:
                equal = True
        else:
            if ip_source == ip_destination:
                equal = True
        if equal:
            print("\nERROR: Invalid IP addresses; source IP is the same as destination IP: " + ip_destination + ".")
            sys.exit(0)

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
            timestamp = pkt[2][0] + pkt[2][1] / 10 ** 6

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
            mss_value = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(mssValue)"))

        # Set TTL based on TTL distribution of IP address
        ttl_dist = self.statistics.get_ttl_distribution(ip_address)
        if len(ttl_dist) > 0:
            ttl_prob_dict = lea.Lea.fromValFreqsDict(ttl_dist)
            ttl_value = ttl_prob_dict.random()
        else:
            ttl_value = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(ttlValue)"))

        # Set Window Size based on Window Size distribution of IP address
        win_dist = self.statistics.get_win_distribution(ip_address)
        if len(win_dist) > 0:
            win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
            win_value = win_prob_dict.random()
        else:
            win_value = Util.handle_most_used_outputs(self.statistics.process_db_query("most_used(winSize)"))

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
