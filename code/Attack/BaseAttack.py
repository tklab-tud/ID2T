import ipaddress
import os
import random
import re
import tempfile
from abc import abstractmethod, ABCMeta

import ID2TLib.libpcapreader as pr
from scapy.utils import PcapWriter

from Attack import AttackParameters
from Attack.AttackParameters import Parameter
from Attack.AttackParameters import ParameterTypes


class BaseAttack(metaclass=ABCMeta):
    """
    Abstract base class for all attack classes. Provides basic functionalities, like parameter validation.
    """

    def __init__(self, statistics, name, description, attack_type):
        """
        To be called within the individual attack class to initialize the required parameters.

        :param statistics: A reference to the Statistics class.
        :param name: The name of the attack class.
        :param description: A short description of the attack.
        :param attack_type: The type the attack belongs to, like probing/scanning, malware.
        """
        # Reference to statistics class
        self.statistics = statistics

        # Class fields
        self.attack_name = name
        self.attack_description = description
        self.attack_type = attack_type
        self.params = {}
        self.supported_params = {}
        self.attack_start_utime = 0
        self.attack_end_utime = 0

    @abstractmethod
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
    def _is_mac_address(mac_address: str):
        """
        Verifies if the given string is a valid MAC address. Accepts the formats 00:80:41:ae:fd:7e and 00-80-41-ae-fd-7e.

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
    def _is_ip_address(ip_address: str):
        """
        Verifies that the given string or list of IP addresses (strings) is a valid IPv4/IPv6 address.
        Accepts comma-separated lists of IP addresses, like "192.169.178.1, 192.168.178.2"

        :param ip_address: The IP address(es) as list of strings or comma-separated string.
        :return: True if all IP addresses are valid, otherwise False. And a list of IP addresses as string.
        """
        ip_address_output = []

        # a comma-separated list of IP addresses must be splitted first
        if isinstance(ip_address, str):
            ip_address = ip_address.split(',')

        for ip in ip_address:
            try:
                ipaddress.ip_address(ip)
                ip_address_output.append(ip)
            except ValueError:
                return False, ip_address_output

        if len(ip_address_output) == 1:
            return True, ip_address_output[0]
        else:
            return True, ip_address_output

    @staticmethod
    def _is_port(ports_input: str):
        """
        Verifies if the given value is a valid port. Accepts port ranges, like 80-90, 80..99, 80...99.

        :param ports_input: The port number as int or string.
        :return: True if the port number is valid, otherwise False. If a single port or a comma-separated list of ports
        was given, a list of int is returned. If a port range was given, the range is resolved
        and a list of int is returned.
        """

        def _is_invalid_port(num):
            """
            Checks whether the port number is invalid.

            :param num: The port number as int.
            :return: True if the port number is invalid, otherwise False.
            """
            return num < 1 or num > 65535

        if isinstance(ports_input, str):
            ports_input = ports_input.replace(' ', '').split(',')
        elif isinstance(ports_input, int):
            ports_input = [ports_input]

        ports_output = []

        for port_entry in ports_input:
            if isinstance(port_entry, int):
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            elif isinstance(port_entry, str) and port_entry.isdigit():
                # port_entry describes a single port
                port_entry = int(port_entry)
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            elif '-' in port_entry or '..' in port_entry:
                # port_entry describes a port range
                # allowed format: '1-49151', '1..49151', '1...49151'
                match = re.match('^([0-9]{1,5})(?:-|\.{2,3})([0-9]{1,5})$', port_entry)
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
    def _is_timestamp(timestamp: str):
        """
        Checks whether the given value is in a valid timestamp format. The accepted format is:
        YYYY-MM-DD h:m:s, whereas h, m, s may be one or two digits.

        :param timestamp: The timestamp to be checked.
        :return: True if the timestamp is valid, otherwise False.
        """
        is_valid = re.match('[0-9]{4}(?:-[0-9]{1,2}){2} (?:[0-9]{1,2}:){2}[0-9]{1,2}', timestamp)
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
            value = distutils.util.strtobool(value.lower())
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

    #########################################
    # HELPER METHODS
    #########################################

    def add_param_value(self, param, value):
        """
        Adds the pair param : value to the dictionary of attack parameters. Prints and error message and skips the
        parameter if the validation fails.

        :param param: The parameter name.
        :param value: The parameter's value.
        :return: None.
        """
        # by default no param is valid
        is_valid = False

        # get AttackParameters instance associated with param
        # for default values assigned in attack classes, like Parameter.PORT_OPEN
        if isinstance(param, AttackParameters.Parameter):
            param_name = param
        # for values given by user input, like port.open
        else:
            # Get Enum key of given string identifier
            param_name = AttackParameters.Parameter(param)

        # Get parameter type of attack's required_params
        param_type = self.supported_params.get(param_name)

        # Verify validity of given value with respect to parameter type
        if param_type is None:
            print('Parameter ' + str(param_name) + ' not available for chosen attack. Skipping parameter.')

        # If value is query -> get value from database
        elif self.statistics.is_query(value):
            value = self.statistics.process_db_query(value, False)
            if value is not None and value is not "":
                is_valid = True
            else:
                print('Error in given parameter value: ' + value + '. Data could not be retrieved.')

        # Validate parameter depending on parameter's type
        elif param_type == ParameterTypes.TYPE_IP_ADDRESS:
            is_valid, value = self._is_ip_address(value)
        elif param_type == ParameterTypes.TYPE_PORT:
            is_valid, value = self._is_port(value)
        elif param_type == ParameterTypes.TYPE_MAC_ADDRESS:
            is_valid = self._is_mac_address(value)
        elif param_type == ParameterTypes.TYPE_INTEGER_POSITIVE:
            if isinstance(value, int) and int(value) >= 0:
                is_valid = True
            elif isinstance(value, str) and value.isdigit() and int(value) >= 0:
                is_valid = True
                value = int(value)
        elif param_type == ParameterTypes.TYPE_FLOAT:
            is_valid, value = self._is_float(value)
            # this is required to avoid that the timestamp's microseconds of the first attack packet is '000000'
            # but microseconds are only chosen randomly if the given parameter does not already specify it
            # e.g. inject.at-timestamp=123456.987654 -> is not changed
            # e.g. inject.at-timestamp=123456 -> is changed to: 123456.[random digits]
            if param_name == Parameter.INJECT_AT_TIMESTAMP and is_valid and ((value - int(value)) == 0):
                value = value + random.uniform(0, 0.999999)
        elif param_type == ParameterTypes.TYPE_TIMESTAMP:
            is_valid = self._is_timestamp(value)
        elif param_type == ParameterTypes.TYPE_BOOLEAN:
            is_valid, value = self._is_boolean(value)
        elif param_type == ParameterTypes.TYPE_PACKET_POSITION:
            ts = pr.pcap_processor(self.statistics.pcap_filepath).get_timestamp_mu_sec(int(value))
            if 0 <= int(value) <= self.statistics.get_packet_count() and ts >= 0:
                is_valid = True
                param_name = Parameter.INJECT_AT_TIMESTAMP
                value = (ts / 1000000)  # convert microseconds from getTimestampMuSec into seconds

        # add value iff validation was successful
        if is_valid:
            self.params[param_name] = value
        else:
            print("ERROR: Parameter " + str(param) + " or parameter value " + str(value) +
                  " not valid. Skipping parameter.")

    def get_param_value(self, param: Parameter):
        """
        Returns the parameter value for a given parameter.

        :param param: The parameter whose value is wanted.
        :return: The parameter's value.
        """
        return self.params.get(param)

    def check_parameters(self):
        """
        Checks whether all parameter values are defined. If a value is not defined, the application is terminated.
        However, this should not happen as all attack should define default parameter values.
        """
        # parameters which do not require default values
        non_obligatory_params = [Parameter.INJECT_AFTER_PACKET, Parameter.NUMBER_ATTACKERS]
        for param, type in self.supported_params.items():
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
        pktdump = PcapWriter(destination, append=append_flag)
        pktdump.write(packets)

        # Store pcap path and close file objects
        pktdump.close()

        return destination

    #########################################
    # RANDOM IP/MAC ADDRESS GENERATORS
    #########################################

    @staticmethod
    def generate_random_ipv4_address(ipClass, n: int = 1):
        """
        Generates n random IPv4 addresses.
        :param n: The number of IP addresses to be generated
        :return: A single IP address, or if n>1, a list of IP addresses
        """

        def is_invalid(ipAddress: ipaddress.IPv4Address):
            return ipAddress.is_multicast or ipAddress.is_unspecified or ipAddress.is_loopback or \
                   ipAddress.is_link_local or ipAddress.is_reserved or ipAddress.is_private

        # Aidmar - generate a random IP from specific class
        #def generate_address():
        #    return ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1))
        def generate_address(ipClass):
            #print(ipClass)
            """if "private" in ipClass:
                ipClassesByte1 = {"A-private": 10, "B-private": 172, "C-private": 192}
                b1 = ipClassesByte1[ipClass]

                ipClassesByte2 = {"A-private": {0,255}, "B-private": {16,131}, "C-private": {168,168}}
                minB2 = ipClassesByte1[ipClass][0]
                maxB2 = ipClassesByte1[ipClass][1]
                b2 = random.randint(minB2, maxB2)

                b3b4 = random.randint(0, 2 ** 16 - 1)

                ipAddress = ipaddress.IPv4Address(str(b1)+str(b2)+str(b3b4))
            else:"""
            if ipClass == "Unknown":
                return ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1))
            else:
                # For DDoS attack, we do not generate private IPs
                if "private" in ipClass:
                    ipClass = ipClass[0] # convert A-private to A
                ipClassesByte1 = {"A": {1,126}, "B": {128,191}, "C":{192, 223}, "D":{224, 239}, "E":{240, 254}}
                temp = list(ipClassesByte1[ipClass])
                minB1 = temp[0]
                maxB1 = temp[1]
                b1 = random.randint(minB1, maxB1)
                b2 = random.randint(1, 255)
                b3 = random.randint(1, 255)
                b4 = random.randint(1, 255)

                ipAddress = ipaddress.IPv4Address(str(b1) +"."+ str(b2) + "." + str(b3) + "." + str(b4))

            return ipAddress


        ip_addresses = []
        for i in range(0, n):
            address = generate_address(ipClass)
            while is_invalid(address):
                address = generate_address(ipClass)
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

        def is_invalid(ipAddress: ipaddress.IPv6Address):
            return ipAddress.is_multicast or ipAddress.is_unspecified or ipAddress.is_loopback or \
                   ipAddress.is_link_local or ipAddress.is_private or ipAddress.is_reserved

        def generate_address():
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
        :return: A single MAC addres, or if n>1, a list of MAC addresses
        """

        def is_invalid(address: str):
            first_octet = int(address[0:2], 16)
            is_multicast_address = bool(first_octet & 0b01)
            is_locally_administered = bool(first_octet & 0b10)
            return is_multicast_address or is_locally_administered

        def generate_address():
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
