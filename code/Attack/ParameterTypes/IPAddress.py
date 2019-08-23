import ipaddress
import typing as t

import ID2TLib.Utility as Util

from Attack.ParameterTypes.String import String


class IPAddress(String):

    def __init__(self, *args):
        super(String, self).__init__(*args)
        self.name = "IPAddress"

    def validate(self, value: str) -> (bool, str):
        is_valid, value = IPAddress._is_ip_address(value)
        return is_valid, value

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
                    if not ip_range:
                        is_valid = False
                    is_valid, ips = append_ips(ip_range)
                    ip_list.extend(ips)
                else:
                    try:
                        ipaddress.ip_address(ip)
                        ip_list.append(ip)
                    except ValueError:
                        return False, ip_list
            return is_valid, ip_list

        if not isinstance(ip_address, list):
            ip_address = [ip_address]

        result, ip_address_output = append_ips(ip_address)

        if len(ip_address_output) == 1:
            return result, ip_address_output[0]
        else:
            return result, ip_address_output
