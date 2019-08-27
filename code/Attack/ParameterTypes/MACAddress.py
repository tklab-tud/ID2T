import re
import typing as t

from Attack.ParameterTypes.BaseType import ParameterType


class MACAddress(ParameterType):

    def __init__(self):
        super(MACAddress, self).__init__()
        self.name = "MACAddress"

    def validate(self, value: str) -> (bool, str):
        return MACAddress._is_mac_address(value), value

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
