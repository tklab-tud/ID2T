import re


class IPAddress:
    """
    A simple class encapsulating an ip-address. An IPAddress can be constructed by string, int and 4-element-list
    (e.g. [8, 8, 8, 8]). This is a lightweight class as it only contains string-to-ip-and-reverse-conversion
    and some convenience methods.
    """

    # a number between 0 and 255, no leading zeros
    _IP_NUMBER_REGEXP = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    # 4 numbers between 0 and 255, joined together with dots
    IP_REGEXP = r"{0}\.{0}\.{0}\.{0}".format(_IP_NUMBER_REGEXP)

    def __init__(self, intlist: "list[int]") -> None:
        """
        Construct an ipv4-address with a list of 4 integers, e.g. to construct the ip 10.0.0.0 pass [10, 0, 0, 0]
        """
        if not isinstance(intlist, list) or not all(isinstance(n, int) for n in intlist):
            raise TypeError("The first constructor argument must be an list of ints")
        if not len(intlist) == 4 or not all(0 <= n <= 255 for n in intlist):
            raise ValueError("The integer list must contain 4 ints in range of 0 and 255, like an ip-address")

        # For easier calculations store the ip as integer, e.g. 10.0.0.0 is 0x0a000000
        self.ipnum = int.from_bytes(bytes(intlist), "big")

    @staticmethod
    def parse(ip: str) -> "IPAddress":
        """
        Parse an ip-address-string. If the string does not comply to the ipv4-format a ValueError is raised
        :param ip: A string-representation of an ip-address, e.g. "10.0.0.0"
        :return: IPAddress-object describing the ip-address
        """
        match = re.match("^" + IPAddress.IP_REGEXP + "$", ip)
        if not match:
            raise ValueError("%s is no ipv4-address" % ip)

        # the matches we get are the numbers of the ip-address (match 0 is the whole ip-address)
        numbers = [int(match.group(i)) for i in range(1, 5)]
        return IPAddress(numbers)

    @staticmethod
    def from_int(numeric: int) -> "IPAddress":
        if numeric not in range(1 << 32):
            raise ValueError("numeric value must be in uint-range")

        # to_bytes is the easiest way to split a 32-bit int into bytes
        return IPAddress(list(numeric.to_bytes(4, "big")))

    @staticmethod
    def is_ipv4(ip: str) -> bool:
        """
        Check if the supplied string is in ipv4-format
        """

        match = re.match("^" + IPAddress.IP_REGEXP + "$", ip)
        return True if match else False

    def to_int(self) -> int:
        """
        Convert the ip-address to a 32-bit uint, e.g. IPAddress.parse("10.0.0.255").to_int() returns 0x0a0000ff
        """
        return self.ipnum

    def is_private(self) -> bool:
        """
        Returns a boolean indicating if the ip-address lies in the private ip-segments (see ReservedIPBlocks)
        """
        return ReservedIPBlocks.is_private(self)

    def get_private_segment(self) -> bool:
        """
        Return the private ip-segment the ip-address belongs to (there are several)
        If this ip does not belong to a private ip-segment a ValueError is raised
        :return: IPAddressBlock
        """
        return ReservedIPBlocks.get_private_segment(self)

    def is_localhost(self) -> bool:
        """
        Returns a boolean indicating if the ip-address lies in the localhost-segment
        """
        return ReservedIPBlocks.is_localhost(self)

    def is_multicast(self) -> bool:
        """
        Returns a boolean indicating if the ip-address lies in the multicast-segment
        """
        return ReservedIPBlocks.is_multicast(self)

    def is_reserved(self) -> bool:
        """
        Returns a boolean indicating if the ip-address lies in the reserved-segment
        """
        return ReservedIPBlocks.is_reserved(self)

    def is_zero_conf(self) -> bool:
        """
        Returns a boolean indicating if the ip-address lies in the zeroconf-segment
        """
        return ReservedIPBlocks.is_zero_conf(self)

    def _tuple(self) -> (int, int, int, int):
        return tuple(self.ipnum.to_bytes(4, "big"))

    def __repr__(self) -> str:
        """
        Following the python style guide, eval(repr(obj)) should equal obj
        """
        return "IPAddress([%i, %i, %i, %i])" % self._tuple()

    def __str__(self) -> str:
        """
        Return the ip-address described by this object in ipv4-format
        """
        return "%i.%i.%i.%i" % self._tuple()

    def __hash__(self) -> int:
        return self.ipnum

    def __eq__(self, other) -> bool:
        if other is None:
            return False

        return isinstance(other, IPAddress) and self.ipnum == other.ipnum

    def __lt__(self, other) -> bool:
        if other is None:
            raise TypeError("Cannot compare to None")
        if not isinstance(other, IPAddress):
            raise NotImplemented  # maybe other can compare to self

        return self.ipnum < other.ipnum

    def __int__(self) -> bool:
        return self.ipnum


class IPAddressBlock:
    """
    This class describes a block of IPv4-addresses, just as a string in CIDR-notation does.
    It can be seen as a range of ip-addresses. To check if a block contains a ip-address
    simply use "ip in ip_block"
    """

    # this regex describes CIDR-notation (an ip-address plus "/XX", whereas XX is a number between 1 and 32)
    CIDR_REGEXP = IPAddress.IP_REGEXP + r"(\/(3[0-2]|[12]?\d)|)?"

    def __init__(self, ip: "Union(str, list, IPAddress)", netmask=32) -> None:
        """
        Construct a ip-block given a ip-address and a netmask. Given an ip and a netmask,
        the constructed ip-block will describe the range ip/netmask (e.g. 127.0.0.1/8)
        :param ip: An ip-address, represented as IPAddress, string or 4-element-list
        """
        if isinstance(ip, str):
            ip = IPAddress.parse(ip)
        elif isinstance(ip, list):
            ip = IPAddress(ip)

        if not 1 <= netmask <= 32:
            raise ValueError("netmask must lie between 1 and 32")

        # clear the unnecessary bits in the base-ip, e.g. this will convert 10.0.0.255/24 to 10.0.0.0/24 which are equivalent
        self.ipnum = ip.to_int() & self._bitmask(netmask)
        self.netmask = netmask

    @staticmethod
    def parse(cidr: str) -> "IPAddressBlock":
        """
        Parse a string in cidr-notation and return a IPAddressBlock describing the ip-segment
        If the string is not in cidr-notation a ValueError is raised
        """

        match = re.match("^" + IPAddressBlock.CIDR_REGEXP + "$", cidr)
        if not match:
            raise ValueError("%s is no valid cidr-notation" % cidr)

        ip = [int(match.group(i)) for i in range(1, 5)]
        suffix = 32 if not match.group(6) else int(match.group(6))

        return IPAddressBlock(ip, suffix)

    def block_size(self) -> int:
        """
        Return the size of the ip-address-block. E.g. the size of someip/24 is 256
        """
        return 2 ** (32 - self.netmask)

    def first_address(self) -> IPAddress:
        """
        Return the first ip-address of the ip-block
        """
        return IPAddress.from_int(self.ipnum)

    def last_address(self) -> IPAddress:
        """
        Return the last ip-address of the ip-block
        """
        return IPAddress.from_int(self.ipnum + self.block_size() - 1)

    def _bitmask(self, netmask: int) -> int:
        ones = lambda x: (1 << x) - 1

        return ones(32) ^ ones(32 - netmask)

    def __repr__(self) -> str:
        """
        Conforming to python style-guide, eval(repr(obj)) equals obj
        """
        return "IPAddressBlock(%s, %i)" % (repr(IPAddress.from_int(self.ipnum)), self.netmask)

    def __str__(self) -> str:
        """
        Return a string in cidr-notation
        """
        return str(IPAddress.from_int(self.ipnum)) + "/" + str(self.netmask)

    def __contains__(self, ip: IPAddress) -> bool:
        return (ip.to_int() & self._bitmask(self.netmask)) == self.ipnum


class ReservedIPBlocks:
    """
    To avoid magic values and save developers some research this class contains several constants
    describing special network-segments and some is_-methods to check if an ip is in the specified segment.
    """

    # a list of ip-addresses that can be used in private networks
    PRIVATE_IP_SEGMENTS = [
        IPAddressBlock.parse(block)
        for block in
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ]

    LOCALHOST_SEGMENT = IPAddressBlock.parse("127.0.0.0/8")

    MULTICAST_SEGMENT = IPAddressBlock.parse("224.0.0.0/4")
    RESERVED_SEGMENT = IPAddressBlock.parse("240.0.0.0/4")

    ZERO_CONF_SEGMENT = IPAddressBlock.parse("169.254.0.0/16")

    @staticmethod
    def is_private(ip: IPAddress) -> bool:
        return any(ip in block for block in ReservedIPBlocks.PRIVATE_IP_SEGMENTS)

    @staticmethod
    def get_private_segment(ip: IPAddress) -> "Optional[IPAddressBlock]":
        if not ReservedIPBlocks.is_private(ip):
            raise ValueError("%s is not part of a private IP segment" % ip)

        for block in ReservedIPBlocks.PRIVATE_IP_SEGMENTS:
            if ip in block:
                return block

    @staticmethod
    def is_localhost(ip: IPAddress) -> bool:
        return ip in ReservedIPBlocks.LOCALHOST_SEGMENT

    @staticmethod
    def is_multicast(ip: IPAddressBlock) -> bool:
        return ip in ReservedIPBlocks.MULTICAST_SEGMENT

    @staticmethod
    def is_reserved(ip: IPAddress) -> bool:
        return ip in ReservedIPBlocks.RESERVED_SEGMENT

    @staticmethod
    def is_zero_conf(ip: IPAddressBlock) -> bool:
        return ip in ReservedIPBlocks.ZERO_CONF_SEGMENT
