import ipaddress

from random import randint, uniform
from os import urandom
from datetime import datetime
from calendar import timegm
from lea import Lea

platforms = {"win7", "win10", "winxp", "win8.1", "macos", "linux", "win8", "winvista", "winnt", "win2000"}
platform_probability = {"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94, "linux": 3.38,
                        "win8": 1.35, "winvista": 0.46, "winnt": 0.31}

x86_nops = {b'\x90', b'\xfc', b'\xfd', b'\xf8', b'\xf9', b'\xf5', b'\x9b'}
x86_pseudo_nops = {b'\x97', b'\x96', b'\x95', b'\x93', b'\x92', b'\x91', b'\x99', b'\x4d', b'\x48', b'\x47', b'\x4f',
                   b'\x40', b'\x41', b'\x37', b'\x3f', b'\x27', b'\x2f', b'\x46', b'\x4e', b'\x98', b'\x9f', b'\x4a',
                   b'\x44', b'\x42', b'\x43', b'\x49', b'\x4b', b'\x45', b'\x4c', b'\x60', b'\x0e', b'\x1e', b'\x50',
                   b'\x55', b'\x53', b'\x51', b'\x57', b'\x52', b'\x06', b'\x56', b'\x54', b'\x16', b'\x58', b'\x5d',
                   b'\x5b', b'\x59', b'\x5f', b'\x5a', b'\x5e', b'\xd6'}
forbidden_chars = [b'\x00', b'\x0a', b'\x0d']


def update_timestamp(timestamp, pps, delay=0):
    """
    Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

    :return: Timestamp to be used for the next packet.
    """
    if delay == 0:
        # Calculate request timestamp
        # To imitate the bursty behavior of traffic
        randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 20, 5 / pps: 7, 10 / pps: 3})
        return timestamp + uniform(1 / pps, randomdelay.random())
    else:
        # Calculate reply timestamp
        randomdelay = Lea.fromValFreqsDict({2 * delay: 70, 3 * delay: 20, 5 * delay: 7, 10 * delay: 3})
        return timestamp + uniform(1 / pps + delay, 1 / pps + randomdelay.random())


def get_interval_pps(complement_interval_pps, timestamp):
    """
    Gets the packet rate (pps) for a specific time interval.

    :param complement_interval_pps: an array of tuples (the last timestamp in the interval, the packet rate in the
    corresponding interval).
    :param timestamp: the timestamp at which the packet rate is required.
    :return: the corresponding packet rate (pps) .
    """
    for row in complement_interval_pps:
        if timestamp<=row[0]:
            return row[1]
    return complement_interval_pps[-1][1] # in case the timstamp > capture max timestamp


def get_nth_random_element(*element_list):
    """
    Returns the n-th element of every list from an arbitrary number of given lists.
    For example, list1 contains IP addresses, list 2 contains MAC addresses. Use of this function ensures that
    the n-th IP address uses always the n-th MAC address.
    :param element_list: An arbitrary number of lists.
    :return: A tuple of the n-th element of every list.
    """
    range_max = min([len(x) for x in element_list])
    if range_max > 0: range_max -= 1
    n = randint(0, range_max)
    return tuple(x[n] for x in element_list)


def index_increment(number: int, max: int):
            if number + 1 < max:
                return number + 1
            else:
                return 0


def get_rnd_os():
    """
    Chooses random platform over an operating system probability distribution

    :return: random platform as string
    """
    os_dist = Lea.fromValFreqsDict(platform_probability)
    return os_dist.random()


def check_platform(platform: str):
    """
    Checks if the given platform is currently supported
    if not exits with error

    :param platform: the platform, which should be validated
    """
    if platform not in platforms:
        print("\nERROR: Invalid platform: " + platform + "." +
              "\n Please select one of the following platforms: ", platforms)
        exit(1)


def get_ip_range(start_ip: str, end_ip: str):
    """
    Generates a list of IPs of a given range. If the start_ip is greater than the end_ip, the reverse range is generated

    :param start_ip: the start_ip of the desired IP-range
    :param end_ip:  the end_ip of the desired IP-range
    :return: a list of all IPs in the desired IP-range, including start-/end_ip
    """
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


def generate_source_port_from_platform(platform: str, previousPort=0):
    """
    Generates the next source port according to the TCP-port-selection strategy of the given platform

    :param platform: the platform for which to generate source ports
    :param previousPort: the previously used/generated source port. Must be 0 if no port was generated before
    :return: the next source port for the given platform
    """
    check_platform(platform)
    if platform in {"winnt", "winxp", "win2000"}:
        if (previousPort == 0) or (previousPort + 1 > 5000):
            return randint(1024, 5000)
        else:
            return previousPort + 1
    elif platform == "linux":
        return randint(32768, 61000)
    else:
        if (previousPort == 0) or (previousPort + 1 > 65535):
            return randint(49152, 65535)
        else:
            return previousPort + 1


def get_filetime_format(timestamp):
    """
    Converts a timestamp into MS FILETIME format

    :param timestamp: a timestamp in seconds
    :return: MS FILETIME timestamp
    """
    boot_datetime = datetime.fromtimestamp(timestamp)
    if boot_datetime.tzinfo is None or boot_datetime.tzinfo.utcoffset(boot_datetime) is None:
        boot_datetime = boot_datetime.replace(tzinfo=boot_datetime.tzname())
    boot_filetime = 116444736000000000 + (timegm(boot_datetime.timetuple()) * 10000000)
    return boot_filetime + (boot_datetime.microsecond * 10)


def get_rnd_boot_time(timestamp, platform="winxp"):
    """
    Generates a random boot time based on a given timestamp and operating system

    :param timestamp: a timestamp in seconds
    :param platform: a platform as string as specified in check_platform above. default is winxp. this param is optional
    :return: timestamp of random boot time in seconds since EPOCH
    """
    check_platform(platform)
    if platform is "linux":
        uptime_in_days = Lea.fromValFreqsDict({3: 50, 7: 25, 14: 12.5, 31: 6.25, 92: 3.125, 183: 1.5625,
                                               365: 0.78125, 1461: 0.390625, 2922: 0.390625})
    elif platform is "macos":
        uptime_in_days = Lea.fromValFreqsDict({7: 50, 14: 25, 31: 12.5, 92: 6.25, 183: 3.125, 365: 3.076171875,
                                               1461: 0.048828125})
    else:
        uptime_in_days = Lea.fromValFreqsDict({3: 50, 7: 25, 14: 12.5, 31: 6.25, 92: 3.125, 183: 1.5625,
                                               365: 0.78125, 1461: 0.78125})
    timestamp -= randint(0, uptime_in_days.random()*86400)
    return timestamp


def get_rnd_x86_nop(count=1, side_effect_free=False, char_filter=set()):
    """
    Generates a specified number of x86 single-byte (pseudo-)NOPs

    :param count: The number of bytes to generate
    :param side_effect_free: Determines whether NOPs with side-effects (to registers or the stack) are allowed
    :param char_filter: A set of bytes which are forbidden to generate
    :return: Random x86 NOP bytestring
    """
    result = b''
    nops = x86_nops.copy()
    if not side_effect_free:
        nops |= x86_pseudo_nops.copy()

    if not isinstance(char_filter, set):
        char_filter = set(char_filter)
    nops = list(nops-char_filter)

    for i in range(0, count):
        result += nops[randint(0, len(nops) - 1)]
    return result


def get_rnd_bytes(count=1, ignore=None):
    """
    Generates a specified number of random bytes while excluding unwanted bytes

    :param count: Number of wanted bytes
    :param ignore: The bytes, which should be ignored, as an array
    :return: Random bytestring
    """
    if ignore is None:
        ignore = []
    result = b''
    for i in range(0, count):
        char = urandom(1)
        while char in ignore:
            char = urandom(1)
        result += char
    return result


def check_payload_len(payload_len: int, limit: int):
    """
    Checks if the len of the payload exceeds a given limit
    :param payload_len: The length of the payload
    :param limit: The limit of the length of the payload which is allowed
    """

    if payload_len > limit:
        print("\nCustom payload too long: ", payload_len, " bytes. Should be a maximum of ", limit, " bytes.")
        exit(1)

def get_bytes_from_file(filepath):
    """
    Converts the content of a file into its byte representation
    The content of the file can either be a string or hexadecimal numbers/bytes (e.g. shellcode)
    The file must have the keyword "str" or "hex" in its first line to specify the rest of the content
    If the content is hex, whitespaces, backslashes, "x", quotation marks and "+" are removed
    Example for a hexadecimal input file:

        hex
        "abcd ef \xff10\ff 'xaa' x \ ab"

    Output: b'\xab\xcd\xef\xff\x10\xff\xaa\xab'

    :param filepath: The path of the file from which to get the bytes
    :return: The bytes of the file (either a byte representation of a string or the bytes contained in the file)
    """
    try:
        file = open(filepath)
        result_bytes = b''
        header = file.readline().strip()
        content = file.read()

        if header == "hex":
            content = content.replace(" ", "").replace("\n", "").replace("\\", "").replace("x", "").replace("\"", "")\
                .replace("'", "").replace("+", "").replace("\r", "")
            try:
                result_bytes = bytes.fromhex(content)
            except ValueError:
                print("\nERROR: Content of file is not all hexadecimal.")
                file.close()
                exit(1)
        elif header == "str":
            result_bytes = content.strip().encode()
        else:
            print("\nERROR: Invalid header found: " + header + ". Try 'hex' or 'str' followed by endline instead.")
            file.close()
            exit(1)

        for forbidden_char in forbidden_chars:
            if forbidden_char in result_bytes:
                print("\nERROR: Forbidden character found in payload: ", forbidden_char)
                file.close()
                exit(1)

        file.close()
        return result_bytes

    except FileNotFoundError:
        print("\nERROR: File not found: ", filepath)
        exit(1)


def handle_most_used_outputs(most_used_x):
    """
    :param most_used_x: Element or list (e.g. from SQL-query output) which should only be one element
    :return: most_used_x if it's not a list. The first element of most_used_x after being sorted if it's a list
    """
    if isinstance(most_used_x, list):
        most_used_x.sort()
        return most_used_x[0]
    else:
        return most_used_x
