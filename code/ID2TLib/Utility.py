import calendar as cal
import datetime as dt
import ipaddress
import ID2TLib.libcpputils as cpputils
import os
import random as rnd
import lea
import xdg.BaseDirectory as BaseDir
import scapy.layers.inet as inet
import scipy.stats as stats
import pytz as pytz

CACHE_DIR = os.path.join(BaseDir.xdg_cache_home, 'id2t')
CODE_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../"
ROOT_DIR = CODE_DIR + "../"
RESOURCE_DIR = ROOT_DIR + "resources/"
TEST_DIR = RESOURCE_DIR + "test/"
OUT_DIR = None
BOTNET_PCAP = RESOURCE_DIR + "2017-11-23_win16_cut_bot_udp.pcap"

# List of common operation systems
platforms = {"win7", "win10", "winxp", "win8.1", "macos", "linux", "win8", "winvista", "winnt", "win2000"}
# Distribution of common operation systems
platform_probability = {"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94, "linux": 3.38,
                        "win8": 1.35, "winvista": 0.46, "winnt": 0.31}

# List of no-ops
x86_nops = {b'\x90', b'\xfc', b'\xfd', b'\xf8', b'\xf9', b'\xf5', b'\x9b'}
# List of pseudo no-ops (includes ops which won't change the state e.g. read access)
x86_pseudo_nops = {b'\x97', b'\x96', b'\x95', b'\x93', b'\x92', b'\x91', b'\x99', b'\x4d', b'\x48', b'\x47', b'\x4f',
                   b'\x40', b'\x41', b'\x37', b'\x3f', b'\x27', b'\x2f', b'\x46', b'\x4e', b'\x98', b'\x9f', b'\x4a',
                   b'\x44', b'\x42', b'\x43', b'\x49', b'\x4b', b'\x45', b'\x4c', b'\x60', b'\x0e', b'\x1e', b'\x50',
                   b'\x55', b'\x53', b'\x51', b'\x57', b'\x52', b'\x06', b'\x56', b'\x54', b'\x16', b'\x58', b'\x5d',
                   b'\x5b', b'\x59', b'\x5f', b'\x5a', b'\x5e', b'\xd6'}
# Characters which result in operational behaviour (e.g. FTPWinaXeExploit.py)
forbidden_chars = [b'\x00', b'\x0a', b'\x0d']

# Used in get_attacker_config
attacker_port_mapping = {}
# Used in get_attacker_config
attacker_ttl_mapping = {}
# Identifier for attacks
generic_attack_names = {"attack", "exploit"}

local_classes = ["A-private", "B-private", "C-private", "A-unused", "D"]
public_classes = ["A", "B", "C", "E"]


def get_network_mode(ip_src: str, ip_dst: str):
    ip_class_src = cpputils.getIPv4Class(ip_src)
    ip_class_dst = cpputils.getIPv4Class(ip_dst)

    if ip_class_src in local_classes and \
       ip_class_dst in local_classes:
        mode = "local"
    elif ip_class_src in public_classes or \
         ip_class_dst in public_classes:
        mode = "public"
    else:
        mode = "unknown"

    return mode


# TODO: create class, params -> constructor, object in base attack
def update_timestamp(timestamp: float, pps: float, latency: float=0):
    """
    Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

    :param timestamp: the base timestamp to update
    :param pps: the packets per second specified by the user
    :param latency: the delay calculated from the statistics db
    :return: Timestamp to be used for the next packet.
    """
    # FIXME: throw Exception if pps==0
    delay = 0.00008
    custom_delay = delay
    if pps != 0:
        custom_delay = 1 / pps

    # Check custom_delay against limits
    if custom_delay < 0.00001:
        print("Warning: PPS is too high. Generated traffic might look unrealistic.\n"
              "Recommended are values equal or lower 100000.", end="\r")
    elif custom_delay < 0.000001:
        custom_delay = 0.000001
        print("Warning: PPS is too high. Dropping to 1,000,000 pps.", end="\r")

    delay = custom_delay

    if latency != 0:
        # Calculate reply timestamp
        delay = latency
    #else Calculate request timestamp

    random_delay = lea.Lea.fromValFreqsDict({delay * 1.3: 12, delay * 1.2: 13, delay * 1.1: 15, delay: 20,
                                             delay / 1.1: 15, delay / 1.2: 13, delay / 1.3: 12})
    delay = rnd.uniform(delay, random_delay.random())

    # add latency or delay to timestamp
    return timestamp + delay


def get_timestamp_from_datetime_str(time: str):
    return pytz.timezone('UTC').localize(dt.datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f")).timestamp()


def get_interval_pps(complement_interval_pps, timestamp):
    """
    Gets the packet rate (pps) for a specific time interval.

    :param complement_interval_pps: an array of tuples (the last timestamp in the interval, the packet rate in the
    corresponding interval).
    :param timestamp: the timestamp at which the packet rate is required.
    :return: the corresponding packet rate (pps) .
    """
    for row in complement_interval_pps:
        if timestamp <= row[0]:
            return row[1]
    return complement_interval_pps[-1][1]  # in case the timestamp > capture max timestamp


def get_nth_random_element(*element_list):
    """
    Returns the n-th element of every list from an arbitrary number of given lists.
    For example, list1 contains IP addresses, list 2 contains MAC addresses. Use of this function ensures that
    the n-th IP address uses always the n-th MAC address.

    :param element_list: An arbitrary number of lists.
    :return: A tuple of the n-th element of every list.
    """
    if len(element_list) <= 0:
        return None
    elif len(element_list) == 1 and len(element_list[0]) > 0:
        return rnd.choice(element_list[0])
    else:
        range_max = min([len(x) for x in element_list])
        if range_max > 0:
            range_max -= 1
            n = rnd.randint(0, range_max)
            return tuple(x[n] for x in element_list)
        else:
            return None


def get_rnd_os():
    """
    Chooses random platform over an operating system probability distribution

    :return: random platform as string
    """
    os_dist = lea.Lea.fromValFreqsDict(platform_probability)
    return os_dist.random()


def check_platform(platform: str) -> None:
    """
    Checks if the given platform is currently supported
    if not exits with error

    :param platform: the platform, which should be validated
    """
    if platform not in platforms:
        raise ValueError("ERROR: Invalid platform: " + platform + "." +
                         "\n Please select one of the following platforms: " + ",".join(platforms))


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
            start = start + 1
    elif start > end:
        while start >= end:
            ips.append(start.exploded)
            start = start - 1
    else:
        ips.append(start_ip)
    return ips


def generate_source_port_from_platform(platform: str, previous_port=0):
    """
    Generates the next source port according to the TCP-port-selection strategy of the given platform

    :param platform: the platform for which to generate source ports
    :param previous_port: the previously used/generated source port. Must be 0 if no port was generated before
    :return: the next source port for the given platform
    """
    check_platform(platform)
    if platform in {"winnt", "winxp", "win2000"}:
        if (previous_port == 0) or (previous_port + 1 > 5000):
            return rnd.randint(1024, 5000)
        else:
            return previous_port + 1
    elif platform == "linux":
        return rnd.randint(32768, 61000)
    else:
        if (previous_port == 0) or (previous_port + 1 > 65535):
            return rnd.randint(49152, 65535)
        else:
            return previous_port + 1


def get_filetime_format(timestamp):
    """
    Converts a timestamp into MS FILETIME format

    :param timestamp: a timestamp in seconds
    :return: MS FILETIME timestamp
    """
    boot_datetime = dt.datetime.utcfromtimestamp(timestamp)
    boot_filetime = 116444736000000000 + (cal.timegm(boot_datetime.timetuple()) * 10000000)
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
        uptime_in_days = lea.Lea.fromValFreqsDict({3: 50, 7: 25, 14: 12.5, 31: 6.25, 92: 3.125, 183: 1.5625,
                                                   365: 0.78125, 1461: 0.390625, 2922: 0.390625})
    elif platform is "macos":
        uptime_in_days = lea.Lea.fromValFreqsDict({7: 50, 14: 25, 31: 12.5, 92: 6.25, 183: 3.125, 365: 3.076171875,
                                                   1461: 0.048828125})
    else:
        uptime_in_days = lea.Lea.fromValFreqsDict({3: 50, 7: 25, 14: 12.5, 31: 6.25, 92: 3.125, 183: 1.5625,
                                                   365: 0.78125, 1461: 0.78125})
    timestamp -= rnd.randint(0, uptime_in_days.random() * 86400)
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
    nops = list(nops - char_filter)

    for i in range(0, count):
        result += nops[rnd.randint(0, len(nops) - 1)]
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
        char = os.urandom(1)
        while char in ignore:
            char = os.urandom(1)
        result += char
    return result


def check_payload_len(payload_len: int, limit: int) -> None:
    """
    Checks if the len of the payload exceeds a given limit

    :param payload_len: The length of the payload
    :param limit: The limit of the length of the payload which is allowed
    """

    if payload_len > limit:
        raise ValueError("Custom payload too long: " + str(payload_len) +
                         " bytes. Should be a maximum of " + str(limit) + " bytes.")


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
            content = content.replace(" ", "").replace("\n", "").replace("\\", "").replace("x", "").replace("\"", "") \
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
    :return: most_used_x if it's not a list. The first element of most_used_x after being sorted if it's a list.
    None if that list is empty.
    """
    if isinstance(most_used_x, list):
        if len(most_used_x) == 0:
            return None
        most_used_x.sort()
        return most_used_x[0]
    else:
        return most_used_x


def get_attacker_config(ip_source_list, ip_address: str):
    """
    Returns the attacker configuration depending on the IP address, this includes the port for the next
    attacking packet and the previously used (fixed) TTL value.

    :param ip_source_list: List of source IPs
    :param ip_address: The IP address of the attacker
    :return: A tuple consisting of (port, ttlValue)
    """
    # Gamma distribution parameters derived from MAWI 13.8G dataset
    alpha, loc, beta = (2.3261710235, -0.188306914406, 44.4853123884)
    gd = stats.gamma.rvs(alpha, loc=loc, scale=beta, size=len(ip_source_list))

    # Determine port
    port = attacker_port_mapping.get(ip_address)
    if port is not None:  # use next port
        next_port = attacker_port_mapping.get(ip_address) + 1
        if next_port > (2 ** 16 - 1):
            next_port = 1
    else:  # generate starting port
        next_port = inet.RandShort()
    attacker_port_mapping[ip_address] = next_port
    # Determine TTL value
    ttl = attacker_ttl_mapping.get(ip_address)
    if ttl is None:  # determine TTL value
        is_invalid = True
        pos = ip_source_list.index(ip_address)
        pos_max = len(gd)
        while is_invalid:
            ttl = int(round(gd[pos]))
            if 0 < ttl < 256:  # validity check
                is_invalid = False
            else:
                pos = (pos + 1) % pos_max
        attacker_ttl_mapping[ip_address] = ttl
    # return port and TTL
    return next_port, ttl


def remove_generic_ending(string):
    """"
    Returns the input string with it's ending cut off, in case it was a generic one

    :param string: Input string
    :return: Input string with ending cut off
    """
    for end in generic_attack_names:
        if string.endswith(end):
            return string[:-len(end)]
    return string


def get_botnet_pcap_db():
    """
    Reads a botnet resource pcap, calculates statistics for it and returns the DB path.

    :return: the database path for the botnet resource pcap statistics DB
    """
    import Core.Statistics
    import ID2TLib.PcapFile as PcapFile

    bot_pcap = PcapFile.PcapFile(BOTNET_PCAP)
    bot_stats = Core.Statistics.Statistics(bot_pcap)
    bot_stats.do_extra_tests = True
    bot_stats.load_pcap_statistics(False, False, True, True, [], False, False)

    return bot_pcap.get_db_path()
