from random import randint
from datetime import datetime, timedelta, tzinfo
from calendar import timegm

from lea import Lea

from scapy.layers.netbios import *

platforms = {"win7", "win10", "winxp", "win8.1", "macos", "linux", "win8", "winvista", "winnt", "win2000"}


def get_rnd_os():
    """
    Chooses random platform over an operating system probability distribution

    :return: random platform as string
    """
    os_dist = Lea.fromValFreqsDict({"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94,
                                    "linux": 3.38, "win8": 1.35, "winvista": 0.46, "winnt": 0.31})
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