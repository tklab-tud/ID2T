from random import randint
from datetime import datetime, timedelta, tzinfo
from calendar import timegm

from lea import Lea

from scapy.layers.netbios import *

platforms = {"win7", "win10", "winxp", "win8.1", "macos", "linux", "win8", "winvista", "winnt", "win2000"}


def get_rnd_os():
    os_dist = Lea.fromValFreqsDict({"win7": 48.43, "win10": 27.99, "winxp": 6.07, "win8.1": 6.07, "macos": 5.94,
                                    "linux": 3.38, "win8": 1.35, "winvista": 0.46, "winnt": 0.31})
    return os_dist.random()


def check_platform(platform: str):
    if platform not in platforms:
        print("\nERROR: Invalid platform: " + platform + "." +
              "\n Please select one of the following platforms: ", platforms)
        exit(1)


def get_ip_range(start_ip: str, end_ip: str):
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
    check_platform(platform)
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