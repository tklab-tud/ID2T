import binascii
import os
import random as rnd

import Lib.Utility as Util

# SMB port
smb_port = 445

# SMB versions
smb_versions = {"1", "2.0", "2.1", "3.0", "3.0.2", "3.1.1"}
smb_versions_per_win = {'win7': "2.1", 'win10': "3.1.1", 'winxp': "1", 'win8.1': "3.0.2", 'win8': "3.0",
                        'winvista': "2.0", 'winnt': "1", "win2000": "1"}
smb_versions_per_samba = {'3.6': "2.0", '4.0': "2.1", '4.1': "3.0", '4.3': "3.1.1"}
# SMB dialects
smb_dialects = ["PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1",
                "NT LM 0.12", "SMB 2.002", "SMB 2.???"]
# SMB security blobs
security_blob_windows = "\x60\x82\x01\x3c\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x82\x01\x30" \
                        "\x30\x82\x01\x2c\xa0\x1a\x30\x18\x06\x0a\x2b\x06\x01\x04\x01\x82" \
                        "\x37\x02\x02\x1e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" \
                        "\xa2\x82\x01\x0c\x04\x82\x01\x08\x4e\x45\x47\x4f\x45\x58\x54\x53" \
                        "\x01\x00\x00\x00\x00\x00\x00\x00\x60\x00\x00\x00\x70\x00\x00\x00" \
                        "\xbc\x84\x03\x97\x6f\x80\x3b\x81\xa6\x45\x1b\x05\x92\x39\xde\x3d" \
                        "\xd6\x91\x85\x49\x8a\xd0\x3b\x58\x87\x99\xb4\x98\xdf\xa6\x1d\x73" \
                        "\x3b\x57\xbf\x05\x63\x5e\x30\xea\xa8\xd8\xd8\x45\xba\x80\x52\xa5" \
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x00\x00\x01\x00\x00\x00" \
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x33\x53\x0d\xea\xf9\x0d\x4d" \
                        "\xb2\xec\x4a\xe3\x78\x6e\xc3\x08\x4e\x45\x47\x4f\x45\x58\x54\x53" \
                        "\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x98\x00\x00\x00" \
                        "\xbc\x84\x03\x97\x6f\x80\x3b\x81\xa6\x45\x1b\x05\x92\x39\xde\x3d" \
                        "\x5c\x33\x53\x0d\xea\xf9\x0d\x4d\xb2\xec\x4a\xe3\x78\x6e\xc3\x08" \
                        "\x40\x00\x00\x00\x58\x00\x00\x00\x30\x56\xa0\x54\x30\x52\x30\x27" \
                        "\x80\x25\x30\x23\x31\x21\x30\x1f\x06\x03\x55\x04\x03\x13\x18\x54" \
                        "\x6f\x6b\x65\x6e\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x50\x75\x62" \
                        "\x6c\x69\x63\x20\x4b\x65\x79\x30\x27\x80\x25\x30\x23\x31\x21\x30" \
                        "\x1f\x06\x03\x55\x04\x03\x13\x18\x54\x6f\x6b\x65\x6e\x20\x53\x69" \
                        "\x67\x6e\x69\x6e\x67\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79"
security_blob_ubuntu = "\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e" \
                       "\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa3\x2a" \
                       "\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\x64\x65\x66\x69\x6e\x65" \
                       "\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6c\x65" \
                       "\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65"
security_blob_macos = "\x60\x7e\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x74\x30\x72\xa0\x44" \
                      "\x30\x42\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x06\x09\x2a" \
                      "\x86\x48\x86\xf7\x12\x01\x02\x02\x06\x06\x2a\x85\x70\x2b\x0e\x03" \
                      "\x06\x06\x2b\x06\x01\x05\x05\x0e\x06\x0a\x2b\x06\x01\x04\x01\x82" \
                      "\x37\x02\x02\x0a\x06\x06\x2b\x05\x01\x05\x02\x07\x06\x06\x2b\x06" \
                      "\x01\x05\x02\x05\xa3\x2a\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f" \
                      "\x64\x65\x66\x69\x6e\x65\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31" \
                      "\x37\x38\x40\x70\x6c\x65\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65"


def get_smb_version(platform: str):
    """
    Returns SMB version based on given platform

    :param platform: the platform as string
    :return: SMB version as string
    """
    Util.check_platform(platform)
    if platform is "linux":
        return rnd.choice(list(smb_versions_per_samba.values()))
    elif platform is "macos":
        return "2.1"
    else:
        return smb_versions_per_win[platform]


def get_smb_platform_data(platform: str, timestamp: float):
    """
    Gets platform-dependent data for SMB 2 packets

    :param platform: the platform for which to get SMB 2 packet data
    :param timestamp: a timestamp for calculating the boot-time
    :return: server_guid, security_blob, capabilities, data_size and server_start_time of the given platform
    """
    Util.check_platform(platform)
    if platform == "linux":
        server_guid = "ubuntu"
        security_blob = security_blob_ubuntu
        capabilities = 0x5
        data_size = 0x800000
        server_start_time = 0
    elif platform == "macos":
        server_guid = binascii.b2a_hex(os.urandom(15)).decode()
        security_blob = security_blob_macos
        capabilities = 0x6
        data_size = 0x400000
        server_start_time = 0
    else:
        server_guid = binascii.b2a_hex(os.urandom(15)).decode()
        security_blob = security_blob_windows
        capabilities = 0x7
        data_size = 0x100000
        server_start_time = Util.get_filetime_format(Util.get_rnd_boot_time(timestamp))
    return server_guid, security_blob, capabilities, data_size, server_start_time


def invalid_smb_version(version: str):
    """
    Prints an error and exits

    :param version: the invalid SMB
    """
    print("\nInvalid smb version: " + version +
          "\nPlease select one of the following versions: ", smb_versions)
    exit(1)
