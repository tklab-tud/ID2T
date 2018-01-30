import os
import hashlib

from definitions import ROOT_DIR

test_resource_dir = ROOT_DIR + "/../resources/test"
test_pcap = ROOT_DIR + "/../resources/test/reference_1998.pcap"
test_pcap_ips = ["10.0.2.15", "52.85.173.182"]
test_pcap_empty = []

"""
helper functions for generic_test
"""


def get_sha256(file):
    """
    Generates a sha256 checksum from file

    :param file: absolute path to file
    :return: sha256 checksum
    """
    sha = hashlib.sha256()
    with open(file, 'rb') as f:
        while True:
            data = f.read(0x100000)
            if not data:
                break
            sha.update(data)
    f.close()
    return sha.hexdigest()


def clean_up(controller):
    """
    Removes the output files from a given controller

    :param controller: controller which created output files
    """
    os.remove(controller.pcap_dest_path)
    os.remove(controller.label_manager.label_file_path)


"""
function patches for unittests
"""


def get_bytes(count, ignore):
    """
    unittest patch for get_rnd_bytes (ID2TLib.Utility.py)

    :param count: count of requested bytes
    :param ignore: <not used>
    :return: a count of As
    """
    return b'A' * count


def get_x86_nop(count, side_effect_free, char_filter):
    """
    unittest patch for get_rnd_x86_nop (ID2TLib.Utility.py)

    :param count: count of requested nops
    :param side_effect_free: <not used>
    :param char_filter: <not used>
    :return: a count of \x90
    """
    return b'\x90' * count
