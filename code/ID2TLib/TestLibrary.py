import hashlib
import os
import random

import ID2TLib.Utility as Util

test_resource_dir = Util.TEST_DIR
test_pcap = Util.TEST_DIR + "reference_1998.pcap"
test_pcap_ips = ["10.0.2.15", "52.85.173.182"]
test_pcap_empty = []

"""
helper functions for ID2TAttackTest
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


def rename_test_result_files(controller, caller_function: str, attack_sub_dir=False, test_sub_dir=False):
    """
    :param controller: controller which created output files
    :param caller_function: the name of the function which called the generic test
    :param attack_sub_dir: create sub-directory for each attack-class if True
    :param test_sub_dir: create sub-directory for each test-function/case if True
    """
    tmp_path_tuple = controller.pcap_dest_path.rpartition("_")
    result_pcap_path = tmp_path_tuple[0] + tmp_path_tuple[1] + caller_function + "_" + tmp_path_tuple[2]

    tmp_label_path_tuple = controller.label_manager.label_file_path.rpartition("_")
    tmp_path_tuple = tmp_label_path_tuple[0].rpartition("_")
    result_labels_path = tmp_path_tuple[0] + tmp_path_tuple[1] + caller_function + "_" + tmp_path_tuple[2]
    result_labels_path = result_labels_path + tmp_label_path_tuple[1] + tmp_label_path_tuple[2]

    if attack_sub_dir:
        caller_attack = caller_function.replace("test_", "").partition("_")[0]
        tmp_dir_tuple = result_pcap_path.rpartition("/")
        result_dir = tmp_dir_tuple[0] + tmp_dir_tuple[1] + caller_attack + "/"
        result_pcap_path = result_dir + tmp_dir_tuple[2]
        os.makedirs(result_dir, exist_ok=True)

        tmp_dir_tuple = result_labels_path.rpartition("/")
        result_labels_path = result_dir + tmp_dir_tuple[2]

    if test_sub_dir:
        tmp_dir_tuple = result_pcap_path.rpartition("/")
        result_dir = tmp_dir_tuple[0] + tmp_dir_tuple[1] + (caller_function.replace("test_", "")) + "/"
        result_pcap_path = result_dir + tmp_dir_tuple[2]
        os.makedirs(result_dir, exist_ok=True)

        tmp_dir_tuple = result_labels_path.rpartition("/")
        result_labels_path = result_dir + tmp_dir_tuple[2]

    os.rename(controller.pcap_dest_path, result_pcap_path)
    controller.pcap_dest_path = result_pcap_path

    os.rename(controller.label_manager.label_file_path, result_labels_path)
    controller.label_manager.label_file_path = result_labels_path


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


def get_attacker_config(ip_source_list, ipAddress: str):
    """
    unittest patch for get_attacker_config (ID2TLib.Utility.py)

    :param ip_source_list: List of source IPs
    :param ipAddress: The IP address of the attacker
    :return: A tuple consisting of (port, ttlValue)
    """
    next_port = random.randint(0, 2 ** 16 - 1)
    ttl = random.randint(1, 255)

    return next_port, ttl

