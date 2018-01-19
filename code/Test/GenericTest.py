import random
import unittest

from ID2TLib.Controller import Controller
from Test.Lib import test_pcap, get_sha256, clean_up


class GenericTest(unittest.TestCase):

    def generic_test(self, attack_args, sha_checksum, seed=5, cleanup=True, pcap=test_pcap, flag_write_file=False,
                     flag_recalculate_stats=False, flag_print_statistics=False):
        random.seed(seed)
        controller = Controller(pcap_file_path=pcap, do_extra_tests=False)
        controller.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics)
        controller.process_attacks(attack_args)
        self.assertEqual(get_sha256(controller.pcap_dest_path), sha_checksum)
        if cleanup:
            clean_up(controller)
