import os
import random
import unittest
import unittest.mock as mock

from ID2TLib.Controller import *
from Test.Lib import test_pcap, get_sha256

# FIXME: create new hashes
sha_one_attacker = '887226f047456608c5c8746c91d387ffa35777650f083564e0104e381155c58e'


class UnitTestSMBLoris(unittest.TestCase):

    def clean_up(self, controller):
        os.remove(controller.pcap_dest_path)
        os.remove(controller.label_manager.label_file_path)

    def test_one_attacker(self):
        random.seed(5)
        controller = Controller(pcap_file_path=test_pcap, do_extra_tests=False)
        controller.load_pcap_statistics(False, False, False)
        controller.process_attacks([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']])
        self.assertEqual(get_sha256(controller.pcap_dest_path), sha_one_attacker)
        self.clean_up(controller)

    #def one_hundred_attacker(self):
        # TODO: implement test

    #def target_ip_not_in_pcap(self):
        # TODO: implement test

    #def five_minutes(self):
        # TODO: implement test

if __name__ == '__main__':
    unittest.main()
