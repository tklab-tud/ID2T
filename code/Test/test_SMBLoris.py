import random
import unittest
import unittest.mock as mock
import hashlib

from definitions import ROOT_DIR
from ID2TLib.Controller import *

sha_one_attacker = '887226f047456608c5c8746c91d387ffa35777650f083564e0104e381155c58e'


class UnitTestSMBLoris(unittest.TestCase):

    def get_sha256(self, file):
        sha = hashlib.sha256()
        with open(file, 'rb') as f:
            while True:
                data = f.read(0x100000)
                if not data:
                    break
                sha.update(data)
        return sha.hexdigest()

    def test_one_attacker(self):
        # TODO: implement test
        random.seed(5)
        controller = Controller(pcap_file_path=ROOT_DIR+"/../resources/test/test.pcap", do_extra_tests=False)
        controller.load_pcap_statistics(False, False, False)
        controller.process_attacks([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']])
        self.assertEqual(self.get_sha256(controller.pcap_dest_path), sha_one_attacker)

    #def one_hundred_attacker(self):
        # TODO: implement test

    #def target_ip_not_in_pcap(self):
        # TODO: implement test

    #def five_minutes(self):
        # TODO: implement test


if __name__ == '__main__':
    unittest.main()
