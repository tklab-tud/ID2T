import random
import unittest
import unittest.mock as mock

from ID2TLib.Controller import *
from Test.Lib import test_pcap, test_pcap_ips, get_sha256, clean_up

# FIXME: create new hashes
sha_one_attacker = '887226f047456608c5c8746c91d387ffa35777650f083564e0104e381155c58e'
sha_one_hundred_attackers = '3cab29e73bc048ea7cbffde51f5637fe00256d896a6788db27fbec3804f19cc9'
sha_ips_in_pcap = '4a072c57bf97c8543305964c4df4de5f010df7da22fc8f414ccbbf88b962ae86'


class UnitTestSMBLoris(unittest.TestCase):

    def test_one_attacker(self):
        random.seed(5)
        controller = Controller(pcap_file_path=test_pcap, do_extra_tests=False)
        controller.load_pcap_statistics(False, False, False)
        controller.process_attacks([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']])
        self.assertEqual(get_sha256(controller.pcap_dest_path), sha_one_attacker)
        clean_up(controller)

    def test_ips_in_pcap(self):
        # TODO: implement test
        ip_src = 'ip.src='+test_pcap_ips[0]
        ip_dst = 'ip.dst='+test_pcap_ips[1]
        random.seed(5)
        controller = Controller(pcap_file_path=test_pcap, do_extra_tests=False)
        controller.load_pcap_statistics(False, False, False)
        controller.process_attacks([['SMBLorisAttack', ip_src, ip_dst]])
        self.assertEqual(get_sha256(controller.pcap_dest_path), sha_ips_in_pcap)
        clean_up(controller)

    #def five_minutes(self):
        # TODO: implement test

    def test_one_hundred_attackers(self):
        random.seed(5)
        controller = Controller(pcap_file_path=test_pcap, do_extra_tests=False)
        controller.load_pcap_statistics(False, False, False)
        controller.process_attacks([['SMBLorisAttack', 'ip.dst=192.168.1.210', 'attackers.count=100']])
        self.assertEqual(get_sha256(controller.pcap_dest_path), sha_one_hundred_attackers)
        clean_up(controller)


if __name__ == '__main__':
    unittest.main()
