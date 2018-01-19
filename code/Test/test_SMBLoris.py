import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes if new test.pcap is used
sha_default = 'cd02bcc6376f4701d13384cbec6e210ea99308dca5d08f58edd3ab190cd50bf2'
sha_one_attacker = '887226f047456608c5c8746c91d387ffa35777650f083564e0104e381155c58e'
sha_one_hundred_attackers = '3cab29e73bc048ea7cbffde51f5637fe00256d896a6788db27fbec3804f19cc9'
sha_ips_in_pcap = '4a072c57bf97c8543305964c4df4de5f010df7da22fc8f414ccbbf88b962ae86'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SMBLorisAttack.py           128      5    96%   60, 73, 78, 155, 188
"""
# TODO: get 100% coverage


class UnitTestSMBLoris(GenericTest):

    def test_default(self):
        # FIXME: maybe use another seed
        self.generic_test([['SMBLorisAttack']], sha_default)

    def test_one_attacker(self):
        self.generic_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']], sha_one_attacker)

    def test_ips_in_pcap(self):
        ip_src = 'ip.src='+test_pcap_ips[0]
        ip_dst = 'ip.dst='+test_pcap_ips[1]
        self.generic_test([['SMBLorisAttack', ip_src, ip_dst]], sha_ips_in_pcap)

    def test_one_hundred_attackers(self):
        self.generic_test([['SMBLorisAttack', 'ip.dst=192.168.1.210', 'attackers.count=100']], sha_one_hundred_attackers)


if __name__ == '__main__':
    unittest.main()
