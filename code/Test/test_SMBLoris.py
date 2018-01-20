import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes if new test.pcap is used
sha_default = 'e6201c4a6b42fb86304b935ee522d4c1f655bc19a4646c4df45a64bb504a0b5c'
sha_one_attacker = '538f584a7a12488269cb22a2986cd0e6f32f0c243c7cce72c5deb5230167897c'
sha_sixteen_attackers = 'ca3cb549a213832e238a25eaadfc8e6c55c0b37b595ca1fc16cfca7c0990d675'
sha_ips_in_pcap = 'bb54c042f870467021958d5f6947d21876b1fa5cda5f27da41adebac8cd44b74'

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

    def test_sixteen_attackers(self):
        self.generic_test([['SMBLorisAttack', 'ip.dst=192.168.1.210', 'attackers.count=16']], sha_sixteen_attackers)


if __name__ == '__main__':
    unittest.main()
