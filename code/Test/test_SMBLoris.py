import unittest
import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
from Test.GenericTest import GenericTest

sha_default = 'cbfb154a80546ebcf0a0d5128bcc42e4d69228c1d97ea4dda49ba156703b78c2'
sha_one_attacker = 'a316ba1a667318ef4b8d1bf5ffee3f58dfcd0221b0cc3ab62dd967379217eb27'
sha_sixteen_attackers = '08b17b360ee9be1657e7c437e5aef354dac374ceca3b4ee437c45c0d9d03a2ef'
sha_ips_in_pcap = 'f299e4139780869d9f02c25ba00f1cad483a4f215d6aef4079b93f7f7e1de22a'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SMBLorisAttack.py           128      4    97%   67, 72, 149, 182
"""
# TODO: get 100% coverage


class UnitTestSMBLoris(GenericTest):

    def test_default(self):
        self.generic_test([['SMBLorisAttack']], sha_default)

    def test_one_attacker(self):
        self.generic_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']], sha_one_attacker)

    def test_ips_in_pcap(self):
        ip_src = 'ip.src='+Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst='+Lib.test_pcap_ips[1]
        self.generic_test([['SMBLorisAttack', ip_src, ip_dst]], sha_ips_in_pcap)

    def test_sixteen_attackers(self):
        self.generic_test([['SMBLorisAttack', 'ip.dst=192.168.1.210', 'attackers.count=16']], sha_sixteen_attackers)

    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_ip_address')
    def test_two_most_used_ips(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = Lib.test_pcap_ips
        self.generic_test([['SMBLorisAttack']], sha_default)

    def test_same_ip_src_dst(self):
        with self.assertRaises(SystemExit):
            self.generic_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.240']], sha_default)


if __name__ == '__main__':
    unittest.main()
