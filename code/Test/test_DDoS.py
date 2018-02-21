import unittest.mock as mock

import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_basic_ddos = '87c6c9cf4b496b84fecfd758c1d891ff06fe234dba2f421a5ab8bd7d6d9239a5'
sha_num_attackers_ddos = 'cbbb9b55d03a0efde965bbb8c38f6ba8a9acbd605cb2f3ac22a6ed6e3958f8e9'
sha_dest_mac_length_zero_ddos = 'acf1d108ab3d4e76636c6b58e08296126a74fcf3936377588376a79716fffd60'
sha_mss_none_ddos = '87c6c9cf4b496b84fecfd758c1d891ff06fe234dba2f421a5ab8bd7d6d9239a5'

# TODO: improve coverage


class UnitTestDDoS(Test.ID2TAttackTest):

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_ddos_basic(self, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack']],
                           sha_basic_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_ddos_num_attackers(self, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack', 'attackers.count=5']],
                           sha_num_attackers_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    @mock.patch('ID2TLib.Statistics.Statistics.get_mac_address', return_value=[])
    def test_ddos_dest_mac_length_zero(self, mock_dest_mac, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack']], sha_dest_mac_length_zero_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_mss', return_value=None)
    def test_ddos_mss_none(self, mock_mss, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack']], sha_mss_none_ddos)

    def test_ddos_order(self):
        self.order_test([['DDoSAttack', 'attackers.count=2']])
