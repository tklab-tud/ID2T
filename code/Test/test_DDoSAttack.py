import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = 'd30a14ba0568cb9c3be0db6a6d8e5d68b703d995015fc2215bfa150a8aff8b2a'
sha_num_attackers_ddos = '0de1ac89bb02e0163a31a0215d59ef2e2d819ffb904f8a99be1ecb52a568a392'
sha_dest_mac_length_zero_ddos = '55720bc3aa43a6abad2db1bd1f9c7ff71cb50f11ca5f17995b24184678c18226'
sha_mss_none_ddos = 'd30a14ba0568cb9c3be0db6a6d8e5d68b703d995015fc2215bfa150a8aff8b2a'
sha_one_attacker_ddos = '8bb7798e85cff15b91c5ee2c0bb65f01ff3097a417bdd2e58a540f89d542bea9'
sha_ip_range_ddos = 'bef5deb3cc7ee7537a90a85323cf885cf5a0431e15ae7001c0c762afc643e7a6'

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
    @mock.patch('Core.Statistics.Statistics.get_mac_address', return_value=[])
    def test_ddos_dest_mac_length_zero(self, mock_dest_mac, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack']], sha_dest_mac_length_zero_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    @mock.patch('Core.Statistics.Statistics.get_most_used_mss', return_value=None)
    def test_ddos_mss_none(self, mock_mss, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack']], sha_mss_none_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_ddos_one_attacker(self, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack', 'ip.src=1.1.1.1']],
                           sha_one_attacker_ddos)

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_ddos_ip_range(self, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack', 'ip.src=1.1.1.1-1.1.1.10']],
                           sha_ip_range_ddos)

    def test_ddos_order(self):
        self.order_test([['DDoSAttack', 'attackers.count=5']])
