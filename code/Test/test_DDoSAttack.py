import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = '2994259bdf4626c3fb7b0bd42ed5da5369017c6f49343f02c8fd806bd7f75d2f'
sha_dest_mac_length_zero_ddos = '7f4df5a432d5919104e2fc51f026933adebf19646a738866e1ded6f5c27a83b8'
sha_ip_range_ddos = 'e6da719c984d7d2eba2cda85c245b14c8a9b527d7349ad8414484bbceadaaac9'
sha_mss_none_ddos = '2994259bdf4626c3fb7b0bd42ed5da5369017c6f49343f02c8fd806bd7f75d2f'
sha_num_attackers_ddos = 'c8be9bc14f2731aade10a62efbbf200ff0d5e0da6368e6ff7316924ad79c9300'
sha_one_attacker_ddos = '0259c13d9ea9c8972f60b50531c5f97c6717e212f22226ad7bc45d90dd5c5200'
sha_port_range_ddos = 'aad21afd99a95fc7c2dfe4bf8cc71864de791f147c874b2e800e0c9084c78388'


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

    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_ddos_port_range(self, mock_get_attacker_config):
        self.checksum_test([['DDoSAttack', 'attackers.count=5', 'port.src=1000-2000']],
                           sha_port_range_ddos)

    def test_ddos_order(self):
        self.order_test([['DDoSAttack', 'attackers.count=5']])
