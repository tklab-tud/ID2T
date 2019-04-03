import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = '5ca7f58a950ffcc434eaac05a2bc8b527f5aa555e654aa164e9bc7f1bfe3a9dd'
sha_dest_mac_length_zero_ddos = '9d4023a84ac9a3bc22c24fda14296edcc2de3c62f87bac313131573233a0d9bf'
sha_ip_range_ddos = 'f1c95069f0c2c1f62d55a0350653911666edd8eb7d5fd3393a7eb2e6f4fe09ce'
sha_mss_none_ddos = '5ca7f58a950ffcc434eaac05a2bc8b527f5aa555e654aa164e9bc7f1bfe3a9dd'
sha_num_attackers_ddos = '3f01dd8ea108a860923f6b7b2452f23e17d3d76806d244e4195ad465475e0709'
sha_one_attacker_ddos = '335fd3bc1ac97680aeef8df359ce6f174d7de1f56ec3451a9aa824c0c34edace'
sha_port_range_ddos = '28f9512ffe3188657cd8d7467f87f8a63b523cf63bd704550ea7daaf8dc112ed'


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
