import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = 'b59bd29233893daa0908e3f603ea379e0f42155c1b7c70ac49a725340b590d8b'
sha_dest_mac_length_zero_ddos = '161d601279bead08769c80d19bb63f9e5f05fbb23261fc7fc138477c7956a65f'
sha_ip_range_ddos = 'c6f0afe30f727cba9c0c0199b6188797ba3891bf7beeb4cde1e5ebbfc37b46e7'
sha_mss_none_ddos = 'b59bd29233893daa0908e3f603ea379e0f42155c1b7c70ac49a725340b590d8b'
sha_num_attackers_ddos = '547553324897c1452d6e90520f7a32afaae383d5502c7c839f6567301c2b66a7'
sha_one_attacker_ddos = '0259c13d9ea9c8972f60b50531c5f97c6717e212f22226ad7bc45d90dd5c5200'
sha_port_range_ddos = '194d0fbe3f2b28587221687f118022b69e822e46cc9244413e6ae967b2561979'


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
