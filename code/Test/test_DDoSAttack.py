import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = '392e51908ddcf687481dcf24776bc449b645a87f61e4a19495139d9fe5df1aec'
sha_dest_mac_length_zero_ddos = '48ebe0c69ad22fb850de5bf1a1fbe8d4a44da2068aa90763da686886374c24d5'
sha_ip_range_ddos = 'f36f68dbdcba6c81d5ea10843ca9e0489f547d248dbca9f62ce422ec842efcad'
sha_mss_none_ddos = '392e51908ddcf687481dcf24776bc449b645a87f61e4a19495139d9fe5df1aec'
sha_num_attackers_ddos = '0865e89f5e24f249b0cbd61a849a951094f7e594220795aa8374effebaa12dd5'
sha_one_attacker_ddos = '2280c9e57492daa5d74803b6e3776e0db0f2c1fe93884a0459eb16d6c9262e0e'
sha_port_range_ddos = '2aea8e4128bdbe367e09a0d2226b74da52abc35a5fe45734a0b8cd9f08c0ce77'


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
