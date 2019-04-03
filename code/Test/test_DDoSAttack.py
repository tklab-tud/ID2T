import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_basic_ddos = '992c6cdb70a1050b9719f45fe77f29d6abd7c0b1a2043f0af0de188ba5df7872'
sha_dest_mac_length_zero_ddos = 'f262bb6618ec07f5a04778108f301bb4469d218a7ae7598ea4aebbd57bad96be'
sha_ip_range_ddos = 'f71689dd6d2ecbe6d5e23fabd6030ffbbd53273223c4caea03194f5f1e5ea315'
sha_mss_none_ddos = '992c6cdb70a1050b9719f45fe77f29d6abd7c0b1a2043f0af0de188ba5df7872'
sha_num_attackers_ddos = '5f29dc76093216ee81469033f011b0d03594864062d0f892b86ee71b1a154324'
sha_one_attacker_ddos = 'b404e68b71476e5a0a4f19cb393b52aae9faefca7c24faad78ed8a493fa01ea6'
sha_port_range_ddos = 'ea0d6a0ec097484ba8a9ddebf150dfd991d7ff834a35686d9f26470e4424af1e'


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
