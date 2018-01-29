import unittest
import unittest.mock as mock

from ID2TLib.Statistics import Statistics
from Test.GenericTest import GenericTest
from Test.Lib import get_win_size, get_attacker_config

sha_basic_ddos = 'f05ce7842014fd90098c06b97f1b6276d93beed3ce5906e2d4281096e383fe0a'
sha_num_attackers_ddos = 'cba7151113fe1c91a52f062cef477c8650fc6e9507698b8981ba790921984d57'
# FIXME: get hash for currently broken test
sha_dest_mac_length_zero_ddos = ''
sha_mss_none_ddos = 'f05ce7842014fd90098c06b97f1b6276d93beed3ce5906e2d4281096e383fe0a'

"""
Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------------------------------------
Attack/DDoSAttack.py                124     7   94%    70, 105-106, 120, 123, 141, 187
"""

class UnitTestDDoS(GenericTest):

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    def test_basic(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack']],
                          sha_basic_ddos)

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    def test_num_attackers(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack', 'attackers.count=5']],
                          sha_num_attackers_ddos)

    # FIXME: currently returns 'ERROR: 'NoneType' object has no attribute 'route'
    #@mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    #@mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    #@mock.patch('ID2TLib.Statistics.Statistics.get_mac_address', return_value='')
    #def test_dest_mac_length_zero(self, mock_dest_mac, mock_get_attacker_config, mock_get_rnd_win_size):
    #    self.generic_test([['DDoSAttack']], sha_dest_mac_length_zero_ddos)

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_mss', return_value=None)
    def test_mss_none(self, mock_mss, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack']], sha_mss_none_ddos)


if __name__ == '__main__':
    unittest.main()
