import unittest
import unittest.mock as mock

from ID2TLib.Statistics import Statistics
from Test.GenericTest import GenericTest
from Test.Lib import get_win_size, get_attacker_config

sha_basic_ddos = 'f05ce7842014fd90098c06b97f1b6276d93beed3ce5906e2d4281096e383fe0a'
sha_num_attackers_ddos = 'cba7151113fe1c91a52f062cef477c8650fc6e9507698b8981ba790921984d57'

"""
Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------------------------------------
Attack/DDoSAttack.py                124     11   94%   70, 105-106, 120, 123, 141, 146, 187
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

if __name__ == '__main__':
    unittest.main()
