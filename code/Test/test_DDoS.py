import unittest
import unittest.mock as mock

from ID2TLib.Statistics import Statistics
from Test.GenericTest import GenericTest
from Test.Lib import get_win_size, get_attacker_config

# FIXME: create new hashes
sha_basic_ddos = 'f05ce7842014fd90098c06b97f1b6276d93beed3ce5906e2d4281096e383fe0a'

"""
Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------------------------------------
Attack/DDoSAttack.py                124     11    91%   70, 81-84, 105-106, 120, 123, 141, 146, 187
"""

class UnitTestDDoS(GenericTest):

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    def test_two_attackers(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack',
                            #'attack.duration=10',
                            #'inject.after-pkt=1',
                            #'ip.src=192.168.189.143,192.168.189.144',
                            #'ip.dst=192.168.189.1',
                            #'packets.per-second=10',
                            #'victim.buffer=1000'
                            ]],
                          sha_basic_ddos)

if __name__ == '__main__':
    unittest.main()
