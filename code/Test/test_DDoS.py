import unittest
import unittest.mock as mock
from random import randint

from ID2TLib.Statistics import Statistics
from Test.GenericTest import GenericTest
from Test.Lib import get_win_size, get_attacker_config

# FIXME: create new hashes
sha_two_attackers = 'c0a494e8553ebd937941bdfb0529b699ca00b7150af92d1152cf1c8ddaebe426'


# seeds: for 5, 23 for 10, 27 for 16, 31 for 1
class UnitTestDDoS(GenericTest):

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    @mock.patch('Attack.DDoSAttack.get_attacker_config', side_effect=get_attacker_config)
    def test_two_attackers(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack',
                            'attack.duration=10',
                            'inject.after-pkt=1',
                            'ip.src=192.168.189.143,192.168.189.144',
                            'ip.dst=192.168.189.1',
                            'packets.per-second=10',
                            'victim.buffer=1000'
                            ]],
                          sha_two_attackers)

if __name__ == '__main__':
    unittest.main()
