import unittest
import unittest.mock as mock
from scapy.layers.inet import RandShort

from ID2TLib.Statistics import Statistics
from Test.GenericTest import GenericTest
from Test.Lib import get_win_size, get_rnd_short

# FIXME: create new hashes
sha_two_attackers = '77da7d909d7f2c86922fc663a2834e8de6c565943d307e9a1146b8cf656b5164'


# seeds: for 5, 23 for 10, 27 for 16, 31 for 1
class UnitTestDDoS(GenericTest):

    @mock.patch.object(Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    #@mock.patch.object(RandShort, '__init__', side_effect=get_rnd_short)
    def test_two_attackers(self, mock_get_rnd_win_size):
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
