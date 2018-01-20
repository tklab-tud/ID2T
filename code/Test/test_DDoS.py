import os
import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes
sha_one_attacker = ''


# seeds: for 5, 23 for 10, 27 for 16, 31 for 1
class UnitTestDDoS(GenericTest):
    def test_one_attacker(self):
        self.generic_test([['DDoSAttack',
                            'attack.duration=10',
                            'attackers.count=1',
                            'inject.after-pkt=1',
                            'ip.src=192.168.189.143',
                            'ip.dst=192.168.189.1',
                            'packets.per-second=10',
                            'victim.buffer=1000'
                            ]],
                          sha_one_attacker)


if __name__ == '__main__':
    unittest.main()
