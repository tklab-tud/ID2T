import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes if new test.pcap is used
sha_default = 'c115719657b597730ae46b42a05ac979e9d30dcfccfead1424321b1e3288e8b6'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/EternalBlueExploit.py       246     10    96%   62, 72, 112, 119, 126-127, 133-134, 139, 266
"""
# TODO: get 100% coverage


class UnitTestEternalBlue(GenericTest):

    def test_default(self):
        # FIXME: maybe use another seed
        self.generic_test([['EternalBlueExploit']], sha_default)


if __name__ == '__main__':
    unittest.main()
