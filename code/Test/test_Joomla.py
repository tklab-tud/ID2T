import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes if new test.pcap is used
sha_default = '27eb51f0b0bb417eb121a874174b09cf65240bf8895d984f3158817e48f9aba2'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/JoomlaRegPrivExploit.py     127      4    97%   62, 71, 116, 123
"""
# TODO: get 100% coverage


class UnitTestJoomla(GenericTest):

    def test_default(self):
        # FIXME: maybe use another seed
        self.generic_test([['JoomlaRegPrivExploit']], sha_default)


if __name__ == '__main__':
    unittest.main()
