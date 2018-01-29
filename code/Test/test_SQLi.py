import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

# FIXME: create new hashes if new test.pcap is used
sha_default = 'fa9a43a8b6eb959f25cf3306c9b94b0957027d91b61edd2c9906a135b814f148'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SQLiAttack.py               159      5    97%   62, 71, 113, 120, 245
"""
# TODO: get 100% coverage


class UnitTestSQLi(GenericTest):

    def test_default(self):
        # FIXME: maybe use another seed
        self.generic_test([['SQLiAttack']], sha_default)


if __name__ == '__main__':
    unittest.main()
