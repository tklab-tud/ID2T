import unittest

import Test.GenericTest as GenericTest

sha_default = 'a130ecdaf5fd8c09ef8418d2dbe7bd68c54e922553eb9fa703df016115393a46'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SQLiAttack.py               159      5    97%   62, 71, 113, 120, 245
"""
# TODO: get 100% coverage


class UnitTestSQLi(GenericTest.GenericTest):

    def test_sqli_default(self):
        self.generic_test([['SQLiAttack']], sha_default)


if __name__ == '__main__':
    unittest.main()
