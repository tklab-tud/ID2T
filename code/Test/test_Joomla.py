import unittest

import Test.GenericTest as GenericTest

sha_default = 'a45bd543ae7416cdc5fd76c886f48990b43075753931683407686aac2cfbc111'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/JoomlaRegPrivExploit.py     127      4    97%   62, 71, 116, 123
"""
# TODO: get 100% coverage


class UnitTestJoomla(GenericTest.GenericTest):

    def test_joomla_default(self):
        self.generic_test([['JoomlaRegPrivExploit']], sha_default)


if __name__ == '__main__':
    unittest.main()
