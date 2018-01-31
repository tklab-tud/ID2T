import unittest

import Test.GenericTest as GenTest

sha_default = 'c707492a0493efcf46a569c91fe77685286402ddfdff3c79e64157b3324dc9f6'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/EternalBlueExploit.py       246     10    96%   62, 72, 112, 119, 126-127, 133-134, 139, 266
"""
# TODO: get 100% coverage


class UnitTestEternalBlue(GenTest.GenericTest):

    def test_eternalblue_default(self):
        self.generic_test([['EternalBlueExploit']], sha_default)


if __name__ == '__main__':
    unittest.main()
