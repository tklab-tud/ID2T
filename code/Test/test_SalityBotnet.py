import unittest
import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.GenericTest as GenericTest

sha_botnet_basic = '8ff1e400dcf01d2d2cb97312cecdb71473ea140f6406ea935f74970aecdd7305'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SalityBotnet.py           77      0    100%
"""
# TODO: get 100% coverage


class UnitTestSalityBotnet(GenericTest.GenericTest):

    def test_botnet_basic(self):
        self.generic_test([['SalityBotnet']], sha_botnet_basic)


if __name__ == '__main__':
    unittest.main()
