import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

sha_botnet_basic = '8ff1e400dcf01d2d2cb97312cecdb71473ea140f6406ea935f74970aecdd7305'
sha_botnet_most_used_ip_in_list = '8ff1e400dcf01d2d2cb97312cecdb71473ea140f6406ea935f74970aecdd7305'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SalityBotnet.py           77      0    100%
"""
# TODO: get 100% coverage


class UnitTestSalityBotnet(GenericTest):

    def test_botnet_basic(self):
        self.generic_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ips(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = test_pcap_ips
        self.generic_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)


if __name__ == '__main__':
    unittest.main()
