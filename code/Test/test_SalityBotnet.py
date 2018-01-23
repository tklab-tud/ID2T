import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import test_pcap_ips

sha_botnet_basic = 'bbe75f917933a9f7727d99137920a70a5f720cabc773da9e24acfd6cba45a87a'
sha_botnet_most_used_ip_in_list ='8583e2563d2756347449aec4b1c7cf7bfc7c0a96db4885627dcf0afc9e59feff'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SalityBotnet.py           77      0    100%   
"""


class UnitTestSalityBotnet(GenericTest):

    def test_botnet_basic(self):
        self.generic_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ips(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = test_pcap_ips
        self.generic_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)


if __name__ == '__main__':
    unittest.main()
