import unittest.mock as mock

import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_botnet_basic = '8ff1e400dcf01d2d2cb97312cecdb71473ea140f6406ea935f74970aecdd7305'
sha_botnet_most_used_ip_in_list = '8ff1e400dcf01d2d2cb97312cecdb71473ea140f6406ea935f74970aecdd7305'


class UnitTestSalityBotnet(Test.ID2TAttackTest):

    def test_botnet_basic(self):
        self.checksum_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ip(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = Lib.test_pcap_ips[0]
        self.checksum_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)
