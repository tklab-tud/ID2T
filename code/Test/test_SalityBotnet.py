import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_botnet_basic = '309bd109a94ca9b9dcbf6597c8f415a55f26e15eeb470d45d4be9b7f9f649d5b'
sha_botnet_most_used_ip_in_list = '309bd109a94ca9b9dcbf6597c8f415a55f26e15eeb470d45d4be9b7f9f649d5b'


class UnitTestSalityBotnet(Test.ID2TAttackTest):
    def test_botnet_basic(self):
        self.checksum_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('Core.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ip(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = Lib.test_pcap_ips[0]
        self.checksum_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)
