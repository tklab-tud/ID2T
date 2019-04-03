import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_botnet_basic = 'd1f17fcb4f8b475e43f23f8a5bd9655489ed432133b0dd8b34433131da6bc18d'
sha_botnet_most_used_ip_in_list = 'd1f17fcb4f8b475e43f23f8a5bd9655489ed432133b0dd8b34433131da6bc18d'


class UnitTestSalityBotnet(Test.ID2TAttackTest):
    def test_botnet_basic(self):
        self.checksum_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('Core.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ip(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = Lib.test_pcap_ips[0]
        self.checksum_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)
