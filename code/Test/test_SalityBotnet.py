import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_botnet_basic = 'fa16b25b8bad5e03c47e195c1c73f80d5667c4445d16aca44dbb390ade3c0d4f'
sha_botnet_most_used_ip_in_list = 'fa16b25b8bad5e03c47e195c1c73f80d5667c4445d16aca44dbb390ade3c0d4f'


class UnitTestSalityBotnet(Test.ID2TAttackTest):
    def test_botnet_basic(self):
        self.checksum_test([['SalityBotnet']], sha_botnet_basic)

    @mock.patch('Core.Statistics.Statistics.get_most_used_ip_address')
    def test_botnet_most_used_ip(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = Lib.test_pcap_ips[0]
        self.checksum_test([['SalityBotnet']], sha_botnet_most_used_ip_in_list)
