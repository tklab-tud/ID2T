import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_default = '0ea04ea0ac61092aee244d56b2efd2e48056b9006c530e708f46b3cb2a9c314b'
sha_ips_not_in_pcap = '03b7d1d2b0c9999aa607ce9ef7186c5f352d2330145a0f9774109d0f21c03aea'
sha_multiple_params = '1f97161c38c2d586a7aedafe265747401317ecd6f1747af5216bb41af7b3aaf8'

# TODO: improve coverage


class UnitTestEternalBlue(Test.ID2TAttackTest):

    def test_eternalblue_default(self):
        self.checksum_test([['EternalBlueExploit']], sha_default)

    def test_eternalblue_ips_not_in_pcap(self):
        self.checksum_test([['EternalBlueExploit', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_eternalblue_multiple_params(self):
        ip_src = 'ip.src='+Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst='+Lib.test_pcap_ips[1]
        self.checksum_test([['EternalBlueExploit', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                             'mac.dst=04:0C:32:2C:63:62', 'port.src=1337', 'port.dst=42']], sha_multiple_params)

    def test_eternalblue_order(self):
        self.order_test([['EternalBlueExploit']])
