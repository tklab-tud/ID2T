import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_default = 'a130ecdaf5fd8c09ef8418d2dbe7bd68c54e922553eb9fa703df016115393a46'
sha_ips_not_in_pcap = 'b3174ab4b7573c317c3e87b35e14eb38d99cf33613d76cfd77b0c30cbf1f1fa2'
sha_multiple_params = 'aac4d2015e2af52dfefc0f76fcbfca664e3420d07af8b574803f56aae70222c5'

# TODO: improve coverage


class UnitTestSQLi(Test.ID2TAttackTest):

    def test_sqli_default(self):
        self.checksum_test([['SQLiAttack']], sha_default)

    def test_sqli_ips_not_in_pcap(self):
        self.checksum_test([['SQLiAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_sqli_multiple_params(self):
        ip_src = 'ip.src='+Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst='+Lib.test_pcap_ips[1]
        self.checksum_test([['SQLiAttack', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                             'mac.dst=04:0C:32:2C:63:62', 'port.dst=42',
                             'target.host=www.ihopethisisnotarealwebsite.com']], sha_multiple_params)
    def test_sqli_order(self):
        self.order_test([['SQLiAttack']])
