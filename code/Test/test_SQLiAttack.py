import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'bb0a52766ee2fdf7c5f59b2c3f0322da463ecd2b91046da2559b4349cbbdc9b8'
sha_ips_not_in_pcap = 'b0b0ac7f4b06a7fd53e5c7c29e0a64095a66ecf317864a48a0c0045132eee1ea'
sha_multiple_params = '597dea34972c8bb03fb70d1d8579eab9a23428f55b0e2352f098b4a2b76a14c7'

# TODO: improve coverage


class UnitTestSQLi(Test.ID2TAttackTest):
    def test_sqli_default(self):
        self.checksum_test([['SQLiAttack']], sha_default)

    def test_sqli_ips_not_in_pcap(self):
        self.checksum_test([['SQLiAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_sqli_multiple_params(self):
        ip_src = 'ip.src=' + Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst=' + Lib.test_pcap_ips[1]
        self.checksum_test([['SQLiAttack', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                             'mac.dst=04:0C:32:2C:63:62', 'port.dst=42',
                             'target.host=www.ihopethisisnotarealwebsite.com']], sha_multiple_params)

    def test_sqli_order(self):
        self.order_test([['SQLiAttack']])
