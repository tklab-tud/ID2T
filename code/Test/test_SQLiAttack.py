import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'e529d41ab412da8d5179bb7a8d780cc6e75fef82f1decdf884923b60c9f90058'
sha_ips_not_in_pcap = 'cfc8e75eee61e55626c9d650d794bc21e74019a40522c50e3ef48987f764fc02'
sha_multiple_params = '3424dccf5aef4a73252b5804ebd0b15a6921cd5859f9a0dd8f2396e6d159dd33'

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
