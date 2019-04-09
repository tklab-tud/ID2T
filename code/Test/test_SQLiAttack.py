import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test


class UnitTestSQLi(Test.ID2TAttackTest):

    def test_sqli_basic(self):
        self.order_test([['SQLiAttack']])

    def test_sqli_ips_not_in_pcap(self):
        self.order_test([['SQLiAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']])

    def test_sqli_multiple_params(self):
        ip_src = 'ip.src=' + Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst=' + Lib.test_pcap_ips[1]
        self.order_test([['SQLiAttack', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                          'mac.dst=04:0C:32:2C:63:62', 'port.dst=42',
                          'target.host=www.ihopethisisnotarealwebsite.com']])
