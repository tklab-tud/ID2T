import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '0ecc9662f9756dc4e0989e3552dade4d7d21df41065257e470f5b361dd9fd04d'
sha_ips_not_in_pcap = '11e053490af2b3f0e7333809afcf6556e3cabc8498508a179f4139b7521a750c'
sha_multiple_params = '60d84f003a8a2e097e5bae1a5c0a093fb0ae000579e7adaa835a7d23bd4447f0'

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
