import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '7a09b7ed40dad424606e6fa6010092f2e5fdbe0b9961201f9798512d5be2f31a'
sha_ips_not_in_pcap = 'f0110cbd536490de1c76be612f1e35f1f7195976674c76bcc6ba0bc5037627de'
sha_multiple_params = 'b7e06edb96bb890fafd737133c7408d56034c05812c28a556bbc4a4723f20748'

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
