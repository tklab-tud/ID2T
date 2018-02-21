import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_default = 'c707492a0493efcf46a569c91fe77685286402ddfdff3c79e64157b3324dc9f6'
sha_ips_not_in_pcap = '55d74bc906edc6b81a04a38539a0521228ee09146ff507cc19f6142a386bc2eb'
sha_multiple_params = '118745f3588a862b7a3f9e5e66e568742db58277084f4783cfc3b41cff8350d3'

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

