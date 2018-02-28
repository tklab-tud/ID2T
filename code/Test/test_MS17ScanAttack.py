import Test.ID2TAttackTest as Test
import ID2TLib.TestLibrary as Lib

sha_default = '7251523bec9294756ac7ced1ad8b3c53625fdad8648b86915c8a4699300ce46a'
sha_ips_not_in_pcap = '6d150cf267fba423b5dabe44b36bee37b0d626c15041131a1f01a81f36ea3dfd'
sha_multiple_params = '765f71390a75827fc362d55c07a2d46d74c6b918b767ae1da2706247adb60919'


class UnitTestMS17Scan(Test.ID2TAttackTest):

    def test_MS17Scan_default(self):
        self.checksum_test([['MS17ScanAttack']], sha_default)

    def test_MS17Scan_ips_not_in_pcap(self):
        self.checksum_test([['MS17ScanAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_MS17Scan_multiple_params(self):
        ip_src = 'ip.src='+Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst='+Lib.test_pcap_ips[1]
        self.checksum_test([['MS17ScanAttack', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                             'mac.dst=04:0C:32:2C:63:62', 'port.src=1337', 'port.dst=42']], sha_multiple_params)

    def test_MS17Scan_order(self):
        self.order_test([['MS17ScanAttack']])
