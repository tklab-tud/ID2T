import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '25a5a1feb01303328f457daab345bc7201c2a47851975609413b7702181fd8d6'
sha_ips_not_in_pcap = '71b3c47ba62234a139c9c9118d0d2e193ad13481795cc8609a593018927731cf'
sha_multiple_params = '5387d5487ece169b542f4e4990393967e95f733a120a6ce09732ef4404486da5'


class UnitTestMS17Scan(Test.ID2TAttackTest):
    def test_MS17Scan_default(self):
        self.checksum_test([['MS17ScanAttack']], sha_default)

    def test_MS17Scan_ips_not_in_pcap(self):
        self.checksum_test([['MS17ScanAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_MS17Scan_multiple_params(self):
        ip_src = 'ip.src=' + Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst=' + Lib.test_pcap_ips[1]
        self.checksum_test([['MS17ScanAttack', ip_src, ip_dst, 'mac.src=00:0C:21:1C:60:61',
                             'mac.dst=04:0C:32:2C:63:62', 'port.src=1337', 'port.dst=42']], sha_multiple_params)

    def test_MS17Scan_order(self):
        self.order_test([['MS17ScanAttack']])
