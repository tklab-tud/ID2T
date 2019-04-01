import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '2c6eff4917c5681e01d3c8242da8802e898eac588be4e315b75d3ec4ab9fff04'
sha_ips_not_in_pcap = 'd654ffe7153a0e910a2f61417e39bcbb3306bce7f7b159e5d1f02a40a9ef6bd9'
sha_multiple_params = '4f6e63b6495f9a75bb79a1cb307448fa5109388f04b4967800fd1ee7e70bff2d'


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
