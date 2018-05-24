import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'a04d77120dbd20b789a5224c629f655a010c8a99b57330039dd15da09303011a'
sha_ips_not_in_pcap = '195e798169c6dc1eec7a006eb75738a4bceca8c28e8dc920fc3d9b5804722eeb'
sha_multiple_params = '594bb82f94c20bde35ccffc485542f68342a2cb2dbc9bdeda933d345c768d570'


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
