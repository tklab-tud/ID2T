import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'a63a7f926b8e8ccf18c1f207caa7cc4abf4562ddedba0c811b009a0730963cb2'
sha_one_attacker = '542fbe7da83fa668e70d4fd5203c67cc75d34349bb613627d7b52a44b9e502e3'
sha_sixteen_attackers = 'a8efc926a47a8bcd4601bf4752568fefdf72f69295daa5e90e79d62c82c6e48e'
sha_ips_in_pcap = '9a1bbad4d61a33102062d2bc28d3149cefd7f19ae4ba8a2c11e07e9cdbb82d2f'

# TODO: improve coverage


class UnitTestSMBLoris(Test.ID2TAttackTest):
    def test_smbloris_default(self):
        self.checksum_test([['SMBLorisAttack']], sha_default)

    def test_smbloris_one_attacker(self):
        self.checksum_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']], sha_one_attacker)

    def test_smbloris_ips_in_pcap(self):
        ip_src = 'ip.src=' + Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst=' + Lib.test_pcap_ips[1]
        self.checksum_test([['SMBLorisAttack', ip_src, ip_dst]], sha_ips_in_pcap)

    def test_smbloris_sixteen_attackers(self):
        self.checksum_test([['SMBLorisAttack', 'ip.dst=192.168.1.210', 'attackers.count=16']], sha_sixteen_attackers)

    def test_smbloris_same_ip_src_dst(self):
        with self.assertRaises(SystemExit):
            self.checksum_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.240']], sha_default)

    def test_smbloris_order(self):
        self.order_test([['SMBLorisAttack', 'attackers.count=1']])
