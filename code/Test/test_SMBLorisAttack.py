import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '1be9058f2b15d8c673e4f008975032f4b0b44639091f9bad5be2dac0860cc284'
sha_one_attacker = 'b868613c62d2107104e8fec1ef8655acbe0b9f2e6dcf08c01b85386cd7687793'
sha_sixteen_attackers = 'a41d5bf452d784502c540696448887877c49547c023b20cc71dc7c7fb0f4fd23'
sha_ips_in_pcap = 'c74a833706b4031f3be2775269061438a3fcd7db7647dc23fa05ed853ff7b1c9'

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
