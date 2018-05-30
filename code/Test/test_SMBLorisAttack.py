import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '0736521d9bb35362704f5ada6fc1d8e74b2623f9361e999c3c60da951f890036'
sha_one_attacker = 'c56b1f6d15142f61df2ef75268f72c5af2d1d43d41157eed4d4cb96550b9384e'
sha_sixteen_attackers = '7681eb409918b8baafaf58fba8e99bc602014bf776195c4e3b69997bd24a8054'
sha_ips_in_pcap = '96786fc8952292414b74ebf23bcf6158890b74c7b3eb5dbc1229f91f50269ffd'

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
