import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'bb18f0f04b7123d99cddfc7743b4421e22958c5ee43c97abced1ff4adb0c5b1e'
sha_one_attacker = '858b045ec42ce5892283c8bbf986aa646bf000031f081a52d6c808874983b4e1'
sha_sixteen_attackers = '5e58a466cdf9c3cce2f0b1adda3803d52c37446c2c5967a4faa71071dc432e74'
sha_ips_in_pcap = 'c14d55f4e4987c381c9415c251c27b72609e0b9d15e52ad8f2ece58329866a2d'

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
