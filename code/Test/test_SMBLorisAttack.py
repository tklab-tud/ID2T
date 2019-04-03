import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = '9fe4fbb6174ecd71382399656d788038a30e4bad151da9de0850825d6b1f5afb'
sha_one_attacker = '858b045ec42ce5892283c8bbf986aa646bf000031f081a52d6c808874983b4e1'
sha_sixteen_attackers = '0e28c2903ef5abc848fe260bdea15c1bd7421fe70f6801ba66b3366913f610f8'
sha_ips_in_pcap = 'fa6f4898b82005af5cf3cf547f5073e6a58c85444785e3a19d729a1ae3044e25'

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
