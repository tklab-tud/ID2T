import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_default = 'b69f106ec7c86ff28d7434206de2243b9641d8a7e569363d8670e4c1cfe89819'
sha_one_attacker = 'faa38854094245aa057afbc1cc4dbad3a82a2b62bdf365e491becde5f9e6e1eb'
sha_sixteen_attackers = 'ff9567a3510f1707fd1a846ab383d005f39eca9bd839d619c280cc2010ca77c4'
sha_ips_in_pcap = '2088d512d77020c64f358c8f661af6b0d33066dad023af04518e91c0e8934227'

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
