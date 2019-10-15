import Lib.TestLibrary as Lib
import Test.ID2TAttackTest as Test


class UnitTestSMBLoris(Test.ID2TAttackTest):

    def test_smbloris_basic(self):
        self.order_test([['SMBLorisAttack']])

    def test_smbloris_one_attacker(self):
        self.order_test([['SMBLorisAttack', 'attackers.count=1']])

    def test_smbloris_ips_not_in_pcap(self):
        self.order_test([['SMBLorisAttack', 'ip.src=192.168.1.240', 'ip.dst=192.168.1.210']])

    def test_smbloris_ips_in_pcaps(self):
        ip_src = 'ip.src=' + Lib.test_pcap_ips[0]
        ip_dst = 'ip.dst=' + Lib.test_pcap_ips[1]
        self.order_test([['SMBLorisAttack', ip_src, ip_dst]])
