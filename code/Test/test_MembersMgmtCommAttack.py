import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = 'f57edd9fe1f8a2cf31d56f263d72d8e10c71d18cb124f0fb0b5bfcab49497419'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
