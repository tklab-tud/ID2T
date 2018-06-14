import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = '116b6cb3f1be37e50333a4f1a2535d96b1b053a4c950655391826b43585cff2b'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
