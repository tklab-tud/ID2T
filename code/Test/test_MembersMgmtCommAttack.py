import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = 'a5c25b8c29b7f0c9b91eaa39c19ebf524f2e5407c0fbdf0f94af45eb1f1c8c74'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
