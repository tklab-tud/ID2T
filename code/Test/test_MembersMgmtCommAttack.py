import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = 'a62f355d0e43c9072ac26a03134fffbf113b1aa02f086456a609b93b54243a50'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
