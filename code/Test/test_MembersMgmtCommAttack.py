import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = 'cc4ec4dec2e9570512eb977e56ebd2793f95c9229ebb6fa640829e1839b016af'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
