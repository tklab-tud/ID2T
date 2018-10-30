import Test.ID2TAttackTest as Test
import ID2TLib.Utility as Util

sha_default = '10080a8fcbee78a2fa58e394ca753ce547822a0a7e8f8f8903abb80ba29c5ae5'


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.checksum_test([['MembersMgmtCommAttack', 'hidden_mark=True']], sha_default, seed=42,
                           pcap=Util.TEST_DIR + "reference_telnet.pcap")
