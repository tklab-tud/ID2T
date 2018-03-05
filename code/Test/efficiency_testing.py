import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_10_000_packets = '1433f4f69e9311ca7f64920f94992a8e8fbd045433fc0143dc47dfd25a6a02c1'
sha_100_000_packets = '4891720093ba32f9794431ee16815931b1866bccac58b8ef750b669742875fb0'


class EfficiencyTests(Test.ID2TAttackTest):

    def test_SMBLoris_10_000(self):
        self.checksum_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=7.7']], sha_10_000_packets,
                           time=True)
        self.assertLessEqual(self.controller.durations[0], 15)

    def test_SMBLoris_100_000(self):
        self.checksum_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=95']], sha_100_000_packets,
                           time=True)
        self.assertLessEqual(self.controller.durations[0], 150)
