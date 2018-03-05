import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_SMBLoris_10_000 = '1433f4f69e9311ca7f64920f94992a8e8fbd045433fc0143dc47dfd25a6a02c1'
sha_SMBLoris_100_000 = '4891720093ba32f9794431ee16815931b1866bccac58b8ef750b669742875fb0'
sha_SMBScan_10_000 = '311cbfc28859597ce7ff58b1bdc8f0ddd733f33ab2bd83a4a7579edadce736aa'
sha_SMBScan_100_000 = '9e55f4c2f035ec52701eabed32757f427627ce5ccf53e30bfc084680a4bf49a2'
sha_SMBScan_hosting_10_000 = '14f92d19535332bf523e94bcb2038309844abedaa848ca7195a343256adba5f3'
sha_SMBScan_hosting_100_000 = '029d064de82122202b6ae53d4efff2ea3318ded73a2987cb16e1e74606532766'


class EfficiencyTests(Test.ID2TAttackTest):

    def test_SMBLoris_10_000(self):
        self.checksum_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=7.7']], sha_SMBLoris_10_000,
                           time=True)
        self.assertLessEqual(self.controller.durations[0], 15)

    def test_SMBLoris_100_000(self):
        self.checksum_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=95']], sha_SMBLoris_100_000,
                           time=True)
        self.assertLessEqual(self.controller.durations[0], 150)

    def test_SMBScan_10_000(self):
        self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10-192.168.197.145']],
                           sha_SMBScan_10_000, time=True)
        self.assertLessEqual(self.controller.durations[0], 15)

    def test_SMBScan_100_000(self):
        self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.0.1-192.168.195.81']],
                           sha_SMBScan_100_000, time=True)
        self.assertLessEqual(self.controller.durations[0], 150)

    def test_SMBScan_hosting_10_000(self):
        self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10-192.168.181.241',
                             'hosting.ip=192.168.178.10-192.168.181.241']], sha_SMBScan_hosting_10_000, time=True)
        self.assertLessEqual(self.controller.durations[0], 15)

    def test_SMBScan_hosting_100_000(self):
        self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10-192.168.217.25',
                             'hosting.ip=192.168.178.10-192.168.217.25']], sha_SMBScan_hosting_100_000, time=True)
        self.assertLessEqual(self.controller.durations[0], 150)
