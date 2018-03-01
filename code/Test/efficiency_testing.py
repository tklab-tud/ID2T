import unittest.mock as mock

import ID2TLib.Utility as Util
import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test

sha_SMBLoris_10_000 = '1433f4f69e9311ca7f64920f94992a8e8fbd045433fc0143dc47dfd25a6a02c1'
sha_SMBLoris_100_000 = '4891720093ba32f9794431ee16815931b1866bccac58b8ef750b669742875fb0'
sha_SMBScan_10_000 = '311cbfc28859597ce7ff58b1bdc8f0ddd733f33ab2bd83a4a7579edadce736aa'
sha_SMBScan_100_000 = '9e55f4c2f035ec52701eabed32757f427627ce5ccf53e30bfc084680a4bf49a2'
sha_SMBScan_hosting_10_000 = '14f92d19535332bf523e94bcb2038309844abedaa848ca7195a343256adba5f3'
sha_SMBScan_hosting_100_000 = '029d064de82122202b6ae53d4efff2ea3318ded73a2987cb16e1e74606532766'
sha_FTPExploit = '75290f0135b13b9d570a484fc7c674b80921a9311cd1229243ea8c547d8c08f0'
sha_Portscan_open = '2e1deda7b36fb39705dd44dcb2350cca547cfb5049a16fb383c522dbe7e1d4e9'
sha_Portscan_close = '3a62f594b9cd31bf7b8c455d1bb5cff3ec2beb044f6da39b066317910f10be66'
sha_SQLi = '40ab01ef72491dcbcc3d8302b578abb5062397e9cd10d81f87aa6b5fff9f3b69'


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

    @mock.patch('ID2TLib.Utility.get_rnd_bytes', side_effect=Lib.get_bytes)
    @mock.patch('ID2TLib.Utility.get_rnd_x86_nop', side_effect=Lib.get_x86_nop)
    def test_FTPExploit(self, mock_get_rnd_x86_nop, mock_get_rnd_bytes):
        self.checksum_test([['FTPWinaXeExploit', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                           sha_FTPExploit, time=True)
        self.assertLessEqual(self.controller.durations[0]*10000/7, 15)

    def test_PortscanAttack_open(self):
        self.checksum_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=80']], sha_Portscan_open, time=True)
        self.assertLessEqual(self.controller.durations[0]*10000/1002, 15)

    def test_PortscanAttack_close(self):
        self.checksum_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=20']], sha_Portscan_close, time=True)
        self.assertLessEqual(self.controller.durations[0]*10, 15)

    def test_sqli_default(self):
        self.checksum_test([['SQLiAttack', 'ip.dst=192.168.0.1']], sha_SQLi)
        self.assertLessEqual(self.controller.durations[0]*10000/6423, 15)
