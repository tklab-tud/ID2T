import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test


class EfficiencyTests(Test.ID2TAttackTest):

    def test_SMBLoris_10_000(self):
        self.temporal_efficiency_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=8.0']],
                                      time_limit=15, factor=10000)

    def test_SMBLoris_100_000(self):
        self.temporal_efficiency_test([['SMBLorisAttack', 'attackers.count=30', 'packets.per-second=98']],
                                      time_limit=150, factor=100000)

    def test_SMBScan_10_000(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                        'ip.dst=192.168.178.10-192.168.197.145']], time_limit=15, factor=10000)

    def test_SMBScan_100_000(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.0.1-192.168.195.76']],
                                      time_limit=150, factor=100000)

    def test_SMBScan_hosting_10_000(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                        'ip.dst=192.168.178.10-192.168.181.241',
                                        'hosting.ip=192.168.178.10-192.168.181.241']], time_limit=15, factor=10000)

    def test_SMBScan_hosting_100_000(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10-192.168.217.25',
                                        'hosting.ip=192.168.178.10-192.168.217.25']], time_limit=150, factor=100000)

    @mock.patch('ID2TLib.Utility.get_rnd_bytes', side_effect=Lib.get_bytes)
    @mock.patch('ID2TLib.Utility.get_rnd_x86_nop', side_effect=Lib.get_x86_nop)
    def test_FTPExploit(self, mock_get_rnd_x86_nop, mock_get_rnd_bytes):
        self.temporal_efficiency_test([['FTPWinaXeExploit', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                                      time_limit=15, factor=10000)

    def test_PortscanAttack_open_10_000(self):
        self.temporal_efficiency_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=80']], time_limit=15,
                                      factor=10000)

    def test_PortscanAttack_close_10_000(self):
        self.temporal_efficiency_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=20']], time_limit=15,
                                      factor=10000)

    def test_SQLi_10_000(self):
        # FIXME: sometimes it takes 15.34028493521018 instead of the normal 7.150923313737726 seconds
        self.temporal_efficiency_test([['SQLiAttack', 'ip.dst=192.168.0.1']], time_limit=15, factor=10000)
