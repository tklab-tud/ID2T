import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
import Test.ID2TAttackTest as Test


class EfficiencyTests(Test.ID2TAttackTest):
    def test_SMBLoris(self):
        self.temporal_efficiency_test([['SMBLorisAttack', 'attackers.count=4', 'packets.per-second=8.0']],
                                      time_limit=1.5, factor=1000)

    def test_SMBScan(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                        'ip.dst=192.168.178.10-192.168.179.253']], time_limit=1.5, factor=1000)

    def test_SMBScan_hosting(self):
        self.temporal_efficiency_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                        'ip.dst=192.168.178.10-192.168.178.109',
                                        'hosting.ip=192.168.178.10-192.168.178.109']], time_limit=1.5, factor=1000)

    @mock.patch('ID2TLib.Utility.get_rnd_bytes', side_effect=Lib.get_bytes)
    @mock.patch('ID2TLib.Utility.get_rnd_x86_nop', side_effect=Lib.get_x86_nop)
    def test_FTPExploit(self, mock_get_rnd_x86_nop, mock_get_rnd_bytes):
        self.temporal_efficiency_test([['FTPWinaXeExploit', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                                      time_limit=1.5, factor=1000)

    def test_PortscanAttack_open(self):
        self.temporal_efficiency_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=80']], time_limit=1.5,
                                      factor=1000)

    def test_PortscanAttack_close(self):
        self.temporal_efficiency_test([['PortscanAttack', 'ip.src=192.168.178.1', 'port.open=20']], time_limit=1.5,
                                      factor=1000)

    def test_SQLi(self):
        # FIXME: sometimes it takes 15.34028493521018 instead of the normal 7.150923313737726 seconds
        self.temporal_efficiency_test([['SQLiAttack', 'ip.dst=192.168.0.1']], time_limit=1.5, factor=1000)

    def test_Joomla(self):
        self.temporal_efficiency_test([['JoomlaRegPrivExploit', 'ip.src=192.168.178.1']], time_limit=1.5, factor=1000)

    def test_SalityBotnet(self):
        self.temporal_efficiency_test([['SalityBotnet']], time_limit=1.5, factor=1000)

    @mock.patch('Attack.BaseAttack.BaseAttack.write_attack_pcap', side_effect=Lib.write_attack_pcap)
    def test_DDoS(self, mock_write_attack_pcap):
        # TODO: update attack args, when DDoS gets refactored
        self.temporal_efficiency_test([['DDoSAttack', 'attackers.count=10', 'packets.per-second=95',
                                        'attack.duration=15']], time_limit=1.5, factor=1000)

        # TODO: add temporal efficiency test(s) for EternalBlue and MS17
