import unittest.mock as mock

import Test.ID2TAttackTest as Test

sha_default = 'f8e77860dd98891d9b163a94b17ad9a9c52d35b595afe72b72218aa27cf8fdc9'
sha_dest_mac_only = '295c8e56d36cbb05c3e9ecee9a5e18f50c6f789d6eb0b4ec8a6dc392083a2941'
sha_multiple_victims_macos = '51624548a58d0edfc3f8072d93baf5995bf996b258658c11d45b790db7119d41'
sha_one_victim_linux = '1e1ac2eab7bdf08a771a74cee7c0ff7c80e273f408bbca7739cf4ca976787b74'
sha_port_shuffle = '9762bb19c5d2d2a3bcc4ac13a06498252161e255c0c9c9f98901d5e825fafe62'
sha_smb2 = 'b6c8f53fe1e2fc4d628e19cefe5476c5bfc530b0f6f5e2e3ef8c2cfeebda810d'
sha_ip_src_shuffle = '25f71ec0096fefae882e9256f612a1c41c80cac591c5ecbb4ed822f3f04952be'
sha_victim_range_winxp_hosting = 'f03904ad5bcb78bcf2a047d9d757fe128eb8f339303ef755ebc82e63d1e16ae7'

# TODO: improve coverage


class UnitTestSMBScan(Test.ID2TAttackTest):
    def test_smbscan_default(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack']], sha_default)

    def test_smbscan_one_victim_linux(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                               sha_one_victim_linux)

    def test_smbscan_victim_range_winxp_hosting(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="winxp"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5']], sha_victim_range_winxp_hosting)

    def test_smbscan_multiple_victims_macos(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="macos"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                 'ip.dst=192.168.178.10,192.168.178.15,192.168.178.20',
                                 'hosting.ip=192.168.178.15,192.168.178.20']], sha_multiple_victims_macos)

    def test_smbscan_invalid_smb_version(self):
        with self.assertRaises(SystemExit):
            self.checksum_test([['SMBScanAttack', 'protocol.version=42']], 'somehash')

    def test_smbscan_invalid_smb_platform(self):
        with self.assertRaises(SystemExit):
            self.checksum_test([['SMBScanAttack', 'hosting.version=1337']], 'somehash')

    def test_smbscan_port_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'port.src.shuffle=false']], sha_port_shuffle)

    def test_smbscan_dest_mac_only(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'mac.dst=00:0C:29:9C:70:64']],
                               sha_dest_mac_only)

    def test_smbscan_src_ip_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'ip.src.shuffle=True']], sha_ip_src_shuffle)

    def test_smbscan_smb2(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'protocol.version=2.1', 'hosting.version=2.1']], sha_smb2)

    def test_smbscan_order(self):
        self.order_test([['SMBScanAttack']])
