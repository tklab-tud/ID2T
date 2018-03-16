import unittest.mock as mock

import Test.ID2TAttackTest as Test

sha_default = 'ef321877edfd828f6e6cd4abbffb5ade9cb66b3acd54ba9f3a5e2bfbeac9c964'
sha_one_victim_linux = '4928d421caaec8f2c4e5c5bb835b5521b705478779cbc8f343b77143a5a66995'
sha_victim_range_winxp_hosting = '4c6cb5cb4f838e75b41af4feb2fd9a6fe7e1b226a38b3e8759ce3d31e5a2535e'
sha_multiple_victims_macos = '82d6d7e0471e6395c77df7b5bac141e48d50afe22841c7c53747bbfdd0de184d'
sha_port_shuffle = '8ef501fa31135b8fea845a2be6a9605e0c3f9c4895b717f9206d485a669c2a73'
sha_dest_mac_only = '0814dadb666e0056ef5b3a572a4971f333376b61e602acb84cb99c851845f016'
sha_ip_src_shuffle = '6c0c9ccbedb631e4965ec36932276a1bd73b8a4aca5a5c46f01fd0a2800a064f'
sha_smb2 = '8755a901295a90362d8041ecf1243a31fff582f5fe64555205625263c253476e'

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
