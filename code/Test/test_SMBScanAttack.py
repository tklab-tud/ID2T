import unittest.mock as mock

import Test.ID2TAttackTest as Test

sha_default = '02d5ccf5483385256b1bb5d0be6ad180813e10fbd4091f2d74b832e9de1bfe7f'
sha_one_victim_linux = '59010614361fbc802f0ff6f6b62f3a1b65eec717aaf7280b977d0044d0dd1651'
sha_victim_range_winxp_hosting = '4f08852e8431ef7fb33dba2cd06df5ac2c306f266701ab26411320cc6c3041af'
sha_multiple_victims_macos = '75e1865dd911627550ac3866340da43c3357d43da85c03e7b3f0e36731d90370'
sha_port_shuffle = '2105fb02cc92de835f969a0dc6c521e2f044be1d2c629e8488385eedf15b8838'
sha_dest_mac_only = '0aba63d0667b49ee27264542a572116f39abdff068841c1a2fa47b7c06688ddf'
sha_ip_src_shuffle = 'f33dc22cb5bed8b5e9f26d02339c96a35f1cf451df11ab90bc07deefc3d8244b'
sha_smb2 = '91f2a13a92b694b9a2ada8604c65b7b3f138bdec54da59c691bf7512972ff3b8'

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
