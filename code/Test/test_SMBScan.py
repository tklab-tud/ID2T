import unittest
import unittest.mock as mock

import Test.GenericTest as GenericTest

sha_default = '264b243c9b67978f3c892327352f4b293c9a79f6023b06b53d0af7628d171c0b'
sha_one_victim_linux = '4928d421caaec8f2c4e5c5bb835b5521b705478779cbc8f343b77143a5a66995'
sha_victim_range_winxp_hosting = '4c6cb5cb4f838e75b41af4feb2fd9a6fe7e1b226a38b3e8759ce3d31e5a2535e'
sha_multiple_victims_macos = '0be79b9ad7346562f392e07a5156de978e02f4f25ae8d409b81cc6e0d726012c'
sha_port_shuffle = '8ef501fa31135b8fea845a2be6a9605e0c3f9c4895b717f9206d485a669c2a73'
sha_dest_mac_only = '0814dadb666e0056ef5b3a572a4971f333376b61e602acb84cb99c851845f016'
sha_ip_src_shuffle = '6c0c9ccbedb631e4965ec36932276a1bd73b8a4aca5a5c46f01fd0a2800a064f'
sha_smb2 = '8755a901295a90362d8041ecf1243a31fff582f5fe64555205625263c253476e'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SMBScanAttack.py            239      9    96%   65, 73-74, 82, 193, 210-211, 284-285
"""
# TODO: get 100% coverage


class UnitTestSMBScan(GenericTest.GenericTest):

    def test_default(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.generic_test([['SMBScanAttack']], sha_default)

    def test_one_victim_linux(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                              sha_one_victim_linux)

    def test_victim_range_winxp_hosting(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="winxp"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5',
                                'ip.dst.end=192.168.178.10', 'hosting.ip=192.168.178.5']],
                              sha_victim_range_winxp_hosting)

    def test_multiple_victims_macos(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="macos"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                'ip.dst=192.168.178.10,192.168.178.15,192.168.178.20',
                                'hosting.ip=192.168.178.15,192.168.178.20']], sha_multiple_victims_macos)

    def test_invalid_smb_version(self):
        with self.assertRaises(SystemExit):
            self.generic_test([['SMBScanAttack', 'protocol.version=42']], 'somehash')

    def test_invalid_smb_platform(self):
        with self.assertRaises(SystemExit):
            self.generic_test([['SMBScanAttack', 'hosting.version=1337']], 'somehash')

    def test_port_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5',
                                'ip.dst.end=192.168.178.10', 'hosting.ip=192.168.178.5', 'port.src.shuffle=false']],
                              sha_port_shuffle)

    def test_dest_mac_only(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                'mac.dst=00:0C:29:9C:70:64']], sha_dest_mac_only)

    def test_src_ip_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5',
                                'ip.dst.end=192.168.178.10', 'hosting.ip=192.168.178.5', 'ip.src.shuffle=True']],
                              sha_ip_src_shuffle)

    def test_smb2(self):

        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.generic_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5',
                                'ip.dst.end=192.168.178.10', 'hosting.ip=192.168.178.5', 'protocol.version=2.1',
                                'hosting.version=2.1']], sha_smb2)


if __name__ == '__main__':
    unittest.main()
