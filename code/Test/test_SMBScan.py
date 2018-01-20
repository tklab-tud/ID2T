import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest

# FIXME: create new hashes if new test.pcap is used
sha_default = '6650602f7ac54b0032504bba24c05a99ed09dcf094a0b6ea3172b95d805807f4'
sha_one_victim_linux = '9da7ca3fe34f7a4f8d93d67b297afd198f0a4eb628171fbd25e15dc3d9bc97b5'
sha_victim_range_winxp_hosting = '5d58804c68e1d94e12150283e4013c678f22fb819eb2207100f0341dacba88ec'
sha_multiple_victims_macos = 'd39cd3dbdb85304d2629884118df070a78f9689ab7b3fd3a046c3706c3cd0f7e'
sha_port_shuffle = 'd32d557c65c01f46ec3de769dc15d223ec13234016898f5ec7aaab1b9549801a'
sha_dest_mac_only = 'af0140c0a2883927d429da82409f6bc091c9743e984111bda7c27d2bf99992ab'
sha_ip_src_shuffle = 'c6ed7baf850ccc3f53551e9a93c0a397629eb064abae7deeafb05d84b2633b05'
sha_smb2 = '8407a3316ba8dfb4ae610cedeeddfe4a7c0be1d420c2cad1c2750a213893618e'


"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/SMBScanAttack.py            239      9    96%   65, 73-74, 82, 193, 210-211, 284-285
"""
# TODO: get 100% coverage


class UnitTestSMBScan(GenericTest):

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
