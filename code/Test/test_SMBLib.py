import unittest

import ID2TLib.SMBLib as SMBLib
import ID2TLib.Utility as Utility


class TestSMBLib(unittest.TestCase):
    def test_get_smb_version_all(self):
        for platform in Utility.platforms:
            with self.subTest(platform):
                result = SMBLib.get_smb_version(platform)
                self.assertTrue((result in SMBLib.smb_versions_per_win.values() or
                                 result in SMBLib.smb_versions_per_samba.values()))

    def test_get_smb_version_invalid(self):
        with self.assertRaises(ValueError):
            SMBLib.get_smb_version("abc")

    def test_get_smb_version_mac(self):
        self.assertEqual(SMBLib.get_smb_version("macos"), "2.1")

    def test_get_smb_version_win(self):
        win_platforms = {'win7', 'win10', 'winxp', 'win8.1', 'win8', 'winvista', 'winnt', "win2000"}

        for platform in win_platforms:
            with self.subTest(platform):
                self.assertIn(SMBLib.get_smb_version(platform), SMBLib.smb_versions_per_win.values())

    def test_get_smb_version_linux(self):
        self.assertIn(SMBLib.get_smb_version("linux"), SMBLib.smb_versions_per_samba.values())

    def test_get_smb_platform_data_invalid(self):
        with self.assertRaises(ValueError):
            SMBLib.get_smb_platform_data("abc", 0)

    def test_get_smb_platform_data_linux(self):
        self.assertEqual((SMBLib.get_smb_platform_data("linux", 0)),
                         ("ubuntu", SMBLib.security_blob_ubuntu, 0x5, 0x800000, 0))

    def test_get_smb_platform_data_mac(self):
        guid, blob, cap, d_size, time = SMBLib.get_smb_platform_data("macos", 0)
        self.assertEqual((blob, cap, d_size, time), (SMBLib.security_blob_macos, 0x6, 0x400000, 0))
        self.assertTrue(isinstance(guid, str) and len(guid) > 0)

    def test_get_smb_platform_data_win(self):
        guid, blob, cap, d_size, time = SMBLib.get_smb_platform_data("win7", 100)
        self.assertEqual((blob, cap, d_size), (SMBLib.security_blob_windows, 0x7, 0x100000))
        self.assertTrue(isinstance(guid, str) and len(guid) > 0)
        self.assertTrue(time <= Utility.get_filetime_format(100))

    def test_invalid_smb_version(self):
        with self.assertRaises(SystemExit):
            SMBLib.invalid_smb_version("abc")
