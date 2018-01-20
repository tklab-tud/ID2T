from unittest import TestCase
from ID2TLib.Utility import *
from Test.Lib import test_resource_dir


class TestUtility(TestCase):

    def test_update_timestamp_no_delay(self):
        self.assertTrue(100+10/5 >= update_timestamp(100, 5) >= 100+1/5)

    def test_update_timestamp_with_delay(self):
        self.assertTrue(100+1/5+10*100 >= update_timestamp(100, 5, 10) >= 100+1/5+10)

    def test_update_timestamp_comparison(self):
        self.assertTrue(update_timestamp(100, 5) <= update_timestamp(100, 5, 10))

    def test_get_interval_pps_below_max(self):
        cipps = [(5, 1), (10, 2), (15, 3)]
        self.assertEqual(get_interval_pps(cipps, 3), 1)
        self.assertEqual(get_interval_pps(cipps, 7), 2)
        self.assertEqual(get_interval_pps(cipps, 12), 3)

    def test_get_interval_pps_above_max(self):
        cipps = [(5, 1), (10, 2), (15, 3)]
        self.assertEqual(get_interval_pps(cipps, 30), 3)

    # Errors if empty list and result bad if only one list
    def test_get_nth_random_element_equal_no(self):
        letters = ["A", "B", "C"]
        numbers = [1, 2, 3]
        results = [("A", 1), ("B", 2), ("C", 3)]
        self.assertIn(get_nth_random_element(letters, numbers), results)

    def test_get_nth_random_element_unequal_no(self):
        letters = ["A", "B", "C"]
        numbers = [1, 2]
        results = [("A", 1), ("B", 2)]
        self.assertIn(get_nth_random_element(letters, numbers), results)

    #def test_get_nth_random_element_single_list(self):
        #letters = ["A", "B", "C"]
        #self.assertIn(get_nth_random_element(letters), letters)

    def test_index_increment_not_max(self):
        self.assertEqual(index_increment(5, 10), 6)

    def test_index_increment_max(self):
        self.assertEqual(index_increment(10, 10), 0)

    # Correct?
    def test_index_increment_max2(self):
        self.assertEqual(index_increment(9, 10), 0)

    def test_get_rnd_os(self):
        self.assertIn(get_rnd_os(), platforms)

    def test_check_platform_valid(self):
        check_platform("linux")

    def test_check_platform_invalid(self):
        with self.assertRaises(SystemExit):
            check_platform("abc")

    def test_get_ip_range_forwards(self):
        start = "192.168.178.254"
        end = "192.168.179.1"
        result = ["192.168.178.254", "192.168.178.255", "192.168.179.0", "192.168.179.1"]
        self.assertEqual(get_ip_range(start, end), result)

    def test_get_ip_range_backwards(self):
        end = "192.168.178.254"
        start = "192.168.179.1"
        result = ["192.168.179.1", "192.168.179.0", "192.168.178.255", "192.168.178.254"]
        self.assertEqual(get_ip_range(start, end), result)

    def test_generate_source_port_from_platform_invalid(self):
        with self.assertRaises(SystemExit):
            generate_source_port_from_platform("abc")

    def test_generate_source_port_from_platform_oldwin_firstport(self):
        self.assertTrue(1024 <= generate_source_port_from_platform("winxp") <= 5000)

    def test_generate_source_port_from_platform_oldwin_nextport(self):
        self.assertEqual(generate_source_port_from_platform("winxp", 2000), 2001)

    def test_generate_source_port_from_platform_oldwin_maxport(self):
        self.assertTrue(1024 <= generate_source_port_from_platform("winxp", 5000) <= 5000)

    def test_generate_source_port_from_platform_linux(self):
        self.assertTrue(32768 <= generate_source_port_from_platform("linux") <= 61000)

    def test_generate_source_port_from_platform_newwinmac_firstport(self):
        self.assertTrue(49152 <= generate_source_port_from_platform("win7") <= 65535)

    def test_generate_source_port_from_platform_newwinmac_nextport(self):
        self.assertEqual(generate_source_port_from_platform("win7", 50000), 50001)

    def test_generate_source_port_from_platform_newwinmac_maxport(self):
        self.assertTrue(49152 <= generate_source_port_from_platform("win7", 65535) <= 65535)

    # Test get_filetime_format????

    def test_get_rnd_boot_time_invalid(self):
        with self.assertRaises(SystemExit):
            get_rnd_boot_time(10, "abc")

    def test_get_rnd_boot_time_linux(self):
        self.assertTrue(get_rnd_boot_time(100, "linux") < 100)

    def test_get_rnd_boot_time_macos(self):
        self.assertTrue(get_rnd_boot_time(100, "macos") < 100)

    def test_get_rnd_boot_time_win(self):
        self.assertTrue(get_rnd_boot_time(100, "win7") < 100)

    def test_get_rnd_x86_nop_len(self):
        result = get_rnd_x86_nop(1000)
        self.assertEqual(len(result), 1000)

    def test_get_rnd_x86_nop_with_sideeffects(self):
        result = get_rnd_x86_nop(1000, False)
        correct = True
        for byte in result:
            if byte.to_bytes(1, "little") not in x86_nops and byte.to_bytes(1, "little") not in x86_pseudo_nops:
                correct = False
        self.assertTrue(correct)

    def test_get_rnd_x86_nop_without_sideeffects(self):
        result = get_rnd_x86_nop(1000, True)
        correct = True
        for byte in result:
            if byte.to_bytes(1, "little") in x86_pseudo_nops:
                correct = False
        self.assertTrue(correct)

    def test_get_rnd_x86_nop_filter(self):
        result = get_rnd_x86_nop(1000, False, x86_nops.copy())
        correct = True
        for byte in result:
            if byte.to_bytes(1, "little") in x86_nops:
                correct = False
        self.assertTrue(correct)

    def test_get_rnd_bytes_number(self):
        result = get_rnd_bytes(1000)
        self.assertEqual(len(result), 1000)

    def test_get_rnd_bytes_filter(self):
        result = get_rnd_bytes(1000, x86_pseudo_nops.copy())
        correct = True
        for byte in result:
            if byte.to_bytes(1, "little") in x86_pseudo_nops:
                correct = False
        self.assertTrue(correct)

    def test_get_bytes_from_file_invalid_path(self):
        with self.assertRaises(SystemExit):
            get_bytes_from_file(test_resource_dir+"/NonExistingFile.txt")

    def test_get_bytes_from_file_invalid_header(self):
        with self.assertRaises(SystemExit):
            get_bytes_from_file(test_resource_dir+"/InvalidHeader.txt")

    def test_get_bytes_from_file_invalid_hexfile(self):
        with self.assertRaises(SystemExit):
            get_bytes_from_file(test_resource_dir+"/InvalidHexFile.txt")

    def test_get_bytes_from_file_str(self):
        result = get_bytes_from_file(test_resource_dir+"/StringTestFile.txt")
        self.assertEqual(result, b'This is a string-test')

    def test_get_bytes_from_file_hex(self):
        result = get_bytes_from_file(test_resource_dir+"/HexTestFile.txt")
        self.assertEqual(result, b'\xab\xcd\xef\xff\x10\xff\xaa\xab')
