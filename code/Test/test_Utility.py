import unittest

import ID2TLib.TestLibrary as Lib
import ID2TLib.Utility as Utility

# TODO: improve coverage


class TestUtility(unittest.TestCase):
    def test_update_timestamp_no_delay(self):
        self.assertTrue(100 + 10 / 5 >= Utility.update_timestamp(100, 5) >= 100 + 1 / 5)

    def test_update_timestamp_with_delay(self):
        self.assertTrue(100 + 1 / 5 + 10 * 100 >= Utility.update_timestamp(100, 5, 10) >= 100 + 1 / 5 + 10)

    def test_update_timestamp_comparison(self):
        self.assertTrue(Utility.update_timestamp(100, 5) <= Utility.update_timestamp(100, 5, 10))

    def test_get_interval_pps_below_max(self):
        cipps = [(5, 1), (10, 2), (15, 3)]
        self.assertEqual(Utility.get_interval_pps(cipps, 3), 1)
        self.assertEqual(Utility.get_interval_pps(cipps, 7), 2)
        self.assertEqual(Utility.get_interval_pps(cipps, 12), 3)

    def test_get_interval_pps_above_max(self):
        cipps = [(5, 1), (10, 2), (15, 3)]
        self.assertEqual(Utility.get_interval_pps(cipps, 30), 3)

    def test_get_nth_random_element_equal_no(self):
        letters = ["A", "B", "C"]
        numbers = [1, 2, 3]
        results = [("A", 1), ("B", 2), ("C", 3)]
        self.assertIn(Utility.get_nth_random_element(letters, numbers), results)

    def test_get_nth_random_element_unequal_no(self):
        letters = ["A", "B", "C"]
        numbers = [1, 2]
        results = [("A", 1), ("B", 2)]
        self.assertIn(Utility.get_nth_random_element(letters, numbers), results)

    def test_get_nth_random_element_single_list(self):
        letters = ["A", "B", "C"]
        self.assertIn(Utility.get_nth_random_element(letters), letters)

    def test_get_nth_random_element_empty_list(self):
        letters = ["A", "B", "C"]
        self.assertEqual(Utility.get_nth_random_element(letters, []), None)

    def test_get_nth_random_element_nothing(self):
        self.assertEqual(Utility.get_nth_random_element(), None)

    def test_get_rnd_os(self):
        self.assertIn(Utility.get_rnd_os(), Utility.platforms)

    def test_check_platform_valid(self):
            Utility.check_platform("linux")

    def test_check_platform_invalid(self):
        with self.assertRaises(ValueError):
            Utility.check_platform("abc")

    def test_get_ip_range_forwards(self):
        start = "192.168.178.254"
        end = "192.168.179.1"
        result = ["192.168.178.254", "192.168.178.255", "192.168.179.0", "192.168.179.1"]
        self.assertEqual(Utility.get_ip_range(start, end), result)

    def test_get_ip_range_backwards(self):
        end = "192.168.178.254"
        start = "192.168.179.1"
        result = ["192.168.179.1", "192.168.179.0", "192.168.178.255", "192.168.178.254"]
        self.assertEqual(Utility.get_ip_range(start, end), result)

    def test_get_ip_range_equal(self):
        end = "192.168.178.254"
        start = "192.168.178.254"
        result = ["192.168.178.254"]
        self.assertEqual(Utility.get_ip_range(start, end), result)

    def test_generate_source_port_from_platform_invalid(self):
        with self.assertRaises(ValueError):
            Utility.generate_source_port_from_platform("abc")

    def test_generate_source_port_from_platform_oldwin_firstport(self):
        self.assertTrue(1024 <= Utility.generate_source_port_from_platform("winxp") <= 5000)

    def test_generate_source_port_from_platform_oldwin_nextport(self):
        self.assertEqual(Utility.generate_source_port_from_platform("winxp", 2000), 2001)

    def test_generate_source_port_from_platform_oldwin_maxport(self):
        self.assertTrue(1024 <= Utility.generate_source_port_from_platform("winxp", 5000) <= 5000)

    def test_generate_source_port_from_platform_linux(self):
        self.assertTrue(32768 <= Utility.generate_source_port_from_platform("linux") <= 61000)

    def test_generate_source_port_from_platform_newwinmac_firstport(self):
        self.assertTrue(49152 <= Utility.generate_source_port_from_platform("win7") <= 65535)

    def test_generate_source_port_from_platform_newwinmac_nextport(self):
        self.assertEqual(Utility.generate_source_port_from_platform("win7", 50000), 50001)

    def test_generate_source_port_from_platform_newwinmac_maxport(self):
        self.assertTrue(49152 <= Utility.generate_source_port_from_platform("win7", 65535) <= 65535)

    # TODO: get_filetime_format Test

    def test_get_rnd_boot_time_invalid(self):
        with self.assertRaises(ValueError):
            Utility.get_rnd_boot_time(10, "abc")

    def test_get_rnd_boot_time_linux(self):
        self.assertTrue(Utility.get_rnd_boot_time(100, "linux") < 100)

    def test_get_rnd_boot_time_macos(self):
        self.assertTrue(Utility.get_rnd_boot_time(100, "macos") < 100)

    def test_get_rnd_boot_time_win(self):
        self.assertTrue(Utility.get_rnd_boot_time(100, "win7") < 100)

    def test_get_rnd_x86_nop_len(self):
        result = Utility.get_rnd_x86_nop(1000)
        self.assertEqual(len(result), 1000)

    def test_get_rnd_x86_nop_with_sideeffects(self):
        result = Utility.get_rnd_x86_nop(1000, False)
        for i in range(0, len(result)):
            with self.subTest(i=i):
                self.assertTrue(result[i].to_bytes(1, "little") in Utility.x86_nops or
                                result[i].to_bytes(1, "little") in Utility.x86_pseudo_nops)

    def test_get_rnd_x86_nop_without_sideeffects(self):
        result = Utility.get_rnd_x86_nop(1000, True)
        for i in range(0, len(result)):
            with self.subTest(i=i):
                self.assertIn(result[i].to_bytes(1, "little"), Utility.x86_nops)
                self.assertNotIn(result[i].to_bytes(1, "little"), Utility.x86_pseudo_nops)

    def test_get_rnd_x86_nop_filter(self):
        result = Utility.get_rnd_x86_nop(1000, False, Utility.x86_nops.copy())
        for i in range(0, len(result)):
            with self.subTest(i=i):
                self.assertNotIn(result[i].to_bytes(1, "little"), Utility.x86_nops)

    def test_get_rnd_x86_nop_single_filter(self):
        result = Utility.get_rnd_x86_nop(1000, False, b'\x20')
        for i in range(0, len(result)):
            with self.subTest(i=i):
                self.assertNotEqual(result[i].to_bytes(1, "little"), b'\x20')

    def test_get_rnd_bytes_number(self):
        result = Utility.get_rnd_bytes(1000)
        self.assertEqual(len(result), 1000)

    def test_get_rnd_bytes_filter(self):
        result = Utility.get_rnd_bytes(1000, Utility.x86_pseudo_nops.copy())
        for i in range(0, len(result)):
            with self.subTest(i=i):
                self.assertNotIn(result[i].to_bytes(1, "little"), Utility.x86_pseudo_nops)

    def test_get_bytes_from_file_invalid_path(self):
        with self.assertRaises(SystemExit):
            Utility.get_bytes_from_file(Lib.test_resource_dir + "/NonExistingFile.txt")

    def test_get_bytes_from_file_invalid_header(self):
        with self.assertRaises(SystemExit):
            Utility.get_bytes_from_file(Lib.test_resource_dir + "/InvalidHeader.txt")

    def test_get_bytes_from_file_invalid_hexfile(self):
        with self.assertRaises(SystemExit):
            Utility.get_bytes_from_file(Lib.test_resource_dir + "/InvalidHexFile.txt")

    def test_get_bytes_from_file_invalid_strfile(self):
        with self.assertRaises(SystemExit):
            Utility.get_bytes_from_file(Lib.test_resource_dir + "/InvalidStringFile.txt")

    def test_get_bytes_from_file_str(self):
        result = Utility.get_bytes_from_file(Lib.test_resource_dir + "/StringTestFile.txt")
        self.assertEqual(result, b'This is a string-test')

    def test_get_bytes_from_file_hex(self):
        result = Utility.get_bytes_from_file(Lib.test_resource_dir + "/HexTestFile.txt")
        self.assertEqual(result, b'\xab\xcd\xef\xff\x10\xff\xaa\xab')

    def test_handle_most_used_outputs_empty(self):
        self.assertIsNone(Utility.handle_most_used_outputs([]))

    def test_handle_most_used_outputs_one(self):
        test_input = "SomeTest"
        self.assertEqual(Utility.handle_most_used_outputs(test_input), test_input)

    def test_handle_most_used_outputs_one_list(self):
        test_input = ["SomeTest"]
        self.assertEqual(Utility.handle_most_used_outputs(test_input), test_input[0])

    def test_handle_most_used_outputs_list_sorted(self):
        test_input = [0, 1, 2, 3, 4]
        self.assertEqual(Utility.handle_most_used_outputs(test_input), 0)

    def test_handle_most_used_outputs_list_unsorted(self):
        test_input = [2, 4, 0, 1, 3]
        self.assertEqual(Utility.handle_most_used_outputs(test_input), 0)

    def test_check_payload_len_exceeded(self):
        with self.assertRaises(SystemExit):
            Utility.check_payload_len(10, 5)

    def test_check_payload_len_valid(self):
        try:
            Utility.check_payload_len(5, 10)
        except SystemExit:
            self.fail()

    def test_remove_generic_ending_attack(self):
        self.assertEqual(Utility.remove_generic_ending("someattack"), "some")

    def test_remove_generic_ending_exploit(self):
        self.assertEqual(Utility.remove_generic_ending("someexploit"), "some")

    def test_remove_generic_ending_wrong_ending(self):
        self.assertEqual(Utility.remove_generic_ending("somestuff"), "somestuff")

    # TODO: get_attacker_config Tests
