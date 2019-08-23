import unittest

import Attack.BaseAttack as BAtk

from Attack.Parameter import MACAddress, IPAddress

# TODO: improve coverage


class TestBaseAttack(unittest.TestCase):

    def test_is_valid_ipaddress_valid(self):
        self.assertTrue(BAtk.BaseAttack.is_valid_ip_address("192.168.178.42"))

    def test_is_valid_ipaddress_invalid(self):
        self.assertFalse(BAtk.BaseAttack.is_valid_ip_address("192.168.1789.42"))

    def test_ip_src_dst_catch_equal_equal(self):
        with self.assertRaises(SystemExit):
            BAtk.BaseAttack.ip_src_dst_catch_equal("192.168.178.42", "192.168.178.42")

    def test_ip_src_dst_catch_equal_unequal(self):
        BAtk.BaseAttack.ip_src_dst_catch_equal("192.168.178.42", "192.168.178.43")

    def test_ip_src_dst_equal_check_equal(self):
        result = BAtk.BaseAttack.ip_src_dst_equal_check("192.168.178.42", "192.168.178.42")
        self.assertTrue(result)

    def test_ip_src_dst_equal_check_unequal(self):
        result = BAtk.BaseAttack.ip_src_dst_equal_check("192.168.178.42", "192.168.178.43")
        self.assertFalse(result)

    def test_clean_whitespaces(self):
        self.assertEqual("a\nb\rc\td\'e", BAtk.BaseAttack.clean_white_spaces("a\\nb\\rc\\td\\\'e"))

    def test_generate_random_ipv4_address(self):
        ip_list = BAtk.BaseAttack.generate_random_ipv4_address("Unknown", 10)
        for ip in ip_list:
            with self.subTest(ip=ip):
                self.assertTrue(IPAddress._is_ip_address(ip))

    def test_generate_random_ipv6_address(self):
        ip_list = BAtk.BaseAttack.generate_random_ipv6_address(10)
        for ip in ip_list:
            with self.subTest(ip=ip):
                self.assertTrue(IPAddress._is_ip_address(ip))

    def test_generate_random_mac_address(self):
        mac_list = BAtk.BaseAttack.generate_random_mac_address(10)
        for mac in mac_list:
            with self.subTest(mac=mac):
                self.assertTrue(MACAddress._is_mac_address(mac))
