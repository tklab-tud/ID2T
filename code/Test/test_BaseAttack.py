import unittest
import Attack.BaseAttack as BaseAttack


class TestBaseAttack(unittest.TestCase):

    def test_is_mac_address_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_mac_address("00:80:41:ae:fd:7e"))

    def test_is_mac_address_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_mac_address("00:80:41:aec:fd:7e"))

    def test_is_mac_address_empty(self):
        self.assertFalse(BaseAttack.BaseAttack._is_mac_address(""))

    def test_is_mac_address_minus_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_mac_address("00-80-41-ae-fd-7e"))

    def test_is_mac_address_minus_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_mac_address("00-80-41-aec-fd-7e"))

    def test_is_mac_address_list_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_mac_address(["00:80:41:ae:fd:7e", "00-80-41-ae-fd-7e"]))

    def test_is_mac_address_list_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_mac_address(["00:80:41:aec:fd:7e", "00-80-41-aec-fd-7e"]))

    def test_is_ip_address_empty(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address("")[0])

    def test_is_ip_address_v4_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_ip_address("192.168.178.1")[0])

    def test_is_ip_address_v4_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address("192.1689.178.1")[0])

    def test_is_ip_address_v6_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_ip_address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")[0])

    def test_is_ip_address_v6_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address("2001:0db8:85a3:08d3X:1319:8a2e:0370:7344")[0])

    def test_is_ip_address_v6_shortened_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_ip_address("2001:0db8:85a3:08d3:1319::0370:7344")[0])

    def test_is_ip_address_v6_shortened_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address("2001::85a3:08d3X::8a2e:0370:7344")[0])

    def test_is_ip_address_list_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_ip_address(["192.168.178.1", "192.168.178.10"])[0])

    def test_is_ip_address_list_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address(["192.1689.178.1", "192.168.178.10"])[0])

    def test_is_ip_address_comma_list_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_ip_address("192.168.178.1,192.168.178.10")[0])

    def test_is_ip_address_comma_list_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_ip_address("192.168.178.1,192.1689.178.10")[0])

    #FIX?
    #def test_is_port_empty(self):
        #self.assertFalse(ba._is_port(""))

    #def test_is_port_empty_list(self):
        #self.assertFalse(ba._is_port([]))

    def test_is_port_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port(5000))

    def test_is_port_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port(70000))

    def test_is_port_string_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port("5000"))

    def test_is_port_string_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port("70000"))

    def test_is_port_string_comma_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port("5000, 4000, 3000"))

    def test_is_port_string_comma_ivalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port("5000, 70000, 3000"))

    def test_is_port_valid_list(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port([5000, 4000, 3000]))

    def test_is_port_invalid_list(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port([5000, 70000, 0]))

    def test_is_port_valid_string_list(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port(["5000", "4000", "3000"]))

    def test_is_port_invalid_string_list(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port(["5000", "70000", "0"]))

    def test_is_port_range_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port("3000-5000"))

    def test_is_port_range_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port("0-70000"))

    def test_is_port_range_dots_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port("3000...5000"))

    def test_is_port_range_dots_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port("0...70000"))

    def test_is_port_range_list_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_port(["3000-5000", "6000-7000"]))

    def test_is_port_range_list_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_port(["0-70000", "6000-7000"]))

    def test_is_timestamp_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_timestamp("2018-01-25 23:54:00"))

    def test_is_timestamp_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_timestamp("20-0100-125 23c:54x:00a"))

    def test_is_boolean_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_boolean("42")[0])

    def test_is_boolean_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_boolean(True))
        self.assertTrue(BaseAttack.BaseAttack._is_boolean(False))

    def test_is_boolean_valid_strings(self):
        for value in {"y", "yes", "t", "true", "on", "1", "n", "no", "f", "false", "off", "0"}:
            with self.subTest(value=value):
                self.assertTrue(BaseAttack.BaseAttack._is_boolean(value))

    def test_is_float_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_float(50.67)[0])

    def test_is_float_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_float("invalid")[0])

    def test_is_domain_valid(self):
        self.assertTrue(BaseAttack.BaseAttack._is_domain("foo://example.com:8042/over/there?name=ferret"))

    def test_is_domain_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack._is_domain("this is not a valid domain, I guess, maybe, let's find out."))

    def test_is_valid_ipaddress_valid(self):
        self.assertTrue(BaseAttack.BaseAttack.is_valid_ip_address(BaseAttack, "192.168.178.42"))

    def test_is_valid_ipaddress_invalid(self):
        self.assertFalse(BaseAttack.BaseAttack.is_valid_ip_address(BaseAttack, "192.168.1789.42"))

    def test_ip_src_dst_equal_check_equal(self):
        with self.assertRaises(SystemExit):
            BaseAttack.BaseAttack.ip_src_dst_equal_check(BaseAttack, "192.168.178.42", "192.168.178.42")

    def test_ip_src_dst_equal_check_unequal(self):
        BaseAttack.BaseAttack.ip_src_dst_equal_check(BaseAttack, "192.168.178.42", "192.168.178.43")

    def test_clean_whitespaces(self):
        self.assertEqual("a\nb\rc\td\'e", BaseAttack.BaseAttack.clean_white_spaces(BaseAttack, "a\\nb\\rc\\td\\\'e"))

    def test_generate_random_ipv4_address(self):
        ip_list = BaseAttack.BaseAttack.generate_random_ipv4_address("Unknown", 10)
        for ip in ip_list:
            with self.subTest(ip=ip):
                self.assertTrue(BaseAttack.BaseAttack._is_ip_address(ip))

    def test_generate_random_ipv6_address(self):
        ip_list = BaseAttack.BaseAttack.generate_random_ipv6_address(10)
        for ip in ip_list:
            with self.subTest(ip=ip):
                self.assertTrue(BaseAttack.BaseAttack._is_ip_address(ip))

    def test_generate_random_mac_address(self):
        mac_list = BaseAttack.BaseAttack.generate_random_mac_address(10)
        for mac in mac_list:
            with self.subTest(mac=mac):
                self.assertTrue(BaseAttack.BaseAttack._is_mac_address(mac))
