import unittest
import random

import ID2TLib.TestLibrary as Lib
import Core.Controller as Ctrl

controller = Ctrl.Controller(pcap_file_path=Lib.test_pcap, do_extra_tests=False, non_verbose=True)
controller.load_pcap_statistics(flag_write_file=False, flag_recalculate_stats=True, flag_print_statistics=False)

ipAddresses = ['10.0.2.15', '104.83.103.45', '13.107.21.200', '131.253.61.100', '172.217.23.142', '172.217.23.174',
               '192.168.33.254', '204.79.197.200', '23.51.123.27', '35.161.3.50', '52.11.17.245', '52.34.37.177',
               '52.39.210.199', '52.41.250.141', '52.85.173.182', '54.149.74.139', '54.187.98.195', '54.192.44.108',
               '54.192.44.177', '72.247.178.113', '72.247.178.67', '93.184.220.29']


class UnitTestInternalQueries(unittest.TestCase):
    # FILE METAINFORMATION TESTS
    def test_get_file_information(self):
        self.assertEqual(controller.statistics.get_file_information(),
                         [('Pcap file path', Lib.test_pcap),
                          ('Total packet count', 1998, 'packets'),
                          ("Recognized packets", 1988, "packets"),
                          ("Unrecognized packets", 10, "PDUs"), ("% Recognized packets", 99.49949949949949, "%"),
                          ("% Unrecognized packets", 0.5005005005005005, "%"),
                          ("Last unknown PDU", '1970-01-01 01:07:39.604899'),
                          ('Capture duration', '384.454345703125', 'seconds'),
                          ('Capture start', '\t1970-01-01 01:01:45.647675'),
                          ('Capture end', '\t1970-01-01 01:08:10.102034')])

    def test_get_packet_count(self):
        self.assertEqual(controller.statistics.get_packet_count(), 1998)

    def test_get_capture_duration(self):
        self.assertEqual(controller.statistics.get_capture_duration(), '384.454345703125')

    def test_get_pcap_timestamp_start(self):
        self.assertEqual(controller.statistics.get_pcap_timestamp_start(), '1970-01-01 01:01:45.647675')

    def test_get_pcap_timestamp_end(self):
        self.assertEqual(controller.statistics.get_pcap_timestamp_end(), '1970-01-01 01:08:10.102034')

    # FIXME: This seems to be the only testcase where float values differ slightly between macOS and Linux
    def test_get_general_file_statistics(self):
        file_stats = controller.statistics.get_general_file_statistics()
        self.assertEqual(file_stats[0], ('Avg. packet rate', 5.196976184844971, 'packets/sec'))
        self.assertEqual(file_stats[1], ('Avg. packet size', 0.0, 'kbytes'))
        self.assertEqual(file_stats[2], ('Avg. packets sent', 90.0, 'packets'))
        self.assertEqual(file_stats[3][0], 'Avg. bandwidth in')
        self.assertAlmostEqual(file_stats[3][1], 0.6302894353866577, places=5)
        self.assertEqual(file_stats[3][2], 'kbit/s')
        self.assertEqual(file_stats[4][0], 'Avg. bandwidth out')
        self.assertAlmostEqual(file_stats[4][1], 0.6302894353866577, places=5)

    # INTERNAL QUERY TESTS
    def test_get_ip_address_count(self):
        self.assertEqual(controller.statistics.get_ip_address_count(), 22)

    def test_get_ip_addresses(self):
        self.assertEqual(controller.statistics.get_ip_addresses(), ipAddresses)

    def test_get_most_used_ip_address(self):
        self.assertEqual(controller.statistics.get_most_used_ip_address(), '10.0.2.15')

    def test_get_random_ip_address(self):
        random.seed(5)
        self.assertEqual(controller.statistics.get_random_ip_address(), '72.247.178.113')

    def test_get_random_ip_address_count_2(self):
        random.seed(5)
        self.assertEqual(controller.statistics.get_random_ip_address(2), ['72.247.178.113', '23.51.123.27'])

    def test_get_ip_address_from_mac(self):
        self.assertEqual(controller.statistics.get_ip_address_from_mac('08:00:27:a3:83:43'), '10.0.2.15')

    def test_get_mac_address_1(self):
        self.assertEqual(controller.statistics.get_mac_address(ip_address='72.247.178.67'), '52:54:00:12:35:02')

    def test_get_mac_address_2(self):
        self.assertEqual(controller.statistics.get_mac_address(ip_address='10.0.2.15'), '08:00:27:a3:83:43')

    def test_get_most_used_mss(self):
        self.assertEqual(controller.statistics.get_most_used_mss(ip_address='10.0.2.15'), 1460)

    def test_get_most_used_ttl(self):
        self.assertEqual(controller.statistics.get_most_used_ttl(ip_address='10.0.2.15'), 128)

    def test_get_pps_sent_1(self):
        self.assertEqual(controller.statistics.get_pps_sent(ip_address='72.247.178.67'), 0)

    def test_get_pps_sent_2(self):
        self.assertEqual(controller.statistics.get_pps_sent(ip_address='10.0.2.15'), 2)

    def test_get_pps_sent_wrong_input(self):
        # wrong input parameter
        with self.assertRaises(TypeError):
            self.assertEqual(controller.statistics.get_pps_sent('08:00:27:a3:83:43'), 32)

    def test_get_pps_received_1(self):
        self.assertEqual(controller.statistics.get_pps_received(ip_address='72.247.178.67'), 0)

    def test_get_pps_received_2(self):
        self.assertEqual(controller.statistics.get_pps_received(ip_address='10.0.2.15'), 3)

    def test_get_ttl_distribution_1(self):
        self.assertEqual(controller.statistics.get_ttl_distribution(ip_address='72.247.178.67'), {64: 5})

    def test_get_ttl_distribution_2(self):
        self.assertEqual(controller.statistics.get_ttl_distribution(ip_address='10.0.2.15'), {128: 817})

    def test_get_mss_distribution_1(self):
        self.assertEqual(controller.statistics.get_mss_distribution(ip_address='72.247.178.67'), {1460: 1})

    def test_get_mss_distribution_2(self):
        self.assertEqual(controller.statistics.get_mss_distribution(ip_address='10.0.2.15'), {1460: 36})

    def test_get_win_distribution_1(self):
        self.assertEqual(controller.statistics.get_win_distribution(ip_address='72.247.178.67'), {65535: 5})

    def test_get_tos_distribution_1(self):
        self.assertEqual(controller.statistics.get_tos_distribution(ip_address='72.247.178.67'), {0: 5})

    def test_get_tos_distribution_2(self):
        self.assertEqual(controller.statistics.get_tos_distribution(ip_address='10.0.2.15'), {0: 817})

    # INTERNAL HELPER-FUNCTION TESTS
    def test_calculate_standard_deviation(self):
        self.assertEqual(controller.statistics.calculate_standard_deviation([1, 1, 2, 3, 5, 8, 13, 21]),
                         6.609652033201143)

    def test_calculate_entropy(self):
        self.assertEqual(controller.statistics.calculate_entropy([1, 1, 2, 3, 5, 8, 13, 21]), 2.371389165297016)

    def test_calculate_entropy_normalized(self):
        self.assertEqual(controller.statistics.calculate_entropy([1, 1, 2, 3, 5, 8, 13, 21], normalized=True),
                         (2.371389165297016, 0.7904630550990053))

    def test_calculate_complement_packet_rates_1(self):
        cpr = controller.statistics.calculate_complement_packet_rates(0)[0:9]
        self.assertEqual(cpr, [(186.418564, 0), (186.418824, 0), (186.419346, 0), (186.445361, 0),
                               (186.46954399999998, 0), (186.476234, 0), (186.477304, 0), (186.48606999999998, 0),
                               (186.486761, 0)])

    def test_calculate_complement_packet_rates_2(self):
        cpr = controller.statistics.calculate_complement_packet_rates(42)[0:9]
        self.assertEqual(cpr, [(186.418564, 41), (186.418824, 42), (186.419346, 42), (186.445361, 42),
                               (186.46954399999998, 42), (186.476234, 42), (186.477304, 42),
                               (186.48606999999998, 42),
                               (186.486761, 42)])
