import unittest

from definitions import ROOT_DIR
import ID2TLib.Controller as Ctrl

# TODO: change to generic path
pcap = ROOT_DIR + "/../resources/test/reference_1998.pcap"

controller = Ctrl.Controller(pcap_file_path=pcap, do_extra_tests=False)
controller.load_pcap_statistics(flag_write_file=False, flag_recalculate_stats=True, flag_print_statistics=False)

#TODO: also change path
file_information = [('Pcap file', ROOT_DIR + '/../resources/test/reference_1998.pcap'),
                    ('Packets', 1998, 'packets'), ('Capture length', '25.4294414520264', 'seconds'),
                    ('Capture start', '1970-01-01 01:01:45.647675'), ('Capture end', '1970-01-01 01:08:10.102034')]

file_statistics = [('Avg. packet rate', 78.57034301757812, 'packets/sec'), ('Avg. packet size', 0.0, 'kbytes'),
                   ('Avg. packets sent', 90.0, 'packets'), ('Avg. bandwidth in', 9.529012680053711, 'kbit/s'),
                   ('Avg. bandwidth out', 9.529012680053711, 'kbit/s')]

#FIXME: currently sorted ascending
ip_addresses = ["10.0.2.15", "104.83.103.45", "13.107.21.200", "131.253.61.100","172.217.23.142",
                "172.217.23.174", "192.168.33.254", "204.79.197.200", "23.51.123.27", "35.161.3.50",
                "52.11.17.245", "52.34.37.177", "52.39.210.199", "52.41.250.141", "52.85.173.182",
                "54.149.74.139", "54.187.98.195", "54.192.44.108", "54.192.44.177", "72.247.178.113",
                "72.247.178.67", "93.184.220.29"]


class TestQueries(unittest.TestCase):
    def test_get_file_information(self):
        self.assertEqual(controller.statistics.get_file_information(), file_information)

    def test_get_general_file_statistics(self):
        self.assertEqual(controller.statistics.get_general_file_statistics(), file_statistics)

    def test_get_capture_duration(self):
        self.assertEqual(controller.statistics.get_capture_duration(),'25.4294414520264')

    def test_get_pcap_timestamp_start(self):
        self.assertEqual(controller.statistics.get_pcap_timestamp_start(), '1970-01-01 01:01:45.647675')

    def test_get_pcap_timestamp_end(self):
        self.assertEqual(controller.statistics.get_pcap_timestamp_end(), '1970-01-01 01:08:10.102034')

    def test_get_pps_sent_1(self):
        self.assertEqual(controller.statistics.get_pps_sent(ip_address='72.247.178.67'), 0)

    def test_get_pps_sent_2(self):
        self.assertEqual(controller.statistics.get_pps_sent(ip_address='10.0.2.15'), 32)

    def test_get_pps_received_1(self):
        self.assertEqual(controller.statistics.get_pps_received(ip_address='72.247.178.67'), 0)

    def test_get_pps_received_2(self):
        self.assertEqual(controller.statistics.get_pps_received(ip_address='10.0.2.15'), 46)

    def test_get_packet_count(self):
        self.assertEqual(controller.statistics.get_packet_count(), 1998)

    def test_get_most_used_ip_address(self):
        self.assertEqual(controller.statistics.get_most_used_ip_address(), '10.0.2.15')

    def test_get_ttl_distribution_1(self):
        self.assertEqual(controller.statistics.get_ttl_distribution(ipAddress='72.247.178.67'), {64: 5})

    def test_get_ttl_distribution_2(self):
        self.assertEqual(controller.statistics.get_ttl_distribution(ipAddress='10.0.2.15'), {128: 817})

    def test_get_mss_distribution_1(self):
        self.assertEqual(controller.statistics.get_mss_distribution(ipAddress='72.247.178.67'), {1460: 1})

    def test_get_mss_distribution_2(self):
        self.assertEqual(controller.statistics.get_mss_distribution(ipAddress='10.0.2.15'), {1460: 36})

    def test_get_win_distribution_1(self):
        self.assertEqual(controller.statistics.get_win_distribution(ipAddress='72.247.178.67'), {65535: 5})

    # TODO: get win_distribution for this ip
    #def test_get_win_distribution_2(self):
    #    self.assertEqual(controller.statistics.get_win_distribution(ipAddress='10.0.2.15'),'')

    def test_get_tos_distribution_1(self):
        self.assertEqual(controller.statistics.get_tos_distribution(ipAddress='72.247.178.67'), {0: 5})

    def test_get_tos_distribution_2(self):
        self.assertEqual(controller.statistics.get_tos_distribution(ipAddress='10.0.2.15'), {0: 817})

    def test_get_ip_address_count(self):
        self.assertEqual(controller.statistics.get_ip_address_count(), 22)

    def test_get_ip_addresses(self):
        self.assertEqual(controller.statistics.get_ip_addresses(), ip_addresses)

    #TODO: move random outside of query and use seed to test
    #def test_get_random_ip_address(self):
    #    self.assertEqual(controller.statistics.get_random_ip_address(), '')

    def test_get_mac_address_1(self):
        self.assertEqual(controller.statistics.get_mac_address(ipAddress='72.247.178.67'), '52:54:00:12:35:02')

    def test_get_mac_address_2(self):
        self.assertEqual(controller.statistics.get_mac_address(ipAddress='10.0.2.15'), '08:00:27:a3:83:43')

    def test_get_most_used_mss(self):
        self.assertEqual(controller.statistics.get_most_used_mss(ipAddress='10.0.2.15'), 1460)

    def test_get_most_used_ttl(self):
        self.assertEqual(controller.statistics.get_most_used_ttl(ipAddress='10.0.2.15'), 128)

    def test_is_query_no_string(self):
        self.assertFalse(controller.statistics.is_query(42))

    def test_is_query_named_query(self):
        self.assertTrue(controller.statistics.is_query('least_used(ipaddress)'))

    def test_is_query_standard_query(self):
        self.assertTrue(controller.statistics.is_query('SELECT * from ip_statistics'))

    def test_calculate_standard_deviation(self):
        self.assertEqual(controller.statistics.calculate_standard_deviation([1,1,2,3,5,8,13,21]), 6.609652033201143)

    def test_calculate_entropy_unnormalized(self):
        self.assertEqual(controller.statistics.calculate_entropy([1,1,2,3,5,8,13,21]), 2.371389165297016)

    def test_calculate_entropy_normalized(self):
        self.assertEqual(controller.statistics.calculate_entropy([1, 1, 2, 3, 5, 8, 13, 21], normalized=True),
                                                                (2.371389165297016, 0.7904630550990053))

    #TODO: get complement packet rates and a reasonable pps
    #def test_calculate_complement_packet_rates(self):
    #    self.assertEqual(controller.statistics.calculate_complement_packet_rates(42), '')


if __name__ == '__main__':
    unittest.main()
