import unittest
import sqlite3
import pyparsing

import Lib.TestLibrary as Lib
import Core.Controller as Ctrl

controller = Ctrl.Controller(pcap_file_path=Lib.test_pcap, do_extra_tests=False, non_verbose=True)
controller.load_pcap_statistics(flag_write_file=False, flag_recalculate_stats=True, flag_print_statistics=False,
                                intervals=[], delete=True)


class UnitTestNestedNamedQueries(unittest.TestCase):
    def test_nested_query(self):
        self.assertEqual(controller.statistics.process_db_query('macaddress(ipaddress in most_used(ipaddress))'),
                         '08:00:27:a3:83:43')
        self.assertEqual(controller.statistics.process_db_query('macaddress(ipaddress in least_used(ipaddress))'),
                         '52:54:00:12:35:02')
        self.assertEqual(controller.statistics.process_db_query('ipaddress(macaddress in least_used(macaddress))'),
                         '10.0.2.15')
        self.assertEqual(controller.statistics.process_db_query('ipaddress(macaddress in 08:00:27:a3:83:43)'),
                         '10.0.2.15')
        self.assertEqual(controller.statistics.process_db_query('ipaddress(macaddress in [08:00:27:a3:83:43])'),
                         '10.0.2.15')
        self.assertEqual(controller.statistics.process_db_query('ipaddress(macaddress in most_used(macaddress))'),
                         ['104.83.103.45', '13.107.21.200', '131.253.61.100', '172.217.23.142', '172.217.23.174',
                          '192.168.33.254', '204.79.197.200', '23.51.123.27', '35.161.3.50', '52.11.17.245',
                          '52.34.37.177', '52.39.210.199', '52.41.250.141', '52.85.173.182', '54.149.74.139',
                          '54.187.98.195', '54.192.44.108', '54.192.44.177', '72.247.178.113', '72.247.178.67',
                          '93.184.220.29'])

        # semantically incorrect query
        with self.assertRaises(sqlite3.OperationalError):
            controller.statistics.process_db_query('ipaddress(ipaddress in most_used(macaddress))')

        # syntactically incorrect query
        with self.assertRaises(pyparsing.ParseException):
            controller.statistics.process_db_query('ipaddress(macaddress in '
                                                   'most_used(macaddress(ipaddress in least_used(ipaddress))))')
