import unittest
import sqlite3

import ID2TLib.TestLibrary as Lib
import Core.Controller as Ctrl

controller = Ctrl.Controller(pcap_file_path=Lib.test_pcap, do_extra_tests=False, non_verbose=True)
controller.load_pcap_statistics(flag_write_file=False, flag_recalculate_stats=True, flag_print_statistics=False,
                                intervals=[], delete=True)


class UnitTestSqlQueries(unittest.TestCase):
    def test_apostrophe(self):
        query = "Select ipAddress from ip_Statistics where pktsSent = '5'"
        query2 = "Select ipAddress from ip_Statistics where pktsSent = 5"
        self.assertEqual(controller.statistics.stats_db.process_db_query(query),
                         controller.statistics.stats_db.process_db_query(query2))

    def test_parenthesis(self):
        query = "Select (ipAddress) from (ip_Statistics) where (pktsSent) = (2 + (3))"
        self.assertEqual("72.247.178.67", controller.statistics.stats_db.process_db_query(query))

    def test_noResult(self):
        query = "Select ipAddress from ip_statistics where ipaddress = 'abc'"
        self.assertEqual([], controller.statistics.stats_db.process_db_query(query))

    def test_severalOperator(self):
        query1 = "Select ipAddress from ip_Statistics where pktsSent = '5'"
        query2 = "Select ipAddress from ip_Statistics where pktsSent < '5'"
        query3 = "Select ipAddress from ip_Statistics where pktsSent <= '5' ORDER BY ipAddress DESC"
        query4 = "Select ipAddress from ip_Statistics where pktsSent > '356'"
        query5 = "Select ipAddress from ip_Statistics where pktsSent >= '356' ORDER BY ipAddress ASC"

        self.assertEqual("72.247.178.67", controller.statistics.stats_db.process_db_query(query1))
        self.assertEqual("72.247.178.113", controller.statistics.stats_db.process_db_query(query2))
        self.assertEqual(["72.247.178.67", "72.247.178.113"], controller.statistics.stats_db.process_db_query(query3))
        self.assertEqual("10.0.2.15", controller.statistics.stats_db.process_db_query(query4))
        self.assertEqual(["10.0.2.15", "172.217.23.174"], controller.statistics.stats_db.process_db_query(query5))

        # compare of tables with different dimension
        with self.assertRaises(sqlite3.OperationalError):
            controller.statistics.stats_db.process_db_query('Select ipAddress from ip_Statistics where pktsSent'
                                                            '= (Select * from ip_Statistics)')

    def test_is_query_standard_query(self):
        self.assertTrue(controller.statistics.is_query('SELECT * from ip_statistics'))
