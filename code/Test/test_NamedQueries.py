import unittest
import pyparsing

import Lib.TestLibrary as Lib
import Core.Controller as Ctrl

controller = Ctrl.Controller(pcap_file_path=Lib.test_pcap, do_extra_tests=False, non_verbose=True)
controller.load_pcap_statistics(flag_write_file=False, flag_recalculate_stats=True, flag_print_statistics=False,
                                intervals=[], delete=True)

ip_addresses = ["10.0.2.15",      "104.83.103.45",  "13.107.21.200",  "131.253.61.100", "172.217.23.142",
                "172.217.23.174", "192.168.33.254", "204.79.197.200", "23.51.123.27",   "35.161.3.50",
                "52.11.17.245",   "52.34.37.177",   "52.39.210.199",  "52.41.250.141",  "52.85.173.182",
                "54.149.74.139",  "54.187.98.195",  "54.192.44.108",  "54.192.44.177",  "72.247.178.113",
                "72.247.178.67",  "93.184.220.29"]

allWinSize = [0,     822,   1330,  5082,  8192,  9900,  27060, 35657, 39917, 47030, 50782, 51310, 52202, 52740, 55062,
              56492, 58520, 59950, 59980, 61380, 62788, 62810, 62811, 62906, 63056, 63076, 63086, 63151, 63261, 63350,
              63370, 63400, 63409, 63456, 63516, 63547, 63552, 63572, 63603, 63628, 63655, 63663, 63675, 63686, 63706,
              63839, 63842, 63886, 63893, 63917, 63954, 63963, 63982, 63991, 64000, 64005, 64088, 64110, 64148, 64165,
              64177, 64189, 64194, 64198, 64209, 64230, 64240, 65535]

leastUsedWinASize = [822,   1330,  5082,  9900,  27060, 35657, 39917, 47030, 50782, 51310, 52202, 52740, 55062, 56492,
                     58520, 59950, 59980, 61380, 63056, 63963, 63982, 64000, 64005, 64198, 64230]

allPort = [53,    80,    443,   49157, 49160, 49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172,
           49173, 49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187,
           49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49247, 49323, 49470, 49636, 49695,
           49798, 49927, 49935, 49945, 50262, 50836, 50968, 51143, 51166, 51350, 51451, 51669, 51713, 52033, 52135,
           52399, 52520, 52644, 52697, 52743, 52786, 52964, 52981, 53059, 53234, 53461, 53691, 53708, 53745, 53836,
           54049, 54446, 54593, 54598, 54652, 54663, 54717, 54853, 54930, 55004, 55018, 55119, 55125, 55299, 55310,
           55463, 55650, 55667, 55752, 55843, 55851, 56146, 56325, 56567, 56589, 56750, 57049, 57179, 57275, 57520,
           57653, 57840, 57957, 57991, 58401, 58440, 58645, 58797, 58814, 58905, 58913, 58943, 59380, 59408, 59461,
           59467, 59652, 59660, 59718, 59746, 59844, 60006, 60209, 60414, 60422, 60659, 60696, 60708, 60756, 60827,
           60840, 61181, 61300, 61592, 61718, 61738, 61769, 61807, 62412, 62428, 62447, 62490, 62625, 62626, 62664,
           63425, 64096, 64121, 64137, 64252, 64334, 64337, 64479, 64509, 64637, 64807, 64811, 65448, 65487]


class UnitTestNamedQueries(unittest.TestCase):
    def test_most_used_ipaddress(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(ipaddress)'), '10.0.2.15')

    def test_most_used_macaddress(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(macaddress)'), '52:54:00:12:35:02')

    def test_most_used_portnumber(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(portnumber)'), 443)

    def test_most_used_protocolname(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(protocolname)'), 'IPv4')

    def test_most_used_ttlvalue(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(ttlvalue)'), 64)

    def test_most_used_mssvalue(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(mssvalue)'), 1460)

    def test_most_used_winsize(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(winsize)'), 65535)

    def test_most_used_ipclass(self):
        self.assertEqual(controller.statistics.process_db_query('most_used(ipclass)'), 'A')

    def test_least_used_ipaddress(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(ipaddress)'), '72.247.178.113')

    def test_least_used_macaddress(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(macaddress)'), '08:00:27:a3:83:43')

    def test_least_used_portnumber(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(portnumber)'), [58645, 59844])

    def test_least_used_protocolname(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(protocolname)'), 'UDP')

    def test_least_used_ttlvalue(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(ttlvalue)'), 255)

    def test_least_used_mssvalue(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(mssvalue)'), 1460)

    def test_least_used_winsize(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(winsize)'), leastUsedWinASize)

    def test_least_used_ipclass(self):
        self.assertEqual(controller.statistics.process_db_query('least_used(ipclass)'), ['A-private', 'C', 'C-private'])

    def test_avg_pktsreceived(self):
        self.assertEqual(controller.statistics.process_db_query('avg(pktsreceived)'), 90.36363636363636)

    def test_avg_pktssent(self):
        self.assertEqual(controller.statistics.process_db_query('avg(pktssent)'), 90.36363636363636)

    def test_avg_kbytesreceived(self):
        self.assertEqual(controller.statistics.process_db_query('avg(kbytesreceived)'), 30.289683948863637)

    def test_avg_kbytessent(self):
        self.assertEqual(controller.statistics.process_db_query('avg(kbytessent)'), 30.289683948863637)

    def test_avg_ttlvalue(self):
        self.assertEqual(controller.statistics.process_db_query('avg(ttlvalue)'), 75.08695652173913)

    def test_avg_mss(self):
        self.assertEqual(controller.statistics.process_db_query('avg(mss)'), 1460.0)

    def test_avg_ipaddress(self):
        with self.assertRaises(pyparsing.ParseException):
            controller.statistics.process_db_query('avg(ipAddress)')

    def test_all_ipaddress(self):
        self.assertEqual(controller.statistics.process_db_query('all(ipaddress)'), ip_addresses)

    def test_all_ttlvalue(self):
        self.assertEqual(controller.statistics.process_db_query('all(ttlvalue)'), [64, 128, 255])

    def test_all_mss(self):
        self.assertEqual(controller.statistics.process_db_query('all(mss)'), 1460)

    def test_all_macaddress(self):
        self.assertEqual(controller.statistics.process_db_query('all(macaddress)'), ['08:00:27:a3:83:43',
                                                                                     '52:54:00:12:35:02'])

    def test_all_portnumber(self):
        self.assertEqual(controller.statistics.process_db_query('all(portnumber)'), allPort)

    def test_all_protocolname(self):
        self.assertEqual(controller.statistics.process_db_query('all(protocolname)'), ['IPv4', 'TCP', 'UDP'])

    def test_all_winsize(self):
        self.assertEqual(controller.statistics.process_db_query('all(winSize)'),
                         allWinSize)

    def test_all_ipclass(self):
        self.assertEqual(controller.statistics.process_db_query('all(ipClass)'),
                         ['A', 'A-private', 'B', 'C', 'C-private'])

    def test_is_query_named_query(self):
        self.assertTrue(controller.statistics.is_query('least_used(ipaddress)'))

    def test_is_query_no_string(self):
        self.assertFalse(controller.statistics.is_query(42))
