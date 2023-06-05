import os
import random
import time
import numpy
from math import sqrt, ceil, log
from operator import itemgetter

import Lib.libpcapreader as pr
import Core.StatsDatabase as statsDB
import Lib.PcapFile as PcapFile
import Lib.Utility as Util
from Lib.IPv4 import IPAddress
import matplotlib.pyplot as plt


class Statistics(object):
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self, pcap_file: PcapFile.PcapFile):
        """
        Creates a new Statistics object.

        :param pcap_file: A reference to the PcapFile object
        """
        if self._initialized:
            return
        # Fields
        self.pcap_filepath = None
        self.path_db = None
        self.do_extra_tests = False
        self.file_info = None
        self.kbyte_rate = {"local": None, "public": None}
        self.interval_stat = {}
        self.interval_len = None

        if pcap_file:
            self.pcap_filepath = pcap_file.pcap_file_path

            # Create folder for statistics database if required
            self.path_db = pcap_file.get_db_path()

            # Class instances
            self.stats_db = self.create_stats_db(self.path_db)
            self._initialized = True

    @staticmethod
    def create_stats_db(path_db):
        path_dir = os.path.dirname(path_db)
        if not os.path.isdir(path_dir):
            os.makedirs(path_dir)
        return statsDB.StatsDatabase(path_db)

    def list_previous_interval_statistic_tables(self, output: bool=True):
        """
        Prints a list of all interval statistic tables from the database.

        :return: A list of intervals in seconds used to create the previous interval statistics tables
        """
        if self.stats_db.process_db_query("SELECT name FROM sqlite_master WHERE name='interval_tables';"):
            previous_interval_tables = self.stats_db.process_db_query("SELECT * FROM interval_tables;")
        else:
            previous_interval_tables = self.stats_db.process_db_query("SELECT name FROM sqlite_master WHERE "
                                                                      "type='table' AND name LIKE "
                                                                      "'interval_statistics_%';")
        previous_intervals = []
        if previous_interval_tables:
            if not isinstance(previous_interval_tables, list):
                previous_interval_tables = [previous_interval_tables]
            if output:
                print("There are " + str(len(previous_interval_tables)) + " interval statistics table(s) in the "
                                                                      "database:")
            i = 0
            if output:
                print("ID".ljust(3) + " | " + "interval in seconds".ljust(30) + " | is_default", end="")
                if len(previous_interval_tables) > 0 and len(previous_interval_tables[0]) > 2:
                    print( " | extra_tests")
                else:
                    print("")
            for table in previous_interval_tables:
                seconds = float(table[0][len("interval_statistics_"):])/1000000
                if output:
                    print(str(i).ljust(3) + " | " + str(seconds).ljust(30) + " | " + str(table[1]).ljust(
                        len("is_default")), end="")
                    if len(table) > 2:
                        print(" | " + str(table[2]))
                    else:
                        print("")
                previous_intervals.append(seconds)
                i = i + 1
        return previous_intervals

    def create_new_db(self, pcap: PcapFile.PcapFile, extra_tests: bool, flag_write_file: bool,
                      flag_recalculate_stats: bool, intervals, delete: bool = False,
                      recalculate_intervals: bool = None):
        pcap_db_path = pcap.get_db_path()
        stats_db = self.create_stats_db(pcap_db_path)
        self.load_pcap_statistics(flag_write_file, flag_recalculate_stats, True, True, intervals, delete,
                                  recalculate_intervals, extra_tests, pcap.pcap_file_path, pcap_db_path, stats_db)

    def load_pcap_statistics(self, flag_write_file: bool, flag_recalculate_stats: bool, flag_print_statistics: bool,
                             flag_non_verbose: bool, intervals, delete: bool = False,
                             recalculate_intervals: bool = None, extra_tests: bool = None, pcap_filepath: str = None,
                             path_db: str = None, stats_db: statsDB.StatsDatabase = None):
        """
        Loads the PCAP statistics for the file specified by pcap_filepath. If the database is not existing yet, the
        statistics are calculated by the PCAP file processor and saved into the newly created database. Otherwise the
        statistics are gathered directly from the existing database.

        :param flag_write_file: Indicates whether the statistics should be written additionally into a text file (True)
        or not (False)
        :param flag_recalculate_stats: Indicates whether eventually existing statistics should be recalculated
        :param flag_print_statistics: Indicates whether the gathered basic statistics should be printed to the terminal
        :param flag_non_verbose: Indicates whether certain prints should be made or not, to reduce terminal clutter
        :param intervals: user specified interval in seconds
        :param delete: Delete old interval statistics.
        :param recalculate_intervals: Recalculate old interval statistics or not. Prompt user if None.
        :param extra_tests:
        :param pcap_filepath:
        :param path_db:
        :param stats_db:
        """
        # Load pcap and get loading time
        time_start = time.perf_counter()

        if extra_tests is None:
            extra_tests = self.do_extra_tests
        if pcap_filepath is None:
            pcap_filepath = self.pcap_filepath
        if path_db is None:
            path_db = self.path_db
        if stats_db is None:
            stats_db = self.stats_db

        # Make sure user specified intervals are a list
        if intervals is None or intervals == []:
            intervals = [0.0]
        elif not isinstance(intervals, list):
            intervals = [intervals]

        current_intervals = intervals[:]

        # Inform user about recalculation of statistics and its reason
        if flag_recalculate_stats:
            print("Flag -r/--recalculate found. Recalculating statistics.")

        outstring_datasource = "from statistics database."

        # Recalculate statistics if database does not exist OR param -r/--recalculate is provided
        # FIXME: probably wanna add a "calculate only extra tests" case in the future
        if (not stats_db.get_db_exists()) or flag_recalculate_stats or stats_db.get_db_outdated():
            # Get interval statistics tables which already exist
            previous_intervals = self.list_previous_interval_statistic_tables()

            pcap_proc = pr.pcap_processor(pcap_filepath, str(extra_tests), Util.RESOURCE_DIR, path_db)

            recalc_intervals = None
            if previous_intervals:
                if delete:
                    recalc_intervals = False
                else:
                    recalc_intervals = recalculate_intervals
                while recalc_intervals is None:
                    user_input = input("Do you want to recalculate them as well? (y)es|(n)o|(d)elete: ")
                    if user_input.lower() == "yes" or user_input.lower() == "y":
                        recalc_intervals = True
                    elif user_input.lower() == "no" or user_input.lower() == "n":
                        recalc_intervals = False
                    elif user_input.lower() == "delete" or user_input.lower() == "d":
                        recalc_intervals = False
                        delete = True
                    else:
                        print("This was no valid input.")

            if recalc_intervals and previous_intervals:
                intervals = list(set(intervals + previous_intervals))
                print("The old interval statistics will be recalculated.")
            elif delete:
                print("The old interval statistics will be deleted.")
            else:
                print("The old interval statistics wont be recalculated.")

            if current_intervals != [0.0]:
                print("User specified intervals will be used to calculate interval statistics: " +
                      str(current_intervals)[1:-1])

            pcap_proc.collect_statistics(intervals)
            pcap_proc.write_to_database(path_db, intervals, delete)
            outstring_datasource = "by PCAP file processor."

            # only print summary of new db if -s flag not set
            if not flag_print_statistics and not flag_non_verbose:
                self.stats_summary_new_db()
        elif (intervals is not None and intervals != []) or extra_tests:
            pcap_proc = pr.pcap_processor(pcap_filepath, str(extra_tests), Util.RESOURCE_DIR, path_db)

            # Get interval statistics tables which already exist
            previous_intervals = self.list_previous_interval_statistic_tables(output=False)

            final_intervals = []
            if not extra_tests:
                for interval in intervals:
                    if interval not in previous_intervals:
                        final_intervals.append(interval)
            else:
                final_intervals = intervals

            if final_intervals != [0.0]:
                pcap_proc.collect_statistics(final_intervals)
                pcap_proc.write_new_interval_statistics(path_db, final_intervals)

        stats_db.set_current_interval_statistics_tables(current_intervals)

        # Load statistics from database
        if stats_db is self.stats_db:
            self.file_info = stats_db.get_file_info()

        time_end = time.perf_counter()
        print("Loaded file statistics in " + str(time_end - time_start)[:4] + " sec " + outstring_datasource)

        # Write statistics if param -e/--export provided
        if flag_write_file:
            self.write_statistics_to_file()
            self.write_statistics_to_file(interval=True)

        # Print statistics if param -s/--statistics provided
        if flag_print_statistics:
            self.print_statistics()

    def get_file_information(self):
        """
        Returns a list of tuples, each containing a information of the file.

        :return: a list of tuples, each consisting of (description, value, unit), where unit is optional.
        """

        pdu_count = self.process_db_query("SELECT SUM(pktCount) FROM unrecognized_pdus")
        if pdu_count is None:
            pdu_count = 0
        pdu_share = pdu_count / self.get_packet_count() * 100
        last_pdu_timestamp = self.process_db_query(
            "SELECT MAX(timestampLastOccurrence) FROM unrecognized_pdus")

        return [("Pcap file path", self.pcap_filepath),
                ("Total packet count", self.get_packet_count(), "packets"),
                ("Recognized packets", self.get_packet_count() - pdu_count, "packets"),
                ("Unrecognized packets", pdu_count, "PDUs"),
                ("% Recognized packets", 100 - pdu_share, "%"),
                ("% Unrecognized packets", pdu_share, "%"),
                ("Last unknown PDU", last_pdu_timestamp),
                ("Capture duration", self.get_capture_duration(), "seconds"),
                ("Capture start", "\t" + str(self.get_pcap_timestamp_start())),
                ("Capture end", "\t" + str(self.get_pcap_timestamp_end()))]

    def get_general_file_statistics(self):
        """
        Returns a list of tuples, each containing a file statistic.

        :return: a list of tuples, each consisting of (description, value, unit).
        """
        return [("Avg. packet rate", self.file_info['avgPacketRate'], "packets/sec"),
                ("Avg. packet size", self.file_info['avgPacketSize'], "kbytes"),
                ("Avg. packets sent", self.file_info['avgPacketsSentPerHost'], "packets"),
                ("Avg. bandwidth in", self.file_info['avgBandwidthIn'], "kbit/s"),
                ("Avg. bandwidth out", self.file_info['avgBandwidthOut'], "kbit/s")]

    def get_interval_statistics(self, table_name: str=""):
        """
        Returns a list of tuples, each containing interval statistics.

        :param table_name: the name of the interval statistics table
        :return: a list of tuples, each consisting of (description, values, unit).
        """
        column_names = self.stats_db.get_field_types(table_name)
        column_names = sorted(column_names)

        result = column_names[0]
        for name in column_names[1:]:
            result += ", " + name

        interval_stats = self.stats_db.process_interval_statistics_query(
            "SELECT {} FROM %s ORDER BY first_pkt_timestamp ASC".format(result),
            table_name)

        inverted_table = {}
        inverted_table["interval_count"] = 0

        for name in column_names:
            inverted_table[name] = []

        for row in interval_stats:
            for column, name in zip(row, column_names):
                if column is not None:
                    if type(column) == str:
                        try:
                            column = int(column)
                        except ValueError:
                            column = float(column)
                    elif type(column) == float:
                        column = round(column, 4)
                inverted_table[name].append(column)

        inverted_table["interval_count"] = len(inverted_table[column_names[0]])

        return sorted(inverted_table.items())

    def get_kbyte_rate(self, mode: str="local", custom_bandwidth_local: float=0, custom_bandwidth_public: float=0):
        """
        Takes a modes "local" or "public" and returns the maximal kybte rate based on the pcaps IP statistics and a
        predefined minimum.

        :param mode: a string that is either "local", "public" or "unknown"
        :param custom_bandwidth_local: bandwidth minimum for local traffic
        :param custom_bandwidth_public: bandwidth minimum for public traffic
        :return: bandwidth in kbyte/sec
        """
        # default bandwidth in kbytes/sec
        bandwidth_local = 12500 # 100 mbit/s
        bandwidth_public = 1250 #  10 mbit/s

        if custom_bandwidth_public != 0:
            bandwidth_public = custom_bandwidth_public
        if custom_bandwidth_local != 0:
            bandwidth_local = custom_bandwidth_local

        minimum_rate = {"local": bandwidth_local, "public": bandwidth_public}

        if mode=="unknown":
            return minimum_rate["local"]

        if not self.kbyte_rate[mode]:
            if mode=="local":
                self.kbyte_rate[mode] = self.stats_db.process_db_query\
                    ("select max(maxKByteRate) from ip_statistics where (ipClass like 'private') or (ipClass in ('A-unused','D'))")
            elif mode=="public":
                self.kbyte_rate[mode] = self.stats_db.process_db_query\
                    ("select max(maxKByteRate) from ip_statistics where ipClass in ('A','B','C','E')")

        if not self.kbyte_rate[mode]:
            return minimum_rate[mode]

        if mode == "local":
            i = 0
            # for local networks
            # set bandwidth to tenfold of its minimum until it is larger than the pcap bandwidth
            while self.kbyte_rate[mode] > minimum_rate[mode]:
                i += 1
                minimum_rate[mode] *= 10 * i
            self.kbyte_rate[mode] = minimum_rate[mode]
        else:
            # for public networks
            # increase the bandwidth by a multiple of 2 mbit/s according to the pcap bandwidth
            self.kbyte_rate[mode] = ceil(self.kbyte_rate[mode])
            remainder = self.kbyte_rate[mode] % 250
            if remainder != 0:
                self.kbyte_rate[mode] += 250 - remainder

        return max([self.kbyte_rate[mode], minimum_rate[mode]])

    def get_current_interval_len(self):
        """
        :return: the current interval length
        """
        if not self.interval_len:
            current_table = self.stats_db.get_current_interval_statistics_table()
            self.interval_len = int(current_table[len("statistics_interval_"):])
        return self.interval_len

    def get_interval_stat(self, table_name: str, field: str="", timestamp: int=0):
        """
        Takes an interval statistics table name, field/column name and a timestamp and provides the requested stat.

        :param table_name: name of the interval statistics table, from which to grab the field
        :param field: the name of the field, which to grab from the interval statistics table
        :param timestamp: the timestamp is used to determine the interval, from which to get the field
        :return: the content of an interval stat defined by interval and field name OR None if there is no interval stat
                 e.g. "kbytes" sent of a specific interval
        """
        if field not in self.interval_stat.keys():
            self.interval_stat[field] = {}

        # get unix timestamp depending on pcap start timestamp
        start = int(Util.get_timestamp_from_datetime_str(self.get_pcap_timestamp_start()) * 1000000)
        diff = timestamp * 1000000
        # catch --inject-empty timestamp issue
        if diff > start:
            diff -= start
        unix_timestamp = start + diff

        # get interval length
        interval_length = self.get_current_interval_len()

        interval = start + int(diff/interval_length) * interval_length

        if interval not in self.interval_stat[field].keys():
            # get interval borders
            lower = int(unix_timestamp - interval_length)
            upper = int(unix_timestamp)
            # catch negative borders
            if lower < 0:
                lower = 0

            # get interval start timestamps
            query_result = self.stats_db.process_interval_statistics_query\
                ("SELECT {0} FROM %s WHERE {1} BETWEEN {2} AND {3}".format(field, "first_pkt_timestamp", lower, upper),
                 table_name)

            result = None
            if query_result:
                result = query_result[0][0]

            self.interval_stat[field][interval] = result

        return self.interval_stat[field][interval], interval

    @staticmethod
    def write_list(desc_val_unit_list, func, line_ending="\n"):
        """
        Takes a list of tuples (statistic name, statistic value, unit) as input, generates a string of these three
        values and applies the function func on this string.

        Before generating the string, it identifies text containing a float number, casts the string to a
        float and rounds the value to two decimal digits.

        :param desc_val_unit_list: The list of tuples consisting of (description, value, unit)
        :param func: The function to be applied to each generated string
        :param line_ending: The formatting string to be applied at the end of each string
        """
        for entry in desc_val_unit_list:
            # Convert text containing float into float
            (description, value) = entry[0:2]
            if isinstance(value, str) and "." in value:
                try:
                    value = float(value)
                except ValueError:
                    pass  # do nothing -> value was not a float
            # round float
            if isinstance(value, float):
                value = round(value, 4)
            # check for lists
            if isinstance(value, list):
                # remove brackets
                value = str(value)[1:-1]
            # write into file
            if len(entry) == 3:
                unit = entry[2]
                func(description + ":\t" + str(value) + " " + unit + line_ending)
            else:
                func(description + ":\t" + str(value) + line_ending)

    def print_statistics(self):
        """
        Prints the basic file statistics to the terminal.
        """
        print("\nPCAP FILE INFORMATION ------------------------------")
        Statistics.write_list(self.get_file_information(), print, "")
        print("\nGENERAL FILE STATISTICS ----------------------------")
        Statistics.write_list(self.get_general_file_statistics(), print, "")
        print("\n")

    @staticmethod
    def calculate_entropy(frequency: list, normalized: bool = False):
        """
        Calculates entropy and normalized entropy of list of elements that have specific frequency
        :param frequency: The frequency of the elements.
        :param normalized: Calculate normalized entropy
        :return: entropy or (entropy, normalized entropy)
        """
        entropy, normalized_ent, n = 0, 0, 0
        sum_freq = sum(frequency)
        for i, x in enumerate(frequency):
            p_x = float(frequency[i] / sum_freq)
            if p_x > 0:
                n += 1
                entropy += - p_x * log(p_x, 2)
        if normalized:
            if log(n) > 0:
                normalized_ent = entropy / log(n, 2)
            return entropy, normalized_ent
        else:
            return entropy

    # TODO: replace complement packet rates with bandwidth calculations
    def calculate_complement_packet_rates(self, pps):
        """
        Calculates the complement packet rates of the background traffic packet rates for each interval.
        Then normalize it to maximum boundary, which is the input parameter pps

        :return: normalized packet rates for each time interval.
        """
        result = self.stats_db.process_interval_statistics_query(
            "SELECT last_pkt_timestamp,pkts_count FROM %s ORDER BY last_pkt_timestamp")
        # print(result)
        bg_interval_pps = []
        complement_interval_pps = []
        intervals_sum = 0
        if result:
            # Get the interval in seconds
            for i, row in enumerate(result):
                if i < len(result) - 1:
                    intervals_sum += ceil((int(result[i + 1][0]) * 10 ** -6) - (int(row[0]) * 10 ** -6))
            interval = intervals_sum / (len(result) - 1)
            # Convert timestamp from micro to seconds, convert packet rate "per interval" to "per second"
            for row in result:
                bg_interval_pps.append((int(row[0]) * 10 ** -6, int(row[1] / interval)))
            # Find max PPS
            max_pps = max(bg_interval_pps, key=itemgetter(1))[1]

            for row in bg_interval_pps:
                complement_interval_pps.append((row[0], int(pps * (max_pps - row[1]) / max_pps)))

        return complement_interval_pps

    def get_tests_statistics(self):
        """
        Writes the calculated basic defects tests statistics into a file.
        """

        # self.stats_db.process_user_defined_query output is list of tuples, thus, we ned [0][0] to access data

        def count_frequncy(values_list):
            """
            TODO : FILL ME
            :param values_list:
            :return:
            """
            values, freq_output = [], []
            for x in values_list:
                if x in values:
                    freq_output[values.index(x)] += 1
                else:
                    values.append(x)
                    freq_output.append(1)
            return values, freq_output

        # Payload Tests
        sum_payload_count = self.stats_db.process_interval_statistics_query("SELECT sum(payload_count) FROM %s")
        pkt_count = self.stats_db.process_user_defined_query("SELECT packetCount FROM file_statistics")
        if sum_payload_count and pkt_count:
            payload_ratio = 0
            if pkt_count[0][0] != 0:
                payload_ratio = float(sum_payload_count[0][0] / pkt_count[0][0] * 100)
        else:
            payload_ratio = -1

        # TCP checksum Tests
        incorrect_checksum_count = self.stats_db.process_interval_statistics_query(
            "SELECT sum(incorrect_tcp_checksum_count) FROM %s")
        correct_checksum_count = self.stats_db.process_interval_statistics_query(
            "SELECT avg(correct_tcp_checksum_count) FROM %s")
        if incorrect_checksum_count and correct_checksum_count:
            incorrect_checksum_ratio = 0
            if (incorrect_checksum_count[0][0] + correct_checksum_count[0][0]) != 0:
                incorrect_checksum_ratio = float(incorrect_checksum_count[0][0] /
                                                 (incorrect_checksum_count[0][0] + correct_checksum_count[0][0]) * 100)
        else:
            incorrect_checksum_ratio = -1

        # IP Src & Dst Tests
        result = self.stats_db.process_user_defined_query("SELECT ipAddress,pktsSent,pktsReceived FROM ip_statistics")
        data, src_frequency, dst_frequency = [], [], []
        if result:
            for row in result:
                src_frequency.append(row[1])
                dst_frequency.append(row[2])
        ip_src_entropy, ip_src_norm_entropy = self.calculate_entropy(src_frequency, True)
        ip_dst_entropy, ip_dst_norm_entropy = self.calculate_entropy(dst_frequency, True)

        new_ip_src_count = self.stats_db.process_interval_statistics_query("SELECT ip_src_novel_Count FROM %s")
        ip_src_novels_per_interval, ip_src_novels_per_interval_frequency = count_frequncy(new_ip_src_count)
        ip_src_novelty_dist_entropy = self.calculate_entropy(ip_src_novels_per_interval_frequency)

        new_ip_dst_count = self.stats_db.process_interval_statistics_query("SELECT ip_dst_novel_Count FROM %s")
        ip_dst_novels_per_interval, ip_dst_novels_per_interval_frequency = count_frequncy(new_ip_dst_count)
        ip_dst_novelty_dist_entropy = self.calculate_entropy(ip_dst_novels_per_interval_frequency)

        # Ports Tests
        port0_count = self.stats_db.process_user_defined_query(
            "SELECT SUM(portCount) FROM ip_ports WHERE portNumber = 0")
        if not port0_count[0][0]:
            port0_count = 0
        else:
            port0_count = port0_count[0][0]
        # FIXME: could be extended
        reserved_port_count = self.stats_db.process_user_defined_query(
            "SELECT SUM(portCount) FROM ip_ports WHERE portNumber IN (100,114,1023,1024,49151,49152,65535)")
        if not reserved_port_count[0][0]:
            reserved_port_count = 0
        else:
            reserved_port_count = reserved_port_count[0][0]

        # TTL Tests
        result = self.stats_db.process_user_defined_query(
            "SELECT ttlValue,SUM(ttlCount) FROM ip_ttl GROUP BY ttlValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        ttl_entropy, ttl_norm_entropy = self.calculate_entropy(frequency, True)
        new_ttl_count = self.stats_db.process_interval_statistics_query("SELECT ttl_novel_count FROM %s")
        ttl_novels_per_interval, ttl_novels_per_interval_frequency = count_frequncy(new_ttl_count)
        ttl_novelty_dist_entropy = self.calculate_entropy(ttl_novels_per_interval_frequency)

        # Window Size Tests
        result = self.stats_db.process_user_defined_query("SELECT winSize,SUM(winCount) FROM tcp_win GROUP BY winSize")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        win_entropy, win_norm_entropy = self.calculate_entropy(frequency, True)
        new_win_size_count = self.stats_db.process_interval_statistics_query("SELECT win_size_novel_count FROM %s")
        win_novels_per_interval, win_novels_per_interval_frequency = count_frequncy(new_win_size_count)
        win_novelty_dist_entropy = self.calculate_entropy(win_novels_per_interval_frequency)

        # ToS Tests
        result = self.stats_db.process_user_defined_query(
            "SELECT tosValue,SUM(tosCount) FROM ip_tos GROUP BY tosValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        tos_entropy, tos_norm_entropy = self.calculate_entropy(frequency, True)
        new_tos_count = self.stats_db.process_interval_statistics_query("SELECT tos_novel_count FROM %s")
        tos_novels_per_interval, tos_novels_per_interval_frequency = count_frequncy(new_tos_count)
        tos_novelty_dist_entropy = self.calculate_entropy(tos_novels_per_interval_frequency)

        # MSS Tests
        result = self.stats_db.process_user_defined_query(
            "SELECT mssValue,SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        mss_entropy, mss_norm_entropy = self.calculate_entropy(frequency, True)
        new_mss_count = self.stats_db.process_interval_statistics_query("SELECT mss_novel_count FROM %s")
        mss_novels_per_interval, mss_novels_per_interval_frequency = count_frequncy(new_mss_count)
        mss_novelty_dist_entropy = self.calculate_entropy(mss_novels_per_interval_frequency)

        result = self.stats_db.process_user_defined_query("SELECT SUM(mssCount) FROM tcp_mss WHERE mssValue > 1460")
        # The most used MSS < 1460. Calculate the ratio of the values bigger that 1460.
        if not result[0][0]:
            result = 0
        else:
            result = result[0][0]
        big_mss = (result / sum(frequency)) * 100

        output = []
        if self.do_extra_tests:
            output = [("Payload ratio", payload_ratio, "%"),
                      ("Incorrect TCP checksum ratio", incorrect_checksum_ratio, "%")]

        output = output + [("# IP addresses", sum([x[0] for x in new_ip_src_count]), ""),
                           ("IP Src Entropy", ip_src_entropy, ""),
                           ("IP Src Normalized Entropy", ip_src_norm_entropy, ""),
                           ("IP Dst Entropy", ip_dst_entropy, ""),
                           ("IP Dst Normalized Entropy", ip_dst_norm_entropy, ""),
                           ("IP SRC Novelty Distribution Entropy", ip_src_novelty_dist_entropy, ""),
                           ("IP DST Novelty Distribution Entropy", ip_dst_novelty_dist_entropy, ""),
                           ("# TTL values", sum([x[0] for x in new_ttl_count]), ""),
                           ("TTL Entropy", ttl_entropy, ""),
                           ("TTL Normalized Entropy", ttl_norm_entropy, ""),
                           ("TTL Novelty Distribution Entropy", ttl_novelty_dist_entropy, ""),
                           ("# WinSize values", sum([x[0] for x in new_win_size_count]), ""),
                           ("WinSize Entropy", win_entropy, ""),
                           ("WinSize Normalized Entropy", win_norm_entropy, ""),
                           ("WinSize Novelty Distribution Entropy", win_novelty_dist_entropy, ""),
                           ("# ToS values", sum([x[0] for x in new_tos_count]), ""),
                           ("ToS Entropy", tos_entropy, ""),
                           ("ToS Normalized Entropy", tos_norm_entropy, ""),
                           ("ToS Novelty Distribution Entropy", tos_novelty_dist_entropy, ""),
                           ("# MSS values", sum([x[0] for x in new_mss_count]), ""),
                           ("MSS Entropy", mss_entropy, ""),
                           ("MSS Normalized Entropy", mss_norm_entropy, ""),
                           ("MSS Novelty Distribution Entropy", mss_novelty_dist_entropy, ""),
                           ("======================", "", "")]

        # Reasoning the statistics values
        if self.do_extra_tests:
            if payload_ratio > 80:
                output.append(("WARNING: Too high payload ratio", payload_ratio, "%."))
            if payload_ratio < 30:
                output.append(("WARNING: Too low payload ratio", payload_ratio, "% (Injecting attacks that are carried "
                                                                                "out in the packet payloads is not "
                                                                                "recommmanded)."))

            if incorrect_checksum_ratio > 5:
                output.append(("WARNING: High incorrect TCP checksum ratio", incorrect_checksum_ratio, "%."))

        if ip_src_norm_entropy > 0.65:
            output.append(("WARNING: High IP source normalized entropy", ip_src_norm_entropy, "."))
        if ip_src_norm_entropy < 0.2:
            output.append(("WARNING: Low IP source normalized entropy", ip_src_norm_entropy, "."))
        if ip_dst_norm_entropy > 0.65:
            output.append(("WARNING: High IP destination normalized entropy", ip_dst_norm_entropy, "."))
        if ip_dst_norm_entropy < 0.2:
            output.append(("WARNING: Low IP destination normalized entropy", ip_dst_norm_entropy, "."))

        if ttl_norm_entropy > 0.65:
            output.append(("WARNING: High TTL normalized entropy", ttl_norm_entropy, "."))
        if ttl_norm_entropy < 0.2:
            output.append(("WARNING: Low TTL normalized entropy", ttl_norm_entropy, "."))
        if ttl_novelty_dist_entropy < 1:
            output.append(("WARNING: Too low TTL novelty distribution entropy", ttl_novelty_dist_entropy,
                           "(The distribution of the novel TTL values is suspicious)."))

        if win_norm_entropy > 0.6:
            output.append(("WARNING: High Window Size normalized entropy", win_norm_entropy, "."))
        if win_norm_entropy < 0.1:
            output.append(("WARNING: Low Window Size normalized entropy", win_norm_entropy, "."))
        if win_novelty_dist_entropy < 4:
            output.append(("WARNING: Low Window Size novelty distribution entropy", win_novelty_dist_entropy,
                           "(The distribution of the novel Window Size values is suspicious)."))

        if tos_norm_entropy > 0.4:
            output.append(("WARNING: High ToS normalized entropy", tos_norm_entropy, "."))
        if tos_norm_entropy < 0.1:
            output.append(("WARNING: Low ToS normalized entropy", tos_norm_entropy, "."))
        if tos_novelty_dist_entropy < 0.5:
            output.append(("WARNING: Low ToS novelty distribution entropy", tos_novelty_dist_entropy,
                           "(The distribution of the novel ToS values is suspicious)."))

        if mss_norm_entropy > 0.4:
            output.append(("WARNING: High MSS normalized entropy", mss_norm_entropy, "."))
        if mss_norm_entropy < 0.1:
            output.append(("WARNING: Low MSS normalized entropy", mss_norm_entropy, "."))
        if mss_novelty_dist_entropy < 0.5:
            output.append(("WARNING: Low MSS novelty distribution entropy", mss_novelty_dist_entropy,
                           "(The distribution of the novel MSS values is suspicious)."))

        if big_mss > 50:
            output.append(("WARNING: High ratio of MSS > 1460", big_mss, "% (High fragmentation rate in Ethernet)."))

        if port0_count > 0:
            output.append(("WARNING: Port number 0 is used in ", port0_count, "packets (awkward-looking port)."))
        if reserved_port_count > 0:
            output.append(("WARNING: Reserved port numbers are used in ", reserved_port_count,
                           "packets (uncommonly-used ports)."))

        return output

    def write_statistics_to_file(self, interval: bool=False):
        """
        Writes the calculated basic statistics into a file.
        """

        def _write_header(title: str):
            """
            Writes the section header into the open file.

            :param title: The section title
            """
            target.write("====================== \n")
            target.write(title + " \n")
            target.write("====================== \n")

        def _write_sub_header(title: str):
            """
            Writes the section header into the open file.

            :param title: The section title
            """
            target.write("---------------------- \n")
            target.write(title + " \n")
            target.write("---------------------- \n")

        if interval:
            ed = ".interval_stat"
        else:
            ed = ".stat"

        target = open(self.pcap_filepath + ed, 'w')
        target.truncate()

        _write_header("PCAP file information")
        Statistics.write_list(self.get_file_information(), target.write)

        if interval:
            _write_header("Interval statistics")
            tables = self.stats_db.get_all_current_interval_statistics_tables()
            for table in tables:
                _write_sub_header(table[len("interval_staistiscs_"):] + " microseconds")
                Statistics.write_list(self.get_interval_statistics(table), target.write)
        else:
            _write_header("General statistics")
            Statistics.write_list(self.get_general_file_statistics(), target.write)

            _write_header("Tests statistics")
            Statistics.write_list(self.get_tests_statistics(), target.write)

        target.close()

    def get_capture_duration(self):
        """
        :return: The duration of the capture in seconds
        """
        return self.file_info['captureDuration']

    def get_pcap_timestamp_start(self):
        """
        :return: The timestamp of the first packet in the PCAP file
        """
        return self.file_info['timestampFirstPacket']

    def get_pcap_timestamp_end(self):
        """
        :return: The timestamp of the last packet in the PCAP file
        """
        return self.file_info['timestampLastPacket']

    def get_pps_sent(self, ip_address: str):
        """
        Calculates the sent packets per seconds for a given IP address.

        :param ip_address: The IP address whose packets per second should be calculated
        :return: The sent packets per seconds for the given IP address
        """
        packets_sent = self.stats_db.process_db_query("SELECT pktsSent from ip_statistics WHERE ipAddress=?", False,
                                                      (ip_address,))
        capture_duration = float(self.get_capture_duration())
        return int(float(packets_sent) / capture_duration)

    def get_pps_received(self, ip_address: str):
        """
        Calculate the packets per second received for a given IP address.

        :param ip_address: The IP address used for the calculation
        :return: The number of packets per second received
        """
        packets_received = self.stats_db.process_db_query("SELECT pktsReceived FROM ip_statistics WHERE ipAddress=?",
                                                          False,
                                                          (ip_address,))
        capture_duration = float(self.get_capture_duration())
        return int(float(packets_received) / capture_duration)

    def get_most_used_pps(self):
        """
        :return: the pps of the most used ip address
        """
        return self.get_pps_received(self.get_most_used_ip_address())

    def get_packet_count(self):
        """
        :return: The number of packets in the loaded PCAP file
        """
        return self.file_info['packetCount']

    def get_rnd_packet_index(self, divisor: int=1):
        """
        Calculates a random packet index. Either over all packets or the first part of the packets.
        For the latter you need to divide the total packet count. Use the divisor parameter for this.

        :param divisor: The divisor for total packet count.
        :return: The randomized packet index.
        """
        return random.randint(1, self.get_packet_count() // divisor)

    def get_most_used_ip_address(self):
        """
        :return: The IP address/addresses with the highest sum of packets sent and received
        """
        return Util.handle_most_used_outputs(self.process_db_query("most_used(ipAddress)"))

    def get_ttl_distribution(self, ip_address: str):
        """
        TODO: FILL ME
        :param ip_address:
        :return:
        """
        result = self.process_db_query('SELECT ttlValue, ttlCount from ip_ttl WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_mss_distribution(self, ip_address: str):
        """
        TODO: FILL ME
        :param ip_address:
        :return:
        """
        result = self.process_db_query('SELECT mssValue, mssCount from tcp_mss WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_win_distribution(self, ip_address: str):
        """
        TODO: FILL ME
        :param ip_address:
        :return:
        """
        result = self.process_db_query('SELECT winSize, winCount from tcp_win WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_win_distribution_for_ip_with_win_sizes(self):
        """
        Retrieves the window size distribution for the IP address with the most unique window sizes in the 'tcp_win' table. 
        If the IP with the most unique window sizes is not assigned (empty string), it falls back to the IP with the second most unique window sizes.
        :return: The window distribution for a  IP address.
        """
        random_ip  = self.process_db_query(
        "SELECT ipAddress FROM (SELECT ipAddress, COUNT(DISTINCT winSize) as uniqueWinSizes FROM tcp_win GROUP BY ipAddress) ORDER BY uniqueWinSizes DESC LIMIT 2"
    )   
        if not random_ip:
            return
        if random_ip[0] == '': # ignore TCP win sizes which are not assigned to an IP. 
            ip_address = random_ip[1]
        else: 
             ip_address = random_ip[0]

        # Now use this IP address to get the window distribution.
        result = self.process_db_query('SELECT winSize, winCount FROM tcp_win WHERE ipAddress="' + ip_address + '" ORDER BY winCount DESC LIMIT 20 ')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_tos_distribution(self, ip_address: str):
        """
        TODO: FILL ME
        :param ip_address:
        :return:
        """
        result = self.process_db_query('SELECT tosValue, tosCount from ip_tos WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_ip_address_count(self):
        """
        TODO: FILL ME
        :return:
        """
        return self.process_db_query("SELECT COUNT(*) FROM ip_statistics")

    def get_ip_addresses(self):
        """
        TODO: FILL ME
        :return:
        """
        return self.process_db_query("SELECT ipAddress FROM ip_statistics")

    def get_random_ip_address(self, count: int = 1, ips: list = None):
        """
        :param count: The number of IP addresses to return
        :param ips: The ips the result should not include
        :return: A randomly chosen IP address from the dataset or iff param count is greater than one, a list of
        randomly chosen IP addresses
        """
        ip_address_list = self.process_db_query("SELECT ipAddress from ip_statistics ORDER BY ipAddress ASC")
        if count == 1:
            return random.choice(ip_address_list)
        else:
            result_list = []
            for i in range(0, count):
                random_ip = random.choice(ip_address_list)
                if ips:
                    while random_ip in ips:
                        random_ip = random.choice(ip_address_list)
                result_list.append(random_ip)
                ip_address_list.remove(random_ip)
            return result_list

    def get_ip_address_from_mac(self, mac_address: str):
        """
        :param mac_address: the MAC address of which the IP shall be returned, if existing in DB
        :return: the IP address used in the dataset by a given MAC address
        """
        return self.process_db_query("SELECT DISTINCT ipAddress FROM ip_mac WHERE macAddress = '" + mac_address + "'")

    def get_mac_addresses(self, ip_addresses: list):
        """
        :return: The MAC addresses used in the dataset for the given IP addresses as a dictionary.
        """
        return dict(self.process_db_query("SELECT DISTINCT ipAddress, macAddress from ip_mac WHERE ipAddress in ("
                                          + str(ip_addresses)[1:-1] + ")"))

    def get_mac_address(self, ip_address: str):
        """
        :return: The MAC address used in the dataset for the given IP address.
        """
        return self.process_db_query("SELECT DISTINCT macAddress from ip_mac WHERE ipAddress = '" + ip_address + "'")

    def get_most_used_ttl_value(self):
        """
        :return: The most used TTL value.
        """
        return self.process_db_query("SELECT ttlValue FROM (SELECT ttlValue, SUM(ttlCount) as occ FROM ip_ttl GROUP BY "
                                     "ttlValue) WHERE occ=(SELECT SUM(ttlCount) as occ FROM ip_ttl GROUP BY ttlValue "
                                     "ORDER BY occ DESC LIMIT 1) ORDER BY ttlValue ASC")

    def get_most_used_ip_class(self):
        """
        :return: The most used IP class.
        """
        return self.process_db_query("SELECT ipClass FROM (SELECT ipClass, COUNT(*) as occ from ip_statistics GROUP BY "
                                     "ipClass ORDER BY occ DESC) WHERE occ=(SELECT COUNT(*) as occ from ip_statistics "
                                     "GROUP BY ipClass ORDER BY occ DESC LIMIT 1) ORDER BY ipClass ASC")

    def get_most_used_win_size(self):
        """
        :return: The most used window size.
        """
        return self.process_db_query("SELECT winSize FROM (SELECT winSize, SUM(winCount) as occ FROM tcp_win GROUP BY "
                                     "winSize) WHERE occ=(SELECT SUM(winCount) as occ FROM tcp_win GROUP BY winSize "
                                     "ORDER BY occ DESC LIMIT 1) ORDER BY winSize ASC")

    def get_most_used_mss_value(self):
        """
        :return: The most used mss value.
        """
        return self.process_db_query("SELECT mssValue FROM (SELECT mssValue, SUM(mssCount) as occ FROM tcp_mss GROUP BY"
                                     " mssValue) WHERE occ=(SELECT SUM(mssCount) as occ FROM tcp_mss GROUP BY mssValue "
                                     "ORDER BY occ DESC LIMIT 1) ORDER BY mssValue ASC")

    def get_most_used_mss(self, ip_address: str):
        """
        :param ip_address: The IP address whose used MSS should be determined
        :return: The TCP MSS value used by the IP address, or if the IP addresses never specified a MSS,
        then None is returned
        """
        mss_value = self.process_db_query('SELECT mssValue from tcp_mss WHERE ipAddress="' + ip_address +
                                          '" AND mssCount == (SELECT MAX(mssCount) from tcp_mss WHERE ipAddress="'
                                          + ip_address + '")')
        if isinstance(mss_value, int):
            return mss_value
        elif isinstance(mss_value, list):
            if len(mss_value) == 0:
                return None
            else:
                mss_value.sort()
                return mss_value[0]
        else:
            return None

    def get_most_used_ttl(self, ip_address: str):
        """
        :param ip_address: The IP address whose used TTL should be determined
        :return: The TTL value used by the IP address, or if the IP addresses never specified a TTL,
        then None is returned
        """
        ttl_value = self.process_db_query('SELECT ttlValue from ip_ttl WHERE ipAddress="' + ip_address +
                                          '" AND ttlCount == (SELECT MAX(ttlCount) from ip_ttl WHERE ipAddress="'
                                          + ip_address + '")')
        if isinstance(ttl_value, int):
            return ttl_value
        elif isinstance(ttl_value, list):
            if len(ttl_value) == 0:
                return None
            else:
                ttl_value.sort()
                return ttl_value[0]
        else:
            return None

    def get_avg_delay_distributions(self, input_pcap: bool = True):
        """
        :return: tuple consisting of avg delay distributions for local and external communication
        """

        if input_pcap:
            delay_db = self.stats_db
        else:
            delay_db = statsDB.StatsDatabase(Util.get_botnet_pcap_db())

        conv_delays = delay_db.process_user_defined_query(
            "SELECT ipAddressA, ipAddressB, avgDelay FROM conv_statistics")
        if len(conv_delays) < 2:
            conv_delays = delay_db.process_user_defined_query(
                "SELECT ipAddressA, ipAddressB, avgDelay FROM conv_statistics_extended")

        if conv_delays:
            external_conv = []
            local_conv = []

            for conv in conv_delays:
                if conv[2] is not None:
                    ip_a = IPAddress.parse(conv[0])
                    ip_b = IPAddress.parse(conv[1])

                    # split into local and external conversations
                    if not ip_a.is_private() or not ip_b.is_private():
                        external_conv.append(conv)
                    else:
                        local_conv.append(conv)

            local_dist = []
            for conv in local_conv:
                local_dist.append(conv[2])

            external_dist = []
            for conv in external_conv:
                external_dist.append(conv[2])

            return local_dist, external_dist
        return [], []

    def get_filtered_degree(self, degree_type: str):
        """
        gets the desired type of degree statistics and filters IPs with degree value zero

        :param degree_type: the desired type of degrees, one of the following: inDegree, outDegree, overallDegree
        :return: the filtered degrees
        """

        degrees_raw = self.stats_db.process_user_defined_query(
            "SELECT ipAddress, %s FROM ip_degrees" % degree_type)

        degrees = []
        if degrees_raw:
            for deg in degrees_raw:
                if int(deg[1]) > 0:
                    degrees.append(deg)

        return degrees

    def get_rnd_win_size(self, pkts_num):
        """
        :param pkts_num: maximum number of window sizes, that should be returned
        :return: A list of randomly chosen window sizes with given length.
        """
        sql_return = self.process_db_query("SELECT DISTINCT winSize FROM tcp_win ORDER BY winsize ASC;")
        if not isinstance(sql_return, list):
            return [sql_return]
        result = []
        for i in range(0, min(pkts_num, len(sql_return))):
            result.append(random.choice(sql_return))
            sql_return.remove(result[i])
        return result

    def get_statistics_database(self):
        """
        :return: A reference to the statistics database object
        """
        return self.stats_db

    def process_db_query(self, query_string_in: str, print_results: bool = False):
        """
        Executes a string identified previously as a query. This can be a standard SQL SELECT/INSERT query or a named
        query.

        :param query_string_in: The query to be processed
        :param print_results: Indicates whether the results should be printed to terminal
        :return: The result of the query
        """
        return self.stats_db.process_db_query(query_string_in, print_results)

    def is_query(self, value: str):
        """
        Checks whether the given string is a standard SQL query (SELECT, INSERT) or a named query.

        :param value: The string to be checked
        :return: True if the string is recognized as a query, otherwise False.
        """
        if not isinstance(value, str):
            return False
        else:
            return (any(x in value.lower().strip() for x in self.stats_db.get_all_named_query_keywords()) or
                    any(x in value.lower().strip() for x in self.stats_db.get_all_sql_query_keywords()))

    @staticmethod
    def calculate_standard_deviation(lst):
        """
        Calculates the standard deviation of a list of numbers.

        :param lst: The list of numbers to calculate its SD.

        """
        num_items = len(lst)
        mean = sum(lst) / num_items
        differences = [x - mean for x in lst]
        sq_differences = [d ** 2 for d in differences]
        ssd = sum(sq_differences)
        variance = ssd / num_items
        sd = sqrt(variance)
        return sd

    def plot_statistics(self, entropy: int, file_format: str = 'pdf'):  # 'png'
        """
        Plots the statistics associated with the dataset.

        :param entropy: the statistics entropy
        :param file_format: The format to be used to save the statistics diagrams.
        """

        def plot_distribution(query_output, title, x_label, y_label, file_ending: str):
            """
            TODO: FILL ME
            :param query_output:
            :param title:
            :param x_label:
            :param y_label:
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            graphx, graphy = [], []
            for row in query_output:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title(title)
            plt.xlabel(x_label)
            plt.ylabel(y_label)
            width = 0.1
            plt.xlim([0, (max(graphx) * 1.1)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-' + title + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_ttl(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_user_defined_query(
                "SELECT ttlValue, SUM(ttlCount) FROM ip_ttl GROUP BY ttlValue")
            title = "TTL Distribution"
            x_label = "TTL Value"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_mss(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_user_defined_query(
                "SELECT mssValue, SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
            title = "MSS Distribution"
            x_label = "MSS Value"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_win(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_user_defined_query(
                "SELECT winSize, SUM(winCount) FROM tcp_win GROUP BY winSize")
            title = "Window Size Distribution"
            x_label = "Window Size"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_protocol(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT protocolName, SUM(protocolCount) FROM ip_protocols GROUP BY protocolName")
            if result:
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])
                plt.autoscale(enable=True, axis='both')
                plt.title("Protocols Distribution")
                plt.xlabel('Protocols')
                plt.ylabel('Number of Packets')
                width = 0.1
                plt.xlim([0, len(graphx)])
                plt.grid(True)

                # Protocols' names on x-axis
                x = range(0, len(graphx))
                my_xticks = graphx
                plt.xticks(x, my_xticks)

                plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-protocol' + file_ending)
                plt.savefig(out, dpi=500)
                return out
            else:
                print("Error plot protocol: No protocol values found!")

        def plot_port(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT portNumber, SUM(portCount) FROM ip_ports GROUP BY portNumber")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Ports Distribution")
            plt.xlabel('Ports Numbers')
            plt.ylabel('Number of Packets')
            width = 0.1
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-port' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # This distribution is not drawable for big datasets
        def plot_ip_src(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT ipAddress, pktsSent FROM ip_statistics")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Source IP Distribution")
            plt.xlabel('Source IP')
            plt.ylabel('Number of Packets')
            width = 0.1
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # IPs on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            # plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-src' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # This distribution is not drawable for big datasets
        def plot_ip_dst(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT ipAddress, pktsReceived FROM ip_statistics")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Destination IP Distribution")
            plt.xlabel('Destination IP')
            plt.ylabel('Number of Packets')
            width = 0.1
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # IPs on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            # plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-dst' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_statistics(query_output, title, x_label, y_label, file_ending: str):
            """
            TODO: FILL ME
            :param query_output:
            :param title:
            :param x_label:
            :param y_label:
            :param file_ending:
            :return:
            """
            plt.gcf().clear()
            graphx, graphy = [], []
            for row in query_output:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title(title)
            plt.xlabel(x_label)
            plt.ylabel(y_label)
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-' + title + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_pkt_count(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, pkts_count FROM %s ORDER BY last_pkt_timestamp")
            title = "Packet Rate"
            x_label = "Time Interval"
            y_label = "Number of Packets"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_src_ent(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, ip_src_entropy FROM %s ORDER BY last_pkt_timestamp")
            title = "Source IP Entropy"
            x_label = "Time Interval"
            y_label = "Entropy"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_dst_ent(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, ip_dst_entropy FROM %s ORDER BY last_pkt_timestamp")
            title = "Destination IP Entropy"
            x_label = "Time Interval"
            y_label = "Entropy"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_ip(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, newIPCount FROM %s ORDER BY last_pkt_timestamp")
            title = "IP Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_port(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, port_novel_count FROM %s ORDER BY last_pkt_timestamp")
            title = "Port Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_ttl(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, ttl_novel_count FROM %s ORDER BY last_pkt_timestamp")
            title = "TTL Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_tos(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, tos_novel_count FROM %s ORDER BY last_pkt_timestamp")
            title = "ToS Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_win_size(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, win_size_novel_count FROM %s ORDER BY last_pkt_timestamp")
            title = "Window Size Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_mss(file_ending: str):
            """
            TODO: FILL ME
            :param file_ending:
            :return:
            """
            query_output = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, mss_novel_count FROM %s ORDER BY last_pkt_timestamp")
            title = "MSS Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_cum_ent(ip_type: str, file_ending: str):
            """
            TODO: FILL ME
            :param ip_type: source or destination
            :param file_ending:
            :return:
            """
            if ip_type == "src":
                sod = "Src"
                full = "Source"
            elif ip_type == "dst":
                sod = "Dst"
                full = "Destination"
            else:
                return None

            plt.gcf().clear()
            result = self.stats_db.process_interval_statistics_query(
                "SELECT last_pkt_timestamp, ip{0}_cum_entropy FROM %s ORDER BY last_pkt_timestamp".format(sod))
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            # If entropy was not calculated do not plot the graph
            if graphy[0] != -1:
                plt.autoscale(enable=True, axis='both')
                plt.title(full + " IP Cumulative Entropy")
                # plt.xlabel('Timestamp')
                plt.xlabel('Time Interval')
                plt.ylabel('Entropy')
                plt.xlim([0, len(graphx)])
                plt.grid(True)

                # timestamp on x-axis
                x = range(0, len(graphx))
                # my_xticks = graphx
                # plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
                # plt.tight_layout()

                # limit the number of xticks
                plt.locator_params(axis='x', nbins=20)

                plt.plot(x, graphy, 'r')
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-' + ip_type + '-cum-ent' + file_ending)
                plt.savefig(out, dpi=500)
                return out

        def plot_degree(degree_type: str, file_ending: str):
            """
            Creates a Plot, visualizing a degree for every IP Address

            :param degree_type: the type of degree, which should be plotted
            :param file_ending: The file extension for the output file containing the plot, e.g. "pdf"
            :return: A filepath to the file containing the created plot
            """
            if degree_type not in ["in", "out", "overall"]:
                return None

            plt.gcf().clear()

            # retrieve data

            degree = self.stats_db.process_user_defined_query(
                "SELECT ipAddress, %s FROM ip_degrees" % (degree_type + "Degree"))

            if degree is None:
                return None

            graphx, graphy = [], []
            for entry in degree:
                if entry[1] <= 0:
                    continue
                # degree values
                graphx.append(entry[1])
                # IP labels
                graphy.append(entry[0])

            # set labels
            plt.title(degree_type + " Degree per IP Address")
            plt.ylabel('IpAddress')
            plt.xlabel(degree_type + 'Degree')

            # set width of the bars
            width = 0.3

            # set scalings
            plt.figure(
                figsize=(int(len(graphx)) / 20 + 5, int(len(graphy) / 5) + 5))  # these proportions just worked well

            # set limits of the axis
            plt.ylim([0, len(graphy)])
            plt.xlim([0, max(graphx) + 10])

            # display numbers at each bar
            for i, v in enumerate(graphx):
                plt.text(v + 1, i + .1, str(v), color='blue', fontweight='bold')

            # display grid for better visuals
            plt.grid(True)

            # plot the bar
            labels = graphy
            graphy = list(range(len(graphx)))
            plt.barh(graphy, graphx, width, align='center', linewidth=1, color='red', edgecolor='red')
            plt.yticks(graphy, labels)
            out = self.pcap_filepath.replace('.pcap', '_plot-' + degree_type + ' Degree of an IP' + file_ending)
            # plt.tight_layout()
            plt.savefig(out, dpi=500)

            return out

        def plot_big_conv_ext_stat(attr: str, title: str, xlabel: str, suffix: str):
            """
            Plots the desired statistc per connection as horizontal bar plot.
            Included are 'half-open' connections, where only one packet is exchanged.
            The given statistics table has to have at least the attributes 'ipAddressA', 'portA', 'ipAddressB',
            'portB' and the specified additional attribute.
            Note: there may be cutoff/scaling problems within the plot if there is too little data.

            :param attr: The desired statistic, named with respect to its attribute in the given statistics table
            :param title: The title of the created plot
            :param xlabel: The name of the x-axis of the created plot
            :param suffix: The suffix of the created file, including file extension
            :return: A filepath to the file containing the created plot
            """
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT ipAddressA, portA, ipAddressB, portB, %s FROM conv_statistics_extended" % attr)

            if result:
                graphy, graphx = [], []
                # plot data in descending order
                result = sorted(result, key=lambda r: r[4])
                # compute plot data
                for i, row in enumerate(result):
                    addr1, addr2 = "%s:%d" % (row[0], row[1]), "%s:%d" % (row[2], row[3])
                    # adjust the justification of strings to improve appearance
                    len_max = max(len(addr1), len(addr2))
                    addr1 = addr1.ljust(len_max)
                    addr2 = addr2.ljust(len_max)
                    # add plot data
                    graphy.append("%s\n%s" % (addr1, addr2))
                    graphx.append(row[4])

            # have x axis and its label appear at the top (instead of bottom)
            fig, ax = plt.subplots()
            ax.xaxis.tick_top()
            ax.xaxis.set_label_position("top")

            # compute plot height in inches for scaling the plot
            dist_mult_height = 0.55  # this value turned out to work well
            plt_height = len(graphy) * dist_mult_height
            # originally, a good title distance turned out to be 1.012 with a plot height of 52.8
            title_distance = 1 + 0.012 * 52.8 / plt_height

            plt.gcf().set_size_inches(plt.gcf().get_size_inches()[0], plt_height)  # set plot height
            plt.gcf().subplots_adjust(left=0.35)

            # set additional plot parameters
            plt.title(title, y=title_distance)
            plt.xlabel(xlabel)
            plt.ylabel('Connection')
            width = 0.5
            plt.grid(True)
            plt.gca().margins(y=0)  # removes the space between data and x-axis within the plot

            # plot the above data, first use plain numbers as graphy to maintain sorting
            plt.barh(range(len(graphy)), graphx, width, align='center', linewidth=0.5, color='red', edgecolor='red')
            # now change the y numbers to the respective address labels
            plt.yticks(range(len(graphy)), graphy)

            # save created figure
            out = self.pcap_filepath.replace('.pcap', suffix)
            plt.savefig(out, dpi=500)
            return out

        def plot_packets_per_connection(file_ending: str):
            """
            Plots the total number of exchanged packets per connection.

            :param file_ending: The file extension for the output file containing the plot
            :return: A filepath to the file containing the created plot
            """

            title = 'Number of exchanged packets per connection'
            suffix = '_plot-PktCount per Connection Distribution' + file_ending

            # plot data and return outpath
            return plot_big_conv_ext_stat("pktsCount", title, "Number of packets", suffix)

        def plot_avg_pkts_per_comm_interval(file_ending: str):
            """
            Plots the average number of exchanged packets per communication interval for every connection.

            :param file_ending: The file extension for the output file containing the plot
            :return: A filepath to the file containing the created plot
            """

            title = 'Average number of exchanged packets per communication interval'
            suffix = '_plot-Avg PktCount Communication Interval Distribution' + file_ending

            # plot data and return outpath
            return plot_big_conv_ext_stat("avgIntervalPktCount", title, "Number of packets", suffix)

        def plot_avg_time_between_comm_interval(file_ending: str):
            """
            Plots the average time between the communication intervals of every connection.

            :param file_ending: The file extension for the output file containing the plot
            :return: A filepath to the file containing the created plot
            """

            title = 'Average time between communication intervals in seconds'
            suffix = '_plot-Avg Time Between Communication Intervals Distribution' + file_ending

            # plot data and return outpath
            return plot_big_conv_ext_stat("avgTimeBetweenIntervals", title, 'Average time between intervals', suffix)

        def plot_avg_comm_interval_time(file_ending: str):
            """
            Plots the average duration of a communication interval of every connection.

            :param file_ending: The file extension for the output file containing the plot
            :return: A filepath to the file containing the created plot
            """

            title = 'Average duration of a communication interval in seconds'
            suffix = '_plot-Avg Duration Communication Interval Distribution' + file_ending

            # plot data and return outpath
            return plot_big_conv_ext_stat("avgIntervalTime", title, 'Average interval time', suffix)

        def plot_total_comm_duration(file_ending: str):
            """
            Plots the total communication duration of every connection.

            :param file_ending: The file extension for the output file containing the plot
            :return: A filepath to the file containing the created plot
            """

            title = 'Total communication duration in seconds'
            suffix = '_plot-Total Communication Duration Distribution' + file_ending

            # plot data and return outpath
            return plot_big_conv_ext_stat("totalConversationDuration", title, 'Duration', suffix)

        def plot_comm_histogram(attr: str, title: str, label: str, suffix: str):
            """
            Plots a histogram about the specified attribute for communications.
            :param attr: The statistics attribute for this histogram
            :param title: The title of the histogram
            :param label: The xlabel of the histogram
            :param suffix: The file suffix
            :return: The path to the created plot
            """

            plt.gcf().clear()
            result_raw = self.stats_db.process_user_defined_query(
                "SELECT %s FROM conv_statistics_extended" % attr)

            # return without plotting if no data available
            if not result_raw:
                return None

            result = []
            for entry in result_raw:
                result.append(entry[0])

            # if title would be cut off, set minimum width
            plt_size = plt.gcf().get_size_inches()
            min_width = len(title) * 0.12
            if plt_size[0] < min_width:
                plt.gcf().set_size_inches(min_width, plt_size[1])  # set plot size

            # set additional plot parameters
            plt.title(title)
            plt.ylabel("Relative frequency of connections")
            plt.xlabel(label)
            plt.grid(True)

            # create 11 bins
            bins = []
            max_val = max(result)
            for i in range(0, 11):
                bins.append(i * max_val / 10)

            # set weights normalize histogram
            weights = numpy.ones_like(result) / float(len(result))

            # plot the above data, first use plain numbers as graphy to maintain sorting
            plt.hist(result, bins=bins, weights=weights, color='red', edgecolor='red', align="mid", rwidth=0.5)
            plt.xticks(bins)

            # save created figure
            out = self.pcap_filepath.replace('.pcap', suffix)
            plt.savefig(out, dpi=500)
            return out

        def plot_histogram_degree(degree_type: str, title: str, label: str, suffix: str):
            """
            Plots a histogram about the specified type for the degree of an IP.
            :param degree_type: The type of degree, i.e. inDegree, outDegree or overallDegree
            :param title: The title of the histogram
            :param label: The xlabel of the histogram
            :param suffix: The file suffix
            :return: The path to the created plot
            """

            plt.gcf().clear()
            result_raw = self.get_filtered_degree(degree_type)

            # return without plotting if no data available
            if not result_raw:
                return None

            result = []
            for entry in result_raw:
                result.append(entry[1])

            # set additional plot parameters
            plt.title(title)
            plt.ylabel("Relative frequency of IPs")
            plt.xlabel(label)
            plt.grid(True)

            # create 11 bins
            bins = []
            max_val = max(result)
            for i in range(0, 11):
                bins.append(int(i * max_val / 10))

            # set weights normalize histogram
            weights = numpy.ones_like(result) / float(len(result))

            # plot the above data, first use plain numbers as graphy to maintain sorting
            plt.hist(result, bins=bins, weights=weights, color='red', edgecolor='red', align="mid", rwidth=0.5)
            plt.xticks(bins)

            # save created figure
            out = self.pcap_filepath.replace('.pcap', suffix)
            plt.savefig(out, dpi=500)
            return out

        ttl_out_path = plot_ttl('.' + file_format)
        print(".", end="", flush=True)
        mss_out_path = plot_mss('.' + file_format)
        print(".", end="", flush=True)
        win_out_path = plot_win('.' + file_format)
        print(".", end="", flush=True)
        protocol_out_path = plot_protocol('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_pktCount = plot_interval_pkt_count('.' + file_format)
        print(".", end="", flush=True)
        if entropy:
            plot_interval_ip_src_ent = plot_interval_ip_src_ent('.' + file_format)
            print(".", end="", flush=True)
            plot_interval_ip_dst_ent = plot_interval_ip_dst_ent('.' + file_format)
            print(".", end="", flush=True)
            plot_interval_ip_src_cum_ent = plot_interval_ip_cum_ent("src", '.' + file_format)
            print(".", end="", flush=True)
            plot_interval_ip_dst_cum_ent = plot_interval_ip_cum_ent("dst", '.' + file_format)
            print(".", end="", flush=True)
        plot_interval_new_ip = plot_interval_new_ip('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_new_port = plot_interval_new_port('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_new_ttl = plot_interval_new_ttl('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_new_tos = plot_interval_new_tos('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_new_win_size = plot_interval_new_win_size('.' + file_format)
        print(".", end="", flush=True)
        plot_interval_new_mss = plot_interval_new_mss('.' + file_format)
        print(".", end="", flush=True)
        plot_hist_indegree_out = plot_histogram_degree("inDegree", "Histogram - Ingoing degree per IP Address",
                                                       "Ingoing degree",
                                                       "_plot-Histogram Ingoing Degree per IP" + file_format)
        print(".", end="", flush=True)
        plot_hist_outdegree_out = plot_histogram_degree("outDegree", "Histogram - Outgoing degree per IP Address",
                                                        "Outgoing degree",
                                                        "_plot-Histogram Outgoing Degree per IP" + file_format)
        print(".", end="", flush=True)
        plot_hist_overalldegree_out = plot_histogram_degree("overallDegree",
                                                            "Histogram - Overall degree per IP Address",
                                                            "Overall degree",
                                                            "_plot-Histogram Overall Degree per IP" + file_format)
        print(".", end="", flush=True)
        plot_hist_pkts_per_connection_out = plot_comm_histogram("pktsCount",
                                                                "Histogram - Number of exchanged packets per connection",
                                                                "Number of packets",
                                                                "_plot-Histogram PktCount per Connection" + "." + file_format)
        print(".", end="", flush=True)
        plot_hist_avgpkts_per_commint_out = plot_comm_histogram("avgIntervalPktCount",
                                                                "Histogram - Average number of exchanged packets per communication interval",
                                                                "Average number of packets",
                                                                "_plot-Histogram Avg PktCount per Interval per Connection" + "." + file_format)
        print(".", end="", flush=True)
        plot_hist_avgtime_betw_commints_out = plot_comm_histogram("avgTimeBetweenIntervals",
                                                                  "Histogram - Average time between communication intervals in seconds",
                                                                  "Average time between intervals",
                                                                  "_plot-Histogram Avg Time Between Intervals per Connection" + "." + file_format)
        print(".", end="", flush=True)
        plot_hist_avg_int_time_per_connection_out = plot_comm_histogram("avgIntervalTime",
                                                                        "Histogram - Average duration of a communication interval in seconds",
                                                                        "Average interval time",
                                                                        "_plot-Histogram Avg Interval Time per Connection" + "." + file_format)
        print(".", end="", flush=True)
        plot_hist_total_comm_duration_out = plot_comm_histogram("totalConversationDuration",
                                                                "Histogram - Total communication duration in seconds",
                                                                "Duration",
                                                                "_plot-Histogram Communication Duration per Connection" + "." + file_format)
        print(".", end="", flush=True)
        if entropy:
            plot_out_degree = plot_degree("out", '.' + file_format)
            print(".", end="", flush=True)
            plot_in_degree = plot_degree("in", '.' + file_format)
            print(".", end="", flush=True)
            plot_overall_degree = plot_degree("overall", '.' + file_format)
            print(".", end="", flush=True)
            plot_packets_per_connection_out = plot_packets_per_connection('.' + file_format)
            print(".", end="", flush=True)
            plot_avg_pkts_per_comm_interval_out = plot_avg_pkts_per_comm_interval('.' + file_format)
            print(".", end="", flush=True)
            plot_avg_time_between_comm_interval_out = plot_avg_time_between_comm_interval('.' + file_format)
            print(".", end="", flush=True)
            plot_avg_comm_interval_time_out = plot_avg_comm_interval_time("." + file_format)
            print(".", end="", flush=True)
            plot_total_comm_duration_out = plot_total_comm_duration("." + file_format)
            print(".", end="", flush=True)
        print(" done.")

        # Time consuming plot
        # port_out_path = plot_port('.' + format)
        # Not drawable for too many IPs
        # ip_src_out_path = plot_ip_src('.' + format)
        # ip_dst_out_path = plot_ip_dst('.' + format)

        print("Saved plots in the input PCAP directory.")

    def stats_summary_post_attack(self, added_packets):
        """
        Prints a summary of relevant statistics after an attack is injected

        :param added_packets: sum of packets added by attacks, gets updated if more than one attack
        :return: None
        """

        total_packet_count = self.get_packet_count() + added_packets
        added_packets_share = added_packets / total_packet_count * 100
        timespan = self.get_capture_duration()

        summary = [("Total packet count", total_packet_count, "packets"),
                   ("Added packet count", added_packets, "packets"),
                   ("Share of added packets", added_packets_share, "%"),
                   ("Capture duration", timespan, "seconds")]

        print("\nPOST INJECTION STATISTICS SUMMARY  --------------------------")
        self.write_list(summary, print, "")
        print("------------------------------------------------------------")

    def stats_summary_new_db(self):
        """
        Prints a summary of relevant statistics when a new db is created

        :return: None
        """

        self.file_info = self.stats_db.get_file_info()
        print("\nNew database has been generated, printing statistics summary... ")
        total_packet_count = self.get_packet_count()
        pdu_count = self.process_db_query("SELECT SUM(pktCount) FROM unrecognized_pdus")
        if pdu_count is None:
            pdu_count = 0
        pdu_share = pdu_count / total_packet_count * 100
        last_pdu_timestamp = self.process_db_query(
            "SELECT MAX(timestampLastOccurrence) FROM unrecognized_pdus")
        timespan = self.get_capture_duration()

        summary = [("Total packet count", total_packet_count, "packets"),
                   ("Recognized packets", total_packet_count - pdu_count, "packets"),
                   ("Unrecognized packets", pdu_count, "PDUs"),
                   ("% Recognized packets", 100 - pdu_share, "%"),
                   ("% Unrecognized packets", pdu_share, "%"),
                   ("Last unknown PDU", last_pdu_timestamp),
                   ("Capture duration", timespan, "seconds")]

        print("\nPCAP FILE STATISTICS SUMMARY  ------------------------------")
        self.write_list(summary, print, "")
        print("------------------------------------------------------------")
