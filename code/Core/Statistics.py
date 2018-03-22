import os
import random
import time
from math import sqrt, ceil, log
from operator import itemgetter

# TODO: double check this import
# does it complain because libpcapreader is not a .py?
import ID2TLib.libpcapreader as pr
import matplotlib

import Core.StatsDatabase as statsDB
import ID2TLib.PcapFile as PcapFile
import ID2TLib.Utility as Util

matplotlib.use('Agg', force=True)
import matplotlib.pyplot as plt


class Statistics:
    def __init__(self, pcap_file: PcapFile.PcapFile):
        """
        Creates a new Statistics object.

        :param pcap_file: A reference to the PcapFile object
        """
        # Fields
        self.pcap_filepath = pcap_file.pcap_file_path
        self.pcap_proc = None
        self.do_extra_tests = False
        self.file_info = None

        # Create folder for statistics database if required
        self.path_db = pcap_file.get_db_path()
        path_dir = os.path.dirname(self.path_db)
        if not os.path.isdir(path_dir):
            os.makedirs(path_dir)

        # Class instances
        self.stats_db = statsDB.StatsDatabase(self.path_db)

    def load_pcap_statistics(self, flag_write_file: bool, flag_recalculate_stats: bool, flag_print_statistics: bool,
                             flag_non_verbose: bool):
        """
        Loads the PCAP statistics for the file specified by pcap_filepath. If the database is not existing yet, the
        statistics are calculated by the PCAP file processor and saved into the newly created database. Otherwise the
        statistics are gathered directly from the existing database.

        :param flag_write_file: Indicates whether the statistics should be written addiotionally into a text file (True)
        or not (False)
        :param flag_recalculate_stats: Indicates whether eventually existing statistics should be recalculated
        :param flag_print_statistics: Indicates whether the gathered basic statistics should be printed to the terminal
        :param flag_non_verbose: Indicates whether certain prints should be made or not, to reduce terminal clutter
        """
        # Load pcap and get loading time
        time_start = time.clock()

        # Inform user about recalculation of statistics and its reason
        if flag_recalculate_stats:
            print("Flag -r/--recalculate found. Recalculating statistics.")

        # Recalculate statistics if database does not exist OR param -r/--recalculate is provided
        if (not self.stats_db.get_db_exists()) or flag_recalculate_stats or self.stats_db.get_db_outdated():
            self.pcap_proc = pr.pcap_processor(self.pcap_filepath, str(self.do_extra_tests))
            self.pcap_proc.collect_statistics()
            self.pcap_proc.write_to_database(self.path_db)
            outstring_datasource = "by PCAP file processor."

            # only print summary of new db if -s flag not set
            if not flag_print_statistics and not flag_non_verbose:
                self.stats_summary_new_db()
        else:
            outstring_datasource = "from statistics database."

        # Load statistics from database
        self.file_info = self.stats_db.get_file_info()

        time_end = time.clock()
        print("Loaded file statistics in " + str(time_end - time_start)[:4] + " sec " + outstring_datasource)

        # Write statistics if param -e/--export provided
        if flag_write_file:
            self.write_statistics_to_file()

        # Print statistics if param -s/--statistics provided
        if flag_print_statistics:
            self.print_statistics()

    def get_file_information(self):
        """
        Returns a list of tuples, each containing a information of the file.

        :return: a list of tuples, each consisting of (description, value, unit), where unit is optional.
        """

        pdu_count = self.process_db_query("SELECT SUM(pktCount) FROM unrecognized_pdus")
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

    def calculate_complement_packet_rates(self, pps):
        """
        Calculates the complement packet rates of the background traffic packet rates for each interval.
        Then normalize it to maximum boundary, which is the input parameter pps

        :return: normalized packet rates for each time interval.
        """
        result = self.process_db_query(
            "SELECT lastPktTimestamp,pktsCount FROM interval_statistics ORDER BY lastPktTimestamp")
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
            values, freq_output = [], []
            for x in values_list:
                if x in values:
                    freq_output[values.index(x)] += 1
                else:
                    values.append(x)
                    freq_output.append(1)
            return values, freq_output

        # Payload Tests
        sum_payload_count = self.stats_db.process_user_defined_query("SELECT sum(payloadCount) FROM "
                                                                     "interval_statistics")
        pkt_count = self.stats_db.process_user_defined_query("SELECT packetCount FROM file_statistics")
        if sum_payload_count and pkt_count:
            payload_ratio = 0
            if pkt_count[0][0] != 0:
                payload_ratio = float(sum_payload_count[0][0] / pkt_count[0][0] * 100)
        else:
            payload_ratio = -1

        # TCP checksum Tests
        incorrect_checksum_count = self.stats_db.process_user_defined_query(
            "SELECT sum(incorrectTCPChecksumCount) FROM interval_statistics")
        correct_checksum_count = self.stats_db.process_user_defined_query(
            "SELECT avg(correctTCPChecksumCount) FROM interval_statistics")
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

        new_ip_count = self.stats_db.process_user_defined_query("SELECT newIPCount FROM interval_statistics")
        ip_novels_per_interval, ip_novels_per_interval_frequency = count_frequncy(new_ip_count)
        ip_novelty_dist_entropy = self.calculate_entropy(ip_novels_per_interval_frequency)

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
        new_ttl_count = self.stats_db.process_user_defined_query("SELECT newTTLCount FROM interval_statistics")
        ttl_novels_per_interval, ttl_novels_per_interval_frequency = count_frequncy(new_ttl_count)
        ttl_novelty_dist_entropy = self.calculate_entropy(ttl_novels_per_interval_frequency)

        # Window Size Tests
        result = self.stats_db.process_user_defined_query("SELECT winSize,SUM(winCount) FROM tcp_win GROUP BY winSize")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        win_entropy, win_norm_entropy = self.calculate_entropy(frequency, True)
        new_win_size_count = self.stats_db.process_user_defined_query("SELECT newWinSizeCount FROM interval_statistics")
        win_novels_per_interval, win_novels_per_interval_frequency = count_frequncy(new_win_size_count)
        win_novelty_dist_entropy = self.calculate_entropy(win_novels_per_interval_frequency)

        # ToS Tests
        result = self.stats_db.process_user_defined_query(
            "SELECT tosValue,SUM(tosCount) FROM ip_tos GROUP BY tosValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        tos_entropy, tos_norm_entropy = self.calculate_entropy(frequency, True)
        new_tos_count = self.stats_db.process_user_defined_query("SELECT newToSCount FROM interval_statistics")
        tos_novels_per_interval, tos_novels_per_interval_frequency = count_frequncy(new_tos_count)
        tos_novelty_dist_entropy = self.calculate_entropy(tos_novels_per_interval_frequency)

        # MSS Tests
        result = self.stats_db.process_user_defined_query(
            "SELECT mssValue,SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        mss_entropy, mss_norm_entropy = self.calculate_entropy(frequency, True)
        new_mss_count = self.stats_db.process_user_defined_query("SELECT newMSSCount FROM interval_statistics")
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

        output = output + [("# IP addresses", sum([x[0] for x in new_ip_count]), ""),
                           ("IP Src Entropy", ip_src_entropy, ""),
                           ("IP Src Normalized Entropy", ip_src_norm_entropy, ""),
                           ("IP Dst Entropy", ip_dst_entropy, ""),
                           ("IP Dst Normalized Entropy", ip_dst_norm_entropy, ""),
                           ("IP Novelty Distribution Entropy", ip_novelty_dist_entropy, ""),
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

    def write_statistics_to_file(self):
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

        target = open(self.pcap_filepath + ".stat", 'w')
        target.truncate()

        _write_header("PCAP file information")
        Statistics.write_list(self.get_file_information(), target.write)

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

    def get_packet_count(self):
        """
        :return: The number of packets in the loaded PCAP file
        """
        return self.file_info['packetCount']

    def get_most_used_ip_address(self):
        """
        :return: The IP address/addresses with the highest sum of packets sent and received
        """
        return Util.handle_most_used_outputs(self.process_db_query("most_used(ipAddress)"))

    def get_ttl_distribution(self, ip_address: str):
        result = self.process_db_query('SELECT ttlValue, ttlCount from ip_ttl WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_mss_distribution(self, ip_address: str):
        result = self.process_db_query('SELECT mssValue, mssCount from tcp_mss WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_win_distribution(self, ip_address: str):
        result = self.process_db_query('SELECT winSize, winCount from tcp_win WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_tos_distribution(self, ip_address: str):
        result = self.process_db_query('SELECT tosValue, tosCount from ip_tos WHERE ipAddress="' + ip_address + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_ip_address_count(self):
        return self.process_db_query("SELECT COUNT(*) FROM ip_statistics")

    def get_ip_addresses(self):
        return self.process_db_query("SELECT ipAddress FROM ip_statistics")

    def get_random_ip_address(self, count: int = 1):
        """
        :param count: The number of IP addreses to return
        :return: A randomly chosen IP address from the dataset or iff param count is greater than one, a list of
        randomly chosen IP addresses
        """
        ip_address_list = self.process_db_query("all(ipAddress)")
        if count == 1:
            return random.choice(ip_address_list)
        else:
            result_list = []
            for i in range(0, count):
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

    def get_mac_address(self, ip_address: str):
        """
        :return: The MAC address used in the dataset for the given IP address.
        """
        return self.process_db_query("SELECT DISTINCT macAddress from ip_mac WHERE ipAddress = '" + ip_address + "'")

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
            query_output = self.stats_db.process_user_defined_query(
                "SELECT ttlValue, SUM(ttlCount) FROM ip_ttl GROUP BY ttlValue")
            title = "TTL Distribution"
            x_label = "TTL Value"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_mss(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT mssValue, SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
            title = "MSS Distribution"
            x_label = "MSS Value"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_win(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT winSize, SUM(winCount) FROM tcp_win GROUP BY winSize")
            title = "Window Size Distribution"
            x_label = "Window Size"
            y_label = "Number of Packets"
            if query_output:
                return plot_distribution(query_output, title, x_label, y_label, file_ending)

        def plot_protocol(file_ending: str):
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
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-src' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # This distribution is not drawable for big datasets
        def plot_ip_dst(file_ending: str):
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
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-dst' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_statistics(query_output, title, x_label, y_label, file_ending: str):
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
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, pktsCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "Packet Rate"
            x_label = "Time Interval"
            y_label = "Number of Packets"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_src_ent(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, ipSrcEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "Source IP Entropy"
            x_label = "Time Interval"
            y_label = "Entropy"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_dst_ent(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, ipDstEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "Destination IP Entropy"
            x_label = "Time Interval"
            y_label = "Entropy"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_ip(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newIPCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "IP Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_port(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newPortCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "Port Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_ttl(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newTTLCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "TTL Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_tos(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newToSCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "ToS Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_win_size(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newWinSizeCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "Window Size Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_new_mss(file_ending: str):
            query_output = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, newMSSCount FROM interval_statistics ORDER BY lastPktTimestamp")
            title = "MSS Novelty Distribution"
            x_label = "Time Interval"
            y_label = "Novel values count"
            if query_output:
                return plot_interval_statistics(query_output, title, x_label, y_label, file_ending)

        def plot_interval_ip_dst_cum_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, ipDstCumEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            # If entropy was not calculated do not plot the graph
            if graphy[0] != -1:
                plt.autoscale(enable=True, axis='both')
                plt.title("Destination IP Cumulative Entropy")
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
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-dst-cum-ent' + file_ending)
                plt.savefig(out, dpi=500)
                return out

        def plot_interval_ip_src_cum_ent(file_ending: str):
            plt.gcf().clear()

            result = self.stats_db.process_user_defined_query(
                "SELECT lastPktTimestamp, ipSrcCumEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            # If entropy was not calculated do not plot the graph
            if graphy[0] != -1:
                plt.autoscale(enable=True, axis='both')
                plt.title("Source IP Cumulative Entropy")
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
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-src-cum-ent' + file_ending)
                plt.savefig(out, dpi=500)
                return out

        ttl_out_path = plot_ttl('.' + file_format)
        mss_out_path = plot_mss('.' + file_format)
        win_out_path = plot_win('.' + file_format)
        protocol_out_path = plot_protocol('.' + file_format)
        plot_interval_pktCount = plot_interval_pkt_count('.' + file_format)
        if entropy:
            plot_interval_ip_src_ent = plot_interval_ip_src_ent('.' + file_format)
            plot_interval_ip_dst_ent = plot_interval_ip_dst_ent('.' + file_format)
            plot_interval_ip_src_cum_ent = plot_interval_ip_src_cum_ent('.' + file_format)
            plot_interval_ip_dst_cum_ent = plot_interval_ip_dst_cum_ent('.' + file_format)
        plot_interval_new_ip = plot_interval_new_ip('.' + file_format)
        plot_interval_new_port = plot_interval_new_port('.' + file_format)
        plot_interval_new_ttl = plot_interval_new_ttl('.' + file_format)
        plot_interval_new_tos = plot_interval_new_tos('.' + file_format)
        plot_interval_new_win_size = plot_interval_new_win_size('.' + file_format)
        plot_interval_new_mss = plot_interval_new_mss('.' + file_format)

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
