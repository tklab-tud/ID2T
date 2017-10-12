from operator import itemgetter
from math import sqrt, ceil, log

import os
import time
import ID2TLib.libpcapreader as pr
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from ID2TLib.PcapFile import PcapFile
from ID2TLib.StatsDatabase import StatsDatabase


class Statistics:
    def __init__(self, pcap_file: PcapFile):
        """
        Creates a new Statistics object.

        :param pcap_file: A reference to the PcapFile object
        """
        # Fields
        self.pcap_filepath = pcap_file.pcap_file_path
        self.pcap_proc = None
        self.do_extra_tests = False

        # Create folder for statistics database if required
        self.path_db = pcap_file.get_db_path()
        path_dir = os.path.dirname(self.path_db)
        if not os.path.isdir(path_dir):
            os.makedirs(path_dir)

        # Class instances
        self.stats_db = StatsDatabase(self.path_db)

    def load_pcap_statistics(self, flag_write_file: bool, flag_recalculate_stats: bool, flag_print_statistics: bool):
        """
        Loads the PCAP statistics for the file specified by pcap_filepath. If the database is not existing yet, the
        statistics are calculated by the PCAP file processor and saved into the newly created database. Otherwise the
        statistics are gathered directly from the existing database.

        :param flag_write_file: Indicates whether the statistics should be written addiotionally into a text file (True)
        or not (False)
        :param flag_recalculate_stats: Indicates whether eventually existing statistics should be recalculated
        :param flag_print_statistics: Indicates whether the gathered basic statistics should be printed to the terminal
        """
        # Load pcap and get loading time
        time_start = time.clock()

        # Inform user about recalculation of statistics and its reason
        if flag_recalculate_stats:
            print("Flag -r/--recalculate found. Recalculating statistics.")

        # Recalculate statistics if database does not exist OR param -r/--recalculate is provided
        if (not self.stats_db.get_db_exists()) or flag_recalculate_stats:
            self.pcap_proc = pr.pcap_processor(self.pcap_filepath, str(self.do_extra_tests))
            self.pcap_proc.collect_statistics()
            self.pcap_proc.write_to_database(self.path_db)
            outstring_datasource = "by PCAP file processor."
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
        return [("Pcap file", self.pcap_filepath),
                ("Packets", self.get_packet_count(), "packets"),
                ("Capture length", self.get_capture_duration(), "seconds"),
                ("Capture start", self.get_pcap_timestamp_start()),
                ("Capture end", self.get_pcap_timestamp_end())]

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
        Takes a list of tuples (statistic name, statistic value, unit) as input, generates a string of these three values
        and applies the function func on this string.

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


    def calculate_entropy(self, frequency:list, normalized:bool = False):
        """
        Calculates entropy and normalized entropy of list of elements that have specific frequency
        :param frequency: The frequency of the elements.
        :param normalized: Calculate normalized entropy
        :return: entropy or (entropy, normalized entropy)
        """
        entropy, normalizedEnt, n = 0, 0, 0
        sumFreq = sum(frequency)
        for i, x in enumerate(frequency):
            p_x = float(frequency[i] / sumFreq)
            if p_x > 0:
                n += 1
                entropy += - p_x * log(p_x, 2)
        if normalized:
            if log(n)>0:
                normalizedEnt = entropy/log(n, 2)
            return entropy, normalizedEnt
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
        intervalsSum = 0
        if result:
            # Get the interval in seconds
            for i, row in enumerate(result):
                if i < len(result) - 1:
                    intervalsSum += ceil((int(result[i + 1][0]) * 10 ** -6) - (int(row[0]) * 10 ** -6))
            interval = intervalsSum / (len(result) - 1)
            # Convert timestamp from micro to seconds, convert packet rate "per interval" to "per second"
            for row in result:
                bg_interval_pps.append((int(row[0]) * 10 ** -6, int(row[1] / interval)))
            # Find max PPS
            maxPPS = max(bg_interval_pps, key=itemgetter(1))[1]

            for row in bg_interval_pps:
                complement_interval_pps.append((row[0], int(pps * (maxPPS - row[1]) / maxPPS)))

        return complement_interval_pps


    def get_tests_statistics(self):
        """
        Writes the calculated basic defects tests statistics into a file.
        """
        # self.stats_db._process_user_defined_query output is list of tuples, thus, we ned [0][0] to access data

        def count_frequncy(valuesList):
            values, frequency = [] , []
            for x in valuesList:
                if x in values:
                    frequency[values.index(x)] += 1
                else:
                    values.append(x)
                    frequency.append(1)
            return values, frequency

        ####### Payload Tests #######
        sumPayloadCount = self.stats_db._process_user_defined_query("SELECT sum(payloadCount) FROM interval_statistics")
        pktCount = self.stats_db._process_user_defined_query("SELECT packetCount FROM file_statistics")
        if sumPayloadCount and pktCount:
            payloadRatio=0
            if(pktCount[0][0]!=0):
                payloadRatio = float(sumPayloadCount[0][0] / pktCount[0][0] * 100)
        else:
            payloadRatio = -1

        ####### TCP checksum Tests #######
        incorrectChecksumCount = self.stats_db._process_user_defined_query("SELECT sum(incorrectTCPChecksumCount) FROM interval_statistics")
        correctChecksumCount = self.stats_db._process_user_defined_query("SELECT avg(correctTCPChecksumCount) FROM interval_statistics")
        if incorrectChecksumCount and correctChecksumCount:
            incorrectChecksumRatio=0
            if(incorrectChecksumCount[0][0] + correctChecksumCount[0][0])!=0:
                incorrectChecksumRatio = float(incorrectChecksumCount[0][0]  / (incorrectChecksumCount[0][0] + correctChecksumCount[0][0] ) * 100)
        else:
            incorrectChecksumRatio = -1

        ####### IP Src Tests #######
        result = self.stats_db._process_user_defined_query("SELECT ipAddress,pktsSent,pktsReceived FROM ip_statistics")
        data, srcFrequency, dstFrequency = [], [], []
        if result:
            for row in result:
                srcFrequency.append(row[1])
                dstFrequency.append(row[2])
        ipSrcEntropy, ipSrcNormEntropy = self.calculate_entropy(srcFrequency, True)
        ipDstEntropy, ipDstNormEntropy = self.calculate_entropy(dstFrequency, True)

        newIPCount = self.stats_db._process_user_defined_query("SELECT newIPCount FROM interval_statistics")
        ipNovelsPerInterval, ipNovelsPerIntervalFrequency = count_frequncy(newIPCount)
        ipNoveltyDistEntropy = self.calculate_entropy(ipNovelsPerIntervalFrequency)

        ####### Ports Tests #######
        port0Count = self.stats_db._process_user_defined_query("SELECT SUM(portCount) FROM ip_ports WHERE portNumber = 0")
        if not port0Count[0][0]:
            port0Count = 0
        else:
            port0Count = port0Count[0][0]
        reservedPortCount = self.stats_db._process_user_defined_query(
            "SELECT SUM(portCount) FROM ip_ports WHERE portNumber IN (100,114,1023,1024,49151,49152,65535)")# could be extended
        if not reservedPortCount[0][0]:
            reservedPortCount = 0
        else:
            reservedPortCount = reservedPortCount[0][0]

        ####### TTL Tests #######
        result = self.stats_db._process_user_defined_query("SELECT ttlValue,SUM(ttlCount) FROM ip_ttl GROUP BY ttlValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        ttlEntropy, ttlNormEntropy  = self.calculate_entropy(frequency,True)
        newTTLCount = self.stats_db._process_user_defined_query("SELECT newTTLCount FROM interval_statistics")
        ttlNovelsPerInterval, ttlNovelsPerIntervalFrequency = count_frequncy(newTTLCount)
        ttlNoveltyDistEntropy = self.calculate_entropy(ttlNovelsPerIntervalFrequency)

        ####### Window Size Tests #######
        result = self.stats_db._process_user_defined_query("SELECT winSize,SUM(winCount) FROM tcp_win GROUP BY winSize")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        winEntropy, winNormEntropy = self.calculate_entropy(frequency, True)
        newWinSizeCount = self.stats_db._process_user_defined_query("SELECT newWinSizeCount FROM interval_statistics")
        winNovelsPerInterval, winNovelsPerIntervalFrequency = count_frequncy(newWinSizeCount)
        winNoveltyDistEntropy = self.calculate_entropy(winNovelsPerIntervalFrequency)

        ####### ToS Tests #######
        result = self.stats_db._process_user_defined_query(
            "SELECT tosValue,SUM(tosCount) FROM ip_tos GROUP BY tosValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        tosEntropy, tosNormEntropy = self.calculate_entropy(frequency, True)
        newToSCount = self.stats_db._process_user_defined_query("SELECT newToSCount FROM interval_statistics")
        tosNovelsPerInterval, tosNovelsPerIntervalFrequency = count_frequncy(newToSCount)
        tosNoveltyDistEntropy = self.calculate_entropy(tosNovelsPerIntervalFrequency)

        ####### MSS Tests #######
        result = self.stats_db._process_user_defined_query(
            "SELECT mssValue,SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
        data, frequency = [], []
        for row in result:
            frequency.append(row[1])
        mssEntropy, mssNormEntropy = self.calculate_entropy(frequency, True)
        newMSSCount = self.stats_db._process_user_defined_query("SELECT newMSSCount FROM interval_statistics")
        mssNovelsPerInterval, mssNovelsPerIntervalFrequency = count_frequncy(newMSSCount)
        mssNoveltyDistEntropy = self.calculate_entropy(mssNovelsPerIntervalFrequency)

        result = self.stats_db._process_user_defined_query("SELECT SUM(mssCount) FROM tcp_mss WHERE mssValue > 1460")
        # The most used MSS < 1460. Calculate the ratio of the values bigger that 1460.
        if not result[0][0]:
            result = 0
        else:
            result = result[0][0]
        bigMSS = (result / sum(frequency)) * 100

        output = [("Payload ratio", payloadRatio, "%"),
                ("Incorrect TCP checksum ratio", incorrectChecksumRatio, "%"),
                ("# IP addresses", sum([x[0] for x in newIPCount]), ""),
                ("IP Src Entropy", ipSrcEntropy, ""),
                ("IP Src Normalized Entropy", ipSrcNormEntropy, ""),
                ("IP Dst Entropy", ipDstEntropy, ""),
                ("IP Dst Normalized Entropy", ipDstNormEntropy, ""),
                ("# TTL values", sum([x[0] for x in newTTLCount]), ""),
                ("TTL Distribution Entropy", ipNoveltyDistEntropy, ""),
                ("TTL Entropy", ttlEntropy, ""),
                ("TTL Normalized Entropy", ttlNormEntropy, ""),
                ("TTL Distribution Entropy", ttlNoveltyDistEntropy, ""),
                ("# WinSize values", sum([x[0] for x in newWinSizeCount]), ""),
                ("WinSize Entropy", winEntropy, ""),
                ("WinSize Normalized Entropy", winNormEntropy, ""),
                ("WinSize Distribution Entropy", winNoveltyDistEntropy, ""),
                ("# ToS values",  sum([x[0] for x in newToSCount]), ""),
                ("ToS Entropy", tosEntropy, ""),
                ("ToS Normalized Entropy", tosNormEntropy, ""),
                ("ToS Distribution Entropy", tosNoveltyDistEntropy, ""),
                ("# MSS values", sum([x[0] for x in newMSSCount]), ""),
                ("MSS Entropy", mssEntropy, ""),
                ("MSS Normalized Entropy", mssNormEntropy, ""),
                ("MSS Distribution Entropy", mssNoveltyDistEntropy, ""),
                ("======================","","")]


        # Reasoning the statistics values
        if payloadRatio > 80:
            output.append(("WARNING: Too high payload ratio", payloadRatio, "%."))
        if payloadRatio < 30:
            output.append(("WARNING: Too low payload ratio", payloadRatio, "% (Injecting attacks that are carried out in the packet payloads is not recommmanded)."))

        if incorrectChecksumRatio > 5:
            output.append(("WARNING: High incorrect TCP checksum ratio",incorrectChecksumRatio,"%."))

        if ipSrcNormEntropy > 0.65:
            output.append(("WARNING: High IP source normalized entropy",ipSrcNormEntropy,"."))
        if ipSrcNormEntropy < 0.2:
            output.append(("WARNING: Low IP source normalized entropy", ipSrcNormEntropy, "."))
        if ipDstNormEntropy > 0.65:
            output.append(("WARNING: High IP destination normalized entropy", ipDstNormEntropy, "."))
        if ipDstNormEntropy < 0.2:
            output.append(("WARNING: Low IP destination normalized entropy", ipDstNormEntropy, "."))

        if ttlNormEntropy > 0.65:
            output.append(("WARNING: High TTL normalized entropy", ttlNormEntropy, "."))
        if ttlNormEntropy < 0.2:
            output.append(("WARNING: Low TTL normalized entropy", ttlNormEntropy, "."))
        if ttlNoveltyDistEntropy < 1:
            output.append(("WARNING: Too low TTL novelty distribution entropy", ttlNoveltyDistEntropy,
                           "(The distribution of the novel TTL values is suspicious)."))

        if winNormEntropy > 0.6:
            output.append(("WARNING: High Window Size normalized entropy", winNormEntropy, "."))
        if winNormEntropy < 0.1:
            output.append(("WARNING: Low Window Size normalized entropy", winNormEntropy, "."))
        if winNoveltyDistEntropy < 4:
            output.append(("WARNING: Low Window Size novelty distribution entropy", winNoveltyDistEntropy,
                           "(The distribution of the novel Window Size values is suspicious)."))

        if tosNormEntropy > 0.4:
            output.append(("WARNING: High ToS normalized entropy", tosNormEntropy, "."))
        if tosNormEntropy < 0.1:
            output.append(("WARNING: Low ToS normalized entropy", tosNormEntropy, "."))
        if tosNoveltyDistEntropy < 0.5:
            output.append(("WARNING: Low ToS novelty distribution entropy", tosNoveltyDistEntropy,
                           "(The distribution of the novel ToS values is suspicious)."))

        if mssNormEntropy > 0.4:
            output.append(("WARNING: High MSS normalized entropy", mssNormEntropy, "."))
        if mssNormEntropy < 0.1:
            output.append(("WARNING: Low MSS normalized entropy", mssNormEntropy, "."))
        if mssNoveltyDistEntropy < 0.5:
            output.append(("WARNING: Low MSS novelty distribution entropy", mssNoveltyDistEntropy,
                           "(The distribution of the novel MSS values is suspicious)."))

        if bigMSS > 50:
            output.append(("WARNING: High ratio of MSS > 1460", bigMSS, "% (High fragmentation rate in Ethernet)."))

        if port0Count > 0:
            output.append(("WARNING: Port number 0 is used in ",port0Count,"packets (awkward-looking port)."))
        if reservedPortCount > 0:
            output.append(("WARNING: Reserved port numbers are used in ",reservedPortCount,"packets (uncommonly-used ports)."))


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
        return self.process_db_query("most_used(ipAddress)")

    def get_ttl_distribution(self, ipAddress: str):
        result = self.process_db_query('SELECT ttlValue, ttlCount from ip_ttl WHERE ipAddress="' + ipAddress + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_mss_distribution(self, ipAddress: str):
        result = self.process_db_query('SELECT mssValue, mssCount from tcp_mss WHERE ipAddress="' + ipAddress + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_win_distribution(self, ipAddress: str):
        result = self.process_db_query('SELECT winSize, winCount from tcp_win WHERE ipAddress="' + ipAddress + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_tos_distribution(self, ipAddress: str):
        result = self.process_db_query('SELECT tosValue, tosCount from ip_tos WHERE ipAddress="' + ipAddress + '"')
        result_dict = {key: value for (key, value) in result}
        return result_dict

    def get_random_ip_address(self, count: int = 1):
        """
        :param count: The number of IP addreses to return
        :return: A randomly chosen IP address from the dataset or iff param count is greater than one, a list of randomly
         chosen IP addresses
        """
        if count == 1:
            return self.process_db_query("random(all(ipAddress))")
        else:
            ip_address_list = []
            for i in range(0, count):
                ip_address_list.append(self.process_db_query("random(all(ipAddress))"))
            return ip_address_list

    def get_mac_address(self, ipAddress: str):
        """
        :return: The MAC address used in the dataset for the given IP address.
        """
        return self.process_db_query('macAddress(ipAddress=' + ipAddress + ")")

    def get_most_used_mss(self, ipAddress: str):
        """
        :param ipAddress: The IP address whose used MSS should be determined
        :return: The TCP MSS value used by the IP address, or if the IP addresses never specified a MSS,
        then None is returned
        """
        mss_value = self.process_db_query('SELECT mssValue from tcp_mss WHERE ipAddress="' + ipAddress + '" ORDER BY mssCount DESC LIMIT 1')
        if isinstance(mss_value, int):
            return mss_value
        else:
            return None

    def get_most_used_ttl(self, ipAddress: str):
        """
        :param ipAddress: The IP address whose used TTL should be determined
        :return: The TTL value used by the IP address, or if the IP addresses never specified a TTL,
        then None is returned
        """
        ttl_value = self.process_db_query(
            'SELECT ttlValue from ip_ttl WHERE ipAddress="' + ipAddress + '" ORDER BY ttlCount DESC LIMIT 1')
        if isinstance(ttl_value, int):
            return ttl_value
        else:
            return None


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


    def calculate_standard_deviation(self, lst):
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


    def plot_statistics(self, format: str = 'pdf'): #'png'
        """
        Plots the statistics associated with the dataset.
        :param format: The format to be used to save the statistics diagrams.
        """

        def plot_ttl(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT ttlValue, SUM(ttlCount) FROM ip_ttl GROUP BY ttlValue")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("TTL Distribution")
            plt.xlabel('TTL Value')
            plt.ylabel('Number of Packets')
            width = 0.1
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ttl' + file_ending)
            plt.savefig(out,dpi=500)
            return out

        def plot_mss(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT mssValue, SUM(mssCount) FROM tcp_mss GROUP BY mssValue")
            if(result):
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])
                plt.autoscale(enable=True, axis='both')
                plt.title("MSS Distribution")
                plt.xlabel('MSS Value')
                plt.ylabel('Number of Packets')
                width = 0.1
                plt.xlim([0, max(graphx)])
                plt.grid(True)
                plt.bar(graphx, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-mss' + file_ending)
                plt.savefig(out,dpi=500)
                return out
            else:
                print("Error plot MSS: No MSS values found!")

        def plot_win(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT winSize, SUM(winCount) FROM tcp_win GROUP BY winSize")
            if (result):
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])
                plt.autoscale(enable=True, axis='both')
                plt.title("Window Size Distribution")
                plt.xlabel('Window Size')
                plt.ylabel('Number of Packets')
                width = 0.1
                plt.xlim([0, max(graphx)])
                plt.grid(True)
                plt.bar(graphx, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-win' + file_ending)
                plt.savefig(out,dpi=500)
                return out
            else:
                print("Error plot WinSize: No WinSize values found!")

        def plot_protocol(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT protocolName, SUM(protocolCount) FROM ip_protocols GROUP BY protocolName")
            if (result):
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
                x = range(0,len(graphx))
                my_xticks = graphx
                plt.xticks(x, my_xticks)

                plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-protocol' + file_ending)
                plt.savefig(out,dpi=500)
                return out
            else:
                print("Error plot protocol: No protocol values found!")

        def plot_port(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
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
            plt.savefig(out,dpi=500)
            return out

        # This distribution is not drawable for big datasets
        def plot_ip_src(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
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
            result = self.stats_db._process_user_defined_query(
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

        def plot_interval_pktCount(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, pktsCount FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Packet Rate")
            plt.xlabel('Timestamp')
            plt.ylabel('Number of Packets')
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-pkt-count' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_ip_src_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, ipSrcEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Source IP Entropy")
            plt.xlabel('Timestamp')
            plt.ylabel('Entropy')
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-src-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_ip_dst_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, ipDstEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Destination IP Entropy")
            plt.xlabel('Timestamp')
            plt.ylabel('Entropy')
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-dst-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_ip_dst_cum_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, ipDstCumEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Destination IP Cumulative Entropy")
            plt.xlabel('Timestamp')
            plt.ylabel('Entropy')
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.plot(x, graphy, 'r')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-dst-cum-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_ip_src_cum_ent(file_ending: str):
            plt.gcf().clear()

            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, ipSrcCumEntropy FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])

            plt.autoscale(enable=True, axis='both')
            plt.title("Source IP Cumulative Entropy")
            plt.xlabel('Timestamp')
            plt.ylabel('Entropy')
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x',nbins=20)

            plt.plot(x, graphy, 'r')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-src-cum-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_new_ip(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, newIPCount FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])

            plt.autoscale(enable=True, axis='both')
            plt.title("IP Novelty Distribution")
            plt.xlabel('Timestamp')
            plt.ylabel('Novel values count')
            plt.xlim([0, len(graphx)])
            plt.grid(True)
            width = 0.5

            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-novel-ip-dist' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_new_ttl(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, newTTLCount FROM interval_statistics ORDER BY lastPktTimestamp")
            if(result):
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])

                plt.autoscale(enable=True, axis='both')
                plt.title("TTL Novelty Distribution")
                plt.xlabel('Timestamp')
                plt.ylabel('Novel values count')
                plt.xlim([0, len(graphx)])
                plt.grid(True)
                width = 0.5

                # timestamp on x-axis
                x = range(0, len(graphx))
                my_xticks = graphx
                plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
                plt.tight_layout()

                # limit the number of xticks
                plt.locator_params(axis='x', nbins=20)

                plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-novel-ttl-dist' + file_ending)
                plt.savefig(out, dpi=500)
                return out
            else:
                print("Error plot TTL: No TTL values found!")

        def plot_interval_new_tos(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, newToSCount FROM interval_statistics ORDER BY lastPktTimestamp")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])

            plt.autoscale(enable=True, axis='both')
            plt.title("ToS Novelty Distribution")
            plt.xlabel('Timestamp')
            plt.ylabel('Novel values count')
            plt.xlim([0, len(graphx)])
            plt.grid(True)
            width = 0.5
            # timestamp on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-novel-tos-dist' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        def plot_interval_new_win_size(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, newWinSizeCount FROM interval_statistics ORDER BY lastPktTimestamp")
            if(result):
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])

                plt.autoscale(enable=True, axis='both')
                plt.title("Window Size Novelty Distribution")
                plt.xlabel('Timestamp')
                plt.ylabel('Novel values count')
                plt.xlim([0, len(graphx)])
                plt.grid(True)
                width = 0.5

                # timestamp on x-axis
                x = range(0, len(graphx))
                my_xticks = graphx
                plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
                plt.tight_layout()

                # limit the number of xticks
                plt.locator_params(axis='x', nbins=20)

                plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-novel-win-size-dist' + file_ending)
                plt.savefig(out, dpi=500)
                return out
            else:
                print("Error plot new values WinSize: No WinSize values found!")

        def plot_interval_new_mss(file_ending: str):
            plt.gcf().clear()

            result = self.stats_db._process_user_defined_query(
                "SELECT lastPktTimestamp, newMSSCount FROM interval_statistics ORDER BY lastPktTimestamp")
            if(result):
                graphx, graphy = [], []
                for row in result:
                    graphx.append(row[0])
                    graphy.append(row[1])

                plt.autoscale(enable=True, axis='both')
                plt.title("MSS Novelty Distribution")
                plt.xlabel('Timestamp')
                plt.ylabel('Novel values count')
                plt.xlim([0, len(graphx)])
                plt.grid(True)
                width = 0.5

                # timestamp on x-axis
                x = range(0, len(graphx))
                my_xticks = graphx
                plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
                plt.tight_layout()

                # limit the number of xticks
                plt.locator_params(axis='x', nbins=20)

                plt.bar(x, graphy, width, align='center', linewidth=1, color='red', edgecolor='red')
                out = self.pcap_filepath.replace('.pcap', '_plot-interval-novel-mss-dist' + file_ending)
                plt.savefig(out, dpi=500)
                return out
            else:
                print("Error plot new values MSS: No MSS values found!")

        ttl_out_path = plot_ttl('.' + format)
        mss_out_path = plot_mss('.' + format)
        win_out_path = plot_win('.' + format)
        protocol_out_path = plot_protocol('.' + format)
        port_out_path = plot_port('.' + format)
        #ip_src_out_path = plot_ip_src('.' + format)
        #ip_dst_out_path = plot_ip_dst('.' + format)
        plot_interval_pktCount = plot_interval_pktCount('.' + format)
        plot_interval_ip_src_ent = plot_interval_ip_src_ent('.' + format)
        plot_interval_ip_dst_ent = plot_interval_ip_dst_ent('.' + format)
        plot_interval_ip_src_cum_ent = plot_interval_ip_src_cum_ent('.' + format)
        plot_interval_ip_dst_cum_ent = plot_interval_ip_dst_cum_ent('.' + format)
        plot_interval_new_ip = plot_interval_new_ip('.' + format)
        plot_interval_new_ttl = plot_interval_new_ttl('.' + format)
        plot_interval_new_tos = plot_interval_new_tos('.' + format)
        plot_interval_new_win_size = plot_interval_new_win_size('.' + format)
        plot_interval_new_mss = plot_interval_new_mss('.' + format)

        print("Saved plots in the input PCAP directory.")
