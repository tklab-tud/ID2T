# Aidmar
from scipy.spatial import distance as dist
import numpy as np
from operator import itemgetter
import math

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

        # Recalculate statistics if database not exists OR param -r/--recalculate was provided
        if (not self.stats_db.get_db_exists()) or flag_recalculate_stats:
            self.pcap_proc = pr.pcap_processor(self.pcap_filepath)
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
                ("#Packets", self.get_packet_count(), "packets"),
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
                value = round(value, 2)
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

    def get_mss(self, ipAddress: str):
        """
        :param ipAddress: The IP address whose used MSS should be determined
        :return: The TCP MSS value used by the IP address, or if the IP addresses never specified a MSS,
        then None is returned
        """
        mss_value = self.process_db_query('SELECT mss from tcp_mss WHERE ipAddress="' + ipAddress + '"')
        if isinstance(mss_value, int):
            return mss_value
        else:
            return None

    # Aidmar
    def get_most_used_mss(self, ipAddress: str):
        """
        :param ipAddress: The IP address whose used MSS should be determined
        :return: The TCP MSS value used by the IP address, or if the IP addresses never specified a MSS,
        then None is returned
        """
        mss_value = self.process_db_query('SELECT mssValue from tcp_mss_dist WHERE ipAddress="' + ipAddress + '" ORDER BY mssCount DESC LIMIT 1')
        if isinstance(mss_value, int):
            return mss_value
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

    def plot_statistics(self, format: str = 'pdf'): #'png'):
        """
        Plots the statistics associated with the dataset prior attack injection.
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
            width = 0.5
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ttl' + file_ending)
            plt.savefig(out,dpi=500)
            return out

        # Aidmar
        def plot_mss(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT mssValue, SUM(mssCount) FROM tcp_mss_dist GROUP BY mssValue")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("MSS Distribution")
            plt.xlabel('MSS Value')
            plt.ylabel('Number of Packets')
            width = 0.5
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-mss' + file_ending)
            plt.savefig(out,dpi=500)
            return out

        # Aidmar
        def plot_win(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT winSize, SUM(winCount) FROM tcp_syn_win GROUP BY winSize")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Window Size Distribution")
            plt.xlabel('Window Size')
            plt.ylabel('Number of Packets')
            width = 0.5
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-win' + file_ending)
            plt.savefig(out,dpi=500)
            return out

        # Aidmar
        def plot_protocol(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT protocolName, SUM(protocolCount) FROM ip_protocols GROUP BY protocolName")
            graphx, graphy = [], []
            for row in result:
                graphx.append(row[0])
                graphy.append(row[1])
            plt.autoscale(enable=True, axis='both')
            plt.title("Protocols Distribution")
            plt.xlabel('Protocols')
            plt.ylabel('Number of Packets')
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # Protocols' names on x-axis
            x = range(0,len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks)

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-protocol' + file_ending)
            plt.savefig(out,dpi=500)
            return out

        # Aidmar
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
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # IPs on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-src' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # Aidmar
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
            width = 0.5
            plt.xlim([0, len(graphx)])
            plt.grid(True)

            # IPs on x-axis
            x = range(0, len(graphx))
            my_xticks = graphx
            plt.xticks(x, my_xticks, rotation='vertical', fontsize=5)
            plt.tight_layout()

            # limit the number of xticks
            plt.locator_params(axis='x', nbins=20)

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-ip-dst' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # Aidmar
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
            width = 0.5
            plt.xlim([0, max(graphx)])
            plt.grid(True)
            plt.bar(graphx, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-port' + file_ending)
            plt.savefig(out,dpi=500)
            return out


        # Aidmar
        def plot_interval_pktCount(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT timestamp, pktsCount FROM interval_statistics ORDER BY timestamp")
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

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-pkt-count' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # Aidmar
        def plot_interval_ip_src_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT timestamp, ipSrcEntropy FROM interval_statistics ORDER BY timestamp")
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

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-src-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # Aidmar
        def plot_interval_ip_dst_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT timestamp, ipDstEntropy FROM interval_statistics ORDER BY timestamp")
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

            plt.bar(x, graphy, width, align='center', linewidth=2, color='red', edgecolor='red')
            out = self.pcap_filepath.replace('.pcap', '_plot-interval-ip-dst-ent' + file_ending)
            plt.savefig(out, dpi=500)
            return out

        # Aidmar
        def plot_interval_ip_dst_cum_ent(file_ending: str):
            plt.gcf().clear()
            result = self.stats_db._process_user_defined_query(
                "SELECT timestamp, ipDstCumEntropy FROM interval_statistics ORDER BY timestamp")
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

        # Aidmar
        def plot_interval_ip_src_cum_ent(file_ending: str):
            plt.gcf().clear()

            result = self.stats_db._process_user_defined_query(
                "SELECT timestamp, ipSrcCumEntropy FROM interval_statistics ORDER BY timestamp")
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

        ttl_out_path = plot_ttl('.' + format)
        mss_out_path = plot_mss('.' + format)
        win_out_path = plot_win('.' + format)
        protocol_out_path = plot_protocol('.' + format)
        port_out_path = plot_port('.' + format)
        ip_src_out_path = plot_ip_src('.' + format)
        ip_dst_out_path = plot_ip_dst('.' + format)
        plot_interval_pktCount = plot_interval_pktCount('.' + format)
        plot_interval_ip_src_ent = plot_interval_ip_src_ent('.' + format)
        plot_interval_ip_dst_ent = plot_interval_ip_dst_ent('.' + format)
        plot_interval_ip_src_cum_ent = plot_interval_ip_src_cum_ent('.' + format)
        plot_interval_ip_dst_cum_ent = plot_interval_ip_dst_cum_ent('.' + format)


        #print("Saved distributions plots at: %s, %s, %s, %s, %s, %s, %s, %s %s" %(ttl_out_path,mss_out_path, win_out_path,
        #protocol_out_path, port_out_path,ip_src_out_path,ip_dst_out_path, plot_interval_pktCount))


     # Aidmar
    def calculate_complement_packet_rates(self, pps):
        """
        Calculates the complement packet rates of the background traffic packet rates per interval.
        Then normalize it to maximum boundary, which is the input parameter pps

        :return: normalized packet rates for each time interval.
        """
        result = self.process_db_query(
            "SELECT timestamp,pktsCount FROM interval_statistics ORDER BY timestamp")
        # print(result)
        bg_interval_pps = []
        complement_interval_pps = []
        intervalsSum = 0
        if result:
            # Get the interval in seconds
            for i, row in enumerate(result):
                if i < len(result) - 1:
                    intervalsSum += math.ceil((int(result[i + 1][0]) * 10 ** -6) - (int(row[0]) * 10 ** -6))
            interval = intervalsSum / (len(result) - 1)
            # Convert timestamp from micro to seconds, convert packet rate "per interval" to "per second"
            for row in result:
                bg_interval_pps.append((int(row[0]) * 10 ** -6, int(row[1] / interval)))
            # Find max PPS
            maxPPS = max(bg_interval_pps, key=itemgetter(1))[1]

            for row in bg_interval_pps:
                complement_interval_pps.append((row[0], int(pps * (maxPPS - row[1]) / maxPPS)))

        return complement_interval_pps

"""
 # Aidmar      

            # bhattacharyya test
            import math

            def mean(hist):
                mean = 0.0;
                for i in hist:
                    mean += i;
                mean /= len(hist);
                return mean;

            def bhatta(hist1, hist2):
                # calculate mean of hist1
                h1_ = mean(hist1);

                # calculate mean of hist2
                h2_ = mean(hist2);

                # calculate score
                score = 0;
                for i in range(len(hist1)):
                    score += math.sqrt(hist1[i] * hist2[i]);
                # print h1_,h2_,score;
                score = math.sqrt(1 - (1 / math.sqrt(h1_ * h2_ * len(hist1) * len(hist1))) * score);
                return score;

            print("\nbhatta distance: " + str(bhatta(graphy, graphy_aftr)))


"""