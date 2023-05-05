import os
import readline
import sys
import shutil
import time
import re

import pyparsing as pp
import Core.AttackController as atkCtrl
import Core.LabelManager as LabelManager
import Core.Statistics as Statistics
import Core.BackgroundTraffic as BackgroundTraffic
import Lib.PcapFile as PcapFile
import Lib.Utility as Util
import Core.StatsDatabase as StatsDB


class Controller:
    def __init__(self, pcap_file_path: str, do_extra_tests: bool, non_verbose: bool=True, pcap_out_path: str=None,
                 debug: bool=False):
        """
        Creates a new Controller, acting as a central coordinator for the whole application.

        :param pcap_file_path:
        """
        # Fields
        self.pcap_src_path = pcap_file_path.strip()
        self.pcap_dest_path = ''
        self.pcap_out_path = pcap_out_path
        self.written_pcaps = []
        self.do_extra_tests = do_extra_tests
        self.non_verbose = non_verbose
        self.seed = None
        self.durations = []
        self.added_packets = 0
        self.created_files = []
        self.debug = debug

        # Initialize class instances
        print("Input file: %s" % self.pcap_src_path)
        self.pcap_file = PcapFile.PcapFile(self.pcap_src_path)
        self.label_manager = LabelManager.LabelManager(self.pcap_src_path)
        self.statistics = Statistics.Statistics(self.pcap_file)
        self.statistics.do_extra_tests = self.do_extra_tests
        self.statisticsDB = self.statistics.get_statistics_database()
        self.attack_controller = atkCtrl.AttackController(self.pcap_file, self.statistics, self.label_manager)

        # Set output directory and create it (if necessary)
        if pcap_out_path is not None:
            out_dir = os.path.dirname(pcap_out_path)
            if not out_dir:  # if out_dir is cwd
                out_dir = "."
            Util.OUT_DIR = out_dir + os.sep
        else:
            Util.OUT_DIR = os.path.join(os.path.dirname(pcap_file_path), "id2t_results") + os.sep
        os.makedirs(Util.OUT_DIR, exist_ok=True)

    def list_interval_statistics(self):
        self.statistics.list_previous_interval_statistic_tables()

    def load_pcap_statistics(self, flag_write_file: bool, flag_recalculate_stats: bool, flag_print_statistics: bool,
                             intervals, delete: bool=False, recalculate_intervals: bool=None):
        """
        Loads the PCAP statistics either from the database, if the statistics were calculated earlier, or calculates
        the statistics and creates a new database.

        :param flag_write_file: Writes the statistics to a file.
        :param flag_recalculate_stats: Forces the recalculation of statistics.
        :param flag_print_statistics: Prints the statistics on the terminal.
        :param intervals: user specified interval in seconds
        :param delete: Delete old interval statistics.
        :param recalculate_intervals: Recalculate old interval statistics or not. Prompt user if None.
        :return: None
        """
        self.statistics.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics,
                                             self.non_verbose, intervals=intervals, delete=delete,
                                             recalculate_intervals=recalculate_intervals)

    def process_attacks(self, attacks_config: list, seeds=None, measure_time: bool=False, inject_empty: bool=False):
        """
        Creates the attack based on the attack name and the attack parameters given in the attacks_config. The
        attacks_config is a list of attacks.
        e.g. [['PortscanAttack', 'ip.src="192.168.178.2",'dst.port=80'],['PortscanAttack', 'ip.src="10.10.10.2"]].
        Merges the individual temporary attack pcaps into one single pcap and merges this single pcap with the
        input dataset if desired.

        :param attacks_config: A list of attacks with their attack parameters.
        :param seeds: A list of random seeds for the given attacks.
        :param measure_time: Measure time for packet generation.
        :param inject_empty: if flag is set, Attack PCAPs will not be merged with the base PCAP, ie. Attacks are injected into an empty PCAP
        """

        # load attacks sequentially
        i = 0
        for attack in attacks_config:
            if seeds is not None and len(seeds) > i:
                rng_seed = seeds[i][0]
            else:
                rng_seed = int.from_bytes(os.urandom(16), sys.byteorder)
            self.attack_controller.set_seed(seed=rng_seed)
            temp_attack_pcap, duration = self.attack_controller.process_attack(attack[0], attack[1:], measure_time)
            self.durations.append(duration)
            self.added_packets += self.attack_controller.total_packets
            if not self.non_verbose:
                self.statistics.stats_summary_post_attack(self.added_packets)
            self.written_pcaps.append(temp_attack_pcap)
            i += 1

        attacks_pcap_path = None

        # merge attack pcaps to get single attack pcap
        if len(self.written_pcaps) > 1:
            print("\nMerging temporary attack pcaps into single pcap file...", end=" ")
            sys.stdout.flush()  # force python to print text immediately
            for i in range(0, len(self.written_pcaps) - 1):
                attacks_pcap = PcapFile.PcapFile(self.written_pcaps[i])
                attacks_pcap_path = attacks_pcap.merge_attack(self.written_pcaps[i + 1])
                os.remove(self.written_pcaps[i + 1])  # remove merged pcap
                self.written_pcaps[i + 1] = attacks_pcap_path
            print("done.")
        elif len(self.written_pcaps) == 1:
            attacks_pcap_path = self.written_pcaps[0]

        if attacks_pcap_path:
            if inject_empty:
                # copy the attack pcap to the directory of the base PCAP instead of merging them
                print("Copying single attack pcap to location of base pcap...", end=" ")
                sys.stdout.flush()  # force python to print text immediately

                timestamp = '_' + time.strftime("%Y%m%d") + '-' + time.strftime("%X").replace(':', '')
                if '.pcap' in self.pcap_src_path:
                    self.pcap_dest_path = self.pcap_src_path.replace(".pcap", timestamp + '.pcap')
                else:
                    self.pcap_dest_path = self.pcap_src_path + timestamp + '.pcap'
                shutil.copy(attacks_pcap_path, self.pcap_dest_path)
            else:
                # merge single attack pcap with all attacks into base pcap
                print("Merging base pcap with single attack pcap...", end=" ")
                sys.stdout.flush()  # force python to print text immediately
                self.pcap_dest_path = self.pcap_file.merge_attack(attacks_pcap_path)
                if attack[0] == 'WinHTTPSysExploit':
                    self.background_traffic = BackgroundTraffic.BackgroundTraffic(self.pcap_dest_path)
                    self.background_traffic.WinHTTPSysExploit = BackgroundTraffic.BackgroundTraffic.WinHTTPSysExploit(self.pcap_dest_path)
                    victim_ip, timestamp_for_malicious_packet, background_manipulation = self.background_traffic.WinHTTPSysExploit.get_temp_attack_details(attacks_pcap_path)
                    if background_manipulation == True:
                        updated_pkt_count = self.background_traffic.WinHTTPSysExploit.modify_background_traffic(victim_ip, timestamp_for_malicious_packet)
            if self.pcap_out_path:
                if not self.pcap_out_path.endswith(".pcap"):
                    self.pcap_out_path += ".pcap"
                result_path = self.pcap_out_path
            else:
                tmp_path_tuple = self.pcap_dest_path.rpartition("/")
                result_path = Util.OUT_DIR + tmp_path_tuple[2]

            os.rename(self.pcap_dest_path, result_path)
            self.pcap_dest_path = result_path
            self.created_files = [self.pcap_dest_path]

            # process/move other created files
            pcap_basename = os.path.splitext(self.pcap_dest_path)[0]
            for x in self.attack_controller.additional_files:
                outpath = pcap_basename + "_" + x
                os.rename(x, outpath)
                self.created_files.append(outpath)

            print("done.")
            if attack[0] == 'WinHTTPSysExploit' and background_manipulation == True: 
                print("------------------------------------------------------------")
                print('Background traffic was impacted by the exploit')
                print('Total packet count: ' + str(updated_pkt_count))
                print("------------------------------------------------------------")

            # delete intermediate PCAP files
            if self.debug:
                print('NOT deleting intermediate attack pcap while in debug mode.')
            else:
                print('Deleting intermediate attack pcap...', end=" ")
                sys.stdout.flush()  # force python to print text immediately
                os.remove(attacks_pcap_path)
                print("done.")

            # write label file with attacks
            self.label_manager.write_label_file(self.pcap_dest_path)
            self.created_files.insert(1, self.label_manager.label_file_path)

            # print status message
            print('\nOutput files created:')
            for filepath in self.created_files:
                print(filepath)
        else:
            print("done.")
            print('\nOutput files created:')
            print("--> No packets were injected. Therefore no output files were created.")

        # print summary statistics
        if not self.non_verbose and len(attacks_config) != 1:
            self.statistics.stats_summary_post_attack(self.added_packets)

    def process_db_queries(self, query, print_results=False):
        """
        Processes a statistics database query. This can be a standard SQL query or a named query.

        :param query: The query as a string or multiple queries as a list of strings.
        :param print_results: Must be True if the results should be printed to terminal.
        :return: The query's result
        """
        print("Processing database query/queries...")
        if isinstance(query, list) or isinstance(query, tuple):
            for q in query:
                self.statisticsDB.process_db_query(q, print_results)
        else:
            self.statisticsDB.process_db_query(query, print_results)

    @staticmethod
    def process_help(params) -> None:
        """
        Prints either general help messages, or information about specific commands.
        :param params: A list of parameters for the help command (can be empty).
        """
        if not params:
            print("Query mode allows you to enter SQL-queries as well as named queries.")
            print()
            print("Named queries:")
            print("\tSelectors:")
            print("\t\tmost_used(...)  -> Returns the most occurring element in all elements")
            print("\t\tleast_used(...) -> Returns the least occurring element in all elements")
            print("\t\tavg(...)        -> Returns the average of all elements")
            print("\t\tall(...)        -> Returns all elements")
            print("\tExtractors:")
            print("\t\trandom(...)     -> Returns a random element from a list")
            print("\t\tfirst(...)      -> Returns the first element from a list")
            print("\t\tlast(...)       -> Returns the last element from a list")
            print("\tParameterized selectors:")
            print("\t\tipAddress(...)  -> Returns all IP addresses fulfilling the specified conditions")
            print("\t\tmacAddress(...) -> Returns all MAC addresses fulfilling the specified conditions")
            print()
            print("Miscellaneous:")
            print("\tlabels            -> List all attacks listed in the label file, if any")
            print("\ttables            -> List all tables from database")
            print("\tcolumns TABLE     -> List column names and types from specified table")
            print()
            print("Additional information is available with 'help [KEYWORD];'")
            print("To get a list of examples, type 'help examples;'")
            print()
            return

        param = params[0].lower()
        if param == "most_used":
            print("most_used can be used as a selector for the following attributes:")
            print("ipAddress | macAddress | portNumber | protocolName | ttlValue | mssValue | winSize | ipClass")
            print()
        elif param == "least_used":
            print("least_used can be used as a selector for the following attributes:")
            print("ipAddress | macAddress | portNumber | protocolName | ttlValue | mssValue | winSize | ipClass")
            print()
        elif param == "avg":
            print("avg can be used as a selector for the following attributes:")
            print("pktsReceived | pktsSent | kbytesSent | kbytesReceived | ttlValue | mss")
            print()
        elif param == "all":
            print("all can be used as a selector for the following attributes:")
            print("ipAddress | ttlValue | mss | macAddress | portNumber | protocolName | winSize | ipClass")
            print()
        elif param in ["random", "first", "last"]:
            print("No additional info available for this keyword.")
            print()
        elif param == "ipaddress":
            print("ipAddress is a parameterized selector which fetches IP addresses based on (a list of) conditions.")
            print("Conditions are of the following form: PARAMETER OPERATOR VALUE")
            print("The following parameters can be specified:")
            print("pktsReceived | pktsSent | kbytesReceived | kbytesSent | maxPktRate | minPktRate | ipClass\n"
                  "macAddress | ttlValue | ttlCount | portDirection | portNumber | portCount | protocolCount\n"
                  "protocolName")
            print()
            print("The following operators can be used:")
            print("<= | < | = | >= | > | in")
            print()
            print("A value can either be a simple values, a list of simple values separated by commas and enclosed "
                  "in [] brackets, or another query.")
            print()
            print("When VALUE is a list (or a query returning a list), the usage of the 'in' operator is mandatory!")
            print()
            print("See 'help examples;' for usage examples.")
            print()
        elif param == "macaddress":
            print("macAddress is a parameterized selector which fetches MAC addresses based on (a list of) conditions.")
            print("Conditions are of the following form: PARAMETER OPERATOR VALUE")
            print("The following parameters can be specified:")
            print("ipAddress")
            print()
            print("See 'help ipAddress' for information on valid operators and values.")
            print()
            print("See 'help examples;' for usage examples.")
            print()
        elif param == "examples":
            print("Get the average amount of sent packets per IP:")
            print("\tavg(pktsSent);")
            print("Get a random IP from all addresses occuring in the pcap:")
            print("\trandom(all(ipAddress));")
            print("Return the MAC address of a specified IP:")
            print("\tmacAddress(ipAddress=192.168.178.2);")
            print("Get the average TTL-value with SQL:")
            print("\tSELECT avg(ttlValue) from ip_ttl;")
            print("Get a random IP address from all addresses that sent and received at least 10 packets:")
            print("\trandom(ipAddress(pktsSent > 10, pktsReceived > 10));")
            print("Get the IP addresses used with one of the MAC addresses in a list:")
            print("\tipAddress(macAddress in [08:00:27:a3:83:43, 52:54:00:12:35:02]);")
            print()
        else:
            print("Unknown keyword '" + param + "', try 'help;' to get a list of allowed keywords'")
            print()

    def internal_command(self, query: str) -> bool:
        # Strip off semicolon, split into command and parameters
        query = query.strip(";").split(" ", 1)
        cmd = query[0].strip().lower()
        if len(query) > 1:
            params = [p for p in re.split("(,|\\\".*?\\\"|'.*?')", query[1]) if p.strip(",").strip()]
            params = list(map(lambda x: x.strip().strip("\"'"), params))
        else:
            params = []

        if cmd == "help":
            self.process_help(params)
            return True
        elif cmd == "labels":
            if not self.label_manager.labels:
                print("No labels found.")
            else:
                print("Attacks listed in the label file:")
                print()
                for i, label in enumerate(self.label_manager.labels):
                    print("Attack number:   " + str(i))
                    print("Attack name:     " + str(label.attack_name))
                    print("Attack note:     " + str(label.attack_note))
                    print("Attack seed:     " + str(label.seed))
                    print("Start timestamp: " + str(label.timestamp_start))
                    print("End timestamp:   " + str(label.timestamp_end))
                    print()
            print()
            return True
        elif cmd == "set":
            if len(params) == 3:
                if params[0].lower() == "attack_note":
                    i = int(params[1])
                    self.label_manager.labels[i].attack_note = params[2]
                return True
        elif cmd == "tables":
            self.statisticsDB.process_db_query("SELECT name FROM sqlite_master WHERE type='table';", True)
            return True
        elif cmd == "columns":
            is_table = self.statisticsDB.process_db_query("SELECT name FROM sqlite_master WHERE type='table' AND name='"
                                                          + params[0].lower() + "';", False)
            if not is_table:
                print("Table " + params[0].lower() + " does not exist.")
                return True
            self.statisticsDB.process_db_query("SELECT * FROM " + params[0].lower(), False)
            columns = self.statisticsDB.get_field_types(params[0].lower())
            for column in columns:
                print(column + ": " + columns[column])
            return True

        return False

    def enter_query_mode(self):
        """
        Enters into the query mode. This is a read-eval-print-loop, where the user can input named queries or SQL
        queries and the results are printed.
        """

        def make_completer(vocabulary):
            """
            TODO: FILL ME
            :param vocabulary:
            :return:
            """
            def custom_template(text, state):
                """
                TODO: FILL ME
                :param text:
                :param state:
                :return:
                """
                results = [x for x in vocabulary if x.startswith(text)] + [None]
                return results[state]

            return custom_template

        readline.parse_and_bind('tab: complete')
        readline.set_completer(make_completer(
            self.statisticsDB.get_all_named_query_keywords() + self.statisticsDB.get_all_sql_query_keywords()))
        history_file = os.path.join(Util.CACHE_DIR, 'query_history')
        try:
            readline.read_history_file(history_file)
        except IOError:
            pass
        print("Entering into query mode...")
        print("Enter statement ending by ';' and press ENTER to send query. Exit by sending an empty query.")
        print("Type 'help;' for information on possible queries.")
        buffer = ""
        while True:
            line = input("> ")
            if line == "":
                break
            buffer += line
            import sqlite3
            if sqlite3.complete_statement(buffer):
                buffer = buffer.strip()
                if not self.internal_command(buffer):
                    try:
                        self.statisticsDB.process_db_query(buffer, True)
                    except sqlite3.Error as e:
                        print("An error occurred:", e.args[0])
                    except pp.ParseException as e:
                        sys.stderr.write("Error in query:\n")
                        sys.stderr.write(buffer)
                        sys.stderr.write("\n")
                        for i in range(1, e.col):
                            sys.stderr.write(" ")
                        sys.stderr.write("^\n\n")
                    except StatsDB.QueryExecutionException as e:
                        sys.stderr.write("An error occured: ")
                        sys.stderr.write(e.args[0] + "\n")
                buffer = ""

        readline.set_history_length(1000)
        readline.write_history_file(history_file)

        # Save the label file, in case content has changed
        self.label_manager.write_label_file(self.pcap_src_path)

    def create_statistics_plot(self, params: str, entropy: bool):
        """
        Plots the statistics to a file by using the given customization parameters.
        """
        print("Statistical plots are being generated", end="", flush=True)
        if params is not None and params[0] is not None:
            # FIXME: cleanup
            params_dict = dict([z.split("=") for z in params])
            self.statistics.plot_statistics(entropy=entropy, file_format=params_dict['format'])
        else:
            self.statistics.plot_statistics(entropy=entropy)