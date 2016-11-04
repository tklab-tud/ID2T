import os

from ID2TLib.AttackController import AttackController
from ID2TLib.LabelManager import LabelManager
from ID2TLib.PcapFile import PcapFile
from ID2TLib.Statistics import Statistics


class Controller:
    def __init__(self, pcap_file_path: str):
        """
        Creates a new Controller, acting as a central coordinator for the whole application.
        :param pcap_file_path:
        """
        # Fields
        self.pcap_src_path = pcap_file_path
        self.pcap_dest_path = ''
        self.written_pcaps = []

        # Initialize class instances
        print("Input file: %s" % self.pcap_src_path)
        self.pcap_file = PcapFile(self.pcap_src_path)
        self.label_manager = LabelManager(self.pcap_src_path)
        self.statistics = Statistics(self.pcap_file)
        self.statisticsDB = self.statistics.get_statistics_database()
        self.attack_controller = AttackController(self.pcap_file, self.statistics, self.label_manager)

    def load_pcap_statistics(self, flag_write_file: bool, flag_recalculate_stats: bool, flag_print_statistics: bool):
        """
        Loads the PCAP statistics either from the database, if the statistics were calculated earlier, or calculates
        the statistics and creates a new database.
        :param flag_write_file: Writes the statistics to a file.
        :param flag_recalculate_stats: Forces the recalculation of statistics.
        :param flag_print_statistics: Prints the statistics on the terminal.
        :return: None
        """
        self.statistics.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics)

    def process_attacks(self, attacks_config: list):
        """
        Creates the attack based on the attack name and the attack parameters given in the attacks_config. The
        attacks_config is a list of attacks, e.g.
        [['PortscanAttack', 'ip.src="192.168.178.2",'dst.port=80'],['PortscanAttack', 'ip.src="10.10.10.2"]]
        :param attacks_config: A list of attacks with their attack parameters.
        """
        # load attacks sequentially
        for attack in attacks_config:
            self.pcap_dest_path = self.attack_controller.process_attack(attack[0], attack[1:])

        # delete intermediate PCAP files
        for i in range(len(self.written_pcaps) - 1):
            os.remove(self.written_pcaps[i])

        # print status message
        print('\nOutput file created: ', self.pcap_dest_path)

        # write label file with attacks
        self.label_manager.write_label_file(self.pcap_dest_path)

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

    def enter_query_mode(self):
        """
        Enters into the query mode. This is a read-eval-print-loop, where the user can input named queries or SQL
        queries and the results are printed.
        """
        print("Entering into query mode...")
        print("Enter statement ending by ';' and press ENTER to send query. Exit by sending an empty query..")
        buffer = ""
        while True:
            line = input("> ")
            if line == "":
                break
            buffer += line
            import sqlite3
            if sqlite3.complete_statement(buffer):
                try:
                    buffer = buffer.strip()
                    self.statisticsDB.process_db_query(buffer, True)
                except sqlite3.Error as e:
                    print("An error occurred:", e.args[0])
                buffer = ""
