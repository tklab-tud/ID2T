#! /usr/bin/python3
import argparse
import sys

from ID2TLib.Controller import Controller


class LoadFromFile(argparse.Action):
    """
    Parses the parameter file given by application param -c/--config.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        with values as f:
            parser.parse_args(f.read().split(), namespace)


class CLI(object):
    def __init__(self):
        """
        Creates a new CLI object used to handle
        """
        # Reference to PcapFile object
        self.args = None
        self.attack_config = None

    def process_arguments(self):
        """
        Loads the application controller, the PCAP file statistics and if present, processes the given attacks. Evaluates
        given queries.
        """
        # Create ID2T Controller
        controller = Controller(self.args.input)

        # Load PCAP statistics
        controller.load_pcap_statistics(self.args.export, self.args.recalculate, self.args.statistics)

        # Process attack(s) with given attack params
        if self.args.attack is not None:
            # If attack is present, load attack with params
            controller.process_attacks(self.args.attack)

        # Parameter -q without arguments was given -> go into query loop
        if self.args.query == [None]:
            controller.enter_query_mode()
        # Parameter -q with arguments was given -> process query
        elif self.args.query is not None:
            controller.process_db_queries(self.args.query, True)

    def parse_arguments(self, args):
        """
        Defines the allowed application arguments and invokes the evaluation of the arguments.

        :param args: The application arguments
        """
        # Create parser for arguments
        parser = argparse.ArgumentParser(description="Intrusion Detection Dataset Toolkit (ID2T) - A toolkit for "
                                                     "injection of synthetically created attacks into PCAP datasets.")
        # Define required arguments
        # requiredNamed = parser.add_argument_group('required named arguments')
        # requiredNamed.add_argument('-i', '--input', metavar="FILEPATH", help='path to the input pcap file',
        # required=True)

        # Define optional arguments
        parser.add_argument('-i', '--input', metavar="FILEPATH", help='path to the input pcap file', required=False)
        parser.add_argument('-c', '--config', metavar='FILEPATH', help='file containing parameters used as input.',
                            action=LoadFromFile, type=open)
        parser.add_argument('-e', '--export',
                            help='stores the statistics as a textfile with ending .stat into the dataset directory',
                            action='store_true', default=False)
        parser.add_argument('-a', '--attack', metavar="ATTACKNAME", action='append',
                            help='injects a new attack into the given dataset.', nargs='+')
        parser.add_argument('-g', '--gui', help='enables the Graphical User Interface (GUI) mode.', action='store_true',
                            default=False)
        parser.add_argument('-r', '--recalculate',
                            help='forces to recalculate the statistics in case of an already existing statistics database.',
                            action='store_true', default=False)
        parser.add_argument('-s', '--statistics', help='print general file statistics to stdout.', action='store_true',
                            default=False)
        parser.add_argument('-q', '--query', metavar="QUERY",
                            action='append', nargs='?',
                            help='queries the statistics database. If no query is provided, the application enters into query mode.')

        # Parse arguments
        self.args = parser.parse_args(args)

        # Either PCAP filepath or GUI mode must be enabled
        if not self.args.input and not self.args.gui:
            parser.error("Parameter -i/--input or -g/--gui required.")

        # GUI mode enabled
        if self.args.gui:
            raise NotImplementedError("Feature not implemented yet.")
            # gui = GUI.GUI()
            pass
        # CLI mode enabled
        else:
            self.process_arguments()


def main(args):
    """
    Creates a new CLI object and invokes the arguments parsing.

    :param args: The provided arguments
    """
    cli = CLI()
    # Check arguments
    cli.parse_arguments(args)


# Uncomment to enable calling by terminal
if __name__ == '__main__':
    main(sys.argv[1:])

# if __name__ == '__main__':
#     FILE = ['-i', '/mnt/hgfs/datasets/95M.pcap']
#     FILE2 = ['-i', '/mnt/hgfs/datasets/95M_20161103-185151.pcap']
#
#
#     ATTACK = ['-a', 'PortscanAttack', 'ip.src=10.2.2.4', 'mac.dst=05:AB:47:B5:19:11',
#               'inject.at-timestamp=1449038705.316721', 'attack.note=Portscan2']
#     ATTACK2 = ['-a', 'PortscanAttack', 'ip.dst=193.133.122.23, ip.src=192.124.34.12', 'inject.after-pkt=34']
#
#     STATS_RECALC = ['-r']
#     STATS_PRINT = ['-s']
#
#     QUERY_MODE_LOOP = ['-q']
#     QUERY_DB = ['-q', 'most_used(ttlValue)']
#
#     main(FILE2 + ATTACK)

    # main(['-c', '/home/pjattke/Thesis/development/code/config'])
