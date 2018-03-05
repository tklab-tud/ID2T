#! /usr/bin/env python3
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

    def parse_arguments(self, args):
        """
        Defines the allowed application arguments and invokes the evaluation of the arguments.

        :param args: The application arguments
        """
        # Create parser for arguments
        parser = argparse.ArgumentParser(description="Intrusion Detection Dataset Toolkit (ID2T) - A toolkit for "
                                         "injecting synthetically created attacks into PCAP files.",
                                         prog="id2t")
        # Required arguments
        required_group = parser.add_argument_group('required arguments')
        required_args_group = required_group.add_mutually_exclusive_group(required=True)

        required_args_group.add_argument('-i', '--input', metavar="PCAP_FILE",
                                         help='path to the input pcap file')
        required_args_group.add_argument('-l', '--list-attacks', action='store_true')

        # Optional arguments
        parser.add_argument('-c', '--config', metavar='CONFIG_FILE', help='file containing configuration parameters.',
                            action=LoadFromFile, type=open)
        parser.add_argument('-e', '--export',
                            help='store statistics as a ".stat" file',
                            action='store_true', default=False)
        parser.add_argument('-r', '--recalculate',
                            help='recalculate statistics even if a cached version exists.',
                            action='store_true', default=False)
        parser.add_argument('-s', '--statistics', help='print file statistics to stdout.', action='store_true',
                            default=False)
        parser.add_argument('-p', '--plot', help='creates the following plots: the values distributions of TTL, MSS, Window Size, '
                                                 'protocol, and the novelty distributions of IP, port, TTL, MSS, Window Size,'
                                                 ' and ToS. In addition to packets count in interval-wise.', action='append',
                            nargs='?')
        parser.add_argument('-q', '--query', metavar="QUERY",
                            action='append', nargs='?',
                            help='query the statistics database. If no query is provided, the application enters query mode.')
        parser.add_argument('-t', '--extraTests', help='perform extra tests on the input pcap file, including calculating IP entropy'
                                                       'in interval-wise, TCP checksum, and checking payload availability.', action='store_true')
        parser.add_argument('-S', '--randomSeed', action='append', help='sets random seed for testing or benchmarking',
                            nargs='+', default=[])
        parser.add_argument('-T', '--time', help='measures packet generation time', action='store_true', default=False)

        # Attack arguments
        parser.add_argument('-a', '--attack', metavar="ATTACK", action='append',
                                       help='injects ATTACK into a PCAP file.', nargs='+')
        # Parse arguments
        self.args = parser.parse_args(args)

        self.process_arguments()

    def process_arguments(self):
        """
        Decide what to do with each  of the command line parameters.
        """
        if self.args.list_attacks:
            # User wants to see the available attacks
            self.process_attack_listing()
        else:
            # User wants to process a PCAP
            self.process_pcap()

    def process_attack_listing(self):
        import pkgutil
        import importlib
        import Attack

        # Find all attacks, exclude some classes
        package = Attack
        attack_names = []
        for _, name, __ in pkgutil.iter_modules(package.__path__):
            if name != 'BaseAttack' and name != 'AttackParameters':
                attack_names.append(name)

        # List the attacks and their parameters
        emph_start = '\033[1m'
        emph_end = '\033[0m'
        for attack_name in attack_names:
            attack_module = importlib.import_module('Attack.{}'.format(attack_name))
            attack_class = getattr(attack_module, attack_name)
            # Instantiate the attack to get to its definitions.
            attack_obj = attack_class()
            print('* {}{}{}'.format(emph_start, attack_obj.attack_name, emph_end))
            print('\t- {}Description:{} {}'.format(emph_start, emph_end,
                                                   attack_obj.attack_description))
            print('\t- {}Type:{} {}'.format(emph_start, emph_end,
                                            attack_obj.attack_type))
            print('\t- {}Supported Parameters:{}'.format(emph_start, emph_end), end=' ')
            # Get all the parameter names in a list and sort them
            param_list = []
            for key in attack_obj.supported_params:
                param_list.append(key.value)
            param_list.sort()
            # Print each parameter type per line
            last_prefix = None
            current_prefix = None
            for param in param_list:
                current_prefix = param.split('.')[0]
                if not last_prefix or current_prefix != last_prefix:
                    print('\n\t + |', end=' ')
                print(param, end=' | ')
                last_prefix = current_prefix
            # Print an empty line
            print()

    def process_pcap(self):
        """
        Loads the application controller, the PCAP file statistics and if present, processes the given attacks. Evaluates
        given queries.
        """
        # Create ID2T Controller
        controller = Controller(self.args.input, self.args.extraTests)

        # Load PCAP statistics
        controller.load_pcap_statistics(self.args.export, self.args.recalculate, self.args.statistics)

        # Create statistics plots
        if self.args.plot is not None:
            doEntropy = False
            if self.args.extraTests:
                doEntropy = True
            controller.create_statistics_plot(self.args.plot, doEntropy)

        # Check random seed
        if not isinstance(self.args.randomSeed, list):
            self.args.randomSeed = [self.args.randomSeed]

        # Process attack(s) with given attack params
        if self.args.attack is not None:
            # If attack is present, load attack with params
            controller.process_attacks(self.args.attack, self.args.randomSeed, self.args.time)

        # Parameter -q without arguments was given -> go into query loop
        if self.args.query == [None]:
            controller.enter_query_mode()
        # Parameter -q with arguments was given -> process query
        elif self.args.query is not None:
            controller.process_db_queries(self.args.query, True)


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