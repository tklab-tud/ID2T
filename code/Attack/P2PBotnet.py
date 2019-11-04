import collections
import datetime as dt
import os
import random as rnd
import sys

import lea
import scapy.layers.inet as inet

import Attack.BaseAttack as BaseAttack
import Lib.Botnet.libbotnetcomm as lb
import Lib.Botnet.Message as Bmsg
import Lib.Generator as Generator
import Lib.Utility as Util

from Attack.Parameter import Parameter, Boolean, FilePath, IntegerPositive, IntegerLimited, IPAddress, Percentage,\
    SpecificString

from Lib.Botnet.CommunicationProcessor import CommunicationProcessor
from Lib.Botnet.MessageMapping import MessageMapping
from Lib.PcapAddressOperations import PcapAddressOperations
from Lib.Ports import PortSelectors


class P2PBotnet(BaseAttack.BaseAttack):
    PACKETS_LIMIT = 'packets.limit'
    ATTACK_DURATION = 'attack.duration'
    NUMBER_INITIATOR_BOTS = 'bots.count'
    FILE_CSV = 'file.csv'
    FILE_XML = 'file.xml'
    IP_REUSE_TOTAL = 'ip.reuse.total'
    IP_REUSE_LOCAL = 'ip.reuse.local'
    IP_REUSE_EXTERNAL = 'ip.reuse.external'
    INJECT_INTO_IPS = 'inject.ip'
    PACKET_PADDING = 'packet.padding'
    NAT_PRESENT = 'nat.present'
    TTL_FROM_CAIDA = 'ttl.from.caida'
    MULTIPORT = 'multiport'
    INTERVAL_SELECT_STRATEGY = 'interval.selection.strategy'
    INTERVAL_SELECT_START = 'interval.selection.start'
    INTERVAL_SELECT_END = 'interval.selection.end'
    HIDDEN_MARK = 'hidden_mark'

    def __init__(self):
        """
        Creates a new instance of the Membership Management Communication.

        """
        # Initialize communication
        super(P2PBotnet, self).__init__(
            "P2P Botnet Communication (P2PBotnet)",
            "Injects P2P Botnet Communication", "Botnet communication")

        # Define allowed parameters and their type
        self.update_params([
            # parameters regarding attack
            Parameter(self.PACKETS_LIMIT, IntegerPositive()),
            Parameter(self.ATTACK_DURATION, IntegerPositive()),

            # use num_attackers to specify number of communicating devices?
            Parameter(self.NUMBER_INITIATOR_BOTS, IntegerPositive()),

            # input file containing botnet communication
            Parameter(self.FILE_CSV, FilePath()),
            Parameter(self.FILE_XML, FilePath()),

            # the percentage of IP reuse (if total and other is specified, percentages are multiplied)
            Parameter(self.IP_REUSE_TOTAL, Percentage()),
            Parameter(self.IP_REUSE_LOCAL, Percentage()),
            Parameter(self.IP_REUSE_EXTERNAL, Percentage()),
            Parameter(self.INJECT_INTO_IPS, IPAddress()),

            # the user-selected padding to add to every packet
            Parameter(self.PACKET_PADDING, IntegerLimited([0, 100])),

            # presence of NAT at the gateway of the network
            Parameter(self.NAT_PRESENT, Boolean()),

            # whether the TTL distribution should be based on the input PCAP
            # or the CAIDA dataset
            Parameter(self.TTL_FROM_CAIDA, Boolean()),

            # whether the destination port of a response should be the ephemeral port
            # its request came from or a static (server)port based on a hostname
            Parameter(self.MULTIPORT, Boolean()),

            # information about the interval selection strategy
            Parameter(self.INTERVAL_SELECT_STRATEGY, SpecificString(["random", "optimal", "custom"])),
            Parameter(self.INTERVAL_SELECT_START, IntegerPositive()),
            Parameter(self.INTERVAL_SELECT_END, IntegerPositive()),

            # determines whether injected packets are marked with an unused IP option
            # to easily filter them in e.g. wireshark
            Parameter(self.HIDDEN_MARK, Boolean())
        ])

        # create dict with MessageType values for fast name lookup
        self.msg_types = {}
        for msg_type in Bmsg.MessageType:
            self.msg_types[msg_type.value] = msg_type

        self.DEFAULT_XML_PATH = None

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with its default values specified in this attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """
        value = None
        # set class constants
        self.DEFAULT_XML_PATH = Util.RESOURCE_DIR + "Botnet/MembersMgmtComm_example.xml"

        if param == self.INJECT_AFTER_PACKET:
            value = self.statistics.get_rnd_packet_index(divisor=5)
        elif param == self.FILE_XML:
            value = self.DEFAULT_XML_PATH
        # Alternatively new attack parameter?
        elif param == self.ATTACK_DURATION:
            value = int(float(self.statistics.get_capture_duration()))
        elif param == self.NUMBER_INITIATOR_BOTS:
            value = 1
        # NAT on by default
        elif param == self.NAT_PRESENT:
            value = True
        elif param == self.IP_REUSE_TOTAL:
            # TODO: change 1 to something better
            value = 1
        elif param == self.IP_REUSE_EXTERNAL:
            value = 0.5
        elif param == self.IP_REUSE_LOCAL:
            value = 0.5
        # add default additional padding
        elif param == self.PACKET_PADDING:
            value = 20
        # choose the input PCAP as default base for the TTL distribution
        elif param == self.TTL_FROM_CAIDA:
            value = False
        # do not use multiple ports for requests and responses
        elif param == self.MULTIPORT:
            value = False
        # interval selection strategy
        elif param == self.INTERVAL_SELECT_STRATEGY:
            value = "optimal"
        elif param == self.HIDDEN_MARK:
            value = False
        if value is None:
            return False
        return self.add_param_value(param, value)

    def generate_attack_packets(self):
        pass

    def generate_attack_pcap(self):
        """
        Injects the packets of this attack into a PCAP and stores it as a temporary file.
        :return: a tuple of the number packets injected, the path to the temporary attack PCAP
        and a list of additionally created files
        """

        # create the final messages that have to be sent, including all bot configurations
        messages = self._create_messages()

        if not messages:
            return 0, None

        # Setup (initial) parameters for packet creation loop
        buffer_size = 1000
        pkt_gen = Generator.PacketGenerator()
        padding = self.get_param_value(self.PACKET_PADDING)
        packets = collections.deque(maxlen=buffer_size)
        total_pkts = 0
        limit_packetcount = self.get_param_value(self.PACKETS_LIMIT)
        limit_duration = self.get_param_value(self.ATTACK_DURATION)
        path_attack_pcap = None
        over_thousand = False

        msg_packet_mapping = MessageMapping(messages, self.statistics.get_pcap_timestamp_start())
        mark_packets = self.get_param_value(self.HIDDEN_MARK)

        # create packets to write to PCAP file
        for msg in messages:
            # retrieve the source and destination configurations
            ip_src, ip_dst = msg.src["IP"], msg.dst["IP"]
            mac_src, mac_dst = msg.src["MAC"], msg.dst["MAC"]
            if msg.type.is_request():
                port_src, port_dst = int(msg.src["SrcPort"]), int(msg.dst["DstPort"])
            else:
                port_src, port_dst = int(msg.src["DstPort"]), int(msg.dst["SrcPort"])
            ttl = int(msg.src["TTL"])

            # update duration
            duration = msg.time - messages[0].time

            # if total number of packets has been sent or the attack duration has been exceeded, stop
            if ((limit_packetcount is not None and total_pkts >= limit_packetcount) or
                    (limit_duration is not None and duration >= limit_duration)):
                break

            # if the type of the message is a NL reply, determine the number of entries
            nl_size = 0
            if msg.type == Bmsg.MessageType.SALITY_NL_REPLY:
                nl_size = rnd.randint(1, 25)    # what is max NL entries?

            # create suitable IP/UDP packet and add to packets list
            packet = pkt_gen.generate_mmcom_packet(ip_src=ip_src, ip_dst=ip_dst, ttl=ttl, mac_src=mac_src,
                                                   mac_dst=mac_dst,
                                                   port_src=port_src, port_dst=port_dst, message_type=msg.type,
                                                   neighborlist_entries=nl_size)
            Generator.add_padding(packet, padding, True, True)

            packet.time = msg.time

            if mark_packets and isinstance(packet.payload, inet.IP):  # do this only for ip-packets
                ip_data = packet.payload
                hidden_opt = inet.IPOption_Security()
                hidden_opt.option = 2  # "normal" security opt
                hidden_opt.security = 16  # magic value indicating NSA

                ip_data.options = hidden_opt

            packets.append(packet)
            msg_packet_mapping.map_message(msg, packet)
            total_pkts += 1

            # Store timestamp of first packet (for attack label)
            if total_pkts <= 1:
                self.attack_start_utime = packets[0].time
            elif total_pkts % buffer_size == 0:  # every 1000 packets write them to the PCAP file (append)
                packets = list(packets)
                if over_thousand:  # if over 1000 packets written, packet-length for the last few packets may differ
                    Generator.equal_length(packets, length=max_len, padding=padding, force_len=True)
                else:
                    Generator.equal_length(packets, padding=padding)
                    max_len = len(packets[-1])
                    over_thousand = True
                last_packet = packets[-1]
                path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                packets = collections.deque(maxlen=buffer_size)

        # if there are unwritten packets remaining, write them to the PCAP file
        if len(packets) > 0:
            packets = list(packets)
            if over_thousand:
                Generator.equal_length(packets, length=max_len, padding=padding, force_len=True)
            else:
                Generator.equal_length(packets, padding=padding)
            path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
            last_packet = packets[-1]

        # write the mapping to a file
        current_ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        mapping_filename = "mapping_" + current_ts + ".xml"
        msg_packet_mapping.write_to_file(mapping_filename)

        # Store timestamp of last packet
        self.attack_end_utime = last_packet.time

        # Return packets sorted by packet by timestamp and total number of packets (sent)
        return total_pkts, path_attack_pcap, [mapping_filename]

    def _create_messages(self):
        """
        Creates the messages that are to be injected into the PCAP.
        :return: the final messages as a list
        """

        def add_ids_to_config(ids_to_add: list, existing_ips: list, new_ips: list, bot_configs: dict,
                              idtype: str = "local", router_mac: str = ""):
            """
            Creates IP and MAC configurations for the given IDs and adds them to the existing configurations object.

            :param ids_to_add: all sorted IDs that have to be configured and added
            :param existing_ips: the existing IPs in the PCAP file that should be assigned to some, or all, IDs
            :param new_ips: the newly generated IPs that should be assigned to some, or all, IDs
            :param bot_configs: the existing configurations for the bots
            :param idtype: the locality type of the IDs
            :param router_mac: the MAC address of the router in the PCAP
            """

            ids = ids_to_add.copy()
            # macgen only needed, when IPs are new local IPs (therefore creating the object here suffices for the
            # current callers to not end up with the same MAC paired with different IPs)
            macgen = Generator.MacAddressGenerator()

            # assign existing IPs and the corresponding MAC addresses in the PCAP to the IDs
            for ip in existing_ips:
                random_id = rnd.choice(ids)
                mac = self.statistics.process_db_query("macAddress(IPAddress=%s)" % ip)
                bot_configs[random_id] = {"Type": idtype, "IP": ip, "MAC": mac}
                ids.remove(random_id)

            # assign new IPs and for local IPs new MACs or for external IPs the router MAC to the IDs
            for ip in new_ips:
                random_id = rnd.choice(ids)
                if idtype == "local":
                    mac = macgen.random_mac()
                elif idtype == "external":
                    mac = router_mac
                bot_configs[random_id] = {"Type": idtype, "IP": ip, "MAC": mac}
                ids.remove(random_id)

        def assign_realistic_ttls(bot_configs: dict):
            """
            Assigns a realisitic ttl to each bot from @param: bot_configs. Uses statistics and distribution to be able
            to calculate a realisitc ttl.
            :param bot_configs: List that contains all bots that should be assigned with realistic ttls.
            """
            ids = sorted(bot_configs.keys())
            for pos, bot in enumerate(ids):
                bot_type = bot_configs[bot]["Type"]
                if bot_type == "local":  # Set fix TTL for local Bots
                    bot_configs[bot]["TTL"] = 128
                    # Set TTL based on TTL distribution of IP address
                else:  # Set varying TTl for external Bots
                    bot_ttl_dist = self.statistics.get_ttl_distribution(bot_configs[bot]["IP"])
                    if len(bot_ttl_dist) > 0:
                        source_ttl_prob_dict = lea.Lea.fromValFreqsDict(bot_ttl_dist)
                        bot_configs[bot]["TTL"] = source_ttl_prob_dict.random()
                    else:
                        most_used_ttl = self.statistics.process_db_query("most_used(ttlValue)")
                        if isinstance(most_used_ttl, list):
                            bot_configs[bot]["TTL"] = rnd.choice(self.statistics.process_db_query("most_used(ttlValue)"))
                        else:
                            bot_configs[bot]["TTL"] = self.statistics.process_db_query("most_used(ttlValue)")

        def assign_realistic_timestamps(messages: list, external_ids: set, local_ids: set, avg_delay_local: list,
                                        avg_delay_external: list, zero_reference: float):
            """
            Assigns realistic timestamps to a set of messages

            :param messages: the set of messages to be updated
            :param external_ids: the set of bot ids, that are outside the network, i.e. external
            :param local_ids: the set of bot ids, that are inside the network, i.e. local
            :param avg_delay_local: the avg_delay distribution between the dispatch and the reception of a packet
                                    between local computers
            :param avg_delay_external: the avg_delay distribution between the dispatch and the reception of a packet
                                       between a local and an external computer
            :param zero_reference: the timestamp which is regarded as the beginning of the pcap_file and therefore
                                   handled like a timestamp that resembles 0
            """
            updated_msgs = []

            # Dict, takes a tuple of 2 Bot_IDs as a key (requester, responder), returns the time of the last response,
            # the requester received necessary in order to make sure, that additional requests are sent only after the
            # response to the last one was received
            last_response = {}

            for m in messages:    # init
                last_response[(m.src, m.dst)] = -1

            # update all timestamps
            for req_msg in messages:

                if req_msg in updated_msgs:
                    # message already updated
                    continue

                # if req_msg.timestamp would be before the timestamp of the response to the last request, req_msg needs
                # to be sent later (else branch)
                if last_response[(req_msg.src, req_msg.dst)] == -1 or last_response[(req_msg.src, req_msg.dst)] < (
                        zero_reference + req_msg.time - 0.05):
                    # update req_msg timestamp with a variation of up to 50ms
                    req_msg.time = zero_reference + req_msg.time + rnd.uniform(-0.05, 0.05)
                    updated_msgs.append(req_msg)

                else:
                    req_msg.time = last_response[(req_msg.src, req_msg.dst)] + 0.06 + rnd.uniform(-0.05, 0.05)

                # update response if necessary
                if req_msg.refer_msg_id != -1:
                    respns_msg = messages[req_msg.refer_msg_id]

                    # check for local or external communication and update response timestamp with the respective
                    # avg delay
                    if req_msg.src in external_ids or req_msg.dst in external_ids and avg_delay_external:
                        # external communication
                        dist = lea.Lea.fromSeq(avg_delay_external)
                    else:
                        # local communication
                        dist = lea.Lea.fromSeq(avg_delay_local)
                    delay = 0

                    while delay < 50 or (float(delay)*0.000001 > 5):
                        delay = dist.random()
                    respns_msg.time = req_msg.time + float(delay) * 0.000001

                    updated_msgs.append(respns_msg)
                    last_response[(req_msg.src, req_msg.dst)] = respns_msg.time

        def assign_ttls_from_caida(bot_configs):
            """
            Assign realistic TTL values to bots with respect to their IP, based on the CAIDA dataset.
            If there exists an entry for a bot's IP, the TTL is chosen based on a distribution over all used TTLs by
            this IP.
            If there is no such entry, the TTL is chosen based on a distribution over all used TTLs and their
            respective frequency.

            :param bot_configs: the existing bot configurations
            """

            def get_ip_ttl_distrib():
                """
                Parses the CSV file containing a mapping between IP and their used TTLs.
                :return: returns a dict with the IPs as keys and dicts for their TTL distribution as values
                """
                ip_based_distrib = {}
                with open("resources/CaidaTTL_perIP.csv", "r") as file:
                    # every line consists of: IP, TTL, Frequency
                    next(file)  # skip CSV header line
                    for line in file:
                        ip_addr, ttl, freq = line.split(",")
                        if ip_addr not in ip_based_distrib:
                            # the values for ip_based_distrib are dicts with key=TTL, value=Frequency
                            ip_based_distrib[ip_addr] = {}
                        ip_based_distrib[ip_addr][ttl] = int(freq)

                return ip_based_distrib

            def get_total_ttl_distrib():
                """
                Parses the CSV file containing an overview of all used TTLs and their respective frequency.
                :return: returns a dict with the TTLs as keys and their frequencies as keys
                """

                total_ttl_distrib = {}
                with open("resources/CaidaTTL_total.csv", "r") as file:
                    # every line consists of: TTL, Frequency, Fraction
                    next(file)  # skip CSV header line
                    for line in file:
                        ttl, freq, _ = line.split(",")
                        total_ttl_distrib[ttl] = int(freq)

                return total_ttl_distrib

            # get the TTL distribution for every IP that is available in "resources/CaidaTTL_perIP.csv"
            ip_ttl_distrib = get_ip_ttl_distrib()
            # build a probability dict for the total TTL distribution
            total_ttl_prob_dict = lea.Lea.fromValFreqsDict(get_total_ttl_distrib())

            # loop over every bot id and assign a TTL to the respective bot
            for bot_id in sorted(bot_configs):
                bot_type = bot_configs[bot_id]["Type"]
                bot_ip = bot_configs[bot_id]["IP"]

                if bot_type == "local":
                    bot_configs[bot_id]["TTL"] = 128

                # if there exists detailed information about the TTL distribution of this IP
                elif bot_ip in ip_ttl_distrib:
                    ip_ttl_freqs = ip_ttl_distrib[bot_ip]
                    # build a probability dict from this IP's TTL distribution
                    source_ttl_prob_dict = lea.Lea.fromValFreqsDict(ip_ttl_freqs)
                    bot_configs[bot_id]["TTL"] = source_ttl_prob_dict.random()

                # otherwise assign a random TTL based on the total TTL distribution
                else:
                    bot_configs[bot_id]["TTL"] = total_ttl_prob_dict.random()

        # parse input CSV or XML
        filepath_xml = self.get_param_value(self.FILE_XML)
        filepath_csv = self.get_param_value(self.FILE_CSV)

        # use C++ communication processor for faster interval finding
        cpp_comm_proc = lb.botnet_comm_processor()

        # only use CSV input if the XML path is the default one
        # --> prefer XML input over CSV input (in case both are given)
        print_updates = False
        if filepath_csv and filepath_xml == self.DEFAULT_XML_PATH:
            filename = os.path.splitext(os.path.basename(filepath_csv))[0]
            filesize = os.path.getsize(filepath_csv) / 2**20  # get filesize in MB
            if filesize > 10:
                print("\nParsing input CSV file...", end=" ")
                sys.stdout.flush()
                print_updates = True
            cpp_comm_proc.parse_csv(filepath_csv)
            if print_updates:
                print("done.")
                print("Writing corresponding XML file...", end=" ")
                sys.stdout.flush()
            filepath_xml = cpp_comm_proc.write_xml(Util.OUT_DIR, filename)
            if print_updates:
                print("done.")
        else:
            filesize = os.path.getsize(filepath_xml) / 2**20  # get filesize in MB
            if filesize > 10:
                print("Parsing input XML file...", end=" ")
                sys.stdout.flush()
                print_updates = True
            cpp_comm_proc.parse_xml(filepath_xml)
            if print_updates:
                print("done.")

        # find a good communication mapping in the input file that matches the users parameters
        nat = self.get_param_value(self.NAT_PRESENT)
        comm_proc = CommunicationProcessor(self.msg_types, nat)
        duration = self.get_param_value(self.ATTACK_DURATION)
        number_init_bots = self.get_param_value(self.NUMBER_INITIATOR_BOTS)
        strategy = self.get_param_value(self.INTERVAL_SELECT_STRATEGY)
        start_idx = self.get_param_value(self.INTERVAL_SELECT_START)
        end_idx = self.get_param_value(self.INTERVAL_SELECT_END)

        potential_long_find_time = (
                    strategy == "optimal" and (filesize > 4 and self.statistics.get_packet_count() > 1000))
        if print_updates or potential_long_find_time:
            if not print_updates:
                print()
            print("Selecting communication interval from input CSV/XML file...", end=" ")
            sys.stdout.flush()
            if potential_long_find_time:
                print("\nWarning: Because of the large input files and the (chosen) interval selection strategy")
                print("'optimal', this may take a while. Consider using selection strategy 'random' or 'custom'...",
                      end=" ")
                sys.stdout.flush()
            print_updates = True

        comm_interval = comm_proc.get_comm_interval(cpp_comm_proc, strategy, number_init_bots, duration, start_idx,
                                                    end_idx)

        if not comm_interval:
            print("Error: An interval that satisfies the input cannot be found.")
            return []
        if print_updates:
            print("done.")  # print corresponding message to interval finding message

        # retrieve the mapping information
        mapped_ids = comm_interval["IDs"]
        packet_start_idx = comm_interval["Start"]
        packet_end_idx = comm_interval["End"]
        while len(mapped_ids) > number_init_bots:
            rm_idx = rnd.randrange(0, len(mapped_ids))
            del mapped_ids[rm_idx]

        if print_updates:
            print("Generating attack packets...", end=" ")
        sys.stdout.flush()
        # get the messages contained in the chosen interval
        abstract_packets = cpp_comm_proc.get_messages(packet_start_idx, packet_end_idx)
        comm_proc.set_mapping(abstract_packets, mapped_ids)
        # determine ID roles and select the messages that are to be mapped into the PCAP
        messages = comm_proc.det_id_roles_and_msgs()
        # use the previously detetermined roles to assign the locality of all IDs
        local_ids, external_ids = comm_proc.det_ext_and_local_ids()

        # determine number of reused local and external IPs
        reuse_percent_total = self.get_param_value(self.IP_REUSE_TOTAL)
        reuse_percent_external = self.get_param_value(self.IP_REUSE_EXTERNAL)
        reuse_percent_local = self.get_param_value(self.IP_REUSE_LOCAL)

        # create IP and MAC configurations for the IDs/Bots
        ipgen = Generator.IPGenerator()
        pcapops = PcapAddressOperations(self.statistics)
        router_mac = pcapops.get_probable_router_mac()
        bot_configs = {}

        # retrieve and assign the IPs and MACs for the bots with respect to the given parameters
        # (IDs are always added to bot_configs in the same order under a given seed)
        number_local_ids, number_external_ids = len(local_ids), len(external_ids)
        # assign addresses for local IDs
        if number_local_ids > 0:
            reuse_count_local = int(reuse_percent_total * reuse_percent_local * number_local_ids)
            existing_local_ips = []
            new_local_ips = []
            inject_into_ips = self.get_param_value(self.INJECT_INTO_IPS)
            if inject_into_ips:
                if not isinstance(inject_into_ips, list):
                    inject_into_ips = [inject_into_ips]
                for ip in inject_into_ips:
                    if not pcapops.in_remaining_local_ips(ip):
                        new_local_ips.append(ip)
                if new_local_ips is not []:
                    print("\nWARNING: the following IPs are not in the source pcap:\n{}".
                          format(str(new_local_ips)[1:-1]))
                for ip in new_local_ips:
                    inject_into_ips.remove(ip)
                existing_local_ips.extend(inject_into_ips)
                existing_local_ips.extend(pcapops.get_existing_local_ips(reuse_count_local - len(inject_into_ips)))
            else:
                existing_local_ips = pcapops.get_existing_local_ips(reuse_count_local)
            remaining_ip_count = number_local_ids - len(existing_local_ips) - len(new_local_ips)
            if remaining_ip_count < 0:
                print("WARNING: too many IPs, reducing by {}".format(remaining_ip_count * -1))
                new_local_ips = new_local_ips[:remaining_ip_count]
            else:
                new_local_ips.extend(pcapops.get_new_local_ips(remaining_ip_count))
            add_ids_to_config(sorted(local_ids), sorted(existing_local_ips), sorted(new_local_ips), bot_configs)

        # assign addresses for external IDs
        if number_external_ids > 0:
            reuse_count_external = int(reuse_percent_total * reuse_percent_external * number_external_ids)
            existing_external_ips = sorted(pcapops.get_existing_external_ips(reuse_count_external))
            remaining = len(external_ids) - len(existing_external_ips)

            for external_ip in existing_external_ips:
                ipgen.add_to_blacklist(external_ip)
            new_external_ips = sorted([ipgen.random_ip() for _ in range(remaining)])
            add_ids_to_config(sorted(external_ids), existing_external_ips, new_external_ips, bot_configs,
                              idtype="external", router_mac=router_mac)

        # this is the timestamp at which the first packet should be injected, the packets have to be shifted to
        # the beginning of the pcap file (INJECT_AT_TIMESTAMP) and then the offset of the packets have to be
        # compensated to start at the given point in time
        zero_reference = self.get_param_value(self.INJECT_AT_TIMESTAMP) - messages[0].time

        # calculate the average delay values for local and external responses
        avg_delay_local, avg_delay_external = self.statistics.get_avg_delay_distributions(False)

        # set timestamps
        assign_realistic_timestamps(messages, external_ids, local_ids, avg_delay_local, avg_delay_external,
                                    zero_reference)

        port_selector = PortSelectors.LINUX
        reserved_ports = set(int(line.strip()) for line in open(Util.RESOURCE_DIR + "reserved_ports.txt").readlines())

        def filter_reserved(get_port):
            port = get_port()
            while port in reserved_ports:
                port = get_port()
            return port

        # create port configurations for the bots
        use_multiple_ports = self.get_param_value(self.MULTIPORT)
        for bot in sorted(bot_configs):
            bot_configs[bot]["SrcPort"] = filter_reserved(port_selector.select_port_udp)
            if not use_multiple_ports:
                bot_configs[bot]["DstPort"] = filter_reserved(Generator.gen_random_server_port)
            else:
                bot_configs[bot]["DstPort"] = filter_reserved(port_selector.select_port_udp)

        # assign realistic TTL for every bot
        if self.get_param_value(self.TTL_FROM_CAIDA):
            assign_ttls_from_caida(bot_configs)
        else:
            assign_realistic_ttls(bot_configs)

        # put together the final messages including the full sender and receiver
        # configurations (i.e. IP, MAC, port, ...) for easier later use
        final_messages = []
        messages = sorted(messages, key=lambda m: m.time)
        new_id = 0

        for msg in messages:
            type_src, type_dst = bot_configs[msg.src]["Type"], bot_configs[msg.dst]["Type"]
            id_src, id_dst = msg.src, msg.dst

            # sort out messages that do not have a suitable locality setting
            if type_src == "external" and type_dst == "external":
                continue

            msg.src, msg.dst = bot_configs[id_src], bot_configs[id_dst]
            msg.src["ID"], msg.dst["ID"] = id_src, id_dst
            msg.msg_id = new_id
            new_id += 1
            # Important here to update refers, if needed later?
            final_messages.append(msg)

        return final_messages
