import os
import sys
from collections import deque
from datetime import datetime
from random import randint, randrange, choice, uniform

import ID2TLib.Botnet.libbotnetcomm as lb
from lea import Lea
from scapy.layers.inet import IP, IPOption_Security

import ID2TLib.Botnet.Message as Bmsg
import ID2TLib.Utility as Util
from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes
from ID2TLib import Generator
from ID2TLib.Botnet.CommunicationProcessor import CommunicationProcessor
from ID2TLib.Botnet.MessageMapping import MessageMapping
from ID2TLib.PcapAddressOperations import PcapAddressOperations
from ID2TLib.Ports import PortSelectors


class MembersMgmtCommAttack(BaseAttack.BaseAttack):
    def __init__(self):
        """
        Creates a new instance of the Membership Management Communication.

        """
        # Initialize communication
        super(MembersMgmtCommAttack, self).__init__(
            "Membership Management Communication Attack (MembersMgmtCommAttack)",
            "Injects Membership Management Communication", "Botnet communication")

        # Define allowed parameters and their type
        self.supported_params = {
            # parameters regarding attack
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PACKETS_LIMIT: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.ATTACK_DURATION: ParameterTypes.TYPE_INTEGER_POSITIVE,

            # use num_attackers to specify number of communicating devices?
            Param.NUMBER_INITIATOR_BOTS: ParameterTypes.TYPE_INTEGER_POSITIVE,

            # input file containing botnet communication
            Param.FILE_CSV: ParameterTypes.TYPE_FILEPATH,
            Param.FILE_XML: ParameterTypes.TYPE_FILEPATH,

            # the percentage of IP reuse (if total and other is specified, percentages are multiplied)
            Param.IP_REUSE_TOTAL: ParameterTypes.TYPE_PERCENTAGE,
            Param.IP_REUSE_LOCAL: ParameterTypes.TYPE_PERCENTAGE,
            Param.IP_REUSE_EXTERNAL: ParameterTypes.TYPE_PERCENTAGE,

            # the user-selected padding to add to every packet
            Param.PACKET_PADDING: ParameterTypes.TYPE_PADDING,

            # presence of NAT at the gateway of the network
            Param.NAT_PRESENT: ParameterTypes.TYPE_BOOLEAN,

            # whether the TTL distribution should be based on the input PCAP
            # or the CAIDA dataset
            Param.TTL_FROM_CAIDA: ParameterTypes.TYPE_BOOLEAN,

            # whether the destination port of a response should be the ephemeral port 
            # its request came from or a static (server)port based on a hostname
            Param.MULTIPORT: ParameterTypes.TYPE_BOOLEAN,

            # information about the interval selection strategy
            Param.INTERVAL_SELECT_STRATEGY: ParameterTypes.TYPE_INTERVAL_SELECT_STRAT,
            Param.INTERVAL_SELECT_START: ParameterTypes.TYPE_INTEGER_POSITIVE,
            Param.INTERVAL_SELECT_END: ParameterTypes.TYPE_INTEGER_POSITIVE,

            # determines whether injected packets are marked with an unused IP option
            # to easily filter them in e.g. wireshark
            Param.HIDDEN_MARK: ParameterTypes.TYPE_BOOLEAN
        }

        # create dict with MessageType values for fast name lookup
        self.msg_types = {}
        for msg_type in Bmsg.MessageType:
            self.msg_types[msg_type.value] = msg_type

    def init_params(self):
        """
        Initialize some parameters of this communication-attack using the user supplied command line parameters.
        The remaining parameters are implicitly set in the provided data file. Note: the timestamps in the file
        have to be sorted in ascending order

        :param statistics: Reference to a statistics object.
        """
        # set class constants
        self.DEFAULT_XML_PATH = Util.RESOURCE_DIR + "Botnet/MembersMgmtComm_example.xml"

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        self.add_param_value(Param.INJECT_AFTER_PACKET, 1 + randint(0, self.statistics.get_packet_count() // 5))

        self.add_param_value(Param.FILE_XML, self.DEFAULT_XML_PATH)

        # Alternatively new attack parameter?
        duration = int(float(self.statistics.get_capture_duration()))
        self.add_param_value(Param.ATTACK_DURATION, duration)
        self.add_param_value(Param.NUMBER_INITIATOR_BOTS, 1)
        # NAT on by default
        self.add_param_value(Param.NAT_PRESENT, True)

        # TODO: change 1 to something better
        self.add_param_value(Param.IP_REUSE_TOTAL, 1)
        self.add_param_value(Param.IP_REUSE_LOCAL, 0.5)
        self.add_param_value(Param.IP_REUSE_EXTERNAL, 0.5)

        # add default additional padding
        self.add_param_value(Param.PACKET_PADDING, 20)

        # choose the input PCAP as default base for the TTL distribution
        self.add_param_value(Param.TTL_FROM_CAIDA, False)

        # do not use multiple ports for requests and responses
        self.add_param_value(Param.MULTIPORT, False)

        # interval selection strategy
        self.add_param_value(Param.INTERVAL_SELECT_STRATEGY, "optimal")

        self.add_param_value(Param.HIDDEN_MARK, False)

    def generate_attack_pcap(self):
        """
        Injects the packets of this attack into a PCAP and stores it as a temporary file.
        :return: a tuple of the number packets injected, the path to the temporary attack PCAP
        and a list of additionally created files
        """

        # create the final messages that have to be sent, including all bot configurations
        messages = self._create_messages()

        if messages == []:
            return 0, None

        # Setup (initial) parameters for packet creation loop
        BUFFER_SIZE = 1000
        pkt_gen = Generator.PacketGenerator()
        padding = self.get_param_value(Param.PACKET_PADDING)
        packets = deque(maxlen=BUFFER_SIZE)
        total_pkts = 0
        limit_packetcount = self.get_param_value(Param.PACKETS_LIMIT)
        limit_duration = self.get_param_value(Param.ATTACK_DURATION)
        path_attack_pcap = None
        overThousand = False

        msg_packet_mapping = MessageMapping(messages, self.statistics.get_pcap_timestamp_start())
        mark_packets = self.get_param_value(Param.HIDDEN_MARK)

        # create packets to write to PCAP file
        for msg in messages:
            # retrieve the source and destination configurations
            id_src, id_dst = msg.src["ID"], msg.dst["ID"]
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
                nl_size = randint(1, 25)    # what is max NL entries?

            # create suitable IP/UDP packet and add to packets list
            packet = pkt_gen.generate_mmcom_packet(ip_src=ip_src, ip_dst=ip_dst, ttl=ttl, mac_src=mac_src,
                                                   mac_dst=mac_dst,
                                                   port_src=port_src, port_dst=port_dst, message_type=msg.type,
                                                   neighborlist_entries=nl_size)
            Generator.add_padding(packet, padding, True, True)

            packet.time = msg.time

            if mark_packets and isinstance(packet.payload, IP):  # do this only for ip-packets
                ip_data = packet.payload
                hidden_opt = IPOption_Security()
                hidden_opt.option = 2  # "normal" security opt
                hidden_opt.security = 16  # magic value indicating NSA

                ip_data.options = hidden_opt

            packets.append(packet)
            msg_packet_mapping.map_message(msg, packet)
            total_pkts += 1

            # Store timestamp of first packet (for attack label)
            if total_pkts <= 1:
                self.attack_start_utime = packets[0].time
            elif total_pkts % BUFFER_SIZE == 0:  # every 1000 packets write them to the PCAP file (append)
                if overThousand:  # if over 1000 packets written, packet-length for the last few packets may differ
                    packets = list(packets)
                    Generator.equal_length(packets, length=max_len, padding=padding, force_len=True)
                    last_packet = packets[-1]
                    path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                    packets = deque(maxlen=BUFFER_SIZE)
                else:
                    packets = list(packets)
                    Generator.equal_length(packets, padding=padding)
                    last_packet = packets[-1]
                    max_len = len(last_packet)
                    overThousand = True
                    path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                    packets = deque(maxlen=BUFFER_SIZE)

        # if there are unwritten packets remaining, write them to the PCAP file
        if len(packets) > 0:
            if overThousand:
                packets = list(packets)
                Generator.equal_length(packets, length = max_len, padding = padding, force_len = True)
                path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                last_packet = packets[-1]
            else:
                packets = list(packets)
                Generator.equal_length(packets, padding = padding)
                path_attack_pcap = self.write_attack_pcap(packets, True, path_attack_pcap)
                last_packet = packets[-1]

        # write the mapping to a file
        current_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        mapping_filename = "mapping_" + current_ts + ".xml"
        msg_packet_mapping.write_to_file(mapping_filename)

        # Store timestamp of last packet
        self.attack_end_utime = last_packet.time

        # Return packets sorted by packet by timestamp and total number of packets (sent)
        return total_pkts , path_attack_pcap, [mapping_filename]

    def generate_attack_packets(self):
        pass

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
                random_id = choice(ids)
                mac = self.statistics.process_db_query("macAddress(IPAddress=%s)" % ip)
                bot_configs[random_id] = {"Type": idtype, "IP": ip, "MAC": mac}
                ids.remove(random_id)

            # assign new IPs and for local IPs new MACs or for external IPs the router MAC to the IDs
            for ip in new_ips:
                random_id = choice(ids)
                if idtype == "local":
                    mac = macgen.random_mac()
                elif idtype == "external":
                    mac = router_mac
                bot_configs[random_id] = {"Type": idtype, "IP": ip, "MAC": mac}
                ids.remove(random_id)

        def assign_realistic_ttls(bot_configs: list):
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
                        source_ttl_prob_dict = Lea.fromValFreqsDict(bot_ttl_dist)
                        bot_configs[bot]["TTL"] = source_ttl_prob_dict.random()
                    else:
                        most_used_ttl = self.statistics.process_db_query("most_used(ttlValue)")
                        if isinstance(most_used_ttl, list):
                            bot_configs[bot]["TTL"] = choice(self.statistics.process_db_query("most_used(ttlValue)"))
                        else:
                            bot_configs[bot]["TTL"] = self.statistics.process_db_query("most_used(ttlValue)")

        def assign_realistic_timestamps(messages: list, external_ids: set, local_ids: set, avg_delay_local: float,
                                        avg_delay_external: float, zero_reference: float):
            """
            Assigns realistic timestamps to a set of messages

            :param messages: the set of messages to be updated
            :param external_ids: the set of bot ids, that are outside the network, i.e. external
            :param local_ids: the set of bot ids, that are inside the network, i.e. local
            :param avg_delay_local: the avg_delay between the dispatch and the reception of a packet between local
                                    computers
            :param avg_delay_external: the avg_delay between the dispatch and the reception of a packet between a local
                                       and an external computer
            :param zero_reference: the timestamp which is regarded as the beginning of the pcap_file and therefore
                                   handled like a timestamp that resembles 0
            """
            updated_msgs = []

            # Dict, takes a tuple of 2 Bot_IDs as a key (requester, responder), returns the time of the last response,
            # the requester received necessary in order to make sure, that additional requests are sent only after the
            # response to the last one was received
            last_response = {}

            for msg in messages:    # init
                last_response[(msg.src, msg.dst)] = -1

            # update all timestamps
            for req_msg in messages:

                if req_msg in updated_msgs :
                    # message already updated
                    continue

                # if req_msg.timestamp would be before the timestamp of the response to the last request, req_msg needs
                # to be sent later (else branch)
                if last_response[(req_msg.src, req_msg.dst)] == -1 or last_response[(req_msg.src, req_msg.dst)] < (
                        zero_reference + req_msg.time - 0.05):
                    # update req_msg timestamp with a variation of up to 50ms
                    req_msg.time = zero_reference + req_msg.time + uniform(-0.05, 0.05)
                    updated_msgs.append(req_msg)

                else:
                    req_msg.time = last_response[(req_msg.src, req_msg.dst)] + 0.06 + uniform(-0.05, 0.05)

                # update response if necessary
                if req_msg.refer_msg_id != -1:
                    respns_msg = messages[req_msg.refer_msg_id]

                    # check for local or external communication and update response timestamp with the respective
                    # avg delay
                    if req_msg.src in external_ids or req_msg.dst in external_ids:
                        # external communication
                        respns_msg.time = req_msg.time + avg_delay_external + uniform(-0.1 * avg_delay_external,
                                                                                      0.1 * avg_delay_external)

                    else:
                        # local communication
                        respns_msg.time = req_msg.time + avg_delay_local + uniform(-0.1 * avg_delay_local,
                                                                                   0.1 * avg_delay_local)

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
            total_ttl_prob_dict = Lea.fromValFreqsDict(get_total_ttl_distrib())

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
                    source_ttl_prob_dict = Lea.fromValFreqsDict(ip_ttl_freqs)
                    bot_configs[bot_id]["TTL"] = source_ttl_prob_dict.random()

                # otherwise assign a random TTL based on the total TTL distribution
                else:
                    bot_configs[bot_id]["TTL"] = total_ttl_prob_dict.random()

        # parse input CSV or XML
        filepath_xml = self.get_param_value(Param.FILE_XML)
        filepath_csv = self.get_param_value(Param.FILE_CSV)

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
        nat = self.get_param_value(Param.NAT_PRESENT)
        comm_proc = CommunicationProcessor(self.msg_types, nat)
        duration = self.get_param_value(Param.ATTACK_DURATION)
        number_init_bots = self.get_param_value(Param.NUMBER_INITIATOR_BOTS)
        strategy = self.get_param_value(Param.INTERVAL_SELECT_STRATEGY)
        start_idx = self.get_param_value(Param.INTERVAL_SELECT_START)
        end_idx = self.get_param_value(Param.INTERVAL_SELECT_END)

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
            rm_idx = randrange(0, len(mapped_ids))
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
        reuse_percent_total = self.get_param_value(Param.IP_REUSE_TOTAL)
        reuse_percent_external = self.get_param_value(Param.IP_REUSE_EXTERNAL)
        reuse_percent_local = self.get_param_value(Param.IP_REUSE_LOCAL)
        reuse_count_external = int(reuse_percent_total * reuse_percent_external * len(mapped_ids))
        reuse_count_local = int(reuse_percent_total * reuse_percent_local * len(mapped_ids))

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
            existing_local_ips = sorted(pcapops.get_existing_local_ips(reuse_count_local))
            new_local_ips = sorted(pcapops.get_new_local_ips(number_local_ids - len(existing_local_ips)))
            add_ids_to_config(sorted(local_ids), existing_local_ips, new_local_ips, bot_configs)

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
        zero_reference = self.get_param_value(Param.INJECT_AT_TIMESTAMP) - messages[0].time

        # calculate the average delay values for local and external responses
        avg_delay_local, avg_delay_external = self.statistics.get_avg_delay_local_ext()

        # set timestamps
        assign_realistic_timestamps(messages, external_ids, local_ids, avg_delay_local, avg_delay_external,
                                    zero_reference)

        portSelector = PortSelectors.LINUX
        reserved_ports = set(int(line.strip()) for line in open(Util.RESOURCE_DIR + "reserved_ports.txt").readlines())

        def filter_reserved(get_port):
            port = get_port()
            while port in reserved_ports:
                port = get_port()
            return port

        # create port configurations for the bots
        use_multiple_ports = self.get_param_value(Param.MULTIPORT)
        for bot in sorted(bot_configs):
            bot_configs[bot]["SrcPort"] = filter_reserved(portSelector.select_port_udp)
            if not use_multiple_ports:
                bot_configs[bot]["DstPort"] = filter_reserved(Generator.gen_random_server_port)
            else:
                bot_configs[bot]["DstPort"] = filter_reserved(portSelector.select_port_udp)

        # assign realistic TTL for every bot
        if self.get_param_value(Param.TTL_FROM_CAIDA):
            assign_ttls_from_caida(bot_configs)
        else:
            assign_realistic_ttls(bot_configs)

        # put together the final messages including the full sender and receiver
        # configurations (i.e. IP, MAC, port, ...) for easier later use
        final_messages = []
        messages = sorted(messages, key=lambda msg: msg.time)
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
