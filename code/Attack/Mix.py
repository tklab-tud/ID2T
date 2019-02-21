import logging
import random as rnd
import os

import lea
import scapy.layers.inet as inet
import scapy.utils

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

import ID2TLib.PcapFile as PcapFile
import Core.Statistics as Statistics

import TMLib.ReWrapper as ReWrapper
import TMLib.Utility as MUtil
import TMLib.TMdict as TMdict

import TMLib.Definitions as TMdef

import TMLib.TMmanager as TMm

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8

class Mix(BaseAttack.BaseAttack):

    default_config_yml_path = Util.RESOURCE_DIR + "mix_config.yml"
    default_attack = Util.RESOURCE_DIR + "hydra-1_tasks.pcap"

    def __init__(self):

        super(Mix, self).__init__("Mix", "Mixes given attack into the target pcap'",
                                  "Any")

        self.pkt_num = 0

        self.attack_file = self.default_attack

        self.readwrite = 'sequence'

        self.attack_statistics = None

        self.supported_params.update({
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT
            , atkParam.Parameter.CUSTOM_PAYLOAD_FILE: atkParam.ParameterTypes.TYPE_FILEPATH
        })

    def init_params(self):
        """
        Initialize all required parameters taking into account user supplied values. If no value is supplied,
        or if a user defined query is supplied, use a statistics object to do the calculations.
        A call to this function requires a call to 'set_statistics' first.
        """
        self.add_param_value(atkParam.Parameter.CUSTOM_PAYLOAD_FILE, self.default_config_yml_path)


    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """

        timestamp_next_pkt = self.get_param_value(atkParam.Parameter.INJECT_AT_TIMESTAMP)

        config_path = self.get_param_value(atkParam.Parameter.CUSTOM_PAYLOAD_FILE)

        ###
        ### Parsing 
        ###

        param_dict = parse_config(config_path)

        ###
        ### Filling dictionaries
        ###

        rewrap = build_rewrapper(self, param_dict)


        ###
        ### Queuing functions
        ###

        fill, config_validate = enqueue_functions(param_dict, rewrap)

        ###
        ### Queuing functions
        ###
        
        validate_and_fill_dict(param_dict, rewrap, fill, config_validate)

        ###
        ### Recalculating dictionaries 
        ###

        rewrap.recalculate_global_dict()

        ###
        ### Reading & rewrapping 
        ###

        rewrapping(self, param_dict, rewrap, timestamp_next_pkt)


    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """

        # write attack packets to pcap
        if self.readwrite != 'sequence': # sequence mode automatically writes to pcap
            self.attack_start_utime = self.packets[0].time
            self.attack_end_utime = self.packets[-1].time

            self.path_attack_pcap = self.write_attack_pcap(self.packets)

        # return packets sorted by packet time_sec_start
        return len(self.packets), self.path_attack_pcap


def parse_config(config_path):
    """
    Parses config into a dictionary, no format checking.

    :param config_path: path to config file
    """
    if config_path[-1] == 'n': ## naive check for json by last letter
        param_dict = MUtil.parse_json_args(config_path)
    else:
        param_dict = MUtil.parse_yaml_args(config_path)
    return param_dict


def build_rewrapper(attack, param_dict):
    """
    Fill dictinaries with data from config.

    :param attack: Mix attack.
    :param param_dict: parsed config
    :return: rewrapper
    """
    if param_dict['atk.file'] != 'default': ## default attack is hydra-1_tasks
        attack.attack_file = param_dict['atk.file']

    ## generate statistics for attack pcap
    attack.attack_statistics = Statistics.Statistics(PcapFile.PcapFile(attack.attack_file))
    attack.attack_statistics.load_pcap_statistics(False, True, False, False, [], False, None)

    ## statistics stored in global dict under the keys
    global_dict = TMdict.GlobalRWdict(statistics = attack.statistics, attack_statistics = attack.attack_statistics)
    packet_dict = TMdict.PacketDataRWdict()
    conversation_dict = TMdict.ConversationRWdict()
    ## dicts stored in a dict under param data_dict under keys from TMdef
    rewrap = ReWrapper.ReWrapper(attack.statistics, global_dict, conversation_dict, packet_dict)

    return rewrap


def enqueue_functions(param_dict, rewrap):
    """
    Enqueue transformation functions and timestamp generation.

    :param param_dict: parsed config file dict
    :param rewrap: Rewrapper
    """
    ## check for timestamp generation section
    fill = set()
    config_validate = set()

    dict_ref = param_dict.get('timestamp')
    if dict_ref:
        ## required by random delay/oscilation functions
        threshold = dict_ref.get('random.threshold')
        if threshold:
            rewrap.data_dict[TMdef.GLOBAL]['timestamp_threshold'] = threshold

        ## main generator function
        timestamp_function = dict_ref.get('generation')
        if timestamp_function:
            timestamp_function_dependency(timestamp_function, rewrap.data_dict)
            TMm.change_timestamp_function(rewrap, timestamp_function)

        ## alterantive generation function
        timestamp_function = dict_ref.get('generation.alt')
        if timestamp_function:
            TMm.enlist_alt_timestamp_generation_function(rewrap, timestamp_function)

        ## postprocessing functions
        postprocess = dict_ref.get('postprocess')
        if postprocess:
            for f in postprocess:
                timestamp_function_dependency(f['function'], rewrap.data_dict)
                rewrap.enqueue_timestamp_postprocess(rewrap, f['function'])

    functions = [
    # Ether
    'mac_change_default'
    # ARP
    , 'arp_change_default'
    # IPv4 & IPv6
    , 'ip_change_default'
    , 'ipv6_change_default'
    # ICMP
    , 'icmp_ip_change_default'
    , 'icmp_tcp_change_default'
    , 'icmp_udp_change_default'
    # TCP
    , 'tcp_change_default'
    # UDP
    , 'udp_change_default'
    # DNS
    , 'dns_change_ips'
    # HTTP
    , 'httpv1_regex_ip_swap'
    ]

    for f in functions:
        _f, _c_v = TMm.enqueue_function(rewrap, f)
        fill.update(_f)
        config_validate.update(_c_v)

    return fill, config_validate


def validate_and_fill_dict(param_dict, rewrap, fill, validate):
    valid = True
    data = rewrap.data_dict
    for f in validate:
        valid &= f(param_dict)
    ## ignored for now
    if not valid:
        print('[WARNING] Invalid config')

    data = rewrap.data_dict
    for f in fill:
        f(data, param_dict)


def rewrapping(attack, param_dict, rewrap, timestamp_next_pkt):
    """
    Parsing and rewrapping (and writing) of attack pcap.

    :param attack: Mix
    :param param_dict: parsed config, dict
    :param rewrap: Rewrapper
    """
    ## check for readwrite mode
    rw = param_dict.get('read.write')
    if rw:
        attack.readwrite = rw
    else: ## default
        attack.readwrite = 'sequence'

    ## read & write all at once
    if attack.readwrite == 'bulk':
        ## read all packets
        packets = scapy.utils.rdpcap(attack.attack_file)

        ## timestamp shift based on first packet and input param
        rewrap.set_timestamp_shift(timestamp_next_pkt - packets[0].time)

        ## rewrapp packets
        for packet in packets:
            rewrap.digest(packet)
            attack.packets.append(packet)

        attack.pkt_num = len(attack.packets)

    ## read & write packet by packet
    elif attack.readwrite == 'sequence':
        ## create packet reader
        packets = scapy.utils.PcapReader(attack.attack_file)

        ## temporary list, avoid recreating lists for writing
        tmp_l = [0]

        attack.pkt_num = 0

        packet = packets.read_packet() # read next packet

        while (packet): # empty packet == None
            tmp_l[0] = packet # store current packet for writing 

            if attack.pkt_num == 0: # first packet
                rewrap.set_timestamp_shift(timestamp_next_pkt - packet.time)
                rewrap.digest(packet)
                attack.attack_start_utime = packet.time
                ## Create new pcap
                attack.path_attack_pcap = attack.write_attack_pcap(packets=tmp_l)
            else:
                rewrap.digest(packet)
                attack.attack_end_utime = packet.time
                ## Apend to existing pcap
                attack.write_attack_pcap(packets=tmp_l, append_flag=True, destination_path=attack.path_attack_pcap)

            attack.pkt_num += 1
            packet = packets.read_packet() # read next packet

def timestamp_function_dependency(fname, data_dict):
    ## requires threshold
    if fname in ['timestamp_random_oscillation','timestamp_delay_forIPconst', 'timestamp_delay']:
        if not data_dict[TMdef.GLOBAL].get('timestamp_threshold'):
            raise ValueError('Missing timestamp threshold')