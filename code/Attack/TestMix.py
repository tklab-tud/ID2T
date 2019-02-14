import logging
import random as rnd
import os
from time import perf_counter
from datetime import datetime
from random import randint

import lea
import scapy.layers.inet as inet
import scapy.utils

import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack
import ID2TLib.Utility as Util

import ID2TLib.PcapFile as PcapFile
import Core.Statistics as Statistics

import Attack.Mix as Mix
import TMLib.ReWrapper as ReWrapper
import TMLib.Utility as MUtil
import TMLib.TMdict as TMdict
import TMLib.Testing as Testing

import TMLib.Definitions as TMdef

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8

class TestMix(BaseAttack.BaseAttack):

    default_config_yml_path = Util.RESOURCE_DIR + "test_mix_config.yml"
    default_attack = Util.RESOURCE_DIR + "hydra-1_tasks.pcap"
    default_tmp_file_name = 'test_mix.pcap'

    def __init__(self):

        super(TestMix, self).__init__("TestMix", "Mixes given attack into the target pcap'",
                                  "Any")

        self.pkt_num = 0

        self.attack_file = self.default_attack

        self.readwrite = 'sequence'

        self.attack_statistics = None

        self.export_filetype = 'xlsx'

        self.output_path = "../TMTestDir"

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

        parsing_start = perf_counter() # <------- TIMER

        param_dict = Mix.parse_config(config_path)

        ###
        ### Filling dictionaries
        ###

        filling_start = perf_counter() # <------- TIMER

        rewrap = Mix.fill_dictionaries(self, param_dict)


        ###
        ### Queuing functions
        ###

        queuing_start = perf_counter() # <------- TIMER

        Mix.enqueue_functions(param_dict, rewrap)

        ###
        ### Recalculating dictionaries 
        ###

        recalc_start = perf_counter() # <------- TIMER

        rewrap.recalculate_global_dict()

        ###
        ### Reading & rewrapping 
        ###

        digest_start = perf_counter() # <------- TIMER

        Mix.rewrapping(self, param_dict, rewrap, timestamp_next_pkt)

        digest_end = perf_counter() # <------- TIMER

        ###
        ### Generating test data 
        ###

        output_path = param_dict.get('test.output.dir.path')
        if output_path and output_path != 'default':
            output_path = os.path.join(output_path, generate_test_dir_name(self.attack_file))
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            self.output_path = output_path

        self.export_filetype = param_dict.get('export.filetype')
        if not self.export_filetype:
            self.export_filetype = 'xlsx'

        if self.export_filetype == 'xlsx':
            Testing.exportSQLite3_toXLSX(Testing.connection_SQLite3_fromStatistics
                , self.statistics
                , 'target'
                , self.output_path)
            Testing.exportSQLite3_toXLSX(Testing.connection_SQLite3_fromStatistics
                , self.attack_statistics
                , 'attack'
                , self.output_path)

        elif self.export_filetype == 'csv':
            output_path = os.path.join(self.output_path, 'CSV_target')
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            Testing.exportSQLite3_toCSV(Testing.connection_SQLite3_fromStatistics
                , self.statistics
                , self.output_path)

            output_path = os.path.join(self.output_path, 'CSV_attack')
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            Testing.exportSQLite3_toCSV(Testing.connection_SQLite3_fromStatistics
                , self.attack_statistics
                , self.output_path)

        with open(os.path.join(self.output_path, 'performance.txt'), 'a') as pfile:
            pfile.write('Mixing ' + self.attack_file + ' at ' + str(datetime.now()) + '\n') 
            pfile.write('    Parsing ' + str(filling_start - parsing_start) + '\n')
            pfile.write('    Filling  ' + str(queuing_start - filling_start) + '\n')
            pfile.write('    Queueing ' + str(recalc_start - queuing_start) + '\n')
            pfile.write('    Recalc ' + str(digest_start - recalc_start) + '\n')
            pfile.write('    Digest ' + str(digest_end - digest_start) + '\n')
            pfile.write(' > Total ' + str(digest_end - parsing_start) + '\n')



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

        # export statistics for generated attack pcap
        generated_attack_statistics = Statistics.Statistics(PcapFile.PcapFile(self.path_attack_pcap))
        generated_attack_statistics.load_pcap_statistics(False, True, False, False, [], False, None)
        if self.export_filetype == 'xlsx':
            Testing.exportSQLite3_toXLSX(Testing.connection_SQLite3_fromStatistics
                , generated_attack_statistics
                , 'generated_attack'
                , self.output_path)
        elif self.export_filetype == 'csv':
            output_path = os.path.join(self.output_path, 'CSV_generated_attack')
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            Testing.exportSQLite3_toCSV(Testing.connection_SQLite3_fromStatistics
                , self.attack_statistics
                , self.output_path)

        # return packets sorted by packet time_sec_start
        return self.pkt_num, self.path_attack_pcap


def generate_test_dir_name(pcap_path):
    name = os.path.splitext(path_leaf(pcap_path))[0]
    name += '_'
    name += datetime.now().isoformat('-')
    name += '_'
    name += str(randint(100,999))
    return name

def path_leaf(path):
    head, tail = os.path.split(path)
    return tail or os.path.basename(head)
