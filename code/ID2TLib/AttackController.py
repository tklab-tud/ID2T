import importlib
import os
import tempfile

from scapy.utils import PcapWriter

from Attack.AttackParameters import Parameter
from ID2TLib import LabelManager
from ID2TLib import Statistics
from ID2TLib.Label import Label
from ID2TLib.PcapFile import PcapFile


class AttackController:
    def __init__(self, pcap_file: PcapFile, statistics_class: Statistics, label_manager: LabelManager):
        """
        Creates a new AttackController. The controller manages the attack injection, including the PCAP writing.
        :param statistics_class:
        """
        self.statistics = statistics_class
        self.pcap_file = pcap_file
        self.label_mgr = label_manager

        self.current_attack = None
        self.added_attacks = []

        # The PCAP where the attack should be injected into
        self.base_pcap = self.statistics.pcap_filepath

    def write_attack_pcap(self):
        """
        Writes the attack's packets into a PCAP file with a temporary filename.
        :return: The path of the written PCAP file.
        """
        packets = self.current_attack.get_packets()

        # Write packets into pcap file
        temp_pcap = tempfile.NamedTemporaryFile(delete=False)
        pktdump = PcapWriter(temp_pcap.name)
        pktdump.write(packets)

        # Store pcap path and close file objects
        pcap_path = temp_pcap.name
        pktdump.close()
        temp_pcap.close()

        return pcap_path

    def create_attack(self, attack_name: str):
        """
        Creates dynamically a new class instance based on the given attack_name.
        :param attack_name: The name of the attack, must correspond to the attack's class name.
        :return: None
        """
        print("\nCreating attack instance of \033[1m" + attack_name + "\033[0m")
        # Load attack class
        attack_module = importlib.import_module("Attack." + attack_name)
        attack_class = getattr(attack_module, attack_name)

        # Set current attack
        self.current_attack = attack_class(self.statistics, self.base_pcap)
        self.added_attacks.append(self.current_attack)

    def process_attack(self, attack: str, params: str):
        """
        Takes as input the name of an attack (classname) and the attack parameters as string. Parses the string of
        attack parameters, creates the attack by writing the attack packets, merges these packets into the existing
        dataset and stores the label file of the injected attacks.
        :param attack: The classname of the attack to injecect.
        :param params: The parameters for attack customization, see attack class for supported params.
        :return: The file path to the created pcap file.
        """
        self.create_attack(attack)

        # Add attack parameters if provided
        print("Validating and adding attack parameters.")
        params_dict = []
        if params is not None:
            # Convert attack param list into dictionary
            for entry in params:
                params_dict.append(entry.split('='))
            params_dict = dict(params_dict)
            # Check if Parameter.INJECT_AT_TIMESTAMP and Parameter.INJECT_AFTER_PACKET are provided at the same time
            # if TRUE: delete Paramter.INJECT_AT_TIMESTAMP (lower priority) and use Parameter.INJECT_AFTER_PACKET
            if (Parameter.INJECT_AFTER_PACKET.value in params_dict) and (
                        Parameter.INJECT_AT_TIMESTAMP.value in params_dict):
                print("CONFLICT: Parameters", Parameter.INJECT_AT_TIMESTAMP.value, "and",
                      Parameter.INJECT_AFTER_PACKET.value,
                      "given at the same time. Ignoring", Parameter.INJECT_AT_TIMESTAMP.value, "and using",
                      Parameter.INJECT_AFTER_PACKET.value, "instead to derive the timestamp.")
                del params_dict[Parameter.INJECT_AT_TIMESTAMP.value]

            # Extract attack_note parameter, if not provided returns an empty string
            key_attack_note = "attack.note"
            attack_note = params_dict.get(key_attack_note, "")
            params_dict.pop(key_attack_note, None)  # delete entry if found, otherwise return an empty string

            # Pass paramters to attack controller
            self.set_params(params_dict)
        else:
            attack_note = ""

        # Write attack into pcap file
        temp_attack_pcap_path = self.write_attack_pcap()

        # Merge attack with existing pcap
        pcap_dest_path = self.pcap_file.merge_attack(temp_attack_pcap_path)

        # Delete temporary attack pcap
        os.remove(temp_attack_pcap_path)

        # Store label into LabelManager
        l = Label(attack, self.get_attack_start_utime(),
                  self.get_attack_end_utime(), attack_note)
        self.label_mgr.add_labels(l)

        return pcap_dest_path

    def get_attack_start_utime(self):
        """
        :return: The start time (timestamp of first packet) of the attack as unix timestamp.
        """
        return self.current_attack.attack_start_utime

    def get_attack_end_utime(self):
        """
        :return: The end time (timestamp of last packet) of the attack as unix timestamp.
        """
        return self.current_attack.attack_end_utime

    def set_params(self, params: dict):
        """
        Sets the attack's parameters.
        :param params: The parameters in a dictionary: {parameter_name: parameter_value}
        :return: None
        """
        for param_key, param_value in params.items():
            self.current_attack.add_param_value(param_key, param_value)
