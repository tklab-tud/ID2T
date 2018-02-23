import importlib
import sys

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
        self.seed = None

    def set_seed(self, seed: int):
        """
        Sets global seed.

        :param seed: random seed
        """
        self.seed = seed

    def create_attack(self, attack_name: str, seed=None):
        """
        Creates dynamically a new class instance based on the given attack_name.
        :param attack_name: The name of the attack, must correspond to the attack's class name.
        :param seed: random seed for param generation
        :return: None
        """
        print("\nCreating attack instance of \033[1m" + attack_name + "\033[0m")
        # Load attack class
        attack_module = importlib.import_module("Attack." + attack_name)
        attack_class = getattr(attack_module, attack_name)

        # Instantiate the desired attack
        self.current_attack = attack_class()
        # Initialize the parameters of the attack with defaults or user supplied values.
        self.current_attack.set_statistics(self.statistics)
        if seed is not None:
            self.current_attack.set_seed(seed=seed)
        self.current_attack.init_params()
        # Record the attack
        self.added_attacks.append(self.current_attack)

    def process_attack(self, attack: str, params: str):
        """
        Takes as input the name of an attack (classname) and the attack parameters as string. Parses the string of
        attack parameters, creates the attack by writing the attack packets and returns the path of the written pcap.
        :param attack: The classname of the attack to injecect.
        :param params: The parameters for attack customization, see attack class for supported params.
        :return: The file path to the created pcap file.
        """
        self.create_attack(attack, self.seed)

        print("Validating and adding attack parameters.")

        # Add attack parameters if provided
        params_dict = []
        if isinstance(params, list) and params:
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
            attack_note = "This attack used only (random) default parameters."

        # Write attack into pcap file
        print("Generating attack packets...", end=" ")
        sys.stdout.flush()  # force python to print text immediately
        total_packets, temp_attack_pcap_path = self.current_attack.generate_attack_pcap()
        print("done. (total: " + str(total_packets) + " pkts.)")

        # Store label into LabelManager
        l = Label(attack, self.get_attack_start_utime(),
                  self.get_attack_end_utime(), attack_note)
        self.label_mgr.add_labels(l)

        return temp_attack_pcap_path

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