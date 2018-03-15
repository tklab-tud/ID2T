import importlib
import sys
import difflib
import pkgutil

import Attack.AttackParameters as atkParam
import Core.LabelManager as LabelManager
import Core.Statistics as Statistics
import ID2TLib.Label as Label
import ID2TLib.PcapFile as PcapFile
import ID2TLib.Utility as Util


class AttackController:
    def __init__(self, pcap_file: PcapFile.PcapFile, statistics_class: Statistics, label_manager: LabelManager):
        """
        Creates a new AttackController. The controller manages the attack injection, including the PCAP writing.

        :param pcap_file: The source .pcap file to run the attack on.
        :param statistics_class: A Statistics Object.
        :param label_manager: A LabelManager Object.
        """
        self.statistics = statistics_class
        self.pcap_file = pcap_file
        self.label_mgr = label_manager

        self.current_attack = None
        self.added_attacks = []
        self.seed = None
        self.total_packets = 0

    def set_seed(self, seed: int):
        """
        Sets rng seed.

        :param seed: rng seed
        """
        self.seed = seed

    @staticmethod
    def choose_attack(input_name):
        """"
        Finds the attack best matching to input_name

        :param input_name: The name of the attack the user put in
        :return: The best matching attack in case one was found
        """

        import Attack

        # Find all attacks, exclude some classes
        package = Attack
        available_attacks = []
        for _, name, __ in pkgutil.iter_modules(package.__path__):
            if name != 'BaseAttack' and name != 'AttackParameters':
                available_attacks.append(name)

        highest_sim = 0.0
        highest_sim_attack = None
        for attack in available_attacks:
            # Check if attack name is accurate
            if input_name == attack:
                return attack
            # Compares input with one of the available attacks
            # Makes comparison with lowercase version with generic endings removed
            # List of generic attack name endings can be found in ID2TLib.Utility
            counter_check = attack.lower()
            if not any(ending in input_name for ending in Util.generic_attack_names):
                counter_check = Util.remove_generic_ending(counter_check)
            similarity = difflib.SequenceMatcher(None, input_name.lower(), counter_check).ratio()
            # Exact match, return appropriate attack name
            if similarity == 1.0:
                return attack
            # Found more likely match
            if similarity > highest_sim:
                highest_sim = similarity
                highest_sim_attack = attack

        # Found no exactly matching attack name, print best match and exit
        if highest_sim >= 0.6:
            print('Found no attack of name ' + input_name + '. The closest match was ' + highest_sim_attack +
                  '.  Use ./id2t -l for a list of available attacks.')
            exit(1)
        # Found no reasonably matching attack name, recommend -l and exit
        else:
            print('Found no attack of name ' + input_name + ' or one similar to it.'
                                                            ' Use ./id2t -l for an overview of available attacks.')
            exit(1)

    def create_attack(self, attack_name: str, seed=None):
        """
        Creates dynamically a new class instance based on the given attack_name.

        :param attack_name: The name of the attack, must correspond to the attack's class name.
        :param seed: random seed for param generation
        :return: None
        """
        attack_name = self.choose_attack(attack_name)

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

    def process_attack(self, attack: str, params: str, time=False):
        """
        Takes as input the name of an attack (classname) and the attack parameters as string. Parses the string of
        attack parameters, creates the attack by writing the attack packets and returns the path of the written pcap.

        :param attack: The classname of the attack to injecect.
        :param params: The parameters for attack customization, see attack class for supported params.
        :param time: Measure packet generation time or not.
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
            if (atkParam.Parameter.INJECT_AFTER_PACKET.value in params_dict) and (
                        atkParam.Parameter.INJECT_AT_TIMESTAMP.value in params_dict):
                print("CONFLICT: Parameters", atkParam.Parameter.INJECT_AT_TIMESTAMP.value, "and",
                      atkParam.Parameter.INJECT_AFTER_PACKET.value,
                      "given at the same time. Ignoring", atkParam.Parameter.INJECT_AT_TIMESTAMP.value, "and using",
                      atkParam.Parameter.INJECT_AFTER_PACKET.value, "instead to derive the timestamp.")
                del params_dict[atkParam.Parameter.INJECT_AT_TIMESTAMP.value]

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
        if time:
            self.current_attack.set_start_time()
        self.current_attack.generate_attack_packets()
        if time:
            self.current_attack.set_finish_time()
        duration = self.current_attack.get_packet_generation_time()
        self.total_packets, temp_attack_pcap_path = self.current_attack.generate_attack_pcap()
        print("done. (total: " + str(self.total_packets) + " pkts", end="")
        if time:
            print(" in ", duration, " seconds", end="")
        print(".)")

        # Store label into LabelManager
        label = Label.Label(attack, self.get_attack_start_utime(),
                            self.get_attack_end_utime(), self.current_attack.params, attack_note)
        self.label_mgr.add_labels(label)

        return temp_attack_pcap_path, duration


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
