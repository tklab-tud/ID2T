import functools


@functools.total_ordering
class Label:
    def __init__(self, attack_name, timestamp_start, timestamp_end, injected_packets, seed, parameters, attack_note=""):
        """
        Creates a new attack label

        :param attack_name: The name of the associated attack
        :param timestamp_start: The timestamp as unix time of the first attack packet
        :param timestamp_end: The timestamp as unix time of the last attack packet
        :param injected_packets: The number of packets injected by the attack
        :param seed: The seed used for randomization
        :param parameters: The list of parameters used to run the attack
        :param attack_note: A note associated to the attack (optional)
        """
        self.attack_name = attack_name
        self.timestamp_start = timestamp_start
        self.timestamp_end = timestamp_end
        self.injected_packets = injected_packets
        self.seed = seed
        self.attack_note = attack_note
        self.parameters = parameters

    def __eq__(self, other):
        return self.timestamp_start == other.timestamp_start

    def __lt__(self, other):
        return self.timestamp_start < other.timestamp_start

    def __gt__(self, other):
        return self.timestamp_start > other.timestamp_start

    def __str__(self):
        # FIXME: maybe add self.parameters as well?
        return ''.join(
            ['(', self.attack_name, ',', self.attack_note, ',', str(self.timestamp_start), ',', str(self.timestamp_end),
             str(self.injected_packets), ',', str(self.seed), ')'])
