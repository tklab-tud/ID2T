from Attack.ParameterTypes.IntegerLimited import IntegerLimited
from Core.Statistics import Statistics


class PacketPosition(IntegerLimited):

    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'

    def __init__(self, args=[]):
        super(PacketPosition, self).__init__(args)
        self.name = "PacketPosition"

    def validate(self, value) -> (bool, int):
        statistics = Statistics(None)
        self.args = [0, statistics.get_packet_count()]

        return IntegerLimited.validate(self, value)

    @staticmethod
    def _is_float(value):
        """
        Checks whether the given value is a float.

        :param value: The value to be checked.
        :return: True if the value is a float, otherwise False. And the casted float.
        """
        try:
            value = float(value)
            return True, value
        except ValueError:
            return False, value
