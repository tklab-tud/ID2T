from Attack.ParameterTypes.BaseType import ParameterType


class Float(ParameterType):

    PACKETS_PER_SECOND = 'packets.per-second'
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'

    def __init__(self):
        super(Float, self).__init__()
        self.name = "Float"

    def validate(self, value) -> (bool, float):
        is_valid, value = Float._is_float(value)
        return is_valid, value

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
