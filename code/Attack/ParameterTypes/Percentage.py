from Attack.ParameterTypes.BaseType import ParameterType


class Percentage(ParameterType):

    def __init__(self):
        super(Percentage, self).__init__()
        self.name = "Percentage"

    def validate(self, value) -> (bool, int):
        return Percentage._is_float(value)[0] and 0 <= value <= 1, value

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
