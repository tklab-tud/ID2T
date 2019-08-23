import Attack.ParameterTypes.BaseType as BaseType


class Percentage(BaseType.ParameterType):

    def __init__(self):
        BaseType.ParameterType.__init__(self)
        self.name = "Percentage"

    @staticmethod
    def validate(value) -> (bool, int):
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
