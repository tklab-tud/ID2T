from Attack.ParameterTypes.BaseType import ParameterType


class Boolean(ParameterType):

    def __init__(self):
        super(Boolean, self).__init__()
        self.name = "Boolean"

    def validate(self, value) -> (bool, int):
        return Boolean._is_boolean(value)

    @staticmethod
    def _is_boolean(value):
        """
        Checks whether the given value (string or bool) is a boolean. Strings are valid booleans if they are in:
        {y, yes, t, true, on, 1, n, no, f, false, off, 0}.

        :param value: The value to be checked.
        :return: True if the value is a boolean, otherwise false. And the casted boolean.
        """
        # If value is already a boolean
        if isinstance(value, bool):
            return True, value

        # If value is a string
        # True values are y, yes, t, true, on and 1;
        # False values are n, no, f, false, off and 0.
        # Raises ValueError if value is anything else.
        try:
            import distutils.core
            import distutils.util
            value = bool(distutils.util.strtobool(value.lower()))
            is_bool = True
        except ValueError:
            is_bool = False
        return is_bool, value
