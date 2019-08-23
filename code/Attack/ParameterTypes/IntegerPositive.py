from Attack.ParameterTypes.BaseType import ParameterType


class IntegerPositive(ParameterType):

    def __init__(self, *args):
        super(IntegerPositive, self).__init__(*args)
        self.name = "IntegerPositive"

    def validate(self, value) -> (bool, int):
        is_valid = False
        if isinstance(value, int) and int(value) >= 0:
            is_valid = True
        elif isinstance(value, str) and value.isdigit() and int(value) >= 0:
            is_valid = True
            value = int(value)
        elif isinstance(value, str) and int(float(value)) >= 0:
            print("WARNING: " + str(IntegerPositive.name) + " requires a positive integer value.\n"
                  "         Float value " + value + " will be converted to an integer.")
            is_valid = True
            value = int(float(value))

        return is_valid, value
