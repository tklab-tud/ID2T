from Attack.ParameterTypes.BaseType import ParameterType


class String(ParameterType):

    def __init__(self, *args):
        super(String, self).__init__(*args)
        self.name = "String"

    def validate(self, value) -> (bool, str):
        is_valid = isinstance(value, str)
        return is_valid, value
