from Attack.ParameterTypes.BaseType import ParameterType


class Dictionary(ParameterType):

    def __init__(self):
        super(Dictionary, self).__init__()
        self.name = "Dictionary"

    def validate(self, value) -> (bool, dict):
        return isinstance(value, dict), value
