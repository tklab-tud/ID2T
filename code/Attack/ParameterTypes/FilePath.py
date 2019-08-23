import os

import Attack.ParameterTypes.BaseType as BaseType


class FilePath(BaseType.ParameterType):

    def __init__(self):
        BaseType.ParameterType.__init__(self)
        self.name = "FilePath"

    @staticmethod
    def validate(value) -> (bool, str):
        return os.path.isfile(value), value
