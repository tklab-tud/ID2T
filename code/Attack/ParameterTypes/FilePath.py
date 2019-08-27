import os

from Attack.ParameterTypes.BaseType import ParameterType


class FilePath(ParameterType):

    def __init__(self):
        super(FilePath, self).__init__()
        self.name = "FilePath"

    def validate(self, value) -> (bool, str):
        return os.path.isfile(value), value
