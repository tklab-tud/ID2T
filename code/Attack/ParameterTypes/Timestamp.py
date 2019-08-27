import re

from Attack.ParameterTypes.BaseType import ParameterType


class Timestamp(ParameterType):

    def __init__(self):
        super(Timestamp, self).__init__()
        self.name = "Timestamp"

    def validate(self, value) -> (bool, int):
        return Timestamp._is_timestamp(value), value

    @staticmethod
    def _is_timestamp(timestamp: str) -> bool:
        """
        Checks whether the given value is in a valid timestamp format. The accepted format is:
        YYYY-MM-DD h:m:s, whereas h, m, s may be one or two digits.

        :param timestamp: The timestamp to be checked.
        :return: True if the timestamp is valid, otherwise False.
        """
        is_valid = re.match(r'[0-9]{4}(?:-[0-9]{1,2}){2} (?:[0-9]{1,2}:){2}[0-9]{1,2}', timestamp)
        return is_valid is not None
