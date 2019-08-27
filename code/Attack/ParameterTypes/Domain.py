import re

from Attack.ParameterTypes.BaseType import ParameterType


class Domain(ParameterType):

    def __init__(self):
        super(Domain, self).__init__()
        self.name = "Domain"

    def validate(self, value) -> (bool, str):
        return Domain._is_domain(value), value

    @staticmethod
    def _is_domain(val: str) -> bool:
        """
        Verifies that the given string is a valid URI.

        :param val: The URI as string.
        :return: True if URI is valid, otherwise False.
        """
        domain = re.match(r'^(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$', val)
        return domain is not None
