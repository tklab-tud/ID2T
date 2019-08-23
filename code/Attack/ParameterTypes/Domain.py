import re

import Attack.ParameterTypes.BaseType as BaseType


class Domain(BaseType.ParameterType):

    def __init__(self):
        BaseType.ParameterType.__init__(self)
        self.name = "Domain"

    @staticmethod
    def validate(value) -> (bool, str):
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
