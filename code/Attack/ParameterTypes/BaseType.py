import abc


class InvalidTypeException(Exception):
    """
    Raised when input value is not of the right type.
    """
    pass


class ParameterType(object):

    def __init__(self, *args):
        self._name = None
        self.args = list(args)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @abc.abstractmethod
    def validate(self, value):
        pass
