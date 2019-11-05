import abc
import random

import Attack.ParameterTypes.BaseType as BaseType

from Attack.ParameterTypes.Boolean import Boolean
from Attack.ParameterTypes.Domain import Domain
from Attack.ParameterTypes.FilePath import FilePath
from Attack.ParameterTypes.Float import Float
from Attack.ParameterTypes.IntegerPositive import IntegerPositive
from Attack.ParameterTypes.IntegerLimited import IntegerLimited
from Attack.ParameterTypes.IPAddress import IPAddress
from Attack.ParameterTypes.MACAddress import MACAddress
from Attack.ParameterTypes.Percentage import Percentage
from Attack.ParameterTypes.Port import Port
from Attack.ParameterTypes.String import String
from Attack.ParameterTypes.SpecificString import SpecificString
from Attack.ParameterTypes.Timestamp import Timestamp


class Parameter(object):

    def __init__(self, name: str, type: BaseType.ParameterType):
        self._name = name
        self._type = type
        self._value = None
        self._user_specified = False

    @abc.abstractmethod
    def _validate(self, value):
        is_valid, value = self.type.validate(value)
        if is_valid:
            return is_valid, value
        else:
            raise BaseType.InvalidTypeException

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        try:
            is_valid, value = self._validate(value)
            self._value = value
        except BaseType.InvalidTypeException:
            print(value, " is not a valid value of type ", self.type.name, ".")
            return

        # Check on specific param values

        # inject at timestamp

        # this is required to avoid that the timestamp's microseconds of the first attack packet is '000000'
        # but microseconds are only chosen randomly if the given parameter does not already specify it
        # e.g. inject.at-timestamp=123456.987654 -> is not changed
        # e.g. inject.at-timestamp=123456 -> is changed to: 123456.[random digits]
        #if self.name == self.INJECT_AT_TIMESTAMP and is_valid and ((value - int(value)) == 0):
        #    value = value + random.uniform(0, 0.999999)

        # packets per second

        # Check user specified pps against limits
        #if self.name == self.PACKETS_PER_SECOND and is_valid and self.user_specified:
        #    if value > 1000000:
        #        value = 1000000
        #        print("WARNING: PPS is too high. Dropping to 1,000,000 pps.")
        #    elif value > 100000:
        #        print("WARNING: PPS is too high. Generated traffic might look unrealistic.\n"
        #              "Recommended are values equal or lower 100000.")
            #elif value == 0:
            #    value = 12500
            #    print("No PPS was specified. Default value ({}) was used.".format(value))

        # inject after packet

        # This function call is valid only if there is a statistics object available.
        #if self.statistics is None:
        #    print('ERROR: Statistics-dependent attack parameter added without setting a statistics object first.')
        #    exit(1)

        #ts = pr.pcap_processor(self.statistics.pcap_filepath, "False", Util.RESOURCE_DIR, "").get_timestamp_mu_sec(int(value))

        #if ts >= 0:
        #    param_name = self.INJECT_AT_TIMESTAMP
        #    value = (ts / 1000000)  # convert microseconds from getTimestampMuSec into seconds

    @property
    def user_specified(self):
        return self._user_specified

    @user_specified.setter
    def user_specified(self, value):
        self._user_specified = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value
