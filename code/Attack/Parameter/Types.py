import enum


class ParameterTypes(enum.Enum):
    """
    Defines types for parameters. These types may be used in the specification of allowed parameters within the
    individual attack classes. The type is used to verify the validity of the given value.
    """
    TYPE_IP_ADDRESS = 0
    TYPE_MAC_ADDRESS = 1
    TYPE_PORT = 2
    TYPE_INTEGER_POSITIVE = 3
    TYPE_TIMESTAMP = 4
    TYPE_BOOLEAN = 5
    TYPE_FLOAT = 6
    TYPE_PACKET_POSITION = 7  # used to derive timestamp from parameter INJECT_AFTER_PACKET
    TYPE_DOMAIN = 8
    TYPE_STRING = 9
    TYPE_FILEPATH = 10
    TYPE_PERCENTAGE = 11
    TYPE_PADDING = 12
    TYPE_INTERVAL_SELECT_STRAT = 13
