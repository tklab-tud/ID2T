from enum import Enum


class Parameter(Enum):
    """
    Defines the shortname for attack parameters. The shortname may be used for attack parameter specification
    when calling ID2T via the command line.
    """
    # type: IP address ------------------------------
    IP_SOURCE = 'ip.src'  # source IP address
    IP_DESTINATION = 'ip.dst'  # destination IP address
    IP_DNS = 'ip.dns'  # IP address of DNS server
    # type: MAC address -----------------------------
    MAC_SOURCE = 'mac.src'  # MAC address of source
    MAC_DESTINATION = 'mac.dst'  # MAC address of destination
    # type: Port ------------------------------------
    PORT_OPEN = 'port.open'  # open ports
    PORT_DESTINATION = 'port.dst'  # destination ports
    PORT_SOURCE = 'port.src'  # source ports
    # type: Digits ----------------------------------
    PACKETS_PER_SECOND = 'packets.per-second'  # packets per second
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'  # unix epoch time where attack should be injected
    INJECT_AFTER_PACKET = 'inject.after-pkt'  # packet after which attack should be injected
    # type: boolean  --------------------------------
    PORT_DEST_SHUFFLE = 'port.dst.shuffle'  # shuffles the destination ports if a list of ports is given
    PORT_ORDER_DESC = 'port.dst.order-desc'  # uses a descending port order instead of a ascending order
    IP_SOURCE_RANDOMIZE = 'ip.src.shuffle'  # randomizes the sources IP address if a list of IP addresses is given
    PORT_SOURCE_RANDOM = 'port.src.shuffle'  # randomizes the source port if a list of sources ports is given


class ParameterTypes(Enum):
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
    TYPE_ASC_DSC = 6
    TYPE_FLOAT = 7
    TYPE_PACKET_POSITION = 8  # used to derive timestamp from parameter INJECT_AFTER_PACKET
