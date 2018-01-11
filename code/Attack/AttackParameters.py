from enum import Enum


class Parameter(Enum):
    """
    Defines the shortname for attack parameters. The shortname may be used for attack parameter specification
    when calling ID2T via the command line.
    """
    # recommended type: IP address -------------------------------
    IP_SOURCE = 'ip.src'  # source IP address
    IP_DESTINATION = 'ip.dst'  # destination IP address
    IP_DNS = 'ip.dns'  # IP address of DNS server
    HOSTING_IP = 'hosting.ip'
    IP_DESTINATION_END = 'ip.dst.end'
    # recommended type: MAC address ------------------------------
    MAC_SOURCE = 'mac.src'  # MAC address of source
    MAC_DESTINATION = 'mac.dst'  # MAC address of destination
    # recommended type: Port -------------------------------------
    PORT_OPEN = 'port.open'  # open ports
    PORT_DESTINATION = 'port.dst'  # destination ports
    PORT_SOURCE = 'port.src'  # source ports
    # recommended type: Integer positive -------------------------
    PACKETS_LIMIT = 'packets.limit'
    NUMBER_ATTACKERS = 'attackers.count'
    ATTACK_DURATION = 'attack.duration' # in seconds
    VICTIM_BUFFER = 'victim.buffer' # in packets
    TARGET_URI = 'target.uri'
    # recommended type: domain -----------------------------------
    TARGET_HOST = 'target.host'

    # recommended type: Float ------------------------------------
    PACKETS_PER_SECOND = 'packets.per-second'  # packets per second
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'  # unix epoch time (seconds.millis) where attack should be injected
    # recommended type: Packet Position ----------------------------------
    INJECT_AFTER_PACKET = 'inject.after-pkt'  # packet after which attack should be injected
    # recommended type: boolean  --------------------------------
    PORT_DEST_SHUFFLE = 'port.dst.shuffle'  # shuffles the destination ports if a list of ports is given
    PORT_DEST_ORDER_DESC = 'port.dst.order-desc'  # uses a descending port order instead of a ascending order
    IP_SOURCE_RANDOMIZE = 'ip.src.shuffle'  # randomizes the sources IP address if a list of IP addresses is given
    PORT_SOURCE_RANDOMIZE = 'port.src.shuffle'  # randomizes the source port if a list of sources ports is given

    PROTOCOL_VERSION = 'protocol.version'
    HOSTING_VERSION = 'hosting.version'
    SOURCE_PLATFORM = 'src.platform'


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
    TYPE_FLOAT = 6
    TYPE_PACKET_POSITION = 7  # used to derive timestamp from parameter INJECT_AFTER_PACKET
    TYPE_DOMAIN = 8
    TYPE_STRING = 9
