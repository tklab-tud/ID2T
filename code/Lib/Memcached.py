import scapy.packet as packet
import scapy.fields as field
import scapy.layers.inet as inet


memcached_port = 11211


class Memcached_Request(packet.Packet):
    namez = "Memcached UDP request packet"
    fields_desc = [field.ShortField("RequestID", 0),
                   field.ShortField("SequenceNumber", 0),
                   field.ShortField("DatagramCount", 1),
                   field.ShortField("Reserved", 0),
                   field.StrField("Request", "\r\n")]


packet.bind_layers(inet.UDP, Memcached_Request, dport=11211)
