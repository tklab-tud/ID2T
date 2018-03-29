#!/usr/bin/python3

import scapy.all
import scapy.packet


# You could compare pcaps by byte or by hash too, but this class tells you
# where exactly pcaps differ
class PcapComparator:
    def compare_files(self, file: str, other_file: str):
        self.compare_captures(scapy.all.rdpcap(file), scapy.all.rdpcap(other_file))

    def compare_captures(self, packetsA, packetsB):
        if len(packetsA) != len(packetsB):
            self.fail("Both pcap's have to have the same amount of packets")

        for i in range(len(packetsA)):
            p, p2 = packetsA[i], packetsB[i]

            if abs(p.time - p2.time) > (10 ** -7):
                self.fail("Packets no %i in the pcap's don't appear at the same time" % (i + 1))
            self.compare_packets(p, p2, i + 1)

    def compare_packets(self, p: scapy.packet.BasePacket, p2: scapy.packet.BasePacket, packet_number: int):
        if p == p2:
            return

        while type(p) != scapy.packet.NoPayload or type(p2) != scapy.packet.NoPayload:
            if type(p) != type(p2):
                self.fail("Packets %i are of incompatible types: %s and %s" % (packet_number, type(p).__name__, type(p2).__name__))

            for field in p.fields:
                if p.fields[field] != p2.fields[field]:
                    packet_type = type(p).__name__
                    v, v2 = p.fields[field], p2.fields[field]

                    self.fail("Packets %i differ in field %s.%s: %s != %s" %
                                (packet_number, packet_type, field, v, v2))

            p = p.payload
            p2 = p2.payload

    def fail(self, message: str):
        raise AssertionError(message)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: %s one.pcap other.pcap" % sys.argv[0])
        exit(0)

    try:
        PcapComparator().compare_files(sys.argv[1], sys.argv[2])
        print("The given pcaps are equal")
    except AssertionError as e:
        print("The given pcaps are not equal")
        print("Error message:", *e.args)
        exit(1)
    except Exception as e:
        print("During the comparison an unexpected error happened")
        print(type(e).__name__ + ":", *e.args)
        exit(1)
