import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import rdpcap, wrpcap
from scapy.all import IP, Ether, TCP, UDP
import sys

file_tel = "telnet-raw.pcap"

from scapy.utils import PcapWriter


def change_pcap(filepath):
    packets = rdpcap(filepath)
    split_filepath = filepath.split(".")
    new_filename = ".".join(split_filepath[:-1]) + "_new." + split_filepath[-1]

    #pktdump = PcapWriter(new_filename, append=True)

    for pkt in packets:
        """
        if pkt is packets[-1]:
            # test ethernet
            pkt[Ether].src = "AA:AA:AA:AA:AA:AA"
            pkt[Ether].dst = "BB:BB:BB:BB:BB:BB"
            #pkt[Ether].type = 0x1000

            pkt[IP].src = "255.255.255.255"
            pkt[IP].dst = "0.0.0.0"
            #pkt[IP].version = 0x1000
            #pkt[IP].ihl = 10
            pkt[IP].tos = 127
            #pkt[IP].len = 200

            # pkttwo = pkt
            #print(pkt.show)
            wrpcap(new_filename, pkt, append=True)
            #print("OK")
            #pktdump.write(pkt)
        """
        if pkt is packets[0]:
            wrpcap(new_filename, pkt)
        elif not pkt is packets[-1]:
            wrpcap(new_filename, pkt, append=True)


    ethernet = Ether(src="AA:AA:AA:AA:AA:AA", dst="BB:BB:BB:BB:BB:BB")
    ip = IP(src="255.255.255.255", dst="0.0.0.0", tos=127)
    tcp = TCP(sport=80, dport=50000, flags="SAF")
    pkt = ethernet/ip/tcp
    pkt.time = packets[-1].time
    wrpcap(new_filename, pkt, append=True)
    #print("OK")
    #pktdump.write(pkt)

def check_l2_diff(idx, payload_one, payload_two):
    # assumes that the L2 protocol of both packets are the same
    # assumes Ethernet as L2 protocol
    err_msg = ""
    if payload_one.name == "Ethernet":
        if payload_one[Ether].src != payload_two[Ether].src:
            err_msg += "Reason: the packets at index %d have a different source MAC address.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (payload_one[Ether].src.upper(), payload_two[Ether].src.upper())
        if payload_one[Ether].dst != payload_two[Ether].dst:
            err_msg += "Reason: the packets at index %d have a different destination MAC address.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (payload_one[Ether].dst.upper(), payload_two[Ether].dst.upper())
        if payload_one[Ether].type != payload_two[Ether].type:
            err_msg += "Reason: the packets at index %d have a different Ethernet type.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (payload_one[Ether].type, payload_two[Ether].type)
        
        if err_msg == "":
            return False, err_msg

        return True, err_msg
    else:
        return False, ""


def check_l3_diff(idx, payload_one, payload_two):
    # assumes that the L3 protocol of both packets are the same
    # assumes IPv4 as L3 protocol
    err_msg = ""
    if payload_one.name == "IP":
        ip_one, ip_two = payload_one[IP], payload_two[IP]
        if ip_one.src != ip_two.src:
            err_msg += "Reason: the packets at index %d have a different source IP address.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.src, ip_two.src)
        if ip_one.dst != ip_two.dst:
            err_msg += "Reason: the packets at index %d have a different destination IP address.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.dst, ip_two.dst)
        if ip_one.version != ip_two.version:
            err_msg += "Reason: the packets at index %d have a different IP version.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.version, ip_two.version)
        if ip_one.ihl != ip_two.ihl:
            err_msg += "Reason: the packets at index %d have a different IP IHL.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.ihl, ip_two.ihl)
        if ip_one.tos != ip_two.tos:
            err_msg += "Reason: the packets at index %d have a different IP TOS.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.tos, ip_two.tos)
        if ip_one.len != ip_two.len:
            err_msg += "Reason: the packets at index %d have a different length.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.len, ip_two.len)
        if ip_one.id != ip_two.id:
            err_msg += "Reason: the packets at index %d have a different IP ID.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.id, ip_two.id)
        if ip_one.flags != ip_two.flags:
            err_msg += "Reason: the packets at index %d have different IP flags.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.flags, ip_two.flags)
        if ip_one.frag != ip_two.frag:
            err_msg += "Reason: the packets at index %d have a different IP fragmentation offset.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.frag, ip_two.frag)
        if ip_one.ttl != ip_two.ttl:
            err_msg += "Reason: the packets at index %d have a different TTL.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.ttl, ip_two.ttl)
        if ip_one.proto != ip_two.proto:
            err_msg += "Reason: the packets at index %d have a different IP protocol field value.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.proto, ip_two.proto)
        if ip_one.chksum != ip_two.chksum:
            err_msg += "Reason: the packets at index %d have a different IP checksum.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.chksum, ip_two.chksum)
        if ip_one.options != ip_two.options:
            err_msg += "Reason: the packets at index %d have different IP options.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (ip_one.options, ip_two.options)
        
        if err_msg == "":
            return False, err_msg

        return True, err_msg
    else:
        return False, ""

def check_l4_diff(idx, payload_one, payload_two):
    # assumes that the L4 protocol of both packets are the same
    # assumes UDP or TCP as L4 protocol
    
    err_msg = ""
    if payload_one.name == "UDP":
        udp_one, udp_two = payload_one[UDP], payload_two[UDP]
        if udp_one.sport != udp_two.sport:
            err_msg += "Reason: the packets at index %d have a different source port.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (udp_one.sport, udp_two.sport)
        if udp_one.dport != udp_two.dport:
            err_msg += "Reason: the packets at index %d have a different destination port.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (udp_one.dport, udp_two.dport)
        if udp_one.len != udp_two.len:
            err_msg += "Reason: the packets at index %d have a different length.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (udp_one.len, udp_two.len)
        if udp_one.chksum != udp_two.chksum:
            err_msg += "Reason: the packets at index %d have a different UDP checksum.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (udp_one.chksum, udp_two.chksum)
        
        if err_msg == "":
            return False, err_msg

        return True, err_msg
    elif payload_one.name == "TCP":
        tcp_one, tcp_two = payload_one[TCP], payload_two[TCP]
        if tcp_one.sport != tcp_two.sport:
            err_msg += "Reason: the packets at index %d have a different source port.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.sport, tcp_two.sport)
        if tcp_one.dport != tcp_two.dport:
            err_msg += "Reason: the packets at index %d have a different destination port.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.dport, tcp_two.dport)
        if tcp_one.seq != tcp_two.seq:
            err_msg += "Reason: the packets at index %d have a different TCP sequence number.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.seq, tcp_two.seq)
        if tcp_one.ack != tcp_two.ack:
            err_msg += "Reason: the packets at index %d have a different TCP acknowledge number.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.ack, tcp_two.ack)
        if tcp_one.dataofs != tcp_two.dataofs:
            err_msg += "Reason: the packets at index %d have a different TCP data offset.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.dataofs, tcp_two.dataofs)
        if tcp_one.reserved != tcp_two.reserved:
            err_msg += "Reason: the packets at index %d have a different TCP reserved value.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.reserved, tcp_two.reserved)
        if tcp_one.flags != tcp_two.flags:
            err_msg += "Reason: the packets at index %d have different TCP flags.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.flags, tcp_two.flags)
        if tcp_one.window != tcp_two.window:
            err_msg += "Reason: the packets at index %d have a different advertised window size.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.window, tcp_two.window)
        if tcp_one.chksum != tcp_two.chksum:
            err_msg += "Reason: the packets at index %d have a different TCP checksum.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.chksum, tcp_two.chksum)
        if tcp_one.urgptr != tcp_two.urgptr:
            err_msg += "Reason: the packets at index %d have a different TCP urgent pointer.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.urgptr, tcp_two.urgptr)
        if tcp_one.options != tcp_two.options:
            err_msg += "Reason: the packets at index %d have different TCP options.\n" % (idx+1)
            err_msg += "Packet 1: %s \t Packet 2: %s\n\n" % (tcp_one.options, tcp_two.options)
        
        if err_msg == "":
            return False, err_msg

        return True, err_msg
    else:
        return False, err_msg

def check_payload_diff(idx, payload_one, payload_two):
    if payload_one != payload_two:
        err_msg = "Reason: the packets at index %d have different payloads.\n" % (idx+1)
        err_msg += "Packet 1:\n===================\n"
        if payload_one.load is not None:
            err_msg += str(payload_one.load)
        else:
            err_msg += "None"
        err_msg += "\n\n"
        err_msg += "Packet 2:\n===================\n"
        if payload_two.load is not None:
            err_msg += str(payload_two.load)
        else:
            err_msg += "None"
        return True, err_msg
    else:
        return False, ""

def check_different_layers(idx, layer_num, payload_one, payload_two):
    if payload_one.name != payload_two.name:
        err_msg = "Reason: the packets at index %d have a different layer %d protocol.\n" % (idx+1, layer_num)
        err_msg += "Packet 1: %s \t Packet 2: %s\n" % (payload_one.name, payload_two.name)
        return True, err_msg
    else:
        return False, ""

def find_detailed_diff(idx, pkt_one, pkt_two):
    def check_reason(check_func, check_same_layer=False):
        nonlocal printed_result
        nonlocal layer_num

        if not check_same_layer:
            status, msg = check_func(idx, payload_one, payload_two)
        else:
            status, msg = check_func(idx, layer_num, payload_one, payload_two)
        if status:
            if not printed_result:
                print("Result: the two PCAPs are not equal.")
                print("============================================")
                printed_result = True
            print("Layer %d:" % layer_num)
            print(msg)
        return status

    payload_one, payload_two = pkt_one, pkt_two
    printed_result = False
    layer_num = 2

    status = check_reason(check_different_layers, True)
    if not status:
        check_reason(check_l2_diff)

    while len(payload_one.payload) != 0:
        layer_num += 1
        payload_one = payload_one.payload
        payload_two = payload_two.payload
        if len(payload_two) == 0:
            if not printed_result:
                print("Result: the two PCAPs are not equal.")
                print("============================================")
                printed_result = True
            print("Reason: the packets at index %d have a different number of layers.\n" % (idx+1))
            return

        status = check_reason(check_different_layers, True)

        if not status:
            if layer_num == 3:
                check_reason(check_l3_diff)
            elif layer_num == 4:
                check_reason(check_l4_diff)
            elif layer_num > 4:
                check_reason(check_payload_diff)

    if printed_result:
        return

    if len(payload_one) == 0 and len(payload_two) != 0:
        if not printed_result:
            print("Result: the two PCAPs are not equal.")
            print("============================================")
        print("Reason: the packets at index %d have a different number of layers.\n" % (idx+1))
        return

    print("Result: the two PCAPs are not equal.")
    print("============================================")
    print("Reason: could not automatically find a detailed reason.")


def do_rough_comparison(filepath_one, filepath_two):
    packets_one = rdpcap(filepath_one)
    packets_two = rdpcap(filepath_two)

    if len(packets_one) != len(packets_two):
        print("Result: the two PCAPs are not equal.")
        print("============================================")
        print("Reason: they contain a different number of packets.")
        return

    for i, pkt_one in enumerate(packets_one):
        pkt_two = packets_two[i]
        # print(pkt_one.payload.payload.payload.name)
        # print()
        # print(pkt_one.show())
        if pkt_one.time != pkt_two.time:
            print("Result: the two PCAPs are not equal.")
            print("============================================")
            print("Reason: the packets at index %d have a different timestamp." % (i+1))
            return

        if pkt_one != pkt_two:
            #print("Result: the two PCAPs are not equal.")
            #print("Reason: the packets at index %d have different contents." % (i+1))
            find_detailed_diff(i, pkt_one, pkt_two)
            return

    print("Success")
    print("There are no differences between %s and %s" % (filepath_one, filepath_two))


def init_comparison():
    if len(sys.argv) != 3:
        print("Error: you need to specify two files to compare.\nCannot accept %d argument(s)" % (len(sys.argv)-1))

    filepath_one, filepath_two = sys.argv[1], sys.argv[2]
    #filepath_one, filepath_two = file_tel, file_tel
    #filepath_one, filepath_two = "shortcap.pcap", "shortcap.pcap"
    #filepath_one, filepath_two = "file1.pcap", "file3_new.pcap"
    print("Comparing %s and %s.\n" % (filepath_one, filepath_two))
    do_rough_comparison(filepath_one, filepath_two)


init_comparison()
#change_pcap("file3.pcap")