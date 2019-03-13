import ID2TLib.Utility as Util

import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dns as dns
#import scapy_http.http as http
import scapy_extend.http as http
import scapy.utils

import re

import TMLib.Definitions as TMdef


#########################################
############## Global vars
#########################################

## IP
ipv4_regex = re.compile(r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
ipv6_regex = re.compile(r'((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|\n'
    r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|\n'
    r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|\n'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}:\n'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}\n'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

## DNS
qdcount = 'qdcount'
rcount = ['ancount', 'nscount', 'arcount']
rname = ['an', 'ns', 'ar']

#########################################
############## Ether
#########################################


def mac_change_default(packet, data):
    """
    Default mac address transformation. 
    Applies mac_src_change and mac_dst_change.

    :param packet: Ether packet; expected scapy ether packet.
    :param data: Dictionary containing entry mac_address_map containing mapping of mac adresses
    """
    mac_src_change(packet, data)
    mac_dst_change(packet, data)


def mac_src_change(packet, data):
    """
    Changest mac src adress of packet based on mac adress map in data.
    Data must be a dictionary containing entry mac_address_map that contains dictionary of adresses in form old_mac: new_mac

    :param packet: Ether packet; expected scapy ether packet.
    :param data: Dictionary containing entry mac_address_map containing mapping of mac adresses
    """
    mac_new = globalRWdict_findMatch(data, 'mac_address_map', packet.getfieldval('src'))
    if mac_new:
        packet.setfieldval('src', mac_new)


def mac_dst_change(packet, data):
    """
    Changest mac dst adress of packet based on mac adress map in data.
    Data must be a dictionary containing entry mac_address_map that contains dictionary of adresses in form old_mac: new_mac

    :param packet: Ether packet; expected scapy ether packet.
    :param data: Dictionary containing entry mac_address_map containing mapping of mac adresses
    """
    mac_new = globalRWdict_findMatch(data, 'mac_address_map', packet.getfieldval('dst'))
    if mac_new:
        packet.setfieldval('dst', mac_new)


###########################################
############### ARP
###########################################


def arp_change_default(packet, data):
    """
    Change hardware and protocol adress of ARP packet based on mac_address_map and ip_address_map.

    :param packet: scapy ARP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    arp_hwsrc_change(packet, data)
    arp_hwdst_change(packet, data)
    arp_psrc_change(packet, data)
    arp_pdst_change(packet, data)


def arp_hwsrc_change(packet, data):
    """
    Change ARP source hardware address using mac_address_map.

    :param packet: scapy ARP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    mac_new = globalRWdict_findMatch(data, 'mac_address_map', packet.getfieldval('hwsrc'))
    if mac_new:
        packet.setfieldval('hwsrc', mac_new)


def arp_hwdst_change(packet, data):
    """
    Change ARP destination hardware address using mac_address_map.

    :param packet: scapy ARP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    mac_new = globalRWdict_findMatch(data, 'mac_address_map', packet.getfieldval('hwdst'))
    if mac_new:
        packet.setfieldval('hwdst', mac_new)


def arp_psrc_change(packet, data):
    """
    Change ARP source protocol address using ip_address_map.

    :param packet: scapy ARP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('psrc'))
    if ip_new:
        packet.setfieldval('psrc', ip_new)


def arp_pdst_change(packet, data):
    """
    Change ARP destination protoco address using ip_address_Map

    :param packet: scapy ARP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('pdst'))
    if ip_new:
        packet.setfieldval('pdst', ip_new)


###########################################
############### IP
###########################################


def ip_change_default(packet, data):
    """
    Default IP address transfomation.
    Applies ip_src_change and ip_dst_change

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ip_ttl_change(packet, data)
    ip_src_change(packet, data)
    ip_dst_change(packet, data)



def ip_src_change(packet, data):
    """
    Changest ip src adress of packet based on ip adress map in data.
    Data must be a dictionary containing entry ip_address_map that contains dictionary of adresses in form old_ip: new_ip

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('src'))
    if ip_new:
        packet.setfieldval('src', ip_new)


def ip_dst_change(packet, data):
    """
    Changest ip dst adress of packet based on ip adress map in data.
    Data must be a dictionary containing entry ip_address_map that contains dictionary of adresses in form old_ip: new_ip

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('dst'))
    if ip_new:
        packet.setfieldval('dst', ip_new)


def ip_ttl_change(packet, data):
    """
    Changes packets ttl value.
    If ip is contained in ip ttl map, new ttl will depend on that value, else it will recieve default ttl value.
    Data must be a dictionary containing field ip_ttl_map containing dictionary of ip: ttl.
    Data must be a dictionary contaiing field ip_ttl_default containing ttl value.

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing field ip_ttl_map and ip_ttl_default.
    """
    ip = packet.getfieldval('src')
    if ip not in data[TMdef.GLOBAL][TMdef.TARGET]['ttl_exceptions']:
        ttl_new = globalRWdict_findMatch(data, 'ip_ttl_map', ip)
        if ttl_new:
            packet.setfieldval('ttl', ttl_new)
        else:
            packet.setfieldval('ttl', data[TMdef.GLOBAL][TMdef.TARGET]['ip_ttl_default'])


def ip_auto_checksum(packet, data):
    packet.setfieldval("chksum", None)


###########################################
############### IPv6
###########################################


def ipv6_change_default(packet, data):
    """
    Default IP address transfomation.
    Applies ip_src_change and ip_dst_change

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ipv6_src_change(packet, data)
    ipv6_dst_change(packet, data)
    ipv6_hlim_change(packet, data)


def ipv6_src_change(packet, data):
    """
    Changest ip src adress of packet based on ip adress map in data.
    Data must be a dictionary containing entry ip_address_map that contains dictionary of adresses in form old_ip: new_ip

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('src'))
    if ip_new:
        packet.setfieldval('src', ip_new)


def ipv6_dst_change(packet, data):
    """
    Changest ip dst adress of packet based on ip adress map in data.
    Data must be a dictionary containing entry ip_address_map that contains dictionary of adresses in form old_ip: new_ip

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing entry ip_address_map containing mapping of ip adresses
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('dst'))
    if ip_new:
        packet.setfieldval('dst', ip_new)


def ipv6_hlim_change(packet, data):
    """
    Changes packets ttl value.
    If ip is contained in ip ttl map, new ttl will depend on that value, else it will recieve default ttl value.
    Data must be a dictionary containing field ip_ttl_map containing dictionary of ip: ttl.
    Data must be a dictionary contaiing field ip_ttl_default containing ttl value.

    :param packet: IP packet; expected scapy IP packet.
    :param data: Dictionary containing field ip_ttl_map and ip_ttl_default.
    """
    ip = packet.getfieldval('src')
    if ip not in data[TMdef.GLOBAL][TMdef.TARGET]['ttl_exceptions']:
        ttl_new = globalRWdict_findMatch(data, 'ip_ttl_map', ip)
        if ttl_new:
            packet.setfieldval('hlim', ttl_new)
        else:
            packet.setfieldval('hlim', data[TMdef.GLOBAL][TMdef.TARGET]['ip_ttl_default'])


###############################################
################## TTL
###############################################

def default_calculate_ttl(statistics, ip):
    """
    UNUSED
    """
    ttl_dist = statistics.get_ttl_distribution(ip)
    if len(ttl_dist) > 0:
        ttl_prob_dict = lea.Lea.fromValFreqsDict(ttl_dist)
        ttl_value = destination_ttl_prob_dict.random()
    else:
        ttl_value = Util.handle_most_used_outputs(statistics.get_most_used_ttl_value())


###############################################
################## ICMPv6
###############################################

def icmpv6_mladdr_change(packet, data):
    """
    Changes ICMPv6 multicast listener address using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('mladdr'))
    if ip_new:
        packet.setfieldval('mladdr', ip_new)


def icmpv6_addr_change(packet, data):
    """
    Changes ICMPv6 ip address using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('addr'))
    if ip_new:
        packet.setfieldval('addr', ip_new)


def icmpv6_prefix_change(packet, data):
    """
    Changes ICMPv6 prefix using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('prefix'))
    if ip_new:
        packet.setfieldval('prefix', ip_new)


def icmpv6_tgt_change(packet, data):
    """
    Changes ICMPv6 target address using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip_new = globalRWdict_findMatch(data, 'ip_address_map', packet.getfieldval('tgt'))
    if ip_new:
        packet.setfieldval('tgt', ip_new)


def icmpv6_sources_change(packet, data):
    """
    Changes ICMPv6 Multicast Listener Query sources using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ips = packet.getfieldval('sources')
    if ips:
        for i in len(ips):
            ip_new = globalRWdict_findMatch(data, 'ip_address_map', ips[i])
            if ip_new:
                ips[i] = ip_new
        packet.setfieldval('sources', ips)


def icmpv6MLReport2_change(packet, data):
    """
    Changes ICMPv6 Multicast Listener Report records using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    records = packet.getfieldval('records')
    if records:
        for i in len(records):
            ipv6_dst_change(packet, data)
            icmpv6_sources_change(packet, data) 


def icmpv6_lladdr_change(packet, data):
    """
    Changes ICMPv6 Neightbor Discovery link layer address using mac_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    mac_new = globalRWdict_findMatch(data, 'mac_address_map', packet.getfieldval('lladdr'))
    if mac_new:
        packet.setfieldval('lladdr', mac_new)


def icmpv6_addresses_change(packet, data):
    """
    Changes ICMPv6 Home Agent Address Discovery Reply home agent addresses field using ip_address_map.

    :param packet: scapy ICMPv6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ips = packet.getfieldval('addresses')
    if ips:
        for i in len(ips):
            ip_new = globalRWdict_findMatch(data, 'ip_address_map', ips[i])
            if ip_new:
                ips[i] = ip_new
        packet.setfieldval('addresses', ips)


###############################################
################## TCP
###############################################


def tcp_change_default(packet, data):
    """
    Changes TCP win size, mss, and ports using win_size_map, mss_map, port_map_forIP.

    :param packet: scapy TCP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    tcp_win_size_change(packet, data)
    tcp_mss_change(packet, data)
    tcp_sport_change(packet, data)
    tcp_dport_change(packet, data)


def tcp_win_size_change(packet, data):
    """
    Changes TCP window size using win_size_map.

    Requires field ip_src_old in data[TMdef.PACKET].

    :param packet: scapy TCP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip = data[TMdef.PACKET]['ip_src_old']
    if ip not in data[TMdef.GLOBAL][TMdef.TARGET]['win_size_exceptions']:
        win = data[TMdef.GLOBAL][TMdef.TARGET]['win_size_map'].get( ip ) # ipmap[ip_new]
        if win:
            packet.setfieldval('window', win)
        else:
            packet.setfieldval('window', data[TMdef.GLOBAL][TMdef.TARGET]['win_size_default'])


def tcp_mss_change(packet, data):
    """
    Changes TCP maximum segment size using mss_map.

    Requires field ip_src_old in data[TMdef.PACKET].

    :param packet: scapy TCP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    ip = data[TMdef.PACKET]['ip_src_old']
    if ip not in data[TMdef.GLOBAL][TMdef.TARGET]['mss_exceptions']:
        # Find mss value
        mss = data[TMdef.GLOBAL][TMdef.TARGET]['mss_map'].get( ip )
        if not mss:
            mss = data[TMdef.GLOBAL][TMdef.TARGET]['mss_default']

        # Check existing field and change/create MSS field
        options = packet.getfieldval('options')
        for i in range(len(options)):
            if options[i][0] == 'MSS':
                options[i] = ('MSS', mss)
                mss = None
                break
        ## Unused, casuses bug where options are extended into padding
        ## If original packet doesn't specify MSS, new one shouldn't either
        # if mss:
        #     if isinstance(options, dict):
        #         options = []
        #     options.append(('MSS', mss))
        packet.setfieldval('options', options)


def tcp_sport_change(packet, data):
    """
    Changes TCP source port based on IP address in IPv4/6 packet using port_map_forIP.

    Requires field ip_src_old in data[TMdef.PACKET].

    :param packet: scapy TCP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    port = packet.getfieldval('sport')
    port_map = data[TMdef.GLOBAL][TMdef.TARGET]['port_map_forIP'].get( data[TMdef.PACKET]['ip_src_old'] )
    if port_map:
        port_new = port_map.get(port)
        if port_new:
            packet.setfieldval('sport', port_new)


def tcp_dport_change(packet, data):
    """
    Changes TCP destination port based on IP address in IPv4/6 packet using port_map_forIP.

    Requires field ip_dst_old in data[TMdef.PACKET].

    :param packet: scapy TCP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    port = packet.getfieldval('dport')
    port_map = data[TMdef.GLOBAL][TMdef.TARGET]['port_map_forIP'].get( data[TMdef.PACKET]['ip_dst_old'] )
    if port_map:
        port_new = port_map.get(port)
        if port_new:
            packet.setfieldval('dport', port_new)


def tcp_auto_checksum(packet, data):
    packet.setfieldval("chksum", None)


###############################################
################## UDP
###############################################


def udp_change_default(packet, data):
    """
    Changes UDP packets source and target ports using port_map_forIP.

    :param packet: scapy UDP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    udp_sport_change(packet, data)
    udp_dport_change(packet, data)


def udp_sport_change(packet, data):
    """
    Changes UDP source port using port_map_forIP.

    Requires field ip_src_old in data[TMdef.PACKET].

    :param packet: scapy UDP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    port = packet.getfieldval('sport')
    port_map = data[TMdef.GLOBAL][TMdef.TARGET]['port_map_forIP'].get( data[TMdef.PACKET]['ip_src_old'] )
    if port_map:
        port_new = port_map.get(port)
        if port_new:
            packet.setfieldval('sport', port_new)


def udp_dport_change(packet, data):
    """
    Changes UDP destination port using port_map_forIP.

    Requires field ip_dst_old in data[TMdef.PACKET].

    :param packet: scapy UDP packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    port = packet.getfieldval('dport')
    port_map = data[TMdef.GLOBAL][TMdef.TARGET]['port_map_forIP'].get( data[TMdef.PACKET]['ip_dst_old'] )
    if port_map:
        port_new = port_map.get(port)
        if port_new:
            packet.setfieldval('dport', port_new)


def udp_auto_checksum(packet, data):
    packet.setfieldval("chksum", None)


###############################################
################## DNS
###############################################

def dns_reverlookup_update(query, data): # TODO move into main dns function
    """
    Processes dnd revers lookup query and matches existing ip address to a new one based on ip_address_map.

    :param query: string containing revese lookup query field from DNS packet.
    :param data: dict containing TMLib.TMdict dictionaries
    :return: new reverse lookup query, or None if IP address was not changed.
    """
    ip = query.split('.', maxsplit=4)
    sufix = ip.pop()
    ip.reverse()
    ip_new = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map'].get('.'.join(ip))
    if ip_new:
        ip_new = ip_new.split('.')
        ip_new.reverse()
        ip_new.append(sufix)
        return '.'.join(ip_new)
    return None


def dns_change_ips(packet, data):
    """
    Changes ip addresses in DNS query for fields query name field (dns question),
    and record data and resource record name fields (resource records) using ip_address_map.

    :param packet: scapy DNS packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    qr = packet.getfieldval('qr') # question/response
    count = packet.getfieldval(qdcount)
    if count > 0:
        resources = packet.getfieldval('qd')
        for i in range(count):
            resource = resources[i] 
            if 12 == resource.getfieldval('qtype'):
                tmp = resource.getfieldval('qname')
                if isinstance(tmp, bytes):
                    ip_new = dns_reverlookup_update( tmp.decode('utf-8'), data)
                    if ip_new:
                        resource.setfieldval('qname', bytes(ip_new,'utf-8'))
                else:
                    ip_new = dns_reverlookup_update( tmp, data)
                    if ip_new:
                        resource.setfieldval('qname', ip_new)

    for i in range(3):
        count = packet.getfieldval(rcount[i])
        if count > 0:
            resources = packet.getfieldval(rname[i])
            for j in range(count):
                resource = resources[j]
                qtype = resource.getfieldval('type')
                if qtype == 1 or qtype == 28:
                    ip_new = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map'].get(resource.getfieldval('rdata'))
                    if ip_new:
                        resource.setfieldval('rdata', ip_new)
                if qtype == 99:
                    ip_map = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map']
                    tmp_data = ipv4_regex.sub(lambda m: ip_map.get(m.group(), m.group()), resource.getfieldval('rdata'))
                    resource.setfieldval('rdata', ipv6_regex.sub(lambda m: ip_map.get(m.group(), m.group()), tmp_data))
                if qtype == 12:
                    tmp = resource.getfieldval('rrname')
                    if isinstance(tmp, bytes):
                        ip_new = dns_reverlookup_update( tmp.decode('utf-8'), data)
                        if ip_new:
                            resource.setfieldval('rrname', bytes(ip_new,'utf-8'))
                    else:
                        ip_new = dns_reverlookup_update( tmp, data)
                        if ip_new:
                            resource.setfieldval('rrname', ip_new)


###############################################
################## HTTP
###############################################


def httpv1_regex_ip_swap(packet, data):
    """
    Changes ip addresses in HTTPv1 payload using ip_address_map.

    :param packet: scapy_extend.http HTTPv1 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    s = packet.getfieldval('HTTP-payload').decode('utf-8')
    ips = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map']
    s = ipv4_regex.sub(lambda m: ips.get(m.group(), m.group()), s)
    s = ipv6_regex.sub(lambda m: ips.get(m.group(), m.group()), s)
    packet.setfieldval('HTTP-payload', s.encode('utf-8'))


###############################################
################## Helpers
###############################################


def globalRWdict_findMatch(data, field, key):
    """
    Generic question for matching TMdef.GLOBAL dict TMdef.TARGET fields for single key.

    :param data: dict containing TMLib.TMdict dictionaries
    :param field: field within data[TMdef.GLOBAL][TMdef.TARGET]
    :param key: key to be search in dict
    :return: Value stored within key or None if none was found
    """
    return data[TMdef.GLOBAL][TMdef.TARGET][field].get( key )


def get_new_ips(packet, data):
    """
    Stores new and old dts/src IP addresses into data[TMdef.PACKET] under
    keys ip_src_old, ip_dst_old, ip_src_new, ip_src_new.

    :param packet: scapy IPv4/6 packet
    :param data: dict containing TMLib.TMdict dictionaries
    """
    get_ip_src(packet, data)
    get_ip_dst(packet, data)


def get_ip_src(packet, data):
    """
    Stores new IP address after searching IP map into volite entry under 'ip_src_new'. 
    If no entry in map with such ip found then new=old.

    :param packet: IP packet; expects scapy IP packet
    :param data: Dictionary containing field 'tmp' containing dictionary.
    """
    ip_org = packet.getfieldval('src')
    data[TMdef.PACKET]['ip_src_old'] = ip_org
    ip_new = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map'].get(ip_org)
    if ip_new:
        data[TMdef.PACKET]['ip_src_new'] = ip_new
    else:
        data[TMdef.PACKET]['ip_src_new'] = ip_org


def get_ip_dst(packet, data):
    """
    Stores new IP address after searching IP map into volite entry under 'ip_dst_new'. 
    If no entry in map with such ip found then new=old.

    :param packet: IP packet; expects scapy IP packet
    :param data: Dictionary containing field 'tmp' containing dictionary.
    """
    ip_org = packet.getfieldval('dst')
    data[TMdef.PACKET]['ip_dst_old'] = ip_org
    ip_new = data[TMdef.GLOBAL][TMdef.TARGET]['ip_address_map'].get(ip_org)
    if ip_new:
        data[TMdef.PACKET]['ip_dst_new'] = ip_new
    else:
        data[TMdef.PACKET]['ip_dst_new'] = ip_org