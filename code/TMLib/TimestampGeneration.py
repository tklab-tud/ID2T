import random

import ID2TLib.Utility as Util

import TMLib.Definitions as TMdef 

###############################################
################## Timestamp avg delay
###############################################

def make_tcp_delay_map(_type ,statistics, data, source):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: dict containing TMLib.TMdict dictionaries
    :param source: TMdef.ATTACK or TMdef.Target
    """
    query = {
    'min' : 'minDelay'
    , 'max' : 'maxDelay'
    , 'avg' : 'avgDelay'
    }.get(_type)

    if not query:
        return 

    conversations = statistics.process_db_query('SELECT ipAddressA, ipAddressB, ' + query + ' FROM conv_statistics')

    delay_dict = data[TMdef.GLOBAL][source].get('tcp_' + _type + '_delay_map')
    if not delay_dict:
        delay_dict = {}
        data[TMdef.GLOBAL][source]['tcp_' + _type + '_delay_map'] = delay_dict

    if conversations:
        for conversation in conversations:
            if len(conversation) != 3:
                continue

            ip_dict = delay_dict.get(conversation[0])
            if not ip_dict:
                ip_dict = {}
                delay_dict[conversation[0]] = ip_dict
            ip_dict[conversation[1]] = conversation[2]
            
            ip_dict = delay_dict.get(conversation[1])
            if not ip_dict:
                ip_dict = {}
                delay_dict[conversation[1]] = ip_dict
            ip_dict[conversation[0]] = conversation[2]


def timestamp_tcp_shift_generic(_type ,packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Generates new timestamp based on average delay in TCP handshake. The delay between packets in attack is
    scaled by ratio target_avg/attack_avg. 
    If no record for the pair of old and new IPS is found, a default function is called from data[TMdef.GLOBAL]
    stored in key generate_timestamp_function_alt.

    Requires data[TMdef.GLOBAL] to have key tcp_avg_delay_map under both TMdef.ATTACK and TMdef.TARGET keys.
    Requires data[TMdef.PACKET] to have ip_src_old, ip_src_new, ip_dst_old, ip_dst_new keys.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    attk_delay = data[TMdef.GLOBAL][TMdef.ATTACK]['tcp_' + _type + '_delay_map'].get(data[TMdef.PACKET]['ip_src_old'])
    source_delay = data[TMdef.GLOBAL][TMdef.TARGET]['tcp_' + _type + '_delay_map'].get(data[TMdef.PACKET]['ip_src_new'])

    if source_delay and attk_delay:
        attk_delay = attk_delay.get(data[TMdef.PACKET]['ip_dst_old'])
        source_delay = source_delay.get(data[TMdef.PACKET]['ip_dst_new'])

    if source_delay and attk_delay:
        delay = curr_timestamp_old - prev_timestamp_old
        return prev_timestamp_new + delay*(source_delay/attk_delay)
    else:
        return data[TMdef.GLOBAL]['generate_timestamp_function_alt'](packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new)



def timestamp_tcp_avg_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Generates new timestamp based on average delay in TCP handshake. The delay between packets in attack is
    scaled by ratio target_avg/attack_avg. 
    If no record for the pair of old and new IPS is found, a default function is called from data[TMdef.GLOBAL]
    stored in key generate_timestamp_function_alt.

    Requires data[TMdef.GLOBAL] to have key tcp_avg_delay_map under both TMdef.ATTACK and TMdef.TARGET keys.
    Requires data[TMdef.PACKET] to have ip_src_old, ip_src_new, ip_dst_old, ip_dst_new keys.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return timestamp_tcp_shift_generic('avg' ,packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new)

def timestamp_tcp_min_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Generates new timestamp based on average delay in TCP handshake. The delay between packets in attack is
    scaled by ratio target_min/attack_min. 
    If no record for the pair of old and new IPS is found, a default function is called from data[TMdef.GLOBAL]
    stored in key generate_timestamp_function_alt.

    Requires data[TMdef.GLOBAL] to have key tcp_avg_delay_map under both TMdef.ATTACK and TMdef.TARGET keys.
    Requires data[TMdef.PACKET] to have ip_src_old, ip_src_new, ip_dst_old, ip_dst_new keys.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return timestamp_tcp_shift_generic('min' ,packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new)


def timestamp_tcp_max_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Generates new timestamp based on average delay in TCP handshake. The delay between packets in attack is
    scaled by ratio target_max/attack_max. 
    If no record for the pair of old and new IPS is found, a default function is called from data[TMdef.GLOBAL]
    stored in key generate_timestamp_function_alt.

    Requires data[TMdef.GLOBAL] to have key tcp_avg_delay_map under both TMdef.ATTACK and TMdef.TARGET keys.
    Requires data[TMdef.PACKET] to have ip_src_old, ip_src_new, ip_dst_old, ip_dst_new keys.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return timestamp_tcp_shift_generic('max' ,packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new)


###############################################
################## Timestamp Packet per Second
###############################################


def timestamp_pps_shift(packet, data): #incomplete
    """
    Unsused, incomplete
    """
    ip_pps_record = data[TMdef.GLOBAL][TMdef.TARGET]['pps_record_map'].get(data[TMdef.PACKET]['ip_src_new'])
    if not ip_pps_record:
        statistics = data[TMdef.GLOBAL]['statistics']
        pps = statistics.get_pps_sent(data[TMdef.PACKET]['ip_src_new'])
        complement_interval_pps = statistics.calculate_complement_packet_rates(pps)
        data[TMdef.GLOBAL][TMdef.TARGET]['pps_record_map'][data[TMdef.PACKET]['ip_src_new']] = {'pps' : pps , 'complement_interval_pps': complement_interval_pps}
    else:
        pps = ip_pps_record['pps']
        complement_interval_pps = ip_pps_record['complement_interval_pps']

    timestamp_this_pkt = data[TMdef.CONVERSATION]['timestamp_next_pkt']

    pps = max(Util.get_interval_pps(complement_interval_pps, timestamp_next_pkt), 10)
    data[TMdef.CONVERSATION]['timestamp_next_pkt'] = Util.update_timestamp(timestamp_next_pkt, pps)

    return timestamp_this_pkt


###############################################
################## Timestamp Static Shift
###############################################


def timestamp_static_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Shift current packet timestamp by specified value. Ignored timestamp changes by postprocessing.
    Data must be a dictionary with field 'timestamp_shift' containing signed float
    Data[TMdef.GLOBAL][TMdef.ATTACK] must contain key timestamp_shift.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return curr_timestamp_old + data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift']


def timestamp_dynamic_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Shift current packet timestamp by specific value. Shifts timestamp in regard to final timestamp of previous
    packet after preprocessing
    Data[TMdef.GLOBAL][TMdef.ATTACK] must contain key timestamp_shift.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return prev_timestamp_new + (curr_timestamp_old - prev_timestamp_old)


###############################################
################## PostProcess
###############################################


def timestamp_delay(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Introduces random delay to the packet between values of curr_timestamp_new and newtimestamp+threshold.
    data[TMdef.GLOBAL] must contain key timestamp_threshold.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    threshold = data[TMdef.GLOBAL]['timestamp_threshold']
    curr_timestamp_new = random.uniform(curr_timestamp_new, curr_timestamp_new + threshold)
    return curr_timestamp_new


def timestamp_delay_forIPlist(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Introduces random delay to the packet between values of curr_timestamp_new and curr_timestamp_new+threshold 
    for ip addresses in timestamp_delay_map using specific threshold for each address.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    ip = data[TMdef.PACKET]['ip_src_old']
    entry = data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_delay_map'].get(ip)
    if entry:
        threshold = entry
        curr_timestamp_new = random.uniform(curr_timestamp_new, curr_timestamp_new + threshold)
    return curr_timestamp_new


def timestamp_delay_forIPconst(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Introduces random delay to the packet between values of curr_timestamp_new and curr_timestamp_new+threshold
    for IP addresses specified in timestamp_delay_set using shared threshold.
    data[TMdef.GLOBAL] must contain key timestamp_threshold

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    ip = data[TMdef.PACKET]['ip_src_old']
    if ip in data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_delay_set']:
        threshold = data[TMdef.GLOBAL]['timestamp_threshold']
        curr_timestamp_new = random.uniform(curr_timestamp_new, curr_timestamp_new + threshold)
    return curr_timestamp_new


def timestamp_random_oscillation(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Introduces random oscillation to the packet timestamps between
    values of curr_timestamp_new-threshold and curr_timestamp_new+threshold.
    data[TMdef.GLOBAL] must contain key timestamp_threshold

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    threshold = data[TMdef.GLOBAL]['timestamp_threshold']
    curr_timestamp_new = random.uniform(curr_timestamp_new - threshold, curr_timestamp_new + threshold)
    return curr_timestamp_new
