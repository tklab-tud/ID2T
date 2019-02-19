import ID2TLib.Utility as Util

import TMLib.Definitions as TMdef 

import TMLib.ReWrapper as ReWrapper

import numbers

def make_attack_tcp_avg_delay_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    data = data.get(TMdef.GLOBAL)
    if data:
        make_tcp_avg_delay_map(data.attack_statistics, data, TMdef.ATTACK)
    

def make_target_tcp_avg_delay_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    data = data.get(TMdef.GLOBAL)
    if data:
        make_tcp_avg_delay_map(data.statistics, data, TMdef.TARGET)


def make_tcp_delay_map_forLabel(statistics, data, source, label):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: TMLib.TMdict.GlobalRWdict dictionary
    :param source: TMdef.ATTACK or TMdef.Target
    """
    LABELS = {
        'avg' : 'tcp_avg_delay_map'
        , 'min' : 'tcp_min_delay_map'
        , 'max' : 'tcp_max_delay_map'
    }

    field = LABELS.get(label)
    if not field:
        return

    conversations = statistics.process_db_query('SELECT ipAddressA, ipAddressB, avgDelay FROM conv_statistics')

    delay_dict = data[source].get(field)
    if not delay_dict:
        delay_dict = {}
        data[TMdef.GLOBAL][source][field] = delay_dict

    for conversation in conversations:
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


def make_tcp_avg_delay_map(statistics, data, source):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: TMLib.TMdict.GlobalRWdict dictionary
    :param source: TMdef.ATTACK or TMdef.Target
    """
    make_tcp_delay_map_forLabel('avg')


def make_tcp_min_delay_map(statistics, data, source):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: TMLib.TMdict.GlobalRWdict dictionary
    :param source: TMdef.ATTACK or TMdef.Target
    """
    make_tcp_delay_map_forLabel('min')


def make_tcp_max_delay_map(statistics, data, source):
    """
    Fills TMdef.GLOBAL dictionary map of tcp handshake average delays (tcp_avg_delay_map)
    based on provided statistics for each existing conversation in statistics.

    :param statistics: Core.Statistics.Statistics object containing pcap statistics
    :param data: TMLib.TMdict.GlobalRWdict dictionary
    :param source: TMdef.ATTACK or TMdef.Target
    """
    make_tcp_delay_map_forLabel('max')


def make_mac_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of mac adresses using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if global_dict and isinstance(global_dict, dict):
        mac_map = param_dict.get('mac.map')
        if mac_map and isinstance(mac_map, list):
            for entry in mac_map:
                entry = entry.get('mac')
                if entry and isinstance(entry, dict):
                    old = entry.get('old')
                    new = entry.get('new')
                    if old and new and isinstance(old, str) and isinstance(new, str):
                        global_dict.to_mac_map(old, new)


def make_ip_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of ip adresses using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if global_dict and isinstance(global_dict, dict):
        ip_map = param_dict.get('ip.map')
        if ip_map and isinstance(ip_map, list):
            for entry in ip_map:
                entry = entry.get('ip')
                if entry and isinstance(entry, dict):
                    old = entry.get('old')
                    new = entry.get('new')
                    if old and new and isinstance(old, str) and isinstance(new, str):
                        global_dict.to_ip_map(old, new)


def make_port_ip_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of old to new ports based on ip adress using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    port_ip_map = param_dict.get('port.ip.map')
    if not port_ip_map and not isinstance(port_ip_map, list):
        return
    for entry in port_ip_map:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type or ip_type != 'old':
            continue
        ip_address = ip.get('address')
        if not ip_address or not isinstance(ip, str):
            continue
        port = entry.get('port')
        if not port or not isinstance(port, dict):
            continue
        old = port.get('old')
        new = port.get('new')
        if old and new and isinstance(old, str) and isinstance(new, str):
            global_dict.port_map_forIP(ip_address, old, new)


def make_mss_ip_exceptions(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of maximum segment size based on ip using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    mss_ip_exceptions = param_dict.get('mss.ip.exceptions')
    if not mss_ip_exceptions and isinstance(mss_ip_exceptions, list):
        return
    for entry in mss_ip_exceptions:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type or ip_type != 'old':
            continue
        ip_address = ip.get('address')
        if ip_address and isinstance(ip_address, str):
            global_dict.to_mss_exceptions(ip_address)


def make_win_ip_exceptions(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of win size exceptions based on ip using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    win_ip_exceptions = param_dict.get('win.ip.exceptions')
    if not win_ip_exceptions or not isinstance(win_ip_exceptions, list):
        return
    for entry in win_ip_exceptions:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type or ip_type != 'old':
            continue
        ip_address = ip.get('address')
        if ip_address and isinstance(ip_address, str):
            global_dict.to_win_size_exceptions(ip_address)


def make_ttl_ip_exceptions(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of time to live expetions based on ip using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    ttl_exceptions = param_dict.get('win.ip.exceptions')
    if not ttl_exceptions or not isinstance(ttl_exceptions, list):
        return
    for entry in ttl_exceptions:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type or ip_type != 'old':
            continue
        ip_address = ip.get('address')
        if ip_address and isinstance(ip_address, str):
            global_dict.to_ttl_exceptions(ip_address)


def make_userdef_tcp_delay(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of user defined tcp delays for ip adress communication using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    tcp_delay = param_dict.get('tcp.delay')
    if not tcp_delay or not isinstance(tcp_delay, list):
        return
    for entry in tcp_delay:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type:
            continue
        ip_source = ip.get('source.address')
        ip_dest = ip.get('destination.address')
        if not ip_source or not ip_dest or isinstance(ip_source, str) or isinstance(ip_dest, str):
            continue
        delay = entry.get('delay')
        if not delay and not isinstance(delay, numbers.Real):
            continue
        if ip_type == 'new':
            global_dict.add_tcp_avg_delay_record(TMdef.TARGET, ip_source,
                 ip_dest, delay)
        if ip_type == 'old':
            global_dict.add_tcp_avg_delay_record(TMdef.ATTACK, ip_source,
                 ip_dest, delay)


def make_timestamp_random_treshold_map(data, config):
    """
    Fills TMdef.GLOBAL dictionary map of random tresholds based on ip using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    timestamp_random_tresholds = param_dict.get('timestamp.random.thresholds')
    if not timestamp_random_tresholds or not isinstance(timestamp_random_tresholds, list):
        return
    for entry in timestamp_random_tresholds:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type:
            continue
        ip_address = ip.get('address')
        if not ip_address or isinstance(ip_address, str):
            continue
        threshold = entry.get('threshold')
        if not threshold and not isinstance(threshold, numbers.Real):
            continue
        if ip_type == 'old':
            global_dict.to_timestamp_random_delay_threshold_map(ip_address, threshold)


def make_timestamp_random_treshold_set(data, config):
    """
    Fills TMdef.GLOBAL dictionary set of mac ip adresses for random treshold using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    timestamp_random_tresholds = param_dict.get('timestamp.random.set')
    if not timestamp_random_tresholds or not isinstance(timestamp_random_tresholds, list):
        return
    for entry in timestamp_random_tresholds:
        ip = entry.get('ip')
        if not ip or not isinstance(ip, dict):
            continue
        ip_type = ip.get('type')
        if not ip_type:
            continue
        ip_address = ip.get('address')
        if not ip_address or isinstance(ip_address, str):
            continue
        if ip_type == 'old':
            global_dict.to_timestamp_random_delay_set(ip_address)



def make_random_treshold(data, config):
    """
    Fills TMdef.GLOBAL dictionary random treshold using config.

    :param data: dict containing TMLib.TMdict dictionaries
    :param config: config file parsed as dict
    """
    global_dict = data.get(TMdef.GLOBAL)
    if not global_dict and not isinstance(global_dict, dict):
        return
    dict_ref = param_dict.get('timestamp')
    if dict_ref:
        ## required by random delay/oscilation functions
        threshold = dict_ref.get('random.threshold')
        if threshold:
            rewrap.data_dict[TMdef.GLOBAL]['timestamp_threshold'] = threshold