import TMLib.TMdict as TMdict
import TMLib.TMdef as TMdef

import numbers


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

mac_regex = re.compile(r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})')

###########################################
############### Ether
###########################################


def validate_ip_map(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['mac_address_map']
    map of mac to mac

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False

    data = data.get('mac_address_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key mac_address_map')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not mac_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not mac address.')
            return False
        if not isinstance(value, str):
            if verbose:
                print('[VALIDATION FAILED]', type(value), 'is not str.')
            return False
        if not mac_regex.fullmatch(value):
            if verbose:
                print('[VALIDATION FAILED]', value, 'is not mac address.')
            return False
    return True


###########################################
############### IP
###########################################

def validate_ip_map(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['ip_address_map']
    map of ip to ip

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False

    data = data.get('ip_address_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key ip_address_map')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(key) and not ipv6_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not ip address.')
            return False
        if not isinstance(value, str):
            if verbose:
                print('[VALIDATION FAILED]', type(value), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(value) and not ipv6_regex.fullmatch(value):
            if verbose:
                print('[VALIDATION FAILED]', value, 'is not ip address.')
            return False
    return True


def validate_ip_ttl_map(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['ip_ttl_default']
    data[TMdef.TARGET]['ip_ttl_exceptions']
    data[TMdef.TARGET]['ip_ttl_map']
    map of ip to ttl value

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False
    
    exceptions = data.get('ttl_exceptions')
    if not exceptions:
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is missing key ttl_exceptions.')
        return False
    if not isinstance(exceptions, set):
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is not set.')
        return False

    default = data.get('ip_ttl_default')
    if not default:
        if verbose:
            print('[VALIDATION FAILED]', type(default), 'is missing key ip_ttl_default.')
        return False
    if not isinstance(default, numbers.Integral):
        if verbose:
            print('[VALIDATION FAILED]', default, 'is not whole Integral.')
        return False
    if default < 0:
        if verbose:
            print('[VALIDATION FAILED]', default, 'is negative Integral.')
        return False

    data = data.get('ip_ttl_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key ip_ttl_map.')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(key) and not ipv6_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not ip address.')
            return False
        if not isinstance(value, numbers.Integral):
            if verbose:
                print('[VALIDATION FAILED]', data, 'is not whole Integral.')
            return False
        if value < 0:
            if verbose:
                print('[VALIDATION FAILED]', data, 'is negative Integral.')
            return False
    return True


###########################################
############### TCP
###########################################


def validate_tcp_win_size_map(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['win_size_default']
    data[TMdef.TARGET]['win_size_exceptions']
    data[TMdef.TARGET]['win_size_map']
    map of ip to win size value

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False
    
    exceptions = data.get('win_size_exceptions')
    if not exceptions:
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is missing key win_size_exceptions.')
        return False
    if not isinstance(exceptions, set):
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is not set.')
        return False

    default = data.get('win_size_default')
    if not default:
        if verbose:
            print('[VALIDATION FAILED]', type(default), 'is missing key win_size_default.')
        return False
    if not isinstance(default, numbers.Integral):
        if verbose:
            print('[VALIDATION FAILED]', default, 'is not whole Integral.')
        return False
    if default < 0:
        if verbose:
            print('[VALIDATION FAILED]', default, 'is negative Integral.')
        return False


    data = data.get('win_size_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key win_size_map.')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(key) and not ipv6_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not ip address.')
            return False
        if not isinstance(value, numbers.Integral):
            if verbose:
                print('[VALIDATION FAILED]', data, 'is not whole Integral.')
            return False
        if value < 0:
            if verbose:
                print('[VALIDATION FAILED]', data, 'is negative Integral.')
            return False
    return True


def validate_tcp_mss_map(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['mss_default']
    data[TMdef.TARGET]['mss_exceptions']
    data[TMdef.TARGET]['mss_map']
    map of ip to mss value

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False
    
    exceptions = data.get('mss_exceptions')
    if not exceptions:
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is missing key mss_exceptions.')
        return False
    if not isinstance(exceptions, set):
        if verbose:
            print('[VALIDATION FAILED]', type(exceptions), 'is not set.')
        return False

    default = data.get('mss_default')
    if not default:
        if verbose:
            print('[VALIDATION FAILED]', type(default), 'is missing key mss_default.')
        return False
    if not isinstance(default, numbers.Integral):
        if verbose:
            print('[VALIDATION FAILED]', default, 'is not whole Integral.')
        return False
    if default < 0:
        if verbose:
            print('[VALIDATION FAILED]', default, 'is negative Integral.')
        return False


    data = data.get('mss_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key mss_map.')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(key) and not ipv6_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not ip address.')
            return False
        if not isinstance(value, numbers.Integral):
            if verbose:
                print('[VALIDATION FAILED]', data, 'is not whole Integral.')
            return False
        if value < 0:
            if verbose:
                print('[VALIDATION FAILED]', data, 'is negative Integral.')
            return False
    return True


def validate_port_map_for_ip(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['port_map_forIP']
    map of ip to port from to port to value

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(TMdef.TARGET)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', TMdef.TARGET, '.')
        return False

    data = data.get('port_map_forIP')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key port_map_forIP.')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for key, value in data.items():
        if not key:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(key, str):
            if verbose:
                print('[VALIDATION FAILED]', type(key), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(key) and not ipv6_regex.fullmatch(key):
            if verbose:
                print('[VALIDATION FAILED]', key, 'is not ip address.')
            return False
        if not isinstance(value, dict):
            if verbose:
                print('[VALIDATION FAILED]', type(data), 'is not dict.')
            return False
        for port_from, port_to in value.items():
            if not port_from:
                if verbose:
                    print('[VALIDATION FAILED] NoneType key.')
                return False
            if not port_to:
                if verbose:
                    print('[VALIDATION FAILED] NoneType value.')
                return False
            if not isinstance(port_from, numbers.Integral):
                if verbose:
                    print('[VALIDATION FAILED]', port_from, 'is not whole Integral.')
                return False
            if port_from < 0 or 65535 < port_from:
                if verbose:
                    print('[VALIDATION FAILED]', port_from, 'is outside port number range.')
                return False
            if not isinstance(port_to, numbers.Integral):
                if verbose:
                    print('[VALIDATION FAILED]', port_to, 'is not whole Integral.')
                return False
            if port_to < 0 or 65535 < port_to:
                if verbose:
                    print('[VALIDATION FAILED]', port_to, 'is outside port number range.')
                return False
    return True


##################################
###### Timestamps 
##################################


def tcp_avg_delay_attack(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.ATTACK]
    data[TMdef.ATTACK]['tcp_avg_delay_map']
    map of ip to ip to delay

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    return tcp_avg_delay_univerzal(data, TMdef.ATTACK, verbose)


def tcp_avg_delay_target(data, verbose=False):
    """
    Tests if dictionary contains

    data[TMdef.TARGET]
    data[TMdef.TARGET]['tcp_avg_delay_map']
    map of ip to ip to delay

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    return tcp_avg_delay_univerzal(data, TMdef.TARGET, verbose)


def tcp_avg_delay_univerzal(data, _name, verbose=False):
    """
    Tests if dictionary contains

    data[_name]
    data[_name]['tcp_avg_delay_map']
    map of ip to ip to delay

    :param data: data dict
    :param verbose: True if print output, else False

    :return: True if valid, else False
    """
    data = data.get(_name)
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key', _name, '.')
        return False

    data = data.get('tcp_avg_delay_map')
    if not data:
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is missing key tcp_avg_delay_map.')
        return False
    if not isinstance(data, dict):
        if verbose:
            print('[VALIDATION FAILED]', type(data), 'is not dict.')
        return False
    for ip_from, value in data.items():
        if not ip_from:
            if verbose:
                print('[VALIDATION FAILED] NoneType key.')
            return False
        if not value:
            if verbose:
                print('[VALIDATION FAILED] NoneType value.')
            return False
        if not isinstance(ip_from, str):
            if verbose:
                print('[VALIDATION FAILED]', type(ip_from), 'is not str.')
            return False
        if not ipv4_regex.fullmatch(ip_from) and not ipv6_regex.fullmatch(ip_from):
            if verbose:
                print('[VALIDATION FAILED]', ip_from, 'is not ip address.')
            return False
        if not isinstance(value, dict):
            if verbose:
                print('[VALIDATION FAILED]', type(data), 'is not dict.')
            return False
        for ip_to, delay in value.items():
            if not ip_to:
                if verbose:
                    print('[VALIDATION FAILED] NoneType key.')
                return False
            if not delay:
                if verbose:
                    print('[VALIDATION FAILED] NoneType key.')
                return False
            if not isinstance(ip_from, str):
                if verbose:
                    print('[VALIDATION FAILED]', type(ip_from), 'is not str.')
                return False
            if not ipv4_regex.fullmatch(ip_to) and not ipv6_regex.fullmatch(ip_to):
                if verbose:
                    print('[VALIDATION FAILED]', ip_to, 'is not ip address.')
                return False
            if not isinstance(delay, numbers.Real):
                if verbose:
                    print('[VALIDATION FAILED]', delay, 'is not whole Integral.')
                return False
            if delay < 0:
                if verbose:
                    print('[VALIDATION FAILED]', delay, 'is negative delay.')
                return False
    return True