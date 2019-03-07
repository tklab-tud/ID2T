import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dns as dns
import scapy.layers.l2 as l2
import scapy.utils

import ID2TLib.Utility as Util

import TMLib.Utility as MUtil
import TMLib.TMdict as TMdict
import TMLib.PacketProcessing as TMpp
import TMLib.TimestampGeneration as TMtg

import TMLib.Definitions as TMdef

import scapy_extend.http as http

import TMLib.ReWrapper as ReWrapper

import TMLib.FillingTMdict as Filler

PROCESSING = 'processing'
PREPROCESSING = 'preprocessing'
POSTPROCESSING = 'postprocessing'
VALIDATION = 'validation'
CONFIG_CHECK = 'configcheck'
ENQUEUE = 'enqueue'
PROTOCOL = 'protocol'
FUNCTION = 'function'
DICTIONARY = 'dictionary'
ALT = 'alt'
KEY = 'key'
FILL = 'load'


"""
Single entry in subsribed_functions represents single tranformation.
Multiple processing, preprocessing & validation functions may be referenced
in single entry (including other entries).

An entry in subsribed_functions must have:
key - unique string name
value - these possible keys
    PROCESSING - contains list of dicionaries with keys PROTOCOL and FUNCTION
                representing protocol and function for rewrapper processing function
    PREPROCESSING - contains list of dictionaries with keys PROTOCOL and FUNCTION
                representing protocol and function for rewrapper preprocessing function
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    ENQUEUE - contains list of entries from subsribed_functions
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
subsribed_functions = { # dictionary of known transformation functions

#################
#### Ether
#################
'mac_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.Ether
        , FUNCTION : TMpp.mac_src_change
        }
    ]
    , FILL : [
        Filler.make_mac_map
    ]
}

, 'mac_dst_change' : {
    PROCESSING : [ 
        {
        PROTOCOL : inet.Ether
        , FUNCTION : TMpp.mac_dst_change
        }
    ]
    , FILL : [
        Filler.make_mac_map
    ]
}

, 'mac_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.Ether
        , FUNCTION : TMpp.mac_change_default
        }
    ]
    , FILL : [
        Filler.make_mac_map
    ]
}

#################
#### ARP
#################

, 'arp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : l2.ARP
        , FUNCTION : TMpp.arp_change_default
        }
    ]
    , FILL : [
        Filler.make_mac_map
        , Filler.make_ip_map
    ]
}

#################
#### IPv4
#################
, 'ip_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_src_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ip_dst_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_dst_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ip_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_change_default
        }
    ]
    , FILL : [
        Filler.make_ip_map
        ,  Filler.make_ttl_ip_exceptions
    ]
}

, 'ip_ttl_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_ttl_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
        ,  Filler.make_ttl_ip_exceptions
    ]
}

#################
#### IPv6
#################
, 'ipv6_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_src_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ipv6_dst_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_dst_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ipv6_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_change_default
        }
    ]
    , FILL : [
        Filler.make_ip_map
        ,  Filler.make_ttl_ip_exceptions
    ]
}

, 'ipv6_hlim_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_hlim_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
        ,  Filler.make_ttl_ip_exceptions
    ]
}

#################
#### ICMPv4
#################
, 'icmp_ip_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IPerror
        , FUNCTION : TMpp.ip_change_default
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'icmp_tcp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.TCPerror
        , FUNCTION : TMpp.tcp_change_default
        }
    ]
    , PREPROCESSING : [
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'icmp_udp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.UDPerror
        , FUNCTION : TMpp.udp_change_default
        }
    ]
    , PREPROCESSING : [
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

#################
#### TCP
#################
, 'tcp_win_size_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.TCP
        , FUNCTION : TMpp.tcp_win_size_change
        }
    ]
    , PREPROCESSING : [ 
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
        , Filler.make_win_ip_exceptions
        , Filler.make_port_ip_map
    ]
}
, 'tcp_mss_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.TCP
        , FUNCTION : TMpp.tcp_mss_change
        }
    ]
    , PREPROCESSING : [ 
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
        , Filler.make_mss_ip_exceptions
        , Filler.make_port_ip_map
    ]
}
, 'tcp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.TCP
        , FUNCTION : TMpp.tcp_change_default
        }
    ]
    , PREPROCESSING : [ 
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
        , Filler.make_mss_ip_exceptions
        , Filler.make_win_ip_exceptions
        , Filler.make_port_ip_map
    ]
}

#################
#### UDP
#################
, 'udp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.UDP
        , FUNCTION : TMpp.udp_change_default
        }
    ]
    , PREPROCESSING : [
        { 
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.get_new_ips
        }
        , {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.get_new_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
        , Filler.make_port_ip_map
    ]
}

#################
#### DNS
#################
, 'dns_change_ips' : {
    PROCESSING : [
        {
        PROTOCOL : dns.DNS
        , FUNCTION : TMpp.dns_change_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

#################
#### HTTPv1
#################
, 'httpv1_regex_ip_swap' : {
    PROCESSING : [
        {
        PROTOCOL : http.HTTPv1 
        , FUNCTION : TMpp.httpv1_regex_ip_swap
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}
}


"""
Single entry in timestamp_function_dict represents single timestamp generation function

An entry in timestamp_function_dict must have:
key - unique string name
value - these possible keys
    FUNCTION - contains timestamp generator function 
    ALT - contains backup/alternative timestamp generation function. 
        If value is string, timestamp_alt_function_dict will be searched.
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
timestamp_function_dict = { # dictionary of known timestamp generation functions
'default' : {
    FUNCTION : TMtg.timestamp_dynamic_shift
}
, 'timestamp_shift' : {
    FUNCTION : TMtg.timestamp_static_shift
}
, 'tcp_avg_shift' : {
    FUNCTION : TMtg.timestamp_tcp_avg_shift
    , ALT : TMtg.timestamp_dynamic_shift
    , FILL : [
        Filler.make_attack_tcp_avg_delay_map
        , Filler.make_target_tcp_avg_delay_map
    ]
}
, 'timestamp_dynamic_shift' : {
    FUNCTION : TMtg.timestamp_dynamic_shift
}
}


"""
Single entry in timestamp_postprocess_dict represents single timestamp postprocess function

An entry in timestamp_postprocess_dict must have:
key - unique string name
value - these possible keys
    FUNCTION - contains timestamp generator function
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper 
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
timestamp_postprocess_dict = {
'timestamp_delay' : {
    FUNCTION : TMtg.timestamp_delay
}
, 'timestamp_delay_forIPlist' : {
    FUNCTION : TMtg.timestamp_delay_forIPlist
}
, 'timestamp_delay_forIPconst' : {
    FUNCTION : TMtg.timestamp_delay_forIPconst
}
, 'timestamp_random_oscillation' : {
    FUNCTION : TMtg.timestamp_random_oscillation
}
}


"""
Single entry in timestamp_alt_function_dict represents single timestamp backup/alt function

An entry in timestamp_alt_function_dict must have:
key - unique string name
value - these possible keys
    FUNCTION - contains timestamp generator function 
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
timestamp_alt_function_dict = { # dictionary of known timestamp generation functions
'default' : {
    FUNCTION : TMtg.timestamp_dynamic_shift
}
, 'timestamp_shift' :{
    FUNCTION :  TMtg.timestamp_static_shift
}
, 'timestamp_dynamic_shift' : {
    FUNCTION : TMtg.timestamp_dynamic_shift
}
}

"""
Single entry in timestamp_generation_mode represents single timestamp tranformation

An entry in timestamp_generation_mode must have:
key - unique string name
value - these possible keys
    PROCESSING - constains single timestamp generation function
    ALT - contains backup/alternative timestamp generation function
    POSTPROCESSING - contains list of postprocessing functions
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
If any of the values, except for key VALIDATION, is string, a coresponding dictionary will be searched.
"""
timestamp_generation_mode = {
    
}


def enqueue_function(rewrapper, name):
    """
    Enqueue transformation (for specific protocol, based on function). 
    Searches for known functions based on name match.
    During rewrapping, functions are executed in enqueue order.

    :param rewrapper: ReWrapper object
    :param name: name of the tranformation, string

    :return: set of functions that fill dictionaries based on parsed config
    """
    fill = set()
    config_validation = set()

    record = subsribed_functions.get(name)
    if record:
        processing = record.get(PROCESSING)
        if processing:
            for entry in processing:
                rewrapper.enqueue_processing_function(entry[PROTOCOL], entry[FUNCTION])
        
        preprocessing = record.get(PREPROCESSING)
        if preprocessing:
            for entry in preprocessing:
                rewrapper.enqueue_preprocessing_function(entry[PROTOCOL], entry[FUNCTION])

        postprocessing = record.get(POSTPROCESSING)
        if postprocessing:
            for entry in postprocessing:
                rewrapper.enqueue_postprocessing_function(entry[PROTOCOL], entry[FUNCTION])

        validation = record.get(VALIDATION)
        if validation:
            data_dict = rewrapper.data_dict
            for entry in preprocessing:
                tmdict = data_dict.get(entry[DICTIONARY])
                if tmdict:
                    tmdict.add_validation_function(entry[FUNCTION])

        enqueue = record.get(ENQUEUE)
        if enqueue:
            for entry in enqueue:
                res = enqueue_function(rewrapper, entry)
                if res:
                    fill.update(res[0])
                    config_validation.update(res[1])

        cfg_validators = record.get(CONFIG_CHECK)
        if cfg_validators:
            config_validation.update(cfg_validators)

        fillers = record.get(FILL)
        if fillers:
            fill.update(fillers)

    return fill, config_validation


def change_timestamp_function(rewrapper, name):
    """
    If name is in timestamp_function_dict, sets the timestamp generator.
    Sets alt generator if it is defined. 

    Adds validation functions if they are defined. 

    :param rewrapper: ReWrapper object
    :param name: name of the function, string

    :return: set of functions that fill dictionaries based on parsed config
    """
    fill = set()
    config_validation = set()

    record = timestamp_function_dict.get(name)
    if record :
        rewrapper.set_timestamp_generator(record[FUNCTION])

        alt = record.get(ALT)
        if alt:
            if isinstance(alt, str):
                fill.update(enlist_alt_timestamp_generation_function(rewrapper, alt))
            else:
                rewrapper.set_backup_timestamp_generator(alt)

        validation = record.get(VALIDATION)
        if validation:
            data_dict = rewrapper.data_dict
            for entry in preprocessing:
                tmdict = data_dict.get(entry[DICTIONARY])
                if tmdict:
                    tmdict.add_validation_function(entry[FUNCTION])

        cfg_validators = record.get(CONFIG_CHECK)
        if cfg_validators:
            config_validation.update(cfg_validators)

        fillers = record.get(FILL)
        if fillers:
            fill.update(fillers)

    return fill, config_validation


def enqueue_timestamp_postprocess(rewrapper, name):
    """
    If name is in timestamp_postprocess_dict, enqueues the timestamp postprocessing function.

    Adds validation functions if they are defined. 

    :param rewrapper: ReWrapper object
    :param name: name of the function, string

    :return: set of functions that fill dictionaries based on parsed config
    """
    fill = set()
    config_validation = set()

    record = timestamp_postprocess_dict.get(name)
    if record :
        rewrapper.enqueue_timestamp_postprocess(record[FUNCTION])

        validation = record.get(VALIDATION)
        if validation:
            data_dict = rewrapper.data_dict
            for entry in preprocessing:
                tmdict = data_dict.get(entry[DICTIONARY])
                if tmdict:
                    tmdict.add_validation_function(entry[FUNCTION])

        cfg_validators = record.get(CONFIG_CHECK)
        if cfg_validators:
            config_validation.update(cfg_validators)

        fillers = record.get(FILL)
        if fillers:
            fill.update(fillers)


    return fill, config_validation


def enlist_alt_timestamp_generation_function(rewrapper, name):
    """
    If name is in timestamp_alt_function_dict, sets the alternative timestamp generator.

    Adds validation functions if they are defined. 

    :param rewrapper: ReWrapper object
    :param name: name of the function, string

    :return: set of functions that fill dictionaries based on parsed config
    """
    fill = set()
    config_validation = set()

    record = timestamp_alt_function_dict.get(name)
    if record :
        rewrapper.set_backup_timestamp_generator(record[FUNCTION])

        validation = record.get(VALIDATION)
        if validation:
            data_dict = rewrapper.data_dict
            for entry in preprocessing:
                tmdict = data_dict.get(entry[DICTIONARY])
                if tmdict:
                    tmdict.add_validation_function(entry[FUNCTION])

        cfg_validators = record.get(CONFIG_CHECK)
        if cfg_validators:
            config_validation.update(cfg_validators)

        fillers = record.get(FILL)
        if fillers:
            fill.update(fillers)

    return fill, config_validation


def apply_timestamp_generation_mode(rewrapper, name):
    """
    If name is in timestamp_generation_mode, sets all timestamp generation, alterantive and postprocess functions.
    Multiple calls of this function on same object will cause some of the entries to be overwritten, while
    others may enqueued. 

    Adds validation functions if they are defined. 

    :param rewrapper: ReWrapper object
    :param name: name of the mode, string

    :return: set of functions that fill dictionaries based on parsed config
    """
    fill = set()
    config_validation = set()

    record = timestamp_generation_mode.get(name)
    if record :
        process = record[FUNCTION]
        if isinstance(process, str):
            fill.update(change_timestamp_function(rewrapper, process))
        else:
            rewrapper.set_timestamp_generator(process)

        alt = record.get(ALT)
        if alt:
            if isinstance(alt, str):
                fill.update(enlist_alt_timestamp_generation_function(rewrapper, alt))
            else:
                rewrapper.set_backup_timestamp_generator(alt)

        postprocess = record.get(FUNCTION)
        for entry in postprocess:
            if isinstance(entry, str):
                fill.update(enqueue_timestamp_postprocess(rewrapper, entry))
            else:
                rewrapper.enqueue_timestamp_postprocess(entry)

        validation = record.get(VALIDATION)
        if validation:
            data_dict = rewrapper.data_dict
            for entry in preprocessing:
                tmdict = data_dict.get(entry[DICTIONARY])
                if tmdict:
                    tmdict.add_validation_function(entry[FUNCTION])

        fillers = record.get(FILL)
        if fillers:
            fill.update(fillers)

        cfg_validators = record.get(CONFIG_CHECK)
        if cfg_validators:
            config_validation.update(cfg_validators)
    return fill, config_validation
