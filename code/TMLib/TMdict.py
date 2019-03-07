import lea

import ID2TLib.Utility as Util
import TMLib.Utility as MUtil

import TMLib.Definitions as TMdef

class GlobalRWdict(dict):
    """
    Extension of dictionary for storing GLOBAL data for rewrapping.
    Data stored in this dictionary should be sharable and usable by multipple instances of rewrapper.
    Data in this dictionary should not be changed during rewrapping, and only added to because of efficency.

    Some of the predefined fields in the dictioanry are:
    'statistics' - Core.Statistics.Statistics object containing statistics of target pcap file
    'attack_statistics' - Core.Statistics.Statistics object containing statistics of inserted attack pcap file

    Predefined keys...
    TMdef.ATTACK - contains data refering to attack, such as timestamp shift
    TMdef.TARGET - contains data refering to target pcap, such as ip maps, etc.
    ... contain sections sections.

    Predefined fields for
    > TMdef.ATTACK :
    timestamp_shift - shift in timestamps based on input starting timestamp and starting timestamp of attack pcap
    tcp_avg_delay_map - map of form ip_from -> ip_to -> tcp_avg delay, of average delays based on tcp handshake between to IPs

    > TMdef.TARGET :
    mac_address_map - map of mac adresses in attack pcap to be transformed to new mac addresses
    ip_address_map - map of ip addresses in attack pcap to be transformed to new ip addresses
    ip_ttl_map - map of new time to live values for ip addresses in attack pcap
    ip_ttl_default - default new time to live value based on target pcap
    pps_record_map - packet per second map for ip, to be used for timestamp generation
    win_size_map - map of new tcp window size values for attack pcap ip addresses 
    win_size_default - default new window size value based on target pcap
    mss_map - map of new maximum segment size values for attack pcap ip addresses
    mss_default - default maximum segment size value based on target pcap
    port_map_forIP - map of new tcp port assignaments for ip in attack pcap in form of ip -> port_old -> port_new
    mss_exceptions - set of IP addresses whose maximum segment size should not be changed
    win_size_exceptions - set of IP addresses whose window size should not be changed
    ttl_exceptions - set of IP addresses whose time to live should not be changed
    tcp_avg_delay_map - map of form ip_from -> ip_to -> tcp_avg delay, of average delays based on tcp handshake between to IPs
    """

    def __init__(self, *args,**kwargs):
        """
        Can be initialized using the same format as a dictionary (dict). 
        Must contain field statistics and attack_statistics.
        field statistics - statistics of a target (reference), Core.Statistics.Statistics object
        field attack_statistics - statistics of the inserted attack, Core.Statistics.Statistics object
        """
        dict.__init__(self,*args,**kwargs)

        self.statistics = kwargs['statistics']
        self.attack_statistics = kwargs['attack_statistics']

        ## Some of the regularily used fields are hardcoded
        self.update({ # data used for rewrapping of layers
        TMdef.ATTACK : {
            'timestamp_shift' : 0 # used by timestamp_shift
            , 'tcp_avg_delay_map' : {}
            , 'timestamp_delay_map' : {}
            , 'timestamp_delay_set' : set()
        }
        , TMdef.TARGET : {
            'mac_address_map' : {}
            , 'ip_address_map' : {}

            , 'ip_ttl_map' : {}
           , 'ip_ttl_default' : Util.handle_most_used_outputs(self.statistics.get_most_used_ttl_value())

            , 'pps_record_map' : {}

            , 'win_size_map' : {}
           , 'win_size_default' : Util.handle_most_used_outputs(self.statistics.get_most_used_win_size())

            , 'mss_map' : {}
           , 'mss_default' : Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())

            , 'port_map_forIP' : {}

            , 'mss_exceptions' : set()
            , 'win_size_exceptions' : set()
            , 'ttl_exceptions' : set()

            , 'tcp_avg_delay_map' : {}
        }
        })

        ## stores functions meant to validate that the required fields exist
        self.validation_functions = []


    ##################################
    ###### Adding 
    ##################################

    def set_timestamp_shift(self, timestamp_shift):
        """
        Sets timestamp shift (negative or positive value depending on direction of the shift).

        :param timestamp_shift: Timestamp shift.
        """
        self[TMdef.ATTACK]['timestamp_shift'] = timestamp_shift


    def to_mss_exceptions(self, ip_from):
        """
        Adds the IP address to Maximum Segment Size Exceptions. MSS value for packets from this IP will not be changed.

        :param ip_from: attack pcap IP address to be added to exceptions, string.
        """
        if ip_from not in self[TMdef.TARGET]['mss_exceptions']:
            self[TMdef.TARGET]['mss_exceptions'].add(ip_from)


    def to_win_size_exceptions(self, ip_from):
        """
        Adds the IP address to Window Size exceptions. Win Size value for the packets from this IP will not be changed.

        :param ip_from: attack pcap IP address to be added to exceptions, string.
        """
        if ip_from not in self[TMdef.TARGET]['win_size_exceptions']:
            self[TMdef.TARGET]['win_size_exceptions'].add(ip_from)


    def to_ttl_exceptions(self, ip_from):
        """
        Adds the IP address to Time To Live exceptions. TTL value for packets from this IP will not be changed.
        
        :param ip_from: attack pcap IP address to be added to exceptions, string.
        """
        if ip_from not in self[TMdef.TARGET]['ttl_exceptions']:
            self[TMdef.TARGET]['ttl_exceptions'].add(ip_from)


    def to_ip_map(self, ip_from, ip_to):
        """
        Add new ip address pair into ip_map. IP_from will be transformed to IP_to during rewrapping

        :param ip_from: old ip address, string
        :param ip_to: new ip address, string
        """
        self[TMdef.TARGET]['ip_address_map'][ip_from] = ip_to


    def to_mac_map(self, mac_from, mac_to):
        """
        Add new mac address pair into mac_map. mac_from will be transformed to mac_to during rewrapping

        :param mac_from: old mac address, string
        :param mac_to: new mac address, string
        """
        self[TMdef.TARGET]['mac_address_map'][mac_from] = mac_to


    def port_map_forIP(self, ip, port_from, port_to):
        """
        Adds new entry to the port map for IP address. Specified port on a given IP address will be mapped to the target port.
        New port assignament must be unique for old port can only be mapped to one value for give IP.

        :param ip: attack pcap IP address, string 
        :param port_from: original port, int or string
        :param port_to: new port value, int or string
        """
        portmap = self[TMdef.TARGET]['port_map_forIP']
        if ip not in portmap:
            portmap[ip] = {}
        portmap[int(port_from)] = int(port_to) 


    def add_tcp_avg_delay_record(self, source, ip_from, ip_to, avg_delay):
        """
        Manually adds ip address conversation and avg_delay into tcp_avg_delay map.
        This overwrites existing entries.

        :param self: dict containing TMLib.TMdict dictionaries
        :param source: TMdef.ATTACK or TMdef.TARGET 
        :param ip_from: source ip, string
        :param ip_to: destination_ip, string
        :param avg_delay: average delay of TCP handshake, float or string
        """
        delay_dict = self[source].get('tcp_avg_delay_map')
        if not delay_dict:
            delay_dict = {}
            self[source]['tcp_avg_delay_map'] = delay_dict

        ip_dict = delay_dict.get(ip_from)
        if not ip_dict:
            ip_dict = {}
            delay_dict[ip_from] = ip_dict
        ip_dict[ip_to] = float(avg_delay)

        ip_dict = delay_dict.get(ip_to)
        if not ip_dict:
            ip_dict = {}
            delay_dict[ip_to] = ip_dict
        ip_dict[ip_from] = float(avg_delay)


    def to_timestamp_random_delay_threshold_map(self, ip, threshold):
        """
        Adds pair of ip address and threshold to the map of timestamp delays under key timestamp_delay_map.

        :param ip: ip address, string
        :param threshold: threshold, float or string
        """
        self[TMdef.ATTACK]['timestamp_delay_map'][ip] = float(threshold)


    def to_timestamp_random_delay_set(self, ip):
        """
        Adds ip address to random delay set.

        :param ip: ip address, string
        """
        if ip not in self[TMdef.ATTACK]['timestamp_delay_set']:
            self[TMdef.ATTACK]['timestamp_delay_set'].add(ip)



    ##################################
    ###### Recalculate 
    ##################################


    def recalculate_ttl(self):
        """
        Recalculates time to live for ip packets based on IP addresses (new) from ip adress map.
        IP address in statistics recieve ttl value based on distribution of ttl values for that address.
        IP addresses not in statistics recieve most used ttl value.
        """
        ip_dict = self[TMdef.TARGET]['ip_address_map']
        ttl_dict = self[TMdef.TARGET]['ip_ttl_map']
        for ip_old, ip_new in ip_dict.items():
            if ip_old not in self[TMdef.TARGET]['ttl_exceptions']:
                ttl_dist = self.statistics.get_ttl_distribution(ip_new)
                if len(ttl_dist) > 0:
                    ttl_prob_dict = lea.Lea.fromValFreqsDict(ttl_dist)
                    ttl_dict[ip_old] = ttl_prob_dict.random()
                else:
                    ttl_dict[ip_old] = Util.handle_most_used_outputs(self.statistics.get_most_used_ttl_value())


    def recalculate_win_size(self):
        """
        Recalculates windows size for ip packets based on IP addresses (new) from ip adress map.
        IP address in statistics recieve win size value based on distribution of win size values for that address.
        IP addresses not in statistics recieve most used win size value.
        """
        ip_dict = self[TMdef.TARGET]['ip_address_map']
        win_dict = self[TMdef.TARGET]['win_size_map']
        for ip_old, ip_new in ip_dict.items():
            if ip_old not in self[TMdef.TARGET]['ttl_exceptions']:
                win_dist = self.statistics.get_win_distribution(ip_new)
                if len(win_dist) > 0:
                    win_prob_dict = lea.Lea.fromValFreqsDict(win_dist)
                    win_dict[ip_old] = win_prob_dict.random()
                else:
                    win_dict[ip_old] = Util.handle_most_used_outputs(self.statistics.get_most_used_win_size())

    def recalculate_mss(self):
        """
        Recalculates maximum segment size for ip packets based on IP addresses (new) from ip adress map.
        IP address in statistics recieve mss value based on distribution of mss values for that address.
        IP addresses not in statistics recieve most used mss value.
        """
        ip_dict = self[TMdef.TARGET]['ip_address_map']
        mss_dict = self[TMdef.TARGET]['mss_map']
        for ip_old, ip_new in ip_dict.items():
            if ip_old not in self[TMdef.TARGET]['ttl_exceptions']:
                mss_dist = self.statistics.get_mss_distribution(ip_new)
                if len(mss_dist) > 0:
                    mss_prob_dict = lea.Lea.fromValFreqsDict(mss_dist)
                    mss_dict[ip_old] = mss_prob_dict.random()
                else:
                    mss_dict[ip_old] = Util.handle_most_used_outputs(self.statistics.get_most_used_mss_value())


    def recalculate(self):
        """
        Executes all recalcuate functions
        """

        self.recalculate_ttl()
        self.recalculate_win_size()
        self.recalculate_mss()


    ##################################
    ###### Validation 
    ##################################


    def add_validation_function(self, function):
        """
        Adds functions that validates specified fields in the dictionary.
        Such function takes GlobalRWdict as a parameter. Returns True if fields are valid, else false.
        All validation functions are executed by method validate().

        :param function: Validation function that takes GlobalRWdict as param and returns True if data is valid, else False
        """
        if function not in self.validation_functions:
            self.validation_functions.append(function)


    def validate(self):
        """
        Executes all validation functions. Returns True if all functions passed, else False.

        :return: True if all validation functions passed, else false.
        """
        check = True
        for function in self.validation_functions:
            check &= function(self)
        return check


class PacketDataRWdict(dict):
    """
    Extends dictionary for storing data for individual packets.
    All data stored in this dictionary is expected to be cleared after processing each packet (or replaced).
    Its intended for use by a single rewrapper.
    """

    def __init__(self, *args,**kwargs):
        """
        Can be initialized same as dictionary.
        """
        dict.__init__(self,*args,**kwargs)
        ## stores functions meant to validate that the required fields exist
        self.validation_functions = []


    ##################################
    ###### Validation 
    ##################################


    def add_validation_function(self, function):
        """
        Adds functions that validates specified fields in the dictionary.
        Such function takes PacketDataRWdict as a parameter. Returns True if fields are valid, else false.
        All validation functions are executed by method validate().

        :param function: Validation function that takes PacketDataRWdict as param and returns True if data is valid, else False
        """
        if function not in self.validation_functions:
            self.validation_functions.append(function)


    def validate(self):
        """
        Executes all validation functions. Returns True if all functions passed, else False.

        :return: True if all validation functions passed, else false.
        """
        check = True
        for function in self.validation_functions:
            check &= function(self)
        return check


class ConversationRWdict(dict):
    """
    Extends dictionary for storing data about conversations
    Data stored in this dictionary is intended for keeping track of conversations. This dictionary is
    expected to be shared by rewrappers and updated per packet (example - data about timestamps).

    Predefined keys:
    timestamp_next_pkt - timestamp of next packet used for packet per second (unused) 
    """

    def __init__(self, *args,**kwargs):
        """
        Can be initialized same as a dictionary.
        """
        dict.__init__(self,*args,**kwargs)
        self.update = {
        'timestamp_next_pkt' : 0
        }
        ## stores functions meant to validate that the required fields exist
        self.validation_functions = []


    ##################################
    ###### Validation 
    ##################################


    def add_validation_function(self, function):
        """
        Adds functions that validates specified fields in the dictionary.
        Such function takes PacketDataRWdict as a parameter and verbose flag (if True, print output).
        Returns True if fields are valid, else false.
        All validation functions are executed by method validate().

        :param function: Validation function that takes PacketDataRWdict as param and returns True if data is valid, else False
        """
        if function not in self.validation_functions:
            self.validation_functions.append(function)


    def validate(self, verbose=False):
        """
        Executes all validation functions. Returns True if all functions passed, else False.

        :return: True if all validation functions passed, else false.
        """
        check = True
        for function in self.validation_functions:
            check &= function(self, verbose)
        return check

