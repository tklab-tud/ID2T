import lea
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

recognized_protocols = [
## Ether
inet.Ether
## ARP
, l2.ARP
## IPv4
, inet.IP
## IPv6
, inet6.IPv6
## ICMP
, inet.ICMP
, inet.IPerror
, inet.TCPerror
, inet.UDPerror
, inet.ICMPerror
## TCP
, inet.TCP
## UDP
, inet.UDP
## DNS
, dns.DNS
]

f_dict = { # dictionary of known transformation functions

#################
#### Ether
#################
'mac_src_change' : {'protocol' : inet.Ether
                    , 'function' : TMpp.mac_src_change}
, 'mac_dst_change' : {'protocol' : inet.Ether
                    , 'function' : TMpp.mac_dst_change}
, 'mac_change_default' : {'protocol' : inet.Ether
                    , 'function' : TMpp.mac_change_default}
#################
#### ARP
#################

, 'arp_change_default' : {'protocol' : l2.ARP
                    , 'function' : TMpp.arp_change_default}


#################
#### IPv4
#################
, 'ip_src_change' : {'protocol' : inet.IP
                    , 'function' : TMpp.ip_src_change}
, 'ip_dst_change' : {'protocol' : inet.IP
                    , 'function' : TMpp.ip_dst_change}
, 'ip_change_default' : {'protocol' : inet.IP
                    , 'function' : TMpp.ip_change_default}
, 'ip_ttl_change' : {'protocol' : inet.IP
                    , 'function' : TMpp.ip_ttl_change}

#################
#### IPv6
#################
, 'ipv6_src_change' : {'protocol' : inet6.IPv6
                    , 'function' : TMpp.ipv6_src_change}
, 'ipv6_dst_change' : {'protocol' : inet6.IPv6
                    , 'function' : TMpp.ipv6_dst_change}
, 'ipv6_change_default' : {'protocol' : inet6.IPv6
                    , 'function' : TMpp.ipv6_change_default}
, 'ipv6_hlim_change' : {'protocol' : inet6.IPv6
                    , 'function' : TMpp.ipv6_hlim_change}

#################
#### ICMPv4
#################
, 'icmp_ip_change_default' : {'protocol' : inet.IPerror
                    , 'function' : TMpp.ip_change_default}
, 'icmp_tcp_change_default' : {'protocol' : inet.TCPerror
                    , 'function' : TMpp.tcp_change_default
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }
, 'icmp_udp_change_default' : {'protocol' : inet.UDPerror, 'function' : TMpp.udp_change_default
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }

#################
#### TCP
#################
, 'tcp_win_size_change' : {'protocol' : inet.TCP
                    , 'function' : TMpp.tcp_win_size_change
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }
, 'tcp_mss_change' : {'protocol' : inet.TCP
                    , 'function' : TMpp.tcp_mss_change
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }
, 'tcp_change_default' : {'protocol' : inet.TCP
                    , 'function' : TMpp.tcp_change_default
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }

#################
#### UDP
#################
, 'udp_change_default' : {'protocol' : inet.UDP
                    , 'function' : TMpp.udp_change_default
                    , 'preprocessing' : 
                            { 
                            inet.IP : TMpp.get_new_ips
                            , inet6.IPv6 : TMpp.get_new_ips
                            }
                    }
#################
#### DNS
#################
, 'dns_change_ips' : {'protocol' : dns.DNS
                    , 'function' : TMpp.dns_change_ips}

#################
#### HTTPv1
#################
, 'httpv1_regex_ip_swap' : {'protocol' : http.HTTPv1 
                    , 'function' : TMpp.httpv1_regex_ip_swap}

}


timestamp_function_dict = { # dictionary of known timestamp generation functions
'default' : TMtg.timestamp_dynamic_shift
, 'timestamp_shift' : TMtg.timestamp_static_shift
, 'tcp_avg_shift' : TMtg.timestamp_tcp_avg_shift
, 'tcp_min_shit' : TMtg.timestamp_tcp_min_shift
, 'tcp_max_shift' : TMtg.timestamp_tcp_max_shift
, 'timestamp_dynamic_shift' : TMtg.timestamp_dynamic_shift
}


timestamp_postprocess_dict = {
'timestamp_delay' : TMtg.timestamp_delay
, 'timestamp_delay_forIPlist' : TMtg.timestamp_delay_forIPlist
, 'timestamp_delay_forIPconst' : TMtg.timestamp_delay_forIPconst
, 'timestamp_random_oscillation' : TMtg.timestamp_random_oscillation
}

timestamp_alt_function_dict = { # dictionary of known timestamp generation functions
'default' : TMtg.timestamp_dynamic_shift
, 'timestamp_shift' : TMtg.timestamp_static_shift
, 'timestamp_dynamic_shift' : TMtg.timestamp_dynamic_shift
}

class ReWrapper(object):
    """
    Class for rewrapping packets.

    ReWrapper stores enqueued transformation functions based on protocols.
    When digesting a packet, tranformation is performed on layers of known protocols by executing enqueued transformation
    function for given protocol. 

    Usage:
    1. Instantiate ReWrapper object and input statistics object for current target pcap
    2. Input required data into the ReWrapper (based on transformation functions)
    3. Enqueue desired transformation functions.
    4. Recalculate internal data (must be done before executing)
    5. Digest packets (applies specified functions to packets)
    """

    def __init__(self, _statistics, _globalRWdict, _conversationRWdict, _packetRWdict):

        self.statistics = _statistics

        # self.queue = []
        # self.layers = []

        self.data_dict = { # data used for rewrapping of layers
        TMdef.GLOBAL : _globalRWdict
        , TMdef.CONVERSATION : _conversationRWdict
        , TMdef.PACKET : _packetRWdict
        }

        self.unwrap_dict = {} # unwrapping functions chosen for packet (support temporary data)
        self.rewrap_dict = {} # rewrapping functions chosen for layers
        # self.rc_dict = {} # recalculation functions chosen 

        self.timestamp_function = timestamp_function_dict['default']
        self.timestamp_postprocess = []
        self.data_dict[TMdef.GLOBAL]['generate_timestamp_function_alt'] = TMtg.timestamp_dynamic_shift


##################################
###### Configuration 
##################################


    def enqueue_function(self, name):
        """
        Enqueue transformation function (for specific protocol, based on function). 
        Searches for known functions based on name match.
        During rewrapping, functions are executed in enqueue order.

        :param name: Name of the function. If such function is known, it will be enqueued.
        """
        record = f_dict.get(name)
        if record:
            if record['protocol'] not in self.rewrap_dict:
                self.rewrap_dict[ record['protocol'] ] = []
            
            if record['function'] not in self.rewrap_dict[ record['protocol'] ]:
                self.rewrap_dict[ record['protocol'] ].append( record['function'] )
            
            record = record.get('preprocessing')
            if record:
                for protocol, function in record.items():
                    if protocol not in self.unwrap_dict:
                        self.unwrap_dict[ protocol ] = []
                    if function not in self.unwrap_dict[ protocol ]:
                        self.unwrap_dict[ protocol ].append(function)



    def change_timestamp_function(self, name):
        """
        Changes timestamp generating function. Functions are searched from known functions based on name match.

        Timestamp generation functions may require specific parameter to be set.

        :param name: Name of the functions. If such function is known, it will replace previous function
        """
        f = timestamp_function_dict.get(name)
        if name :
            self.timestamp_function = f


    def enqueue_timestamp_postprocess(self, name):
        """
        Enqueues postprocessing function that is applied after main timestamp generator function.

        :param name: name of the function. If such name is found, it will append the function.
        """
        f = timestamp_postprocess_dict.get(name)
        if name :
            self.timestamp_postprocess.append(f)


    def enlist_alt_timestamp_generation_function(self, name):
        """
        Select alternative generation function that may be required/used by the timestamp generation function.

        :param name: name of the function. If such name is found, it will be selected as alt generation function
        """
        f = timestamp_alt_function_dict.get(name)
        if name :
            self.data_dict[TMdef.GLOBAL]['generate_timestamp_function_alt'] = f


    def set_timestamp_next_pkt(self, timestamp_next_pkt):
        """
        Sets timestamp for next packet.

        :param timestamp_next_pkt: Timestamp for next packet. 
        """
        self.data_dict[TMdef.CONVERSATION]['timestamp_next_pkt'] = timestamp_next_pkt


    def get_timestamp_next_pkt(self):
        """
        Getter for timestamp for next packet.

        :return: Timestamp for next packet.
        """
        return self.data_dict[TMdef.CONVERSATION]['timestamp_next_pkt']


    def set_timestamp_shift(self, timestamp_shift):
        """
        Sets timestamp shift (negative or positive value depending on direction of the shift).

        :param timestamp_shift: Timestamp shift.
        """
        self.data_dict[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift'] = timestamp_shift


    def get_timestamp_shift(self):
        """
        Getter for timestamp shift.

        :return: Timestamp shift.
        """
        return self.data_dict[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift']


##################################
###### Recalculating
##################################

    def recalculate_global_dict(self):
        """
        Executes all recalcuate functions
        """
        for _type in ['min', 'max', 'avg']:
            TMtg.make_tcp_delay_map(_type, self.statistics, self.data_dict, TMdef.TARGET)
            TMtg.make_tcp_delay_map(_type, self.data_dict[TMdef.GLOBAL].attack_statistics, self.data_dict, TMdef.ATTACK)
        self.data_dict[TMdef.GLOBAL].recalculate()


##################################
###### Timestamp Generation
##################################


    def generate_timestamp(self, packet, data):
        ## Get timestamp data
        previous_timestamp_old = data[TMdef.CONVERSATION].get('previous_timestamp_old')
        previous_timestamp_new = data[TMdef.CONVERSATION].get('previous_timestamp_new')
        current_timestamp_old = packet.time

        ## Update timestamp data
        data[TMdef.CONVERSATION]['previous_timestamp_old'] = current_timestamp_old
        new_timestamp = current_timestamp_old
        if not previous_timestamp_old: 
            ## IF this is the first packet, only shift
            new_timestamp = packet.time + data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift']
        else:        
            ## Apply base timestamp generation function
            new_timestamp = self.timestamp_function(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp)
            ## Apply PostProcess functions
            for f in self.timestamp_postprocess:
                new_timestamp = f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp)
        
        ## Update timestamp data
        data[TMdef.CONVERSATION]['previous_timestamp_new'] = new_timestamp
        return new_timestamp

##################################
###### Rewraping 
##################################

    def unwrap(self, packet):
        """
        Recursively reads layers of the packets (only for implemented protocols) and queues transformation
        functions for each read layer.

        :param packet: Interpreted packet; expected scapy protocol packet.
        """
        protocol = type(packet)
        if protocol in recognized_protocols:
#            self.layers.append(packet)

            unwrapping_functions = self.unwrap_dict.get(protocol)
            if unwrapping_functions:
                for f in unwrapping_functions:
                    f(packet, self.data_dict)

            tranform_functions = self.rewrap_dict.get(protocol)
            if tranform_functions:
                #elf.queue.append( tranform_functions ) # list of transformation functions
                for f in tranform_functions: # TEST - does changing port prevent parsing protocol in TCP packet?
                    f(packet, self.data_dict)
            # else:
            #     self.queue.append([])

            self.unwrap(packet.payload)



    # def rewrap(self, packet):
    #     """
    #     Applies transformation functions to packet-layers top-to-bottom and changes resulting packets timestamp

    #     :param packet: Transformed packet; expected scapy Ether packet
    #     """
    #     for i in range(len(self.layers)-1,-1,-1):
    #         for f in self.queue[i]:
    #             f(self.layers[i], self.data_dict)
    #     packet.time = self.generate_timestamp(packet, self.data_dict)
    #     return packet


    def digest(self, packet):
        """
        Transforms old packet into new, changed packet based on previous configuration.

        :param packet: Interpreted packet; expected object is a scapy Ether packet.

        :return: Transformed packet.
        """
        # self.queue = []
        # self.layers = []
        self.unwrap(packet)
        # return self.rewrap(packet)
        packet.time = self.generate_timestamp(packet, self.data_dict)
        return packet