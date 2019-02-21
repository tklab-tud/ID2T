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

        if _statistics is None or _globalRWdict is None or _conversationRWdict is None or _packetRWdict is None:
            raise TypeError('NoneType passed on rewrapper init.')

        if not isinstance(_globalRWdict, TMdict.GlobalRWdict):
            raise TypeError('Wrong dictionary type passed on rewrapper init, TMdict.GlobalRWdict expected but got ' + type(_globalRWdict))

        if not isinstance(_conversationRWdict, TMdict.ConversationRWdict):
            raise TypeError('Wrong dictionary type passed on rewrapper init, TMdict.ConversationRWdict expected but got ' + type(_conversationRWdict))

        if not isinstance(_packetRWdict, TMdict.PacketDataRWdict):
            raise TypeError('Wrong dictionary type passed on rewrapper init, TMdict.PacketDataRWdict expected but got ' + type(_packetRWdict))
        
        self.statistics = _statistics

        # self.queue = []
        # self.layers = []

        self.data_dict = { # data used for rewrapping of layers
        TMdef.GLOBAL : _globalRWdict
        , TMdef.CONVERSATION : _conversationRWdict
        , TMdef.PACKET : _packetRWdict
        }

        self.preprocess_dict = {} # preprocessing functions chosen for packet (support temporary data)
        self.process_dict = {} # processing functions chosen for layers
        self.postprocess_dict = {} # postrprocessing function chosen for layers

        self.timestamp_function = None
        self.timestamp_postprocess = []
        self.data_dict[TMdef.GLOBAL]['generate_timestamp_function_alt'] = TMtg.timestamp_dynamic_shift


##################################
###### Configuration 
##################################

    
    def enqueue_preprocessing_function(self, protocol, function):
        """
        Enqueue packet preprocessing function for a protocol.

        Preprocessing function is executed before processing functions.

        :param protocol: protocol, type of the packet layer object
        :param function: packet preprocessing function with two parameters: packet, data
        """
        if not function or not protocol:
            raise TypeError('NoneType passed as packet preprocessing function.')

        queue = self.preprocess_dict.get(protocol)
        if not queue:
            queue = []
            self.preprocess_dict[protocol] = queue
        queue.append(function)


    def enqueue_processing_function(self, protocol, function):
        """
        Enqueue packet processing function for a protocol.

        :param protocol: protocol, type of the packet layer object
        :param function: packet processing function with two parameters: packet, data
        """
        if not function or not protocol:
            raise TypeError('NoneType passed as packet processing function.')

        queue = self.process_dict.get(protocol)
        if not queue:
            queue = []
            self.process_dict[protocol] = queue
        queue.append(function)


    def enqueue_postprocessing_function(self, protocol, function):
        """ 
        Enqueue packet preprocessing function for a protocol.

        Preprocessing function is executed before processing functions.

        :param protocol: protocol, type of the packet layer object
        :param function: packet preprocessing function with two parameters: packet, data
        """
        if not function or not protocol:
            raise TypeError('NoneType passed as packet preprocessing function.')

        queue = self.postprocess_dict.get(protocol)
        if not queue:
            queue = []
            self.postprocess_dict[protocol] = queue
        queue.append(function)


    def set_timestamp_generator(self, function):
        """
        Set timestamp generation function.
        
        Function must have these parameters:
            packet - current packet
            data - data dict
            previous_timestamp_old - original timestamp of previous packet
            previous_timestamp_new - final (after application of all functions) generated timestamp of the previous packte
            current_timestamp_old - original timestamp of the current packet
            new_timestamp - new (after application of all previous functions) timestamp of the current packet,
                            if none was applied then current_timestamp_old == new_timestamp
        Function must return new timestamp value and returned_value >= previous_timestamp_new must hold.

        :param function: timestamp generator function
        """
        if not function:
            raise TypeError('NoneType passed as timestamp generator function.')
        self.timestamp_function = function


    def set_backup_timestamp_generator(self, function):
        """
        Set backup timestamp generation function. May be required/used by the main timestamp generation function.
        
        Function must have these parameters:
            packet - current packet
            data - data dict
            previous_timestamp_old - original timestamp of previous packet
            previous_timestamp_new - final (after application of all functions) generated timestamp of the previous packte
            current_timestamp_old - original timestamp of the current packet
            new_timestamp - new (after application of all previous functions) timestamp of the current packet,
                            if none was applied then current_timestamp_old == new_timestamp
        Function must return new timestamp value and returned_value >= previous_timestamp_new must hold.

        :param function: timestamp generator function
        """
        if not function:
            raise TypeError('NoneType passed as alternative timestamp generator function.')
        self.data_dict[TMdef.GLOBAL]['generate_timestamp_function_alt'] = function


    def enqueue_timestamp_postprocess(self, function):
        """
        Enqueues postprocessing function that is applied after main timestamp generator function.
        
        Function must have these parameters:
            packet - current packet
            data - data dict
            previous_timestamp_old - original timestamp of previous packet
            previous_timestamp_new - final (after application of all functions) generated timestamp of the previous packte
            current_timestamp_old - original timestamp of the current packet
            new_timestamp - new (after application of all previous functions) timestamp of the current packet,
                            if none was applied then current_timestamp_old == new_timestamp
        Function must return new timestamp value and returned_value >= previous_timestamp_new must hold.

        :param function: name of the function. If such name is found, it will append the function.
        """
        if not function:
            raise TypeError('NoneType passed as timestamp postprocess function.')
        self.timestamp_postprocess.append(function)


    def set_timestamp_next_pkt(self, timestamp_next_pkt):
        """
        Sets timestamp for next packet.

        :param timestamp_next_pkt: Timestamp for next packet. 
        """
        if not timestamp_next_pkt:
            raise TypeError('NoneType passed as timestamp_next_pkt value.')
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
        if not timestamp_shift:
            raise TypeError('NoneType passed as timestamp_shift value.')
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
        self.data_dict[TMdef.GLOBAL].recalculate()

##################################
###### validate dicts
##################################

    def validate_global_dict(self, verbose=False):
        return self.data_dict[TMdef.GLOBAL].validate()

    def validate_conv_dict(self):
        return self.data_dict[TMdef.CONVERSATION].validate()

    def validate_packet_dict(self):
        return self.data_dict[TMdef.PACKET].validate()


##################################
###### Timestamp Generation
##################################


    def generate_timestamp(self, packet, data):
        """
        Generates new timestamp by applying timestamp processing and postprocessing functions.

        If generated timestamp is lower than the final timestamp of previous packet, 0 delay is used and warning is printed.

        :param packet: current packet, scapy packet (frame)
        :param data: data dict
        """
        ## Get timestamp data
        previous_timestamp_old = data[TMdef.CONVERSATION].get('previous_timestamp_old') ## get old timestamp of prev packet
        previous_timestamp_new = data[TMdef.CONVERSATION].get('previous_timestamp_new') ## get new timestamp of prev packet
        current_timestamp_old = packet.time ## get old timestamp of cur packet

        ## Update timestamp data
        data[TMdef.CONVERSATION]['previous_timestamp_old'] = current_timestamp_old ## update data from next iteration
        ## Default value
        new_timestamp = current_timestamp_old 
        if not previous_timestamp_old: 
            ## IF this is the first packet, only shift
            new_timestamp = packet.time + data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift']
        else: ## Test every timestamp if new_timestamp >= previous_timestamp_new
            ## Apply base timestamp generation function
            new_timestamp = test_generated_timestamp_order(previous_timestamp_new,
                self.timestamp_function(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp),
                self.timestamp_function, 
                new_timestamp)
            ## Apply PostProcess functions
            for f in self.timestamp_postprocess:
                new_timestamp = test_generated_timestamp_order(previous_timestamp_new,
                    f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp),
                    f,
                    new_timestamp)
            
            ## Final test in case every function failed the check
            ## Default value with 0 delay
            new_timestamp = test_generated_timestamp_order(previous_timestamp_new,
                new_timestamp,
                "!all!",
                previous_timestamp_new)
            ## Warn if 0 delay was generated
            if new_timestamp == previous_timestamp_new:
                print('[WARNING] Final timestamp for packet with delay 0 generated at ', new_timestamp)
        
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

            preprocess_f = self.preprocess_dict.get(protocol)
            if preprocess_f:
                for f in preprocess_f:
                    f(packet, self.data_dict)

            process_f = self.process_dict.get(protocol)
            if process_f:
                for f in process_f: # TEST - does changing port prevent parsing protocol in TCP packet?
                    f(packet, self.data_dict)

            postprocess_f = self.postprocess_dict.get(protocol)
            if postprocess_f:
                for f in postprocess_f:
                    f(packet, self.data_dict)

            self.unwrap(packet.payload)


    def digest(self, packet):
        """
        Transforms old packet into new, changed packet based on previous configuration.

        :param packet: Interpreted packet; expected object is a scapy Ether packet.

        :return: Transformed packet.
        """
        if not packet:
            raise TypeError('NoneType passed as packet for digestion.')

        self.unwrap(packet)
        packet.time = self.generate_timestamp(packet, self.data_dict)
        return packet


##################################
###### Helpers 
##################################

def test_generated_timestamp_order(previous_timestamp_new, new_timestamp, function, backup_timestamp):
    """
    Test if the newly generated timestamp is smaller then timestamp of previous packet. 
    If yes, return backup timestamp and print warning.

    :param previous_timestamp_new: final timestamp of previous packet, float
    :param new_timestamp: newest generated timestamp for final packet, float
    :param function: function that generated the timestamp
    :param backup_timestamp: value to be returned if condition does not hold

    :return: new_timestamp if condition holds, else backup_timestamp
    """
    if new_timestamp < previous_timestamp_new:
        print('[WARNING] Erronous timestamp generated by', function, 'with new timestamp', new_timestamp, '<', previous_timestamp_new,
            '. Replacing by', backup_timestamp)
        return backup_timestamp
    return new_timestamp

