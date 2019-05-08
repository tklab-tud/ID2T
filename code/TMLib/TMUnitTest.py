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

import TMLib.ReWrapper as ReWrap

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

def build_mock_dict():
    data = dict()
    tmp = {}
    tmp[TMdef.TARGET] = {
        'mac_address_map' : {
            'F6:DA:77:F3:E2:E0' : '8C:37:E1:F2:C8:E5'
            , 'ED:FA:E9:69:21:90' : 'FB:88:E6:CE:48:69'
            , 'F9:7D:4D:06:FF:E2' : 'F2:23:9A:2F:42:67'
        }
        , 'ip_address_map' : {
            '181.149.152.176' : '124.233.255.79'
            , '80.142.128.2' : '167.47.163.121'
            , '107.149.218.168' : '196.125.180.91'
        }

        , 'ip_ttl_map' : {
            '181.149.152.176' : 99
            , '80.142.128.2' : 98
            , '107.149.218.168' : 97
        }
        , 'ip_ttl_default' : 100

        , 'pps_record_map' : {}

        , 'win_size_map' : {
            '181.149.152.176' : 199
            , '80.142.128.2' : 198
            , '107.149.218.168' : 197
        }
        , 'win_size_default' : 200

        , 'mss_map' : {
            '181.149.152.176' : 299
            , '80.142.128.2' : 298
            , '107.149.218.168' : 297
        }
        , 'mss_default' : 300

        , 'port_map_forIP' : {
            '181.149.152.176' : {
                20 : 30
                }
            , '80.142.128.2' : {}
            , '107.149.218.168' : {}
        }

        , 'mss_exceptions' : set(['107.149.218.168'])
        , 'win_size_exceptions' : set(['107.149.218.168'])
        , 'ttl_exceptions' : set(['107.149.218.168'])

        , 'tcp_avg_delay_map' : {}
    }
    tmp[TMdef.ATTACK] = {
        'timestamp_shift' : 0 # used by timestamp_shift
        , 'tcp_avg_delay_map' : {}
        , 'timestamp_delay_map' : {}
        , 'timestamp_delay_set' : set()
    }
    data[TMdef.GLOBAL] = tmp
    data[TMdef.CONVERSATION] = dict()
    data[TMdef.PACKET] = dict()


    return data


def compare_mac_pkts(_f, _s):
    result = True
    for field in _f.fields_desc:
        field = field.name
        result &= ( _f.getfieldval(field) == _s.getfieldval(field) )
    return result

def build_mock_rewrapper():
    statistics = {}
    globalRWdict = {
    TMdef.ATTACK : {'timestamp_shift' : 0}
    , TMdef.TARGET : {}
    }
    conversationRWdict = {} 
    packetRWdict = {}

    rw = ReWrap.ReWrapper(statistics, globalRWdict, conversationRWdict, packetRWdict)

    return rw, statistics, globalRWdict, conversationRWdict, packetRWdict

def mock_function(i):
    def mock_labeled_function():
        return i
    return mock_labeled_function
