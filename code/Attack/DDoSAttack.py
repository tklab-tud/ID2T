import logging
import random as rnd
from statistics import mean
import subprocess, shlex
import pathlib
import shutil

import lea
import scapy.layers.inet as inet
import scapy.utils

import xml.etree.cElementTree as ET
from xml.dom.minidom import parse, parseString
import configparser

import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util

from Attack.Parameter import Parameter, Float, IntegerPositive, IPAddress, MACAddress, Port, String
import ipaddress as ip_addr

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8

DATARATES = ["10Mbps", "100Mbps", "1Gbps", "10Gbps", "40Gbps", "100Gbps", "200Gbps", "400Gbps"]
UDP_MIN_PAYLOAD = 8
UDP_MIN_OVH = 56
AVG_TCP_HANDSHAKE_PAYLOAD = 82

class DDoSAttack(BaseAttack.BaseAttack):
    PORT_SOURCE = 'port.src'
    PORT_DESTINATION = 'port.dst'
    NUMBER_ATTACKERS = 'attackers.count'
    NUMBER_VICTIMS = 'victims.count'
    VICTIM_PACKET_CAPACITY = 'victim.packet_capacity'
    VICTIM_DATA_CAPACITY = 'victim.data_capacity'
    VICTIM_MAX_SOCKETS = 'victim.max_sockets'
    CHANNEL_DATARATE = 'channel.datarate'
    CHANNEL_DELAY = 'channel.delay'
    CHANNEL_BER = 'channel.ber'
    CHANNEL_PER = 'channel.per'
    SUBTYPE = 'attack.subtype'
    TCP = 'tcp.version'
    QTENV = 'qtenv'
    PAYLOAD_SIZE = 'payload.size'


    def __init__(self):
        """
        Creates a new instance of the DDoS attack.
        """
        # Initialize attack
        super(DDoSAttack, self).__init__("DDoS Attack", "Injects a DDoS attack'",
                                         "Resource Exhaustion")

        self.pkt_num = 0
        self.path_attack_pcap = None

        self.total_pkt_num = 0
        self.default_port = 0

        self.OMNETPP_RES = Util.RESOURCE_DIR + 'inet-ddos/'
        self.current_ddos = ''

        self.attackers = []
        self.victims = []

        # Define allowed parameters and their type
        self.update_params([
            Parameter(self.SUBTYPE, String()),
            Parameter(self.IP_SOURCE, IPAddress()),
            Parameter(self.MAC_SOURCE, MACAddress()),
            Parameter(self.PORT_SOURCE, Port()),

            Parameter(self.IP_DESTINATION, IPAddress()),
            Parameter(self.MAC_DESTINATION, MACAddress()),
            Parameter(self.PORT_DESTINATION, Port()),

            Parameter(self.PACKETS_PER_SECOND, Float()),
            Parameter(self.NUMBER_ATTACKERS, IntegerPositive()),
            Parameter(self.NUMBER_VICTIMS, IntegerPositive()),
            Parameter(self.ATTACK_DURATION, IntegerPositive()),
            Parameter(self.VICTIM_PACKET_CAPACITY, IntegerPositive()),
            Parameter(self.VICTIM_DATA_CAPACITY, IntegerPositive()),
            Parameter(self.VICTIM_MAX_SOCKETS, IntegerPositive()),
            Parameter(self.CHANNEL_DATARATE, String()),
            Parameter(self.CHANNEL_DELAY, Float()),
            Parameter(self.CHANNEL_BER, Float()),
            Parameter(self.CHANNEL_PER, Float()),
            Parameter(self.PAYLOAD_SIZE, IntegerPositive()),
            Parameter(self.TCP, String()),
            Parameter(self.QTENV, String()),
        ])

    def init_param(self, param: str) -> bool:
        """
        Initialize a parameter with a default value specified in the specific attack.

        :param param: parameter, which should be initialized
        :return: True if initialization was successful, False if not
        """

        value = None

        # Attack configuration

        if param == self.SUBTYPE:
            value = 'syn_flood'
        elif param == self.QTENV:
            value = "false"
        elif param == self.TCP:
            value = 'NEW_RENO'
        elif param == self.NUMBER_ATTACKERS:
            value = rnd.randint(1, 4)  #FIXME
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        elif param == self.PACKETS_PER_SECOND:
            value = 0.0
        elif param == self.ATTACK_DURATION:
            value = rnd.randint(15, 35)
        elif param == self.NUMBER_VICTIMS:
            value = rnd.randint(1, 4)  #FIXME
        elif param == self.PAYLOAD_SIZE:
            value = 8

        # Attacker(s) configuration
        
        elif param == self.IP_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if not num_attackers:
                return False
            # The most used IP class in background traffic
            most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
            value = self.generate_random_ipv4_address(most_used_ip_class, num_attackers)            
        
        elif param == self.MAC_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if not num_attackers:
                return False
            value = self.generate_random_mac_address(num_attackers)
            
        elif param == self.PORT_SOURCE:
            num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
            if not num_attackers:
                return False
            
            self.ephemeral_ports = [int(inet.RandShort()) for i in range(num_attackers)]            
            value = self.ephemeral_ports


        # Victim(s) configuration
       
        elif param == self.IP_DESTINATION:
            num_victims = self.get_param_value(self.NUMBER_VICTIMS)
            if not num_victims:
                return False
            value = self.statistics.get_random_ip_address(count=num_victims)

        elif param == self.MAC_DESTINATION:
            ip_dst = self.get_param_value(self.IP_DESTINATION)
            if not ip_dst:
                return False

            if isinstance(ip_dst, str):
                value = self.get_mac_address(ip_dst)
            elif isinstance(ip_dst, list):
                value = []
                for ip in ip_dst:
                    value.append(self.get_mac_address(ip))

        elif param == self.VICTIM_PACKET_CAPACITY:
            value = 100
        elif param == self.VICTIM_DATA_CAPACITY:
            value = 100000000
        
        elif param == self.VICTIM_MAX_SOCKETS:
            value = 0 # infinite

        # Channel configuration
        elif param == self.CHANNEL_DATARATE:
            value = ''
        elif param == self.CHANNEL_DELAY:
            value = 0.0
        elif param == self.CHANNEL_BER:
            value = 0.0
        elif param == self.CHANNEL_PER:
            value = 0.0

        if value is None:
            return False
        
        return self.add_param_value(param, value)

    def get_router_address(self, ip):
        return str(list(ip_addr.ip_network(ip+'/24', False).hosts())[0])

    def generate_config_xml(self):
        root = ET.Element('config')
        
        for idx, attacker in enumerate(self.attackers):
            interface = ET.SubElement(root, 'interface')
            interface.set('hosts', 'attacker['+str(idx)+']')
            interface.set('names', 'eth0')
            interface.set('netmask', '255.255.255.0')
            interface.set('address', attacker[0])

            interface_router = ET.SubElement(root, 'interface')
            interface_router.set('hosts', 'router')
            interface_router.set('names', 'eth'+str(idx))
            interface_router.set('netmask', '255.255.255.0')
            interface_router.set('address', self.get_router_address(attacker[0]))

        for idx, victim in enumerate(self.victims):
            interface = ET.SubElement(root, 'interface')
            interface.set('hosts', 'victim['+str(idx)+']')
            interface.set('names', 'eth0')
            interface.set('netmask', '255.255.255.0')
            interface.set('address', victim[0])

            interface_router = ET.SubElement(root, 'interface')
            interface_router.set('hosts', 'router')
            interface_router.set('names', 'eth'+str(idx+len(self.attackers)))
            interface_router.set('netmask', '255.255.255.0')
            interface_router.set('address', self.get_router_address(victim[0]))

        tree = ET.tostring(root, encoding='unicode')

        tr = parseString(tree).toprettyxml()[23:]

        with open(self.OMNETPP_RES+self.current_ddos+"/simulations/ip-config.xml", "w") as f:
            f.write(tr)

    def _validate_datarate(self, datarate):
        if datarate in DATARATES:
            return True
        raise Exception('Channel datarate must be among these: ' + str(DATARATES))

    def _closest_to_datarate(self, datarate):
        standard_sizes = {10: "10Mbps", 100: "100Mbps", 1000: "1Gbps", 10000: "10Gbps", 40000: "40Gbps", 100000: "100Gbps", 200000: "200Gbps", 400000: "400Gbps"}
        in_mbps = datarate*8*pow(10, -6)

        k = min(standard_sizes.keys(), key=lambda x:abs(x - in_mbps))

        return standard_sizes[k]        
    
    def generate_omnetpp_ini(self):
        template_ini = Util.RESOURCE_DIR + 'inet-ddos/' + self.current_ddos + '/template.ini'
        config = configparser.RawConfigParser()
        config.optionxform = str

        num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
        num_victims = self.get_param_value(self.NUMBER_VICTIMS)
        attack_duration = self.get_param_value(self.ATTACK_DURATION)
        self.current_ddos = self.get_param_value(self.SUBTYPE)
        channel_datarate = self.get_param_value(self.CHANNEL_DATARATE)
        channel_delay = self.get_param_value(self.CHANNEL_DELAY)
        channel_ber = self.get_param_value(self.CHANNEL_BER)
        channel_per = self.get_param_value(self.CHANNEL_PER)

        victim_packet_capacity = self.get_param_value(self.VICTIM_PACKET_CAPACITY)
        victim_data_capacity = self.get_param_value(self.VICTIM_DATA_CAPACITY)
        victim_max_sockets = self.get_param_value(self.VICTIM_MAX_SOCKETS)
        
        with open(template_ini, 'r') as f:
            try:  
                config.read(template_ini)
            except:
                raise IOError()

        # Attack config
        config['General']['sim-time-limit'] = str(attack_duration)+'s'
        config['General']['**.attackersCount'] = str(num_attackers)
        config['General']['**.victimsCount'] = str(num_victims)
        config['General']['**.attacker[*].numApps'] = str(num_victims)
        config['General']['**.victim[*].numApps'] = '1'

        payload_size = 0

        if ("udp_flood" == self.current_ddos):
            n_apps = len(self.victims)
            payload_size = self.get_param_value(self.PAYLOAD_SIZE)

            config['General']['**.attacker[*].app[*].messageLength'] = str(payload_size)+'B'
            config['General']['**.attacker[*].app[*].sendInterval'] = '0.01s'
            config['General']['**.attacker[*].app[*].burstDuration'] = '15s'
            config['General']['**.attacker[*].app[*].sleepDuration'] = '1s'

            for idx, victim in enumerate(self.victims):
                config['General']['**.attacker[*].app['+str(idx)+'].destPort'] = str(victim[2])
                config['General']['**.victim['+str(idx)+'].udp.mss'] = str(victim[3])
                config['General']['**.victim['+str(idx)+'].app[0].localPort'] = str(victim[2])
                config['General']['**.victim[*].eth[*].queue.dataQueue.packetCapacity'] = str(victim_packet_capacity)
            
            for idx, attacker in enumerate(self.attackers):
                config['General']['**.attacker['+str(idx)+'].app[0].localPort'] = str(attacker[2])

            payload_size += UDP_MIN_OVH

        elif ("syn_flood" == self.current_ddos):
            payload_size = AVG_TCP_HANDSHAKE_PAYLOAD

            pass

        elif ("low_and_slow" == self.current_ddos):
            payload_size = UDP_MIN_OVH+UDP_MIN_PAYLOAD
            pass

        elif ("dns_amplification" == self.current_ddos):
            payload_size = UDP_MIN_OVH+UDP_MIN_PAYLOAD
            pass

        else:
            raise Exception("You shouldn't be here")
        
        # Channel config
        if channel_datarate:
            self._validate_datarate(channel_datarate)
            config['General']['**.channel.datarate'] = channel_datarate

        else:
            c_datarate = mean(self.pps_victims)*payload_size
            config['General']['**.channel.datarate'] = self._closest_to_datarate(c_datarate)

        config['General']['**.channel.delay'] = str(channel_delay)+'s'
        config['General']['**.channel.ber'] = str(channel_ber)
        config['General']['**.channel.per'] = str(channel_per)
        
        with open(self.omnetpp_ini, 'w') as configfile:
            config.write(configfile)

    def run_simulation(self):
        
        inet_dir = "inet/"

        cmd = '''opp_run \
        -u {gui} \
        -n {src_dir} \
        -n {simulations_dir} \
        -n {inet_dir}/src/ \
        -x inet.common.selfdoc \
        -x inet.linklayer.configurator.gatescheduling.z3 \
        -x inet.emulation \
        -x inet.showcases.visualizer.osg \
        -x inet.examples.emulation \
        -x inet.showcases.emulation \
        -x inet.transportlayer.tcp_lwip \
        -x inet.applications.voipstream \
        -x inet.visualizer.osg \
        -x inet.examples.voipstream \
        -f {omnetpp_ini} \
        --image-path={inet_dir}/images \
        -l {inet_dir}/src/libINET.so \
        '''.format(simulations_dir=self.simulations_dir, src_dir=self.src_dir, omnetpp_ini=self.omnetpp_ini, inet_dir=inet_dir, gui="Qtenv" if "true" == self.get_param_value(self.QTENV) else "Cmdenv")
        
        args = shlex.split(cmd)

        subprocess.run(args)


    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

        num_attackers = self.get_param_value(self.NUMBER_ATTACKERS)
        num_victims = self.get_param_value(self.NUMBER_VICTIMS)
        attack_duration = self.get_param_value(self.ATTACK_DURATION)
        self.current_ddos = self.get_param_value(self.SUBTYPE)
        payload_size = self.get_param_value(self.PAYLOAD_SIZE)

        channel_datarate = self.get_param_value(self.CHANNEL_DATARATE)
        channel_delay = self.get_param_value(self.CHANNEL_DELAY)
        channel_ber = self.get_param_value(self.CHANNEL_BER)
        channel_per = self.get_param_value(self.CHANNEL_PER)


        victim_packet_capacity = self.get_param_value(self.VICTIM_PACKET_CAPACITY)
        victim_data_capacity = self.get_param_value(self.VICTIM_DATA_CAPACITY)
        victim_max_sockets = self.get_param_value(self.VICTIM_MAX_SOCKETS)
        tcp_version = self.get_param_value(self.TCP)

        if (self.current_ddos != "syn_flood") and (self.current_ddos != "udp_flood") and (self.current_ddos != "dns_amplification") and (self.current_ddos != "low_and_slow"):
            raise Exception('Unrecognized DDoS subtype.')
        
        if (payload_size < UDP_MIN_PAYLOAD):
            raise Exception('Payload minimum is set to 8bytes')

        self.template_pcap_path = "results/template.pcap"

        ip_attackers_list = self.get_param_value(self.IP_SOURCE)
        mac_attackers_list = self.get_param_value(self.MAC_SOURCE)

        ip_victims_list = self.get_param_value(self.IP_DESTINATION)
        mac_victims_list = self.get_param_value(self.MAC_DESTINATION)

        # Make sure IPs and MACs are lists
        if not isinstance(ip_attackers_list, list):
            ip_attackers_list = [ip_attackers_list]

        if not isinstance(mac_attackers_list, list):
            mac_attackers_list = [mac_attackers_list]

        if not isinstance(ip_victims_list, list):
            ip_victims_list = [ip_victims_list]

        if not isinstance(mac_victims_list, list):
            mac_victims_list = [mac_victims_list]

        if (num_attackers != None) and (num_attackers != 0):
            # user supplied self.NUMBER_ATTACKERS
            num_rnd_ips = num_attackers - len(ip_attackers_list)
            num_rnd_macs = num_attackers - len(mac_attackers_list)
            if num_rnd_ips:
                # The most used IP class in background traffic
                most_used_ip_class = Util.handle_most_used_outputs(self.statistics.get_most_used_ip_class())
                # Create random attackers based on user input self.NUMBER_ATTACKERS
                ip_attackers_list.extend(self.generate_random_ipv4_address(most_used_ip_class, num_rnd_ips))
            if num_rnd_macs:
                mac_attackers_list.extend(self.generate_random_mac_address(num_rnd_macs))

        # Generate MACs for each IP that has no corresponding MAC yet
        if (num_attackers == None) or (num_attackers == 0):
            if len(ip_attackers_list) > len(mac_attackers_list):
                mac_attackers_list.extend(self.generate_random_mac_address(len(ip_attackers_list)-len(mac_attackers_list)))
            num_attackers = min(len(ip_attackers_list), len(mac_attackers_list)) 

        self.attackers = [(ip, mac, port) for ip, mac, port in zip(ip_attackers_list, mac_attackers_list, self.ephemeral_ports)]

        port_victims_list = []

        for victim_ip in ip_victims_list:
            port_destination = self.get_param_value(self.PORT_DESTINATION)
            if not port_destination:  # user did not define port_dest
                port_destination = self.statistics.process_db_query(
                    "SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + victim_ip +
                    "' AND portCount==(SELECT MAX(portCount) FROM ip_ports WHERE portDirection='in' AND ipAddress='" +
                    victim_ip + "');")
            if not port_destination:  # no port was retrieved
                port_destination = self.statistics.process_db_query(
                    "SELECT portNumber FROM (SELECT portNumber, SUM(portCount) as occ FROM ip_ports WHERE "
                    "portDirection='in' GROUP BY portNumber ORDER BY occ DESC) WHERE occ=(SELECT SUM(portCount) "
                    "FROM ip_ports WHERE portDirection='in' GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT 1);")
            if not port_destination:
                port_destination = max(1, int(inet.RandShort()))

            port_destination = Util.handle_most_used_outputs(port_destination)
            port_victims_list.append(port_destination)
        
        # Check ip.src == ip.dst
        self.ip_src_dst_catch_equal(ip_attackers_list, ip_victims_list)
       
        # MSS that was used by victims IPs in background traffic
        mss_list = []
        for victim_ip in ip_victims_list:
            mss_dst = self.statistics.get_most_used_mss(victim_ip)
            if mss_dst is None:
                mss_dst = self.statistics.get_most_used_mss_value()
            mss_dst = Util.handle_most_used_outputs(mss_dst)
            mss_list.append(mss_dst)

        self.victims = [(ip, mac, port, mss) for ip, mac, port, mss in zip(ip_victims_list, mac_victims_list, port_victims_list, mss_list)]

        # Initialize parameters
        most_used_ip_address = self.statistics.get_most_used_ip_address()

        self.pps_victims = []
        for v in self.victims:
            ip_destination = v[0]
            pps = self.get_param_value(self.PACKETS_PER_SECOND)
            if pps == 0:
                result = self.statistics.process_db_query(
                    "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + ip_destination + "';")
                if result is not None and result != 0:
                    pps = result
                else:
                    result = self.statistics.process_db_query(
                        "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + most_used_ip_address + "';")
                    pps = result
            self.pps_victims.append(pps)
        
        self.path_attack_pcap = None

        self.proj_dir = Util.RESOURCE_DIR+"inet-ddos/"+self.current_ddos
        self.src_dir = self.proj_dir+"/src/"
        self.simulations_dir = self.proj_dir+"/simulations/"
        self.omnetpp_ini = self.simulations_dir+"omnetpp.ini"
        self.network_ned = self.simulations_dir+'package.ned'

        self.generate_config_xml()

        self.generate_omnetpp_ini()

        self.run_simulation()

        raw_packets = scapy.utils.PcapReader(self.template_pcap_path)
        
        assoc = {a[0]: a[1] for a in self.attackers}
        assoc.update({v[0]: v[1] for v in self.victims})

        rel_time = 0

        for self.pkt_num, pkt in enumerate(raw_packets):
            if not pkt.haslayer(inet.IP):
                continue

            if self.pkt_num == 0:
                rel_time = pkt.time

            eth_frame = pkt
            ip_pkt = eth_frame.payload
            
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if src_ip in assoc:
                eth_frame.src = assoc[src_ip]
            if dst_ip in assoc:
                eth_frame.dst = assoc[dst_ip]
            
            new_pkt = (eth_frame / ip_pkt)
            new_time = pkt.time-rel_time

            timestamp_next_pkt += new_time
            new_pkt.time = timestamp_next_pkt

            self.add_packet(new_pkt, src_ip, dst_ip)

        if self.buffer_full():
            self.flush_packets()
        
        print(self.packets)
                
        shutil.rmtree(pathlib.Path('results/'))
        
    def generate_attack_pcap(self):
        """
        Creates a pcap containing the attack packets.

        :return: The location of the generated pcap file.
        """

        
        # Store timestamp of first packet (for attack label)
        self.attack_start_utime = self.packets[0].time
        self.attack_end_utime = self.packets[-1].time

        if len(self.packets) > 0:
            self.packets = sorted(self.packets, key=lambda pkt: pkt.time)
            self.path_attack_pcap = self.write_attack_pcap(self.packets, True, self.path_attack_pcap)

        # return packets sorted by packet time_sec_start
        # pkt_num+1: because pkt_num starts at 0
        return self.pkt_num + 1, self.path_attack_pcap
