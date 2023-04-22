import logging
import random as rnd

import lea
import scapy.layers.inet as inet
import scapy.utils

import xml.etree.cElementTree as ET
from xml.dom.minidom import parse, parseString

import Attack.BaseAttack as BaseAttack
import Lib.Utility as Util

from Attack.Parameter import Parameter, Float, IntegerPositive, IPAddress, MACAddress, Port, String

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# noinspection PyPep8


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
            Parameter(self.CHANNEL_DATARATE, Float()),
            Parameter(self.CHANNEL_DELAY, Float()),
            Parameter(self.CHANNEL_BER, Float()),
            Parameter(self.CHANNEL_PER, Float()),
            Parameter(self.TCP, String())
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
        elif param == self.TCP:
            value = 'NEW_RENO'
        elif param == self.NUMBER_ATTACKERS:
            value = rnd.randint(1, 4)  #FIXME
        elif param == self.INJECT_AFTER_PACKET:
            value = rnd.randint(0, self.statistics.get_packet_count())
        elif param == self.PACKETS_PER_SECOND:
            value = 0.0
        elif param == self.ATTACK_DURATION:
            value = rnd.randint(30, 300)
        elif param == self.NUMBER_VICTIMS:
            value = rnd.randint(1, 4)  #FIXME

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
            value = 0.0 #infinite
        elif param == self.CHANNEL_DELAY:
            value = 0.0
        elif param == self.CHANNEL_BER:
            value = 0.0
        elif param == self.CHANNEL_PER:
            value = 0.0

        if value is None:
            return False
        
        return self.add_param_value(param, value)

    def generate_config_xml(self):
        root = ET.Element('config')
        
        for idx, attacker in enumerate(self.attackers):
            interface = ET.SubElement(root, 'interface')
            interface.set('among', 'attacker['+str(idx)+'] router')
            # interface.set('names', 'eth0')
            interface.set('address', attacker[0])

        for idx, victim in enumerate(self.victims):
            interface = ET.SubElement(root, 'interface')
            interface.set('among', 'victim['+str(idx)+'] router')
            # interface.set('names', 'eth0')
            interface.set('address', victim[0])

        tree = ET.tostring(root, encoding='unicode')

        tr = parseString(tree).toprettyxml()[23:]

        with open(self.OMNETPP_RES+self.current_ddos+"/simulations/ip-config-id2t.xml", "w") as f:
            f.write(tr)

    def generate_omnetpp_ini(self):
        pass

    def run_simulation(self):
        pass

    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """

        timestamp_next_pkt = self.get_param_value(self.INJECT_AT_TIMESTAMP)

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
        tcp_version = self.get_param_value(self.TCP)

        if (self.current_ddos != "syn_flood") and (self.current_ddos != "udp_flood") and (self.current_ddos != "dns_amplification"):
            raise Exception('Unrecognized DDoS subtype.')

        self.template_pcap_path = self.OMNETPP_RES + self.current_ddos + "/simulations/results/template.pcap"

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
        # most_used_ip_address = self.statistics.get_most_used_ip_address()
        # pps = self.get_param_value(self.PACKETS_PER_SECOND)
        #if pps == 0:
        #    result = self.statistics.process_db_query(
        #        "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + ip_destination + "';")
        #    if result is not None and result != 0:
        #        pps = num_attackers * result
        #    else:
        #        result = self.statistics.process_db_query(
        #            "SELECT MAX(maxPktRate) FROM ip_statistics WHERE ipAddress='" + most_used_ip_address + "';")
        #        pps = num_attackers * result

        # Calculate complement packet rates of the background traffic for each interval
        # attacker_pps = pps / num_attackers
        #complement_interval_attacker_pps = self.statistics.calculate_complement_packet_rates(attacker_pps)

        self.path_attack_pcap = None

        self.generate_config_xml()

        self.generate_omnetpp_ini()

        self.run_simulation()

        raw_packets = scapy.utils.PcapReader(self.template_pcap_path)
        
        assoc = {a[0]: a[1] for a in self.attackers}
        assoc.update({v[0]: v[1] for v in self.victims})

        rel_time = 0

        for self.pkt_num, pkt in enumerate(raw_packets):
            if self.pkt_num == 0:
                rel_time = pkt.time

            eth_frame = pkt
            ip_pkt = eth_frame.payload

            src_ip = ip_pkt.src
            src_mac = eth_frame.src
            dst_ip = ip_pkt.dst
            dst_mac = eth_frame.dst

            if src_ip in assoc:
                eth_frame.src = assoc[src_ip]
            if dst_ip in assoc:
                eth_frame.dst = assoc[dst_ip]
            
            new_pkt = (eth_frame / ip_pkt)
            new_time = pkt.time-rel_time

            timestamp_next_pkt += new_time
            new_pkt.time = timestamp_next_pkt

            self.add_packet(new_pkt, src_ip, dst_ip)

        return
        # omnetpp.ini, ipconfig.xml configuration creation
        # omnetpp run
        # template pcap retrieve




        # Stores triples of (timestamp, source_id, destination_id) for each timestamp.
        # Victim has id=0. Attacker tuple does not need to specify the destination because it's always the victim.
        timestamps_tuples = []
        # For each attacker(id), stores the current source-ports of SYN-packets
        # which still have to be acknowledged by the victim, as a "FIFO" for each attacker
        previous_attacker_port = []
        replies_count = 0
        already_used_pkts = 0
        sum_diff = 0

        self.attack_start_utime = self.get_param_value(self.INJECT_AT_TIMESTAMP)
        self.timestamp_controller.set_pps(attacker_pps)
        attack_ends_time = self.timestamp_controller.get_timestamp() + attack_duration

        # For each attacker, generate his own packets, then merge all packets
        for attacker in range(num_attackers):
            # set latency limit to either the minimal latency occurring in the pcap, the default or the user specified limit
            # get minimal and maximal latency found in the pcap
            if not latency_limit:
                min_latency, max_latency = self.get_reply_latency(ip_attackers_list[attacker], ip_destination)
                latency_limit = min_latency

            # Initialize empty port "FIFO" for current attacker
            previous_attacker_port.append([])
            # Calculate timestamp of first SYN-packet of attacker
            timestamp_next_pkt = self.timestamp_controller.reset_timestamp()
            if attacker != 0:
                timestamp_next_pkt = rnd.uniform(timestamp_next_pkt,
                                                 self.timestamp_controller.next_timestamp(latency=latency_limit))
            # calculate each attackers packet count without exceeding the total number of attackers
            attacker_pkts_num = 0
            if already_used_pkts < pkts_num:
                random_offset = rnd.randint(0, int(pkts_num / num_attackers / 2))
                if attacker == num_attackers-1:
                    random_offset = 0
                attacker_pkts_num = int((pkts_num - already_used_pkts) / (num_attackers - attacker)) + random_offset
                already_used_pkts += attacker_pkts_num
                # each attacker gets a different pps according to his pkt count offset
                ratio = float(attacker_pkts_num) / float(pkts_num)
                attacker_pps = pps * ratio
                self.timestamp_controller.set_pps(attacker_pps)

            for pkt_num in range(attacker_pkts_num):
                # Count attack packets that exceed the attack duration
                if timestamp_next_pkt > attack_ends_time:
                    diff = timestamp_next_pkt-attack_ends_time
                    sum_diff += diff
                    self.exceeding_packets += 1

                # Add timestamp of attacker SYN-packet. Attacker tuples do not need to specify destination
                timestamps_tuples.append((timestamp_next_pkt, attacker+1))

                # Calculate timestamp of victim ACK-packet
                timestamp_reply = self.timestamp_controller.next_timestamp(latency=latency_limit)

                # Add timestamp of victim ACK-packet(victim always has id=0)
                timestamps_tuples.append((timestamp_reply, 0, attacker+1))

                # Calculate timestamp for next attacker SYN-packet
                self.timestamp_controller.set_timestamp(timestamp_next_pkt)
                timestamp_next_pkt = self.timestamp_controller.next_timestamp()

        # Sort timestamp-triples according to their timestamps in ascending order
        timestamps_tuples.sort(key=lambda tmstmp: tmstmp[0])
        self.attack_start_utime = timestamps_tuples[0][0]

        # For each triple, generate packet
        for timestamp in timestamps_tuples:
            # tuple layout: [timestamp, attacker_id]

            # If current current triple is an attacker
            if timestamp[1] != 0:

                attacker_id = timestamp[1]-1
                # Build request package
                # Select one IP address and its corresponding MAC address
                ip_source = ip_attackers_list[attacker_id]
                mac_source = mac_attackers_list[attacker_id]

                # Determine source port
                (port_source, ttl_value) = Util.get_attacker_config(ip_attackers_list, ip_source)

                # If source ports were specified by the user, get random port from specified ports
                if port_source_list[0] != self.default_port:
                    port_source = rnd.choice(port_source_list)

                # Push port of current attacker SYN-packet into port "FIFO" of the current attacker
                # only if victim can still respond, otherwise, memory is wasted
                if replies_count <= victim_buffer:
                    previous_attacker_port[attacker_id].insert(0, port_source)

                request_ether = inet.Ether(dst=mac_destination, src=mac_source)
                request_ip = inet.IP(src=ip_source, dst=ip_destination, ttl=ttl_value)
                # Random win size for each packet
                source_win_size = rnd.choice(source_win_sizes)
                request_tcp = inet.TCP(sport=port_source, dport=port_destination, flags='S', ack=0,
                                       window=source_win_size)

                request = (request_ether / request_ip / request_tcp)
                request.time = timestamp[0]

                pkt = request

            # If current triple is the victim
            elif replies_count <= victim_buffer:
                # Build reply package
                attacker_id = timestamp[2]-1
                ip_source = ip_attackers_list[attacker_id]

                reply_ether = inet.Ether(src=mac_destination, dst=mac_attackers_list[attacker_id])
                reply_ip = inet.IP(src=ip_destination, dst=ip_source, flags='DF')
                # Pop port from attacker's port "FIFO" into destination port
                reply_tcp = inet.TCP(sport=port_destination, dport=previous_attacker_port[attacker_id].pop(), seq=0,
                                     ack=1, flags='SA', window=destination_win_value, options=[('MSS', mss_dst)])
                reply = (reply_ether / reply_ip / reply_tcp)

                reply.time = timestamp[0]

                pkt = reply
            else:
                continue

            result = self.add_packet(pkt, ip_source, ip_destination)

            if result == 1:
                replies_count += 1

            if self.buffer_full():
                self.flush_packets()

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
