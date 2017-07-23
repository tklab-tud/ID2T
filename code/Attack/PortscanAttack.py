import logging
import csv
import socket

# Aidmar
from operator import itemgetter
import math

from random import shuffle, randint, choice, uniform

from lea import Lea

from Attack import BaseAttack
from Attack.AttackParameters import Parameter as Param
from Attack.AttackParameters import ParameterTypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# noinspection PyPep8
from scapy.layers.inet import IP, Ether, TCP


class PortscanAttack(BaseAttack.BaseAttack):
    # Nmap default packet rate
    maxDefaultPPS = 300
    minDefaultPPS = 5

    # Aidmar
    def get_ports_from_nmap_service_dst(self, ports_num):
        """
        Read the most ports_num frequently open ports from nmap-service-tcp file to be used in Portscan attack.

        :return: Ports numbers to be used as default dest ports or default open ports in Portscan attack.
        """
        ports_dst = []
        spamreader = csv.reader(open('nmap-services-tcp.csv', 'rt'), delimiter=',')
        for count in range(ports_num):
            # escape first row (header)
            next(spamreader)
            # save ports numbers
            ports_dst.append(next(spamreader)[0])
        # shuffle ports numbers
        if(ports_num==1000): # used for port.dst
            temp_array = [[0 for i in range(10)] for i in range(100)]
            port_dst_shuffled = []
            for count in range(0, 9):
                temp_array[count] = ports_dst[count * 100:count * 100 + 99]
                shuffle(temp_array[count])
                port_dst_shuffled += temp_array[count]
        else: # used for port.open
            shuffle(ports_dst)
            port_dst_shuffled = ports_dst
        return port_dst_shuffled

 
    def is_valid_ip_address(self,addr):
        """
        Check if the IP address family is suported.

        :param addr: IP address to be checked
        :return: Boolean
        """
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False

    def __init__(self, statistics, pcap_file_path):
        """
        Creates a new instance of the PortscanAttack.

        :param statistics: A reference to the statistics class.
        """
        # Initialize attack
        super(PortscanAttack, self).__init__(statistics, "Portscan Attack", "Injects a nmap 'regular scan'",
                                             "Scanning/Probing")

        # Define allowed parameters and their type
        self.supported_params = {
            Param.IP_SOURCE: ParameterTypes.TYPE_IP_ADDRESS,
            Param.IP_DESTINATION: ParameterTypes.TYPE_IP_ADDRESS,
            Param.PORT_SOURCE: ParameterTypes.TYPE_PORT,
            Param.PORT_DESTINATION: ParameterTypes.TYPE_PORT,
            Param.PORT_OPEN: ParameterTypes.TYPE_PORT,
            Param.MAC_SOURCE: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.MAC_DESTINATION: ParameterTypes.TYPE_MAC_ADDRESS,
            Param.INJECT_AT_TIMESTAMP: ParameterTypes.TYPE_FLOAT,
            Param.INJECT_AFTER_PACKET: ParameterTypes.TYPE_PACKET_POSITION,
            Param.PORT_DEST_SHUFFLE: ParameterTypes.TYPE_BOOLEAN,
            Param.PORT_DEST_ORDER_DESC: ParameterTypes.TYPE_BOOLEAN,
            Param.IP_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN,
            Param.PACKETS_PER_SECOND: ParameterTypes.TYPE_FLOAT,
            Param.PORT_SOURCE_RANDOMIZE: ParameterTypes.TYPE_BOOLEAN
        }

        # PARAMETERS: initialize with default values
        # (values are overwritten if user specifies them)
        most_used_ip_address = self.statistics.get_most_used_ip_address()
        if isinstance(most_used_ip_address, list):
            most_used_ip_address = most_used_ip_address[0]

        self.add_param_value(Param.IP_SOURCE, most_used_ip_address)
        self.add_param_value(Param.IP_SOURCE_RANDOMIZE, 'False')
        self.add_param_value(Param.MAC_SOURCE, self.statistics.get_mac_address(most_used_ip_address))

        random_ip_address = self.statistics.get_random_ip_address()
        # Aidmar - ip-dst should be valid and not equal to ip.src
        while not self.is_valid_ip_address(random_ip_address) or random_ip_address==most_used_ip_address:
            random_ip_address = self.statistics.get_random_ip_address()

        self.add_param_value(Param.IP_DESTINATION, random_ip_address)
        destination_mac = self.statistics.get_mac_address(random_ip_address)
        if isinstance(destination_mac, list) and len(destination_mac) == 0:
            destination_mac = self.generate_random_mac_address()
        self.add_param_value(Param.MAC_DESTINATION, destination_mac)

        self.add_param_value(Param.PORT_DESTINATION, self.get_ports_from_nmap_service_dst(1000))
        #self.add_param_value(Param.PORT_DESTINATION, '1-1023,1720,1900,8080,56652')

        # Not used initial value
        self.add_param_value(Param.PORT_OPEN, '1,11,111,1111')

        self.add_param_value(Param.PORT_DEST_SHUFFLE, 'False')
        self.add_param_value(Param.PORT_DEST_ORDER_DESC, 'False')

        self.add_param_value(Param.PORT_SOURCE, randint(1024, 65535))
        self.add_param_value(Param.PORT_SOURCE_RANDOMIZE, 'False')

        # Aidamr - we used pps for sent packets, so no need to include received packets rate
        # most used ip not necessary provide a realsitic packet rate for portscan attack
        # calculating the pps is not accurate (taking the whole capture duration into account ingnores the intermittent
        # of packets flow)
        #self.add_param_value(Param.PACKETS_PER_SECOND,
                             #(self.statistics.get_pps_sent(most_used_ip_address) +
                             # self.statistics.get_pps_received(most_used_ip_address)) / 2)
        # Aidmar
        # using nmap empirically observed packet rate [5,300] packet per second
        self.add_param_value(Param.PACKETS_PER_SECOND,self.maxDefaultPPS)

        self.add_param_value(Param.INJECT_AFTER_PACKET, randint(0, self.statistics.get_packet_count()))

    def generate_attack_pcap(self):
        def update_timestamp(timestamp, pps, maxdelay):
            """
            Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.

            :return: Timestamp to be used for the next packet.
            """
            # Aidmar - why to use 0.1/pps?
            #return timestamp + uniform(0.1 / pps, maxdelay)
            # Aidmar
            return timestamp + uniform(1 / pps, maxdelay)

        mac_source = self.get_param_value(Param.MAC_SOURCE)
        mac_destination = self.get_param_value(Param.MAC_DESTINATION)
        pps = self.get_param_value(Param.PACKETS_PER_SECOND)
        # Aidmar - unjustified distribution
        # randomdelay = Lea.fromValFreqsDict({1 / pps: 70, 2 / pps: 20, 5 / pps: 7, 10 / pps: 3})
        # maxdelay = randomdelay.random()

        # Aidmar
        # Calculate the complement packet rates of the background traffic packet rates per interval
        result = self.statistics.process_db_query(
            "SELECT timestamp,pktsCount FROM interval_statistics ORDER BY timestamp")
        print(result)
        bg_interval_pps = []
        intervalsSum = 0
        if result:
            # Get the interval in seconds
            for i,row in enumerate(result):
                if i<len(result)-1:
                    intervalsSum += math.ceil((int(result[i+1][0]) * 10 ** -6) - (int(row[0]) * 10 ** -6))
            interval = intervalsSum/(len(result)-1)
            # Convert timestamp from micro to seconds, convert packet rate "per interval" to "per second"
            for row in result:
                bg_interval_pps.append((int(row[0]) * 10 ** -6, int(row[1]/interval)))
            # Find max PPS
            maxPPS = max(bg_interval_pps, key=itemgetter(1))[1]
            complement_interval_pps = []
            for row in bg_interval_pps:
                complement_interval_pps.append((row[0], int(pps * (maxPPS - row[1])/maxPPS)))
            print(complement_interval_pps)

        def getIntervalPPS(timestamp):
            for row in complement_interval_pps:
                if timestamp<=row[0]:
                    return row[1]
            return complement_interval_pps[-1][1] # in case the timstamp > capture max timestamp


        # Determine ports
        dest_ports = self.get_param_value(Param.PORT_DESTINATION)
        if self.get_param_value(Param.PORT_DEST_ORDER_DESC):
            dest_ports.reverse()
        elif self.get_param_value(Param.PORT_DEST_SHUFFLE):
            shuffle(dest_ports)
        if self.get_param_value(Param.PORT_SOURCE_RANDOMIZE):
            sport = randint(1, 65535)
        else:
            sport = self.get_param_value(Param.PORT_SOURCE)

        # Timestamp
        timestamp_next_pkt = self.get_param_value(Param.INJECT_AT_TIMESTAMP)
        # store start time of attack
        self.attack_start_utime = timestamp_next_pkt

        # Initialize parameters
        packets = []
        ip_source = self.get_param_value(Param.IP_SOURCE)
        ip_destination = self.get_param_value(Param.IP_DESTINATION)

        # Aidmar - check ip.src == ip.dst
        if ip_source == ip_destination:
            print("\nERROR: Invalid IP addresses; source IP is the same as destination IP: " + ip_source + ".")
            import sys
            sys.exit(0)

        # open ports
        # Aidmar
        ports_open = self.get_param_value(Param.PORT_OPEN)
        if ports_open == [1,11,111,1111]:  # user did not define open ports
            # the ports that were already used by ip.dst (direction in) in the background traffic are open ports
            ports_used_by_ip_dst = None #self.statistics.process_db_query(
                #"SELECT portNumber FROM ip_ports WHERE portDirection='in' AND ipAddress='" + ip_destination + "'")
            if ports_used_by_ip_dst:
                ports_open = ports_used_by_ip_dst
                print("\nPorts used by %s: %s" % (ip_destination, ports_open))
            else: # if no ports were retrieved from database
            # Take open ports from nmap-service file
                #ports_temp = self.get_ports_from_nmap_service_dst(100)
                #ports_open = ports_temp[0:randint(1,10)]
            # OR take open ports from the most used ports in traffic statistics
                ports_open = self.statistics.process_db_query(
                    "SELECT portNumber FROM ip_ports GROUP BY portNumber ORDER BY SUM(portCount) DESC LIMIT "+str(randint(1,10)))
                print("\nPorts retrieved from statistics: %s" % (ports_open))
        # in case of one open port, convert ports_open to array
        if not isinstance(ports_open, list):
            ports_open = [ports_open]
        # =========================================================================================================

        # MSS (Maximum Segment Size) for Ethernet. Allowed values [536,1500]
        # Aidmar
        mss_dst = self.statistics.get_most_used_mss(ip_destination)
        if mss_dst is None:
            mss_dst = self.statistics.process_db_query("most_used(mssValue)")
        mss_src = self.statistics.get_most_used_mss(ip_source)
        if mss_src is None:
            mss_src = self.statistics.process_db_query("most_used(mssValue)")
        # mss = self.statistics.get_mss(ip_destination)
        # =========================================================================================================

        # Set TTL based on TTL distribution of IP address
        ttl_dist = self.statistics.get_ttl_distribution(ip_source)
        if len(ttl_dist) > 0:
            ttl_prob_dict = Lea.fromValFreqsDict(ttl_dist)
            ttl_value = ttl_prob_dict.random()
        else:
            ttl_value = self.statistics.process_db_query("most_used(ttlValue)")

        # Aidmar
        replies = []

        for dport in dest_ports:
            # Aidmar - move to here to generate different maxdelay for each packet
            randomdelay = Lea.fromValFreqsDict({1 / pps: 85, 2 / pps: 10, 5 / pps: 5})
            maxdelay = randomdelay.random()

            # Parameters changing each iteration
            if self.get_param_value(Param.IP_SOURCE_RANDOMIZE) and isinstance(ip_source, list):
                ip_source = choice(ip_source)

            # 1) Build request package
            request_ether = Ether(src=mac_source, dst=mac_destination)
            request_ip = IP(src=ip_source, dst=ip_destination, ttl=ttl_value)

            # Aidmar - random src port for each packet
            sport = randint(1, 65535)
            # Aidmar - use most used window size
            win_size = self.statistics.process_db_query("most_used(winSize)")
            request_tcp = TCP(sport=sport, dport=dport,  window=win_size, flags='S', options=[('MSS', mss_src)])
            # =========================================================================================================

            request = (request_ether / request_ip / request_tcp)
            # first packet uses timestamp provided by attack parameter Param.INJECT_AT_TIMESTAMP
            """if len(packets) > 0:
                timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)
            request.time = timestamp_next_pkt
            """
            # Aidmar
            request.time = timestamp_next_pkt

            # 2) Build reply package
            if dport in ports_open:  # destination port is OPEN
                reply_ether = Ether(src=mac_destination, dst=mac_source)
                reply_ip = IP(src=ip_destination, dst=ip_source, flags='DF')
                #if mss_dst is None:
                #   reply_tcp = TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=29200)
                #else:
                reply_tcp = TCP(sport=dport, dport=sport, seq=0, ack=1, flags='SA', window=29200,
                                    options=[('MSS', mss_dst)])
                reply = (reply_ether / reply_ip / reply_tcp)
                # Aidmar - edit name timestamp_reply
                timestamp_reply = update_timestamp(timestamp_next_pkt, pps, maxdelay) # TO-DO


                if len(replies) > 0:
                    last_reply_timestamp = replies[-1].time
                    timestamp_reply = timestamp_next_pkt
                    while (timestamp_reply <= last_reply_timestamp):
                        timestamp_reply = update_timestamp(timestamp_reply, pps, maxdelay)
                else:
                    timestamp_reply = update_timestamp(timestamp_next_pkt, pps, maxdelay)

                reply.time = timestamp_reply
                replies.append(reply)

                # requester confirms
                # TO-DO: confirms should be in Attacker queue not in victim (reply) queue
                confirm_ether = request_ether
                confirm_ip = request_ip
                confirm_tcp = TCP(sport=sport, dport=dport, seq=1, window=0, flags='R')
                reply = (confirm_ether / confirm_ip / confirm_tcp)
                # Aidmar - edit name timestamp_confirm
                timestamp_confirm = update_timestamp(timestamp_reply, pps, maxdelay) # TO-DO
                reply.time = timestamp_confirm
                replies.append(reply)

                # else: destination port is NOT OPEN -> no reply is sent by target

            # Aidmar
            # Append reply
            if replies:
                while timestamp_next_pkt >= replies[0].time:
                    packets.append(replies[0])
                    replies.remove(replies[0])
                    if len(replies) == 0:
                        break

            # Append request
            packets.append(request)

            # Aidmar
            pps = self.minDefaultPPS if getIntervalPPS(timestamp_next_pkt) is None else max(getIntervalPPS(timestamp_next_pkt),1) # avoid case of pps = 0
            timestamp_next_pkt = update_timestamp(timestamp_next_pkt, pps, maxdelay)

        # Requests are sent all, send all replies
        if len(replies)>0:
            for reply in replies:
                packets.append(reply)

        # store end time of attack
        self.attack_end_utime = packets[-1].time

        # write attack packets to pcap
        pcap_path = self.write_attack_pcap(sorted(packets, key=lambda pkt: pkt.time))

        # return packets sorted by packet time_sec_start
        return len(packets), pcap_path
