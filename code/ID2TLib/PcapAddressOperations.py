from random import choice

from Core import Statistics
from ID2TLib.IPv4 import IPAddress

is_ipv4 = IPAddress.is_ipv4

class PcapAddressOperations():

    def __init__(self, statistics: Statistics, uncertain_ip_mult: int=3):
        """
        Initializes a pcap information extractor that uses the provided statistics for its operations.

        :param statistics: The statistics of the pcap file
        :param uncertain_ip_mult: the mutliplier to create new address space when the remaining observed space has been drained
        """
        self.statistics = statistics
        self.UNCERTAIN_IPSPACE_MULTIPLIER = uncertain_ip_mult

        stat_result = self.statistics.process_db_query("most_used(macAddress)", print_results=False)
        if isinstance(stat_result, list):
            self.probable_router_mac = choice(stat_result)
        else:
            self.probable_router_mac = stat_result

        self._init_ipaddress_ops()

    def get_probable_router_mac(self):
        """
        Returns the most probable router MAC address based on the most used MAC address in the statistics.
        :return: the MAC address
        """
        return self.probable_router_mac

    def pcap_contains_priv_ips(self):
        """
        Returns if the provided traffic contains private IPs.
        :return: True if the provided traffic contains private IPs, otherwise False
        """
        return self.contains_priv_ips

    def get_local_address_range(self):
        """
        Returns a tuple with the start and end of the observed local IP range.
        :return: The IP range as tuple
        """
        return str(self.min_local_ip), str(self.max_local_ip)

    def get_count_rem_local_ips(self):
        """
        Returns the number of local IPs in the pcap file that have not aldready been returned by get_existing_local_ips.
        :return: the not yet assigned local IPs
        """
        return len(self.remaining_local_ips)

    def get_existing_local_ips(self, count: int=1):
        """
        Returns the given number of local IPs that are existent in the pcap file.

        :param count: the number of local IPs to return
        :return: the chosen local IPs
        """

        if count > len(self.remaining_local_ips):
            print("Warning: There are no more {} local IPs in the .pcap file. Returning all remaining local IPs.".format(count))

        total = min(len(self.remaining_local_ips), count)

        retr_local_ips = []
        local_ips = self.remaining_local_ips
        for _ in range(0, total):
            random_local_ip = choice(sorted(local_ips))
            retr_local_ips.append(str(random_local_ip))
            local_ips.remove(random_local_ip)

        return retr_local_ips

    def get_new_local_ips(self, count: int=1):
        """
        Returns in the pcap not existent local IPs that are in proximity of the observed local IPs. IPs can be returned
        that are either between the minimum and maximum observed IP and are therefore considered certain
        or that are above the observed maximum address, are more likely to not belong to the local network 
        and are therefore considered uncertain.

        :param count: the number of new local IPs to return
        :return: the newly created local IP addresses
        """

        unused_local_ips = self.unused_local_ips
        uncertain_local_ips = self.uncertain_local_ips
        count_certain = min(count, len(unused_local_ips))
        retr_local_ips = []

        for _ in range(0, count_certain):
            random_local_ip = choice(sorted(unused_local_ips))
            retr_local_ips.append(str(random_local_ip))
            unused_local_ips.remove(random_local_ip)

        # retrieve uncertain local ips
        if count_certain < count:
            count_uncertain = count - count_certain

            # check if new uncertain IPs have to be created
            if len(uncertain_local_ips) < count_uncertain:
                ipspace_multiplier = self.UNCERTAIN_IPSPACE_MULTIPLIER

                max_new_ip = self.max_uncertain_local_ip.to_int() + ipspace_multiplier * count_uncertain

                count_new_ips = max_new_ip - self.max_uncertain_local_ip.to_int()

                # create ipspace_multiplier * count_uncertain new uncertain local IP addresses
                last_gen_ip = None
                for i in range(1, count_new_ips + 1):
                    ip = IPAddress.from_int(self.max_uncertain_local_ip.to_int() + i)
                    # exclude the definite broadcast address
                    if self.priv_ip_segment:
                        if ip.to_int() >= self.priv_ip_segment.last_address().to_int():
                            break
                    uncertain_local_ips.add(ip)
                    last_gen_ip = ip
                self.max_uncertain_local_ip = last_gen_ip

            # choose the uncertain IPs to return
            total_uncertain = min(count_uncertain, len(uncertain_local_ips))
            for _ in range(0, total_uncertain):
                random_local_ip = choice(sorted(uncertain_local_ips))
                retr_local_ips.append(str(random_local_ip))
                uncertain_local_ips.remove(random_local_ip)
            
        return retr_local_ips

    def get_existing_external_ips(self, count: int=1):
        """
        Returns the given number of external IPs that are existent in the pcap file.

        :param count: the number of external IPs to return
        :return: the chosen external IPs
        """

        if not (len(self.external_ips) > 0):
            print("Warning: .pcap does not contain any external ips.")
            return []

        total = min(len(self.remaining_external_ips), count)
        retr_external_ips = []
        external_ips = self.remaining_external_ips

        for _ in range(0, total):
            random_external_ip = choice(sorted(external_ips))
            retr_external_ips.append(str(random_external_ip))
            external_ips.remove(random_external_ip)

        return retr_external_ips

    def _init_ipaddress_ops(self):
        """
        Load and process data needed to perform functions on the IP addresses contained in the statistics
        """

        # retrieve local and external IPs
        all_ips_str = set(self.statistics.process_db_query("all(ipAddress)", print_results=False))
        external_ips_str = set(self.statistics.process_db_query("ipAddress(macAddress=%s)" % self.get_probable_router_mac(), print_results=False))  # including router
        local_ips_str = all_ips_str - external_ips_str
        external_ips = set()
        local_ips = set()
        self.contains_priv_ips = False
        self.priv_ip_segment = None

        # convert local IP strings to IPv4.IPAddress representation
        for ip in local_ips_str:
            if is_ipv4(ip):
                ip = IPAddress.parse(ip)
                if ip.is_private() and not self.contains_priv_ips:
                    self.contains_priv_ips = True
                    self.priv_ip_segment = ip.get_private_segment()
                # exclude local broadcast address and other special addresses
                if (not str(ip) == "255.255.255.255") and (not ip.is_localhost()) and (not ip.is_multicast()) and (not ip.is_reserved()) and (not ip.is_zero_conf()):
                    local_ips.add(ip)

        # convert external IP strings to IPv4.IPAddress representation
        for ip in external_ips_str:
            if is_ipv4(ip):
                ip = IPAddress.parse(ip)
                # if router MAC can definitely be mapped to local/private IP, add it to local_ips (because at first it is stored in external_ips, see above)
                # this depends on whether the local network is identified by a private IP address range or not.
                if ip.is_private():
                    local_ips.add(ip)
                # exclude local broadcast address and other special addresses
                elif (not str(ip) == "255.255.255.255") and (not ip.is_localhost()) and (not ip.is_multicast()) and (not ip.is_reserved()) and (not ip.is_zero_conf()):
                    external_ips.add(ip)

        min_local_ip, max_local_ip = min(local_ips), max(local_ips)

        # save the certain unused local IPs of the network
        unused_local_ips = set()
        for i in range(min_local_ip.to_int() + 1, max_local_ip.to_int()):
            ip = IPAddress.from_int(i)
            if not ip in local_ips:
                unused_local_ips.add(ip)

        # save the gathered information for efficient later use
        self.external_ips = frozenset(external_ips)
        self.remaining_external_ips = external_ips
        self.min_local_ip, self.max_local_ip = min_local_ip, max_local_ip
        self.max_uncertain_local_ip = max_local_ip
        self.local_ips = frozenset(local_ips)
        self.remaining_local_ips = local_ips
        self.unused_local_ips = unused_local_ips
        self.uncertain_local_ips = set()