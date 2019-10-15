from random import choice

from Core import Statistics
from Lib.IPv4 import IPAddress

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

    def in_remaining_local_ips(self, ip: str) -> bool:
        """
        Returns if IP is exists in pcap.
        :return: True if the IP is in the remaining local ips, False if not
        """
        return ip in self.remaining_local_ips

    def get_existing_local_ips(self, count: int=1):
        """
        Returns the given number of local IPs that are existent in the pcap file.

        :param count: the number of local IPs to return
        :return: the chosen local IPs
        """

        if count <= 0:
            return []

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

        if count <= 0:
            return []

        # add more unused local ips to the pool, if needed
        while len(self.unused_local_ips) < count and self.expand_unused_local_ips() == True:
            pass

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
        # external_ips_str = set(self.statistics.process_db_query("ipAddress(macAddress=%s)" % self.get_probable_router_mac(), print_results=False))  # including router
        # local_ips_str = all_ips_str - external_ips_str
        external_ips = set()
        local_ips = set()
        all_ips = set()

        self.contains_priv_ips = False
        self.priv_ip_segment = None

        # convert IP strings to IPv4.IPAddress representation
        for ip in all_ips_str:
            if is_ipv4(ip):
                ip = IPAddress.parse(ip)
                # exclude local broadcast address and other special addresses
                if (not str(ip) == "255.255.255.255") and (not ip.is_localhost()) and (not ip.is_multicast()) and (
                not ip.is_reserved()) and (not ip.is_zero_conf()):
                    all_ips.add(ip)

        for ip in all_ips:
            if ip.is_private():
                local_ips.add(ip)

        external_ips = all_ips - local_ips

        # save the certain unused local IPs of the network
        # to do that, divide the unused local Addressspace into chunks of (chunks_size) Addresses
        # initally only the first chunk will be used, but more chunks can be added to the pool of unused_local_ips if needed
        self.min_local_ip, self.max_local_ip = min(local_ips), max(local_ips)
        local_ip_range = (self.max_local_ip.to_int()) - (self.min_local_ip.to_int() + 1)
        if local_ip_range < 0:
            # for min,max pairs like (1,1), (1,2) there is no free address in between, but for (1,1) local_ip_range may be -1, because 1-(1+1)=-1
            local_ip_range = 0

        # chunk size can be adjusted if needed
        self.chunk_size = 200

        self.current_chunk = 1
        if local_ip_range < self.chunk_size:
            # there are not more than chunk_size unused IP Addresses to begin with
            self.chunks = 0
            self.chunk_remainder = local_ip_range
        else:
            # determine how many chunks of (chunk_size) Addresses there are and the save the remainder
            self.chunks = local_ip_range // self.chunk_size
            self.chunk_remainder = local_ip_range % self.chunk_size

        # add the first chunk of IP Addresses
        self.unused_local_ips = set()
        self.expand_unused_local_ips()

        # save the gathered information for efficient later use
        self.external_ips = frozenset(external_ips)
        self.remaining_external_ips = external_ips
        self.max_uncertain_local_ip = self.max_local_ip
        self.local_ips = frozenset(local_ips)
        # print("External IPS: " + str(external_ips))
        # print("LOCAL IPS: " + str(local_ips))
        self.remaining_local_ips = local_ips
        self.uncertain_local_ips = set()

    def expand_unused_local_ips(self):
        """
        expands the set of unused_local_ips by one chunk_size
        to illustrate this algorithm: suppose we have a chunksize of 100 and an Address space of 1 to 1000 (1 and 1000 are unused too), we then have 10 chunks
        every time this method is called, one chunk (100 Addresses) is added, each chunk starts at the base_address + the number of its chunk
        then, every chunk_amounth'th Address is added. Therefore for 10 chunks, every 10th address is added
        For the above example for the first, second and last call, we get the following IPs, respectively:
        first Call:  1+0,  1+10,  1+20,  1+30, ...,  1+990
        second Call: 2+0,  2+10,  2+20,  2+30, ...,  2+990
        ten'th Call: 10+0, 10+10, 10+20, 10+30, ..., 10+990

        :return: False if there are no more available unusd local IP Addresses, True otherwise
        """

        if self.current_chunk == self.chunks+1:
            # all chunks are used up, therefore add the remainder
            remainder_base_addr = self.min_local_ip.to_int() + self.chunks*self.chunk_size + 1
            for i in range(0,self.chunk_remainder):
                ip = IPAddress.from_int(remainder_base_addr + i)
                self.unused_local_ips.add(ip)

            self.current_chunk = self.current_chunk + 1
            return True

        elif self.current_chunk <= self.chunks:
            # add another chunk
            # choose IPs from the whole address space, that is available
            base_address = self.min_local_ip.to_int() + self.current_chunk

            for i in range(0,self.chunk_size):
                ip = IPAddress.from_int(base_address + i*self.chunks)
                self.unused_local_ips.add(ip)

            self.current_chunk = self.current_chunk + 1
            return True

        else:
            # no free IPs remaining
            return False