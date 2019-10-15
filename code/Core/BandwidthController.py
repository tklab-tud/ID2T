import Lib.Utility as Util

class BandwidthController:

    def __init__(self, custom_max_bandwidth: float=0, custom_bandwidth_local: float=0,
                 custom_bandwidth_public: float=0, statistics = None):
        """

        :param custom_max_bandwidth: maximum bandwidth to be set as a hard limit, discarding the pcaps bandwidth
        :param custom_bandwidth_local: bandwidth minimum for local traffic
        :param custom_bandwidth_public: bandwidth minimum for public traffic
        :param statistics: the statistics object of the current attack
        """
        self.custom_max_bandwidth = custom_max_bandwidth
        self.custom_bandwidth_local = custom_bandwidth_local
        self.custom_bandwidth_public = custom_bandwidth_public
        self.statistics = statistics

    def get_remaining_bandwidth(self, timestamp: int=0, ip_src: str= "", ip_dst: str= ""):
        """
        This function calculates the remaining bandwidth based on the maximum bandwidth available and the kbytes already
        sent inside the interval corresponding to the timestamp given.

        !!! custom_max_bandwidth is mutually exclusive to custom_bandwidth_local and/or custom_bandwidth_public
        :param timestamp: the timestamp of the current packet
        :param ip_src: the source IP
        :param ip_dst: the destination IP
        :return: the remaining bandwidth in kbyte/s
        """
        mode = Util.get_network_mode(ip_src, ip_dst)

        if self.custom_max_bandwidth != 0:
            bandwidth = self.custom_max_bandwidth
        else:
            bandwidth = self.statistics.get_kbyte_rate(mode, self.custom_bandwidth_local, self.custom_bandwidth_public)

        remaining_bandwidth = bandwidth

        current_table = self.statistics.stats_db.get_current_interval_statistics_table()
        kbytes_sent, interval = self.statistics.get_interval_stat(table_name=current_table, field="kbytes",
                                                                  timestamp=timestamp)
        if not kbytes_sent:
            kbytes_sent = 0
        kbytes_sent = kbytes_sent

        duration = self.statistics.get_current_interval_len()
        used_bandwidth = float((kbytes_sent * 1000) / duration)
        remaining_bandwidth -= used_bandwidth
        return remaining_bandwidth, interval
