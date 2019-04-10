import lea
import random as rnd


class TimestampController:

    def __init__(self, timestamp: float, pps: float):
        """

        :param timestamp: the base timestamp to update
        :param pps: the packets per second for request pkts
        :return:
        """
        self.first_timestamp = timestamp
        self.previous_timestamp = timestamp
        self.pps = pps

    def get_pps(self):
        """

        :return:
        """
        return self.pps

    def set_pps(self, pps: float):
        """

        :param pps:
        """
        self.pps = pps

    def get_timestamp(self):
        """

        :return:
        """
        return self.previous_timestamp

    def reset_timestamp(self):
        """

        :return:
        """
        self.previous_timestamp = self.first_timestamp
        return self.previous_timestamp

    def set_timestamp(self, timestamp: int):
        """

        :param timestamp:
        """
        self.previous_timestamp = timestamp

    def next_timestamp(self, latency: float=0):
        """
        Calculates the next timestamp to be used based on the packet per second rate (pps) and the maximum delay.
        Parameter consideration order: latency > pps > default delay

        :param latency: the latency for reply pkts
        :return: timestamp to be used for the next packet.
        """
        # get delay by pps
        delay = 1 / self.pps

        if latency != 0:
            # Calculate reply timestamp
            delay = latency
        #else Calculate request timestamp

        random_delay = lea.Lea.fromValFreqsDict({delay * 1.3: 12, delay * 1.2: 13, delay * 1.1: 15, delay: 20,
                                                 delay / 1.1: 15, delay / 1.2: 13, delay / 1.3: 12})
        delay = rnd.uniform(delay, random_delay.random())

        # add latency or delay to timestamp
        self.previous_timestamp = self.previous_timestamp + delay
        return self.previous_timestamp