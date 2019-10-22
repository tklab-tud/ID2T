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
        self.current_timestamp = timestamp
        self.pps = pps

    def get_pps(self) -> float:
        """
        :return: the currently used packets per seconds
        """
        return self.pps

    def set_pps(self, pps: float):
        """
        :param pps: the packets per second for request pkts
        """
        self.pps = pps

    def get_timestamp(self) -> float:
        """
        :return: the base timestamp, which will be updated
        """
        return self.current_timestamp

    def reset_timestamp(self) -> float:
        """
        Resets the current timestamp to the timestamp the object was initialized with.
        :return: the base timestamp, which will be updated
        """
        self.current_timestamp = self.first_timestamp
        return self.current_timestamp

    def set_timestamp(self, timestamp: float):
        """
        :param timestamp: the base timestamp to update
        """
        self.current_timestamp = timestamp

    def next_timestamp(self, latency: float = 0) -> float:
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
        # Else calculate request timestamp

        random_delay = lea.Lea.fromValFreqsDict({delay * 1.3: 12, delay * 1.2: 13, delay * 1.1: 15, delay: 20,
                                                 delay / 1.1: 15, delay / 1.2: 13, delay / 1.3: 12})
        delay = rnd.uniform(delay, random_delay.random())

        # add latency or delay to timestamp
        self.current_timestamp = self.current_timestamp + delay
        return self.current_timestamp
