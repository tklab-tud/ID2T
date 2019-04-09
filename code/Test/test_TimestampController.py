import unittest

import Core.TimestampController as tsCtrl


class TestTimestampController(unittest.TestCase):

    def test_update_timestamp_no_delay(self):
        timestamp = 100
        pps = 5
        latency = 1 / pps
        tc = tsCtrl.TimestampController(timestamp, pps)
        for i in range(100):
            val = tc.next_timestamp()
            print("\n{}\n".format(val))
            self.assertTrue(timestamp + latency / 1.3 <= val <= timestamp + latency * 1.3)
            timestamp = val

    def test_update_timestamp_with_delay(self):
        timestamp = 100
        pps = 5
        latency = 10
        tc = tsCtrl.TimestampController(timestamp, pps)
        for i in range(100):
            val = tc.next_timestamp(latency)
            print("\n{}\n".format(val))
            self.assertTrue(timestamp + latency / 1.3 <= val <= timestamp + latency * 1.3)
            timestamp = val

    def test_update_timestamp_comparison(self):
        timestamp = 100
        pps = 5
        latency = 10
        tc = tsCtrl.TimestampController(timestamp, pps)
        self.assertTrue(tc.next_timestamp() <= tc.next_timestamp(latency))