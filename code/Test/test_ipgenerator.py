from ID2TLib.Generator import IPGenerator
import unittest


# FIXME: These tests rely on randomness. They are NOT repeatable, and therefore unsuitable as unittests!
class IPGeneratorTestCase(unittest.TestCase):
    IP_GENERATOR = None
    IP_SAMPLES = None
    IP_SAMPLES_NUM = 1000

    @classmethod
    def setUpClass(cls):
        cls.IP_GENERATOR = IPGenerator()
        cls.IP_SAMPLES = [cls.IP_GENERATOR.random_ip() for _ in range(cls.IP_SAMPLES_NUM)]

    def test_valid_ips(self):
        ip = None

        try:
            for ip in self.IP_SAMPLES:
                parts = ip.split(".")
                self.assertTrue(len(parts) == 4)

                numbers = [int(i) for i in parts]
                self.assertTrue(all(n in range(256) for n in numbers))
        except:
            self.fail("%s is not a valid IPv4" % ip)

    def test_generates_localhost_ip(self):
        self.assertFalse(any(ip.startswith("127.") for ip in self.IP_SAMPLES))

    def test_generates_private_ip(self):
        def private_ip(ip):
            private_starts = ["10.", "192.168."] + ["172.%i." % i for i in range(16, 32)]
            return any(ip.startswith(start) for start in private_starts)

        self.assertFalse(any(map(private_ip, self.IP_SAMPLES)))

    def test_unique_ips(self):
        self.assertTrue(len(self.IP_SAMPLES) == len(set(self.IP_SAMPLES)))

    def test_blacklist(self):
        generator = IPGenerator(blacklist=["42.0.0.0/8"])
        self.assertFalse(any(generator.random_ip().startswith("42.") for _ in range(self.IP_SAMPLES_NUM)))
