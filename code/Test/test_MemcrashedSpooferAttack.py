import Test.ID2TAttackTest as Test

sha_default = "85f8112304b346bf7381d6cbdf18e510f9a90ac641308cd743bd2d9eb3c2c6d2"
sha_ips_not_in_pcap = "b7a1149593be981fe1776889c43342033730cb8ba5b98b142581164986db3a77"


class UnitTestMemcrashedSpooferAttack(Test.ID2TAttackTest):
    def test_memcrashed_spoofer_default(self):
        self.checksum_test([['MemcrashedSpooferAttack']], sha_default)

    def test_memcrashed_spoofer_ips_not_in_pcap(self):
        self.checksum_test([['MemcrashedSpooferAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_memcrashed_spoofer_order(self):
        self.order_test([['MemcrashedSpooferAttack']])
