import Test.ID2TAttackTest as Test

sha_default = "065e7de040fb41bcaad81b705fb70f3e07807f0d3dc1efe0f437929ff33b49f8"
sha_ips_not_in_pcap = "46c015fde4509227ee70fbe1557fe0efd3ac76abf58e00dcbbcf09d0b950fb5f"


class UnitTestMemcrashedSpooferAttack(Test.ID2TAttackTest):
    def test_memcrashed_spoofer_default(self):
        self.checksum_test([['MemcrashedSpooferAttack']], sha_default)

    def test_memcrashed_spoofer_ips_not_in_pcap(self):
        self.checksum_test([['MemcrashedSpooferAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_memcrashed_spoofer_order(self):
        self.order_test([['MemcrashedSpooferAttack']])
