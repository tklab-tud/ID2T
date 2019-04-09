import Test.ID2TAttackTest as Test


class UnitTestMemcrashedSpooferAttack(Test.ID2TAttackTest):

    def test_memcrashed_spoofer_basic(self):
        self.order_test([['MemcrashedSpooferAttack']])

    def test_memcrashed_spoofer_ips_not_in_pcap(self):
        self.order_test([['MemcrashedSpooferAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']])
