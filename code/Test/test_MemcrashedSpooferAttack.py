import Test.ID2TAttackTest as Test

sha_default = "88c62360baee6067a8f0e9c002c329bf800b59aab2c7f97ccad5e76cfd00a5b2"
sha_ips_not_in_pcap = "83d47486673a87fda0bed8842e406738053cdff519746165565d71cda6d968cc"


class UnitTestMemcrashedSpooferAttack(Test.ID2TAttackTest):
    def test_memcrashed_spoofer_default(self):
        self.checksum_test([['MemcrashedSpooferAttack']], sha_default)

    def test_memcrashed_spoofer_ips_not_in_pcap(self):
        self.checksum_test([['MemcrashedSpooferAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_memcrashed_spoofer_order(self):
        self.order_test([['MemcrashedSpooferAttack']])
