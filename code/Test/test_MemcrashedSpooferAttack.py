import Test.ID2TAttackTest as Test

sha_default = "4d670567a16bcf917447753a0bad731e7d3c0bede76f73c7e1d182c5943d3d13"
sha_ips_not_in_pcap = "f5907db8e8054cf9ef38d4444c7d3d49c5cef16e67956e03aa3e2cbe3fff02de"


class UnitTestMemcrashedSpooferAttack(Test.ID2TAttackTest):
    def test_memcrashed_spoofer_default(self):
        self.checksum_test([['MemcrashedSpooferAttack']], sha_default)

    def test_memcrashed_spoofer_ips_not_in_pcap(self):
        self.checksum_test([['MemcrashedSpooferAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_ips_not_in_pcap)

    def test_memcrashed_spoofer_order(self):
        self.order_test([['MemcrashedSpooferAttack']])
