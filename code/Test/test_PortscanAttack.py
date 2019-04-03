import Test.ID2TAttackTest as Test

sha_portscan_default = '2b4eaf1a98562711b0d223d4e3c7bf8804a8e5d5b252ec0bc3c1ded50a5a26dc'
sha_portscan_reverse_ports = '08f939da620a7f53f47f3e04663ea2f7329c6f42fd037022bc3870c8c8b825a3'
sha_portscan_shuffle_dst_ports = 'aac46bf9f645cd9278082491aa581f8690f999955316228a732b786004bc5a1c'
sha_portscan_shuffle_src_ports = '5781f72f330812c569afcc13a46882ccd42720fa0ba5a62b6bd65104d9d6847a'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '74bdc899509d7923c0ba98b3d4e1baea69386482d0198f19dc2e5db57cfd80ca'

# TODO: improve coverage


class UnitTestPortscanAttack(Test.ID2TAttackTest):
    def test_portscan_default(self):
        self.checksum_test([['PortscanAttack']], sha_portscan_default)

    def test_portscan_reverse_ports(self):
        self.checksum_test([['PortscanAttack', 'port.dst.order-desc=1']], sha_portscan_reverse_ports)

    def test_portscan_shuffle_dst_ports(self):
        self.checksum_test([['PortscanAttack', 'port.dst.shuffle=1']], sha_portscan_shuffle_dst_ports)

    def test_portscan_shuffle_src_ports(self):
        self.checksum_test([['PortscanAttack', 'port.src.shuffle=1']], sha_portscan_shuffle_src_ports)

    def test_portscan_ips_not_in_pcap(self):
        self.checksum_test([['PortscanAttack', 'ip.src=1.1.1.1', 'ip.dst=2.2.2.2']], sha_portscan_ips_not_in_pcap)

    def test_portscan_order(self):
        self.order_test([['PortscanAttack']])
