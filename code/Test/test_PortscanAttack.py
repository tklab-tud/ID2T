import Test.ID2TAttackTest as Test

sha_portscan_default = '1b08b88ad12c968d303cb4bef6595004b9b2b2d865dfbce702c29b5b272fbf84'
sha_portscan_reverse_ports = 'd4e0657f54665765edd56d59f863e1e0e414070a46d73ab1181ff6789abd3a98'
sha_portscan_shuffle_dst_ports = '53fd5a0fa97c8c778b5b8803347ce86aaf7ebb8bb2e1a288d26a694ade6174c9'
sha_portscan_shuffle_src_ports = '1129914c7f435262818461be32dc5fbb46f19671b8d62a89691fb6e1429e1fc4'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '32a9fd322b27f0fa4d51988d9f4c2afa854d8f9487399c4c2555f577f629ea28'

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
