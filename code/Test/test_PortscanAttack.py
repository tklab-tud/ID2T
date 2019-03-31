import Test.ID2TAttackTest as Test

sha_portscan_default = '24791d93b3af78ad2c4a3dc3f1f83b4c74d1a8ae732a45644158f6909a5ad3d8'
sha_portscan_reverse_ports = '3a12d359510a53e6cbb3c6b88096ad925d09e161aca55fc6f2b9aaf7333b7dc5'
sha_portscan_shuffle_dst_ports = '2dd91e8c9f4b5e1a661e4223376e551f3b409846c40d26cca0ec9e29d2ab2445'
sha_portscan_shuffle_src_ports = 'aba4de8d88fef6c8f3f799b31ecf6840681a58446ba7c438988f7a7c5ff445d0'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '8b740fe20fb7d2ad3d1f8008120198c6b19564c3b155919998a39f1e729f9c83'

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
