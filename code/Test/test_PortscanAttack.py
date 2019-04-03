import Test.ID2TAttackTest as Test

sha_portscan_default = 'f1e569bd81fb1b8aaf2ddd0d1d6f90e76879e678198359bda59d45f7a89b35a9'
sha_portscan_reverse_ports = '12a062d2f5c176378edaf5c82df843a3ce22c8d0d6f27eb00a0cc165941109ab'
sha_portscan_shuffle_dst_ports = 'bd9dd27bf7c6146c30c714c4e4dc72801d90dd6761c8ffefd015ee44819552c4'
sha_portscan_shuffle_src_ports = 'bfdafa4f0d73566e91063362c68d307de7e7b82a3bd74c5a59e442bc857a4c64'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '34b6c755b89dc6dae3c1170b52e321699f0ce5c134bfbc46ddad603ddf65d619'

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
