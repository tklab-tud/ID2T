import Test.ID2TAttackTest as Test

sha_portscan_default = 'b70c543c8d9bb4bf7ef8cfe09c23254a968c66a9f4174aea0ec2aa65bc1f090f'
sha_portscan_reverse_ports = '0ea771c6ded24cb667c00d490653ee620f5c29975e966d14dd5bba5008048eac'
sha_portscan_shuffle_dst_ports = 'dea87a34d21d7efa8128fa2d7471e2b4265ad4e150b00b24da8e182149e6fe81'
sha_portscan_shuffle_src_ports = 'cf0fe4c8f9d0d1f016aaebe6ce0a3d66af72d1c6cbc4c671391374506d7f5a9e'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = 'd4703defeaaf8d421f79eb15eb019eed6d4644448054cebcb0caba300d3e0012'

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
