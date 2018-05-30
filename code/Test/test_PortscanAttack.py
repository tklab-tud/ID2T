import Test.ID2TAttackTest as Test

sha_portscan_default = '6b594d6384036c2c1dbf59ea8b7c56e644001255ca464450b6d082db65063018'
sha_portscan_reverse_ports = 'ea2972c5a544ed395122e05673f6635b932c6141cfb934aa3b98764bfd75c261'
sha_portscan_shuffle_dst_ports = '093feb6281627c0cf744cecc1587805f1d8ccbdd225aedc78943e67903f607f4'
sha_portscan_shuffle_src_ports = 'f1656aae0f813a5f54eb5eb10ece6971aab11c05fb783a7d38b6ee5960c53499'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '94568a8cd53d55ec903ef13334eae7db71f4ade765afa6510eb4a7f2e05ba89b'

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
