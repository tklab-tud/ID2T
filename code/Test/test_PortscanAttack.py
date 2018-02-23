import Test.ID2TAttackTest as Test

sha_portscan_default = '6af539fb9f9a28f84a5c337a07dbdc1a11885c5c6de8f9a682bd74b89edc5130'
sha_portscan_reverse_ports = '1c03342b7b94fdd1c9903d07237bc5239ebb7bd77a3dd137c9c378fa216c5382'
sha_portscan_shuffle_dst_ports = '40485e47766438425900b787c4cda4ad1b5cd0d233b80f38bd45b5a88b70a797'
sha_portscan_shuffle_src_ports = '48578b45e18bdbdc0a9f3f4cec160ccb58839250348ec4d3ec44c1b15da248de'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_ips_not_in_pcap = '7f0f65beb8398fc1abe65b0819b6e3a5ce143fd8c9eafb2d5498b84f21cec9e1'

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
