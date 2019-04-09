import Test.ID2TAttackTest as Test


class UnitTestSMBScan(Test.ID2TAttackTest):

    def test_smbscan_basic(self):
        self.order_test([['SMBScanAttack']])

    def test_smbscan_one_victim_linux(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']])

    def test_smbscan_ip_range(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                          'hosting.ip=192.168.178.5']])

    def test_smbscan_victims_macos(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                          'ip.dst=192.168.178.10,192.168.178.15,192.168.178.20',
                          'hosting.ip=192.168.178.15,192.168.178.20']])

    def test_smbscan_invalid_smb_version(self):
        with self.assertRaises(SystemExit):
            self.order_test([['SMBScanAttack', 'protocol.version=42']])

    def test_smbscan_invalid_smb_platform(self):
        with self.assertRaises(SystemExit):
            self.order_test([['SMBScanAttack', 'hosting.version=1337']])

    def test_smbscan_port_shuffle(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                          'hosting.ip=192.168.178.5', 'port.src.shuffle=false']])

    def test_smbscan_dest_mac_only(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'mac.dst=00:0C:29:9C:70:64']])

    def test_smbscan_src_ip_shuffle(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                          'hosting.ip=192.168.178.5', 'ip.src.shuffle=True']])

    def test_smbscan_smb2(self):
        self.order_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                          'hosting.ip=192.168.178.5', 'protocol.version=2.1', 'hosting.version=2.1']])
