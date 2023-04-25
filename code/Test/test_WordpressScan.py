import Test.ID2TAttackTest as Test

class UnitTestWordpressScan(Test.ID2TAttackTest):
    def test_wordpress_basic(self): 
        self.order_test([['WordpressScan']])

    def test_wordpress_ips_not_in_pcap(self):
        self.order_test([['WordpressScan', 'ip.src=12.23.211.21', 'ip.dst=2.131.44.20']])

    def test_wordpress_mac(self): 
        self.order_test([['WordpressScan','mac.src=00:0C:21:1C:60:61','mac.dst=04:0C:32:2C:63:62',]])

    def test_wordpress_port_source(self):
        self.order_test([['WordpressScan','port.src=3300']])