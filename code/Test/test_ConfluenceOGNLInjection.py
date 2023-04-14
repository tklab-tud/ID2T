import Test.ID2TAttackTest as Test

class UnitTestConfluenceOGNLInjection(Test.ID2TAttackTest):
    def test_confluence_OGNL_injection_basic(self): 
        self.order_test([['ConfluenceOGNLInjection']])

    def test_confluence_OGNL_injection_ips_not_in_pcap(self):
        self.order_test([['ConfluenceOGNLInjection', 'ip.src=12.23.211.21', 'ip.dst=2.131.44.20']])

    def test_confluence_OGNL_injection_mac(self): 
        self.order_test([['ConfluenceOGNLInjection','mac.src=00:0C:21:1C:60:61','mac.dst=04:0C:32:2C:63:62',]])