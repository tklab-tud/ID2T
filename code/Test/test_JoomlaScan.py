import Test.ID2TAttackTest as Test

class UnitTestJoomlaScan(Test.ID2TAttackTest):
     def test_joomla_basic(self): 
         self.order_test([['JoomlaScan']])

     def test_joomla_ips_not_in_pcap(self):
         self.order_test([['JoomlaScan', 'ip.src=12.23.211.21', 'ip.dst=2.131.44.20']])

     def test_joomla_mac(self): 
         self.order_test([['JoomlaScan','mac.src=00:0C:21:1C:60:61','mac.dst=04:0C:32:2C:63:62',]])

     def test_joomla_port_destination(self):
         self.order_test([['JoomlaScan','port.dst=3300']])