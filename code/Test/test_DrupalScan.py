import Test.ID2TAttackTest as Test

class UnitTestDrupalScan(Test.ID2TAttackTest):
     def test_drupal_basic(self): 
         self.order_test([['DrupalScan']])

     def test_drupal_ips_not_in_pcap(self):
         self.order_test([['DrupalScan', 'ip.src=12.23.211.21', 'ip.dst=2.131.44.20']])

     def test_drupal_mac(self): 
         self.order_test([['DrupalScan','mac.src=00:0C:21:1C:60:61','mac.dst=04:0C:32:2C:63:62',]])

     def test_drupal_port_destination(self):
         self.order_test([['DrupalScan','port.dst=3300']])