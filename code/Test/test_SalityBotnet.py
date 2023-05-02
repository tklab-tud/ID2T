import Test.ID2TAttackTest as Test


class UnitTestSalityBotnet(Test.ID2TAttackTest):

    def test_sality_basic(self):
        self.order_test([['SalityBotnet']])

    def test_sality_mac_source(self):
        self.order_test([['SalityBotnet', 'mac.src=00:19:36:v4:77:ey']])

    def test_sality_ip_source(self):
        self.order_test([['SalityBotnet', 'ip.src=213.146.212.41']])

    def test_sality_packets_per_second(self):
        self.order_test([['SalityBotnet', 'packets.per-second=400']])