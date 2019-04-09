import Test.ID2TAttackTest as Test


class UnitTestDDoS(Test.ID2TAttackTest):

    def test_ddos_basic(self):
        self.order_test([['DDoSAttack']])

    def test_ddos_num_attackers(self):
        self.order_test([['DDoSAttack', 'attackers.count=5']])

    def test_ddos_one_ip(self):
        self.order_test([['DDoSAttack', 'ip.src=1.1.1.1']])

    def test_ddos_ip_range(self):
        self.order_test([['DDoSAttack', 'ip.src=1.1.1.1-1.1.1.10']])

    def test_ddos_port_range(self):
        self.order_test([['DDoSAttack', 'attackers.count=5', 'port.src=1000-2000']])
