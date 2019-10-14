import Test.ID2TAttackTest as Test


class UnitTestP2PBotnet(Test.ID2TAttackTest):
    def test_regression(self):
        self.order_test([['P2PBotnet', 'hidden_mark=True']])
