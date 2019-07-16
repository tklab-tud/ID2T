import Test.ID2TAttackTest as Test


class UnitTestMembersMgmtCommAttack(Test.ID2TAttackTest):
    def test_regression(self):
        self.order_test([['MembersMgmtCommAttack', 'hidden_mark=True']])
