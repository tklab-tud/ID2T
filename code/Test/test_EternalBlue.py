import Test.ID2TAttackTest as Test

sha_default = 'c707492a0493efcf46a569c91fe77685286402ddfdff3c79e64157b3324dc9f6'

# TODO: improve coverage


class UnitTestEternalBlue(Test.ID2TAttackTest):

    def test_eternal_blue_default(self):
        self.checksum_test([['EternalBlueExploit']], sha_default)

    def test_eternal_blue_order(self):
        self.order_test([['EternalBlueExploit']])
