import Test.ID2TAttackTest as Test

sha_default = 'a45bd543ae7416cdc5fd76c886f48990b43075753931683407686aac2cfbc111'

# TODO: improve coverage


class UnitTestJoomla(Test.ID2TAttackTest):

    def test_joomla_default(self):
        self.checksum_test([['JoomlaRegPrivExploit']], sha_default)

    def test_joomla_order(self):
        self.order_test([['JoomlaRegPrivExploit']])
