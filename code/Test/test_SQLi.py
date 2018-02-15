import Test.ID2TAttackTest as Test

sha_default = 'a130ecdaf5fd8c09ef8418d2dbe7bd68c54e922553eb9fa703df016115393a46'

# TODO: improve coverage


class UnitTestSQLi(Test.ID2TAttackTest):

    def test_sqli_default(self):
        self.checksum_test([['SQLiAttack']], sha_default)
