import unittest

import Core.AttackController as atkCtrl


class TestAttackController(unittest.TestCase):
    def test_choose_attack_correct_name(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("UnitTestAttack"), "UnitTestAttack")

    def test_choose_attack_lower_case(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("unittestattack"), "UnitTestAttack")

    def test_choose_attack_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("UnitTest"), "UnitTestAttack")

    def test_choose_attack_lower_case_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("unittest"), "UnitTestAttack")

    def test_choose_attack_lower_case_invalid_name(self):
        with self.assertRaises(SystemExit):
            atkCtrl.AttackController.choose_attack("somewrongname")
