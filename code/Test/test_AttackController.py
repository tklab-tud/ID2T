import unittest

import Core.AttackController as atkCtrl


class TestAttackController(unittest.TestCase):
    def test_choose_attack_correct_name(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("UnitTestA_UnitTestB"), "UnitTestA_UnitTestB")

    def test_choose_attack_lower_case(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("unittesta_unittestb"), "UnitTestA_UnitTestB")

    def test_choose_attack_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("UnitTestA"), "UnitTestA_UnitTestB")

    def test_choose_attack_lower_case_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("unittesta"), "UnitTestA_UnitTestB")

    def test_choose_attack_lower_case_invalid_name(self):
        with self.assertRaises(SystemExit):
            atkCtrl.AttackController.choose_attack("somewrongname")
