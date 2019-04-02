import unittest

import Core.AttackController as atkCtrl


class TestAttackController(unittest.TestCase):
    def test_choose_attack_correct_name(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("DDoSAttack"), "DDoSAttack")

    def test_choose_attack_lower_case(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("ddosattack"), "DDoSAttack")

    def test_choose_attack_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("DDoS"), "DDoSAttack")

    def test_choose_attack_lower_case_no_ending(self):
        self.assertEqual(atkCtrl.AttackController.choose_attack("ddos"), "DDoSAttack")

    def test_choose_attack_lower_case_invalid_name(self):
        with self.assertRaises(SystemExit):
            atkCtrl.AttackController.choose_attack("somewrongname")
