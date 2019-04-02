import unittest
import unittest.mock as mock
import Core.Controller as Ctrl


class TestController(unittest.TestCase):
    @mock.patch("builtins.print")
    def test_process_help(self, mock_print):
        Ctrl.Controller.process_help(None)
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_most_used(self, mock_print):
        Ctrl.Controller.process_help(["most_used"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_least_used(self, mock_print):
        Ctrl.Controller.process_help(["least_used"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_avg(self, mock_print):
        Ctrl.Controller.process_help(["avg"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_all(self, mock_print):
        Ctrl.Controller.process_help(["all"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_random(self, mock_print):
        Ctrl.Controller.process_help(["random"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_first(self, mock_print):
        Ctrl.Controller.process_help(["first"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_last(self, mock_print):
        Ctrl.Controller.process_help(["last"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_ipaddress(self, mock_print):
        Ctrl.Controller.process_help(["ipaddress"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_macaddress(self, mock_print):
        Ctrl.Controller.process_help(["macaddress"])
        self.assertTrue(mock_print.called)

    @mock.patch("builtins.print")
    def test_process_help_examples(self, mock_print):
        Ctrl.Controller.process_help(["examples"])
        self.assertTrue(mock_print.called)
