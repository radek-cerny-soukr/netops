import argparse
import contextlib
import io
import subprocess
import sys
import unittest
from unittest.mock import patch
from netops import init


def arguments(**changes):
    values = {"audit": None, "accept_local_audit": False, "syslog_host": None, "syslog_port": 6514, "audit_budget": 268435456}
    values.update(changes)
    return argparse.Namespace(**values)


class InitAuditChoice(unittest.TestCase):
    def choose(self, answers, **changes):
        output = io.StringIO()
        replies = iter(answers)
        def reply(prompt=""):
            try:
                return next(replies)
            except StopIteration:
                raise EOFError from None
        with patch("builtins.input", reply), contextlib.redirect_stdout(output):
            audit = init.choose_audit(arguments(**changes))
        return audit, output.getvalue()

    def test_missing_terminal_explains_the_noninteractive_choices(self):
        with self.assertRaises(ValueError) as caught:
            self.choose([])
        self.assertEqual(str(caught.exception), init.NONINTERACTIVE)
        with self.assertRaises(ValueError) as caught:
            self.choose([""])
        self.assertEqual(str(caught.exception), init.NONINTERACTIVE)

    def test_interactive_local_warns_once_and_reports_local_limits(self):
        audit, output = self.choose(["", "LOCAL"])
        self.assertEqual(audit["mode"], "local")
        self.assertEqual(output.count(init.WARNING), 1)
        self.assertIn("local segments 16777216 bytes", output)

    def test_noninteractive_local_warns_once(self):
        audit, output = self.choose([], audit="local", accept_local_audit=True)
        self.assertEqual(audit["mode"], "local")
        self.assertEqual(output.count(init.WARNING), 1)

    def test_syslog_reports_only_the_delivery_queue(self):
        for answers, changes in ((["syslog.example.invalid", ""], {}), ([], {"audit": "syslog", "syslog_host": "syslog.example.invalid"})):
            with self.subTest(changes=changes):
                audit, output = self.choose(answers, **changes)
                self.assertEqual((audit["mode"], audit["host"], audit["port"]), ("syslog", "syslog.example.invalid", 6514))
                self.assertNotIn("local", output)
                self.assertNotIn(init.WARNING, output)
                self.assertIn("Audit queue budget: 268435456 bytes", output)

    def test_unaccepted_local_and_bad_port_are_refused_with_fixed_text(self):
        with self.assertRaisesRegex(ValueError, "^Local audit was not explicitly accepted$"):
            self.choose(["", "no"])
        with self.assertRaises(ValueError) as caught:
            self.choose(["syslog.example.invalid", "SYNTHETIC-PORT-CANARY"])
        self.assertEqual(str(caught.exception), "Syslog port must be a decimal port number")
        with self.assertRaisesRegex(ValueError, "^Noninteractive local audit requires --accept-local-audit$"):
            self.choose([], audit="local")


class Help(unittest.TestCase):
    def test_help_lists_operator_commands_and_hides_the_internal_worker(self):
        result = subprocess.run([sys.executable, "-B", "-m", "netops", "--help"], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SUPPRESS", result.stdout)
        self.assertNotIn("worker", result.stdout)
        for command in ("init", "configure", "ca", "token", "audit", "admin", "auditor"):
            self.assertIn(command, result.stdout)


if __name__ == "__main__":
    unittest.main()
