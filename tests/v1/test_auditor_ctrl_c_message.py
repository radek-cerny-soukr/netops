"""Ctrl+C in an operator `auditor` command ends with one line and rc 130, not a Python traceback (task 209)."""
import io
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

# Installed-image unit test: netops.operator needs fastmcp, which only the product image has (task 258, P3).
from netops import cli


class CtrlC(unittest.TestCase):
    def run_cli(self, command):
        err = io.StringIO()
        with patch.object(sys, "argv", ["netops", command, "collect"]), \
                patch("netops.operator.role_cli", side_effect=KeyboardInterrupt), redirect_stderr(err):
            return cli.main(), err.getvalue()

    def test_auditor_interrupt_is_one_line_rc_130(self):
        code, text = self.run_cli("auditor")
        self.assertEqual(code, 130)
        self.assertEqual(text, "netops: interrupted by the user\n")
        self.assertNotIn("Traceback", text)

    def test_admin_interrupt_is_not_changed(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_cli("admin")


if __name__ == "__main__":
    unittest.main()
