import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from netops import cli, operator
from netops.diagnostics import configuration_error

CANARY = "SYNTHETIC-PRIVATE-ERROR-MUST-NOT-APPEAR"
GENERIC = "netops: Configuration operation failed; inspect private state and audit before retrying; operation failed without automatic retry\n"

class ConfigureExceptionBoundary(unittest.TestCase):
    def invoke(self, function, role="auditor"):
        errors, output = io.StringIO(), io.StringIO()
        with patch.object(operator, "configure", function), \
                patch.object(sys, "argv", ["netops", "configure", role]), \
                contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
            rc = cli.main()
        self.assertEqual(rc, 2)
        self.assertEqual(output.getvalue(), "")
        return errors.getvalue()

    def test_untyped_validator_errors_never_cross_the_cli_boundary(self):
        for error in (ValueError(CANARY), UnicodeDecodeError("utf-8", b"\xff", 0, 1, CANARY)):
            with self.subTest(error=type(error).__name__):
                def reject(role):
                    raise error
                self.assertEqual(self.invoke(reject), GENERIC)

    def test_invalid_utf8_reaches_actual_input_parser_without_echoing_bytes(self):
        def actual_parser(role):
            stream = io.TextIOWrapper(io.BytesIO(b'{"tenant":"\xff"}'))
            with patch.object(operator.os, "geteuid", return_value=0), \
                    patch.object(operator, "acquire_state", return_value=99), \
                    patch.object(operator, "_operator_audit_preflight"), \
                    patch.object(operator, "demote"), patch.object(operator, "role_environment"), \
                    patch.object(operator.os, "close"), patch.object(sys, "stdin", stream):
                return operator.configure_auditor()
        self.assertEqual(self.invoke(actual_parser), "netops: Input JSON encoding is invalid; operation failed without automatic retry\n")

    def test_typed_renderer_retains_exact_schema_guidance(self):
        def reject(role):
            raise configuration_error(field="vault.version", code="version2")
        self.assertEqual(self.invoke(reject), "netops: Invalid role configuration: vault.version: version must be 2; operation failed without automatic retry\n")
