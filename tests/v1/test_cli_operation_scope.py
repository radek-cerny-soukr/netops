import contextlib
import io
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from netops import cli, operator, health
from netops.diagnostics import OPERATION_SUFFIX, operation_error
from netops.state import OperatorAccessError, StateCompatibilityError

CANARY = "SYNTHETIC-PRIVATE-OS-DETAIL"
FAILURE = "Operation failed; inspect private state and audit before retrying"
PERMISSION = "NetOps could not access required files; check ownership and permissions"


class CliOperationScope(unittest.TestCase):
    cases = (
        (["token", "show"], cli, "read_private"),
        (["token", "rotate"], cli, "write_private"),
        (["ca", "export"], cli, "read_private"),
        (["ca", "rotate"], operator, "acquire_state"),
        (["connection"], cli, "read_private"),
        (["audit", "recover"], operator, "acquire_state"),
        (["health"], health, "check"),
        (["admin", "doctor"], operator, "acquire_state"),
        (["auditor", "import-snapshot", "--name", "example"], operator, "acquire_state"),
    )

    def call(self, arguments, module, attribute, error):
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            (state / "gateway/config.json").write_text("{}")
            (state / "gateway/config.json").chmod(0o600)
            with patch.object(cli, "STATE", state), patch.object(cli.os, "geteuid", return_value=0), \
                    patch.object(module, attribute, side_effect=error), \
                    patch.object(sys, "argv", ["netops", *arguments]), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(cli.main(), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(CANARY, errors.getvalue())
        return errors.getvalue()

    def test_nonconfiguration_os_faults_use_neutral_operation_guidance(self):
        for arguments, module, attribute in self.cases:
            for kind, message in ((OSError, FAILURE), (PermissionError, PERMISSION)):
                with self.subTest(command=arguments, kind=kind.__name__):
                    self.assertEqual(self.call(arguments, module, attribute, kind(CANARY)),
                                     "netops: " + message + OPERATION_SUFFIX)

    def test_configure_keeps_configuration_guidance(self):
        for role in ("helper", "admin", "auditor"):
            for kind, message in (
                (OSError, "Configuration operation failed; inspect private state and audit before retrying"),
                (PermissionError, "Configuration could not access required files; check ownership and permissions"),
            ):
                with self.subTest(role=role, kind=kind.__name__):
                    self.assertEqual(self.call(["configure", role], operator, "acquire_state", kind(CANARY)),
                                     "netops: " + message + OPERATION_SUFFIX)

    def test_known_state_access_and_audit_refusals_keep_precedence(self):
        for error in (
            StateCompatibilityError("Fixed state compatibility refusal"),
            OperatorAccessError("Fixed operator access refusal"),
            operation_error("audit-unavailable"),
        ):
            with self.subTest(kind=type(error).__name__):
                self.assertEqual(self.call(["admin", "doctor"], operator, "acquire_state", error),
                                 "netops: " + str(error) + OPERATION_SUFFIX)


if __name__ == "__main__":
    unittest.main()
