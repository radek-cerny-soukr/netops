import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import cli, health, operator, bootstrap
from netops.diagnostics import OPERATION_SUFFIX

HINT = "NetOps is not initialized; run docker compose run --rm netops init first"
CANARY = "SYNTHETIC-PRIVATE-TOKEN-CANARY"


class InitializationGuidance(unittest.TestCase):
    def call(self, arguments, state, uid=0):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(cli, "STATE", state), patch.object(health, "STATE", state), \
                patch.object(operator, "STATE", state), patch.object(bootstrap, "STATE", state), \
                patch.object(cli.os, "geteuid", return_value=uid), \
                patch.object(sys, "argv", ["netops", *arguments]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cli.main()
        return code, output.getvalue(), errors.getvalue()

    def test_missing_initialization_has_exact_hint_across_read_and_maintenance_commands(self):
        commands = (["ca"], ["ca", "rotate"], ["token", "show"], ["token", "rotate"],
                    ["connection"], ["audit", "show"], ["audit", "tail"], ["audit", "pending"],
                    ["audit", "stats"], ["audit", "recover"], ["health"], ["serve"])
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            for arguments in commands:
                with self.subTest(command=arguments):
                    uid = 51000 if arguments == ["health"] else 0
                    self.assertEqual(self.call(arguments, state, uid),
                                     (2, "", "netops: " + HINT + OPERATION_SUFFIX))
                    self.assertEqual(list((state / "gateway").iterdir()), [])

    def test_partial_token_is_neither_disclosed_nor_rotated_without_config(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            token = state / "gateway/token"
            token.write_bytes(CANARY.encode())
            token.chmod(0o600)
            for action in ("show", "rotate"):
                with self.subTest(action=action):
                    self.assertEqual(self.call(["token", action], state),
                                     (2, "", "netops: " + HINT + OPERATION_SUFFIX))
                    self.assertEqual(token.read_bytes(), CANARY.encode())

    def test_present_config_and_missing_material_are_not_reported_as_missing_init(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            (state / "gateway/config.json").write_text("{}")
            (state / "gateway/config.json").chmod(0o600)
            for arguments in (["token", "show"], ["ca"]):
                with self.subTest(command=arguments):
                    code, output, errors = self.call(arguments, state)
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertNotIn(HINT, errors)
                    self.assertIn("Operation failed; inspect private state and audit", errors)

    def test_malformed_and_symlink_config_are_not_missing_initialization(self):
        from netops.files import UIDS
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            path = state / "gateway/config.json"
            with patch.dict(UIDS, {"gateway": os.getuid()}):
                for symlink in (False, True):
                    path.unlink(missing_ok=True)
                    if symlink:
                        path.symlink_to("absent-target")
                    else:
                        path.write_text(CANARY)
                        path.chmod(0o600)
                    with self.subTest(symlink=symlink):
                        code, output, errors = self.call(["connection"], state)
                        self.assertEqual(code, 2)
                        self.assertEqual(output, "")
                        self.assertNotIn(HINT, errors)
                        self.assertNotIn(CANARY, errors)

    def test_unsearchable_state_is_an_access_failure_not_missing_initialization(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            gateway = state / "gateway"
            gateway.mkdir(mode=0o700)
            gateway.chmod(0o000)
            try:
                code, output, errors = self.call(["token", "show"], state)
            finally:
                gateway.chmod(0o700)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertNotIn(HINT, errors)
            self.assertIn("NetOps could not access required files", errors)

    def test_nondirectory_state_is_an_operational_failure_not_missing_initialization(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            gateway = state / "gateway"
            gateway.write_text("synthetic regular file")
            code, output, errors = self.call(["connection"], state)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertNotIn(HINT, errors)
            self.assertIn("Operation failed; inspect private state and audit", errors)
            self.assertEqual(gateway.read_text(), "synthetic regular file")

    def test_uid_refusal_precedes_missing_initialization(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            for arguments in (["token", "show"], ["token", "rotate"], ["ca", "rotate"], ["audit", "recover"], ["health"]):
                with self.subTest(command=arguments):
                    code, output, errors = self.call(arguments, state, 1000)
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertNotIn(HINT, errors)
                    self.assertTrue("user" in errors or "Health runs only" in errors)
            self.assertEqual(list(state.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
