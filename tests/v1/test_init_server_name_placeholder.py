import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import cli, init

PLACEHOLDER = "replace-me-with-certificate-dns-name"
REFUSAL = ("netops: NETOPS_SERVER_NAME is still the env.example placeholder; set it in .env to the exact DNS name"
           " your MCP clients will use; operation failed without automatic retry\n")
REACHED = "SYNTHETIC-PREPARE-REACHED"


class ServerNamePlaceholder(unittest.TestCase):
    def call(self, name, state):
        calls = []
        def prepare():
            calls.append(True)
            raise ValueError(REACHED)
        output, errors = io.StringIO(), io.StringIO()
        environment = {"NETOPS_BIND_IP": "127.0.0.1", "NETOPS_PORT": "8443", "NETOPS_SERVER_NAME": name}
        with patch.dict(os.environ, environment), patch.object(init, "STATE", state), \
                patch.object(init.os, "geteuid", return_value=0), \
                patch.object(init, "prepare", prepare), \
                patch.object(sys, "argv", ["netops", "init", "--audit", "local", "--accept-local-audit"]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cli.main()
        return code, output.getvalue(), errors.getvalue(), calls

    def test_placeholder_is_refused_before_any_state_is_prepared(self):
        for name in (PLACEHOLDER, PLACEHOLDER.upper(), "Replace-Me-With-Certificate-DNS-Name"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                state = Path(raw)
                self.assertEqual(self.call(name, state), (2, "", REFUSAL, []))
                self.assertEqual(list(state.iterdir()), [])

    def test_real_names_reach_initialization(self):
        for name in ("mcp.example.invalid", "localhost", PLACEHOLDER + ".example.invalid", "replace-me"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                code, output, errors, calls = self.call(name, Path(raw))
                self.assertEqual((code, output, calls), (2, "", [True]))
                self.assertIn(REACHED, errors)
                self.assertNotIn("placeholder", errors)

    def test_initialized_placeholder_instance_keeps_its_state_and_still_starts(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            (state / "gateway").mkdir(mode=0o700)
            config = state / "gateway" / "config.json"
            settings = {"version": 1, "product_version": "1.0.0", "server_name": PLACEHOLDER, "external_port": 8443,
                        "admin_enabled": True, "audit": {"mode": "local"}}
            config.write_text(json.dumps(settings))
            config.chmod(0o600)
            before = config.read_bytes()
            self.assertEqual(self.call(PLACEHOLDER, state), (2, "", REFUSAL, []))
            self.assertEqual(config.read_bytes(), before)
            with patch.dict(os.environ, {"NETOPS_SERVER_NAME": PLACEHOLDER}):
                self.assertIsNone(init.changed_identity(settings))


if __name__ == "__main__":
    unittest.main()
