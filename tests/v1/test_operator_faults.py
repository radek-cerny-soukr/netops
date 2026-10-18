import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from netops import certificates, operator
from netops.audit import Audit, AuditUnavailable
from netops.files import write_private

NAME = "mcp.example.invalid"


def state_with(config):
    directory = tempfile.TemporaryDirectory()
    gateway = Path(directory.name) / "gateway"
    gateway.mkdir(mode=0o700)
    (gateway / "audit").mkdir(mode=0o700)
    write_private(gateway / "config.json", json.dumps(config).encode())
    return directory, gateway


class OperatorPartialResults(unittest.TestCase):
    def run_workflow(self, function, config, gateway, record, stdin=None):
        output, error = io.StringIO(), io.StringIO()
        descriptor = os.open("/dev/null", os.O_RDONLY)
        patches = [patch.object(operator, "STATE", gateway.parent), patch.object(operator, "_gateway_operator", return_value=(descriptor, config)),
                   patch.object(Audit, "record", record), patch.object(certificates, "DIRECTORY", gateway)]
        if stdin is not None:
            patches.append(patch("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin.encode()))))
        with contextlib.ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(error))
            try:
                rc = function()
            except ValueError as refusal:
                rc = refusal
        return rc, output.getvalue(), error.getvalue()

    def test_recovery_without_its_audit_record_is_a_partial_result(self):
        config = {"version": 1, "product_version": "1.0.0", "server_name": NAME, "audit": {"mode": "local"}}
        directory, gateway = state_with(config)
        with directory:
            write_private(gateway / "audit" / "current.jsonl", b'{"direction":"request","correlation":"c"}\n{"incomplete":')
            async def unavailable(*args, **kwargs):
                raise AuditUnavailable("synthetic")
            rc, output, error = self.run_workflow(operator.recover_audit, config, gateway, unavailable)
            self.assertEqual(rc, 3)
            self.assertNotIn("recorded in the audit", output)
            self.assertIn("could not be recorded", error)
            self.assertTrue((gateway / "audit" / "current.jsonl").read_bytes().endswith(b"}\n"))

    def test_rotation_without_its_completion_record_is_a_partial_result(self):
        config = {"version": 1, "product_version": "1.0.0", "server_name": NAME, "audit": {"mode": "local"}}
        directory, gateway = state_with(config)
        with directory, patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NETOPS_SERVER_NAME", None)
            with patch.object(certificates, "DIRECTORY", gateway):
                certificates.create_ca(NAME)
                certificates.renew(NAME, force=True)
            calls = []
            async def first_only(*args, **kwargs):
                calls.append(args)
                if len(calls) > 1:
                    raise AuditUnavailable("synthetic")
            rc, output, error = self.run_workflow(operator.rotate_instance_ca, config, gateway, first_only)
            self.assertEqual(rc, 3)
            self.assertIn("Instance CA rotated", output)
            self.assertIn("completion record could not be written", error)
            with patch.object(certificates, "DIRECTORY", gateway):
                certificates.verify_pairs()


if __name__ == "__main__":
    unittest.main()
