import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import __version__, cli, operator
from netops.files import UIDS, write_private
from netops.diagnostics import OPERATION_FAILURE, OPERATION_PERMISSION, REASONS, GENERAL_OPERATION_FAILURE, GENERAL_OPERATION_PERMISSION
import test_configure_guidance_boundary as guide
import test_diagnostic_precision as precision

CANARY = guide.CANARY
SUFFIX = guide.SUFFIX

class OperatorFailureConsistency(unittest.TestCase):
    vault = guide.ConfigureGuidanceBoundary.vault
    auditor = guide.ConfigureGuidanceBoundary.auditor
    admin = precision.DiagnosticPrecision.admin
    invoke = guide.ConfigureGuidanceBoundary.invoke
    assert_message = guide.ConfigureGuidanceBoundary.assert_message

    commands = (["configure", "helper"], ["configure", "admin"], ["configure", "auditor"],
                ["admin", "doctor"], ["auditor", "import-snapshot", "--name", "example"],
                ["auditor", "import-policy", "--name", "example", "--platform", "fortios"])

    def captured(self, arguments, acquisition=None, audit=None):
        errors, output = io.StringIO(), io.StringIO()
        descriptor = os.open("/dev/null", os.O_RDONLY) if audit else None
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(operator.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(sys, "argv", ["netops", *arguments]))
                stack.enter_context(contextlib.redirect_stderr(errors))
                stack.enter_context(contextlib.redirect_stdout(output))
                if acquisition is not None:
                    stack.enter_context(patch.object(operator, "acquire_state", side_effect=acquisition))
                else:
                    stack.enter_context(patch.object(operator, "acquire_state", return_value=descriptor))
                    stack.enter_context(patch.object(operator, "_operator_audit_preflight", side_effect=audit))
                self.assertEqual(cli.main(), 2)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(CANARY, errors.getvalue())
        return errors.getvalue()

    def test_shared_acquisition_faults_have_equal_cli_guidance(self):
        for kind, message in ((PermissionError, OPERATION_PERMISSION), (OSError, OPERATION_FAILURE)):
            for arguments in self.commands:
                with self.subTest(kind=kind.__name__, command=arguments):
                    expected = message if arguments[0] == "configure" else (
                        GENERAL_OPERATION_PERMISSION if kind is PermissionError else GENERAL_OPERATION_FAILURE)
                    self.assertEqual(self.captured(arguments, acquisition=kind(CANARY)),
                                     "netops: " + expected + SUFFIX)

    def test_shared_audit_refusal_has_equal_cli_guidance(self):
        from netops.diagnostics import operation_error
        for arguments in self.commands:
            with self.subTest(command=arguments):
                self.assertEqual(self.captured(arguments, audit=operation_error("audit-unavailable")),
                                 "netops: Mandatory MCP audit unavailable; operator workflow refused" + SUFFIX)

    def test_policy_import_read_fault_is_operational_and_has_shared_suffix(self):
        from netops_auditor import management
        uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for role in ("gateway", "auditor"):
                (state / role).mkdir(mode=0o700)
            write_private(state / "gateway/config.json", json.dumps({
                "version": 1, "product_version": "1.0.4", "audit": {"mode": "local"}}).encode())
            errors, output = io.StringIO(), io.StringIO()
            with patch.object(operator, "STATE", state), patch.dict(UIDS, {"auditor": uid}), \
                    patch.object(operator, "demote"), patch.object(operator, "role_environment"), \
                    patch.object(operator, "_operator_audit_preflight"), \
                    patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))), \
                    patch.object(operator.os, "getegid", return_value=uid), \
                    patch.object(management, "read_regular", side_effect=PermissionError(CANARY)) as read, \
                    patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}"))), \
                    patch.object(sys, "argv", ["netops", "auditor", "import-policy", "--name", "example", "--platform", "fortios"]), \
                    contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(), 2)
            self.assertTrue(read.called)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "netops: Auditor input could not be stored privately" + SUFFIX)
            self.assertEqual(list((state / "auditor/inputs").iterdir()), [])

    def test_admin_config_limit_identifies_config_and_size(self):
        document = self.admin()
        document["config"]["devices"]["example-device"]["firmware"] = CANARY + "x" * (1024 * 1024)
        self.assert_message("admin", document,
                            "Invalid role configuration: config: exceeds its supported byte limit")

    def test_admin_config_surrogate_identifies_config_json(self):
        document = self.admin()
        document["config"]["devices"]["example-device"]["address"] = chr(0xD800)
        self.assert_message("admin", document, "Invalid role configuration: config: " + REASONS["json"])

    def test_admin_loader_io_does_not_claim_invalid_document(self):
        from netops_admin import config
        with patch.object(config, "read_regular", side_effect=PermissionError(CANARY)):
            self.assert_message("admin", self.admin(),
                                "Role configuration could not be loaded: config: " + REASONS["read"])

    def test_actual_json_number_limit_refusal_has_fixed_input_reason(self):
        limit = sys.get_int_max_str_digits()
        self.assertGreater(limit, 0, "The supported runtime must retain its integer conversion limit")
        raw = b"9" * (limit + 1)
        for role in ("helper", "admin", "auditor", "syslog"):
            with self.subTest(role=role):
                self.assert_message(role, raw, "Input JSON exceeds supported number or nesting limits")

    def test_saved_topic_read_fault_has_private_state_guidance_at_cli(self):
        document = self.admin()
        document["config"]["notify"] = {"server": "https://notify.example.invalid"}
        original = operator.read_private
        def read(path, *args, **kwargs):
            if Path(path).name == "notification.env":
                raise PermissionError(CANARY)
            return original(path, *args, **kwargs)
        with patch.object(operator, "read_private", side_effect=read):
            self.assert_message("admin", document,
                                "Saved Admin notification topic could not be read safely; inspect private state before supplying a replacement")

    def test_composed_admin_schema_fields_are_rendered_at_the_actual_cli(self):
        for field in ("library", "calibration"):
            document = self.admin()
            schema = {"library": "/synthetic/library", "calibration": "/synthetic/calibration",
                      "schema_sha256": "0" * 64, "calibration_sha256": "0" * 64, "vdoms": ["root"]}
            schema[field] = CANARY
            document["config"]["devices"]["example-device"]["schema"] = schema
            with self.subTest(field=field):
                self.assert_message("admin", document,
                                    "Invalid role configuration: config.devices[].schema." + field + ": must be an absolute path without NUL")

    def test_operator_error_precedence_includes_token_ca_and_audit(self):
        from netops.state import StateCompatibilityError, OperatorAccessError, read_state_settings
        cases = ((["token", "show"], cli, "read_private"),
                 (["token", "rotate"], cli, "write_private"),
                 (["ca", "export"], cli, "read_private"),
                 (["ca", "rotate"], operator, "acquire_state"),
                 (["audit", "recover"], operator, "acquire_state"))
        for arguments, module, attribute in cases:
            failures = ((PermissionError(CANARY), GENERAL_OPERATION_PERMISSION),
                        (OSError(CANARY), GENERAL_OPERATION_FAILURE),
                        (StateCompatibilityError("Fixed state compatibility refusal"), "Fixed state compatibility refusal"),
                        (OperatorAccessError("Fixed operator access refusal"), "Fixed operator access refusal"))
            for error, expected in failures:
                with self.subTest(command=arguments, kind=type(error).__name__), tempfile.TemporaryDirectory() as raw:
                    state = Path(raw)
                    (state / "gateway").mkdir(mode=0o700)
                    (state / "gateway/config.json").write_text(json.dumps({"version": 1, "product_version": __version__}))
                    (state / "gateway/config.json").chmod(0o600)
                    read_state_settings(state)
                    errors = io.StringIO()
                    with patch.object(cli, "STATE", state), patch.object(cli.os, "geteuid", return_value=0),                             patch.object(module, attribute, side_effect=error),                             patch.object(sys, "argv", ["netops", *arguments]),                             contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cli.main(), 2)
                    self.assertEqual(errors.getvalue(), "netops: " + expected + SUFFIX)

    def test_admin_exact_serialized_byte_limit_is_preserved(self):
        from netops_admin.config import CONFIG_MAX_BYTES
        import copy
        uid = os.geteuid()
        for size in (CONFIG_MAX_BYTES, CONFIG_MAX_BYTES + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                for role in ("gateway", "admin"):
                    (state / role).mkdir(mode=0o700)
                write_private(state / "gateway/config.json", json.dumps({
                    "version": 1, "product_version": "1.0.4", "audit": {"mode": "local"}}).encode())
                document = self.admin()
                candidate = copy.deepcopy(document["config"])
                candidate["state_dir"] = str(state / "admin/changes")
                candidate["audit_file"] = str(state / "admin/operations.jsonl")
                device = candidate["devices"]["example-device"]
                device["firmware"] = ""
                device["vault"] = str(state / "admin/vault.json")
                padding = size - len(json.dumps(candidate).encode())
                document["config"]["devices"]["example-device"]["firmware"] = "x" * padding
                candidate["devices"]["example-device"]["firmware"] = "x" * padding
                expected = json.dumps(candidate).encode()
                self.assertEqual(len(expected), size)
                errors, output = io.StringIO(), io.StringIO()
                with patch.object(operator, "STATE", state), patch.dict(UIDS, {"gateway": uid, "admin": uid}),                         patch.object(operator, "demote"), patch.object(operator, "role_environment"),                         patch.object(operator, "_operator_audit_preflight"),                         patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))),                         patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(document).encode()))),                         patch.object(sys, "argv", ["netops", "configure", "admin"]),                         contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                    result = cli.main()
                if size == CONFIG_MAX_BYTES:
                    self.assertEqual(result, 0, errors.getvalue())
                    self.assertEqual(errors.getvalue(), "")
                    self.assertEqual((state / "admin/config.json").read_bytes(), expected)
                else:
                    self.assertEqual(result, 2)
                    self.assertEqual(errors.getvalue(),
                                     "netops: Invalid role configuration: config: exceeds its supported byte limit" + SUFFIX)
                    self.assertFalse((state / "admin/config.json").exists())
                self.assertEqual(list((state / "admin").glob(".configure-*")), [])
