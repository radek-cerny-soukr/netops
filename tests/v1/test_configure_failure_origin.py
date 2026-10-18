import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from netops import cli, files, operator
import test_configure_guidance_boundary as guide

CANARY = guide.CANARY
SUFFIX = guide.SUFFIX
OPERATION = "Configuration operation failed; inspect private state and audit before retrying"
PERMISSION = "Configuration could not access required files; check ownership and permissions"

class ConfigureFailureOrigin(unittest.TestCase):
    invoke = guide.ConfigureGuidanceBoundary.invoke
    assert_message = guide.ConfigureGuidanceBoundary.assert_message

    def captured(self, role, function):
        errors, output = io.StringIO(), io.StringIO()
        with patch.object(operator, "configure", side_effect=function), \
                patch.object(sys, "argv", ["netops", "configure", role]), \
                contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(CANARY, errors.getvalue())
        return errors.getvalue()

    def test_unknown_failures_do_not_claim_invalid_input_or_echo_data(self):
        for role in ("helper", "admin", "auditor", "syslog"):
            for failure in (ValueError(CANARY), RuntimeError(CANARY), OSError(CANARY)):
                with self.subTest(role=role, kind=type(failure).__name__):
                    def fail(role):
                        raise failure
                    self.assertEqual(self.captured(role, fail), "netops: " + OPERATION + SUFFIX)

    def test_permission_error_points_to_access_without_disclosing_path(self):
        for role in ("helper", "admin", "auditor", "syslog"):
            def fail(role):
                raise PermissionError(CANARY)
            with self.subTest(role=role):
                self.assertEqual(self.captured(role, fail), "netops: " + PERMISSION + SUFFIX)

    def test_real_file_validation_refusals_keep_their_operational_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case, expected in (("mode", "Private file permissions are required"),
                                    ("owner", "Unexpected file owner"),
                                    ("links", "A single-link regular file is required"),
                                    ("size", "File exceeds its documented size limit"),
                                    ("changed", "File changed during read"),
                                    ("length", "File length changed during read")):
                with self.subTest(case=case):
                    path = root / (case + ".json")
                    path.write_bytes(b"123")
                    path.chmod(0o644 if case == "mode" else 0o600)
                    if case == "links":
                        os.link(path, root / (case + ".other"))
                    def fail(role):
                        maximum = 1 if case == "size" else 100
                        owner = os.geteuid() + 1 if case == "owner" else os.geteuid()
                        original = os.read
                        def read(fd, count):
                            data = original(fd, count)
                            if case == "changed":
                                path.write_bytes(b"1234")
                            return data
                        if case in ("changed", "length"):
                            action = (lambda fd, count: b"") if case == "length" else read
                            with patch.object(files.os, "read", side_effect=action):
                                return files.read_private(path, maximum=maximum, owner=owner)
                        return files.read_private(path, maximum=maximum, owner=owner)
                    self.assertEqual(self.captured("syslog", fail), "netops: " + expected + SUFFIX)

    def test_json_hooks_preserve_fixed_duplicate_and_nonfinite_reasons(self):
        for role in ("helper", "admin", "auditor", "syslog"):
            for raw, expected in ((b'{"' + CANARY.encode() + b'":1,"' + CANARY.encode() + b'":2}',
                                   "Duplicate JSON object keys are unsupported"),
                                  (b'{"' + CANARY.encode() + b'":NaN}', "Nonfinite JSON constants are unsupported")):
                with self.subTest(role=role, expected=expected):
                    self.assert_message(role, raw, expected)

    def test_actual_utf8_input_has_fixed_input_guidance(self):
        for role in ("helper", "admin", "auditor", "syslog"):
            with self.subTest(role=role):
                self.assert_message(role, b'{"private":"\\xff"}'.replace(b"\\xff", b"\xff"), "Input JSON encoding is invalid")


    def test_supported_json_encodings_are_not_restricted_by_diagnostics(self):
        document = {"synthetic": "example"}
        for encoding in ("utf-8", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                self.assertEqual(operator._configuration_document(json.dumps(document).encode(encoding)), document)

    def test_ambiguous_loader_codes_are_neutral_and_schema_codes_are_specific(self):
        from netops.diagnostics import configuration_error, REASONS
        for code in ("read", "regular", "owner", "private-mode", "single-link", "policy"):
            field = "config.devices[].audit_policy" if code == "policy" else "vault"
            error = ValueError(CANARY)
            error.diagnostic = (field, code)
            with self.subTest(code=code):
                self.assertEqual(str(configuration_error(error)),
                                 "Role configuration could not be loaded: " + field + ": " + REASONS[code])
        error = ValueError(CANARY)
        error.diagnostic = ("vault.version", "version2")
        self.assertEqual(str(configuration_error(error)), "Invalid role configuration: vault.version: version must be 2")

    def test_untrusted_operational_marker_does_not_authorize_exception_text(self):
        error = ValueError(CANARY)
        error.operation_diagnostic = CANARY
        def fail(role):
            raise error
        self.assertEqual(self.captured("helper", fail), "netops: " + OPERATION + SUFFIX)
