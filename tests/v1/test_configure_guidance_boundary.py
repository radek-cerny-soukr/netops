import contextlib
from datetime import datetime, timedelta, timezone
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from netops import cli, operator
from netops.files import write_private
import test_configuration_diagnostics as base

CANARY = "SYNTHETIC-PRIVATE-INPUT-MUST-NOT-APPEAR"
SUFFIX = "; operation failed without automatic retry\n"

class ConfigureGuidanceBoundary(unittest.TestCase):
    vault = base.StructuredConfigurationDiagnostics.vault
    auditor = base.StructuredConfigurationDiagnostics.auditor

    def invoke(self, role, document, maximum=None):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "gateway").mkdir(mode=0o700)
            (state / role).mkdir(mode=0o700, exist_ok=True)
            settings = {"version": 1, "product_version": "1.0.2", "audit": {"mode": "local"}}
            write_private(state / "gateway/config.json", json.dumps(settings).encode())
            before = {str(p.relative_to(state)): p.read_bytes() for p in state.rglob("*") if p.is_file()}
            errors, output = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(operator, "STATE", state))
                stack.enter_context(patch.object(operator, "demote"))
                stack.enter_context(patch.object(operator, "role_environment"))
                stack.enter_context(patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))))
                stack.enter_context(patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw))))
                stack.enter_context(patch.object(sys, "argv", ["netops", "configure", role]))
                stack.enter_context(contextlib.redirect_stderr(errors))
                stack.enter_context(contextlib.redirect_stdout(output))
                if maximum is not None:
                    stack.enter_context(patch.object(operator, "MAX_MESSAGE", maximum))
                rc = cli.main()
            self.assertEqual(rc, 2, errors.getvalue())
            self.assertEqual(output.getvalue(), "")
            after = {str(p.relative_to(state)): p.read_bytes() for p in state.rglob("*")
                     if p.is_file() and p.name != "instance.lock" and "audit" not in p.parts}
            self.assertEqual(after, before)
            return errors.getvalue()

    def assert_message(self, role, document, message, **kwargs):
        self.assertEqual(self.invoke(role, document, **kwargs), "netops: " + message + SUFFIX)

    def leaf(self, constraints=True):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.example.invalid")])
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)))
        if constraints:
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    def test_syslog_refusals_preserve_exact_fixed_guidance(self):
        cases = [
            ({}, "Syslog configuration requires host, optional port and optional public ca_pem", {}),
            ({"host": "syslog.example.invalid", "port": CANARY}, "Syslog port must be a decimal port number", {}),
            ({"host": "syslog.example.invalid", "port": 0}, "Syslog port must be between 1 and 65535", {}),
            (b'{"host":"syslog.example.invalid","port":1e9999}', "Syslog port must be a decimal port number", {}),
            ({"host": "-invalid"}, "Invalid certificate DNS name", {}),
            ({"host": "syslog.example.invalid", "ca_pem": self.leaf()}, "The supplied public certificate must be a CA", {}),
            (b"x" * 17, "Configuration exceeds supported size", {"maximum": 16}),
        ]
        for document, expected, kwargs in cases:
            with self.subTest(expected=expected):
                self.assert_message("syslog", document, expected, **kwargs)

    def test_untyped_syslog_errors_are_fixed_and_never_described_as_role_errors(self):
        for error in (ValueError(CANARY), UnicodeDecodeError("utf-8", b"\xff", 0, 1, CANARY)):
            errors = io.StringIO()
            with patch.object(operator, "configure", side_effect=error), \
                    patch.object(sys, "argv", ["netops", "configure", "syslog"]), \
                    contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(), 2)
            self.assertEqual(errors.getvalue(), "netops: Configuration operation failed; inspect private state and audit before retrying" + SUFFIX)

    def test_role_envelopes_and_size_keep_fixed_guidance(self):
        for role in ("helper", "admin", "auditor"):
            with self.subTest(role=role):
                expected = ("Auditor configuration requires tenant/catalog and an optional inventory/vault pair"
                            if role == "auditor" else "Use inventory/vault for Helper or config/vault with optional notification_topic for Admin")
                self.assert_message(role, {}, expected)
                self.assert_message(role, b"x" * 17, "Configuration exceeds supported size", maximum=16)

    def test_helper_section_keeps_fixed_guidance(self):
        document = self.auditor()
        entry = document["inventory"]["devices"][0]
        entry["helper"], entry["auditor"] = {}, None
        payload = {"inventory": document["inventory"], "vault": document["vault"]}
        self.assert_message("helper", payload, "Invalid Helper inventory. Each helper section requires account_role, ssh_platform, enabled_queries and egress; check field types, target scope and credential references in docs/helper-configuration.md")

    def test_admin_notification_refusals_keep_fixed_guidance(self):
        messages = [
            (None, True, CANARY, "notification_topic requires a notify server in Admin config"),
            ([], False, None, "Admin notify must be an object"),
            ({}, True, "/", "Admin notification_topic must contain 8 to 64 letters, digits, underscores or hyphens"),
            ({}, False, None, "No saved notification topic is available; supply notification_topic for setup or restore the private notification file"),
        ]
        for notify, present, topic, expected in messages:
            payload = {"vault": self.vault(), "config": {"version": 1, "devices": {"example-device": {}}}}
            if notify is not None:
                payload["config"]["notify"] = notify
            if present:
                payload["notification_topic"] = topic
            with self.subTest(expected=expected):
                self.assert_message("admin", payload, expected)

    def test_busy_lock_preserves_operational_guidance(self):
        import fcntl
        from netops.files import UIDS
        uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); (state / "gateway").mkdir(mode=0o700)
            write_private(state / "gateway/config.json", json.dumps({"version": 1, "product_version": "1.0.2"}).encode())
            lock = os.open(state / "gateway/instance.lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                errors = io.StringIO()
                with patch.object(operator, "STATE", state), patch.dict(UIDS, {"gateway": uid}), \
                        patch.object(operator.os, "geteuid", return_value=0), \
                        patch.object(sys, "argv", ["netops", "configure", "helper"]), \
                        contextlib.redirect_stderr(errors):
                    self.assertEqual(cli.main(), 2)
                self.assertEqual(errors.getvalue(), "netops: Stop the running instance before modifying role configuration or running an operator workflow" + SUFFIX)
            finally:
                os.close(lock)


    def test_json_syntax_error_reports_only_fixed_text_and_line_column(self):
        raw = b'{\n "private":"' + CANARY.encode() + b'"\n "host":"syslog.example.invalid"\n}'
        for role in ("helper", "admin", "auditor", "syslog"):
            with self.subTest(role=role):
                self.assert_message(role, raw, "Input is not valid JSON (line 3, column 2)")

    def test_invalid_syslog_certificate_names_the_fixed_ca_pem_field(self):
        for certificate in (CANARY, self.leaf(constraints=False), {"private": CANARY}):
            with self.subTest(kind=type(certificate).__name__):
                self.assert_message("syslog", {"host": "syslog.example.invalid", "ca_pem": certificate},
                                    "ca_pem must contain a PEM-encoded CA certificate with BasicConstraints")

    def test_known_certificate_parser_refusals_name_ca_pem_without_exception_data(self):
        failures = (
            x509.InvalidVersion(CANARY, 3),
            x509.DuplicateExtension(CANARY, ExtensionOID.BASIC_CONSTRAINTS),
            x509.UnsupportedGeneralNameType(CANARY),
        )
        for error in failures:
            with self.subTest(kind=type(error).__name__), patch.object(x509, "load_pem_x509_certificate", side_effect=error):
                self.assert_message("syslog", {"host": "syslog.example.invalid", "ca_pem": CANARY},
                                    "ca_pem must contain a PEM-encoded CA certificate with BasicConstraints")
