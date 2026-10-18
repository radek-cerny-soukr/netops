import contextlib
import copy
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import cli, operator
from netops.diagnostics import configuration_error
from netops.files import write_private

CANARY = "SYNTHETIC-PRIVATE-INPUT-MUST-NOT-APPEAR"

class StructuredConfigurationDiagnostics(unittest.TestCase):
    def vault(self):
        return {"version": 2, "credentials": {"example-credential": {
            "kind": "password", "login": "example-user", "value": CANARY}}}

    def auditor(self):
        return {"tenant": "example-tenant", "catalog": "fortios", "vault": self.vault(),
                "inventory": {"version": 2, "devices": [{
                    "name": "example-device", "platform": "fortios", "address": "192.0.2.1", "port": 22,
                    "role": "perimeter", "credential": "example-credential",
                    "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
                    "helper": None, "auditor": {"channel": "ssh", "source": None,
                        "required_sections": ["system global"], "tls_fingerprint": None}}]}}

    def invoke(self, role, document):
        current_uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "gateway").mkdir(mode=0o700)
            (state / role).mkdir(mode=0o700)
            write_private(state / "gateway/config.json", json.dumps({
                "version": 1, "product_version": "1.0.0", "audit": {"mode": "local"}}).encode())
            stream = io.TextIOWrapper(io.BytesIO(json.dumps(document).encode()))
            errors, output = io.StringIO(), io.StringIO()
            with patch.object(operator, "STATE", state), patch.object(operator, "demote"), \
                    patch.object(operator, "role_environment"), \
                    patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(current_uid))), \
                    patch.object(sys, "stdin", stream), patch.object(sys, "argv", ["netops", "configure", role]), \
                    contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                result = cli.main()
            self.assertEqual(result, 2, errors.getvalue())
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(list((state / role).iterdir()), [])
            self.assertNotIn(CANARY, errors.getvalue())
            self.assertNotIn("example-user", errors.getvalue())
            self.assertNotIn("example-device", errors.getvalue())
            self.assertNotIn("example-credential", errors.getvalue())
            return errors.getvalue()

    def test_actual_auditor_vault_and_inventory_failures_reach_cli_as_field_and_reason(self):
        cases = [
            (("vault", "version"), 9, "vault.version", "version must be 2"),
            (("vault", "credentials", "example-credential", "login"), "bad/" + CANARY,
             "vault.credentials[].login", "plain user name"),
            (("vault", "credentials", "example-credential", "kind"), CANARY,
             "vault.credentials[].kind", "password, ssh-key"),
            (("inventory", "version"), 9, "inventory.version", "version must be 2"),
            (("inventory", "devices", 0, "port"), CANARY, "inventory.devices[].port", "1..65535"),
            (("inventory", "devices", 0, "auditor", "channel"), CANARY,
             "inventory.devices[].auditor.channel", "file, fortios-rest or ssh"),
            (("inventory", "devices", 0, "credential"), CANARY, "inventory.devices[].credential", "existing record"),
            (("inventory", "devices", 0, "auditor", "source"), CANARY,
             "inventory.devices[].auditor.source", "must be null"),
            (("inventory", "devices", 0, "auditor"), {CANARY: CANARY},
             "inventory.devices[].auditor.channel", "is required"),
            (("tenant",), None, "auditor.tenant", "string without U+001F"),
            (("catalog",), CANARY, "auditor.catalog", "exos, fortios"),
        ]
        for path, value, field, reason in cases:
            with self.subTest(path=path):
                document = self.auditor()
                cursor = document
                for part in path[:-1]:
                    cursor = cursor[part]
                cursor[path[-1]] = value
                message = self.invoke("auditor", document)
                self.assertIn(field.replace("inventory.devices[]", "inventory.devices[0]") + ":", message)
                self.assertIn(reason, message)

    def test_tenant_types_and_fingerprint_separator_are_explained(self):
        for value in (None, 123, [], {}, CANARY + "\x1f"):
            document = self.auditor()
            document["tenant"] = value
            message = self.invoke("auditor", document)
            self.assertIn("auditor.tenant: must be a string without U+001F", message)

    def test_actual_auditor_failure_for_wrong_channel_credential_is_explained(self):
        document = self.auditor()
        document["vault"]["credentials"]["example-credential"] = {"kind": "api-token", "value": CANARY}
        message = self.invoke("auditor", document)
        self.assertIn("inventory.devices[0].credential:", message)
        self.assertIn("ssh uses password or ssh-key", message)

    def test_schema_words_and_one_character_input_never_redact_the_reason(self):
        messages = []
        for alias in ("a", "version", "password", "file"):
            document = {"version": 99, "credentials": {alias: {
                "kind": "password", "login": alias, "value": alias}}}
            from netops_core.vault import load, VaultError
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "vault.json"
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                with self.assertRaises(VaultError) as caught:
                    load(path)
                messages.append(str(configuration_error(caught.exception, document)))
        self.assertEqual(len(set(messages)), 1)
        self.assertEqual(messages[0], "Invalid role configuration: vault.version: version must be 2")

    def test_admin_validator_metadata_survives_short_aliases_and_unknown_keys(self):
        from netops_admin.config import load_config
        from netops_admin.errors import Rejected
        for alias in ("a", "version", "password", "file", CANARY):
            document = {"version": 1, "state_dir": "/synthetic", "audit_file": "/synthetic/audit",
                        "devices": {alias: {CANARY: CANARY}}}
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(document))
                with self.assertRaises(Rejected) as caught:
                    load_config(path)
                message = str(configuration_error(caught.exception, document))
            self.assertIn("config.devices[]: contains unknown fields", message)
            self.assertNotIn(CANARY, message)

    def test_unstructured_or_untrusted_metadata_is_never_echoed(self):
        for error in (ValueError(CANARY), RuntimeError(CANARY)):
            error.diagnostic = (CANARY, CANARY)
            self.assertEqual(str(configuration_error(error)), "Invalid role configuration: configuration: invalid configuration; check the documented schema")
        error = ValueError(CANARY)
        error.__context__ = error
        self.assertEqual(str(configuration_error(error)), "Invalid role configuration: configuration: invalid configuration; check the documented schema")

    def test_import_audit_precedes_demotion_and_input_processing(self):
        for kind in ("import-snapshot", "import-policy"):
            with self.subTest(kind=kind):
                events = []
                with patch.object(operator.os, "geteuid", return_value=0), \
                        patch.object(operator, "acquire_state", return_value=99), \
                        patch.object(operator, "_operator_audit_preflight", side_effect=lambda *args: events.append(("audit", args))), \
                        patch.object(operator, "demote", side_effect=lambda uid: events.append(("demote", uid))), \
                        patch.object(operator, "role_environment"), patch.object(operator.os, "close"), \
                        patch("netops.auditor_inputs.main", side_effect=lambda *args: events.append(("input", None)) or 0):
                    self.assertEqual(operator.role_cli("auditor", [kind, "--name", CANARY]), 0)
                self.assertEqual(events[0], ("audit", ("auditor", kind)))
                self.assertEqual([event[0] for event in events], ["audit", "demote", "input"])

    def test_import_audit_failure_blocks_all_input_processing(self):
        with patch.object(operator.os, "geteuid", return_value=0), \
                patch.object(operator, "acquire_state", return_value=99), \
                patch.object(operator, "_operator_audit_preflight", side_effect=ValueError("audit unavailable")), \
                patch.object(operator, "demote") as demote, patch.object(operator.os, "close"), \
                patch("netops.auditor_inputs.main") as imported:
            with self.assertRaisesRegex(ValueError, "audit unavailable"):
                operator.role_cli("auditor", ["import-snapshot", "--name", CANARY])
        demote.assert_not_called()
        imported.assert_not_called()
