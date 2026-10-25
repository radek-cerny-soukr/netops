import ast
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

from netops import operator
from netops.diagnostics import configuration_error, FIELDS, REASONS
from netops.files import UIDS, write_private
from netops_core import inventory
import test_configuration_diagnostics as base

CANARY = base.CANARY
REQUIRED = "is required for the selected platform, credential kind or channel"
FALLBACK = "Invalid role configuration: configuration: invalid configuration; check the documented schema"
SUFFIX = "; operation failed without automatic retry\n"

class DiagnosticPrecision(unittest.TestCase):
    vault = base.StructuredConfigurationDiagnostics.vault
    auditor = base.StructuredConfigurationDiagnostics.auditor
    invoke = base.StructuredConfigurationDiagnostics.invoke

    def exact(self, role, document, field, reason):
        self.assertEqual(self.invoke(role, document), "netops: Invalid role configuration: " + field + ": " + reason + SUFFIX)

    def admin(self):
        vault = self.vault()
        vault["credentials"]["example-check"] = {"kind": "password", "login": "example-check-user", "value": CANARY}
        return {"vault": vault, "config": {"version": 1, "devices": {"example-device": {
            "platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
            "credential": "example-credential", "check_credential": "example-check"}}}}

    def test_missing_fields_name_the_first_trusted_schema_field(self):
        cases = [
            (("vault",), "version", "vault.version"),
            (("vault", "credentials", "example-credential"), "value", "vault.credentials[].value"),
            (("inventory",), "devices", "inventory.devices"),
            (("inventory", "devices", 0), "port", "inventory.devices[0].port"),
            (("inventory", "devices", 0, "auditor"), "required_sections", "inventory.devices[0].auditor.required_sections"),
        ]
        for path, key, field in cases:
            with self.subTest(field=field):
                document = self.auditor()
                cursor = document
                for part in path:
                    cursor = cursor[part]
                cursor.pop(key)
                self.exact("auditor", document, field, REQUIRED)

    def test_list_index_locates_the_failing_device_without_its_alias(self):
        document = self.auditor()
        extra = copy.deepcopy(document["inventory"]["devices"][0])
        extra["name"] = CANARY
        extra.pop("port")
        document["inventory"]["devices"].append(extra)
        self.exact("auditor", document, "inventory.devices[1].port", REQUIRED)

    def test_reference_errors_point_to_the_calling_field(self):
        document = self.auditor()
        document["inventory"]["devices"][0]["credential"] = CANARY
        self.exact("auditor", document, "inventory.devices[0].credential", "must name an existing record")
        for credential, field in (("example-credential", "credential"), ("example-check", "check_credential")):
            with self.subTest(field=field):
                document = self.admin()
                del document["vault"]["credentials"][credential]
                self.exact("admin", document, "config.devices[]." + field, "must name an existing record")

    def test_admin_device_and_limits_paths_match_actual_document_locations(self):
        document = self.admin()
        document["config"]["devices"]["example-device"]["port"] = CANARY
        self.exact("admin", document, "config.devices[].port", "must be an integer in the documented range")
        document = self.admin()
        document["config"]["limits"] = {"changes_per_day": CANARY}
        self.exact("admin", document, "config.limits.changes_per_day", "must be an integer in the documented range")

    def test_enum_guidance_lists_trusted_choices_without_the_value(self):
        from netops_core import platforms, legacy_ssh
        cases = [
            ("role", "must be one of " + ", ".join(inventory.ROLES)),
            ("platform", "must be one of " + ", ".join(platforms.PLATFORMS) + "; aliases: " +
             ", ".join(alias + " -> " + platforms.ALIASES[alias] for alias in sorted(platforms.ALIASES))),
            ("legacy_ssh", "must be null or one of " + ", ".join(legacy_ssh.PROFILES)),
        ]
        for field, reason in cases:
            with self.subTest(field=field):
                document = self.auditor()
                document["inventory"]["devices"][0][field] = CANARY
                self.exact("auditor", document, "inventory.devices[0]." + field, reason)
        document = self.auditor()
        document["catalog"] = CANARY
        self.exact("auditor", document, "auditor.catalog", "must be one of exos, fortios")

    def test_missing_auditor_section_has_required_field_guidance(self):
        document = self.auditor()
        document["inventory"]["devices"][0]["auditor"] = None
        document["inventory"]["devices"][0]["helper"] = {}
        self.exact("auditor", document, "inventory.devices[0].auditor", REQUIRED)

    def test_implicit_context_does_not_transfer_unrelated_schema_metadata(self):
        try:
            raise inventory.InventoryError(CANARY, field="inventory.devices[].port", code="optional-port")
        except inventory.InventoryError:
            try:
                raise ValueError(CANARY)
            except ValueError as error:
                self.assertIsNotNone(error.__context__)
                self.assertEqual(str(configuration_error(error)), FALLBACK)

    def test_explicit_causes_keep_guidance_and_cycles_terminate_exactly(self):
        original = inventory.InventoryError(CANARY, field="inventory.devices[].port", code="optional-port")
        outer = ValueError(CANARY)
        outer.__cause__ = original
        self.assertEqual(str(configuration_error(outer)), "Invalid role configuration: inventory.devices[].port: must be null or an integer in 1..65535")
        outer.__cause__ = outer
        self.assertEqual(str(configuration_error(outer)), FALLBACK)

    def test_literal_validator_metadata_is_in_the_renderer_whitelist(self):
        import inspect
        import netops_core.vault
        import netops_admin.config
        import netops_auditor.inventory
        for module in (inventory, netops_core.vault, netops_admin.config, netops_auditor.inventory):
            tree = ast.parse(Path(inspect.getfile(module)).read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        if keyword.arg == "field":
                            self.assertIn(keyword.value.value, FIELDS)
                        if keyword.arg == "code":
                            self.assertIn(keyword.value.value, REASONS)

    def test_import_writes_real_audit_metadata_before_storing_private_input(self):
        uid = os.geteuid()
        policy = json.dumps({"version": 1, "platform": "fortios", "required_rules": ["address-policy"],
                             "address_networks": ["192.0.2.0/24"]}).encode()
        for kind, data, extra in (("import-snapshot", CANARY.encode(), []),
                                   ("import-policy", policy, ["--platform", "fortios"])):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                for role in ("gateway", "auditor"):
                    (state / role).mkdir(mode=0o700)
                write_private(state / "gateway/config.json", json.dumps({
                    "version": 1, "product_version": "1.0.2", "audit": {"mode": "local"}}).encode())
                with patch.object(operator, "STATE", state), patch.dict(UIDS, {"auditor": uid}), \
                        patch.object(operator, "demote"), patch.object(operator, "role_environment"), \
                        patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))), \
                        patch.object(operator.os, "getegid", return_value=uid), \
                        patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(data))), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(operator.role_cli("auditor", [kind, "--name", CANARY, *extra]), 0)
                rows = [json.loads(line) for path in (state / "gateway/audit").glob("*.jsonl")
                        for line in path.read_text().splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["direction"], "operator")
                self.assertEqual(rows[0]["payload"], {"action": "operator-preflight", "role": "auditor", "workflow": kind})
                self.assertNotIn(CANARY, json.dumps(rows))
                inputs = list((state / "auditor/inputs").iterdir())
                self.assertEqual(len(inputs), 1)
                self.assertEqual(inputs[0].read_bytes(), data)
