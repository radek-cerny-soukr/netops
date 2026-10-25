import unittest
from pathlib import Path
import tempfile
import os
from unittest.mock import patch
from netops.results import tool_failed

class ToolFailures(unittest.TestCase):
    def result(self, **body):
        return {"content": [], "structuredContent": body, "isError": False}

    def test_helper_refusals_are_errors_and_diagnostic_results_survive(self):
        for reason in ("host-key", "policy", "timeout", "credential"):
            self.assertTrue(tool_failed("helper", "ssh_read", self.result(ok=False, error=reason)))
        self.assertFalse(tool_failed("helper", "tcp_probe", self.result(ok=True, reachable=False)))
        self.assertFalse(tool_failed("helper", "helper_status", self.result(ok=True)))
        self.assertTrue(tool_failed("helper", "ssh_read", {"isError": True}))

    def test_admin_refusals_and_uncertain_writes_are_errors(self):
        for tool in ("admin_apply", "admin_preview", "admin_schema_apply", "admin_schema_preview"):
            for outcome in ("rejected", "unknown", "reverted", "revert-failed"):
                self.assertTrue(tool_failed("admin", tool, self.result(result=outcome)))
            for outcome in ("confirmed", "ready", "known-request"):
                self.assertFalse(tool_failed("admin", tool, self.result(result=outcome)))
        self.assertTrue(tool_failed("admin", "admin_doctor", self.result(ready=False)))
        self.assertFalse(tool_failed("admin", "admin_doctor", self.result(ready=True)))
        self.assertTrue(tool_failed("admin", "admin_status", self.result(result="unknown-operation")))
        self.assertFalse(tool_failed("admin", "admin_status", self.result(result="rejected", status="finished")))

    def test_auditor_findings_are_successful_queries(self):
        self.assertFalse(tool_failed("auditor", "list_findings", self.result(status="fail", findings=[{"status":"failed"}])))
        self.assertTrue(tool_failed("auditor", "list_findings", {"isError": True}))

    def test_gateway_preserves_error_payload_and_marks_mcp_result(self):
        import asyncio
        from netops.gateway import RemoteTool
        for role, name, payload in (("helper","ssh_read",{"ok":False,"error":"pin refused"}),
                                    ("admin","admin_apply",{"result":"unknown","change_id":"example"})):
            wire={"content":[{"type":"text","text":"refused"}],"structuredContent":payload,"isError":False}
            async def fake_rpc(*args, wire=wire):
                return {"result":wire}
            with patch("netops.gateway.rpc",fake_rpc):
                result=asyncio.run(RemoteTool(name=name,parameters={"type":"object"},role=role).run({}))
            self.assertTrue(result.is_error)
            self.assertEqual(result.structured_content,payload)

    def test_sarif_output_private_on_create_replace_and_alias_refused(self):
        from netops_auditor.cli import _write_regular
        from netops_auditor.inputs import InputError
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"report.sarif"
            _write_regular(p,b"new")
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            p.chmod(0o644)
            _write_regular(p,b"replacement")
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            self.assertEqual(p.read_bytes(),b"replacement")
            link=Path(directory)/"link";link.symlink_to(p)
            with self.assertRaises(OSError):_write_regular(link,b"alter")
            alias=Path(directory)/"hard";os.link(p,alias)
            with self.assertRaises(InputError):_write_regular(p,b"alter")
            self.assertEqual(p.read_bytes(),b"replacement")

    def test_inventory_roles_are_english(self):
        from netops_core.inventory import ROLES
        self.assertEqual(ROLES,("perimeter","internal","lab"))

class AdminNotificationConfiguration(unittest.TestCase):
    def test_topic_is_validated_private_and_preserved_on_reconfigure(self):
        from netops.operator import _admin_notification
        from netops.files import write_private
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            config={"notify":{"server":"https://notify.example.invalid","topic_file":"/unusable/outside"}}
            data=_admin_notification(config,{"notification_topic":"synthetic_topic"},root)
            self.assertEqual(data,b"NTFY_TOPIC=synthetic_topic\n")
            self.assertEqual(config["notify"]["topic_file"],str(root/"notification.env"))
            write_private(root/"notification.env",data)
            self.assertEqual(_admin_notification(config,{},root),data)
            for topic in ("too", "line\ninjection", "bad=field", 123, None):
                with self.assertRaises(ValueError):_admin_notification(config,{"notification_topic":topic},root)
            self.assertEqual((root/"notification.env").read_bytes(),data)
            self.assertIsNone(_admin_notification({}, {}, root))

    def test_missing_and_unreadable_stored_topic_are_distinct_refusals(self):
        from netops.operator import _admin_notification
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaisesRegex(ValueError,"^No saved notification topic is available; supply notification_topic for setup or restore the private notification file$"):
                _admin_notification({"notify":{"server":"https://notify.example.invalid"}},{},root)
            path=root/"notification.env"
            path.write_bytes(b"malformed-synthetic-topic")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,"^Saved Admin notification topic could not be read safely; inspect private state before supplying a replacement$"):
                _admin_notification({"notify":{"server":"https://notify.example.invalid"}},{},root)
            self.assertEqual(path.read_bytes(),b"malformed-synthetic-topic")
            with self.assertRaises(ValueError):_admin_notification({},{"notification_topic":"synthetic_topic"},root)

class AdminUnifiedAuditPaths(unittest.TestCase):
    def test_operator_selects_unified_audit_policy_without_changing_command_arguments(self):
        from netops import operator
        with patch("netops.operator.os.geteuid", return_value=0), patch("netops.operator.acquire_state", return_value=99), \
             patch("netops.operator.demote"), patch("netops.operator._admin_audit_preflight"), patch("netops.operator.role_environment"), patch("netops.operator.os.close"), \
             patch("netops_admin.cli.main", return_value=0) as main:
            self.assertEqual(operator.role_cli("admin", ["doctor", "--device", "example-device"]), 0)
        main.assert_called_once_with(["doctor", "--config", "/var/lib/netops/admin/config.json",
                                      "--device", "example-device"], require_export=False)

    def test_worker_selects_unified_audit_policy_before_accepting_mcp_calls(self):
        import asyncio
        import json
        from types import SimpleNamespace
        from netops import worker
        class Finished(Exception):
            pass
        seen = []
        def build(config, **options):
            seen.append((config, options))
            return object()
        def configure(**options):
            options["runtime_factory"]("configured-device")
        module = SimpleNamespace(configure=configure, build_runtime=build)
        with patch("netops.worker.os.geteuid", return_value=51003), patch("netops.worker.os.getegid", return_value=51003), \
             patch("netops.worker.role_environment", return_value=Path("/var/lib/netops/admin")), \
             patch("netops.worker.read_private", return_value=json.dumps({"devices": {"example-device": {}}}).encode()), \
             patch("netops.worker.importlib", SimpleNamespace(import_module=lambda name: module)), \
             patch("netops.worker.asyncio.start_unix_server", side_effect=Finished):
            with self.assertRaises(Finished):
                asyncio.run(worker.run("admin"))
        self.assertEqual(seen, [("configured-device", {"require_export": False})])

class AdminMandatoryAuditPreflight(unittest.TestCase):
    def fixture(self, root):
        from netops.files import write_private
        directory = root / "gateway"
        directory.mkdir(mode=0o700)
        write_private(directory / "config.json", __import__("json").dumps({"audit": {"mode": "local"}}).encode())
        return directory

    def test_operator_preflight_writes_real_gateway_audit_as_gateway_uid(self):
        import json
        from netops import operator
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            self.fixture(state)
            with patch("netops.operator.STATE", state), patch("netops.operator.demote"):
                operator._admin_audit_preflight()
            events = [json.loads(line) for line in (state / "gateway/audit/current.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["direction"], "operator")
            self.assertEqual(events[0]["payload"], {"role": "admin", "action": "operator-preflight", "workflow": "other"})

    def test_operator_preflight_refuses_missing_invalid_corrupt_and_unwritable_audit(self):
        import json
        from netops import operator
        from netops.files import write_private
        for failure in ("missing-config", "invalid-mode", "corrupt-log", "fsync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                state = Path(temp)
                directory = self.fixture(state)
                if failure == "missing-config":
                    (directory / "config.json").unlink()
                elif failure == "invalid-mode":
                    write_private(directory / "config.json", json.dumps({"audit": {"mode": "disabled"}}).encode(), replace=True)
                elif failure == "corrupt-log":
                    (directory / "audit").mkdir(mode=0o700)
                    write_private(directory / "audit/current.jsonl", b'{"incomplete":')
                with patch("netops.operator.STATE", state), patch("netops.operator.demote"):
                    if failure == "fsync":
                        with patch("netops.audit.os.fsync", side_effect=OSError("synthetic disk failure")):
                            with self.assertRaisesRegex(ValueError, "Mandatory MCP audit unavailable"):
                                operator._admin_audit_preflight()
                    else:
                        with self.assertRaisesRegex(ValueError, "Mandatory MCP audit unavailable"):
                            operator._admin_audit_preflight()

    def test_preflight_records_only_allowlisted_workflow_without_argument_values(self):
        import json
        from netops import operator
        for arguments, expected in ((["undo", "--device", "synthetic_private_alias", "--reason", "synthetic_secret"], "undo"),
                                    (["synthetic_secret", "--device=synthetic_private_alias"], "other")):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temp:
                state = Path(temp)
                self.fixture(state)
                with patch("netops.operator.STATE", state), patch("netops.operator.demote"):
                    operator._admin_audit_preflight(arguments)
                raw = (state / "gateway/audit/current.jsonl").read_text()
                self.assertNotIn("synthetic_private_alias", raw)
                self.assertNotIn("synthetic_secret", raw)
                self.assertEqual(json.loads(raw)["payload"]["workflow"], expected)

    def test_preflight_diagnostic_contains_exception_type_without_its_message(self):
        from netops import operator
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            self.fixture(state)
            reader, writer = os.pipe()
            original_write = os.write
            def redirect(descriptor, data):
                return original_write(writer if descriptor == 2 else descriptor, data)
            try:
                with patch("netops.operator.STATE", state), patch("netops.operator.demote"), \
                     patch("netops.operator.os.write", side_effect=redirect), \
                     patch("netops.audit.os.fsync", side_effect=OSError("synthetic_secret")):
                    with self.assertRaisesRegex(ValueError, "Mandatory MCP audit unavailable"):
                        operator._admin_audit_preflight(["enroll"])
                os.close(writer)
                writer = None
                diagnostic = os.read(reader, 4096).decode()
                self.assertIn("AuditUnavailable", diagnostic)
                self.assertNotIn("synthetic_secret", diagnostic)
            finally:
                os.close(reader)
                if writer is not None:
                    os.close(writer)


class SafeConfigurationDiagnostics(unittest.TestCase):
    def test_actual_admin_config_error_explains_field_without_echoing_alias_or_misplaced_secret(self):
        import json
        from netops.operator import _configuration_error
        from netops_admin.config import load_config
        from netops_admin.errors import Rejected
        document = {"version": 1, "state_dir": "/synthetic", "audit_file": "/synthetic/audit",
                    "devices": {"synthetic_secret_alias": {"synthetic_secret_key": "synthetic_secret_value"}}}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "config.json"
            path.write_text(json.dumps(document))
            with self.assertRaises(Rejected) as caught:
                load_config(path)
            diagnostic = str(_configuration_error(caught.exception, document))
        self.assertIn("unknown fields", diagnostic)
        for value in ("synthetic_secret_alias", "synthetic_secret_key", "synthetic_secret_value"):
            self.assertNotIn(value, diagnostic)

    def test_actual_vault_error_explains_version_without_echoing_credentials(self):
        import json
        from netops.operator import _configuration_error
        from netops_core.vault import load, VaultError
        document = {"version": 9, "credentials": {"synthetic_secret_name": {
            "kind": "password", "login": "synthetic_secret_login", "value": "synthetic_secret_value"}}}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "vault.json"
            path.write_text(json.dumps(document))
            path.chmod(0o600)
            with self.assertRaises(VaultError) as caught:
                load(path)
            diagnostic = str(_configuration_error(caught.exception, document))
        self.assertIn("must be 2", diagnostic)
        for value in ("synthetic_secret_name", "synthetic_secret_login", "synthetic_secret_value"):
            self.assertNotIn(value, diagnostic)

    def test_unknown_fields_escaped_and_truncated_aliases_never_echo_input(self):
        from netops.operator import _configuration_error
        from netops_admin.errors import Rejected, shown
        values = ("canary\\nwith\\tescapes", "canary" * 20, "canary_\\u001b_terminal")
        for value in values:
            with self.subTest(value=value):
                detail = str(_configuration_error(Rejected(["invalid " + shown(value)]), {value: value}))
                self.assertNotIn(value, detail)
                self.assertNotIn(repr(value[:64])[1:-1], detail)
                self.assertIn("configuration", detail)

    def test_redaction_markers_are_not_reprocessed_by_short_input_values(self):
        from netops.operator import _configuration_error
        error = ValueError("A D E R C T [ ] canary")
        message = str(_configuration_error(error, {"field": ["A", "D", "E", "R", "C", "T", "[", "]", "canary"]}))
        self.assertNotIn("canary", message)
        self.assertLess(len(message), 300)

    def test_configure_cli_routes_admin_and_auditor_validation_reasons_without_secrets(self):
        import contextlib
        import io
        import itertools
        import json
        import sys
        from netops import cli, operator
        vault = {"version": 2, "credentials": {}}
        admin = {"config": {"version": 1, "devices": {"canary_private_alias": {
            "canary_unknown_key": "canary_private_password"}}}, "vault": vault}
        record = {"name": "canary_private_alias", "platform": "fortios", "address": None, "port": None,
                  "role": "perimeter", "credential": None, "host_key_fingerprint": None, "legacy_ssh": None,
                  "auditor": {"channel": "file", "source": "/synthetic/snapshot.conf",
                              "required_sections": ["system global"], "tls_fingerprint": None}, "helper": None}
        auditor = {"tenant": "synthetic", "catalog": "fortios",
                   "inventory": {"version": 2, "devices": [record]},
                   "vault": {"version": 99, "credentials": {"canary_private_name": {
                       "kind": "password", "login": "canary_private_login", "value": "canary_private_password"}}}}
        current_uid = os.geteuid()
        for role, document, expected in (("admin", admin, "unknown fields"), ("auditor", auditor, "must be 2")):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temp:
                state = Path(temp)
                (state / "gateway").mkdir(mode=0o700)
                from netops.files import write_private
                write_private(state / "gateway/config.json", json.dumps({
                    "version": 1, "product_version": "1.0.1", "audit": {"mode": "local"}}).encode())
                (state / role).mkdir(mode=0o700)
                stream = io.TextIOWrapper(io.BytesIO(json.dumps(document).encode()))
                errors = io.StringIO()
                with patch.object(operator, "STATE", state), patch.object(operator, "demote"), \
                     patch.object(operator, "role_environment"), \
                     patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(current_uid))), \
                     patch.object(sys, "stdin", stream), patch.object(sys, "argv", ["netops", "configure", role]), \
                     contextlib.redirect_stderr(errors):
                    result = cli.main()
                self.assertEqual(result, 2)
                self.assertIn(expected, errors.getvalue())
                for value in ("canary_private_alias", "canary_unknown_key", "canary_private_name",
                              "canary_private_login", "canary_private_password"):
                    self.assertNotIn(value, errors.getvalue())
                self.assertEqual(list((state / role).iterdir()), [])
