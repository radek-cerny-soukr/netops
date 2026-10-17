import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from netops.audit import Audit, AuditUnavailable
from netops.files import read_private, write_private
from netops.gateway import AuditBoundary
from netops.redaction import redact, terminal_safe

class PrivateFiles(unittest.TestCase):
    def test_read_rejects_aliases_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "value"
            write_private(path, b"private")
            self.assertEqual(read_private(path), b"private")
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                read_private(alias)
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(ValueError):
                read_private(path)
            alias.unlink()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_private(path)

    def test_redaction_is_explicit_and_terminal_output_is_safe(self):
        payload, paths = redact({"password": "hidden", "body": "known-secret\x1b[31m", "nested": [{"authorization": "Bearer other"}]}, ("known-secret",))
        self.assertNotIn("known-secret", json.dumps(payload))
        self.assertNotIn("hidden", json.dumps(payload))
        self.assertEqual(len(paths), 3)
        self.assertNotIn("\x1b", terminal_safe(payload))
        embedded, marked = redact({"text": '{"password":"embedded-secret","ok":true}'})
        self.assertNotIn("embedded-secret", embedded["text"])
        self.assertTrue(marked)
        self.assertTrue(json.loads(embedded["text"])["ok"])

    def test_all_engines_report_the_single_product_version(self):
        import importlib
        from netops import __version__
        for name in ("netops_core", "netops_helper", "netops_auditor", "netops_admin"):
            self.assertEqual(importlib.import_module(name).__version__, __version__)

    def test_runtime_omits_pip_and_the_unused_standalone_healthcheck(self):
        import importlib.util
        self.assertIsNone(importlib.util.find_spec("pip"))
        self.assertIsNone(importlib.util.find_spec("netops_helper.selftest"))

    def test_instance_certificate_has_strict_identifiers_and_does_not_rotate_key_on_renewal(self):
        from cryptography import x509
        from netops import certificates
        from netops.files import UIDS
        self.assertEqual(os.geteuid(), UIDS["gateway"], "Run image unit tests as the gateway UID")
        with tempfile.TemporaryDirectory() as directory:
            with patch("netops.certificates.DIRECTORY", Path(directory)):
                certificates.create_ca("mcp.example.invalid")
                certificates.renew("mcp.example.invalid", force=True)
                key = (Path(directory) / "server.key").read_bytes()
                leaf = x509.load_pem_x509_certificate((Path(directory) / "server.pem").read_bytes())
                self.assertIsNotNone(leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier))
                self.assertIsNotNone(leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier))
                certificates.renew("mcp.example.invalid", force=True)
                self.assertEqual((Path(directory) / "server.key").read_bytes(), key)
                ca = x509.load_pem_x509_certificate((Path(directory) / "ca.pem").read_bytes())
                constraints = ca.extensions.get_extension_for_class(x509.NameConstraints).value
                self.assertEqual(constraints.permitted_subtrees[0].value, "mcp.example.invalid")
                self.assertEqual(len(constraints.excluded_subtrees), 2)
                with self.assertRaisesRegex(ValueError, "DNS name"):
                    certificates.server_name("192.0.2.1")

    def test_legacy_state_is_rejected_before_any_permission_change(self):
        from netops import bootstrap
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            legacy = state / "legacy-data.json"
            legacy.write_bytes(b"unchanged")
            before = state.stat().st_mode
            with patch("netops.bootstrap.STATE", state), patch("netops.bootstrap.os.geteuid", return_value=0), patch("netops.bootstrap.os.chown") as chown, patch("netops.bootstrap.os.chmod") as chmod:
                with self.assertRaisesRegex(ValueError, "0.x"):
                    bootstrap.prepare()
                chown.assert_not_called()
                chmod.assert_not_called()
            self.assertEqual(legacy.read_bytes(), b"unchanged")
            self.assertEqual(state.stat().st_mode, before)


    def test_helper_validation_explains_schema_without_echoing_values(self):
        from netops.operator import _validate_helper_inventory
        from netops_core import vault
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_private(directory / "vault.json", json.dumps({"version": 2, "credentials": {
                "fixture-ro": {"kind": "password", "login": "fixture-user", "value": "synthetic-only-value"}}}).encode())
            store = vault.load(directory / "vault.json")
            device = {"name": "misplaced-private-value-canary", "platform": "linux",
                      "address": "192.0.2.10", "port": 22, "role": "lab", "credential": "fixture-ro",
                      "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
                      "auditor": None, "helper": {"account_role": "read-only"}}
            for address in ("192.0.2.10", "misplaced-private-value-canary"):
                device["address"] = address
                write_private(directory / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode(), replace=True)
                with self.assertRaises(ValueError) as caught:
                    _validate_helper_inventory(directory / "inventory.json", store)
                message = str(caught.exception)
                self.assertIn("ssh_platform", message)
                self.assertIn("enabled_queries", message)
                self.assertIn("egress", message)
                self.assertIn("docs/helper-configuration.md", message)
                self.assertNotIn("misplaced-private-value-canary", message)


class RuntimeHealth(unittest.TestCase):
    def test_unready_role_is_refused_with_python_optimization_enabled(self):
        import subprocess
        import sys
        code = """
import asyncio
from unittest.mock import AsyncMock, patch
from netops.health import check_roles
async def main():
    with patch("netops.health.rpc", new=AsyncMock(return_value={"ready": True})):
        await check_roles(["helper"])
    with patch("netops.health.rpc", new=AsyncMock(return_value={"ready": False})):
        try:
            await check_roles(["helper"])
        except ValueError:
            return
        raise SystemExit(91)
asyncio.run(main())
"""
        result = subprocess.run([sys.executable, "-O", "-B", "-c", code],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

class AuditGate(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, app, audit):
        boundary = AuditBoundary(app, audit)
        boundary.token = lambda: "test-value-" * 6
        events = []
        received = False
        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"example","arguments":{"password":"secret"}}}', "more_body": False}
            await asyncio.get_running_loop().create_future()
        async def send(event):
            events.append(event)
        scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp", "headers": [(b"authorization", ("Bearer " + boundary.token()).encode())]}
        await boundary(scope, receive, send)
        return events

    async def test_immediate_disconnect_after_complete_large_body_is_audited_as_abandoned_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls = []
            async def app(scope, receive, send):
                calls.append(True)
            boundary = AuditBoundary(app, audit)
            boundary.token = lambda: "test-value-" * 6
            body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"example","arguments":{"password":"secret"}}}'
            received = False
            async def receive():
                nonlocal received
                if not received:
                    received = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}
            events = []
            async def send(event):
                events.append(event)
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp", "headers": [(b"authorization", ("Bearer " + boundary.token()).encode())]}
            await boundary(scope, receive, send)
            self.assertEqual(calls, [])
            self.assertEqual(events, [])
            lines = [json.loads(line) for line in (Path(directory) / "current.jsonl").read_text().splitlines()]
            self.assertEqual([line["direction"] for line in lines], ["request", "client_disconnect", "connection_end"])
            self.assertEqual(len({line["correlation"] for line in lines}), 1)
            self.assertEqual(lines[0]["payload"]["params"]["arguments"]["password"], "[REDACTED]")
            self.assertEqual(lines[1]["payload"], {"phase": "before_dispatch", "complete_body": True, "received_bytes": len(body), "operation_executed": False})
            self.assertEqual(lines[2]["payload"], {"delivery": "not_started"})

    async def test_unauthenticated_flood_never_reads_body_or_consumes_operation_audit(self):
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                audit = Audit(directory, {"mode": mode, "host": "example.invalid", "budget_bytes": 16777216})
                await audit.record("request", {"legitimate": "preserved"}, "prior")
                originals = {path: path.read_bytes() for path in audit._files()}
                calls = []
                async def app(scope, receive, send):
                    calls.append(True)
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b'{"ok":true}'})
                boundary = AuditBoundary(app, audit)
                boundary.token = lambda: "synthetic-value-" * 4
                async def receive():
                    self.fail("Unauthenticated body must never be read")
                for index in range(1000):
                    events = []
                    async def send(event):
                        events.append(event)
                    headers = [(b"content-length", b"1048576")]
                    if index % 2:
                        headers.append((b"authorization", b"Bearer invalid"))
                    await boundary({"type": "http", "scheme": "https", "method": "POST", "path": "/mcp", "headers": headers}, receive, send)
                    self.assertEqual(events[0]["status"], 401)
                self.assertEqual(calls, [])
                self.assertEqual({path: path.read_bytes() for path in audit._files()}, originals)
                await audit.flush_rejections()
                summary = json.loads(read_private(audit.rejections_path, 4096))
                self.assertEqual(summary["counts"]["authentication_required"], 1000)
                self.assertFalse(summary["body_read"])
                self.assertLess(audit.rejections_path.stat().st_size, 4096)
                events = await self.invoke(app, audit)
                self.assertEqual(events[0]["status"], 200)
                self.assertEqual(len(calls), 1)

    async def test_request_and_response_are_durable_before_dispatch_and_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            async def app(scope, receive, send):
                lines = (Path(directory) / "current.jsonl").read_text().splitlines()
                self.assertEqual(json.loads(lines[-1])["direction"], "request")
                self.assertEqual(json.loads(lines[-1])["payload"]["params"]["arguments"]["password"], "[REDACTED]")
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'})
            events = await self.invoke(app, audit)
            self.assertEqual(events[0]["status"], 200)
            lines = [json.loads(line) for line in (Path(directory) / "current.jsonl").read_text().splitlines()]
            self.assertEqual([line["direction"] for line in lines], ["request", "response", "connection_end"])
            self.assertTrue(lines[0]["redaction"]["paths"])
            self.assertFalse(lines[0]["redaction"]["byte_transcript"])

    async def test_failed_request_fsync_prevents_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls = []
            async def app(scope, receive, send):
                calls.append(True)
            with patch("netops.audit.os.fsync", side_effect=OSError("full disk")):
                events = await self.invoke(app, audit)
            self.assertEqual(calls, [])
            self.assertEqual(events[0]["status"], 503)
            payload = json.loads(events[1]["body"])
            self.assertFalse(payload["operation_may_have_completed"])

    async def test_failed_response_fsync_withholds_result_and_marks_unknown_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            async def app(scope, receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b'{"result":"sensitive-device-output"}'})
                audit._append = lambda event: (_ for _ in ()).throw(OSError("full disk"))
            events = await self.invoke(app, audit)
            self.assertEqual(events[0]["status"], 503)
            payload = json.loads(events[1]["body"])
            self.assertTrue(payload["operation_may_have_completed"])
            self.assertNotIn("sensitive-device-output", events[1]["body"].decode())
            self.assertFalse(payload["automatic_retry"])

    async def test_incomplete_record_blocks_following_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            write_private(Path(directory) / "current.jsonl", b'{"incomplete":')
            with self.assertRaises(AuditUnavailable):
                await audit.record("request", {"operation": "must-not-run"}, "test")
            self.assertEqual((Path(directory) / "current.jsonl").read_bytes(), b'{"incomplete":')

    async def test_syslog_records_are_queued_durably_and_budget_exhaustion_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "syslog", "host": "example.invalid"})
            await audit.record("request", {"a": 1}, "test")
            queued = list(Path(directory).glob("*.queue"))
            self.assertEqual(len(queued), 1)
            self.assertEqual(json.loads(read_private(queued[0]))["payload"], {"a": 1})
            audit.budget = 1
            with self.assertRaises(AuditUnavailable):
                await audit.record("request", {"b": 2}, "second")
            self.assertEqual(len(list(Path(directory).glob("*.queue"))), 1)

class CertificateMonitor(unittest.IsolatedAsyncioTestCase):
    async def test_renewal_failure_stops_the_instance(self):
        from types import SimpleNamespace
        from netops.gateway import monitor
        server = SimpleNamespace(should_exit=False)
        with patch("netops.certificates.renew", side_effect=OSError("simulated unavailable storage")):
            await monitor(server, SimpleNamespace(ssl=None), [], "localhost")
        self.assertTrue(server.should_exit)

    async def test_reload_failure_stops_the_instance(self):
        from types import SimpleNamespace
        from netops.gateway import monitor
        server = SimpleNamespace(should_exit=False)
        class BrokenTLS:
            def load_cert_chain(self, *args):
                raise ValueError("simulated reload failure")
        with patch("netops.certificates.renew", return_value=True):
            await monitor(server, SimpleNamespace(ssl=BrokenTLS()), [], "localhost")
        self.assertTrue(server.should_exit)

    async def test_worker_failure_stops_the_instance_before_renewal(self):
        from types import SimpleNamespace
        from netops.gateway import monitor
        server = SimpleNamespace(should_exit=False)
        child = SimpleNamespace(poll=lambda: 1)
        with patch("netops.certificates.renew") as renewal:
            await monitor(server, SimpleNamespace(ssl=None), [child], "localhost")
        renewal.assert_not_called()
        self.assertTrue(server.should_exit)


class ForwardedHelper(unittest.TestCase):
    def test_real_mcp_forwarded_device_call_persists_role_audit(self):
        import subprocess
        import sys
        code = r"""
import asyncio
import json
import os
from pathlib import Path
import socket
import tempfile
from netops import bootstrap
from netops.files import write_private

async def main():
    with tempfile.TemporaryDirectory() as temp:
        state = Path(temp)
        helper = state / "helper"
        helper.mkdir(mode=0o700)
        bootstrap.STATE = state
        bootstrap.role_environment("helper")
        os.environ["NETOPS_INVENTORY_PATH"] = str(helper / "inventory.json")
        os.environ["NETOPS_VAULT_PATH"] = str(helper / "vault.json")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            device = {"name": "fixture-linux", "platform": "linux", "address": "127.0.0.1",
                      "port": port, "role": "lab", "credential": "fixture-ro",
                      "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
                      "auditor": None, "helper": {
                          "account_role": "read-only", "ssh_platform": "linux",
                          "enabled_queries": ["kernel"],
                          "egress": {"addresses": ["127.0.0.1"], "tcp_ports": [port],
                                     "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
                                     "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}}
            write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
            write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
                "fixture-ro": {"kind": "password", "login": "fixture-user",
                               "value": "synthetic-test-only-password"}}}).encode())
            from netops import worker
            worker.STATE = state
            from netops_helper import server
            result = await worker.HelperBridge().call(server.mcp, "tcp_probe",
                                                      {"target": "fixture-linux", "port": port})
            assert result["isError"] is False, result
            data = result.get("structuredContent")
            if data is None:
                data = json.loads(result["content"][0]["text"])
            assert data["ok"] is True, data
            records = [json.loads(line) for line in (helper / "operations.jsonl").read_text().splitlines()]
            assert [row["status"] for row in records] == ["started", "ok"], records
            assert Path.home() == helper
            assert ((helper / "operations.jsonl").stat().st_mode & 0o777) == 0o600
            assert records[0]["operation_id"] == records[1]["operation_id"]
        finally:
            listener.close()
asyncio.run(main())
"""
        result = subprocess.run([sys.executable, "-B", "-c", code],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
