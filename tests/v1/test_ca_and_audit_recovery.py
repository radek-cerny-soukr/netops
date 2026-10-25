import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from netops import __version__
from netops.audit import Audit, AuditUnavailable, incomplete_tail, recover
from netops.files import UIDS, write_private

NAME = "mcp.example.invalid"


class InstanceCARotation(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), UIDS["gateway"], "Run image unit tests as the gateway UID")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        patcher = patch("netops.certificates.DIRECTORY", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_rotation_issues_a_new_constrained_ca_and_server_pair_and_keeps_the_old_one(self):
        from cryptography import x509
        from netops import certificates
        certificates.create_ca(NAME)
        certificates.renew(NAME, force=True)
        old_ca = (self.path / "ca.pem").read_bytes()
        old_key = (self.path / "server.key").read_bytes()
        previous = certificates.ca_fingerprint()
        current, expires, retired = certificates.rotate_ca(NAME)
        self.assertNotEqual(current, previous)
        self.assertNotEqual((self.path / "server.key").read_bytes(), old_key)
        self.assertEqual((self.path / retired / "ca.pem").read_bytes(), old_ca)
        self.assertEqual((self.path / retired / "server.key").read_bytes(), old_key)
        self.assertEqual(oct((self.path / retired).stat().st_mode & 0o777), "0o700")
        ca = x509.load_pem_x509_certificate((self.path / "ca.pem").read_bytes())
        leaf = x509.load_pem_x509_certificate((self.path / "server.pem").read_bytes())
        leaf.verify_directly_issued_by(ca)
        with self.assertRaises(Exception):
            leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(old_ca))
        constraints = ca.extensions.get_extension_for_class(x509.NameConstraints).value
        self.assertEqual(constraints.permitted_subtrees[0].value, NAME)
        self.assertEqual(len(constraints.excluded_subtrees), 2)
        self.assertGreater(expires - datetime.now(timezone.utc), timedelta(days=729))
        again, _, _ = certificates.rotate_ca(NAME)
        self.assertNotEqual(again, current)

    def test_expiring_ca_refuses_renewal_with_rotation_guidance_and_warns_early(self):
        from netops import certificates
        with patch("netops.certificates.CA_LIFETIME", timedelta(days=5)):
            certificates.create_ca(NAME)
        with self.assertRaisesRegex(ValueError, "ca rotate"):
            certificates.renew(NAME, force=True)
        text, remaining = certificates.ca_notice()
        self.assertLessEqual(remaining, certificates.CA_HEALTH)
        self.assertIn("Rotate it now", text)
        certificates.rotate_ca(NAME)
        text, remaining = certificates.ca_notice()
        self.assertNotIn("Rotate it now", text)
        self.assertGreater(remaining, certificates.CA_WARNING)


    def test_mismatched_or_missing_pairs_are_refused_with_rotation_guidance(self):
        from netops import certificates
        certificates.create_ca(NAME)
        certificates.renew(NAME, force=True)
        certificates.verify_pairs()
        good_key = (self.path / "ca.key").read_bytes()
        _, _, retired = certificates.rotate_ca(NAME)
        self.assertEqual((self.path / retired / "ca.key").read_bytes(), good_key)
        self.assertEqual(oct((self.path / retired / "ca.key").stat().st_mode & 0o777), "0o600")
        write_private(self.path / "ca.key", good_key, replace=True)
        with self.assertRaisesRegex(ValueError, "ca rotate"):
            certificates.verify_pairs()
        (self.path / "server.key").unlink()
        with self.assertRaisesRegex(ValueError, "ca rotate"):
            certificates.verify_pairs()
        certificates.rotate_ca(NAME)
        certificates.verify_pairs()

    def test_notice_and_rotation_work_without_a_readable_ca(self):
        from netops import certificates
        text, remaining = certificates.ca_notice()
        self.assertIn("ca rotate", text)
        self.assertLessEqual(remaining, timedelta(0))
        write_private(self.path / "ca.pem", b"not a certificate")
        current, _, _ = certificates.rotate_ca(NAME)
        self.assertEqual(current, certificates.ca_fingerprint())
        certificates.verify_pairs()


class AuditRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_recovery_quarantines_only_the_incomplete_tail_and_unblocks_audit(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current.jsonl"
            write_private(path, b'{"direction":"request","n":1}\n{"incomplete":')
            audit = Audit(directory, {"mode": "local"})
            with self.assertRaises(AuditUnavailable):
                await audit.record("request", {"operation": "must-not-run"}, "blocked")
            self.assertTrue(incomplete_tail(path))
            results = recover(directory)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["bytes"], len(b'{"incomplete":'))
            self.assertEqual(results[0]["sha256"], hashlib.sha256(b'{"incomplete":').hexdigest())
            self.assertEqual((Path(directory) / results[0]["quarantine"]).read_bytes(), b'{"incomplete":')
            self.assertEqual(path.read_bytes(), b'{"direction":"request","n":1}\n')
            self.assertFalse(incomplete_tail(path))
            self.assertEqual(recover(directory), [])
            await audit.record("request", {"operation": "allowed"}, "after")
            self.assertEqual(len(path.read_bytes().splitlines()), 2)

    def test_invalid_complete_record_refuses_recovery_without_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current.jsonl"
            original = b'{"ok":1}\nnot-json\n{"incomplete":'
            write_private(path, original)
            with self.assertRaisesRegex(ValueError, "nothing was changed"):
                recover(directory)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()), ["current.jsonl"])

    async def test_incomplete_current_segment_is_not_rotated_into_history(self):
        from netops.files import MAX_MESSAGE
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current.jsonl"
            write_private(path, b'{"pad":"' + b"x" * MAX_MESSAGE + b'"}\n{"incomplete":')
            audit = Audit(directory, {"mode": "local", "segment_bytes": MAX_MESSAGE, "budget_bytes": MAX_MESSAGE * 8})
            with self.assertRaises(AuditUnavailable):
                await audit.record("request", {"operation": "must-not-run"}, "rotation")
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()), ["current.jsonl"])

    def test_audit_cli_skips_an_incomplete_tail_and_explains_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "gateway" / "audit"
            audit.mkdir(parents=True)
            write_private(audit.parent / "config.json", json.dumps({
                "version": 1, "product_version": __version__, "server_name": NAME,
                "external_port": 8443, "admin_enabled": True,
                "audit": {"mode": "local", "budget_bytes": 268435456,
                          "segment_bytes": 16777216, "retention_seconds": 604800},
            }).encode())
            write_private(audit / "current.jsonl", b'{"time":"t","direction":"request","correlation":"c","payload":{}}\n{"incomplete":')
            for action in ("tail", "stats", "pending"):
                with self.subTest(action=action):
                    done = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", action], env=dict(os.environ, NETOPS_STATE_DIR=directory),
                                          capture_output=True, text=True, timeout=60)
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertIn("incomplete record", done.stderr)
                    self.assertIn("audit recover", done.stderr)
                    self.assertNotIn("JSONDecodeError", done.stderr)
            done = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", "tail"], env=dict(os.environ, NETOPS_STATE_DIR=directory),
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.stdout.count('"correlation"'), 1, done.stdout)



class PendingAndIdentity(unittest.TestCase):
    def test_pending_lists_every_operation_with_an_uncertain_outcome(self):
        def request(key):
            return {"time": "t", "direction": "request", "correlation": key, "payload": {"method": "tools/call", "id": 1, "params": {"name": "admin_apply"}}}
        def response(key, result=None):
            payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {"result": result} if result else {}}}
            return {"time": "t", "direction": "response", "correlation": key, "payload": payload}
        records = [request("no-response"),
                   request("normal"), response("normal"),
                   request("interrupted"), {"time": "t", "direction": "interrupted", "correlation": "interrupted", "payload": {}}, response("interrupted"),
                   request("withheld"), {"time": "t", "direction": "response_withheld", "correlation": "withheld", "payload": {}},
                   request("unknown"), response("unknown", "unknown"),
                   request("revert"), response("revert", "revert-failed"),
                   request("confirmed"), response("confirmed", "confirmed")]
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "gateway" / "audit"
            audit.mkdir(parents=True)
            write_private(audit.parent / "config.json", json.dumps({
                "version": 1, "product_version": __version__, "server_name": NAME,
                "external_port": 8443, "admin_enabled": True,
                "audit": {"mode": "local", "budget_bytes": 268435456,
                          "segment_bytes": 16777216, "retention_seconds": 604800},
            }).encode())
            write_private(audit / "current.jsonl", "".join(json.dumps(record) + "\n" for record in records).encode())
            done = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", "pending"], env=dict(os.environ, NETOPS_STATE_DIR=directory),
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            listed = {key for key in ("no-response", "normal", "interrupted", "withheld", "unknown", "revert", "confirmed") if '"' + key + '"' in done.stdout}
            self.assertEqual(listed, {"no-response", "interrupted", "withheld", "unknown", "revert"})
            for phrase in ("no response recorded", "interrupted; a response is recorded", "token changed", "Admin result unknown", "Admin result revert-failed"):
                self.assertIn(phrase, done.stdout)

    def test_changed_server_name_is_refused_and_connection_uses_the_current_port(self):
        import contextlib
        import io
        from netops import init
        settings = {"server_name": "mcp.example.invalid", "external_port": 8443}
        with patch.dict(os.environ, {"NETOPS_SERVER_NAME": "MCP.example.invalid", "NETOPS_PORT": "9443"}):
            self.assertIsNone(init.changed_identity(settings))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch("netops.certificates.ca_notice", return_value=("notice", None)):
                init.connection(settings)
            self.assertIn("https://mcp.example.invalid:9443/mcp", output.getvalue())
            self.assertIn("Export the public CA: docker compose run --rm netops ca > netops-ca.pem", output.getvalue())
        with patch.dict(os.environ, {"NETOPS_SERVER_NAME": "other.example.invalid"}):
            self.assertIn("restore the previous value", init.changed_identity(settings))

    def test_a_server_name_initialized_with_capitals_still_starts(self):
        from netops import init
        settings = {"server_name": "MCP.Example.invalid", "external_port": 8443}
        for value in ("MCP.Example.invalid", "mcp.example.invalid", "MCP.EXAMPLE.INVALID"):
            with self.subTest(value=value), patch.dict(os.environ, {"NETOPS_SERVER_NAME": value}):
                self.assertIsNone(init.changed_identity(settings))
        with patch.dict(os.environ, {"NETOPS_SERVER_NAME": "Other.Example.invalid"}):
            self.assertIn("restore the previous value", init.changed_identity(settings))



class AuditFileSafety(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_a_fifo_in_place_of_a_segment_is_refused_without_blocking(self):
        import threading
        fifo = self.path / "current.jsonl"
        os.mkfifo(fifo, 0o600)
        outcome = []
        def probe():
            try:
                incomplete_tail(fifo)
                outcome.append("returned")
            except ValueError:
                outcome.append("refused")
        worker = threading.Thread(target=probe, daemon=True)
        worker.start()
        worker.join(5)
        self.assertEqual(outcome, ["refused"])

    def test_recovery_refuses_a_segment_that_changed_after_it_was_read(self):
        from netops import audit
        segment = self.path / "current.jsonl"
        content = b'{"a": 1}\n{"b": 2}\n{"partial": tr'
        write_private(segment, content, os.geteuid())
        original = audit.read_private
        def stale(path, limit, owner):
            return original(path, limit, owner)[:-3]
        with patch("netops.audit.read_private", stale):
            with self.assertRaisesRegex(ValueError, "changed during recovery; it was not modified"):
                recover(self.path)
        self.assertEqual(segment.read_bytes(), content)
        self.assertEqual(list(self.path.glob("incomplete-*.partial")), [])

    def test_recovery_changes_nothing_when_the_audit_cannot_be_opened(self):
        from netops import operator
        audit_dir = self.path / "gateway" / "audit"
        audit_dir.mkdir(parents=True, mode=0o700)
        segment = audit_dir / "current.jsonl"
        content = b'{"a": 1}\n{"partial": tr'
        write_private(segment, content, os.geteuid())
        write_private(audit_dir / "rejections.json", b"{}", os.geteuid())
        descriptor = os.open(os.devnull, os.O_RDONLY)
        settings = {"audit": {"mode": "local", "budget_bytes": 268435456, "segment_bytes": 16777216, "retention_seconds": 604800}}
        with patch("netops.operator._gateway_operator", return_value=(descriptor, settings)), patch("netops.operator.STATE", self.path):
            with self.assertRaises(Exception):
                operator.recover_audit()
        self.assertEqual(segment.read_bytes(), content)
        self.assertEqual(list(audit_dir.glob("incomplete-*.partial")), [])

    def _refused_within(self, function):
        import threading
        outcome = []
        def probe():
            try:
                function()
                outcome.append("returned")
            except ValueError:
                outcome.append("refused")
        worker = threading.Thread(target=probe, daemon=True)
        worker.start()
        worker.join(5)
        return outcome

    def test_a_fifo_is_refused_without_blocking_by_recovery_and_private_file_access(self):
        from netops.files import read_private
        fifo = self.path / "current.jsonl"
        os.mkfifo(fifo, 0o600)
        self.assertEqual(self._refused_within(lambda: recover(self.path)), ["refused"])
        self.assertEqual(self._refused_within(lambda: read_private(fifo, 4096, os.geteuid())), ["refused"])
        self.assertEqual(self._refused_within(lambda: write_private(fifo, b"x", os.geteuid(), replace=True)), ["refused"])
        self.assertEqual(list(self.path.glob("incomplete-*.partial")), [])

if __name__ == "__main__":
    unittest.main()
