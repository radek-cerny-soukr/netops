import asyncio
import contextlib
from datetime import timedelta
import io
import itertools
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from netops import __version__, audit as audit_module, bootstrap, certificates, cli, gateway, operator
from netops.files import UIDS, write_private

SHORT_NAME = "mcp.example.invalid"
LONG_NAME = "a" * 56 + ".netops-long-name.example.invalid"
SUFFIX = "; operation failed without automatic retry\n"
PREFLIGHT = {"role": "gateway", "action": "operator-preflight", "workflow": "configure"}


def temporary_directory(case):
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    return Path(temporary.name)


class ServerCertificateName(unittest.TestCase):
    def issue(self, name):
        directory = temporary_directory(self)
        with patch.object(certificates, "DIRECTORY", directory), patch.dict(UIDS, {"gateway": os.geteuid()}):
            certificates.create_ca(name)
            certificates.renew(name, force=True)
        return directory

    def handshake(self, directory, hostname):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(directory / "server.pem", directory / "server.key")
        client_context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
        left, right = socket.socketpair()
        errors = []
        def serve():
            try:
                with server_context.wrap_socket(right, server_side=True) as connection:
                    connection.recv(1)
            except (OSError, ssl.SSLError) as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with client_context.wrap_socket(left, server_hostname=hostname) as connection:
                connection.sendall(b"x")
        finally:
            left.close()
            right.close()
            thread.join(10)

    def test_long_dns_name_keeps_full_san_and_verifies_at_a_tls_client(self):
        self.assertGreater(len(LONG_NAME), 64)
        directory = self.issue(LONG_NAME)
        leaf = x509.load_pem_x509_certificate((directory / "server.pem").read_bytes())
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(san.value.get_values_for_type(x509.DNSName), [LONG_NAME])
        self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME), [])
        self.assertTrue(san.critical)
        self.handshake(directory, LONG_NAME)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake(directory, "b" + LONG_NAME[1:])

    def test_short_dns_name_keeps_its_common_name(self):
        directory = self.issue(SHORT_NAME)
        leaf = x509.load_pem_x509_certificate((directory / "server.pem").read_bytes())
        self.assertEqual([item.value for item in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)], [SHORT_NAME])
        self.handshake(directory, SHORT_NAME)

    def test_invalid_dns_name_is_refused_before_any_file_is_written(self):
        for name in ("a" * 64 + ".example.invalid", ("a" * 62 + ".") * 4 + "invalid", "mcp..example.invalid", "-mcp.example.invalid"):
            with self.subTest(length=len(name)):
                directory = temporary_directory(self)
                with patch.object(certificates, "DIRECTORY", directory), patch.dict(UIDS, {"gateway": os.geteuid()}):
                    with self.assertRaises(ValueError):
                        certificates.create_ca(name)
                self.assertEqual(list(directory.iterdir()), [])


class SyslogConfiguration(unittest.TestCase):
    def state(self, audit):
        state = temporary_directory(self)
        (state / "gateway").mkdir(mode=0o700)
        (state / "gateway" / "audit").mkdir(mode=0o700)
        settings = {"version": 1, "product_version": __version__, "server_name": SHORT_NAME, "audit": audit}
        write_private(state / "gateway" / "config.json", json.dumps(settings).encode())
        return state

    def configure(self, state, document):
        uid = os.geteuid()
        errors, output = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(operator, "STATE", state))
            stack.enter_context(patch.dict(UIDS, {"gateway": uid}))
            stack.enter_context(patch.object(operator, "demote"))
            stack.enter_context(patch.object(operator, "role_environment"))
            stack.enter_context(patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))))
            stack.enter_context(patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(document).encode()))))
            stack.enter_context(patch.object(sys, "argv", ["netops", "configure", "syslog"]))
            stack.enter_context(contextlib.redirect_stderr(errors))
            stack.enter_context(contextlib.redirect_stdout(output))
            rc = cli.main()
        return rc, output.getvalue(), errors.getvalue()

    def audit_settings(self, state):
        return json.loads((state / "gateway" / "config.json").read_bytes())["audit"]

    def payloads(self, paths):
        return [json.loads(line)["payload"] for path in paths for line in path.read_bytes().splitlines()]

    def full_queue(self, state):
        queue = state / "gateway" / "audit" / ("1-" + "0" * 32 + ".queue")
        descriptor = os.open(queue, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.ftruncate(descriptor, 16777216)
        finally:
            os.close(descriptor)
        return queue

    def test_first_syslog_configuration_is_recorded_in_the_local_audit_before_the_change(self):
        state = self.state({"mode": "local"})
        rc, output, errors = self.configure(state, {"host": "syslog.example.invalid"})
        self.assertEqual(rc, 0, errors)
        self.assertIn("TLS syslog receiver and trust configured", output)
        self.assertEqual(self.audit_settings(state)["host"], "syslog.example.invalid")
        self.assertEqual(self.payloads([state / "gateway" / "audit" / "current.jsonl"]), [PREFLIGHT])

    def test_change_of_a_configured_target_is_queued_in_the_audit(self):
        state = self.state({"mode": "syslog", "host": "old.example.invalid", "port": 6514})
        rc, output, errors = self.configure(state, {"host": "new.example.invalid", "port": 6515})
        self.assertEqual(rc, 0, errors)
        self.assertEqual((self.audit_settings(state)["host"], self.audit_settings(state)["port"]), ("new.example.invalid", 6515))
        self.assertEqual(self.payloads(sorted((state / "gateway" / "audit").glob("*.queue"))), [PREFLIGHT])

    def test_repair_of_a_target_whose_queue_is_full_is_saved_and_reported_as_unrecorded(self):
        state = self.state({"mode": "syslog", "host": "unreachable.example.invalid", "port": 6514, "budget_bytes": 16777216})
        queue = self.full_queue(state)
        rc, output, errors = self.configure(state, {"host": "reachable.example.invalid"})
        self.assertEqual(rc, 3, errors)
        self.assertIn("TLS syslog receiver and trust configured", output)
        self.assertIn("not recorded in the audit", errors)
        self.assertEqual(self.audit_settings(state)["host"], "reachable.example.invalid")
        self.assertEqual(sorted((state / "gateway" / "audit").glob("*.queue")), [queue])

    def test_invalid_repair_input_is_refused_and_leaves_the_target_unchanged(self):
        state = self.state({"mode": "syslog", "host": "unreachable.example.invalid", "port": 6514, "budget_bytes": 16777216})
        self.full_queue(state)
        before = (state / "gateway" / "config.json").read_bytes()
        rc, output, errors = self.configure(state, {"host": "-invalid"})
        self.assertEqual((rc, output, errors), (2, "", "netops: Invalid certificate DNS name" + SUFFIX))
        self.assertEqual((state / "gateway" / "config.json").read_bytes(), before)

    def test_local_audit_that_cannot_record_refuses_before_any_change(self):
        state = self.state({"mode": "local"})
        write_private(state / "gateway" / "audit" / "current.jsonl", b'{"incomplete":')
        before = (state / "gateway" / "config.json").read_bytes()
        rc, output, errors = self.configure(state, {"host": "syslog.example.invalid"})
        self.assertEqual((rc, output, errors), (2, "", "netops: Mandatory MCP audit unavailable; operator workflow refused" + SUFFIX))
        self.assertEqual((state / "gateway" / "config.json").read_bytes(), before)

    def test_numeric_host_is_refused_with_its_own_reason(self):
        for host in (5, True, 6514.0):
            with self.subTest(host=host):
                state = self.state({"mode": "local"})
                before = (state / "gateway" / "config.json").read_bytes()
                rc, output, errors = self.configure(state, {"host": host})
                self.assertEqual((rc, output, errors), (2, "", "netops: Syslog host must be a DNS name or IP address written as a JSON string" + SUFFIX))
                self.assertEqual((state / "gateway" / "config.json").read_bytes(), before)

    def test_ip_address_host_is_still_accepted(self):
        state = self.state({"mode": "local"})
        rc, output, errors = self.configure(state, {"host": "192.0.2.10"})
        self.assertEqual(rc, 0, errors)
        self.assertEqual(self.audit_settings(state)["host"], "192.0.2.10")


class GatewayServerConfig(unittest.TestCase):
    def test_uvicorn_serves_without_websocket_protocol(self):
        captured = {}
        class Stop(Exception):
            pass
        def config(app, **options):
            captured.update(options)
            raise Stop
        async def application(*args, **kwargs):
            return object()
        with patch("netops.init.check_start"), patch("netops.certificates.renew"), \
                patch("netops.certificates.ca_notice", return_value=("", timedelta(days=365))), \
                patch.object(gateway, "application", application), patch.object(gateway, "stop_requested", return_value=False), \
                patch.object(gateway.uvicorn, "Config", side_effect=config):
            with self.assertRaises(Stop):
                gateway.serve({"server_name": SHORT_NAME}, [], [])
        self.assertEqual(captured["ws"], "none")


class InstanceLock(unittest.TestCase):
    def state(self):
        state = temporary_directory(self)
        (state / "gateway").mkdir(mode=0o700)
        settings = {"version": 1, "product_version": __version__, "server_name": SHORT_NAME, "audit": {"mode": "local"}}
        write_private(state / "gateway" / "config.json", json.dumps(settings).encode(), UIDS["gateway"] if os.geteuid() == 0 else None)
        return state

    def acquire(self, entry, state, gateway=None):
        uids = {} if os.geteuid() == 0 else {"gateway": os.geteuid() if gateway is None else gateway}
        settings_check = patch.object(operator, "read_state_settings", return_value={}) if gateway is not None else contextlib.nullcontext()
        with patch.dict(UIDS, uids):
            if entry == "operator":
                with patch.object(operator, "STATE", state), settings_check:
                    os.close(operator.acquire_state())
                return
            settings = {"product_version": __version__, "admin_enabled": False}
            with patch.object(bootstrap, "STATE", state), patch.object(bootstrap, "RUNTIME", state / "run"), patch.object(bootstrap, "prepare"), \
                    patch.object(bootstrap, "stop_requested", return_value=False), \
                    patch("netops.state.read_state_settings", return_value=settings), \
                    patch.object(bootstrap.subprocess, "Popen", side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    bootstrap.serve()

    def test_new_lock_is_owned_by_the_gateway_and_acquired(self):
        for entry in ("operator", "bootstrap"):
            with self.subTest(entry=entry):
                state = self.state()
                self.acquire(entry, state)
                self.assertEqual((state / "gateway" / "instance.lock").stat().st_uid, UIDS["gateway"] if os.geteuid() == 0 else os.geteuid())

    def test_hardlinked_lock_is_refused_before_its_owner_changes(self):
        for entry in ("operator", "bootstrap"):
            with self.subTest(entry=entry):
                state = self.state()
                victim = state / "victim"
                victim.write_bytes(b"")
                victim.chmod(0o600)
                os.link(victim, state / "gateway" / "instance.lock")
                with self.assertRaisesRegex(ValueError, "A single-link regular file is required"):
                    self.acquire(entry, state)
                self.assertEqual(victim.stat().st_uid, os.geteuid())

    def test_lock_owned_by_another_role_is_refused(self):
        for entry in ("operator", "bootstrap"):
            with self.subTest(entry=entry):
                state = self.state()
                lock = state / "gateway" / "instance.lock"
                lock.write_bytes(b"")
                lock.chmod(0o600)
                owner = UIDS["helper"] if os.geteuid() == 0 else os.geteuid()
                if os.geteuid() == 0:
                    os.chown(lock, owner, owner)
                with self.assertRaisesRegex(ValueError, "Unexpected file owner"):
                    self.acquire(entry, state, None if os.geteuid() == 0 else owner + 1)
                self.assertEqual(lock.stat().st_uid, owner)


if __name__ == "__main__":
    unittest.main()


class FullSyslogQueueAtStart(unittest.TestCase):
    def start(self, available):
        state = temporary_directory(self)
        (state / "gateway").mkdir(mode=0o700)
        directory = state / "gateway" / "audit"
        settings = {"audit": {"mode": "syslog", "host": "receiver.example.invalid", "port": 6514, "budget_bytes": 16777216, "segment_bytes": 4194304}}
        filler = audit_module.Audit(directory, settings["audit"])
        start_payload = {"version": __version__, "roles": []}

        async def fill():
            for payload in ({"blob": "x" * 1000000}, {"blob": "x" * 10000}, start_payload):
                while True:
                    try:
                        await filler.record("filler", payload, "f" * 32)
                    except audit_module.AuditUnavailable:
                        break

        asyncio.run(fill())
        before = {path.name: path.read_bytes() for path in directory.glob("*.queue")}
        delivered = []

        def deliver(audit, paths):
            if not available:
                raise ConnectionRefusedError("synthetic receiver unavailable")
            for path in paths:
                audit._frames(path)
                start_queued = any(json.loads(other.read_bytes())["direction"] == "instance_start" for other in directory.glob("*.queue"))
                delivered.append((path.name, json.loads(path.read_bytes())["direction"], start_queued))

        async def lifetime():
            boundary = await gateway.application(settings, [], [])
            async with boundary.app.router.lifespan_context(boundary.app):
                pass

        with patch.object(gateway, "STATE", state), patch.object(audit_module.Audit, "_deliver", deliver):
            try:
                asyncio.run(lifetime())
                error = None
            except audit_module.AuditUnavailable as caught:
                error = caught
        remaining = {path.name: json.loads(path.read_bytes())["direction"] for path in directory.glob("*.queue")}
        return before, delivered, remaining, error, {path.name: path.read_bytes() for path in directory.glob("*.queue")}

    def test_reachable_receiver_drains_the_valid_full_queue_before_the_start_record(self):
        before, delivered, remaining, error, _ = self.start(True)
        self.assertIsNone(error)
        names = [name for name, _, _ in delivered]
        self.assertEqual(len(names), len(set(names)))
        self.assertFalse(set(names) & set(remaining))
        self.assertTrue(delivered and not delivered[0][2] and delivered[0][1] == "filler")
        directions = {name: direction for name, direction, _ in delivered} | remaining
        self.assertEqual({name for name, direction in directions.items() if direction == "filler"}, set(before))
        self.assertEqual(sorted(direction for direction in directions.values() if direction != "filler"), ["instance_start", "instance_stop"])

    def test_unreachable_receiver_refuses_the_start_and_keeps_every_queued_record(self):
        before, delivered, remaining, error, after = self.start(False)
        self.assertIsInstance(error, audit_module.AuditUnavailable)
        self.assertEqual(delivered, [])
        self.assertEqual(after, before)
        self.assertNotIn("instance_start", remaining.values())
