"""F3: an unreachable SSH target must not be reported as a host key problem.

Run inside the product image with `--network none`, so 192.0.2.1 (TEST-NET-1)
has no route. Every other peer is a socket this test opens on 127.0.0.1.
A genuine foreign host key comes from a minimal in-test SSH server
(curve25519-sha256 + ssh-ed25519, built on `cryptography`) whose key is
generated per run.
"""

import base64
import errno
import hashlib
import os
import re
import socket
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault(
    "NETOPS_HELPER_AUDIT_PATH",
    os.path.join(tempfile.mkdtemp(prefix="f3-helper-audit-"), "audit.jsonl"),
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from netops_core import ssh as core_ssh
from netops_core.hostkey import fingerprint_of
import netops_helper.engine as engine
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_auditor import collect
from netops_admin import access

UNROUTED = "192.0.2.1"
LOOPBACK = "127.0.0.1"
SHORT_TIMEOUT = 2.0

FALSE_KEY_CLAIM = re.compile(
    r"offered no host key|did not offer the pinned|no offered host key matches"
    r"|key\(s\) offered|offer(?:s|ed)? (?:a )?different host key",
    re.IGNORECASE,
)
REACHABILITY_HINT = re.compile(r"reachab", re.IGNORECASE)
HOST_KEY_REFUSAL = re.compile(r"host[ -]?key|pinned", re.IGNORECASE)
CLAIMS_UNREACHABLE = re.compile(r"unreachable|not reachable|cannot reach", re.IGNORECASE)


def _string(data):
    return struct.pack(">I", len(data)) + data


def _mpint(data):
    data = data.lstrip(b"\x00")
    if data and data[0] & 0x80:
        data = b"\x00" + data
    return _string(data)


def _namelist(names):
    return _string(",".join(names).encode("ascii"))


class _Reader:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = b""

    def exactly(self, size):
        while len(self.buffer) < size:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise EOFError
            self.buffer += chunk
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def line(self):
        while b"\n" not in self.buffer:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise EOFError
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.rstrip(b"\r")

    def packet(self):
        length = struct.unpack(">I", self.exactly(4))[0]
        body = self.exactly(length)
        padding = body[0]
        return body[1:length - padding]


def _packet(payload):
    padding = 8 - (5 + len(payload)) % 8
    if padding < 4:
        padding += 8
    return struct.pack(">IB", 1 + len(payload) + padding, padding) + payload + os.urandom(padding)


class ForeignKeySshServer:
    """Answers the SSH key exchange with its own ed25519 host key, then closes."""

    VERSION = b"SSH-2.0-NetOpsF3Test_1.0"

    def __init__(self):
        self.host_key = Ed25519PrivateKey.generate()
        raw = self.host_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.blob = _string(b"ssh-ed25519") + _string(raw)
        self.blob_b64 = base64.b64encode(self.blob).decode("ascii")
        self.fingerprint = fingerprint_of(self.blob_b64)
        self.key_exchanges = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.lock = threading.Lock()
        self.closing = False
        self.connections = []
        self.workers = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def close(self):
        with self.lock:
            self.closing = True
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            self.listener.close()
        deadline = time.monotonic() + 5
        self.thread.join(max(0, deadline - time.monotonic()))
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                connection.close()
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        alive = [thread.name for thread in [self.thread, *workers] if thread.is_alive()]
        if alive:
            raise AssertionError("test SSH server threads still running after close: %s" % alive)

    def _accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            with self.lock:
                if self.closing:
                    connection.close()
                    return
                worker = threading.Thread(target=self._serve, args=(connection,), daemon=True)
                self.connections.append(connection)
                try:
                    worker.start()
                except BaseException:
                    self.connections.remove(connection)
                    connection.close()
                    raise
                self.workers.append(worker)

    def _serve(self, connection):
        try:
            connection.settimeout(10)
            connection.sendall(self.VERSION + b"\r\n")
            reader = _Reader(connection)
            client_version = reader.line()
            while not client_version.startswith(b"SSH-"):
                client_version = reader.line()
            client_kexinit = reader.packet()
            server_kexinit = (
                b"\x14" + os.urandom(16)
                + _namelist(["curve25519-sha256", "curve25519-sha256@libssh.org"])
                + _namelist(["ssh-ed25519"])
                + _namelist(["aes128-ctr"]) + _namelist(["aes128-ctr"])
                + _namelist(["hmac-sha2-256"]) + _namelist(["hmac-sha2-256"])
                + _namelist(["none"]) + _namelist(["none"])
                + _namelist([]) + _namelist([])
                + b"\x00" + struct.pack(">I", 0)
            )
            connection.sendall(_packet(server_kexinit))
            init = reader.packet()
            if init[0] != 30:
                return
            client_public = init[5:5 + struct.unpack(">I", init[1:5])[0]]
            ephemeral = X25519PrivateKey.generate()
            server_public = ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(client_public))
            exchange_hash = hashlib.sha256(
                _string(client_version) + _string(self.VERSION)
                + _string(client_kexinit) + _string(server_kexinit)
                + _string(self.blob) + _string(client_public) + _string(server_public)
                + _mpint(shared)
            ).digest()
            signature = _string(b"ssh-ed25519") + _string(self.host_key.sign(exchange_hash))
            self.key_exchanges += 1
            connection.sendall(_packet(
                b"\x1f" + _string(self.blob) + _string(server_public) + _string(signature)
            ) + _packet(b"\x15"))
            reader.packet()
        except (EOFError, OSError, IndexError, ValueError, struct.error):
            pass
        finally:
            connection.close()


def _closed_loopback_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((LOOPBACK, 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class SilentListener:
    """A listener whose accept queue is full, so new connection attempts time out."""

    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(0)
        self.port = self.listener.getsockname()[1]
        self.fillers = []
        for _ in range(8):
            filler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            filler.settimeout(0.5)
            try:
                filler.connect((LOOPBACK, self.port))
            except OSError:
                filler.close()
                break
            self.fillers.append(filler)

    def close(self):
        for filler in self.fillers:
            filler.close()
        self.listener.close()


def _connect_outcome(address, port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect((address, port))
    except socket.timeout:
        return "timeout"
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    finally:
        probe.close()
    return "connected"


def _unreachable_targets(test):
    """(label, address, port) for: no route, refused, connect timeout."""
    silent = SilentListener()
    test.addCleanup(silent.close)
    targets = (
        ("network unreachable", UNROUTED, 22, ("ENETUNREACH", "EHOSTUNREACH", "timeout")),
        ("connection refused", LOOPBACK, _closed_loopback_port(), ("ECONNREFUSED",)),
        ("connect timeout", LOOPBACK, silent.port, ("timeout",)),
    )
    for label, address, port, expected in targets:
        test.assertIn(_connect_outcome(address, port), expected, "harness precondition: " + label)
    return tuple(target[:3] for target in targets)


def _random_pin():
    return fingerprint_of(base64.b64encode(os.urandom(51)).decode("ascii"))


class _ExecutionSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise core_ssh.SshError("f3 test: command execution must not be reached")


class _Case(unittest.TestCase):
    def assert_reachability_diagnosis(self, label, text):
        self.assertIsNone(
            FALSE_KEY_CLAIM.search(text),
            "%s: error claims a host key problem: %r" % (label, text),
        )
        self.assertRegex(text, REACHABILITY_HINT, "%s: no reachability hint in %r" % (label, text))

    def assert_host_key_refusal(self, text):
        self.assertRegex(text, HOST_KEY_REFUSAL)
        self.assertNotRegex(text, CLAIMS_UNREACHABLE)


class HelperSshRead(_Case):
    def setUp(self):
        engine._CONNECTION_LANES.clear()
        engine._HOST_KEY_LINE_CACHE.clear()
        self.addCleanup(engine._HOST_KEY_LINE_CACHE.clear)
        self.addCleanup(engine._CONNECTION_LANES.clear)
        timeout = mock.patch.object(engine, "_HOST_KEY_SCAN_TIMEOUT_SECONDS", SHORT_TIMEOUT)
        timeout.start()
        self.addCleanup(timeout.stop)
        self.spy = _ExecutionSpy()
        execution = mock.patch.object(core_ssh, "run_command", self.spy)
        execution.start()
        self.addCleanup(execution.stop)

    def auth(self, address, port, pin):
        return TargetAuth(
            alias="f3-device", host=address, port=port, login="reader",
            secret="f3-synthetic-credential", host_key_fingerprint=pin,
            ssh_platform="linux", enabled_queries=("hostname",),
            egress=EgressPolicy(addresses=(address,), tcp_ports=(port,)),
        )

    def read(self, auth):
        return engine.ssh_read(auth, "linux", "hostname", None, 0, 16_000)

    def test_unreachable_target_is_not_reported_as_host_key_problem(self):
        for label, address, port in _unreachable_targets(self):
            with self.subTest(label):
                engine._HOST_KEY_LINE_CACHE.clear()
                answer = self.read(self.auth(address, port, _random_pin()))
                self.assertIs(answer["ok"], False, answer)
                self.assert_reachability_diagnosis(label, answer["error"])
        self.assertEqual(self.spy.calls, [])

    def test_control_matching_key_is_accepted_by_the_test_server(self):
        server = ForeignKeySshServer()
        self.addCleanup(server.close)
        line = engine.host_key_line(self.auth(LOOPBACK, server.port, server.fingerprint))
        self.assertIn(server.blob_b64, line)

    def test_control_foreign_host_key_is_refused_without_running_the_command(self):
        server = ForeignKeySshServer()
        self.addCleanup(server.close)
        answer = self.read(self.auth(LOOPBACK, server.port, _random_pin()))
        self.assertGreaterEqual(server.key_exchanges, 1, "harness: the test server was never asked")
        self.assertIs(answer["ok"], False, answer)
        self.assert_host_key_refusal(answer["error"])
        self.assertEqual(self.spy.calls, [])


class _Credential:
    login = "auditor-reader"

    def use(self):
        return "f3-synthetic-credential"


class AuditorCollectSsh(_Case):
    def collect(self, address, port, pin, run):
        return collect.collect_ssh(
            "f3-device", "fortios", address, port, _Credential(), pin,
            timeout=SHORT_TIMEOUT, run=run,
        )

    def test_unreachable_target_is_not_reported_as_host_key_problem(self):
        spy = _ExecutionSpy()
        for label, address, port in _unreachable_targets(self):
            with self.subTest(label):
                with self.assertRaises(collect.CollectError) as raised:
                    self.collect(address, port, _random_pin(), spy)
                self.assert_reachability_diagnosis(label, str(raised.exception))
        self.assertEqual(spy.calls, [])

    def test_control_foreign_host_key_is_refused_without_running_the_command(self):
        server = ForeignKeySshServer()
        self.addCleanup(server.close)
        spy = _ExecutionSpy()
        with self.assertRaises(collect.CollectError) as raised:
            self.collect(LOOPBACK, server.port, _random_pin(), spy)
        self.assertGreaterEqual(server.key_exchanges, 1, "harness: the test server was never asked")
        self.assert_host_key_refusal(str(raised.exception))
        self.assertEqual(spy.calls, [])


class AdminDeviceAccess(_Case):
    def setUp(self):
        timeout = mock.patch.object(access, "QUERY_TIMEOUT_SECONDS", SHORT_TIMEOUT)
        timeout.start()
        self.addCleanup(timeout.stop)
        self.spy = _ExecutionSpy()
        execution = mock.patch.object(access.ssh, "run_command", self.spy)
        execution.start()
        self.addCleanup(execution.stop)

    def handle(self, address, port, pin):
        handle = access.DeviceAccess.__new__(access.DeviceAccess)
        handle.device = SimpleNamespace(
            name="f3-device", platform="fortios", address=address, port=port,
            host_key_fingerprint=pin, legacy_ssh=None, check_address=None,
        )
        handle.credential = handle.check_credential = _Credential()
        handle._host_key_lines = {}
        return handle

    def test_unreachable_target_is_not_reported_as_host_key_problem(self):
        for label, address, port in _unreachable_targets(self):
            with self.subTest(label):
                with self.assertRaises(access.AccessError) as raised:
                    self.handle(address, port, _random_pin()).query("get system status")
                self.assert_reachability_diagnosis(label, str(raised.exception))
        self.assertEqual(self.spy.calls, [])

    def test_control_foreign_host_key_is_refused_without_running_the_command(self):
        server = ForeignKeySshServer()
        self.addCleanup(server.close)
        with self.assertRaises(access.AccessError) as raised:
            self.handle(LOOPBACK, server.port, _random_pin()).query("get system status")
        self.assertGreaterEqual(server.key_exchanges, 1, "harness: the test server was never asked")
        self.assert_host_key_refusal(str(raised.exception))
        self.assertEqual(self.spy.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
