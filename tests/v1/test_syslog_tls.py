import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from netops.audit import Audit
from netops.files import MAX_MESSAGE, read_private, write_private
from netops.syslog_parts import decode_messages

def received_messages(connection):
    messages = []
    while True:
        prefix = bytearray()
        while True:
            part = connection.recv(1)
            if not part:
                if prefix:
                    raise ValueError("Truncated octet count")
                return messages
            if part == b" ":
                break
            if not part.isdigit() or len(prefix) >= 9:
                raise ValueError("Invalid octet count")
            prefix.extend(part)
        expected = int(prefix)
        if not 0 < expected <= 2048:
            raise ValueError("Message exceeds the syslog interoperability cap")
        message = bytearray()
        while len(message) < expected:
            block = connection.recv(min(65536, expected - len(message)))
            if not block:
                raise ValueError("Truncated message")
            message.extend(block)
        messages.append(bytes(message).split(b" - netops - - - ", 1)[1])

def received_records(messages):
    ids = list(dict.fromkeys(json.loads(body)["record_id"] for body in messages))
    return [json.loads(decode_messages(messages, record_id)) for record_id in ids]

class SyslogTLS(unittest.IsolatedAsyncioTestCase):
    def identity(self, directory):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        write_private(directory / "cert.pem", cert.public_bytes(serialization.Encoding.PEM))
        write_private(directory / "key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return directory / "cert.pem", directory / "key.pem"

    async def exchange(self, size, clean, reply=True, fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cert, key = self.identity(directory)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            result = {}
            def receiver():
                try:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with context.wrap_socket(raw, server_side=True, suppress_ragged_eofs=False) as connection:
                        if not clean:
                            connection.recv(1)
                            return
                        messages = received_messages(connection)
                        records = received_records(messages)
                        self.assertEqual(len(records), 1)
                        result["message"] = records[0]
                        result["parts"] = len(messages)
                        if reply:
                            connection.unwrap()
                except Exception as error:
                    result["error"] = type(error).__name__
                finally:
                    listener.close()
            thread = threading.Thread(target=receiver, daemon=True)
            thread.start()
            audit = Audit(directory / "audit", {"mode": "syslog", "host": "localhost", "port": listener.getsockname()[1], "ca_file": str(cert)})
            await audit.record("request", {"padding": "x" * size}, "large-record")
            queued = audit._files()[0]
            original = read_private(queued, MAX_MESSAGE * 2)
            if fault:
                from unittest.mock import patch
                method, error = fault
                with patch.object(ssl.SSLSocket, method, side_effect=error):
                    with self.assertRaises(type(error)):
                        await asyncio.to_thread(audit._send, queued)
                self.assertEqual(read_private(queued, MAX_MESSAGE * 2), original)
            elif clean:
                await asyncio.to_thread(audit._send, queued)
                self.assertFalse(queued.exists())
            else:
                with self.assertRaises(OSError):
                    await asyncio.to_thread(audit._send, queued)
                self.assertEqual(read_private(queued, MAX_MESSAGE * 2), original)
            await asyncio.to_thread(thread.join, 12)
            self.assertFalse(thread.is_alive())
            if clean and not fault:
                self.assertNotIn("error", result)
                self.assertEqual(result["message"]["payload"]["padding"], "x" * size)
                self.assertGreater(result["parts"], 1)

    async def test_one_mib_and_max_message_arrive_complete_before_queue_removal(self):
        for size in (1024 * 1024, MAX_MESSAGE):
            with self.subTest(size=size):
                await self.exchange(size, True)

    async def test_receiver_that_reads_our_close_notify_without_replying_removes_queued_record(self):
        for size in (1024, MAX_MESSAGE):
            with self.subTest(size=size):
                await self.exchange(size, True, reply=False)

    async def test_only_eof_after_our_close_notify_is_tolerated(self):
        for method, error in (("sendall", ssl.SSLEOFError(8, "EOF during send")), ("unwrap", TimeoutError("timed out")),
                              ("unwrap", ConnectionResetError(104, "reset")), ("unwrap", ssl.SSLError(1, "alert"))):
            with self.subTest(method=method, error=type(error).__name__):
                await self.exchange(1024, True, fault=(method, error))

    async def test_receiver_reset_keeps_complete_queued_record(self):
        await self.exchange(MAX_MESSAGE, False)

    async def test_forwarding_batches_hundreds_of_records_in_order_over_few_connections(self):
        import time
        count = 300
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cert, key = self.identity(directory)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            listener.settimeout(30)
            received, state = [], {"connections": 0}
            def frames(connection):
                messages = received_messages(connection)
                received.extend(row["correlation"] for row in received_records(messages))
            def receiver():
                try:
                    while len(received) < count:
                        raw, _ = listener.accept()
                        raw.settimeout(30)
                        state["connections"] += 1
                        with context.wrap_socket(raw, server_side=True) as connection:
                            frames(connection)
                            connection.unwrap()
                except Exception as error:
                    state["error"] = type(error).__name__
                finally:
                    listener.close()
            thread = threading.Thread(target=receiver, daemon=True)
            thread.start()
            audit = Audit(directory / "audit", {"mode": "syslog", "host": "localhost", "port": listener.getsockname()[1], "ca_file": str(cert)})
            for index in range(count):
                await audit.record("request", {"index": index}, "record-%04d" % index)
            started = time.monotonic()
            forwarder = asyncio.create_task(audit.forward())
            while audit._files() and time.monotonic() - started < 30:
                await asyncio.sleep(0.05)
            audit.stop.set()
            await forwarder
            await asyncio.to_thread(thread.join, 10)
            self.assertNotIn("error", state)
            self.assertEqual(audit._files(), [])
            self.assertEqual(received, ["record-%04d" % index for index in range(count)])
            self.assertLessEqual(state["connections"], 2)
            self.assertLess(time.monotonic() - started, 20)

    async def test_unreachable_receiver_keeps_records_and_reports_once(self):
        import io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            closed = socket.socket()
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
            closed.close()
            audit = Audit(directory / "audit", {"mode": "syslog", "host": "localhost", "port": port})
            for index in range(5):
                await audit.record("request", {"index": index}, "kept-%d" % index)
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                forwarder = asyncio.create_task(audit.forward())
                await asyncio.sleep(4)
                audit.stop.set()
                await forwarder
            self.assertEqual(len(audit._files()), 5)
            self.assertEqual(stderr.getvalue().count("syslog delivery failed"), 1, stderr.getvalue())

if __name__ == "__main__":
    unittest.main()
