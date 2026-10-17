import asyncio
import datetime
import ssl
import tempfile
import unittest
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from netops.audit import Audit
from netops.gateway import AuditBoundary

TOKEN = "synthetic-gateway-token-for-test-only-123456"


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class Probe(AuditBoundary):
    def __init__(self, app, audit, entered):
        super().__init__(app, audit)
        self.entered = entered
        self.token = lambda: TOKEN

    async def handle(self, scope, receive, send, original_token):
        self.entered.append(scope["path"])
        return await super().handle(scope, receive, send, original_token)


class UvicornH11Admission(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        cert_path, key_path = certificate(self.directory.name)
        self.release = asyncio.get_running_loop().create_future()
        async def app(scope, receive, send):
            if scope["type"] == "lifespan":
                return
            await asyncio.shield(self.release)
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b"{}"})
        self.entered = []
        self.audit = Audit(Path(self.directory.name) / "audit", {"mode": "local"})
        self.boundary = Probe(app, self.audit, self.entered)
        config = uvicorn.Config(self.boundary, host="127.0.0.1", port=0, ssl_certfile=str(cert_path),
                                ssl_keyfile=str(key_path), log_level="critical", lifespan="off", http="h11")
        self.server = uvicorn.Server(config)
        self.serving = asyncio.create_task(self.server.serve())
        while not self.server.started:
            await asyncio.sleep(0.01)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        self.context = ssl.create_default_context(cafile=str(cert_path))
        self.connections = []

    async def asyncTearDown(self):
        if not self.release.done():
            self.release.set_result(None)
        for writer in self.connections:
            writer.close()
        self.server.should_exit = True
        await asyncio.wait_for(self.serving, 10)
        self.directory.cleanup()

    async def send(self, head, body=b""):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port, ssl=self.context, server_hostname="localhost")
        self.connections.append(writer)
        writer.write(head.encode("latin-1") + b"\r\n" + body)
        await writer.drain()
        return reader

    def head(self, method, path, headers):
        lines = ["%s %s HTTP/1.1" % (method, path), "Host: localhost", "Authorization: Bearer " + TOKEN]
        lines += ["%s: %s" % pair for pair in headers]
        return "\r\n".join(lines) + "\r\n"

    async def status(self, reader, seconds):
        try:
            line = await asyncio.wait_for(reader.readline(), seconds)
        except TimeoutError:
            return None
        return int(line.split()[1]) if line else 0

    async def hold(self):
        body = b'{"method":"synthetic-call","pad":"' + b"a" * (70000 - 36) + b'"}'
        await self.send(self.head("POST", "/mcp", [("Content-Length", str(len(body)))]), body)
        for _ in range(300):
            if self.entered:
                return
            await asyncio.sleep(0.01)
        self.fail("the holding large request never entered")

    async def test_large_bodies_wait_and_small_get_passes_through_the_real_h11_server(self):
        await self.hold()
        await self.send(self.head("GET", "/health", [("Content-Length", "70000")]), b"y" * 70000)
        await self.send(self.head("POST", "/mcp", [("Transfer-Encoding", "chunked")]), b"5\r\nhello\r\n0\r\n\r\n")
        small = await self.send(self.head("GET", "/health", []))
        for _ in range(300):
            if len(self.entered) >= 2:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.entered, ["/mcp", "/health"], "only the holder and the bodyless GET may enter")
        self.assertEqual(await self.status(small, 3), 200)
        await asyncio.sleep(0.3)
        self.assertEqual(self.entered, ["/mcp", "/health"], "a large body entered while admission was held")
        self.release.set_result(None)
        for _ in range(300):
            if len(self.entered) == 4:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(sorted(self.entered[2:]), ["/health", "/mcp"])

    async def test_ambiguous_lengths_are_refused_by_h11_before_the_gateway(self):
        for headers in ([("Content-Length", "+5")], [("Content-Length", "5"), ("Content-Length", "6")],
                        [("Content-Length", "0x10")]):
            with self.subTest(headers=headers):
                before = list(self.entered)
                reader = await self.send(self.head("POST", "/mcp", headers), b"hello")
                status = await self.status(reader, 3)
                self.assertIn(status, (400, 0), headers)
                self.assertEqual(self.entered, before)

    async def test_h11_accepts_length_with_chunked_and_the_gateway_still_waits(self):
        await self.hold()
        await self.send(self.head("POST", "/mcp", [("Content-Length", "5"), ("Transfer-Encoding", "chunked")]),
                        b"5\r\nhello\r\n0\r\n\r\n")
        await asyncio.sleep(0.5)
        self.assertEqual(self.entered, ["/mcp"], "a request with length and chunked framing entered while admission was held")
        self.release.set_result(None)
        for _ in range(300):
            if len(self.entered) == 2:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.entered, ["/mcp", "/mcp"])


if __name__ == "__main__":
    unittest.main()
