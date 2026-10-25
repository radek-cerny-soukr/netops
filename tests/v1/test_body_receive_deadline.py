import asyncio
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import uvicorn

from netops import gateway
from netops.audit import Audit
from test_admission_uvicorn import TOKEN, Probe, certificate

DEADLINE = 0.5


def records(audit):
    return [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]


class BodyReceiveDeadline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.deadline = patch.object(gateway, "BODY_RECEIVE_SECONDS", DEADLINE, create=True)
        self.deadline.start()
        self.directory = tempfile.TemporaryDirectory()
        cert_path, key_path = certificate(self.directory.name)
        self.dispatched = []
        async def app(scope, receive, send):
            message = await receive()
            self.dispatched.append(json.loads(message["body"])["marker"])
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"content-length", b"2")]})
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
        for writer in self.connections:
            writer.close()
        self.server.should_exit = True
        await asyncio.wait_for(self.serving, 10)
        self.directory.cleanup()
        self.deadline.stop()

    async def connect(self, marker, declared, sent):
        body = json.dumps({"marker": marker, "pad": "a" * declared}).encode()
        head = "\r\n".join(["POST /mcp HTTP/1.1", "Host: localhost", "Authorization: Bearer " + TOKEN,
                            "Content-Type: application/json", "Content-Length: %d" % len(body)]) + "\r\n\r\n"
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port, ssl=self.context, server_hostname="localhost")
        self.connections.append(writer)
        writer.write(head.encode() + body[:sent if sent is not None else len(body)])
        await writer.drain()
        return reader, writer, len(body)

    async def wait_for(self, condition, seconds=5):
        for _ in range(int(seconds * 100)):
            if condition():
                return True
            await asyncio.sleep(0.01)
        return False

    async def answer(self, reader, seconds):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), seconds)
        except (TimeoutError, asyncio.IncompleteReadError):
            return None, b""
        length = next(int(line.split(b":", 1)[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:"))
        body = await asyncio.wait_for(reader.readexactly(length), seconds)
        return int(head.split()[1]), head + body

    async def closed(self, reader, seconds):
        try:
            return await asyncio.wait_for(reader.read(), seconds) == b""
        except (ConnectionError, ssl.SSLError):
            return True

    def rejections(self):
        return [r for r in records(self.audit) if r["direction"] == "rejection"]

    async def test_sixteen_incomplete_small_bodies_release_their_slots_at_the_deadline(self):
        holders = [await self.connect("holder-%d" % index, 100, 40) for index in range(16)]
        self.assertTrue(await self.wait_for(lambda: len(self.entered) == 16), "the holders never took the general slots")
        control, _, _ = await self.connect("control", 100, None)
        status, _ = await self.answer(control, DEADLINE * 8)
        self.assertEqual(status, 200, "a complete request stayed blocked behind incomplete bodies")
        self.assertEqual(self.dispatched, ["control"], "an incomplete body reached the application")
        for reader, _, _ in holders:
            status, raw = await self.answer(reader, 5)
            self.assertEqual(status, 408)
            self.assertIn(b"connection: close", raw.lower())
            self.assertIn(b'"request_body_timeout"', raw)
            self.assertTrue(await self.closed(reader, 5), "the connection stayed open after the 408 response")
        self.assertTrue(await self.wait_for(lambda: self.boundary.slots._value == 16), "a slot was not returned")
        rejected = self.rejections()
        self.assertEqual(len(rejected), 16)
        for record in rejected:
            self.assertEqual(record["payload"], {"reason": "body_timeout", "phase": "request_body", "complete_body": False,
                                                 "received_bytes": 40, "operation_executed": False})
        text = json.dumps(records(self.audit))
        self.assertNotIn("holder-", text, "a body fragment of an incomplete request reached the audit")
        self.assertNotIn(TOKEN, text)

    async def test_incomplete_large_body_releases_the_large_lane(self):
        holder, _, _ = await self.connect("large-holder", 200000, 100000)
        self.assertTrue(await self.wait_for(lambda: len(self.entered) == 1), "the large holder never entered")
        second, _, size = await self.connect("large-second", 200000, None)
        status, _ = await self.answer(second, DEADLINE * 8)
        self.assertEqual(status, 200, "a complete large request stayed blocked behind an incomplete large body")
        self.assertEqual(self.dispatched, ["large-second"])
        status, _ = await self.answer(holder, 5)
        self.assertEqual(status, 408)
        self.assertTrue(await self.closed(holder, 5), "the connection stayed open after the 408 response")
        self.assertTrue(await self.wait_for(lambda: self.boundary.large_requests._value == 1), "the large lane was not returned")
        rejected = self.rejections()
        self.assertEqual(len(rejected), 1)
        self.assertFalse(rejected[0]["payload"]["complete_body"])
        self.assertGreater(rejected[0]["payload"]["received_bytes"], 0)
        self.assertLess(rejected[0]["payload"]["received_bytes"], size)

    async def test_body_completed_in_parts_before_the_deadline_is_dispatched(self):
        reader, writer, size = await self.connect("slow", 100, 40)
        body = json.dumps({"marker": "slow", "pad": "a" * 100}).encode()
        await asyncio.sleep(DEADLINE / 3)
        writer.write(body[40:])
        await writer.drain()
        status, _ = await self.answer(reader, 5)
        self.assertEqual(status, 200)
        self.assertEqual(self.dispatched, ["slow"])
        self.assertEqual(self.rejections(), [])


if __name__ == "__main__":
    unittest.main()
