import asyncio
import json
import tempfile
import unittest

from netops.audit import Audit
from netops.gateway import AuditBoundary

TOKEN = "synthetic-gateway-token-for-test-only-123456"
WAIT = 0.3


class Request:
    def __init__(self, boundary, scope, body=b'{"method":"synthetic-call"}'):
        self.read = asyncio.Event()
        self.statuses = []
        self.body = body
        self.task = asyncio.create_task(boundary(scope, self.receive, self.send))

    async def receive(self):
        self.read.set()
        return {"type": "http.request", "body": self.body, "more_body": False}

    async def send(self, event):
        if event["type"] == "http.response.start":
            self.statuses.append(event["status"])


class Admission(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.audit = Audit(self.directory.name, {"mode": "local"})
        self.release = asyncio.get_running_loop().create_future()
        async def app(scope, receive, send):
            await receive()
            await asyncio.shield(self.release)
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b"{}"})
        self.boundary = AuditBoundary(app, self.audit)
        self.boundary.token = lambda: TOKEN
        self.requests = []

    async def asyncTearDown(self):
        if not self.release.done():
            self.release.set_result(None)
        for request in self.requests:
            if not request.task.done():
                request.task.cancel()
        await asyncio.gather(*(request.task for request in self.requests), return_exceptions=True)
        self.directory.cleanup()

    def scope(self, method="POST", headers=(), version="1.1", token=TOKEN, path="/mcp"):
        pairs = [(b"authorization", ("Bearer " + token).encode())] + [(name.encode(), value.encode()) for name, value in headers]
        scope = {"type": "http", "scheme": "https", "method": method, "path": path, "headers": pairs}
        if version is not None:
            scope["http_version"] = version
        return scope

    def start(self, scope, body=b'{"method":"synthetic-call"}'):
        request = Request(self.boundary, scope, body)
        self.requests.append(request)
        return request

    async def entered(self, request, seconds=WAIT):
        try:
            await asyncio.wait_for(asyncio.shield(request.read.wait()), seconds)
            return True
        except TimeoutError:
            return False

    async def hold_large(self):
        holder = self.start(self.scope(headers=[("content-length", "70000")]))
        self.assertTrue(await self.entered(holder, 3), "the first large request did not start")
        return holder

    def records(self):
        return [json.loads(line) for path in self.audit._files() for line in path.read_bytes().splitlines()]

    async def test_framing_decides_admission_for_every_method_and_path(self):
        cases = (
            ("GET /health without framing", "GET", "/health", (), "1.1", False),
            ("GET /health with a 4 MiB length", "GET", "/health", (("content-length", "4194303"),), "1.1", True),
            ("chunked GET", "GET", "/mcp", (("transfer-encoding", "chunked"),), "1.1", True),
            ("POST length 0", "POST", "/mcp", (("content-length", "0"),), "1.1", False),
            ("POST length 65536", "POST", "/mcp", (("content-length", "65536"),), "1.1", False),
            ("POST length 65537", "POST", "/mcp", (("content-length", "65537"),), "1.1", True),
            ("length +5", "POST", "/mcp", (("content-length", "+5"),), "1.1", True),
            ("length with a space", "POST", "/mcp", (("content-length", " 5"),), "1.1", True),
            ("length list", "POST", "/mcp", (("content-length", "5,5"),), "1.1", True),
            ("hex length", "POST", "/mcp", (("content-length", "0x10"),), "1.1", True),
            ("30 digit length", "POST", "/mcp", (("content-length", "1" * 30),), "1.1", True),
            ("duplicate length", "POST", "/mcp", (("content-length", "5"), ("content-length", "5")), "1.1", True),
            ("length and chunked", "POST", "/mcp", (("content-length", "5"), ("transfer-encoding", "chunked")), "1.1", True),
            ("HEAD without framing", "HEAD", "/mcp", (), "1.1", False),
            ("OPTIONS without framing", "OPTIONS", "/mcp", (), "1.1", False),
            ("GET HTTP/1.0 without framing", "GET", "/mcp", (), "1.0", False),
            ("POST without framing", "POST", "/mcp", (), "1.1", True),
            ("GET without http_version", "GET", "/mcp", (), None, True),
        )
        await self.asyncTearDown()
        for label, method, path, headers, version, large in cases:
            with self.subTest(label):
                await self.asyncSetUp()
                try:
                    holder = await self.hold_large()
                    probe = self.start(self.scope(method, headers, version, path=path))
                    self.assertEqual(await self.entered(probe), not large,
                                     "%s entered while a large request held admission" % label if large
                                     else "%s waited behind a large request" % label)
                    if large:
                        self.release.set_result(None)
                        self.assertTrue(await self.entered(probe, 3), "%s never entered after release" % label)
                finally:
                    await self.asyncTearDown()

    async def test_waiting_large_requests_do_not_hold_slots(self):
        await self.hold_large()
        waiting = [self.start(self.scope(headers=[("content-length", "70000")])) for _ in range(15)]
        small = self.start(self.scope(headers=[("content-length", "20")]))
        self.assertTrue(await self.entered(small, 3), "a small request waited behind fifteen queued large requests")
        self.assertFalse(any([await self.entered(request, 0.05) for request in waiting]))

    def assert_admission_cancelled(self, new, method="POST", path="/mcp"):
        new = [item for item in new if item["direction"] != "request"]
        self.assertEqual([item["direction"] for item in new], ["admission_cancelled", "connection_end"])
        self.assertEqual(len({item["correlation"] for item in new}), 1)
        payload = new[0]["payload"]
        self.assertEqual(payload, {"phase": "admission", "body_read": False, "received_bytes": 0,
                                   "operation_executed": False, "reason": "cancelled"})
        self.assertEqual((new[0].get("method"), new[0].get("path"), new[0].get("authenticated")), (method, path, True))
        self.assertNotIn("request_headers", new[0])
        self.assertEqual(new[1]["payload"], {"delivery": "not_started"})

    async def test_a_cancelled_large_waiter_reads_nothing_and_is_audited_as_not_admitted(self):
        await self.hold_large()
        before = self.records()
        waiter = self.start(self.scope(headers=[("content-length", "70000")]), body=b'{"synthetic-body-canary":1}')
        self.assertFalse(await self.entered(waiter))
        waiter.task.cancel()
        await asyncio.gather(waiter.task, return_exceptions=True)
        self.assertFalse(waiter.read.is_set())
        self.assertEqual(waiter.statuses, [])
        new = self.records()[len(before):]
        self.assert_admission_cancelled(new)
        self.assertNotIn("synthetic-body-canary", json.dumps(new))

    async def test_a_cancelled_small_waiter_for_a_slot_is_audited_as_not_admitted(self):
        holders = [self.start(self.scope(headers=[("content-length", "20")])) for _ in range(16)]
        for holder in holders:
            self.assertTrue(await self.entered(holder, 3))
        before = self.records()
        waiter = self.start(self.scope(headers=[("content-length", "20")]))
        self.assertFalse(await self.entered(waiter))
        waiter.task.cancel()
        await asyncio.gather(waiter.task, return_exceptions=True)
        self.assertFalse(waiter.read.is_set())
        self.assert_admission_cancelled(self.records()[len(before):])

    async def test_the_shutdown_barrier_waits_until_cancelled_waiters_are_recorded(self):
        await self.hold_large()
        waiters = [self.start(self.scope(headers=[("content-length", "70000")])) for _ in range(3)]
        await asyncio.sleep(0)
        barrier = getattr(self.boundary, "no_waiters", None)
        self.assertIsNotNone(barrier, "the boundary exposes no waiter barrier for shutdown")
        self.assertFalse(barrier.is_set())
        before = len(self.records())
        for waiter in waiters:
            waiter.task.cancel()
        await asyncio.wait_for(barrier.wait(), 5)
        self.assertEqual(len(self.records()) - before, 6, "the barrier opened before every cancelled waiter was recorded")

    async def test_a_request_cancelled_while_its_body_is_read_is_audited_as_incomplete_body(self):
        started = asyncio.Event()
        stalled = asyncio.get_running_loop().create_future()
        async def receive():
            if not started.is_set():
                started.set()
                return {"type": "http.request", "body": b'{"method":', "more_body": True}
            return await stalled
        async def send(event):
            pass
        before = self.records()
        task = asyncio.create_task(self.boundary(self.scope(headers=[("content-length", "20")]), receive, send))
        await asyncio.wait_for(started.wait(), 3)
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        new = [item for item in self.records()[len(before):] if item["direction"] != "request"]
        self.assertNotIn("admission_cancelled", [item["direction"] for item in new])
        self.assertEqual([item["direction"] for item in new], ["request_body_cancelled", "connection_end"])
        self.assertEqual(len({item["correlation"] for item in new}), 1)
        self.assertEqual(new[0]["payload"], {"phase": "request_body", "complete_body": False, "received_bytes": 10,
                                             "operation_executed": False, "reason": "cancelled"})
        self.assertEqual((new[0].get("method"), new[0].get("path"), new[0].get("authenticated")), ("POST", "/mcp", True))
        self.assertNotIn("request_headers", new[0])
        self.assertNotIn('"method":', json.dumps(new[0]["payload"]))
        self.assertEqual(new[1]["payload"], {"delivery": "not_started"})
        self.assertEqual(getattr(self.boundary, "waiting", 0), 0)

    async def test_an_unauthenticated_large_request_is_refused_while_admission_is_held(self):
        await self.hold_large()
        stranger = self.start(self.scope(headers=[("content-length", "4194303")], token="synthetic-wrong-token-0000000000000000"))
        await asyncio.wait_for(stranger.task, 1)
        self.assertEqual(stranger.statuses, [401])
        self.assertFalse(stranger.read.is_set())


if __name__ == "__main__":
    unittest.main()
