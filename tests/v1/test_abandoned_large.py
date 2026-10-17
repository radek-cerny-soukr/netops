import asyncio
import io
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import uvicorn

from netops.audit import Audit
from netops.gateway import AuditBoundary
from test_admission_uvicorn import TOKEN, Probe, certificate

PRIVATE = "synthetic-private-receive-failure"


def records(audit):
    return [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]


class AbandonedLargeRequest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        cert_path, key_path = certificate(self.directory.name)
        self.release = asyncio.get_running_loop().create_future()
        self.calls = []
        async def app(scope, receive, send):
            message = await receive()
            self.calls.append(json.loads(message["body"])["marker"])
            if len(self.calls) == 1:
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

    async def asyncTearDown(self):
        if not self.release.done():
            self.release.set_result(None)
        self.server.should_exit = True
        await asyncio.wait_for(self.serving, 10)
        self.directory.cleanup()

    def request(self, marker, size=200000):
        body = json.dumps({"marker": marker, "pad": "a" * size}).encode()
        head = "\r\n".join(["POST /mcp HTTP/1.1", "Host: localhost", "Authorization: Bearer " + TOKEN,
                            "Content-Type: application/json", "Content-Length: %d" % len(body)]) + "\r\n\r\n"
        return head.encode() + body, len(body)

    async def connect(self, payload):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port, ssl=self.context, server_hostname="localhost")
        writer.write(payload)
        await writer.drain()
        return reader, writer

    async def wait_for(self, condition, seconds=5):
        for _ in range(int(seconds * 100)):
            if condition():
                return True
            await asyncio.sleep(0.01)
        return False

    async def scenario(self, abandon):
        holder_reader, holder = await self.connect(self.request("holder")[0])
        self.assertTrue(await self.wait_for(lambda: self.calls == ["holder"]), "holder never dispatched")
        payload, size = self.request("second")
        reader, writer = await self.connect(payload)
        await asyncio.sleep(0.5)
        if abandon:
            writer.close()
            await asyncio.sleep(0.5)
        self.assertEqual(self.entered, ["/mcp"], "the second large request entered while the lane was held")
        self.release.set_result(None)
        self.assertTrue(await self.wait_for(lambda: len(self.entered) == 2), "second request never left admission")
        await asyncio.sleep(1.0)
        holder_status = (await asyncio.wait_for(holder_reader.readline(), 5)).split()[1]
        holder.close()
        self.assertEqual(holder_status, b"200")
        return reader, writer, size

    def chains(self):
        result = {}
        for record in records(self.audit):
            if record["direction"] not in ("instance_start", "instance_stop"):
                result.setdefault(record["correlation"], []).append(record)
        return list(result.values())

    async def test_abandoned_large_request_is_audited_with_content_and_never_dispatched(self):
        _, _, size = await self.scenario(abandon=True)
        self.assertEqual(self.calls, ["holder"], "work was done for a client that already left")
        chains = self.chains()
        self.assertEqual(sorted(tuple(r["direction"] for r in c) for c in chains),
                         [("request", "client_disconnect", "connection_end"), ("request", "response", "connection_end")])
        abandoned = next(c for c in chains if c[1]["direction"] == "client_disconnect")
        self.assertEqual(abandoned[0]["payload"]["marker"], "second", "the complete request content must be audited")
        self.assertEqual(abandoned[1]["payload"], {"phase": "before_dispatch", "complete_body": True, "received_bytes": size, "operation_executed": False})
        self.assertEqual(abandoned[2]["payload"], {"delivery": "not_started"})

    async def test_live_large_request_is_still_dispatched_and_answered(self):
        reader, writer, _ = await self.scenario(abandon=False)
        self.assertEqual(self.calls, ["holder", "second"])
        self.assertEqual((await asyncio.wait_for(reader.readline(), 5)).split()[1], b"200")
        writer.close()
        self.assertNotIn("client_disconnect", [r["direction"] for r in records(self.audit)])


class OwnedDisconnectCheck(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, outer_cancels, cleanup_fails):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            loop = asyncio.get_running_loop()
            loop_errors = []
            loop.set_exception_handler(lambda _, context: loop_errors.append(context))
            dispatched, sent = [], []
            async def app(scope, receive, send):
                dispatched.append(True)
                await receive()
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"{}"})
            boundary = AuditBoundary(app, audit)
            boundary.token = lambda: TOKEN
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {"pad": "a" * 70000}}}).encode()
            scope = {"type": "http", "scheme": "https", "http_version": "1.1", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + TOKEN).encode()), (b"content-length", str(len(body)).encode())]}
            first, active, peak = [True], [0], [0]
            cleanup_entered, cleanup_release = asyncio.Event(), asyncio.Event()
            async def receive():
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                try:
                    if first[0]:
                        first[0] = False
                        return {"type": "http.request", "body": body, "more_body": False}
                    try:
                        await loop.create_future()
                    except asyncio.CancelledError:
                        cleanup_entered.set()
                        await cleanup_release.wait()
                        if cleanup_fails:
                            raise OSError(PRIVATE)
                        raise
                finally:
                    active[0] -= 1
            async def send(event):
                sent.append(event)
            async def all_slots():
                taken = 0
                try:
                    for _ in range(16):
                        await boundary.slots.acquire()
                        taken += 1
                finally:
                    for _ in range(taken):
                        boundary.slots.release()
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                task = asyncio.create_task(boundary(scope, receive, send))
                await asyncio.wait_for(cleanup_entered.wait(), 5)
                barrier = asyncio.create_task(all_slots())
                for _ in range(outer_cancels):
                    task.cancel()
                    await asyncio.sleep(0.02)
                await asyncio.sleep(0.2)
                self.assertFalse(task.done(), "the request finished while its own receive was still unwinding")
                self.assertFalse(barrier.done(), "a slot was released while the receive cleanup was still owned")
                self.assertEqual(dispatched, [], "dispatch overlapped the unfinished disconnect check")
                cleanup_release.set()
                await asyncio.wait((task, barrier), timeout=5)
                self.assertTrue(task.done() and barrier.done())
                for _ in range(5):
                    await asyncio.sleep(0)
            self.assertEqual(peak[0], 1, "two receive calls overlapped")
            self.assertEqual(loop_errors, [])
            self.assertNotIn(PRIVATE, stderr.getvalue())
            return task, [r["direction"] for r in records(audit)], records(audit), dispatched, sent

    async def test_timeout_path_waits_for_receive_cleanup_then_dispatches(self):
        task, directions, _, dispatched, sent = await self.run_case(outer_cancels=0, cleanup_fails=False)
        self.assertFalse(task.cancelled())
        self.assertEqual(dispatched, [True])
        self.assertEqual(directions, ["request", "response", "connection_end"])
        self.assertEqual(sent[0]["status"], 200)

    async def test_repeated_outer_cancel_during_check_is_owned_and_audited_as_interrupted(self):
        task, directions, items, dispatched, sent = await self.run_case(outer_cancels=3, cleanup_fails=False)
        self.assertTrue(task.cancelled())
        self.assertEqual(dispatched, [])
        self.assertEqual(sent, [])
        self.assertEqual(directions, ["request", "interrupted", "connection_end"])
        self.assertIs(items[1]["payload"]["operation_may_have_completed"], False)
        self.assertEqual(items[2]["payload"], {"delivery": "interrupted"})

    async def test_failing_receive_cleanup_under_cancel_leaks_nothing(self):
        task, directions, _, dispatched, sent = await self.run_case(outer_cancels=3, cleanup_fails=True)
        self.assertTrue(task.cancelled())
        self.assertEqual(dispatched, [])
        self.assertEqual(directions, ["request", "interrupted", "connection_end"])


if __name__ == "__main__":
    unittest.main()
