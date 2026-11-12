"""Audit failure and ASGI backpressure after the first progress report."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops import gateway
from netops.audit import Audit, AuditUnavailable

TOKEN = "synthetic-progress-delivery-token-123456789"
CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
    "name": "triage_health", "arguments": {"target": "device-a"},
    "_meta": {"progressToken": "test"}}}


class ProgressDeliveryFailures(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, *, fail_audit=False, blocked=None, app_error=False, disconnect=False):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(Path(directory) / "audit", {"mode": "local"})
            original = audit.record
            async def record(direction, *args, **kwargs):
                if fail_audit and direction == "response":
                    raise AuditUnavailable("synthetic audit failure")
                return await original(direction, *args, **kwargs)
            audit.record = record
            finished = asyncio.Event()
            sending = asyncio.Event()
            async def app(scope, receive, send):
                try:
                    await receive()
                    await gateway.PROGRESS_SINK.get()({"progress": 1, "total": 2})
                    if app_error:
                        raise ValueError("synthetic operation failure")
                    if blocked or disconnect:
                        await asyncio.Event().wait()
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": json.dumps({
                        "jsonrpc": "2.0", "id": 7, "result": {}}).encode()})
                finally:
                    finished.set()
            events = []
            async def send(event):
                events.append(event)
                sending.set()
                is_error = b'operation_failed' in event.get("body", b"")
                if ((blocked == "start" and event["type"] == "http.response.start")
                        or (blocked == "progress" and b'notifications/progress' in event.get("body", b""))
                        or (blocked == "error" and is_error) or disconnect):
                    await asyncio.Event().wait()
            received = False
            async def receive():
                nonlocal received
                if not received:
                    received = True
                    return {"type": "http.request", "body": json.dumps(CALL).encode()}
                if disconnect:
                    await sending.wait()
                    return {"type": "http.disconnect"}
                await asyncio.Event().wait()
            boundary = gateway.AuditBoundary(app, audit)
            boundary.token = lambda: TOKEN
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + TOKEN).encode())]}
            error = None
            with patch.object(gateway, "RESPONSE_SEND_SECONDS", 0.03):
                task = asyncio.create_task(boundary(scope, receive, send))
                done, _ = await asyncio.wait((task,), timeout=0.3)
                timely = bool(done)
                if not done:
                    task.cancel()
                try:
                    await task
                except BaseException as exc:
                    error = exc
            self.assertTrue(timely, "SSE delivery held admission past its deadline")
            self.assertTrue(finished.is_set(), "application task was not reaped")
            self.assertEqual(boundary.slots._value, gateway.MAX_CONCURRENT_REQUESTS)
            self.assertEqual([e["status"] for e in events if e["type"] == "http.response.start"], [200])
            return events, error

    async def test_result_audit_failure_does_not_send_second_headers_or_false_outcome(self):
        events, error = await self.exercise(fail_audit=True)
        self.assertIsInstance(error, AuditUnavailable)
        self.assertNotIn(b'operation_may_have_completed', b''.join(e.get("body", b"") for e in events))
        self.assertFalse(any(e["type"] == "http.response.body" and not e.get("more_body", False) for e in events))

    async def test_start_progress_and_error_sends_are_bounded(self):
        for blocked in ("start", "progress", "error"):
            with self.subTest(blocked=blocked):
                _, error = await self.exercise(blocked=blocked, app_error=blocked == "error")
                self.assertIsInstance(error, TimeoutError)

    async def test_progress_disconnect_reaps_application(self):
        _, error = await self.exercise(disconnect=True)
        self.assertIsNone(error)
