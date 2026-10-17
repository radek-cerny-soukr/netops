import asyncio
from datetime import datetime
import json
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from netops import audit as audit_module
from netops import gateway
from netops.audit import Audit
from netops.gateway import AuditBoundary, RemoteTool
from netops.redaction import redact

TOKEN = "synthetic-gateway-token-for-test-only-123456"
NO_FINDING = "No finding matches the requested fingerprint for this device"
CANARY = "synthetic-fingerprint-canary-0001"


class AuditContractNegatives(unittest.IsolatedAsyncioTestCase):
    def records(self, audit):
        return [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]

    def boundary(self, app, audit):
        boundary = AuditBoundary(app, audit)
        boundary.token = lambda: TOKEN
        return boundary

    def scope(self):
        return {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                "headers": [(b"authorization", ("Bearer " + TOKEN).encode())]}

    async def receive(self):
        return {"type": "http.request", "body": b'{"method":"synthetic-call"}', "more_body": False}

    async def cancel_and_wait(self, task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        self.assertTrue(task.cancelled())

    def assert_interrupted_tail(self, records, prefix, may_have_completed):
        self.assertEqual([item["direction"] for item in records],
                         prefix + ["interrupted", "connection_end"])
        self.assertEqual(len({item["correlation"] for item in records}), 1)
        self.assertIs(records[-2]["payload"].get("operation_may_have_completed"), may_have_completed)
        self.assertIs(records[-2]["payload"].get("automatic_retry"), False)
        self.assertEqual(records[-1]["payload"].get("delivery"), "interrupted")

    async def test_c4_cancel_during_request_commit_before_dispatch_reports_not_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls, sent = [], []
            entered = asyncio.Event()
            release = threading.Event()
            loop = asyncio.get_running_loop()
            actual_append = audit._append
            def append(event):
                if event["direction"] == "request":
                    loop.call_soon_threadsafe(entered.set)
                    if not release.wait(10):
                        raise TimeoutError("Synthetic append gate deadline")
                actual_append(event)
            async def app(scope, receive, send):
                calls.append(True)
            async def send(event):
                sent.append(event)
            with patch.object(audit, "_append", append):
                task = asyncio.create_task(self.boundary(app, audit)(self.scope(), self.receive, send))
                try:
                    await asyncio.wait_for(entered.wait(), 3)
                    task.cancel()
                    await asyncio.sleep(0)
                finally:
                    release.set()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.assertTrue(task.cancelled())
            self.assertEqual(calls, [])
            self.assertEqual(sent, [])
            self.assert_interrupted_tail(self.records(audit), ["request"], False)

    async def test_c5_cancel_after_dispatch_reports_operation_may_have_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls, sent = [], []
            app_started = asyncio.Event()
            async def app(scope, receive, send):
                calls.append(True)
                app_started.set()
                await asyncio.get_running_loop().create_future()
            async def send(event):
                sent.append(event)
            task = asyncio.create_task(self.boundary(app, audit)(self.scope(), self.receive, send))
            await asyncio.wait_for(app_started.wait(), 3)
            await self.cancel_and_wait(task)
            self.assertEqual(calls, [True])
            self.assertEqual(sent, [])
            self.assert_interrupted_tail(self.records(audit), ["request"], True)

    async def test_c6_cancel_during_send_after_committed_response_is_audited_as_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls, sent = [], []
            send_blocked = asyncio.Event()
            async def app(scope, receive, send):
                calls.append(True)
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b'{"result":"synthetic-result"}'})
            async def send(event):
                sent.append(event["type"])
                if event["type"] == "http.response.start":
                    send_blocked.set()
                    await asyncio.get_running_loop().create_future()
            task = asyncio.create_task(self.boundary(app, audit)(self.scope(), self.receive, send))
            await asyncio.wait_for(send_blocked.wait(), 3)
            await self.cancel_and_wait(task)
            self.assertEqual(calls, [True])
            self.assertEqual(sent, ["http.response.start"])
            records = self.records(audit)
            self.assert_interrupted_tail(records, ["request", "response", "connection_end"], True)
            self.assertEqual(records[2]["payload"].get("delivery"), "committed-before-send")
            self.assertEqual(records[1]["payload"], {"result": "synthetic-result"})

    async def slow_large_and_fast_small(self, directory):
        audit = Audit(directory, {"mode": "local"})
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()
        started = asyncio.Event()
        release = threading.Event()
        inline = []
        def blocked(value, secrets):
            payload = value["payload"]
            if isinstance(payload, dict) and payload.get("marker") == "large":
                if threading.get_ident() == loop_thread:
                    inline.append(True)
                    started.set()
                else:
                    loop.call_soon_threadsafe(started.set)
                    if not release.wait(10):
                        raise TimeoutError("Synthetic redaction gate deadline")
            return redact(value, secrets)
        with patch.object(audit_module, "redact", blocked):
            large = asyncio.create_task(audit.record("request", {"marker": "large", "blob": "x" * 262144}, "large"))
            try:
                await asyncio.wait_for(started.wait(), 3)
                await audit.record("request", {"marker": "small"}, "small", heavy=False)
            finally:
                release.set()
                await large
        return self.records(audit), inline

    async def test_c2_file_order_times_never_decrease_under_slow_large_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            records, _ = await self.slow_large_and_fast_small(directory)
            self.assertEqual(sorted(item["correlation"] for item in records), ["large", "small"])
            times = [datetime.fromisoformat(item["time"]) for item in records]
            self.assertEqual(times, sorted(times))

    async def test_c2_small_record_is_committed_before_slow_large_record(self):
        with tempfile.TemporaryDirectory() as directory:
            records, inline = await self.slow_large_and_fast_small(directory)
            self.assertEqual(inline, [], "Redaction must execute outside the event loop")
            self.assertEqual([item["correlation"] for item in records], ["small", "large"])
            self.assertLessEqual(datetime.fromisoformat(records[0]["time"]), datetime.fromisoformat(records[1]["time"]))

    def wire(self, structured):
        return {"result": {"content": [], "structuredContent": structured, "isError": False}}

    async def run_tool(self, role, name, wire):
        schema = {"type": "object", "properties": {"device": {"type": "string"}, "fingerprint": {"type": "string"}}}
        arguments = {"device": "synthetic-device", "fingerprint": CANARY}
        rpc = AsyncMock(return_value=wire)
        with patch.object(gateway, "rpc", rpc):
            result = await RemoteTool(name=name, parameters=schema, role=role).run(arguments)
        rpc.assert_awaited_once_with(role, {"action": "call", "name": name, "arguments": arguments})
        return result

    def rendered(self, result):
        return "".join(getattr(item, "text", "") for item in result.content) + json.dumps(result.structured_content)

    async def test_c9_auditor_finding_detail_missing_finding_is_error_without_canary(self):
        result = await self.run_tool("auditor", "finding_detail", self.wire({"result": None}))
        self.assertTrue(result.is_error)
        self.assertEqual([item.text for item in result.content], [NO_FINDING])
        self.assertIsNone(result.structured_content)
        self.assertNotIn(CANARY, self.rendered(result))

    async def test_c9_same_shape_for_other_role_or_tool_is_not_rewritten(self):
        for role, name in (("helper", "finding_detail"), ("auditor", "list_findings")):
            with self.subTest(role=role, name=name):
                result = await self.run_tool(role, name, self.wire({"result": None}))
                self.assertFalse(result.is_error)
                self.assertEqual(result.content, [])
                self.assertEqual(result.structured_content, {"result": None})
                self.assertNotIn(NO_FINDING, self.rendered(result))

    async def test_c9_existing_finding_passes_unchanged(self):
        result = await self.run_tool("auditor", "finding_detail", self.wire({"result": {"id": 1}}))
        self.assertFalse(result.is_error)
        self.assertEqual(result.content, [])
        self.assertEqual(result.structured_content, {"result": {"id": 1}})
        self.assertNotIn(NO_FINDING, self.rendered(result))

    async def test_c3_token_recheck_read_failure_closes_connection_without_request_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls, sent = [], []
            reads = 0
            async def app(scope, receive, send):
                calls.append(True)
            boundary = AuditBoundary(app, audit)
            def read_token():
                nonlocal reads
                reads += 1
                if reads > 1:
                    raise OSError("synthetic-private-token-read-failure")
                return TOKEN
            boundary.token = read_token
            async def send(event):
                sent.append(event)
            await boundary(self.scope(), self.receive, send)
            self.assertEqual(calls, [])
            self.assertEqual(self.records(audit), [])
            self.assertEqual(sent[0]["status"], 503)
            headers = [(name.lower(), value.lower()) for name, value in sent[0]["headers"]]
            self.assertIn((b"connection", b"close"), headers)
            self.assertNotIn(b"synthetic-private-token-read-failure", sent[1]["body"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
