import asyncio
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from netops import audit as audit_module
from netops.audit import Audit
from netops.gateway import AuditBoundary
from netops.redaction import redact


class AuditCancellation(unittest.IsolatedAsyncioTestCase):
    def records(self, audit):
        return [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]

    async def test_maximum_cardinality_record_preserves_content_without_blocking_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            payload = {"oids": [1] * 2097077, "password": "synthetic-private-canary"}
            complete = asyncio.Event()
            delays = []
            async def heartbeat():
                previous = time.monotonic()
                while not complete.is_set():
                    await asyncio.sleep(0.05)
                    now = time.monotonic()
                    delays.append(now - previous)
                    previous = now
            pulse = asyncio.create_task(heartbeat())
            await asyncio.sleep(0)
            try:
                await audit.record("request", payload, "maximum")
            finally:
                complete.set()
                await pulse
            delay = max(delays)
            records = self.records(audit)
            self.assertEqual(len(records), 1)
            self.assertEqual(len(records[0]["payload"]["oids"]), len(payload["oids"]))
            self.assertTrue(all(item == 1 for item in records[0]["payload"]["oids"]))
            self.assertEqual(records[0]["payload"]["password"], "[REDACTED]")
            self.assertLess(delay, 0.5)

    async def test_repeated_cancel_waits_for_redaction_and_durable_commit(self):
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                audit = Audit(directory, {"mode": mode})
                started = asyncio.Event()
                release = threading.Event()
                finished = threading.Event()
                loop = asyncio.get_running_loop()
                def blocked(value, secrets):
                    loop.call_soon_threadsafe(started.set)
                    release.wait(10)
                    try:
                        return redact(value, secrets)
                    finally:
                        finished.set()
                with patch.object(audit_module, "redact", blocked):
                    task = asyncio.create_task(audit.record("request", {"password": "synthetic-private-canary"}, "cancel"))
                    try:
                        await asyncio.wait_for(started.wait(), 3)
                        self.assertFalse(finished.is_set(), "Redaction must execute outside the event loop")
                        task.cancel()
                        await asyncio.sleep(0.01)
                        task.cancel()
                        await asyncio.sleep(0.01)
                        self.assertFalse(task.done(), "Caller must own the work until its durable commit finishes")
                    finally:
                        release.set()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                self.assertTrue(finished.is_set())
                self.assertTrue(task.cancelled())
                records = self.records(audit)
                self.assertEqual([item["direction"] for item in records], ["request"])
                self.assertEqual(records[0]["payload"]["password"], "[REDACTED]")

    async def test_request_and_response_cancel_have_no_early_dispatch_or_delivery(self):
        for phase in ("request", "response"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                audit = Audit(directory, {"mode": "local"})
                started = asyncio.Event()
                release = threading.Event()
                finished = threading.Event()
                calls, sent, dispatch_audit = [], [], []
                loop = asyncio.get_running_loop()
                def blocked(value, secrets):
                    payload = value["payload"]
                    matches = isinstance(payload, dict) and (
                        payload.get("method") == "synthetic-call" if phase == "request"
                        else payload.get("result") == "synthetic-result")
                    if matches:
                        loop.call_soon_threadsafe(started.set)
                        release.wait(10)
                    try:
                        return redact(value, secrets)
                    finally:
                        if matches:
                            finished.set()
                async def app(scope, receive, send):
                    dispatch_audit.append([item["direction"] for item in self.records(audit)])
                    calls.append(True)
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b'{"result":"synthetic-result"}'})
                boundary = AuditBoundary(app, audit)
                boundary.token = lambda: "synthetic-gateway-token-for-test-only-123456"
                async def receive():
                    return {"type": "http.request", "body": b'{"method":"synthetic-call"}', "more_body": False}
                async def send(event):
                    sent.append(event)
                scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                         "headers": [(b"authorization", ("Bearer " + boundary.token()).encode())]}
                with patch.object(audit_module, "redact", blocked):
                    task = asyncio.create_task(boundary(scope, receive, send))
                    try:
                        await asyncio.wait_for(started.wait(), 3)
                        self.assertFalse(finished.is_set())
                        self.assertEqual(len(calls), 0 if phase == "request" else 1)
                        self.assertEqual(sent, [])
                        task.cancel()
                        await asyncio.sleep(0.01)
                        task.cancel()
                        await asyncio.sleep(0.01)
                        self.assertFalse(task.done())
                    finally:
                        release.set()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                self.assertTrue(task.cancelled())
                self.assertEqual(sent, [])
                self.assertEqual(len(calls), 0 if phase == "request" else 1)
                self.assertEqual(dispatch_audit, [] if phase == "request" else [["request"]])
                records = self.records(audit)
                self.assertEqual([item["direction"] for item in records],
                                 ["request"] + (["response"] if phase == "response" else []) + ["interrupted", "connection_end"])
                self.assertEqual(len({item["correlation"] for item in records}), 1)
                self.assertEqual(records[-1]["payload"]["delivery"], "interrupted")

    async def test_cancel_during_cancellation_audit_still_records_connection_end(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            app_started = asyncio.Event()
            cleanup_started = asyncio.Event()
            release = threading.Event()
            finished = threading.Event()
            sent = []
            loop = asyncio.get_running_loop()
            def blocked(value, secrets):
                matches = value["payload"].get("automatic_retry") is False
                if matches and not finished.is_set():
                    loop.call_soon_threadsafe(cleanup_started.set)
                    release.wait(10)
                    finished.set()
                return redact(value, secrets)
            async def app(scope, receive, send):
                app_started.set()
                await asyncio.Event().wait()
            boundary = AuditBoundary(app, audit)
            boundary.token = lambda: "synthetic-gateway-token-for-test-only-123456"
            async def receive():
                return {"type": "http.request", "body": b'{}', "more_body": False}
            async def send(event):
                sent.append(event)
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + boundary.token()).encode())]}
            with patch.object(audit_module, "redact", blocked):
                task = asyncio.create_task(boundary(scope, receive, send))
                try:
                    await asyncio.wait_for(app_started.wait(), 3)
                    task.cancel()
                    await asyncio.wait_for(cleanup_started.wait(), 3)
                    self.assertFalse(finished.is_set())
                    task.cancel()
                    await asyncio.sleep(0.01)
                    task.cancel()
                    await asyncio.sleep(0.01)
                    self.assertFalse(task.done())
                finally:
                    release.set()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.assertTrue(task.cancelled())
            self.assertEqual(sent, [])
            self.assertEqual([item["direction"] for item in self.records(audit)],
                             ["request", "interrupted", "connection_end"])

    async def test_cancellation_audit_failure_never_claims_operation_did_not_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            app_started = asyncio.Event()
            calls, sent = [], []
            async def app(scope, receive, send):
                calls.append(True)
                app_started.set()
                await asyncio.Event().wait()
            boundary = AuditBoundary(app, audit)
            boundary.token = lambda: "synthetic-gateway-token-for-test-only-123456"
            async def receive():
                return {"type": "http.request", "body": b'{}', "more_body": False}
            async def send(event):
                sent.append(event)
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + boundary.token()).encode())]}
            stderr = io.StringIO()
            attempts = []
            actual_append = audit._append
            def append(event):
                attempts.append((event["direction"], event["correlation"]))
                actual_append(event)
            with patch("sys.stderr", stderr), patch.object(audit, "_append", append):
                task = asyncio.create_task(boundary(scope, receive, send))
                await asyncio.wait_for(app_started.wait(), 3)
                with patch.object(audit_module.os, "fsync", side_effect=OSError("synthetic fsync failure")):
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.assertEqual(calls, [True])
            self.assertTrue(task.cancelled())
            self.assertEqual(sent, [])
            self.assertIn("cancellation audit unavailable", stderr.getvalue())
            self.assertEqual([direction for direction, key in attempts], ["request", "interrupted", "connection_end"])
            self.assertEqual(len({key for direction, key in attempts}), 1)
            self.assertNotIn("synthetic fsync failure", stderr.getvalue())

    async def test_repeated_cancel_keeps_append_lock_until_actual_writer_finishes(self):
        for mode in ("local", "syslog"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                audit = Audit(directory, {"mode": mode})
                actual_append = audit._append
                entered = asyncio.Event()
                release = threading.Event()
                finished = threading.Event()
                second_entered = threading.Event()
                loop = asyncio.get_running_loop()
                def append(event):
                    if event["correlation"] == "first":
                        loop.call_soon_threadsafe(entered.set)
                        if not release.wait(10):
                            raise TimeoutError("Synthetic append gate deadline")
                        try:
                            actual_append(event)
                        finally:
                            finished.set()
                    else:
                        second_entered.set()
                        actual_append(event)
                tasks = []
                with patch.object(audit, "_append", append):
                    try:
                        first = asyncio.create_task(audit.record("request", {"index": 1}, "first"))
                        tasks.append(first)
                        await asyncio.wait_for(entered.wait(), 3)
                        first.cancel()
                        await asyncio.sleep(0.01)
                        first.cancel()
                        await asyncio.sleep(0.01)
                        second = asyncio.create_task(audit.record("request", {"index": 2}, "second"))
                        tasks.append(second)
                        await asyncio.sleep(0.05)
                        self.assertFalse(first.done())
                        self.assertTrue(audit.lock.locked())
                        self.assertFalse(finished.is_set())
                        self.assertFalse(second_entered.is_set())
                    finally:
                        release.set()
                        done, pending = await asyncio.wait(tasks, timeout=10)
                        for task in done:
                            if not task.cancelled():
                                task.result()
                        self.assertFalse(pending)
                self.assertTrue(finished.is_set())
                self.assertTrue(first.cancelled())
                self.assertTrue(second.done())
                self.assertEqual([item["correlation"] for item in self.records(audit)], ["first", "second"])

    async def test_cancel_during_revoked_token_rejection_retains_only_aggregation(self):
        for phase in ("reject", "send"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                audit = Audit(directory, {"mode": "local"})
                entered = asyncio.Event()
                calls, statuses = [], []
                token = "synthetic-gateway-token-for-test-only-123456"
                reads = 0
                async def app(scope, receive, send):
                    calls.append(True)
                boundary = AuditBoundary(app, audit)
                def read_token():
                    nonlocal reads
                    reads += 1
                    return token if reads == 1 else token + "-rotated"
                boundary.token = read_token
                actual_reject = audit.reject
                async def reject(reason):
                    await actual_reject(reason)
                    if phase == "reject":
                        entered.set()
                        await asyncio.Event().wait()
                async def receive():
                    return {"type": "http.request", "body": b'{"private":"synthetic-only"}', "more_body": False}
                async def send(event):
                    if event["type"] == "http.response.start":
                        statuses.append(event["status"])
                        if phase == "send":
                            entered.set()
                            await asyncio.Event().wait()
                scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                         "headers": [(b"authorization", ("Bearer " + token).encode())]}
                with patch.object(audit, "reject", reject):
                    task = asyncio.create_task(boundary(scope, receive, send))
                    try:
                        await asyncio.wait_for(entered.wait(), 3)
                    finally:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                await audit.flush_rejections()
                self.assertTrue(task.cancelled())
                self.assertEqual(calls, [])
                self.assertEqual(self.records(audit), [])
                self.assertEqual(audit.rejections["authentication_required"], 1)
                self.assertEqual(statuses, [] if phase == "reject" else [401])

    async def test_token_recheck_read_failure_refuses_without_per_request_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory, {"mode": "local"})
            calls, sent = [], []
            reads = 0
            token = "synthetic-gateway-token-for-test-only-123456"
            async def app(scope, receive, send):
                calls.append(True)
            boundary = AuditBoundary(app, audit)
            def read_token():
                nonlocal reads
                reads += 1
                if reads > 1:
                    raise OSError("synthetic-private-token-read-failure")
                return token
            boundary.token = read_token
            async def receive():
                return {"type": "http.request", "body": b"{}", "more_body": False}
            async def send(event):
                sent.append(event)
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + token).encode())]}
            await boundary(scope, receive, send)
            self.assertEqual(calls, [])
            self.assertEqual(self.records(audit), [])
            self.assertEqual(sent[0]["status"], 503)
            payload = json.loads(sent[1]["body"])
            self.assertEqual(payload, {"error": "audit_unavailable", "automatic_retry": False,
                                       "operation_may_have_completed": False})
            self.assertNotIn("synthetic-private-token-read-failure", sent[1]["body"].decode())
