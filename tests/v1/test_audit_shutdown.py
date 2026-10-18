import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from netops import audit as audit_module
from netops import gateway
from netops.audit import Audit


SHUTDOWN_ERROR = "netops: audit shutdown incomplete; inspect durable audit before any retry"
TOKEN = "synthetic-shutdown-token-for-test-only-123456"


def shutdown_child(phase, directory):
    os.umask(0o077)
    state = Path(directory)
    (state / "gateway").mkdir(mode=0o700)
    release = threading.Event()
    watchdog_delays = []
    watchdogs = []
    original_http_app = gateway.FastMCP.http_app
    original_write = audit_module.write_private
    holder = {}

    def proof(stage, **extra):
        if stage == "complete":
            assert watchdogs and all(timer.daemon and timer.finished.is_set() for timer in watchdogs)
            assert not any(task.get_coro().__qualname__ == "Audit.record.<locals>.commit"
                           for task in asyncio.all_tasks()), "An audit commit escaped shutdown ownership"
        (state / "proof.json").write_text(json.dumps({"phase": phase, "stage": stage,
            "watchdog_delays": list(watchdog_delays), **extra}))

    def factory(path, settings):
        audit = Audit(path, settings)
        holder["audit"] = audit
        original_append = audit._append

        def append(event):
            blocked = ((phase == "request" and event["direction"] == "request")
                       or (phase == "stop_append" and event["direction"] == "instance_stop"))
            if blocked:
                proof(phase + "_entered")
                holder["loop"].call_soon_threadsafe(holder["entered"].set)
                if phase == "stop_append":
                    def cancel_closer():
                        holder["closer"].cancel()
                        proof(phase + "_entered", cancel_requested=True)
                    holder["loop"].call_soon_threadsafe(cancel_closer)
                if not release.wait(4):
                    raise TimeoutError("Synthetic append gate deadline")
            original_append(event)

        audit._append = append
        return audit

    def http_app(self, *args, **kwargs):
        app = original_http_app(self, *args, **kwargs)
        original = app.router.lifespan_context

        @asynccontextmanager
        async def controlled(app):
            async with original(app):
                try:
                    yield
                finally:
                    proof("original_exit_entered")
                    time.sleep(0.5)
                    proof("original_exit_sleep_returned")
                    raise AssertionError("Shutdown watchdog did not interrupt the blocked event loop")

        if phase == "original_exit":
            app.router.lifespan_context = controlled
        return app

    def write_private(path, *args, **kwargs):
        if phase == "rejections" and Path(path).name == "rejections.json":
            holder["loop"].call_soon_threadsafe(holder["entered"].set)
            if not release.wait(4):
                raise TimeoutError("Synthetic rejection gate deadline")
        return original_write(path, *args, **kwargs)

    async def scenario():
        loop = asyncio.get_running_loop()
        holder.update(loop=loop, entered=asyncio.Event())
        actual_timer = threading.Timer

        def timer(interval, callback, *args, **kwargs):
            owned = getattr(callback, "__module__", None) == gateway.__name__
            if owned:
                assert interval == 20, "Actual shutdown budget must be twenty seconds"
                watchdog_delays.append(interval)
                if phase == "request":
                    proof("request_entered")
                if phase in ("original_exit", "request", "stop_append"):
                    interval = 0.1
            result = actual_timer(interval, callback, *args, **kwargs)
            if owned:
                watchdogs.append(result)
            return result

        with patch.object(gateway, "threading", threading, create=True), patch.object(gateway.threading, "Timer", timer):
            boundary = await gateway.application({"audit": {"mode": "local"}}, [], [])
            inner = boundary.app
            close_requested, lifespan_ready = asyncio.Event(), asyncio.Event()

            async def lifetime():
                async with inner.router.lifespan_context(inner):
                    lifespan_ready.set()
                    await close_requested.wait()

            closing = asyncio.create_task(lifetime())
            holder["closer"] = closing
            await asyncio.wait_for(lifespan_ready.wait(), 2)
            boundary.token = lambda: TOKEN
            sent = []

            async def business(scope, receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b'{"result":"synthetic"}'})

            async def receive():
                return {"type": "http.request", "body": b'{"method":"synthetic"}', "more_body": False}

            async def send(event):
                sent.append(event)

            boundary.app = business
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(b"authorization", ("Bearer " + TOKEN).encode())]}
            if phase == "barrier":
                slots = getattr(gateway, "MAX_CONCURRENT_REQUESTS", 16)
                assert slots == 16
                for index in range(slots):
                    await boundary.slots.acquire()
                request = asyncio.create_task(boundary(scope, receive, send))
                await asyncio.sleep(0)
                close_requested.set()
                try:
                    await asyncio.sleep(0.05)
                    assert not closing.done(), "Shutdown passed occupied slots"
                    assert not request.done() and not sent
                    assert all(item["direction"] != "instance_stop" for item in records(state))
                finally:
                    for index in range(slots):
                        boundary.slots.release()
                    await asyncio.wait_for(asyncio.gather(request, closing), 3)
                rows = records(state)
                calls = [item for item in rows if item["direction"] in ("request", "response", "connection_end")]
                assert [item["direction"] for item in calls] == ["request", "response", "connection_end"]
                assert len({item["correlation"] for item in calls}) == 1
                assert rows[-1]["direction"] == "instance_stop" and len(sent) == 2
                proof("complete")
            elif phase == "rejections":
                rejected_scope = {**scope, "headers": []}
                request = asyncio.create_task(boundary(rejected_scope, receive, send))
                await asyncio.wait_for(holder["entered"].wait(), 2)
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)
                close_requested.set()
                try:
                    await asyncio.sleep(0.05)
                    assert not closing.done(), "Shutdown lost an owned rejection persist"
                    assert all(item["direction"] != "instance_stop" for item in records(state))
                finally:
                    release.set()
                    await asyncio.wait_for(closing, 3)
                summary = json.loads((state / "gateway/audit/rejections.json").read_text())
                assert summary["counts"]["authentication_required"] == 1
                assert records(state)[-1]["direction"] == "instance_stop"
                proof("complete")
            else:
                if phase == "request":
                    holder["request"] = asyncio.create_task(boundary(scope, receive, send))
                    await asyncio.wait_for(holder["entered"].wait(), 2)
                close_requested.set()
                await closing
                raise AssertionError("Shutdown returned without enforcing its deadline")

    try:
        with patch.object(gateway, "STATE", state), patch.object(gateway, "Audit", factory), \
             patch.object(gateway.FastMCP, "http_app", http_app), \
             patch.object(audit_module, "write_private", write_private):
            asyncio.run(scenario())
    finally:
        release.set()


def records(state):
    return [json.loads(line) for path in sorted((state / "gateway/audit").glob("*.jsonl"))
            for line in path.read_bytes().splitlines()]


class AuditShutdown(unittest.TestCase):
    def run_child(self, phase):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-B", "-c",
                "import runpy,sys;runpy.run_path(sys.argv[1])['shutdown_child'](sys.argv[2],sys.argv[3])",
                str(Path(__file__).resolve()), phase, directory]
            try:
                child = subprocess.run(command, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                self.fail("Owned shutdown child exceeded its deadline; timeout is not a PASS")
            marker = Path(directory) / "proof.json"
            self.assertTrue(marker.exists(), "Child did not complete its phase: " + child.stderr)
            observed = json.loads(marker.read_text())
            self.assertEqual(observed["phase"], phase)
            self.assertEqual(observed["watchdog_delays"], [20])
            rows = records(Path(directory))
            if phase in ("barrier", "rejections"):
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(observed["stage"], "complete")
            else:
                self.assertEqual(child.returncode, 1, child.stderr)
                self.assertIn(SHUTDOWN_ERROR, child.stderr.splitlines())
                self.assertEqual(observed["stage"], phase + "_entered")
                self.assertFalse(any(row["direction"] == "instance_stop" for row in rows))
                if phase == "stop_append":
                    self.assertTrue(observed.get("cancel_requested"))

    def test_slot_barrier_waits_for_queued_boundary_call_and_audit_tail(self):
        self.run_child("barrier")

    def test_shutdown_joins_cancelled_auth_rejection_persist(self):
        self.run_child("rejections")

    def test_deadline_is_armed_before_original_lifespan_exit(self):
        self.run_child("original_exit")

    def test_deadline_does_not_write_stop_before_request_drain(self):
        self.run_child("request")

    def test_deadline_exits_during_cancel_draining_actual_stop_append(self):
        self.run_child("stop_append")

