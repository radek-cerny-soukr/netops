import asyncio
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from netops.audit import Audit
from netops.gateway import AuditBoundary

class PartialBodyOwnership(unittest.IsolatedAsyncioTestCase):
    async def check_cancellation(self,fail_append):
        with tempfile.TemporaryDirectory() as directory:
            audit=Audit(directory,{"mode":"local"})
            reading,entered=asyncio.Event(),asyncio.Event()
            release=threading.Event()
            loop=asyncio.get_running_loop()
            attempted=[];dispatched=[];sent=[]
            original_append=audit._append
            original_record=audit.record
            async def record(direction,payload,correlation,**kwargs):
                attempted.append((direction,correlation))
                return await original_record(direction,payload,correlation,**kwargs)
            def append(event):
                if event["direction"]=="request_body_cancelled":
                    loop.call_soon_threadsafe(entered.set)
                    if not release.wait(5):raise RuntimeError("synthetic append gate deadline")
                    if fail_append:raise OSError("synthetic private append failure")
                return original_append(event)
            async def app(scope,receive,send):dispatched.append(True)
            boundary=AuditBoundary(app,audit)
            token="synthetic-partial-body-token-01234567890123456789"
            boundary.token=lambda:token
            scope={"type":"http","scheme":"https","http_version":"1.1","method":"POST","path":"/mcp",
                   "headers":[(b"authorization",("Bearer "+token).encode()),(b"content-length",b"60000"),
                              (b"x-synthetic-header",b"synthetic-header-canary")]}
            fragment=b'{"password":"synthetic-fragment-canary'
            seen=False
            async def receive():
                nonlocal seen
                if not seen:
                    seen=True
                    return {"type":"http.request","body":fragment,"more_body":True}
                reading.set()
                return await asyncio.Future()
            async def send(event):sent.append(event)
            async def all_slots():
                acquired=0
                try:
                    for _ in range(16):
                        await boundary.slots.acquire();acquired+=1
                finally:
                    for _ in range(acquired):boundary.slots.release()
            stderr=io.StringIO()
            task=barrier=pulse=None
            with patch.object(audit,"_append",append),patch.object(audit,"record",record),patch("sys.stderr",stderr):
                try:
                    task=asyncio.create_task(boundary(scope,receive,send))
                    await asyncio.wait_for(reading.wait(),2)
                    task.cancel()
                    pulse=asyncio.create_task(entered.wait())
                    await asyncio.wait((task,pulse),timeout=2,return_when=asyncio.FIRST_COMPLETED)
                    self.assertTrue(entered.is_set(),"partial-body cancellation escaped without its durable audit attempt")
                    barrier=asyncio.create_task(all_slots())
                    for _ in range(3):
                        task.cancel();await asyncio.sleep(0.02)
                        self.assertFalse(task.done(),"cancel released the request before its append settled")
                        self.assertFalse(barrier.done(),"all slots became available while the audit append was still owned")
                    self.assertEqual(dispatched,[]);self.assertEqual(sent,[])
                finally:
                    release.set()
                    if pulse is not None and not pulse.done():pulse.cancel()
                    jobs=[item for item in (task,pulse,barrier) if item is not None]
                    done,pending=await asyncio.wait(jobs,timeout=8)
                    for item in pending:item.cancel()
                    await asyncio.gather(*jobs,return_exceptions=True)
                    self.assertFalse(pending,"private cancellation fixture failed to settle")
            self.assertTrue(task.cancelled())
            self.assertEqual([item[0] for item in attempted],["request_body_cancelled","connection_end"])
            self.assertEqual(len({item[1] for item in attempted}),1)
            self.assertEqual(dispatched,[]);self.assertEqual(sent,[])
            self.assertNotIn("synthetic private append failure",stderr.getvalue())
            self.assertEqual("cancellation audit unavailable" in stderr.getvalue(),fail_append)
            if not fail_append:
                records=[json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
                self.assertEqual([event["direction"] for event in records],["request_body_cancelled","connection_end"])
                self.assertEqual(records[0]["payload"],{"phase":"request_body","complete_body":False,
                    "received_bytes":len(fragment),"operation_executed":False,"reason":"cancelled"})
                self.assertEqual(records[1]["payload"],{"delivery":"not_started"})
                text=json.dumps(records)
                for canary in (token,"synthetic-fragment-canary","synthetic-header-canary"):
                    self.assertNotIn(canary,text)
    async def test_repeated_cancel_retains_slot_and_commits_both_records(self):
        await self.check_cancellation(False)
    async def test_append_failure_still_attempts_end_and_never_dispatches(self):
        await self.check_cancellation(True)
