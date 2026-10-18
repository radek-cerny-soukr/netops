import asyncio
import os
import signal
import unittest
from unittest.mock import patch


def abort_timeout(*unused):
    os.write(2, b"Synthetic startup RPC controls did not settle\n")
    os._exit(2)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, abort_timeout)
    signal.alarm(60)

from netops import gateway

REAL_WAIT = asyncio.wait


class StartupRpcControls(unittest.IsolatedAsyncioTestCase):
    def assert_no_new_pending(self, before):
        pending = [task.get_coro().__qualname__ for task in asyncio.all_tasks()
                   if task not in before and not task.done()]
        self.assertEqual(pending, [])

    async def settled(self, task):
        done, _ = await REAL_WAIT((task,), timeout=5)
        if not done:
            abort_timeout()
        if not task.cancelled():
            task.exception()

    async def test_normal_rpc_preserves_result_and_calls_once(self):
        before = set(asyncio.all_tasks())
        expected = {"tools": [{"name": "synthetic"}]}
        calls = []
        async def rpc(role, message):
            calls.append((role, message))
            return expected
        with patch.object(gateway, "rpc", rpc), patch.object(gateway, "stop_requested", lambda: False):
            self.assertIs(await gateway.startup_rpc("helper"), expected)
        self.assertEqual(calls, [("helper", {"action": "list"})])
        self.assert_no_new_pending(before)

    async def test_rpc_exception_is_not_reclassified_or_retried(self):
        before = set(asyncio.all_tasks())
        failure = gateway.RoleUnavailable("Synthetic RPC failure")
        calls = []
        async def rpc(role, message):
            calls.append((role, message))
            raise failure
        with patch.object(gateway, "rpc", rpc), patch.object(gateway, "stop_requested", lambda: False):
            with self.assertRaises(gateway.RoleUnavailable) as caught:
                await gateway.startup_rpc("auditor")
        self.assertIs(caught.exception, failure)
        self.assertEqual(calls, [("auditor", {"action": "list"})])
        self.assert_no_new_pending(before)

    async def interrupted_rpc(self, by_stop):
        before = set(asyncio.all_tasks())
        entered, finalizing, release, finalized = (asyncio.Event() for _ in range(4))
        stopping = asyncio.Event()
        never = asyncio.Event()
        joins = asyncio.Queue()
        calls, children = [], []
        owner = None
        async def rpc(role, message):
            calls.append((role, message))
            children.append(asyncio.current_task())
            entered.set()
            try:
                await never.wait()
            finally:
                finalizing.set()
                await release.wait()
                finalized.set()
        async def observed_wait(futures, *args, **kwargs):
            if asyncio.current_task() is owner and any(task.cancelling() for task in futures):
                joins.put_nowait(None)
            return await REAL_WAIT(futures, *args, **kwargs)
        with patch.object(gateway, "rpc", rpc), patch.object(gateway, "stop_requested", stopping.is_set), patch.object(gateway.asyncio, "wait", observed_wait):
            owner = asyncio.create_task(gateway.startup_rpc("admin"))
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
                if by_stop:
                    stopping.set()
                else:
                    self.assertTrue(owner.cancel())
                await asyncio.wait_for(finalizing.wait(), timeout=5)
                await asyncio.wait_for(joins.get(), timeout=5)
                if not by_stop:
                    for _ in range(2):
                        self.assertTrue(owner.cancel())
                        await asyncio.wait_for(joins.get(), timeout=5)
                        self.assertFalse(owner.done())
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].cancelling(), 1)
                self.assertFalse(owner.done())
                self.assertFalse(children[0].done())
                self.assertFalse(finalized.is_set())
                release.set()
                expected = gateway.StartupStopped if by_stop else asyncio.CancelledError
                with self.assertRaises(expected):
                    await owner
                self.assertTrue(finalized.is_set())
                self.assertTrue(children[0].done())
                self.assertTrue(children[0].cancelled())
                self.assertEqual(children[0].cancelling(), 1)
            finally:
                release.set()
                if not owner.done():
                    owner.cancel()
                for child in children:
                    if not child.done():
                        child.cancel()
                await self.settled(owner)
                for child in children:
                    await self.settled(child)
        self.assertEqual(calls, [("admin", {"action": "list"})])
        self.assert_no_new_pending(before)

    async def test_stop_cancels_once_and_joins_finalizer(self):
        await self.interrupted_rpc(by_stop=True)

    async def test_repeated_outer_cancel_does_not_cancel_finalizer_again(self):
        await self.interrupted_rpc(by_stop=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
