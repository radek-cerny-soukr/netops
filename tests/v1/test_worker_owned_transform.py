import asyncio
import contextvars
import threading
import unittest
from netops import worker

class WorkerOwnedTransform(unittest.IsolatedAsyncioTestCase):
    async def test_pure_result_identity_and_exception_are_preserved(self):
        sentinel=object()
        self.assertIs(await worker._owned_thread(lambda:sentinel),sentinel)
        def fail():raise ValueError("synthetic-transform-failure")
        with self.assertRaisesRegex(ValueError,"synthetic-transform-failure"):
            await worker._owned_thread(fail)
    async def test_call_context_is_preserved_in_the_executor(self):
        marker=contextvars.ContextVar("worker-transform-test",default="missing")
        token=marker.set("request-context")
        try:self.assertEqual(await worker._owned_thread(marker.get),"request-context")
        finally:marker.reset(token)
    async def test_repeated_cancel_keeps_the_lock_until_the_thread_settles(self):
        loop=asyncio.get_running_loop()
        entered=asyncio.Event()
        release,finished=threading.Event(),threading.Event()
        calls=[]
        lock=asyncio.Lock()
        def operation():
            calls.append(True);loop.call_soon_threadsafe(entered.set)
            try:
                if not release.wait(5):raise RuntimeError("synthetic gate deadline")
                return "done"
            finally:finished.set()
        async def owner():
            async with lock:return await worker._owned_thread(operation)
        task=asyncio.create_task(owner())
        try:
            await asyncio.wait_for(entered.wait(),2)
            for _ in range(3):
                task.cancel();await asyncio.sleep(0.02)
                self.assertFalse(task.done())
                self.assertTrue(lock.locked())
            self.assertFalse(finished.is_set())
        finally:release.set()
        with self.assertRaises(asyncio.CancelledError):await asyncio.wait_for(task,2)
        self.assertTrue(finished.is_set());self.assertFalse(lock.locked())
        self.assertEqual(calls,[True])
    async def test_executor_failure_is_not_lost_during_cancel(self):
        loop=asyncio.get_running_loop()
        contexts=[];previous=loop.get_exception_handler()
        loop.set_exception_handler(lambda loop,context:contexts.append(context))
        self.addCleanup(loop.set_exception_handler,previous)
        entered=asyncio.Event();release=threading.Event()
        def operation():
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(5):raise RuntimeError("synthetic gate deadline")
            raise ValueError("synthetic-after-cancel")
        task=asyncio.create_task(worker._owned_thread(operation))
        try:
            await asyncio.wait_for(entered.wait(),2)
            task.cancel();await asyncio.sleep(0.02)
            self.assertFalse(task.done())
        finally:release.set()
        with self.assertRaisesRegex(ValueError,"synthetic-after-cancel"):await asyncio.wait_for(task,2)
        await asyncio.sleep(0)
        self.assertEqual(contexts,[], "owned failure must not also escape to the event loop handler")
