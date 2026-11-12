"""The Helper worker hands the gateway's progress sink to the triage tool and only for the call that asked."""

import asyncio
import json
import unittest
from types import SimpleNamespace

from netops import ipc, worker
from netops_helper import progress


class Proxy:
    emitted = None
    session_secrets = {}
    transport_secrets = ()

    def request(self, raw):
        return raw

    def response(self, raw):
        return raw


class Server:
    def __init__(self):
        self.seen = []

    async def call_tool(self, name, arguments):
        self.seen.append(progress.transport())
        sink = progress.transport()
        if sink is not None:
            await sink(0, 4, "triage_vpn: 0 of at most 4 reads (started)")
            await sink(1, 4, "triage_vpn: 1 of at most 4 reads (system_status)")
        return SimpleNamespace(content=[], structured_content={"ok": True}, is_error=False, meta=None)


class ProgressBridge(unittest.IsolatedAsyncioTestCase):
    def bridge(self):
        bridge = worker.HelperBridge.__new__(worker.HelperBridge)
        bridge.proxy = Proxy()
        return bridge

    async def test_the_sink_is_bound_for_the_call_that_asked_and_unbound_afterwards(self):
        got, server = [], Server()

        async def sink(done, total, text):
            got.append((done, total, text))

        result = await self.bridge().call(server, "triage_vpn", {"target": "t", "tunnel": "T1"}, sink)
        self.assertEqual(result["structuredContent"], {"ok": True})
        self.assertEqual([item[:2] for item in got], [(0, 4), (1, 4)])
        self.assertIs(server.seen[0], sink)
        self.assertIsNone(progress.transport())

    async def test_a_call_without_a_sink_sees_none(self):
        server = Server()
        await self.bridge().call(server, "triage_vpn", {"target": "t", "tunnel": "T1"})
        self.assertEqual(server.seen, [None])

    async def test_the_lines_written_to_the_gateway_are_exactly_what_the_gateway_accepts(self):
        line = worker.progress_line(1, 4, "triage_vpn: 1 of at most 4 reads (system_status)")
        self.assertTrue(line.endswith(b"\n") and b"\n" not in line[:-1])
        self.assertEqual(ipc.progress_report(json.loads(line)["progress"]),
                         {"progress": 1, "total": 4, "message": "triage_vpn: 1 of at most 4 reads (system_status)"})
        self.assertEqual(set(json.loads(line)), {"progress"})
        self.assertEqual(worker.PROGRESS_TOOLS, {"triage_health", "triage_routing", "triage_vpn", "triage_slb"})


if __name__ == "__main__":
    unittest.main()
