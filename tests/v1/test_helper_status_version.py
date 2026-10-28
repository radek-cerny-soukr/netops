import importlib
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import netops
from netops import worker


class HelperStatusVersion(unittest.IsolatedAsyncioTestCase):
    async def check_version(self, version):
        with patch.object(netops, "__version__", version):
            importlib.reload(worker)
            try:
                proxy = SimpleNamespace(
                    emitted=None,
                    session_secrets=(),
                    request=lambda data: data,
                    response=lambda data: data,
                    _helper_status_payload=lambda: {
                        "target_aliases": ["device.example.invalid"],
                        "target_rate_limits": [],
                        "invalid_target_count": 0,
                    },
                )
                bridge = worker.HelperBridge.__new__(worker.HelperBridge)
                bridge.proxy = proxy
                server = SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(
                    content=[], structured_content={}, is_error=False, meta=None)))
                actual = await bridge.call(server, "helper_status", {})
                server.call_tool.assert_awaited_once_with("helper_status", {})
                self.assertIs(actual["isError"], False)
                self.assertEqual(len(actual["content"]), 1)
                self.assertEqual(actual["content"][0]["type"], "text")
                structured = actual["structuredContent"]
                textual = json.loads(actual["content"][0]["text"])
                self.assertEqual(textual, structured)
                self.assertEqual(structured["version"], netops.__version__)
                self.assertEqual(structured["transport"], "HTTPS Streamable HTTP")
                self.assertEqual(structured["target_aliases"], ["device.example.invalid"])
                self.assertEqual(structured["target_rate_limits"], [])
                self.assertEqual(structured["invalid_target_count"], 0)
            finally:
                self.addCleanup(importlib.reload, worker)
        importlib.reload(worker)

    async def test_current_canonical_version_control(self):
        await self.check_version("1.0.3")

    async def test_new_canonical_version_in_both_actual_bridge_representations(self):
        await self.check_version("1.0.4")


if __name__ == "__main__":
    unittest.main()
