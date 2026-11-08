import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from netops import worker
from netops.files import write_private
from netops_helper import proxy


FTP_REFUSAL = "unencrypted_protocol: FTP/FTPS is unavailable in the SSH/HTTPS-only default profile"


class WorkerSnmpGet(unittest.IsolatedAsyncioTestCase):
    def enroll(self, snmp_credential):
        state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = state / "helper"
        helper.mkdir(mode=0o700)
        device = {"name": "device-a", "platform": "linux", "address": "192.0.2.10",
                  "port": 22, "role": "lab", "credential": "fixture-ro",
                  "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
                  "auditor": None, "helper": {
                      "account_role": "read-only", "ssh_platform": "linux",
                      "enabled_queries": ["kernel"], "snmp_credential": snmp_credential,
                      "egress": {"addresses": ["192.0.2.10"], "tcp_ports": [22],
                                 "udp_ports": [161], "tcp_port_ranges": [], "udp_port_ranges": [],
                                 "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}}
        write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
        write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "fixture-user",
                           "value": "synthetic-snmp-bridge-password"},
            "fixture-community": {"kind": "snmp-community", "login": None,
                                  "value": "synthetic-snmp-bridge-community"}}}).encode())
        self.enterContext(patch.object(worker, "STATE", state))
        self.enterContext(patch.object(proxy, "INVENTORY", helper / "inventory.json"))

    def bridge(self):
        bridge = worker.HelperBridge()
        self.request = self.enterContext(patch.object(bridge.proxy, "request", wraps=bridge.proxy.request))
        self.server = SimpleNamespace(call_tool=AsyncMock())
        return bridge

    def refusal(self, result):
        self.assertIs(result["isError"], True)
        self.assertEqual(len(result["content"]), 1)
        text = result["content"][0]["text"]
        self.assertNotIn("unencrypted_protocol", text)
        self.assertNotIn("SNMPv2c and FTP/FTPS", text)
        self.request.assert_called_once()
        self.server.call_tool.assert_not_awaited()
        return json.loads(text)

    async def test_snmp_get_on_unenrolled_target_is_refused_by_proxy(self):
        self.enroll(None)
        bridge = self.bridge()
        result = await bridge.call(self.server, "snmp_get", {"target": "unenrolled-device", "oids": ["1.3.6.1.2.1.1.1.0"]})
        error = self.refusal(result)
        self.assertEqual(error["code"], -32001)
        self.assertEqual(error["data"]["category"], "unknown_alias")

    async def test_snmp_get_without_snmp_credential_is_refused_by_proxy(self):
        self.enroll(None)
        bridge = self.bridge()
        result = await bridge.call(self.server, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]})
        error = self.refusal(result)
        self.assertEqual(error["code"], -32006)
        self.assertEqual(error["data"]["category"], "auth_material")

    async def test_snmp_get_with_legacy_community_returns_proxy_guidance(self):
        self.enroll("fixture-community")
        bridge = self.bridge()
        result = await bridge.call(self.server, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]})
        error = self.refusal(result)
        self.assertEqual(error["code"], -32006)
        self.assertEqual(error["data"]["category"], "auth_material")
        self.assertEqual(error["data"]["reason"], "legacy_snmp_community")
        self.assertEqual(error["data"]["guidance"], proxy.LEGACY_SNMP_GUIDANCE)
        self.assertIn("snmpv3-authpriv", error["data"]["guidance"])
        self.assertNotIn("synthetic-snmp-bridge-community", result["content"][0]["text"])

    async def test_ftp_list_is_still_refused_by_worker(self):
        bridge = worker.HelperBridge.__new__(worker.HelperBridge)
        bridge.proxy = SimpleNamespace(request=Mock())
        server = SimpleNamespace(call_tool=AsyncMock())
        result = await bridge.call(server, "ftp_list", {"target": "device-a", "remote_path": "/"})
        self.assertEqual(result, {"content": [{"type": "text", "text": FTP_REFUSAL}], "isError": True})
        bridge.proxy.request.assert_not_called()
        server.call_tool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
