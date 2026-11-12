"""Every triage through the real proxy and worker when the target SSH cannot be reached (live 1.0.7 finding 5).

The answer is a structured result with error_code, failed_step and missing, as for triage_health, never the
generic -32603 "Role operation failed".
"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netops import worker
from netops.files import write_private
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine, proxy, server
from netops_helper.proxy import TRIAGE_SLB_REQUIRED_QUERIES

EGRESS = {"tcp_ports": [22], "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
          "allow_icmp": False, "allow_dns": False, "tls_server_names": []}


def device(name, platform, address, helper):
    return {"name": name, "platform": platform, "address": address, "port": 22, "role": "lab",
            "credential": "fixture-ro", "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None,
            "auditor": None, "helper": {"account_role": "read-only", "rate_limit": {"requests": 60, "window_seconds": 1},
                                        "egress": {"addresses": [address], **EGRESS}, **helper}}


CALLS = (
    ("triage_health", {"target": "fw-a"}),
    ("triage_routing", {"target": "fw-a", "address": "192.0.2.1"}),
    ("triage_flow", {"target": "fw-a", "src": "192.0.2.1", "dst": "198.51.100.1", "port": 443, "proto": "tcp"}),
    ("triage_vpn", {"target": "fw-a", "tunnel": "vpn-one"}),
    ("wifi_triage", {"target": "fw-a", "mac": "00:00:5e:00:53:01"}),
    ("wifi_triage", {"target": "fw-a", "mac": "00:00:5e:00:53:01", "summary": True}),
    ("triage_slb", {"target": "adc-a", "virtual_server": "VS_ONE"}),
)


class UnreachableTriage(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = self.state / "helper"
        helper.mkdir(mode=0o700)
        devices = [
            device("fw-a", "fortios", "192.0.2.10", {
                "ssh_platform": "fortios", "fortios_output_standard_verified": True,
                "enabled_queries": ["system_status", "route_lookup", "policy_lookup_ipv4", "wifi_events"],
                "read_inventory": {"addresses": ["192.0.2.1"]}}),
            device("adc-a", "fortiadc", "192.0.2.40", {
                "ssh_platform": "fortiadc", "enabled_queries": sorted(TRIAGE_SLB_REQUIRED_QUERIES),
                "read_inventory": {"config_access": ["read"], "adc_virtual_servers": ["VS_ONE"], "adc_vdoms": ["root"]}}),
        ]
        write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": devices}).encode())
        write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "fixture-user", "value": "synthetic-triage-password-only"}}}).encode())
        self.enterContext(patch.object(worker, "STATE", self.state))
        self.enterContext(patch.object(proxy, "INVENTORY", helper / "inventory.json"))
        self.enterContext(patch.object(helper_audit, "_RECORDER", Recorder(helper / "operations.jsonl", "helper")))
        self.bridge = worker.HelperBridge()
        await self.bridge.tools(server.mcp)
        self.enterContext(patch.object(self.bridge.proxy, "_consume_rate_limit"))
        self.enterContext(patch.object(self.bridge.proxy, "_consume_rate_limits", create=True))

    async def test_every_triage_returns_a_structured_transport_failure(self):
        for error, code in ((ConnectionRefusedError("connect refused synthetic-secret"), "connection_refused"),
                            (OSError("SSH closed synthetic-secret"), "ssh_unavailable"),
                            (TimeoutError("timed out synthetic-secret"), "timeout")):
            for tool, arguments in CALLS:
                with self.subTest(tool=tool, summary=arguments.get("summary", False), code=code):
                    with patch.object(engine, "read_from_device", side_effect=error) as read:
                        result = await self.bridge.call(server.mcp, tool, arguments)
                    wire = json.dumps(result)
                    self.assertNotIn("-32603", wire)
                    self.assertNotIn("Role operation failed", wire)
                    self.assertNotIn("synthetic-secret", wire)
                    self.assertFalse(result["isError"], result)
                    data = result["structuredContent"]
                    self.assertEqual(json.loads(result["content"][0]["text"])["error_code"], code)
                    self.assertEqual((data["ok"], data["error_code"], data["failed_step"], data["verdict"]),
                                     (False, code, "system_status", "incomplete"))
                    self.assertEqual(data["target"], arguments["target"])
                    if not arguments.get("summary"):
                        self.assertEqual(data["missing"][0]["step"], "system_status")
                    self.assertEqual(data["vantage"]["device"], arguments["target"])
                    self.assertIs(data["vantage"]["packets_sent"], False)
                    self.assertEqual(read.call_count, 1)


if __name__ == "__main__":
    unittest.main()
