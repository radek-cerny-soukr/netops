"""FortiADC transport failures through the real proxy, worker bridge, engine and SSH transport (live 1.0.7 N1-N3).

Only the OpenSSH programs are fake: `ssh-keyscan` and `ssh` on PATH answer like the real clients for an
unreachable host, a refused connection, a host key that is not the pin, a refused password and a dropped
connection. Every tool answers a structured result with the transport class and its advice instead of the
JSON-RPC error -32603 "Role operation failed", and the Helper operation summary records the same class.
It lives in the Helper suite, whose temporary directory may hold executables; the image selftest mounts /tmp noexec.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import worker
from netops.files import write_private
from netops_core.audit import Recorder
from netops_core.hostkey import fingerprint_of
from netops_helper import audit as helper_audit, engine, proxy, server
from netops_helper.proxy import TRIAGE_SLB_REQUIRED_QUERIES

PIN_BLOB = base64.b64encode(b"bridge-transport-class-host-key").decode()
OTHER_BLOB = base64.b64encode(b"another-host-key-not-the-pin").decode()
PASSWORD = "synthetic-bridge-password-only"
FAKE_SSH = """#!{python}
import json, sys
plan = json.load(open({plan!r}))
mode = "probe" if "netops-hostkey" in sys.argv else "pty" if "-tt" in sys.argv else "exec"
step = plan[mode]
(sys.stdout if mode == "pty" else sys.stderr).write(step["said"] + "\\n")
sys.exit(step["code"])
"""
FAKE_KEYSCAN = """#!{python}
import json, sys
blob = json.load(open({plan!r}))["keyscan"]
if not blob:
    sys.exit(1)
sys.stdout.write("%s ssh-ed25519 %s\\n" % (sys.argv[-1], blob))
"""
UNUSED = {"code": 99, "said": "must not run"}
DENIED = {"code": 255, "said": "fixture-user@192.0.2.40: Permission denied (password,keyboard-interactive)."}
SCENARIOS = {
    "unreachable": ("", {"code": 255, "said": "ssh: connect to host 192.0.2.40 port 22: No route to host"}, UNUSED, UNUSED),
    "connection_refused": ("", {"code": 255, "said": "ssh: connect to host 192.0.2.40 port 22: Connection refused"},
                           UNUSED, UNUSED),
    "host_key_mismatch": (OTHER_BLOB, UNUSED, UNUSED, UNUSED),
    "auth": (PIN_BLOB, UNUSED, DENIED, DENIED),
    "disconnected": (PIN_BLOB, UNUSED, {"code": 255, "said": "Connection closed by 192.0.2.40 port 22"},
                     {"code": 255, "said": "Connection to 192.0.2.40 closed by remote host."}),
}
CALLS = (
    ("ssh_read", {"target": "adc-a", "platform": "fortiadc", "query": "system_status"}),
    ("config_read", {"target": "adc-a", "platform": "fortiadc", "section": "all", "include_all": True,
                     "redaction": "full"}),
    ("fortios_diagnostics", {"target": "adc-a", "recipe": "ping", "address": "192.0.2.11", "interface": ""}),
    ("fortios_diagnostics", {"target": "adc-a", "recipe": "system_event_logs", "address": "", "interface": "",
                             "count": 10}),
    ("triage_slb", {"target": "adc-a", "virtual_server": "VS_ONE"}),
)


def _program(path, body):
    path.write_text(body.replace("{python}", sys.executable, 1), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class TransportClassesThroughTheBridge(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = self.state / "helper"
        helper.mkdir(mode=0o700)
        device = {
            "name": "adc-a", "platform": "fortiadc", "address": "192.0.2.40", "port": 22, "role": "lab",
            "credential": "fixture-ro", "host_key_fingerprint": fingerprint_of(PIN_BLOB), "legacy_ssh": None,
            "auditor": None, "helper": {
                "account_role": "read-only", "rate_limit": {"requests": 60, "window_seconds": 1},
                "egress": {"addresses": ["192.0.2.40"], "tcp_ports": [22], "udp_ports": [], "tcp_port_ranges": [],
                           "udp_port_ranges": [], "allow_icmp": True, "allow_dns": False, "tls_server_names": []},
                "ssh_platform": "fortiadc", "enabled_queries": sorted({*TRIAGE_SLB_REQUIRED_QUERIES, "system_status"}),
                "read_inventory": {"config_access": ["read"], "adc_virtual_servers": ["VS_ONE"], "adc_vdoms": ["root"],
                                   "addresses": ["192.0.2.11"], "diagnostic_recipes": ["ping", "system_event_logs"]}}}
        firewall = json.loads(json.dumps(device))
        firewall.update(name="fw-a", platform="fortios")
        firewall["helper"].update(
            ssh_platform="fortios", fortios_output_standard_verified=True,
            enabled_queries=["system_status", "physical_interfaces", "interface_vlan_ids", "lldp_summary", "bridge_mac_table"],
            read_inventory={"switches": ["internal"]})
        write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device, firewall]}).encode())
        write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "fixture-user", "value": PASSWORD}}}).encode())
        self.audit = helper / "operations.jsonl"
        self.plan = self.state / "plan.json"
        binaries = self.state / "bin"
        binaries.mkdir()
        _program(binaries / "ssh", FAKE_SSH.replace("{plan!r}", repr(str(self.plan))))
        _program(binaries / "ssh-keyscan", FAKE_KEYSCAN.replace("{plan!r}", repr(str(self.plan))))
        self.enterContext(patch.dict(os.environ, {"PATH": "%s:%s" % (binaries, os.environ.get("PATH", ""))}))
        self.enterContext(patch.object(worker, "STATE", self.state))
        self.enterContext(patch.object(proxy, "INVENTORY", helper / "inventory.json"))
        self.enterContext(patch.object(helper_audit, "_RECORDER", Recorder(self.audit, "helper")))
        self.enterContext(patch.object(engine, "_sleep", lambda seconds: None))
        engine._HOST_KEY_LINE_CACHE.clear()
        self.addCleanup(engine._HOST_KEY_LINE_CACHE.clear)
        self.bridge = worker.HelperBridge()
        await self.bridge.tools(server.mcp)
        self.enterContext(patch.object(self.bridge.proxy, "_consume_rate_limit"))
        self.enterContext(patch.object(self.bridge.proxy, "_consume_rate_limits", create=True))

    def use(self, code):
        keyscan, probe, exec_step, pty_step = SCENARIOS[code]
        self.plan.write_text(json.dumps({"keyscan": keyscan, "probe": probe, "exec": exec_step, "pty": pty_step}))
        engine._HOST_KEY_LINE_CACHE.clear()

    def summaries(self, event):
        lines = self.audit.read_text().splitlines() if self.audit.exists() else []
        return [entry for entry in map(json.loads, lines) if entry["event"] == event and entry["status"] == "failed"]

    async def test_every_fortiadc_tool_names_the_transport_class(self):
        for code in SCENARIOS:
            for tool, arguments in CALLS:
                with self.subTest(code=code, tool=tool, recipe=arguments.get("recipe")):
                    self.use(code)
                    before = len(self.summaries(tool))
                    result = await self.bridge.call(server.mcp, tool, arguments)
                    wire = json.dumps(result)
                    self.assertNotIn("-32603", wire)
                    self.assertNotIn("Role operation failed", wire)
                    for private in (PASSWORD, "Permission denied", "No route to host", "closed by", "port 22:"):
                        self.assertNotIn(private, wire)
                    self.assertIn("structuredContent", result, wire)
                    data = result["structuredContent"]
                    self.assertIs(data["ok"], False, data)
                    self.assertEqual((data["error_code"], data["error"]), (code, engine._TRANSPORT_ADVICE[code]))
                    if tool == "triage_slb":
                        self.assertEqual(data["missing"][0]["error_code"], code)
                    failed = self.summaries(tool)
                    self.assertEqual(len(failed), before + 1)
                    self.assertEqual(failed[-1]["detail"], code)

    async def test_the_password_and_the_network_are_told_apart(self):
        answers = {}
        for code in ("unreachable", "host_key_mismatch", "auth"):
            self.use(code)
            result = await self.bridge.call(server.mcp, "fortios_diagnostics", CALLS[2][1])
            answers[code] = result["structuredContent"]["error"]
        self.assertIn("reachable", answers["unreachable"])
        self.assertNotIn("password", answers["unreachable"])
        self.assertIn("pin", answers["host_key_mismatch"])
        self.assertIn("password", answers["auth"])
        self.assertNotIn(" pin", answers["auth"])

    async def test_local_fortigate_tables_keep_transport_classes_through_the_bridge(self):
        for code in SCENARIOS:
            for table in ("interface", "vlan", "lldp_neighbor", "mac_entry"):
                with self.subTest(code=code, table=table):
                    self.use(code)
                    before = len(self.summaries("switch_read"))
                    result = await self.bridge.call(server.mcp, "switch_read", {"target": "fw-a", "table": table})
                    self.assertFalse(result["isError"], result)
                    data = result["structuredContent"]
                    self.assertFalse(data["ok"])
                    self.assertEqual((data["error_code"], data["error"]), (code, engine._TRANSPORT_ADVICE[code]))
                    self.assertEqual(data["records"], [])
                    failed = self.summaries("switch_read")
                    self.assertEqual(len(failed), before + 1)
                    self.assertEqual(failed[-1]["detail"], code)
                    wire = json.dumps(result)
                    for private in (PASSWORD, "Permission denied", "No route to host", "closed by", "-32603"):
                        self.assertNotIn(private, wire)

    async def test_clean_success_and_classified_failure_share_the_worker_path(self):
        plain = "CPU usage: 1%\n"
        identity = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
        colored = "\x1b[1m" + plain.rstrip("\n") + "\x1b[0m\x07\n"
        arguments = {"target": "adc-a", "platform": "fortiadc", "query": "system_performance"}
        # Successful device text uses the real engine, response sanitizer, proxy and worker.
        with patch.object(engine, "read_from_device",
                          side_effect=lambda auth, platform, command: (0, identity if command == "get system status" else colored)):
            result = await self.bridge.call(server.mcp, "ssh_read", arguments)
        data = result["structuredContent"]
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["untrusted_device_output"], plain)
        self.assertEqual(data["content_sha256"], hashlib.sha256(plain.encode()).hexdigest())
        self.assertEqual(data["total_bytes"], len(plain.encode()))
        self.assertEqual(json.loads(result["content"][0]["text"]), data)
        # The same bridge next runs real SSH classification; sanitization must retain its fields.
        self.use("auth")
        failed = (await self.bridge.call(server.mcp, "ssh_read", arguments))["structuredContent"]
        self.assertEqual((failed["error_code"], failed["error"]), ("auth", engine._TRANSPORT_ADVICE["auth"]))


if __name__ == "__main__":
    unittest.main()
