from contextlib import ExitStack
from dataclasses import replace
import json
import os
import threading
from unittest import TestCase, mock

from netops_helper import engine
from netops_helper.auth import TargetAuth, EgressPolicy

ADDRESS = "192.0.2.183"
STATUS = ("Version: FortiGate-VM64-KVM v7.6.7,build3704,240101\n"
          "Virtual domain configuration: disable\nCurrent virtual domain: root\n")

def enrolled():
    return TargetAuth(alias="fixture", host="192.0.2.20", port=22, login="reader",
                      secret="auth-canary-91", host_key_fingerprint="SHA256:fixture",
                      ssh_platform="fortinet", enabled_queries=("system_status",),
                      fortios_output_standard_verified=True,
                      read_inventory={"diagnostic_recipes": ("sniffer", "flow"),
                                      "addresses": (ADDRESS,), "interfaces": ("port2",)},
                      egress=EgressPolicy(addresses=("192.0.2.20",), tcp_ports=(22,)))

class Shell:
    def __init__(self, status=STATUS, fail_cleanup=False):
        self.status, self.fail_cleanup = status, fail_cleanup
        self.commands = []
        self.enabled = False
        self.filtered = False
        self.interrupted = threading.Event()
    def navigate(self, command):
        self.commands.append(command)
        raise AssertionError("H3_MUST_NOT_SWITCH_VDOM")
    def interrupt(self):
        self.interrupted.set()
    def listen(self, timeout):
        if not self.interrupted.wait(timeout):
            raise AssertionError("H3_DEADLINE_DID_NOT_INTERRUPT")
        return "bounded flow data"
    def command(self, command, timeout=10):
        from netops_helper.fortios_diagnostics import FLOW_FIELDS
        self.commands.append(command)
        if command == "get system status":
            return self.status
        if command.startswith('show full-configuration system interface "'):
            return 'config system interface\n edit "port2"\n set vdom "root"\n next\nend\n'
        if command == "diagnose netlink interface list port2":
            return "if=port2 family=00 type=1 index=4"
        if command.startswith("diagnose sniffer packet "):
            return ("synthetic packet auth-canary-91\n" * 100)
        if command == "diagnose debug flow filter":
            return "\n".join(k+": "+(ADDRESS if self.filtered and k=="Host addr" else "any")
                             for k in sorted(FLOW_FIELDS))
        if command.startswith("diagnose debug flow filter addr "):
            self.filtered = True
        if command == "diagnose debug flow filter clear":
            self.filtered = False
        if command == "diagnose debug enable":
            self.enabled = True
        if command == "diagnose debug disable":
            if self.fail_cleanup:
                raise RuntimeError("auth-canary-91")
            self.enabled = False
        if command == "diagnose debug info":
            return "debug output: "+("enable" if self.enabled else "disable")
        return ""

class DiagnosticBlock(TestCase):
    def invoke(self, shell, auth=None, recipe="sniffer", runner=None, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
            audit=stack.enter_context(mock.patch.object(engine, "record"))
            stack.enter_context(mock.patch.object(engine, "_resolve_target_ipv4", return_value=("192.0.2.20",)))
            pin=stack.enter_context(mock.patch.object(engine, "host_key_line", return_value="pinned-host-key"))
            stack.enter_context(mock.patch.object(engine, "_paced_connection"))
            session=stack.enter_context(mock.patch.object(engine.core_session, "Session"))
            stack.enter_context(mock.patch.object(engine, "_FortiosDiagnosticShell", return_value=shell))
            result=(runner() if runner else engine.fortios_diagnostics(
                auth or enrolled(), recipe, ADDRESS, "port2",
                count=2, timeout=1, max_bytes=1000, **kwargs))
            pin.assert_called_once_with(auth or enrolled(), "192.0.2.20", "fortinet")
            self.assertEqual(session.call_args.kwargs["capture_max_bytes"], 131072)
            self.assertEqual(session.call_args.kwargs["timeout_seconds"], 30)
            return result, audit.call_args_list

    def test_measured_802_identity_and_neighbor_refusal_block(self):
        status = STATUS.replace("FortiGate-VM64-KVM v7.6.7,build3704",
                                "FortiGate-VM64 v8.0.2,build0251")
        for recipe in ("sniffer", "flow"):
            with self.subTest(recipe=recipe):
                result, audit = self.invoke(Shell(status), recipe=recipe)
                self.assertEqual(tuple(result["identity"]),
                                 ("FortiGate-VM64", "8.0.2", "0251"))
                self.assertEqual(result["cleanup"], "verified")
                self.assertNotIn("auth-canary-91", json.dumps(result)+repr(audit))
        for variant in (status.replace("build0251", "build0252"),
                        status.replace("v8.0.2", "v8.0.3"),
                        status.replace("FortiGate-VM64", "FortiGate-VM64-KVM")):
            with self.subTest(status=variant[:60]):
                shell = Shell(variant)
                with self.assertRaises(ValueError):
                    self.invoke(shell)
                self.assertEqual(shell.commands, ["get system status"])

    def test_registry_free_capture_scope_and_output_block(self):
        shell=Shell()
        try:
            result, audit=self.invoke(shell)
        except Exception as error:
            self.fail("H3_REGISTRY_FREE_PASSAGE_REQUIRED: "+type(error).__name__+": "+str(error))
        self.assertEqual(tuple(result["identity"]), ("FortiGate-VM64-KVM","7.6.7","3704"))
        self.assertEqual(result["vdom"], "root")
        self.assertNotIn("schema_sha256", result)
        self.assertEqual(result["cleanup"], "verified")
        self.assertTrue(result["truncated"])
        self.assertGreater(result["total_bytes"], result["returned_bytes"])
        self.assertLessEqual(result["returned_bytes"], 1000)
        self.assertNotIn("auth-canary-91", json.dumps(result)+repr(audit))
        self.assertFalse(any(c.startswith(("config ", "edit ")) for c in shell.commands))
        with mock.patch.object(engine, "record"), mock.patch.object(engine, "_resolve_target_ipv4") as resolve:
            with self.assertRaises(ValueError):
                engine.fortios_diagnostics(replace(enrolled(), read_inventory={}),
                                           "sniffer", ADDRESS, "port2")
            resolve.assert_not_called()

    def test_inventory_proxy_mcp_registry_free_block(self):
        import asyncio
        from base64 import b64encode
        from types import SimpleNamespace
        from fastmcp import Client
        from netops_core.hostkey import fingerprint_of
        from netops_helper import inventory, proxy, server
        entry = SimpleNamespace(
            credential="fixture-account", name="fixture", address="192.0.2.20", port=22,
            host_key_fingerprint=fingerprint_of(b64encode(b"fixture-host-key").decode()),
            legacy_ssh=None, helper={
                "account_role": "read-only", "ssh_platform": "fortios",
                "enabled_queries": ["system_status"], "fortios_output_standard_verified": True,
                "read_inventory": {"diagnostic_recipes": ["sniffer", "flow"],
                                   "addresses": [ADDRESS], "interfaces": ["port2"]},
                "egress": {"addresses": ["192.0.2.20"], "tcp_ports": [22],
                           "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
                           "allow_icmp": False, "allow_dns": False, "tls_server_names": []}})
        section = inventory.section(entry)
        gateway = proxy.Proxy()
        credential = SimpleNamespace(login="reader", kind="password", use=lambda: "auth-canary-91")
        envelope = gateway._auth_context(entry, section, credential, None, "fortios_diagnostics")
        auth = TargetAuth.decode("fixture", envelope)
        args = gateway._validate_tool_arguments("fortios_diagnostics", {
            "target": "fixture", "recipe": "sniffer", "address": ADDRESS,
            "interface": "port2", "count": 2, "timeout": 1, "max_bytes": 1000})
        gateway._authorize_tool("fortios_diagnostics", args, entry, section)
        async def call():
            async with Client(server.mcp) as client:
                result = await client.call_tool("fortios_diagnostics", dict(args, auth_context=envelope))
                self.assertFalse(result.is_error)
                return result.data
        try:
            result, audit = self.invoke(Shell(), auth=auth, runner=lambda: asyncio.run(call()))
        except Exception as error:
            self.fail("H3_REGISTRY_FREE_MCP_REQUIRED: "+type(error).__name__+": "+str(error))
        self.assertEqual(tuple(result["identity"]), ("FortiGate-VM64-KVM", "7.6.7", "3704"))
        self.assertEqual(result["vdom"], "root")
        self.assertNotIn("schema_sha256", result)
        self.assertNotIn("auth-canary-91", json.dumps(result)+repr(audit))

    def test_identity_mode_and_selector_stop_before_diagnose_block(self):
        variants=[STATUS.replace("disable","enable"), STATUS.replace("disable","unknown"),
                  STATUS.replace("Virtual domain configuration: disable\n",""),
                  STATUS+"Virtual domain configuration: disable\n",
                  STATUS.replace("Current virtual domain: root","Current virtual domain: VD1"),
                  STATUS.replace("Version:","Malformed:"),
                  STATUS+STATUS, STATUS.replace("build3704","build9999"), "x"*65537,
                  STATUS.replace("root","root\x00")]
        for status in variants:
            shell=Shell(status)
            with self.subTest(status=status[:60]):
                with self.assertRaises(ValueError, msg="H3_UNVERIFIED_MODE_MUST_REFUSE"):
                    self.invoke(shell)
                self.assertFalse(any(c.startswith(("diagnose ", "execute ", "config ", "edit "))
                                     for c in shell.commands), "H3_UNVERIFIED_DIAGNOSTIC_SENT")
        shell=Shell()
        with self.assertRaisesRegex(ValueError, "config_platform_not_supported"):
            self.invoke(shell, vdom="root")
        self.assertEqual(shell.commands, [], "H3_EXPLICIT_VDOM_MUST_STOP_BEFORE_CONTACT")

    def test_flow_deadline_restore_and_cleanup_failure_block(self):
        shell=Shell()
        try:
            result, unused=self.invoke(shell, recipe="flow")
        except Exception as error:
            self.fail("H3_REGISTRY_FREE_FLOW_REQUIRED: "+type(error).__name__+": "+str(error))
        self.assertTrue(result["deadline_reached"])
        self.assertTrue(shell.interrupted.is_set())
        self.assertFalse(shell.enabled)
        self.assertFalse(shell.filtered)
        self.assertIn("diagnose debug flow trace stop", shell.commands)
        broken=Shell(fail_cleanup=True)
        with self.assertRaisesRegex(ValueError, "session was closed") as caught:
            self.invoke(broken, recipe="flow")
        self.assertNotIn("auth-canary-91", str(caught.exception))
        self.assertIn("diagnose debug flow trace stop", broken.commands)
        self.assertIn("diagnose debug flow filter clear", broken.commands)
