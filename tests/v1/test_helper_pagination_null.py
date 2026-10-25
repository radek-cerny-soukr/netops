import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import FastMCP
from netops import __version__, gateway, worker
from netops.audit import Audit
from netops.files import write_private
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine, proxy, server


class HelperPaginationNull(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = self.state / "helper"
        helper.mkdir(mode=0o700)
        pin = "SHA256:" + "A" * 43
        section = {"account_role": "read-only", "ssh_platform": "fortios",
                   "enabled_queries": ["system_status"],
                   "read_inventory": {"schema_paths": ["firewall address"]},
                   "fortios_output_standard_verified": True,
                   "rate_limit": {"requests": 60, "window_seconds": 60},
                   "egress": {"addresses": ["192.0.2.10"], "tcp_ports": [22],
                              "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
                              "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}
        device = {"name": "device-a", "platform": "fortios", "address": "192.0.2.10",
                  "port": 22, "role": "lab", "credential": "fixture-ro",
                  "host_key_fingerprint": pin, "legacy_ssh": None, "auditor": None,
                  "helper": section}
        write_private(helper / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
        write_private(helper / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "fixture-user",
                           "value": "synthetic-pagination-password-only"}}}).encode())
        library = {"format": 1, "platform": "fortios", "hardware": "FortiGate-VM64-KVM",
                   "os_version": "8.0.0", "build": "0167", "config": {
                       "firewall address": {"kind": "table", "scope": "vdom",
                                            "available": True, "attrs": {"comment": {"type": "string"}}}}}
        library_bytes = json.dumps(library).encode()
        write_private(helper / "library.json", library_bytes)
        write_private(helper / "registry.json", json.dumps({"format": 1, "targets": {"device-a": {
            "schema": "library.json", "sha256": hashlib.sha256(library_bytes).hexdigest(),
            "host_key_fingerprint": pin}}}).encode())
        self.enterContext(patch.object(worker, "STATE", self.state))
        self.enterContext(patch.object(proxy, "INVENTORY", helper / "inventory.json"))
        self.enterContext(patch.dict(os.environ, {"NETOPS_SCHEMA_REGISTRY": str(helper / "registry.json")}))
        self.log = helper / "operations.jsonl"
        self.enterContext(patch.object(helper_audit, "_RECORDER", Recorder(self.log, "helper")))
        self.enterContext(patch.object(engine, "_SSH_PAGE_CACHE", {}))
        self.read = self.enterContext(patch.object(engine, "read_from_device", side_effect=self.device_read))
        self.bridge = worker.HelperBridge()
        self.descriptors = {tool["name"]: tool for tool in await self.bridge.tools(server.mcp)}

        async def rpc(role, request):
            self.assertEqual(role, "helper")
            self.assertEqual(request["action"], "call")
            return {"result": await self.bridge.call(server.mcp, request["name"], request["arguments"])}

        self.rpc = self.enterContext(patch.object(gateway, "rpc", AsyncMock(side_effect=rpc)))

    def device_read(self, auth, platform, command):
        self.assertEqual((auth.alias, platform), ("device-a", "fortinet"))
        if command == "get system status":
            return 0, ("Version: FortiGate-VM64-KVM v8.0.0,build0167,release\n"
                       "Current virtual domain: root\n" + "x" * 3500 + "\n")
        self.assertEqual(command, "show full-configuration")
        return 0, 'config firewall address\n edit "one"\n set comment "' + "x" * 3500 + '"\n next\nend\n'

    def arguments(self, name):
        arguments = {"target": "device-a", "offset": 0, "max_bytes": 1000}
        arguments.update({"platform": "fortios", "query": "system_status"} if name == "ssh_read"
                         else {"path": "firewall address", "view": "get"})
        return arguments

    def remote(self, name):
        return gateway.RemoteTool(name=name, role="helper", parameters=self.descriptors[name]["inputSchema"])

    async def test_initial_null_and_omitted_keep_exact_request_and_complete_audit(self):
        directory = self.state / "gateway"
        directory.mkdir(mode=0o700)
        token = "synthetic-pagination-gateway-token-only-123456"
        write_private(directory / "token", token.encode())
        write_private(directory / "config.json", json.dumps({"version": 1, "product_version": __version__, "audit": {"mode": "local"}}, separators=(",", ":")).encode())
        audit = Audit(directory / "audit", {"mode": "local"})
        mcp = FastMCP("pagination-null-contract")
        for name in ("ssh_read", "schema_read"):
            mcp.add_tool(self.remote(name))
        inner = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
        boundary = gateway.AuditBoundary(inner, audit)
        inputs = {}
        outcomes = {}
        with patch.object(gateway, "STATE", self.state):
            async with inner.router.lifespan_context(inner):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                        base_url="https://mcp.example.invalid",
                        headers={"Authorization": "Bearer " + token,
                                 "Accept": "application/json, text/event-stream"}) as client:
                    initialized = await client.post("/mcp", json={"jsonrpc": "2.0", "id": "initialize",
                        "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                        "capabilities": {}, "clientInfo": {"name": "pagination-contract", "version": "1.0.0"}}})
                    self.assertEqual(initialized.status_code, 200, initialized.text)
                    client.headers["MCP-Protocol-Version"] = initialized.json()["result"]["protocolVersion"]
                    ready = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                    self.assertEqual(ready.status_code, 202, ready.text)
                    for name in ("ssh_read", "schema_read"):
                        for mode in ("omitted", "null", "hash"):
                            args = self.arguments(name)
                            if mode != "omitted":
                                args["content_sha256"] = None if mode == "null" else "a" * 64
                            key = name + "-" + mode
                            body = {"jsonrpc": "2.0", "id": key, "method": "tools/call",
                                    "params": {"name": name, "arguments": args}}
                            inputs[key] = body
                            result = await client.post("/mcp", json=body)
                            self.assertEqual(result.status_code, 200, result.text)
                            wire = result.json()["result"]
                            self.assertIs(wire["isError"], False, wire)
                            data = wire["structuredContent"]
                            self.assertIs(data["ok"], True)
                            self.assertEqual(data["pagination_source"], "fresh")
                            self.assertGreater(data["next_offset"], 0)
                            outcomes[key] = data
        for name in ("ssh_read", "schema_read"):
            self.assertEqual(outcomes[name + "-omitted"], outcomes[name + "-null"])
            self.assertEqual(outcomes[name + "-omitted"], outcomes[name + "-hash"])
        rows = [json.loads(line) for path in (directory / "audit").glob("*.jsonl")
                for line in path.read_text().splitlines()]
        requests = [row for row in rows if row["direction"] == "request"
                    and row["payload"].get("method") == "tools/call"]
        self.assertEqual(len(requests), 6)
        self.assertEqual({row["payload"]["id"] for row in requests}, set(inputs))
        for row in requests:
            self.assertEqual(row["payload"], inputs[row["payload"]["id"]])
            sequence = [item for item in rows if item["correlation"] == row["correlation"]]
            self.assertEqual([item["direction"] for item in sequence], ["request", "response", "connection_end"])
            self.assertEqual(sequence[1]["payload"]["result"]["structuredContent"], outcomes[row["payload"]["id"]])
        done = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", "pending"],
                              env=dict(os.environ, NETOPS_STATE_DIR=str(self.state)),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        role_rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([row["status"] for row in role_rows], ["started", "ok"] * 6)
        for first, second in zip(role_rows[::2], role_rows[1::2]):
            self.assertEqual(first["operation_id"], second["operation_id"])
        self.assertEqual(self.read.call_count, 9)

    async def test_unnamed_continuation_same_guard_and_named_continuation_cached(self):
        with patch.object(engine, "_missing_continuation", wraps=engine._missing_continuation) as guard:
            for name in ("ssh_read", "schema_read"):
                outputs = []
                for explicit_null in (False, True):
                    args = dict(self.arguments(name), offset=1000)
                    if explicit_null:
                        args["content_sha256"] = None
                    result = await self.remote(name).run(args)
                    self.assertTrue(result.is_error)
                    outputs.append([item.model_dump() for item in result.content])
                self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(guard.call_count, 4)
        self.read.assert_not_called()
        self.assertFalse(self.log.exists())
        for name in ("ssh_read", "schema_read"):
            first = await self.remote(name).run(self.arguments(name))
            self.assertFalse(first.is_error)
            data = first.structured_content
            count = self.read.call_count
            args = dict(self.arguments(name), offset=data["next_offset"], content_sha256=data["content_sha256"])
            second = await self.remote(name).run(args)
            self.assertFalse(second.is_error)
            self.assertEqual(second.structured_content["pagination_source"], "cached")
            self.assertEqual(second.structured_content["content_sha256"], data["content_sha256"])
            self.assertEqual(self.read.call_count, count)

    async def test_malformed_hash_strings_refused_by_real_proxy_before_engine(self):
        with patch.object(engine, "_missing_continuation", wraps=engine._missing_continuation) as guard:
            for name in ("ssh_read", "schema_read"):
                for value in ("a" * 63, "a" * 65, "A" * 64, "g" * 64):
                    self.rpc.reset_mock()
                    result = await self.remote(name).run(dict(self.arguments(name), content_sha256=value))
                    self.assertTrue(result.is_error)
                    error = json.loads(result.content[0].text)
                    self.assertEqual((error["code"], error["data"]["category"]), (-32602, "invalid_params"))
                    self.rpc.assert_awaited_once()
            guard.assert_not_called()
        self.read.assert_not_called()
        self.assertFalse(self.log.exists())

    async def test_gateway_rejects_nonstring_nonnull_hash_before_rpc(self):
        for name in ("ssh_read", "schema_read"):
            for value in (1, True, {}):
                self.rpc.reset_mock()
                result = await self.remote(name).run(dict(self.arguments(name), content_sha256=value))
                self.assertTrue(result.is_error)
                error = json.loads(result.content[0].text)
                self.assertEqual((error["code"], error["data"]["category"]), (-32602, "invalid_params"))
                self.rpc.assert_not_awaited()
        self.read.assert_not_called()
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
