import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
import jsonschema
from fastmcp import FastMCP
from netops import __version__, gateway
from netops.audit import Audit
from netops.files import write_private
from netops.ipc import RoleUnavailable
from netops_helper.proxy import Proxy


class ArgumentGuidance(unittest.IsolatedAsyncioTestCase):
    async def descriptor(self, role, name):
        import importlib
        module = importlib.import_module({
            "admin": "netops_admin.mcp_server", "auditor": "netops_auditor.mcp_server",
            "helper": "netops_helper.server",
        }[role])
        return next(tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)
                    for tool in await module.mcp.list_tools() if tool.name == name)

    def remote(self, role, descriptor):
        return gateway.RemoteTool(name=descriptor["name"], parameters=descriptor["inputSchema"], role=role)

    async def test_tcp_timeout_descriptor_advertises_existing_inclusive_bounds(self):
        descriptor = await self.descriptor("helper", "tcp_probe")
        schema = descriptor["inputSchema"]
        timeout = schema["properties"]["timeout"]
        self.assertEqual(timeout.get("type"), "number")
        self.assertEqual(timeout.get("default"), 5.0)
        self.assertEqual(timeout.get("minimum"), 0.2)
        self.assertEqual(timeout.get("maximum"), 15.0)
        self.assertEqual(set(schema.get("required", [])), {"target", "port"})

    async def test_tcp_timeout_schema_refuses_invalid_values_before_rpc_and_preserves_valid_arguments(self):
        remote = self.remote("helper", await self.descriptor("helper", "tcp_probe"))
        base = {"target": "fixture-device", "port": 443}
        for arguments in (base, *({**base, "timeout": value} for value in (0.2, 5.0, 15.0, 10, 10.0))):
            rpc = AsyncMock(return_value={"result": {
                "content": [{"type": "text", "text": "synthetic TCP response"}], "isError": False}})
            with self.subTest(arguments=arguments), patch.object(gateway, "rpc", rpc):
                result = await remote.run(arguments)
                self.assertFalse(result.is_error)
                self.assertEqual(result.content[0].text, "synthetic TCP response")
                rpc.assert_awaited_once_with("helper", {"action": "call", "name": "tcp_probe",
                                                       "arguments": arguments})
                self.assertIs(rpc.await_args.args[1]["arguments"], arguments)
        for value in (0.199, 15.001, 20, True, False, "5", None):
            rpc = AsyncMock(return_value={"result": {
                "content": [{"type": "text", "text": "unexpected dispatch"}], "isError": False}})
            with self.subTest(timeout=value), patch.object(gateway, "rpc", rpc):
                result = await remote.run({**base, "timeout": value})
                rpc.assert_not_awaited()
                self.assertTrue(result.is_error)
                error = json.loads(result.content[0].text)
                self.assertEqual(error["code"], -32602)
                self.assertEqual(error["data"]["category"], "invalid_params")
                self.assertEqual(error["message"], "Tool arguments do not match tools/list inputSchema")

    async def test_missing_required_fields_are_tool_errors_without_dispatch(self):
        for role, name, field in (("admin", "admin_doctor", "device"), ("auditor", "rule_detail", "rule_id")):
            remote = self.remote(role, await self.descriptor(role, name))
            server = FastMCP("argument-contract")
            server.add_tool(remote)
            rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "unexpected dispatch"}]}})
            with self.subTest(name=name), patch.object(gateway, "rpc", rpc):
                result = await server.call_tool(name, {})
                self.assertTrue(result.is_error)
                error = json.loads(result.content[0].text)
                self.assertEqual(error["code"], -32602)
                self.assertEqual(error["data"]["category"], "invalid_params")
                self.assertIn(field, error["message"])
                rpc.assert_not_awaited()

    async def test_schema_wrong_types_and_unknown_private_fields_are_refused_without_echo(self):
        descriptor = Proxy._target_scope_tool()
        remote = self.remote("helper", descriptor)
        for arguments in ({"target": 5}, {"target": None},
                          {"target": "example", "SYNTHETIC-PRIVATE-KEY-CANARY": "SYNTHETIC-PRIVATE-VALUE-CANARY"}):
            rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "unexpected dispatch"}]}})
            with self.subTest(arguments=arguments), patch.object(gateway, "rpc", rpc):
                result = await remote.run(arguments)
                self.assertTrue(result.is_error)
                encoded = "".join(item.text for item in result.content)
                self.assertNotIn("SYNTHETIC-PRIVATE", encoded)
                self.assertEqual(json.loads(encoded)["data"]["category"], "invalid_params")
                rpc.assert_not_awaited()

    async def test_valid_arguments_and_optional_null_default_semantics_are_preserved(self):
        schema = {"type": "object", "properties": {
            "count": {"type": "integer"}, "note": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
            "required": ["count"], "additionalProperties": False}
        remote = gateway.RemoteTool(name="synthetic", role="auditor", parameters=schema)
        for arguments in ({"count": 5}, {"count": 0, "note": None}, {"count": 1, "note": "example"}):
            rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "success"}]}})
            with self.subTest(arguments=arguments), patch.object(gateway, "rpc", rpc):
                result = await remote.run(arguments)
                self.assertFalse(result.is_error)
                self.assertEqual(result.content[0].text, "success")
                rpc.assert_awaited_once_with("auditor", {"action": "call", "name": "synthetic", "arguments": arguments})
        for arguments in ({"count": "5"}, {"count": True}):
            rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "unexpected dispatch"}]}})
            with self.subTest(arguments=arguments), patch.object(gateway, "rpc", rpc):
                self.assertTrue((await remote.run(arguments)).is_error)
                rpc.assert_not_awaited()

    async def test_invalid_installed_schema_and_role_transport_faults_are_operational(self):
        remote = gateway.RemoteTool(name="synthetic", role="auditor", parameters={"type": "not-a-type"})
        rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "unexpected dispatch"}]}})
        with patch.object(gateway, "rpc", rpc), self.assertRaises(RoleUnavailable) as caught:
            await remote.run({"SYNTHETIC-PRIVATE-KEY-CANARY": "SYNTHETIC-PRIVATE-VALUE-CANARY"})
        self.assertNotIn("invalid_params", str(caught.exception))
        self.assertNotIn("SYNTHETIC-PRIVATE", str(caught.exception))
        rpc.assert_not_awaited()
        remote = gateway.RemoteTool(name="synthetic", role="auditor", parameters={"type": "object"})
        with patch.object(gateway, "rpc", AsyncMock(side_effect=RoleUnavailable("Role transport unavailable"))), \
                self.assertRaisesRegex(RoleUnavailable, "^Role transport unavailable$"):
            await remote.run({})

    async def test_invalid_call_has_a_complete_actual_audit_and_no_pending_operation(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            directory = state / "gateway"
            directory.mkdir(mode=0o700)
            token = "synthetic-gateway-token-for-public-test-only-12345"
            write_private(directory / "token", token.encode())
            write_private(directory / "config.json", json.dumps({"version": 1, "product_version": __version__, "audit": {"mode": "local"}}, separators=(",", ":")).encode())
            audit = Audit(directory / "audit", {"mode": "local"})
            server = FastMCP("audited-argument-contract")
            server.add_tool(self.remote("helper", Proxy._target_scope_tool()))
            inner = server.http_app(path="/mcp", json_response=True, stateless_http=True)
            boundary = gateway.AuditBoundary(inner, audit)
            rpc = AsyncMock(return_value={"result": {"content": [{"type": "text", "text": "unexpected dispatch"}]}})
            headers = {"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"}
            with patch.object(gateway, "STATE", state), patch.object(gateway, "rpc", rpc):
                async with inner.router.lifespan_context(inner):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary), base_url="https://mcp.example.invalid", headers=headers) as client:
                        initialized = await client.post("/mcp", json={"jsonrpc": "2.0", "id": "initialize", "method": "initialize",
                            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                       "clientInfo": {"name": "NetOps contract test", "version": "1.0.0"}}})
                        self.assertEqual(initialized.status_code, 200, initialized.text)
                        client.headers["MCP-Protocol-Version"] = initialized.json()["result"]["protocolVersion"]
                        ready = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                        self.assertEqual(ready.status_code, 202, ready.text)
                        result = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "target_scope", "arguments": {}}})
                        for path in (directory / "audit").glob("*.jsonl"):
                            path.chmod(0o400)
                        (directory / "audit").chmod(0o500)
                        try:
                            with patch.object(gateway, "argument_error") as validate:
                                refused = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                    "params": {"name": "target_scope", "arguments": {}}})
                                self.assertEqual(refused.status_code, 503)
                                self.assertEqual(refused.json()["error"], "audit_unavailable")
                                validate.assert_not_called()
                        finally:
                            (directory / "audit").chmod(0o700)
                            for path in (directory / "audit").glob("*.jsonl"):
                                path.chmod(0o600)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertTrue(result.json()["result"]["isError"])
            rpc.assert_not_awaited()
            records = [json.loads(line) for path in (directory / "audit").glob("*.jsonl") for line in path.read_text().splitlines()]
            requests = [item for item in records if item["direction"] == "request" and item["payload"].get("method") == "tools/call"]
            self.assertEqual(len(requests), 1)
            key = requests[0]["correlation"]
            self.assertEqual([item["direction"] for item in records if item["correlation"] == key],
                             ["request", "response", "connection_end"])
            done = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", "pending"],
                                  env=dict(os.environ, NETOPS_STATE_DIR=raw), capture_output=True, text=True, timeout=60)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))

    async def test_large_invalid_argument_keeps_event_loop_responsive(self):
        import asyncio
        import time
        from netops_helper import server as helper_server
        descriptor = next(tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)
                          for tool in await helper_server.mcp.list_tools() if tool.name == "snmp_get")
        remote = self.remote("helper", descriptor)
        arguments = {"target": "synthetic.example.invalid", "oids": [1] * 1000000}
        self.assertLess(len(json.dumps(arguments, separators=(",", ":")).encode()), gateway.MAX_MESSAGE)
        rpc = AsyncMock()
        started = time.monotonic()

        async def heartbeat():
            await asyncio.sleep(0.05)
            return time.monotonic() - started

        with patch.object(gateway, "rpc", rpc):
            pulse = asyncio.create_task(heartbeat())
            await asyncio.sleep(0)
            result = await remote.run(arguments)
            elapsed = time.monotonic() - started
            delay = await pulse
        self.assertTrue(result.is_error)
        self.assertEqual(json.loads(result.content[0].text)["data"]["category"], "invalid_params")
        self.assertLess(delay, 0.5)
        self.assertLess(elapsed, 3)
        rpc.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
