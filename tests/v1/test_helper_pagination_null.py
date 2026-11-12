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

    async def test_multiword_secrets_with_controls_through_engine_proxy_worker(self):
        status = "Version: FortiGate-VM64-KVM v8.0.0,build0167,release\r\n"
        for secret_line in ("password: first CNRY0000001Q CNRY0000002Q\r\n",
                            "secret: first CNRY0000001Q CNRY0000002Q\r\n",
                            "\x1b[0m\ntoken: first CNRY0000001Q CNRY0000002Q\n",
                            "pass\x08word: first CNRY0000001Q CNRY0000002Q\n"):
            with self.subTest(line=secret_line):
                raw = status + secret_line + "safe diagnostic tail\r\n" * 150
                self.read.side_effect = lambda *args: (0, raw)
                joined, pages = await self.read_pages_through_transport("ssh_read")
                text = joined.decode()
                self.assertNotIn("CNRY", text)
                self.assertNotIn("first", text)
                self.assertNotIn("\r", text)
                self.assertNotIn("\x1b", text)
                self.assertEqual(text.count("safe diagnostic tail"), 150)
                self.assertGreater(len(pages), 1)

    async def test_unfinished_terminal_strings_preserve_lines_through_ssh_and_switch(self):
        # Use an enrolled IOS target for both raw logs and normalized OSPF.
        inventory = self.state / "helper" / "inventory.json"
        document = json.loads(inventory.read_text())
        device = document["devices"][0]
        device["platform"] = "cisco_ios"
        device["helper"].update(ssh_platform="cisco_ios", enabled_queries=["log_messages", "ospf_neighbors"],
                                device_types=["switch"], read_inventory={})
        write_private(inventory, json.dumps(document).encode(), replace=True)
        identity = "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.9(3)M12\r\n"
        rows = ("192.0.2.1 1 FULL/DR 00:00:31 198.51.100.1 Gi0/1\r\n"
                "192.0.2.2 1 2WAY/DROTHER 00:00:32 198.51.100.2 Gi0/2\r\n")
        for introducer in ("]", "P", "X", "^", "_"):
            with self.subTest(introducer=introducer):
                logs = ("Nov 10 10:00:01 sshd: Invalid user \x1b" + introducer + "untrusted-name\r\n"
                        "Nov 10 10:00:02 sshd: Accepted publickey for operator\r\n"
                        "Nov 10 10:00:03 config changed\r\n")
                ospf = ("Neighbor ID Pri State Dead Time Address Interface\r\n"
                        "\x1b" + introducer + "unexpected diagnostic\r\n" + rows)
                def transport(auth, platform, command):
                    self.assertEqual(platform, "cisco_ios")
                    if command == "show version":
                        return 0, identity
                    if command == "show logging":
                        return 0, logs
                    self.assertEqual(command, "show ip ospf neighbor")
                    return 0, ospf
                self.read.side_effect = transport
                result = await self.bridge.call(server.mcp, "ssh_read", {
                    "target": "device-a", "platform": "cisco_ios", "query": "log_messages"})
                self.assertFalse(result["isError"], result)
                raw = result["structuredContent"]
                expected = logs.replace("\x1b" + introducer, "").replace("\r", "")
                self.assertEqual(raw["untrusted_device_output"], expected)
                self.assertEqual(raw["content_sha256"], hashlib.sha256(expected.encode()).hexdigest())
                result = await self.bridge.call(server.mcp, "switch_read", {
                    "target": "device-a", "table": "ospf_neighbor"})
                self.assertFalse(result["isError"], result)
                data = result["structuredContent"]
                self.assertEqual(json.loads(result["content"][0]["text"]), data)
                self.assertEqual(data["status"], "unparsed")
                self.assertEqual([row["state"] for row in data["records"]], ["full", "2way"])
                self.assertEqual([row["neighbor_id"] for row in data["records"]], ["192.0.2.1", "192.0.2.2"])
                self.assertEqual([line["text"] for line in data["unparsed"]], ["unexpected diagnostic"])
                self.assertFalse(data["coverage"]["complete"])
                expected_ospf = ospf.replace("\x1b" + introducer, "").replace("\r", "")
                self.assertEqual(data["sources"][0]["content_sha256"], hashlib.sha256(expected_ospf.encode()).hexdigest())

    async def test_crlf_credential_redaction_survives_exec_proxy_worker_and_pages(self):
        from types import SimpleNamespace

        secret = "alfa-example\r\nbravo-example"
        vault_path = self.state / "helper" / "vault.json"
        vault = json.loads(vault_path.read_text())
        vault["credentials"]["fixture-ro"]["value"] = secret
        write_private(vault_path, json.dumps(vault).encode(), replace=True)
        status = "Version: FortiGate-VM64-KVM v8.0.0,build0167,release\r\n"
        raw = status + ("řádek\r\n" * 150) + "echo " + secret + "\r\necho " + secret.replace("\r\n", "\n") + "\r\n" + "tail\r\n" * 150
        expected = raw.replace(secret, "<REDACTED>").replace("\r\n", "\n").replace(secret.replace("\r\n", "\n"), "<REDACTED>").encode()
        self.read.side_effect = engine._exec_read
        with patch.object(engine, "_resolve_target_ipv4", return_value=("192.0.2.10",)), \
             patch.object(engine, "host_key_line", return_value="synthetic-pinned"), \
             patch.object(engine, "_exec_command", return_value=SimpleNamespace(rc=0, stdout=raw.encode())) as transport:
            arguments, parts = self.arguments("ssh_read"), []
            while True:
                result = await self.bridge.call(server.mcp, "ssh_read", arguments)
                self.assertFalse(result["isError"], result)
                page = result["structuredContent"]
                self.assertEqual(json.loads(result["content"][0]["text"]), page)
                text = page["untrusted_device_output"]
                self.assertNotIn("alfa-example", text)
                self.assertNotIn("bravo-example", text)
                self.assertNotIn("\r", text)
                self.assertEqual(page["content_sha256"], hashlib.sha256(expected).hexdigest())
                self.assertEqual(page["total_bytes"], len(expected))
                self.assertEqual(page["offset"], sum(map(len, parts)))
                self.assertEqual(page["returned_bytes"], len(text.encode()))
                parts.append(text.encode())
                end = sum(map(len, parts))
                self.assertEqual(page["complete"], end == len(expected))
                self.assertEqual(page["next_offset"], None if page["complete"] else end)
                if page["complete"]:
                    break
                arguments.update(offset=page["next_offset"], content_sha256=page["content_sha256"])
            self.assertGreater(len(parts), 1)
            self.assertEqual(b"".join(parts), expected)
            transport.assert_called_once()
            self.assertEqual(self.read.call_count, 1)

    async def test_large_crlf_output_with_a_secret_joins_to_the_declared_hash_for_both_paged_reads(self):
        from types import SimpleNamespace

        secret = "synthetic-pagination-password-only"
        status = "Version: FortiGate-VM64-KVM v8.0.0,build0167,release\r\nCurrent virtual domain: root\r\n"
        body = ("config firewall address\r\n" + "".join(
            ' edit "obj%d"\r\n set comment "%s %s"\r\n set password ENC synthetic-enc-%d\r\n next\r\n'
            % (index, "ž" * (index % 7) + "x" * 90, secret if index % 50 == 0 else "plain", index)
            for index in range(600)) + "end\r\n")
        outputs = {}

        def transport(auth, address, known_hosts_line, credential, command, platform, **options):
            return SimpleNamespace(rc=0, stdout=outputs[command].encode())

        self.read.side_effect = engine._exec_read
        with patch.object(engine, "_resolve_target_ipv4", return_value=("192.0.2.10",)), \
             patch.object(engine, "host_key_line", return_value="synthetic-pinned"), \
             patch.object(engine, "_exec_command", side_effect=transport), \
             patch.object(self.bridge.proxy, "_consume_rate_limit"):
            for name, changes in (("ssh_read", {}), ("schema_read", {"view": "show"})):
                # ssh_read pages the status output itself; schema_read pages its report of the configuration.
                outputs.update({"get system status": status + body if name == "ssh_read" else status,
                                "show full-configuration": body})
                for size in (1000, 4093, 48000):
                    with self.subTest(tool=name, max_bytes=size):
                        with patch.object(engine, "_SSH_PAGE_CACHE", {}):
                            joined, pages = await self.read_pages_through_transport(name, max_bytes=size, **changes)
                        self.assertGreater(len(joined), 48000)
                        self.assertGreater(len(pages), 1)
                        self.assertNotIn(secret.encode(), joined)
                        self.assertNotIn(b"synthetic-enc-", joined)
                        self.assertNotIn(b"\r", joined)

    async def read_pages_through_transport(self, tool, **changes):
        """Pages of one capture: every page agrees with its JSON text, and the join has the declared hash and size."""
        args = dict(self.arguments(tool), **changes)
        pages = []
        for _ in range(512):
            response = await self.bridge.call(server.mcp, tool, args)
            self.assertFalse(response["isError"], response)
            data = response["structuredContent"]
            self.assertEqual(json.loads(response["content"][0]["text"])["untrusted_device_output"],
                             data["untrusted_device_output"])
            self.assertEqual(data["offset"], sum(page["returned_bytes"] for page in pages))
            self.assertEqual(data["returned_bytes"], len(data["untrusted_device_output"].encode()))
            pages.append(data)
            if data["complete"]:
                break
            args.update(offset=data["next_offset"], content_sha256=data["content_sha256"])
        joined = b"".join(page["untrusted_device_output"].encode() for page in pages)
        self.assertEqual({page["content_sha256"] for page in pages}, {hashlib.sha256(joined).hexdigest()})
        self.assertEqual({page["total_bytes"] for page in pages}, {len(joined)})
        return joined, pages

    async def test_later_target_reads_retain_pending_and_completed_target_secrets(self):
        secrets = ("SYNTHETIC_ACTIVE_TARGET_PASSWORD", "synthetic-active-auth-context")
        for completed in (False, True):
            with self.subTest(completed=completed):
                p = self.bridge.proxy
                p.session_secrets.clear()
                p.pending[1] = "tools/call"
                p.pending_tools[1] = "ssh_read"
                p.response_secrets[1] = secrets
                p._remember_session_secrets(secrets)
                for index in range(256):
                    p._remember_session_secrets((f"synthetic-password-{index}", f"synthetic-context-{index}"))
                if completed:
                    p.response(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode())
                contexts = []

                def read(auth, platform, command):
                    contexts.append(auth.redaction_secrets)
                    rc, text = self.device_read(auth, platform, command)
                    return rc, text.replace("x" * 3500, "plain " + " and ".join(secrets) + " tail " + "x" * 3500)

                self.read.side_effect = read
                for name in ("ssh_read", "schema_read"):
                    with self.subTest(name=name):
                        # HelperBridge runs engine -> proxy -> final worker redaction and page guard.
                        with patch.object(worker, "_page_changes", wraps=worker._page_changes) as guard:
                            result = await self.bridge.call(server.mcp, name, self.arguments(name))
                        self.assertFalse(result["isError"], result)
                        for view in (result["structuredContent"], json.loads(result["content"][0]["text"])):
                            for secret in secrets:
                                self.assertNotIn(secret, view["untrusted_device_output"])
                        guard.assert_called_once()
                        self.assertEqual(worker._page_changes(*guard.call_args.args), [])
                        self.assertEqual(1 in p.pending, not completed)
                self.assertTrue(contexts)
                for context in contexts:
                    for secret in secrets:
                        self.assertIn(secret, context)

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

    async def test_missing_continuation_hash_is_explained_on_wire(self):
        for name, label in (("ssh_read", "SSH"), ("schema_read", "schema")):
            first = await self.bridge.call(server.mcp, name, self.arguments(name))
            self.assertFalse(first["isError"])
            offset = first["structuredContent"]["next_offset"]
            self.assertGreater(offset, 0)
            reads_before = self.read.call_count
            for mode in ("omitted", "null"):
                args = dict(self.arguments(name), offset=offset)
                if mode == "null":
                    args["content_sha256"] = None
                refused = await self.bridge.call(server.mcp, name, args)
                self.assertTrue(refused["isError"])
                wire = "\n".join(item.get("text", "") for item in refused["content"])
                self.assertNotIn("Role operation failed", wire)
                self.assertNotIn("-32603", wire)
                data = refused["structuredContent"]
                self.assertEqual(data["error_code"], name.split("_")[0] + "_pagination_snapshot_required")
                self.assertEqual(data["error"], label + " pagination needs the content_sha256 of its first page; restart at offset 0")
                self.assertEqual(data["restart_offset"], 0)
                self.assertEqual(json.loads(refused["content"][0]["text"])["error_code"], data["error_code"])
            self.assertEqual(self.read.call_count, reads_before)

    async def test_expired_and_wrong_hash_continuations_have_own_code(self):
        for name in ("ssh_read", "schema_read"):
            first = await self.bridge.call(server.mcp, name, self.arguments(name))
            data = first["structuredContent"]
            reads_before = self.read.call_count
            for snapshot in ("0" * 64, data["content_sha256"]):
                with patch.object(engine, "_SSH_PAGE_CACHE", {}):
                    args = dict(self.arguments(name), offset=data["next_offset"], content_sha256=snapshot)
                    refused = await self.bridge.call(server.mcp, name, args)
                    self.assertTrue(refused["isError"])
                    self.assertEqual(refused["structuredContent"]["error_code"],
                                     name.split("_")[0] + "_pagination_expired")
                    self.assertNotIn("-32603", json.dumps(refused))
            self.assertEqual(self.read.call_count, reads_before)

    HEADER = ("Version: FortiGate-VM64-KVM v8.0.0,build0167,release\n"
              "Current virtual domain: root\n")

    async def read_pages(self, body, tool="ssh_read", **changes):
        status = self.HEADER
        self.read.side_effect = lambda auth, platform, command: (
            0, status if tool == "schema_read" and command == "get system status" else body)
        args = dict(self.arguments(tool), **changes)
        logged = len(self.log.read_text().splitlines()) if self.log.exists() else 0
        pages, expected_hash, reads_after_first = [], None, None
        for number in range(512):
            response = await self.bridge.call(server.mcp, tool, args)
            self.assertFalse(response["isError"], response)
            data = response["structuredContent"]
            wire = json.loads(response["content"][0]["text"])
            for name in ("untrusted_device_output", "content_sha256", "returned_bytes", "total_bytes",
                         "next_offset", "offset", "complete"):
                self.assertEqual(wire[name], data[name], name)
                self.assertIs(type(wire[name]), type(data[name]), name)
            self.assertRegex(data["content_sha256"], "^[0-9a-f]{64}$")
            self.assertIs(type(data["returned_bytes"]), int)
            if number == 0:
                expected_hash, reads_after_first = data["content_sha256"], self.read.call_count
            else:
                self.assertEqual(data["pagination_source"], "cached")
                self.assertEqual(self.read.call_count, reads_after_first)
            self.assertEqual(data["content_sha256"], expected_hash)
            self.assertEqual(data["offset"], sum(page["returned_bytes"] for page in pages))
            pages.append(data)
            if data["complete"]:
                break
            args.update(offset=data["next_offset"], content_sha256=expected_hash)
        else:
            self.fail("pagination did not finish within the bounded fixture")
        joined = b"".join(page["untrusted_device_output"].encode("utf-8") for page in pages)
        for page in pages:
            self.assertEqual(page["returned_bytes"], len(page["untrusted_device_output"].encode("utf-8")))
        self.assertEqual(len(joined), pages[-1]["total_bytes"])
        self.assertEqual(hashlib.sha256(joined).hexdigest(), expected_hash)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()][logged:]
        self.assertEqual([row["status"] for row in rows], ["started", "ok"] * len(pages))
        self.assertEqual(rows[1]["result_sha256"], expected_hash)
        return joined, pages

    async def test_schema_reports_are_valid_json_and_stable_through_proxy_and_worker(self):
        dense = 'config firewall address\n' + ''.join(
            ' edit "obj%d"\n set comment "%s token=synthetic-token-%d"\n'
            ' set password ENC synthetic-enc-%d\n set psksecret "synthetic-psk-%d"\n'
            ' set fortitoken "FTK%d"\n set ciphertext "set passwd synthetic-%d"\n next\n'
            % (i, 'x' * (40 + i * 7), i, i, i, i, i) for i in range(12)) + 'end\n'
        large = 'config firewall address\n' + ''.join(
            ' edit "obj%d"\n set comment "%s"\n set fortitoken "FTK%d"\n next\n'
            % (i, 'x' * 150, i) for i in range(300)) + 'end\n'
        # Match the measured-schema fixtures: fortitoken is a string, not a password type.
        path = self.state / 'helper/library.json'
        library = json.loads(path.read_text())
        library['config']['firewall address']['attrs'].update({
            'fortitoken': {'type': 'string'}, 'ciphertext': {'type': 'string'},
            'password': {'type': 'password'}, 'psksecret': {'type': 'string'}})
        write_private(path, json.dumps(library).encode(), replace=True)
        registry = self.state / 'helper/registry.json'
        data = json.loads(registry.read_text())
        data['targets']['device-a']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        write_private(registry, json.dumps(data).encode(), replace=True)
        with patch.object(self.bridge.proxy, '_consume_rate_limit'):
            for body, count in ((dense, 12), (large, 300)):
                for view in ('get', 'show'):
                    expected = None
                    for size in (1000, 1001, 1777, 4096, 16000, 48000):
                        with self.subTest(objects=count, view=view, max_bytes=size):
                            joined, pages = await self.read_pages(body, 'schema_read', view=view, max_bytes=size)
                            report = json.loads(joined)
                            self.assertEqual(len(report['objects']), count)
                            if expected is None:
                                expected = joined
                            self.assertEqual(joined, expected)
                            self.assertNotIn(b'synthetic-token-', joined)
                            self.assertNotIn(b'FTK', joined)
                            if count == 300:
                                self.assertGreater(len(pages), 1)
                                self.assertGreater(len(joined), 48000)

    async def test_schema_nested_arrays_survive_the_complete_response_path(self):
        from netops_helper import schema_read
        report = {'objects': [{'attributes': {'password': ['nested-password'],
                    'fortitoken': ['nested-fortitoken']},
                    'nested': [[{'comment': 'visible', 'values': ['token=nested-token', 7]},
                                ['ž' * 1600, ['visible' * 400]]]]}]}
        expected = None
        with patch.object(schema_read, 'snapshot', return_value=report):
            for size in (1000, 1777, 48000):
                joined, pages = await self.read_pages('synthetic snapshot', 'schema_read', max_bytes=size)
                decoded = json.loads(joined)
                self.assertEqual(decoded['objects'][0]['nested'][0][0]['comment'], 'visible')
                self.assertEqual(decoded['objects'][0]['nested'][0][1][0], 'ž' * 1600)
                for hidden in ('nested-password', 'nested-fortitoken', 'nested-token'):
                    self.assertNotIn(hidden, joined.decode())
                if expected is None:
                    expected = joined
                self.assertEqual(joined, expected)
                self.assertEqual(len(pages) > 1, size < 48000)

        # A secret may also span the JSON punctuation between separate values.
        secret = 'a","b'
        self.bridge.proxy.session_secrets[secret] = None
        with patch.object(schema_read, 'snapshot', return_value={'values': ['x' * 990 + 'a', 'b' + 'z' * 1100]}):
            result = await self.bridge.call(server.mcp, 'schema_read', self.arguments('schema_read'))
        self.assertTrue(result['isError'])
        self.assertNotIn(secret, json.dumps(result))

    async def test_schema_page_altered_by_a_later_layer_is_withheld(self):
        real = worker._redacted_result

        def altered(*args):
            result = real(*args)
            result['structuredContent']['untrusted_device_output'] += 'changed'
            return result

        with patch.object(worker, '_redacted_result', side_effect=altered):
            result = await self.bridge.call(server.mcp, 'schema_read', self.arguments('schema_read'))
        self.assertTrue(result['isError'])
        self.assertEqual(result['structuredContent']['error_code'], 'page_changed_by_redaction')
        self.assertEqual(result['structuredContent']['changed_fields'], ['untrusted_device_output'])
        self.assertNotIn('xxxxx', json.dumps(result))

    async def test_session_and_transport_secrets_cannot_cross_ssh_page_boundaries(self):
        secret = 'SYNTHETICVALUE123'
        with patch.object(self.bridge.proxy, '_consume_rate_limit'):
            for source in ('session', 'transport'):
                if source == 'session':
                    self.bridge.proxy.session_secrets[secret] = None
                else:
                    self.bridge.proxy.transport_secrets = (secret,)
                for size in (1000, 1001, 1007, 1777, 16000, 48000):
                    for prefix in ('\n', self.HEADER):
                        with self.subTest(source=source, max_bytes=size, newline=prefix == '\n'):
                            body = prefix + 'x' * (size - 1) + secret + 'z' * 1100
                            # Identity/transport is the fixture boundary; exercise the exact review output.
                            with patch.object(engine, "_verified_read", return_value=(0, body)):
                                joined, pages = await self.read_pages(body, max_bytes=size)
                            self.assertNotIn(secret.encode(), joined)
                            self.assertGreater(len(pages), 1)
                self.bridge.proxy.session_secrets.pop(secret, None)
                self.bridge.proxy.transport_secrets = ()

    async def test_session_and_transport_secrets_cannot_cross_schema_page_boundaries(self):
        from netops_helper import schema_read
        secret = 'SYNTHETICVALUE123'
        with patch.object(self.bridge.proxy, '_consume_rate_limit'):
            for source in ('session', 'transport'):
                if source == 'session':
                    self.bridge.proxy.session_secrets[secret] = None
                else:
                    self.bridge.proxy.transport_secrets = (secret,)
                for size in (1000, 1001, 1007, 1777, 16000, 48000):
                    for newline in (False, True):
                        with self.subTest(source=source, max_bytes=size, newline=newline):
                            # The unredacted JSON would split the value five bytes into it.
                            start = '\n' if newline else ''
                            prefix = len(json.dumps({'value': start}, separators=(',', ':')).encode()) - 2
                            report = {'value': start + 'x' * (size - 5 - prefix) + secret + 'z' * 1100}
                            with patch.object(schema_read, 'snapshot', return_value=report):
                                joined, pages = await self.read_pages('synthetic snapshot', 'schema_read', max_bytes=size)
                            self.assertNotIn(secret, '\n'.join(json.loads(joined).values()))
                            self.assertNotIn(secret.encode(), joined)
                self.bridge.proxy.session_secrets.pop(secret, None)
                self.bridge.proxy.transport_secrets = ()

    async def test_redaction_context_is_private_and_cannot_be_injected_by_clients(self):
        from netops_helper.proxy import Proxy, ToolArgumentsError
        for name in ('ssh_read', 'schema_read'):
            properties = self.descriptors[name]['inputSchema']['properties']
            self.assertNotIn('auth_context', properties)
            self.assertNotIn('redaction_context', properties)
            with self.assertRaises(ToolArgumentsError):
                Proxy._validate_tool_arguments(name, dict(self.arguments(name), redaction_context=[]))
        # Standalone proxy tool-list filtering uses the same private field set.
        tool = {'name': 'ssh_read', 'inputSchema': {'type': 'object', 'properties': {
            'target': {'type': 'string'}, 'auth_context': {}, 'redaction_context': {}},
            'required': ['target', 'redaction_context']}}
        self.bridge.proxy.pending['private-schema'] = 'tools/list'
        message = {'jsonrpc': '2.0', 'id': 'private-schema', 'result': {'tools': [tool]}}
        public = json.loads(self.bridge.proxy.response(json.dumps(message).encode()))
        schema = next(item for item in public['result']['tools'] if item['name'] == 'ssh_read')['inputSchema']
        self.assertEqual(set(schema['properties']), {'target'})
        self.assertEqual(schema['required'], ['target'])

    async def test_new_session_secret_invalidates_an_older_cached_snapshot(self):
        from netops_helper import schema_read
        secret = 'SYNTHETICVALUE123'
        body = self.HEADER + 'x' * 980 + secret + 'z' * 1100
        report = {'value': 'x' * 990 + secret + 'z' * 1100}
        self.read.side_effect = lambda *args: (0, body)
        with patch.object(schema_read, 'snapshot', return_value=report):
            for name in ('ssh_read', 'schema_read'):
                self.bridge.proxy.session_secrets.pop(secret, None)
                first = await self.bridge.call(server.mcp, name, self.arguments(name))
                self.assertFalse(first['isError'])
                page = first['structuredContent']
                self.bridge.proxy.session_secrets[secret] = None
                args = dict(self.arguments(name), offset=page['next_offset'], content_sha256=page['content_sha256'])
                result = await self.bridge.call(server.mcp, name, args)
                self.assertTrue(result['isError'])
                self.assertEqual(result['structuredContent']['error_code'], name.split('_')[0] + '_pagination_expired')
                self.assertNotIn(secret, json.dumps(result))

    async def test_unrelated_new_session_secret_does_not_expire_a_cached_snapshot(self):
        # Reading another target adds its secrets to the session; the pages of this one stay valid.
        for name in ('ssh_read', 'schema_read'):
            first = await self.bridge.call(server.mcp, name, self.arguments(name))
            page = first['structuredContent']
            self.assertFalse(first['isError'])
            self.assertIsNotNone(page['next_offset'])
            self.bridge.proxy.session_secrets['synthetic-other-target-secret'] = None
            reads_before = self.read.call_count
            args = dict(self.arguments(name), offset=page['next_offset'], content_sha256=page['content_sha256'])
            second = await self.bridge.call(server.mcp, name, args)
            self.assertFalse(second['isError'], second)
            self.assertEqual(second['structuredContent']['content_sha256'], page['content_sha256'])
            self.assertEqual(second['structuredContent']['pagination_source'], 'cached')
            self.assertEqual(self.read.call_count, reads_before)
            self.bridge.proxy.session_secrets.pop('synthetic-other-target-secret')

    async def test_unverifiable_schema_report_is_withheld_with_its_own_code_and_no_restart(self):
        from netops_helper import schema_read
        secret = 'a","b'
        report = {'values': ['x' * 990 + 'a', 'b' + 'z' * 1100]}
        self.bridge.proxy.session_secrets[secret] = None
        with patch.object(schema_read, 'snapshot', return_value=report):
            result = await self.bridge.call(server.mcp, 'schema_read', self.arguments('schema_read'))
        self.assertTrue(result['isError'])
        data = result['structuredContent']
        self.assertEqual(data['error_code'], 'schema_redaction_unverified')
        self.assertEqual(data['error'], 'schema redaction could not be verified; report withheld')
        self.assertNotIn('restart_offset', data)  # reading again would be refused in the same way
        self.assertEqual(json.loads(result['content'][0]['text']), data)
        self.assertNotIn('-32603', json.dumps(result))
        self.assertNotIn('x' * 100, json.dumps(result))

    async def test_digest_describes_final_redacted_paginated_text(self):
        body = (self.HEADER + "x" * 1300 + "\n128-length passwd                 : enabled\n"
                "password: synthetic-fixture-only-value\n" + "ž" * 1800)
        joined, pages = await self.read_pages(body)
        self.assertGreater(len(pages), 3)
        self.assertNotIn(b"synthetic-fixture-only-value", joined)
        self.assertIn(b"128-length [REDACTED]\n", joined)
        self.assertIn("ž" * 1800, joined.decode("utf-8"))
        self.assertNotIn("synthetic-fixture-only-value", self.log.read_text())

    async def test_secrets_and_markers_are_redacted_on_the_whole_text_across_page_edges(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n" + "QUJD" * 60 + "\n-----END RSA PRIVATE KEY-----")
        body = (self.HEADER + "x" * (994 - len(self.HEADER)) + "\npassword: synthetic-boundary-value\n"
                "set psksecret ENC synthetic-enc-value\n" + pem + "\n"
                "already [REDACTED] and <REDACTED> markers\n" + "y" * 1500)
        joined, pages = await self.read_pages(body)
        text = joined.decode("utf-8")
        for hidden in ("synthetic-boundary", "synthetic-enc-value", "QUJD", "PRIVATE KEY"):
            self.assertNotIn(hidden, text)
            for page in pages:
                self.assertNotIn(hidden, page["untrusted_device_output"])
        self.assertIn("already [REDACTED] and <REDACTED> markers", text)

    async def test_page_altered_by_a_later_layer_is_withheld_not_returned_with_stale_metadata(self):
        # Pages end on a newline, so only a page without one can cut a marker. The JSON line below is
        # longer than a page; the second page ends inside "password":<REDACTED>, which a later layer
        # completes, and must be withheld even with the 1.0.7 redactor.
        body = self.HEADER + '{"k":"' + "x" * 980 + '","password":"SYNTHETICVAL"}\n' + "y" * 1500
        self.read.side_effect = lambda *args, **kwargs: (0, body)
        args = self.arguments("ssh_read")
        first = await self.bridge.call(server.mcp, "ssh_read", args)
        self.assertFalse(first["isError"], first)
        self.assertEqual(first["structuredContent"]["untrusted_device_output"], self.HEADER)
        args.update(offset=first["structuredContent"]["next_offset"], content_sha256=first["structuredContent"]["content_sha256"])
        response = await self.bridge.call(server.mcp, "ssh_read", args)
        self.assertTrue(response["isError"])
        data = response["structuredContent"]
        self.assertEqual((data["ok"], data["error_code"], data["restart_offset"]), (False, "page_changed_by_redaction", 0))
        self.assertEqual(data["changed_fields"], ["untrusted_device_output"])
        self.assertNotIn("xxxxxxxx", json.dumps(response))
        self.assertNotIn("SYNTHETICVAL", json.dumps(response))

    async def test_pages_with_a_kept_label_before_the_marker_are_cut_on_a_line_and_not_withheld(self):
        # `passphrase = <value>` keeps its label, so a page boundary inside the marker used to make a
        # later layer change the page. With lines of about 100 bytes every page now ends after a newline.
        body = self.HEADER + "".join(
            "line %03d %s\n%s\npassphrase = synthetic-fixture-%03d\n" % (number, "x" * 60, '{"k":"v","password":"SYNTHETICVAL%03d"}' % number, number)
            for number in range(40))
        for max_bytes in (1000, 1013, 1111, 1500):
            joined, pages = await self.read_pages(body, max_bytes=max_bytes)
            self.assertGreater(len(pages), 2)
            self.assertTrue(all(page["untrusted_device_output"].endswith("\n") for page in pages))
            text = joined.decode("utf-8")
            self.assertIn("passphrase = [REDACTED]\n", text)
            self.assertNotIn("synthetic-fixture", text)
            self.assertNotIn("SYNTHETICVAL", text)

    def use_password(self, value):
        write_private(self.state / "helper" / "vault.json", json.dumps({"version": 2, "credentials": {
            "fixture-ro": {"kind": "password", "login": "fixture-user", "value": value}}}).encode(), replace=True)

    async def test_known_secret_equal_to_a_byte_count_keeps_the_page_metadata(self):
        # Synthetic password "1000": the proxy turned returned_bytes and next_offset into a marker.
        # The newline at byte 999 makes the first page exactly 1000 bytes.
        self.use_password("1000")
        body = self.HEADER + "x" * (999 - len(self.HEADER)) + "\n" + "x" * 500 + "\nvalue 1000 end\n"
        joined, pages = await self.read_pages(body)
        self.assertEqual((pages[0]["returned_bytes"], pages[0]["next_offset"]), (1000, 1000))
        self.assertIs(type(pages[0]["next_offset"]), int)
        self.assertEqual(len(pages), 2)
        self.assertNotIn(b"1000", joined)
        self.assertIn(b"\nvalue <REDACTED> end\n", joined)

    async def test_known_secret_inside_the_content_hash_keeps_the_page_metadata(self):
        # Synthetic password "abc" that occurs in the SHA-256 of the output.
        self.use_password("abc")
        body = next(text for text in (self.HEADER + "x" * 1500 + str(number) for number in range(100000))
                    if "abc" in hashlib.sha256(text.encode()).hexdigest())
        joined, pages = await self.read_pages(body)
        self.assertIn("abc", pages[0]["content_sha256"])
        self.assertEqual(joined, body.encode())

    async def test_page_whose_metadata_a_later_layer_changes_is_withheld(self):
        # A layer that does not keep the metadata out of its redaction (here the proxy).
        self.use_password("1000")
        body = self.HEADER + "x" * (999 - len(self.HEADER)) + "\n" + "x" * 500 + "\n"
        self.read.side_effect = lambda *args, **kwargs: (0, body)
        for name in ("ssh_read",):
            with patch.object(proxy, "page_metadata", side_effect=lambda value, tool="ssh_read": None):
                response = await self.bridge.call(server.mcp, name, self.arguments(name))
            self.assertTrue(response["isError"], name)
            data = response["structuredContent"]
            self.assertEqual((data["error_code"], data["restart_offset"]), ("page_changed_by_redaction", 0))
            self.assertEqual(data["changed_fields"], ["next_offset", "returned_bytes"])
            self.assertNotIn("xxxxxxxx", json.dumps(response))

    async def test_refusal_is_classified_by_type_through_the_real_fastmcp_call(self):
        with patch.object(worker, "_pagination_refusal", wraps=worker._pagination_refusal) as classify:
            for name in ("ssh_read", "schema_read"):
                first = await self.bridge.call(server.mcp, name, self.arguments(name))
                args = dict(self.arguments(name), offset=first["structuredContent"]["next_offset"])
                refused = await self.bridge.call(server.mcp, name, args)
                self.assertTrue(refused["isError"])
        self.assertEqual(classify.call_count, 2)
        for call in classify.call_args_list:
            error = call.args[0]
            chain, current = [], error
            while current is not None and len(chain) < 20:
                chain.append(current)
                current = current.__cause__ or current.__context__
            refusals = [item for item in chain if isinstance(item, engine.PaginationRefused)]
            # FastMCP wraps the engine exception; the original typed exception is in the chain.
            self.assertTrue(refusals, [type(item).__name__ for item in chain])
            self.assertIsNot(error, refusals[0])
            self.assertIs(worker._pagination_refusal(error), refusals[0])

    async def test_unrelated_error_with_similar_text_stays_an_internal_error(self):
        similar = ("synthetic wrapper: " + engine._SSH_SNAPSHOT_UNNAMED,
                   engine._SSH_SNAPSHOT_UNNAMED + " (synthetic)",
                   engine._SSH_SNAPSHOT_EXPIRED.upper())
        for text in similar:
            for kind in (RuntimeError, ValueError):
                with patch.object(engine, "_validate_pagination", side_effect=kind(text)):
                    response = await self.bridge.call(server.mcp, "ssh_read", self.arguments("ssh_read"))
                self.assertTrue(response["isError"])
                wire = json.dumps(response)
                self.assertIn("-32603", wire)
                self.assertIn("Role operation failed", wire)
                self.assertNotIn("error_code", wire)
                self.assertNotIn("synthetic", wire)
        self.read.assert_not_called()

    def test_classifier_walks_the_whole_cause_and_context_graph(self):
        refusal = engine._pagination_refused(engine._SCHEMA_SNAPSHOT_EXPIRED)
        deep = refusal
        for number in range(30):
            wrapper = RuntimeError("synthetic wrapper %d" % number)
            wrapper.__cause__ = deep
            deep = wrapper
        self.assertIs(worker._pagination_refusal(deep), refusal)
        # The refusal only in __context__ while __cause__ leads elsewhere.
        outer = RuntimeError("synthetic outer")
        outer.__cause__ = KeyError("synthetic other")
        outer.__context__ = refusal
        self.assertIs(worker._pagination_refusal(outer), refusal)
        # Cycles end.
        first, second = RuntimeError("a"), RuntimeError("b")
        first.__context__, second.__context__ = second, first
        self.assertIsNone(worker._pagination_refusal(first))
        # Text fallback: exact text only.
        exact = worker._pagination_refusal(RuntimeError(engine._SSH_SNAPSHOT_UNNAMED))
        self.assertEqual((exact.code, str(exact)), ("ssh_pagination_snapshot_required", engine._SSH_SNAPSHOT_UNNAMED))
        for text in ("x" + engine._SSH_SNAPSHOT_UNNAMED, engine._SSH_SNAPSHOT_UNNAMED + "\n", "Error calling tool 'ssh_read': "
                     + engine._SSH_SNAPSHOT_UNNAMED, engine._SSH_SNAPSHOT_UNNAMED.replace("SSH", "ssh")):
            self.assertIsNone(worker._pagination_refusal(RuntimeError(text)), text)

    async def test_missing_continuation_hash_through_the_gateway_http_endpoint(self):
        directory = self.state / "gateway"
        directory.mkdir(mode=0o700)
        token = "synthetic-pagination-gateway-token-only-123456"
        write_private(directory / "token", token.encode())
        write_private(directory / "config.json", json.dumps({"version": 1, "product_version": __version__, "audit": {"mode": "local"}}, separators=(",", ":")).encode())
        audit = Audit(directory / "audit", {"mode": "local"})
        mcp = FastMCP("pagination-refusal-contract")
        for name in ("ssh_read", "schema_read"):
            mcp.add_tool(self.remote(name))
        inner = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
        boundary = gateway.AuditBoundary(inner, audit)
        with patch.object(gateway, "STATE", self.state):
            async with inner.router.lifespan_context(inner):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                        base_url="https://mcp.example.invalid",
                        headers={"Authorization": "Bearer " + token,
                                 "Accept": "application/json, text/event-stream"}) as client:
                    initialized = await client.post("/mcp", json={"jsonrpc": "2.0", "id": "initialize",
                        "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                        "capabilities": {}, "clientInfo": {"name": "pagination-refusal", "version": "1.0.0"}}})
                    self.assertEqual(initialized.status_code, 200, initialized.text)
                    client.headers["MCP-Protocol-Version"] = initialized.json()["result"]["protocolVersion"]
                    ready = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                    self.assertEqual(ready.status_code, 202, ready.text)
                    for name in ("ssh_read", "schema_read"):
                        first = await client.post("/mcp", json={"jsonrpc": "2.0", "id": name + "-first",
                            "method": "tools/call", "params": {"name": name, "arguments": self.arguments(name)}})
                        page = first.json()["result"]["structuredContent"]
                        args = dict(self.arguments(name), offset=page["next_offset"])
                        reads = self.read.call_count
                        refused = await client.post("/mcp", json={"jsonrpc": "2.0", "id": name + "-next",
                            "method": "tools/call", "params": {"name": name, "arguments": args}})
                        self.assertEqual(refused.status_code, 200, refused.text)
                        body = refused.json()
                        self.assertNotIn("error", body)
                        wire = body["result"]
                        self.assertIs(wire["isError"], True)
                        self.assertEqual(wire["structuredContent"]["error_code"],
                                         name.split("_")[0] + "_pagination_snapshot_required")
                        self.assertEqual(wire["structuredContent"]["restart_offset"], 0)
                        self.assertNotIn("-32603", refused.text)
                        self.assertEqual(self.read.call_count, reads)

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
