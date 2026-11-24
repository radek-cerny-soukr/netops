"""Network overview over TLS, audited gateway, role IPC, and the actual Helper worker."""

import asyncio
from contextlib import ExitStack
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import uvicorn
from fastmcp import FastMCP

from netops import gateway, ipc, worker
from netops.audit import Audit
from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy, server
from test_progress_stream import Boundary, HEADERS, certificate, sse_messages


class OverviewRegistration(unittest.TestCase):
    def test_public_overview_is_registered(self):
        tools = asyncio.run(worker.HelperBridge().tools(server.mcp))
        names = [tool["name"] for tool in tools]
        self.assertEqual(names.count("network_overview"), 1)
        schema = next(tool["inputSchema"] for tool in tools if tool["name"] == "network_overview")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["properties"]), {"targets", "groups", "after", "limit", "timeout_seconds"})


def inventory(directory, count=2):
    devices, materials = [], {}
    for index in range(count):
        address = f"192.0.2.{10 + index}"
        credential = f"sample-reader-{index}"
        materials[credential] = {"kind": "password", "login": "reader",
                                 "value": ("zQv", "zzQvy")[index % 2]}
        devices.append({
            "name": f"device-{index}", "platform": "linux", "role": "internal",
            "address": address, "port": 22, "credential": credential, "legacy_ssh": None, "auditor": None,
            "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "helper": {"account_role": "read-only", "ssh_platform": "linux", "device_types": ["switch"],
                       "enabled_queries": ["kernel", "hostname"],
                       "egress": {"addresses": [address], "tcp_ports": [22], "tcp_port_ranges": [],
                                  "udp_ports": [], "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False,
                                  "tls_server_names": []}},
        })
    (directory / "inventory.json").write_text(json.dumps({"version": 2, "devices": devices}))
    vault = directory / "vault.json"
    vault.write_text(json.dumps({"version": 2, "credentials": materials}))
    vault.chmod(0o600)


async def https_case(tmp_path, *, disconnect=False):
    from netops_helper.overview import model

    def plan(scope):
        return (model.ReadSpec("kernel", "kernel", ("version",)),
                model.ReadSpec("hostname", "hostname", ("model",)))

    def assemble(scope, reads):
        fields = {}
        if reads["kernel"].text:
            fields["version"] = "6.8"
        if reads["hostname"].text:
            fields["model"] = reads["hostname"].text.strip()
        return model.DeviceFacts(fields)

    state = tmp_path / "state"
    role_directory = state / "helper"
    role_directory.mkdir(parents=True)
    (tmp_path / "helper").mkdir()
    inventory(role_directory, 5 if disconnect else 2)
    cert, key = certificate(tmp_path)
    four_reads_started = Event()
    overview_cancelled = Event()
    overview_finished = asyncio.Event()
    release = Event()
    commands = []
    overview_ipc = worker._overview_ipc

    async def observe_overview(*args):
        try:
            return await overview_ipc(*args)
        finally:
            overview_finished.set()

    def at_ssh(host, port, login, credential, pin, command, **options):
        commands.append((host, command))
        if disconnect:
            if len(commands) >= 4:
                four_reads_started.set()
            assert release.wait(30)
        if host == "192.0.2.11" and not disconnect:
            raise ConnectionRefusedError()
        text = "Linux node 6.8.0-generic synthetic kernel output\n" if command == "uname -a" else "unit-zzQvy-zQv-9\n"
        return ssh.Result(0, text.encode(), "", "", "")

    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {}))
        stack.enter_context(patch.dict(worker.UIDS, {"gateway": os.geteuid(), "helper": os.geteuid()}))
        stack.enter_context(patch.object(worker, "TARGET_LOCK_GID", os.getegid()))
        stack.enter_context(patch.object(worker.os, "getgroups", return_value=[os.getegid()]))
        stack.enter_context(patch.object(worker, "STATE", state))
        stack.enter_context(patch.object(worker, "RUNTIME", tmp_path))
        stack.enter_context(patch.object(ipc, "RUNTIME", tmp_path))
        stack.enter_context(patch.object(worker, "TARGET_LOCK_DIR", tmp_path / "target-locks"))
        stack.enter_context(patch.object(worker, "role_environment", return_value=role_directory))
        stack.enter_context(patch.object(proxy, "INVENTORY", role_directory / "inventory.json"))
        stack.enter_context(patch.object(engine, "_lane_directory", return_value=tmp_path / "ssh-lanes"))
        stack.enter_context(patch.object(engine.core_hostkey, "scan", return_value="test-pinned-key"))
        stack.enter_context(patch.object(engine.core_ssh, "run_command", at_ssh))
        stack.enter_context(patch.object(audit, "_RECORDER", Recorder(role_directory / "operations.jsonl", "helper")))
        stack.enter_context(patch.object(server, "Event", return_value=overview_cancelled))
        if disconnect:
            stack.enter_context(patch.object(worker, "_overview_ipc", observe_overview))
        stack.enter_context(patch.dict(sys.modules, {"netops_helper.overview.linux": SimpleNamespace(plan=plan, assemble=assemble)}))
        task = asyncio.create_task(worker.run("helper"))
        serving = None
        try:
            for _ in range(200):
                if (tmp_path / "helper/worker.sock").exists():
                    break
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)
            descriptor = next(tool for tool in (await ipc.rpc("helper", {"action": "list"}))["tools"]
                              if tool["name"] == "network_overview")
            mcp = FastMCP("NetOps")
            mcp.add_tool(gateway.RemoteTool(name="network_overview", parameters=descriptor["inputSchema"], role="helper"))
            audit_store = Audit(tmp_path / "gateway-audit", {"mode": "local"})
            boundary = Boundary(mcp.http_app(path="/mcp", json_response=True, stateless_http=True), audit_store)
            web = uvicorn.Server(uvicorn.Config(boundary, host="127.0.0.1", port=0, http="h11",
                                               ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="critical"))
            serving = asyncio.create_task(web.serve())
            for _ in range(200):
                if web.started:
                    break
                if serving.done():
                    serving.result()
                await asyncio.sleep(0.01)
            url = f"https://localhost:{web.servers[0].sockets[0].getsockname()[1]}/mcp"
            payload = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "network_overview", "arguments": {}}}
            if not disconnect:
                payload["params"]["_meta"] = {"progressToken": "overview-test"}
            async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(cert)), timeout=10) as client:
                if disconnect:
                    pending = asyncio.create_task(client.post(url, headers=HEADERS, json=payload))
                    try:
                        assert await asyncio.to_thread(four_reads_started.wait, 5), commands
                    finally:
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
                    assert await asyncio.to_thread(overview_cancelled.wait, 5)
                    release.set()
                    async with asyncio.timeout(10):
                        await overview_finished.wait()
                        while not (audit_store.current.exists() and "interrupted" in audit_store.current.read_text()):
                            await asyncio.sleep(0.02)
                    assert len(commands) == 4
                    assert all(command == "uname -a" for _, command in commands)
                else:
                    response = await client.post(url, headers=HEADERS, json=payload)
                    assert response.status_code == 200
                    messages = sse_messages(response.text)
                    assert [message["params"]["progress"] for message in messages[:-1]] == [1, 2], response.text
                    result = messages[-1]["result"]
                    assert not result["isError"]
                    structured = result["structuredContent"]
                    assert structured["status"] == "partial"
                    assert [row["reachability"] for row in structured["devices"]] == ["reachable", "unreachable"], structured
                    assert structured["devices"][0]["status"] == "complete"
                    assert json.loads(result["content"][0]["text"]) == structured
                    combined = response.text + audit_store.current.read_text() + (role_directory / "operations.jsonl").read_text()
                    assert "zzQvy" not in combined and "zQv" not in combined
        finally:
            release.set()
            if serving is not None:
                web.should_exit = True
                await asyncio.wait_for(serving, 10)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class OverviewThroughHTTPS(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_uses_the_worker_and_audited_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            await https_case(Path(directory))

    async def test_client_disconnect_stops_new_device_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            await https_case(Path(directory), disconnect=True)
