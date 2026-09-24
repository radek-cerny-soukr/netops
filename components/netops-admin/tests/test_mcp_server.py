from __future__ import annotations

import asyncio
import json

import pytest

fastmcp = pytest.importorskip("fastmcp")

from fake_fortios import FakeFortiOS  # noqa: E402
from test_execute import SECRET, make_runtime  # noqa: E402

from netops_admin import mcp_server  # noqa: E402


def call(name, arguments):
    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            result = await client.call_tool(name, arguments, raise_on_error=False)
            return result.structured_content or json.loads(result.content[0].text)

    return asyncio.run(run())


def listed():
    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            return sorted(tool.name for tool in await client.list_tools())

    return asyncio.run(run())


@pytest.fixture
def served(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: runtime)
    return device, runtime


def arguments(**fields):
    body = {"device": "lab", "table": "firewall address", "op": "create", "key": "new-host",
            "changes": {"subnet": "192.0.2.30/32", "comment": "new host"},
            "reason": "because %s" % SECRET, "user_request": "please, token %s" % SECRET,
            "request_id": "req-mcp-0001"}
    body.update(fields)
    return body


def test_only_the_declared_tools_exist():
    assert listed() == sorted(mcp_server.TOOL_NAMES)


def test_apply_and_status_carry_no_free_text(served, tmp_path):
    device, runtime = served
    answer = call("admin_apply", arguments())
    assert answer["result"] == "confirmed" and answer["status"] == "finished"
    assert "new-host" in device.addresses
    assert SECRET not in json.dumps(answer)
    status = call("admin_status", {"request_id": "req-mcp-0001"})
    assert status["change_id"] == answer["change_id"] and SECRET not in json.dumps(status)
    assert SECRET not in (tmp_path / "audit" / "audit.jsonl").read_text()


def test_repeated_request_returns_the_same_operation(served):
    device, runtime = served
    first = call("admin_apply", arguments())
    blocks = len(device.applied_blocks)
    again = call("admin_apply", arguments())
    assert again["change_id"] == first["change_id"] and len(device.applied_blocks) == blocks


def test_rejection_is_an_answer_without_free_text(served):
    device, runtime = served
    answer = call("admin_apply", arguments(key="all", reason="secret %s" % SECRET))
    assert answer["result"] == "rejected" and answer["notification"] == "not-required"
    assert SECRET not in json.dumps(answer) and device.applied_blocks == []


def test_unknown_or_malformed_operation_is_not_read(served, tmp_path):
    outside = {"change_id": "x", "request_id": "x", "status": "finished", "result": "confirmed", "steps": []}
    (tmp_path / "state" / "outside.json").write_text(json.dumps(outside))
    assert call("admin_status", {"change_id": "../outside"})["result"] == "unknown-operation"
    assert call("admin_status", {"request_id": "../outside"})["result"] == "unknown-operation"
    assert call("admin_status", {"change_id": "0" * 32})["result"] == "unknown-operation"


def test_second_operation_is_refused_while_one_runs(served):
    assert mcp_server._ACTIVE.acquire(blocking=False)
    try:
        answer = call("admin_apply", arguments())
    finally:
        mcp_server._ACTIVE.release()
    assert answer["result"] == "rejected" and "another operation" in answer["reasons"][0]


def test_configuration_comes_from_the_environment(tmp_path):
    with pytest.raises(mcp_server.ConfigurationError):
        mcp_server.configure({})
    with pytest.raises(mcp_server.ConfigurationError):
        mcp_server.configure({mcp_server.CONFIG_VARIABLE: str(tmp_path / "missing.json")})
