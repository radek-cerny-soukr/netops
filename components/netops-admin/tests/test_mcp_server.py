from __future__ import annotations

import asyncio
import json

import pytest

fastmcp = pytest.importorskip("fastmcp")

from fake_fortios import FakeFortiOS  # noqa: E402
from test_execute import SECRET, make_runtime  # noqa: E402

import netops_admin  # noqa: E402
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


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_the_handshake_announces_the_package_name_and_version(mode):
    async def run():
        async with fastmcp.Client(mcp_server.mcp, mode=mode) as client:
            return client.server_info, client.initialize_result

    info, initialized = asyncio.run(run())
    assert (info.name, info.version) == ("netops-admin", netops_admin.__version__)
    assert info.version != fastmcp.__version__
    if mode == "legacy":
        assert initialized.server_info == info


@pytest.fixture
def schema_served(tmp_path,monkeypatch):
    from test_schema_execute import runtime as schema_fixture
    context,device=schema_fixture(tmp_path,monkeypatch)
    monkeypatch.setattr(mcp_server,"_CONFIGURATION",context.config)
    monkeypatch.setattr(mcp_server,"build_runtime",lambda config:context)
    return device,context


def schema_arguments(operations=None):
    from test_schema_plan import op
    return {"device":"lab","operations":operations if operations is not None else [op()],
            "reason":"because "+SECRET,"user_request":"operator "+SECRET,
            "request_id":"req-schema-mcp-0001"}


def test_schema_mcp_batch_and_preview_share_the_real_runtime(schema_served):
    from test_schema_plan import op
    device,context=schema_served
    arguments=schema_arguments([op(changes={"comment":"first"}),op(changes={"comment":"final"})])
    preview=call("admin_schema_preview",arguments)
    assert preview["result"]=="ready"
    assert not list(context.store.records())
    answer=call("admin_schema_apply",arguments)
    assert answer["result"]=="confirmed" and answer["budget_changes"]==2
    assert SECRET not in json.dumps(answer)
    again=call("admin_schema_apply",arguments)
    assert again["change_id"]==answer["change_id"]
    assert len(list(context.store.records()))==1


@pytest.mark.parametrize("operations",[[],[{"path":None}],["set hostname bad"]])
def test_schema_mcp_malformed_operations_are_refused_without_write(schema_served,operations):
    _,context=schema_served
    answer=call("admin_schema_apply",schema_arguments(operations))
    assert answer["result"]=="rejected"
    assert not list(context.store.records())


def test_schema_mcp_shares_the_server_operation_lock(schema_served):
    assert mcp_server._ACTIVE.acquire(blocking=False)
    try:
        answer=call("admin_schema_apply",schema_arguments())
    finally:
        mcp_server._ACTIVE.release()
    assert answer["result"]=="rejected" and "another operation" in answer["reasons"][0]


# 109-15 and 109-16 over MCP

def test_ten_tools_include_the_undo_preview_and_the_bound_undo_and_unblock():
    # 1.0.12 G07: admin_undo and admin_unblock exist, each bound to the hash of its approved preview
    assert len(mcp_server.TOOL_NAMES) == 10
    assert {"admin_undo_preview", "admin_undo", "admin_unblock_preview", "admin_unblock"} <= set(mcp_server.TOOL_NAMES)
    assert "admin_undo_preview" in mcp_server.INSTRUCTIONS
    assert "approved" in mcp_server.INSTRUCTIONS and "a person runs" in mcp_server.INSTRUCTIONS
    assert "never confirms the operation" in mcp_server.INSTRUCTIONS


def test_apply_bound_to_the_preview_is_confirmed(served):
    device, runtime = served
    ahead = call("admin_preview", arguments())
    assert ahead["result"] == "ready"
    answer = call("admin_apply", dict(arguments(), expected_plan_sha256=ahead["plan_sha256"]))
    assert answer["result"] == "confirmed" and "new-host" in device.addresses


def test_apply_with_a_changed_plan_is_rejected_with_plan_changed(served):
    device, runtime = served
    body = arguments(op="update", key="spare-host", changes={"comment": "approved"}, request_id="req-mcp-bound-2")
    ahead = call("admin_preview", body)
    device.addresses["spare-host"]["comment"] = "someone else"
    blocks = len(device.applied_blocks)
    answer = call("admin_apply", dict(body, expected_plan_sha256=ahead["plan_sha256"]))
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["plan_changed"]
    assert answer["reason_details"][0]["expected"] == ahead["plan_sha256"]
    assert len(device.applied_blocks) == blocks and list(runtime.store.records()) == []
    assert SECRET not in json.dumps(answer)


@pytest.mark.parametrize("value", ["A" * 64, "a" * 10, "z" * 64])
def test_apply_with_a_malformed_plan_hash_is_rejected(served, value):
    device, runtime = served
    answer = call("admin_apply", dict(arguments(), expected_plan_sha256=value))
    assert answer["result"] == "rejected" and "64 lowercase hexadecimal" in answer["reasons"][0]
    assert device.applied_blocks == [] and "new-host" not in device.addresses


def test_apply_without_a_plan_hash_and_repeat_with_any_hash(served):
    device, runtime = served
    first = call("admin_apply", arguments())
    assert first["result"] == "confirmed"
    blocks = len(device.applied_blocks)
    again = call("admin_apply", dict(arguments(), expected_plan_sha256="0" * 64))
    assert again["change_id"] == first["change_id"] and len(device.applied_blocks) == blocks


def test_schema_apply_has_no_plan_binding():
    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            return {tool.name: tool.input_schema for tool in await client.list_tools()}

    schemas = asyncio.run(run())
    assert "expected_plan_sha256" in schemas["admin_apply"]["properties"]
    assert "expected_plan_sha256" not in schemas["admin_apply"].get("required", [])
    assert "expected_plan_sha256" not in schemas["admin_schema_apply"]["properties"]
    assert set(schemas["admin_undo_preview"]["properties"]) == {"change_id", "reason"}


def test_undo_preview_is_read_only_and_names_the_undo(served, tmp_path):
    device, runtime = served
    first = call("admin_apply", arguments(op="update", key="spare-host", changes={"comment": "mine"}))
    assert first["result"] == "confirmed"
    blocks, records = len(device.applied_blocks), len(list(runtime.store.records()))
    audit = (tmp_path / "audit" / "audit.jsonl").read_text()
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "because %s" % SECRET})
    assert ahead["result"] == "ready" and ahead["undo_of"] == first["change_id"]
    assert ahead["request_id"] == "undo-%s" % first["change_id"]
    assert len(device.applied_blocks) == blocks and len(list(runtime.store.records())) == records
    assert (tmp_path / "audit" / "audit.jsonl").read_text() == audit
    assert device.addresses["spare-host"]["comment"] == "mine"
    assert SECRET not in json.dumps(ahead)


def test_undo_preview_of_an_unknown_or_undone_change_is_rejected(served):
    from netops_admin import execute

    device, runtime = served
    assert call("admin_undo_preview", {"change_id": "0" * 32, "reason": "x"})["result"] == "rejected"
    first = call("admin_apply", arguments(op="update", key="spare-host", changes={"comment": "mine"}))
    assert execute.undo(runtime, first["change_id"], "investigated")["result"] == "confirmed"
    answer = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "x"})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["undo_already_done"]


def test_undo_preview_shares_the_server_operation_lock(served):
    assert mcp_server._ACTIVE.acquire(blocking=False)
    try:
        answer = call("admin_undo_preview", {"change_id": "0" * 32, "reason": "x"})
    finally:
        mcp_server._ACTIVE.release()
    assert answer["result"] == "rejected" and "another operation" in answer["reasons"][0]
