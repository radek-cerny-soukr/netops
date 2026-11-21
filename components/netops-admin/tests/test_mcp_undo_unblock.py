"""1.0.12 G07 (FP-29, X-02): MCP admin_undo and admin_unblock bound to the approval of their previews.

The device is FakeFortiOSNet: the real anonymised interface and route tables of the lab FortiGate-60F 7.6.8 build3744
(fixtures/fortios_7_6_8_net, task 439) with the generic automation safeguard of FakeFortiOS. The test object is a
temporary VLAN on `internal`, as in the live run (task-evidence/g07). The state unknown is produced the way the live
harness produces it: the connection is lost right after the change was confirmed and the safeguard was removed.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import re

import pytest

fastmcp = pytest.importorskip("fastmcp")

from fake_fortios_net import FakeFortiOSNet  # noqa: E402
from test_execute import SECRET, audit_lines, steps  # noqa: E402
from test_fortios_network import IF, runtime  # noqa: E402

from netops_admin import execute, mcp_server  # noqa: E402
from netops_admin.blocking import unblock_digest  # noqa: E402
from netops_admin.errors import Rejected  # noqa: E402

VLAN = {"vdom": "root", "interface": "internal", "vlanid": 3502, "ip": "198.51.100.145/29", "allowaccess": "ping",
        "alias": "netops 502", "description": "NetOps G07 test"}
KEY = "n502-v"


def call(name, arguments):
    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            result = await client.call_tool(name, arguments, raise_on_error=False)
            if result.structured_content is not None:
                return result.structured_content
            text = result.content[0].text
            try:
                return json.loads(text)
            except ValueError:
                return {"tool_error": text, "is_error": result.is_error}

    return asyncio.run(run())


def schemas():
    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            return {tool.name: tool.input_schema for tool in await client.list_tools()}

    return asyncio.run(run())


def enabled(rt):
    """1.0.12 G07 r2 (decision of the administrator 2026-11-18): admin_undo, admin_unblock_preview and admin_unblock
    are off unless the Admin configuration opts in with mcp_undo. (A build without the option has nothing to enable.)"""
    if any(field.name == "mcp_undo" for field in dataclasses.fields(rt.config)):
        rt.config = dataclasses.replace(rt.config, mcp_undo=True)
    return rt


def serve(tmp_path, monkeypatch, opt_in):
    device = FakeFortiOSNet()
    rt = runtime(tmp_path, device)
    if opt_in:
        enabled(rt)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", rt.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: rt)
    return device, rt


@pytest.fixture
def served(tmp_path, monkeypatch):
    return serve(tmp_path, monkeypatch, True)


@pytest.fixture
def served_default(tmp_path, monkeypatch):
    return serve(tmp_path, monkeypatch, False)


def hashes(answer):
    return set(re.findall(r"[0-9a-f]{64}", json.dumps(answer)))


def after_digest(rt, side="after"):
    """The unblock_sha256 any client can compute from what the block and the operation say, without a preview."""
    blocked = rt.store.blocked("lab")
    record = rt.store.operation(blocked["change_id"])
    return unblock_digest("lab", blocked, record, side, record["plan"]["predicted"][side])


def vlan(op="create", changes=None, request_id="req-g07-0001"):
    return {"device": "lab", "table": IF, "op": op, "key": KEY,
            "changes": dict(VLAN) if changes is None and op == "create" else (changes or {}),
            "reason": "because %s" % SECRET, "user_request": "please, token %s" % SECRET, "request_id": request_id}


def interfaces(device):
    return json.dumps(device.net["system interface"], sort_keys=True)


def removal(lines):
    # the confirmation of FortiOS: the safeguard stitch is deleted (render_safeguard_removal)
    return lines[:1] == ["config system automation-stitch"] and len(lines) > 1 and lines[1].startswith("delete")


def unknown_after_confirmation(device, request_id="req-g07-0002"):
    """The live harness: the management path is lost right after the safeguard was removed."""
    device.unreachable_after_apply = removal
    answer = call("admin_apply", vlan(request_id=request_id))
    device.unreachable_after_apply = None
    device.unreachable = False
    return answer


# --- tool surface -------------------------------------------------------------------------------------------------

def test_the_bound_tools_require_the_hash_of_their_preview():
    found = schemas()
    assert set(found["admin_undo"]["properties"]) == {"change_id", "reason", "expected_plan_sha256"}
    assert set(found["admin_undo"]["required"]) == {"change_id", "reason", "expected_plan_sha256"}
    assert set(found["admin_unblock_preview"]["properties"]) == {"device"}
    assert set(found["admin_unblock"]["properties"]) == {"device", "reason", "expected_unblock_sha256"}
    assert set(found["admin_unblock"]["required"]) == {"device", "reason", "expected_unblock_sha256"}


def test_an_undo_without_its_hash_is_refused_by_the_schema(served):
    device, rt = served
    first = call("admin_apply", vlan())
    blocks = len(device.applied_blocks)
    answer = call("admin_undo", {"change_id": first["change_id"], "reason": "x"})
    assert "tool_error" in answer and answer["is_error"]
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]


# --- FP-29: undo over MCP -----------------------------------------------------------------------------------------

def test_undo_bound_to_the_approved_undo_preview_returns_the_vlan(served, tmp_path):
    device, rt = served
    baseline = interfaces(device)
    first = call("admin_apply", vlan())
    assert first["result"] == "confirmed" and KEY in device.net[IF], first
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return the test VLAN"})
    assert ahead["result"] == "ready" and ahead["op"] == "delete" and ahead["predicted"]["after"] is None
    assert KEY in device.net[IF]
    back = call("admin_undo", {"change_id": first["change_id"], "reason": "return the test VLAN",
                               "expected_plan_sha256": ahead["plan_sha256"]})
    assert back["result"] == "confirmed" and back["request_id"] == "undo-%s" % first["change_id"]
    assert (back["op"], back["key"]) == ("delete", KEY)
    assert KEY not in device.net[IF] and interfaces(device) == baseline
    assert not device.stitches and not device.triggers and not device.actions
    # readback through status: the undo is its own journaled operation
    assert call("admin_status", {"change_id": back["change_id"]})["result"] == "confirmed"
    events = [event for event in audit_lines(tmp_path) if event.get("change_id") == back["change_id"]]
    assert events[0]["event"] == "start" and events[0]["plan_sha256"] == ahead["plan_sha256"]
    assert SECRET not in json.dumps([ahead, back])
    # the same undo again returns its operation; another undo is undo_already_done
    blocks = len(device.applied_blocks)
    again = call("admin_undo", {"change_id": first["change_id"], "reason": "return the test VLAN",
                                "expected_plan_sha256": ahead["plan_sha256"]})
    assert again["change_id"] == back["change_id"] and len(device.applied_blocks) == blocks
    other = call("admin_undo", {"change_id": first["change_id"], "reason": "again",
                                "expected_plan_sha256": ahead["plan_sha256"]})
    assert other["result"] == "rejected" and other["reason_codes"] == ["undo_already_done"]


def test_undo_with_another_plan_hash_is_refused_before_any_write(served):
    device, rt = served
    first = call("admin_apply", vlan())
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    blocks, records = len(device.applied_blocks), len(rt.store.records())
    answer = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                 "expected_plan_sha256": "0" * 64})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["plan_changed"]
    # 502-rv finding 1: the refusal names only the hash that was sent, never the current one
    assert answer["reason_details"][0] == {"code": "plan_changed", "expected": "0" * 64}
    assert hashes(answer) == {"0" * 64}
    malformed = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                    "expected_plan_sha256": "A" * 64})
    assert malformed["result"] == "rejected" and "64 lowercase hexadecimal" in malformed["reasons"][0]
    assert len(device.applied_blocks) == blocks and len(rt.store.records()) == records
    assert KEY in device.net[IF]
    # the preview was presented once (with a wrong hash): its hash is used up, a new preview is needed
    used = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                               "expected_plan_sha256": ahead["plan_sha256"]})
    assert used["result"] == "rejected" and used["reason_codes"] == ["plan_changed"]
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]
    # nothing was journaled under undo-CHANGE_ID: the undo of a new approved preview runs
    again = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    assert again["result"] == "ready"
    back = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                               "expected_plan_sha256": again["plan_sha256"]})
    assert back["result"] == "confirmed" and KEY not in device.net[IF]


def test_undo_of_an_object_changed_after_the_preview_writes_nothing(served):
    device, rt = served
    first = call("admin_apply", vlan(op="create"))
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    device.net[IF][KEY]["attrs"]["alias"] = "changed by hand"
    blocks = len(device.applied_blocks)
    answer = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                 "expected_plan_sha256": ahead["plan_sha256"]})
    assert answer["result"] == "rejected"
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]


def test_undo_of_an_unknown_operation_is_refused(served):
    device, rt = served
    answer = unknown_after_confirmation(device)
    assert answer["result"] == "unknown"
    refused = call("admin_undo", {"change_id": answer["change_id"], "reason": "x", "expected_plan_sha256": "0" * 64})
    assert refused["result"] == "rejected" and "only a confirmed operation" in refused["reasons"][0]


# --- X-02: unblock after unknown over MCP -------------------------------------------------------------------------

def test_unknown_then_unblock_after_reading_the_after_state(served, tmp_path):
    device, rt = served
    baseline = interfaces(device)
    answer = unknown_after_confirmation(device)
    assert answer["result"] == "unknown"
    change = answer["change_id"]
    assert rt.store.blocked("lab")["change_id"] == change
    assert KEY in device.net[IF] and not device.stitches
    accounts = rt.store.baseline("lab")
    refused = call("admin_preview", vlan(op="update", changes={"alias": "next"}, request_id="req-g07-0003"))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["device_blocked"]

    blocks = len(device.applied_blocks)
    ahead = call("admin_unblock_preview", {"device": "lab"})
    assert ahead["result"] == "ready" and ahead["observed"] == "after"
    assert ahead["change_id"] == change and ahead["operation_result"] == "unknown"
    assert ahead["object"]["alias"] == VLAN["alias"] and "not confirmed" in ahead["effect"]
    assert len(device.applied_blocks) == blocks and rt.store.blocked("lab") is not None

    wrong = call("admin_unblock", {"device": "lab", "reason": "investigated", "expected_unblock_sha256": "0" * 64})
    assert wrong["result"] == "rejected" and wrong["reason_codes"] == ["unblock_changed"]
    assert "actual" not in wrong["reason_details"][0] and hashes(wrong) == {"0" * 64}
    assert rt.store.blocked("lab") is not None
    # the presented preview is used up; the person approves a new one
    ahead = call("admin_unblock_preview", {"device": "lab"})
    assert ahead["result"] == "ready" and ahead["observed"] == "after"

    lifted = call("admin_unblock", {"device": "lab", "reason": "investigated %s" % SECRET,
                                    "expected_unblock_sha256": ahead["unblock_sha256"]})
    assert lifted["result"] == "unblocked" and lifted["observed"] == "after"
    assert rt.store.blocked("lab") is None and len(device.applied_blocks) == blocks
    record = rt.store.operation(change)
    assert (record["status"], record["result"]) == ("finished", "unknown")
    assert steps(record)[-1] == "unblocked_observed_after"
    assert rt.store.baseline("lab") == accounts
    event = [e for e in audit_lines(tmp_path) if e["event"] == "administrative"][-1]
    assert event["action"] == "unblock observed after" and event["change_id"] == change
    assert SECRET not in json.dumps([ahead, lifted]) and SECRET not in (tmp_path / "audit" / "audit.jsonl").read_text()
    status = call("admin_status", {"change_id": change})
    assert status["result"] == "unknown" and status["steps"][-1] == "unblocked_observed_after"
    assert call("admin_unblock_preview", {"device": "lab"}) == {"result": "not-blocked", "device": "lab"}

    # the return of the change is a new approved change, not a confirmation of the unknown one
    remove = vlan(op="delete", request_id="req-g07-0004")
    plan = call("admin_preview", remove)
    assert plan["result"] == "ready"
    gone = call("admin_apply", dict(remove, expected_plan_sha256=plan["plan_sha256"]))
    assert gone["result"] == "confirmed" and interfaces(device) == baseline


def test_the_before_state_keeps_the_block_for_a_person(served):
    # 502-rv finding 2: the state before is not lifted over MCP; a person checks it (admin recover, admin unblock)
    device, rt = served
    baseline = interfaces(device)
    answer = unknown_after_confirmation(device)
    del device.net[IF][KEY]  # a person removed the VLAN by hand
    assert interfaces(device) == baseline
    blocks = len(device.applied_blocks)
    refused = call("admin_unblock_preview", {"device": "lab"})
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["unblock_operator_only"]
    assert "state before" in refused["reasons"][0] and "admin recover" in refused["reasons"][0]
    assert "unblock_sha256" not in refused and hashes(refused) == set()
    lifted = call("admin_unblock", {"device": "lab", "reason": "removed by hand",
                                    "expected_unblock_sha256": after_digest(rt, "before")})
    assert lifted["result"] == "rejected" and lifted["reason_codes"] == ["unblock_operator_only"]
    assert rt.store.blocked("lab")["change_id"] == answer["change_id"]
    assert rt.store.operation(answer["change_id"])["result"] == "unknown"
    assert len(device.applied_blocks) == blocks


def test_unblock_with_the_hash_of_another_state_is_refused(served):
    device, rt = served
    unknown_after_confirmation(device)
    ahead = call("admin_unblock_preview", {"device": "lab"})
    assert ahead["observed"] == "after"
    del device.net[IF][KEY]
    answer = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": ahead["unblock_sha256"]})
    # the state before is refused as such (502-rv finding 2), whatever hash is sent
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["unblock_operator_only"]
    assert rt.store.blocked("lab") is not None


def test_a_state_on_neither_side_keeps_the_block(served):
    device, rt = served
    unknown_after_confirmation(device)
    device.net[IF][KEY]["attrs"]["alias"] = "changed by hand"
    for name, arguments in (("admin_unblock_preview", {"device": "lab"}),
                            ("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": "0" * 64})):
        answer = call(name, arguments)
        assert answer["result"] == "rejected" and answer["reason_codes"] == ["unblock_state_unverified"]
        assert "neither the state before nor the state after" in answer["reasons"][0]
    assert rt.store.blocked("lab") is not None


def test_a_check_account_that_disagrees_keeps_the_block(served):
    device, rt = served
    unknown_after_confirmation(device)
    device.check_unreadable = True
    answer = call("admin_unblock_preview", {"device": "lab"})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["unblock_state_unverified"]
    device.check_unreadable = False
    real = device.show
    device.show = lambda table, key: real(table, key).replace("netops 502", "netops 999")
    answer = call("admin_unblock_preview", {"device": "lab"})
    assert answer["result"] == "rejected" and "check account sees" in answer["reasons"][0]
    assert rt.store.blocked("lab") is not None


def test_a_left_safeguard_keeps_the_block_for_admin_recover(served):
    device, rt = served
    # the path is lost right after the change: the safeguard stays installed
    device.unreachable_after_apply = lambda lines: lines[:1] == ["config system interface"]
    answer = call("admin_apply", vlan())
    device.unreachable_after_apply = None
    device.unreachable = False
    assert answer["result"] == "unknown" and device.stitches
    refused = call("admin_unblock_preview", {"device": "lab"})
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["unblock_state_unverified"]
    assert "safeguard is still installed" in refused["reasons"][0] and "admin recover" in refused["reasons"][0]
    assert rt.store.blocked("lab") is not None


def test_other_blocks_stay_the_operator_command(served):
    device, rt = served
    rt.store.block("lab", None, "administrator table")
    answer = call("admin_unblock_preview", {"device": "lab"})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["unblock_operator_only"]
    assert "admin unblock" in answer["reasons"][0]
    answer = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": "0" * 64})
    assert answer["reason_codes"] == ["unblock_operator_only"] and rt.store.blocked("lab") is not None
    # a confirmed operation that blocks (not persisted) is not an unknown state either
    assert execute.unblock(rt, "lab", "operator") is True
    first = call("admin_apply", vlan())
    rt.store.block("lab", first["change_id"], "not persisted")
    answer = call("admin_unblock_preview", {"device": "lab"})
    assert answer["reason_codes"] == ["unblock_operator_only"]


def test_changed_administrator_accounts_stay_the_operator_command(served):
    device, rt = served
    unknown_after_confirmation(device)
    rt.store.save_baseline("lab", "0" * 64)
    answer = call("admin_unblock_preview", {"device": "lab"})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["unblock_operator_only"]
    assert "administrator accounts changed" in answer["reasons"][0]


def test_unblock_input_checks_and_the_server_lock(served):
    device, rt = served
    assert call("admin_unblock_preview", {"device": "lab"}) == {"result": "not-blocked", "device": "lab"}
    assert call("admin_unblock_preview", {"device": "other"})["result"] == "rejected"
    unknown_after_confirmation(device)
    digest = call("admin_unblock_preview", {"device": "lab"})["unblock_sha256"]
    for reason, value in (("", digest), ("x" * 501, digest), ("ok", "A" * 64), ("ok", "a" * 63)):
        answer = call("admin_unblock", {"device": "lab", "reason": reason, "expected_unblock_sha256": value})
        assert answer["result"] == "rejected", (reason, value)
    assert rt.store.blocked("lab") is not None
    assert mcp_server._ACTIVE.acquire(blocking=False)
    try:
        for name, arguments in (("admin_unblock_preview", {"device": "lab"}),
                                ("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": digest}),
                                ("admin_undo", {"change_id": "0" * 32, "reason": "x", "expected_plan_sha256": digest})):
            answer = call(name, arguments)
            assert answer["result"] == "rejected" and "another operation" in answer["reasons"][0]
    finally:
        mcp_server._ACTIVE.release()
    assert rt.store.blocked("lab") is not None


def test_the_unblock_digest_binds_block_operation_and_state():
    record = {"result": "unknown", "reason": "r", "plan": {"plan_sha256": "a" * 64}}
    block = {"device": "lab", "change_id": "c" * 32, "reason": "unknown"}
    base = unblock_digest("lab", block, record, "after", {"alias": "x"})
    assert len(base) == 64
    assert base != unblock_digest("lab", block, record, "before", None)
    assert base != unblock_digest("lab", block, dict(record, result="revert-failed"), "after", {"alias": "x"})
    assert base != unblock_digest("lab", dict(block, reason="other"), record, "after", {"alias": "x"})
    assert base != unblock_digest("lab", block, record, "after", {"alias": "y"})
    with pytest.raises(ValueError):
        unblock_digest("lab", block, record, "neither", None)


# --- 502-rv finding 1: a hash is valid only for the preview this server issued -------------------------------------

def test_an_undo_hash_obtained_without_the_undo_preview_writes_nothing(served):
    device, rt = served
    first = call("admin_apply", vlan())
    # the plan_sha256 of an ordinary preview of the same delete equals the plan of the undo (RESULT-502 open item 5)
    plain = call("admin_preview", vlan(op="delete", request_id="req-g07-0009"))
    assert plain["result"] == "ready"
    blocks, records = len(device.applied_blocks), len(rt.store.records())
    answer = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                 "expected_plan_sha256": plain["plan_sha256"]})
    assert answer["result"] == "rejected" and answer["reason_codes"] == ["plan_changed"]
    assert len(device.applied_blocks) == blocks and len(rt.store.records()) == records and KEY in device.net[IF]


def test_a_hash_from_an_undo_refusal_is_not_usable(served):
    device, rt = served
    first = call("admin_apply", vlan())
    blocks = len(device.applied_blocks)
    refused = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                  "expected_plan_sha256": "f" * 64})
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["plan_changed"]
    leaked = sorted(hashes(refused) - {"f" * 64})
    assert leaked == []
    for digest in [detail.get("actual") for detail in refused["reason_details"] if detail.get("actual")]:
        answer = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                     "expected_plan_sha256": digest})
        assert answer["result"] == "rejected"
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]


def test_an_old_undo_hash_after_a_change_of_state_writes_nothing(served):
    device, rt = served
    first = call("admin_apply", vlan())
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    assert ahead["result"] == "ready"
    # the state changes and comes back: two more approved changes of the same object
    for number, alias in ((5, "changed"), (6, VLAN["alias"])):
        change = vlan(op="update", changes={"alias": alias}, request_id="req-g07-000%d" % number)
        plan = call("admin_preview", change)
        assert call("admin_apply", dict(change, expected_plan_sha256=plan["plan_sha256"]))["result"] == "confirmed"
    blocks = len(device.applied_blocks)
    # the object is in the state of the preview again (same plan), but the journal of the device changed since
    stale = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                "expected_plan_sha256": ahead["plan_sha256"]})
    assert stale["result"] == "rejected" and stale["reason_codes"] == ["plan_changed"]
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]


def test_an_expired_undo_preview_writes_nothing(served, monkeypatch):
    device, rt = served
    first = call("admin_apply", vlan())
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    monkeypatch.setattr(execute, "PREVIEW_TICKET_SECONDS", -1, raising=False)
    blocks = len(device.applied_blocks)
    stale = call("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                "expected_plan_sha256": ahead["plan_sha256"]})
    assert stale["result"] == "rejected" and stale["reason_codes"] == ["plan_changed"]
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]


def test_an_unblock_hash_computed_without_the_preview_lifts_nothing(served):
    device, rt = served
    answer = unknown_after_confirmation(device)
    digest = after_digest(rt)
    lifted = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": digest})
    assert lifted["result"] == "rejected" and lifted["reason_codes"] == ["unblock_changed"]
    # the refusal names only the hash that was sent (expected), no other one
    assert hashes(lifted) == {digest} and "actual" not in lifted["reason_details"][0]
    assert rt.store.blocked("lab")["change_id"] == answer["change_id"]


def test_an_old_unblock_hash_after_a_change_of_state_lifts_nothing(served):
    device, rt = served
    answer = unknown_after_confirmation(device)
    ahead = call("admin_unblock_preview", {"device": "lab"})
    assert ahead["result"] == "ready"
    # the object changes (the preview of that state is refused) and comes back
    device.net[IF][KEY]["attrs"]["alias"] = "changed by hand"
    assert call("admin_unblock_preview", {"device": "lab"})["reason_codes"] == ["unblock_state_unverified"]
    device.net[IF][KEY]["attrs"]["alias"] = VLAN["alias"]
    stale = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": ahead["unblock_sha256"]})
    assert stale["result"] == "rejected" and stale["reason_codes"] == ["unblock_changed"]
    assert rt.store.blocked("lab")["change_id"] == answer["change_id"]


# --- 502-rv finding 2: revert-failed and schema transactions stay the operator command ---------------------------

def test_a_revert_failed_block_stays_the_operator_command(served, monkeypatch):
    from test_execute_notify_and_budget import after_check, blind_safeguard

    device, rt = served
    # the safeguard never fires and the postcheck finds a difference: after its expiry the change is still there
    device.on_apply = blind_safeguard
    after_check(monkeypatch, 1, ["scripted postcheck difference"])
    answer = call("admin_apply", vlan())
    device.on_apply = None
    assert answer["result"] == "revert-failed", answer
    assert KEY in device.net[IF] and not device.stitches and not device.triggers and not device.actions
    blocks = len(device.applied_blocks)
    refused = call("admin_unblock_preview", {"device": "lab"})
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["unblock_operator_only"]
    assert "admin recover" in refused["reasons"][0] and "admin unblock" in refused["reasons"][0]
    lifted = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": after_digest(rt)})
    assert lifted["result"] == "rejected" and lifted["reason_codes"] == ["unblock_operator_only"]
    assert rt.store.blocked("lab")["change_id"] == answer["change_id"]
    assert len(device.applied_blocks) == blocks


def test_a_schema_transaction_block_stays_the_operator_command(tmp_path, monkeypatch):
    from test_schema_execute import op as schema_op, request as schema_request, runtime as schema_bench

    value, fake = schema_bench(tmp_path, monkeypatch)
    done = execute.apply(value, "lab", schema_request([schema_op()]))
    assert done["result"] == "confirmed"
    change = done["change_id"]

    def unknown(record):
        # the device holds the verified after state; only the confirmation was not proven
        record["result"], record["reason"] = "unknown", "confirmation unverified"
        return True

    value.store.update(change, unknown)
    value.store.block("lab", change, "confirmation unverified")
    record = value.store.operation(change)
    blocks = len(fake.applied_blocks)
    digest = unblock_digest("lab", value.store.blocked("lab"), record, "after", record["plan"]["predicted"]["after"])
    for attempt in (lambda: execute.preview_unblock(value, "lab"),
                    lambda: execute.unblock_observed(value, "lab", "x", digest)):
        with pytest.raises(Rejected) as caught:
            attempt()
        assert caught.value.reason_codes == ["unblock_operator_only"]
        assert "schema transaction" in caught.value.reasons[0] and "admin recover" in caught.value.reasons[0]
    assert value.store.blocked("lab")["change_id"] == change and len(fake.applied_blocks) == blocks


# --- decision of the administrator 2026-11-18: the MCP undo and unblock are opt-in ------------------------------

def test_the_bound_tools_are_off_without_the_opt_in(served_default):
    device, rt = served_default
    first = call("admin_apply", vlan())
    ahead = call("admin_undo_preview", {"change_id": first["change_id"], "reason": "return"})
    assert ahead["result"] == "ready"
    blocks = len(device.applied_blocks)
    for name, arguments in (("admin_undo", {"change_id": first["change_id"], "reason": "return",
                                            "expected_plan_sha256": ahead["plan_sha256"]}),
                            ("admin_unblock_preview", {"device": "lab"}),
                            ("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": "0" * 64})):
        answer = call(name, arguments)
        assert answer["result"] == "rejected" and answer["reason_codes"] == ["mcp_undo_disabled"], (name, answer)
        assert "mcp_undo" in answer["reasons"][0] and "admin undo" in answer["reasons"][0]
    assert len(device.applied_blocks) == blocks and KEY in device.net[IF]
    # the operator commands are unchanged
    back = execute.undo(rt, first["change_id"], "operator undo")
    assert back["result"] == "confirmed" and KEY not in device.net[IF]


def test_an_unknown_block_stays_without_the_opt_in(served_default):
    device, rt = served_default
    answer = unknown_after_confirmation(device)
    lifted = call("admin_unblock", {"device": "lab", "reason": "x", "expected_unblock_sha256": after_digest(rt)})
    assert lifted["reason_codes"] == ["mcp_undo_disabled"]
    assert rt.store.blocked("lab")["change_id"] == answer["change_id"]
    assert execute.unblock(rt, "lab", "operator") is True and rt.store.blocked("lab") is None


def test_the_opt_in_is_an_explicit_boolean_of_the_configuration(tmp_path):
    from test_issue5_admin import config_file

    from netops_admin.config import load_config

    assert load_config(config_file(tmp_path)).mcp_undo is False
    assert load_config(config_file(tmp_path, mcp_undo=False)).mcp_undo is False
    assert load_config(config_file(tmp_path, mcp_undo=True)).mcp_undo is True
    for value in ("true", 1, None):
        with pytest.raises(Rejected, match="mcp_undo must be true or false") as caught:
            load_config(config_file(tmp_path, mcp_undo=value))
        assert caught.value.diagnostic == ("config.mcp_undo", "boolean")
