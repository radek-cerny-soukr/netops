"""G00-1 (task 430): an untested firmware warns instead of refusing; the warning is part of plan_sha256.

The golden digests were computed by task-evidence/430/golden_probe.py on the unchanged dev-1.0.12 tree (fef1757),
where the same plans had no firmware_support: a tested plan keeps the plan_sha256 of 1.0.10/1.0.11.
"""
from __future__ import annotations

import json

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS
from test_execute import audit_lines, make_runtime, request

from netops_admin import engine, execute, mcp_server, notify, readiness
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

GOLDEN = {
    ("fortios", None): "72f85c581357136f1e2f9f457cb42555b76d78e06c2edaa3685fee3873858823",
    ("exos", "33.7.1.6"): "ca1f629e4945153c5122ffe462354ab79cfb6db008f9ad8ea266b4d20d4c95ba",
    ("exos", "33.6.1.14"): "4a54b93d07e0e0d6e0c8f59d843d456c8e6838d33c19eae3cb2b1d44fc2efae9",
}


def _plan(platform, snapshot, firmware=None):
    fields = {} if platform == "fortios" else {"table": "vlan", "key": "guest", "changes": {"tag": 3000}}
    return engine.build_plan(platform, snapshot, parse_request(request_bytes(**fields)), firmware=firmware,
                             device="lab")


def _content_1011(plan):
    """The digest of 1.0.10 and 1.0.11, written out independently of engine.plan_digest."""
    return engine._digest({"device": plan["device"], "platform": plan["platform"], "firmware": plan["firmware"],
                           "commands": plan["commands"], "inverse": plan["inverse"],
                           "before": plan["predicted"]["before"], "after": plan["predicted"]["after"]})


@pytest.mark.parametrize(("platform", "firmware"), sorted(GOLDEN, key=str))
def test_tested_plans_keep_the_golden_digest(platform, firmware, fortios_snapshot, exos_snapshot):
    plan = _plan(platform, fortios_snapshot if platform == "fortios" else exos_snapshot, firmware)
    assert plan["firmware_support"]["status"] == "tested"
    assert plan["firmware_support"]["message"] is None
    assert plan["plan_sha256"] == GOLDEN[(platform, firmware)] == _content_1011(plan)


@pytest.mark.parametrize("firmware", ["33.7.2", "33.6.1", "32.6.2.68"])
def test_untested_plan_binds_the_warning_in_its_digest(firmware, exos_snapshot):
    plan = _plan("exos", exos_snapshot, firmware)
    support = plan["firmware_support"]
    assert support["status"] == "untested" and support["device_version"] == firmware
    assert support["tested_versions"] == ["33.7.1.6", "33.6.1.14"]
    assert support["message"].startswith("ExtremeXOS %s is not among the versions" % firmware)
    content = _content_1011(plan)
    assert plan["plan_sha256"] != content
    unbound = json.loads(json.dumps(plan))
    unbound["firmware_support"] = dict(support, status="tested", message=None)
    assert engine.plan_digest(unbound) == content
    assert plan["plan_sha256"] == engine.plan_digest(plan)
    assert engine._read_plan(plan) is plan


def test_untested_plan_without_its_warning_is_not_accepted(exos_snapshot):
    plan = _plan("exos", exos_snapshot, "33.7.2")
    stripped = {name: value for name, value in plan.items() if name != "firmware_support"}
    with pytest.raises(Rejected) as caught:
        engine._read_plan(stripped)
    assert caught.value.reasons == ["plan content does not match its plan_sha256"]
    forged = dict(plan, firmware_support=dict(plan["firmware_support"], status="tested", message=None))
    with pytest.raises(Rejected):
        engine._read_plan(forged)
    malformed = dict(plan, firmware_support={"status": "untested"})
    with pytest.raises(Rejected) as caught:
        engine._read_plan(malformed)
    assert caught.value.reasons == ["plan holds a value of the wrong type"]


def test_a_journaled_plan_of_1011_without_firmware_support_stays_readable(exos_snapshot):
    plan = _plan("exos", exos_snapshot, "33.7.1.6")
    old = {name: value for name, value in plan.items() if name != "firmware_support"}
    assert engine._read_plan(old) is old
    assert engine.verify(old, exos_snapshot, expect="before")["result"] == "match"


def test_preview_and_apply_on_a_tested_build_report_tested(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", request())
    assert preview["firmware_support"]["status"] == "tested"
    record = execute.apply(runtime, "lab", request(), expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed"
    assert mcp_server.summary(record)["firmware_support"]["status"] == "tested"
    start = next(event for event in audit_lines(tmp_path) if event["event"] == "start")
    assert start["firmware_tested"] is True
    title, body = notify.message(record)
    assert "warning" not in body


def test_untested_build_preview_hash_approves_the_apply(tmp_path):
    device = type("Untested", (FakeFortiOS,), {"firmware": ("8.0.0", "0168")})()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", request())
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested"
    tested_preview = execute.preview(make_runtime(tmp_path / "tested", FakeFortiOS()), "lab", request())
    assert tested_preview["commands"] == preview["commands"]
    assert tested_preview["plan_sha256"] != preview["plan_sha256"]
    record = execute.apply(runtime, "lab", request(), expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    summary = mcp_server.summary(record)
    assert summary["firmware_support"] == preview["firmware_support"]
    status = runtime.store.operation(record["change_id"])
    assert mcp_server.summary(status)["firmware_support"]["status"] == "untested"
    title, body = notify.message(record)
    assert "warning: firmware 8.0.0 build0168 is not among the tested versions" in body
    assert "check the result" in body


def test_doctor_lists_untested_operations_and_the_t1_limit():
    operations = readiness._operations("fortios", "8.0.2 build0251")
    assert operations["firewall address"] == "create update delete"
    assert operations["firewall addrgrp"] == "create update delete (untested on 8.0.2 build0251)"
    # 1.0.12 G20: the webhook safeguard has a REST inverse for DHCP reservations (the T1 limit applies to no table now)
    assert operations["system dhcp server/reserved-address"] == "create update delete (untested on 8.0.2 build0251)"
    assert operations["system dns-database/dns-entry"] == "create update delete (untested on 8.0.2 build0251)"
    support = readiness._firmware_support("fortios", "8.0.2 build0251")
    assert support["firewall address"]["status"] == "tested"
    assert support["firewall addrgrp"]["status"] == "untested"
    assert support["system dhcp server/reserved-address"]["status"] == "untested"
    older = readiness._operations("fortios", "7.6.9 build4000")
    assert older["system dhcp server/reserved-address"] == "create update delete (untested on 7.6.9 build4000)"


def test_doctor_report_carries_firmware_support(tmp_path):
    report = readiness.doctor(make_runtime(tmp_path, FakeFortiOS()), "lab")
    assert report["firmware"] == "8.0.0 build0167"
    assert report["firmware_support"]["firewall address"]["status"] == "tested"
    assert set(report["firmware_support"]) == set(report["operations"])


def test_tool_descriptions_promise_a_warning_not_a_refusal():
    import asyncio

    fastmcp = pytest.importorskip("fastmcp")

    async def run():
        async with fastmcp.Client(mcp_server.mcp) as client:
            return {tool.name: tool for tool in await client.list_tools()}

    tools = asyncio.run(run())
    for name in ("admin_preview", "admin_apply", "admin_status", "admin_doctor"):
        assert "firmware_support" in tools[name].description, name
        assert "untested" in tools[name].description, name
    assert "Unmeasured operations are refused" not in tools["admin_schema_apply"].description
    assert "firmware_support" in mcp_server.INSTRUCTIONS
