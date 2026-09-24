from __future__ import annotations

from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime

from netops_admin import execute, readiness


def journal_is_empty(runtime, tmp_path):
    audit = tmp_path / "audit" / "audit.jsonl"
    return runtime.store.records() == [] and (not audit.exists() or audit.read_text() == "")


def statuses(report):
    return {item["check"]: item["status"] for item in report["checks"]}


def test_preview_returns_the_plan_and_changes_nothing(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "ready" and result["reasons"] == []
    assert result["predicted"]["before"] is None
    assert result["predicted"]["after"]["subnet"] == "192.0.2.30 255.255.255.255"
    assert result["commands"] and result["inverse_commands"] > 0
    assert device.applied_blocks == [] and "new-host" not in device.addresses
    assert journal_is_empty(runtime, tmp_path)
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"


def test_preview_and_apply_share_the_plan(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    previewed = execute.preview(runtime, "lab", request())
    applied = execute.apply(runtime, "lab", request())
    assert applied["plan"]["plan_sha256"] == previewed["plan_sha256"]
    assert applied["plan"]["commands"] == previewed["commands"]


def test_preview_reports_a_foreign_administrator_without_blocking(tmp_path):
    device = FakeFortiOS()
    device.admins.append("persisted-account")
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected"
    assert "other administrators than the configured" in result["reasons"][0]
    assert runtime.store.blocked("lab") is None
    assert runtime.store.rejections_since(0) == 0
    assert device.applied_blocks == []


def test_preview_without_enrollment_still_shows_the_plan(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.store.clear_enrollment("lab")
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected"
    assert any("enroll self-test is required" in reason for reason in result["reasons"])
    assert result["commands"]


def test_preview_of_a_started_request_names_its_operation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    blocks = len(device.applied_blocks)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "known-request" and result["change_id"] == record["change_id"]
    assert len(device.applied_blocks) == blocks


def test_preview_refuses_a_leftover_safeguard_like_apply(tmp_path):
    device = FakeFortiOS()
    device.stitches["netops-sg-deadbeef0000-s"] = {"trigger": None, "action": None}
    result = execute.preview(make_runtime(tmp_path, device), "lab", request())
    assert result["result"] == "rejected" and "still installed" in result["reasons"][0]


def test_doctor_reports_every_check_without_touching_the_device(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    report = readiness.doctor(runtime, "lab")
    assert report["firmware"] == "8.0.0 build0167"
    found = statuses(report)
    for name in ("credentials", "write account and host key", "firmware", "administrator accounts",
                 "check account", "leftover safeguards", "device prechecks", "audit policy", "enrollment",
                 "journal and audit log writable", "device state", "budgets"):
        assert found[name] == readiness.OK, name
    assert found["notification"] == readiness.MISSING
    assert found["audit export"] == readiness.MISSING
    assert report["ready"] is False
    assert report["operations"]["firewall address"] == "create update delete"
    assert report["operations"]["firewall addrgrp"] == "not measured on this firmware"
    assert device.applied_blocks == []
    assert journal_is_empty(runtime, tmp_path)


def test_doctor_names_what_refuses(tmp_path):
    device = FakeFortiOS()
    device.stitches["netops-sg-deadbeef0000-s"] = {"trigger": None, "action": None}
    device.check_unreadable = True
    runtime = make_runtime(tmp_path, device)
    runtime.store.clear_enrollment("lab")
    runtime.store.block("lab", None, "foreign change")
    found = statuses(readiness.doctor(runtime, "lab"))
    assert found["leftover safeguards"] == readiness.REFUSED
    assert found["check account"] == readiness.REFUSED
    assert found["device state"] == readiness.REFUSED
    assert found["enrollment"] == readiness.MISSING
    assert found["administrator accounts"] == readiness.OK


def test_doctor_skips_what_it_cannot_reach(tmp_path):
    device = FakeFortiOS()
    device.unreadable = True
    report = readiness.doctor(make_runtime(tmp_path, device), "lab")
    found = statuses(report)
    assert found["write account and host key"] == readiness.REFUSED
    assert found["enrollment"] == readiness.SKIPPED and found["check account"] == readiness.SKIPPED
    assert report["operations"] == {} and report["firmware"] is None


def test_doctor_does_not_block_on_changed_accounts(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    device.admins.append("persisted-account")
    found = statuses(readiness.doctor(runtime, "lab"))
    assert found["administrator accounts"] == readiness.REFUSED
    assert found["enrollment"] == readiness.SKIPPED
    assert runtime.store.blocked("lab") is None


def test_doctor_on_exos_reads_the_default_vlan_with_the_check_account(tmp_path):
    device = FakeExos()
    runtime = make_exos_runtime(tmp_path, device)
    report = readiness.doctor(runtime, "sw")
    found = statuses(report)
    assert found["check account"] == readiness.OK
    assert found["device prechecks"] == readiness.OK
    assert found["enrollment"] == readiness.OK
    assert device.applied_blocks == [] and device.saves == 0
    device.unsaved = True
    assert statuses(readiness.doctor(runtime, "sw"))["device prechecks"] == readiness.REFUSED
