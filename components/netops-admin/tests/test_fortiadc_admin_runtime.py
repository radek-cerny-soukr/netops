"""FortiADC pool members through the common Admin engine: preview with plan_sha256, apply from a fresh plan,
readback by the check account, audit and journal through Runtime, undo, enroll, recover and the compensating return
of a platform without an on-device timer (verification)."""
from __future__ import annotations

import copy
import json

import pytest
from conftest import request_bytes
from fake_fortiadc_admin import FakeADC, measured

from netops_admin import (cli, engine, enrollment, exec_fortiadc, execute, fortiadc_plan, readiness)
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile, firmware_support, load_profiles
from netops_admin.request import parse_request
from approved_apply import approved_apply, preview_hash

SECRET = "SECRET-MARKER-0306"
TABLE = "load-balance pool/pool_member"


def make_runtime(tmp_path, device, notifier=None, certified=True, **fields):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"adc": Device(
            name="adc", platform="fortiadc", address="192.0.2.40", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=fields.pop("firmware", None), safeguard_seconds=180,
            confirm_margin_seconds=45, protected=fields.pop("protected", {}), **fields)},
    )
    runtime = execute.Runtime(config, lambda _device: device, notifier=notifier, sleep=lambda _seconds: None,
                              require_export=False)
    if certified:
        from enrollment_helpers import certify
        certify(runtime, device, "adc")
    return runtime


def request(**fields):
    fields.setdefault("table", TABLE)
    fields.setdefault("op", "update")
    fields.setdefault("key", "pool-a:1")
    fields.setdefault("changes", {"status": "disable"})
    fields.setdefault("user_request", "take member 1 out, token %s" % SECRET)
    fields.setdefault("reason", "maintenance of rs-1")
    fields.setdefault("request_id", "req-adc-0001")
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


def audit_lines(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]


class Stub:
    """Returns the measured answers of FortiADC-KVM 7.6.7 build0676 (fortiadc-kvm, verification, anonymized)."""

    ANSWERS = {
        "get system status": "get_system_status.txt",
        "show load-balance pool": "show_load-balance_pool.txt",
        "show load-balance virtual-server": "show_load-balance_virtual-server.txt",
        "show load-balance real-server": "show_load-balance_real-server.txt",
        "show system admin": "show_system_admin.txt",
    }

    def query(self, command):
        return measured(self.ANSWERS[command])


# --- snapshot and plan from the measured device answers ---------------------------------------------------------

def test_measured_answers_compose_a_snapshot_with_pager_and_repeated_prompts_removed():
    text = exec_fortiadc.snapshot(Stub())
    assert "--More--" not in text and "FortiADC-KVM #" not in text
    snapshot = fortiadc_plan.load(text, None)
    assert snapshot.firmware == "7.6.7 build0676"
    assert snapshot.pools == ["POOL_APP", "LAB_POOL_SMTP", "LAB_POOL_DNS", "netops-tlsca-pool"]
    members = snapshot.entries(TABLE)
    # the cookie rsN of member N is the default the device gives a member without a cookie
    assert members["LAB_POOL_SMTP:2"].attributes == {"pool-member-service-port": "25", "real-server": "RS_B"}
    assert members["POOL_APP:1"].attributes == {"real-server": "RS_A"}
    assert sorted(snapshot.virtual_servers()) == ["LAB_VS_DNS", "LAB_VS_HTTPS", "LAB_VS_SMTP", "VS_APP_HTTP",
                                                  "netops-tlsca-vs"]
    assert snapshot.virtual_servers()["LAB_VS_SMTP"]["load-balance-pool"] == "LAB_POOL_SMTP"
    assert sorted(snapshot.admins()) == ["admin", "netops-read"]
    assert sorted(snapshot.real_servers()) == ["RS_A", "RS_B", "netops-tlsca-rs"]


def test_measured_snapshot_plans_a_status_change_with_its_inverse():
    text = exec_fortiadc.snapshot(Stub()).encode("utf-8")
    plan = engine.build_plan("fortiadc", text, request(key="LAB_POOL_SMTP:2"))
    assert plan["predicted"]["before"] == {"pool-member-service-port": "25", "real-server": "RS_B"}
    assert plan["predicted"]["after"]["status"] == "disable"
    assert plan["commands"] == ["config load-balance pool", 'edit "LAB_POOL_SMTP"', "config pool_member", "edit 2",
                                "set status disable", "next", "end", "next", "end"]
    assert plan["inverse"][4] == "set status enable"
    assert engine.verify(plan, text, expect="before")["result"] == "match"


def test_measured_snapshot_plans_an_add_and_a_remove():
    text = exec_fortiadc.snapshot(Stub()).encode("utf-8")
    add = engine.build_plan("fortiadc", text, request(op="create", key="LAB_POOL_SMTP:3", changes={
        "real-server": "RS_A", "pool-member-service-port": 2525, "status": "disable"}))
    assert add["commands"][4:7] == ['set real-server "RS_A"', "set pool_member_service_port 2525",
                                    "set status disable"]
    assert add["inverse"] == ["config load-balance pool", 'edit "LAB_POOL_SMTP"', "config pool_member",
                              "delete 3", "end", "next", "end"]
    with pytest.raises(Rejected) as enabled:
        engine.build_plan("fortiadc", text, request(key="LAB_POOL_SMTP:2", op="delete", changes={}))
    assert "status disable or maintain" in enabled.value.reasons[0]


def test_custom_cookie_is_kept_and_restored_by_the_inverse():
    text = exec_fortiadc.snapshot(Stub()).replace("set pool_member_cookie rs2", "set pool_member_cookie web-b")
    plan = engine.build_plan("fortiadc", text.encode("utf-8"), request(key="LAB_POOL_SMTP:2"))
    assert plan["predicted"]["before"]["pool-member-cookie"] == "web-b"


def test_listing_without_a_configuration_block_is_refused():
    with pytest.raises(Rejected):
        fortiadc_plan.listing("Command fail. Return code is -284 (CLI parsing error.)\n", "show load-balance pool")


def test_snapshot_without_the_firmware_line_or_a_section_is_refused():
    text = exec_fortiadc.snapshot(Stub())
    with pytest.raises(Rejected):
        fortiadc_plan.load(text.split("\n", 1)[1], None)
    with pytest.raises(Rejected):
        fortiadc_plan.load(text.replace("config system admin", "config system adminx"), None)
    with pytest.raises(Rejected) as other:
        fortiadc_plan.load(text, "7.6.6 build0600")
    assert "7.6.7 build0676" in other.value.reasons[0]


def test_profile_lists_the_tested_build_and_reports_others_untested():
    profile = load_profiles()[("fortiadc", TABLE)]
    assert profile.versions == ("7.6.7 build0676",) and profile.exact_versions
    other = find_profile("fortiadc", TABLE, "7.6.8 build0700")
    assert other.versions == profile.versions
    assert firmware_support(other, "7.6.8 build0700")["status"] == "untested"
    assert firmware_support(other, "7.6.7 build0676")["status"] == "tested"


def test_offline_plan_command_accepts_fortiadc(tmp_path, capsys):
    snapshot = tmp_path / "snapshot.txt"
    snapshot.write_text(exec_fortiadc.snapshot(Stub()))
    body = tmp_path / "request.json"
    body.write_bytes(request_bytes(table=TABLE, op="update", key="LAB_POOL_SMTP:1", changes={"status": "maintain"}))
    assert cli.main(["plan", "--platform", "fortiadc", "--snapshot", str(snapshot), "--request", str(body)]) == 0
    assert json.loads(capsys.readouterr().out)["predicted"]["after"]["status"] == "maintain"


# --- preview and apply through Runtime ------------------------------------------------------------------------------

def test_preview_changes_nothing_and_names_the_return_mechanism(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "adc", request())
    assert result["result"] == "ready", result
    assert result["platform"] == "fortiadc" and result["firmware"] == "7.6.7 build0676"
    assert result["return_mechanism"] == exec_fortiadc.RETURN_MECHANISM
    assert result["audit_unevaluated"] == {"fortiadc.auditor": exec_fortiadc.AUDIT_NOT_RUN[2]}
    assert any("healthy enabled member" in check for check in result["prechecks"])
    assert len(result["plan_sha256"]) == 64
    assert device.applied_blocks == [] and runtime.store.records() == []
    assert any(command.startswith("diagnose server-load-balance vs_stat") for command in device.queries)


def test_apply_with_the_previewed_hash_is_confirmed_journaled_and_audited(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    approved = execute.preview(runtime, "adc", request())["plan_sha256"]
    record = execute.apply(runtime, "adc", request(), expected_plan_sha256=approved)
    assert record["result"] == "confirmed", steps(record)
    assert device.pools["pool-a"][1]["status"] == "disable"
    assert steps(record)[:3] == ["foreign_sessions_unreadable", "compensation_armed", "change_start"]
    assert steps(record)[-3:] == ["audit_not_run", "check_identity_passed", "confirm_start"]
    assert record["safeguard"]["fire_at"] == "none" and record["safeguard"]["name"].startswith("compensation-")
    assert device.check_queries[-1] == "show load-balance pool pool-a"
    assert runtime.store.operation(record["change_id"])["result"] == "confirmed"
    assert runtime.store.request("req-adc-0001")["change_id"] == record["change_id"]
    events = audit_lines(tmp_path)
    assert [event["event"] for event in events][0] == "start" and events[-1]["result"] == "confirmed"
    assert events[0]["platform"] == "fortiadc" and events[0]["plan_sha256"] == approved
    assert SECRET not in (tmp_path / "audit" / "audit.jsonl").read_text()
    assert "dGVzdC1vbmx5" not in (tmp_path / "audit" / "audit.jsonl").read_text()
    again = execute.apply(runtime, "adc", request(), expected_plan_sha256=approved)
    assert again["change_id"] == record["change_id"] and len(device.applied_blocks) == 1


def test_changed_plan_is_refused_before_any_write(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    approved = execute.preview(runtime, "adc", request())["plan_sha256"]
    device.pools["pool-a"][1]["status"] = "maintain"
    with pytest.raises(Rejected) as changed:
        execute.apply(runtime, "adc", request(), expected_plan_sha256=approved)
    assert changed.value.reason_codes == ["plan_changed"] and device.applied_blocks == []


def test_undo_preview_and_undo_return_the_status(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "adc", request())
    preview = execute.preview_undo(runtime, record["change_id"], "back in service")
    assert preview["result"] == "ready" and preview["commands"][4] == "set status enable"
    undone = execute.undo(runtime, record["change_id"], "back in service")
    assert undone["result"] == "confirmed" and device.pools["pool-a"][1]["status"] == "enable"
    with pytest.raises(Rejected) as twice:
        execute.undo(runtime, record["change_id"], "again")
    assert twice.value.reason_codes == ["undo_already_done"]


def test_add_disabled_member_and_remove_it_return_the_pool(tmp_path):
    device = FakeADC()
    before = copy.deepcopy(device.pools)
    runtime = make_runtime(tmp_path, device)
    add = approved_apply(runtime, "adc", request(op="create", key="pool-a:9", request_id="req-adc-add-1", changes={
        "real-server": "rs-new", "pool-member-service-port": 8080, "status": "disable"}))
    assert add["result"] == "confirmed", steps(add)
    assert device.pools["pool-a"][9] == {"status": "disable", "real-server": "rs-new",
                                         "pool_member_service_port": "8080", "pool_member_cookie": "rs9"}
    remove = approved_apply(runtime, "adc", request(op="delete", key="pool-a:9", changes={},
                                                   request_id="req-adc-remove-1"))
    assert remove["result"] == "confirmed", steps(remove)
    assert device.pools == before


def test_undo_of_an_add_removes_the_member(tmp_path):
    device = FakeADC()
    before = copy.deepcopy(device.pools)
    runtime = make_runtime(tmp_path, device)
    add = approved_apply(runtime, "adc", request(op="create", key="pool-a:9", request_id="req-adc-add-2", changes={
        "real-server": "rs-new", "pool-member-service-port": 8080, "status": "disable"}))
    assert execute.undo(runtime, add["change_id"], "not needed")["result"] == "confirmed"
    assert device.pools == before


def test_undo_of_a_remove_recreates_the_member_with_its_settings(tmp_path):
    device = FakeADC()
    before = copy.deepcopy(device.pools)
    runtime = make_runtime(tmp_path, device)
    removed = approved_apply(runtime, "adc", request(op="delete", key="pool-a:2", changes={},
                                                    request_id="req-adc-remove-2"))
    assert removed["result"] == "confirmed" and 2 not in device.pools["pool-a"]
    assert execute.undo(runtime, removed["change_id"], "still needed")["result"] == "confirmed"
    recreated = dict(device.pools["pool-a"][2])
    assert recreated.pop("pool_member_cookie") == "rs2"  # the default the device gives a member without a cookie
    assert recreated == before["pool-a"][2]


@pytest.mark.parametrize(("fields", "phrase"), [
    ({"op": "create", "key": "pool-a:9", "changes": {"real-server": "rs-new", "pool-member-service-port": 8080,
                                                     "status": "enable"}}, "created with status disable"),
    ({"op": "create", "key": "pool-a:9", "changes": {"real-server": "rs-1", "pool-member-service-port": 80,
                                                     "status": "disable"}}, "already a member"),
    ({"op": "create", "key": "pool-a:9", "changes": {"real-server": "rs-none", "pool-member-service-port": 80,
                                                     "status": "disable"}}, "not configured"),
    ({"op": "create", "key": "pool-a:9", "changes": {"real-server": "rs-new", "status": "disable",
                                                     "pool-member-cookie": "rs9"}}, "by default"),
    ({"op": "delete", "key": "pool-a:1", "changes": {}}, "status disable or maintain"),
    ({"op": "delete", "key": "pool-b:1", "changes": {}}, "last member of a pool"),
    ({"op": "update", "key": "pool-a:1", "changes": {"real-server": "rs-2"}}, "cannot be updated"),
    ({"op": "update", "key": "pool-a:1", "changes": {"status": "down"}}, "must match"),
    ({"op": "update", "key": "pool-z:1", "changes": {"status": "disable"}}, "not configured"),
])
def test_refusals_write_nothing(tmp_path, fields, phrase):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as refused:
        approved_apply(runtime, "adc", request(**fields))
    assert any(phrase in reason for reason in refused.value.reasons), refused.value.reasons
    assert device.applied_blocks == [] and runtime.store.records() == []


def test_last_healthy_member_is_never_disabled(tmp_path):
    device = FakeADC()
    device.pools["pool-a"][4]["status"] = "disable"
    device.health["vs-a"] = {1: "UP", 2: "DOWN", 3: "DOWN", 4: "UP"}
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "adc", request())
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["no_healthy_member"]
    with pytest.raises(Rejected) as refused:
        approved_apply(runtime, "adc", request())
    assert "without a healthy enabled member" in refused.value.reasons[0]
    assert device.applied_blocks == []


def test_unreadable_health_refuses_the_status_change(tmp_path):
    device = FakeADC()
    device.vs_stat_error = True
    with pytest.raises(Rejected) as refused:
        approved_apply(make_runtime(tmp_path, device), "adc", request())
    assert "health" in refused.value.reasons[0] and device.applied_blocks == []


def test_apply_needs_enrollment(tmp_path):
    device = FakeADC()
    with pytest.raises(Rejected) as refused:
        approved_apply(make_runtime(tmp_path, device, certified=False), "adc", request())
    assert refused.value.reason_codes == ["enrollment_required"] and device.applied_blocks == []


def test_other_administrators_refuse_and_block(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    device.admins["intruder"] = {"is-system-admin": "yes"}
    with pytest.raises(Rejected):
        approved_apply(runtime, "adc", request())
    assert runtime.store.blocked("adc") is not None and device.applied_blocks == []


# --- compensating return -----------------------------------------------------------------------------------------

def test_ignored_write_is_reverted_without_a_second_write(tmp_path):
    device = FakeADC()
    device.ignore_writes = True
    record = approved_apply(make_runtime(tmp_path, device), "adc", request())
    assert (record["result"], record["reason"]) == ("reverted", "prediction mismatch")
    assert "compensation_not_needed" in steps(record) and len(device.applied_blocks) == 1


def test_lost_check_account_after_the_write_is_compensated(tmp_path):
    device = FakeADC()
    original = device.apply

    def apply(steps_, spec):
        answer = original(steps_, spec)
        device.check_unreadable = True
        return answer

    device.apply = apply
    record = approved_apply(make_runtime(tmp_path, device), "adc", request())
    assert (record["result"], record["reason"]) == ("reverted", "check identity unavailable"), steps(record)
    assert steps(record)[-3:] == ["compensation_start", "compensation_applied", "compensation_verified"]
    assert device.pools["pool-a"][1]["status"] == "enable"
    assert device.applied_blocks[1][4] == "set status enable"


def test_refused_write_is_compensated_and_verified(tmp_path):
    device = FakeADC()
    device.fail_after_write = {1}
    record = approved_apply(make_runtime(tmp_path, device), "adc", request())
    assert (record["result"], record["reason"]) == ("reverted", "change failed")
    assert device.pools["pool-a"][1]["status"] == "enable"


def test_unreadable_state_after_the_write_is_unknown_and_blocks(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    approved = preview_hash(runtime, "adc", request())
    device.fail_snapshot_after = device.snapshots + 1
    record = execute.apply(runtime, "adc", request(), expected_plan_sha256=approved)
    assert record["result"] == "unknown" and runtime.store.blocked("adc") is not None
    with pytest.raises(Rejected) as blocked:
        approved_apply(runtime, "adc", request(request_id="req-adc-0002"))
    assert blocked.value.reason_codes == ["device_blocked"]


def test_failed_compensation_is_revert_failed(tmp_path):
    device = FakeADC()
    original = device.apply
    calls = []

    def apply(steps_, spec):
        calls.append(1)
        if len(calls) == 1:
            answer = original(steps_, spec)
            device.check_unreadable = True
            return answer
        raise RuntimeError("refused")

    device.apply = apply
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "adc", request())
    assert record["result"] == "revert-failed" and "compensation_failed" in steps(record)
    assert runtime.store.blocked("adc") is not None


class Interrupted(BaseException):
    pass


def test_recover_returns_an_interrupted_change(tmp_path):
    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    original = device.check_query

    def check_query(command):
        if device.applied_blocks:
            raise Interrupted()
        return original(command)

    device.check_query = check_query
    with pytest.raises(Interrupted):
        approved_apply(runtime, "adc", request())
    assert device.pools["pool-a"][1]["status"] == "disable"
    device.check_query = original
    settled = execute.recover(runtime, "adc")
    assert [(item["result"], item["reason"]) for item in settled] == [("reverted", "interrupted")]
    assert device.pools["pool-a"][1]["status"] == "enable"


# --- enroll, doctor, MCP, legacy commands ------------------------------------------------------------------------

def test_enroll_creates_and_returns_a_disabled_probe_member(tmp_path):
    device = FakeADC()
    before = copy.deepcopy(device.pools)
    runtime = make_runtime(tmp_path, device, notifier=lambda _record: "sent", certified=False)
    record = enrollment.run(runtime, "adc", "pool-a:99:rs-new:8081")
    assert (record["result"], record["reason"], record.get("enrollment")) == (
        "reverted", "enrollment self-test", "valid"), steps(record)
    assert device.applied_blocks[0][4:7] == ['set real-server "rs-new"', "set pool_member_service_port 8081",
                                             "set status disable"]
    assert device.applied_blocks[1][3] == "delete 99"
    assert device.pools == before
    assert approved_apply(runtime, "adc", request())["result"] == "confirmed"


def test_enroll_without_notification_is_refused(tmp_path):
    device = FakeADC()
    with pytest.raises(Rejected):
        enrollment.run(make_runtime(tmp_path, device, certified=False), "adc", "pool-a:99:rs-new:8081")
    assert device.applied_blocks == []


@pytest.mark.parametrize("probe", ["pool-a:99:rs-new", "pool-a::rs-new:80", "192.0.2.0/30"])
def test_malformed_enroll_probe_is_refused(tmp_path, probe):
    with pytest.raises(Rejected):
        enrollment.run(make_runtime(tmp_path, FakeADC(), notifier=lambda _r: "sent", certified=False), "adc", probe)


def test_doctor_reads_identity_rights_and_enrollment(tmp_path):
    device = FakeADC()
    report = readiness.doctor(make_runtime(tmp_path, device), "adc")
    found = {item["check"]: item for item in report["checks"]}
    for name in ("write account and host key", "firmware", "administrator accounts", "check account",
                 "write account rights", "check account rights", "leftover safeguards", "device prechecks",
                 "enrollment"):
        assert found[name]["status"] == readiness.OK, (name, found[name])
    assert found["check account"]["detail"] == "reads system status hostname"
    assert found["audit policy"]["status"] == readiness.UNVERIFIED
    assert report["firmware"] == "7.6.7 build0676"
    assert report["operations"] == {TABLE: "create update delete",
                                    fortiadc_plan.REAL_SERVERS: "create update",
                                    fortiadc_plan.VIRTUAL_SERVERS: "update"}
    assert device.applied_blocks == []


def test_mcp_preview_and_apply_accept_fortiadc(tmp_path, monkeypatch):
    pytest.importorskip("fastmcp")
    from test_mcp_server import call
    from netops_admin import mcp_server

    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda *_args, **_kwargs: runtime)
    body = {"device": "adc", "table": TABLE, "op": "update", "key": "pool-a:1", "changes": {"status": "disable"},
            "reason": "maintenance", "user_request": "take member 1 out", "request_id": "req-adc-mcp-1"}
    preview = call("admin_preview", body)
    assert preview["result"] == "ready" and device.applied_blocks == []
    answer = call("admin_apply", dict(body, expected_plan_sha256=preview["plan_sha256"]))
    assert answer["result"] == "confirmed" and answer["table"] == TABLE
    assert call("admin_status", {"request_id": "req-adc-mcp-1"})["result"] == "confirmed"
    undo = call("admin_undo_preview", {"change_id": answer["change_id"], "reason": "back"})
    assert undo["result"] == "ready" and undo["undo_of"] == answer["change_id"]
    doctor = call("admin_doctor", {"device": "adc"})
    assert doctor["platform"] == "fortiadc"
    assert "FortiADC" in mcp_server.INSTRUCTIONS


def test_legacy_commands_still_work_and_say_they_are_deprecated(tmp_path, monkeypatch, capsys):
    from netops_admin import config as config_module

    device = FakeADC()
    runtime = make_runtime(tmp_path, device)
    device.prompts = False
    monkeypatch.setattr(config_module, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "open_access", lambda _device: device)
    argv = ["pool-member", "--config", str(tmp_path / "admin.json"), "--device", "adc", "--pool", "pool-a",
            "--member", "2", "--status", "maintain"]
    # like every apply, the legacy write needs the plan_sha256 of its own approved preview: without it nothing is written
    code = cli.main(argv)
    out = capsys.readouterr()
    refused = json.loads(out.out)
    assert (code, refused["result"], refused["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert device.applied_blocks == [] and "deprecated" in out.err and TABLE in out.err
    code = cli.main(argv + ["--preview"])
    previewed = json.loads(capsys.readouterr().out)
    assert (code, previewed["result"], device.applied_blocks) == (0, "ready", [])
    code = cli.main(argv + ["--expect-plan-sha256", previewed["plan_sha256"]])
    out = capsys.readouterr()
    assert code == 0 and json.loads(out.out)["result"] == "confirmed"
    assert len(device.applied_blocks) == 1
    assert "deprecated" in out.err and TABLE in out.err
