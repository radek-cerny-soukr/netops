from __future__ import annotations

import dataclasses
import json
import time

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS

from netops_admin import execute
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from approved_apply import approved_apply

SECRET = "SECRET-MARKER-4711"


def make_runtime(tmp_path, device, export_status=None, limits=None, simulate_unmeasured_profiles=False, **device_fields):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=export_status, notify=None, limits=dict(limits or DEFAULT_LIMITS),
        devices={"lab": dataclasses.replace(Device(
            name="lab", platform="fortios", address="192.0.2.1", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw", check_credential="ro",
            firmware=None, safeguard_seconds=180, confirm_margin_seconds=45, protected={},
        ), **device_fields)},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance,
                              simulate_unmeasured_profiles=simulate_unmeasured_profiles)
    return certify(runtime, device, "lab")


def request(**fields):
    fields.setdefault("key", "new-host")
    fields.setdefault("changes", {"subnet": "192.0.2.30/32", "comment": "new host"})
    fields.setdefault("user_request", "please add the host, token %s" % SECRET)
    return parse_request(request_bytes(**fields))


def audit_lines(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]


def steps(record):
    return [step["step"] for step in record["steps"]]


def test_create_is_confirmed_and_the_safeguard_is_gone(tmp_path):
    device = FakeFortiOS()
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "confirmed"
    assert device.addresses["new-host"]["subnet"] == "192.0.2.30 255.255.255.255"
    assert not device.stitches and not device.triggers and not device.actions
    assert steps(record)[:4] == ["foreign_sessions", "safeguard_install", "safeguard_verified", "change_start"]
    events = audit_lines(tmp_path)
    assert [event["event"] for event in events][0] == "start"
    assert events[-1]["event"] == "result" and events[-1]["result"] == "confirmed"
    assert events[0]["changes"] == {"comment": "text of 8 characters", "subnet": "ipv4-network changed"}


def test_free_text_never_reaches_the_audit_log_or_the_journal(tmp_path):
    device = FakeFortiOS()
    record = approved_apply(make_runtime(tmp_path, device), "lab",
                           request(reason="because %s" % SECRET, changes={"subnet": "192.0.2.30/32", "comment": "x"}))
    assert SECRET not in (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET not in json.dumps(record)
    assert SECRET not in "".join(path.read_text() for path in (tmp_path / "state").rglob("*.json"))


def test_update_and_delete_are_confirmed(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"},
                                                 request_id="req-update-1"))["result"] == "confirmed"
    assert device.addresses["spare-host"]["comment"] == "two words"
    assert approved_apply(runtime, "lab", request(op="delete", key="spare-host", changes={},
                                                 request_id="req-delete-1"))["result"] == "confirmed"
    assert "spare-host" not in device.addresses


def test_prediction_mismatch_is_reverted_by_the_safeguard(tmp_path):
    device = FakeFortiOS()
    device.drop_comment = True
    record = approved_apply(make_runtime(tmp_path, device), "lab",
                           request(op="update", key="spare-host", changes={"comment": "two words"}))
    assert record["result"] == "reverted"
    assert record["reason"] == "prediction mismatch"
    assert record["postcheck_differences"]
    assert device.addresses["spare-host"]["comment"] == "unused"
    assert not device.stitches


def test_refused_line_leaves_nothing_behind(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def refuse_the_change(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake.fail_at_line = 3
        else:
            fake.fail_at_line = None

    device.on_apply = refuse_the_change
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert "new-host" not in device.addresses
    assert "change_failed" in steps(record)


def test_a_partial_write_is_reverted(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def refuse_late(fake, lines):
        blocks.append(lines)
        fake.fail_at_line = 4 if len(blocks) == 2 else None

    device.on_apply = refuse_late
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert "new-host" not in device.addresses


def test_foreign_administrator_blocks_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.admins.append("persisted-account")
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "lab", request())
    assert "other administrators than the configured" in caught.value.reasons[0]
    assert device.applied_blocks == []
    device.admins.remove("persisted-account")
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "lab", request(request_id="req-after-block"))
    assert "blocked" in caught.value.reasons[0]
    assert execute.unblock(runtime, "lab", "investigated")
    from enrollment_helpers import certify
    certify(runtime, device, "lab")
    assert approved_apply(runtime, "lab", request(request_id="req-after-unblock"))["result"] == "confirmed"


def test_administrator_created_during_the_change_is_reverted_and_blocks(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def create_account(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake.admins.append("sneaky")

    device.on_apply = create_account
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "lab", request())
    assert record["result"] == "reverted"
    assert record["reason"] == "administrator table"
    assert runtime.store.blocked("lab") is not None


def test_repeated_request_returns_the_same_operation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request())
    again = approved_apply(runtime, "lab", request())
    assert again["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == 3
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "lab", request(changes={"subnet": "192.0.2.31/32"}))
    assert "different request" in caught.value.reasons[0]


def test_repeated_request_after_restart_is_not_executed_again(tmp_path):
    device = FakeFortiOS()
    first = approved_apply(make_runtime(tmp_path, device), "lab", request())
    restarted = make_runtime(tmp_path, device)
    again = approved_apply(restarted, "lab", request())
    assert again["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == 3


def test_leftover_safeguard_is_refused(tmp_path):
    device = FakeFortiOS()
    device.stitches["netops-sg-deadbeef0000-s"] = {"trigger": None, "action": None}
    with pytest.raises(Rejected) as caught:
        approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert "still installed" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_no_time_left_means_no_confirmation(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def slow_change(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake.clock = fake.clock.replace(minute=2, second=30)

    device.on_apply = slow_change
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert "confirm_skipped" in steps(record)
    assert "new-host" not in device.addresses


def test_timer_race_during_confirmation_is_reported_as_reverted(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def late_removal(fake, lines):
        blocks.append(lines)
        if len(blocks) == 3:
            fake.advance(200)

    device.on_apply = late_removal
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert "new-host" not in device.addresses


def test_crash_after_the_change_is_settled_by_recover(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def crash(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake._run(lines)
            raise KeyboardInterrupt

    device.on_apply = crash
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        approved_apply(runtime, "lab", request())
    assert "new-host" in device.addresses
    with pytest.raises(Rejected):
        approved_apply(runtime, "lab", request(request_id="req-while-running"))
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "lab")
    assert [record["result"] for record in settled] == ["reverted"]
    assert "new-host" not in device.addresses and not device.stitches


def test_crash_after_confirmation_is_settled_as_confirmed(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def crash_after_removal(fake, lines):
        blocks.append(lines)
        if len(blocks) == 3:
            fake._run(lines)
            raise KeyboardInterrupt

    device.on_apply = crash_after_removal
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        approved_apply(runtime, "lab", request())
    device.on_apply = None
    settled = execute.recover(runtime, "lab")
    assert [record["result"] for record in settled] == ["confirmed"]
    assert "new-host" in device.addresses


def test_unreadable_device_is_rejected_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.unreadable = True
    with pytest.raises(Rejected) as caught:
        approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert "could not be read before any change" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unwritable_audit_log_is_rejected_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit").chmod(0o500)
    try:
        with pytest.raises(Rejected) as caught:
            approved_apply(runtime, "lab", request())
    finally:
        (tmp_path / "audit").chmod(0o700)
    assert "audit log" in caught.value.reasons[0]
    assert device.applied_blocks == []


@pytest.mark.parametrize(("status", "fragment"), [
    ({"updated_at": 0, "pending": 0}, "stale"),
    ({"updated_at": "now", "pending": 1001}, "over the limit"),
    ({"updated_at": "now", "pending": 5, "oldest_pending_age_seconds": 901}, "older than the limit"),
    ({"updated_at": "now", "pending": 0, "audit_file": "/var/lib/netops-admin-audit/audit.jsonl"}, "another audit file"),
    ({"updated_at": "now", "pending": 0, "audit_file": "audit.jsonl"}, "cannot be read"),
])
def test_blocked_export_is_rejected_before_any_mutation(tmp_path, status, fragment):
    device = FakeFortiOS()
    status = dict(status)
    if status["updated_at"] == "now":
        status["updated_at"] = time.time()
    path = tmp_path / "export-status.json"
    path.write_text(json.dumps(status))
    with pytest.raises(Rejected) as caught:
        approved_apply(make_runtime(tmp_path, device, export_status=str(path)), "lab", request())
    assert fragment in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_busy_device_lock_is_rejected(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    with runtime.store.lock("lab"):
        with pytest.raises(Rejected) as caught:
            approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert "device lock" in caught.value.reasons[0]


def test_safeguard_that_does_not_read_back_is_removed_and_nothing_changes(tmp_path):
    device = FakeFortiOS()
    device.trigger_override = "2026-09-23 23:59:59"
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert record["reason"] == "safeguard not verified"
    assert "new-host" not in device.addresses
    assert len(device.applied_blocks) == 2
    assert not device.stitches and not device.triggers and not device.actions


def test_foreign_change_in_the_window_is_reverted_and_blocks(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def foreign(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake.addresses["srv-web"]["comment"] = "changed by someone else"

    device.on_apply = foreign
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    assert record["result"] == "reverted"
    assert record["reason"] == "foreign change"
    assert device.addresses["spare-host"]["comment"] == "unused"
    assert device.addresses["srv-web"]["comment"] == "changed by someone else"
    assert runtime.store.blocked("lab")["reason"] == "foreign change"


def test_running_operation_without_a_safeguard_still_blocks_new_changes(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.store.save({"change_id": "c" * 32, "device": "lab", "status": "running", "request_id": "old-request-1"})
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "lab", request())
    assert "unfinished operation" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_journal_writes_are_synced_to_disk(tmp_path, monkeypatch):
    from netops_admin import state

    synced = []
    real = state.os.fsync

    def counting(descriptor):
        synced.append(descriptor)
        return real(descriptor)

    monkeypatch.setattr(state.os, "fsync", counting)
    state.write_atomic(tmp_path / "record.json", {"a": 1})
    assert len(synced) == 2


def foreign_comment(fake):
    fake.addresses["srv-web"]["comment"] = "changed by someone else"


def test_foreign_change_before_the_safeguard_is_removed_is_returned_by_the_safeguard(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    reads, check_query = [], device.check_query

    def reading(command):
        answer = check_query(command)
        reads.append(command)
        if len(reads) == 2:
            foreign_comment(device)
        return answer

    device.check_query = reading
    record = approved_apply(runtime, "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "foreign change"
    assert "confirm_start" not in steps(record)
    assert "new-host" not in device.addresses and device.addresses["srv-web"]["comment"] == "changed by someone else"
    assert not device.stitches and not device.triggers and not device.actions
    assert runtime.store.blocked("lab")["reason"] == "foreign change"


def test_foreign_change_after_the_safeguard_is_removed_blocks(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    apply_lines = device.apply

    def applying(lines, spec):
        accepted = apply_lines(lines, spec)
        if lines[:1] == ["config system automation-stitch"] and lines[1].startswith("delete"):
            foreign_comment(device)
        return accepted

    device.apply = applying
    record = approved_apply(runtime, "lab", request())
    assert record["result"] == "unknown" and record["reason"] == "foreign change after the safeguard was removed"
    assert record["differences"] == ["configuration outside the planned object changed"]
    assert device.addresses["new-host"]["comment"] == "new host"
    assert runtime.store.blocked("lab")["reason"] == "foreign change after the safeguard was removed"


def test_unreadable_return_check_after_the_safeguard_is_removed_still_finishes_and_blocks(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    apply_lines = device.apply
    removed = []

    def applying(lines, spec):
        accepted = apply_lines(lines, spec)
        if lines[:1] == ["config system automation-stitch"] and lines[1].startswith("delete"):
            foreign_comment(device)
            removed.append(True)
        return accepted

    verify = execute.engine.verify

    def verifying(*args, **kwargs):
        if removed and kwargs.get("expect") == "before":
            raise ValueError("unreadable snapshot")
        return verify(*args, **kwargs)

    device.apply = applying
    monkeypatch.setattr(execute.engine, "verify", verifying)
    record = approved_apply(runtime, "lab", request())
    assert record["status"] == "finished"
    assert record["result"] == "unknown" and record["reason"] == "foreign change after the safeguard was removed"
    assert runtime.store.blocked("lab")["reason"] == "foreign change after the safeguard was removed"


def test_confirmation_without_a_save_takes_no_check_after_it(tmp_path):
    device = FakeFortiOS()
    record = approved_apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "confirmed" and record["reason"] is None
    assert steps(record)[-2:] == ["check_identity_passed", "confirm_start"]


def test_preview_preserves_corrupt_enrollment_reason_codes(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    (runtime.store.enrollments / 'lab.json').write_text('{broken')
    preview = execute.preview(runtime, 'lab', request())
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, 'lab', request())
    assert preview['reason_codes'] == caught.value.reason_codes == ['state_unreadable']
    assert preview['reason_details'] == caught.value.reason_details


# 109-15: optional binding of apply to the approved preview (expected_plan_sha256)

def _rejections(runtime):
    return runtime.store.rejections_since(runtime.store.budget_now() - execute.HOUR)


def _starts(tmp_path):
    path = tmp_path / "audit" / "audit.jsonl"
    return [event for event in audit_lines(tmp_path) if event["event"] == "start"] if path.exists() else []


def test_apply_with_the_previewed_plan_hash_is_confirmed(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    ahead = execute.preview(runtime, "lab", request(request_id="req-bound-0001"))
    assert ahead["result"] == "ready" and len(ahead["plan_sha256"]) == 64
    record = execute.apply(runtime, "lab", request(request_id="req-bound-0001"),
                           expected_plan_sha256=ahead["plan_sha256"])
    assert record["result"] == "confirmed"
    assert record["plan"]["plan_sha256"] == ahead["plan_sha256"]
    assert device.addresses["new-host"]["subnet"] == "192.0.2.30 255.255.255.255"


def test_object_changed_after_the_preview_is_refused_with_plan_changed_before_any_write(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    approved = request(op="update", key="spare-host", changes={"comment": "approved"}, request_id="req-bound-0002")
    ahead = execute.preview(runtime, "lab", approved)
    assert ahead["result"] == "ready"
    device.addresses["spare-host"]["comment"] = "someone else"
    blocks, records, starts, refused = (len(device.applied_blocks), len(list(runtime.store.records())),
                                        len(_starts(tmp_path)), _rejections(runtime))
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", approved, expected_plan_sha256=ahead["plan_sha256"])
    assert caught.value.reasons == [execute.PLAN_CHANGED]
    assert caught.value.reason_codes == ["plan_changed"]
    [detail] = caught.value.reason_details
    assert detail["code"] == "plan_changed" and detail["expected"] == ahead["plan_sha256"]
    assert len(detail["actual"]) == 64 and detail["actual"] != ahead["plan_sha256"]
    assert len(device.applied_blocks) == blocks and not device.stitches
    assert device.addresses["spare-host"]["comment"] == "someone else"
    assert len(list(runtime.store.records())) == records
    assert runtime.store.request("req-bound-0002") is None
    assert len(_starts(tmp_path)) == starts
    assert _rejections(runtime) == refused + 1


@pytest.mark.parametrize("value", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, " " + "a" * 63, "", 7, ["a" * 64]])
def test_malformed_plan_hash_is_rejected_before_the_device_is_read(tmp_path, value):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    refused = _rejections(runtime)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(), expected_plan_sha256=value)
    assert "64 lowercase hexadecimal" in caught.value.reasons[0]
    assert device.applied_blocks == [] and "new-host" not in device.addresses
    assert list(runtime.store.records()) == []
    assert _rejections(runtime) == refused + 1


def test_malformed_plan_hash_counts_against_the_rejection_budget(tmp_path):
    from netops_admin.errors import BudgetExhausted
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=dict(DEFAULT_LIMITS, rejections_per_hour=2))
    for number in range(2):
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, "lab", request(request_id="req-hash-%04d" % number), expected_plan_sha256="A" * 64)
        assert not isinstance(caught.value, BudgetExhausted)
    assert _rejections(runtime) == 2
    assert device.applied_blocks == [] and list(runtime.store.records()) == []
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request())
    assert "rejected requests" in caught.value.reasons[0]
    assert "new-host" not in device.addresses


def test_plan_changed_counts_against_the_rejection_budget(tmp_path):
    from netops_admin.errors import BudgetExhausted
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=dict(DEFAULT_LIMITS, rejections_per_hour=2))
    approved = request(op="update", key="spare-host", changes={"comment": "approved"}, request_id="req-bound-0006")
    ahead = execute.preview(runtime, "lab", approved)
    assert ahead["result"] == "ready"
    device.addresses["spare-host"]["comment"] = "someone else"
    for _ in range(2):
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, "lab", approved, expected_plan_sha256=ahead["plan_sha256"])
        assert caught.value.reason_codes == ["plan_changed"]
    assert _rejections(runtime) == 2
    assert device.applied_blocks == [] and list(runtime.store.records()) == []
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request())
    assert "rejected requests" in caught.value.reasons[0]
    assert "new-host" not in device.addresses


def test_apply_without_the_plan_hash_behaves_as_before(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    approved = request(op="update", key="spare-host", changes={"comment": "approved"}, request_id="req-bound-0004")
    ahead = execute.preview(runtime, "lab", approved)
    device.addresses["spare-host"]["comment"] = "someone else"
    record = approved_apply(runtime, "lab", approved)
    assert record["result"] == "confirmed"
    assert record["plan"]["plan_sha256"] != ahead["plan_sha256"]
    assert device.addresses["spare-host"]["comment"] == "approved"


def test_repeated_request_id_returns_the_started_operation_whatever_plan_hash(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    ahead = execute.preview(runtime, "lab", request(request_id="req-bound-0005"))
    first = execute.apply(runtime, "lab", request(request_id="req-bound-0005"), expected_plan_sha256=ahead["plan_sha256"])
    assert first["result"] == "confirmed"
    blocks = len(device.applied_blocks)
    again = execute.apply(runtime, "lab", request(request_id="req-bound-0005"), expected_plan_sha256="0" * 64)
    assert again["change_id"] == first["change_id"]
    plain = approved_apply(runtime, "lab", request(request_id="req-bound-0005"))
    assert plain["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == blocks


def test_plan_hash_is_not_part_of_the_request_identity():
    assert "expected_plan_sha256" not in json.dumps(request().__dict__)
    assert request().fingerprint() == request().fingerprint()
