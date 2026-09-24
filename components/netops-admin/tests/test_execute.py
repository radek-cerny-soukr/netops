from __future__ import annotations

import json
import time

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS

from netops_admin import execute
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

SECRET = "SECRET-MARKER-4711"


def make_runtime(tmp_path, device, export_status=None, limits=None):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=export_status, notify=None, limits=dict(limits or DEFAULT_LIMITS),
        devices={"lab": Device(
            name="lab", platform="fortios", address="192.0.2.1", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw", check_credential="ro",
            firmware=None, safeguard_seconds=180, confirm_margin_seconds=45, protected={},
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance)
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
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
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
    record = execute.apply(make_runtime(tmp_path, device), "lab",
                           request(reason="because %s" % SECRET, changes={"subnet": "192.0.2.30/32", "comment": "x"}))
    assert SECRET not in (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET not in json.dumps(record)
    assert SECRET not in "".join(path.read_text() for path in (tmp_path / "state").rglob("*.json"))


def test_update_and_delete_are_confirmed(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"},
                                                 request_id="req-update-1"))["result"] == "confirmed"
    assert device.addresses["spare-host"]["comment"] == "two words"
    assert execute.apply(runtime, "lab", request(op="delete", key="spare-host", changes={},
                                                 request_id="req-delete-1"))["result"] == "confirmed"
    assert "spare-host" not in device.addresses


def test_prediction_mismatch_is_reverted_by_the_safeguard(tmp_path):
    device = FakeFortiOS()
    device.drop_comment = True
    record = execute.apply(make_runtime(tmp_path, device), "lab",
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
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
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
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted"
    assert "new-host" not in device.addresses


def test_foreign_administrator_blocks_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.admins.append("persisted-account")
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert "other administrators than the configured" in caught.value.reasons[0]
    assert device.applied_blocks == []
    device.admins.remove("persisted-account")
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(request_id="req-after-block"))
    assert "blocked" in caught.value.reasons[0]
    assert execute.unblock(runtime, "lab", "investigated")
    from enrollment_helpers import certify
    certify(runtime, device, "lab")
    assert execute.apply(runtime, "lab", request(request_id="req-after-unblock"))["result"] == "confirmed"


def test_administrator_created_during_the_change_is_reverted_and_blocks(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def create_account(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake.admins.append("sneaky")

    device.on_apply = create_account
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "reverted"
    assert record["reason"] == "administrator table"
    assert runtime.store.blocked("lab") is not None


def test_repeated_request_returns_the_same_operation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request())
    again = execute.apply(runtime, "lab", request())
    assert again["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == 3
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(changes={"subnet": "192.0.2.31/32"}))
    assert "different request" in caught.value.reasons[0]


def test_repeated_request_after_restart_is_not_executed_again(tmp_path):
    device = FakeFortiOS()
    first = execute.apply(make_runtime(tmp_path, device), "lab", request())
    restarted = make_runtime(tmp_path, device)
    again = execute.apply(restarted, "lab", request())
    assert again["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == 3


def test_leftover_safeguard_is_refused(tmp_path):
    device = FakeFortiOS()
    device.stitches["netops-sg-deadbeef0000-s"] = {"trigger": None, "action": None}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab", request())
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
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
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
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
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
        execute.apply(runtime, "lab", request())
    assert "new-host" in device.addresses
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab", request(request_id="req-while-running"))
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
        execute.apply(runtime, "lab", request())
    device.on_apply = None
    settled = execute.recover(runtime, "lab")
    assert [record["result"] for record in settled] == ["confirmed"]
    assert "new-host" in device.addresses


def test_unreadable_device_is_rejected_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.unreadable = True
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert "could not be read before any change" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unwritable_audit_log_is_rejected_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit").chmod(0o500)
    try:
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, "lab", request())
    finally:
        (tmp_path / "audit").chmod(0o700)
    assert "audit log" in caught.value.reasons[0]
    assert device.applied_blocks == []


@pytest.mark.parametrize(("status", "fragment"), [
    ({"updated_at": 0, "pending": 0}, "stale"),
    ({"updated_at": "now", "pending": 1001}, "over the limit"),
    ({"updated_at": "now", "pending": 5, "oldest_pending_age_seconds": 901}, "older than the limit"),
])
def test_blocked_export_is_rejected_before_any_mutation(tmp_path, status, fragment):
    device = FakeFortiOS()
    status = dict(status)
    if status["updated_at"] == "now":
        status["updated_at"] = time.time()
    path = tmp_path / "export-status.json"
    path.write_text(json.dumps(status))
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device, export_status=str(path)), "lab", request())
    assert fragment in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_busy_device_lock_is_rejected(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    with runtime.store.lock("lab"):
        with pytest.raises(Rejected) as caught:
            execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert "device lock" in caught.value.reasons[0]


def test_safeguard_that_does_not_read_back_is_removed_and_nothing_changes(tmp_path):
    device = FakeFortiOS()
    device.trigger_override = "2026-09-23 23:59:59"
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
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
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
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
        execute.apply(runtime, "lab", request())
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
