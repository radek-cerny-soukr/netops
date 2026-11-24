"""Z1: real journal and access failures through the execution error paths."""
from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest
from fake_fortios import FakeFortiOS
from test_enrollment import ready
from test_execute import audit_lines, make_runtime, request, steps

from netops_admin import enrollment, execute
from netops_admin.access import DeviceAccess
from netops_admin.errors import StateUnreadable
from approved_apply import approved_apply


def test_delivery_refresh_propagates_an_unreadable_journal(tmp_path):
    status = tmp_path / "export.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1}))
    runtime = make_runtime(tmp_path, FakeFortiOS(), export_status=str(status))
    record = approved_apply(runtime, "lab", request())
    assert record["audit_delivery"] == "pending"
    status.write_text(json.dumps({"updated_at": record["finished_at_epoch"] + 1, "pending": 0}))
    journal = runtime.store.operations / (record["change_id"] + ".json")
    journal.write_text("{broken journal")
    events = audit_lines(tmp_path)

    with pytest.raises(StateUnreadable) as caught:
        execute.refresh_delivery(runtime, record)

    assert "operations/" + journal.name in caught.value.reasons[0]
    assert journal.read_text() == "{broken journal"
    assert record["audit_delivery"] == "pending"
    assert audit_lines(tmp_path) == events


def test_enrollment_notification_exception_prevents_device_writes(tmp_path):
    runtime, device, name = ready(tmp_path)
    attempts = []

    def disconnected_channel(record):
        attempts.append(record["result"])
        raise ConnectionError("notification peer disconnected")

    runtime.notifier = disconnected_channel
    record = enrollment.run(runtime, name, "192.0.2.254/32")

    assert attempts == ["enrollment-preflight", "rejected"]
    assert (record["result"], record["reason"], record["notification"]) == (
        "rejected", "enrollment notification unavailable", "failed")
    saved = runtime.store.operation(record["change_id"])
    assert (saved["result"], saved["reason"], saved["notification"]) == (
        record["result"], record["reason"], record["notification"])
    assert runtime.store.enrollment(name) is None
    assert device.applied_blocks == []
    assert "safeguard_install" not in steps(record)


def test_recovery_keeps_unverified_safeguard_when_credentials_are_missing(tmp_path):
    device = FakeFortiOS()
    device.unreachable_after_apply = lambda _lines: True
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == ("unknown", "safeguard not verified")
    assert device.stitches and "change_start" not in steps(record)
    before = len(device.applied_blocks)
    configured = replace(runtime.config.devices["lab"], vault=str(tmp_path / "missing-vault.json"))
    runtime.config = replace(runtime.config, devices={"lab": configured})
    runtime.access_factory = DeviceAccess

    [recovered] = execute.recover(runtime, "lab")

    assert recovered["change_id"] == record["change_id"]
    assert (recovered["result"], recovered["reason"]) == ("unknown", "safeguard not verified")
    assert steps(recovered)[-2:] == ["recovery_start", "recovery_access_failed"]
    assert recovered["steps"][-1]["detail"] == "AccessError"
    assert runtime.store.operation(record["change_id"]) == recovered
    assert runtime.store.blocked("lab")["change_id"] == record["change_id"]
    assert len(device.applied_blocks) == before and device.stitches
