from __future__ import annotations

import json

import pytest
from conftest import request_bytes
from fake_exos import FIRMWARE, FakeExos

from netops_admin import execute
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.request import parse_request


def make_runtime(tmp_path, device, accounts=("admin", "netops-rw"), firmware=FIRMWARE):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"sw": Device(
            name="sw", platform="exos", address="192.0.2.2", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw", check_credential="ro",
            firmware=firmware, safeguard_seconds=180, confirm_margin_seconds=45, protected={},
            legacy_ssh="rsa-sha1", accounts=tuple(accounts),
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance)
    return certify(runtime, device, "sw")


def request(**fields):
    fields.setdefault("table", "vlan")
    fields.setdefault("key", "guest")
    fields.setdefault("changes", {"tag": 3999, "description": "guest wifi"})
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


def clean(device):
    return not device.profiles and not device.timers


def test_create_is_confirmed_saved_and_the_safeguard_is_gone(tmp_path):
    device = FakeExos()
    record = execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert record["result"] == "confirmed"
    assert device.vlans["guest"] == {"tag": "3999", "description": "guest wifi"}
    assert clean(device) and not device.unsaved and device.saves == 1
    assert steps(record)[:4] == ["foreign_sessions", "safeguard_install", "safeguard_verified", "change_start"]
    assert steps(record)[-1] == "configuration_saved"
    first = device.applied_blocks[0]
    assert first[0] == ("ask", "create upm profile %s" % record["safeguard"]["name"][:-1] + "p", b"Start typing")
    assert first[1] == ("raw", "configure cli mode persistent")
    assert first[2] == ("raw", "configure cli mode scripting ignore-error")
    assert first[3] == ("raw", "delete vlan guest")
    assert all(len(name) <= 13 for name in (record["safeguard"]["name"], first[0][1].split()[3]))
    start = json.loads((tmp_path / "audit" / "audit.jsonl").read_text().splitlines()[0])
    assert start["safeguard"] == record["safeguard"]["name"]


def test_update_remove_and_delete_are_confirmed(tmp_path):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "sw", request(op="update", key="spare", changes={"description": "parked"},
                                                request_id="req-update-1"))["result"] == "confirmed"
    assert device.vlans["spare"]["description"] == "parked"
    assert execute.apply(runtime, "sw", request(op="update", key="spare", changes={"description": None},
                                                request_id="req-update-2"))["result"] == "confirmed"
    assert "description" not in device.vlans["spare"]
    assert execute.apply(runtime, "sw", request(op="delete", key="spare", changes={},
                                                request_id="req-delete-1"))["result"] == "confirmed"
    assert "spare" not in device.vlans and clean(device) and device.saves == 3


def test_prediction_mismatch_is_reverted_by_the_timer_and_saved(tmp_path):
    device = FakeExos()
    device.drop_description = True
    record = execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert "guest" not in device.vlans and clean(device)
    assert not device.unsaved and device.saves == 1


def test_unsaved_foreign_changes_are_refused_before_any_mutation(tmp_path):
    device = FakeExos()
    device.unsaved = True
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert "unsaved" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_other_firmware_is_refused(tmp_path):
    device = FakeExos()
    device.firmware = "33.6.1"
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert "33.6.1" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unexpected_account_blocks_before_any_mutation(tmp_path):
    device = FakeExos()
    device.accounts.append("intruder")
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", request())
    assert "accounts differ" in caught.value.reasons[0]
    assert runtime.store.blocked("sw")["reason"] == "administrator table"
    assert device.applied_blocks == []


def test_account_created_during_the_change_is_reverted_and_blocks(tmp_path):
    device = FakeExos()

    def create_account(fake, steps):
        if len(fake.applied_blocks) == 2:
            fake.accounts.append("sneaky")

    device.on_apply = create_account
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "administrator table"
    assert "guest" not in device.vlans
    assert runtime.store.blocked("sw")["reason"] == "administrator table"


def test_leftover_safeguard_is_refused(tmp_path):
    device = FakeExos()
    device.profiles["netopsabcdefp"] = ["delete vlan guest"]
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert "still installed" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_timer_scheduled_elsewhere_is_removed_and_nothing_changes(tmp_path):
    device = FakeExos()
    device.timer_shift = 60
    record = execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "safeguard not verified"
    assert "guest" not in device.vlans and clean(device) and not device.unsaved
    assert len(device.applied_blocks) == 3


def test_profile_that_reads_back_differently_is_removed_and_nothing_changes(tmp_path):
    device = FakeExos()
    device.body_override = ["show switch"]
    record = execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "safeguard not verified"
    assert "guest" not in device.vlans and clean(device)


def test_refused_line_is_reverted(tmp_path):
    device = FakeExos()

    def refuse(fake, steps):
        fake.fail_at_line = 2 if len(fake.applied_blocks) == 2 else None

    device.on_apply = refuse
    record = execute.apply(make_runtime(tmp_path, device), "sw", request())
    assert record["result"] == "reverted" and "change_failed" in steps(record)
    assert "guest" not in device.vlans and clean(device)


def test_crash_after_the_change_is_settled_by_recover(tmp_path):
    device = FakeExos()

    def crash(fake, steps):
        if len(fake.applied_blocks) == 2:
            fake._run(steps)
            raise KeyboardInterrupt

    device.on_apply = crash
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "sw", request())
    assert "guest" in device.vlans
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "sw")
    assert [record["result"] for record in settled] == ["reverted"]
    assert "guest" not in device.vlans and clean(device)


def test_failed_save_after_confirmation_blocks(tmp_path):
    device = FakeExos()
    device.refuse_save = True
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "confirmed" and record["reason"] == "not persisted"
    assert "persist_failed" in steps(record)
    assert runtime.store.blocked("sw")["reason"] == "not persisted"


def test_foreign_change_in_the_window_is_reverted_not_saved_and_blocks(tmp_path):
    device = FakeExos()

    def foreign(fake, steps):
        if len(fake.applied_blocks) == 2:
            fake.vlans["DATA"]["description"] = "someone else"

    device.on_apply = foreign
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", request(op="update", key="spare", changes={"description": "mine"}))
    assert record["result"] == "reverted" and record["reason"] == "foreign change"
    assert device.vlans["spare"]["description"] == "unused"
    assert device.saves == 0 and device.unsaved
    assert runtime.store.blocked("sw")["reason"] == "foreign change"
