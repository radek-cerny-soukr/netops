"""Cisco NX-OS 9.3(12) (Nexus 9000v): plan, preview, apply behind the scheduler safeguard (checkpoint + one-time job,
variant 3 of the measurement), confirmation, immediate return by configure replace, expiry of the job, enrollment,
recovery, refusals and audit. The device is FakeNxos, whose answers come from measured outputs
(fixtures/nxos_9_3_12)."""
from __future__ import annotations

import datetime
import json
import re
from copy import deepcopy

import pytest
from conftest import request_bytes
from fake_nxos import FIRMWARE, FakeNxos, fixture

from netops_admin import audit_gate, execute, exec_nxos, nxos
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.request import parse_request

ACCOUNTS = ("admin", "user01", "user02")
SECRET_TEXT = "k7c Nx Vb8Wn"
KEY = "Ethernet1/48"


@pytest.fixture
def device(monkeypatch):
    fake = FakeNxos()
    monkeypatch.setattr(exec_nxos, "PAUSE", fake.advance)
    return fake


def make_runtime(tmp_path, device, accounts=ACCOUNTS, firmware=FIRMWARE, safeguard=180):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"lab-nxos": Device(
            name="lab-nxos", platform="nxos", address="192.0.2.55", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=firmware, safeguard_seconds=safeguard, confirm_margin_seconds=45,
            protected={}, accounts=tuple(accounts),
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance, require_export=False)
    runtime.monotonic = lambda: device.uptime
    return certify(runtime, device, "lab-nxos")


def request(**fields):
    fields.setdefault("table", "interface")
    fields.setdefault("op", "update")
    fields.setdefault("key", KEY)
    fields.setdefault("changes", {"description": "netops-c6b-test"})
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


BASELINE = FakeNxos().running()


def lines_with(text, name, *children):
    return text.replace("interface %s\n" % name, "interface %s\n%s" % (name, "".join("  %s\n" % line
                                                                                   for line in children)), 1)


# ---- plan adapter on the measured running configuration ----

def test_snapshot_of_the_measured_running_configuration():
    snapshot = nxos.load(BASELINE, FIRMWARE)
    assert snapshot.firmware == "9.3(12)" and snapshot.hostname == "host05"
    assert {"Ethernet1/1", "Ethernet1/48", "mgmt0", "loopback0", "Vlan10"} <= set(snapshot.interfaces)
    assert snapshot.vlans == {"1", "10", "20"}
    assert snapshot.entries("interface")[KEY].attributes == {}
    assert snapshot.interface_lines("Ethernet1/1") == ["switchport mode trunk", "switchport trunk allowed vlan 10,20"]
    assert snapshot.safeguard_names() == []


@pytest.mark.parametrize("text, category", [
    (BASELINE.replace("!Command: show running-config\n", ""), "snapshot unreadable"),
    (BASELINE.split("line console")[0], "snapshot incomplete"),
    (BASELINE.replace("version 9.3(12) Bios:version", "versio"), "snapshot unreadable"),
])
def test_an_incomplete_snapshot_is_refused(text, category):
    with pytest.raises(SnapshotRejected) as caught:
        nxos.load(text, FIRMWARE)
    assert caught.value.category == category


def test_another_release_than_configured_is_refused():
    with pytest.raises(SnapshotRejected) as caught:
        nxos.load(BASELINE, "10.3(4a)")
    assert caught.value.category == "snapshot firmware mismatch"


def test_plan_renders_configure_terminal_lines_and_the_inverse():
    plan = build_plan("nxos", BASELINE.encode(), request(changes={"description": "netops-c6b-test",
                                                                  "admin-state": "disabled"}), firmware=FIRMWARE)
    assert plan["commands"] == ["configure terminal", "interface Ethernet1/48", "shutdown",
                                "description netops-c6b-test", "end"]
    assert plan["inverse"] == ["configure terminal", "interface Ethernet1/48", "no shutdown", "no description", "end"]
    assert plan["predicted"] == {"before": {}, "after": {"description": "netops-c6b-test", "admin-state": "disabled"}}
    assert "WHOLE running configuration" in plan["rollback_evidence"]
    assert "physical Nexus 9000 is not verified" in plan["rollback_evidence"]


def test_access_vlan_plan_and_prediction_verify_ignore_only_the_own_scheduler_blocks():
    plan = build_plan("nxos", BASELINE.encode(), request(table="vlan-membership", changes={"access-vlan": 10}),
                      firmware=FIRMWARE)
    assert plan["commands"] == ["configure terminal", "interface Ethernet1/48", "switchport access vlan 10", "end"]
    assert plan["inverse"] == ["configure terminal", "interface Ethernet1/48", "no switchport access vlan", "end"]
    plan["safeguard_id"] = "ab" * 16
    after = lines_with(BASELINE, KEY, "switchport access vlan 10")
    own = ("scheduler job name netops-abababababab\n  rollback running-config checkpoint netops-abababababab atomic\n"
           "  \nend-job\n\nscheduler schedule name netops-abababababab\n  job name netops-abababababab\n"
           "  time start 2026:11:16:01:12\n")
    assert verify(plan, (after + own).encode())["result"] == "match"
    assert verify(plan, (BASELINE + own).encode(), expect="before")["result"] == "match"
    foreign = own.replace("abababababab", "0123456789ab")
    assert verify(plan, (after + foreign).encode())["rest_matches"] is False
    other = lines_with(after, "Ethernet1/47", "description foreign")
    assert verify(plan, other.encode())["rest_matches"] is False


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": 30}}, "vlan_missing"),
    ({"table": "vlan-membership", "changes": {"access-vlan": 3999}}, "vlan_reserved"),
    ({"key": "mgmt0"}, "port_management_interface"),
    ({"key": "Vlan10"}, "port_unsupported_interface"),
    ({"key": "Ethernet1/1", "changes": {"admin-state": "disabled"}}, "port_uplink"),
    ({"key": "Ethernet1/1", "table": "vlan-membership", "changes": {"access-vlan": 20}}, "port_uplink"),
])
def test_plan_refusals_carry_codes(fields, code):
    with pytest.raises(Rejected) as caught:
        build_plan("nxos", BASELINE.encode(), request(**fields), firmware=FIRMWARE)
    assert caught.value.reason_codes == [code]


def test_description_of_an_uplink_is_allowed_and_a_missing_interface_is_refused():
    plan = build_plan("nxos", BASELINE.encode(), request(key="Ethernet1/1"), firmware=FIRMWARE)
    assert plan["predicted"]["after"] == {"description": "netops-c6b-test"}
    with pytest.raises(Rejected) as caught:
        build_plan("nxos", BASELINE.encode(), request(key="Ethernet1/99"), firmware=FIRMWARE)
    assert "not in the running configuration" in caught.value.reasons[0]


@pytest.mark.parametrize("key, extra, code", [
    ("Ethernet1/1", (), "port_uplink"),
    (KEY, ("channel-group 1 mode active",), "port_lag_member"),
    (KEY, ("no switchport",), "port_routed"),
])
def test_enabling_a_disabled_protected_port_is_refused_in_the_plan(key, extra, code):
    text = lines_with(BASELINE, key, *(extra + ("shutdown",)))
    with pytest.raises(Rejected) as caught:
        build_plan("nxos", text.encode(), request(key=key, changes={"admin-state": "enabled"}), firmware=FIRMWARE)
    assert caught.value.reason_codes == [code]
    plan = build_plan("nxos", text.encode(), request(key=key), firmware=FIRMWARE)
    assert plan["predicted"]["after"]["admin-state"] == "disabled"


# ---- measured answers ----

def test_measured_errors_are_refusals_and_measured_successes_are_not():
    for name in ("switchport-access-vlan__3999-reserved.txt", "switchport-access-vlan__mgmt0-invalid.txt",
                 "switchport-access-vlan__4095-invalid.txt", "interface-ethernet1-99__invalid-range.txt",
                 "no-scheduler-job__schedule-in-progress.txt", "no-scheduler-schedule__schedule-in-progress.txt",
                 "scheduler-job-rollback__checkpoint-missing-invalid.txt",
                 "rollback-checkpoint-atomic__failed-undo-scheduler-job.txt", "ro__show-running-config-denied.txt"):
        assert nxos.cli_error("echo\n" + fixture(name)) is not None, name
    for name in ("checkpoint__done.txt", "no-checkpoint__done.txt", "copy-running-config-startup-config__ok.txt",
                 "copy-running-config-bootflash__ok.txt", "delete-bootflash-no-prompt__ok.txt",
                 "configure-replace__no-timeout-ok.txt", "rollback-checkpoint-atomic__success.txt",
                 "no-scheduler-schedule__pending-ok.txt"):
        assert nxos.cli_error("echo\n" + fixture(name)) is None, name


def test_measured_readback_and_precheck_answers():
    assert nxos.status_row(fixture("show-interface-Eth1-48-status__baseline.txt"), KEY) == {
        "name": "--", "status": "notconnec", "vlan": "1"}
    assert nxos.status_row(fixture("show-interface-Eth1-48-status__ro-desc-shutdown.txt"), KEY)["status"] == "disabled"
    assert nxos.status_row(fixture("show-interface-Eth1-48-status__vlan30-inactive.txt"), KEY)["vlan"] == "30"
    assert nxos.description_row(fixture("show-interface-description__baseline.txt"), KEY) == ""
    assert nxos.description_row(fixture("show-interface-description__baseline.txt"), "Ethernet1/99") is None
    assert nxos.switchport(fixture("show-interface-Eth1-48-switchport__baseline.txt"), KEY) == {
        "switchport": "Enabled", "mode": "access", "access-vlan": "1"}
    assert nxos.trunk_ports(fixture("show-interface-trunk__baseline.txt")) == {"Eth1/1"}
    assert nxos.lldp_ports(fixture("show-lldp-neighbors__baseline.txt")) == {"mgmt0"}
    assert nxos.learned_macs(fixture("show-mac-address-table-interface-Eth1-48__empty.txt")) == 0
    assert nxos.learned_macs(fixture("show-mac-address-table__baseline.txt")) == 11
    assert nxos.vlan_exists(fixture("show-vlan-id-10__baseline.txt"), "10")
    assert not nxos.vlan_exists(fixture("show-vlan-id-30__not-found.txt"), "30")
    assert nxos.users(fixture("show-users.txt")) == (1, 0)
    assert nxos.nxos_version(fixture("show-version.txt")) == "9.3(12)"
    assert nxos.clock(fixture("show-clock__utc-ntp-warning.txt")) == (2026, 11, 16, 1, 4, 39, "UTC")
    assert nxos.feature_state(fixture("show-feature.txt"), "scheduler") == "disabled"
    assert nxos.feature_state(fixture("show-feature-include-scheduler__enabled.txt"), "scheduler") == "enabled"
    assert nxos.feature_state(fixture("show-feature.txt"), "eigrp") == "disabled"


def test_measured_scheduler_checkpoint_and_session_answers():
    pending = exec_nxos.schedule(fixture("show-scheduler-schedule-name__pending.txt"), "netops-c6-2")
    assert pending == {"time": datetime.datetime(2026, 11, 16, 1, 12), "executed": False, "status": "-NA-"}
    fired = exec_nxos.schedule(fixture("show-scheduler-schedule__v3-fired-success.txt"), "netops-c6-5")
    assert fired["executed"] and fired["status"] == "Success (0)"
    assert exec_nxos.schedule(fixture("show-scheduler-schedule-name__not-found-after-v1-run.txt"), "x") is None
    with pytest.raises(Rejected):
        exec_nxos.schedule(fixture("show-scheduler-schedule__v3-fired-success.txt"), "netops-c6-2")
    assert exec_nxos.checkpoints(fixture("show-checkpoint-summary-user__one.txt")) == ["netops-c6-2"]
    assert exec_nxos.checkpoints(fixture("show-checkpoint-summary-user__empty.txt")) == []
    assert exec_nxos.files(fixture("dir-bootflash-include-netops__two.txt")) == ["netops-c6-before.cfg",
                                                                                "netops-c6-cand.cfg"]
    assert exec_nxos.sessions(fixture("show-configuration-session-summary__none.txt")) == []
    assert exec_nxos.sessions(fixture("show-configuration-session-summary__one.txt")) == ["netops-c6-s1"]
    assert not exec_nxos.rollback_running(fixture("show-rollback-log-exec__not-available.txt"))
    assert not exec_nxos.rollback_running(fixture("show-rollback-log-verify__success.txt"))
    scheduler = nxos.load(BASELINE + fixture("show-running-config-section-scheduler__v3-after-fire.txt"), None)
    assert scheduler.safeguard_names() == ["netops-c6-2", "netops-c6-5"]
    assert [minutes for minutes in map(exec_nxos.minutes, (60, 61, 180, 900))] == [2, 3, 4, 16]


def test_the_prompt_anchor_matches_the_carriage_return_before_every_prompt():
    # bytes of the interactive session read on the lab node in task 318 (login banner end and three commands)
    spec = exec_nxos.prompt_spec("host05")
    for data in (b"*  Cisco in writing.   *\r\n****\r\n\rhost05# ", b"end\r\r\n\rhost05# ",
                 b"configure terminal\r\r\nEnter configuration commands, one per line. End with CNTL/Z.\r\n\rhost05(config)# ",
                 b"interface ethernet1/48\r\r\n\rhost05(config-if)# "):
        assert spec.anchor in data and b"\nhost05" not in data
        assert spec.error(data.decode()) is None
    refused = "interface ethernet1/99\r\r\n                                     ^\r\nInvalid range at '^' marker.\rhost05(config)# "
    assert spec.error(refused) == "Invalid range at '^' marker."


def test_refusal_texts_with_a_nonzero_exit_status_are_judged_by_their_text(device):
    status, text = device.query_status("show scheduler schedule name netops-0123456789ab")
    assert status == 1 and exec_nxos._schedule(device, "netops-0123456789ab") is None
    assert exec_nxos.safeguard_disarmed(device, {"change_id": "0123456789ab" + "0" * 20})
    assert not exec_nxos.rollback_running(exec_nxos._read(device, "show rollback log verify"))


# ---- preview, apply, confirm, undo ----

def test_preview_reads_and_writes_nothing(tmp_path, device):
    result = execute.preview(make_runtime(tmp_path, device), "lab-nxos", request())
    assert result["result"] == "ready", result
    assert result["platform"] == "nxos" and result["firmware"] == "9.3(12)"
    assert result["commands"][0] == "configure terminal" and len(result["plan_sha256"]) == 64
    assert device.applied_blocks == [] and device.check_queries


def test_description_is_confirmed_saved_after_the_confirmation_and_undone(tmp_path, device):
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-nxos", request())
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    label = record["safeguard"]["name"]
    assert device.applied_blocks[0] == exec_nxos.install_lines(label, 180)
    assert device.applied_blocks[0][7] == "time start +4"
    assert device.applied_blocks[1] == ["configure terminal", "interface Ethernet1/48",
                                        "description netops-c6b-test", "end"]
    assert device.applied_blocks[2:] == [
        ["configure terminal", "no scheduler schedule name %s" % label, "end"],
        ["configure terminal", "no scheduler job name %s" % label, "end"],
        ["no checkpoint %s" % label], ["delete bootflash:%s-pred.cfg no-prompt" % label],
        ["copy running-config startup-config"]]
    assert device.saves == 1 and device.saved_while_armed == 0 and device.clean()
    assert device.interface(KEY) == ["description netops-c6b-test"]
    assert "check_identity_passed" in steps(record) and steps(record)[-1] == "configuration_saved"
    item = record["safeguard"]
    assert item["fire_at"] == "device scheduler job" and item["own"] == dict.fromkeys(exec_nxos.KINDS, True)
    device_time = datetime.datetime.strptime(item["device_time"], "%Y-%m-%d %H:%M:%S")
    assert device_time == datetime.datetime(2026, 11, 16, 1, 8) and item["phase"] == "installed"
    # the lead the device shows (01:08:00 less the checkpoint at 01:04:39), 1 s and the drift allowance less
    assert item["lead_seconds"] == pytest.approx(200 * 0.98)
    assert "show clock" not in device.queries
    undone = execute.undo(runtime, record["change_id"], "operator asked to undo")
    assert undone["result"] == "confirmed"
    assert device.interface(KEY) == [] and device._config() == device.saved and device.clean()


def test_shutdown_and_no_shutdown(tmp_path, device):
    runtime = make_runtime(tmp_path, device)
    down = execute.apply(runtime, "lab-nxos", request(changes={"admin-state": "disabled"}, request_id="req-down-1"))
    assert down["result"] == "confirmed" and device.interface(KEY) == ["shutdown"]
    up = execute.apply(runtime, "lab-nxos", request(changes={"admin-state": "enabled"}, request_id="req-up-1"))
    assert up["result"] == "confirmed" and device.interface(KEY) == []
    assert device.saves == 2 and device.saved_while_armed == 0
    assert "port Ethernet1/48: 0 learned MAC entries, no LLDP neighbor" in up["plan"]["prechecks"]


def test_access_vlan_is_confirmed_and_undone(tmp_path, device):
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-nxos", request(table="vlan-membership", changes={"access-vlan": 10}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.interface(KEY) == ["switchport access vlan 10"]
    assert "show interface Ethernet1/48 switchport" in device.check_queries
    assert execute.undo(runtime, record["change_id"], "back to VLAN 1")["result"] == "confirmed"
    assert device.interface(KEY) == [] and device.clean()


# ---- immediate return and the timed return ----

def test_lost_check_account_is_returned_at_once_by_configure_replace(tmp_path, device):
    def lose_check_account(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet1/48"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos",
                           request(changes={"description": "netops-c6b-b", "admin-state": "disabled"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    label = record["safeguard"]["name"]
    assert "revert_now_done" in steps(record) and device.replaces == 1
    assert ["configure replace bootflash:%s-pred.cfg" % label] in device.applied_blocks
    assert device.logfile == [] and device.interface(KEY) == [] and device.clean()
    assert device._config() == device.saved and device.saved_while_armed == 0
    assert device.now < datetime.datetime.strptime(record["safeguard"]["device_time"], "%Y-%m-%d %H:%M:%S")


def test_check_account_mismatch_is_returned_at_once(tmp_path, device):
    device.check_override = {}

    def stale(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet1/48"]:
            fake.check_override = {"show interface description": fixture("show-interface-description__baseline.txt")}

    device.on_apply = stale
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos", request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert device.interface(KEY) == [] and device.clean() and device.replaces == 1


def test_a_refused_replace_waits_for_the_job_which_returns_the_change(tmp_path, device):
    device.refuse_replace = True
    device.on_apply = lambda fake, block: setattr(fake, "check_unreadable", block[:2] == [
        "configure terminal", "interface Ethernet1/48"] or fake.check_unreadable)
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos",
                           request(table="vlan-membership", changes={"access-vlan": 10}))
    assert record["result"] == "reverted", (record["reason"], steps(record))
    assert "revert_now_unverified" in steps(record) and "safeguard_removed" in steps(record)
    label = record["safeguard"]["name"]
    assert any("Job Name       : %s " % label in block for block in device.logfile)
    assert device.rollback_log["name"] == label and device.rollback_log["status"] == "Success"
    # the schedule was refused while "in progress" after the run and removed on a later attempt
    attempts = [block for block in device.applied_blocks if block[1:2] == ["no scheduler schedule name %s" % label]]
    assert len(attempts) >= 2
    assert device.interface(KEY) == [] and device.clean() and device._config() == device.saved


def test_enrollment_self_test_waits_for_the_job(tmp_path, device):
    from netops_admin import enrollment

    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "sent"
    runtime.store.clear_enrollment("lab-nxos")
    record = enrollment.run(runtime, "lab-nxos", KEY)
    assert record["result"] == "reverted" and record["reason"] == "enrollment self-test", steps(record)
    assert record["plan"]["predicted"]["after"]["description"].startswith("netops-enroll-")
    assert record.get("enrollment") == "valid", steps(record)
    assert device.replaces == 0 and len(device.logfile) == 1
    assert device.interface(KEY) == [] and device.clean()


def test_interrupted_change_is_recovered_by_the_job(tmp_path, device):
    runtime = make_runtime(tmp_path, device)

    def killed(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet1/48"]:
            fake.on_apply = None
            fake.apply(block, exec_nxos.prompt_spec(fake.hostname))
            raise KeyboardInterrupt

    device.on_apply = killed
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab-nxos", request(changes={"description": "netops-c6b-kill"},
                                                    request_id="req-kill-1"))
    assert device.interface(KEY) == ["description netops-c6b-kill"]
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert [record["result"] for record in settled] == ["reverted"], [steps(record) for record in settled]
    assert settled[0]["reason"] == "interrupted" and device.replaces == 0 and len(device.logfile) == 1
    assert device.interface(KEY) == [] and device.clean() and device._config() == device.saved


def test_interrupted_confirmation_is_recovered_as_confirmed(tmp_path, device):
    runtime = make_runtime(tmp_path, device)

    def killed(fake, block):
        if block[1:2] and block[1].startswith("no scheduler schedule name"):
            fake.on_apply = None
            fake.apply(block, exec_nxos.prompt_spec(fake.hostname))
            raise KeyboardInterrupt

    device.on_apply = killed
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab-nxos", request(request_id="req-kill-2"))
    assert device.checkpoints and not device.schedules
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert [record["result"] for record in settled] == ["confirmed"], [steps(record) for record in settled]
    assert device.interface(KEY) == ["description netops-c6b-test"] and device.clean()
    assert device._config() == device.saved


def test_safeguard_at_another_time_is_removed_before_any_change(tmp_path, device):
    device.time_shift_minutes = 5
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos", request())
    assert record["result"] == "reverted" and record["reason"] == "safeguard not verified"
    assert device.clean() and device.interface(KEY) == []
    assert not any(block[:2] == ["configure terminal", "interface Ethernet1/48"] for block in device.applied_blocks)


def test_a_job_created_after_its_checkpoint_fails_its_rollback():
    # variant 1 of the measurement, which the install order of Admin avoids
    fake = FakeNxos()
    spec = exec_nxos.prompt_spec(fake.hostname)
    fake.apply(["checkpoint netops-v1", "configure terminal", "interface Ethernet1/48", "shutdown", "end"], spec)
    fake.apply(["configure terminal", "scheduler job name netops-v1",
                "rollback running-config checkpoint netops-v1 atomic", "exit", "end"], spec)
    with pytest.raises(Exception):
        fake.apply(["rollback running-config checkpoint netops-v1 atomic"], spec)
    assert fake.interface(KEY) == ["shutdown"]


# ---- refusals before any write ----

@pytest.mark.parametrize("prepare, fields, code", [
    (lambda fake: fake.lldp_extra.append("Eth1/48"), {"changes": {"admin-state": "disabled"}}, "port_lldp_neighbor"),
    (lambda fake: fake.learned_macs.__setitem__(KEY, 2), {"changes": {"admin-state": "disabled"}},
     "port_learned_mac"),
    (lambda fake: fake.trunk_extra.append("Eth1/48"), {"changes": {"admin-state": "disabled"}}, "port_uplink"),
    (lambda fake: fake.trunk_extra.append("Eth1/48"), {"table": "vlan-membership", "changes": {"access-vlan": 10}},
     "port_uplink"),
    (lambda fake: setattr(fake, "scheduler_enabled", False), {}, "scheduler_feature_disabled"),
    (lambda fake: fake.config_sessions.append("operator-work"), {}, "foreign_config_session"),
    (lambda fake: setattr(fake, "rollback_running", True), {}, "rollback_in_progress"),
])
def test_port_in_use_and_switch_state_are_refused_before_any_write(tmp_path, device, prepare, fields, code):
    prepare(device)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-nxos", request(**fields))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == []


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": 30}}, "vlan_missing"),
    ({"key": "mgmt0", "changes": {"description": "x"}}, "port_management_interface"),
    ({"key": "Ethernet1/1", "changes": {"admin-state": "disabled"}}, "port_uplink"),
])
def test_missing_vlan_management_and_trunk_are_refused_with_zero_writes(tmp_path, device, fields, code):
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-nxos", request(**fields))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab-nxos", request(**fields))
    assert device.applied_blocks == []


def test_leftover_unsaved_changes_and_other_firmware_are_refused(tmp_path, device):
    device.checkpoints["netops-0123456789ab"] = device._config()
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), "lab-nxos", request())
    assert "checkpoint netops-0123456789ab" in caught.value.reasons[0]
    device.checkpoints.clear()
    device.body = lines_with("\n".join(device.body) + "\n", "Ethernet1/47", "description foreign").split("\n")[:-1]
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), "lab-nxos", request(request_id="req-unsaved"))
    assert "unsaved configuration changes" in caught.value.reasons[0]
    device.saved = device._config()
    device.firmware = "10.3(4a)"
    with pytest.raises(Rejected):
        execute.apply(make_runtime(tmp_path / "c", device), "lab-nxos", request(request_id="req-firmware"))
    assert device.applied_blocks == []


def test_unexpected_account_blocks_the_device(tmp_path, device):
    runtime = make_runtime(tmp_path, device, accounts=("admin", "user01"))
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-nxos", request())
    assert "accounts differ" in caught.value.reasons[0]
    assert runtime.store.blocked("lab-nxos")["reason"] == "administrator table"


def test_audit_log_holds_no_text_and_no_secret(tmp_path, device):
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-nxos", request(changes={"description": SECRET_TEXT}))
    assert record["result"] == "confirmed"
    log = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET_TEXT not in log and "SECRET-PASSWORD-SENTINEL" not in log
    start = json.loads(log.splitlines()[0])
    assert start["platform"] == "nxos" and start["changes"] == {"description": "text of %d characters"
                                                                 % len(SECRET_TEXT)}
    assert start["safeguard"] == record["safeguard"]["name"]


def test_audit_gate_has_no_nxos_rules_and_refuses_a_policy():
    assert audit_gate.rule_count("nxos") == 0
    assert audit_gate.baseline("nxos", BASELINE, "lab-nxos") == {}
    with pytest.raises(Rejected):
        audit_gate.evaluate("nxos", BASELINE, {"required_rules": []}, "interface")


def test_doctor_is_ready_after_enrollment(tmp_path, device):
    from netops_admin import readiness

    report = readiness.doctor(make_runtime(tmp_path, device), "lab-nxos")
    statuses = {item["check"]: item["status"] for item in report["checks"]}
    assert statuses["check account"] == "ok" and statuses["leftover safeguards"] == "ok"
    assert statuses["device prechecks"] == "ok" and statuses["enrollment"] == "ok", report
    assert report["operations"] == {
        "interface": "update", "vlan-membership": "update", "vlan": "create update delete",
        "static-route": "create update delete", "l3-interface": "create update delete",
        "dhcp-relay": "create update delete",
        "port-bounce": "port-bounce", "port-channel": "create delete", "port-channel-member": "update",
        "vpc-domain": "create update delete", "vpc-peer-link": "update", "vpc-port": "update",
        "ip-access-list": "create update delete", "interface-access-group": "update",
        "ntp-server": "create update delete", "ntp-source": "update",
        "syslog-server": "create update delete", "syslog-source": "update",
        "dns-server": "create update delete", "dns-domain": "update", "startup-config": "save",
    }


def test_doctor_reports_the_missing_scheduler_feature(tmp_path, device):
    from netops_admin import readiness

    device.scheduler_enabled = False
    report = readiness.doctor(make_runtime(tmp_path, device), "lab-nxos")
    prechecks = next(item for item in report["checks"] if item["check"] == "device prechecks")
    assert prechecks["status"] == "refused" and prechecks["reason_codes"] == ["scheduler_feature_disabled"]
    assert report["ready"] is False


# ---- review 318: interrupted installation, ownership, protection of the whole change, recover by state ----

def test_measured_checkpoint_creation_time():
    text = fixture("show-checkpoint-summary-user__one.txt")
    assert exec_nxos.checkpoint_created(text, "netops-c6-2") == datetime.datetime(2026, 11, 16, 1, 10, 16)
    assert exec_nxos.checkpoint_created(text, "netops-c6-3") is None
    assert exec_nxos.checkpoint_created(fixture("show-checkpoint-summary-user__empty.txt"), "netops-c6-2") is None


def killed_before(device, prefix, occurrence=1):
    """The Admin process dies right before the install line starting with prefix (its occurrence) is sent."""
    seen = []

    def kill(fake, step):
        if step.startswith(prefix):
            seen.append(step)
            if len(seen) == occurrence:
                fake.on_line = None
                raise KeyboardInterrupt

    device.on_line = kill


def install_killed(tmp_path, device, prefix, occurrence=1):
    runtime = make_runtime(tmp_path, device)
    killed_before(device, prefix, occurrence)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab-nxos", request(request_id="req-install-kill"))
    record = runtime.store.running("lab-nxos")[0]
    assert "change_start" not in steps(record)
    return record


def test_an_interrupted_installation_left_alone_blocks_the_scheduler(tmp_path, device):
    # the danger of finding 1: the job is armed while its checkpoint is still the placeholder without the job
    record = install_killed(tmp_path, device, "no checkpoint")
    assert record["safeguard"]["phase"] == "armed before the checkpoint holds the job"
    assert record["safeguard"]["own"] == {"checkpoint": True, "job": True, "schedule": True, "file": False}
    device.advance(600)
    assert device.stuck_jobs == {record["safeguard"]["name"]} and device.rollback_log["status"] == "Failed"


def test_recover_removes_the_job_of_an_interrupted_installation_before_it_runs(tmp_path, device):
    """Finding 1: killed between time start and no checkpoint; recover recognises the phase and deletes the own
    schedule first, then the job and the placeholder checkpoint, without waiting for the job."""
    record = install_killed(tmp_path, device, "no checkpoint")
    label = record["safeguard"]["name"]
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert settled[0]["reason"] == "interrupted"
    names = steps(settled[0])
    assert names[names.index("recovery_start"):][:3] == ["recovery_start", "installation_interrupted",
                                                         "safeguard_removed"]
    removal = [block for block in device.applied_blocks if block[1:2] and block[1].startswith("no scheduler")]
    assert removal == [["configure terminal", "no scheduler schedule name %s" % label, "end"],
                       ["configure terminal", "no scheduler job name %s" % label, "end"]]
    assert device.uptime < 60 and device.clean() and device._config() == device.saved
    device.advance(900)
    assert device.logfile == [] and device.stuck_jobs == set() and device.rollback_log is None


def test_recover_blocks_when_snapshot_is_lost_after_safeguard_cleanup(tmp_path, device):
    installed = install_killed(tmp_path, device, "no checkpoint")
    runtime = make_runtime(tmp_path, device)
    writes = len(device.applied_blocks)
    persisted = deepcopy(device.saved)

    def lose_snapshot():
        assert device.clean()
        raise OSError("synthetic private NX-OS diagnostic")

    device.snapshot = lose_snapshot
    record, = execute.recover(runtime, "lab-nxos")

    assert (record["result"], record["reason"]) == ("unknown", "interrupted")
    assert steps(record)[-2:] == ["safeguard_removed", "revert_unverified"]
    assert runtime.store.blocked("lab-nxos")["change_id"] == installed["change_id"]
    label = installed["safeguard"]["name"]
    assert device.applied_blocks[writes:] == [
        ["configure terminal", f"no scheduler schedule name {label}", "end"],
        ["configure terminal", f"no scheduler job name {label}", "end"],
        [f"no checkpoint {label}"],
    ]
    assert device.clean() and device._config() == device.saved == persisted
    assert "synthetic private NX-OS diagnostic" not in repr(runtime.store.records())


@pytest.mark.parametrize("prefix, occurrence, phase", [
    ("configure terminal", 1, "placeholder checkpoint"),
    ("scheduler schedule name", 1, "job created"),
    ("time start", 1, "schedule created"),
    ("end", 1, "armed before the checkpoint holds the job"),
    ("checkpoint", 2, "placeholder checkpoint removed"),
    ("copy running-config bootflash:", 1, "checkpoint holds the job and the schedule"),
])
def test_recover_discards_an_installation_interrupted_in_any_phase(tmp_path, device, prefix, occurrence, phase):
    record = install_killed(tmp_path, device, prefix, occurrence)
    assert record["safeguard"]["phase"] == phase
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert device.clean() and device._config() == device.saved and device.uptime < 60
    device.advance(900)
    assert device.logfile == [] and device.stuck_jobs == set()


def test_recover_after_the_blocked_job_ran_is_unknown_with_the_manual_procedure(tmp_path, device):
    record = install_killed(tmp_path, device, "no checkpoint")
    label = record["safeguard"]["name"]
    device.advance(600)
    runtime = make_runtime(tmp_path, device)
    settled = execute.recover(runtime, "lab-nxos")
    assert settled[0]["result"] == "unknown", steps(settled[0])
    assert settled[0]["reason"] == "interrupted safeguard installation; manual cleanup needed"
    assert steps(settled[0])[-1] == "safeguard_removal_unverified"
    assert "left: checkpoint, job, schedule" in settled[0]["steps"][-1]["detail"]
    manual = settled[0]["safeguard"]["manual_cleanup"]
    assert "no scheduler job name %s" % label in manual and "no feature scheduler" in manual
    assert runtime.store.blocked("lab-nxos") is not None
    assert not any(block == ["configure terminal", "no feature scheduler", "end"] for block in device.applied_blocks)
    assert device.scheduler_enabled is True


def test_an_object_whose_creation_answer_was_lost_is_not_removed(tmp_path, device):
    """Finding 2: the answer of "scheduler schedule name L" never reached Admin, so the schedule is not proven own:
    recover removes the own job and leaves the schedule, the checkpoint (while a schedule exists) and the device
    blocked with the manual procedure."""
    runtime = make_runtime(tmp_path, device)

    def lose_answer(fake, block):
        if block[:1] and block[0].startswith("checkpoint "):
            inner = fake.line_answered

            def answered(number, answer):
                if number == 6:
                    raise KeyboardInterrupt
                inner(number, answer)

            fake.line_answered = answered

    device.on_apply = lose_answer
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab-nxos", request(request_id="req-lost-answer"))
    record = runtime.store.running("lab-nxos")[0]
    label = record["safeguard"]["name"]
    assert record["safeguard"]["own"] == {"checkpoint": True, "job": True, "schedule": False, "file": False}
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert settled[0]["result"] == "unknown", steps(settled[0])
    assert label in device.schedules and label not in device.jobs and label in device.checkpoints
    assert not any(block[1:2] == ["no scheduler schedule name %s" % label] for block in device.applied_blocks)


def test_a_foreign_object_of_the_same_name_before_the_installation_is_left_alone(tmp_path, device):
    """Finding 2: a checkpoint of the same name appears after the prechecks; the installation does not start and
    Admin deletes nothing (the foreign checkpoint stays, the device is blocked)."""
    runtime = make_runtime(tmp_path, device)
    foreign = {}

    def appear(fake, command):
        running = runtime.store.running("lab-nxos") if command == "show checkpoint summary user" else []
        if running and not foreign and "safeguard_install" in steps(running[0]):
            label = exec_nxos.safeguard_label(running[0]["change_id"])
            foreign[label] = fake.checkpoints[label] = fake._config()

    device.on_query = appear
    record = execute.apply(runtime, "lab-nxos", request(request_id="req-foreign"))
    assert foreign, "the foreign checkpoint was not created"
    assert record["result"] == "unknown" and record["reason"] == "safeguard not verified", steps(record)
    assert record["safeguard"]["own"] == dict.fromkeys(exec_nxos.KINDS, False)
    assert device.applied_blocks == [] and set(device.checkpoints) == set(foreign)
    assert runtime.store.blocked("lab-nxos") is not None


def test_a_collision_on_the_first_checkpoint_removes_nothing(tmp_path, device):
    """Finding 2: the name was free, then a checkpoint of the same name appears right before the own checkpoint
    line, which the switch refuses; nothing was created by the own session, so nothing is removed."""
    runtime = make_runtime(tmp_path, device)

    def collide(fake, step):
        if step.startswith("checkpoint netops-"):
            fake.on_line = None
            fake.checkpoints[step.split()[1]] = fake._config()

    device.on_line = collide
    record = execute.apply(runtime, "lab-nxos", request(request_id="req-collision"))
    assert record["result"] == "unknown" and record["reason"] == "safeguard not verified", steps(record)
    assert record["safeguard"]["own"] == dict.fromkeys(exec_nxos.KINDS, False)
    assert len(device.applied_blocks) == 1 and len(device.checkpoints) == 1 and not device.jobs
    assert "safeguard_removal_unverified" in steps(record)


def test_a_slow_installation_leaves_the_change_unwritten(tmp_path, device):
    """Finding 3: too little of the own timer is left on the monotonic clock of Admin before the write; nothing is
    written and the safeguard is removed at once (configure replace of the unchanged state, then the cleanup)."""
    device.on_apply = lambda fake, block: setattr(fake, "line_seconds", 8 if block[:1] and block[0].startswith(
        "checkpoint netops-") else 0)
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos", request())
    assert record["result"] == "reverted" and record["reason"] == "no time left to write", steps(record)
    assert "change_not_written" in steps(record) and "change_start" not in steps(record)
    assert not any(block[:2] == ["configure terminal", "interface Ethernet1/48"] for block in device.applied_blocks)
    assert device.clean() and device.logfile == [] and device._config() == device.saved


def test_a_line_is_not_sent_when_the_job_is_near_and_the_job_returns_the_written_lines(tmp_path, device):
    """Finding 3: every line is sent only while LINE_MARGIN_SECONDS of the own timer are left on the monotonic clock
    of Admin; with too little left for configure replace the job is awaited and returns the lines already written."""
    def slow_lines(fake, block):
        fake.line_seconds = 45 if block[:2] == ["configure terminal", "interface Ethernet1/48"] else 0

    device.on_apply = slow_lines
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos",
                           request(changes={"description": "netops-c6b-slow", "admin-state": "disabled"}))
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    assert device.unsent_lines == 1 and "revert_now_skipped" in steps(record) and device.replaces == 0
    assert len(device.logfile) == 1 and device.rollback_log["status"] == "Success"
    assert device.interface(KEY) == [] and device.clean() and device._config() == device.saved


def test_a_change_left_after_the_job_ran_is_returned_by_configure_replace(tmp_path, device):
    """Finding 3: the immediate return failed, the job ran, but the port is changed again right after the rollback
    (a late line or someone else): the own saved file returns it before the result is given up."""
    device.refuse_replace = True

    def lose_check_account(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet1/48"]:
            fake.check_unreadable = True

    def late_write(fake, name):
        fake._set(KEY, re.compile(r"^shutdown$"), "shutdown")
        fake.refuse_replace = False

    device.on_apply = lose_check_account
    device.on_fire = late_write
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos", request(changes={"admin-state": "disabled"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    names = steps(record)
    assert "revert_now_unverified" in names and "expiry_not_returned" in names and names.count("revert_now_done") == 1
    assert device.replaces == 1 and len(device.logfile) == 1
    assert device.interface(KEY) == [] and device.clean() and device._config() == device.saved


def test_recover_after_the_job_returned_needs_no_device_clock(tmp_path, device):
    """Finding 4: the job returned the change before recover; show clock is refused, recover decides by the state of
    the scheduler at once and never reads the clock."""
    runtime = make_runtime(tmp_path, device)

    def killed(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet1/48"]:
            fake.on_apply = None
            fake.apply(block, exec_nxos.prompt_spec(fake.hostname))
            raise KeyboardInterrupt

    device.on_apply = killed
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab-nxos", request(changes={"description": "netops-c6b-kill"}, request_id="req-kill-4"))
    device.advance(400)
    assert device.interface(KEY) == [] and len(device.logfile) == 1
    device.clock_refused = True
    start = device.uptime
    settled = execute.recover(make_runtime(tmp_path, device), "lab-nxos")
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert "show clock" not in device.queries and device.clean() and device._config() == device.saved
    assert device.uptime - start <= exec_nxos.CLEANUP_LIMIT_SECONDS + execute.EXPIRY_GRACE_SECONDS


def test_the_whole_operation_never_reads_the_device_clock(tmp_path, device):
    device.clock_refused = True
    record = execute.apply(make_runtime(tmp_path, device), "lab-nxos", request())
    assert record["result"] == "confirmed", steps(record)
    assert "show clock" not in device.queries
