"""Arista EOS (cEOSLab 4.36.1F): plan, preview, apply behind the commit-timer safeguard, confirm, expiry, abort,
refusals and audit. The device is FakeEos, whose answers come from measured outputs (fixtures/eos_4_36_1F)."""
from __future__ import annotations

import json

import pytest
from conftest import request_bytes
from fake_eos import FIRMWARE, FakeEos, fixture

from netops_admin import audit_gate, eos, exec_eos, execute
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.request import parse_request

ACCOUNTS = ("admin", "netops-admin", "netops-ro")
SECRET_TEXT = "k7c Eos Vb8Wn"


def make_runtime(tmp_path, device, accounts=ACCOUNTS, firmware=FIRMWARE, protected=None):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"lab-ceos": Device(
            name="lab-ceos", platform="eos", address="192.0.2.53", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=firmware, safeguard_seconds=180, confirm_margin_seconds=45,
            protected=protected or {}, accounts=tuple(accounts),
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance, require_export=False)
    runtime.monotonic = lambda: device.uptime
    return certify(runtime, device, "lab-ceos")


def request(**fields):
    fields.setdefault("table", "interface")
    fields.setdefault("op", "update")
    fields.setdefault("key", "Ethernet10")
    fields.setdefault("changes", {"description": "netops-c7b-test"})
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


BASELINE = fixture("show-running-config__baseline.txt")


# ---- plan adapter on the measured running configuration ----

def test_snapshot_of_the_measured_running_configuration():
    snapshot = eos.load(BASELINE, FIRMWARE)
    assert snapshot.firmware == "4.36.1F" and snapshot.hostname == "host01"
    assert {"Ethernet1", "Ethernet10", "Ethernet15", "Management0", "Loopback0", "Vlan10"} <= set(snapshot.interfaces)
    assert snapshot.vlans == {"1", "10", "20"}
    assert snapshot.entries("interface")["Ethernet10"].attributes == {}
    assert snapshot.interface_lines("Ethernet1") == ["switchport trunk allowed vlan 10,20", "switchport mode trunk"]


def test_exec_answer_of_show_running_config_parses_like_the_session_answer():
    # measured in task 304: ssh exec answers with an empty line, the echo "> show running-config" and the header
    # "! Command: show running-config at line 1"
    exec_text = FakeEos().snapshot()
    assert exec_text.startswith("\n> show running-config\n! Command: show running-config at line 1\n")
    shown, session = eos.load(exec_text, FIRMWARE), eos.load(BASELINE, FIRMWARE)
    assert shown.hostname == session.hostname and set(shown.interfaces) == set(session.interfaces)
    assert shown.rest_digest("interface", "Ethernet10") == session.rest_digest("interface", "Ethernet10")


@pytest.mark.parametrize("text, category", [
    (BASELINE.replace("! Command: show running-config\n", ""), "snapshot unreadable"),
    (BASELINE.rsplit("end", 1)[0], "snapshot incomplete"),
])
def test_an_incomplete_snapshot_is_refused(text, category):
    with pytest.raises(SnapshotRejected) as caught:
        eos.load(text, FIRMWARE)
    assert caught.value.category == category


def test_another_release_than_configured_is_refused():
    with pytest.raises(SnapshotRejected) as caught:
        eos.load(BASELINE, "4.35.0F")
    assert caught.value.category == "snapshot firmware mismatch"


def test_plan_renders_configure_terminal_lines_and_the_inverse():
    plan = build_plan("eos", BASELINE.encode(), request(changes={"description": "netops-c7b-test",
                                                                 "admin-state": "disabled"}), firmware=FIRMWARE)
    assert plan["commands"] == ["configure terminal", "interface Ethernet10", "shutdown",
                                "description netops-c7b-test", "end"]
    assert plan["inverse"] == ["configure terminal", "interface Ethernet10", "no shutdown", "no description", "end"]
    assert plan["predicted"] == {"before": {}, "after": {"description": "netops-c7b-test", "admin-state": "disabled"}}
    assert "WHOLE running configuration" in plan["rollback_evidence"]


def test_access_vlan_plan_and_prediction_verify():
    plan = build_plan("eos", BASELINE.encode(), request(table="vlan-membership", changes={"access-vlan": 10}),
                      firmware=FIRMWARE)
    assert plan["commands"] == ["configure terminal", "interface Ethernet10", "switchport access vlan 10", "end"]
    assert plan["inverse"] == ["configure terminal", "interface Ethernet10", "no switchport access vlan", "end"]
    after = BASELINE.replace("interface Ethernet10\n", "interface Ethernet10\n   switchport access vlan 10\n")
    assert verify(plan, after.encode())["result"] == "match"
    assert verify(plan, BASELINE.encode(), expect="before")["result"] == "match"
    other = after.replace("interface Ethernet11\n", "interface Ethernet11\n   description foreign\n")
    assert verify(plan, other.encode())["rest_matches"] is False


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": 3999}}, "vlan_missing"),
    ({"key": "Management0"}, "port_management_interface"),
    ({"key": "Loopback0"}, "port_unsupported_interface"),
    ({"key": "Ethernet1", "changes": {"admin-state": "disabled"}}, "port_uplink"),
])
def test_plan_refusals_carry_codes(fields, code):
    with pytest.raises(Rejected) as caught:
        build_plan("eos", BASELINE.encode(), request(**fields), firmware=FIRMWARE)
    assert caught.value.reason_codes == [code]


def test_description_of_an_uplink_is_allowed_and_a_missing_interface_is_refused():
    plan = build_plan("eos", BASELINE.encode(), request(key="Ethernet1"), firmware=FIRMWARE)
    assert plan["predicted"]["after"] == {"description": "netops-c7b-test"}
    with pytest.raises(Rejected) as caught:
        build_plan("eos", BASELINE.encode(), request(key="Ethernet99"), firmware=FIRMWARE)
    assert "EOS would create it" in caught.value.reasons[0]


def test_measured_warnings_and_errors_are_refusals():
    for name in ("switchport-access-vlan__nonexistent-3999.txt", "interface-Ethernet99__nonexistent.txt",
                 "commit-timer__rejected-other-pending.txt"):
        assert eos.cli_error("echo\n" + fixture(name)) is not None
    for name in ("write-memory__ok.txt", "configure-session-abort__timer-armed.txt"):
        assert eos.cli_error("echo\n" + fixture(name)) is None


def test_measured_readback_answers():
    assert eos.description_row(fixture("show-interfaces-Ethernet10-description__ro-pending.txt"),
                               "Ethernet10")["description"] == "netops-c7-test"
    assert eos.status_row(fixture("show-interfaces-Ethernet10-status__shutdown.txt"), "Ethernet10") == "disabled"
    assert eos.status_row(fixture("show-interfaces-Ethernet10-status__baseline.txt"), "Ethernet10") == "connected"
    assert eos.switchport(fixture("show-interfaces-Ethernet10-switchport__ro-pending-vlan10.txt"),
                          "Ethernet10") == {"mode": "static access", "access-vlan": "10"}
    assert eos.lldp_ports(fixture("show-lldp-neighbors__baseline.txt")) == {"Et1", "Et2", "Et4", "Et5", "Ma0"}
    assert eos.learned_macs(fixture("show-mac-address-table-interface-Ethernet10__empty.txt")) == 0
    assert eos.vlan_exists(fixture("show-vlan-id-10__baseline.txt"), "10")
    assert not eos.vlan_exists(fixture("show-vlan-id-3999__missing.txt"), "3999")
    assert eos.users(fixture("show-users.txt")) == (1, 0)
    assert eos.privilege(fixture("show-privilege__priv1.txt")) == 1
    assert eos.image_version(fixture("show-version.txt")) == "4.36.1F"


def test_measured_session_states_drive_the_safeguard_checks():
    record = {"change_id": "c7" * 16}
    label = exec_eos.safeguard_label(record["change_id"])

    class Answer:
        def __init__(self, text, log=""):
            self.text, self.log = text.replace("netops-c7-1", label), log

        def query(self, command):
            return self.log if command.startswith("show logging") else self.text

    armed = Answer(fixture("show-configuration-sessions-detail-json__timer-armed.json"))
    assert not exec_eos.safeguard_absent(armed, record) and not exec_eos.safeguard_disarmed(armed, record)
    confirmed = Answer(fixture("show-configuration-sessions-detail-json__confirmed.json"))
    assert exec_eos.safeguard_disarmed(confirmed, record) and not exec_eos.safeguard_absent(confirmed, record)
    log = fixture("show-logging__timer-fired.txt").replace("netops-c7-3", label)
    fired = Answer(fixture("show-configuration-sessions-detail-json__fired.json"), log)
    assert exec_eos.safeguard_fired(fired, record)
    assert not exec_eos.safeguard_fired(Answer(fixture("show-configuration-sessions-detail-json__fired.json")), record)
    assert exec_eos._cleanup_lines(json.loads(armed.text), label) == [
        "configure session %s commit" % label, "no configure session %s" % label]
    leftover = json.loads(fixture("show-configuration-sessions-detail-json__leftover-after-disconnect.json")
                          .replace("netops-c7-9", label))
    assert exec_eos._cleanup_lines(leftover, label) == ["configure session %s abort" % label]


# ---- preview, apply, confirm, undo ----

def test_preview_reads_and_writes_nothing(tmp_path):
    device = FakeEos()
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos", request())
    assert result["result"] == "ready", result
    assert result["platform"] == "eos" and result["firmware"] == "4.36.1F"
    assert result["commands"][0] == "configure terminal" and len(result["plan_sha256"]) == 64
    assert device.applied_blocks == [] and device.check_queries


def test_description_is_confirmed_saved_after_the_confirmation_and_undone(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ceos", request())
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    label = record["safeguard"]["name"]
    assert device.applied_blocks[0] == ["configure session %s" % label, "commit timer 00:03:00"]
    assert device.applied_blocks[1] == ["configure terminal", "interface Ethernet10", "description netops-c7b-test",
                                        "end"]
    assert device.applied_blocks[2] == ["configure session %s commit" % label, "no configure session %s" % label]
    assert device.applied_blocks[3] == ["write memory"]
    assert device.saves == 1 and device.saved_while_pending == 0
    assert device.interface("Ethernet10") == ["description netops-c7b-test"]
    assert device.sessions == {} and device.timer is None
    assert any("COMMIT_TIMER_COMPLETED" in line for line in device.log)
    assert "check_identity_passed" in steps(record) and steps(record)[-1] == "configuration_saved"
    undone = execute.undo(runtime, record["change_id"], "operator asked to undo")
    assert undone["result"] == "confirmed"
    assert device.interface("Ethernet10") == [] and device.lines == device.saved and device.sessions == {}


def test_shutdown_and_no_shutdown(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    down = execute.apply(runtime, "lab-ceos", request(changes={"admin-state": "disabled"}, request_id="req-down-1"))
    assert down["result"] == "confirmed" and device.interface("Ethernet10") == ["shutdown"]
    up = execute.apply(runtime, "lab-ceos", request(changes={"admin-state": "enabled"}, request_id="req-up-1"))
    assert up["result"] == "confirmed" and device.interface("Ethernet10") == []
    assert device.saves == 2 and device.saved_while_pending == 0


def test_access_vlan_is_confirmed_and_undone(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ceos", request(table="vlan-membership", changes={"access-vlan": 10}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.interface("Ethernet10") == ["switchport access vlan 10"]
    assert any("show interfaces Ethernet10 switchport" == query for query in device.check_queries)
    assert execute.undo(runtime, record["change_id"], "back to VLAN 1")["result"] == "confirmed"
    assert device.interface("Ethernet10") == [] and device.vlans() == {"1", "10", "20"}


def test_lost_check_account_leaves_the_change_unconfirmed_and_the_timer_reverts_it(tmp_path):
    device = FakeEos()

    def lose_check_account(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(make_runtime(tmp_path, device), "lab-ceos",
                           request(changes={"description": "netops-c7b-b", "admin-state": "disabled"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    label = record["safeguard"]["name"]
    assert device.interface("Ethernet10") == [] and device.sessions == {} and device.timer is None
    fired = [line for line in device.log if label in line]
    assert any("COMMIT_TIMER_TIMEDOUT" in line for line in fired)
    assert any("COMMIT_REVERTED" in line for line in fired)
    assert not any(block[:1] == ["configure session %s commit" % label] for block in device.applied_blocks)
    assert device.saved_while_pending == 0 and device.lines == device.saved


def test_check_account_mismatch_is_reverted(tmp_path):
    device = FakeEos()
    device.check_override = {}

    def stale(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_override = {"show interfaces Ethernet10 description": fixture(
                "show-interfaces-Ethernet10-description__baseline.txt")}

    device.on_apply = stale
    record = execute.apply(make_runtime(tmp_path, device), "lab-ceos", request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert device.interface("Ethernet10") == []


def test_refused_commit_timer_aborts_the_uncommitted_session(tmp_path):
    device = FakeEos()
    device.refuse_commit_timer = True
    record = execute.apply(make_runtime(tmp_path, device), "lab-ceos", request())
    assert record["result"] == "reverted" and record["reason"] == "safeguard not verified"
    label = record["safeguard"]["name"]
    assert device.applied_blocks[-2] == ["configure session %s abort" % label]
    assert device.sessions == {} and device.interface("Ethernet10") == []
    assert not any(block[:1] == ["configure terminal"] for block in device.applied_blocks)


def test_timer_at_another_time_is_confirmed_away_before_any_change(tmp_path):
    device = FakeEos()
    device.timer_shift = 120
    record = execute.apply(make_runtime(tmp_path, device), "lab-ceos", request())
    assert record["result"] == "reverted" and record["reason"] == "safeguard not verified"
    assert device.sessions == {} and device.timer is None
    assert not any(block[:1] == ["configure terminal"] for block in device.applied_blocks)


def test_abort_during_the_pending_timer_returns_at_once():
    device = FakeEos()
    device.apply(["configure session netops-0123456789ab", "commit timer 00:03:00"], exec_eos.prompt_spec("host01"))
    device.apply(["configure terminal", "interface Ethernet10", "shutdown", "end"], exec_eos.prompt_spec("host01"))
    assert device.interface("Ethernet10") == ["shutdown"]
    device.apply(["configure session netops-0123456789ab abort"], exec_eos.prompt_spec("host01"))
    assert device.interface("Ethernet10") == [] and device.sessions == {} and device.timer is None


@pytest.mark.parametrize("prepare, code", [
    (lambda fake: setattr(fake, "lldp_extra", ["Et10"]), "port_lldp_neighbor"),
    (lambda fake: fake.learned_macs.__setitem__("Ethernet10", 2), "port_learned_mac"),
])
def test_port_in_use_is_refused_before_any_write(tmp_path, prepare, code):
    device = FakeEos()
    prepare(device)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ceos", request(changes={"admin-state": "disabled"}))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == []


# ---- task 304-r2: admin up gets the same port checks as admin down ----

def _shut(text: str, name: str, extra: str = "") -> str:
    return text.replace("interface %s\n" % name, "interface %s\n%s   shutdown\n" % (name, extra), 1)


@pytest.mark.parametrize("key, extra, code", [
    ("Ethernet1", "", "port_uplink"),
    ("Ethernet10", "   channel-group 1 mode active\n", "port_lag_member"),
    ("Ethernet10", "   no switchport\n", "port_routed"),
])
def test_enabling_a_disabled_protected_port_is_refused_in_the_plan(key, extra, code):
    text = _shut(BASELINE, key, extra)
    assert "shutdown" in eos.load(text, FIRMWARE).interface_lines(key)
    with pytest.raises(Rejected) as caught:
        build_plan("eos", text.encode(), request(key=key, changes={"admin-state": "enabled"}), firmware=FIRMWARE)
    assert caught.value.reason_codes == [code]
    # the description alone keeps working on such a port
    plan = build_plan("eos", text.encode(), request(key=key), firmware=FIRMWARE)
    assert plan["predicted"]["after"] == {"description": "netops-c7b-test", "admin-state": "disabled"}


def test_disruptive_covers_the_admin_state_in_both_directions():
    assert eos.disruptive("interface", {}, {"admin-state": "disabled"})
    assert eos.disruptive("interface", {"admin-state": "disabled"}, {})
    assert eos.disruptive("interface", {"admin-state": "disabled"}, {"admin-state": "enabled"})
    assert not eos.disruptive("interface", {}, {"description": "x"})
    assert not eos.disruptive("interface", {"admin-state": "disabled"}, {"admin-state": "disabled",
                                                                          "description": "x"})


def _shut_device(device, name, extra=()):
    start = device.lines.index("interface %s" % name)
    device.lines[start + 1:start + 1] = ["   " + line for line in extra] + ["   shutdown"]
    device.saved = list(device.lines)


@pytest.mark.parametrize("key, extra, code", [
    ("Ethernet1", (), "port_uplink"),
    ("Ethernet10", ("channel-group 1 mode active",), "port_lag_member"),
])
def test_enabling_a_disabled_trunk_or_lag_member_is_refused_before_any_write(tmp_path, key, extra, code):
    device = FakeEos()
    _shut_device(device, key, extra)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", request(key=key, changes={"admin-state": "enabled"}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-ceos", request(key=key, changes={"admin-state": "enabled"}))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == [] and "shutdown" in device.interface(key)


@pytest.mark.parametrize("prepare, code", [
    (lambda fake: setattr(fake, "lldp_extra", ["Et10"]), "port_lldp_neighbor"),
    (lambda fake: fake.learned_macs.__setitem__("Ethernet10", 2), "port_learned_mac"),
])
def test_enabling_a_disabled_port_in_use_is_refused_before_any_write(tmp_path, prepare, code):
    device = FakeEos()
    _shut_device(device, "Ethernet10")
    prepare(device)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ceos", request(changes={"admin-state": "enabled"}))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == [] and device.interface("Ethernet10") == ["shutdown"]


def test_enabling_a_disabled_access_port_is_confirmed(tmp_path):
    device = FakeEos()
    _shut_device(device, "Ethernet10")
    record = execute.apply(make_runtime(tmp_path, device), "lab-ceos", request(changes={"admin-state": "enabled"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.interface("Ethernet10") == [] and device.lines == device.saved
    assert "port Ethernet10 has no LLDP neighbor and no learned MAC address" in record["plan"]["prechecks"]


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": 3999}}, "vlan_missing"),
    ({"key": "Management0", "changes": {"description": "x"}}, "port_management_interface"),
])
def test_missing_vlan_and_management_are_refused_with_zero_writes(tmp_path, fields, code):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", request(**fields))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab-ceos", request(**fields))
    assert device.applied_blocks == [] and "vlan 3999" not in device.lines


def test_foreign_pending_session_and_foreign_timer_are_refused(tmp_path):
    device = FakeEos()
    device.sessions["operator-work"] = {"state": "pending", "user": "admin"}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), "lab-ceos", request())
    assert caught.value.reason_codes == ["foreign_config_session"]
    device.sessions["operator-work"]["state"] = "committed"
    device.timer = {"name": "operator-work", "checkpoint": list(device.lines), "expire": device.epoch + 600}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), "lab-ceos", request(request_id="req-foreign-2"))
    assert caught.value.reason_codes == ["foreign_config_session"]
    assert device.applied_blocks == []


def test_own_leftover_session_is_refused(tmp_path):
    device = FakeEos()
    device.sessions["netops-0123456789ab"] = {"state": "pending", "user": ""}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ceos", request())
    assert "netops-0123456789ab" in caught.value.reasons[0] and device.applied_blocks == []


def test_privilege_1_and_unsaved_changes_are_refused(tmp_path):
    device = FakeEos()
    device.privilege = 1
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), "lab-ceos", request())
    assert caught.value.reason_codes == ["write_account_privilege"]
    device = FakeEos()
    device.saved = device.saved[:-2] + ["end"]
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), "lab-ceos", request())
    assert "unsaved configuration changes" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unexpected_account_blocks_the_device(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device, accounts=("admin", "netops-admin"))
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-ceos", request())
    assert "accounts differ" in caught.value.reasons[0]
    assert runtime.store.blocked("lab-ceos")["reason"] == "administrator table"


def test_audit_log_holds_no_text_and_no_secret(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ceos", request(changes={"description": SECRET_TEXT}))
    assert record["result"] == "confirmed"
    log = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET_TEXT not in log and "REDIGOVANO" not in log and "sha512" not in log
    start = json.loads(log.splitlines()[0])
    assert start["platform"] == "eos" and start["changes"] == {"description": "text of %d characters"
                                                                % len(SECRET_TEXT)}
    assert start["safeguard"] == record["safeguard"]["name"]


def test_audit_gate_has_no_eos_rules_and_refuses_a_policy():
    assert audit_gate.rule_count("eos") == 0
    assert audit_gate.baseline("eos", BASELINE, "lab-ceos") == {}
    with pytest.raises(Rejected):
        audit_gate.evaluate("eos", BASELINE, {"required_rules": []}, "interface")


def test_enrollment_self_test_changes_the_description_and_is_reverted(tmp_path):
    from netops_admin import enrollment

    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "sent"
    runtime.store.clear_enrollment("lab-ceos")
    record = enrollment.run(runtime, "lab-ceos", "Ethernet10")
    assert record["result"] == "reverted" and record["reason"] == "enrollment self-test"
    assert record["plan"]["predicted"]["after"]["description"].startswith("netops-enroll-")
    assert record.get("enrollment") == "valid", steps(record)
    assert device.interface("Ethernet10") == [] and device.sessions == {}


def test_doctor_is_ready_after_enrollment(tmp_path):
    from netops_admin import readiness

    device = FakeEos()
    report = readiness.doctor(make_runtime(tmp_path, device), "lab-ceos")
    statuses = {item["check"]: item["status"] for item in report["checks"]}
    assert statuses["check account"] == "ok" and statuses["leftover safeguards"] == "ok"
    assert statuses["device prechecks"] == "ok" and statuses["enrollment"] == "ok", report
    # 1.0.12 G123: the EOS port bounce and PoE cycle are operations of their own tables
    assert report["operations"] == {"interface": "update", "vlan-membership": "update", "vlan": "create update delete",
                                    "port-bounce": "port-bounce", "inline-power": "poe-cycle",
                                    "static-route": "create update delete", "l3-interface": "create update delete",
                                    "ip-routing": "update", "vrrp": "create update delete",
                                    "varp": "create update delete", "varp-mac": "update",
                                    "ip-access-list": "create update delete", "interface-access-group": "update",
                                    "port-channel": "create update delete", "port-channel-member": "update",
                                    "mlag-port": "update", "mlag-peer": "update", "stp-port": "update", "stp-vlan": "update",
                                    "ospf-process": "create delete", "ospf-network": "create update delete",
                                    "ospf-interface": "update", "ip-prefix-list": "create update delete",
                                    "route-map": "create update delete", "bgp-neighbor": "create update delete",
                                    "dhcp-pool": "create update delete", "dhcp-relay": "create update delete",
                                    "ntp-server": "create update delete", "syslog-host": "create delete",
                                    "dns-server": "create update delete", "system-services": "update", "startup-config": "save"}
