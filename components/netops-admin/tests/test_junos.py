"""Juniper Junos ELS (vJunos-switch 26.2R1.7): plan, preview, apply behind the commit confirmed safeguard, timer
restart by the change commit, confirmation, expiry, refusals, recovery and audit. The device is FakeJunos, whose
answers come from measured outputs (fixtures/junos_26_2R1_7)."""
from __future__ import annotations

import datetime
import json

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos, fixture

from netops_admin import audit_gate, config as config_module, exec_junos, execute, junos
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.request import parse_request

ACCOUNTS = ("netops-admin", "netops-ro")
SECRET_TEXT = "k7c Junos Vb8Wn"
NAME = "lab-vjunos"


def make_runtime(tmp_path, device, accounts=ACCOUNTS, firmware=FIRMWARE, protected=None, margin=300):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={NAME: Device(
            name=NAME, platform="junos", address="192.0.2.56", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=firmware, safeguard_seconds=600, confirm_margin_seconds=margin,
            protected=protected or {}, accounts=tuple(accounts),
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance, require_export=False)
    runtime.monotonic = lambda: device.uptime
    return certify(runtime, device, NAME)


def request(**fields):
    fields.setdefault("table", "interface")
    fields.setdefault("op", "update")
    fields.setdefault("key", "ge-0/0/2")
    fields.setdefault("changes", {"description": "netops-c8b-test"})
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


SCREEN, ENTER, EMPTY, COMPARE, LEAVE = junos.SCREEN, junos.ENTER, junos.COMPARE_EMPTY, junos.COMPARE, junos.LEAVE
CHANGE = 'commit confirmed 10 comment "netops-change"'
PROBE = [SCREEN, "configure", LEAVE]


# ---- plan adapter on the set-format configuration ----

def test_snapshot_of_the_lab_configuration():
    snapshot = junos.load(BASELINE, FIRMWARE)
    assert snapshot.firmware == "26.2R1.7" and snapshot.hostname == "host01"
    assert {"ge-0/0/0", "ge-0/0/1", "ge-0/0/2", "fxp0", "irb", "lo0"} <= set(snapshot.interfaces)
    assert snapshot.vlans == {"default", "D10", "D20"}
    entries = snapshot.entries("vlan-membership")
    assert entries["ge-0/0/2"].attributes == {"access-vlan": "default"}
    assert entries["ge-0/0/1"].attributes == {"access-vlan": "D20"}
    # 1.0.12 G137 (J07): a trunk lists its mode and tagged VLANs instead of nothing
    assert entries["ge-0/0/0"].attributes == {"mode": "trunk", "trunk-vlans": "D10 D20"}
    assert entries["ge-0/0/0"].unsupported == []
    assert snapshot.entries("interface")["ge-0/0/2"].attributes == {}


@pytest.mark.parametrize("text, category", [
    (BASELINE.replace("set version 26.2R1.7\n", ""), "snapshot unreadable"),
    (BASELINE.rstrip("\n"), "snapshot incomplete"),
    ("\nerror: syntax error, expecting <command>: bogus-command\n", "snapshot unreadable"),
    (BASELINE + "edit interfaces\n", "snapshot unreadable"),
])
def test_an_unreadable_or_cut_snapshot_is_refused(text, category):
    with pytest.raises(SnapshotRejected) as caught:
        junos.load(text, FIRMWARE)
    assert caught.value.category == category


def test_another_release_than_configured_is_refused():
    with pytest.raises(SnapshotRejected) as caught:
        junos.load(BASELINE, "25.4R1.12")
    assert caught.value.category == "snapshot firmware mismatch"


def test_quoted_description_and_disable_are_read():
    text = BASELINE + 'set interfaces ge-0/0/3 description "netops c8 a"\nset interfaces ge-0/0/3 disable\n'
    entry = junos.load(text, FIRMWARE).entries("interface")["ge-0/0/3"]
    assert entry.attributes == {"description": "netops c8 a", "admin-state": "disabled"} and not entry.unsupported


def test_plan_renders_the_interactive_lines_and_the_inverse():
    plan = build_plan("junos", BASELINE.encode(), request(changes={"description": "netops c8b",
                                                                   "admin-state": "disabled"}), firmware=FIRMWARE)
    assert plan["commands"] == [SCREEN, ENTER, EMPTY, "set interfaces ge-0/0/2 disable",
                                'set interfaces ge-0/0/2 description "netops c8b"', COMPARE, CHANGE, LEAVE]
    assert plan["inverse"] == [SCREEN, ENTER, EMPTY, "delete interfaces ge-0/0/2 disable",
                               "delete interfaces ge-0/0/2 description", COMPARE, CHANGE, LEAVE]
    assert plan["predicted"] == {"before": {}, "after": {"description": "netops c8b", "admin-state": "disabled"}}
    assert "commit check" not in " ".join(plan["commands"]) and "rollback" not in " ".join(plan["commands"])
    assert "root via other" in plan["rollback_evidence"]


def test_access_vlan_plan_deletes_the_member_before_it_sets_the_new_one():
    plan = build_plan("junos", BASELINE.encode(), request(table="vlan-membership", changes={"access-vlan": "D10"}),
                      firmware=FIRMWARE)
    members = "interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members"
    assert plan["commands"] == [SCREEN, ENTER, EMPTY, "delete " + members, "set %s D10" % members, COMPARE, CHANGE, LEAVE]
    assert plan["inverse"][3:5] == ["delete " + members, "set %s default" % members]
    assert plan["predicted"] == {"before": {"access-vlan": "default"}, "after": {"access-vlan": "D10"}}
    after = BASELINE.replace("vlan members default", "vlan members D10")
    assert verify(plan, after.encode())["result"] == "match"
    assert verify(plan, BASELINE.encode(), expect="before")["result"] == "match"
    other = after.replace("set vlans D20 vlan-id 20\n", "set vlans D20 vlan-id 20\nset vlans D30 vlan-id 30\n")
    assert verify(plan, other.encode())["rest_matches"] is False


def test_an_unconfigured_port_is_an_implicit_key():
    plan = build_plan("junos", BASELINE.encode(), request(key="ge-0/0/5"), firmware=FIRMWARE)
    assert plan["predicted"] == {"before": {}, "after": {"description": "netops-c8b-test"}}
    after = BASELINE + "set interfaces ge-0/0/5 description netops-c8b-test\n"
    assert verify(plan, after.encode())["result"] == "match"


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": "D3999"}}, "vlan_missing"),
    ({"key": "fxp0"}, "port_management_interface"),
    ({"key": "em0"}, "port_management_interface"),
    ({"key": "lo0"}, "port_unsupported_interface"),
    ({"key": "ge-0/0/0", "changes": {"admin-state": "disabled"}}, "port_uplink"),
    ({"key": "ge-0/0/5", "table": "vlan-membership", "changes": {"access-vlan": "D20"}}, "port_not_access"),
])
def test_plan_refusals_carry_codes(fields, code):
    with pytest.raises(Rejected) as caught:
        build_plan("junos", BASELINE.encode(), request(**fields), firmware=FIRMWARE)
    assert caught.value.reason_codes == [code]


def test_lag_member_and_routed_port_are_refused_for_a_disruptive_change():
    lag = BASELINE + "set interfaces ge-0/0/4 ether-options 802.3ad ae0\n"
    with pytest.raises(Rejected) as caught:
        build_plan("junos", lag.encode(), request(key="ge-0/0/4", changes={"admin-state": "disabled"}),
                   firmware=FIRMWARE)
    assert caught.value.reason_codes == ["port_lag_member"]
    routed = BASELINE + "set interfaces ge-0/0/4 unit 0 family inet address 192.0.2.9/24\n"
    with pytest.raises(Rejected) as caught:
        build_plan("junos", routed.encode(), request(key="ge-0/0/4", changes={"admin-state": "disabled"}),
                   firmware=FIRMWARE)
    assert caught.value.reason_codes == ["port_routed"]
    # the description alone keeps working on such a port
    assert build_plan("junos", lag.encode(), request(key="ge-0/0/4"), firmware=FIRMWARE)["commands"]


def test_enabling_a_disabled_trunk_is_refused_in_the_plan():
    text = BASELINE + "set interfaces ge-0/0/0 disable\n"
    with pytest.raises(Rejected) as caught:
        build_plan("junos", text.encode(), request(key="ge-0/0/0", changes={"admin-state": "enabled"}),
                   firmware=FIRMWARE)
    assert caught.value.reason_codes == ["port_uplink"]


def test_shared_configuration_of_the_port_is_outside_the_profile():
    # 1.0.12 G137 (JP12): an inherited description, a deactivated statement and apply-groups-except are refused;
    # inheritance that does not touch the description (an empty interface-range, a group that is not applied)
    # no longer blocks the description of the port
    for extra in ("set interfaces interface-range access member ge-0/0/2\n"
                  "set interfaces interface-range access description x\n",
                  "set groups lab interfaces <ge-*> description x\nset apply-groups lab\n",
                  "set groups lab interfaces ge-0/0/2 description x\nset interfaces ge-0/0/2 apply-groups-except lab\n",
                  "deactivate interfaces ge-0/0/2 unit 0\n"):
        with pytest.raises(Rejected) as caught:
            build_plan("junos", (BASELINE + extra).encode(), request(), firmware=FIRMWARE)
        assert "outside the profile" in caught.value.reasons[0], extra
    for extra in ("set interfaces interface-range access member ge-0/0/2\n",
                  "set groups lab interfaces <ge-*> description x\n"):
        assert build_plan("junos", (BASELINE + extra).encode(), request(), firmware=FIRMWARE)["commands"]


@pytest.mark.parametrize("value", ['a"b', "a\\b", "a?b", "  lead", "x" * 241, "a\tb", "a\u00a0b", "end "])
def test_a_description_that_the_cli_would_read_differently_is_refused(value):
    with pytest.raises(Rejected):
        build_plan("junos", BASELINE.encode(), request(changes={"description": value}), firmware=FIRMWARE)


# ---- measured answers ----

def _line(echo, name):
    return "%s\n%s\n[edit]\nnetops-admin@host01# " % (echo, fixture(name))


@pytest.mark.parametrize("echo, name", [
    ("set interfaces ge-0/0/2 bogus", "set-bogus__syntax-error.txt"),
    ('commit confirmed 10 comment "netops-change"', "commit-check__vlan-D3999-does-not-exist.txt"),
    ('commit comment "netops-x"', "commit-private__conflict-not-committed.txt"),
    ('commit confirmed 1 comment "x"', "commit-confirmed__private-not-supported.txt"),
    ("configure", "configure__foreign-exclusive-uncommitted-shared-candidate.txt"),
    ("configure exclusive", "configure-exclusive__foreign-private-uncommitted.txt"),
    ("configure private", "configure-private__foreign-exclusive-warning.txt"),
    (junos.COMPARE_EMPTY, "show-compare__desc-a2-D10.txt"),
    ('set interfaces ge-0/0/2 description netops c8bez', "set-description-unquoted-spaces__syntax-error.txt"),
])
def test_measured_refusals_are_errors(echo, name):
    assert junos.cli_error(_line(echo, name)) is not None


@pytest.mark.parametrize("echo, name", [
    ("configure exclusive", "configure-exclusive__enter.txt"),
    ('commit confirmed 3 comment "netops-0123456789ab"', "commit-confirmed-3__empty-safeguard.txt"),
    ('commit comment "netops-0123456789ab-ok"', "commit-comment__confirm.txt"),
    ("set interfaces ge-0/0/2 disable", "set__ok-empty.txt"),
    ("delete interfaces ge-0/0/2 disable", "delete__ok-empty.txt"),
    (junos.LEAVE, "exit__pending-banner.txt"),
    (junos.COMPARE, "show-compare__desc-a2-D10.txt"),
    (junos.COMPARE_EMPTY, "show-compare__empty-pending.txt"),
])
def test_measured_successes_are_not_errors(echo, name):
    assert junos.cli_error(_line(echo, name)) is None


def test_the_screen_width_line_must_be_confirmed_and_long_lines_keep_one_echo():
    assert junos.cli_error("set cli screen-width 1024\nScreen width set to 1024\n\nnetops-admin@host01> ") is None
    assert junos.cli_error("set cli screen-width 1024\n\nnetops-admin@host01> ") is not None
    plan = build_plan("junos", BASELINE.encode(), request(table="vlan-membership", changes={"access-vlan": "D10"}),
                      firmware=FIRMWARE)
    assert plan["commands"][0] == SCREEN and max(len(line) for line in plan["commands"]) < 1000


def test_a_missing_statement_is_no_error_only_for_delete():
    assert junos.cli_error("delete interfaces ge-0/0/2 disable\nwarning: statement not found\n[edit]\nx@h# ") is None
    assert junos.cli_error("set interfaces ge-0/0/2 disable\nwarning: statement not found\n[edit]\nx@h# ") is not None
    assert junos.cli_error("configure\n\n[edit]\nx@h# ") is not None


def test_measured_readback_answers():
    assert junos.description_of(fixture("show-interfaces-descriptions__ro-pending-desc-a2.txt"),
                                "ge-0/0/2") == "netops-c8-a2"
    assert junos.description_of(fixture("show-interfaces-descriptions__empty.txt"), "ge-0/0/2") == ""
    assert junos.interface_row(fixture("show-interfaces-ge-0-0-2-terse__ro-disabled-pending.txt"),
                               "ge-0/0/2") == {"admin": "down", "link": "down"}
    assert junos.interface_row(fixture("show-interfaces-em0-terse__not-found.txt"), "em0") is None
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__access-D10.txt"),
                           "ge-0/0/2") == [("D10", "untagged")]
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__access-default.txt"),
                           "ge-0/0/2") == [("default", "untagged")]
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__unconfigured-empty.txt"),
                           "ge-0/0/2") is None
    assert junos.vlan_exists(fixture("show-vlans-D10__baseline.txt"), "D10")
    assert not junos.vlan_exists(fixture("show-vlans-D3999__missing-empty.txt"), "D3999")
    assert junos.lldp_ports(fixture("show-lldp-neighbors__baseline.txt")) == {"ge-0/0/0"}
    assert junos.learned_macs(fixture("show-ethernet-switching-table-interface-ge-0-0-2__empty.txt"), "ge-0/0/2") == 0
    assert junos.users(fixture("show-system-users__admin-plus-console-ro.txt")) == 2
    login, klass, permissions = junos.authorization(fixture("show-cli-authorization__admin-super-user.txt"))
    assert (login, klass) == ("netops-admin", "super-user") and {"configure", "view-configuration"} <= permissions
    assert junos.authorization(fixture("show-cli-authorization__ro-read-only.txt"))[2] == {"view"}
    assert junos.running_version(fixture("show-version-match__hostname-model-junos.txt")) == "26.2R1.7"


def test_measured_commit_histories():
    pending = junos.commits(fixture("show-system-commit__pending-1min.txt"))
    assert pending[0].pending and pending[0].comment == "netops-c8-a2" and pending[0].minutes == 1
    assert pending[0].at == "2026-11-16 01:43:19" and not any(commit.pending for commit in pending[1:])
    fired = junos.commits(fixture("show-system-commit__after-auto-rollback.txt"))
    assert (fired[0].user, fired[0].via, fired[0].comment) == ("root", "other", None)
    assert fired[1].comment == "netops-c8-b" and fired[1].confirmed and not fired[1].pending
    two = junos.commits(fixture("show-system-commit-match__two-confirmed-pending.txt"))
    assert two[0].pending and two[0].comment is None and two[1].confirmed and not two[1].pending
    assert junos.commits(fixture("show-system-commit__ro-pending.txt"))[0].pending


def test_measured_histories_drive_the_safeguard_checks():
    record = {"change_id": "c8" * 16}
    label = exec_junos.safeguard_label(record["change_id"])

    class Answer:
        def __init__(self, text):
            self.text = text

        def query(self, command):
            assert command == exec_junos.QUERY_COMMITS
            return self.text

    armed = Answer(fixture("show-system-commit__pending-1min.txt").replace("netops-c8-a2", label))
    assert not exec_junos.safeguard_absent(armed, record) and not exec_junos.safeguard_fired(armed, record)
    assert exec_junos.leftovers(armed) == [label]
    fired = Answer(fixture("show-system-commit__after-auto-rollback.txt").replace("netops-c8-b", label))
    assert exec_junos.safeguard_fired(fired, record) and exec_junos.safeguard_absent(fired, record)
    assert not exec_junos.safeguard_disarmed(fired, record)
    confirmed = Answer(fixture("show-system-commit__confirmed-with-comment.txt").replace(
        "netops-c8-undo", label).replace("netops-c8-confirm-undo", label + "-ok"))
    assert exec_junos.safeguard_disarmed(confirmed, record) and not exec_junos.safeguard_fired(confirmed, record)
    assert exec_junos.leftovers(Answer(fixture("show-system-commit__baseline.txt"))) == []


# ---- preview, apply, confirm, undo ----

def test_preview_writes_nothing_and_only_enters_the_shared_configuration_mode(tmp_path):
    device = FakeJunos()
    result = execute.preview(make_runtime(tmp_path, device), NAME, request())
    assert result["result"] == "ready", result
    assert result["platform"] == "junos" and result["firmware"] == "26.2R1.7" and result["safeguard_seconds"] == 600
    assert result["commands"][-2] == CHANGE and len(result["plan_sha256"]) == 64
    assert device.applied_blocks == [PROBE] and device.check_queries
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


def test_description_is_confirmed_and_undone(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request(changes={"description": "netops c8b"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    label = record["safeguard"]["name"]
    assert device.applied_blocks[1] == [SCREEN, ENTER, EMPTY, 'commit confirmed 10 comment "%s"' % label, LEAVE]
    assert device.applied_blocks[2] == [SCREEN, ENTER, EMPTY, 'set interfaces ge-0/0/2 description "netops c8b"', COMPARE,
                                        CHANGE, LEAVE]
    assert device.applied_blocks[3] == [SCREEN, ENTER, EMPTY, 'commit comment "%s-ok"' % label, LEAVE]
    assert device.interface("ge-0/0/2")[0] == 'description "netops c8b"' and not device.pending()
    assert [item["comment"] for item in device.history[:3]] == [label + "-ok", "netops-change", label]
    assert "safeguard_rearmed" in steps(record) and "check_identity_passed" in steps(record)
    assert "configuration_saved" not in steps(record)
    rearmed = next(step for step in record["steps"] if step["step"] == "safeguard_rearmed")
    assert rearmed["detail"] == record["safeguard"]["device_expiry"]
    assert record["safeguard"]["fire_at"] == exec_junos.FIRE_AT_TEXT and record["safeguard"]["verified"] is True
    assert record["safeguard"]["head"]["comment"] == "netops-change"
    assert record["safeguard"]["commit"]["comment"] == label
    undone = execute.undo(runtime, record["change_id"], "operator asked to undo")
    assert undone["result"] == "confirmed", (undone["reason"], steps(undone))
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


def test_disable_and_enable(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    down = execute.apply(runtime, NAME, request(changes={"admin-state": "disabled"}, request_id="req-down-1"))
    assert down["result"] == "confirmed" and "disable" in device.interface("ge-0/0/2")
    assert "port ge-0/0/2 has no LLDP neighbor and no learned MAC address" in down["plan"]["prechecks"]
    up = execute.apply(runtime, NAME, request(changes={"admin-state": "enabled"}, request_id="req-up-1"))
    assert up["result"] == "confirmed" and "disable" not in device.interface("ge-0/0/2")
    assert "delete interfaces ge-0/0/2 disable" in device.applied_blocks[-2]


def test_access_vlan_is_confirmed_and_undone(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request(table="vlan-membership", changes={"access-vlan": "D10"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert "unit 0 family ethernet-switching vlan members D10" in device.interface("ge-0/0/2")
    assert "show ethernet-switching interface ge-0/0/2" in device.check_queries
    assert "VLAN D10 exists; port ge-0/0/2 is an access port" in record["plan"]["prechecks"]
    assert execute.undo(runtime, record["change_id"], "back to VLAN default")["result"] == "confirmed"
    assert device.lines == BASELINE.rstrip("\n").split("\n")


def test_lost_check_account_is_returned_at_once_by_the_inverse_under_the_timer(tmp_path):
    # review pattern 3: a failed readback is returned at once while the own timer is pending, not after the expiry:
    # the inverse set/delete lines are committed with a plain commit, which ends the own timer and keeps the inverse
    # (task 378: an inverse committed with commit confirmed is undone by the expiry), then a fresh snapshot proves
    # the state before
    device = FakeJunos()

    def lose_check_account(fake, block):
        if CHANGE in block:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(make_runtime(tmp_path, device), NAME,
                           request(changes={"description": "netops-c8b-b", "admin-state": "disabled"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    label = record["safeguard"]["name"]
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    assert [item["comment"] for item in device.history[:3]] == [label + "-revert", "netops-change", label]
    assert device.history[0]["minutes"] is None and not device.history[0]["pending"]
    assert device.applied_blocks[3] == [SCREEN, ENTER, EMPTY, "delete interfaces ge-0/0/2 disable",
                                        "delete interfaces ge-0/0/2 description", COMPARE,
                                        'commit comment "%s-revert"' % label, LEAVE]
    assert len(device.applied_blocks) == 4
    names = steps(record)
    assert names.index("revert_now_start") < names.index("revert_now_done") and "safeguard_removed" not in names
    assert not any(item["via"] == "other" for item in device.history[:3]) and device.broadcasts == []
    # the inverse is kept: nothing is pending any more, so no expiry can bring the change back
    device.advance(1200)
    assert device.lines == BASELINE.rstrip("\n").split("\n") and device.history[0]["comment"] == label + "-revert"


def test_check_account_mismatch_is_returned(tmp_path):
    device = FakeJunos()
    device.check_override = {}

    def stale(fake, block):
        if CHANGE in block:
            fake.check_override = {"show interfaces descriptions": "\n"}

    device.on_apply = stale
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert device.interface("ge-0/0/2") == ["unit 0 family ethernet-switching interface-mode access",
                                            "unit 0 family ethernet-switching vlan members default"]


def test_a_commit_refused_by_the_device_is_returned_by_the_safeguard(tmp_path):
    device = FakeJunos()

    def drop_vlan(fake, block):
        if CHANGE in block:
            fake.lines = [line for line in fake.lines if not line.startswith("set vlans D10 ")]

    device.on_apply = drop_vlan
    record = execute.apply(make_runtime(tmp_path, device), NAME,
                           request(table="vlan-membership", changes={"access-vlan": "D10"}))
    # no change commit exists; the confirmation of the empty safeguard is refused as well (the running configuration
    # lost the VLAN that the port uses), so the timer returns it
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    assert "unit 0 family ethernet-switching vlan members default" in device.interface("ge-0/0/2")
    assert not device.pending() and "revert_now_unverified" in steps(record)
    label = record["safeguard"]["name"]
    assert not any('"%s-revert"' % label in line for block in device.applied_blocks for line in block)


def test_a_refused_change_commit_confirms_the_empty_safeguard_at_once(tmp_path):
    # pattern c): nothing of the change was committed, so the return is the confirmation of the own empty safeguard
    # after the state before is proven, without waiting for the expiry
    from netops_admin.access import AccessError

    device = FakeJunos()

    def refuse(fake, step):
        if step == CHANGE:
            raise AccessError("line 6 was refused by the device: the commit did not answer 'commit complete'", 5)

    device.before_line = refuse
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    label = record["safeguard"]["name"]
    assert [item["comment"] for item in device.history[:2]] == [label + "-ok", label] and not device.pending()
    assert "revert_now_done" in steps(record) and device.broadcasts == []
    assert device.lines == BASELINE.rstrip("\n").split("\n")


def test_a_slow_device_skips_the_confirmation_and_the_timer_returns_the_change(tmp_path):
    device = FakeJunos()

    def slow_reads(fake, block):
        if CHANGE in block:
            fake.read_delay = 120

    device.on_apply = slow_reads
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "no time left to confirm", steps(record)
    assert device.lines == BASELINE.rstrip("\n").split("\n")


def test_a_foreign_commit_between_safeguard_and_change_is_not_confirmed(tmp_path):
    device = FakeJunos()

    def foreign_commit(fake, block):
        if CHANGE in block:
            # any commit confirms the pending safeguard (measured)
            fake._record("operator", "cli", comment="maintenance")
            fake.timer = None

    device.on_apply = foreign_commit
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] != "confirmed"
    assert "safeguard_rearm_unverified" in steps(record)
    assert not any(block[3:4] == ['commit comment "%s-ok"' % record["safeguard"]["name"]]
                   for block in device.applied_blocks)


def test_interrupted_change_is_recovered_after_the_timer(tmp_path):
    device = FakeJunos()

    class Interrupted(BaseException):
        pass

    def interrupt(command):
        raise Interrupted()

    def stop_after_change(fake, block):
        if CHANGE in block:
            fake.check_query = interrupt

    device.on_apply = stop_after_change
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        execute.apply(runtime, NAME, request(request_id="req-kill-1"))
    assert runtime.store.running(NAME) and device.pending()
    del device.check_query
    settled = execute.recover(runtime, NAME)
    assert [record["result"] for record in settled] == ["reverted"], [steps(record) for record in settled]
    assert settled[0]["reason"] == "interrupted"
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


@pytest.mark.parametrize("prepare, code", [
    (lambda fake: setattr(fake, "lldp_extra", ["ge-0/0/2"]), "port_lldp_neighbor"),
    (lambda fake: fake.learned_macs.__setitem__("ge-0/0/2", 2), "port_learned_mac"),
])
def test_port_in_use_is_refused_before_any_write(tmp_path, prepare, code):
    device = FakeJunos()
    prepare(device)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), NAME, request(changes={"admin-state": "disabled"}))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == [PROBE]


@pytest.mark.parametrize("fields, code", [
    ({"table": "vlan-membership", "changes": {"access-vlan": "D3999"}}, "vlan_missing"),
    ({"key": "fxp0", "changes": {"description": "x"}}, "port_management_interface"),
    ({"key": "ge-0/0/99"}, "port_missing"),
])
def test_missing_vlan_management_and_missing_port_are_refused_with_zero_writes(tmp_path, fields, code):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, NAME, request(**fields))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    with pytest.raises(Rejected):
        execute.apply(runtime, NAME, request(**fields))
    assert all(block == PROBE for block in device.applied_blocks)
    assert device.history[0]["at"] == "2026-11-11 14:04:21"


def test_vlan_missing_on_the_device_is_refused(tmp_path):
    device = FakeJunos()
    device.vlans = lambda: {"default", "D20"}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), NAME,
                      request(table="vlan-membership", changes={"access-vlan": "D10"}))
    assert caught.value.reason_codes == ["vlan_missing"] and "show vlans D10" in caught.value.reasons[0]


@pytest.mark.parametrize("prepare", [
    lambda fake: setattr(fake, "foreign_editor", True),
    lambda fake: setattr(fake, "foreign_candidate", fake.lines + ["set interfaces ge-0/0/3 description foreign"]),
])
def test_someone_in_configuration_mode_or_an_uncommitted_change_is_refused(tmp_path, prepare):
    device = FakeJunos()
    prepare(device)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, NAME, request())
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["foreign_config_session"]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, NAME, request())
    assert caught.value.reason_codes == ["foreign_config_session"]
    assert all(block[:2] == [SCREEN, "configure"] for block in device.applied_blocks)
    assert device.history[0]["at"] == "2026-11-11 14:04:21"


def test_foreign_pending_commit_confirmed_and_own_leftover_are_refused(tmp_path):
    device = FakeJunos()
    device._record("operator", "cli", minutes=5, comment="maintenance", pending=True)
    device.timer = {"minutes": 5, "expire": device.epoch + 300, "target": list(device.lines)}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), NAME, request())
    assert caught.value.reason_codes == ["foreign_config_session"] and device.applied_blocks == []
    device = FakeJunos()
    device._record("netops-admin", "cli", minutes=10, comment="netops-0123456789ab", pending=True)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), NAME, request())
    assert "netops-0123456789ab" in caught.value.reasons[0] and device.applied_blocks == []


def test_missing_permission_and_another_release_are_refused(tmp_path):
    device = FakeJunos()
    device.permissions_missing = ("configure",)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), NAME, request())
    assert caught.value.reason_codes == ["write_account_privilege"]
    device = FakeJunos()
    device.firmware = "26.2R1.8"
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), NAME, request())
    assert "runs Junos 26.2R1.8" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unexpected_account_blocks_the_device(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device, accounts=("netops-admin",))
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, NAME, request())
    assert "accounts differ" in caught.value.reasons[0]
    assert runtime.store.blocked(NAME)["reason"] == "administrator table"


def test_account_digest_leaves_out_the_password_hashes():
    device = FakeJunos()
    target = Device(name=NAME, platform="junos", address="192.0.2.56", port=22, host_key_fingerprint="SHA256:" + "A" * 43,
                    vault="/v", credential="rw", firmware=FIRMWARE, safeguard_seconds=600, confirm_margin_seconds=300,
                    protected={}, accounts=ACCOUNTS, check_credential="ro")
    first = exec_junos.accounts_check(device, target, BASELINE)
    other = BASELINE.replace('encrypted-password "<REDIGOVANO>"', 'encrypted-password "<JINY>"')
    assert exec_junos.accounts_check(device, target, other) == first
    assert exec_junos.accounts_check(device, target, BASELINE.replace("class read-only", "class operator")) != first


def test_audit_log_holds_no_text_and_no_secret(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request(changes={"description": SECRET_TEXT}))
    assert record["result"] == "confirmed"
    log = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET_TEXT not in log and "REDIGOVANO" not in log and "encrypted-password" not in log
    start = json.loads(log.splitlines()[0])
    assert start["platform"] == "junos" and start["changes"] == {"description": "text of %d characters"
                                                                  % len(SECRET_TEXT)}
    assert start["safeguard"] == record["safeguard"]["name"]


def test_audit_gate_has_no_junos_rules_and_refuses_a_policy():
    assert audit_gate.rule_count("junos") == 0
    assert audit_gate.baseline("junos", BASELINE, NAME) == {}
    with pytest.raises(Rejected):
        audit_gate.evaluate("junos", BASELINE, {"required_rules": []}, "interface")


def test_enrollment_self_test_changes_the_description_and_the_timer_returns_it(tmp_path):
    from netops_admin import enrollment

    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "sent"
    runtime.store.clear_enrollment(NAME)
    record = enrollment.run(runtime, NAME, "ge-0/0/2")
    assert record["result"] == "reverted" and record["reason"] == "enrollment self-test", steps(record)
    assert record["plan"]["predicted"]["after"]["description"].startswith("netops-enroll-")
    assert record.get("enrollment") == "valid", steps(record)
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    assert (device.history[0]["user"], device.history[0]["via"]) == ("root", "other")


def test_doctor_is_ready_after_enrollment(tmp_path):
    from netops_admin import readiness

    device = FakeJunos()
    report = readiness.doctor(make_runtime(tmp_path, device), NAME)
    statuses = {item["check"]: item["status"] for item in report["checks"]}
    assert statuses["check account"] == "ok" and statuses["leftover safeguards"] == "ok"
    assert statuses["device prechecks"] == "ok" and statuses["enrollment"] == "ok", report
    assert report["operations"] == {"interface": "update", "vlan-membership": "update", "vlan": "create update delete",
                                    "system": "update", "ntp-server": "create update delete",
                                    "syslog-host": "create update delete",
                                    "static-route": "create update delete", "irb": "create update delete",
                                    "vrrp": "create update delete",
                                    **{table: "create update delete" for table in (*junos.routing.TABLES, *junos.fltr.TABLES)},
                                    "poe": "update (untested on %s)" % FIRMWARE,
                                    "inline-power": "poe-cycle (untested on %s)" % FIRMWARE,
                                    "port-bounce": "port-bounce",
                                    "lag": "create update delete", "rstp": "update", "rstp-interface": "update",
                                    **{table: "create update delete" for table in junos.srx.TABLES},
                                    **{table: "create update delete" for table in junos.dhcp.TABLES}}


def _device_data(**fields):
    data = {"platform": "junos", "address": "192.0.2.56", "host_key_fingerprint": "SHA256:" + "A" * 43,
            "vault": "/v/vault.json", "credential": "rw", "check_credential": "ro", "accounts": list(ACCOUNTS),
            "safeguard_seconds": 600, "confirm_margin_seconds": 300}
    data.update(fields)
    return data


def test_configuration_needs_the_junos_timer_and_margin():
    device = config_module._device(NAME, _device_data())
    assert device.platform == "junos" and device.safeguard_seconds == 600
    for fields, fragment in (({"safeguard_seconds": 900}, "safeguard_seconds 600"),
                             ({"confirm_margin_seconds": 120}, "at least 240"),
                             ({"accounts": []}, "Junos needs the expected accounts")):
        with pytest.raises(Rejected) as caught:
            config_module._device(NAME, _device_data(**fields))
        assert fragment in caught.value.reasons[0]


def test_device_access_gives_junos_reads_and_commit_lines_longer_limits(monkeypatch):
    from types import SimpleNamespace

    from netops_admin import access

    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(legacy_ssh=None, address="192.0.2.56", port=22, platform="junos")
    handle._host_key_lines, handle.credential, timeouts = {"192.0.2.56": "192.0.2.56 ssh-ed25519 AAAA"}, object(), []

    def run_command(*_arguments, timeout_seconds, **_options):
        timeouts.append(timeout_seconds)
        return SimpleNamespace(rc=0, stdout=b"Hostname: host01\n")

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    handle.query("show version")
    handle.read_seconds = 7.5
    handle.query("show version")
    assert timeouts == [access.JUNOS_QUERY_TIMEOUT_SECONDS, 7.5] and access.JUNOS_QUERY_TIMEOUT_SECONDS == 180.0
    spec = exec_junos.prompt_spec("host01")
    assert access._line_seconds(spec, CHANGE) == exec_junos.COMMIT_LINE_SECONDS == 420
    assert access._line_seconds(spec, SCREEN) == exec_junos.LINE_SECONDS
    assert access._line_seconds(exec_junos.PromptSpec(anchor=b"x", ends=(), continuation=None, error=None),
                                "x") == access.LINE_TIMEOUT_SECONDS


def test_change_interrupted_before_its_timer_refresh_is_recovered_on_a_slow_device(tmp_path):
    # measured in task 319: the change commit took about 4 minutes and the automatic rollback 273 s, so the proof came
    # 530 s after the fire_at of the safeguard commit that an interrupted record still holds
    device = FakeJunos()
    device.commit_seconds, device.rollback_seconds = 240, 300

    class Interrupted(BaseException):
        pass

    original = device.query

    def query(command):
        if command == exec_junos.QUERY_COMMITS and device.history[0]["comment"] == "netops-change" \
                and device.history[0]["pending"] and not device.recovering:
            raise Interrupted()
        return original(command)

    device.recovering = False
    device.query = query
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        execute.apply(runtime, NAME, request(request_id="req-kill-2"))
    record = runtime.store.running(NAME)[0]
    assert "safeguard_rearmed" not in steps(record) and device.pending()
    device.recovering = True
    settled = execute.recover(runtime, NAME)
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    # recover waited by show system commit only (no device clock), past the expiry of the safeguard commit
    assert settled[0]["safeguard"]["fire_at"] == exec_junos.FIRE_AT_TEXT
    late = device.epoch - datetime.datetime.strptime(settled[0]["safeguard"]["device_expiry"], "%Y-%m-%d %H:%M:%S") \
        .replace(tzinfo=datetime.timezone.utc).timestamp()
    assert exec_junos.FIRING_SLACK_SECONDS > late > 480


# ---- task 319-r2: the four safeguard protections of the IOS and NX-OS reviews, through the shared hooks ----

FOREIGN = "netops-ffffffffffff"


def _foreign_pending(fake, comment=FOREIGN, target=None, later=5):
    """Someone else (the same account) commits a commit confirmed: it confirms whatever was pending (measured) and
    leaves its own timer pending."""
    fake.advance(later)
    fake._record("netops-admin", "cli", minutes=10, comment=comment, pending=True)
    fake.timer = {"minutes": 10, "expire": fake.epoch + 630, "target": list(fake.lines if target is None else target)}


def _queries(device):
    seen = []
    original = device.query

    def query(command):
        seen.append(command)
        return original(command)

    device.query = query
    return seen


def test_a_foreign_timer_that_appears_after_the_prechecks_is_never_committed_over(tmp_path):
    # pattern a): the session of the safeguard sees the banner of someone else's pending commit confirmed in its empty
    # compare and ends before the commit line, which would confirm it; nothing is changed
    device = FakeJunos()

    def appear(fake, block):
        if any(line.startswith('commit confirmed 10 comment "netops-') and line != CHANGE for line in block):
            _foreign_pending(fake)

    device.on_apply = appear
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request())
    assert record["result"] == "rejected" and record["reason"] == "safeguard refused by the device", steps(record)
    assert record["reason_codes"] == ["foreign_config_session"]
    assert device.history[0]["comment"] == FOREIGN and device.pending()
    assert record["safeguard"]["name"] not in [item["comment"] for item in device.history]
    assert len(device.applied_blocks) == 2 and runtime.store.blocked(NAME) is None


def test_a_foreign_timer_of_the_same_account_after_the_change_is_never_confirmed(tmp_path):
    # pattern a): a commit confirmed of the same account (even with the comment netops-change) lands over the own
    # timer before the confirmation; the newest row is no longer the recorded head, so neither the confirmation nor
    # the immediate return is sent; the foreign timer ends by itself and the result is honest
    device = FakeJunos()
    original = device.check_query

    def check_query(command):
        if not getattr(device, "landed", False) and device.timer is not None and device.history[0]["comment"] == \
                "netops-change":
            device.landed = True
            _foreign_pending(device, comment="netops-change")
        return original(command)

    device.check_query = check_query
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    label = record["safeguard"]["name"]
    assert record["result"] == "revert-failed", (record["reason"], steps(record))
    assert "confirm_unverified" in steps(record) and "revert_now_unverified" in steps(record)
    assert len(device.applied_blocks) == 3
    assert not any(line in ('commit comment "%s-ok"' % label, 'commit comment "%s-revert"' % label,
                            'commit confirmed 10 comment "%s-revert"' % label)
                   for block in device.applied_blocks for line in block)


def test_an_unproven_installation_is_never_confirmed_by_recover(tmp_path):
    # pattern a): the history after the safeguard commit cannot be read, so the installation is not proven; the
    # operation ends unknown and recover sends no commit while a rollback is pending, and clears it after the expiry
    device = FakeJunos()
    original = device.query
    state = {"failed": False}

    def query(command):
        if command == exec_junos.QUERY_COMMITS and device.timer is not None and not state["failed"]:
            state["failed"] = True
            raise AccessError("query failed: banner exchange timeout")
        return original(command)

    from netops_admin.access import AccessError

    device.query = query
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request())
    assert record["result"] == "unknown" and record["reason"] == "safeguard not verified", steps(record)
    assert record["safeguard"].get("verified") is None and runtime.store.blocked(NAME) is not None
    blocks = len(device.applied_blocks)
    execute.recover(runtime, NAME)
    assert len(device.applied_blocks) == blocks and device.pending()
    assert steps(runtime.store.operation(record["change_id"]))[-1] == "safeguard_removal_unverified"
    device.advance(900)
    execute.recover(runtime, NAME)
    assert len(device.applied_blocks) == blocks and not device.pending()
    assert steps(runtime.store.operation(record["change_id"]))[-1] == "safeguard_removed"


def test_ownership_needs_the_recorded_rows_not_the_account_or_the_prefix():
    record = {"change_id": "c8" * 16}
    label = exec_junos.safeguard_label(record["change_id"])
    own = junos.commits("0   2026-11-16 03:54:20 UTC by netops-admin via cli commit confirmed, rollback in 10mins\n"
                        "    %s\n    rollback pending\n1   2026-11-11 14:04:21 UTC by root via other\n" % label)
    assert not exec_junos._owned(own, record)
    record["safeguard"] = {"verified": True, "commit": {"at": "2026-11-16 03:54:20", "user": "netops-admin",
                                                        "comment": label}}
    record["safeguard"]["head"] = dict(record["safeguard"]["commit"])
    assert exec_junos._owned(own, record)
    same_account = junos.commits(
        "0   2026-11-16 03:55:02 UTC by netops-admin via cli commit confirmed, rollback in 10mins\n"
        "    netops-change\n    rollback pending\n"
        "1   2026-11-16 03:54:20 UTC by netops-admin via cli commit confirmed, rollback in 10mins\n    %s\n" % label)
    assert not exec_junos._owned(same_account, record)
    record["safeguard"]["head"] = {"at": "2026-11-16 03:55:02", "user": "netops-admin", "comment": "netops-change"}
    assert exec_junos._owned(same_account, record)
    record["safeguard"]["verified"] = False
    assert not exec_junos._owned(same_account, record)


def test_too_little_time_after_a_slow_safeguard_commit_writes_nothing(tmp_path):
    # pattern b): the time left is counted on the monotonic clock of Admin from before the safeguard was requested;
    # with less than the change session and the readback with the confirmation margin left nothing is written, and
    # the empty safeguard (no change commit exists) is proven and confirmed at once
    device = FakeJunos()
    device.empty_commit_seconds = 200
    runtime = make_runtime(tmp_path, device)
    queries = _queries(device)
    record = execute.apply(runtime, NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "no time left to write", steps(record)
    detail = next(step["detail"] for step in record["steps"] if step["step"] == "change_not_written")
    assert "405 s needed" in detail
    assert not any(line.startswith("set interfaces") for block in device.applied_blocks for line in block)
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    assert exec_junos.QUERY_CLOCK not in queries


def test_no_line_of_the_change_is_sent_without_the_time_of_its_commit(tmp_path):
    # pattern b): every line up to the change commit needs COMMIT_BUDGET_SECONDS of the own timer; a session that
    # slows down stops before the commit, which is never sent; the empty safeguard returns at its expiry
    device = FakeJunos()

    def slow(fake, step):
        if step.startswith("set interfaces"):
            fake.advance(420)

    device.before_line = slow
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    failed = next(step["detail"] for step in record["steps"] if step["step"] == "change_failed")
    assert failed.startswith("AccessError after 3 lines")
    assert "revert_now_skipped" in steps(record)
    assert "netops-change" not in [item["comment"] for item in device.history]
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


def test_the_line_guard_lets_the_lines_after_the_change_commit_through():
    left = {"value": 500.0}
    guard = exec_junos.line_guard_for([SCREEN, ENTER, EMPTY, "set interfaces ge-0/0/2 disable", COMPARE, CHANGE,
                                       LEAVE], lambda: left["value"])
    assert all(guard() for _ in range(5))
    left["value"] = exec_junos.COMMIT_BUDGET_SECONDS - 1
    assert not guard()
    guard = exec_junos.line_guard_for([SCREEN, CHANGE, LEAVE], lambda: left["value"])
    left["value"] = exec_junos.COMMIT_BUDGET_SECONDS
    assert guard() and guard()
    left["value"] = 0
    assert guard()


def test_the_restarted_timer_is_counted_between_two_lower_bounds():
    class Adapter:
        @staticmethod
        def timer_seconds(_device):
            return 588.0

    end = execute._restarted_end
    assert end(Adapter, None, {"safeguard": {}}, 0.0, 100.0, 300.0) == 688.0
    assert end(Adapter, None, {"safeguard": {"restart_offset_seconds": 250.0}}, 0.0, 100.0, 300.0) == 838.0
    # a device clock that jumped forward never counts past the answer of the session
    assert end(Adapter, None, {"safeguard": {"restart_offset_seconds": 4000.0}}, 0.0, 100.0, 300.0) == 888.0
    assert end(Adapter, None, {"safeguard": {"restart_offset_seconds": 50.0}}, 0.0, 100.0, 300.0) == 688.0
    assert exec_junos.timer_seconds(None) == pytest.approx(588.0)


def test_budgets_cover_the_measured_session_and_leave_the_margin(tmp_path):
    # 600 s less 2 % drift; the measured E2E of task 319 left 271-286 s at the confirmation when counted from the
    # change session, more with the restart offset of the two commit rows
    device = FakeJunos()
    target = make_runtime(tmp_path, device).config.devices[NAME]
    needed = max(exec_junos.SESSION_BUDGET_SECONDS, exec_junos.READBACK_BUDGET_SECONDS
                 + config_module.JUNOS_MIN_CONFIRM_MARGIN_SECONDS + exec_junos.RESTART_SLACK_SECONDS)
    assert needed < exec_junos.timer_seconds(target) - 120 and exec_junos.REVERT_NOW_SECONDS >= 235
    assert exec_junos.COMMIT_BUDGET_SECONDS >= 150 and exec_junos.TIMER_WATCH is True
    assert exec_junos.MIN_CONFIRM_MARGIN_SECONDS >= exec_junos.REVERT_NOW_SECONDS


def test_a_failed_inverse_is_left_to_the_timer(tmp_path):
    # pattern c): when the immediate return cannot be proven (its commit is refused), Admin waits for the expiry
    device = FakeJunos()

    def lose_check_account(fake, block):
        if CHANGE in block:
            fake.check_unreadable = True

    def refuse(fake, step):
        if step.endswith('-revert"'):
            raise AccessError("line 7 was refused by the device: error: configuration database locked", 6)

    from netops_admin.access import AccessError

    device.on_apply = lose_check_account
    device.before_line = refuse
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    assert "revert_now_unverified" in steps(record)
    assert (device.history[0]["user"], device.history[0]["via"]) == ("root", "other")
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


def test_the_confirmation_is_not_sent_once_the_own_timer_ended_in_the_session(tmp_path):
    # pattern a)/d): the banner of the pending timer is gone in the confirmation session (expired between the read
    # and the session), so the plain commit, which would make the automatic rollback fail, is never sent
    device = FakeJunos()
    state = {"done": False}

    def expire(fake, block):
        if block[3:4] and block[3].startswith("commit comment") and not state["done"]:
            state["done"] = True
            fake.advance(fake.timer["expire"] - fake.epoch)

    device.on_apply = expire
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] in ("reverted", "unknown"), (record["reason"], steps(record))
    assert record["result"] != "confirmed" and "confirm_unverified" in steps(record)
    label = record["safeguard"]["name"]
    assert label + "-ok" not in [item["comment"] for item in device.history]


def test_recover_decides_by_the_commit_history_without_the_device_clock(tmp_path):
    # pattern d): the device clock is unreadable (or wrong) for the whole operation and recover; the interrupted
    # change is settled by "rollback pending" and "root via other" only, and a failed history read counts as pending
    device = FakeJunos()
    original = device.query
    seen = []
    flaky = {"left": 3}

    def query(command):
        seen.append(command)
        if command == exec_junos.QUERY_CLOCK:
            raise AssertionError("the device clock was read")
        if command == exec_junos.QUERY_COMMITS and getattr(device, "recovering", False) and flaky["left"]:
            flaky["left"] -= 1
            raise RuntimeError("history unreadable")
        return original(command)

    class Interrupted(BaseException):
        pass

    def interrupt(command):
        raise Interrupted()

    def stop_after_change(fake, block):
        if CHANGE in block:
            fake.check_query = interrupt

    device.query = query
    device.on_apply = stop_after_change
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        execute.apply(runtime, NAME, request(request_id="req-kill-3"))
    del device.check_query
    device.recovering = True
    settled = execute.recover(runtime, NAME)
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert flaky["left"] == 0 and exec_junos.QUERY_CLOCK not in seen
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    assert (device.history[0]["user"], device.history[0]["via"]) == ("root", "other")


def test_recover_waits_for_a_rollback_pending_above_the_own_safeguard_and_never_confirms_it(tmp_path):
    # pattern d): an interrupted operation whose own timer is still pending is left to its expiry; recover never
    # sends a commit (it would confirm the change) and proves the return by the root via other row
    device = FakeJunos()

    class Interrupted(BaseException):
        pass

    def interrupt(command):
        raise Interrupted()

    def stop_after_change(fake, block):
        if CHANGE in block:
            fake.check_query = interrupt

    device.on_apply = stop_after_change
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        execute.apply(runtime, NAME, request(request_id="req-kill-4"))
    del device.check_query
    blocks = len(device.applied_blocks)
    settled = execute.recover(runtime, NAME)
    assert [item["result"] for item in settled] == ["reverted"] and len(device.applied_blocks) == blocks
    assert "revert_now_start" not in steps(settled[0])


# ---- task 319-r3: the change commit is adopted as the head after a failed read, before the immediate return ----

def _fail_first_history_after_change(device, failures=1):
    """Fail the given number of initial commit-history reads after the change commit."""
    from netops_admin.access import AccessError

    original = device.query
    state = {"failed": 0}

    def query(command):
        if command == exec_junos.QUERY_COMMITS and state["failed"] < failures and device.history[0]["comment"] == \
                "netops-change" and device.history[0]["pending"]:
            state["failed"] += 1
            raise AccessError("query failed: ssh: connection reset")
        return original(command)

    device.query = query
    return state


def _returned_at_once(device, record):
    label = record["safeguard"]["name"]
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    assert [item["comment"] for item in device.history[:3]] == [label + "-revert", "netops-change", label]
    assert device.applied_blocks[3] == [SCREEN, ENTER, EMPTY, "delete interfaces ge-0/0/2 description", COMPARE,
                                        'commit comment "%s-revert"' % label, LEAVE]
    assert len(device.applied_blocks) == 4
    assert not any(item["via"] == "other" for item in device.history[:3]) and device.broadcasts == []
    names = steps(record)
    assert names.index("change_head_adopted") < names.index("revert_now_start") < names.index("revert_now_done")
    assert "revert_now_unverified" not in names and "revert_now_skipped" not in names


def test_a_failed_read_after_the_change_commit_adopts_it_and_returns_at_once(tmp_path):
    # review 319-r2rv finding 1 (a): the read of safeguard_rearmed fails once after the own change commit; before the
    # immediate return show system commit is read again, the change row right above the own safeguard row (own change
    # comment, write account, rollback pending) becomes the head and the inverse is committed at once
    device = FakeJunos()
    state = _fail_first_history_after_change(device)
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted", (record["reason"], steps(record))
    assert record["reason"] == "safeguard not verified after the change" and state["failed"] == 1
    assert "safeguard_rearm_unverified" in steps(record) and "safeguard_rearmed" not in steps(record)
    _returned_at_once(device, record)


def test_failed_junos_change_head_reread_leaves_the_return_to_its_timer(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    state = _fail_first_history_after_change(device, failures=2)

    record = execute.apply(runtime, NAME, request())

    assert (record["result"], record["reason"]) == ("reverted", "safeguard not verified after the change")
    names = steps(record)
    assert state["failed"] == 2 and "change_head_unverified" in names and "change_head_adopted" not in names
    assert "revert_now_unverified" in names and "safeguard_removed" in names
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()
    label = record["safeguard"]["name"]
    assert not any(label + "-revert" in line or label + "-ok" in line
                   for block in device.applied_blocks for line in block)
    assert runtime.store.blocked(NAME) is None


def test_a_failed_exit_after_the_change_commit_adopts_it_and_returns_at_once(tmp_path):
    # review 319-r2rv finding 1 (b): the connection fails on exit configuration-mode after the change commit answered
    # commit complete; the change counts as failed, its commit is adopted as the head and returned by the inverse
    from netops_admin.access import AccessError

    device = FakeJunos()
    state = {"committed": False}

    def after(fake, step):
        if step == CHANGE:
            state["committed"] = True

    def cut(fake, step):
        if step == LEAVE and state["committed"]:
            state["committed"] = False
            raise AccessError("line 7 was not answered: ssh: connection reset", 6)

    device.after_line, device.before_line = after, cut
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "reverted" and record["reason"] == "change failed", (record["reason"], steps(record))
    assert "change_failed" in steps(record) and "safeguard_rearmed" not in steps(record)
    _returned_at_once(device, record)


@pytest.mark.parametrize("landing", ["foreign-above-change", "other-user-change-comment", "own-account-foreign"])
def test_a_foreign_commit_above_the_safeguard_is_never_adopted(tmp_path, landing):
    # review 319-r2rv finding 1 (c): after the failed read anything else than exactly the own change row right above
    # the own safeguard row (a foreign commit confirmed above the change, a netops-change row of another user, a
    # foreign comment of the write account) is never adopted: no immediate return, the timer returns
    from netops_admin.access import AccessError

    device = FakeJunos()
    # the change commit answered: its read fails once; the change commit refused: the read before the return answers
    state = _fail_first_history_after_change(device) if landing == "foreign-above-change" else {"failed": 0}

    def land(fake, step):
        if step != CHANGE:
            return
        if landing == "other-user-change-comment":
            # another session commits its own commit confirmed "netops-change" and the own change commit is refused
            fake._record("operator", "cli", minutes=10, comment="netops-change", pending=True)
            fake.timer = {"minutes": 10, "expire": fake.epoch + 630, "target": list(fake.lines)}
            raise AccessError("line 6 was refused by the device: error: configuration database locked", 5)
        if landing == "own-account-foreign":
            _foreign_pending(fake)
            raise AccessError("line 6 was refused by the device: error: configuration database locked", 5)

    def above(fake, step):
        if step == CHANGE and landing == "foreign-above-change":
            # the expiry returns the state before the newest commit confirmed (task 378): the foreign one, which
            # holds the own change
            _foreign_pending(fake, comment="netops-change")

    device.before_line, device.after_line = land, above
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    label = record["safeguard"]["name"]
    names = steps(record)
    assert "change_head_adopted" not in names and "revert_now_unverified" in names, (record["reason"], names)
    assert record["safeguard"]["head"] == record["safeguard"]["commit"]
    assert not any(line in ('commit comment "%s-ok"' % label, 'commit comment "%s-revert"' % label,
                            'commit confirmed 10 comment "%s-revert"' % label)
                   for block in device.applied_blocks for line in block)
    assert record["result"] != "confirmed" and not device.pending()
    assert (device.history[0]["user"], device.history[0]["via"]) == ("root", "other")
    assert state["failed"] == (1 if landing == "foreign-above-change" else 0)
    if landing == "foreign-above-change":
        # the foreign timer returned the state with the own change; Admin reports it truthfully
        assert record["result"] == "revert-failed", (record["reason"], names)
        assert "description netops-c8b-test" in device.interface("ge-0/0/2")
    else:
        assert device.lines == BASELINE.rstrip("\n").split("\n")


# ---- task 378: the expiry returns the state before the NEWEST commit confirmed (measured on vJunos 26.2R1.7) ----

S1_LABEL, S2_LABEL = "netops-t378s1", "netops-t378s2"


def _rows(commits):
    return [(commit.user, commit.via, commit.minutes, commit.comment, commit.pending) for commit in commits]


def _fake_rows(device, count):
    return [(item["user"], item["via"], item["minutes"], item["comment"], item["pending"])
            for item in device.history[:count]]


def _measured_port(name):
    return [line[len("set interfaces ge-0/0/2 "):] for line in fixture(name).split("\n") if line]


def _measured_sequence(device, label, change, inverse_committed):
    """The measured command sequence of task 378 on the fake (the lines of exec_junos, commit confirmed 2): an empty
    safeguard, the description change, the inverse committed or the session ended right before its commit."""
    spec = exec_junos.prompt_spec(device.hostname)
    device.apply([SCREEN, ENTER, EMPTY, 'commit confirmed 2 comment "%s"' % label, LEAVE], spec)
    device.apply([SCREEN, ENTER, EMPTY, 'set interfaces ge-0/0/2 description "%s"' % change, COMPARE,
                  'commit confirmed 2 comment "netops-change"', LEAVE], spec)
    changed = list(device.lines)
    inverse = [SCREEN, ENTER, EMPTY, "delete interfaces ge-0/0/2 description", COMPARE]
    device.apply(inverse + (['commit confirmed 2 comment "%s-revert"' % label, LEAVE] if inverse_committed else []),
                 spec)
    return changed


def test_measured_expiry_after_an_inverse_commit_confirmed_brings_the_change_back():
    # S1, measured: the inverse committed with commit confirmed and then no confirmation (the process interrupted);
    # the expiry returned the state before the inverse, i.e. the change, not the state before the safeguard
    assert _measured_port("show-configuration-interfaces-ge-0-0-2-display-set__t378-baseline.txt") == \
        FakeJunos().interface("ge-0/0/2")
    pending = junos.commits(fixture("show-system-commit__t378-s1-inverse-pending.txt"))
    assert _rows(pending) == [("netops-admin", "cli", 2, S1_LABEL + "-revert", True),
                              ("netops-admin", "cli", 2, "netops-change", False),
                              ("netops-admin", "cli", 2, S1_LABEL, False)]
    assert exec_junos.pending_banner(fixture("commit-confirmed-2__t378-s1-inverse-restarts-timer.txt"))
    assert _measured_port("show-configuration-interfaces-ge-0-0-2-display-set__t378-s1-inverse-pending.txt") == \
        _measured_port("show-configuration-interfaces-ge-0-0-2-display-set__t378-baseline.txt")
    fired = junos.commits(fixture("show-system-commit__t378-s1-after-expiry-change-back.txt"))
    measured_after = _measured_port(
        "show-configuration-interfaces-ge-0-0-2-display-set__t378-s1-after-expiry-change-back.txt")
    assert measured_after[0] == "description t378-s1-change"
    assert fixture("show-system-rollback-compare-1-0__t378-s1-after-expiry-change-back.txt").split("\n")[1] == \
        "+   description t378-s1-change;"
    assert fixture("show-system-rollback-compare-2-0__t378-s1-after-expiry-equals-change.txt").strip() == ""
    # the model gives the same rows and the same port
    device = FakeJunos()
    changed = _measured_sequence(device, S1_LABEL, "t378-s1-change", inverse_committed=True)
    assert _fake_rows(device, 3) == _rows(pending)
    assert device.interface("ge-0/0/2") == _measured_port(
        "show-configuration-interfaces-ge-0-0-2-display-set__t378-s1-inverse-pending.txt")
    device.advance(600)
    assert _fake_rows(device, 4) == _rows(fired) and not device.pending()
    assert device.interface("ge-0/0/2") == measured_after and device.lines == changed


def test_measured_expiry_without_the_inverse_commit_returns_the_state_before():
    # S2, measured: the session of the inverse ended before its commit; the expiry returned the state before the
    # change commit, which is the state before the empty safeguard
    pending = junos.commits(fixture("show-system-commit__t378-s2-session-ended-change-pending.txt"))
    assert _rows(pending) == _rows(junos.commits(fixture("show-system-commit__t378-s2-change-pending.txt")))
    assert _rows(pending) == [("netops-admin", "cli", 2, "netops-change", True),
                              ("netops-admin", "cli", 2, S2_LABEL, False)]
    assert fixture("show-compare__t378-s2-inverse-not-committed.txt").split("\n")[1] == \
        "-   description t378-s2-change;"
    fired = junos.commits(fixture("show-system-commit__t378-s2-after-expiry-returned.txt"))
    assert fixture("show-system-rollback-compare-1-0__t378-s2-after-expiry-returned.txt").split("\n")[1] == \
        "-   description t378-s2-change;"
    device = FakeJunos()
    _measured_sequence(device, S2_LABEL, "t378-s2-change", inverse_committed=False)
    assert _fake_rows(device, 2) == _rows(pending)
    device.advance(600)
    assert _fake_rows(device, 3) == _rows(fired) and not device.pending()
    assert device.interface("ge-0/0/2") == _measured_port(
        "show-configuration-interfaces-ge-0-0-2-display-set__t378-s2-after-expiry-returned.txt")
    assert device.lines == BASELINE.rstrip("\n").split("\n")


def test_measured_histories_of_task_378_drive_the_end_of_the_timer():
    # the measured histories read through the adapter (fake transport answering the measured text): pending is armed,
    # root via other above the own safeguard is the end of the timer, whose state only the snapshot judges
    class Answer:
        def __init__(self, name, label):
            self.text = fixture(name).replace(label, exec_junos.safeguard_label(record["change_id"]))
            self.credential = None

        def query(self, command):
            assert command == exec_junos.QUERY_COMMITS
            return self.text

    record = {"change_id": "78" * 16}
    label = exec_junos.safeguard_label(record["change_id"])
    for name, measured in (("show-system-commit__t378-s1-inverse-pending.txt", S1_LABEL),
                           ("show-system-commit__t378-s2-change-pending.txt", S2_LABEL)):
        armed = Answer(name, measured)
        assert not exec_junos.safeguard_fired(armed, record) and not exec_junos.safeguard_absent(armed, record)
        assert exec_junos.leftovers(armed) == ([label + "-revert"] if "s1" in name else ["netops-change"])
    for name, measured in (("show-system-commit__t378-s1-after-expiry-change-back.txt", S1_LABEL),
                           ("show-system-commit__t378-s2-after-expiry-returned.txt", S2_LABEL)):
        ended = Answer(name, measured)
        assert exec_junos.safeguard_fired(ended, record) and exec_junos.safeguard_absent(ended, record)
        assert not exec_junos.safeguard_disarmed(ended, record)
    # the own immediate return of the fixed adapter: the plain -revert row (layout of a measured plain commit row)
    # above the change ends the own timer, nothing is pending and no expiry follows
    returned = Answer("show-system-commit__t378-s2-change-pending.txt", S2_LABEL)
    returned.text = "0   2026-11-16 19:51:40 UTC by netops-admin via cli\n    %s-revert\n" % label + "\n".join(
        "%-3d%s" % (int(row[:3]) + 1, row[3:]) if row[:1].isdigit() else row
        for row in returned.text.split("\n") if row.strip() != "rollback pending")
    assert _rows(junos.commits(returned.text))[:2] == [("netops-admin", "cli", None, label + "-revert", False),
                                                       ("netops-admin", "cli", 2, "netops-change", False)]
    assert exec_junos.safeguard_fired(returned, record) and exec_junos.safeguard_absent(returned, record)
    foreign = Answer("show-system-commit__t378-s2-change-pending.txt", S2_LABEL)
    foreign.text = returned.text.replace("by netops-admin via cli\n    %s-revert" % label,
                                         "by operator via cli\n    %s-revert" % label, 1)
    foreign.credential = type("Credential", (), {"login": "netops-admin"})()
    assert not exec_junos.safeguard_fired(foreign, record) and not exec_junos.safeguard_absent(foreign, record)


def _interrupt_after_the_inverse(device):
    """The process is killed right after the commit of the immediate return answered (the next snapshot)."""
    class Interrupted(BaseException):
        pass

    original = device.snapshot

    def snapshot():
        if (device.history[0]["comment"] or "").endswith("-revert"):
            raise Interrupted()
        return original()

    device.snapshot = snapshot
    return Interrupted


def test_an_interrupted_immediate_return_keeps_the_state_before_and_recover_proves_it(tmp_path):
    # task 378, S1 on the fixed adapter: the inverse is committed with a plain commit, so a process killed right after
    # it leaves no pending timer that could bring the change back; recover sends nothing and reports reverted
    device = FakeJunos()

    def lose_check_account(fake, block):
        if CHANGE in block:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    interrupted = _interrupt_after_the_inverse(device)
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(interrupted):
        execute.apply(runtime, NAME, request(request_id="req-kill-378"))
    record = runtime.store.running(NAME)[0]
    label = record["safeguard"]["name"]
    assert "revert_now_done" in steps(record) and not device.pending()
    assert [item["comment"] for item in device.history[:3]] == [label + "-revert", "netops-change", label]
    device.advance(1200)
    assert device.lines == BASELINE.rstrip("\n").split("\n") and device.history[0]["comment"] == label + "-revert"
    del device.snapshot
    device.check_unreadable = False
    blocks = len(device.applied_blocks)
    settled = execute.recover(runtime, NAME)
    assert [item["result"] for item in settled] == ["reverted"], [steps(item) for item in settled]
    assert settled[0]["reason"] == "interrupted" and len(device.applied_blocks) == blocks
    assert device.lines == BASELINE.rstrip("\n").split("\n") and not device.pending()


def test_an_unreadable_state_after_the_immediate_return_is_unknown_and_stays_returned(tmp_path):
    # the snapshot after the plain inverse commit fails: the state is not proven, so the result is unknown (the
    # operator checks the port by hand, docs), and no timer is left that could bring the change back
    from netops_admin.access import AccessError

    device = FakeJunos()

    def lose_check_account(fake, block):
        if CHANGE in block:
            fake.check_unreadable = True

    original = device.snapshot

    def snapshot():
        if (device.history[0]["comment"] or "").endswith("-revert") and not getattr(device, "seen", False):
            device.seen = True
            raise AccessError("query failed: ssh: connection reset")
        return original()

    device.on_apply = lose_check_account
    device.snapshot = snapshot
    record = execute.apply(make_runtime(tmp_path, device), NAME, request())
    assert record["result"] == "unknown" and record["reason"] == "check identity unavailable", steps(record)
    assert "revert_unverified" in steps(record) and not device.pending()
    device.advance(1200)
    assert device.lines == BASELINE.rstrip("\n").split("\n")
    assert not any(item["via"] == "other" for item in device.history[:3])
