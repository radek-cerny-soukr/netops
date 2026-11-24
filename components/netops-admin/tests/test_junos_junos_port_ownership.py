"""1.0.12 JUNOS-PORT-OWNERSHIP (Junos ELS, vJunos-switch 26.2R1.7): NTP servers and the NTP source address (J31), remote syslog hosts
with severity, port and facility-override (J32), name-servers, domain-name and host-name (J33).

Parsers run on anonymised outputs measured on the lab switch (fixtures/junos_26_2R1_7, files *__junos_port_ownership*,
private measurement record); preview, apply, readback and undo run against FakeJunos, whose system statements follow the same
measurements (prefer on the server line, single values replaced, name-servers in the order of entry, the prompt with
the new host name right after its commit)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos, fixture

from netops_admin import access, exec_junos, execute, junos
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from test_access import Shell, device_access
from test_junos import CHANGE, COMPARE, EMPTY, ENTER, LEAVE, NAME, PROBE, SCREEN, make_runtime, steps
from approved_apply import approved_apply

COUNTER = iter(range(1, 10000))
SELECTED = fixture("show-configuration-system-display-set-selected__junos_port_ownership-after.txt")
FINAL = fixture("show-system-display-set-candidate__junos_port_ownership-probe3-final.txt")
MOVED = fixture("show-system-display-set-candidate__junos_port_ownership-name-server-moved.txt")


def request(**fields):
    fields.setdefault("request_id", "junos-port-ownership-unit-%04d" % next(COUNTER))
    fields.setdefault("op", "update")
    fields.setdefault("table", "system")
    fields.setdefault("key", "system")
    fields.setdefault("changes", {})
    return parse_request(request_bytes(**fields))


def with_lines(text, base=BASELINE):
    """The reconstructed lab configuration with measured system lines (a measured host-name replaces the old one)."""
    lines = [line for line in base.rstrip("\n").split("\n")]
    extra = [line for line in text.split("\n") if line.startswith("set ")]
    if any(line.startswith("set system host-name ") for line in extra):
        lines = [line for line in lines if not line.startswith("set system host-name ")]
    at = max(index for index, line in enumerate(lines) if line.startswith("set system ")) + 1
    return "\n".join(lines[:at] + extra + lines[at:]) + "\n"


def plan_of(text=BASELINE, **fields):
    return build_plan("junos", text.encode(), request(**fields), firmware=FIRMWARE)


def refused(text=BASELINE, **fields):
    with pytest.raises(Rejected) as caught:
        plan_of(text, **fields)
    return caught.value


def body(plan):
    """The set/delete lines of a planned session (without the fixed session lines)."""
    fixed = {SCREEN, ENTER, EMPTY, COMPARE, CHANGE, LEAVE}
    return [line for line in plan if line not in fixed]


def lab_device(text=""):
    device = FakeJunos()
    if text:
        device.lines = with_lines(text).rstrip("\n").split("\n")
    return device


def _confirmed(record):
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert "check_identity_passed" in steps(record)
    return record


# ---- measured answers ----

def test_measured_statements_give_the_states_of_the_three_tables():
    snapshot = junos.load(with_lines(SELECTED), FIRMWARE)
    system = snapshot.entries("system")["system"]
    assert system.attributes == {"host-name": "host02", "domain-name": "junos-port-ownership.example", "name-servers": "192.0.2.53",
                                 "ntp-source-address": "192.0.2.9"} and not system.unsupported
    ntp = snapshot.entries("ntp-server")
    assert sorted(ntp) == ["192.0.2.1", "2001:db8:1::123"]
    assert all(entry.attributes == {} and not entry.unsupported for entry in ntp.values())
    host = snapshot.entries("syslog-host")["192.0.2.10"]
    assert host.attributes == {"severity": "notice", "port": "5514", "facility-override": "local7"}
    # the local syslog files are no remote host
    assert list(junos.load(with_lines(fixture("show-configuration-system-syslog-display-set__junos_port_ownership.txt")),
                           FIRMWARE).entries("syslog-host")) == ["192.0.2.10"]


def test_measured_candidate_with_prefer_two_source_addresses_and_moved_name_server():
    snapshot = junos.load(with_lines(FINAL), FIRMWARE)
    system = snapshot.entries("system")["system"]
    # two source-addresses (a set adds, measured) are outside the profile: the system table is refused
    # the last measured candidate holds the host-name "-bad" (Junos took it), outside the attribute pattern (r2)
    assert system.unsupported == ["host-name outside the profile pattern", "2 ntp source-addresses"]
    assert system.attributes["name-servers"] == "192.0.2.54 192.0.2.53 2001:db8:1::53"
    ntp = snapshot.entries("ntp-server")
    assert ntp["192.0.2.1"].attributes == {"prefer": "yes"} and ntp["192.0.2.2"].attributes == {}
    assert "2001:db8:1::a1" in ntp
    syslog = snapshot.entries("syslog-host")
    assert syslog["192.0.2.10"].attributes == {"severity": "info", "port": "5515", "facility-override": "local6"}
    assert syslog["2001:db8:1::10"].attributes == {"severity": "warning"}
    moved = junos.load(with_lines(MOVED), FIRMWARE).entries("system")["system"]
    assert moved.attributes["name-servers"] == "192.0.2.54 2001:db8:1::53 192.0.2.53"


def test_scoped_reads_and_the_range_error_answer():
    for name, table, key in (("show-configuration-system-ntp-display-set__junos_port_ownership.txt", "ntp-server", "192.0.2.1"),
                             ("show-configuration-system-syslog-host-192.0.2.10-display-set__junos_port_ownership.txt",
                              "syslog-host", "192.0.2.10")):
        rows = junos.answer_rows(fixture(name))
        assert rows and all(row.startswith("set system ") for row in rows)
        assert key in junos.g145_entries(junos.load("set version 26.2R1.7\n" + "\n".join(rows) + "\n", None), table)
    answer = fixture("set-system-syslog-host-port-70000__range-error.txt")
    # the caret row marks the refusal; the range row is an error row of its own (1.0.12 JUNOS-PORT-OWNERSHIP)
    assert junos.cli_error(answer) == "^"
    assert junos.cli_error(answer.replace(" " * 62 + "^\n", "")).startswith("Value 70000 is not within range")


# ---- plans: only the differing statements, the inverse returns the state before ----

def test_ntp_server_create_prefer_and_delete_with_inverse():
    plan = plan_of(table="ntp-server", op="create", key="192.0.2.1", changes={"prefer": "yes"})
    assert body(plan["commands"]) == ["set system ntp server 192.0.2.1 prefer"]
    assert body(plan["inverse"]) == ["delete system ntp server 192.0.2.1"]
    assert plan["predicted"] == {"before": None, "after": {"prefer": "yes"}}
    text = with_lines("set system ntp server 192.0.2.1 prefer\nset system ntp server 192.0.2.2")
    plan = plan_of(text, table="ntp-server", key="192.0.2.1", changes={"prefer": "no"})
    assert body(plan["commands"]) == ["delete system ntp server 192.0.2.1 prefer"]
    assert body(plan["inverse"]) == ["set system ntp server 192.0.2.1 prefer"]
    plan = plan_of(text, table="ntp-server", op="delete", key="192.0.2.2")
    assert body(plan["commands"]) == ["delete system ntp server 192.0.2.2"]
    assert any("192.0.2.1" in note for note in plan["prechecks"])


def test_syslog_host_lines_replace_single_values():
    plan = plan_of(table="syslog-host", op="create", key="192.0.2.10",
                   changes={"severity": "notice", "port": 5514, "facility-override": "local7"})
    assert body(plan["commands"]) == ["set system syslog host 192.0.2.10 any notice",
                                      "set system syslog host 192.0.2.10 port 5514",
                                      "set system syslog host 192.0.2.10 facility-override local7"]
    assert body(plan["inverse"]) == ["delete system syslog host 192.0.2.10"]
    text = with_lines(SELECTED)
    plan = plan_of(text, table="syslog-host", key="192.0.2.10", changes={"severity": "info", "port": None})
    assert body(plan["commands"]) == ["set system syslog host 192.0.2.10 any info",
                                      "delete system syslog host 192.0.2.10 port"]
    assert body(plan["inverse"]) == ["set system syslog host 192.0.2.10 any notice",
                                     "set system syslog host 192.0.2.10 port 5514"]


def test_system_lines_for_host_name_domain_source_address_and_name_server_order():
    text = with_lines("set system name-server 192.0.2.53\nset system name-server 192.0.2.54\n"
                      "set system name-server 192.0.2.55\nset system ntp source-address 192.0.2.9")
    plan = plan_of(text, changes={"host-name": "host01-junos-port-ownership", "domain-name": "junos-port-ownership.example",
                                  "ntp-source-address": "192.0.2.8"})
    assert body(plan["commands"]) == ["set system host-name host01-junos-port-ownership", "set system domain-name junos-port-ownership.example",
                                      "delete system ntp source-address 192.0.2.9",
                                      "set system ntp source-address 192.0.2.8"]
    assert body(plan["inverse"]) == ["set system host-name host01", "delete system domain-name",
                                     "delete system ntp source-address 192.0.2.8",
                                     "set system ntp source-address 192.0.2.9"]
    # appending touches nothing else; removing a middle server re-enters the later ones (measured order of entry)
    plan = plan_of(text, changes={"name-servers": ["192.0.2.53", "192.0.2.54", "192.0.2.55", "2001:DB8::53"]})
    assert body(plan["commands"]) == ["set system name-server 2001:db8::53"]
    plan = plan_of(text, changes={"name-servers": "192.0.2.53 192.0.2.55"})
    assert body(plan["commands"]) == ["delete system name-server 192.0.2.54", "delete system name-server 192.0.2.55",
                                      "set system name-server 192.0.2.55"]
    assert body(plan["inverse"]) == ["delete system name-server 192.0.2.55", "set system name-server 192.0.2.54",
                                     "set system name-server 192.0.2.55"]
    # the prediction of the commands equals the measured order of entry
    after = junos.load(junos.snapshot_after(text, plan), FIRMWARE).entries("system")["system"]
    assert after.attributes["name-servers"] == "192.0.2.53 192.0.2.55"


@pytest.mark.parametrize(("text", "fields", "fragment"), [
    ("", dict(table="ntp-server", op="create", key="2001:DB8::1", changes={}), "must be written as 2001:db8::1"),
    ("", dict(table="ntp-server", op="create", key="224.0.1.129", changes={}), "not a usable unicast"),
    ("set system ntp server 192.0.2.1 key 1", dict(table="ntp-server", op="delete", key="192.0.2.1"),
     "outside the profile: ntp server key"),
    ("set system ntp server 192.0.2.1", dict(table="ntp-server", op="create", key="192.0.2.1", changes={}),
     "already used"),
    ("", dict(table="ntp-server", op="delete", key="192.0.2.7"), "NTP server 192.0.2.7 is not in the configuration"),
    ("set system syslog host 192.0.2.10 any notice\nset system syslog host 192.0.2.10 source-address 192.0.2.9",
     dict(table="syslog-host", key="192.0.2.10", changes={"port": 5514}), "syslog host statement source-address"),
    ("set system syslog host 192.0.2.10 any notice\nset system syslog host 192.0.2.10 port 5514",
     dict(table="syslog-host", key="192.0.2.10", changes={"severity": None}), "update needs severity"),
    ("set system host-name edge_01", dict(changes={"domain-name": "junos-port-ownership.example"}),
     "host-name outside the profile pattern"),
    ("", dict(table="syslog-host", op="create", key="192.0.2.10", changes={"port": 514}), "create needs severity"),
    ("", dict(table="syslog-host", op="create", key="192.0.2.10", changes={"severity": "bogus"}), "must match"),
    ("", dict(table="syslog-host", op="create", key="192.0.2.10", changes={"severity": "info", "port": 70000}),
     "1..65535"),
    ("", dict(table="syslog-host", op="create", key="192.0.2.10",
              changes={"severity": "info", "facility-override": "local8"}), "must match"),
    ("", dict(changes={"host-name": "-bad"}), "must match"),
    ("", dict(changes={"host-name": None}), "cannot be removed"),
    ("", dict(changes={"name-servers": ["192.0.2.53", "192.0.2.53"]}), "twice"),
    ("set system name-server 192.0.2.53 routing-instance mgmt_junos", dict(changes={"domain-name": "junos-port-ownership.example"}),
     "name-server 192.0.2.53 routing-instance"),
    ("set groups junos-port-ownership system name-server 192.0.2.53\nset apply-groups junos-port-ownership",
     dict(changes={"domain-name": "junos-port-ownership.example"}), "system configuration from groups"),
])
def test_refusals(text, fields, fragment):
    base = with_lines(text) if text else BASELINE
    error = refused(base, **fields)
    assert fragment in " ".join(error.reasons), error.reasons


def test_a_deactivated_ntp_stanza_is_refused():
    base = with_lines("set system ntp server 192.0.2.2") + "deactivate system ntp\n"
    error = refused(base, table="ntp-server", op="delete", key="192.0.2.2")
    assert "deactivated or protected statement" in " ".join(error.reasons)


# ---- the prompt of a host-name change (measured answers through DeviceAccess) ----

def test_the_prompt_anchor_skips_the_old_host_name_in_the_echo_before_the_banner():
    # measured (set-system-host-name__junos_port_ownership-pending-banner.txt): the echo of "set system host-name <old>" carries the
    # old name, then the "# commit confirmed" banner, then the prompt with the NEW name of the pending change
    pending = fixture("set-system-host-name__junos_port_ownership-pending-banner.txt").replace("\n", "\r\n").encode()
    commit = fixture("commit-comment__junos_port_ownership-host-name-back-prompt.txt").replace("\n", "\r\n").encode()
    leave = b"exit configuration-mode \r\nExiting configuration mode\r\n\r\nnetops-admin@host01> "
    shell = Shell([b"\r\nnetops-admin@host02> ", b"set cli screen-width 1024 \r\nScreen width set to 1024\r\n\r\nnetops-admin@host02> ",
                   b"configure exclusive \r\nwarning: uncommitted changes will be discarded on exit\r\n"
                   b"Entering configuration mode\r\n\r\n# commit confirmed will be rolled back "
                   b"in 3 minutes\r\n[edit]\r\nnetops-admin@host02# ", pending, commit, leave])
    # the session of an undo: logged in while the new name host02 is committed, host01 is the name it returns to
    spec = exec_junos.prompt_spec("host02", ("host01",))
    handle = device_access(shell)
    lines = [SCREEN, ENTER, "set system host-name host01", 'commit comment "junos-port-ownership-measure-back"', LEAVE]
    assert handle.apply(lines, spec) == 5
    answers = handle.last_answers
    assert answers[2].rstrip().endswith("netops-admin@host02#")
    assert "commit complete" in answers[3] and answers[3].rstrip().endswith("netops-admin@host01#")
    assert answers[4].rstrip().endswith("netops-admin@host01>")


def test_the_measured_prompt_after_a_host_name_commit_carries_the_new_name():
    answer = fixture("commit-confirmed-3__junos_port_ownership-host-name-prompt.txt")
    assert answer.rstrip().endswith("netops-admin@host02#") and "commit complete" in answer
    spec = exec_junos.prompt_spec("host01", exec_junos.plan_hostnames(
        {"table": "system", "predicted": {"before": {"host-name": "host01"}, "after": {"host-name": "host02"}}},
        "host01"))
    assert spec.anchor == b"@host01" and spec.anchors == (b"@host02",)
    assert exec_junos.prompt_spec("host01").anchors == ()
    assert access._usable_anchor(b"@host01") and not access._usable_anchor(b"@bad name")


# ---- preview, apply, readback and undo through FakeJunos ----

def test_preview_writes_nothing(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    for fields in (dict(changes={"host-name": "host01-junos-port-ownership"}),
                   dict(table="ntp-server", op="create", key="192.0.2.1", changes={}),
                   dict(table="syslog-host", op="create", key="192.0.2.10", changes={"severity": "notice"})):
        result = execute.preview(runtime, NAME, request(**fields))
        assert result["result"] == "ready", result
    assert all(block == PROBE for block in device.applied_blocks) and not device.pending()


def test_ntp_server_and_source_address_are_applied_read_back_and_undone(tmp_path):
    device = lab_device("set system ntp server 192.0.2.2 prefer")
    runtime = make_runtime(tmp_path, device)
    runtime.config.limits["changes_per_device_per_hour"] = 20
    before = list(device.lines)
    created = _confirmed(approved_apply(runtime, NAME, request(table="ntp-server", op="create", key="2001:db8::123",
                                                              changes={"prefer": "yes"})))
    assert "set system ntp server 2001:db8::123 prefer" in device.lines
    assert "set system ntp server 192.0.2.2 prefer" in device.lines
    source = _confirmed(approved_apply(runtime, NAME, request(changes={"ntp-source-address": "192.0.2.9"})))
    assert "set system ntp source-address 192.0.2.9" in device.lines
    _confirmed(execute.undo(runtime, source["change_id"], "remove the test source address"))
    _confirmed(execute.undo(runtime, created["change_id"], "remove the test server"))
    assert device.lines == before


def test_syslog_host_lifecycle_keeps_the_local_files(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    runtime.config.limits["changes_per_device_per_hour"] = 20
    before = list(device.lines)
    files = [line for line in before if line.startswith("set system syslog file ")]
    created = _confirmed(approved_apply(runtime, NAME, request(
        table="syslog-host", op="create", key="192.0.2.10",
        changes={"severity": "notice", "port": 5514, "facility-override": "local7"})))
    changed = _confirmed(approved_apply(runtime, NAME, request(
        table="syslog-host", key="192.0.2.10", changes={"severity": "info", "facility-override": None})))
    assert [line for line in device.lines if "syslog host" in line] == [
        "set system syslog host 192.0.2.10 any info", "set system syslog host 192.0.2.10 port 5514"]
    _confirmed(execute.undo(runtime, changed["change_id"], "back to notice"))
    deleted = _confirmed(approved_apply(runtime, NAME, request(table="syslog-host", op="delete", key="192.0.2.10")))
    assert not any("syslog host" in line for line in device.lines)
    _confirmed(execute.undo(runtime, deleted["change_id"], "recreate"))
    assert "set system syslog host 192.0.2.10 facility-override local7" in device.lines
    _confirmed(execute.undo(runtime, created["change_id"], "remove the test host"))
    assert device.lines == before and [line for line in device.lines if "syslog file" in line] == files


def test_name_servers_keep_the_existing_ones_and_the_undo_restores_the_order(tmp_path):
    device = lab_device("set system name-server 192.0.2.53\nset system name-server 192.0.2.54\n"
                        "set system name-server 192.0.2.55")
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"name-servers": "192.0.2.53 192.0.2.55"})))
    assert [line for line in device.lines if "name-server" in line] == [
        "set system name-server 192.0.2.53", "set system name-server 192.0.2.55"]
    _confirmed(execute.undo(runtime, record["change_id"], "the old resolver order"))
    assert device.lines == before


def test_host_name_and_domain_are_changed_with_the_new_prompt_and_returned(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"host-name": "sw-junos-port-ownership",
                                                                      "domain-name": "junos-port-ownership.example"})))
    assert device.hostname == "sw-junos-port-ownership" and "set system domain-name junos-port-ownership.example" in device.lines
    assert any("prompt" in note for note in record["plan"]["prechecks"])
    _confirmed(execute.undo(runtime, record["change_id"], "the lab name back"))
    assert device.hostname == "host01" and device.lines == before


def test_without_the_new_name_the_session_after_the_host_name_commit_fails():
    # a new name that does not start with the old one (host01-junos-port-ownership would carry "@host01" in its prompt)
    device = lab_device()
    spec = exec_junos.prompt_spec(device.hostname)
    with pytest.raises(access.AccessError) as caught:
        device.apply([SCREEN, ENTER, EMPTY, "set system host-name sw-junos-port-ownership", COMPARE, CHANGE, LEAVE], spec)
    assert "no prompt anchor" in str(caught.value) and caught.value.accepted_lines == 5


def test_verify_sees_a_foreign_change_of_another_object(tmp_path):
    text = with_lines("set system ntp server 192.0.2.2")
    plan = plan_of(text, table="ntp-server", op="create", key="192.0.2.1", changes={})
    after = junos.snapshot_after(text, plan)
    assert verify(plan, after.encode(), expect="after")["result"] == "match"
    foreign = after.replace("set system ntp server 192.0.2.2\n", "")
    result = verify(plan, foreign.encode(), expect="after")
    assert result["result"] == "mismatch" and not result["rest_matches"]


def test_the_readback_refuses_a_read_with_foreign_rows():
    device = SimpleNamespace(query=lambda command: "error: syntax error\n")
    plan = {"table": "ntp-server", "key": "192.0.2.1", "firmware": FIRMWARE}
    with pytest.raises(Rejected):
        exec_junos.observe(device, plan)


# ---- 1.0.12 JUNOS-PORT-OWNERSHIP r2: review findings 3, 4 and 6  ----

def test_r2_3_an_unusable_check_account_refuses_the_change_before_any_write(tmp_path):
    # the password of the check account is not usable: the readback of the write account alone never passes
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    device.check_unreadable = True
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, NAME, request(changes={"host-name": "sw-junos-port-ownership"}))
    assert "check account" in " ".join(caught.value.reasons), caught.value.reasons
    assert all(block == PROBE for block in device.applied_blocks) and device.lines == before


def test_r2_3_a_check_account_lost_after_the_commit_returns_the_change(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)

    def lose_check_account(fake, block):
        if CHANGE in block:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = approved_apply(runtime, NAME, request(changes={"host-name": "sw-junos-port-ownership"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    assert "check_identity_passed" not in steps(record) and "check_identity_failed" in steps(record)
    assert device.lines == before and not device.pending()
    assert "show version" in device.check_queries


def test_r2_3_the_check_account_must_see_the_new_host_name(tmp_path):
    # a check account that still sees the old name (another device behind check_address) is a mismatch
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    stale = device.version_text()

    def stale_name(fake, block):
        if CHANGE in block:
            fake.check_override = {"show version": stale}

    device.on_apply = stale_name
    record = approved_apply(runtime, NAME, request(table="ntp-server", op="create", key="192.0.2.1", changes={}))
    assert record["result"] == "confirmed" and "check_identity_passed" in steps(record)
    record = approved_apply(runtime, NAME, request(changes={"host-name": "sw-junos-port-ownership"}))
    assert record["result"] == "reverted" and "check_identity_passed" not in steps(record), steps(record)
    assert device.hostname == "host01"
    assert [line for line in device.lines if line != "set system ntp server 192.0.2.1"] == before


def test_r2_4_the_undo_returns_a_host_name_with_dots(tmp_path):
    # Junos takes a host name with dots (measured, private measurement record "vjunos-switch.junos-port-ownership"); the undo must return
    # the name read from the device
    device = lab_device("set system host-name edge.example.net")
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    assert device.hostname == "edge.example.net"
    plan = plan_of(with_lines("set system host-name edge.example.net"), changes={"host-name": "edge-new"})
    assert body(plan["commands"]) == ["set system host-name edge-new"]
    assert body(plan["inverse"]) == ["set system host-name edge.example.net"]
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"host-name": "edge-new"})))
    assert device.hostname == "edge-new"
    _confirmed(execute.undo(runtime, record["change_id"], "the old dotted name back"))
    assert device.hostname == "edge.example.net" and device.lines == before


def test_r2_6_a_facility_threshold_is_changed_and_the_other_facilities_stay(tmp_path):
    lines = ("set system syslog host 192.0.2.10 any warning\nset system syslog host 192.0.2.10 authorization info\n"
             "set system syslog host 192.0.2.10 daemon notice\nset system syslog host 192.0.2.10 port 5514")
    host = junos.load(with_lines(lines), FIRMWARE).entries("syslog-host")["192.0.2.10"]
    assert host.attributes == {"severity": "warning", "severity-authorization": "info", "severity-daemon": "notice",
                               "port": "5514"} and not host.unsupported
    plan = plan_of(with_lines(lines), table="syslog-host", key="192.0.2.10", changes={"severity-daemon": "warning"})
    assert body(plan["commands"]) == ["set system syslog host 192.0.2.10 daemon warning"]
    assert body(plan["inverse"]) == ["set system syslog host 192.0.2.10 daemon notice"]
    device = lab_device(lines)
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    assert execute.preview(runtime, NAME, request(table="syslog-host", key="192.0.2.10",
                                                  changes={"severity-daemon": "warning"}))["result"] == "ready"
    record = _confirmed(approved_apply(runtime, NAME, request(table="syslog-host", key="192.0.2.10",
                                                             changes={"severity-daemon": "warning"})))
    assert [line for line in device.lines if "syslog host" in line] == [
        "set system syslog host 192.0.2.10 any warning", "set system syslog host 192.0.2.10 authorization info",
        "set system syslog host 192.0.2.10 daemon warning", "set system syslog host 192.0.2.10 port 5514"]
    _confirmed(execute.undo(runtime, record["change_id"], "daemon back to notice"))
    assert device.lines == before


def test_r2_6_a_facility_only_host_is_created_deleted_and_recreated_by_the_undo(tmp_path):
    device = lab_device("set system syslog host 192.0.2.11 daemon notice")
    runtime = make_runtime(tmp_path, device)
    runtime.config.limits["changes_per_device_per_hour"] = 20
    before = list(device.lines)
    plan = plan_of(table="syslog-host", op="create", key="192.0.2.12", changes={"severity-daemon": "warning"})
    # a facility selector, not facility-override (which relabels the messages of all facilities)
    assert body(plan["commands"]) == ["set system syslog host 192.0.2.12 daemon warning"]
    deleted = _confirmed(approved_apply(runtime, NAME, request(table="syslog-host", op="delete", key="192.0.2.11")))
    assert not any("syslog host" in line for line in device.lines)
    _confirmed(execute.undo(runtime, deleted["change_id"], "recreate the daemon host"))
    # the same statements (FakeJunos places a recreated statement by its words, Junos shows the schema order)
    assert sorted(device.lines) == sorted(before)
