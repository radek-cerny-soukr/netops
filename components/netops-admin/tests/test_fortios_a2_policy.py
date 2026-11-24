"""1.0.13 A2: firewall service group, firewall schedule recurring, firewall schedule onetime (fortios_tab_policy);
the inspection-mode attribute of firewall policy is not delivered (no live run on 8.0.2).

The tables are the shipped registrations with the shipped profiles. Every operation runs the real path: execute
(preview, apply, undo, recover) -> exec_fortios -> the production access.DeviceAccess (one OpenSSH session held per
account, the Fortinet dialog) -> the OpenSSH test client (fortinet_ssh_fixture) -> the simulated device
(fake_fortios_a2) started from the show answers captured on FortiGate-60F 7.6.8 (fixtures/fortios_a2). The parser,
the Snapshot, the planning, rest_digest, rest_inverse, the safeguard rendering, the journal and the audit are real.
"""
from __future__ import annotations

import itertools
from dataclasses import replace

import pytest
from fake_fortios_a2 import (FIXTURES, GROUP, ONETIME, RECURRING, SCHEDULE_GROUP, FakeFortiOSA2, FakeFortiOSA2Webhook,
                             lose_check_after)
from test_execute import request
from test_fortios_tables_registry import audit_events, runtime_for, ssh_sessions  # noqa: F401 (fixture)

from netops_admin import engine, execute, fortios, fortios_tab_policy, fortios_tables, profiles, readiness
from netops_admin.errors import Rejected

REQUESTS = itertools.count(1)
POLICY = "firewall policy"
TESTED, WEBHOOK, UNTESTED = "7.6.8 build3744", "8.0.2 build0251", "7.6.7 build3704"
A2_TABLES = (GROUP, RECURRING, ONETIME)
CREATE = {
    GROUP: ("a2-web", {"member": ["HTTP", "HTTPS"], "comment": "A2 test group"}),
    RECURRING: ("a2-office", {"day": ["friday", "monday"], "start": "08:00", "end": "17:30"}),
    ONETIME: ("a2-window", {"start": "10:00 2026/12/01", "end": "11:30 2026/12/01"}),
}
UPDATE = {
    GROUP: {"member": ["DNS", "HTTPS"]},
    RECURRING: {"end": "18:00"},
    ONETIME: {"expiration-days": "0"},
}
ATTRIBUTE = {GROUP: "service", RECURRING: "schedule", ONETIME: "schedule"}


def ask(table, key, op, changes, **extra):
    return request(table=table, key=key, op=op, changes=changes, request_id="a2-request-%04d" % next(REQUESTS),
                   **extra)


def without_uuids(text):
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("set uuid "))


def steps_of(record):
    steps = [(step["step"], step.get("detail")) for step in record["steps"]]
    return record["result"], record.get("reason_codes"), steps


def approved(runtime, request_):
    current = runtime.lab.device
    before, written = current.snapshot(), list(current.applied_blocks)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    current = runtime.lab.device
    assert current.snapshot() == before and current.applied_blocks == written  # the preview writes nothing
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", steps_of(record)
    assert engine.verify(record["plan"], runtime.lab.device.snapshot().encode())["result"] == "match"
    return record, before


def undone(runtime, record, before):
    preview = execute.preview_undo(runtime, record["change_id"], "Restore the A2 baseline", issue=True)
    assert preview["result"] == "ready", preview
    restored = execute.undo(runtime, record["change_id"], "Restore the A2 baseline", preview["plan_sha256"])
    assert restored["result"] == "confirmed", steps_of(restored)
    current = runtime.lab.device
    assert engine.verify(record["plan"], current.snapshot().encode(), expect="before")["result"] == "match"
    assert without_uuids(current.snapshot()) == without_uuids(before)
    assert not current.stitches and not current.actions and not current.triggers
    return restored


def wired(runtime_for, tmp_path, device=None, **fields):
    """The wired lab (test_fortios_tables_registry.runtime_for) with firewall policy opted in. A profile that is not
    measured yet is refused in production (profile_not_measured, see test_an_unmeasured_profile_is_refused); the
    tests drive it as the live measurement does."""
    runtime = runtime_for(tmp_path, device or FakeFortiOSA2())
    current = runtime.config.devices["lab"]
    fields.setdefault("opt_in", tuple(current.opt_in) + (POLICY,))
    runtime.config = replace(runtime.config, devices={"lab": replace(current, **fields)})
    from enrollment_helpers import certify
    certify(runtime, runtime.lab.device, "lab")  # the enrollment binds the device configuration
    runtime.simulate_unmeasured_profiles = True
    return runtime


def policy_state(**extra):
    return {"srcintf": "port1", "dstintf": "port2", "srcaddr": "all", "dstaddr": "all", "action": "accept",
            "status": "disable", "schedule": "always", "service": "HTTP", **extra}


# ------------------------------------------------------------------------------------------- registration

def test_the_a2_tables_are_registered_with_their_profiles():
    fortios_tables.reset()
    assert set(fortios_tab_policy.TABLES) == set(A2_TABLES) <= fortios_tables.PLANNED_TABLES
    loaded = profiles.load_profiles()
    for table in A2_TABLES:
        item = fortios_tables.hooks(table)
        assert item.kind == "object" and item.impact and item.preview_code == "fortios_object_preview_required"
        assert item.rest_verified == frozenset()  # no REST inverse verified on 8.0.x: refused there
        assert item.policy_attributes == (ATTRIBUTE[table],)
        profile = loaded[("fortios", table)]
        assert profile.versions == (TESTED,) and profile.exact_versions and profile.provisional
        assert not profile.isolated_update and profile.volatile == ("uuid",)
        fortios_tables.check_profile(profile)
    assert set(A2_TABLES) <= set(fortios_tables.impact_tables())
    assert "inspection-mode" not in loaded[("fortios", POLICY)].attributes  # not delivered (no live run on 8.0.2)


def test_the_captured_show_answers_parse_as_the_profiles_read_them():
    header = "#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=netops-rw\n"
    snapshot = fortios.Snapshot(header + (FIXTURES / "service-group-show.txt").read_text()
                                + (FIXTURES / "schedule-recurring-show.txt").read_text())
    assert set(snapshot.entries(GROUP)) == {"Email Access", "Web Access", "Windows AD", "Exchange Server"}
    assert snapshot.entries(ONETIME) == {}  # show omits the empty table
    loaded = profiles.load_profiles()
    state, unsupported = engine._entry_state(snapshot, loaded[("fortios", RECURRING)],
                                             snapshot.entries(RECURRING)["default-darrp-optimize"])
    assert unsupported == [] and state == {"start": "01:00", "end": "01:30",
                                           "day": "friday monday saturday sunday thursday tuesday wednesday"}
    # the defaults show omits are the values show full-configuration lists
    full = (FIXTURES / "schedule-recurring-full.txt").read_text()
    assert "set start 00:00" in full and "set label-day none" in full and "set fabric-object disable" in full
    assert "set comment ''" in (FIXTURES / "service-group-full.txt").read_text()
    # the simulator starts from exactly these answers
    device = FakeFortiOSA2()
    for table, name in ((GROUP, "service-group-show.txt"), (RECURRING, "schedule-recurring-show.txt")):
        assert "\n".join(device.table_lines(table)) + "\n" == (FIXTURES / name).read_text()


# ------------------------------------------------------------------------------------------- create, update, delete

@pytest.mark.parametrize("table", A2_TABLES)
def test_create_update_delete_with_undo(runtime_for, tmp_path, table):
    key, changes = CREATE[table]
    runtime = wired(runtime_for, tmp_path)
    created, baseline = approved(runtime, ask(table, key, "create", changes))
    assert created["plan"]["predicted"]["before"] is None
    shown = runtime.lab.device.check_query('show %s "%s"' % (table, key))
    assert shown.splitlines()[2].strip().startswith("set uuid ")
    updated, before_update = approved(runtime, ask(table, key, "update", UPDATE[table]))
    undone(runtime, updated, before_update)
    deleted, before_delete = approved(runtime, ask(table, key, "delete", {}))
    assert key not in runtime.lab.device.tables[table].objects
    assert deleted["plan"]["inverse_identity_changes"] == ["uuid"]
    recreated = undone(runtime, deleted, before_delete)
    undone(runtime, recreated, baseline)  # The recreation has its own UUID and journal record.
    assert key not in runtime.lab.device.tables[table].objects
    sessions = ssh_sessions(runtime)
    assert set(sessions) == {("netops-rw", "192.0.2.1"), ("netops-check", "198.51.100.15")}


def test_the_rendered_commands_follow_the_measured_cli(runtime_for, tmp_path):
    runtime = wired(runtime_for, tmp_path)
    group, _ = approved(runtime, ask(GROUP, *CREATE[GROUP][:1], "create", CREATE[GROUP][1]))
    assert group["plan"]["commands"] == ["config firewall service group", '    edit "a2-web"',
                                         '        set comment "A2 test group"', '        set member "HTTP" "HTTPS"',
                                         "    next", "end"]
    recurring, _ = approved(runtime, ask(RECURRING, "a2-office", "create", CREATE[RECURRING][1]))
    assert recurring["plan"]["predicted"]["after"] == {"day": "friday monday", "start": "08:00", "end": "17:30"}
    assert runtime.lab.device.tables[RECURRING].objects["a2-office"]["attrs"]["day"] == "monday friday"
    onetime, _ = approved(runtime, ask(ONETIME, "a2-window", "create", CREATE[ONETIME][1]))
    # FortiOS refuses a quoted start or end (-160): Admin writes the two words unquoted
    assert onetime["plan"]["commands"] == ["config firewall schedule onetime", '    edit "a2-window"',
                                           "        set start 10:00 2026/12/01", "        set end 11:30 2026/12/01",
                                           "    next", "end"]
    assert onetime["plan"]["inverse"] == ["config firewall schedule onetime", '    delete "a2-window"', "end"]
    # a change from the measured default returns by an explicit set of the default (design A 1.5b)
    expiry, _ = approved(runtime, ask(ONETIME, "a2-window", "update", {"expiration-days": "0"}))
    assert expiry["plan"]["inverse"][2] == "        set expiration-days 3"


def test_a_device_that_refuses_a_quoted_time_never_sees_one(runtime_for, tmp_path):
    runtime = wired(runtime_for, tmp_path)
    (runtime.lab.directory / "refuse-line").write_text('set start "')
    approved(runtime, ask(ONETIME, "a2-window", "create", CREATE[ONETIME][1]))


def test_a_refused_line_ends_in_change_failed_and_the_object_returns(runtime_for, tmp_path):
    runtime = wired(runtime_for, tmp_path)
    request_ = ask(GROUP, "a2-web", "create", CREATE[GROUP][1])
    preview = execute.preview(runtime, "lab", request_)
    (runtime.lab.directory / "refuse-line").write_text('set member "HTTP" "HTTPS"')
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert "change_failed" in [step["step"] for step in record["steps"]], steps_of(record)
    assert record["result"] in ("reverted", "failed"), steps_of(record)
    assert "a2-web" not in runtime.lab.device.tables[GROUP].objects


# ------------------------------------------------------------------------------------------- refusals before a write

@pytest.mark.parametrize("identity", ["replaced", "unrecorded"])
def test_undo_create_requires_the_original_uuid(runtime_for, tmp_path, identity):
    runtime = wired(runtime_for, tmp_path)
    key, changes = CREATE[GROUP]
    created, _ = approved(runtime, ask(GROUP, key, "create", changes))
    if identity == "replaced":
        device = runtime.lab.device
        objects = device.tables[GROUP].objects
        attrs = objects[key]["attrs"]
        # A different object with the same attributes and key has a fresh FortiOS UUID.
        attrs["uuid"] = device._uuid()
        runtime.lab.store(device)
    else:
        # A confirmed journal from before UUIDs were recorded provides no proof of identity.
        created.pop("fortios_object_uuid", None)
        runtime.store.save(created)
    before = runtime.lab.device.snapshot()
    written = list(runtime.lab.device.applied_blocks)
    preview = execute.preview_undo(runtime, created["change_id"], "Undo the original creation")
    assert preview["result"] == "rejected" and "identity" in " ".join(preview["reasons"]), preview
    with pytest.raises(Rejected, match="identity") as caught:
        execute.undo(runtime, created["change_id"], "Undo the original creation")
    if identity == "replaced":
        assert (preview["reason_codes"], caught.value.reason_codes) == (
            ["undo_identity_mismatch"], ["undo_identity_mismatch"],
        )
    assert runtime.lab.device.snapshot() == before and runtime.lab.device.applied_blocks == written


def test_delete_refuses_a_key_used_in_another_table(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    key = "shared-name"
    device.tables[GROUP].objects[key] = device.tables[GROUP].objects.pop("Web Access")
    device.addresses[key.upper()] = dict(device.addresses["all"])
    runtime = wired(runtime_for, tmp_path, device)
    before = runtime.lab.device.snapshot()
    preview = execute.preview(runtime, "lab", ask(GROUP, key, "delete", {}))
    assert preview["result"] == "rejected" and "already used" in " ".join(preview["reasons"]), preview
    assert runtime.lab.device.snapshot() == before and not runtime.lab.device.applied_blocks


def test_update_refuses_a_comment_undo_cannot_submit(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    key = "maintenance"
    device.tables[GROUP].objects[key] = device.tables[GROUP].objects.pop("Web Access")
    device.tables[GROUP].objects[key]["attrs"]["comment"] = "Údržba"
    runtime = wired(runtime_for, tmp_path, device)
    before = runtime.lab.device.snapshot()
    preview = execute.preview(runtime, "lab", ask(GROUP, key, "update", {"comment": "Maintenance"}))
    assert preview["result"] == "rejected" and "printable ASCII" in " ".join(preview["reasons"]), preview
    assert runtime.lab.device.snapshot() == before and not runtime.lab.device.applied_blocks


def test_update_refuses_to_restore_an_inverted_schedule(runtime_for, tmp_path):
    from netops_auditor import l1_fortios

    capture = (FIXTURES / "probe-onetime-unquoted.txt").read_text()
    section = next(block.split("\nend", 1)[0] for block in capture.split("\nconfig " + ONETIME + "\n")
                   if '    edit "' in block and "set end 09:00 2026/12/01" in block.split("\nend", 1)[0])
    node, = l1_fortios.parse("config " + ONETIME + "\n" + section + "\nend\n").sub[ONETIME].entries.values()
    key = node.path[-1]
    device = FakeFortiOSA2()
    device.tables[ONETIME].objects[key] = {"attrs": {name: field.value() for name, field in node.attrs.items()},
                                         "children": {}}
    runtime = wired(runtime_for, tmp_path, device)
    before = runtime.lab.device.snapshot()
    preview = execute.preview(runtime, "lab", ask(ONETIME, key, "update", {"end": "11:30 2026/12/01"}))
    assert preview["result"] == "rejected" and "end must be later" in " ".join(preview["reasons"]), preview
    assert runtime.lab.device.snapshot() == before and not runtime.lab.device.applied_blocks


@pytest.mark.parametrize("table", A2_TABLES)
def test_apply_without_the_approved_preview_is_refused(runtime_for, tmp_path, table):
    runtime = wired(runtime_for, tmp_path)
    before = runtime.lab.device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(table, CREATE[table][0], "create", CREATE[table][1]))
    assert caught.value.reason_codes == ["fortios_object_preview_required"]
    assert runtime.lab.device.applied_blocks == [] and runtime.lab.device.snapshot() == before
    assert ssh_sessions(runtime) == [] and audit_events(tmp_path) == []


@pytest.mark.parametrize(("table", "key", "changes", "reason"), [
    (GROUP, "a2-web", {"member": ["HTTP", "missing-svc"]}, "missing from the snapshot: missing-svc"),
    (GROUP, "a2-web", {"member": ["HTTP", "Web Access"]}, "space or a quote"),
    (RECURRING, "a2-office", {"day": ["monday", "holiday"]}, "day must name one or more weekdays"),
    (ONETIME, "a2-window", {"start": "10:00 2026/12/01", "end": "09:00 2026/12/01"}, "end must be later"),
    (ONETIME, "a2-window", {"start": "10:00 2026/12/01", "end": "10:00 2026/12/01"}, "end must be later"),
    (ONETIME, "a2-window", {"start": "10:00 2026/02/29", "end": "10:00 2026/03/01"}, "HH:MM YYYY/MM/DD"),
])
def test_invalid_objects_are_refused_in_the_preview(runtime_for, tmp_path, table, key, changes, reason):
    runtime = wired(runtime_for, tmp_path)
    preview = execute.preview(runtime, "lab", ask(table, key, "create", changes))
    assert preview["result"] == "rejected" and reason in " ".join(preview["reasons"]), preview
    assert runtime.lab.device.applied_blocks == []


@pytest.mark.parametrize(("table", "changes"), [
    (RECURRING, {"day": ["monday"], "start": "8:05"}),
    (ONETIME, {"start": "10:00 2026/12/1", "end": "11:30 2026/12/01"}),
    (ONETIME, {"start": '10:00 2026/12/01" set comment x', "end": "11:30 2026/12/01"}),
    (ONETIME, {"start": "10:00 2026/12/01", "end": "11:30 2026/12/02", "expiration-days": "101"}),
])
def test_values_outside_the_measured_form_are_refused(table, changes):
    profile = profiles.load_profiles()[("fortios", table)]
    from netops_admin.request import canonical_value
    with pytest.raises(Rejected):
        for name, value in changes.items():
            canonical_value(profile.attributes[name], value, "fortios")


def test_a_group_never_holds_itself(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.tables[GROUP].objects["a2-outer"] = {"attrs": {"member": "a2-inner HTTP"}, "children": {}}
    device.tables[GROUP].objects["a2-inner"] = {"attrs": {"member": "HTTPS"}, "children": {}}
    runtime = wired(runtime_for, tmp_path, device)
    for key, members in (("a2-inner", ["a2-outer"]), ("a2-inner", ["a2-inner", "DNS"])):
        preview = execute.preview(runtime, "lab", ask(GROUP, key, "update", {"member": members}))
        assert preview["result"] == "rejected" and "would hold itself" in " ".join(preview["reasons"]), preview


@pytest.mark.parametrize("table", A2_TABLES)
def test_delete_of_an_object_a_policy_uses_is_refused(runtime_for, tmp_path, table):
    key, changes = CREATE[table]
    device = FakeFortiOSA2()
    runtime = wired(runtime_for, tmp_path, device)
    approved(runtime, ask(table, key, "create", changes))
    current = runtime.lab.device
    current.policies["7"] = policy_state(**{ATTRIBUTE[table]: key})
    runtime.lab.store(current)
    preview = execute.preview(runtime, "lab", ask(table, key, "delete", {}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_object_referenced"], preview


def test_a_schedule_change_of_an_active_policy_needs_endpoint_impact(runtime_for, tmp_path):
    runtime = wired(runtime_for, tmp_path)
    created, _ = approved(runtime, ask(RECURRING, "a2-office", "create", CREATE[RECURRING][1]))
    current = runtime.lab.device
    current.policies["7"] = policy_state(schedule="a2-office", status="enable")
    runtime.lab.store(current)
    change = {"end": "19:00"}
    preview = execute.preview(runtime, "lab", ask(RECURRING, "a2-office", "update", change))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_policy_impact_required"], preview
    # a comment-free schedule has no harmless attribute: every change alters the traffic of the policy
    record, before = approved(runtime, ask(RECURRING, "a2-office", "update", change, endpoint_impact="a2-office"))
    assert record["plan"]["endpoint_impact"] == "a2-office"
    assert any("Explicit endpoint impact accepted for firewall schedule recurring a2-office" in line
               for line in record["plan"]["prechecks"])
    undone(runtime, record, before)  # the undo of the saved plan needs no new confirmation
    assert created["result"] == "confirmed"


def test_a_member_of_a_group_an_active_policy_uses_needs_endpoint_impact(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.tables[GROUP].objects["a2-inner"] = {"attrs": {"member": "HTTPS"}, "children": {}}
    device.tables[GROUP].objects["a2-outer"] = {"attrs": {"member": "a2-inner HTTP"}, "children": {}}
    device.policies["7"] = policy_state(service="a2-outer", status="enable")
    runtime = wired(runtime_for, tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(GROUP, "a2-inner", "update", {"member": ["DNS"]}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_policy_impact_required"], preview
    assert "through a2-outer" in " ".join(preview["reasons"])
    # a comment change does not alter the traffic
    approved(runtime, ask(GROUP, "a2-inner", "update", {"comment": "documented"}))


def test_a_schedule_in_a_schedule_group_of_an_active_policy_needs_endpoint_impact(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.tables[ONETIME].objects["a2-window"] = {
        "attrs": {"start": "10:00 2026/12/01", "end": "11:30 2026/12/01"}, "children": {}}
    device.tables[SCHEDULE_GROUP].objects["a2-sgroup"] = {"attrs": {"member": "a2-window"}, "children": {}}
    device.policies["7"] = policy_state(schedule="a2-sgroup", status="enable")
    runtime = wired(runtime_for, tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(ONETIME, "a2-window", "update", {"end": "12:00 2026/12/01"}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_policy_impact_required"], preview
    approved(runtime, ask(ONETIME, "a2-window", "update", {"end": "12:00 2026/12/01"}, endpoint_impact="a2-window"))


def test_an_object_of_a_protected_policy_is_never_changed(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.tables[GROUP].objects["a2-web"] = {"attrs": {"member": "HTTP"}, "children": {}}
    device.policies["7"] = policy_state(service="a2-web", status="enable")
    runtime = wired(runtime_for, tmp_path, device,
                    protected={"system interface": ["wan1"], "firewall policy": ["7"]})
    preview = execute.preview(runtime, "lab", ask(GROUP, "a2-web", "update", {"member": ["HTTPS"]},
                                                  endpoint_impact="a2-web"))
    assert preview["result"] == "rejected" and "protected firewall policies 7" in " ".join(preview["reasons"])


# ------------------------------------------------------------------------------------------- safeguard and readback

@pytest.mark.parametrize("table", A2_TABLES)
def test_the_lost_check_account_after_the_change_is_reverted_by_the_safeguard(runtime_for, tmp_path, table):
    device = FakeFortiOSA2()
    device.on_apply = lose_check_after(table)
    runtime = wired(runtime_for, tmp_path, device)
    request_ = ask(table, CREATE[table][0], "create", CREATE[table][1])
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", steps_of(record)
    assert "check_identity_failed" in [step["step"] for step in record["steps"]] or \
        "final_check_failed" in [step["step"] for step in record["steps"]], steps_of(record)
    assert CREATE[table][0] not in runtime.lab.device.tables[table].objects


class Interrupted(BaseException):
    pass


def test_an_interrupted_apply_is_recovered_by_the_safeguard(runtime_for, tmp_path, monkeypatch):
    runtime = wired(runtime_for, tmp_path)
    request_ = ask(RECURRING, "a2-office", "create", CREATE[RECURRING][1])
    preview = execute.preview(runtime, "lab", request_)
    step = execute._step

    def interrupt(runtime_, record, name, detail=None):
        step(runtime_, record, name, detail)
        if name == "change_applied":
            raise Interrupted()

    with monkeypatch.context() as patch:
        patch.setattr(execute, "_step", interrupt)
        with pytest.raises(Interrupted):
            execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert "a2-office" in runtime.lab.device.tables[RECURRING].objects
    settled, = execute.recover(runtime, "lab")
    assert settled["result"] == "reverted", settled["steps"]
    assert "a2-office" not in runtime.lab.device.tables[RECURRING].objects
    assert execute.recover(runtime, "lab") == []


def test_an_incomplete_readback_is_not_confirmed(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.check_after_write = {'show firewall service group "a2-web"':
                                'config firewall service group\n    edit "a2-web"\n        set member "HTTP"\n'}
    runtime = wired(runtime_for, tmp_path, device)
    request_ = ask(GROUP, "a2-web", "create", CREATE[GROUP][1])
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", steps_of(record)
    assert "a2-web" not in runtime.lab.device.tables[GROUP].objects


def test_a_shown_attribute_outside_the_profile_refuses_the_object(runtime_for, tmp_path):
    device = FakeFortiOSA2()
    device.tables[GROUP].objects["a2-web"] = {"attrs": {"member": "HTTP", "color": "5"}, "children": {}}
    runtime = wired(runtime_for, tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(GROUP, "a2-web", "update", {"comment": "x"}))
    assert preview["result"] == "rejected" and "outside the profile" in " ".join(preview["reasons"]), preview


# ------------------------------------------------------------------------------------------- versions

@pytest.mark.parametrize("table", A2_TABLES)
def test_fortios_8_0_2_refuses_every_operation_before_any_write(runtime_for, tmp_path, table):
    device = FakeFortiOSA2Webhook()
    runtime = wired(runtime_for, tmp_path, device)
    request_ = ask(table, CREATE[table][0], "create", CREATE[table][1])
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"], preview
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["safeguard_no_rest_inverse"]
    current = runtime.lab.device
    assert current.applied_blocks == [] and not current.api_users and not current.webhooks
    operations = readiness._operations("fortios", WEBHOOK)[table]
    assert operations.startswith("refused"), operations


@pytest.mark.parametrize("table", A2_TABLES)
def test_an_unmeasured_profile_is_refused(runtime_for, tmp_path, table):
    runtime = wired(runtime_for, tmp_path)
    runtime.simulate_unmeasured_profiles = False
    request_ = ask(table, CREATE[table][0], "create", CREATE[table][1])
    if profiles.load_profiles()[("fortios", table)].measured:
        assert execute.preview(runtime, "lab", request_)["result"] == "ready"
    else:
        with pytest.raises(Rejected) as caught:
            execute.preview(runtime, "lab", request_)
        assert caught.value.reason_codes == ["profile_not_measured"]
    assert runtime.lab.device.applied_blocks == []


@pytest.mark.parametrize("table", A2_TABLES)
def test_an_untested_build_is_a_warning(table):
    profile = profiles.load_profiles()[("fortios", table)]
    assert profiles.firmware_support(profile, UNTESTED)["status"] == "untested"
    expected = "tested" if profile.measured else "untested"
    assert profiles.firmware_support(profile, TESTED)["status"] == expected


# ------------------------------------------------------------------------------------------- policy inspection-mode

def with_policy(device, **extra):
    device.policies["7"] = policy_state(**extra)
    return device


def test_inspection_mode_is_not_delivered_without_the_measurement_on_8_0_2(runtime_for, tmp_path):
    # design A 4 (A2): inspection-mode joins the policy profile only with a live update and undo through Admin on
    # 7.6.8 and on 8.0.2; the 8.0.2 run could not use the webhook safeguard (see the result of the group), so the
    # attribute is not managed: a request naming it is refused before any write
    assert "inspection-mode" not in profiles.load_profiles()[("fortios", POLICY)].attributes
    probe = (FIXTURES / "probe-policy-inspection-mode.txt").read_text()
    assert "inspection-mode     : proxy" in probe and "entry is not found in table" in probe  # measured, not saved
    runtime = wired(runtime_for, tmp_path, with_policy(FakeFortiOSA2()))
    preview = execute.preview(runtime, "lab", ask(POLICY, "7", "update", {"inspection-mode": "proxy"}))
    assert preview["result"] == "rejected" and "inspection-mode" in " ".join(preview["reasons"]), preview
    # a policy that already shows inspection-mode proxy holds configuration outside the profile: Admin leaves it
    current = runtime.lab.device
    current.policies["7"]["inspection-mode"] = "proxy"
    runtime.lab.store(current)
    preview = execute.preview(runtime, "lab", ask(POLICY, "7", "update", {"comments": "documented"}))
    assert preview["result"] == "rejected" and "inspection-mode" in " ".join(preview["reasons"]), preview
    assert runtime.lab.device.applied_blocks == []

