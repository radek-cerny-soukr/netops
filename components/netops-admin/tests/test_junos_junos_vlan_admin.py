"""1.0.12 JUNOS-VLAN-ADMIN (Junos ELS, vJunos-switch 26.2R1.7): VLAN create/rename/description/delete (J08, J20), access/trunk
with tagged and native VLAN (J07), voice VLAN (J50), VLAN statements inherited from groups and interface-ranges
(JP12) and a long UTF-8 port description (JP17).

Parsers and the inheritance evaluation run on anonymised outputs measured on the lab switch (fixtures/junos_26_2R1_7,
files *__junos_vlan_admin-*, private measurement record); preview, apply, readback and undo run against FakeJunos, whose answers are built
from the same measured layouts."""
from __future__ import annotations

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos, fixture

from netops_admin import exec_junos, execute, junos
from netops_admin.engine import build_plan, plan_digest, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from test_junos import CHANGE, COMPARE, EMPTY, ENTER, LEAVE, NAME, PROBE, SCREEN, make_runtime, steps
from approved_apply import approved_apply

COMPOSITE = fixture("show-configuration-display-set__junos_vlan_admin-composite.txt")
LONG = fixture("show-configuration-interfaces-ge-0-0-2-display-set__junos_vlan_admin-access-voice-utf8.txt").split(
    "description ", 1)[1].split("\n", 1)[0].strip('"')
SYMBOLS = fixture("show-configuration-interfaces-ge-0-0-2-display-set__junos_vlan_admin-symbols-240.txt").split(
    "description ", 1)[1].split("\n", 1)[0][1:-1]
SW = "unit 0 family ethernet-switching"
MEMBERS = "interfaces ge-0/0/2 %s vlan members" % SW


COUNTER = iter(range(1, 10000))


def request(**fields):
    fields.setdefault("request_id", "junos-vlan-admin-unit-%04d" % next(COUNTER))
    fields.setdefault("op", "update")
    fields.setdefault("key", "ge-0/0/2")
    fields.setdefault("table", "vlan-membership")
    return parse_request(request_bytes(**fields))


def plan_of(text=BASELINE, **fields):
    return build_plan("junos", text.encode(), request(**fields), firmware=FIRMWARE)


def refused(text=BASELINE, **fields):
    with pytest.raises(Rejected) as caught:
        plan_of(text, **fields)
    return caught.value


def lab_device(extra=""):
    """FakeJunos with the measured test VLANs (private measurement record) and optional further statements."""
    device = FakeJunos()
    device.lines += ["set vlans junos-vlan-admin-data vlan-id 3901", "set vlans junos-vlan-admin-voice vlan-id 3902",
                     "set vlans junos-vlan-admin-trunk vlan-id 3903"] + [line for line in extra.split("\n") if line]
    return device


# ---- measured answers (J07, J50, J08, JP12, JP17) ----

def test_switching_rows_of_access_voice_and_trunk_ports():
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__junos_vlan_admin-ro-access-voice.txt"),
                           "ge-0/0/2") == [("junos-vlan-admin-data", "untagged"), ("junos-vlan-admin-voice", "tagged")]
    # a native-vlan-id whose VLAN is no member is committed, but the port does not carry it (measured)
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__junos_vlan_admin-ro-trunk-native-not-member.txt"),
                           "ge-0/0/2") == [("junos-vlan-admin-trunk", "tagged"), ("junos-vlan-admin-data", "tagged")]
    rows = junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-2__junos_vlan_admin-ro-trunk-native-member.txt"),
                           "ge-0/0/2")
    assert sorted(rows) == [("junos-vlan-admin-data", "tagged"), ("junos-vlan-admin-voice", "untagged")]
    assert junos.switching(fixture("show-ethernet-switching-interface-ge-0-0-7__junos_vlan_admin-ro-group.txt"),
                           "ge-0/0/7") == [("junos-vlan-admin-data", "untagged")]


def test_vlan_list_mode_and_detail_of_the_check_account():
    tags = junos.vlan_tags(fixture("show-vlans__junos_vlan_admin-ro.txt"))
    assert {tags["3901"], tags["3902"], tags["3903"], tags["10"], tags["1"]} == {
        "junos-vlan-admin-data", "junos-vlan-admin-voice", "junos-vlan-admin-trunk", "D10", "default"}
    access = fixture("show-vlans-junos-vlan-admin-data-extensive__ro-access.txt")
    assert junos.vlan_port_mode(access, "ge-0/0/2") == "access" and junos.vlan_port_mode(access, "ge-0/0/7") == "access"
    assert junos.vlan_port_mode(access, "ge-0/0/5") is None
    assert junos.vlan_detail(access, "junos-vlan-admin-data") == {"interfaces": ["ge-0/0/2.0", "ge-0/0/7.0"], "macs": 0}
    trunk = fixture("show-vlans-junos-vlan-admin-data2-extensive__junos_vlan_admin-trunk-group.txt")
    assert junos.vlan_port_mode(trunk, "ge-0/0/2") == "trunk" and junos.vlan_port_mode(trunk, "ge-0/0/7") == "access"
    assert junos.vlan_port_mode(fixture("show-vlans-junos-vlan-admin-voice-extensive__ro-access-voice.txt"), "ge-0/0/2") == "access"
    assert junos.vlan_port_mode(fixture("show-vlans-junos-vlan-admin-voice-extensive__ro-trunk-native.txt"), "ge-0/0/2") == "trunk"


@pytest.mark.parametrize("text", ["", "\nerror: syntax error, expecting <command>: vlanz\n",
                                  "\nRouting instance        VLAN name             Tag          Interfaces\n"
                                  "default-switch          junos-vlan-admin-data\n"])
def test_an_unreadable_or_cut_vlan_list_is_refused(text):
    with pytest.raises(Rejected):
        junos.vlan_tags(text)


def test_a_vlan_answer_without_its_mac_count_is_incomplete():
    text = fixture("show-vlans-junos-vlan-admin-data-extensive__ro-access.txt")
    cut = text.split("Total MAC count")[0]
    with pytest.raises(Rejected):
        junos.vlan_detail(cut, "junos-vlan-admin-data")
    with pytest.raises(Rejected):
        junos.vlan_detail(text, "junos-vlan-admin-voice")


def test_utf8_descriptions_are_read_literally():
    assert "Žďár" in LONG and "→" in LONG and len(LONG) > 200
    assert junos.description_of(fixture("show-interfaces-descriptions__junos_vlan_admin-ro-utf8.txt"), "ge-0/0/2") == LONG
    assert len(SYMBOLS) <= 240 and "|" in SYMBOLS and "☎" in SYMBOLS
    assert junos.description_of(fixture("show-interfaces-descriptions__junos_vlan_admin-ro-symbols-240.txt"),
                                "ge-0/0/2") == SYMBOLS
    entry = junos.load(COMPOSITE, FIRMWARE).entries("interface")["ge-0/0/2"]
    assert entry.attributes == {"description": LONG} and not entry.unsupported


# ---- inheritance evaluation against the device's own view (JP12) ----

@pytest.mark.parametrize("port, name, kind", [
    ("ge-0/0/7", "show-configuration-interfaces-ge-0-0-7-display-inheritance-display-set__junos_vlan_admin-group.txt", "group"),
    ("ge-0/0/8", "show-configuration-interfaces-ge-0-0-8-display-inheritance-display-set__junos_vlan_admin-wildcard-group.txt",
     "group"),
    ("ge-0/0/9", "show-configuration-interfaces-ge-0-0-9-display-inheritance-display-set__junos_vlan_admin-range.txt",
     "interface-range"),
])
def test_the_evaluated_inheritance_equals_display_inheritance(port, name, kind):
    snapshot = junos.load(COMPOSITE, FIRMWARE)
    measured = sorted(row for row in fixture(name).split("\n") if row.startswith("set "))
    assert sorted("set interfaces %s %s" % (port, rest) for rest in snapshot.effective(port)) == measured
    _found, owners, unsupported = snapshot.owners("vlan-membership", port)
    assert owners["members"].kind == kind and not unsupported
    assert owners["members"].scope == [port]


def test_inherited_and_own_vlan_statements_give_the_port_state():
    entries = junos.load(COMPOSITE, FIRMWARE).entries("vlan-membership")
    assert entries["ge-0/0/2"].attributes == {"access-vlan": "junos-vlan-admin-data", "voice-vlan": "junos-vlan-admin-voice"}
    assert entries["ge-0/0/7"].attributes == {"access-vlan": "junos-vlan-admin-data"}
    assert entries["ge-0/0/8"].attributes == {"access-vlan": "junos-vlan-admin-trunk"}
    assert entries["ge-0/0/9"].attributes == {"access-vlan": "junos-vlan-admin-voice"}
    assert not any(entries[port].unsupported for port in ("ge-0/0/2", "ge-0/0/7", "ge-0/0/8", "ge-0/0/9"))


def test_an_inherited_access_vlan_is_edited_in_its_group_and_the_origin_is_shown():
    plan = plan_of(COMPOSITE, key="ge-0/0/7", changes={"access-vlan": "junos-vlan-admin-voice"})
    group = "groups junos-vlan-admin-grp interfaces ge-0/0/7 %s vlan members" % SW
    assert plan["commands"] == [SCREEN, ENTER, EMPTY, "delete " + group, "set %s junos-vlan-admin-voice" % group, COMPARE, CHANGE,
                                LEAVE]
    assert plan["inverse"][3:5] == ["delete " + group, "set %s junos-vlan-admin-data" % group]
    assert ("members of ge-0/0/7 is inherited from configuration group junos-vlan-admin-grp (ge-0/0/7); the change edits it there "
            "and applies to ge-0/0/7") in plan["prechecks"]
    after = COMPOSITE.replace("interfaces ge-0/0/7 %s vlan members junos-vlan-admin-data" % SW,
                              "interfaces ge-0/0/7 %s vlan members junos-vlan-admin-voice" % SW)
    assert verify(plan, after.encode())["result"] == "match"
    assert verify(plan, COMPOSITE.encode(), expect="before")["result"] == "match"


def test_a_wildcard_group_and_a_range_are_edited_where_they_configure_the_port():
    plan = plan_of(COMPOSITE, key="ge-0/0/8", changes={"access-vlan": "junos-vlan-admin-data"})
    assert plan["commands"][3:5] == [
        'delete groups junos-vlan-admin-grpw interfaces "<ge-0/0/[89]>" %s vlan members' % SW,
        'set groups junos-vlan-admin-grpw interfaces "<ge-0/0/[89]>" %s vlan members junos-vlan-admin-data' % SW]
    plan = plan_of(COMPOSITE, key="ge-0/0/9", changes={"access-vlan": "junos-vlan-admin-data"})
    assert plan["commands"][3:5] == ["delete interfaces interface-range junos-vlan-admin-rng %s vlan members" % SW,
                                     "set interfaces interface-range junos-vlan-admin-rng %s vlan members junos-vlan-admin-data" % SW]


@pytest.mark.parametrize("extra, port, fragment", [
    ("set interfaces interface-range junos-vlan-admin-rng member ge-0/0/6\n", "ge-0/0/9", "also configures ge-0/0/6"),
    ("set apply-groups junos-vlan-admin-grpw\nset interfaces ge-0/0/9 unit 0 family ethernet-switching interface-mode access\n",
     "ge-0/0/8", "also configures ge-0/0/9"),
])
def test_an_inherited_statement_shared_with_other_ports_is_refused_with_them(extra, port, fragment):
    caught = refused(COMPOSITE + extra, key=port, changes={"access-vlan": "junos-vlan-admin-data"})
    assert caught.reason_codes == ["inherited_shared"] and fragment in caught.reasons[0]


@pytest.mark.parametrize("extra, fragment", [
    ("set interfaces ge-0/0/7 unit 0 family ethernet-switching vlan members junos-vlan-admin-voice\n", "is configured in"),
    ("set interfaces ge-0/0/7 apply-groups-except junos-vlan-admin-grpw\n", "apply-groups-except"),
    ("set groups junos-vlan-admin-grp when chassis node0\n", "condition"),
])
def test_inheritance_the_adapter_does_not_evaluate_is_refused(extra, fragment):
    caught = refused(COMPOSITE + extra, key="ge-0/0/7", changes={"access-vlan": "junos-vlan-admin-voice"})
    assert fragment in " ".join(caught.reasons)


# ---- trunk, native and voice VLAN (J07, J50) ----

TRUNK = {"mode": "trunk", "trunk-vlans": ["D10", "D20"], "native-vlan": 10, "access-vlan": None}


def test_access_to_trunk_with_tagged_and_native_vlan_and_its_inverse():
    plan = plan_of(changes=TRUNK)
    assert plan["commands"] == [SCREEN, ENTER, EMPTY, "set interfaces ge-0/0/2 %s interface-mode trunk" % SW,
                                "delete " + MEMBERS, "set %s D10" % MEMBERS, "set %s D20" % MEMBERS,
                                "set interfaces ge-0/0/2 native-vlan-id 10", COMPARE, CHANGE, LEAVE]
    assert plan["inverse"] == [SCREEN, ENTER, EMPTY, "set interfaces ge-0/0/2 %s interface-mode access" % SW,
                               "delete " + MEMBERS, "set %s default" % MEMBERS,
                               "delete interfaces ge-0/0/2 native-vlan-id", COMPARE, CHANGE, LEAVE]
    assert plan["predicted"] == {"before": {"access-vlan": "default"},
                                 "after": {"mode": "trunk", "trunk-vlans": "D10 D20", "native-vlan": "10"}}
    after = BASELINE.replace("set interfaces ge-0/0/2 %s interface-mode access\nset %s default\n" % (SW, MEMBERS),
                             "set interfaces ge-0/0/2 native-vlan-id 10\nset interfaces ge-0/0/2 %s interface-mode "
                             "trunk\nset %s D10\nset %s D20\n" % (SW, MEMBERS, MEMBERS))
    assert verify(plan, after.encode())["result"] == "match"


@pytest.mark.parametrize("key, changes, fragment, code", [
    ("ge-0/0/2", {"mode": "trunk", "access-vlan": None}, "needs trunk-vlans", None),
    ("ge-0/0/1", {"mode": "trunk", "trunk-vlans": ["D10"]}, "has no access-vlan", None),
    ("ge-0/0/2", {"mode": "trunk", "trunk-vlans": ["D10"], "native-vlan": 20}, "must be one of", None),
    ("ge-0/0/2", {"mode": "trunk", "trunk-vlans": ["D10", "D30"]}, "D30", "vlan_missing"),
    ("ge-0/0/2", {"mode": "trunk", "trunk-vlans": ["D10"], "native-vlan": 30}, "native VLAN 30", "vlan_missing"),
    ("ge-0/0/2", {"native-vlan": 10}, "has no native-vlan", None),
    ("ge-0/0/2", {"voice-vlan": "D30"}, "D30", "vlan_missing"),
    ("ge-0/0/1", {"voice-vlan": "D20"}, "must differ", None),
    ("ge-0/0/2", {"voice-vlan": "default"}, "CLI keyword", None),
])
def test_inconsistent_membership_requests_are_refused(key, changes, fragment, code):
    caught = refused(key=key, changes=changes)
    assert fragment in " ".join(caught.reasons) and caught.reason_codes == ([code] if code else caught.reason_codes)


def test_the_uplink_trunk_lists_its_members_and_the_trunk_check_stays_for_its_admin_state():
    entry = junos.load(BASELINE, FIRMWARE).entries("vlan-membership")["ge-0/0/0"]
    assert entry.attributes == {"mode": "trunk", "trunk-vlans": "D10 D20"} and not entry.unsupported
    plan = plan_of(key="ge-0/0/0", changes={"trunk-vlans": ["D10"]})
    assert plan["commands"][3:5] == ["delete interfaces ge-0/0/0 %s vlan members" % SW,
                                     "set interfaces ge-0/0/0 %s vlan members D10" % SW]
    caught = refused(key="ge-0/0/0", table="interface", changes={"admin-state": "disabled"})
    assert caught.reason_codes == ["port_uplink"]


def test_voice_vlan_on_an_access_port_needs_lldp_med():
    plan = plan_of(changes={"voice-vlan": "D10"})
    assert plan["commands"][3:-3] == ["set switch-options voip interface ge-0/0/2.0 vlan D10"]
    assert plan["inverse"][3:-3] == ["delete switch-options voip interface ge-0/0/2.0"]
    without = BASELINE.replace("set protocols lldp-med interface all\n", "")
    assert "LLDP-MED" in refused(without, changes={"voice-vlan": "D10"}).reasons[0]
    port_only = without + "set protocols lldp-med interface ge-0/0/2\n"
    assert plan_of(port_only, changes={"voice-vlan": "D10"})["commands"]
    caught = refused(BASELINE + "set switch-options voip interface ge-0/0/0.0 vlan D20\n", key="ge-0/0/0",
                     changes={"trunk-vlans": ["D10"]})
    assert "voice VLAN on a trunk" in caught.reasons[0]


# ---- VLAN table (J08, J20) ----

def vlan_request(op, key, changes=None):
    return dict(table="vlan", op=op, key=key, changes=changes or {})


def test_vlan_create_and_delete_are_inverse():
    plan = plan_of(**vlan_request("create", "3910", {"name": "junos-vlan-admin-new", "description": "Kancelář – VoIP"}))
    assert plan["commands"][3:-3] == ["set vlans junos-vlan-admin-new vlan-id 3910",
                                      'set vlans junos-vlan-admin-new description "Kancelář – VoIP"']
    assert plan["inverse"][3:-3] == ["delete vlans junos-vlan-admin-new"]
    assert "VLAN ID 3910 and name junos-vlan-admin-new are unused in the configuration" in plan["prechecks"]
    after = BASELINE + 'set vlans junos-vlan-admin-new description "Kancelář – VoIP"\nset vlans junos-vlan-admin-new vlan-id 3910\n'
    assert verify(plan, after.encode())["result"] == "match"
    gone = plan_of(after, **vlan_request("delete", "3910"))
    assert gone["commands"][3:-3] == ["delete vlans junos-vlan-admin-new"]
    assert gone["inverse"][3:-3] == plan["commands"][3:-3]


@pytest.mark.parametrize("op, key, changes, fragment", [
    ("create", "10", {"name": "junos-vlan-admin-x"}, "already used"),
    ("create", "3910", {"name": "D10"}, "already used"),
    ("create", "3910", {}, "create needs name"),
    ("create", "1", {"name": "junos-vlan-admin-x"}, "protected"),
    ("create", "4095", {"name": "junos-vlan-admin-x"}, "does not match"),
    ("create", "3910", {"name": "default"}, "CLI keyword"),
    ("create", "3910", {"name": "junos-vlan-admin-ž"}, "ASCII"),
    ("delete", "10", {}, "used by"),
    ("delete", "3999", {}, "not in the configuration"),
    ("update", "10", {"name": "D20"}, "already used"),
])
def test_vlan_refusals(op, key, changes, fragment):
    caught = refused(**vlan_request(op, key, changes))
    assert fragment in " ".join(caught.reasons), caught.reasons


def test_rename_moves_the_measured_references_and_keeps_the_irb():
    # measured (private measurement record): rename vlans moves only the VLAN stanza with its IRB; a member left on the old
    # name fails the commit
    stanza = fixture("show-compare__junos_vlan_admin-rename-only-stanza.txt")
    assert "junos-vlan-admin-trunk2" in stanza and "members" not in stanza
    assert "vlan junos-vlan-admin-trunk configured under interface ge-0/0/2.0 does not exist" in fixture(
        "commit-confirmed__junos_vlan_admin-rename-reference-not-moved.txt")
    text = COMPOSITE.replace("set vlans junos-vlan-admin-trunk vlan-id 3903\n", "set vlans junos-vlan-admin-trunk vlan-id 3903\n"
                             "set vlans junos-vlan-admin-trunk l3-interface irb.3903\n")
    plan = plan_of(text, **vlan_request("update", "3903", {"name": "junos-vlan-admin-trunk2"}))
    group = 'groups junos-vlan-admin-grpw interfaces "<ge-0/0/[89]>" %s vlan members' % SW
    assert plan["commands"][3:-3] == ["rename vlans junos-vlan-admin-trunk to junos-vlan-admin-trunk2", "delete %s junos-vlan-admin-trunk" % group,
                                      "set %s junos-vlan-admin-trunk2" % group]
    assert plan["inverse"][3:-3] == ["rename vlans junos-vlan-admin-trunk2 to junos-vlan-admin-trunk", "delete %s junos-vlan-admin-trunk2" % group,
                                     "set %s junos-vlan-admin-trunk" % group]
    assert "rename keeps VLAN ID 3903 and its IRB irb.3903; references moved to the new name: 1" \
        in plan["prechecks"]
    measured = [line for line in fixture("show-configuration-display-set-match-junos_vlan_admin__junos_vlan_admin-renamed.txt").split("\n")
                if line.startswith("set ")]
    assert 'set groups junos-vlan-admin-grpw interfaces "<ge-0/0/[89]>" %s vlan members junos-vlan-admin-trunk2' % SW in measured
    after = text.replace("junos-vlan-admin-trunk ", "junos-vlan-admin-trunk2 ").replace("members junos-vlan-admin-trunk\n", "members junos-vlan-admin-trunk2\n")
    assert verify(plan, after.encode())["result"] == "match"
    assert verify(plan, text.encode())["result"] != "match"
    voice = plan_of(COMPOSITE, **vlan_request("update", "3902", {"name": "junos-vlan-admin-phone"}))
    assert voice["commands"][3] == "rename vlans junos-vlan-admin-voice to junos-vlan-admin-phone"
    assert sorted(voice["commands"][4:-3]) == sorted([
        "set switch-options voip interface ge-0/0/2.0 vlan junos-vlan-admin-phone",
        "delete interfaces interface-range junos-vlan-admin-rng %s vlan members junos-vlan-admin-voice" % SW,
        "set interfaces interface-range junos-vlan-admin-rng %s vlan members junos-vlan-admin-phone" % SW])


def test_rename_refuses_a_reference_it_cannot_move():
    text = BASELINE + "set protocols unsupported vlan D10\n"
    caught = refused(text, **vlan_request("update", "10", {"name": "D11"}))
    assert "does not move" in caught.reasons[0]
    described = BASELINE + 'set interfaces ge-0/0/5 description "uplink D10 kancelář"\n'
    assert plan_of(described, **vlan_request("update", "10", {"name": "D11"}))["commands"]


# ---- blocking findings from the JUNOS-VLAN-ADMIN review ----

# Scenarios use the measured baseline, composite and VLAN table fixtures, with synthetic deltas for the
# review's configuration and truncated reads. LAB-ONLY is a synthetic marker, never a device credential.
@pytest.mark.parametrize("op, changes", [("delete", {}), ("update", {"name": "D11"})])
def test_review_vlan_refusal_keeps_configuration_values_private(tmp_path, op, changes):
    device = FakeJunos()
    device.lines.append("set snmp community LAB-ONLY view D10")
    result = execute.preview(make_runtime(tmp_path, device), NAME, request(**vlan_request(op, "10", changes)))
    assert result["result"] == "rejected"
    assert "LAB-ONLY" not in str(result)


@pytest.mark.parametrize("number, port", [("3901", "ge-0/0/2"), ("3901", "ge-0/0/7"),
                                          ("3902", "ge-0/0/9"), ("3903", "ge-0/0/8")])
def test_review_rename_checks_protected_member_ports(tmp_path, number, port):
    device = FakeJunos()
    device.lines = COMPOSITE.splitlines()
    runtime = make_runtime(tmp_path, device, protected={"vlan-membership": [port]})
    result = execute.preview(runtime, NAME, request(**vlan_request("update", number, {"name": "renamed"})))
    assert result["result"] == "rejected"
    assert port in " ".join(result["reasons"]) and "protected" in " ".join(result["reasons"])


@pytest.mark.parametrize("hierarchy", ["unit 0", SW, SW + " vlan"])
def test_review_rename_checks_group_applied_below_port(tmp_path, hierarchy):
    device = FakeJunos()
    device.lines = COMPOSITE.replace("set apply-groups junos-vlan-admin-grp",
                                     f"set interfaces ge-0/0/7 {hierarchy} apply-groups junos-vlan-admin-grp").splitlines()
    runtime = make_runtime(tmp_path, device, protected={"vlan-membership": ["ge-0/0/7"]})
    result = execute.preview(runtime, NAME, request(**vlan_request("update", "3901", {"name": "renamed"})))
    assert result["result"] == "rejected"
    assert "protected" in result["reasons"][0] and "ge-0/0/7" in result["reasons"][0]


@pytest.mark.parametrize("port, expected", [("ge-0/0/9", "rejected"), ("ge-0/0/8", "ready")])
def test_review_rename_limits_wildcard_group_to_the_application_scope(tmp_path, port, expected):
    device = FakeJunos()
    device.lines = COMPOSITE.replace("set interfaces ge-0/0/8 apply-groups junos-vlan-admin-grpw",
                                     f"set interfaces interface-range junos-vlan-admin-rng {SW} apply-groups junos-vlan-admin-grpw").splitlines()
    runtime = make_runtime(tmp_path, device, protected={"vlan-membership": [port]})
    result = execute.preview(runtime, NAME, request(**vlan_request("update", "3903", {"name": "renamed"})))
    assert result["result"] == expected


@pytest.mark.parametrize("protected", [{}, {"vlan-membership": ["ge-0/0/7"]}])
def test_review_rename_refuses_unknown_group_application_scope(tmp_path, protected):
    device = FakeJunos()
    device.lines = COMPOSITE.replace("set apply-groups junos-vlan-admin-grp",
                                     "set groups junos-vlan-admin-parent apply-groups junos-vlan-admin-grp\n"
                                     "set apply-groups junos-vlan-admin-parent").splitlines()
    runtime = make_runtime(tmp_path, device, protected=protected)
    result = execute.preview(runtime, NAME, request(**vlan_request("update", "3901", {"name": "renamed"})))
    assert result["result"] == "rejected"
    assert "configuration group application scope cannot be determined" in result["reasons"][0]


@pytest.mark.parametrize("expect", ["before", "after"])
def test_review_rename_detects_irb_loss_in_snapshot(tmp_path, expect):
    device = lab_device("set vlans junos-vlan-admin-trunk l3-interface irb.3903")
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    record = _confirmed(approved_apply(runtime, NAME, request(**vlan_request(
        "update", "3903", {"name": "junos-vlan-admin-renamed"}))))
    snapshot = before if expect == "before" else device.snapshot()
    name = "junos-vlan-admin-trunk" if expect == "before" else "junos-vlan-admin-renamed"
    binding = "set vlans %s l3-interface irb.3903\n" % name
    assert snapshot.count(binding) == 1
    verdict = verify(record["plan"], snapshot.replace(binding, "").encode(), expect=expect)
    assert verdict["result"] == "mismatch" and any("l3-interface" in row for row in verdict["differences"])


@pytest.mark.parametrize("undo", [False, True])
def test_review_rename_checks_irb_in_scoped_readback(tmp_path, undo):
    device = lab_device("set vlans junos-vlan-admin-trunk l3-interface irb.3903")
    runtime = make_runtime(tmp_path, device)
    rename = request(**vlan_request("update", "3903", {"name": "junos-vlan-admin-renamed"}))
    renamed = _confirmed(approved_apply(runtime, NAME, rename)) if undo else None
    wanted_name = "junos-vlan-admin-trunk" if undo else "junos-vlan-admin-renamed"
    scoped = "show configuration vlans %s | display set" % wanted_name
    original_query = device.query

    def query(command):
        answer = original_query(command)
        if command == scoped:
            return "\n".join(row for row in answer.splitlines() if " l3-interface " not in row) + "\n"
        return answer

    device.query = query
    result = (execute.undo(runtime, renamed["change_id"], "rename back") if undo
              else approved_apply(runtime, NAME, rename))
    assert result["result"] == "reverted" and "check_identity_failed" in steps(result)
    name = "junos-vlan-admin-renamed" if undo else "junos-vlan-admin-trunk"
    assert "set vlans %s l3-interface irb.3903" % name in device.lines


@pytest.mark.parametrize("path, tail", [("igmp-snooping vlan", ""), ("igmp-snooping vlan", " immediate-leave"),
                                        ("mld-snooping vlan", ""), ("vstp vlan", ""),
                                        ("mstp msti 1 vlan", "")])
def test_review_rename_moves_protocol_reference_through_apply_and_undo(tmp_path, path, tail):
    statement = "set protocols %s junos-vlan-admin-data%s" % (path, tail)
    device = lab_device(statement)
    runtime = make_runtime(tmp_path, device)
    baseline = set(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(**vlan_request(
        "update", "3901", {"name": "junos-vlan-admin-renamed"}))))
    assert statement not in device.lines and statement.replace("junos-vlan-admin-data", "junos-vlan-admin-renamed") in device.lines
    _confirmed(execute.undo(runtime, record["change_id"], "rename protocol VLAN back"))
    assert set(device.lines) == baseline


VLAN_TABLE_HEADER = "\n".join(fixture("show-vlans__junos_vlan_admin-ro.txt").splitlines()[:2]) + "\n"


def test_review_header_only_vlan_list_refuses_create(tmp_path):
    device = lab_device()
    original_query = device.query
    device.query = lambda command: VLAN_TABLE_HEADER if command == "show vlans" else original_query(command)
    result = execute.preview(make_runtime(tmp_path, device), NAME, request(**vlan_request(
        "create", "3910", {"name": "junos-vlan-admin-new"})))
    assert result["result"] == "rejected" and "VLAN list" in " ".join(result["reasons"])


def test_review_header_only_vlan_list_cannot_confirm_delete(tmp_path):
    device = lab_device()
    device.after_line = lambda fake, step: setattr(fake, "check_override", {"show vlans": VLAN_TABLE_HEADER}) \
        if step == CHANGE else None
    result = approved_apply(make_runtime(tmp_path, device), NAME, request(**vlan_request("delete", "3901")))
    assert result["result"] == "reverted" and "check_identity_failed" in steps(result)
    assert "set vlans junos-vlan-admin-data vlan-id 3901" in device.lines


def test_review_member_update_leaves_untouched_shared_mode_alone(tmp_path):
    device = lab_device(
        "set interfaces interface-range shared member ge-0/0/8\n"
        "set interfaces interface-range shared member ge-0/0/9\n"
        "set interfaces interface-range shared %s interface-mode access\n"
        "set interfaces ge-0/0/9 %s vlan members junos-vlan-admin-data" % (SW, SW))
    runtime = make_runtime(tmp_path, device)
    baseline = set(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(key="ge-0/0/9", changes={"access-vlan": "junos-vlan-admin-voice"})))
    assert record["plan"]["commands"][3:-3] == [
        "delete interfaces ge-0/0/9 %s vlan members" % SW,
        "set interfaces ge-0/0/9 %s vlan members junos-vlan-admin-voice" % SW]
    _confirmed(execute.undo(runtime, record["change_id"], "restore access VLAN"))
    assert set(device.lines) == baseline


def test_review_undo_restores_implicit_vlan_membership(tmp_path):
    device = lab_device(
        "set interfaces interface-range singleton member ge-0/0/9\n"
        "set interfaces interface-range singleton %s interface-mode access" % SW)
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    baseline = set(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(key="ge-0/0/9", changes={"access-vlan": "junos-vlan-admin-data"})))
    member = "interfaces ge-0/0/9 %s vlan members" % SW
    assert record["plan"]["inverse"][3:-3] == ["delete " + member]
    explicit = before + "set " + member + " default\n"
    assert verify(record["plan"], explicit.encode(), expect="before")["result"] == "mismatch"
    undo = _confirmed(execute.undo(runtime, record["change_id"], "restore implicit access VLAN"))
    assert undo["plan"]["commands"][3:-3] == ["delete " + member]
    assert set(device.lines) == baseline


def test_undo_of_legacy_plan_refuses_to_guess_how_default_was_configured(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"access-vlan": "junos-vlan-admin-data"})))
    plan = record["plan"]
    plan["predicted"]["before"] = {}
    plan["plan_sha256"] = plan_digest(plan)
    with pytest.raises(Rejected, match="whether default VLAN membership was explicit"):
        execute.undo_request(record, "restore the default access VLAN")


@pytest.mark.parametrize("inactive", ["deactivate protocols lldp-med",
                                     "deactivate protocols lldp-med interface all",
                                     "inactive: set protocols lldp-med interface all"])
def test_review_inactive_lldp_med_refuses_voice_vlan(tmp_path, inactive):
    device = FakeJunos()
    if inactive.startswith("inactive:"):
        device.lines.remove("set protocols lldp-med interface all")
    device.lines.append(inactive)
    result = execute.preview(make_runtime(tmp_path, device), NAME, request(changes={"voice-vlan": "D10"}))
    assert result["result"] == "rejected" and "LLDP-MED is not enabled" in " ".join(result["reasons"])


def test_review_angle_brackets_in_description_apply_and_undo_literally(tmp_path):
    device = FakeJunos()
    prior, wanted = "Původní <A-11> VoIP", "Kancelář <A-12> VoIP"
    device.lines.insert(next(i for i, line in enumerate(device.lines) if line.startswith("set interfaces ge-0/0/2 ")),
                        'set interfaces ge-0/0/2 description "%s"' % prior)
    runtime = make_runtime(tmp_path, device)
    baseline = list(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(table="interface", changes={"description": wanted})))
    assert record["plan"]["commands"][3] == 'set interfaces ge-0/0/2 description "%s"' % wanted
    assert record["plan"]["inverse"][3] == 'set interfaces ge-0/0/2 description "%s"' % prior
    _confirmed(execute.undo(runtime, record["change_id"], "restore description"))
    assert device.lines == baseline


# ---- JP17: long UTF-8 description ----

def test_a_long_utf8_description_is_planned_quoted_and_symbols_are_kept():
    plan = plan_of(table="interface", changes={"description": LONG})
    assert plan["commands"][3] == 'set interfaces ge-0/0/2 description "%s"' % LONG
    plan = plan_of(table="interface", changes={"description": SYMBOLS})
    assert plan["commands"][3] == 'set interfaces ge-0/0/2 description "%s"' % SYMBOLS
    assert plan_of(table="interface", changes={"description": "é" * 240})["commands"]


# ---- preview, apply, readback and undo against FakeJunos ----

def _confirmed(record):
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert "check_identity_passed" in steps(record)
    return record


def test_preview_of_the_new_tables_writes_nothing(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    for fields in (dict(changes=TRUNK), vlan_request("create", "3910", {"name": "junos-vlan-admin-new"})):
        result = execute.preview(runtime, NAME, request(**fields))
        assert result["result"] == "ready", result
    assert all(block == PROBE for block in device.applied_blocks) and not device.pending()


def test_trunk_is_confirmed_read_back_by_the_check_account_and_undone(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    changes = {"mode": "trunk", "trunk-vlans": ["junos-vlan-admin-data", "junos-vlan-admin-voice"], "native-vlan": 3902,
               "access-vlan": None}
    record = _confirmed(approved_apply(runtime, NAME, request(changes=changes)))
    assert device.port_vlans("ge-0/0/2") == [("junos-vlan-admin-data", "tagged", "trunk"), ("junos-vlan-admin-voice", "untagged", "trunk")]
    assert "show vlans junos-vlan-admin-data extensive" in device.check_queries
    assert _confirmed(execute.undo(runtime, record["change_id"], "back to access"))["plan"]["predicted"]["after"] == {
        "access-vlan": "default"}
    assert device.lines == before


def test_voice_vlan_is_confirmed_and_undone_without_the_port_checks_of_the_data_vlan(tmp_path):
    device = lab_device()
    device.learned_macs["ge-0/0/2"] = 1   # a phone is connected: the data VLAN stays, the voice VLAN may be added
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"voice-vlan": "junos-vlan-admin-voice"})))
    assert "set switch-options voip interface ge-0/0/2.0 vlan junos-vlan-admin-voice" in device.lines
    _confirmed(execute.undo(runtime, record["change_id"], "remove the voice VLAN"))
    assert device.lines == before
    refused_record = execute.preview(runtime, NAME, request(changes={"access-vlan": "junos-vlan-admin-data"}))
    assert refused_record["result"] == "rejected" and refused_record["reason_codes"] == ["port_learned_mac"]


def test_vlan_lifecycle_create_rename_with_a_member_and_delete(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    runtime.config.limits["changes_per_device_per_hour"] = 20
    baseline = list(device.lines)
    created = _confirmed(approved_apply(runtime, NAME, request(**vlan_request(
        "create", "3910", {"name": "junos-vlan-admin-new", "description": "Kancelář – VoIP"}))))
    assert 'set vlans junos-vlan-admin-new description "Kancelář – VoIP"' in device.lines
    member = _confirmed(approved_apply(runtime, NAME, request(changes={"access-vlan": "junos-vlan-admin-new"})))
    renamed = _confirmed(approved_apply(runtime, NAME, request(**vlan_request("update", "3910",
                                                                             {"name": "junos-vlan-admin-renamed"}))))
    assert "set interfaces ge-0/0/2 %s vlan members junos-vlan-admin-renamed" % SW in device.lines
    assert any(line.startswith("set vlans junos-vlan-admin-renamed ") for line in device.lines)
    _confirmed(execute.undo(runtime, renamed["change_id"], "name back"))
    assert "set interfaces ge-0/0/2 %s vlan members junos-vlan-admin-new" % SW in device.lines
    refusal = execute.preview(runtime, NAME, request(**vlan_request("delete", "3910")))
    assert refusal["result"] == "rejected" and "used by" in " ".join(refusal["reasons"])
    _confirmed(execute.undo(runtime, member["change_id"], "port back"))
    deleted = _confirmed(approved_apply(runtime, NAME, request(**vlan_request("delete", "3910"))))
    assert not any("junos-vlan-admin-new" in line for line in device.lines)
    _confirmed(execute.undo(runtime, deleted["change_id"], "recreate"))
    assert 'set vlans junos-vlan-admin-new description "Kancelář – VoIP"' in device.lines
    _confirmed(execute.undo(runtime, created["change_id"], "remove the test VLAN"))
    assert device.lines == baseline


def test_an_inherited_access_vlan_is_changed_in_the_group_and_returned(tmp_path):
    extra = ("set groups junos-vlan-admin-grp interfaces ge-0/0/7 %s interface-mode access\n"
             "set groups junos-vlan-admin-grp interfaces ge-0/0/7 %s vlan members junos-vlan-admin-data\nset apply-groups junos-vlan-admin-grp\n" % (SW, SW))
    device = lab_device(extra)
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    record = _confirmed(approved_apply(runtime, NAME, request(key="ge-0/0/7", changes={"access-vlan": "junos-vlan-admin-voice"})))
    assert "set groups junos-vlan-admin-grp interfaces ge-0/0/7 %s vlan members junos-vlan-admin-voice" % SW in device.lines
    assert not any(line.startswith("set interfaces ge-0/0/7 ") for line in device.lines)
    assert any("inherited from configuration group junos-vlan-admin-grp" in text for text in record["plan"]["prechecks"])
    _confirmed(execute.undo(runtime, record["change_id"], "group back"))
    assert device.lines == before


def test_a_different_inheritance_on_the_device_is_refused_before_any_write(tmp_path):
    extra = ("set groups junos-vlan-admin-grp interfaces ge-0/0/7 %s interface-mode access\n"
             "set groups junos-vlan-admin-grp interfaces ge-0/0/7 %s vlan members junos-vlan-admin-data\nset apply-groups junos-vlan-admin-grp\n" % (SW, SW))
    device = lab_device(extra)
    original = device.query

    def query(command):
        answer = original(command)
        return answer.replace("members junos-vlan-admin-data", "members junos-vlan-admin-trunk") if "display inheritance" in command else answer

    device.query = query
    result = execute.preview(make_runtime(tmp_path, device), NAME, request(key="ge-0/0/7",
                                                                          changes={"access-vlan": "junos-vlan-admin-voice"}))
    assert result["result"] == "rejected" and "display inheritance" in " ".join(result["reasons"])
    assert all(block == PROBE for block in device.applied_blocks)


def test_utf8_description_is_confirmed_and_undone(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    record = _confirmed(approved_apply(runtime, NAME, request(table="interface", changes={"description": SYMBOLS})))
    assert 'description "%s"' % SYMBOLS in device.interface("ge-0/0/2")
    _confirmed(execute.undo(runtime, record["change_id"], "description back"))
    assert device.lines == BASELINE.rstrip("\n").split("\n")


def test_an_incomplete_check_answer_after_the_change_returns_it(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    before = list(device.lines)
    cut = "\nRouting instance: default-switch\nVLAN Name: junos-vlan-admin-data                      State: Active\nTag: 3901\n"
    device.after_line = lambda fake, step: setattr(fake, "check_override", {"show vlans junos-vlan-admin-data extensive": cut}) \
        if step == CHANGE else None
    changes = {"mode": "trunk", "trunk-vlans": ["junos-vlan-admin-data"], "access-vlan": None}
    record = approved_apply(runtime, NAME, request(changes=changes))
    assert record["result"] != "confirmed" and "check_identity_failed" in steps(record)
    assert device.lines == before and not device.pending()


def test_vlan_observe_reads_the_name_with_the_check_account_and_the_description_from_the_configuration():
    device = lab_device('set vlans junos-vlan-admin-data description "Kancelář – VoIP"')
    plan = {"table": "vlan", "key": "3901", "predicted": {}}
    assert exec_junos.observe(device, plan) == {"name": "junos-vlan-admin-data", "description": "Kancelář – VoIP"}
    assert "show vlans" in device.check_queries
    assert exec_junos.observe(device, dict(plan, key="3999")) is None


@pytest.mark.parametrize("target, port, matches", [
    ('"<ge-0/0/[89]>"', "ge-0/0/8", True), ('"<ge-0/0/[89]>"', "ge-0/0/7", False), ("<ge-*>", "ge-0/0/17", True),
    ("<ge-0/0/?>", "ge-0/0/10", False), ("<ge-0/0/[!0-5]>", "ge-0/0/6", True), ("<ge-0/0/[!0-5]>", "ge-0/0/5", False),
    ("ge-0/0/7", "ge-0/0/7", True), ("<xe-*>", "ge-0/0/1", False),
])
def test_group_wildcards_as_junos_matches_them(target, port, matches):
    assert junos._matches(target, port) is matches


def test_undo_restores_default_among_trunk_members(tmp_path):
    device = lab_device()
    runtime = make_runtime(tmp_path, device)
    _confirmed(approved_apply(runtime, NAME, request(changes={
        "mode": "trunk", "trunk-vlans": ["D10", "default"], "access-vlan": None})))
    record = _confirmed(approved_apply(runtime, NAME, request(changes={"trunk-vlans": ["D10", "D20"]})))
    _confirmed(execute.undo(runtime, record["change_id"], "restore original trunk members"))
    assert set(device.port_vlans("ge-0/0/2")) == {("D10", "tagged", "trunk"), ("default", "tagged", "trunk")}


@pytest.mark.parametrize(("protected", "expected"), [
    ({}, "ready"), ({"vlan-membership": ["ge-0/0/9.0"]}, "rejected"),
    ({"vlan-membership": ["ge-0/0/6"]}, "ready"),
])
def test_rename_with_interface_range_member_pattern(tmp_path, protected, expected):
    # Measured composite with the member expressed in Junos interface-range bracket syntax.
    device = FakeJunos()
    device.lines = COMPOSITE.replace("junos-vlan-admin-rng member ge-0/0/9", "junos-vlan-admin-rng member ge-0/0/[8-9]").splitlines()
    args = request(**vlan_request("update", "3902", {"name": "junos-vlan-admin-renamed"}))
    result = execute.preview(make_runtime(tmp_path, device, protected=protected), NAME, args)
    assert result["result"] == expected
    if expected == "rejected":
        assert "ge-0/0/9" in str(result["reasons"])


def test_rename_checks_wildcard_group_at_the_root_against_a_protected_range_member(tmp_path):
    # The physical port has no statements of its own. Group and range variants of the lab capture.
    device = FakeJunos()
    device.lines = COMPOSITE.replace("<ge-0/0/[89]>", "<ge-0/0/*>").replace(
        "set interfaces ge-0/0/8 apply-groups junos-vlan-admin-grpw", "set apply-groups junos-vlan-admin-grpw").replace(
        "junos-vlan-admin-rng member ge-0/0/9", "junos-vlan-admin-rng member ge-0/0/[8-12]").splitlines()
    args = request(**vlan_request("update", "3903", {"name": "junos-vlan-admin-renamed"}))
    result = execute.preview(make_runtime(tmp_path, device, protected={"interface": ["ge-0/0/10.0"]}),
                             NAME, args)
    assert result["result"] == "rejected" and "ge-0/0/10.0" in str(result["reasons"])


def test_vlan_preview_reports_measured_rollback_evidence(tmp_path):
    device = lab_device()
    result = execute.preview(make_runtime(tmp_path, device), NAME,
                             request(**vlan_request("create", "3907", {"name": "junos-vlan-admin-new"})))
    assert result["result"] == "ready"
    assert "commit confirmed 10" in result["rollback_evidence"]
    assert "TBD" not in result["rollback_evidence"]


def test_vlan_delete_in_use_reports_a_specific_reason(tmp_path):
    device = FakeJunos()
    device.lines = COMPOSITE.splitlines()
    result = execute.preview(make_runtime(tmp_path, device), NAME, request(**vlan_request("delete", "3902", {})))
    assert result["result"] == "rejected"
    assert result["reason_codes"] == ["vlan_in_use"]
