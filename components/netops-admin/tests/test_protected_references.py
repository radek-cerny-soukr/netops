from __future__ import annotations

import dataclasses

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_exos import FakeExos
from test_fortios import plan, rejected, replace
from test_port_inventory import FACTORY, FIRMWARE, TWELVE
from test_execute_exos import make_runtime, request

from netops_admin import engine, execute
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

GROUP = '        set member "grouped-host"'
REFERENCE = "reference to protected object"
SWITCH = FACTORY + (
    'create vlan "users"\nconfigure vlan users tag 10\n'
    'create vlan "staff"\nconfigure vlan staff tag 20\n'
    "configure vlan users add ports 5,7 untagged\n"
    "configure vlan guest add ports 5 tagged\n"
    "configure vlan guest add ports 6 untagged\n"
)
UNRESOLVED = SWITCH + "configure vlan staff add ports all tagged\n"


def exos_plan(table, key, changes, protected, text=SWITCH, ports=TWELVE):
    body = parse_request(request_bytes(table=table, op="update", key=key, changes=changes))
    return engine.build_plan("exos", text.encode("utf-8"), body, firmware=FIRMWARE, ports=ports, protected=protected)


def exos_reasons(*args, **fields):
    with pytest.raises(Rejected) as caught:
        exos_plan(*args, **fields)
    return caught.value.reasons


def test_group_change_that_keeps_a_protected_member_is_refused(fortios_snapshot):
    snapshot = replace(fortios_snapshot, GROUP, '        set member "grouped-host" "srv-web"')
    rejected(snapshot, REFERENCE + " 'srv-web'", protected={"firewall address": ["srv-web"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": ["lab-net", "srv-web"]})


def test_group_member_in_other_letter_case_than_the_protected_name_is_refused(fortios_snapshot):
    snapshot = replace(fortios_snapshot, GROUP, '        set member "grouped-host" "srv-web"')
    rejected(snapshot, REFERENCE, protected={"firewall address": ["SRV-Web"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": ["lab-net", "srv-web"]})


def test_group_without_a_protected_member_is_planned(fortios_snapshot):
    document = plan(fortios_snapshot, protected={"firewall address": ["srv-web"]}, table="firewall addrgrp",
                    op="update", key="servers", changes={"member": ["grouped-host", "lab-net"]})
    assert document["predicted"]["after"] == {"member": "grouped-host lab-net"}


@pytest.mark.parametrize("port", ["5", "6"])
@pytest.mark.parametrize("name", ["guest", "GUEST"])
def test_display_string_of_a_port_in_a_protected_vlan_is_refused(port, name):
    reasons = exos_reasons("ports", port, {"display-string": "desk"}, {"vlan": [name]})
    assert any(REFERENCE + " 'guest'" in reason for reason in reasons), reasons


def test_display_string_of_a_port_outside_protected_vlans_is_planned():
    document = exos_plan("ports", "7", {"display-string": "desk"}, {"vlan": ["guest"]})
    assert document["predicted"]["after"] == {"display-string": "desk"}


def test_membership_change_that_keeps_a_protected_tagged_vlan_is_refused():
    reasons = exos_reasons("vlan-membership", "5", {"tagged": ["guest", "staff"]}, {"vlan": ["guest"]})
    assert any(REFERENCE + " 'guest'" in reason for reason in reasons), reasons


def test_membership_change_of_a_port_with_a_protected_native_vlan_is_refused():
    reasons = exos_reasons("vlan-membership", "6", {"tagged": ["staff"]}, {"vlan": ["guest"]})
    assert any(REFERENCE + " 'guest'" in reason for reason in reasons), reasons


def test_membership_change_without_a_protected_vlan_is_planned():
    document = exos_plan("vlan-membership", "7", {"tagged": ["staff"]}, {"vlan": ["guest"]})
    assert document["predicted"]["after"] == {"untagged": "users", "tagged": "staff"}


def test_vlan_description_change_of_a_vlan_holding_a_protected_port_is_refused():
    reasons = exos_reasons("vlan", "users", {"description": "office"}, {"ports": ["5"]}, ports=None)
    assert any(REFERENCE + " '5'" in reason for reason in reasons), reasons


def test_vlan_description_change_of_a_vlan_without_a_protected_port_is_planned():
    document = exos_plan("vlan", "staff", {"description": "office"}, {"ports": ["5"]}, ports=None)
    assert document["predicted"]["after"]["description"] == "office"


def test_builtin_default_counts_only_when_it_is_listed():
    assert exos_plan("ports", "8", {"display-string": "desk"}, {"vlan": ["guest"]})["commands"]
    reasons = exos_reasons("ports", "8", {"display-string": "desk"}, {"vlan": ["Default"]})
    assert any(REFERENCE + " 'Default'" in reason for reason in reasons), reasons


def test_unreadable_membership_refuses_a_port_change_only_when_names_are_protected():
    assert exos_plan("ports", "7", {"display-string": "desk"}, {}, text=UNRESOLVED, ports=None)["commands"]
    reasons = exos_reasons("ports", "7", {"display-string": "desk"}, {"vlan": ["guest"]}, text=UNRESOLVED, ports=None)
    assert any("protected" in reason and "cannot be evaluated" in reason for reason in reasons), reasons


def test_apply_refuses_a_display_string_on_a_port_of_a_protected_vlan_of_the_device(tmp_path):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["sw"] = dataclasses.replace(runtime.config.devices["sw"], protected={"vlan": ["data"]})
    runtime = certify(runtime, device, "sw")
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", request(table="ports", op="update", key="2", changes={"display-string": "desk"}))
    assert any(REFERENCE + " 'DATA'" in reason for reason in caught.value.reasons), caught.value.reasons
    assert device.applied_blocks == []
    record = execute.apply(runtime, "sw", request(table="ports", op="update", key="6", changes={"display-string": "desk"},
                                                  request_id="req-port-six"))
    assert record["result"] == "confirmed" and device.port_strings["6"] == "desk"


ADDRGRP = "config firewall addrgrp\n"


def nested(snapshot, *groups):
    text = "".join('    edit "%s"\n        set uuid 00000000-0000-4000-8000-0000000000%02x\n        set member %s\n    next\n'
                   % (name, 0xa0 + index, " ".join('"%s"' % item for item in members))
                   for index, (name, members) in enumerate(groups))
    return replace(snapshot, ADDRGRP, ADDRGRP + text)


def test_group_nested_in_a_protected_group_is_refused(fortios_snapshot):
    snapshot = nested(fortios_snapshot, ("admin-hosts", ["servers"]))
    rejected(snapshot, REFERENCE + " 'admin-hosts'", protected={"firewall addrgrp": ["admin-hosts"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": ["grouped-host", "lab-net"]})


def test_group_nested_two_levels_below_a_protected_group_is_refused(fortios_snapshot):
    snapshot = nested(fortios_snapshot, ("admin-hosts", ["middle"]), ("middle", ["servers"]))
    rejected(snapshot, REFERENCE + " 'admin-hosts'", protected={"firewall addrgrp": ["Admin-Hosts"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": ["grouped-host", "lab-net"]})


def test_group_outside_a_protected_group_and_comment_of_its_member_are_planned(fortios_snapshot):
    snapshot = nested(fortios_snapshot, ("admin-hosts", ["servers"]), ("lab-group", ["lab-net"]))
    protected = {"firewall addrgrp": ["admin-hosts"]}
    document = plan(snapshot, protected=protected, table="firewall addrgrp", op="update", key="lab-group",
                    changes={"member": ["lab-net", "spare-host"]})
    assert document["predicted"]["after"] == {"member": "lab-net spare-host"}
    document = plan(snapshot, protected=protected, table="firewall address", op="update", key="grouped-host",
                    changes={"comment": "member host"})
    assert document["predicted"]["after"]["comment"] == "member host"


def test_group_excluded_from_a_protected_group_is_refused(fortios_snapshot):
    text = ('    edit "admin-hosts"\n        set uuid 00000000-0000-4000-8000-0000000000b0\n'
            '        set member "lab-net"\n        set exclude enable\n        set exclude-member "servers"\n    next\n')
    snapshot = replace(fortios_snapshot, ADDRGRP, ADDRGRP + text)
    rejected(snapshot, REFERENCE + " 'admin-hosts'", protected={"firewall addrgrp": ["admin-hosts"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": ["grouped-host", "lab-net"]})


def nested_member(fortios_snapshot, members, *groups):
    snapshot = replace(fortios_snapshot, GROUP, "        set member %s" % " ".join('"%s"' % item for item in members))
    return nested(snapshot, *groups)


@pytest.mark.parametrize("members", [["lab-net"], ["inner", "spare-host"]], ids=["removed", "kept"])
def test_group_holding_a_protected_address_through_a_subgroup_is_refused(fortios_snapshot, members):
    snapshot = nested_member(fortios_snapshot, ["inner", "lab-net"], ("inner", ["deep"]), ("deep", ["srv-web"]))
    rejected(snapshot, REFERENCE + " 'srv-web'", protected={"firewall address": ["SRV-Web"]},
             table="firewall addrgrp", op="update", key="servers", changes={"member": members})


def test_group_whose_subgroups_hold_no_protected_address_is_planned(fortios_snapshot):
    snapshot = nested_member(fortios_snapshot, ["inner", "lab-net"], ("inner", ["spare-host"]))
    document = plan(snapshot, protected={"firewall address": ["srv-web"]}, table="firewall addrgrp",
                    op="update", key="servers", changes={"member": ["lab-net"]})
    assert document["predicted"]["after"] == {"member": "lab-net"}
