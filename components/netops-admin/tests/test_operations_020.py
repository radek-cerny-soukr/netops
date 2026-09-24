import json
from dataclasses import replace

import pytest

from conftest import request_bytes
from enrollment_helpers import certify
from fake_020 import FortiOS767, ExosMembership
from test_execute import make_runtime
from test_execute_exos import make_runtime as make_exos_runtime
from netops_admin import engine, execute, membership
from netops_admin.errors import Rejected
from netops_admin.request import parse_request


def request(table, key, changes, op="update", request_id="operation-example"):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes, request_id=request_id))


def runtime_for(tmp_path, platform):
    if platform == "fortios":
        target = FortiOS767()
        return make_runtime(tmp_path, target), target, "lab"
    target = ExosMembership()
    runtime = make_exos_runtime(tmp_path, target)
    policy = {"version": 1, "platform": "exos",
              "port_vlans": {"10": {"tagged": ["guest", "users", "staging"], "untagged": ["users", "staging", "guest"]}},
              "protected_ports": ["12", "13"], "management_vlans": ["Mgmt"]}
    device = replace(runtime.config.devices["sw"], audit_policy=policy)
    runtime.config = replace(runtime.config, devices={"sw": device})
    certify(runtime, target, "sw")
    return runtime, target, "sw"


CASES = [
    ("fortios", "firewall addrgrp", "group-example", {"member": ["srv-web"]}, "update"),
    ("fortios", "system dhcp server/reserved-address", "1:2",
     {"ip": "192.0.2.102", "mac": "00:00:5e:00:53:02", "description": "second"}, "create"),
    ("fortios", "system dhcp server/reserved-address", "1:1", {"ip": "192.0.2.103"}, "update"),
    ("fortios", "system dhcp server/reserved-address", "1:1", {}, "delete"),
    ("exos", "vlan-membership", "10", {"tagged": []}, "update"),
    ("exos", "vlan-membership", "10", {"tagged": ["guest", "staging"]}, "update"),
    ("exos", "vlan-membership", "10", {"untagged": "staging"}, "update"),
    ("exos", "vlan-membership", "10", {"untagged": "guest", "tagged": ["users"]}, "update"),
]


@pytest.mark.parametrize("platform,table,key,changes,op", CASES)
def test_execute_and_undo_restore_independent_device_model(tmp_path, platform, table, key, changes, op):
    runtime, target, name = runtime_for(tmp_path, platform)
    before = target.snapshot()
    record = execute.apply(runtime, name, request(table, key, changes, op))
    assert record["result"] == "confirmed"
    assert target.snapshot() != before
    undone = execute.undo(runtime, record["change_id"], "restore example")
    assert undone["result"] == "confirmed"
    assert engine.verify(record["plan"], target.snapshot().encode(), expect="before")["result"] == "match"


@pytest.mark.parametrize("platform,table,key,changes,op", CASES)
def test_lost_control_read_triggers_real_simulated_timer_inverse(tmp_path, platform, table, key, changes, op):
    runtime, target, name = runtime_for(tmp_path, platform)
    before = target.snapshot()
    def fail_after_change(fake, _lines):
        if len(fake.applied_blocks) == 2:
            fake.check_unreadable = True
    target.on_apply = fail_after_change
    record = execute.apply(runtime, name, request(table, key, changes, op))
    assert record["result"] == "reverted"
    assert engine.verify(record["plan"], target.snapshot().encode(), expect="before")["result"] == "match"


def test_last_group_member_is_refused_before_any_write(tmp_path):
    runtime, target, name = runtime_for(tmp_path, "fortios")
    with pytest.raises(Rejected, match="at least one"):
        execute.apply(runtime, name, request("firewall addrgrp", "group-example", {"member": []}))
    assert not target.applied_blocks


@pytest.mark.parametrize("changes", [
    {"ip": "198.51.100.20"}, {"ip": "192.0.2.1"},
    {"mac": ":".join(["ff"] * 6)}, {"mac": ":".join(["00"] * 6)},
])
def test_bad_reservation_is_refused_before_any_write(tmp_path, changes):
    runtime, target, name = runtime_for(tmp_path, "fortios")
    with pytest.raises(Rejected):
        execute.apply(runtime, name, request("system dhcp server/reserved-address", "1:1", changes))
    assert not target.applied_blocks


def test_conflicting_reservation_is_refused_by_predicted_audit(tmp_path):
    runtime, target, name = runtime_for(tmp_path, "fortios")
    with pytest.raises(Rejected, match="audit"):
        execute.apply(runtime, name, request("system dhcp server/reserved-address", "1:2",
                      {"ip": "192.0.2.101", "mac": "00:00:5e:00:53:02"}, "create"))
    assert not target.applied_blocks


def test_management_vlan_is_protected_even_when_allowlisted(tmp_path):
    runtime, target, name = runtime_for(tmp_path, "exos")
    device = runtime.config.devices[name]
    policy = dict(device.audit_policy, management_vlans=["users"])
    runtime.config = replace(runtime.config, devices={name: replace(device, audit_policy=policy)})
    certify(runtime, target, name)
    with pytest.raises(Rejected, match="management VLAN"):
        execute.apply(runtime, name, request("vlan-membership", "10", {"untagged": "staging"}))
    assert not target.applied_blocks


def test_membership_check_parser_reads_multiple_modes_and_rejects_wrong_port():
    text = "Port /Tagged VLAN Name(s)\n10 Untagged users\n Tagged guest, staging\n"
    assert membership.shown(text, "10") == {"untagged": "users", "tagged": "guest staging"}
    with pytest.raises(Rejected):
        membership.shown(text, "11")
