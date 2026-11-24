"""Blocking findings of the review, through Admin and the measured cEOS transport fake."""
from __future__ import annotations

import pytest

from fake_eos import eos_switchport_admin
from test_eos import make_runtime, request, steps
from test_eos_eos_switchport_admin_r2 import PORT, STALE_PHONE, _real_check_answers_before_the_write, measured_lines, port, prepared

from netops_admin import engine, eos, execute


def test_combined_access_vlan_and_disabled_dot1x_keep_leftover_pae(tmp_path):
    stanza = measured_lines(STALE_PHONE)
    device = prepared(stanza, vlans=(("3990", "eos-switchport-admin-data"), ("3991", "eos-switchport-admin-voice"), ("3992", "eos-switchport-admin-test")))
    _real_check_answers_before_the_write(device)
    runtime = make_runtime(tmp_path, device)
    change = port(changes={"access-vlan": 3992, "dot1x": "disabled"}, request_id="eos-switchport-admin-r3-dot1x")

    preview = execute.preview(runtime, "lab-ceos", change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", f"interface {PORT}", "switchport access vlan 3992", "end"]
    record = execute.apply(runtime, "lab-ceos", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    plan = runtime.store.operation(record["change_id"])["plan"]
    assert plan["inverse"] == ["configure terminal", f"interface {PORT}", "switchport access vlan 3990", "end"]
    assert sorted(device.interface(PORT)) == sorted(line.replace("access vlan 3990", "access vlan 3992")
                                                    for line in stanza)
    undone = execute.undo(runtime, record["change_id"], "return to VLAN 3990")
    assert undone["result"] == "confirmed", (undone.get("reason"), steps(undone))
    assert sorted(device.interface(PORT)) == sorted(stanza) and device.lines == device.saved
    assert all("no dot1x pae authenticator" not in block for block in device.applied_blocks)


@pytest.mark.parametrize("op,original_name", [("create", None), ("update", "eos-switchport-admin-named")])
def test_explicit_default_vlan_name_merges_with_an_adjacent_default_vlan_and_undoes(tmp_path, op, original_name):
    device = prepared(vlans=(("3992", "VLAN3992"), ("3994", "VLAN3992")))
    if original_name is not None:
        device._add_vlan("3993")
        device._vlan_line("3993", ["name", original_name], f"name {original_name}")
        device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    change = request(table="vlan", op=op, key="3993", changes={"name": "VLAN3993"}, request_id="eos-switchport-admin-r3-vlan")
    before = device.snapshot()

    preview = execute.preview(runtime, "lab-ceos", change)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "lab-ceos", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    capture = eos_switchport_admin("show-session-config-diffs__adjacent-default-vlans.txt")
    measured = "\n".join(line[1:] for line in capture.splitlines()[2:])
    assert measured in device.snapshot()
    plan = runtime.store.operation(record["change_id"])["plan"]
    assert measured in eos.snapshot_after(before, plan)
    missing_neighbor = device.snapshot().replace("vlan 3992-3993", "vlan 3993")
    verification = engine.verify(plan, missing_neighbor.encode())
    assert verification["object_matches"] and not verification["rest_matches"]
    assert device.vlan_name("3993") == "VLAN3993"

    undo_preview = execute.preview_undo(runtime, record["change_id"], "restore the original VLAN state")
    assert undo_preview["result"] == "ready", undo_preview
    undone = execute.undo(runtime, record["change_id"], "restore the original VLAN state")
    assert undone["result"] == "confirmed", (undone.get("reason"), steps(undone))
    assert device.snapshot() == before and device.lines == device.saved
