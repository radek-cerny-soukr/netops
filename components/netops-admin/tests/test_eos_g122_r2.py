"""1.0.12 G122 r2: regressions of the blocking findings of review 491-rv on Arista EOS (cEOSLab 4.36.1F).

Every case runs the real path (execute.preview/apply/undo, engine plan, exec_eos prechecks and check-account readback)
against FakeEos, whose answers come from outputs measured on cEOS 2253 (fixtures/eos_g122, task-evidence/g122 and
task-evidence/g122/r2/raw). Nothing of the read under test is mocked.

1. E04: the undo of removing a VLAN that does not exist (yet) from a trunk allowed list restores the list.
2. E05/E46: a phone VLAN left on an access port (EOS keeps it after "switchport mode access") does not block an access
   VLAN change, and "voice-vlan: null" removes it (plan, apply, readback, undo).
3. E05/E19: the explicit name VLANnnnn (the EOS default name, measured: no name line is stored) previews and applies
   alike.
"""
from __future__ import annotations

from fake_eos import FakeEos, g122
from test_eos import make_runtime, request, steps

from netops_admin import execute

PORT = "Ethernet12"
STALE_PHONE = g122("show-running-config-interfaces-Ethernet12__access-stale-phone.txt")


def port(**fields):
    fields.setdefault("table", "vlan-membership")
    fields.setdefault("key", PORT)
    return request(**fields)


def prepared(stanza_lines=(), vlans=(("3990", "g122-data"), ("3991", "g122-voice"))):
    """FakeEos with named test VLANs and the given (measured) Ethernet12 lines, all of it saved."""
    device = FakeEos()
    for vid, name in vlans:
        device._add_vlan(vid)
        device._vlan_line(vid, ["name", name], "name " + name)
    start, end = device._block("interface %s" % PORT)
    device.lines[start + 1:end] = ["   " + line.strip() for line in stanza_lines]
    device.saved = list(device.lines)
    return device


def measured_lines(text):
    return [line.strip() for line in text.splitlines()[1:] if line.strip()]


# ---- finding 1 (E04): undo restores an allowed list with a VLAN that does not exist ----

TRUNK_SPARSE = ["switchport trunk native vlan 3990", "switchport trunk allowed vlan 3990-3992", "switchport mode trunk"]


def test_undo_of_removing_a_missing_vlan_from_the_allowed_list_restores_it(tmp_path):
    device = prepared(TRUNK_SPARSE)
    assert "3992" not in device.vlans()
    runtime = make_runtime(tmp_path, device)
    narrowed = execute.apply(runtime, "lab-ceos", port(changes={"allowed-vlans": "3990-3991"},
                                                       endpoint_impact=PORT, request_id="g122-r2-1"))
    assert narrowed["result"] == "confirmed", (narrowed.get("reason"), steps(narrowed))
    assert "switchport trunk allowed vlan 3990-3991" in device.interface(PORT)
    preview = execute.preview_undo(runtime, narrowed["change_id"], "restore the reserved VLAN 3992")
    assert preview["result"] == "ready", (preview.get("reasons"), preview.get("reason_codes"))
    assert preview["commands"][2] == "switchport trunk allowed vlan 3990-3992"
    assert "checked VLANs required for this change; port Ethernet12 is in trunk mode" in preview["prechecks"]
    undone = execute.undo(runtime, narrowed["change_id"], "restore the reserved VLAN 3992")
    assert undone["result"] == "confirmed", (undone.get("reason"), undone.get("reasons"))
    # FakeEos appends a changed line; EOS orders them canonically, so the lines are compared as a set
    assert sorted(device.interface(PORT)) == sorted(TRUNK_SPARSE) and device.lines == device.saved
    assert "3992" not in device.vlans()


def test_a_user_request_still_cannot_add_a_missing_vlan_to_the_allowed_list(tmp_path):
    device = prepared(["switchport trunk native vlan 3990", "switchport trunk allowed vlan 3990-3991",
                       "switchport mode trunk"])
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos",
                             port(changes={"allowed-vlans": "3990-3992"}, endpoint_impact=PORT,
                                  request_id="undo-g122-r2-forged"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["vlan_missing"]
    assert device.applied_blocks == []


# ---- finding 2 (E05/E46): phone VLAN left on an access port ----

def _real_check_answers_before_the_write(device):
    """The measured pair of the stale port: switchport (static access, VLAN 3990, no Phone VLAN line) and dot1x
    (force-authorized, MAB enabled); after the write the fake builds the answers from its lines."""
    device.check_override = {
        "show interfaces %s switchport" % PORT: g122("show-interfaces-Ethernet12-switchport__access-3990.txt"),
        "show dot1x interface %s" % PORT: g122("show-dot1x-interface-Ethernet12__force-authorized-mab.txt")}

    def written(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_override = None

    device.on_apply = written


def test_access_vlan_change_on_a_port_with_a_left_over_phone_vlan_applies_and_undoes(tmp_path):
    stanza = measured_lines(STALE_PHONE)
    device = prepared(stanza)
    _real_check_answers_before_the_write(device)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", port(changes={"access-vlan": 20}, request_id="g122-r2-2"))
    assert preview["result"] == "ready", (preview.get("reasons"), preview.get("reason_codes"))
    assert preview["commands"] == ["configure terminal", "interface %s" % PORT, "switchport access vlan 20", "end"]
    record = execute.apply(runtime, "lab-ceos", port(changes={"access-vlan": 20}, request_id="g122-r2-2"),
                           expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("reasons"), steps(record))
    assert sorted(device.interface(PORT)) == sorted(line.replace("access vlan 3990", "access vlan 20")
                                                    for line in stanza)
    undone = execute.undo(runtime, record["change_id"], "back to VLAN 3990")
    assert undone["result"] == "confirmed", (undone.get("reason"), undone.get("reasons"))
    assert sorted(device.interface(PORT)) == sorted(stanza) and device.lines == device.saved


def test_left_over_phone_vlan_is_removed_with_voice_vlan_null_and_restored_by_undo(tmp_path):
    stanza = ["switchport access vlan 3990", "switchport phone vlan 3991"]
    device = prepared(stanza)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", port(changes={"voice-vlan": None}, request_id="g122-r2-3"))
    assert preview["result"] == "ready", (preview.get("reasons"), preview.get("reason_codes"))
    assert preview["commands"] == ["configure terminal", "interface %s" % PORT, "no switchport phone vlan", "end"]
    record = execute.apply(runtime, "lab-ceos", port(changes={"voice-vlan": None}, request_id="g122-r2-3"),
                           expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("reasons"), steps(record))
    assert device.interface(PORT) == ["switchport access vlan 3990"]
    undone = execute.undo(runtime, record["change_id"], "the phone VLAN line back")
    assert undone["result"] == "confirmed", (undone.get("reason"), undone.get("reasons"))
    assert sorted(device.interface(PORT)) == sorted(stanza) and device.lines == device.saved


def test_a_new_phone_vlan_outside_trunk_phone_mode_stays_refused(tmp_path):
    device = prepared(["switchport access vlan 3990"])
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos",
                             port(changes={"voice-vlan": 3991}, request_id="g122-r2-4"))
    assert result["result"] == "rejected" and "trunk phone" in " ".join(result["reasons"])
    assert device.applied_blocks == []


# ---- finding 3 (E05/E19): explicit default name VLANnnnn ----

def test_rename_to_the_default_name_previews_and_applies_alike_and_undoes(tmp_path):
    device = prepared(vlans=(("3990", "g122-data"), ("3991", "g122-voice"), ("3992", "g122-named")))
    runtime = make_runtime(tmp_path, device)
    rename = request(table="vlan", key="3992", changes={"name": "VLAN3992"}, request_id="g122-r2-5")
    preview = execute.preview(runtime, "lab-ceos", rename)
    assert preview["result"] == "ready", (preview.get("reasons"), preview.get("reason_codes"))
    record = execute.apply(runtime, "lab-ceos", rename, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("reasons"), steps(record))
    assert device.vlan_name("3992") == "VLAN3992"
    undone = execute.undo(runtime, record["change_id"], "the test name back")
    assert undone["result"] == "confirmed", (undone.get("reason"), undone.get("reasons"))
    assert device.vlan_name("3992") == "g122-named" and device.lines == device.saved


def test_create_with_the_default_name_previews_and_applies_alike_and_undoes(tmp_path):
    device = prepared()
    runtime = make_runtime(tmp_path, device)
    create = request(table="vlan", op="create", key="3994", changes={"name": "VLAN3994"}, request_id="g122-r2-6")
    preview = execute.preview(runtime, "lab-ceos", create)
    assert preview["result"] == "ready", (preview.get("reasons"), preview.get("reason_codes"))
    record = execute.apply(runtime, "lab-ceos", create, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("reasons"), steps(record))
    assert device.vlan_name("3994") == "VLAN3994"
    undone = execute.undo(runtime, record["change_id"], "remove the test VLAN")
    assert undone["result"] == "confirmed" and "3994" not in device.vlans() and device.lines == device.saved
