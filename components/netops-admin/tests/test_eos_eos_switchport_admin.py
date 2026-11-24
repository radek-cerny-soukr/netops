"""1.0.12 EOS-SWITCHPORT-ADMIN on Arista EOS (cEOSLab 4.36.1F): VLAN lifecycle and rename (E05/E19), trunk mode, allowed and native
VLAN (E04), voice (phone) VLAN with 802.1X/MAB (E46) and a long description with diacritics (EP19).

Every device answer comes from outputs measured on cEOS (fixtures/eos_eos_switchport_admin, private measurement record): the plan
adapter reads the real interface and VLAN stanzas, the check-account parsers read the real switchport, dot1x and
VLAN answers, and FakeEos builds its answers from them for preview, confirmed apply, readback and undo.
"""
from __future__ import annotations

import pytest
from fake_eos import FIRMWARE, FakeEos, fixture, eos_switchport_admin
from test_eos import make_runtime, request, steps

from netops_admin import eos, execute
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from approved_apply import approved_apply

BASELINE = fixture("show-running-config__baseline.txt")
TRUNK_DOT1X = eos_switchport_admin("show-running-config-interfaces-Ethernet12__trunk-dot1x.txt")
TRUNK_PHONE = eos_switchport_admin("show-running-config-interfaces-Ethernet12__trunk-phone.txt")
STALE_PHONE = eos_switchport_admin("show-running-config-interfaces-Ethernet12__access-stale-phone.txt")
VLANS = eos_switchport_admin("show-running-config-section-vlan__created.txt")
LONG = ("Kancelář 2.patro – tiskárna HP, zásuvka D12/3 \"A\" | !x #y; Žluťoučký kůň úpěl ďábelské ódy, "
        "telefon ☎ linka 245")


def with_port(stanza: str, vlans: bool = True) -> str:
    """The measured baseline with the measured Ethernet12 stanza and test VLAN blocks of cEOS."""
    text = BASELINE.replace("interface Ethernet12\n!\n", stanza.rstrip("\n") + "\n!\n", 1)
    if vlans:
        blocks = VLANS.replace("vlan 3991", "!\nvlan 3991").rstrip("\n") + "\n!\n"
        text = text.replace("vlan 20\n   name D20\n!\n", "vlan 20\n   name D20\n!\n" + blocks, 1)
    return text


def plan(text=BASELINE, **fields):
    return build_plan("eos", text.encode(), request(**fields), firmware=FIRMWARE)


def port(**fields):
    fields.setdefault("table", "vlan-membership")
    fields.setdefault("key", "Ethernet12")
    return request(**fields)


# ---- plan adapter on the measured running configuration ----

def test_measured_stanzas_parse_into_the_profile_attributes():
    snapshot = eos.load(with_port(TRUNK_DOT1X), FIRMWARE)
    assert snapshot.entries("vlan-membership")["Ethernet12"].attributes == {
        "native-vlan": "3990", "voice-vlan": "3991", "allowed-vlans": "3990-3991", "mode": "trunk",
        "dot1x": "enabled", "mab": "enabled"}
    # the measured "switchport phone trunk tagged" is outside the profile
    assert snapshot.entries("vlan-membership")["Ethernet12"].unsupported
    assert snapshot.entries("interface")["Ethernet12"].attributes == {"description": LONG}
    assert {vid: entry.attributes for vid, entry in snapshot.entries("vlan").items()} == {
        "10": {"name": "D10"}, "20": {"name": "D20"}, "3990": {"name": "eos-switchport-admin-data"}, "3991": {"name": "eos-switchport-admin-voice"}}
    phone = eos.load(with_port(TRUNK_PHONE), FIRMWARE).entries("vlan-membership")["Ethernet12"]
    assert phone.attributes["mode"] == "trunk phone"
    assert eos.load(with_port(TRUNK_PHONE), FIRMWARE).references("vlan", "3991") == ["Ethernet12"]


def test_vlan_create_rename_delete_plans():
    created = plan(table="vlan", op="create", key="3990", changes={"name": "eos-switchport-admin-data"})
    assert created["commands"] == ["configure terminal", "vlan 3990", "name eos-switchport-admin-data", "end"]
    assert created["inverse"] == ["configure terminal", "no vlan 3990", "end"]
    after = with_port("interface Ethernet12", vlans=True).replace("vlan 3991\n   name eos-switchport-admin-voice\n!\n", "")
    assert verify(created, after.encode())["result"] == "match"
    renamed = plan(after, table="vlan", op="update", key="3990", changes={"name": "eos-switchport-admin-renamed"})
    assert renamed["commands"] == ["configure terminal", "vlan 3990", "name eos-switchport-admin-renamed", "end"]
    assert renamed["inverse"] == ["configure terminal", "vlan 3990", "name eos-switchport-admin-data", "end"]
    unnamed = plan(after, table="vlan", op="update", key="3990", changes={"name": None})
    assert unnamed["commands"][2] == "no name" and unnamed["predicted"]["after"] == {}
    deleted = plan(after, table="vlan", op="delete", key="3990", changes={})
    assert deleted["commands"] == ["configure terminal", "no vlan 3990", "end"]
    assert deleted["inverse"] == ["configure terminal", "vlan 3990", "name eos-switchport-admin-data", "end"]


@pytest.mark.parametrize("fields, text, fragment", [
    ({"op": "create", "key": "1", "changes": {"name": "x"}}, BASELINE, "protected"),
    ({"op": "create", "key": "10", "changes": {"name": "x"}}, BASELINE, "already used"),
    ({"op": "create", "key": "3990", "changes": {"name": "eos-switchport-admin-žluť"}}, BASELINE, "printable ASCII"),
    ({"op": "create", "key": "3990", "changes": {"name": "eos-switchport-admin space"}}, BASELINE, "must match"),
    ({"op": "create", "key": "3990", "changes": {"name": "x" * 33}}, BASELINE, "longer than 32"),
    ({"op": "delete", "key": "3991", "changes": {}}, with_port(TRUNK_PHONE), "referenced"),
    ({"op": "delete", "key": "10", "changes": {}}, BASELINE, "referenced"),
])
def test_vlan_refusals(fields, text, fragment):
    with pytest.raises(Rejected) as caught:
        plan(text, table="vlan", **fields)
    assert fragment in " ".join(caught.value.reasons)


def test_trunk_allowed_native_and_voice_plans():
    trunk = plan(with_port("interface Ethernet12"), table="vlan-membership", key="Ethernet12", endpoint_impact="Ethernet12",
                 changes={"mode": "trunk", "allowed-vlans": "3991,3990", "native-vlan": 3990})
    assert trunk["commands"] == ["configure terminal", "interface Ethernet12", "switchport trunk allowed vlan 3990-3991",
                                 "switchport mode trunk", "switchport trunk native vlan 3990", "end"]
    assert trunk["inverse"] == ["configure terminal", "interface Ethernet12", "no switchport trunk allowed vlan",
                                "switchport mode access", "no switchport trunk native vlan", "end"]
    assert trunk["endpoint_impact"] == "Ethernet12"
    stanza = "interface Ethernet12\n   switchport trunk native vlan 3990\n   switchport trunk allowed vlan 3990-3991\n" \
             "   switchport mode trunk"
    removed = plan(with_port(stanza), table="vlan-membership", key="Ethernet12", changes={"allowed-vlans": "3990"})
    assert removed["commands"][2] == "switchport trunk allowed vlan 3990"
    assert removed["inverse"][2] == "switchport trunk allowed vlan 3990-3991"
    # a retained allowed VLAN may be missing; a newly added one must exist
    sparse = stanza.replace("3990-3991", "3990-3999")
    assert plan(with_port(sparse), table="vlan-membership", key="Ethernet12",
                changes={"allowed-vlans": "3990,3992-3999"})["predicted"]["after"]["allowed-vlans"] == "3990,3992-3999"
    with pytest.raises(Rejected) as caught:
        plan(with_port(stanza), table="vlan-membership", key="Ethernet12", changes={"allowed-vlans": "3990-3992"})
    assert caught.value.reason_codes == ["vlan_missing"]
    voice = plan(with_port("interface Ethernet12"), table="vlan-membership", key="Ethernet12",
                 changes={"mode": "trunk phone", "native-vlan": 3990, "voice-vlan": 3991, "dot1x": "enabled",
                          "mab": "enabled"})
    assert voice["commands"][2:-1] == ["dot1x pae authenticator", "dot1x port-control auto",
                                       "dot1x mac based authentication", "switchport mode trunk phone",
                                       "switchport trunk native vlan 3990", "switchport phone vlan 3991"]
    assert voice["inverse"][2:-1] == ["no dot1x port-control", "no dot1x pae authenticator",
                                      "no dot1x mac based authentication", "switchport mode access",
                                      "no switchport trunk native vlan", "no switchport phone vlan"]


@pytest.mark.parametrize("changes, fragment", [
    ({"voice-vlan": 3991}, "voice-vlan needs mode trunk phone"),
    ({"mode": "trunk", "voice-vlan": 3991}, "voice-vlan needs mode trunk phone"),
    ({"mab": "enabled"}, "mab needs dot1x enabled"),
    ({"native-vlan": 3990}, "apply to a trunk"),
    ({"mode": "dot1q-tunnel"}, "must match"),
])
def test_membership_combinations_eos_ignores_are_refused(changes, fragment):
    with pytest.raises(Rejected) as caught:
        plan(with_port("interface Ethernet12"), table="vlan-membership", key="Ethernet12", changes=changes)
    assert fragment in " ".join(caught.value.reasons)


def test_a_stale_phone_vlan_outside_trunk_phone_mode_is_tolerated_like_before():
    # measured stanza after "switchport mode access": phone VLAN, phone trunk and pae without port-control auto stay;
    # EOS-SWITCHPORT-ADMIN r2 (review finding 2): an access VLAN change keeps them as before EOS-SWITCHPORT-ADMIN (the runtime path is in
    # test_eos_eos_switchport_admin_r2.py)
    changed = plan(with_port(STALE_PHONE), table="vlan-membership", key="Ethernet12", changes={"access-vlan": 20})
    assert changed["commands"] == ["configure terminal", "interface Ethernet12", "switchport access vlan 20", "end"]
    assert changed["predicted"]["after"] == {"access-vlan": "20", "voice-vlan": "3991", "mab": "enabled"}
    stale = "interface Ethernet12\n   switchport access vlan 3990\n   switchport phone vlan 3991"
    assert plan(with_port(stale), table="vlan-membership", key="Ethernet12",
                changes={"access-vlan": 20})["commands"][2] == "switchport access vlan 20"
    removed = plan(with_port(stale), table="vlan-membership", key="Ethernet12", changes={"voice-vlan": None})
    assert removed["commands"][2] == "no switchport phone vlan" and removed["predicted"]["after"] == {
        "access-vlan": "3990"}
    # the left-over lines would act after a mode, 802.1X or MAB change, so such a change is refused
    for changes in ({"mode": "trunk phone", "voice-vlan": 3991}, {"dot1x": "enabled"}, {"mab": "disabled"}):
        with pytest.raises(Rejected) as caught:
            plan(with_port(STALE_PHONE), table="vlan-membership", key="Ethernet12", changes=changes,
                 endpoint_impact="Ethernet12")
        assert "outside the profile" in " ".join(caught.value.reasons), changes
    # a changed phone VLAN outside trunk phone mode is still refused
    with pytest.raises(Rejected) as caught:
        plan(with_port(stale), table="vlan-membership", key="Ethernet12", changes={"voice-vlan": 3990})
    assert "voice-vlan needs mode trunk phone" in caught.value.reasons[0]


def test_left_over_lines_stay_in_the_rest_and_in_the_predicted_configuration():
    text = with_port(STALE_PHONE)
    snapshot = eos.load(text, FIRMWARE)
    entry = snapshot.entries("vlan-membership")["Ethernet12"]
    assert entry.unsupported == [] and entry.leftover == ["switchport phone trunk untagged", "dot1x pae authenticator"]
    changed = plan(text, table="vlan-membership", key="Ethernet12", changes={"access-vlan": 20})
    predicted = eos.snapshot_after(text, changed)
    assert "   switchport phone trunk untagged" in predicted and "   dot1x pae authenticator" in predicted
    assert verify(changed, predicted.encode())["result"] == "match"
    without_pae = predicted.replace("   dot1x pae authenticator\n", "", 1)
    assert verify(changed, without_pae.encode())["result"] == "mismatch"


def test_explicit_default_vlan_name_is_planned_as_no_name():
    # Review finding 3: the captured running configuration omits the default name VLAN3992.
    named = with_port("interface Ethernet12").replace("vlan 3991\n   name eos-switchport-admin-voice\n!\n",
                                                      "vlan 3991\n   name eos-switchport-admin-voice\n!\nvlan 3992\n   name eos-switchport-admin-named\n!\n")
    renamed = plan(named, table="vlan", op="update", key="3992", changes={"name": "VLAN3992"})
    assert renamed["commands"] == ["configure terminal", "vlan 3992", "no name", "end"]
    assert renamed["predicted"]["after"] == {} and renamed["inverse"][2] == "name eos-switchport-admin-named"
    created = plan(table="vlan", op="create", key="3994", changes={"name": "VLAN3994"})
    assert created["commands"] == ["configure terminal", "vlan 3994", "end"] and created["predicted"]["after"] == {}
    # another VLAN's default form is an ordinary name
    other = plan(table="vlan", op="create", key="3994", changes={"name": "VLAN3992"})
    assert other["predicted"]["after"] == {"name": "VLAN3992"}


def test_long_description_with_diacritics_and_literal_symbols():
    result = plan(key="Ethernet12", changes={"description": LONG})
    assert result["commands"] == ["configure terminal", "interface Ethernet12", "description " + LONG, "end"]
    assert result["predicted"]["after"] == {"description": LONG}
    assert len(plan(key="Ethernet12", changes={"description": "é" * 240})["commands"][2]) == 252


@pytest.mark.parametrize("value, fragment", [
    ("a?b", "without '?'"), ("a\tb", "printable"), ("a b", "printable"), (" lead", "spaces"),
    ("trail ", "spaces"), ("x" * 241, "longer than 240"),
])
def test_description_that_eos_would_not_store_literally_is_refused(value, fragment):
    with pytest.raises(Rejected) as caught:
        plan(key="Ethernet12", changes={"description": value})
    assert fragment in " ".join(caught.value.reasons)


# ---- check-account parsers on the real answers ----

def test_membership_readback_of_the_measured_switchport_answers():
    assert eos.membership(eos_switchport_admin("show-interfaces-Ethernet12-switchport__trunk.txt"), "Ethernet12") == {
        "mode": "trunk", "access-vlan": "1", "native-vlan": "3990", "allowed-vlans": "3990-3991"}
    assert eos.membership(eos_switchport_admin("show-interfaces-Ethernet12-switchport__trunk-phone.txt"), "Ethernet12") == {
        "mode": "trunk phone", "access-vlan": "1", "native-vlan": "3990", "allowed-vlans": "all", "voice-vlan": "3991"}
    assert eos.membership(eos_switchport_admin("show-interfaces-Ethernet12-switchport__trunk-phone-tagged.txt"), "Ethernet12")[
        "voice-vlan"] == "3991"
    assert eos.membership(eos_switchport_admin("show-interfaces-Ethernet12-switchport__access-3990.txt"), "Ethernet12") == {
        "mode": "access", "access-vlan": "3990", "native-vlan": "1", "allowed-vlans": "all"}
    with pytest.raises(Rejected):
        eos.membership(eos_switchport_admin("show-interfaces-Ethernet12-switchport__trunk.txt"), "Ethernet11")
    cut = eos_switchport_admin("show-interfaces-Ethernet12-switchport__trunk.txt").split("Trunking VLANs")[0]
    with pytest.raises(Rejected) as caught:
        eos.membership(cut, "Ethernet12")
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_dot1x_readback_of_the_measured_answers():
    assert eos.dot1x_state(eos_switchport_admin("show-dot1x-interface-Ethernet12__auto-mab.txt"), "Ethernet12") == {
        "dot1x": "enabled", "mab": "enabled"}
    assert eos.dot1x_state(eos_switchport_admin("show-dot1x-interface-Ethernet12__force-authorized-mab.txt"), "Ethernet12") == {
        "dot1x": "port-control force-authorized", "mab": "enabled"}
    assert eos.dot1x_state(eos_switchport_admin("show-dot1x-interface-Ethernet12__none.txt"), "Ethernet12") == {}
    assert eos.dot1x_state(eos_switchport_admin("show-dot1x-interface-Ethernet12__auto.txt"), "Ethernet12") == {"dot1x": "enabled"}
    cut = eos_switchport_admin("show-dot1x-interface-Ethernet12__auto-mab.txt").split("MAC-based")[0]
    with pytest.raises(Rejected):
        eos.dot1x_state(cut, "Ethernet12")


def test_vlan_and_description_readback_of_the_measured_answers():
    assert eos.vlan_state(eos_switchport_admin("show-vlan-id-3990__created.txt"), "3990") == {"name": "eos-switchport-admin-data"}
    assert eos.vlan_state(fixture("show-vlan-id-3999__missing.txt"), "3999") is None
    assert eos.vlan_state(eos_switchport_admin("show-vlan-id-3999__missing-exec-rc1.txt"), "3999") is None
    assert eos.vlan_exists(eos_switchport_admin("show-vlan-id-3999__missing-exec-rc1.txt"), "3999") is False
    assert eos.vlan_state(eos_switchport_admin("show-vlan-id-3992__unnamed.txt"), "3992") == {}
    assert eos.description_row(eos_switchport_admin("show-interfaces-Ethernet12-description__utf8.txt"), "Ethernet12") == {
        "status": "up", "description": LONG}
    assert eos.status_row(eos_switchport_admin("show-interfaces-Ethernet12-status__utf8.txt"), "Ethernet12") == "connected"
    assert eos.learned_macs(eos_switchport_admin("show-mac-address-table-vlan-10__learned.txt")) == 5
    assert eos.learned_macs(eos_switchport_admin("show-mac-address-table-vlan-3990__empty.txt")) == 0
    assert "privileged mode required" in eos_switchport_admin("show-running-config-interfaces-Ethernet12__ro-denied.txt")


# ---- preview, confirmed apply, readback and undo through the fake transport ----

def test_vlan_lifecycle_preview_apply_readback_and_undo(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", request(table="vlan", op="create", key="3990",
                                                           changes={"name": "eos-switchport-admin-data"}, request_id="eos-switchport-admin-u-1"))
    assert preview["result"] == "ready" and device.applied_blocks == [] and "3990" not in device.vlans()
    created = execute.apply(runtime, "lab-ceos", request(table="vlan", op="create", key="3990",
                                                         changes={"name": "eos-switchport-admin-data"}, request_id="eos-switchport-admin-u-1"),
                            expected_plan_sha256=preview["plan_sha256"])
    assert created["result"] == "confirmed", (created.get("reason"), steps(created))
    assert device.vlan_name("3990") == "eos-switchport-admin-data" and "show vlan id 3990" in device.check_queries
    renamed = approved_apply(runtime, "lab-ceos", request(table="vlan", op="update", key="3990",
                                                         changes={"name": "eos-switchport-admin-renamed"}, request_id="eos-switchport-admin-u-2"))
    assert renamed["result"] == "confirmed" and device.vlan_name("3990") == "eos-switchport-admin-renamed"
    assert execute.undo(runtime, renamed["change_id"], "back to the old name")["result"] == "confirmed"
    assert device.vlan_name("3990") == "eos-switchport-admin-data"
    assert execute.undo(runtime, created["change_id"], "remove the test VLAN")["result"] == "confirmed"
    assert "3990" not in device.vlans() and device.lines == device.saved and device.sessions == {}


def test_vlan_delete_with_learned_macs_is_refused_before_any_write(tmp_path):
    device = FakeEos()
    device.learned_macs["vlan 20"] = 5
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos",
                             request(table="vlan", op="delete", key="20", changes={}))
    assert result["result"] == "rejected"
    assert "referenced" in " ".join(result["reasons"]) or result["reason_codes"] == ["port_learned_mac"]
    assert device.applied_blocks == []


def _create_vlans(device):
    for vid, name in (("3990", "eos-switchport-admin-data"), ("3991", "eos-switchport-admin-voice")):
        device._add_vlan(vid)
        device._vlan_line(vid, ["name", name], "name " + name)
    device.saved = list(device.lines)


def test_trunk_needs_endpoint_impact_then_applies_reads_back_and_undoes(tmp_path):
    device = FakeEos()
    _create_vlans(device)
    runtime = make_runtime(tmp_path, device)
    changes = {"mode": "trunk", "allowed-vlans": "3990-3991", "native-vlan": 3990}
    refused = execute.preview(runtime, "lab-ceos", port(changes=changes, request_id="eos-switchport-admin-u-3"))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["endpoint_impact_required"]
    record = approved_apply(runtime, "lab-ceos", port(changes=changes, endpoint_impact="Ethernet12",
                                                     request_id="eos-switchport-admin-u-4"))
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert set(device.interface("Ethernet12")) == {"switchport trunk allowed vlan 3990-3991", "switchport mode trunk",
                                                   "switchport trunk native vlan 3990"}
    assert "show dot1x interface Ethernet12" in device.check_queries
    added = approved_apply(runtime, "lab-ceos", port(changes={"allowed-vlans": "3990"}, endpoint_impact="Ethernet12",
                                                    request_id="eos-switchport-admin-u-5"))
    assert added["result"] == "confirmed" and "switchport trunk allowed vlan 3990" in device.interface("Ethernet12")
    assert execute.undo(runtime, added["change_id"], "add 3991 again")["result"] == "confirmed"
    assert "switchport trunk allowed vlan 3990-3991" in device.interface("Ethernet12")
    assert execute.undo(runtime, record["change_id"], "back to access")["result"] == "confirmed"
    assert device.interface("Ethernet12") == [] and device.lines == device.saved


def test_voice_vlan_with_dot1x_and_mab_applies_reads_back_and_undoes(tmp_path):
    device = FakeEos()
    _create_vlans(device)
    runtime = make_runtime(tmp_path, device)
    changes = {"mode": "trunk phone", "native-vlan": 3990, "voice-vlan": 3991, "dot1x": "enabled", "mab": "enabled"}
    record = approved_apply(runtime, "lab-ceos", port(changes=changes, endpoint_impact="Ethernet12",
                                                     request_id="eos-switchport-admin-u-6"))
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert "dot1x pae authenticator" in device.interface("Ethernet12")
    assert execute.undo(runtime, record["change_id"], "remove the phone port")["result"] == "confirmed"
    assert device.interface("Ethernet12") == [] and device.lines == device.saved


def test_unreadable_dot1x_answer_after_the_write_is_reverted(tmp_path):
    device = FakeEos()
    _create_vlans(device)
    cut = eos_switchport_admin("show-dot1x-interface-Ethernet12__auto-mab.txt").split("MAC-based")[0]

    def break_check(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_override = {"show dot1x interface Ethernet12": cut}

    device.on_apply = break_check
    record = approved_apply(make_runtime(tmp_path, device), "lab-ceos",
                           port(changes={"mode": "trunk phone", "voice-vlan": 3991, "dot1x": "enabled"},
                                endpoint_impact="Ethernet12", request_id="eos-switchport-admin-u-7"))
    assert record["result"] == "reverted", (record.get("reason"), steps(record))
    assert device.interface("Ethernet12") == [] and device.lines == device.saved


def test_long_description_is_applied_read_back_and_undone(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "lab-ceos", request(key="Ethernet12", changes={"description": LONG},
                                                        request_id="eos-switchport-admin-u-8"))
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert device.interface("Ethernet12") == ["description " + LONG]
    assert execute.undo(runtime, record["change_id"], "remove the description")["result"] == "confirmed"
    assert device.interface("Ethernet12") == []


def test_a_port_in_use_keeps_needing_endpoint_impact(tmp_path):
    device = FakeEos()
    device.learned_macs["Ethernet10"] = 2
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos",
                             port(key="Ethernet10", changes={"access-vlan": 10}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_learned_mac"]
    accepted = execute.preview(make_runtime(tmp_path / "b", device), "lab-ceos",
                               port(key="Ethernet10", changes={"access-vlan": 10}, endpoint_impact="Ethernet10"))
    assert accepted["result"] == "ready" and any("explicitly accepted" in check for check in accepted["prechecks"])


def test_access_vlan_of_a_trunk_now_needs_endpoint_impact_at_runtime(tmp_path):
    # before EOS-SWITCHPORT-ADMIN the plan refused every trunk port (port_uplink); the membership of a trunk is now planned and the
    # runtime check asks for the explicit endpoint impact
    plan(table="vlan-membership", key="Ethernet1", changes={"access-vlan": 20})
    device = FakeEos()
    result = execute.preview(make_runtime(tmp_path, device), "lab-ceos",
                             port(key="Ethernet1", changes={"access-vlan": 20}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["endpoint_impact_required"]
