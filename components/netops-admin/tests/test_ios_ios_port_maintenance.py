"""1.0.12 IOS-PORT-MAINTENANCE: port bounce (IOS-C021) and PoE of a Cisco IOS or IOS XE port (IOS-M023 setting, IOS-M024 cycle).

Every case runs the real path (execute.preview/apply/undo or ios_cycle.preview/apply, engine plan, exec_ios prechecks,
postcheck and check-account readback) against FakeIos. Link answers come from outputs measured on the GNS3 IOSvL2
15.2(20200924:215240) (fixtures/ios_ios_port_maintenance, private measurement record). The lab node has no PoE: its refusal of `show power
inline` and of `power inline ...` is measured; the PoE answers of a PoE switch come from the Cisco manual (see
fixtures/ios_ios_port_maintenance/PROVENANCE.md, marked derived where adapted) and are produced by FakeIos for the ports named in
poe_ports.
"""
from __future__ import annotations

import copy
import dataclasses
from pathlib import Path

import pytest

from fake_ios import FakeIos, ios_port_maintenance
from test_ios import make_runtime, steps

from netops_admin import engine, exec_ios, execute, ios, ios_cycle
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile, load_profiles

FW = "15.2(20200924:215240)"
PORT = "GigabitEthernet1/3"
BOUNCE, POE = ios_cycle.BOUNCE, ios_cycle.POE


def device_with(*lines, link=True, poe=None, node="iosvl2"):
    """The measured lab node whose free test port GigabitEthernet1/3 got the given interface lines."""
    device = FakeIos(node)
    start, end = device._block("interface %s" % PORT)
    device.lines[start + 1:end] = [" " + line for line in lines] + [" negotiation auto"]
    device.saved = list(device.lines)
    if link:
        device.link_up.add(PORT)
    if poe is not None:
        device.poe_ports[PORT] = poe
    return device


def runtime_for(tmp_path, device, seconds=240, **fields):
    runtime = make_runtime(tmp_path, device, seconds=seconds, simulate_unmeasured_profiles=True)
    if fields:
        runtime.config.devices["lab-ios"] = dataclasses.replace(runtime.config.devices["lab-ios"], **fields)
    return runtime


def cycle(action, port=PORT, request_id="ios-port-maintenance-cycle-0001", impact=None):
    return ios_cycle.request(action, "lab-ios", port, "restart the device on the port", "bounce the port",
                             request_id, impact)


def setting(changes, port=PORT, request_id="ios-port-maintenance-set-0001", impact=False, table="inline-power"):
    from conftest import request_bytes
    from netops_admin.request import parse_request
    fields = dict(table=table, key=port, op="update", changes=changes, request_id=request_id)
    if impact:
        fields["endpoint_impact"] = port
    return parse_request(request_bytes(**fields))


def codes(call, *args, **kwargs):
    """Reason codes of a refusal, whether the preview raises it or returns it."""
    try:
        result = call(*args, **kwargs)
    except Rejected as exc:
        return exc.reason_codes
    assert result["result"] == "rejected", result
    return result["reason_codes"]


def run_cycle(runtime, action, request_id, impact=None, port=PORT):
    preview = ios_cycle.preview(runtime, "lab-ios", action, cycle(action, port, request_id, impact))
    assert preview["result"] == "ready", preview
    return preview, ios_cycle.apply(runtime, "lab-ios", action, cycle(action, port, request_id, impact),
                                    expected_plan_sha256=preview["plan_sha256"])


def interface_lines(device, port=PORT):
    return device.interface(port)


# ---- registration ----

@pytest.mark.parametrize("platform, firmware", [("ios", FW), ("iosxe", "17.18.2")])
def test_profiles_of_the_three_tables_exist_for_ios_and_ios_xe(platform, firmware):
    profiles = load_profiles()
    assert profiles[(platform, "port-bounce")].action == "port-bounce"
    assert profiles[(platform, "poe-cycle")].action == "poe-cycle"
    assert profiles[(platform, "inline-power")].action is None
    assert find_profile(platform, "inline-power", firmware).ops == ("update",)
    assert "not measured on PoE hardware" in profiles[(platform, "inline-power")].rollback_evidence.replace("NOT", "not")


# ---- the measured answers and the parsers ----

def test_status_row_reads_the_measured_status_column():
    assert ios.status_row(ios_port_maintenance("show-interfaces-status-Gi1-2__notconnect.txt"), "GigabitEthernet1/2") == "notconnect"
    assert ios.status_row(ios_port_maintenance("show-interfaces-status-Gi1-2__disabled.txt"), "GigabitEthernet1/2") == "disabled"
    table = ios_port_maintenance("show-interfaces-status__baseline.txt")
    assert [ios.status_row(table, name) for name in ("GigabitEthernet0/0", "GigabitEthernet1/0", "GigabitEthernet1/3")] \
        == ["connected", "disabled", "notconnect"]
    assert ios.status_row(table, "GigabitEthernet1/9") is None


def test_status_row_reads_the_ios_xe_table_with_its_own_widths():
    table = ios_port_maintenance("show-interfaces-status__iolxe-l2.txt")
    assert [ios.status_row(table, name) for name in ("Ethernet0/0", "Ethernet0/1", "Ethernet2/0")] == [
        "connected", "disabled", "connected"]
    assert ios.status_row(table, "Ethernet9/9") is None


@pytest.mark.parametrize("text", ["", "\n% Invalid input detected at '^' marker.\n",
                                  'Line has invalid autocommand "show interfaces Gi1/2 status"',
                                  "\nPort      Name               Status       Vlan       Duplex  Speed Type \n"
                                  "Gi1/2                        flapping     1          a-full   auto RJ45\n"])
def test_unreadable_status_is_unreadable_not_a_state(text):
    with pytest.raises(Rejected) as caught:
        ios.status_row(text, "GigabitEthernet1/2")
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_poe_row_reads_the_manual_layout_and_a_refusal_is_no_row():
    row = ios.poe_row(ios_port_maintenance("show-power-inline-Gi1-0-4__doc-auto-on.txt"), "GigabitEthernet1/0/4")
    assert row == {"admin": "auto", "oper": "on", "max-milliwatts": "60000"}
    assert ios.poe_row(ios_port_maintenance("show-power-inline-Gi1-0-4__derived-never-off.txt"), "GigabitEthernet1/0/4")["admin"] == "off"
    assert ios.poe_row(ios_port_maintenance("show-power-inline-Gi1-0-4__derived-static-on.txt"),
                       "GigabitEthernet1/0/4") == {"admin": "static", "oper": "on", "max-milliwatts": "15400"}
    assert ios.poe_row(ios_port_maintenance("show-power-inline__exec-refused.txt"), "GigabitEthernet1/2") is None
    assert ios.poe_row(ios_port_maintenance("show-power-inline-Gi1-0-4__doc-auto-on.txt"), "GigabitEthernet1/0/5") is None
    with pytest.raises(Rejected):
        ios.poe_row("Interface Admin Oper\nGi1/0/4 sideways on x 4 60.0\n", "GigabitEthernet1/0/4")
    with pytest.raises(Rejected):
        ios.poe_row("something else\n", "GigabitEthernet1/0/4")


@pytest.mark.parametrize("lines, expected", [
    ([], {}),
    (["power inline never"], {"mode": "never"}),
    (["power inline static max 15400"], {"mode": "static", "max-milliwatts": "15400"}),
    (["power inline auto max 7000"], {"mode": "auto", "max-milliwatts": "7000"}),
    (["power inline port priority high"], {}),
])
def test_snapshot_reads_the_power_inline_line_and_leaves_the_other_ones(lines, expected):
    device = device_with(*lines)
    snapshot = ios.load(device.snapshot(), FW)
    assert snapshot.entries("inline-power")[PORT].attributes == expected
    assert snapshot.entries("inline-power")[PORT].unsupported == []
    # the line belongs to the PoE table only: the interface table does not see it
    assert snapshot.entries("interface")[PORT].attributes == {}


def test_poe_line_renders_the_one_replacing_line():
    assert ios.poe_line({}) is None and ios.poe_line({"mode": "never"}) == "power inline never"
    assert ios.poe_line({"mode": "static"}) == "power inline static"
    assert ios.poe_line({"max-milliwatts": "7000"}) == "power inline auto max 7000"
    assert ios.render_poe(PORT, {}) == ["configure terminal", "interface " + PORT, "power inline auto", "end"]
    for bad in ({"mode": "never", "max-milliwatts": "7000"}, {"max-milliwatts": "3999"}, {"max-milliwatts": "90001"},
                {"mode": "sideways"}):
        with pytest.raises(Rejected):
            ios.poe_line(bad)


# ---- IOS-C021: the port bounce ----

def test_bounce_previews_without_a_write_and_names_both_commands(tmp_path):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)
    preview = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, impact=PORT))
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + PORT, "shutdown", "end"]
    assert preview["cycle_commands"][-4:] == ["configure terminal", "interface " + PORT, "no shutdown", "end"]
    assert preview["cycle_state"] == {"link": "connected", "lldp": "False", "learned_macs": "0"}
    assert preview["hold_seconds"] == ios_cycle.HOLD_SECONDS
    assert device.applied_blocks == [] and device.timer is None and device.saves == 0


def test_review_1_connected_without_mac_or_neighbors_requires_impact(tmp_path):
    device = device_with("switchport mode access")
    measured = ios_port_maintenance("show-interfaces-status__baseline.txt")
    device.check_override = {"show interfaces %s status" % PORT:
                             measured.replace("Gi1/3", "Gi1/9").replace("Gi0/0", "Gi1/3")}
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["endpoint_impact_required"]
    assert device.applied_blocks == []


def test_review_2_negotiated_trunk_carrying_management_vlan_is_refused(tmp_path):
    device = device_with("switchport mode dynamic desirable", "switchport trunk allowed vlan 10,99")
    capture = ((Path(__file__).parent / "fixtures") / "ios_xe_switchports" / "switchport-removed.txt").read_text()
    answer = (capture.replace("Name: Et0/1", "Name: Gi1/3")
              .replace("Administrative Mode: trunk", "Administrative Mode: dynamic desirable")
              .replace("Access Mode VLAN: 3780 (netops-xe-switchports-renamed)", "Access Mode VLAN: 1 (default)")
              .replace("Trunking Native Mode VLAN: 3780 (netops-xe-switchports-renamed)", "Trunking Native Mode VLAN: 1 (default)")
              .replace("Trunking VLANs Enabled: 3780", "Trunking VLANs Enabled: 10,99"))
    device.query_override["show interfaces %s switchport" % PORT] = answer
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE, impact=PORT)) == ["port_management_vlan"]
    assert device.applied_blocks == []


def test_review_3_poe_mode_requires_a_preview_hash(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    change = setting({"mode": "never"})
    assert execute.preview(runtime, "lab-ios", change)["result"] == "ready"
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-ios", change)
    assert caught.value.reason_codes == ["plan_changed"]
    assert device.applied_blocks == []


def test_bounce_is_one_operation_with_the_link_before_and_after(tmp_path):
    device = device_with("switchport mode access")
    before, saved = interface_lines(device), list(device.saved)
    runtime = runtime_for(tmp_path, device)
    preview, record = run_cycle(runtime, BOUNCE, "ios-port-maintenance-bounce-0001", impact=PORT)
    assert record["result"] == "confirmed" and record["reason"] is None, (record.get("reason"), steps(record))
    assert interface_lines(device) == before and device.lines == saved and device.timer is None
    cycle_record = record["cycle"]
    assert cycle_record["before"] == {"status": "connected"} and cycle_record["off"] == {"status": "disabled"}
    assert cycle_record["after"] == {"status": "connected"}
    names = steps(record)
    assert names.index("port_off_observed") < names.index("off_held") < names.index("port_enable_start") \
        < names.index("port_on_observed") < names.index("confirm_start") < names.index("safeguard_confirmed")
    sent = [line for line in device.sent_lines if line in ("shutdown", "no shutdown")]
    assert sent == ["shutdown", "no shutdown"]
    assert device.saves == 0 and device.saved_while_pending == 0
    # one operation: a second request with the same id returns it without a new cycle
    again = ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bounce-0001", impact=PORT),
                            expected_plan_sha256=preview["plan_sha256"])
    assert again["change_id"] == record["change_id"] and device.sent_lines.count("shutdown") == 1


def test_bounce_of_a_free_port_without_link_reports_notconnect_before_and_after(tmp_path):
    device = device_with("switchport mode access", link=False)
    runtime = runtime_for(tmp_path, device)
    _preview, record = run_cycle(runtime, BOUNCE, "ios-port-maintenance-bounce-0002")
    assert record["result"] == "confirmed" and record["reason"] is None
    assert record["cycle"]["before"] == {"status": "notconnect"} and record["cycle"]["after"] == {"status": "notconnect"}


def test_bounce_waits_for_the_link_and_reports_one_that_does_not_come_back(tmp_path):
    device = device_with("switchport mode access")
    device.link_delay = 12
    runtime = runtime_for(tmp_path, device)
    _preview, record = run_cycle(runtime, BOUNCE, "ios-port-maintenance-bounce-0003", impact=PORT)
    assert record["result"] == "confirmed" and record["reason"] is None
    late = device_with("switchport mode access")
    late.link_delay = 600
    runtime = runtime_for(tmp_path / "late", late)
    _preview, record = run_cycle(runtime, BOUNCE, "ios-port-maintenance-bounce-0004", impact=PORT)
    assert record["result"] == "confirmed" and record["reason"] == ios_cycle.LINK_NOT_BACK
    assert record["cycle"]["after"] == {"status": "notconnect"} and late.lines == late.saved


def test_bounce_of_a_disabled_port_is_refused_before_any_write(tmp_path):
    device = device_with("switchport mode access", "shutdown")
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["port_disabled"]
    assert device.applied_blocks == []
    with pytest.raises(Rejected) as caught:
        ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bounce-0005"),
                        expected_plan_sha256="0" * 64)
    assert device.applied_blocks == [] and caught.value.reason_codes


def test_bounce_has_no_undo_and_needs_the_approved_hash(tmp_path):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bounce-0006", impact=PORT))
    assert caught.value.reason_codes == ["plan_changed"] and device.applied_blocks == []
    with pytest.raises(Rejected) as caught:
        ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bounce-0006", impact=PORT),
                        expected_plan_sha256="f" * 64)
    assert caught.value.reason_codes == ["plan_changed"] and device.applied_blocks == []
    _preview, record = run_cycle(runtime, BOUNCE, "ios-port-maintenance-bounce-0007", impact=PORT)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record["change_id"], "return the port")
    assert caught.value.reason_codes == ["undo_not_applicable"]


def test_the_table_of_an_operation_is_changed_by_that_operation_only(tmp_path):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)
    plain = setting({"admin-state": "disabled"}, table="port-bounce", request_id="ios-port-maintenance-direct-0001")
    assert codes(execute.preview, runtime, "lab-ios", plain) == ["action_only_table"]
    wrong = setting({"admin-state": "enabled"}, table="port-bounce", request_id="ios-port-maintenance-direct-0002")
    with pytest.raises(Rejected) as caught:
        execute._preview(runtime, "lab-ios", wrong, action=BOUNCE)
    assert caught.value.reason_codes == ["action_unsupported"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("lines, port, code", [
    ([], PORT, "port_uplink"),                                              # dynamic auto: treated as an uplink
    (["switchport mode trunk"], PORT, "port_management_vlan"),            # allowed VLANs "all" carry the management VLAN
    (["switchport mode access", "channel-group 3 mode active"], PORT, "port_lag_member"),
    (["switchport mode access", "ip address 203.0.113.9 255.255.255.0"], PORT, "port_ip_address"),
    (["switchport mode access"], "GigabitEthernet0/0", "port_management_vlan"),
    (["switchport mode access"], "Vlan99", "port_unsupported_interface"),
])
def test_bounce_protections_refuse_before_any_write(tmp_path, lines, port, code):
    device = device_with(*lines)
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE, port)) == [code]
    # an explicit endpoint impact never waives the management, port-channel and routing protections
    if code != "port_uplink":
        assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE, port, impact=port)) == [code]
    assert device.applied_blocks == []


def test_a_trunk_or_dynamic_port_is_bounced_only_with_the_explicit_impact(tmp_path):
    device = device_with("switchport trunk encapsulation dot1q", "switchport mode trunk",
                         "switchport trunk allowed vlan 10,20")
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["port_uplink"]
    plain = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-t-0001"))
    accepted = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-t-0002", impact=PORT))
    assert accepted["result"] == "ready" and plain["result"] == "rejected"
    assert any("endpoint impact explicitly accepted" in line for line in accepted["prechecks"])


def test_a_trunk_that_carries_the_management_vlan_is_never_bounced(tmp_path):
    device = device_with("switchport trunk encapsulation dot1q", "switchport mode trunk",
                         "switchport trunk allowed vlan 10,99")
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE, impact=PORT)) == ["port_management_vlan"]


@pytest.mark.parametrize("what, code", [("lldp", "port_lldp_neighbor"), ("cdp", "port_lldp_neighbor"),
                                        ("mac", "port_learned_mac")])
def test_an_occupied_port_needs_the_explicit_impact(tmp_path, what, code):
    device = device_with("switchport mode access")
    if what == "lldp":
        device.lldp_extra.append(PORT)
    elif what == "cdp":
        device.cdp_extra.append(PORT)
    else:
        device.learned_macs[PORT] = 2
    runtime = runtime_for(tmp_path, device)
    refusal = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-occ-0001"))
    assert refusal["result"] == "rejected" and refusal["reason_codes"] == [code]
    accepted = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-occ-0002", impact=PORT))
    assert accepted["result"] == "ready" and accepted["plan_sha256"] != ""
    record = ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-occ-0002", impact=PORT),
                             expected_plan_sha256=accepted["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert record["plan"]["endpoint_impact"] == PORT


def test_the_impact_acknowledgement_is_bound_to_the_plan(tmp_path):
    device = device_with("switchport mode access")
    device.learned_macs[PORT] = 1
    runtime = runtime_for(tmp_path, device)
    accepted = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bind-0001", impact=PORT))
    other = device_with("switchport mode access")
    other.learned_macs[PORT] = 1
    other_runtime = runtime_for(tmp_path / "other", other)
    plain = ios_cycle.preview(other_runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bind-0002", impact=PORT))
    assert plain["plan_sha256"] == accepted["plan_sha256"]
    with pytest.raises(Rejected) as caught:
        ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-bind-0003", impact=PORT),
                        expected_plan_sha256=accepted["plan_sha256"][:-1] + ("0" if accepted["plan_sha256"][-1] != "0" else "1"))
    assert caught.value.reason_codes == ["plan_changed"] and device.sent_lines == []


def test_a_protected_interface_is_protected_for_the_bounce_and_the_poe_changes(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device, protected={"interface": [PORT]})
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["port_protected"]
    assert codes(ios_cycle.preview, runtime, "lab-ios", POE, cycle(POE)) == ["port_protected"]
    assert codes(execute.preview, runtime, "lab-ios", setting({"mode": "never"})) == ["port_protected"]
    assert device.applied_blocks == []


def test_the_cycle_is_refused_when_the_timer_cannot_cover_it(tmp_path):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device, seconds=120)
    result = codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE))
    assert result == ["safeguard_margin_insufficient"]
    try:
        ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-margin-0002"))
    except Rejected as exc:
        detail = exc.reason_details[0]
        assert detail["required_safeguard_seconds"] == ios_cycle.required_safeguard_seconds(
            runtime.config.devices["lab-ios"], BOUNCE) == 240
    assert device.applied_blocks == [] and device.timer is None


def test_a_platform_without_these_operations_is_refused_with_its_code(tmp_path):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)
    runtime.config.devices["lab-ios"] = dataclasses.replace(runtime.config.devices["lab-ios"], platform="eos")
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["action_unsupported"]


def test_unreadable_link_state_refuses_before_any_write(tmp_path):
    device = device_with("switchport mode access")
    device.check_override = {"show interfaces %s status" % PORT: "\n% Invalid input detected at '^' marker.\n"}
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["port_usage_unreadable"]
    assert device.applied_blocks == []


def test_a_failed_second_line_returns_the_port_by_the_timer_command(tmp_path):
    device = device_with("switchport mode access")
    before = interface_lines(device)
    runtime = runtime_for(tmp_path, device)
    calls = []

    def break_enable(target, step_lines):
        if "no shutdown" in step_lines:
            calls.append(step_lines)
            raise ios_cycle.Rejected(["the device went away"])

    device.on_apply = break_enable
    preview = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-fail-0001", impact=PORT))
    record = ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-fail-0001", impact=PORT),
                             expected_plan_sha256=preview["plan_sha256"])
    assert calls and record["result"] == "reverted", (record["result"], record.get("reason"), steps(record))
    assert interface_lines(device) == before and device.timer is None


def test_a_port_that_does_not_go_down_is_returned(tmp_path):
    device = device_with("switchport mode access")
    before = interface_lines(device)
    runtime = runtime_for(tmp_path, device)
    device.check_override = {"show interfaces %s status" % PORT: ios_port_maintenance("show-interfaces-status-Gi1-2__notconnect.txt")
                             .replace("Gi1/2", "Gi1/3")}
    preview = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-stuck-0001", impact=PORT))
    assert preview["result"] == "ready"
    record = ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-stuck-0001", impact=PORT),
                             expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert interface_lines(device) == before and device.timer is None


# ---- the lab switch has no PoE: measured refusal ----

@pytest.mark.parametrize("operation", ["setting", POE])
def test_a_port_without_poe_is_refused_with_poe_not_capable(tmp_path, operation):
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)
    if operation == "setting":
        found = codes(execute.preview, runtime, "lab-ios", setting({"mode": "never"}))
    else:
        found = codes(ios_cycle.preview, runtime, "lab-ios", POE, cycle(POE))
    assert found == ["poe_not_capable"]
    assert device.applied_blocks == [] and device.timer is None
    assert "show power inline %s" % PORT in device.queries


@pytest.mark.parametrize("command", ["show interfaces %s switchport", "show interfaces %s status",
                                     "show mac address-table interface %s"])
def test_a_failed_read_of_the_port_state_has_its_own_code_not_an_unspecified_refusal(tmp_path, command):
    from netops_admin.access import AccessError
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path, device)

    def broken(target, asked):
        if asked == command % PORT:
            raise AccessError("timed out")

    device.on_query = broken
    device.on_check_query = broken
    assert codes(ios_cycle.preview, runtime, "lab-ios", BOUNCE, cycle(BOUNCE)) == ["port_usage_unreadable"]
    assert device.applied_blocks == []


def test_a_timeout_reading_the_poe_state_is_not_a_refusal(tmp_path):
    from netops_admin.access import AccessError
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)

    def slow(target, command):
        if command.startswith("show power inline"):
            raise AccessError("timed out")

    device.on_query = slow
    assert codes(execute.preview, runtime, "lab-ios", setting({"mode": "never"})) == ["poe_state_unreadable"]


# ---- IOS-M023: the PoE mode and the maximum of a port, with undo ----

def poe_round_trip(tmp_path, before_lines, changes, command, inverse, request_id, *, impact=False, device=None):
    device = device or device_with("switchport mode access", *before_lines, poe={"device": True})
    before, saved = interface_lines(device), list(device.saved)
    runtime = runtime_for(tmp_path, device)
    change = setting(changes, request_id=request_id, impact=impact)
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + PORT, command, "end"]
    assert device.applied_blocks == [] and device.saved == saved
    record = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert device.lines == device.saved and device.timer is None
    assert record["plan"]["inverse"] == ["configure terminal", "interface " + PORT, inverse, "end"]
    undone = execute.undo(runtime, record["change_id"], "return the port")
    assert undone["result"] == "confirmed", (undone.get("reason"), steps(undone))
    assert interface_lines(device) == before and device.lines == device.saved
    return preview, record, device


def test_poe_never_is_applied_read_back_by_the_check_account_and_undone(tmp_path):
    preview, record, device = poe_round_trip(tmp_path, [], {"mode": "never"}, "power inline never",
                                            "power inline auto", "ios-port-maintenance-poe-0001")
    assert any("PoE" in line and "Admin auto" in line for line in preview["prechecks"])
    assert "show power inline %s" % PORT in device.check_queries
    assert "check_identity_passed" in steps(record)


def test_poe_static_with_a_maximum_replaces_the_earlier_line_and_undo_writes_it_back(tmp_path):
    poe_round_trip(tmp_path, ["power inline auto max 7000"], {"mode": "static", "max-milliwatts": "15400"},
                   "power inline static max 15400", "power inline auto max 7000", "ios-port-maintenance-poe-0002")


def test_poe_never_drops_the_maximum_and_undo_restores_the_whole_line(tmp_path):
    preview, _record, _device = poe_round_trip(tmp_path, ["power inline static max 15400"], {"mode": "never"},
                                               "power inline never", "power inline static max 15400", "ios-port-maintenance-poe-0003")
    assert preview["predicted"]["after"] == {"mode": "never"}


def test_poe_maximum_alone_keeps_the_mode(tmp_path):
    poe_round_trip(tmp_path, ["power inline static"], {"max-milliwatts": "12000"}, "power inline static max 12000",
                   "power inline static", "ios-port-maintenance-poe-0004")


def test_poe_back_to_the_default_is_written_as_the_explicit_auto(tmp_path):
    poe_round_trip(tmp_path, ["power inline never"], {"mode": "auto"}, "power inline auto", "power inline never",
                   "ios-port-maintenance-poe-0005")


@pytest.mark.parametrize("changes", [{"mode": "never", "max-milliwatts": "7000"}, {"max-milliwatts": "3000"},
                                     {"max-milliwatts": "100000"}, {"mode": "sideways"}, {"max-milliwatts": "7k"}])
def test_poe_values_outside_the_documented_ones_are_refused(tmp_path, changes):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    result = execute.preview(runtime, "lab-ios", setting(changes, request_id="ios-port-maintenance-bad-0001"))
    assert result["result"] == "rejected" and device.applied_blocks == []


def test_poe_setting_that_changes_nothing_is_refused(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    result = execute.preview(runtime, "lab-ios", setting({"mode": "auto"}, request_id="ios-port-maintenance-same-0001"))
    assert result["result"] == "rejected" and result["reasons"] == ["update changes nothing"]


def test_poe_setting_on_an_occupied_port_needs_the_explicit_impact_also_for_its_undo(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    device.learned_macs[PORT] = 1
    runtime = runtime_for(tmp_path, device)
    assert codes(execute.preview, runtime, "lab-ios", setting({"mode": "never"}, request_id="ios-port-maintenance-occ-0003")) == [
        "port_learned_mac"]
    poe_round_trip(tmp_path / "ok", [], {"mode": "never"}, "power inline never", "power inline auto", "ios-port-maintenance-occ-0004",
                   impact=True, device=device)


def test_the_check_account_must_see_the_mode_of_the_configuration(tmp_path):
    device = device_with("switchport mode access", "power inline static max 15400", poe={"device": True})
    device.check_override = {"show power inline %s" % PORT: ios_port_maintenance("show-power-inline-Gi1-0-4__doc-auto-on.txt")
                             .replace("Gi1/0/4", "Gi1/3")}
    runtime = runtime_for(tmp_path, device)
    result = execute.preview(runtime, "lab-ios", setting({"mode": "never"}, request_id="ios-port-maintenance-view-0001"))
    assert result["result"] == "rejected" and "another state than the snapshot" in result["reasons"][0]


# ---- IOS-M024: the PoE cycle ----

def test_poe_cycle_restores_the_earlier_line_and_reports_the_power_before_and_after(tmp_path):
    device = device_with("switchport mode access", "power inline static max 15400", poe={"device": True, "boot_delay": 8})
    before, saved = interface_lines(device), list(device.saved)
    runtime = runtime_for(tmp_path, device)
    preview, record = run_cycle(runtime, POE, "ios-port-maintenance-cycle-0001")
    assert preview["commands"] == ["configure terminal", "interface " + PORT, "power inline never", "end"]
    assert preview["cycle_commands"][-2] == "power inline static max 15400"
    assert preview["cycle_state"]["poe"] == "on"
    assert record["result"] == "confirmed" and record["reason"] is None, (record.get("reason"), steps(record))
    assert interface_lines(device) == before and device.lines == saved and device.timer is None
    cycle_record = record["cycle"]
    assert (cycle_record["before"]["admin"], cycle_record["before"]["oper"]) == ("static", "on")
    assert (cycle_record["off"]["admin"], cycle_record["off"]["oper"]) == ("off", "off")
    assert (cycle_record["after"]["admin"], cycle_record["after"]["oper"]) == ("static", "on")
    sent = [line for line in device.sent_lines if line.startswith("power inline")]
    assert sent == ["power inline never", "power inline static max 15400"]


def test_poe_cycle_of_a_default_port_writes_the_explicit_auto(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    _preview, record = run_cycle(runtime, POE, "ios-port-maintenance-cycle-0002")
    assert record["result"] == "confirmed"
    assert [line for line in device.sent_lines if line.startswith("power inline")] == [
        "power inline never", "power inline auto"]
    assert device.lines == device.saved and "power inline auto" not in " ".join(interface_lines(device))


def test_poe_cycle_whose_device_does_not_return_is_reverted_with_the_reason(tmp_path):
    device = device_with("switchport mode access", poe={"device": True, "boot_delay": 600})
    runtime = runtime_for(tmp_path, device)
    # the device draws power at the start: before the cycle it is on
    device.enabled_at.clear()
    _preview, record = run_cycle(runtime, POE, "ios-port-maintenance-cycle-0003")
    assert record["result"] == "reverted" and record["reason"] == ios_cycle.PD_NOT_BACK
    assert device.lines == device.saved and device.timer is None


@pytest.mark.parametrize("poe, code", [({"device": False}, "poe_device_not_powered")])
def test_poe_cycle_needs_a_powered_device(tmp_path, poe, code):
    device = device_with("switchport mode access", poe=poe)
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", POE, cycle(POE)) == [code]
    assert device.applied_blocks == []


def test_poe_cycle_of_a_port_configured_never_is_refused(tmp_path):
    device = device_with("switchport mode access", "power inline never", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", POE, cycle(POE)) == ["poe_disabled"]


def test_poe_cycle_of_an_occupied_ap_trunk_needs_the_impact_and_keeps_the_management_vlan_rule(tmp_path):
    lines = ("switchport trunk encapsulation dot1q", "switchport mode trunk", "switchport trunk allowed vlan 10,20")
    device = device_with(*lines, poe={"device": True})
    device.cdp_extra.append(PORT)
    runtime = runtime_for(tmp_path, device)
    assert codes(ios_cycle.preview, runtime, "lab-ios", POE, cycle(POE)) == ["port_uplink"]
    _preview, record = run_cycle(runtime, POE, "ios-port-maintenance-cycle-0004", impact=PORT)
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    management = device_with(*lines[:2], "switchport trunk allowed vlan 10,99", poe={"device": True})
    assert codes(ios_cycle.preview, runtime_for(tmp_path / "m", management), "lab-ios", POE,
                 cycle(POE, impact=PORT)) == ["port_management_vlan"]


def test_a_cycle_that_fails_before_the_enable_leaves_the_configuration_as_before(tmp_path):
    device = device_with("switchport mode access", "power inline auto max 7000", poe={"device": True})
    before = interface_lines(device)
    runtime = runtime_for(tmp_path, device)

    def break_enable(target, step_lines):
        if any(line.startswith("power inline auto") for line in step_lines):
            raise ios_cycle.Rejected(["the device went away"])

    device.on_apply = break_enable
    preview = ios_cycle.preview(runtime, "lab-ios", POE, cycle(POE, request_id="ios-port-maintenance-fail-0002"))
    record = ios_cycle.apply(runtime, "lab-ios", POE, cycle(POE, request_id="ios-port-maintenance-fail-0002"),
                             expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted" and interface_lines(device) == before and device.timer is None


# ---- plans and the stored state ----

def test_forged_cycle_state_is_refused_by_the_plan_reader(tmp_path):
    device = device_with("switchport mode access", poe={"device": True})
    runtime = runtime_for(tmp_path, device)
    plan = engine.build_plan("ios", device.snapshot().encode(), cycle(POE), firmware=FW)
    plan["cycle_state"] = {"link": "connected", "lldp": "False", "learned_macs": "0", "poe": "on"}
    plan["plan_sha256"] = engine.plan_digest(plan)
    assert engine._read_plan(plan)["cycle_state"]["poe"] == "on"
    for broken in ({"link": "connected"}, {"link": 1, "lldp": "x", "learned_macs": "0", "poe": "on"}):
        forged = copy.deepcopy(plan)
        forged["cycle_state"] = broken
        forged["plan_sha256"] = engine.plan_digest(forged)
        with pytest.raises(Rejected):
            engine._read_plan(forged)
    inline = copy.deepcopy(plan)
    inline["table"] = "inline-power"
    with pytest.raises(Rejected):
        engine._read_plan(inline)


def test_the_cycle_state_is_bound_into_the_plan_hash(tmp_path):
    quiet = device_with("switchport mode access")
    busy = device_with("switchport mode access")
    busy.learned_macs[PORT] = 1
    first = ios_cycle.preview(runtime_for(tmp_path / "a", quiet), "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-h-0001", impact=PORT))
    second = ios_cycle.preview(runtime_for(tmp_path / "b", busy), "lab-ios", BOUNCE,
                               cycle(BOUNCE, request_id="ios-port-maintenance-h-0002", impact=PORT))
    assert first["plan_sha256"] != second["plan_sha256"]
    assert first["cycle_state"]["learned_macs"] == "0" and second["cycle_state"]["learned_macs"] == "1"


def test_the_iosxe_switch_plans_the_same_bounce():
    device = FakeIos("iolxe-l2")
    start, end = device._block("interface %s" % device.port)
    device.lines[start + 1:end] = [" switchport mode access", " negotiation auto"]
    plan = engine.build_plan("iosxe", device.snapshot().encode(), cycle(BOUNCE, port=device.port), firmware="17.18.2")
    assert plan["commands"][-2:] == ["shutdown", "end"] and plan["inverse"][-2:] == ["no shutdown", "end"]
    assert plan["predicted"] == {"before": {}, "after": {"admin-state": "disabled"}}


# ---- interruption of the process: recover returns the port ----

class Killed(BaseException):
    """The process of Admin is gone: not an Exception, so no handler of the operation runs."""


def interrupted(tmp_path, action, when, **device_fields):
    lines = ["switchport mode access"] + device_fields.pop("lines", [])
    device = device_with(*lines, **device_fields)
    before = interface_lines(device)
    runtime = runtime_for(tmp_path, device)
    change = cycle(action, request_id="ios-port-maintenance-kill-0001", impact=PORT if action == BOUNCE else None)
    preview = ios_cycle.preview(runtime, "lab-ios", action, change)
    assert preview["result"] == "ready", preview

    def die(target, step_lines):
        if when(step_lines):
            raise Killed()

    device.on_apply = die
    with pytest.raises(Killed):
        ios_cycle.apply(runtime, "lab-ios", action, change,
                        expected_plan_sha256=preview["plan_sha256"])
    device.on_apply = None
    return device, runtime, before


def test_recover_returns_a_bounce_that_died_with_the_port_shut_down(tmp_path):
    device, runtime, before = interrupted(tmp_path, BOUNCE, lambda lines: "no shutdown" in lines)
    assert "shutdown" in interface_lines(device) and device.timer is not None
    settled = execute.recover(runtime, "lab-ios")
    assert [record["result"] for record in settled] == ["reverted"] and settled[0]["reason"] == "interrupted"
    assert interface_lines(device) == before and device.timer is None and device.lines == device.saved


def test_recover_returns_a_poe_cycle_that_died_with_the_power_off(tmp_path):
    device, runtime, before = interrupted(tmp_path, POE, lambda lines: any(
        line.startswith("power inline auto") for line in lines), poe={"device": True}, lines=["power inline auto max 7000"])
    assert "power inline never" in interface_lines(device)
    settled = execute.recover(runtime, "lab-ios")
    assert [record["result"] for record in settled] == ["reverted"]
    assert interface_lines(device) == before and device.timer is None


def test_recover_settles_a_bounce_that_died_while_confirming_and_one_that_died_after_the_confirmation(tmp_path):
    # died in the session of configure confirm: the timer is still pending and returns the (equal) configuration
    device, runtime, before = interrupted(tmp_path / "a", BOUNCE, lambda lines: lines == [exec_ios.QUERY_TIMER,
                                                                                          "configure confirm"])
    settled = execute.recover(runtime, "lab-ios")
    assert [record["result"] for record in settled] == ["reverted"] and interface_lines(device) == before
    assert device.timer is None
    # died after the confirmation: the port is back, the timer is gone, the record is confirmed by recover
    device = device_with("switchport mode access")
    runtime = runtime_for(tmp_path / "b", device)
    preview = ios_cycle.preview(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-kill-0002", impact=PORT))

    original = device.snapshot

    def snapshot():
        if "configure confirm" in device.sent_lines and device.timer is None:
            raise Killed()
        return original()

    device.snapshot = snapshot
    with pytest.raises(Killed):
        ios_cycle.apply(runtime, "lab-ios", BOUNCE, cycle(BOUNCE, request_id="ios-port-maintenance-kill-0002", impact=PORT),
                        expected_plan_sha256=preview["plan_sha256"])
    device.snapshot = original
    settled = execute.recover(runtime, "lab-ios")
    assert [record["result"] for record in settled] == ["confirmed"], [(r["result"], r["reason"]) for r in settled]
    assert device.timer is None and device.lines == device.saved
