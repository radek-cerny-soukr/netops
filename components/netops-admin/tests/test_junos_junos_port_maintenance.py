"""1.0.12 JUNOS-PORT-MAINTENANCE (Junos ELS, vJunos-switch 26.2R1.7): port bounce (J11), PoE cycle (J10), persistent PoE disable (J09),
speed, auto-negotiation and MTU (J23).

Answers of the switch come from outputs measured on the lab switch (fixtures/junos_junos_port_maintenance, PROVENANCE.md); the PoE
answers of an EX switch come from the Juniper documentation (vJunos has no PoE). Preview, apply, readback and the
return run against FakeJunos."""
from __future__ import annotations

from functools import partial
import pytest
from fake_junos import BASELINE, FIRMWARE, FakeJunos, fixture_junos_port_maintenance
from test_junos import CHANGE, NAME, make_runtime as _make_runtime, request, steps

from netops_admin import execute, junos, junos_cycle
from netops_admin.engine import build_plan
from netops_admin.errors import Rejected
from approved_apply import approved_apply

make_runtime = partial(_make_runtime, simulate_unmeasured_profiles=True)


PORT = "ge-0/0/9"
BASE = BASELINE.rstrip("\n").split("\n")


def cycle_request(action, port=PORT, **fields):
    return junos_cycle.request(action, NAME, port, "test cycle", "cycle %s" % port,
                               fields.pop("request_id", "junos-port-maintenance-%s-1" % action), **fields)


def run_cycle(runtime, action, change=None, **fields):
    change = change or cycle_request(action, **fields)
    preview = junos_cycle.preview(runtime, NAME, action, change)
    assert preview["result"] == "ready", preview
    return preview, junos_cycle.apply(runtime, NAME, action, change, expected_plan_sha256=preview["plan_sha256"])


def codes(function, *arguments):
    """Reason codes of a refusal, whether the preview raises it or returns it."""
    try:
        result = function(*arguments)
    except Rejected as exc:
        return exc.reason_codes
    assert result["result"] == "rejected", result
    return result["reason_codes"]


# ---- parsers on measured and documented answers ----

def test_poe_answers_of_vjunos_and_of_an_ex_switch():
    assert junos.poe_state(fixture_junos_port_maintenance("show-poe-interface-ge-0-0-9__vjunos-no-controller.txt"), PORT) is None
    on = junos.poe_state(fixture_junos_port_maintenance("show-poe-interface-ge-0-0-3__ex-doc-on.txt"), "ge-0/0/3")
    assert on == {"configured": "enabled", "state": "powered"}
    assert junos.poe_state(fixture_junos_port_maintenance("show-poe-interface-ge-0-0-3__derived-off.txt"), "ge-0/0/3") == {
        "configured": "enabled", "state": "off"}
    assert junos.poe_state(fixture_junos_port_maintenance("show-poe-interface-ge-0-0-3__derived-disabled.txt"), "ge-0/0/3")[
        "configured"] == "disabled"
    # another port or an incomplete block is unreadable, never "off"
    for text in (fixture_junos_port_maintenance("show-poe-interface-ge-0-0-3__ex-doc-on.txt"), "PoE interface status:\n"):
        with pytest.raises(Rejected) as caught:
            junos.poe_state(text, "ge-0/0/4" if "ge-0/0/3" in text else "ge-0/0/3")
        assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_links_up_of_the_lab_switch():
    assert junos.physical_up(fixture_junos_port_maintenance("show-interfaces-terse__lab.txt")) == ["ge-0/0/0", "ge-0/0/1"]
    row = junos.interface_row(fixture_junos_port_maintenance("show-interfaces-ge-0-0-9-terse__admin-down.txt"), PORT)
    assert (row["admin"], row["link"]) == ("down", "down")


# ---- J23: speed, auto-negotiation, MTU ----

def test_link_parameters_are_rendered_and_predicted():
    plan = build_plan("junos", BASELINE.encode(), request(key=PORT, changes={"mtu": 9000, "speed": "1g",
                                                                              "auto-negotiation": "disabled"}),
                      firmware=FIRMWARE)
    assert plan["commands"][3:6] == ["set interfaces ge-0/0/9 ether-options no-auto-negotiation",
                                    "set interfaces ge-0/0/9 mtu 9000", "set interfaces ge-0/0/9 speed 1g"]
    assert plan["predicted"]["after"] == {"auto-negotiation": "disabled", "mtu": "9000", "speed": "1g"}
    assert plan["predicted"]["before"] == {} and "delete interfaces ge-0/0/9 mtu" in plan["inverse"]
    assert "delete interfaces ge-0/0/9 ether-options no-auto-negotiation" in plan["inverse"] or \
        "delete interfaces ge-0/0/9 ether-options auto-negotiation" in plan["inverse"]


@pytest.mark.parametrize("changes", [{"mtu": 255}, {"mtu": 9193}, {"speed": "100g"}, {"auto-negotiation": "maybe"}])
def test_values_outside_the_measured_range_are_refused(changes):
    with pytest.raises(Rejected):
        build_plan("junos", BASELINE.encode(), request(key=PORT, changes=changes), firmware=FIRMWARE)


def test_mtu_is_confirmed_read_back_and_undone(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, NAME, request(key=PORT, changes={"mtu": 9000}, request_id="junos-port-maintenance-mtu-1"))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.interface(PORT) == ["mtu 9000"] and not device.pending()
    undone = execute.undo(runtime, record["change_id"], "return the MTU")
    assert undone["result"] == "confirmed" and device.lines == BASE


def test_auto_negotiation_replaces_the_other_statement_and_is_returned(tmp_path):
    device = FakeJunos()
    device.lines.append("set interfaces ge-0/0/9 ether-options no-auto-negotiation")
    before = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, NAME, request(key=PORT, changes={"auto-negotiation": "enabled", "speed": "100m"},
                                                  request_id="junos-port-maintenance-an-1"))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert sorted(device.interface(PORT)) == ["ether-options auto-negotiation", "speed 100m"]
    undone = execute.undo(runtime, record["change_id"], "return")
    assert undone["result"] == "confirmed" and sorted(device.lines) == sorted(before)


def test_a_link_parameter_of_a_port_in_use_needs_the_impact(tmp_path):
    device = FakeJunos()
    device.learned_macs[PORT] = 1
    assert codes(execute.preview, make_runtime(tmp_path, device), NAME,
                 request(key=PORT, changes={"mtu": 9000})) == ["port_learned_mac"]
    result = execute.preview(make_runtime(tmp_path, device), NAME,
                             request(key=PORT, changes={"mtu": 9000}, endpoint_impact=PORT))
    assert result["result"] == "ready", result


# ---- J09: persistent PoE disable ----

def test_poe_disable_and_enable_by_apply(tmp_path):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, NAME, request(table="poe", key=PORT, changes={"admin-state": "disabled"},
                                                  request_id="junos-port-maintenance-poe-1", endpoint_impact=PORT))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert "set poe interface ge-0/0/9 disable" in device.lines
    undone = execute.undo(runtime, record["change_id"], "enable PoE")
    assert undone["result"] == "confirmed" and device.lines == BASE


def test_poe_on_a_switch_without_controller_is_refused_before_any_write(tmp_path):
    device = FakeJunos()
    assert codes(execute.preview, make_runtime(tmp_path, device), NAME,
                 request(table="poe", key=PORT, changes={"admin-state": "disabled"})) == ["poe_not_capable"]
    assert device.lines == BASE and not device.pending()


def test_poe_disabled_by_all_is_not_evaluated():
    text = BASELINE + "set poe interface all disable\n"
    snapshot = junos.load(text, FIRMWARE)
    assert snapshot._entry("poe", PORT).unsupported == ["poe interface all disabled"]


def test_the_poe_table_is_changed_only_by_its_operation(tmp_path):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    assert codes(execute.preview, make_runtime(tmp_path, device), NAME,
                 request(table="inline-power", key=PORT, changes={"admin-state": "disabled"})) == ["action_only_table"]


# ---- J11: port bounce ----

def test_bounce_previews_without_a_write_and_returns_the_port(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    preview = junos_cycle.preview(runtime, NAME, junos_cycle.BOUNCE, cycle_request(junos_cycle.BOUNCE))
    assert preview["result"] == "ready" and preview["operation"] == "port-bounce", preview
    assert preview["commands"][3] == "set interfaces ge-0/0/9 disable" and device.lines == BASE
    assert device.applied_blocks == [[junos.SCREEN, "configure", junos.LEAVE]]
    _, record = run_cycle(runtime, junos_cycle.BOUNCE)
    assert record["result"] == "confirmed" and record.get("reason") is None, (record.get("reason"), steps(record))
    order = ["port_before", "change_applied", "postcheck_passed", "port_off_observed", "off_held",
             "port_enable_applied", "port_enable_verified", "confirm_start", "port_on_observed"]
    assert [name for name in steps(record) if name in order] == order
    assert record["cycle"]["off"]["admin"] == "down" and record["cycle"]["after"]["admin"] == "up"
    label = record["safeguard"]["name"]
    assert device.lines == BASE and not device.pending()
    assert [item["comment"] for item in device.history[:3]] == [label + "-revert", "netops-change", label]
    assert not device.history[0]["minutes"]
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(runtime, record["change_id"], "undo a bounce")
    assert caught.value.reason_codes == ["undo_not_applicable"]


def test_bounce_of_a_disabled_port_and_of_a_port_in_use(tmp_path):
    device = FakeJunos()
    device.lines.append("set interfaces ge-0/0/9 disable")
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE)) == ["port_disabled"]
    device = FakeJunos()
    device.learned_macs[PORT] = 2
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE)) == ["port_learned_mac"]
    device.lldp_extra = [PORT]
    device.learned_macs = {}
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE)) == ["port_lldp_neighbor"]


def test_bounce_refuses_a_trunk_and_the_only_link(tmp_path):
    device = FakeJunos()
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE, "ge-0/0/0")) == ["port_uplink"]
    device.up_ports = {"ge-0/0/1"}
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE, "ge-0/0/1", endpoint_impact="ge-0/0/1")) == [
        "port_management_interface"]


def test_a_protected_port_is_not_bounced(tmp_path):
    device = FakeJunos()
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device, protected={"interface": [PORT]}), NAME,
                 junos_cycle.BOUNCE, cycle_request(junos_cycle.BOUNCE)) == ["port_protected"]


def test_a_bounce_whose_link_does_not_return_is_reported(tmp_path):
    device = FakeJunos()
    device.up_ports = {"ge-0/0/0", "ge-0/0/1", PORT}
    runtime = make_runtime(tmp_path, device)
    preview = junos_cycle.preview(runtime, NAME, junos_cycle.BOUNCE, cycle_request(junos_cycle.BOUNCE))
    assert preview["cycle_state"]["link"] == "up" if "cycle_state" in preview else True
    original = device._interface_query

    def link_stays_down(command):
        answer = original(command)
        if command == "show interfaces %s terse" % PORT and device.history[0]["comment"] and \
                device.history[0]["comment"].endswith("-revert"):
            return answer.replace("up    up", "up    down", 1)
        return answer
    device._interface_query = link_stays_down
    record = junos_cycle.apply(runtime, NAME, junos_cycle.BOUNCE, cycle_request(junos_cycle.BOUNCE),
                               expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and record["reason"] == junos_cycle.LINK_NOT_BACK, steps(record)
    assert device.lines == BASE


def test_a_bounce_needs_the_approved_preview(tmp_path):
    device = FakeJunos()
    assert codes(junos_cycle.apply, make_runtime(tmp_path, device), NAME, junos_cycle.BOUNCE,
                 cycle_request(junos_cycle.BOUNCE)) == ["plan_changed"]
    assert device.applied_blocks == []


def test_a_failed_return_leaves_the_timer_to_bring_the_port_back(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    change = cycle_request(junos_cycle.BOUNCE)
    preview = junos_cycle.preview(runtime, NAME, junos_cycle.BOUNCE, change)

    def refuse_the_return(fake, step):
        if step.startswith('commit comment "') and step.endswith('-revert"'):
            raise AssertionError("must not run")
    # the return is the 4th session of the operation: break it by making the commit history unreadable
    device.on_apply = lambda fake, steps_: (_ for _ in ()).throw(Exception("lost")) if any(
        "-revert" in item for item in steps_) else None
    record = junos_cycle.apply(runtime, NAME, junos_cycle.BOUNCE, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] in ("reverted", "unknown", "revert-failed") and "port_enable_applied" not in steps(record)
    assert device.lines == BASE and not device.pending()


# ---- J10: PoE cycle ----

def test_poe_cycle_returns_the_power(tmp_path):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    runtime = make_runtime(tmp_path, device)
    preview, record = run_cycle(runtime, junos_cycle.POE)
    assert preview["commands"][3] == "set poe interface ge-0/0/9 disable"
    assert record["result"] == "confirmed" and record.get("reason") is None, (record.get("reason"), steps(record))
    assert record["cycle"]["before"] == {"configured": "enabled", "state": "powered"}
    assert record["cycle"]["off"]["configured"] == "disabled" and record["cycle"]["after"]["state"] == "powered"
    assert device.lines == BASE and not device.pending()


def test_poe_cycle_of_a_port_without_power_or_controller(tmp_path):
    device = FakeJunos()
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.POE,
                 cycle_request(junos_cycle.POE)) == ["poe_not_capable"]
    device.poe_capable = True
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.POE,
                 cycle_request(junos_cycle.POE)) == ["poe_device_not_powered"]
    device.powered = {PORT}
    device.lines.append("set poe interface ge-0/0/9 disable")
    assert codes(junos_cycle.preview, make_runtime(tmp_path, device), NAME, junos_cycle.POE,
                 cycle_request(junos_cycle.POE)) == ["poe_disabled"]


def test_poe_cycle_without_restored_power_finishes_as_reverted(tmp_path):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    runtime = make_runtime(tmp_path, device)
    change = cycle_request(junos_cycle.POE)
    preview = junos_cycle.preview(runtime, NAME, junos_cycle.POE, change)
    original = device._interface_query

    def power_lost(command):
        if command == "show poe interface %s" % PORT and device.history[0]["comment"] and \
                device.history[0]["comment"].endswith("-revert"):
            device.powered = set()
        return original(command)
    device._interface_query = power_lost
    record = junos_cycle.apply(runtime, NAME, junos_cycle.POE, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted" and record["reason"] == junos_cycle.PD_NOT_BACK, steps(record)
    assert device.lines == BASE


@pytest.mark.parametrize("hashed", [False, True])
def test_shipped_poe_cycle_is_refused_as_unmeasured_before_the_plan_hash(tmp_path, hashed):
    # The disabled PoE cycle profile is refused by the measured gate first, like the EOS and IOS cycles: apply
    # without the plan hash does not report plan_changed, and nothing reaches the device or the journal.
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    runtime = _make_runtime(tmp_path, device)

    def unexpected_access(_device):
        pytest.fail("the disabled profile must be refused before opening the transport")

    runtime.access_factory = unexpected_access
    change = cycle_request(junos_cycle.POE)
    assert codes(junos_cycle.preview, runtime, NAME, junos_cycle.POE, change) == ["profile_not_measured"]
    apply = partial(junos_cycle.apply, expected_plan_sha256="0" * 64) if hashed else junos_cycle.apply
    assert codes(apply, runtime, NAME, junos_cycle.POE, change) == ["profile_not_measured"]
    assert device.applied_blocks == [] and device.lines == BASE and runtime.store.records() == []
