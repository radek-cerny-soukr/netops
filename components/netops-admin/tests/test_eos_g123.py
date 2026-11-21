"""1.0.12 G123: bounce, PoE and link parameters of an Arista EOS port (E06, E07, E08, E23).

Every case runs the real path (execute.preview/apply/undo or eos_cycle.preview/apply, engine plan, exec_eos prechecks,
postcheck and check-account readback) against FakeEos, whose answers come from outputs measured on cEOS 2253
(fixtures/eos_g123, task-evidence/g123/raw) or, for PoE, from the Arista EOS manual (fixtures/eos_g123/PROVENANCE.md).
"""
from __future__ import annotations

import dataclasses

import pytest

from fake_eos import FakeEos, g123
from test_eos import make_runtime, request, steps

from netops_admin import eos, eos_cycle, execute
from netops_admin.errors import Rejected

PORT = "Ethernet12"


def port(**fields):
    fields.setdefault("table", "interface")
    fields.setdefault("key", PORT)
    return request(**fields)


def runtime_for(tmp_path, device, safeguard_seconds=180, **kwargs):
    runtime = make_runtime(tmp_path, device, **kwargs)
    target = runtime.config.devices["lab-ceos"]
    runtime.config.devices["lab-ceos"] = dataclasses.replace(target, safeguard_seconds=safeguard_seconds)
    from enrollment_helpers import certify
    return certify(runtime, device, "lab-ceos")


def codes(call, *args):
    """Reason codes of a refusal, whether the preview raises it or returns it."""
    try:
        result = call(*args)
    except Rejected as exc:
        return exc.reason_codes
    assert result["result"] == "rejected", result
    return result["reason_codes"]


def refused(runtime, change):
    return codes(execute.preview, runtime, "lab-ceos", change)


def round_trip(tmp_path, device, changes, command, inverse, request_id):
    """Preview without a write, confirmed apply, readback of the write account, undo back to the lines before."""
    before, saved = device.interface(PORT), list(device.saved)
    runtime = make_runtime(tmp_path, device)
    change = port(changes=changes, request_id=request_id)
    preview = execute.preview(runtime, "lab-ceos", change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface %s" % PORT, command, "end"]
    assert device.applied_blocks == [] and device.saved == saved
    record = execute.apply(runtime, "lab-ceos", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert command in device.interface(PORT) and device.lines == device.saved
    plan = runtime.store.operation(record["change_id"])["plan"]
    assert plan["inverse"] == ["configure terminal", "interface %s" % PORT, inverse, "end"]
    undone = execute.undo(runtime, record["change_id"], "return the port")
    assert undone["result"] == "confirmed", (undone.get("reason"), steps(undone))
    assert device.interface(PORT) == before and device.lines == device.saved
    return preview


# ---- E23: MTU and speed (measured on cEOS 4.36.1F) ----

def test_snapshot_reads_the_measured_mtu_and_speed_lines():
    device = FakeEos()
    for name in ("mtu-9000", "speed-100mfull", "speed-auto", "shutdown"):
        lines = [line.strip() for line in g123("show-running-config-interfaces-Ethernet12__%s.txt" % name)
                 .splitlines()[1:]]
        start, end = device._block("interface %s" % PORT)
        device.lines[start + 1:end] = ["   " + line for line in lines]
        entry = eos.load(device.snapshot(), "4.36.1F").entries("interface")[PORT]
        assert entry.unsupported == []
        expected = {"mtu-9000": {"mtu": "9000"}, "speed-100mfull": {"speed": "100mfull"},
                    "speed-auto": {"speed": "auto"}, "shutdown": {"admin-state": "disabled"}}[name]
        assert entry.attributes == expected


def test_mtu_change_previews_applies_reads_back_and_undoes(tmp_path):
    preview = round_trip(tmp_path, FakeEos(), {"mtu": 9000}, "mtu 9000", "no mtu", "g123-mtu-1")
    assert "mtu 9000 is within the Ethernet MTU 9214 of port Ethernet12" in preview["prechecks"]


def test_mtu_above_the_ethernet_mtu_is_refused_before_any_write(tmp_path):
    device = FakeEos()
    assert refused(make_runtime(tmp_path, device), port(changes={"mtu": 9215}, request_id="g123-mtu-2")) == [
        "port_capability_unsupported"]
    assert device.applied_blocks == []


def test_speed_change_previews_applies_reads_back_and_undoes(tmp_path):
    preview = round_trip(tmp_path, FakeEos(), {"speed": "100mfull"}, "speed 100mfull", "no speed", "g123-speed-1")
    assert "port Ethernet12 lists speed 100mfull in its hardware capabilities" in preview["prechecks"]


def test_speed_auto_with_an_explicit_rate_requires_autonegotiation_support(tmp_path):
    # measured: the cEOS port lists no "auto" and EOS refuses "speed auto 1g" (% Cannot advertise ...)
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    assert refused(runtime, port(changes={"speed": "auto 1g"}, request_id="g123-speed-auto-1g")) == [
        "port_capability_unsupported"]
    assert device.applied_blocks == []


def test_speed_that_is_not_an_eos_value_is_refused_by_the_profile(tmp_path):
    device = FakeEos()
    assert refused(make_runtime(tmp_path, device), port(changes={"speed": "1000full"}, request_id="g123-speed-bad"))
    assert device.applied_blocks == []


def test_unreadable_hardware_answer_refuses_with_its_code(tmp_path):
    device = FakeEos()
    device.hardware = g123("show-interfaces-Ethernet2-18-hardware__arista-doc.txt")  # another port only
    assert refused(make_runtime(tmp_path, device), port(changes={"speed": "10g"}, request_id="g123-speed-3")) == [
        "port_usage_unreadable"]
    assert device.applied_blocks == []


def test_speed_capabilities_of_the_arista_manual():
    doc = g123("show-interfaces-Ethernet2-18-hardware__arista-doc.txt")
    assert eos.hardware_speeds(doc, "Ethernet2") == {"10G/full", "40G/full", "auto"}
    assert eos.hardware_speeds(doc, "Ethernet18") == {"10G/full"}
    assert eos.speed_supported("auto", eos.hardware_speeds(doc, "Ethernet2"))
    assert eos.speed_supported("auto 40g-4", eos.hardware_speeds(doc, "Ethernet2"))
    assert eos.speed_supported("auto", eos.hardware_speeds(doc, "Ethernet18"))
    assert not eos.speed_supported("1g", eos.hardware_speeds(doc, "Ethernet18"))
    lanes = eos.hardware_speeds(g123("show-interfaces-Ethernet4-1-hardware__arista-doc.txt"), "Ethernet4/1")
    assert lanes == {"100G-2/full", "400G-8/full"}
    assert eos.speed_supported("100g-2", lanes) and eos.speed_supported("400g-8", lanes)
    assert not eos.speed_supported("100g-4", lanes)
    measured = eos.hardware_speeds(g123("show-interfaces-Ethernet12-hardware.txt"), PORT)
    assert {"1G/full", "100M/full", "10G/full"} <= measured and "auto" not in measured
    assert eos.ethernet_mtu(g123("show-interfaces-Ethernet12__baseline.txt"), PORT) == 9214


def test_check_account_view_drops_speed_mtu_and_poe():
    assert eos.check_view("interface", {"description": "x", "speed": "1g", "mtu": "9000", "poe": "disabled"}) == {
        "description": "x"}


# ---- E06: PoE of a port ----

def test_poe_change_on_a_switch_without_poe_is_refused_before_any_write(tmp_path):
    # measured on cEOS: show poe interface N answers "% Unavailable command (not supported on this hardware platform)"
    device = FakeEos()
    assert refused(make_runtime(tmp_path, device), port(changes={"poe": "disabled"}, request_id="g123-poe-1")) == [
        "poe_not_capable"]
    assert device.applied_blocks == []


def test_poe_disable_on_a_poe_port_previews_applies_and_undoes(tmp_path):
    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    preview = round_trip(tmp_path, device, {"poe": "disabled"}, "poe disabled", "no poe disabled", "g123-poe-2")
    assert "port Ethernet12 has PoE: PSE enabled, powered" in preview["prechecks"]


def test_poe_answer_of_the_manual_and_unreadable_answers():
    assert eos.poe_state(g123("show-poe-interface-Ethernet46__arista-doc.txt"), "Ethernet46") == {
        "configured": "enabled", "state": "powered", "class": "class0", "power": "1.40W"}
    assert eos.poe_state(g123("show-poe-interface-Ethernet46__disabled-derived.txt"), "Ethernet46")["configured"] \
        == "disabled"
    for text, key in ((g123("show-poe-interface-Ethernet46__arista-doc.txt"), "Ethernet47"),
                      (g123("show-poe-interface-Ethernet12__ro-invalid-exec-rc1.txt"), PORT),
                      ("\n".join(g123("show-poe-interface-Ethernet46__arista-doc.txt").splitlines()[:3]), "Ethernet46")):
        with pytest.raises(Rejected) as caught:
            eos.poe_state(text, key)
        assert caught.value.reason_codes == ["poe_state_unreadable"]
    assert eos.poe_unavailable(1, g123("show-poe-interface-Ethernet12__unavailable-exec-rc1.txt"))
    assert not eos.poe_unavailable(1, g123("show-poe-interface-Ethernet12__ro-invalid-exec-rc1.txt"))


# ---- E08: port bounce ----

def bounce(device_name="lab-ceos", **fields):
    return eos_cycle.request(eos_cycle.BOUNCE, device_name, fields.pop("key", PORT), "test bounce",
                             "bounce port 12", fields.pop("request_id", "g123-bounce-1"), **fields)


def apply_cycle(runtime, action, change, preview=None):
    if preview is None:
        preview = eos_cycle.preview(runtime, "lab-ceos", action, change)
    return eos_cycle.apply(runtime, "lab-ceos", action, change, expected_plan_sha256=preview["plan_sha256"])


def test_bounce_previews_without_a_write_and_confirms_with_the_link_back(tmp_path):
    device = FakeEos()
    lines, saved = list(device.lines), list(device.saved)
    runtime = make_runtime(tmp_path, device)
    preview = eos_cycle.preview(runtime, "lab-ceos", eos_cycle.BOUNCE, bounce())
    assert preview["result"] == "ready", preview
    assert preview["cycle_commands"] == ["configure terminal", "interface %s" % PORT, "shutdown", "end",
                                         "configure terminal", "interface %s" % PORT, "no shutdown", "end"]
    assert device.applied_blocks == [] and device.saved == saved
    record = apply_cycle(runtime, eos_cycle.BOUNCE, bounce(), preview)
    assert record["result"] == "confirmed" and record.get("reason") is None, (record.get("reason"), steps(record))
    order = ["port_before", "change_applied", "postcheck_passed", "port_off_observed", "off_held",
             "port_enable_verified", "port_on_observed", "confirm_start"]
    assert [name for name in steps(record) if name in order] == order
    assert record["cycle"]["before"] == {"status": "connected"} and record["cycle"]["after"] == {"status": "connected"}
    assert "disabled" in device.status_reads and device.status_reads[-1] == "connected"
    assert device.lines == lines and device.saved == lines and device.timer is None
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(runtime, record["change_id"], "undo a bounce")
    assert caught.value.reason_codes == ["undo_not_applicable"]


def test_bounce_reports_a_link_that_does_not_come_back(tmp_path):
    device = FakeEos()
    device.link_after_bounce = "notconnect"
    record = apply_cycle(make_runtime(tmp_path, device), eos_cycle.BOUNCE, bounce())
    assert record["result"] == "confirmed" and record["reason"] == eos_cycle.LINK_NOT_BACK, steps(record)
    assert "shutdown" not in device.interface(PORT)


def test_bounce_lost_check_read_is_returned_by_the_safeguard(tmp_path):
    device = FakeEos()

    def lose_check_account(fake, lines):
        if "shutdown" in lines:
            fake.check_unreadable = True
    device.on_apply = lose_check_account
    record = apply_cycle(make_runtime(tmp_path, device), eos_cycle.BOUNCE, bounce())
    assert record["result"] != "confirmed", steps(record)
    assert "shutdown" not in device.interface(PORT) and device.timer is None


@pytest.mark.parametrize("setup,code", [
    (lambda device: device._set(PORT, __import__("re").compile("^shutdown$"), "shutdown"), "port_disabled"),
    (lambda device: device.lldp_extra.append("Et12"), "port_lldp_neighbor"),
    (lambda device: device.learned_macs.update({PORT: 2}), "port_learned_mac"),
    (lambda device: device._set(PORT, __import__("re").compile("^switchport mode "), "switchport mode trunk"),
     "port_uplink"),
])
def test_bounce_refusals_before_any_write(tmp_path, setup, code):
    device = FakeEos()
    setup(device)
    device.saved = list(device.lines)
    assert codes(eos_cycle.preview, make_runtime(tmp_path, device), "lab-ceos", eos_cycle.BOUNCE, bounce()) == [code]
    assert device.applied_blocks == []


def test_bounce_with_endpoint_impact_is_allowed_on_a_port_with_a_neighbor(tmp_path):
    device = FakeEos()
    device.lldp_extra.append("Et12")
    preview = eos_cycle.preview(make_runtime(tmp_path, device), "lab-ceos", eos_cycle.BOUNCE,
                                bounce(endpoint_impact=PORT))
    assert preview["result"] == "ready", preview


def test_bounce_of_a_protected_interface_and_with_a_short_safeguard_is_refused(tmp_path):
    device = FakeEos()
    assert codes(eos_cycle.preview, make_runtime(tmp_path / "p", device, protected={"interface": [PORT]}), "lab-ceos",
                 eos_cycle.BOUNCE, bounce()) == ["port_protected"]
    assert codes(eos_cycle.preview, runtime_for(tmp_path / "s", device, safeguard_seconds=120), "lab-ceos",
                 eos_cycle.BOUNCE, bounce()) == ["safeguard_margin_insufficient"]
    assert device.applied_blocks == []


def test_bounce_table_is_changed_only_by_its_operation(tmp_path):
    device = FakeEos()
    assert refused(make_runtime(tmp_path, device), port(table="port-bounce", changes={"admin-state": "disabled"},
                                                        request_id="g123-direct")) == ["action_only_table"]


# ---- E07: PoE cycle ----

def poe_cycle(**fields):
    return eos_cycle.request(eos_cycle.POE, "lab-ceos", PORT, "AP does not answer", "restart the AP on port 12",
                             fields.pop("request_id", "g123-poe-cycle-1"), **fields)


def test_poe_cycle_on_a_switch_without_poe_is_refused_before_any_write(tmp_path):
    device = FakeEos()
    assert codes(eos_cycle.preview, runtime_for(tmp_path, device, safeguard_seconds=240), "lab-ceos", eos_cycle.POE,
                 poe_cycle()) == ["poe_not_capable"]
    assert device.applied_blocks == []


def test_poe_cycle_needs_a_safeguard_that_covers_the_on_wait(tmp_path):
    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    assert codes(eos_cycle.preview, make_runtime(tmp_path, device), "lab-ceos", eos_cycle.POE, poe_cycle()) == [
        "safeguard_margin_insufficient"]
    assert eos_cycle.cycle_seconds(eos_cycle.POE) == 169 and eos_cycle.cycle_seconds(eos_cycle.BOUNCE) == 109


@pytest.mark.parametrize("after,reason", [("powered", None), ("detecting", eos_cycle.PD_NOT_BACK)])
def test_poe_cycle_powers_off_and_on_and_reports_the_powered_device(tmp_path, after, reason):
    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    device.poe_after_cycle = after
    lines = list(device.lines)
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    preview = eos_cycle.preview(runtime, "lab-ceos", eos_cycle.POE, poe_cycle())
    assert preview["result"] == "ready", preview
    assert preview["cycle_commands"][2] == "poe disabled" and preview["cycle_commands"][6] == "no poe disabled"
    assert device.applied_blocks == []
    record = apply_cycle(runtime, eos_cycle.POE, poe_cycle(), preview)
    assert record["result"] == ("reverted" if reason else "confirmed")
    assert record.get("reason") == reason, steps(record)
    order = ["poe_before", "poe_off_observed", "off_held", "poe_enable_verified", "poe_on_observed", "confirm_start"]
    assert [name for name in steps(record) if name in order] == order
    assert record["cycle"]["off"]["configured"] == "disabled" and record["cycle"]["after"]["state"] == after
    assert device.lines == lines and device.saved == lines


def test_exos_poe_cycle_stays_refused_for_eos_through_its_own_module(tmp_path):
    from netops_admin import exos_poe
    device = FakeEos()
    assert codes(exos_poe.preview, make_runtime(tmp_path, device), "lab-ceos",
                 exos_poe.request("lab-ceos", "12", "r", "u", "g123-exos-module")) == ["action_unsupported"]


# ---- public path: the CLI commands port-bounce and poe-cycle on EOS ----

def test_cli_port_bounce_and_poe_cycle_on_eos(monkeypatch, tmp_path, capsys):
    import json

    from netops_admin import cli, config

    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda _config, **_kwargs: runtime)
    base = ["--config", str(tmp_path / "admin.json"), "--device", "lab-ceos", "--port", PORT,
            "--reason", "client hangs", "--user-request", "bounce port 12"]
    assert cli.main(["port-bounce"] + base + ["--request-id", "g123-cli-1", "--preview"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["result"] == "ready" and shown["operation"] == "port-bounce" and device.applied_blocks == []
    assert cli.main(["port-bounce"] + base + ["--request-id", "g123-cli-2", "--expect-plan-sha256", shown["plan_sha256"]]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "confirmed"
    assert "shutdown" not in device.interface(PORT)
    device.lldp_extra.append("Et12")
    assert cli.main(["port-bounce"] + base + ["--request-id", "g123-cli-3", "--preview"]) == cli.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["port_lldp_neighbor"]
    assert cli.main(["port-bounce"] + base + ["--request-id", "g123-cli-4", "--preview", "--endpoint-impact", PORT]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "ready"
    # poe-cycle of the EXOS command reaches the EOS operation; the lab switch has no PoE (measured answer)
    runtime.config.devices["lab-ceos"] = dataclasses.replace(runtime.config.devices["lab-ceos"], safeguard_seconds=240)
    from enrollment_helpers import certify
    certify(runtime, device, "lab-ceos")
    written = len(device.applied_blocks)
    assert cli.main(["poe-cycle"] + base + ["--request-id", "g123-cli-5", "--preview"]) == cli.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["poe_not_capable"]
    assert len(device.applied_blocks) == written
    assert not any("poe disabled" in line for block in device.applied_blocks for line in block)
