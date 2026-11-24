"""EOS-PORT-MAINTENANCE review regressions through Admin and the fixture-backed EOS transport."""
import inspect
import json
import re
from dataclasses import replace

import pytest

from fake_eos import FakeEos, eos_port_maintenance
from fake_fortios import DeviceRefused
from test_eos import make_runtime, request, steps
from test_eos_eos_port_maintenance import PORT, bounce, codes, poe_cycle, round_trip, runtime_for

from netops_admin import engine, eos_cycle, execute, notify
from netops_admin.errors import Rejected
from approved_apply import approved_apply


TARGET = "lab-ceos"


def preview(runtime, action, change):
    return eos_cycle.preview(runtime, TARGET, action, change)


def apply(runtime, action, change, plan):
    # Exercise cycle semantics on the baseline too, where apply has no hash parameter.
    approval = ({"expected_plan_sha256": plan["plan_sha256"]}
                if "expected_plan_sha256" in inspect.signature(eos_cycle.apply).parameters else {})
    return eos_cycle.apply(runtime, TARGET, action, change, **approval)


@pytest.mark.parametrize("action", [eos_cycle.BOUNCE, eos_cycle.POE])
@pytest.mark.parametrize("svi", [True, False])
def test_endpoint_impact_cannot_waive_management_path(tmp_path, action, svi):
    device = FakeEos()
    if svi:
        device._set(PORT, re.compile("^switchport access vlan "), "switchport access vlan 10")
    else:
        device.all_status = eos_port_maintenance("show-interfaces-Ethernet12-status__connected.txt")
    device.saved = list(device.lines)
    device.lldp_extra.append("Et12")
    device.learned_macs[PORT] = 1
    device.poe_ports[PORT] = "powered"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    change = (bounce if action == eos_cycle.BOUNCE else poe_cycle)(endpoint_impact=PORT)
    assert codes(preview, runtime, action, change) == [
        "port_management_vlan" if svi else "port_management_interface"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("action", [eos_cycle.BOUNCE, eos_cycle.POE])
@pytest.mark.parametrize("path,expected", [
    ("management_source", None),
    ("svi_source", "port_management_vlan"),
    ("svi_address", "port_management_vlan"),
    ("management_vrf_only", None),
    ("unproven", "port_usage_unreadable"),
])
def test_cycle_distinguishes_data_svi_from_management(tmp_path, action, path, expected):
    device = FakeEos()
    device._set("Management0", re.compile("^vrf "), "vrf MGMT")
    device._set("Vlan20", re.compile("^ip address "), "ip address 192.0.2.254/24")
    device._set(PORT, re.compile("^switchport access vlan "), "switchport access vlan 20")
    device.saved = list(device.lines)
    device.ssh_source = {"svi_source": "192.0.2.36", "management_source": "203.0.113.36"}.get(path, "198.51.100.42")
    if path == "management_source":
        device.ssh_status += "SSHD status for VRF MGMT: enabled\n"
    if path == "management_vrf_only":
        device.ssh_status = device.ssh_status.replace(
            "SSHD status for Default VRF: enabled",
            "SSHD status for Default VRF: disabled\nSSHD status for VRF MGMT: enabled",
        )
    device.lldp_extra.append("Et12")
    device.learned_macs[PORT] = 1
    device.poe_ports[PORT] = "powered"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    if path == "svi_address":
        from enrollment_helpers import certify

        runtime.config.devices[TARGET] = replace(runtime.config.devices[TARGET], check_address="192.0.2.254")
        certify(runtime, device, TARGET)
    change = (bounce if action == eos_cycle.BOUNCE else poe_cycle)(endpoint_impact=PORT)

    if expected:
        assert codes(preview, runtime, action, change) == [expected]
    else:
        plan = preview(runtime, action, change)
        assert plan["result"] == "ready", plan
    assert device.applied_blocks == []


@pytest.mark.parametrize("destination,mgmt_ssh,data_ssh,source,duplicate,expected", [
    ("192.0.2.254", False, True, "203.0.113.36", False, "port_management_vlan"),
    ("203.0.113.53", True, True, "192.0.2.36", False, None),
    ("203.0.113.53", True, True, "192.0.2.36", True, "port_management_vlan"),
    ("203.0.113.53", True, False, "192.0.2.36", True, None),
    ("192.0.2.254", True, False, "192.0.2.36", False, "port_usage_unreadable"),
])
@pytest.mark.parametrize("action", [eos_cycle.BOUNCE, eos_cycle.POE])
def test_cycle_checks_ssh_vrf_and_all_dns_destinations(
        tmp_path, action, destination, mgmt_ssh, data_ssh, source, duplicate, expected):
    from enrollment_helpers import certify

    device = FakeEos()
    device._set("Management0", re.compile("^vrf "), "vrf MGMT")
    device._set("Vlan20", re.compile("^ip address "), "ip address 192.0.2.254/24")
    if duplicate:
        device._set("Loopback0", re.compile("^ip address "), "ip address 203.0.113.53/32")
    device._set(PORT, re.compile("^switchport access vlan "), "switchport access vlan 20")
    device.saved = list(device.lines)
    if not data_ssh:
        device.ssh_status = device.ssh_status.replace("Default VRF: enabled", "Default VRF: disabled")
    if mgmt_ssh:
        device.ssh_status += "SSHD status for VRF MGMT: enabled\n"
    device.ssh_source = source
    device.resolve_addresses = {"switch.example.test": {destination}}.__getitem__
    device.poe_ports[PORT] = "powered"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    runtime.config.devices[TARGET] = replace(runtime.config.devices[TARGET], address="switch.example.test")
    certify(runtime, device, TARGET)
    change = (bounce if action == eos_cycle.BOUNCE else poe_cycle)(endpoint_impact=PORT)
    if expected:
        assert codes(preview, runtime, action, change) == [expected]
    else:
        assert preview(runtime, action, change)["result"] == "ready"
    assert device.applied_blocks == []


@pytest.mark.parametrize("command", ["port-bounce", "poe-cycle"])
def test_cli_requires_the_approved_cycle_plan(tmp_path, monkeypatch, capsys, command):
    from netops_admin import cli, config

    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda _config, **_kwargs: runtime)
    args = [command, "--config", str(tmp_path / "admin.json"), "--device", TARGET, "--port", PORT,
            "--reason", "cycle", "--user-request", "cycle the port", "--request-id", "eos-port-maintenance-r2-cli"]
    assert cli.main(args + ["--preview"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert cli.main(args) == cli.EXIT_REJECTED
    capsys.readouterr()
    assert cli.main(args + ["--expect-plan-sha256", "0" * 64]) == cli.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["plan_changed"]
    assert device.applied_blocks == []
    assert cli.main(args + ["--expect-plan-sha256", plan["plan_sha256"]]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "confirmed"


@pytest.mark.parametrize("table", ["port-bounce", "inline-power"])
def test_mcp_requires_the_approved_cycle_plan(tmp_path, monkeypatch, table):
    from test_mcp_server import call, mcp_server

    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    args = {"device": TARGET, "table": table, "op": "update", "key": PORT,
            "changes": {"admin-state": "disabled"}, "reason": "cycle", "user_request": "cycle the port",
            "request_id": "eos-port-maintenance-r2-mcp"}
    plan = call("admin_preview", args)
    assert plan["result"] == "ready", plan
    assert call("admin_apply", args)["result"] == "rejected"
    assert call("admin_apply", dict(args, expected_plan_sha256="0" * 64))["reason_codes"] == ["plan_changed"]
    assert device.applied_blocks == []
    assert call("admin_apply", dict(args, expected_plan_sha256=plan["plan_sha256"]))["result"] == "confirmed"


def test_cycle_plan_changes_when_the_link_changes(tmp_path):
    device = FakeEos()
    runtime = make_runtime(tmp_path, device)
    plan = preview(runtime, eos_cycle.BOUNCE, bounce())
    device.link = "notconnect"
    fresh = preview(runtime, eos_cycle.BOUNCE, bounce())
    assert plan["plan_sha256"] != fresh["plan_sha256"]
    assert codes(apply, runtime, eos_cycle.BOUNCE, bounce(), plan) == ["plan_changed"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("prior,change,command,inverse", [
    ("speed-100mfull", "auto", "speed auto", "speed 100mfull"),
    ("speed-auto", "100mfull", "speed 100mfull", "speed auto"),
])
def test_plain_speed_auto_applies_and_is_restored(tmp_path, prior, change, command, inverse):
    device = FakeEos()
    line = eos_port_maintenance("show-running-config-interfaces-Ethernet12__%s.txt" % prior).splitlines()[1].strip()
    device._set(PORT, re.compile("^speed "), line)
    device.saved = list(device.lines)
    plan = round_trip(tmp_path, device, {"speed": change}, command, inverse, "eos-port-maintenance-r2-speed")
    assert "Plain 'speed auto' is accepted without a matching hardware speed entry." in plan["rollback_evidence"]


@pytest.mark.parametrize("poe_disabled", [False, True])
def test_undo_legacy_description_journal_with_existing_speed_and_mtu(tmp_path, poe_disabled):
    device = FakeEos()
    for name, prefix in (("speed-100mfull", "speed"), ("mtu-9000", "mtu")):
        line = eos_port_maintenance("show-running-config-interfaces-Ethernet12__%s.txt" % name).splitlines()[1].strip()
        device._set(PORT, re.compile("^" + prefix + " "), line)
    if poe_disabled:
        device._set(PORT, re.compile("^poe "), "poe disabled")
    device.saved = list(device.lines)
    original = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    result = approved_apply(runtime, TARGET, request(key=PORT, changes={"description": "temporary"}))
    assert result["result"] == "confirmed"
    # Recreate the pre-EOS-PORT-MAINTENANCE journal representation for this confirmed description change.
    stored = runtime.store.operation(result["change_id"])
    plan = stored["plan"]
    plan.pop("state_schema", None)
    for side in plan["predicted"].values():
        for attr in ("speed", "mtu", "poe"):
            side.pop(attr, None)
    plan["plan_sha256"] = stored["plan_sha256"] = engine.plan_digest(plan)
    runtime.store.save(stored)

    restored = execute.undo(runtime, stored["change_id"], "return the description")
    assert restored["result"] == "confirmed", restored
    assert device.lines == device.saved == original


@pytest.mark.parametrize("attr,fixture", [("speed", "speed-100mfull"), ("mtu", "mtu-9000")])
def test_undo_current_description_journal_refuses_new_port_settings(tmp_path, attr, fixture):
    device = FakeEos()
    device._set(PORT, re.compile("^poe "), "poe disabled")
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    result = approved_apply(runtime, TARGET, request(key=PORT, changes={"description": "temporary"}))
    assert result["result"] == "confirmed", result
    stored = runtime.store.operation(result["change_id"])
    assert all(attr not in side and side["poe"] == "disabled" for side in stored["plan"]["predicted"].values())
    line = eos_port_maintenance("show-running-config-interfaces-Ethernet12__%s.txt" % fixture).splitlines()[1].strip()
    device._set(PORT, re.compile("^" + attr + " "), line)
    device.saved = list(device.lines)
    writes = list(device.applied_blocks)

    preview = execute.preview_undo(runtime, result["change_id"], "return the description")
    assert preview["result"] == "rejected", preview
    assert preview["reasons"] == ["the object differs from the state the undo was planned against"]
    with pytest.raises(Rejected, match="the object differs from the state the undo was planned against"):
        execute.undo(runtime, result["change_id"], "return the description")
    assert stored["plan"]["state_schema"] == 2
    assert device.applied_blocks == writes


def test_poe_cycle_refuses_a_port_that_is_only_detecting(tmp_path):
    device = FakeEos()
    device.poe_ports[PORT] = "detecting"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    assert codes(preview, runtime, eos_cycle.POE, poe_cycle()) == ["poe_device_not_powered"]
    assert device.applied_blocks == []


def test_poe_cycle_cannot_confirm_when_power_does_not_return(tmp_path):
    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    device.poe_after_cycle = "detecting"
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    plan = preview(runtime, eos_cycle.POE, poe_cycle())
    result = apply(runtime, eos_cycle.POE, poe_cycle(), plan)
    assert result["result"] == "reverted" and result["reason"] == eos_cycle.PD_NOT_BACK
    assert result["cycle"]["after"]["state"] == "detecting"
    assert "poe disabled" not in device.interface(PORT)


def test_reads_cannot_confirm_a_bounce_after_the_timer_expires(tmp_path):
    class SlowEos(FakeEos):
        def check_query(self, command):
            if self.link_after_bounce is None and self.link == "notconnect" and "shutdown" not in self.interface(PORT):
                self.advance(12)
                if self.timer is None:
                    self.link = "connected"
            return super().check_query(command)

    device = SlowEos()
    device.link_after_bounce = "notconnect"
    runtime = make_runtime(tmp_path, device)
    plan = preview(runtime, eos_cycle.BOUNCE, bounce())
    result = apply(runtime, eos_cycle.BOUNCE, bounce(), plan)
    assert result.get("reason") == eos_cycle.LINK_NOT_BACK, steps(result)
    assert result["cycle"]["after"]["status"] == "notconnect"
    assert "shutdown" not in device.interface(PORT) and device.timer is None


def test_slow_config_read_cannot_confirm_an_expired_bounce(tmp_path):
    class SlowSnapshot(FakeEos):
        def snapshot(self):
            if any("no shutdown" in block for block in self.applied_blocks) and self.timer is not None:
                self.advance(181)
            return super().snapshot()

    device = SlowSnapshot()
    runtime = make_runtime(tmp_path, device)
    plan = preview(runtime, eos_cycle.BOUNCE, bounce())
    result = apply(runtime, eos_cycle.BOUNCE, bounce(), plan)
    assert result["result"] == "reverted", (result.get("reason"), steps(result))
    assert "confirm_start" not in steps(result)
    assert "shutdown" not in device.interface(PORT) and device.timer is None


@pytest.mark.parametrize("action,change,after,reason,result", [
    (eos_cycle.BOUNCE, bounce, "notconnect", eos_cycle.LINK_NOT_BACK, "confirmed"),
    (eos_cycle.POE, poe_cycle, "detecting", eos_cycle.PD_NOT_BACK, "reverted"),
])
def test_uninterrupted_cycle_keeps_failed_return_when_save_fails(tmp_path, action, change, after, reason, result):
    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    if action == eos_cycle.BOUNCE:
        device.link_after_bounce = after
    else:
        device.poe_after_cycle = after

    def refuse_save(_device, lines):
        if "write memory" in lines:
            raise DeviceRefused(0)

    device.on_apply = refuse_save
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    plan = preview(runtime, action, change())
    finished = apply(runtime, action, change(), plan)
    assert finished["result"] == result
    assert finished["cycle"]["return_failure"] == reason
    assert finished["reason"] == reason + "; not persisted"
    assert runtime.store.blocked(TARGET)


@pytest.mark.parametrize("interruption,persist_fails", [
    ("disarmed", False), ("disarmed", True), ("armed", True),
])
@pytest.mark.parametrize("action,change,after,reason,result", [
    (eos_cycle.BOUNCE, bounce, "notconnect", eos_cycle.LINK_NOT_BACK, "confirmed"),
    (eos_cycle.POE, poe_cycle, "detecting", eos_cycle.PD_NOT_BACK, "reverted"),
])
def test_recover_keeps_the_failed_return(
        tmp_path, monkeypatch, action, change, after, reason, result, interruption, persist_fails):
    from test_mcp_server import call, mcp_server

    device = FakeEos()
    device.poe_ports[PORT] = "powered"
    if action == eos_cycle.BOUNCE:
        device.link_after_bounce = after
    else:
        device.poe_after_cycle = after
    runtime = runtime_for(tmp_path, device, safeguard_seconds=240)
    notifications = []

    def send(record):
        notifications.append(notify.message(record)[1])
        return "sent"

    runtime.notifier = send

    def crash(_device, lines):
        if interruption == "armed":
            interrupted = any(re.fullmatch(r"configure session netops-[0-9a-f]+ commit", line) for line in lines)
        else:
            interrupted = "write memory" in lines
        if interrupted:
            raise KeyboardInterrupt

    plan = preview(runtime, action, change())
    device.on_apply = crash
    with pytest.raises(KeyboardInterrupt):
        apply(runtime, action, change(), plan)
    def refuse_save(_device, lines):
        if "write memory" in lines:
            raise DeviceRefused(0)

    device.on_apply = refuse_save if persist_fails else None
    finished, = execute.recover(runtime, TARGET)
    expected = "%s; not persisted" % reason if persist_fails else reason
    assert finished["result"] == ("reverted" if interruption == "armed" else result)
    assert finished["cycle"]["return_failure"] == reason
    assert finished["reason"] == expected
    report = [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]
    outcome, = [event for event in report if event["event"] == "result"]
    assert outcome["reason"] == expected
    assert ("reason: " + expected) in notifications[0].splitlines()
    assert bool(runtime.store.blocked(TARGET)) == persist_fails
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    status = call("admin_status", {"change_id": finished["change_id"]})
    assert status["reason"] == expected
