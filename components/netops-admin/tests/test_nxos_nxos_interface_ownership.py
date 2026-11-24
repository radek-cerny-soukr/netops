"""Ordered NX-OS profile batches exercised through the Admin engine and a fixture-backed transport."""
from dataclasses import replace
from pathlib import Path

import pytest

from fake_nxos import fixture
from netops_admin import engine, exec_nxos, execute, nxos
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_nxos import make_runtime, request
from test_nxos_nxos_switchport_admin import LabNxos, VLAN
from test_nxos_nxos_routing_admin import measured as measured_l3

DEVICE = "lab-nxos"
PORT = "Ethernet1/64"
FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_interface_ownership"
CREATE_VLAN = {"table": "vlan", "op": "create", "key": VLAN, "changes": {"name": "netops-nx-port-base"}}
MOVE_PORT = {"table": "vlan-membership", "op": "update", "key": PORT, "changes": {"access-vlan": int(VLAN)}}
DESCRIBE = {"table": "interface", "op": "update", "key": PORT, "changes": {"description": "NETOPS-NXOS-INTERFACE-OWNERSHIP"}}


def captured(lab, name):
    return (FIXTURES / f"{lab}__{name}.txt").read_text()


class BatchNxos(LabNxos):
    def __init__(self):
        super().__init__()
        self.refuse_description = False
        self.incomplete = False
        self.connected = False

    def _line(self, line, mode):
        if self.refuse_description and line == "description NETOPS-NXOS-INTERFACE-OWNERSHIP":
            return fixture("interface-ethernet1-99__invalid-range.txt")
        return super()._line(line, mode)

    def query(self, command):
        if command == "show interface vlan 20":
            return measured_l3("svi-up")
        if command == "show interface loopback 900":
            return measured_l3("interfaces-loop")
        if command == f"show interface {PORT} status" and not self.interface(PORT):
            text = captured("nexus9300v", "status")
            if self.incomplete:
                return text.rsplit("\n", 2)[0]
            if self.connected:
                return text.replace("notconnec", "connected ")
            return text
        if command == f"show interface {PORT} switchport" and not self.interface(PORT):
            return captured("nexus9300v", "switchport")
        if command == f"show vlan id {VLAN}" and VLAN not in self.vlans():
            return captured("nexus9300v", "vlan").replace("3966", VLAN)
        if command == "show system vlan reserved":
            return captured("nexus9300v", "reserved")
        return super().query(command)

    def check_query(self, command):
        if command == "show interface loopback 900":
            return measured_l3("interfaces-loop")
        return super().check_query(command)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    device = BatchNxos()
    monkeypatch.setattr(exec_nxos, "PAUSE", device.advance)
    return device, make_runtime(tmp_path, device)


def batch(*steps, **fields):
    return request(table="batch", key="batch", changes=list(steps), **fields)


@pytest.mark.parametrize("lab", ("nexus9300v", "nexus-peer-a", "nexus-peer-b"))
def test_lab_fixtures_identify_idle_port_and_missing_vlan(lab):
    assert nxos.nxos_version(captured(lab, "version")) == "9.3(12)"
    assert nxos.vlan_status(captured(lab, "vlan"), "3966") is None
    assert nxos.status_row(captured(lab, "status"), PORT)["status"] == "notconnec"
    assert nxos.membership_status(captured(lab, "switchport"), PORT) == nxos.MEMBERSHIP_DEFAULTS


@pytest.mark.parametrize("second_port", (False, True))
def test_dependent_vlan_and_port_batch_applies_and_undoes(lab, second_port):
    device, runtime = lab
    before = nxos.save_snapshot_digest(device.running())
    operations = [CREATE_VLAN, MOVE_PORT]
    if second_port:
        operations.append({**DESCRIBE, "key": "Ethernet1/63"})
    tables = [step["table"] for step in operations]
    req = batch(*operations)
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview
    assert [step["table"] for step in preview["operations"]] == tables
    assert not device.applied_blocks
    with pytest.raises(Rejected) as denied:
        execute.apply(runtime, DEVICE, req)
    assert denied.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks

    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert [step["result"] for step in record["batch_results"]] == ["verified"] * len(operations)
    assert engine.verify(record["plan"], device.running().encode())["result"] == "match"
    assert f"switchport access vlan {VLAN}" in device.interface(PORT)
    if second_port:
        assert "description NETOPS-NXOS-INTERFACE-OWNERSHIP" in device.interface("Ethernet1/63")

    undo_preview = execute.preview_undo(runtime, record["change_id"], "restore", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    assert [step["table"] for step in undo_preview["operations"]] == list(reversed(tables))
    returned = execute.undo(runtime, record["change_id"], "restore",
                            expected_plan_sha256=undo_preview["plan_sha256"])
    assert returned["result"] == "confirmed", returned
    assert nxos.save_snapshot_digest(device.running()) == before
    assert device.clean()


@pytest.mark.parametrize("partial", (False, True))
def test_cli_refusal_of_second_step_returns_first_with_its_inverse(lab, partial):
    device, runtime = lab
    before = nxos.save_snapshot_digest(device.running())
    other_port = {**DESCRIBE, "key": "Ethernet1/63", "changes": {"description": "NETOPS-NXOS-INTERFACE-OWNERSHIP-FIRST"}}
    second = {**DESCRIBE, "changes": {**DESCRIBE["changes"], "admin-state": "disabled"}} if partial else DESCRIBE
    req = batch(other_port, second)
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview
    device.refuse_description = True
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert [step["result"] for step in record["batch_results"]] == ["reverted", "failed"]
    assert [step["detail"] for step in record["steps"] if step["step"] == "batch_step_reverted"] == ["2", "1"]
    assert ["configure terminal", "interface Ethernet1/63", "no description", "end"] in device.applied_blocks
    if partial:
        assert ["configure terminal", f"interface {PORT}", "no shutdown", "no description", "end"] in device.applied_blocks
    assert not device.replaces
    assert nxos.save_snapshot_digest(device.running()) == before
    assert device.clean()


def test_second_write_session_failure_returns_only_the_written_step(lab):
    device, runtime = lab
    before = nxos.save_snapshot_digest(device.running())
    first = {**DESCRIBE, "key": "Ethernet1/63"}
    req = batch(first, DESCRIBE)
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview

    def fail_to_open(_device, commands):
        if f"interface {PORT}" in commands:
            raise AccessError("SSH write session did not open")

    device.on_apply = fail_to_open
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert nxos.save_snapshot_digest(device.running()) == before and device.clean()
    assert [(step["result"], step.get("rollback")) for step in record["batch_results"]] == [
        ("reverted", "verified"), ("failed", None)]
    for event in ("batch_step_start", "batch_step_reverted"):
        assert [step["detail"] for step in record["steps"] if step["step"] == event] == ["1"]


def test_incomplete_second_port_read_refuses_entire_preview(lab):
    device, runtime = lab
    device.incomplete = True
    preview = execute.preview(runtime, DEVICE, batch({**DESCRIBE, "key": "Ethernet1/63"}, DESCRIBE))
    assert preview["result"] == "rejected"
    assert "unspecified_refusal" not in preview["reason_codes"]
    assert not device.applied_blocks


def test_active_interface_requires_per_step_impact(lab):
    device, runtime = lab
    device.connected = True
    preview = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, DESCRIBE))
    assert preview["reason_codes"] == ["endpoint_impact_required"]
    preview = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, {**DESCRIBE, "endpoint_impact": PORT}))
    assert preview["result"] == "ready", preview
    assert preview["operations"][1]["endpoint_impact"] == PORT
    assert not device.applied_blocks


def test_batch_preview_recognizes_active_loopback_and_requires_per_step_impact(lab):
    device, runtime = lab
    device.body.extend(("interface loopback900", "  ip address 192.0.2.222/32"))
    device.saved = device._config()
    loopback = {"table": "l3-interface", "op": "update", "key": "loopback900",
                "changes": {"admin-state": "disabled"}}
    denied = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, loopback))
    assert denied["reason_codes"] == ["endpoint_impact_required"], denied
    preview = execute.preview(runtime, DEVICE, batch(
        CREATE_VLAN, {**loopback, "endpoint_impact": "loopback900"}))
    assert preview["result"] == "ready", preview
    assert not device.applied_blocks


def test_adding_relay_to_active_svi_requires_impact_even_when_relay_is_absent(lab):
    device, runtime = lab
    relay = {"table": "dhcp-relay", "op": "create", "key": "Vlan20:192.0.2.200", "changes": {}}
    preview = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, relay))
    assert preview["reason_codes"] == ["endpoint_impact_required"]
    approved = {**relay, "endpoint_impact": relay["key"]}
    plan = engine.build_plan("nxos", device.running().encode(), batch(CREATE_VLAN, approved))
    assert plan["batch_steps"][1]["endpoint_impact"] == relay["key"]
    assert not device.applied_blocks


@pytest.mark.parametrize("table,key,op,changes,protected", (
    ("vlan-membership", PORT, "update", {"access-vlan": 10}, "Eth1/64"),
    ("l3-interface", "Vlan3900", "update", {"admin-state": "disabled"}, "Vlan3900"),
    ("l3-interface", "loopback19", "update", {"admin-state": "disabled"}, "loopback19"),
    ("port-channel", "port-channel140", "create", {}, "Po140"),
))
def test_batch_honors_interface_protection_across_profiles(lab, table, key, op, changes, protected):
    device, runtime = lab
    current = runtime.config.devices[DEVICE]
    runtime.config.devices[DEVICE] = replace(current, protected={"interface": [protected]})
    # Planning rejects the protected key before looking up the scoped object's existence.
    with pytest.raises(Rejected) as denied:
        engine.build_plan("nxos", device.running().encode(), batch(
            CREATE_VLAN, {"table": table, "op": op, "key": key, "changes": changes}
        ), protected=runtime.config.devices[DEVICE].protected)
    assert denied.value.reason_codes == ["port_protected"]


def test_changed_order_invalidates_preview(lab):
    device, runtime = lab
    first = {**DESCRIBE, "key": "Ethernet1/63"}
    preview = execute.preview(runtime, DEVICE, batch(first, DESCRIBE))
    with pytest.raises(Rejected) as denied:
        execute.apply(runtime, DEVICE, batch(DESCRIBE, first), expected_plan_sha256=preview["plan_sha256"])
    assert denied.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks


def test_untested_firmware_warns_for_every_step(lab):
    device, _ = lab
    snapshot = device.running().replace("version 9.3(12)", "version 9.3(13)")
    plan = engine.build_plan("nxos", snapshot.encode(), batch(CREATE_VLAN, MOVE_PORT))
    assert plan["firmware_support"]["status"] == "untested"
    assert all(step["firmware_support"]["status"] == "untested" for step in plan["batch_steps"])


def test_mcp_batch_preview_apply_and_status(lab, monkeypatch):
    from netops_admin import mcp_server
    from test_mcp_server import call

    device, runtime = lab
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: runtime)
    args = {"device": DEVICE, "table": "batch", "op": "update", "key": "batch",
            "reason": "joint access port and VLAN change", "user_request": "apply this approved plan",
            "request_id": "batch-mcp-001", "changes": [CREATE_VLAN, MOVE_PORT]}
    preview = call("admin_preview", args)
    assert preview["result"] == "ready" and not device.applied_blocks
    response = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert response["result"] == "confirmed"
    status = call("admin_status", {"request_id": args["request_id"]})
    assert status["operations"] == response["operations"]
    assert [step["result"] for step in status["operations"]] == ["verified", "verified"]


def test_mcp_batch_prewrite_refusal_omits_rollback_for_unwritten_step(lab, monkeypatch):
    from netops_admin import mcp_server
    from test_mcp_server import call

    device, runtime = lab
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: runtime)
    first_port = "Ethernet1/63"
    first_description = "NETOPS-NXOS-INTERFACE-OWNERSHIP-FIRST"
    first = {**DESCRIBE, "key": first_port, "changes": {"description": first_description}}
    args = {"device": DEVICE, "table": "batch", "op": "update", "key": "batch",
            "reason": "label two disconnected ports", "user_request": "apply this approved plan",
            "request_id": "batch-mcp-prewrite", "changes": [first, DESCRIBE]}
    before = nxos.save_snapshot_digest(device.running())
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview

    def connect_second_port(fake, line):
        if line == f"description {first_description}":
            fake.connected = True

    device.on_line = connect_second_port
    response = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    status = call("admin_status", {"request_id": args["request_id"]})
    assert response["result"] == status["result"] == "reverted"
    assert response["steps"].count("batch_step_start") == 1
    assert response["steps"].count("batch_step_verified") == 1
    assert response["steps"].count("batch_step_reverted") == 1
    assert device.applied_blocks.count(["configure terminal", f"interface {first_port}",
                                       f"description {first_description}", "end"]) == 1
    assert device.applied_blocks.count(["configure terminal", f"interface {first_port}",
                                       "no description", "end"]) == 1
    assert all(f"interface {PORT}" not in commands for commands in device.applied_blocks)
    assert not device.replaces
    assert nxos.save_snapshot_digest(device.running()) == before
    assert device.clean()
    assert status["operations"] == response["operations"]
    first_result, second_result = response["operations"]
    assert first_result["key"] == first_port
    assert first_result["result"] == "reverted"
    assert first_result["rollback"] == "verified"
    assert second_result["key"] == PORT
    assert second_result["result"] == "failed"
    assert second_result["reason_codes"] == ["endpoint_impact_required"]
    assert "rollback" not in second_result
