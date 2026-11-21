"""G42 public Admin operations backed by the measured EXOS CLI layouts."""
from dataclasses import replace
from pathlib import Path

import pytest

from enrollment_helpers import certify
from fake_exos import FakeExos
from test_exos_port_admin_poe import poe_runtime
from test_mcp_server import call
from netops_admin import engine, exos, mcp_server


FIXTURES = Path(__file__).parent / "fixtures" / "exos_g42"
DESCRIPTION = "G42 Room 210 Test Desk"


def reading(name, device="x440"):
    return (FIXTURES / device / (name + ".txt")).read_text()


def args(table, changes, key="10", **fields):
    return dict({"device": "sw", "table": table, "op": "update", "key": key, "changes": changes,
                 "reason": "G42 test", "user_request": "Test the isolated port", "request_id": "g42-port-10"}, **fields)


def setup(monkeypatch, tmp_path, device, **options):
    runtime = poe_runtime(tmp_path, device, **options)
    runtime.config = replace(runtime.config, mcp_undo=True)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: runtime)
    return runtime


def audit_policy(runtime, device, **fields):
    policy = {"version": 1, "platform": "exos", **fields}
    switch = replace(runtime.config.devices["sw"], audit_policy=policy)
    runtime.config.devices["sw"] = switch
    certify(runtime, device, "sw")


def preview_apply(device, request):
    prior = device.snapshot()
    blocks = list(device.applied_blocks)
    preview = call("admin_preview", request)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == prior and blocks == device.applied_blocks
    applied = call("admin_apply", dict(request, expected_plan_sha256=preview["plan_sha256"]))
    assert applied["result"] == "confirmed" and applied["reason"] is None, applied
    return preview, applied


def undo(device, applied):
    before = device.snapshot()
    base = {"change_id": applied["change_id"], "reason": "restore original port state"}
    check = call("admin_undo_preview", base)
    assert check["result"] == "ready" and device.snapshot() == before, check
    undone = call("admin_undo", dict(base, expected_plan_sha256=check["plan_sha256"]))
    assert undone["result"] == "confirmed" and undone["reason"] is None, undone


@pytest.mark.parametrize("key", ["10", "2:10"])
def test_description_readback_and_undo_preserve_short_display(monkeypatch, tmp_path, key):
    device = FakeExos()
    if key != "10":
        device.port_numbers = [key]
    device.port_strings[key] = "Short10"
    real = device.check_query

    def check(command):
        if command == f"show ports {key} information detail":
            name = "port-10-described" if key in device.port_descriptions else "port-10-info"
            return reading(name).replace("Port:\t10", f"Port:\t{key}(Short10):", 1)
        return real(command)

    device.check_query = check
    setup(monkeypatch, tmp_path, device)
    before = device.snapshot()
    preview, applied = preview_apply(device, args("ports", {"description-string": DESCRIPTION, "display-string": "Short10"}, key))
    assert preview["commands"] == [f'configure ports {key} description-string "{DESCRIPTION}"']
    assert reading("config-10-described").strip().replace("ports 10", "ports " + key) in device.snapshot()
    assert device.port_strings[key] == "Short10"
    undo(device, applied)
    assert device.snapshot() == before


def test_description_incomplete_readback_refuses_before_write(monkeypatch, tmp_path):
    device = FakeExos()
    real = device.check_query
    device.check_query = lambda cmd: reading("port-10-info").split("Link State:")[0] if cmd.endswith(
        "information detail") else real(cmd)
    setup(monkeypatch, tmp_path, device)
    answer = call("admin_preview", args("ports", {"description-string": DESCRIPTION}))
    assert answer["reason_codes"] == ["port_usage_unreadable"]
    assert not device.applied_blocks


@pytest.mark.parametrize(("table", "operation"), [("poe-cycle", "poe"), ("port-bounce", "port")])
def test_cycles_require_approved_preview_and_restore_state(monkeypatch, tmp_path, table, operation):
    device = FakeExos()
    device.poe_detail_measured["10"] = reading("poe-10-detail")
    device.on_apply = lambda *_: device.poe_detail_measured.clear()
    setup(monkeypatch, tmp_path, device)
    request = args(table, {"admin-state": "disabled"})
    denied = call("admin_apply", request)
    assert denied["reason_codes"] == ["plan_changed"] and not device.applied_blocks
    before = device.snapshot()
    preview, applied = preview_apply(device, request)
    assert preview["operation"] == applied["operation"] == table
    assert applied["readback"]["off"]["configured"] == "disabled"
    assert applied["readback"]["after"]["configured"] == "enabled"
    assert device.snapshot() == before and device.saves == 1
    assert not device.timers and not device.profiles
    if operation == "port":
        assert device.uptime >= preview["hold_seconds"] == 5


def test_permanent_poe_update_and_undo_distinct_from_cycle(monkeypatch, tmp_path):
    device = FakeExos()
    setup(monkeypatch, tmp_path, device)
    before = device.snapshot()
    request = args("inline-power", {"admin-state": "disabled"})
    preview, applied = preview_apply(device, request)
    assert preview["commands"] == ["disable inline-power ports 10"]
    assert device.poe_disabled == {"10"}
    cycle = call("admin_preview", dict(request, table="poe-cycle"))
    assert cycle["reason_codes"] == ["request_id_reused"]
    undo(device, applied)
    assert device.snapshot() == before


def test_stack_port_state_and_poe_return(monkeypatch, tmp_path):
    device = FakeExos()
    key = "2:10"
    device.port_numbers = [key]
    device.poe_ports = {key}
    setup(monkeypatch, tmp_path, device)
    before = device.snapshot()
    for table, command, state in (
            ("ports", "disable ports 2:10", device.ports_disabled),
            ("inline-power", "disable inline-power ports 2:10", device.poe_disabled)):
        preview, applied = preview_apply(device, args(table, {"admin-state": "disabled"}, key, request_id=f"g42-{table}"))
        assert preview["commands"] == [command] and state == {key}
        undo(device, applied)
        assert device.snapshot() == before and not state


def test_stack_poe_cycle_confirms_and_reads_both_sides(monkeypatch, tmp_path):
    device = FakeExos()
    key = "2:10"
    device.port_numbers = [key]
    device.poe_ports = {key}
    device.poe_detail_templates[key] = reading("poe-2-10-detail", "stack")
    setup(monkeypatch, tmp_path, device)
    request = args("poe-cycle", {"admin-state": "disabled"}, key)
    before = device.snapshot()
    refused = call("admin_apply", request)
    assert refused["reason_codes"] == ["plan_changed"] and not device.applied_blocks
    preview, applied = preview_apply(device, request)
    assert preview["cycle_commands"] == ["disable inline-power ports 2:10", "enable inline-power ports 2:10"]
    assert applied["operation"] == "poe-cycle"
    for phase, configured, state in (
            ("before", "enabled", "searching"), ("off", "disabled", "disabled"), ("after", "enabled", "searching")):
        assert applied["readback"][phase]["configured"] == configured
        assert applied["readback"][phase]["state"] == state
    assert device.snapshot() == before and device.saves == 1
    assert not device.timers and not device.profiles and not device.poe_off


def test_repeated_enable_of_enabled_poe_reports_no_change(monkeypatch, tmp_path):
    device = FakeExos()
    device.poe_detail_measured["10"] = reading("poe-10-detail")
    setup(monkeypatch, tmp_path, device)
    before = device.snapshot()
    request = args("inline-power", {"admin-state": "enabled"})
    for tool in ("admin_preview", "admin_apply"):
        answer = call(tool, request)
        assert answer["result"] == "rejected"
        assert answer["reasons"] == ["inline power of port 10 is already configured enabled"]
        assert "poe_disabled" not in answer["reason_codes"]
    assert device.snapshot() == before and not device.applied_blocks


@pytest.mark.parametrize(("mode", "lag_peer"), [("tagged", False), ("untagged", False), ("tagged", True)])
def test_data_port_refuses_management_vlan_from_port_policy(monkeypatch, tmp_path, mode, lag_peer):
    device = FakeExos()
    if lag_peer:
        snapshot = device.snapshot
        device.snapshot = lambda: snapshot().replace("# Module ems", "enable sharing 10 grouping 10,11 lacp\n# Module ems")
    runtime = setup(monkeypatch, tmp_path, device)
    modes = {"tagged": [], "untagged": ["Default"]}
    modes[mode] = ["oob"]
    audit_policy(runtime, device, management_vlans=["OOB"], port_vlans={"11" if lag_peer else "10": modes})
    request = args("ports", {"admin-state": "disabled"}, **({"endpoint_impact": "10"} if lag_peer else {}))
    result = call("admin_preview", request)
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_management_vlan"], result
    assert not device.applied_blocks


@pytest.mark.parametrize("table", ["inline-power", "poe-cycle"])
@pytest.mark.parametrize(("path", "reason"), [
    ("ssh-client", "port_management_interface"),
    ("management-vlan", "port_management_vlan"),
    ("lag", "port_lag_member"),
])
def test_power_off_refuses_a_delivering_management_path_port(monkeypatch, tmp_path, table, path, reason):
    device = FakeExos()
    device.powered_devices.add("10")
    assert device.poe_state("10") == "delivering"
    if path == "ssh-client":
        device.ssh_client_port = "10"
    elif path == "lag":
        snapshot = device.snapshot
        device.snapshot = lambda: snapshot().replace("# Module ems", "enable sharing 10 grouping 10,11 lacp\n# Module ems")
    runtime = setup(monkeypatch, tmp_path, device)
    if path == "management-vlan":
        audit_policy(runtime, device, management_vlans=["default"])
    request = args(table, {"admin-state": "disabled"})
    result = call("admin_preview", request)
    assert result["result"] == "rejected" and result["reason_codes"] == [reason], result
    assert not device.applied_blocks


def test_stack_port_can_be_added_to_a_vlan_as_tagged():
    import json

    from netops_admin.request import parse_request

    device = FakeExos()
    request = parse_request(json.dumps(args("vlan", {"tagged-ports": ["2:10"]}, "DATA")).encode())
    plan = engine.build_plan("exos", device.snapshot().encode(), request, firmware=device.firmware,
                             ports=[*device.port_numbers, "2:10"])
    assert plan["commands"] == ["configure vlan DATA add ports 2:10 tagged"]
    assert plan["inverse"] == ["configure vlan DATA delete ports 2:10"]


def test_bounce_refuses_an_already_disabled_port(monkeypatch, tmp_path):
    device = FakeExos()
    device.ports_disabled.add("10")
    device.ports_down.add("10")
    setup(monkeypatch, tmp_path, device)
    result = call("admin_preview", args("port-bounce", {"admin-state": "disabled"}))
    assert result["reason_codes"] == ["port_disabled"] and not device.applied_blocks


def test_incomplete_link_state_refuses_before_write(monkeypatch, tmp_path):
    device = FakeExos()
    original = device.query
    configuration = reading("port-10-config").splitlines()[0]
    device.query = lambda cmd: configuration if cmd.endswith("configuration no-refresh") else original(cmd)
    setup(monkeypatch, tmp_path, device)
    result = call("admin_preview", args("port-bounce", {"admin-state": "disabled"}))
    assert result["reason_codes"] == ["port_usage_unreadable"] and not device.applied_blocks


def test_poe_rejects_non_poe_and_vm(monkeypatch, tmp_path):
    device = FakeExos()
    original = device.query_status
    setup(monkeypatch, tmp_path, device)
    for model, key, code in [("x440", "16", "poe_not_capable"), ("d-exos", "10", "poe_disabled")]:
        device.query_status = lambda command: ((250 if key == "16" else 0, reading(f"poe-{key}-info", model))
                                               if command.startswith("show inline-power") else original(command))
        result = call("admin_preview", args("inline-power", {"admin-state": "disabled"}, key))
        assert result["reason_codes"] == [code], result
        assert not device.applied_blocks


@pytest.mark.parametrize(("lag", "key", "peer"), [(False, "10", "12"), (True, "10", "12"), (True, "2:10", "2:12")])
def test_trunk_or_lag_is_explicit_and_returns(monkeypatch, tmp_path, lag, key, peer):
    device = FakeExos()
    if ":" in key:
        device.port_numbers = [key, peer]
    real_snapshot, real_query, real_check = device.snapshot, device.query, device.check_query
    config = f"enable sharing {key} grouping {key},{peer} algorithm address-based L2\n" if lag else ""
    config += f"configure vlan DATA add ports {key} tagged\n"
    device.snapshot = lambda: real_snapshot().replace("# Module ems", config + "# Module ems")
    device.query = lambda cmd: reading("sessions", "d-exos") if cmd == "show session" else real_query(cmd)
    def check(command):
        if command.startswith("show iproute vr "):
            return reading("route-" + command.split()[-1], "d-exos")
        return real_check(command)

    device.check_query = check
    device.lldp_text = reading("lldp", "d-exos")
    device.fdb_text = reading("fdb", "d-exos")
    setup(monkeypatch, tmp_path, device)
    request = args("ports", {"admin-state": "disabled"}, key)
    denied = call("admin_preview", request)
    assert denied["reason_codes"] == ["port_lag_member" if lag else "port_uplink"]
    request["endpoint_impact"] = key
    before = device.snapshot()
    preview, applied = preview_apply(device, request)
    assert preview["port_impact"]["tagged_vlans"] == "DATA"
    assert preview["port_impact"]["lag_ports"] == (f"{key}, {peer}" if lag else "")
    assert device.ports_disabled == {key}
    undo(device, applied)
    assert device.snapshot() == before


def test_legacy_port_plan_keeps_description_outside_its_owned_state():
    from netops_admin.request import parse_request
    import json

    device = FakeExos()
    device.port_descriptions["10"] = DESCRIPTION
    before = device.snapshot()
    plan = engine.build_plan("exos", before.encode(), parse_request(
        json.dumps(args("ports", {"admin-state": "disabled"})).encode()), firmware=device.firmware)
    plan.pop("state_schema")
    for state in plan["predicted"].values():
        state.pop("description-string")
    plan["rest_sha256"] = exos.Snapshot(before, device.firmware).rest_digest("ports", "10", port_description=False)
    plan["plan_sha256"] = engine.plan_digest(plan)
    assert engine.verify(plan, before.encode(), expect="before")["result"] == "match"
    device.port_descriptions["10"] = "Changed externally"
    assert engine.verify(plan, device.snapshot().encode(), expect="before")["result"] == "mismatch"
