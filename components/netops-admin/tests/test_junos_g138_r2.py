"""G138 review regressions through the Admin engine and a fixture-backed transport."""
import hashlib
from dataclasses import replace

import pytest

from enrollment_helpers import certify
from fake_junos import FakeJunos, fixture, fixture_g138
from test_junos import CHANGE, NAME, make_runtime, request, steps
from test_junos_g138 import PORT, codes, cycle_request

from netops_admin import engine, execute, junos_cycle

# RFC 2544 benchmarking prefix for a client network outside every connected subnet: the anonymised baseline already
# uses all three documentation /24s as connected subnets (written as a prefix: no full non-documentation address)
CLIENT_NET = "198.18.201."


@pytest.mark.parametrize("operation", ["bounce", "mtu", "speed", "poe", "poe-cycle"])
@pytest.mark.parametrize("key,topology,reason", [
    ("ge-0/0/0", "trunk", "port_uplink"),
    (PORT, "lldp", "port_lldp_neighbor"),
    ("ge-0/0/1", "irb-access", "port_management_interface"),
    (PORT, "unresolved-irb-vlan", "port_usage_unreadable"),
    (PORT, "only-live-link", "port_management_interface"),
])
def test_endpoint_impact_still_protects_uplinks_and_management(tmp_path, operation, key, topology, reason):
    device = FakeJunos()
    if topology == "lldp":
        device.lldp_extra = [key]
    if topology == "only-live-link":
        device.up_ports = {key}
    if topology == "irb-access":
        device.lines.append("set interfaces irb unit 20 family inet address 192.0.2.56/24")
    if topology == "unresolved-irb-vlan":
        device.lines.extend(['set groups MGMT vlans "<*>" l3-interface irb.20', "set apply-groups MGMT"])
    device.poe_capable, device.powered = True, {key}
    runtime = make_runtime(tmp_path, device)
    before = device.lines[:]
    history = device.history[:]
    fields = {"endpoint_impact": key}
    if operation in ("bounce", "poe-cycle"):
        action = junos_cycle.BOUNCE if operation == "bounce" else junos_cycle.POE
        refusal = codes(junos_cycle.preview, runtime, NAME, action, cycle_request(action, key, **fields))
    else:
        changes = {"mtu": 9000} if operation == "mtu" else {"speed": "1g"}
        if operation == "poe":
            fields.update(table="poe")
            changes = {"admin-state": "disabled"}
        refusal = codes(execute.preview, runtime, NAME, request(key=key, changes=changes, **fields))
    assert refusal == [reason]
    assert device.lines == before and device.history == history and not device.pending()


@pytest.mark.parametrize("changes,detail", [
    ({"mtu": 9000}, "default"),
    ({"mtu": 9000}, "truncated"),
    ({"speed": "100m"}, "default"),
    ({"auto-negotiation": "disabled"}, "default"),
])
def test_link_readback_must_agree_before_confirmation(tmp_path, changes, detail):
    device = FakeJunos()
    header, measured = fixture_g138("show-interfaces-ge-0-0-9-match-mtu__9000.txt").splitlines()
    answer = header + "\n"
    if detail == "default":
        answer += measured.replace("MTU: 9000", "MTU: 1514") + "\n"
    device.check_override = {"show interfaces %s" % PORT: answer}
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request(key=PORT, changes=changes))
    assert record["result"] == "reverted", (record.get("reason"), steps(record))
    assert "check_identity_failed" in steps(record) and "confirm_start" not in steps(record)
    assert "show interfaces %s" % PORT in device.check_queries
    assert device.interface(PORT) == [] and not device.pending()


@pytest.mark.parametrize("drop_link", [False, True])
def test_speed_undo_checks_link_and_accepts_the_measured_automatic_rate(tmp_path, drop_link):
    device = FakeJunos()
    device.up_ports.add(PORT)
    runtime = make_runtime(tmp_path, device)
    before = device.lines[:]
    confirmed = execute.apply(runtime, NAME, request(key=PORT, changes={"speed": "100m"}))
    assert confirmed["result"] == "confirmed"
    assert device.interface(PORT) == ["speed 100m"]

    command = "show interfaces " + PORT

    def observe_default(fake, line):
        if line == CHANGE and "speed 100m" not in fake.interface(PORT):
            assert "Speed: 1000mbps" in fake.query(command)
            if drop_link:
                fake.up_ports.remove(PORT)

    device.after_line = observe_default
    device.check_queries.clear()
    preview = execute.preview_undo(runtime, confirmed["change_id"], "restore negotiated speed", issue=True)
    assert preview["result"] == "ready"
    undone = execute.undo(runtime, confirmed["change_id"], "restore negotiated speed",
                          expected_plan_sha256=preview["plan_sha256"])
    assert command in device.check_queries and not device.pending()
    if drop_link:
        assert undone["result"] == "reverted" and "confirm_start" not in steps(undone)
        assert device.interface(PORT) == ["speed 100m"]
    else:
        assert undone["result"] == "confirmed", (undone["reason"], steps(undone))
        assert steps(undone).index("check_identity_passed") < steps(undone).index("confirm_start")
        assert device.lines == before


@pytest.mark.parametrize("operation", ["bounce", "mtu"])
@pytest.mark.parametrize("path", ["fxp0", "nat-fxp0", "target-irb", "check-irb", "default-irb", "peer-irb", "unknown"])
def test_disruptive_preview_on_g137_irb_vlan(tmp_path, operation, path):
    device = FakeJunos()
    device.lines = fixture("show-configuration-display-set__g137-composite.txt").splitlines()
    port = "ge-0/0/2"
    device.up_ports.add(port)
    if path in ("target-irb", "check-irb", "default-irb", "peer-irb"):
        # Derived variants of G137 with a client IRB address and, in one case, its default gateway.
        device.lines.append("set interfaces irb unit 3901 family inet address " + CLIENT_NET + "201/24")
    if path == "default-irb":
        device.lines.remove("set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1")
        device.lines.append("set routing-options static route 0.0.0.0/0 next-hop " + CLIENT_NET + "202")
    if path in ("nat-fxp0", "peer-irb"):
        device.ssh_paths = [("192.0.2.56", CLIENT_NET + "202")]
    runtime = make_runtime(tmp_path, device)
    if path in ("target-irb", "check-irb", "unknown", "nat-fxp0"):
        field = "check_address" if path == "check-irb" else "address"
        address = "192.0.2.251" if path in ("unknown", "nat-fxp0") else CLIENT_NET + "201"
        runtime.config.devices[NAME] = replace(runtime.config.devices[NAME], **{field: address})
        certify(runtime, device, NAME)
    before = device.lines[:]
    history = device.history[:]
    if operation == "bounce":
        action = junos_cycle.BOUNCE
        args = (junos_cycle.preview, runtime, NAME, action, cycle_request(action, port))
    else:
        args = (execute.preview, runtime, NAME, request(key=port, changes={"mtu": 9000}))
    if path in ("fxp0", "nat-fxp0"):
        preview = args[0](*args[1:])
        assert preview["result"] == "ready", preview
    else:
        assert codes(*args) == ["port_management_interface"]
    assert device.lines == before and device.history == history and not device.pending()


def test_poe_disable_needs_operational_power_off(tmp_path):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    # Model the controller still reporting power ON after the configuration is disabled.
    answer = fixture_g138("show-poe-interface-ge-0-0-3__ex-doc-on.txt")
    stale = answer.replace("ge-0/0/3", PORT).replace("Enabled", "Disabled")

    def delay_power_off(fake, line):
        if line == CHANGE:
            fake.check_override = {"show poe interface %s" % PORT: stale}

    device.after_line = delay_power_off
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, NAME, request(table="poe", key=PORT, changes={"admin-state": "disabled"}))
    assert record["result"] == "reverted", (record.get("reason"), steps(record))
    assert "check_identity_failed" in steps(record) and "confirm_start" not in steps(record)
    assert "set poe interface %s disable" % PORT not in device.lines and not device.pending()


def test_legacy_description_undo_with_preexisting_mtu(tmp_path):
    device = FakeJunos()
    device.lines.append("set interfaces %s mtu 9000" % PORT)
    runtime = make_runtime(tmp_path, device)
    before = device.lines[:]
    confirmed = execute.apply(runtime, NAME, request(key=PORT, changes={"description": "old format"}))
    assert confirmed["result"] == "confirmed"
    # 1.0.11 stored MTU among the rest of the configuration, outside the two state dictionaries.
    plan = confirmed["plan"]
    plan.pop("state_schema", None)
    plan["admin_version"] = "1.0.11"
    for state in plan["predicted"].values():
        del state["mtu"]
    plan["rest_sha256"] = hashlib.sha256("\n".join(before).encode()).hexdigest()
    plan["plan_sha256"] = engine.plan_digest(plan)
    runtime.store.save(confirmed)
    preview = execute.preview_undo(runtime, confirmed["change_id"], "restore description")
    assert preview["result"] == "ready"
    assert preview["predicted"]["after"] == {"mtu": "9000"}
    undone = execute.undo(runtime, confirmed["change_id"], "restore description")
    assert undone["result"] == "confirmed" and device.interface(PORT) == ["mtu 9000"]


def test_current_description_undo_refuses_unrecorded_mtu_drift(tmp_path):
    device = FakeJunos()
    runtime = make_runtime(tmp_path, device)
    confirmed = execute.apply(runtime, NAME, request(key=PORT, changes={"description": "current format"}))
    assert confirmed["result"] == "confirmed"
    device.lines.append("set interfaces %s mtu 9000" % PORT)
    preview = execute.preview_undo(runtime, confirmed["change_id"], "restore description")
    assert preview["result"] == "rejected"
    assert preview["reasons"] == ["the object differs from the state the undo was planned against"]


@pytest.mark.parametrize("changes,operation,expected", [
    ({"mtu": 9000}, "interface", "tested"),
    ({"speed": "1g"}, "interface", "untested"),
    ({"auto-negotiation": "disabled"}, "interface", "untested"),
    ({"mtu": 9000, "speed": "1g"}, "interface", "untested"),
    ({"admin-state": "disabled"}, "poe", "untested"),
    (None, "poe-cycle", "untested"),
    (None, "bounce", "tested"),
])
def test_preview_reports_firmware_support_for_the_requested_operation(tmp_path, changes, operation, expected):
    device = FakeJunos()
    device.poe_capable, device.powered = True, {PORT}
    runtime = make_runtime(tmp_path, device)
    if changes is None:
        action = junos_cycle.BOUNCE if operation == "bounce" else junos_cycle.POE
        preview = junos_cycle.preview(runtime, NAME, action, cycle_request(action))
    else:
        preview = execute.preview(runtime, NAME, request(table=operation, key=PORT, changes=changes))
    assert preview["result"] == "ready"
    assert preview["firmware_support"]["status"] == expected
    assert any(" is measured for " in check for check in preview["prechecks"]) == (expected == "tested")
