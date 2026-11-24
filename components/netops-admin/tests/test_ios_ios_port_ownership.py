"""IOS profile batches through the Admin runtime and the simulated SSH transport."""
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_ios import FakeIos
from fake_ios_acl import G64Ios
from test_ios import make_runtime, steps
from test_ios_ios_static_routing import G62Ios
from test_ios_ios_dhcp import DhcpIos, POOL, RANGE, dhcp_state, pool
from test_ios_ios_system_services import NTP, SYSLOG, ServiceIos
from test_mcp_server import call

from netops_admin import engine, exec_ios, execute, ios, ios_acl, mcp_server
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "ios_ios_port_ownership"
DEVICE = "lab-ios"
PORT = "GigabitEthernet1/0"
SECOND = "GigabitEthernet1/1"


def fixture(name):
    return (FIXTURES / name).read_text()


def description(port, value, **fields):
    return dict(table="interface", op="update", key=port, changes={"description": value}, **fields)


def acl(name, family="ipv4", rules="10 permit ip any any"):
    return dict(table="ip-access-list", op="create", key=family + ":" + name, changes={"rules": rules})


def batch(*changes):
    return parse_request(request_bytes(table="batch", op="update", key="batch", changes=list(changes)))


def baseline(fake):
    return tuple(line for line in fake.lines if not line.startswith(ios.VOLATILE_HEADER))


def test_measured_node_identity_and_cli_readbacks():
    for name, version, port in (("router", "15.9(3)M12", "GigabitEthernet0/3"),
                                ("switch", "15.2(20200924:215240)", PORT)):
        assert ios.version(fixture(name + "-version.txt"))["version"] == version
        assert ios.load(fixture(name + "-configuration.txt"), version).interfaces[port]
        assert ios.description_row(fixture(name + "-descriptions.txt"), port)["status"] == "admin down"
        assert exec_ios.parse_timer(fixture(name + "-timer.txt")) is None
    assert ios_acl.observe_acl(fixture("router-acl-absent.txt"), "ipv4:NETOPS-IOS-PORT-OWNERSHIP-TEST") is None
    assert ios.refused(fixture("router-unsupported.txt"))


def test_mcp_preview_requires_hash_and_two_port_apply_readback_undo(tmp_path, monkeypatch):
    switch = FakeIos()
    runtime = make_runtime(tmp_path, switch)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: runtime)
    args = dict(device=DEVICE, table="batch", op="update", key="batch", request_id="ios-port-ownership-mcp-001",
                changes=[description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-FIRST"), description(SECOND, "NETOPS-IOS-PORT-OWNERSHIP-SECOND")],
                reason="IOS-PORT-OWNERSHIP approved lab plan", user_request="Label two ports")
    before = baseline(switch)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    assert not switch.applied_blocks
    missing = call("admin_apply", args)
    assert missing["result"] == "rejected"
    assert not switch.applied_blocks

    result = call("admin_apply", dict(args, expected_plan_sha256=preview["plan_sha256"]))
    assert result["result"] == "confirmed", result
    assert [step["result"] for step in result["operations"]] == ["verified", "verified"]
    assert call("admin_status", {"request_id": args["request_id"]})["operations"] == result["operations"]
    assert "description NETOPS-IOS-PORT-OWNERSHIP-FIRST" in switch.interface(PORT)
    assert "description NETOPS-IOS-PORT-OWNERSHIP-SECOND" in switch.interface(SECOND)

    original = runtime.store.operation(result["change_id"])
    undo = execute.preview_undo(runtime, original["change_id"], "rollback lab batch", issue=True)
    assert undo["result"] == "ready", undo
    restored = execute.undo(runtime, original["change_id"], "rollback lab batch",
                            expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert baseline(switch) == before
    assert switch.saved == switch.lines and switch.timer is None


@pytest.mark.parametrize("failure", ["truncated", "timeout", "active"])
def test_preview_refuses_incomplete_or_active_second_port(tmp_path, failure):
    switch = FakeIos()
    runtime = make_runtime(tmp_path, switch)
    output = fixture("switch-descriptions.txt")
    if failure == "truncated":
        output = "\n".join(line for line in output.splitlines() if not line.startswith("Gi1/1 "))
        code = "ios_batch_read_unreadable"
    elif failure == "active":
        active_row = next(line for line in output.splitlines() if line.startswith("Gi0/3 "))
        idle_row = next(line for line in output.splitlines() if line.startswith("Gi1/1 "))
        output = output.replace(idle_row, active_row.replace("Gi0/3", "Gi1/1", 1))
        code = "endpoint_impact_required"
    else:
        def fail(_switch, command):
            if command == exec_ios.QUERY_DESCRIPTIONS:
                raise AccessError("SSH read timed out")
        switch.on_check_query = fail
        code = "ios_batch_read_timeout"

    switch.check_override = {exec_ios.QUERY_DESCRIPTIONS: output}
    request = batch(description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-FIRST"), description(SECOND, "NETOPS-IOS-PORT-OWNERSHIP-SECOND"))
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code], preview
    assert not switch.applied_blocks
    if failure == "active":
        accepted = batch(description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-FIRST"),
                         description(SECOND, "NETOPS-IOS-PORT-OWNERSHIP-SECOND", endpoint_impact=SECOND))
        preview = execute.preview(runtime, DEVICE, accepted)
        assert preview["result"] == "ready", preview


def test_second_step_read_refusal_returns_only_the_written_step(tmp_path):
    switch = FakeIos()
    runtime = make_runtime(tmp_path, switch)
    before = baseline(switch)
    request = batch(description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-FIRST"), description(SECOND, "NETOPS-IOS-PORT-OWNERSHIP-SECOND"))
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "ready", preview
    def fail_after_first(target, command):
        if command == exec_ios.QUERY_DESCRIPTIONS and "description NETOPS-IOS-PORT-OWNERSHIP-FIRST" in target.interface(PORT):
            reads_with_first.append(command)
            if len(reads_with_first) == 2:
                raise AccessError("SSH read timed out")
    reads_with_first = []
    switch.on_check_query = fail_after_first
    result = execute.apply(runtime, DEVICE, request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "reverted", result
    assert steps(result).count("batch_step_start") == 1
    assert [step["result"] for step in result["batch_results"]] == ["reverted", "failed"]
    assert result["batch_results"][0]["rollback"] == "verified"
    assert result["batch_results"][1]["reason_codes"] == ["ios_batch_read_timeout"]
    assert "rollback" not in result["batch_results"][1]
    assert "description NETOPS-IOS-PORT-OWNERSHIP-SECOND" not in switch.sent_lines
    assert baseline(switch) == before and switch.timer is None


@pytest.mark.parametrize("rollback", ["verified", "safeguard-verified"])
def test_second_write_session_failure_returns_only_the_written_step(tmp_path, rollback):
    switch = FakeIos()
    runtime = make_runtime(tmp_path, switch)
    before = baseline(switch)
    request = batch(description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-FIRST"), description(SECOND, "NETOPS-IOS-PORT-OWNERSHIP-SECOND"))
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "ready", preview

    def fail_to_open(_switch, commands):
        reverting_first = f"interface {PORT}" in commands and "description NETOPS-IOS-PORT-OWNERSHIP-FIRST" not in commands
        if f"interface {SECOND}" in commands or (rollback == "safeguard-verified" and reverting_first):
            raise AccessError("SSH write session did not open")

    switch.on_apply = fail_to_open
    result = execute.apply(runtime, DEVICE, request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "reverted", result
    assert f"interface {SECOND}" not in switch.sent_lines
    assert baseline(switch) == before and switch.timer is None
    assert ("batch_return_unverified" in steps(result)) == (rollback == "safeguard-verified")
    assert [(step["result"], step.get("rollback")) for step in result["batch_results"]] == [
        ("reverted", rollback), ("failed", None)]
    assert [step["detail"] for step in result["steps"] if step["step"] == "batch_step_start"] == ["1"]
    assert [step["detail"] for step in result["steps"] if step["step"] == "batch_step_reverted"] == (
        ["1"] if rollback == "verified" else [])


def test_two_acl_steps_verify_reordered_stanzas_and_undo(tmp_path):
    router = G64Ios("iosv")
    runtime = make_runtime(tmp_path, router, accounts=("user01", "user02"))
    before = ios.batch_snapshot(router.snapshot(), router.firmware)
    request = batch(acl("NETOPS-IOS-PORT-OWNERSHIP-Z", rules="10 permit tcp 198.51.100.0/24 any eq 80"), acl("NETOPS-IOS-PORT-OWNERSHIP-A"))
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "ready", preview
    result = execute.apply(runtime, DEVICE, request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert {"NETOPS-IOS-PORT-OWNERSHIP-Z", "NETOPS-IOS-PORT-OWNERSHIP-A"} <= router.acls()["ipv4"].keys()
    look = execute.preview_undo(runtime, result["change_id"], "rollback ACLs", issue=True)
    assert look["result"] == "ready", look
    undo = execute.undo(runtime, result["change_id"], "rollback ACLs", expected_plan_sha256=look["plan_sha256"])
    assert undo["result"] == "confirmed", undo
    assert ios.batch_snapshot(router.snapshot(), router.firmware) == before


def test_acl_created_before_attachment_and_undone_in_reverse_order(tmp_path):
    router = G64Ios("iosv")
    runtime = make_runtime(tmp_path, router, accounts=("user01", "user02"))
    key = "GigabitEthernet0/2:ipv6:in"
    acl_step = acl("NETOPS-IOS-PORT-OWNERSHIP-V6", "ipv6", "10 permit tcp any any eq 80")
    attachment = dict(table="interface-access-group", op="update", key=key,
                      changes={"acl": "NETOPS-IOS-PORT-OWNERSHIP-V6"}, endpoint_impact=key)
    request = batch(acl_step, attachment)
    before = ios.batch_snapshot(router.snapshot(), router.firmware)
    assert execute.preview(runtime, DEVICE, batch(attachment, acl_step))["reason_codes"] == ["ios_acl_undefined"]
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "ready", preview
    assert not router.applied_blocks
    result = execute.apply(runtime, DEVICE, request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", (result["reason"], result["batch_results"], result["steps"])
    assert "ipv6 traffic-filter NETOPS-IOS-PORT-OWNERSHIP-V6 in" in router.interface("GigabitEthernet0/2")
    look = execute.preview_undo(runtime, result["change_id"], "return ACL and attachment", issue=True)
    assert look["result"] == "ready", look
    assert look["commands"].index("no ipv6 traffic-filter NETOPS-IOS-PORT-OWNERSHIP-V6 in") < \
        look["commands"].index("no ipv6 access-list NETOPS-IOS-PORT-OWNERSHIP-V6")
    undo = execute.undo(runtime, result["change_id"], "return ACL and attachment",
                        expected_plan_sha256=look["plan_sha256"])
    assert undo["result"] == "confirmed", undo
    assert ios.batch_snapshot(router.snapshot(), router.firmware) == before


@pytest.mark.parametrize("node,interface", [("iosv", "Loopback900"), ("iosvl2", "Vlan900")])
def test_created_l3_interface_can_be_read_by_the_next_step_and_undone(tmp_path, node, interface):
    device = G62Ios(node)
    runtime = make_runtime(tmp_path, device)
    create = dict(table="l3-interface", op="create", key=interface,
                  changes={"ipv6-address": "2001:db8:68::1/64"})
    second_key = interface[:-1] + "1"
    second = dict(table="l3-interface", op="create", key=second_key, endpoint_impact=second_key,
                  changes={"ipv6-address": "2001:db8:69::1/64"})
    preview = execute.preview(runtime, DEVICE, batch(create, second))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["endpoint_impact_required"], preview
    create["endpoint_impact"] = interface
    confirmed_round_trip(runtime, device, batch(create, second))


def test_dhcp_exclusion_then_pool_against_measured_cli_states(tmp_path):
    device = DhcpIos()
    runtime = make_runtime(tmp_path, device)
    add_pool = pool(POOL)
    only_exclusion = dhcp_state(device, additions=[RANGE])
    both_objects = dhcp_state(device, additions=[RANGE, *add_pool])
    device.replays = [
        ([RANGE], only_exclusion), ([line.strip() for line in add_pool], both_objects),
        (["no ip dhcp pool " + POOL], only_exclusion), (["no " + RANGE], device.lines),
    ]
    exclusion = dict(table="dhcp-exclusion", op="create", key="192.0.2.20-192.0.2.29", changes={})
    pool_step = dict(table="dhcp-pool", op="create", key=POOL,
                     changes={"network": "192.0.2.0/24", "default-router": "192.0.2.1 192.0.2.2",
                              "dns-server": "192.0.2.3 192.0.2.4"})
    confirmed_round_trip(runtime, device, batch(exclusion, pool_step))
    assert not device.replays


def test_two_service_profiles_share_confirmed_batch(tmp_path):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    ntp = dict(table="ntp-server", op="create", key=NTP, changes={})
    syslog = dict(table="syslog-host", op="create", key=SYSLOG, changes={})
    confirmed_round_trip(runtime, device, batch(ntp, syslog))


def test_vlan_membership_and_description_share_a_port_in_the_same_batch(tmp_path):
    switch = FakeIos()
    switch.vlans.add("3780")
    runtime = make_runtime(tmp_path, switch)
    membership = dict(table="vlan-membership", op="update", key=PORT, changes={"access-vlan": 3780})
    confirmed_round_trip(runtime, switch, batch(membership, description(PORT, "NETOPS-IOS-PORT-OWNERSHIP-VLAN")))
    assert "switchport access vlan 3780" in switch.sent_lines
    assert "switchport access vlan 1" in switch.sent_lines


def confirmed_round_trip(runtime, device, request):
    before = ios.batch_snapshot(device.snapshot(), device.firmware)
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "ready", preview
    assert not device.applied_blocks
    result = execute.apply(runtime, DEVICE, request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", (result["reason"], result["batch_results"], result["steps"])
    assert [step["result"] for step in result["batch_results"]] == ["verified", "verified"]
    look = execute.preview_undo(runtime, result["change_id"], "return approved objects", issue=True)
    assert look["result"] == "ready", look
    undo = execute.undo(runtime, result["change_id"], "return approved objects",
                        expected_plan_sha256=look["plan_sha256"])
    assert undo["result"] == "confirmed", (undo["reason"], undo["batch_results"], undo["steps"])
    assert ios.batch_snapshot(device.snapshot(), device.firmware) == before
    assert device.saved == device.lines and device.timer is None


@pytest.mark.parametrize("table,op,key,changes,protected", [
    ("interface", "update", PORT, {"description": "IOS-PORT-OWNERSHIP"}, PORT),
    ("vlan-membership", "update", PORT, {"access-vlan": 10}, PORT),
    ("l3-interface", "create", "Vlan3968", {"ipv4-address": "192.0.2.68/24"}, "Vlan3968"),
    ("l3-interface", "create", "Loopback3968", {"ipv4-address": "192.0.2.68/32"}, "Loopback3968"),
    ("interface-access-group", "update", "Port-channel68:ipv4:in", {"acl": "NETOPS-IOS-PORT-OWNERSHIP-A"}, "Port-channel68"),
    ("dhcp-relay", "create", "Vlan3968:192.0.2.68", {}, "Vlan3968"),
])
def test_protected_interface_covers_every_interface_kind(table, op, key, changes, protected):
    switch = FakeIos()
    request = batch(description(SECOND, "IOS-PORT-OWNERSHIP"), dict(table=table, op=op, key=key, changes=changes))
    with pytest.raises(Rejected) as denied:
        engine.build_plan("ios", switch.snapshot().encode(), request, firmware=switch.firmware,
                          protected={"interface": [protected.lower()]})
    assert denied.value.reason_codes == ["port_protected"]


def test_vtp_server_refuses_vlan_lifecycle_before_writing(tmp_path):
    class Switch(FakeIos):
        def snapshot(self):
            return ios.with_vlan_database(super().snapshot(), fixture("switch-vlan-brief.txt"))

    switch = Switch()
    switch.query_override["show vtp status"] = fixture("switch-vtp.txt")
    runtime = make_runtime(tmp_path, switch)
    request = batch(description(PORT, "NETOPS-IOS-PORT-OWNERSHIP"),
                    dict(table="vlan", op="create", key="3968", changes={"name": "NETOPS-IOS-PORT-OWNERSHIP"}))
    preview = execute.preview(runtime, DEVICE, request)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["action_unsupported"], preview
    assert not switch.applied_blocks
