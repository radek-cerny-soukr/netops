"""Cisco IOS and IOS XE (IOSv 15.9(3)M12, IOSvL2 15.2(20200924:215240), IOL XE 17.18.2, IOL-L2 XE 17.18.2): plan,
preview, apply behind the revert-timer safeguard, confirm, expiry, refusals and audit. The device is FakeIos, whose
answers come from measured outputs (fixtures/ios_c45)."""
from __future__ import annotations

import datetime
import json

import pytest
from conftest import request_bytes
from fake_ios import NODES, FakeIos, fixture

from netops_admin import audit_gate, exec_ios, execute, ios
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.request import parse_request

ACCOUNTS = ("netops-admin", "netops-ro")
SECRET_TEXT = "k7c Ios Vb8Wn"
ALL = tuple(NODES)
SWITCHES = ("iosvl2", "iolxe-l2")
ROUTERS = ("iosv", "iolxe")
# configure confirm and configure revert now follow a read of the timer in the same interactive session (task 320)
CONFIRM = [exec_ios.QUERY_TIMER, "configure confirm"]
REVERT_NOW = [exec_ios.QUERY_TIMER, "configure revert now"]


def make_runtime(tmp_path, device, accounts=ACCOUNTS, firmware=None, platform=None, seconds=180):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"lab-ios": Device(
            name="lab-ios", platform=platform or device.platform, address="192.0.2.51", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=firmware or device.firmware, safeguard_seconds=seconds,
            confirm_margin_seconds=45, protected={}, accounts=tuple(accounts),
        )},
    )
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance, require_export=False)
    runtime.monotonic = lambda: device.uptime
    return certify(runtime, device, "lab-ios")


def request(device, **fields):
    fields.setdefault("table", "interface")
    fields.setdefault("op", "update")
    fields.setdefault("key", device.port)
    fields.setdefault("changes", {"description": "netops-c45-test"})
    return parse_request(request_bytes(**fields))


def steps(record):
    return [step["step"] for step in record["steps"]]


def baseline(node):
    return fixture(node, "show-running-config__exec.txt")


# ---- plan adapter on the measured running configurations ----

@pytest.mark.parametrize("node", ALL)
def test_snapshot_of_the_measured_running_configuration(node):
    platform, firmware, switch, port, _path, _seconds = NODES[node]
    snapshot = ios.load(baseline(node), firmware)
    assert snapshot.firmware == firmware and snapshot.hostname.startswith("host")
    assert port in snapshot.interfaces
    assert snapshot.entries("interface")[port].attributes == {"admin-state": "disabled"}
    assert snapshot.entries("vlan-membership")[port].attributes == {}
    assert ("switchport mode access" in snapshot.interface_lines(port)) == switch
    assert snapshot.addressed(port) == []


def test_banners_of_iosv_are_skipped_and_an_open_banner_is_refused():
    text = baseline("iosv")
    assert text.count("banner ") == 3 and "interface GigabitEthernet0/2" in text
    snapshot = ios.load(text, "15.9(3)M12")
    assert not any(block.header.startswith("IOSv") for block in snapshot.blocks)
    cut = text[:text.index("banner login")] + "banner login ^C\nopen text\nend\n"
    with pytest.raises(SnapshotRejected) as caught:
        ios.load(cut, "15.9(3)M12")
    assert caught.value.category == "snapshot unreadable"


@pytest.mark.parametrize("text, category", [
    (baseline("iosvl2").replace("Building configuration...", ""), "snapshot unreadable"),
    (baseline("iosvl2").rsplit("end", 1)[0], "snapshot incomplete"),
    ("\n\nLine has invalid autocommand \"show running-config\"\n", "snapshot unreadable"),
])
def test_an_incomplete_or_refused_snapshot_is_refused(text, category):
    with pytest.raises(SnapshotRejected) as caught:
        ios.load(text, "15.2(20200924:215240)")
    assert caught.value.category == category


def test_another_release_train_than_configured_is_refused_and_the_firmware_is_required():
    with pytest.raises(SnapshotRejected) as caught:
        ios.load(baseline("iosv"), "15.2(20200924:215240)")
    assert caught.value.category == "snapshot firmware mismatch"
    assert ios.load(baseline("iolxe"), "17.18.2").firmware == "17.18.2"
    with pytest.raises(Rejected):
        ios.load(baseline("iolxe"), None)


def test_rest_digest_ignores_the_volatile_header_and_the_own_lines():
    text = baseline("iosvl2")
    plan = build_plan("ios", text.encode(), request(FakeIos("iosvl2")), firmware="15.2(20200924:215240)")
    later = text.replace("! Last configuration change at", "! Last configuration change at 00:00:00 UTC x")
    after = later.replace("interface GigabitEthernet1/0\n", "interface GigabitEthernet1/0\n description "
                                                              "netops-c45-test\n")
    assert verify(plan, after.encode())["result"] == "match"
    foreign = after.replace("interface GigabitEthernet1/1\n", "interface GigabitEthernet1/1\n description x\n")
    assert verify(plan, foreign.encode())["rest_matches"] is False


def test_plan_renders_configure_terminal_lines_and_the_inverse():
    device = FakeIos("iosv")
    plan = build_plan("ios", baseline("iosv").encode(), request(device, changes={
        "description": "netops-c45-test", "admin-state": "enabled"}), firmware=device.firmware)
    assert plan["commands"] == ["configure terminal", "interface GigabitEthernet0/2", "no shutdown",
                                "description netops-c45-test", "end"]
    assert plan["inverse"] == ["configure terminal", "interface GigabitEthernet0/2", "shutdown", "no description",
                               "end"]
    assert plan["predicted"] == {"before": {"admin-state": "disabled"}, "after": {"description": "netops-c45-test"}}
    assert "WHOLE running configuration" in plan["rollback_evidence"]


def test_access_vlan_plan_returns_to_vlan_1_by_name():
    device = FakeIos("iolxe-l2")
    plan = build_plan("iosxe", baseline("iolxe-l2").encode(), request(
        device, table="vlan-membership", changes={"access-vlan": 10}), firmware="17.18.2")
    assert plan["commands"] == ["configure terminal", "interface Ethernet0/1", "switchport access vlan 10", "end"]
    assert plan["inverse"] == ["configure terminal", "interface Ethernet0/1", "switchport access vlan 1", "end"]


@pytest.mark.parametrize("node, fields, code", [
    ("iosv", {"key": "GigabitEthernet0/1.10"}, "port_unsupported_interface"),
    ("iosv", {"key": "Loopback0"}, "port_unsupported_interface"),
    ("iosvl2", {"key": "Vlan99"}, "port_unsupported_interface"),
    ("iosvl2", {"key": "GigabitEthernet0/1", "changes": {"admin-state": "disabled"}}, "port_uplink"),
    ("iosvl2", {"key": "GigabitEthernet0/2", "table": "vlan-membership", "changes": {"access-vlan": 20}},
     "port_uplink"),
    ("iosv", {"key": "GigabitEthernet0/0", "changes": {"admin-state": "disabled"}}, "port_ip_address"),
    ("iosv", {"key": "GigabitEthernet0/1", "changes": {"admin-state": "disabled"}}, "port_ip_address"),
    ("iolxe", {"key": "Ethernet0/1", "changes": {"admin-state": "disabled"}}, "port_ip_address"),
    ("iolxe-l2", {"table": "vlan-membership", "changes": {"access-vlan": 1002}}, "vlan_reserved"),
])
def test_plan_refusals_carry_codes(node, fields, code):
    device = FakeIos(node)
    with pytest.raises(Rejected) as caught:
        build_plan(device.platform, baseline(node).encode(), request(device, **fields), firmware=device.firmware)
    assert caught.value.reason_codes == [code]


def _with_lines(text, name, extra):
    return text.replace("interface %s\n" % name, "interface %s\n%s" % (name, "".join(" %s\n" % line for line in extra)),
                        1)


@pytest.mark.parametrize("extra, code", [
    (("channel-group 1 mode active",), "port_lag_member"),
    (("no switchport",), "port_routed"),
    (("switchport mode dynamic desirable",), "port_uplink"),
])
def test_enabling_a_disabled_protected_port_is_refused_in_the_plan(extra, code):
    text = _with_lines(baseline("iosvl2"), "GigabitEthernet1/0", extra)
    device = FakeIos("iosvl2")
    with pytest.raises(Rejected) as caught:
        build_plan("ios", text.encode(), request(device, changes={"admin-state": "enabled"}), firmware=device.firmware)
    assert caught.value.reason_codes == [code]
    plan = build_plan("ios", text.encode(), request(device), firmware=device.firmware)
    assert plan["predicted"]["after"] == {"description": "netops-c45-test", "admin-state": "disabled"}


def test_an_interface_in_a_management_vrf_is_refused():
    text = _with_lines(baseline("iolxe"), "Ethernet0/2", ("vrf forwarding Mgmt-intf",))
    with pytest.raises(Rejected) as caught:
        build_plan("iosxe", text.encode(), request(FakeIos("iolxe")), firmware="17.18.2")
    assert caught.value.reason_codes == ["port_management_interface"]


def test_missing_interface_is_refused():
    device = FakeIos("iosv")
    with pytest.raises(Rejected) as caught:
        build_plan("ios", baseline("iosv").encode(), request(device, key="GigabitEthernet9/9"), firmware=device.firmware)
    assert "not in the running configuration" in caught.value.reasons[0]


def test_disruptive_covers_the_admin_state_in_both_directions():
    assert ios.disruptive("interface", {}, {"admin-state": "disabled"})
    assert ios.disruptive("interface", {"admin-state": "disabled"}, {})
    assert not ios.disruptive("interface", {"admin-state": "disabled"}, {"admin-state": "disabled",
                                                                          "description": "x"})
    assert ios.disruptive("vlan-membership", {}, {"access-vlan": "10"})


# ---- measured answers ----

@pytest.mark.parametrize("node", ALL)
def test_measured_answers_of_every_node(node):
    platform, firmware, switch, port, path, _seconds = NODES[node]
    version = ios.version(fixture(node, "show-version.txt"))
    assert version["version"] == firmware and version["switch"] == switch and version["xe"] == (platform == "iosxe")
    assert ios.privilege(fixture(node, "show-privilege__admin-priv15.txt")) == 15
    assert ios.privilege(fixture(node, "show-privilege__ro-priv1.txt")) == 1
    assert exec_ios.parse_timer(fixture(node, "show-archive-config-rollback-timer__none.txt")) is None
    pending = exec_ios.parse_timer(fixture(node, "show-archive-config-rollback-timer__pending.txt"))
    assert pending["minutes"] == 1 and pending["user"] == "netops-admin" and pending["type"] == "absolute timer"
    when, zone = exec_ios.parse_clock(fixture(node, "show-clock.txt"))
    assert zone == ("CET" if platform == "iosxe" else "UTC") and pending["zone"] == zone
    assert isinstance(when, datetime.datetime)
    assert ios.archive(fixture(node, "show-archive__baseline.txt")) == {"maximum": 14, "path": path + "netops-archive-",
                                                                       "recent": None}
    assert ios.archive(fixture(node, "show-archive__pending.txt"))["recent"].startswith(path + "netops-archive-")
    assert ios.unsaved(fixture(node, "show-archive-config-differences-startup-running__baseline.txt")) == []
    assert ios.users(fixture(node, "show-users__single.txt")) == (1, 0)
    assert ios.users(fixture(node, "show-users__two-sessions-pending.txt"))[1] == 1
    assert ios.description_row(fixture(node, "show-interfaces-description__ro-baseline.txt"), port) == {
        "status": "admin down", "description": ""}
    assert ios.short_name(port) not in ios.lldp_ports(fixture(node, "show-lldp-neighbors__baseline.txt"))
    assert ios.cdp_name(port) not in ios.cdp_ports(fixture(node, "show-cdp-neighbors__baseline.txt"))
    addresses = ios.session_addresses(fixture(node, "show-tcp-brief__exec.txt"))
    interfaces = ios.ip_interfaces(fixture(node, "show-ip-interface-brief__baseline.txt"))
    assert len(addresses) == 1 and port not in {interfaces.get(address) for address in addresses}
    assert ios.refused(fixture(node, "exec__invalid-command__rc0.txt"))
    assert ios.refused(fixture(node, "exec__ro-show-running-config-denied__rc0.txt"))
    assert ios.cli_error("echo\n" + fixture(node, "show-archive-config-rollback-timer__ro.txt"))
    assert ios.cli_error("echo\n" + fixture(node, "configure-terminal-revert-timer__second-while-pending.txt"))
    assert ios.cli_error("echo\n" + fixture(node, "config__interface-nonexistent.txt"))
    for name in ("configure-terminal-revert-timer-1__empty-safeguard.txt", "configure-confirm__ok.txt",
                 "configure-confirm__nothing-pending.txt", "write-memory__after-confirm.txt"):
        assert ios.cli_error("echo\n" + fixture(node, name)) is None, name


@pytest.mark.parametrize("node", SWITCHES)
def test_measured_switch_answers(node):
    port = NODES[node][3]
    assert ios.switchport(fixture(node, "show-interfaces-port-switchport__ro-baseline.txt"), port) == {
        "mode": "static access", "access-vlan": "1"}
    assert ios.vlan_exists(fixture(node, "show-vlan-id-10__exec.txt"), "10")
    assert ios.vlan_exists(fixture(node, "show-vlan-id-333__pending.txt"), "333")
    assert not ios.vlan_exists(fixture(node, "show-vlan-id-3999__missing.txt"), "3999")
    assert ios.learned_macs(fixture(node, "show-mac-address-table-interface__baseline.txt"), port) == 0
    assert ios.cli_error("echo\n" + fixture(node, "config__switchport-access-vlan-3999-nonexistent.txt"))


@pytest.mark.parametrize("node", ROUTERS)
def test_measured_router_answers(node):
    assert ios.cli_error("echo\n" + fixture(node, "config__switchport-access-vlan-10-router.txt"))
    assert ios.switchport(fixture(node, "exec__invalid-command__rc0.txt"), NODES[node][3]) is None


def test_lldp_rows_with_a_cut_device_id_and_cdp_rows_on_two_lines():
    assert ios.lldp_ports(fixture("iosvl2", "show-lldp-neighbors__baseline.txt")) == {"Gi0/0", "Gi0/1", "Gi0/2"}
    assert ios.cdp_ports(fixture("iosvl2", "show-cdp-neighbors__baseline.txt")) == {"Gig0/0", "Gig0/1"}
    assert ios.cdp_ports(fixture("iolxe", "show-cdp-neighbors__baseline.txt")) <= {"Eth0/0", "Eth0/1"}
    assert ios.lldp_ports("% LLDP is not enabled\n") == set() and ios.cdp_ports("% CDP is not enabled\n") == set()
    with pytest.raises(Rejected) as caught:
        ios.lldp_ports("garbage")
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_the_certificate_diff_of_ios_xe_is_no_unsaved_change():
    text = fixture("iolxe", "show-archive-config-differences-startup-running__baseline.txt")
    assert "crypto pki certificate chain" in text and ios.unsaved(text) == []
    assert ios.unsaved(text.replace("crypto pki certificate chain TP", "interface Ethernet0/2\n +description x\n"
                                    "crypto pki certificate chain TP", 1)) == ["interface Ethernet0/2",
                                                                                " +description x"]


def test_the_log_proves_fired_and_confirmed_timers_of_the_own_archive():
    events = ios.archive_events(fixture("iosvl2", "show-logging-archive__fired.txt"))
    names = [text.split("to config ")[1].split(" in ")[0] for event, text in events if event == "START_ABSTIMER"]
    assert len(names) == 4
    assert ios.archive_outcome(events, names[0], "netops-admin") == "confirmed"
    assert ios.archive_outcome(events, names[1], "netops-admin") == "fired"  # revert now ends in a rollback too
    assert ios.archive_outcome(events, names[2], "netops-admin") == "confirmed"
    assert ios.archive_outcome(events, names[3], "netops-admin") == "fired"
    assert ios.archive_outcome(events, names[3], "someone") == "fired"
    assert ios.archive_outcome(events, "flash:other", "netops-admin") is None
    assert ios.archive_outcome([], names[3], "netops-admin") is None


def test_users_of_an_iosv_line_number_without_space():
    text = "    Line       User       Host(s)              Idle       Location\n" \
           "*578 vty 0     netops-adm idle                 00:00:00 192.0.2.36\n" \
           " 579 vty 1     admin      idle                 00:00:00 192.0.2.40\n"
    assert ios.users(text) == (1, 1)


# ---- preview, apply, confirm, undo on every node ----

@pytest.mark.parametrize("node", ALL)
def test_preview_reads_and_writes_nothing(tmp_path, node):
    device = FakeIos(node)
    result = execute.preview(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert result["result"] == "ready", result
    assert result["platform"] == device.platform and result["firmware"] == device.firmware
    assert result["commands"][0] == "configure terminal" and len(result["plan_sha256"]) == 64
    assert device.applied_blocks == [] and device.check_queries
    assert any("does not carry the management address" in check for check in result["prechecks"])


@pytest.mark.parametrize("node", ALL)
def test_description_is_confirmed_saved_after_the_confirmation_and_undone(tmp_path, node):
    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ios", request(device))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.applied_blocks[0] == ["configure terminal revert timer 3", "end"]
    assert device.applied_blocks[1] == ["configure terminal", "interface %s" % device.port,
                                        "description netops-c45-test", "end"]
    assert device.applied_blocks[2] == CONFIRM
    assert device.applied_blocks[3] == ["write memory"]
    assert device.saves == 1 and device.saved_while_pending == 0 and device.timer is None
    assert "description netops-c45-test" in device.interface(device.port)
    assert record["safeguard"]["archive"] == device.archives[-1] and record["safeguard"]["minutes"] == 3
    assert any("CONFIRM" in line for line in device.log)
    assert "check_identity_passed" in steps(record) and steps(record)[-1] == "configuration_saved"
    undone = execute.undo(runtime, record["change_id"], "operator asked to undo")
    assert undone["result"] == "confirmed"
    assert "description netops-c45-test" not in device.interface(device.port)
    assert device.lines == device.saved and device.timer is None and device.saved_while_pending == 0


@pytest.mark.parametrize("node", ALL)
def test_no_shutdown_and_shutdown(tmp_path, node):
    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    up = execute.apply(runtime, "lab-ios", request(device, changes={"admin-state": "enabled"}, request_id="req-up-1"))
    assert up["result"] == "confirmed", (up["reason"], steps(up))
    assert "shutdown" not in device.interface(device.port)
    down = execute.apply(runtime, "lab-ios", request(device, changes={"admin-state": "disabled"},
                                                     request_id="req-down-1"))
    assert down["result"] == "confirmed" and "shutdown" in device.interface(device.port)
    assert device.saves == 2 and device.saved_while_pending == 0


@pytest.mark.parametrize("node", SWITCHES)
def test_access_vlan_is_confirmed_and_undone(tmp_path, node):
    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ios", request(device, table="vlan-membership", changes={"access-vlan": 10}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert "switchport access vlan 10" in device.interface(device.port)
    assert "show interfaces %s switchport" % device.port in device.check_queries
    assert "VLAN 10 exists" in record["plan"]["prechecks"]
    assert execute.undo(runtime, record["change_id"], "back to VLAN 1")["result"] == "confirmed"
    assert device.applied_blocks[-3][2] == "switchport access vlan 1"
    assert not any(line.startswith("switchport access vlan") for line in device.interface(device.port))
    assert device.vlans == {"1", "10", "20", "99"}


@pytest.mark.parametrize("node", ROUTERS)
def test_access_vlan_on_a_router_is_refused_before_any_write(tmp_path, node):
    device = FakeIos(node)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ios",
                      request(device, table="vlan-membership", changes={"access-vlan": 10}))
    if node == "iosv":
        assert "is not measured on firmware '15.9(3)M12'" in caught.value.reasons[0]
    else:
        assert caught.value.reason_codes == ["port_routed"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("node, fields, code", [
    ("iosvl2", {"table": "vlan-membership", "changes": {"access-vlan": 3999}}, "vlan_missing"),
    ("iolxe-l2", {"table": "vlan-membership", "changes": {"access-vlan": 333}}, "vlan_missing"),
    ("iosvl2", {"table": "vlan-membership", "changes": {"access-vlan": 99}}, "port_management_vlan"),
    ("iosvl2", {"key": "GigabitEthernet0/0"}, "port_management_vlan"),
    ("iolxe-l2", {"key": "Ethernet0/0", "changes": {"admin-state": "disabled"}}, "port_management_vlan"),
    ("iosv", {"key": "GigabitEthernet0/0"}, "port_management_interface"),
    ("iolxe", {"key": "Ethernet0/0"}, "port_management_interface"),
    ("iosvl2", {"key": "GigabitEthernet0/1", "changes": {"description": "x"}}, None),
])
def test_missing_vlan_and_management_are_refused_with_zero_writes(tmp_path, node, fields, code):
    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ios", request(device, **fields))
    if code is None:
        assert preview["result"] == "ready", preview
        return
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code], preview
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab-ios", request(device, **fields))
    assert device.applied_blocks == [] and device.vlans <= {"1", "10", "20", "99"}


@pytest.mark.parametrize("node, prepare, code", [
    ("iosvl2", lambda fake: fake.lldp_extra.append("GigabitEthernet1/0"), "port_lldp_neighbor"),
    ("iolxe-l2", lambda fake: fake.cdp_extra.append("Ethernet0/1"), "port_lldp_neighbor"),
    ("iosv", lambda fake: fake.cdp_extra.append("GigabitEthernet0/2"), "port_lldp_neighbor"),
    ("iosvl2", lambda fake: fake.learned_macs.__setitem__("GigabitEthernet1/0", 2), "port_learned_mac"),
    ("iolxe-l2", lambda fake: fake.learned_macs.__setitem__("Ethernet0/1", 1), "port_learned_mac"),
])
@pytest.mark.parametrize("state", ("enabled", "disabled"))
def test_port_in_use_is_refused_in_both_directions_before_any_write(tmp_path, node, prepare, code, state):
    device = FakeIos(node)
    prepare(device)
    if state == "disabled":
        start = device.lines.index("interface %s" % device.port)
        device.lines = [line for index, line in enumerate(device.lines) if not (
            index > start and line == " shutdown" and index < start + 4)]
        device.saved = list(device.lines)
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device, changes={"admin-state": state}))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == []


def test_a_port_that_is_not_static_access_is_refused_on_the_switch(tmp_path):
    device = FakeIos("iolxe-l2")
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab-ios",
                      request(device, key="Ethernet0/2", changes={"admin-state": "enabled"}))
    assert caught.value.reason_codes == ["port_uplink"] and device.applied_blocks == []


def test_a_pending_timer_of_anyone_is_refused(tmp_path):
    device = FakeIos("iosv")
    device.foreign_timer = {"configured": device.now, "minutes": 10, "user": "admin"}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), "lab-ios", request(device))
    assert caught.value.reason_codes == ["rollback_timer_pending"] and device.applied_blocks == []
    device.foreign_timer["user"] = "netops-admin"
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), "lab-ios", request(device, request_id="req-own-left"))
    assert "a safeguard of an earlier operation is still installed" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_archive_not_configured_privilege_and_unsaved_changes_are_refused(tmp_path):
    device = FakeIos("iolxe")
    device.query_override["show archive"] = "\n%Archive feature not enabled\n"
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device), "lab-ios", request(device))
    assert caught.value.reason_codes == ["archive_not_configured"]
    device = FakeIos("iolxe")
    device.privilege = 1
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device), "lab-ios", request(device))
    assert caught.value.reason_codes == ["write_account_privilege"]
    device = FakeIos("iolxe")
    device.saved = [line for line in device.saved if line != " shutdown"]
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "c", device), "lab-ios", request(device))
    assert "unsaved configuration changes" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_another_firmware_or_platform_than_the_device_is_refused(tmp_path):
    device = FakeIos("iolxe")
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "a", device, platform="ios"), "lab-ios", request(device))
    assert any("not the configured platform ios" in reason for reason in caught.value.reasons)
    device = FakeIos("iosvl2")
    device.firmware = "15.2(20200924:000000)"
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path / "b", device, firmware="15.2(20200924:215240)"), "lab-ios",
                      request(device))
    assert device.applied_blocks == []


# ---- the safeguard returns an unconfirmed change ----

@pytest.mark.parametrize("node", ALL)
@pytest.mark.parametrize("log_lost", (False, True))
def test_lost_check_account_leaves_the_change_unconfirmed_and_the_timer_reverts_it(tmp_path, node, log_lost):
    device = FakeIos(node)
    device.log_lost = log_lost

    def lose_check_account(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios",
                           request(device, changes={"description": "netops-c45-b", "admin-state": "enabled"}))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    assert device.interface(device.port) == FakeIos(node).interface(device.port) and device.timer is None
    assert any("ROLLBACK_START" in line and record["safeguard"]["archive"] in line for line in device.log)
    assert REVERT_NOW in device.applied_blocks
    assert not any(block == CONFIRM for block in device.applied_blocks)
    assert device.saved_while_pending == 0 and device.lines == device.saved


def test_check_account_mismatch_is_reverted(tmp_path):
    device = FakeIos("iosvl2")

    def stale(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_override = {"show interfaces description": fixture(
                "iosvl2", "show-interfaces-description__ro-baseline.txt")}

    device.on_apply = stale
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert device.interface(device.port) == ["switchport mode access", "shutdown", "negotiation auto"]


def cleanup_blocks(device) -> list:
    return [block for block in device.applied_blocks
            if block in (CONFIRM, REVERT_NOW, ["write memory"])]


def test_a_timer_of_another_user_is_never_confirmed(tmp_path):
    device = FakeIos("iolxe")
    device.timer_user = "admin"
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "unknown" and record["reason"] == "safeguard not verified", steps(record)
    assert cleanup_blocks(device) == []
    assert not any(block[:1] == ["configure terminal"] for block in device.applied_blocks)


@pytest.mark.parametrize("node", ("iosvl2", "iolxe"))
@pytest.mark.parametrize("user", ("netops-admin", "admin"))
def test_a_second_timer_is_refused_by_the_device_and_never_touched(tmp_path, node, user):
    """Review 315 finding 1: the prechecks see no timer, then another session (also of the same account and with the
    same minutes and time) starts one; the own request is refused with "already activated". Admin never confirms,
    returns or saves over that timer, whatever its account and time."""
    device = FakeIos(node)

    def foreign(fake, block):
        if block[:1] == ["configure terminal revert timer 3"]:
            fake.foreign_timer = {"configured": fake.now, "minutes": 3, "user": user}

    device.on_apply = foreign
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ios", request(device))
    assert record["result"] == "rejected" and record["reason"] == "safeguard refused by the device", steps(record)
    assert record["reason_codes"] == ["rollback_timer_pending"]
    assert record["safeguard"]["install"] == "refused" and "verified" not in record["safeguard"]
    assert steps(record)[-1] == "safeguard_not_verified"
    assert device.applied_blocks == [["configure terminal revert timer 3", "end"]]
    assert device.foreign_touched == [] and device.foreign_timer is not None and device.archives == []
    assert not exec_ios.remove_safeguard(device, record, exec_ios.prompt_spec(device.hostname))
    assert not exec_ios.revert_now(device, record, exec_ios.prompt_spec(device.hostname))
    assert device.foreign_touched == [] and len(device.applied_blocks) == 1


def test_a_timer_of_the_own_account_and_time_without_own_proof_is_not_owned(tmp_path):
    """The tolerance by account and time alone is gone: a record without the proof of the own session (verified)
    never owns a pending timer, even with the same time configured and minutes."""
    device = FakeIos("iosv")
    device.foreign_timer = {"configured": device.now, "minutes": 3, "user": "netops-admin"}
    configured = device.now.strftime("%Y-%m-%d %H:%M:%S")
    record = {"change_id": "c6" * 16, "safeguard": {"fire_at": exec_ios.FIRE_AT_TEXT, "configured": configured,
                                                    "minutes": 3, "seconds": 180}}
    spec = exec_ios.prompt_spec(device.hostname)
    assert exec_ios.safeguard_state(device, record) == "absent"
    assert not exec_ios.remove_safeguard(device, record, spec) and not exec_ios.revert_now(device, record, spec)
    assert device.foreign_touched == [] and device.applied_blocks == []
    record["safeguard"]["verified"] = True
    assert exec_ios.safeguard_state(device, record) == "armed"


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_an_unverified_own_installation_is_left_to_the_device_and_never_confirmed(tmp_path, node):
    """The own session reported the archive, but the timer is not readable afterwards: unknown, no confirm, no
    revert now, no write memory; the timer returns the empty change itself and recover does not confirm it."""
    device = FakeIos(node)
    reads = []

    def unreadable(fake, command):
        if command == "show archive config rollback timer" and fake.archives:
            reads.append(command)
            if len(reads) == 1:
                raise Rejected(["read failed"])

    device.on_query = unreadable
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ios", request(device))
    assert record["result"] == "unknown" and record["reason"] == "safeguard not verified", steps(record)
    assert record["safeguard"]["archive"] == device.archives[-1] and "verified" not in record["safeguard"]
    assert cleanup_blocks(device) == [] and device.timer is not None
    assert execute.recover(runtime, "lab-ios")[-1]["change_id"] == record["change_id"]
    assert cleanup_blocks(device) == [] and device.timer is not None
    device.advance(200)
    assert device.timer is None and device.lines == device.saved


# ---- the safeguard protects the whole write (review 315 finding 2) ----

def test_the_shortest_timer_is_two_minutes():
    assert [exec_ios._minutes(seconds) for seconds in (60, 61, 120, 121, 180, 900)] == [2, 2, 2, 3, 3, 15]
    device = type("D", (), {"safeguard_seconds": 60})()
    assert exec_ios.timer_seconds(device) == pytest.approx(117.6)
    # until the write about 13 s are spent; then the write, the readback and the smallest confirm margin
    needed = 13 + exec_ios.WRITE_BUDGET_SECONDS + exec_ios.READBACK_BUDGET_SECONDS
    assert needed + 15 > 60 * (1 - exec_ios.DRIFT_FRACTION) and needed + 45 < exec_ios.timer_seconds(device)


@pytest.mark.parametrize("node", ("iosvl2", "iolxe"))
def test_slow_reads_after_the_installation_leave_the_change_unwritten(tmp_path, node):
    device = FakeIos(node)

    def slow(fake, command):
        if command == "show archive" and fake.archives:
            fake.advance(60)

    device.on_query = slow
    record = execute.apply(make_runtime(tmp_path, device, seconds=120), "lab-ios", request(device))
    assert record["result"] == "reverted" and record["reason"] == "no time left to write", steps(record)
    assert "change_not_written" in steps(record) and "change_start" not in steps(record)
    assert not any(block[:1] == ["configure terminal"] for block in device.applied_blocks)
    assert device.applied_blocks[1:] == [REVERT_NOW, ["write memory"]]
    assert device.timer is None and device.lines == device.saved and device.saved_while_pending == 0


def test_a_timer_that_is_gone_before_the_write_leaves_the_change_unwritten(tmp_path):
    device = FakeIos("iosv")

    def confirmed_by_someone(fake, command):
        if command == "show archive" and fake.archives and fake.timer is not None:
            fake.timer = None

    device.on_query = confirmed_by_someone
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert "change_not_written" in steps(record) and "change_start" not in steps(record), steps(record)
    assert record["result"] == "reverted" and record["reason"] == "no time left to write"
    assert "revert_now_unverified" in steps(record) and device.lines == device.saved
    assert not any(block[:1] == ["configure terminal"] for block in device.applied_blocks)
    assert REVERT_NOW not in device.applied_blocks and CONFIRM not in device.applied_blocks


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_a_line_is_not_sent_when_the_timer_is_nearly_over(tmp_path, node):
    device = FakeIos(node)

    def slow_lines(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.line_seconds = 28

    device.on_apply = slow_lines
    record = execute.apply(make_runtime(tmp_path, device, seconds=120), "lab-ios",
                           request(device, changes={"description": "netops-c45-b", "admin-state": "enabled"}))
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    assert device.unsent_lines == 1 and "revert_now_done" in steps(record)
    assert device.applied_blocks[2] == REVERT_NOW and device.uptime >= 112
    assert device.interface(device.port) == FakeIos(node).interface(device.port) and device.timer is None


# ---- the timer is read again in the session of configure confirm and configure revert now (task 320) ----

def installed(node):
    device = FakeIos(node)
    record = {"change_id": "c7" * 16, "safeguard": {"fire_at": exec_ios.FIRE_AT_TEXT}}
    spec = exec_ios.prompt_spec(device.hostname)
    assert exec_ios.install_safeguard(device, record, {}, type("D", (), {"safeguard_seconds": 120})(), spec) == []
    return device, record, spec


def foreign_timer(user):
    def start(fake, block):
        if block in (CONFIRM, REVERT_NOW):
            fake.timer = None
            fake.advance(1)
            fake.foreign_timer = {"configured": fake.now, "minutes": 2, "user": user}
    return start


def gone(fake, block):
    if block in (CONFIRM, REVERT_NOW):
        fake.timer = None


@pytest.mark.parametrize("node", ("iosv", "iolxe"))
def test_the_own_timer_read_in_the_same_session_is_confirmed_and_returned(node):
    device, record, spec = installed(node)
    sent = len(device.sent_lines)
    assert exec_ios.remove_safeguard(device, record, spec)
    assert device.sent_lines[sent:] == CONFIRM and device.timer is None
    assert any("CONFIRM" in line for line in device.log)
    device, record, spec = installed(node)
    sent = len(device.sent_lines)
    assert exec_ios.revert_now(device, record, spec)
    assert device.sent_lines[sent:] == REVERT_NOW and device.timer is None
    assert any("REVERTNOW" in line for line in device.log)


@pytest.mark.parametrize("node", ("iosvl2", "iolxe-l2"))
@pytest.mark.parametrize("user", ("netops-admin", "admin"))
def test_a_foreign_timer_seen_in_the_session_right_before_the_command_is_never_touched(node, user):
    """The exec read still shows the own timer; in the interactive session, right before the command, another
    session has ended it and started its own (also of the same account): nothing is sent, the answer is the one of
    a timer that is not the own one (False), and the foreign timer stays."""
    for command, call in (("configure confirm", exec_ios.remove_safeguard), ("configure revert now",
                                                                          exec_ios.revert_now)):
        device, record, spec = installed(node)
        device.on_apply = foreign_timer(user)
        assert call(device, record, spec) is False
        assert device.sent_lines[-1] == exec_ios.QUERY_TIMER and command not in device.sent_lines
        assert device.foreign_touched == [] and device.foreign_timer is not None


@pytest.mark.parametrize("node", ("iosv", "iolxe"))
def test_a_timer_gone_in_the_session_right_before_the_command_leaves_it_unsent(node):
    """The own timer ended between the exec read and the session (someone confirmed it): configure confirm is not
    sent and the own timer is reported absent (True, as when the exec read already shows no timer); configure revert
    now is not sent and reports no return (False, execute.py waits for the expiry and judges the configuration)."""
    device, record, spec = installed(node)
    device.on_apply = gone
    assert exec_ios.remove_safeguard(device, record, spec) is True
    assert device.sent_lines[-1] == exec_ios.QUERY_TIMER and "configure confirm" not in device.sent_lines
    device, record, spec = installed(node)
    device.on_apply = gone
    assert exec_ios.revert_now(device, record, spec) is False
    assert device.sent_lines[-1] == exec_ios.QUERY_TIMER and "configure revert now" not in device.sent_lines


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_a_foreign_timer_before_the_confirmation_leaves_the_operation_unknown(tmp_path, node):
    device = FakeIos(node)
    device.on_apply = foreign_timer("netops-admin")
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "unknown" and record["reason"] == "confirmation unverified", steps(record)
    assert "confirm_unverified" in steps(record) and "revert_now_unverified" in steps(record)
    assert "configure confirm" not in device.sent_lines and "configure revert now" not in device.sent_lines
    assert device.foreign_touched == [] and device.foreign_timer is not None and device.saves == 0


# ---- a failed write or readback is returned at once (review 315 finding 3) ----

@pytest.mark.parametrize("node", ALL)
def test_a_failed_readback_is_returned_at_once_with_configure_revert_now(tmp_path, node):
    device = FakeIos(node)

    def lose_check_account(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", steps(record)
    assert steps(record)[-3:] == ["revert_now_start", "revert_now_done", "configuration_saved"]
    assert device.applied_blocks[2:] == [REVERT_NOW, ["write memory"]]
    assert device.uptime < 30 and device.timer is None and device.lines == device.saved
    assert any("REVERTNOW" in line for line in device.log) and "show clock" not in device.queries


def test_a_refused_change_line_is_returned_at_once(tmp_path):
    device = FakeIos("iosvl2")

    def remove_port(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.lines = [line.replace("interface GigabitEthernet1/0", "interface GigabitEthernet1/9")
                          for line in fake.lines]

    device.on_apply = remove_port
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "reverted" and record["reason"] == "change failed", steps(record)
    assert REVERT_NOW in device.applied_blocks and device.uptime < 30
    assert device.lines == device.saved and device.timer is None


def test_when_revert_now_fails_the_timer_is_awaited_by_reading_it(tmp_path):
    device = FakeIos("iosv")
    device.revert_now_ignored = True

    def stale(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.check_override = {"show interfaces description": fixture(
                "iosv", "show-interfaces-description__ro-baseline.txt")}

    device.on_apply = stale
    record = execute.apply(make_runtime(tmp_path, device), "lab-ios", request(device))
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch", steps(record)
    assert "revert_now_unverified" in steps(record) and device.uptime >= 180
    assert device.lines == device.saved and device.timer is None and "show clock" not in device.queries


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_the_enrollment_self_test_is_left_to_the_expiry(tmp_path, node):
    from netops_admin import enrollment

    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "sent"
    runtime.store.clear_enrollment("lab-ios")
    record = enrollment.run(runtime, "lab-ios", device.port)
    assert record["result"] == "reverted" and record["reason"] == "enrollment self-test", steps(record)
    assert REVERT_NOW not in device.applied_blocks and device.uptime >= 180


def test_safeguard_minutes_are_rounded_up_and_the_own_timer_is_proven_by_the_own_session():
    device = FakeIos("iosv")
    record = {"change_id": "c4" * 16, "safeguard": {"fire_at": exec_ios.FIRE_AT_TEXT, "name": "netops-c4c4c4c4c4c4"}}
    plan = {"key": device.port}
    problems = exec_ios.install_safeguard(device, record, plan, type("D", (), {"safeguard_seconds": 61})(),
                                          exec_ios.prompt_spec(device.hostname))
    assert problems == [] and device.applied_blocks[-1] == ["configure terminal revert timer 2", "end"]
    item = record["safeguard"]
    assert item["verified"] is True and item["archive"] == device.archives[-1] and item["minutes"] == 2
    assert item["configured"] == device.now.strftime("%Y-%m-%d %H:%M:%S") and item["fire_at"] == exec_ios.FIRE_AT_TEXT
    assert "show clock" not in device.queries
    assert exec_ios.safeguard_state(device, record) == "armed"
    assert not exec_ios.safeguard_absent(device, record) and not exec_ios.safeguard_fired(device, record)
    with pytest.raises(Rejected):
        exec_ios.persist(device, exec_ios.prompt_spec(device.hostname))
    assert device.saves == 0
    device.advance(120)
    assert device.timer is not None and exec_ios.safeguard_state(device, record) == "armed"  # IOS returns in 7 s
    device.advance(7)
    assert device.timer is None and exec_ios.safeguard_state(device, record) == "fired"
    device.log_lost = True
    assert exec_ios.safeguard_state(device, record) == "absent" and exec_ios.safeguard_fired(device, record)


def test_a_confirmed_timer_is_disarmed_by_the_log():
    device = FakeIos("iolxe-l2")
    record = {"change_id": "c5" * 16, "safeguard": {"fire_at": (device.now + datetime.timedelta(seconds=60)).strftime(
        "%Y-%m-%d %H:%M:%S"), "name": "netops-c5c5c5c5c5c5"}}
    spec = exec_ios.prompt_spec(device.hostname)
    assert exec_ios.install_safeguard(device, record, {}, type("D", (), {"safeguard_seconds": 60})(), spec) == []
    assert exec_ios.remove_safeguard(device, record, spec)
    assert exec_ios.safeguard_state(device, record) == "disarmed" and exec_ios.safeguard_disarmed(device, record)


def test_recover_after_an_interrupted_apply_waits_for_the_timer(tmp_path):
    device = FakeIos("iolxe")
    runtime = make_runtime(tmp_path, device)

    class Killed(BaseException):
        pass

    def kill(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.on_apply = None
            fake.apply(block, exec_ios.prompt_spec(fake.hostname))
            raise Killed()

    device.on_apply = kill
    with pytest.raises(Killed):
        execute.apply(runtime, "lab-ios", request(device))
    assert device.timer is not None and "description netops-c45-test" in device.interface(device.port)
    settled = execute.recover(runtime, "lab-ios")
    assert len(settled) == 1 and settled[0]["result"] == "reverted", steps(settled[0])
    assert device.timer is None and device.lines == device.saved
    assert "show clock" not in device.queries and REVERT_NOW not in device.applied_blocks


def interrupted(tmp_path, node):
    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)

    class Killed(BaseException):
        pass

    def kill(fake, block):
        if block[:1] == ["configure terminal"]:
            fake.on_apply = None
            fake.apply(block, exec_ios.prompt_spec(fake.hostname))
            raise Killed()

    device.on_apply = kill
    with pytest.raises(Killed):
        execute.apply(runtime, "lab-ios", request(device))
    return device, runtime


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_recover_reads_the_timer_until_it_ends_without_the_device_clock(tmp_path, node):
    """Review 315 finding 4: recover decides by the state of the timer, read again and again within a limit on the
    monotonic clock of Admin; show clock is never needed (here it is refused) and failed timer reads do not end it."""
    device, runtime = interrupted(tmp_path, node)
    device.query_override["show clock"] = fixture(node, "exec__invalid-command__rc0.txt")
    failures = []

    def flaky(fake, command):
        if command == "show archive config rollback timer" and len(failures) < 3:
            failures.append(command)
            raise Rejected(["read failed"])

    device.on_query = flaky
    settled = execute.recover(runtime, "lab-ios")
    assert len(settled) == 1 and settled[0]["result"] == "reverted", steps(settled[0])
    assert len(failures) == 3 and "show clock" not in device.queries
    assert device.timer is None and device.lines == device.saved and device.saved_while_pending == 0


def test_recover_gives_up_at_its_monotonic_limit_when_the_timer_does_not_end(tmp_path):
    device, runtime = interrupted(tmp_path, "iolxe")
    device.timer["fire"] += datetime.timedelta(hours=2)
    settled = execute.recover(runtime, "lab-ios")
    assert settled[0]["result"] == "unknown" and settled[0]["reason"] == "interrupted", steps(settled[0])
    assert "revert_unverified" in steps(settled[0])
    assert execute.EXPIRY_WAIT_LIMIT_SECONDS <= device.uptime < execute.EXPIRY_WAIT_LIMIT_SECONDS + 60
    assert cleanup_blocks(device) == [] and device.timer is not None and "show clock" not in device.queries


# ---- accounts, audit, enrollment, doctor ----

def test_unexpected_account_blocks_the_device(tmp_path):
    device = FakeIos("iosv")
    runtime = make_runtime(tmp_path, device, accounts=("netops-admin",))
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-ios", request(device))
    assert "accounts differ" in caught.value.reasons[0]
    assert runtime.store.blocked("lab-ios")["reason"] == "administrator table"


def test_audit_log_holds_no_text_and_no_secret(tmp_path):
    device = FakeIos("iolxe-l2")
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab-ios", request(device, changes={"description": SECRET_TEXT}))
    assert record["result"] == "confirmed"
    log = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET_TEXT not in log and "REDIGOVANO" not in log
    start = json.loads(log.splitlines()[0])
    assert start["platform"] == "iosxe" and start["changes"] == {"description": "text of %d characters"
                                                                  % len(SECRET_TEXT)}
    assert start["safeguard"] == record["safeguard"]["name"]


def test_audit_gate_has_no_ios_rules_and_refuses_a_policy():
    for platform in ("ios", "iosxe"):
        assert audit_gate.rule_count(platform) == 0
        assert audit_gate.baseline(platform, baseline("iosv"), "lab-ios") == {}
        with pytest.raises(Rejected):
            audit_gate.evaluate(platform, baseline("iosv"), {"required_rules": []}, "interface")


@pytest.mark.parametrize("node", ("iosv", "iolxe-l2"))
def test_enrollment_self_test_changes_the_description_and_is_reverted(tmp_path, node):
    from netops_admin import enrollment

    device = FakeIos(node)
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "sent"
    runtime.store.clear_enrollment("lab-ios")
    record = enrollment.run(runtime, "lab-ios", device.port)
    assert record["result"] == "reverted" and record["reason"] == "enrollment self-test", steps(record)
    assert record["plan"]["predicted"]["after"]["description"].startswith("netops-enroll-")
    assert record.get("enrollment") == "valid", steps(record)
    assert device.interface(device.port) == FakeIos(node).interface(device.port) and device.timer is None


@pytest.mark.parametrize("node", ALL)
def test_doctor_is_ready_after_enrollment(tmp_path, node):
    from netops_admin import readiness

    device = FakeIos(node)
    report = readiness.doctor(make_runtime(tmp_path, device), "lab-ios")
    statuses = {item["check"]: item["status"] for item in report["checks"]}
    assert statuses["check account"] == "ok" and statuses["leftover safeguards"] == "ok", report
    assert statuses["device prechecks"] == "ok" and statuses["enrollment"] == "ok", report
    expected = {"interface": "update", "vlan-membership": "update"}
    if node == "iosv":
        expected["vlan-membership"] = "not measured on this firmware"
    assert report["operations"] == expected


def test_doctor_refuses_a_check_account_with_privilege_15(tmp_path):
    from netops_admin import readiness

    device = FakeIos("iosv")
    device.check_privilege = 15
    report = readiness.doctor(make_runtime(tmp_path, device), "lab-ios")
    statuses = {item["check"]: item["status"] for item in report["checks"]}
    assert statuses["check account"] == "refused" and not report["ready"]


def test_plan_sha256_differs_between_ios_and_ios_xe_targets():
    device = FakeIos("iolxe")
    text = baseline("iolxe").encode()
    first = build_plan("iosxe", text, request(device), firmware="17.18.2", device="lab-a")
    second = build_plan("iosxe", text, request(device), firmware="17.18.2", device="lab-b")
    assert first["plan_sha256"] != second["plan_sha256"] and first["commands"] == second["commands"]
