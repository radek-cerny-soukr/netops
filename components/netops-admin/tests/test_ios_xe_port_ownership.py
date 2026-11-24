"""IOS XE batches through public MCP and the Admin SSH transport boundary."""
import asyncio
from dataclasses import replace
from pathlib import Path
import re

import pytest

from enrollment_helpers import certify
from fake_ios import short
from fake_iosxe_acl import G82Ios
from netops_admin import exec_ios, execute, ios, ios_acl, mcp_server
from netops_admin.access import AccessError
from test_ios import make_runtime
from test_ios_ios_port_ownership import acl, baseline, batch, description
from test_ios_xe_access_control import ACCOUNTS, BASELINE
from test_ios_xe_system_services import XEServiceTransport
from test_mcp_server import call

FIXTURES = Path(__file__).parent / "fixtures" / "ios_xe_port_ownership"
TARGET = "lab-ios"
ROUTER_PORT = "Ethernet1/2"
SWITCH_PORT = "Ethernet0/1"
RULE = "10 permit ip any any"
ACL_NAME = "NETOPS-XE-PORT-OWNERSHIP-713"
ACL_HEADER = "ip access-list extended " + ACL_NAME
NTP = "192.0.2.10"


def fixture(node, output):
    model = "iol-xe-switch" if node == "iolxe-l2" else "iol-xe-router"
    return (FIXTURES / f"{model}-{output}.txt").read_text()


def runtime(tmp_path, monkeypatch, device, accounts=("netops-admin", "netops-ro"), **config):
    rt = make_runtime(tmp_path, device, accounts=accounts, seconds=300)
    rt.config = replace(rt.config, mcp_undo=True, **config)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", rt.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: rt)
    return rt


def arguments(*operations):
    return dict(device=TARGET, table="batch", op="update", key="batch", request_id="xe-port-ownership-mcp-0001",
                changes=list(operations), reason="XE-PORT-OWNERSHIP approved lab plan", user_request="Apply the two lab changes")


def measured_descriptions(device, port):
    text = fixture(device.node, "description")
    value = next((line.removeprefix("description ") for line in device.interface(port)
                  if line.startswith("description ")), "")
    column = text.splitlines()[0].index("Description")
    return "\n".join(line.ljust(column) + value if line.startswith(short(port) + " ") else line
                     for line in text.splitlines()) + "\n"


class Router(G82Ios):
    def check_query(self, command):
        if command == exec_ios.QUERY_DESCRIPTIONS:
            return measured_descriptions(self, ROUTER_PORT)
        return super().check_query(command)


class Switch(XEServiceTransport):
    def __init__(self):
        super().__init__("iolxe-l2")
        self.query_override[f"show interfaces {SWITCH_PORT} switchport"] = fixture(self.node, "switchport")

    def check_query(self, command):
        if command == exec_ios.QUERY_DESCRIPTIONS and command not in (self.check_override or {}):
            return measured_descriptions(self, SWITCH_PORT)
        return super().check_query(command)


class SwitchWithAcl(Switch):
    def _line(self, line, mode):
        if mode[0] == "config":
            if line == ACL_HEADER:
                self.lines.insert(self.lines.index("end"), ACL_HEADER)
                mode[0] = "xe-port-ownership-acl"
                return ""
            if line == "no " + ACL_HEADER:
                start, end = self._block(ACL_HEADER)
                del self.lines[start:end]
                return ""
        if mode[0] == "xe-port-ownership-acl":
            if line == RULE:
                self.lines.insert(self.lines.index(ACL_HEADER) + 1, " " + RULE)
                return ""
            if line == "exit":
                mode[0] = "config"
                return ""
        return super()._line(line, mode)

    def snapshot(self):
        native = super().snapshot()
        if ACL_HEADER not in self.lines:
            return native
        v4 = fixture(self.node, "ipv4-listing")
        v6 = fixture(self.node, "ipv6-listing")
        return ios_acl.with_listing(native, v4 + "\n" + self.acl_listing(), v6)

    def acl_listing(self):
        if ACL_HEADER not in self.lines:
            return fixture(self.node, "acl-absent")
        return fixture(self.node, "acl-created")

    def check_query(self, command):
        if command == f"show ip access-lists {ACL_NAME}":
            return self.acl_listing()
        return super().check_query(command)


def round_trip(rt, device, args):
    before = baseline(device)
    saved = list(device.saved)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "tested"
    assert [step["table"] for step in preview["operations"]] == [step["table"] for step in args["changes"]]
    assert not device.applied_blocks

    missing = call("admin_apply", args)
    assert missing["reason_codes"] == ["plan_changed"]
    assert not device.applied_blocks

    applied = call("admin_apply", dict(args, expected_plan_sha256=preview["plan_sha256"]))
    assert applied["result"] == "confirmed", (applied["operations"], applied["steps"])
    assert [step["result"] for step in applied["operations"]] == ["verified", "verified"]
    assert call("admin_status", {"request_id": args["request_id"]})["operations"] == applied["operations"]
    assert "description NETOPS-XE-PORT-OWNERSHIP" in device.interface(args["changes"][0]["key"])
    change_id = applied["change_id"]
    plan = rt.store.operation(change_id)["plan"]
    assert all(step["ios_batch_step"] for step in plan["batch_steps"])
    assert device.timer is None
    return before, saved, change_id


def undo_round_trip(device, before, change_id, second):
    args = dict(change_id=change_id, reason="Restore the two lab objects")
    preview = call("admin_undo_preview", args)
    assert preview["result"] == "ready", preview
    assert [step["table"] for step in preview["operations"]] == [second, "interface"]
    undone = call("admin_undo", dict(args, expected_plan_sha256=preview["plan_sha256"]))
    assert undone["result"] == "confirmed", undone
    assert baseline(device) == before and device.timer is None


def test_xe_description_and_acl_mcp_round_trip(tmp_path, monkeypatch):
    device = Router(BASELINE)
    rt = runtime(tmp_path, monkeypatch, device, ACCOUNTS)
    name = ACL_NAME
    args = arguments(description(ROUTER_PORT, "NETOPS-XE-PORT-OWNERSHIP"), acl(name, rules=RULE))
    before, _, change_id = round_trip(rt, device, args)
    assert "10 permit ip any any" in device.check_query(f"show ip access-lists {name}")
    undo_round_trip(device, before, change_id, "ip-access-list")
    assert not device.check_query(f"show ip access-lists {name}").strip()


def test_xe_service_batch_keeps_startup_and_undo_works_with_unsaved_running(tmp_path, monkeypatch):
    device = Switch()
    rt = runtime(tmp_path, monkeypatch, device)
    args = arguments(description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP"), dict(table="ntp-server", op="create", key=NTP, changes={}))
    before, saved, change_id = round_trip(rt, device, args)
    assert f"ntp server {NTP}" in device.services
    assert device.saved == saved and device.saves == 0
    undo_round_trip(device, before, change_id, "ntp-server")
    assert device.saved == saved and device.saves == 0


@pytest.mark.parametrize("variant,code", [("truncated", "ios_batch_read_unreadable"),
                                          ("active", "endpoint_impact_required"),
                                          ("timeout", "ios_batch_read_timeout")])
def test_xe_preview_checks_second_step_before_any_write(tmp_path, monkeypatch, variant, code):
    device = Switch()
    runtime(tmp_path, monkeypatch, device)
    text = fixture(device.node, "description")
    if variant == "truncated":
        text = "\n".join(line for line in text.splitlines() if not line.startswith(short(SWITCH_PORT) + " "))
    elif variant == "timeout":
        def fail_read(_device, command):
            if command == exec_ios.QUERY_DESCRIPTIONS:
                raise AccessError("SSH timed out")
        device.on_check_query = fail_read
    else:
        device._set(SWITCH_PORT, re.compile(r"^shutdown$"))
        device.saved = list(device.lines)
        text = text.replace("admin down     down", "up             up")
    device.check_override = {exec_ios.QUERY_DESCRIPTIONS: text}
    ntp = dict(table="ntp-server", op="create", key=NTP, changes={})
    result = call("admin_preview", arguments(ntp, description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP")))
    assert result["reason_codes"] == [code], result
    assert not device.applied_blocks
    if variant == "active":
        result = call("admin_preview", arguments(ntp, description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP", endpoint_impact=SWITCH_PORT)))
        assert result["result"] == "ready", result


@pytest.mark.parametrize("node,port", [("iolxe", ROUTER_PORT), ("iolxe-l2", SWITCH_PORT)])
def test_xe_port_ownership_measured_target_is_idle_on_both_xe_images(node, port):
    assert ios.version(fixture(node, "version"))["version"] == "17.18.2"
    assert ios.description_row(fixture(node, "description"), port, require_table=True)["status"] == "admin down"
    assert exec_ios.parse_timer(fixture(node, "timer")) is None
    assert not fixture(node, "acl-absent").strip()
    assert " shutdown" in fixture(node, "interface").splitlines()


def test_xe_batch_refuses_protected_second_target(tmp_path, monkeypatch):
    device = Switch()
    rt = runtime(tmp_path, monkeypatch, device)
    rt.config.devices[TARGET].protected.update({"interface": [SWITCH_PORT]})
    args = arguments(dict(table="ntp-server", op="create", key=NTP, changes={}),
                     description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP"))
    result = call("admin_preview", args)
    assert result["reason_codes"] == ["port_protected"], result
    assert not device.applied_blocks


@pytest.mark.parametrize("protected_vlans", [[], ["20"]], ids=["unprotected", "protected"])
@pytest.mark.parametrize("table,changes,command", [
    ("interface", {"admin-state": "disabled"}, "shutdown"),
    ("vlan-membership", {"access-vlan": 10}, "switchport access vlan 10"),
], ids=["disable", "access-vlan"])
def test_xe_batch_respects_inventory_access_vlan(tmp_path, protected_vlans, table, changes, command):
    device = Switch()
    device._set(SWITCH_PORT, re.compile(r"^shutdown$"), "switchport access vlan 20")
    device.saved = list(device.lines)
    device.check_override = {exec_ios.QUERY_DESCRIPTIONS: fixture(device.node, "description").replace(
        "admin down     down", "up             up")}
    device.query_override[f"show interfaces {SWITCH_PORT} switchport"] = fixture(device.node, "switchport").replace(
        "Access Mode VLAN: 1 (default)", "Access Mode VLAN: 20 (D20)").replace(
        "Operational Mode: down", "Operational Mode: static access")
    rt = make_runtime(tmp_path, device)
    if protected_vlans:
        rt.config.devices[TARGET].protected["vlan"] = protected_vlans
        certify(rt, device, TARGET)
    port_change = dict(table=table, op="update", key=SWITCH_PORT, changes=changes, endpoint_impact=SWITCH_PORT)
    ntp = dict(table="ntp-server", op="create", key=NTP, changes={})

    result = execute.preview(rt, TARGET, batch(port_change, ntp))

    assert not device.sent_lines
    if protected_vlans:
        assert result["result"] == "rejected" and result["reason_codes"] == ["port_management_vlan"], result
    else:
        assert result["result"] == "ready" and not result["reason_codes"], result
        port, service = result["operations"]
        assert command in port["commands"]
        assert any("Vlan99" in check for check in port["prechecks"])
        assert f"ntp server {NTP}" in service["commands"]


@pytest.mark.parametrize("admin_mode,operational_lines,allowed,protected,reason", [
    ("dynamic desirable", ["trunk"], "10,98-100", [], "port_management_vlan"),
    ("dynamic auto", ["trunk"], "10,19-21", ["20"], "port_management_vlan"),
    ("dynamic desirable", ["trunk"], "10,20", [], None),
    ("dynamic auto", ["static access"], "10,99", [], None),
    ("trunk", ["trunk"], "10,99", [], "port_management_vlan"),
    ("trunk", ["down"], "10,99", [], "port_management_vlan"),
    ("dynamic desirable", [], "10,99", [], "port_usage_unreadable"),
    ("dynamic desirable", [""], "10,99", [], "port_usage_unreadable"),
    ("dynamic desirable", ["unknown"], "10,99", [], "port_usage_unreadable"),
    ("dynamic desirable", ["static access", "trunk"], "10,99", [], "port_usage_unreadable"),
], ids=["negotiated-live-vlan", "negotiated-inventory-vlan", "negotiated-unprotected", "operational-access",
        "configured-trunk", "configured-trunk-down", "missing-mode", "blank-mode", "unknown-mode", "duplicate-mode"])
def test_xe_batch_checks_operational_trunk(tmp_path, admin_mode, operational_lines, allowed, protected, reason):
    device = Switch()
    device._set(SWITCH_PORT, re.compile(r"^shutdown$"), f"switchport trunk allowed vlan {allowed}")
    configured_mode = None if admin_mode == "dynamic auto" else f"switchport mode {admin_mode}"
    device._set(SWITCH_PORT, re.compile(r"^switchport mode "), configured_mode)
    device.saved = list(device.lines)
    status = "down           down" if operational_lines == ["down"] else "up             up"
    device.check_override = {exec_ios.QUERY_DESCRIPTIONS: fixture(device.node, "description").replace(
        "admin down     down", status)}
    switchport = fixture(device.node, "switchport").replace(
        "Administrative Mode: static access", f"Administrative Mode: {admin_mode}").replace(
        "Operational Mode: down\n", "".join(f"Operational Mode: {mode}\n" for mode in operational_lines)).replace(
        "Trunking VLANs Enabled: ALL", f"Trunking VLANs Enabled: {allowed}")
    if admin_mode.startswith("dynamic "):
        switchport = switchport.replace("Negotiation of Trunking: Off", "Negotiation of Trunking: On")
    device.query_override[f"show interfaces {SWITCH_PORT} switchport"] = switchport
    rt = make_runtime(tmp_path, device)
    if protected:
        rt.config.devices[TARGET].protected["vlan"] = protected
        certify(rt, device, TARGET)
    port = dict(table="interface", op="update", key=SWITCH_PORT, changes={"admin-state": "disabled"},
                endpoint_impact=SWITCH_PORT)
    ntp = dict(table="ntp-server", op="create", key=NTP, changes={})

    result = execute.preview(rt, TARGET, batch(port, ntp))

    assert not device.sent_lines
    if reason:
        assert result["result"] == "rejected" and result["reason_codes"] == [reason], result
    else:
        assert result["result"] == "ready" and not result["reason_codes"], result
        change, service = result["operations"]
        assert "shutdown" in change["commands"]
        assert any("Vlan99" in check for check in change["prechecks"])
        assert f"ntp server {NTP}" in service["commands"]


def test_xe_batch_reports_untested_firmware_as_warning(tmp_path, monkeypatch):
    device = Switch()
    device.firmware = "17.18.3"
    runtime(tmp_path, monkeypatch, device)
    args = arguments(description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP"), dict(table="ntp-server", op="create", key=NTP, changes={}))
    result = call("admin_preview", args)
    assert result["result"] == "ready", result
    assert result["firmware_support"]["status"] == "untested"
    assert not device.applied_blocks


def test_mcp_advertises_xe_batch_and_its_endpoint_impact_requirement():
    tools = {tool.name: tool.description for tool in asyncio.run(mcp_server.mcp.list_tools())}
    for name in ("admin_preview", "admin_apply"):
        assert "IOS or IOS XE profile batch" in tools[name]
        assert "The same requirement applies to IOS and IOS XE batches" in tools[name]


def test_xe_first_configured_acl_ignores_operational_only_listings(tmp_path, monkeypatch):
    device = SwitchWithAcl()
    rt = runtime(tmp_path, monkeypatch, device)
    args = arguments(description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP"), acl(ACL_NAME, rules=RULE))
    before, _, change_id = round_trip(rt, device, args)
    assert "! netops-acl ipv4 implicit_permit listed" in device.snapshot()
    assert RULE in device.check_query(f"show ip access-lists {ACL_NAME}")
    undo_round_trip(device, before, change_id, "ip-access-list")


def test_xe_second_command_refusal_returns_first_step(tmp_path, monkeypatch):
    class RefusingSwitch(Switch):
        def _line(self, line, mode):
            if line == "ntp server 0.0.0.0":
                assert mode[0] == "config"
                assert "description NETOPS-XE-PORT-OWNERSHIP-RETURN" in self.interface(SWITCH_PORT)
                return fixture(self.node, "ntp-refused").strip()
            return super()._line(line, mode)

    device = RefusingSwitch()
    runtime(tmp_path, monkeypatch, device)
    args = arguments(description(SWITCH_PORT, "NETOPS-XE-PORT-OWNERSHIP-RETURN"),
                     dict(table="ntp-server", op="create", key="0.0.0.0", changes={}))
    before = baseline(device)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    assert not device.applied_blocks
    result = call("admin_apply", dict(args, expected_plan_sha256=preview["plan_sha256"]))
    assert result["result"] == "reverted", result
    assert [(step["result"], step["rollback"]) for step in result["operations"]] == [
        ("reverted", "verified"), ("failed", "verified")]
    assert result["steps"].count("batch_step_start") == 2
    assert result["steps"].count("batch_step_reverted") == 2
    assert device.sent_lines.index("description NETOPS-XE-PORT-OWNERSHIP-RETURN") < device.sent_lines.index("ntp server 0.0.0.0")
    assert device.sent_lines.index("ntp server 0.0.0.0") < device.sent_lines.index("no description")
    assert baseline(device) == before and device.timer is None and device.saves == 0
