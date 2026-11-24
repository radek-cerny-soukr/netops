"""1.0.12 XE-ETHERCHANNEL (XE-M028 EtherChannel/LACP membership) on IOL-L2 XE 17.18.2 over real anonymised answers.

The fixtures (fixtures/ios_xe_etherchannel) were captured on Cisco IOL-L2 XE 17.18.2 in GNS3 by independent CLI sessions of
the write account and the privilege-1 check account. The raw measurements are private. The Helper anonymizer
(tests/support/anonymize_fixture.py) processed the public captures. The free test ports Ethernet0/1
and Ethernet0/2 joined port-channel 41 (created by IOS), changed the LACP mode, tried a direct move to 42 (refused),
left the group, and the port-channel was removed. G81Ios is FakeIos with that running configuration; it changes the
configuration lines like the measured device and answers in the measured shapes.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_ios import FakeIos, short
from test_ios import make_runtime, steps

from netops_admin import engine, exec_ios, execute, ios
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from approved_apply import approved_apply

F = Path(__file__).parent / "fixtures" / "ios_xe_etherchannel"
FW = "17.18.2"
DEVICE = SimpleNamespace(platform="iosxe", firmware=FW)
TABLE = "etherchannel-member"
ACCOUNTS = ("user01", "user02")


def fixture(name):
    return (F / name).read_text()


BASELINE = fixture("admin-show-running-config__baseline.txt")
ACTIVE = fixture("admin-show-running-config__member41-active.txt")
# Derived from the measured member configuration by detaching its only member.
EMPTY = ACTIVE.replace(" channel-group 41 mode active\n", "")
PASSIVE = fixture("admin-show-running-config__member41-passive.txt")
TWO = fixture("admin-show-running-config__two-members.txt")
ET02 = fixture("admin-show-running-config__et02-member.txt")


def static_et02(text):
    return text.replace("interface Ethernet0/2\n", "interface Ethernet0/2\n switchport mode access\n")


def answer(name):
    """The answer of an interactive line without its echo and the prompt (fixtures config__*)."""
    return "\n".join(fixture(name).rstrip("\n").split("\n")[1:-1])


def body(text):
    return text[text.index("Building configuration..."):].rstrip("\n").split("\n")


def stable(lines):
    """The configuration lines without the header that changes with every change (size, time of the change)."""
    return [line for line in lines if not line.startswith(ios.VOLATILE_HEADER)]


def request(op, key="Ethernet0/1", changes=None, request_id="req-xe-etherchannel-0001"):
    return parse_request(request_bytes(table=TABLE, op=op, key=key, changes=changes or {}, request_id=request_id))


def plan(req, text=BASELINE):
    return engine.build_plan("iosxe", text.encode(), req, firmware=FW)


# ---- the fake switch ----

class G81Ios(FakeIos):
    def __init__(self, text=BASELINE):
        super().__init__("iolxe-l2")
        self.group_limit = 48
        self.header = text[:text.index("Building configuration...")]
        self.lines = body(text)
        self.saved = list(self.lines)
        self.hostname = next(line.split()[1] for line in self.lines if line.startswith("hostname "))
        self.query_override = {
            "show version": fixture("admin-show-version.txt"),
            "show tcp brief": fixture("admin-show-tcp-brief.txt"),
            "show ip interface brief": fixture("admin-show-ip-interface-brief.txt"),
            "show cdp neighbors": fixture("admin-show-cdp-neighbors.txt")}

    def _group(self, name):
        found = [line.split() for line in self.interface(name) or [] if line.startswith("channel-group ")]
        return (found[0][1], found[0][3]) if found else None

    def _children(self, name, keep, add=None):
        start, end = self._block("interface " + name)
        children = [line for line in self.lines[start + 1:end] if keep(line)]
        self.lines[start + 1:end] = children + ([" " + add] if add else [])

    def _line(self, line, mode):
        words = line.split()
        current = mode[0]
        if current == "exec" or words == ["end"]:
            return super()._line(line, mode)
        if words == ["exit"]:
            mode[0] = "config"
            return ""
        if words[:2] == ["no", "interface"] and len(words) == 3 and words[2].startswith("Port-channel"):
            if self.interface(words[2]) is None:
                return answer("config__no-interface-Port-channel42__absent.txt")
            start, end = self._block("interface " + words[2])
            del self.lines[start:end + 1]
            group = words[2][len("Port-channel"):]
            # measured: removing the port-channel removes the membership of every member port
            for name in [line.split()[1] for line in self.lines if line.startswith("interface Ethernet")]:
                if (self._group(name) or (None,))[0] == group:
                    self._children(name, lambda child: not child.strip().startswith("channel-group "))
            return ""
        if current.startswith("interface:") and current.split(":", 1)[1].startswith("Ethernet"):
            name = current.split(":", 1)[1]
            if words[:3] == ["switchport", "access", "vlan"] or words == ["no", "switchport", "access", "vlan"]:
                start, end = self._block("interface " + name)
                children = [child for child in self.lines[start + 1:end]
                            if not child.strip().startswith("switchport access vlan ")]
                if words[0] != "no":
                    offset = next((i for i, child in enumerate(children) if child.strip().startswith("switchport ")),
                                  len(children))
                    children.insert(offset, " " + line)
                self.lines[start + 1:end] = children
                return ""
            joined = self._group(name)
            if words[:1] == ["channel-group"] and len(words) == 4 and words[2] == "mode":
                if joined is not None and joined[0] != words[1]:
                    return answer("config__channel-group-42-mode-active__member-of-41.txt").replace(
                        "channel-group 41", "channel-group @OLD").replace("channel-group 42", "channel-group " + words[1]
                                                                          ).replace("@OLD", joined[0]).replace(
                        "Et0/1", short(name))
                self._children(name, lambda child: not child.strip().startswith("channel-group "), line.strip())
                if self.interface("Port-channel" + words[1]) is None:
                    first = next(index for index, text in enumerate(self.lines) if text.startswith("interface "))
                    self.lines[first:first] = ["interface Port-channel" + words[1], "!"]
                    return answer("config__channel-group-41-mode-active__create.txt").replace("41", words[1])
                return ""
            if words == ["no", "channel-group"]:
                if joined is None:
                    return answer("config__no-channel-group__not-member.txt").replace("Et0/2", short(name))
                self._children(name, lambda child: not child.strip().startswith("channel-group "))
                return ""
        return super()._line(line, mode)

    def query(self, command):
        if command not in self.query_override:
            match = re.fullmatch(r"show etherchannel ([0-9]+) summary", command)
            if match:
                self.queries.append(command)
                if int(match.group(1)) > self.group_limit:
                    return 'Line has invalid autocommand "%s"' % command
                return fixture("admin-show-etherchannel-summary__empty.txt")
            match = re.fullmatch(r"show mac address-table interface (\S+)", command)
            if match:
                self.queries.append(command)
                count = self.learned_macs.get(match.group(1), 0)
                return fixture("admin-show-mac-address-table-interface-Ethernet0-1__baseline.txt").rstrip("\n") + \
                    "\n" + "".join("  10    0000.5e00.53%02x    DYNAMIC     %s\n" % (index, short(match.group(1)))
                                   for index in range(count))
            if command == "show lldp neighbors":
                self.queries.append(command)
                rows = "".join("%-20s%-15s120        R               Gi0/9\n" % ("host09", short(port))
                               for port in self.lldp_extra)
                return fixture("admin-show-lldp-neighbors.txt").replace("\nTotal entries", rows + "\nTotal entries")
        return super().query(command)

    def _interface_query(self, command):
        if command == "show interfaces description":
            return fixture("ro-show-interfaces-description__baseline.txt")
        group = re.fullmatch(r"show interfaces (Port-channel[0-9]+) switchport", command)
        if group:
            name = group.group(1)
            lines = self.interface(name)
            text = super()._interface_query(command).replace("Name: " + name, "Name: Po" + name[12:])
            if lines == []:
                return text.replace("Access Mode VLAN: 1 (default)", "Access Mode VLAN: unassigned")
            allowed = next((line.split()[-1] for line in lines or [] if line.startswith("switchport trunk allowed vlan ")), None)
            return text.replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: " + allowed) if allowed else text
        match = re.fullmatch(r"show interfaces (Ethernet\S+) (etherchannel|switchport)", command)
        if match is None:
            return super()._interface_query(command)
        name, kind = match.groups()
        joined = self._group(name)
        number = name.replace("/", "-")
        if kind == "switchport":
            if not self.switch:
                return super()._interface_query(command)
            lines = self.interface(name)
            if "switchport mode access" not in lines or any(line.startswith("switchport access vlan ") for line in lines):
                return super()._interface_query(command)
            if joined is None:
                if not (F / ("ro-show-interfaces-%s-switchport__baseline.txt" % number)).is_file():
                    return super()._interface_query(command)
                return fixture("ro-show-interfaces-%s-switchport__baseline.txt" % number).replace(
                    "Administrative Mode: dynamic auto", "Administrative Mode: static access")
            return fixture("ro-show-interfaces-Ethernet0-1-switchport__member.txt").replace(
                "Po41", "Po" + joined[0]).replace("Name: Et0/1", "Name: " + short(name))
        if joined is None:
            return fixture("ro-show-interfaces-Ethernet0-1-etherchannel__none.txt")
        text = fixture("ro-show-interfaces-Ethernet0-1-etherchannel__%s.txt" % joined[1])
        return text.replace("Channel group = 41", "Channel group = " + joined[0]).replace(
            "Pseudo port-channel = Po41", "Pseudo port-channel = Po" + joined[0]).replace("\nEt0/1 ", "\n%s " % short(name))


def runtime(tmp_path, device):
    return make_runtime(tmp_path, device, accounts=ACCOUNTS)


# ---- the measured configurations and answers ----

def test_members_of_the_measured_configurations():
    assert ios.load(BASELINE, FW).entries(TABLE) == {}
    assert ios.load(ACTIVE, FW).entries(TABLE)["Ethernet0/1"].attributes == {"channel-group": "41", "mode": "active"}
    two = ios.load(TWO, FW).entries(TABLE)
    assert {name: entry.attributes for name, entry in two.items()} == {
        "Ethernet0/1": {"channel-group": "41", "mode": "passive"},
        "Ethernet0/2": {"channel-group": "41", "mode": "active"}}
    assert ios.group_members(ios.load(TWO, FW), "41") == ["Ethernet0/1", "Ethernet0/2"]
    # IOS creates the missing port-channel as an empty interface before the first interface
    assert "interface Port-channel41\n!\ninterface Ethernet0/0" in ACTIVE and "Port-channel41" not in BASELINE


def test_the_measured_help_offers_lacp_and_other_modes():
    help_text = fixture("help__channel-group-41-mode.txt")
    assert re.findall(r"^  (\S+) ", help_text, re.MULTILINE) == ["active", "auto", "desirable", "on", "passive"]


def test_the_device_refusals_of_etherchannel_lines_are_errors():
    assert ios.cli_error("x\n" + answer("config__channel-group-42-mode-active__member-of-41.txt")).startswith(
        "Command Rejected : Et0/1 is already part of channel-group 41")
    assert ios.cli_error("x\n" + answer("config__no-channel-group__not-member.txt")).startswith("Command Rejected:")
    assert ios.cli_error("x\n" + answer("config__no-interface-Port-channel42__absent.txt")).startswith("% Invalid input")
    assert ios.cli_error("x\n" + answer("config__channel-group-41-mode-active__create.txt")) is None


def test_check_account_answers_of_the_device():
    assert ios.member_state(fixture("ro-show-interfaces-Ethernet0-1-etherchannel__active.txt"), "Ethernet0/1") == {
        "channel-group": "41", "mode": "active"}
    assert ios.member_state(fixture("ro-show-interfaces-Ethernet0-1-etherchannel__passive.txt"), "Ethernet0/1") == {
        "channel-group": "41", "mode": "passive"}
    assert ios.member_state(fixture("ro-show-interfaces-Ethernet0-1-etherchannel__none.txt"), "Ethernet0/1") is None
    port = ios.etherchannel_port(fixture("ro-show-interfaces-Ethernet0-2-etherchannel__active.txt"), "Ethernet0/2")
    assert port == {"channel-group": "41", "mode": "active", "protocol": "LACP", "state": "Down Not-in-Bndl"}


@pytest.mark.parametrize("text", [
    fixture("ro-show-interfaces-Ethernet0-2-etherchannel__active.txt"),  # another port
    fixture("ro-show-interfaces-Ethernet0-1-etherchannel__active.txt").split("Flags:")[0],  # cut answer
    "\n\nLine has invalid autocommand \"show interfaces Ethernet0/1 etherchannel\"",  # refused (measured shape)
    fixture("ro-show-privilege.txt"),
])
def test_check_account_answers_that_are_not_about_the_port_are_refused(text):
    with pytest.raises(Rejected):
        ios.member_state(text, "Ethernet0/1")


# ---- plans from the measured running configuration ----

def test_join_renders_the_measured_line_and_the_inverse_removes_the_created_port_channel():
    p = plan(request("create", changes={"channel-group": 41, "mode": "active"}))
    assert p["commands"] == ["configure terminal", "interface Ethernet0/1", "channel-group 41 mode active", "end"]
    assert p["inverse"] == ["configure terminal", "interface Ethernet0/1", "no channel-group", "exit",
                            "no interface Port-channel41", "end"]
    assert p["predicted"] == {"before": None, "after": {"channel-group": "41", "mode": "active"}}
    # the empty port-channel created by IOS is not a change outside the object
    after = engine.verify(p, ACTIVE.encode())
    assert after["result"] == "match", after


def test_joining_an_existing_group_keeps_its_port_channel():
    p = plan(request("create", key="Ethernet0/2", changes={"channel-group": 41, "mode": "active"}), PASSIVE)
    assert p["commands"] == ["configure terminal", "interface Ethernet0/2", "channel-group 41 mode active", "end"]
    assert p["inverse"] == ["configure terminal", "interface Ethernet0/2", "no channel-group", "end"]
    assert engine.verify(p, TWO.encode())["result"] == "match"


def test_mode_change_is_in_place_and_a_move_unbundles_first():
    mode = plan(request("update", changes={"mode": "passive"}), ACTIVE)
    assert mode["commands"] == ["configure terminal", "interface Ethernet0/1", "channel-group 41 mode passive", "end"]
    assert mode["inverse"] == ["configure terminal", "interface Ethernet0/1", "channel-group 41 mode active", "end"]
    assert engine.verify(mode, PASSIVE.encode())["result"] == "match"
    move = plan(request("update", changes={"channel-group": 42}), ACTIVE)
    assert move["commands"] == ["configure terminal", "interface Ethernet0/1", "no channel-group",
                                "channel-group 42 mode active", "end"]
    assert move["inverse"] == ["configure terminal", "interface Ethernet0/1", "no channel-group",
                               "channel-group 41 mode active", "exit", "no interface Port-channel42", "end"]


def test_leaving_keeps_the_port_channel_even_without_members():
    last = plan(request("delete"), ACTIVE)
    assert last["commands"] == ["configure terminal", "interface Ethernet0/1", "no channel-group", "end"]
    assert last["inverse"] == ["configure terminal", "interface Ethernet0/1", "channel-group 41 mode active", "end"]
    assert engine.verify(last, EMPTY.encode())["result"] == "match"
    other = plan(request("delete", key="Ethernet0/1"), TWO)
    assert other["commands"] == ["configure terminal", "interface Ethernet0/1", "no channel-group", "end"]
    assert engine.verify(other, ET02.encode())["result"] == "match"
    configured = ACTIVE.replace("interface Port-channel41\n!", "interface Port-channel41\n description lag41\n!")
    assert plan(request("delete"), configured)["commands"][-2:] == ["no channel-group", "end"]


def test_a_foreign_change_next_to_the_object_is_detected():
    p = plan(request("create", changes={"channel-group": 41, "mode": "active"}))
    foreign = ACTIVE.replace("interface Ethernet0/2\n shutdown", "interface Ethernet0/2\n shutdown\n channel-group 41 mode active")
    result = engine.verify(p, foreign.encode())
    assert result["result"] == "mismatch" and not result["rest_matches"]


@pytest.mark.parametrize("op,key,changes,text,message", [
    ("create", "Ethernet0/1", {"channel-group": 41, "mode": "on"}, BASELINE, "must match"),
    ("create", "Ethernet0/1", {"channel-group": 41, "mode": "desirable"}, BASELINE, "mode is longer"),
    ("create", "Ethernet0/1", {"channel-group": 0, "mode": "active"}, BASELINE, "1..2147483647"),
    ("create", "Ethernet0/1", {"channel-group": 41}, BASELINE, "create needs mode"),
    ("create", "Ethernet0/1", {"channel-group": 42, "mode": "active"}, ACTIVE, "already used"),
    ("create", "Port-channel41", {"channel-group": 41, "mode": "active"}, ACTIVE, "does not match"),
    ("create", "Ethernet9/9", {"channel-group": 41, "mode": "active"}, BASELINE, "not in the running"),
    ("update", "Ethernet0/1", {"mode": "passive"}, BASELINE, "not a member of any channel-group"),
    ("delete", "Ethernet0/2", {}, ACTIVE, "not a member of any channel-group"),
    ("update", "Ethernet0/1", {"mode": "active"}, ACTIVE, "changes nothing"),
    ("update", "Ethernet0/1", {"mode": None}, ACTIVE, "cannot"),
], ids=lambda value: value if isinstance(value, str) and len(value) < 40 else None)
def test_refusals_before_any_write(op, key, changes, text, message):
    with pytest.raises(Rejected, match=message):
        plan(request(op, key=key, changes=changes), text)


@pytest.mark.parametrize("line,code", [
    (" switchport mode trunk", "port_uplink"),
    (" no switchport", "port_routed"),
])
def test_uplink_and_routed_ports_are_refused(line, code):
    text = BASELINE.replace("interface Ethernet0/1\n switchport mode access", "interface Ethernet0/1\n" + line)
    with pytest.raises(Rejected) as caught:
        plan(request("create", changes={"channel-group": 41, "mode": "active"}), text)
    assert caught.value.reason_codes == [code]


def test_pagp_or_static_members_are_outside_the_profile():
    text = ACTIVE.replace("channel-group 41 mode active", "channel-group 41 mode on")
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("update", changes={"mode": "passive"}), text)
    with pytest.raises(Rejected, match="already used"):
        plan(request("create", changes={"channel-group": 42, "mode": "active"}), text)


def test_a_routed_port_channel_is_refused():
    text = ACTIVE.replace("interface Port-channel41\n!", "interface Port-channel41\n no switchport\n!")
    with pytest.raises(Rejected) as caught:
        plan(request("create", key="Ethernet0/2", changes={"channel-group": 41, "mode": "active"}), text)
    assert caught.value.reason_codes == ["port_routed"]


def test_other_tables_still_refuse_a_member_port():
    with pytest.raises(Rejected) as caught:
        engine.build_plan("iosxe", ACTIVE.encode(), parse_request(request_bytes(
            table="interface", op="update", key="Ethernet0/1", changes={"admin-state": "enabled"})), firmware=FW)
    assert caught.value.reason_codes == ["port_lag_member"]


# ---- live prechecks of Admin (write account reads) ----

def test_free_test_port_passes_the_live_prechecks():
    device = G81Ios()
    p = plan(request("create", changes={"channel-group": 41, "mode": "active"}))
    assert exec_ios.plan_prechecks(device, DEVICE, p, BASELINE) == []
    assert any("free Layer 2 port" in check and "Vlan99" in check for check in p["prechecks"])
    member = G81Ios(ACTIVE)
    q = plan(request("update", changes={"mode": "passive"}), ACTIVE)
    assert exec_ios.plan_prechecks(member, DEVICE, q, ACTIVE) == []
    assert any("down in channel-group 41" in check for check in q["prechecks"])


@pytest.mark.parametrize("prepare,key,code", [
    (lambda device: None, "Ethernet0/0", "port_management_vlan"),
    (lambda device: device.lldp_extra.append("Ethernet0/1"), "Ethernet0/1", "port_lldp_neighbor"),
    (lambda device: device.learned_macs.update({"Ethernet0/1": 2}), "Ethernet0/1", "port_learned_mac"),
    (lambda device: setattr(device, "switch", False), "Ethernet0/1", "port_routed"),
    (lambda device: device.query_override.update({"show interfaces Ethernet0/1 etherchannel": fixture(
        "ro-show-interfaces-Ethernet0-1-etherchannel__none.txt")[:5]}), "Ethernet0/1", "port_usage_unreadable"),
])
def test_live_prechecks_refuse_ports_in_use(prepare, key, code):
    device = G81Ios()
    prepare(device)
    p = plan(request("create", key=key, changes={"channel-group": 41, "mode": "active"}))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, BASELINE)
    assert caught.value.reason_codes == [code]


def test_a_bundled_member_is_refused():
    # the port state of a member with a partner; only the state text of the measured answer differs
    device = G81Ios(ACTIVE)
    device.query_override["show interfaces Ethernet0/1 etherchannel"] = fixture(
        "ro-show-interfaces-Ethernet0-1-etherchannel__active.txt").replace("Down Not-in-Bndl", "Up Mstr In-Bndl")
    p = plan(request("delete"), ACTIVE)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACTIVE)
    assert caught.value.reason_codes == ["port_lag_active"]


def test_observe_reads_the_membership_with_the_check_account():
    device = G81Ios(ACTIVE)
    p = plan(request("update", changes={"mode": "passive"}), ACTIVE)
    assert engine.observed_state(p, exec_ios.observe(device, p)) == p["predicted"]["before"]
    assert device.check_queries == ["show interfaces Ethernet0/1 etherchannel"]
    assert exec_ios.observe(G81Ios(), plan(request("create", changes={"channel-group": 41, "mode": "active"}))) is None


# ---- end to end through Admin: preview without a write, apply, readback, undo ----

def test_preview_writes_nothing(tmp_path):
    device = G81Ios()
    result = execute.preview(runtime(tmp_path, device), "lab-ios",
                             request("create", changes={"channel-group": 41, "mode": "active"}))
    assert result["result"] == "ready", result
    assert device.applied_blocks == [] and device.lines == device.saved


def test_join_is_confirmed_read_back_and_undone_to_the_baseline(tmp_path):
    device = G81Ios()
    rt = runtime(tmp_path, device)
    record = approved_apply(rt, "lab-ios", request("create", changes={"channel-group": 41, "mode": "active"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.applied_blocks[1] == record["plan"]["commands"]
    assert stable(device.lines) == stable(body(ACTIVE)) and device.timer is None
    assert "show interfaces Ethernet0/1 etherchannel" in device.check_queries
    back = execute.undo(rt, record["change_id"], "XE-ETHERCHANNEL return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert back["plan"]["commands"][-3:] == ["exit", "no interface Port-channel41", "end"]
    assert stable(device.lines) == stable(body(BASELINE))


@pytest.mark.parametrize("text,req", [
    (ACTIVE, request("update", changes={"mode": "passive"})),
    (ACTIVE, request("update", changes={"channel-group": 42})),
    (ACTIVE, request("delete")),
    (PASSIVE, request("create", key="Ethernet0/2", changes={"channel-group": 41, "mode": "active"})),
    (TWO, request("delete", key="Ethernet0/1")),
], ids=["mode", "move", "leave-last", "join-existing", "leave-other"])
def test_changes_of_the_measured_members_are_undone(tmp_path, text, req):
    device = G81Ios(static_et02(text))
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    record = approved_apply(rt, "lab-ios", req)
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.applied_blocks[1] == record["plan"]["commands"]
    back = execute.undo(rt, record["change_id"], "XE-ETHERCHANNEL return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert device.lines == before


def test_measured_states_are_reached_by_admin(tmp_path):
    device = G81Ios(static_et02(BASELINE))
    rt = runtime(tmp_path, device)
    assert approved_apply(rt, "lab-ios", request("create", changes={"channel-group": 41, "mode": "active"}))[
        "result"] == "confirmed"
    assert approved_apply(rt, "lab-ios", request("update", changes={"mode": "passive"}, request_id="req-xe-etherchannel-0002"))[
        "result"] == "confirmed"
    assert stable(device.lines) == stable(body(static_et02(PASSIVE)))
    assert approved_apply(rt, "lab-ios", request("create", key="Ethernet0/2", changes={"channel-group": 41, "mode": "active"},
                                                request_id="req-xe-etherchannel-0003"))["result"] == "confirmed"
    assert stable(device.lines) == stable(body(static_et02(TWO)))
    assert approved_apply(rt, "lab-ios", request("delete", request_id="req-xe-etherchannel-0004"))["result"] == "confirmed"
    assert stable(device.lines) == stable(body(static_et02(ET02)))
    assert approved_apply(rt, "lab-ios", request("delete", key="Ethernet0/2", request_id="req-xe-etherchannel-0005"))[
        "result"] == "confirmed"
    assert stable(device.lines) == stable(body(static_et02(EMPTY)))


def test_a_device_refusal_during_the_write_is_returned_by_the_timer(tmp_path):
    device = G81Ios()
    rt = runtime(tmp_path, device)
    before = list(device.lines)

    # someone puts the port into group 43 right before the write; IOS refuses the join (measured answer)
    def taken(fake, block):
        if block[:2] == ["configure terminal", "interface Ethernet0/1"]:
            index = fake.lines.index("interface Ethernet0/1")
            fake.lines[index + 1:index + 1] = [" channel-group 43 mode active"]
    device.on_apply = taken
    record = approved_apply(rt, "lab-ios", request("create", changes={"channel-group": 41, "mode": "active"}))
    assert record["result"] in ("reverted", "unknown"), (record["result"], steps(record))
    assert "change_failed" in steps(record)
    assert device.lines == before


def test_undo_keeps_a_preexisting_empty_port_channel(tmp_path):
    device = G81Ios(EMPTY)
    rt = runtime(tmp_path, device)
    record = approved_apply(rt, "lab-ios", request("create", changes={"channel-group": 41, "mode": "active"}))
    assert record["result"] == "confirmed"
    preview = execute.preview_undo(rt, record["change_id"], "restore preexisting Port-channel41")
    assert "no interface Port-channel41" not in preview["commands"]
    result = execute.undo(rt, record["change_id"], "restore preexisting Port-channel41")
    assert result["result"] == "confirmed"
    assert stable(device.lines) == stable(body(EMPTY))


@pytest.mark.parametrize("unexpected", ["missing-existing", "foreign-creation", "missing-on-return"])
def test_readback_checks_even_empty_port_channels(tmp_path, unexpected):
    initial = ACTIVE
    if unexpected == "missing-on-return":
        initial = ACTIVE.replace("interface Port-channel41\n", "interface Port-channel42\n!\ninterface Port-channel41\n")
    device = G81Ios(initial)
    rt = runtime(tmp_path, device)
    original_line = device._line

    def altered_line(line, mode):
        if line == "no channel-group" and unexpected == "missing-on-return":
            return "% Invalid input detected"
        result = original_line(line, mode)
        if line == "no channel-group" and unexpected == "missing-existing":
            start, end = device._block("interface Port-channel41")
            del device.lines[start:end + 1]
        if line == "no channel-group" and unexpected == "foreign-creation":
            start = device.lines.index("interface Ethernet0/0")
            device.lines[start:start] = ["interface Port-channel42", "!"]
        if line == "configure revert now" and unexpected == "missing-on-return":
            start, end = device._block("interface Port-channel42")
            del device.lines[start:end + 1]
        return result

    device._line = altered_line
    record = approved_apply(rt, "lab-ios", request("delete"))
    if unexpected == "missing-on-return":
        assert record["result"] == "unknown", (record["reason"], steps(record))
    else:
        assert record["result"] == "reverted", (record["reason"], steps(record))
        assert "postcheck_failed" in steps(record)


def test_access_vlan_alignment_is_predicted_and_undone(tmp_path):
    text = BASELINE.replace("interface Ethernet0/0\n",
                            "interface Port-channel41\n switchport access vlan 20\n switchport mode access\n!\n"
                            "interface Ethernet0/0\n")
    text = text.replace("interface Ethernet0/1\n", "interface Ethernet0/1\n switchport access vlan 10\n")
    device = G81Ios(text)
    rt = runtime(tmp_path, device)
    record = approved_apply(rt, "lab-ios", request("create", changes={"channel-group": 41, "mode": "active"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert record["plan"]["commands"].index("switchport access vlan 20") < record["plan"]["commands"].index(
        "channel-group 41 mode active")
    assert "switchport access vlan 10" in record["plan"]["inverse"]
    assert "switchport access vlan 20" in device.interface("Ethernet0/1")
    result = execute.undo(rt, record["change_id"], "restore VLAN 10")
    assert result["result"] == "confirmed", (result["reason"], steps(result))
    assert stable(device.lines) == stable(body(text))


@pytest.mark.parametrize("guarded", ["ethernet0/1", "PORT-CHANNEL41", "Et0/1", "po41"])
def test_interface_protection_covers_membership(tmp_path, guarded):
    device = G81Ios(ACTIVE)
    rt = runtime(tmp_path, device)
    rt.config.devices["lab-ios"].protected["interface"] = [guarded]
    certify(rt, device, "lab-ios")
    result = execute.preview(rt, "lab-ios", request("delete"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_protected"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("scenario,code", [
    ("dynamic", "port_uplink"),
    ("link-up", "port_uplink"),
    ("management-trunk", "port_management_vlan"),
    ("truncated-target", "port_usage_unreadable"),
])
def test_prechecks_cover_the_member_link_and_target_group(tmp_path, scenario, code):
    text = BASELINE
    if scenario == "dynamic":
        text = text.replace("interface Ethernet0/1\n switchport mode access\n", "interface Ethernet0/1\n")
    if scenario in ("management-trunk", "truncated-target"):
        text = text.replace("interface Ethernet0/0\n",
                            "interface Port-channel41\n switchport trunk allowed vlan 99\n switchport mode trunk\n!\n"
                            "interface Ethernet0/0\n")
    device = G81Ios(text)
    if scenario == "link-up":
        description = fixture("ro-show-interfaces-description__baseline.txt")
        device.query_override["show interfaces description"] = re.sub(
            r"(?m)^Et0/1 .*", "%-31s%-15s%-9s" % ("Et0/1", "up", "up"), description)
    if scenario == "truncated-target":
        device.query_override["show interfaces Port-channel41 switchport"] = "Name: Po41\nSwitchport: Enabled\n"
    result = execute.preview(runtime(tmp_path, device), "lab-ios",
                             request("create", changes={"channel-group": 41, "mode": "active"}))
    assert result["result"] == "rejected" and result["reason_codes"] == [code], result
    assert device.applied_blocks == []


@pytest.mark.parametrize("mode", ["dynamic auto", "dynamic desirable"])
@pytest.mark.parametrize("field", ["Administrative", "Operational"])
def test_member_dynamic_switchport_mode_is_an_uplink(tmp_path, mode, field):
    device = G81Ios()
    command = "show interfaces Ethernet0/1 switchport"
    body = fixture("ro-show-interfaces-Ethernet0-1-switchport__baseline.txt")
    # DERIVED: change only the reported mode in the real switchport answer.
    device.query_override[command], replacements = re.subn(r"(?m)^" + field + r" Mode: [^\n]+$",
                                                         field + " Mode: " + mode, body)
    assert replacements == 1
    result = execute.preview(runtime(tmp_path, device), "lab-ios",
                             request("create", changes={"channel-group": 41, "mode": "active"}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_uplink"], result
    assert command in device.queries and device.applied_blocks == []


@pytest.mark.parametrize("limit,group,expected", [(48, 49, "rejected"), (128, 49, "ready"), (128, 41, "ready")])
def test_channel_group_range_and_switch_capability_are_read_from_the_device(tmp_path, limit, group, expected):
    device = G81Ios()
    device.group_limit = limit
    if limit == 128:
        device.query_override["show version"] = fixture("admin-show-version.txt").replace(
            "X86_64BI_LINUX_L2", "CAT9K_IOSXE")
    result = execute.preview(runtime(tmp_path, device), "lab-ios",
                             request("create", changes={"channel-group": group, "mode": "active"}))
    assert result["result"] == expected, result
    assert "show etherchannel %d summary" % group in device.queries
    assert device.applied_blocks == []
