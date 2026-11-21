"""G125 through Admin's preview, apply, verification and undo with EOS wire captures."""

import json
from pathlib import Path
import re

import pytest

from fake_eos import FakeEos
from test_eos import make_runtime, request
from netops_admin import eos, execute
from netops_admin.access import AccessError

FIXTURES = Path(__file__).parent / "fixtures" / "eos_g125"
PORT = "Ethernet12"
CHANNEL = "Port-Channel900"
MLAG_SECTION = "mlag configuration"


def capture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class LabEOS(FakeEos):
    def __init__(self):
        super().__init__()
        self.insert(*capture("stp-global.txt").splitlines(), "!")
        self.write_answers = {}
        self.check_answers = {}
        self.reads = []
        self.link_up = set()
        self.vlan_ports = {}
        self.saved = list(self.lines)

    def insert(self, *lines):
        index = self.lines.index("end")
        self.lines[index:index] = lines

    def section(self):
        if MLAG_SECTION not in self.lines:
            return []
        start, end = self._block(MLAG_SECTION)
        return self.lines[start:end]

    def query_status(self, command):
        match = re.fullmatch(r"show interfaces (\S+) \| json", command)
        if match and self.interface(match[1]) is None:
            self.reads.append(command)
            return 1, capture("missing-channel.txt").replace(CHANNEL, match[1])
        return super().query_status(command)

    def check_query_status(self, command):
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        if command.startswith("show running-config"):
            denied = capture("ro-running-config-denied.txt")
            return 1, denied.replace("show running-config interfaces Ethernet12", command)
        if command in self.check_answers:
            return self.check_answers[command]
        return self.query_status(command)

    def query(self, command):
        self.reads.append(command)
        if command in self.write_answers:
            answer = self.write_answers[command]
            if isinstance(answer, Exception):
                raise answer
            return answer
        match = re.fullmatch(r"show interfaces (\S+) \| json", command)
        if match:
            name = match[1]
            source, old_name = ("channel.json", "Port-Channel104") if name.startswith("Port-Channel") else (
                "ethernet.json", PORT)
            answer = json.loads(capture(source))
            row = answer["interfaces"].pop(old_name)
            row["name"] = name
            row["description"] = next((line.removeprefix("description ") for line in self.interface(name)
                                       if line.startswith("description ")), "")
            row["interfaceStatus"] = "connected" if name in self.link_up else (
                "disabled" if "shutdown" in self.interface(name) else "notconnect")
            answer["interfaces"][name] = row
            return json.dumps(answer)
        if command == f"show interfaces {PORT} status | json":
            data = json.loads(capture("ethernet-member-status.json"))
            setting = self.member_setting()
            if setting is None:
                data["interfaceStatuses"][PORT]["vlanInformation"] = {
                    "vlanId": 1, "interfaceMode": "bridged", "interfaceForwardingModel": "bridged",
                }
            else:
                data["interfaceStatuses"][PORT]["vlanInformation"]["vlanExplanation"] = f"in Po{setting[1]}"
            return json.dumps(data)
        if command == "show port-channel dense | json":
            setting = self.member_setting()
            data = json.loads(capture("channel-dense-static.json" if setting and setting[2] == "on"
                                      else "channel-dense-passive.json"))
            row = data["portChannels"].pop(CHANNEL)
            if setting:
                if setting[2] in {"active", "passive"}:
                    row["lacpMode"] = setting[2]
                    row["ports"][PORT]["lacpState"]["activity"] = setting[2] == "active"
                data["portChannels"]["Port-Channel" + setting[1]] = row
            return json.dumps(data)
        match = re.fullmatch(r"show spanning-tree interface (\S+) detail \| json", command)
        if match:
            data = json.loads(capture("stp-port.json" if match[1] in self.link_up else "stp-port-inactive.json"))
            data["interface"] = match[1]
            return json.dumps(data)
        match = re.fullmatch(r"show spanning-tree vlan (\d+) detail \| json", command)
        if match:
            data = json.loads(capture("stp-vlan-bridge.json"))
            instance = data["spanningTreeVlanInstances"].pop("1")
            vlan = instance["spanningTreeVlanInstance"]
            vlan["protocol"] = "rapidPvst"
            vlan["instanceName"] = "VLAN" + match[1]
            vlan["bridge"]["systemIdExtension"] = int(match[1])
            priority = re.compile(r"spanning-tree vlan-id " + match[1] + r" priority (\d+)")
            configured = next((m[1] for line in self.lines if (m := priority.fullmatch(line))), "32768")
            vlan["bridge"]["priority"] = int(configured) + int(match[1])
            data["spanningTreeVlanInstances"][match[1]] = instance
            return json.dumps(data)
        match = re.fullmatch(r"show interfaces (\S+) switchport", command)
        if match and match[1] == "Port-Channel200":
            return capture("peer-switchport.txt").replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: 4094")
        if match and match[1] == CHANNEL:
            return capture("ethernet-switchport.txt").replace("Et12", "Po900")
        match = re.fullmatch(r"show mac address-table interface (\S+)", command)
        if match and not self.learned_macs.get(match[1]):
            return capture("empty-macs.txt")
        if command == "show lldp neighbors | json":
            return capture("lldp.json")
        if command == "show mlag | json":
            baseline = "a-mlag.json" if any(line.strip().startswith("domain-id ") for line in self.section()) else (
                "disabled-mlag.json")
            data = json.loads(capture(baseline))
            for command_prefix, key, default in (("local-interface ", "localInterface", ""),
                                                  ("peer-address ", "peerAddress", "0.0.0.0"),
                                                  ("peer-link ", "peerLink", "")):
                data[key] = next((line.strip()[len(command_prefix):] for line in self.section()
                                  if line.strip().startswith(command_prefix)
                                  and not line.strip().startswith("peer-address heartbeat ")), default)
            return json.dumps(data)
        if command == "show mlag interfaces | json":
            obj = json.loads(capture("no-mlag-interfaces.json"))
            recorded = json.loads(capture("mlag-test-channel.json"))["interfaces"]["900"]
            for line in self.lines[:-1]:
                if line.startswith("interface Port-Channel"):
                    for setting in self.interface(line.split()[1]):
                        if setting.startswith("mlag "):
                            obj["interfaces"][setting.split()[1]] = {
                                **recorded, "localInterface": line.split()[1], "peerInterface": "", "status": "configured",
                            }
            return json.dumps(obj)
        match = re.fullmatch(r"show vlan id (\d+) \| json", command)
        if match:
            row = json.loads(capture("vlan.json"))["vlans"]["1"]
            row["interfaces"] = {port: row["interfaces"]["Ethernet6"]
                                 for port in self.vlan_ports.get(match[1], ())}
            return json.dumps({"vlans": {match[1]: row}})
        return super().query(command)

    def member_setting(self):
        return next((match for line in self.interface(PORT)
                     if (match := re.fullmatch(r"channel-group (\d+) mode (active|passive|on)", line))), None)

    def _line(self, line, mode):
        if mode[0] == "config":
            if line == "interface " + CHANNEL and self.interface(CHANNEL) is None:
                self._add_interface(CHANNEL)
                mode[0] = "interface:" + CHANNEL
                return ""
            if line == "no interface " + CHANNEL:
                start, end = self._block("interface " + CHANNEL)
                del self.lines[start:end + 1]
                return ""
            if line == MLAG_SECTION:
                mode[0] = "mlag"
                return ""
            match = re.fullmatch(r"(no )?spanning-tree vlan-id (\d+) priority(?: (\d+))?", line)
            if match:
                prefix = "spanning-tree vlan-id " + match[2] + " priority"
                for old in list(self.lines):
                    if old.startswith(prefix + " "):
                        self.lines.remove(old)
                if not match[1]:
                    index = next(i for i, old in enumerate(self.lines) if old.startswith("spanning-tree mode "))
                    self.lines.insert(index + 1, line)
                return ""
        if mode[0] == "mlag" and (line.startswith(("peer-address ", "peer-link ", "local-interface "))
                                  or line in ("no peer-address", "no peer-link", "no local-interface")):
            if not self.section():
                self.insert(MLAG_SECTION, "!")
            start, end = self._block(MLAG_SECTION)
            setting = line.removeprefix("no ").split()[0]
            self.lines[start + 1:end] = [old for old in self.lines[start + 1:end]
                                         if not old.strip().startswith(setting + " ")
                                         or old.strip().startswith("peer-address heartbeat ")]
            if line.startswith("no "):
                if self.section() == [MLAG_SECTION]:
                    del self.lines[start:start + 2]
            else:
                self.lines.insert(start + 1, "   " + line)
            return ""
        if mode[0].startswith("interface:"):
            name = mode[0].split(":", 1)[1]
            body = line.removeprefix("no ")
            for prefix in ("channel-group", "mlag", "spanning-tree portfast", "spanning-tree bpduguard",
                           "spanning-tree cost"):
                if body == prefix or body.startswith(prefix + " "):
                    self._set(name, re.compile("^" + prefix + r"(?: |$)"),
                              None if line.startswith("no ") else line)
                    return ""
        return super()._line(line, mode)


def change(table, key, changes, op="update"):
    return request(table=table, key=key, changes=changes, op=op, request_id="g125-request-0001")


def round_trip(tmp_path, device, item, commands):
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    baseline = device.snapshot()
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", *commands, "end"]
    assert device.snapshot() == baseline and not device.applied_blocks
    assert device.check_queries
    assert all(not command.startswith("show running-config") for command in device.check_queries)
    device.check_queries.clear()
    record = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record["steps"])
    assert device.snapshot() != baseline and device.lines == device.saved
    assert len(device.check_queries) >= 2
    assert all(not command.startswith("show running-config") for command in device.check_queries)
    reason = "Restore the measured baseline"
    undo = execute.preview_undo(runtime, record["change_id"], reason, issue=True)
    assert undo["result"] == "ready", undo
    device.check_queries.clear()
    restored = execute.undo(runtime, record["change_id"], reason, expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", (restored.get("reason"), restored["steps"])
    assert len(device.check_queries) >= 2
    assert all(not command.startswith("show running-config") for command in device.check_queries)
    assert device.snapshot() == baseline and device.lines == device.saved
    assert not device.sessions
    return preview


@pytest.mark.parametrize("op", ["create", "delete"])
def test_e20_empty_port_channel_tracks_lifetime(tmp_path, op):
    device = LabEOS()
    line = "interface " + CHANNEL
    if op == "delete":
        device._add_interface(CHANNEL)
        device.saved = list(device.lines)
    round_trip(tmp_path, device, change("port-channel", CHANNEL, {}, op),
               [line if op == "create" else "no " + line])


def test_e20_channel_description_is_read_by_operator(tmp_path):
    device = LabEOS()
    round_trip(tmp_path, device, change("port-channel", CHANNEL, {"description": "G125 readback"}, "create"),
               ["interface " + CHANNEL, "description G125 readback"])


def test_e20_lost_check_account_during_readback_reverts_the_change(tmp_path):
    device = LabEOS()
    baseline = device.snapshot()
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    item = change("port-channel", CHANNEL, {}, "create")
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview

    def lose_check_account(fake, block):
        if block[:2] == ["configure terminal", "interface " + CHANNEL]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert record["reason"] == "check identity unavailable"
    assert "show interfaces %s | json" % CHANNEL in device.check_queries
    assert device.snapshot() == baseline and device.lines == device.saved
    assert not device.sessions and device.timer is None


@pytest.mark.parametrize(("initial", "requested", "commands"), [
    (None, {"group": 900, "mode": "active"}, ["channel-group 900 mode active"]),
    (None, {"group": 900, "mode": "on"}, ["channel-group 900 mode on"]),
    ("active", {"mode": "passive"}, ["no channel-group", "channel-group 900 mode passive"]),
    ("passive", {"mode": "active"}, ["no channel-group", "channel-group 900 mode active"]),
    ("active", {"group": None, "mode": None}, ["no channel-group"]),
])
def test_e20_member_changes_preserve_existing_channel(tmp_path, initial, requested, commands):
    device = LabEOS()
    device._add_interface(CHANNEL)
    device._set(PORT, re.compile(r".*"), "shutdown")
    if initial:
        filename = "lacp-member.txt" if initial == "active" else "lab-lacp-passive.txt"
        measured = capture(filename).splitlines()[-1].strip()
        device._set(PORT, re.compile("^channel-group "), measured.replace("104", "900"))
    device.saved = list(device.lines)
    round_trip(tmp_path, device, change("port-channel-member", PORT, requested), ["interface " + PORT, *commands])
    assert device.interface(CHANNEL) == []


def test_e21_add_local_mlag_id_and_remove_only_the_binding(tmp_path):
    device = LabEOS()
    device._add_interface(CHANNEL)
    device.insert(*capture("a-mlag-peer.txt").splitlines(), "!")
    device.saved = list(device.lines)
    round_trip(tmp_path, device, change("mlag-port", CHANNEL, {"mlag-id": 900}),
               ["interface " + CHANNEL, "mlag 900"])
    assert device.interface(CHANNEL) == []
    assert device.section() == capture("a-mlag-peer.txt").splitlines()


def test_e21_stage_peer_settings_and_restore_unconfigured_state(tmp_path):
    device = LabEOS()
    peer = json.loads(capture("a-mlag.json"))["peerAddress"]
    device._add_interface("Port-Channel200")
    device._add_interface("Vlan4094")
    device.saved = list(device.lines)
    round_trip(tmp_path, device, change("mlag-peer", "global", {
        "local-interface": "Vlan4094", "peer-address": peer, "peer-link": "Port-Channel200",
    }), ["mlag configuration", "local-interface Vlan4094", "peer-address " + peer, "peer-link Port-Channel200"])
    assert not device.section()


def test_e22_port_settings_and_undo_keep_shutdown(tmp_path):
    device = LabEOS()
    device._set(PORT, re.compile(r".*"), "shutdown")
    device.saved = list(device.lines)
    round_trip(tmp_path, device, change("stp-port", PORT, {"portfast": "edge", "bpdu-guard": "enable", "cost": 20001}),
               ["interface " + PORT, "spanning-tree portfast edge", "spanning-tree bpduguard enable",
                "spanning-tree cost 20001"])
    assert device.interface(PORT) == ["shutdown"]


@pytest.mark.parametrize("reply", [(1, "% Invalid input at line 1"), (0, "{}"),
                                   (0, capture("stp-port.json"))])
def test_e22_stp_readback_failure_after_write_reverts(tmp_path, reply):
    device = LabEOS()
    device._set(PORT, re.compile(r".*"), "shutdown")
    device.saved = list(device.lines)
    baseline = device.snapshot()
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    item = change("stp-port", PORT, {"cost": 12000})
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview

    def fail_after_change(fake, block):
        if "spanning-tree cost 12000" in block:
            fake.check_answers[f"show spanning-tree interface {PORT} detail | json"] = reply

    device.on_apply = fail_after_change
    record = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert record["reason"] == "check identity unavailable"
    assert device.snapshot() == baseline and device.lines == device.saved
    assert not device.sessions and device.timer is None


def test_e22_vendor_rapid_pvst_priority_and_untested_firmware_warning(tmp_path):
    device = LabEOS()
    device.lines[device.lines.index("spanning-tree mode mstp")] = "spanning-tree mode rapid-pvst"
    device.firmware = "4.37.1F"
    device.lines = [line.replace("4.36.1F", device.firmware) for line in device.lines]
    device._add_vlan("3910")
    device.saved = list(device.lines)
    preview = round_trip(tmp_path, device, change("stp-vlan", "3910", {"priority": 20480}),
                         ["spanning-tree vlan-id 3910 priority 20480"])
    assert preview["firmware_support"]["status"] == "untested"


def test_e22_vlan_carrying_a_protected_port_is_refused(tmp_path):
    device = LabEOS()
    device.lines[device.lines.index("spanning-tree mode mstp")] = "spanning-tree mode rapid-pvst"
    device._add_vlan("3910")
    device.vlan_ports["3910"] = ["Ethernet6"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device, protected={"interface": ["Ethernet6"]})
    preview = execute.preview(runtime, "lab-ceos", change("stp-vlan", "3910", {"priority": 20480}))
    assert preview["reason_codes"] == ["port_protected"], preview
    assert not device.applied_blocks and device.lines == device.saved


@pytest.mark.parametrize("port", ["Port-Channel200", "Ethernet1"])
def test_e22_vlan_with_automatically_protected_uplink_is_refused(tmp_path, port):
    device = LabEOS()
    device.lines[device.lines.index("spanning-tree mode mstp")] = "spanning-tree mode rapid-pvst"
    device._add_vlan("3910")
    device.vlan_ports["3910"] = [port]
    device.link_up.add(port)
    if port == "Port-Channel200":
        device._add_interface(port)
        device.insert(*capture("a-mlag-peer.txt").splitlines(), "!")
    device._set(port, re.compile("^switchport trunk allowed vlan "), "switchport trunk allowed vlan 3910")
    device._set(port, re.compile("^switchport mode "), "switchport mode trunk")
    device.write_answers["show interfaces %s switchport" % port] = (
        capture("peer-switchport.txt").replace("Name: Po200", "Name: " + eos.short_name(port))
        .replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: 3910"))
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", change("stp-vlan", "3910", {"priority": 20480}))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == ["port_uplink"], preview
    assert not device.applied_blocks and device.lines == device.saved


def test_e22_mac_table_missing_unicast_header_is_refused(tmp_path):
    device = LabEOS()
    device.write_answers["show mac address-table interface " + PORT] = "\n".join(
        capture("empty-macs.txt").splitlines()[5:13])
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", change("stp-port", PORT, {"cost": 12000}))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == ["eos_l2_readback_unreadable"], preview
    assert not device.applied_blocks and device.lines == device.saved


@pytest.mark.parametrize(("table", "key", "changes", "setup", "code"), [
    ("port-channel-member", PORT, {"group": 900, "mode": "active"}, "connected", "port_lag_active"),
    ("port-channel-member", PORT, {"group": 900, "mode": "active"}, "protected", "port_protected"),
    ("port-channel-member", PORT, {"group": 900, "mode": "active"}, "missing", "eos_l2_dependency"),
    ("stp-port", PORT, {"cost": 12000}, "cut_macs", "eos_l2_readback_unreadable"),
    ("stp-port", PORT, {"cost": 12000}, "timeout", "eos_l2_read_timeout"),
    ("stp-vlan", "3910", {"priority": 20480}, "mstp", "eos_stp_mode"),
    ("mlag-peer", "global", {"peer-address": "192.0.2.123"}, "active_mlag", "port_uplink"),
    ("mlag-port", CHANNEL, {"mlag-id": 900}, "cut_mlag", "eos_l2_readback_unreadable"),
])
def test_refusals_before_any_write(tmp_path, table, key, changes, setup, code):
    device = LabEOS()
    if setup != "missing":
        device._add_interface(CHANNEL)
    if setup == "connected":
        device.link_up.add(PORT)
    if setup == "cut_macs":
        device.write_answers["show mac address-table interface " + PORT] = capture("empty-macs.txt").split("Multicast")[0]
    if setup == "timeout":
        device.write_answers["show interfaces " + PORT + " | json"] = AccessError("SSH query timed out")
    if setup == "mstp":
        device._add_vlan("3910")
    if setup in ("active_mlag", "cut_mlag"):
        device.insert(*capture("a-mlag-peer.txt").splitlines(), "!")
        device._add_interface("Port-Channel200")
        device._add_interface("Vlan4094")
    if setup == "cut_mlag":
        device.write_answers["show mlag interfaces | json"] = capture("a-mlag-interfaces.json")[:-4]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device, protected={"interface": [CHANNEL]} if setup == "protected" else None)
    preview = execute.preview(runtime, "lab-ceos", change(table, key, changes))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == [code], preview
    assert not device.applied_blocks and device.lines == device.saved
