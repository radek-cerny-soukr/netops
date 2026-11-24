import re
from pathlib import Path

import pytest

from fake_nxos import FakeNxos
from netops_admin import execute, nxos
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_nxos import FIRMWARE, KEY, make_runtime, request

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_switchport_admin"
VLAN = "3900"
NAME = "netops-nx-port-base"


def captured(case):
    return (FIXTURES / ("nexus9300v__" + case + ".txt")).read_text()


def switch_pair_trunk():
    return (FIXTURES / "nexus-peer-a__uplink-switchport.txt").read_text()


class LabNxos(FakeNxos):
    def __init__(self):
        super().__init__()
        self.occupied = False
        self.client_learned = True
        self.cdp_neighbor = False
        self.port_read_error = None
        self.vlan_read_override = None

    def _vlan_name(self):
        if "vlan " + VLAN not in self.body:
            return None
        first, end = self._block("vlan " + VLAN)
        return next((line.strip()[5:] for line in self.body[first + 1:end] if line.startswith("  name ")), None)

    def _line(self, line, mode):
        if mode[0] == "config" and line == "vlan " + VLAN:
            if VLAN not in self.vlans():
                index = self.body.index("vlan 1,10,20")
                self.body[index] = next(row for row in captured("vlan-created-config").splitlines()
                                        if row.startswith("vlan 1,"))
            mode[0] = "vlan"
            return ""
        if mode[0] == "config" and line == "no vlan " + VLAN:
            if "vlan " + VLAN in self.body:
                first, end = self._block("vlan " + VLAN)
                del self.body[first:end]
            self.body[self.body.index("vlan 1,10,20,3900")] = "vlan 1,10,20"
            return ""
        if mode[0] == "vlan" and (line.startswith("name ") or line == "no name"):
            if "vlan " + VLAN in self.body:
                first, end = self._block("vlan " + VLAN)
                del self.body[first:end]
            if line != "no name":
                _, insertion = self._block("vlan 20")
                self.body[insertion:insertion] = ["vlan " + VLAN, "  " + line]
            return ""
        return super()._line(line, mode)

    def _interface_line(self, name, words, line):
        for prefix, default in (("switchport mode", "access"), ("switchport trunk allowed vlan", "all"),
                                ("switchport trunk native vlan", "1")):
            if line.startswith(prefix + " ") or line == "no " + prefix:
                self._set(name, re.compile("^" + prefix + " "),
                          None if line in ("no " + prefix, prefix + " " + default) else line)
                return ""
        return super()._interface_line(name, words, line)

    def _interface_query(self, command):
        if command == "show interface " + KEY + " switchport" and self.interface(KEY) is not None:
            lines = self.interface(KEY)
            is_trunk = "switchport mode trunk" in lines
            if is_trunk:
                text = switch_pair_trunk().replace("Name: Ethernet1/1\n", "Name: Ethernet1/48\n")
            else:
                text = super()._interface_query(command)
            native = next((line.split()[-1] for line in lines
                           if line.startswith("switchport trunk native vlan ")), "1")
            allowed = next((line.split()[-1] for line in lines
                            if line.startswith("switchport trunk allowed vlan ")), "1-4094")
            text = re.sub(r"Trunking Native Mode VLAN: .*", "Trunking Native Mode VLAN: " + native, text)
            return re.sub(r"Trunking VLANs Allowed: .*", "Trunking VLANs Allowed: " + allowed, text)
        return super()._interface_query(command)

    def query(self, command):
        if command == "show cdp neighbors":
            text = captured("cdp")
            return text.replace("mgmt0", "Eth1/48", 1) if self.cdp_neighbor else text
        if command == "show system vlan reserved":
            return captured("reserved")
        if command == "show vlan id " + VLAN:
            if VLAN not in self.vlans():
                return captured("vlan-absent")
            name = self._vlan_name() or "VLAN3900"
            # The default-name case replaces just the measured value in its original fixed-width column.
            return captured("vlan-created").replace(f"{NAME:32}", f"{name:32}")
        if command == "show mac address-table vlan " + VLAN:
            return captured("port-mac")
        if command == "show mac address-table interface " + KEY:
            if self.port_read_error:
                raise self.port_read_error
            if self.occupied and "shutdown" not in self.interface(KEY):
                if self.client_learned:
                    return captured("occupied-mac").replace("Eth1/2", "Eth1/48")
                return captured("port-mac")
        if command == "show interface " + KEY + " status" and self.occupied and "shutdown" not in self.interface(KEY):
            vlan = next((line.split()[-1] for line in self.interface(KEY)
                         if line.startswith("switchport access vlan ")), "1")
            return captured("occupied-status").replace("Eth1/2 ", "Eth1/48").replace("connected 20", f"connected {vlan:2}")
        return super().query(command)

    def check_query(self, command):
        if command == "show vlan id " + VLAN:
            self.check_queries.append(command)
            return self.vlan_read_override if self.vlan_read_override is not None else self.query(command)
        return super().check_query(command)


@pytest.fixture
def lab(tmp_path):
    device = LabNxos()
    return device, make_runtime(tmp_path, device)


def confirmed(runtime, req):
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert "postcheck_passed" in {step["step"] for step in record["steps"]}
    return record


def undone(runtime, record):
    preview = execute.preview_undo(runtime, record["change_id"], "restore measured device state", issue=True)
    assert preview["result"] == "ready", preview
    result = execute.undo(runtime, record["change_id"], "restore measured device state",
                          expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result


def test_occupied_port_binds_endpoint_impact_and_undo(lab):
    device, runtime = lab
    device.occupied = True
    device._set(KEY, re.compile(r"^switchport access vlan "), "switchport access vlan 20")
    device.saved = device._config()
    before = device.running()
    changes = {"admin-state": "disabled"}
    not_approved = execute.preview(runtime, "lab-nxos", request(changes=changes))
    assert not_approved["reason_codes"] == ["port_learned_mac"]
    approved_request = request(changes=changes, endpoint_impact=KEY)
    preview = execute.preview(runtime, "lab-nxos", approved_request)
    assert preview["result"] == "ready", preview
    assert preview["port_impact"] == {"link": "connected", "mode": "access", "vlan": "20", "learned_macs": "1"}
    assert device.applied_blocks == []
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, "lab-nxos", approved_request)
    assert device.applied_blocks == []
    device.occupied = False
    with pytest.raises(Rejected) as changed:
        execute.apply(runtime, "lab-nxos", approved_request, expected_plan_sha256=preview["plan_sha256"])
    assert changed.value.reason_codes == ["plan_changed"] and device.applied_blocks == []
    device.occupied = True
    record = confirmed(runtime, approved_request)
    assert "shutdown" in device.interface(KEY)
    undone(runtime, record)
    assert nxos.load(device.running(), FIRMWARE).lines[3:] == nxos.load(before, FIRMWARE).lines[3:]
    assert device.clean()


def test_port_with_retained_cdp_neighbor_is_protected_even_when_down(lab):
    device, runtime = lab
    device.cdp_neighbor = True
    preview = execute.preview(runtime, "lab-nxos", request(changes={"admin-state": "disabled"}))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["port_cdp_neighbor"]
    assert not device.applied_blocks


def test_connected_access_vlan_undo_before_client_relearns_mac(lab):
    device, runtime = lab
    device.occupied = True
    device._set(KEY, re.compile(r"^switchport access vlan "), "switchport access vlan 20")
    device.saved = initial = device._config()

    moved = confirmed(runtime, request(table="vlan-membership", changes={"access-vlan": 10}, endpoint_impact=KEY))
    device.client_learned = False
    assert execute.preview(runtime, "lab-nxos", request(table="vlan-membership", changes={"access-vlan": 20},
                                                        endpoint_impact=KEY, request_id="new-move"))["reason_codes"] == [
        "port_uplink"]
    preview = execute.preview_undo(runtime, moved["change_id"], "restore access VLAN")
    assert preview["result"] == "ready", preview
    assert preview["port_impact"] == {"link": "connected", "mode": "access", "vlan": "10", "learned_macs": "0"}

    device.lldp_extra.append("Eth1/48")
    assert execute.preview_undo(runtime, moved["change_id"], "restore access VLAN")["reason_codes"] == [
        "port_lldp_neighbor"]
    device.lldp_extra.clear()
    device.cdp_neighbor = True
    assert execute.preview_undo(runtime, moved["change_id"], "restore access VLAN")["reason_codes"] == [
        "port_cdp_neighbor"]
    device.cdp_neighbor = False

    undone(runtime, moved)
    assert device._config() == initial and device.clean()


@pytest.mark.parametrize("failure, code", [("truncated", "port_usage_unreadable"), ("timeout", "nxos_l2_read_timeout")])
def test_port_preflight_error_is_explicit_and_read_only(lab, monkeypatch, failure, code):
    device, runtime = lab
    if failure == "timeout":
        device.port_read_error = AccessError("query timed out")
    else:
        text = captured("port-mac")
        original = device.query

        def incomplete(command):
            if command == "show mac address-table interface " + KEY:
                return text[:text.index("---------+")]
            return original(command)

        monkeypatch.setattr(device, "query", incomplete)
    result = execute.preview(runtime, "lab-nxos", request(changes={"admin-state": "disabled"}, endpoint_impact=KEY))
    assert result["result"] == "rejected" and result["reason_codes"] == [code]
    assert device.applied_blocks == []


def test_vlan_cannot_be_activated_by_creating_an_already_referenced_id(lab):
    device, runtime = lab
    device._set(KEY, re.compile(r"^switchport access vlan "), "switchport access vlan " + VLAN)
    device.saved = device._config()
    preview = execute.preview(runtime, "lab-nxos", request(table="vlan", op="create", key=VLAN,
                                                         changes={"name": NAME}))
    assert preview["reason_codes"] == ["vlan_in_use"]
    assert device.applied_blocks == []


def test_vlan_lifecycle_keeps_aggregate_header_and_restores_exact_name(lab):
    device, runtime = lab
    initial = device._config()
    create = request(table="vlan", op="create", key=VLAN, changes={"name": NAME}, request_id="nxos-switchport-admin-create")
    preview = execute.preview(runtime, "lab-nxos", create)
    assert preview["predicted"] == {"before": None, "after": {"name": NAME}}
    assert device.applied_blocks == []
    created = confirmed(runtime, create)
    base = device._config()
    rename = request(table="vlan", key=VLAN, changes={"name": "netops-nxos-switchport-admin-new"}, request_id="nxos-switchport-admin-rename")
    renamed = confirmed(runtime, rename)
    assert device._vlan_name() == "netops-nxos-switchport-admin-new"
    undone(runtime, renamed)
    assert device._config() == base
    delete = request(table="vlan", op="delete", key=VLAN, changes={}, request_id="nxos-switchport-admin-delete")
    deleted = confirmed(runtime, delete)
    assert VLAN not in device.vlans()
    undone(runtime, deleted)
    assert device._config() == base
    undone(runtime, created)
    assert device._config() == initial and device.clean()


def test_vlan_delete_undo_recreates_existing_unnamed_vlan(lab):
    device, runtime = lab
    device.body[device.body.index("vlan 1,10,20")] = "vlan 1,10,20,3900"
    device.saved = device._config()
    initial = device._config()
    deleted = confirmed(runtime, request(table="vlan", op="delete", key=VLAN, changes={}))
    assert deleted["plan"]["predicted"] == {"before": {}, "after": None}
    undone(runtime, deleted)
    assert device._config() == initial and device.clean()


def test_vlan_readback_requires_a_complete_table(lab):
    device, runtime = lab
    device.body[device.body.index("vlan 1,10,20")] = "vlan 1,10,20,3900"
    device.saved = device._config()
    device.vlan_read_override = captured("vlan-created").split("VLAN Type")[0]
    result = execute.preview(runtime, "lab-nxos", request(table="vlan", op="delete", key=VLAN, changes={}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_usage_unreadable"]
    assert device.applied_blocks == []


def test_trunk_mode_vlans_and_dormant_settings_are_reversible(lab):
    device, runtime = lab
    initial = device._config()
    changes = {"mode": "trunk", "allowed-vlans": "20,1,10", "native-vlan": 20}
    refused = execute.preview(runtime, "lab-nxos", request(table="vlan-membership", changes=changes))
    assert refused["reason_codes"] == ["endpoint_impact_required"]
    assert device.applied_blocks == []
    trunk_request = request(table="vlan-membership", changes=changes, endpoint_impact=KEY, request_id="nxos-switchport-admin-trunk")
    trunk = confirmed(runtime, trunk_request)
    assert trunk["plan"]["commands"] == [
        "configure terminal", "interface Ethernet1/48", "switchport trunk allowed vlan 1,10,20",
        "switchport trunk native vlan 20", "switchport mode trunk", "end",
    ]
    trunk_lines = set(device.interface(KEY))

    prune = request(table="vlan-membership", changes={"allowed-vlans": "10,20"}, endpoint_impact=KEY,
                    request_id="nxos-switchport-admin-prune")
    pruned = confirmed(runtime, prune)
    assert pruned["plan"]["commands"][2:-1] == ["switchport trunk allowed vlan 10,20"]
    undone(runtime, pruned)
    assert set(device.interface(KEY)) == trunk_lines

    access = request(table="vlan-membership", changes={"mode": "access"}, endpoint_impact=KEY,
                     request_id="nxos-switchport-admin-access")
    converted = confirmed(runtime, access)
    assert converted["plan"]["predicted"]["after"] == {"allowed-vlans": "1,10,20", "native-vlan": "20"}
    assert converted["plan"]["commands"][2:-1] == ["switchport mode access"]
    undone(runtime, converted)
    assert set(device.interface(KEY)) == trunk_lines
    undone(runtime, trunk)
    assert device._config() == initial and device.clean()


def test_trunk_prunes_default_allowed_vlans_and_undo_restores_all(lab):
    device, runtime = lab
    device._set(KEY, re.compile(r"^switchport mode "), "switchport mode trunk")
    device.saved = initial = device._config()
    assert device.vlans() == {"1", "10", "20"}

    pruned = confirmed(runtime, request(table="vlan-membership", changes={"allowed-vlans": "1-19,21-4094"},
                                        endpoint_impact=KEY))
    assert pruned["plan"]["predicted"] == {"before": {"mode": "trunk"},
                                            "after": {"mode": "trunk", "allowed-vlans": "1-19,21-4094"}}
    assert pruned["plan"]["inverse"][2:-1] == ["no switchport trunk allowed vlan"]

    undone(runtime, pruned)
    assert device._config() == initial and device.clean()


def test_trunk_refuses_unidentified_live_link_even_with_impact(lab):
    device, runtime = lab
    device.occupied = True
    result = execute.preview(runtime, "lab-nxos", request(table="vlan-membership", changes={"mode": "trunk"},
                                                          endpoint_impact=KEY))
    assert result["reason_codes"] == ["port_uplink"]
    assert device.applied_blocks == []
