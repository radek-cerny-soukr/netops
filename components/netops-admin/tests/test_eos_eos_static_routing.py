"""Exercise EOS EOS-STATIC-ROUTING through Admin preview/apply/undo over the measured cEOS transport fixtures."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from fake_eos import FakeEos
from test_eos import make_runtime, request, steps
from test_eos_eos_port_maintenance import codes

from netops_admin import eos, execute
from netops_admin.access import AccessError

FIXTURES = Path(__file__).parent / "fixtures" / "eos_eos_static_routing"
ROUTES = "show running-config | include ^ip route |^ipv6 route |^end$"
VRF = "eos-static-routing-route"
SVI = "Vlan3984"
PORT = "Ethernet12"
VARP_SVI = "Vlan3985"
VARP_MAC = "00:00:5e:00:53:01"
VARP_MAC_TABLE = "show mac address-table vlan 3985"


def raw(name):
    return (FIXTURES / (name + ".txt")).read_text()


# RFC 2544 benchmarking prefix for the remapped management network: the three documentation /24s are taken by the
# anonymised baseline and the EOS-STATIC-ROUTING test port (written as a prefix so that no full non-documentation address is spelled)
MANAGEMENT_NET = "198.18.0."


class FakeL3Eos(FakeEos):
    def __init__(self):
        super().__init__()
        # The anonymised EOS-SWITCHPORT-ADMIN baseline uses the documentation network needed by the EOS-STATIC-ROUTING test port.
        self.lines = [line.replace("203.0.113.", MANAGEMENT_NET) for line in self.lines]
        self.lines[2:2] = ["vrf instance " + VRF, "!"]
        self.add_lines("no ip routing vrf " + VRF)
        for vlan, suffix in (("3984", "vrrp"), ("3985", "varp")):
            self._add_vlan(vlan)
            self._vlan_line(vlan, ["name", "eos-static-routing-" + suffix], "name eos-static-routing-" + suffix)
        self.saved = list(self.lines)
        self.ssh_status = raw("management-ssh")
        self.routes_answer = None
        self.vlan_mac_reads = []
        self.varp_mac_answer = None

    def add_lines(self, *lines):
        index = self.lines.index("end")
        self.lines[index:index] = lines

    def setup_interface(self, fixture, *, gateway=True):
        header, *children = raw(fixture).splitlines()
        self.add_lines(header, *(line for line in children if gateway or not line.strip().startswith(
            ("vrrp ", "ip virtual-router address "))), "!")
        self.saved = list(self.lines)

    def query(self, command):
        if command == ROUTES:
            if isinstance(self.routes_answer, Exception):
                raise self.routes_answer
            if self.routes_answer is not None:
                return self.routes_answer
            return "\n".join(line for line in self.lines if line.startswith(("ip route ", "ipv6 route "))
                             or line == "end") + "\n"
        if command.startswith("show running-config interfaces "):
            key = command.split()[-1]
            lines = self.interface(key)
            return "" if lines is None else "\n".join(("interface " + key, *("   " + line for line in lines))) + "\n"
        if command == "show interfaces Ethernet12 switchport":
            return raw("routed-ethernet-view" if "no switchport" in self.interface(PORT) else "ethernet-access-view")
        if command.startswith("show mac address-table vlan "):
            self.vlan_mac_reads.append(command)
        if command == VARP_MAC_TABLE and ("ip virtual-router mac-address " + VARP_MAC in self.lines):
            if isinstance(self.varp_mac_answer, AccessError):
                raise self.varp_mac_answer
            if self.varp_mac_answer is not None:
                return self.varp_mac_answer
            answer = raw("varp-vlan-cpu-mac")
            return answer.replace("Cpu", "Et1") if self.learned_macs.get("vlan 3985") else answer
        if command == "show vlan id 3984":
            return raw("vlan")
        return super().query(command)

    def check_query(self, command):
        if self.check_override is not None and command in self.check_override:
            return super().check_query(command)
        if command == "show interfaces Vlan3984 | json" and self.interface(SVI) is None:
            return raw("missing-svi-oper")
        if command == "show interfaces Ethernet12 switchport":
            return self.query(command)
        if command == "show vrf | json":
            data = json.loads(raw("vrf"))
            protocols = data["vrfs"][VRF]["protocols"]
            for family, prefix in (("ipv4", "ip routing"), ("ipv6", "ipv6 unicast-routing")):
                if prefix + " vrf " + VRF not in self.lines:
                    protocols[family]["routingState"] = "down"
            return json.dumps(data)
        if command == "show ip virtual-router | json":
            mac = next((line.split()[-1] for line in self.lines if line.startswith("ip virtual-router mac-address ")),
                       None)
            if mac is None:
                return raw("empty-varp")
            data = json.loads(raw("varp"))
            data["virtualMacs"][0]["macAddress"] = mac
            ip = next((line.split()[-1] for line in (self.interface(VARP_SVI) or [])
                       if line.startswith("ip virtual-router address ")), None)
            if ip is None:
                data["virtualRouters"].clear()
            else:
                data["virtualRouters"][0]["virtualIps"][0]["ip"] = ip
            return json.dumps(data)
        return super().check_query(command)

    def _line(self, line, mode):
        current = mode[0]
        if current == "config":
            if line == "interface " + SVI and self.interface(SVI) is None:
                self.add_lines(line, "!")
                mode[0] = "interface:" + SVI
                return ""
            if line == "no interface " + SVI:
                start, end = self._block("interface " + SVI)
                del self.lines[start:end + 1]
                return ""
            if line.startswith(("ip route ", "ipv6 route ", "no ip route ", "no ipv6 route ")):
                body = line.removeprefix("no ")
                words = body.split()
                route_and_hop = " ".join(words[:6])
                self.lines[:] = [entry for entry in self.lines
                                 if entry != route_and_hop and not entry.startswith(route_and_hop + " ")]
                if not line.startswith("no "):
                    self.add_lines(body)
                return ""
            if line.startswith(("ip routing vrf ", "ipv6 unicast-routing vrf ",
                                "no ip routing vrf ", "no ipv6 unicast-routing vrf ")):
                body = line.removeprefix("no ")
                if body.startswith("ip routing "):
                    old = body if line.startswith("no ") else "no " + body
                    self.lines[self.lines.index(old)] = line
                elif line.startswith("no "):
                    self.lines.remove(body)
                else:
                    self.add_lines(line)
                return ""
            if line.startswith("ip virtual-router mac-address "):
                self.add_lines(line)
                return ""
            if line == "no ip virtual-router mac-address":
                return "% Incomplete command"
            if line.startswith("no ip virtual-router mac-address "):
                self.lines.remove(line[3:])
                return ""
        if current.startswith("interface:"):
            target = current.split(":", 1)[1]
            body = line.removeprefix("no ")
            if body == "switchport":
                self._set(target, re.compile(r"^no switchport$"), line if line.startswith("no ") else None)
                return ""
            if body.startswith(("ip address", "ipv6 address", "vrf ", "ip virtual-router address")):
                prefix = next(p for p in ("ip address", "ipv6 address", "vrf", "ip virtual-router address")
                              if body.startswith(p))
                self._set(target, re.compile("^" + prefix + " "), None if line.startswith("no ") else line)
                return ""
            if body.startswith("vrrp "):
                prefix = " ".join(body.split()[:3]) + " "
                self._set(target, re.compile("^" + prefix), None if line.startswith("no ") else line)
                return ""
        return super()._line(line, mode)


def change(table, key, changes, op="update", **kwargs):
    return request(table=table, key=key, changes=changes, op=op, request_id="eos-static-routing-" + op, **kwargs)


def round_trip(tmp_path, device, item, commands):
    runtime = make_runtime(tmp_path, device)
    baseline = device.snapshot()
    writes = len(device.applied_blocks)
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", *commands, "end"]
    assert len(device.applied_blocks) == writes and device.snapshot() == baseline
    applied = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", (applied.get("reason"), steps(applied))
    assert device.lines == device.saved and device.snapshot() != baseline
    restored = execute.undo(runtime, applied["change_id"], "restore measured baseline")
    assert restored["result"] == "confirmed", (restored.get("reason"), steps(restored))
    assert device.snapshot() == baseline and device.lines == device.saved


@pytest.mark.parametrize(("prefix", "hop", "family"), [
    ("198.51.100.0/24", "192.0.2.1", "ip"), ("::/0", "2001:db8:1::1", "ipv6"),
])
def test_create_static_route_preview_confirm_readback_undo(tmp_path, prefix, hop, family):
    device = FakeL3Eos()
    round_trip(tmp_path, device, change("static-route", "vrf:%s:%s" % (VRF, prefix), {"next-hop": hop}, "create"),
               ["%s route vrf %s %s %s" % (family, VRF, prefix, hop)])


def test_update_static_route_replaces_only_the_old_hop(tmp_path):
    device = FakeL3Eos()
    line = next(line for line in raw("configured-global").splitlines() if line.startswith("ip route vrf "))
    device.add_lines(line)
    device.saved = list(device.lines)
    _, _, _, vrf, prefix, old = line.split()
    replacement = "192.0.2.9"
    round_trip(tmp_path, device, change("static-route", "vrf:%s:%s" % (vrf, prefix), {"next-hop": replacement}),
               [line.removesuffix(old) + replacement, "no " + line])


def test_create_svi_with_two_address_families_and_undo(tmp_path):
    device = FakeL3Eos()
    round_trip(tmp_path, device, change("l3-interface", SVI,
               {"ipv4-address": "192.0.2.2/24", "ipv6-address": "2001:db8:124::2/64", "vrf": VRF}, "create"),
               ["interface " + SVI, "vrf " + VRF, "ip address 192.0.2.2/24", "ipv6 address 2001:db8:124::2/64"])


@pytest.mark.parametrize("op", ["update", "delete"])
def test_undo_restores_svi_description_from_snapshot(tmp_path, op):
    device = FakeL3Eos()
    device.setup_interface("svi-utf8-description")
    runtime = make_runtime(tmp_path, device)
    baseline = device.snapshot()
    changes = {"description": "Sklad"} if op == "update" else {}
    item = change("l3-interface", SVI, changes, op)

    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    applied = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", steps(applied)
    assert "description Brána skladu" not in (device.interface(SVI) or [])

    reason = "Restore the SVI description"
    undo = execute.preview_undo(runtime, applied["change_id"], reason, issue=True)
    assert undo["result"] == "ready", undo
    assert "description Brána skladu" in undo["commands"]
    restored = execute.undo(runtime, applied["change_id"], reason, expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", steps(restored)
    assert device.snapshot() == baseline and device.lines == device.saved


def test_routed_port_undo_restores_switchport(tmp_path):
    device = FakeL3Eos()
    round_trip(tmp_path, device, change("l3-interface", PORT,
               {"mode": "routed", "ipv4-address": "203.0.113.2/24"}, endpoint_impact=PORT),
               raw("routed-ethernet").splitlines()[0:1] +
               [line.strip() for line in raw("routed-ethernet").splitlines()[1:]])


def test_ip_routing_matches_vrf_view_and_undo(tmp_path):
    round_trip(tmp_path, FakeL3Eos(), change("ip-routing", VRF, {"ipv4": "enabled", "ipv6": "enabled"}),
               ["ip routing vrf " + VRF, "ipv6 unicast-routing vrf " + VRF])


def test_vrrp_uses_configured_priority_and_undoes_just_the_group(tmp_path):
    device = FakeL3Eos()
    device.setup_interface("routed-svi", gateway=False)
    runtime = make_runtime(tmp_path, device)
    baseline = device.snapshot()
    key = SVI + ":24"
    item = change("vrrp", key, {"virtual-ip": "192.0.2.254", "priority": 120}, "create")

    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + SVI, "vrrp 24 priority-level 120",
                                   "vrrp 24 ipv4 192.0.2.254", "end"]
    assert not device.applied_blocks and device.snapshot() == baseline
    applied = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", steps(applied)
    assert {"vrrp 24 ipv4 192.0.2.254", "vrrp 24 priority-level 120"} <= set(device.interface(SVI))

    device.learned_macs["vlan 3984"] = 1
    writes = len(device.applied_blocks)
    assert codes(execute.preview, runtime, "lab-ceos", change("vrrp", key, {"priority": 121})) == ["port_learned_mac"]
    reason = "Restore the VRRP group state"
    device.vlan_mac_reads.clear()
    undo = execute.preview_undo(runtime, applied["change_id"], reason, issue=True)
    assert undo["result"] == "ready", undo
    assert undo["commands"] == ["configure terminal", "interface " + SVI, "no vrrp 24", "end"]
    assert len(device.applied_blocks) == writes
    assert "show mac address-table vlan 3984" in device.vlan_mac_reads
    device.vlan_mac_reads.clear()
    restored = execute.undo(runtime, applied["change_id"], reason, expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", steps(restored)
    assert "show mac address-table vlan 3984" in device.vlan_mac_reads
    assert device.snapshot() == baseline and device.lines == device.saved


def test_varp_mac_and_varp_svi_verified_via_operational_json(tmp_path):
    device = FakeL3Eos()
    round_trip(tmp_path / "mac", device, change("varp-mac", "global", {"mac-address": VARP_MAC}),
               ["ip virtual-router mac-address " + VARP_MAC])
    device.setup_interface("varp-svi", gateway=False)
    device.add_lines("ip virtual-router mac-address " + VARP_MAC)
    device.saved = list(device.lines)
    round_trip(tmp_path / "vip", device, change("varp", VARP_SVI, {"virtual-ip": "198.51.100.254"}, "create"),
               ["interface " + VARP_SVI, "ip virtual-router address 198.51.100.254"])


@pytest.mark.parametrize(("answer", "reason"), [
    ("% Invalid input\n", "eos_l3_readback_unreadable"),
    ("ip route vrf eos-static-routing-route 198.51.100.0/24 192.0.2.1\n", "eos_l3_readback_unreadable"),
    (AccessError("query timed out"), "eos_l3_read_timeout"),
])
def test_incomplete_refused_or_timed_out_route_read_does_not_write(tmp_path, answer, reason):
    device = FakeL3Eos()
    device.routes_answer = answer
    runtime = make_runtime(tmp_path, device)
    item = change("static-route", "vrf:eos-static-routing-route:198.51.100.0/24", {"next-hop": "192.0.2.1"}, "create")
    assert codes(execute.preview, runtime, "lab-ceos", item) == [reason]
    assert device.applied_blocks == []


def test_unreadable_varp_and_protected_svi_fail_closed(tmp_path):
    device = FakeL3Eos()
    device.check_override = {"show ip virtual-router | json": raw("varp").split('"virtualRouters"')[0]}
    runtime = make_runtime(tmp_path, device, protected={"vlan": ["3984"]})
    assert codes(execute.preview, runtime, "lab-ceos", change("varp-mac", "global", {"mac-address": VARP_MAC})) == [
        "eos_l3_readback_unreadable"]
    assert codes(execute.preview, runtime, "lab-ceos", change("l3-interface", SVI, {}, "create")) == ["port_protected"]
    assert device.applied_blocks == []


def test_management_default_route_and_connected_port_are_protected(tmp_path):
    device = FakeL3Eos()
    runtime = make_runtime(tmp_path, device)
    assert codes(execute.preview, runtime, "lab-ceos", change("static-route", "0.0.0.0/0",
                                                            {"next-hop": MANAGEMENT_NET + "2"})) == ["port_management_interface"]
    assert codes(execute.preview, runtime, "lab-ceos", change("l3-interface", PORT, {"mode": "routed"})) == [
        "endpoint_impact_required"]
    assert device.applied_blocks == []


def test_prediction_preserves_unmanaged_svi_configuration(tmp_path):
    device = FakeL3Eos()
    device.setup_interface("routed-svi", gateway=False)
    baseline = device.snapshot()
    runtime = make_runtime(tmp_path, device)
    item = change("l3-interface", SVI, {"ipv6-address": "2001:db8:124::8/64"})
    preview = execute.preview(runtime, "lab-ceos", item)
    applied = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", steps(applied)
    plan = runtime.store.operation(applied["change_id"])["plan"]
    predicted = eos.load(eos.snapshot_after(baseline, plan), "4.36.1F")
    assert "no autostate" in predicted.interface_lines(SVI)
    assert "ipv6 address 2001:db8:124::8/64" in predicted.interface_lines(SVI)
    assert execute.undo(runtime, applied["change_id"], "Restore IPv6 prefix")["result"] == "confirmed"
    assert device.snapshot() == baseline


def test_incomplete_vlan_read_refuses_before_any_write(tmp_path):
    device = FakeL3Eos()
    device.query_status = lambda command: (0, "VLAN  Name  Status") if command == "show vlan id 3984" else (0, "")
    runtime = make_runtime(tmp_path, device)
    assert codes(execute.preview, runtime, "lab-ceos", change("l3-interface", SVI, {}, "create")) == [
        "eos_l3_readback_unreadable"]
    assert device.applied_blocks == []


def test_varp_refuses_a_static_mac_on_a_physical_port(tmp_path):
    device = FakeL3Eos()
    device.setup_interface("varp-svi", gateway=False)
    device.add_lines("ip virtual-router mac-address " + VARP_MAC)
    device.saved = list(device.lines)
    device.learned_macs["vlan 3985"] = 1
    runtime = make_runtime(tmp_path, device)
    item = change("varp", VARP_SVI, {"virtual-ip": "198.51.100.254"}, "create")
    assert codes(execute.preview, runtime, "lab-ceos", item) == ["port_learned_mac"]
    assert device.applied_blocks == []


@pytest.mark.parametrize(("answer", "refusal"), [
    pytest.param(raw("varp-vlan-cpu-mac").replace("Cpu", "Et1"), "port_learned_mac", id="static-et1"),
    pytest.param(raw("varp-vlan-cpu-mac").replace("3985    0000.5e00.5301    STATIC      Cpu\n", ""),
                 "port_usage_unreadable", id="missing-row"),
    pytest.param(raw("varp-vlan-cpu-mac").replace("Total Mac Addresses for this criterion: 1\n", ""),
                 "port_usage_unreadable", id="missing-unicast-total"),
    pytest.param(AccessError("exit status 1"), "eos_l3_readback_unreadable", id="unavailable"),
    pytest.param(AccessError("query timed out"), "eos_l3_read_timeout", id="timeout"),
])
def test_varp_undo_refuses_unsafe_mac_table(tmp_path, answer, refusal):
    device = FakeL3Eos()
    device.setup_interface("varp-svi", gateway=False)
    device.add_lines("ip virtual-router mac-address " + VARP_MAC)
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    item = change("varp", VARP_SVI, {"virtual-ip": "198.51.100.254"}, "create")
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    applied = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", steps(applied)
    baseline = device.snapshot()
    writes = len(device.applied_blocks)

    reason = "Restore the VARP virtual address state"
    undo = execute.preview_undo(runtime, applied["change_id"], reason, issue=True)
    assert undo["result"] == "ready", undo

    device.varp_mac_answer = answer
    assert codes(execute.preview_undo, runtime, applied["change_id"], reason) == [refusal]
    assert codes(execute.undo, runtime, applied["change_id"], reason, undo["plan_sha256"]) == [refusal]
    assert len(device.applied_blocks) == writes
    assert device.snapshot() == baseline and device.lines == device.saved
