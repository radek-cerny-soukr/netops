"""1.0.12 IOS-STATIC-ROUTING (IOS-M025 static routes, IOS-M026 L3 interfaces) on IOS over real anonymised answers.

The fixtures (fixtures/ios_ios_static_routing, PROVENANCE.md) were captured in GNS3 on Cisco IOSv 15.9(3)M12
and Cisco IOSvL2 15.2(20200924:215240) by independent CLI sessions of the write account and
the privilege-1 check account (verification, private measurement record). G62Ios is the XE-STATIC-ROUTING fake router
(FakeIos with the L3 lines) started from these running configurations; it adds the measured IOS behaviour: a new SVI
starts with shutdown, a second subinterface of a port with the same VID is refused and still created, a deleted SVI
disappears from show interfaces description while a deleted subinterface stays "deleted".
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ios import FakeIos
from test_ios import make_runtime, steps
from test_ios_xe_static_routing import G80Ios

from netops_admin import engine, exec_ios, execute, ios
from netops_admin.access import DeviceAccess
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from approved_apply import approved_apply

F = Path(__file__).parent / "fixtures" / "ios_ios_static_routing"
FW = {"iosv": "15.9(3)M12", "iosvl2": "15.2(20200924:215240)"}


def fixture(node, name):
    return (F / node / name).read_text()


# Derived (PROVENANCE.md): the anonymiser has only three documentation /24 networks, so the VLAN 20 addresses
# (Gi0/1.20 of iosv, Vlan20 of iosvl2) landed in the /24 of VLAN 10 and would overlap it; they are moved to a free
# documentation subnet so that the plans see the measured, non-overlapping layout.
VLAN20 = ((" ip address 203.0.113.254 255.255.255.0\n", " ip address 198.51.100.161 255.255.255.240\n"),
          (" ip address 203.0.113.246 255.255.255.0\n", " ip address 198.51.100.162 255.255.255.240\n"))


def unoverlapped(text):
    for old, new in VLAN20:
        text = text.replace(old, new)
    return text


BASE = {node: unoverlapped(fixture(node, "admin-show-running-config__baseline.txt")) for node in FW}
ROUTES = unoverlapped(fixture("iosv", "admin-show-running-config__routes.txt"))
OBJECTS = unoverlapped(fixture("iosv", "admin-show-running-config__objects.txt"))
SWITCH_OBJECTS = unoverlapped(fixture("iosvl2", "admin-show-running-config__objects.txt"))


def ios_spelling(line):
    """IOS writes IPv6 in capitals, compressed, with single spaces; the anonymiser wrote lower case, '::0/64' and
    widened columns. The fake device keeps the IOS spelling, which its 'no' lines match."""
    words = line.split()
    if line.startswith(("ip route", "ipv6 route", " ip address", " ipv6 address")):
        words = [str(ipaddress.ip_interface(word)).upper() if ":" in word and "/" in word
                 else str(ipaddress.ip_address(word)).upper() if ":" in word else word for word in words]
        return (" " if line.startswith(" ") else "") + " ".join(words)
    return line


def request(table, op, key, changes=None, request_id="req-ios-static-routing-0001"):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {}, request_id=request_id))


def plan(req, text=None, node="iosv", **kwargs):
    return engine.build_plan("ios", (text or BASE[node]).encode(), req, firmware=FW[node], **kwargs)


class G62Ios(G80Ios):
    def __init__(self, node="iosv", text=None):
        FakeIos.__init__(self, node)
        text = text or BASE[node]
        self.header = text[:text.index("Building configuration...")]
        self.lines = [ios_spelling(line) for line in text[text.index("Building configuration..."):].rstrip("\n")
                      .split("\n")]
        self.saved = list(self.lines)
        self.hostname = re.search(r"^hostname (\S+)$", text, re.MULTILINE).group(1)
        self.deleted = set()
        self.query_override = {command: fixture(node, "admin-show-%s__baseline.txt" % name) for command, name in (
            ("show tcp brief", "tcp-brief"), ("show ip interface brief", "ip-interface-brief"),
            ("show lldp neighbors", "lldp-neighbors"), ("show cdp neighbors", "cdp-neighbors"))}
        if node == "iosvl2":
            empty = fixture(node, "admin-show-mac-address-table-vlan-900__baseline.txt")
            self.query_override["show mac address-table vlan 10"] = fixture(
                node, "admin-show-mac-address-table-vlan-10__baseline.txt")
            for vid in range(900, 910):
                self.query_override["show mac address-table vlan %d" % vid] = empty

    def _create(self, name):
        super()._create(name)
        if ios.SVI.match(name):
            # measured: a new SVI starts with " no ip address" and " shutdown"
            start, end = self._block("interface " + name)
            self.lines.insert(end, " shutdown")

    def _l3(self, name, words, line, mode):
        if words[:2] == ["encapsulation", "dot1Q"]:
            parent = ios.SUBINTERFACE.match(name).group(1)
            for other in [line.split()[1] for line in self.lines if line.startswith("interface " + parent + ".")]:
                if other != name and "encapsulation dot1Q " + words[2] in self.interface(other):
                    # the measured answer; the empty subinterface stays in the running configuration
                    return ("%%Configuration of multiple subinterfaces of the same main\ninterface with the same VID "
                            "(%s) is not permitted.\nThis VID is already configured on %s." % (words[2], other))
        return super()._l3(name, words, line, mode)

    def check_query(self, command):
        if command == "show interfaces description" and not (self.check_override and command in self.check_override):
            self.check_queries.append(command)
            snapshot = ios.load(self.snapshot(), self.firmware)
            rows = fixture(self.node, "ro-show-interfaces-description__baseline.txt").strip("\n").split("\n")
            names = [name for name in snapshot.interfaces if ios.L3_KEY.fullmatch(name)] + sorted(self.deleted)
            for name in names:
                lines = snapshot.interface_lines(name)
                parent = ios.SUBINTERFACE.match(name)
                down = "shutdown" in lines or (parent is not None
                                               and "shutdown" in snapshot.interface_lines(parent.group(1)))
                status = "deleted" if name in self.deleted else "admin down" if down else "up"
                description = next((item[len("description "):] for item in lines if item.startswith("description ")),
                                   "")
                row = "%-31s%-15s%-9s%s" % (ios.short_name(name), status, "up" if status == "up" else "down",
                                            description)
                same = [index for index, old in enumerate(rows) if old.split()[:1] == [ios.short_name(name)]]
                if same:
                    rows[same[0]] = row
                else:
                    rows.append(row)
            # a deleted SVI or Loopback disappears (measured), a deleted subinterface stays "deleted"
            shown = {ios.short_name(name) for name in list(snapshot.interfaces) + sorted(self.deleted)}
            rows = [row for row in rows if row.startswith("Interface ") or row.split()[:1] and row.split()[0] in shown]
            return "\n" + "\n".join(rows) + "\n"
        return super().check_query(command)

    def _static(self, snapshot, four, vrf):
        legend = fixture("iosv", "ro-show-ip-static-route-vrf-blue__baseline.txt" if four
                         else "ro-show-ipv6-static-vrf-blue__baseline.txt")
        if not four:
            legend = legend.replace("IPv6 Static routes Table - blue", "IPv6 Static routes Table - %s" % (vrf or "default"))
        rows = []
        for block in snapshot.blocks:
            words = block.header.split()
            if words[:2] != (["ip", "route"] if four else ["ipv6", "route"]):
                continue
            rest = words[2:]
            if (rest[:1] == ["vrf"]) != (vrf is not None) or (vrf is not None and rest[1] != vrf):
                continue
            rest = rest[2:] if vrf else rest
            if four:
                network = ios._route_line(block.header)[0].split(":")[-1]
                distance = rest[3] if len(rest) > 3 and rest[3].isdigit() else "1"
                rows.append("M  %s [%s/0] via %s [A]" % (network, distance, rest[2]))
            else:
                distance = rest[2] if len(rest) > 2 else "1"
                rows.append("*   %s via %s, distance %s" % (rest[0], rest[1], distance))
        if four and not rows:
            return legend
        if four:
            return legend.rstrip("\n") + "\n\nStatic local RIB for %s \n\n" % (vrf or "default") + "\n".join(rows) + "\n"
        return legend.rstrip("\n") + "\n" + "\n".join(rows) + "\n"


def runtime(tmp_path, device):
    return make_runtime(tmp_path, device)


DEVICE = {node: SimpleNamespace(platform="ios", firmware=FW[node]) for node in FW}


# ---- profiles ----

def test_ios_profiles_are_measured_on_both_images():
    from netops_admin import profiles
    loaded = profiles.load_profiles()
    for table in ("static-route", "l3-interface"):
        profile = loaded[("ios", table)]
        assert profile.versions == ("15.9(3)M12", "15.2(20200924:215240)") and profile.ops == ("create", "update", "delete")
        assert "IOSv 15.9(3)M12" in profile.rollback_evidence
    pattern = loaded[("ios", "l3-interface")].key_pattern
    assert all(pattern.fullmatch(key) for key in ("Vlan900", "Vlan4094", "Loopback900", "GigabitEthernet0/3.900"))
    assert not any(pattern.fullmatch(key) for key in ("Vlan0", "Vlan4095", "GigabitEthernet0/3", "Port-channel1"))
    assert not loaded[("iosxe", "l3-interface")].key_pattern.fullmatch("Vlan900")


# ---- static routes: plans from the measured running configuration ----

def test_routes_of_the_measured_ios_configuration():
    entries = ios.load(ROUTES, FW["iosv"]).entries("static-route")
    assert entries["198.51.100.0/25"].attributes == {"next-hop": "203.0.113.7"}
    assert entries["198.51.100.128/26"].attributes == {"next-hop": "203.0.113.7", "distance": "50"}
    assert entries["vrf:blue:198.51.100.192/27"].attributes == {"next-hop": "203.0.113.247"}
    assert entries["2001:db8:a::/64"].attributes == {"next-hop": "2001:db8:7::7"}
    assert entries["vrf:blue:2001:db8:b::/64"].attributes == {"next-hop": "2001:db8:8::7", "distance": "9"}
    assert entries["198.51.100.224/28"].unsupported and entries["198.51.100.240/29"].unsupported


def test_ipv4_and_vrf_ipv6_route_create_render_the_measured_lines():
    p = plan(request("static-route", "create", "198.51.100.0/25", {"next-hop": "203.0.113.7"}))
    assert p["commands"] == ["configure terminal", "ip route 198.51.100.0 255.255.255.128 203.0.113.7", "end"]
    assert p["inverse"] == ["configure terminal", "no ip route 198.51.100.0 255.255.255.128 203.0.113.7", "end"]
    six = plan(request("static-route", "create", "vrf:blue:2001:db8:b::/64", {"next-hop": "2001:DB8:8::7", "distance": 9}))
    assert six["commands"][1] == "ipv6 route vrf blue 2001:db8:b::/64 2001:db8:8::7 9"
    assert six["inverse"][1] == "no ipv6 route vrf blue 2001:db8:b::/64 2001:db8:8::7"
    four = plan(request("static-route", "create", "vrf:blue:198.51.100.192/27", {"next-hop": "203.0.113.247"}))
    assert four["commands"][1] == "ip route vrf blue 198.51.100.192 255.255.255.224 203.0.113.247"


def test_route_update_and_delete_on_the_measured_routes():
    distance = plan(request("static-route", "update", "198.51.100.0/25", {"distance": 20}), ROUTES)
    assert distance["commands"][1:-1] == ["ip route 198.51.100.0 255.255.255.128 203.0.113.7 20"]
    assert distance["inverse"][1:-1] == ["ip route 198.51.100.0 255.255.255.128 203.0.113.7"]
    hop = plan(request("static-route", "update", "198.51.100.128/26", {"next-hop": "203.0.113.8"}), ROUTES)
    assert hop["commands"][1:-1] == ["ip route 198.51.100.128 255.255.255.192 203.0.113.8 50",
                                     "no ip route 198.51.100.128 255.255.255.192 203.0.113.7"]
    deleted = plan(request("static-route", "delete", "vrf:blue:2001:db8:b::/64"), ROUTES)
    assert deleted["commands"][1:-1] == ["no ipv6 route vrf blue 2001:db8:b::/64 2001:db8:8::7"]
    assert deleted["inverse"][1:-1] == ["ipv6 route vrf blue 2001:db8:b::/64 2001:db8:8::7 9"]


@pytest.mark.parametrize("key,changes,message", [
    ("0.0.0.0/0", {"next-hop": "203.0.113.7"}, "protected"),
    ("vrf:blue:0.0.0.0/0", {"next-hop": "203.0.113.247"}, "default route"),
    ("vrf:red:198.51.100.0/25", {"next-hop": "203.0.113.7"}, "not defined"),
    ("198.51.100.0/25", {"next-hop": "2001:db8:7::7"}, "not an IPv4"),
    ("2001:db8:a::/64", {"next-hop": "2001:db8:7::7", "distance": 255}, "1..254"),
])
def test_route_refusals_before_any_write(key, changes, message):
    with pytest.raises(Rejected, match=message):
        plan(request("static-route", "create", key, changes))


@pytest.mark.parametrize("key", ["198.51.100.224/28", "198.51.100.240/29"])
def test_interface_next_hop_and_named_route_are_outside_the_profile(key):
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("static-route", "delete", key), ROUTES)


def test_check_account_route_answers_of_ios():
    def state(name, key, node="iosv"):
        return ios.static_route_state(fixture(node, name), key)
    assert state("ro-show-ip-static-route__routes.txt", "198.51.100.128/26") == {"next-hop": "203.0.113.7",
                                                                                "distance": "50"}
    assert state("ro-show-ip-static-route__distance.txt", "198.51.100.0/25") == {"next-hop": "203.0.113.7",
                                                                                "distance": "20"}
    assert state("ro-show-ip-static-route-vrf-blue__routes.txt", "vrf:blue:198.51.100.192/27") == {
        "next-hop": "203.0.113.247", "distance": "1"}
    assert state("ro-show-ipv6-static-vrf-blue__routes.txt", "vrf:blue:2001:db8:b::/64") == {
        "next-hop": "2001:db8:8::7", "distance": "9"}
    assert state("ro-show-ipv6-static__distance.txt", "2001:db8:a::/64") == {"next-hop": "2001:db8:7::7",
                                                                            "distance": "30"}
    # IOSvL2 without ipv6 unicast-routing: the route is configured but not installed (no '*')
    assert state("ro-show-ipv6-static__routes.txt", "2001:db8:a::/64", "iosvl2") == {"next-hop": "2001:db8:7::1",
                                                                                    "distance": "1"}
    assert state("ro-show-ip-static-route__baseline.txt", "198.51.100.0/25") is None
    # a VRF without static routes: only the legend, which reads "Codes in []" on IOS 15 (XE-STATIC-ROUTING knew "Codes in ()")
    assert state("ro-show-ip-static-route-vrf-blue__baseline.txt", "vrf:blue:198.51.100.192/27") is None
    # a VRF whose last route was removed: the RIB line without rows
    assert state("ro-show-ip-static-route-vrf-blue__empty.txt", "vrf:blue:198.51.100.192/27") is None
    assert state("ro-show-ipv6-static-vrf-blue__empty.txt", "vrf:blue:2001:db8:b::/64") is None
    with pytest.raises(Rejected, match="2 next hops"):
        state("ro-show-ip-static-route__two-hops.txt", "198.51.100.0/25")
    with pytest.raises(Rejected, match="2 next hops"):
        state("ro-show-ipv6-static__two-hops.txt", "2001:db8:a::/64")
    with pytest.raises(Rejected, match="not a route through an address"):
        state("ro-show-ip-static-route__routes.txt", "198.51.100.224/28")
    with pytest.raises(Rejected, match="not recognised"):
        state("ro-show-ip-interface-Loopback900__objects.txt", "198.51.100.0/25")


# ---- L3 interfaces ----

def test_l3_entries_of_the_measured_router_and_switch():
    entries = ios.load(OBJECTS, FW["iosv"]).entries("l3-interface")
    assert entries["Loopback900"].attributes == {"description": "netops-ios-static-routing test",
                                                 "ipv4-address": "198.51.100.1 255.255.255.240",
                                                 "ipv6-address": "2001:db8:2::1/64"}
    assert entries["Loopback901"].attributes == {"description": "netops-ios-static-routing vrf", "vrf": "blue",
                                                 "ipv4-address": "198.51.100.17 255.255.255.240",
                                                 "ipv6-address": "2001:db8:3::1/64"}
    assert entries["GigabitEthernet0/3.900"].attributes == {"encapsulation": "900",
                                                            "ipv4-address": "198.51.100.33 255.255.255.240",
                                                            "ipv6-address": "2001:db8:1::1/64"}
    assert entries["GigabitEthernet0/1.10"].unsupported and "GigabitEthernet0/3" not in entries
    switch = ios.load(SWITCH_OBJECTS, FW["iosvl2"]).entries("l3-interface")
    assert switch["Vlan900"].attributes == {"description": "netops-ios-static-routing svi", "admin-state": "disabled",
                                            "ipv4-address": "198.51.100.65 255.255.255.240",
                                            "ipv6-address": "2001:db8:c::1/64"}
    assert switch["Vlan10"].attributes == {"ipv4-address": "203.0.113.2 255.255.255.0"}
    bare = fixture("iosvl2", "admin-show-running-config-interface-Vlan900__bare.txt")
    assert [line.strip() for line in bare.splitlines() if line.startswith(" ")] == ["no ip address", "shutdown"]


def test_svi_create_adds_no_shutdown_because_a_new_svi_starts_shut():
    p = plan(request("l3-interface", "create", "Vlan900", {"description": "netops-ios-static-routing svi",
                                                           "ipv4-address": "198.51.100.65/28",
                                                           "ipv6-address": "2001:db8:c::1/64"}), node="iosvl2")
    assert p["commands"] == ["configure terminal", "interface Vlan900", "no shutdown", "description netops-ios-static-routing svi",
                             "ip address 198.51.100.65 255.255.255.240", "ipv6 address 2001:db8:c::1/64", "end"]
    assert p["inverse"] == ["configure terminal", "no interface Vlan900", "end"]
    shut = plan(request("l3-interface", "create", "Vlan901", {"admin-state": "disabled"}), node="iosvl2")
    assert shut["commands"] == ["configure terminal", "interface Vlan901", "shutdown", "end"]
    # the inverse of the delete of a shut SVI recreates it shut; of an enabled SVI with no shutdown
    deleted = plan(request("l3-interface", "delete", "Vlan900"), SWITCH_OBJECTS, node="iosvl2")
    assert deleted["inverse"] == ["configure terminal", "interface Vlan900", "description netops-ios-static-routing svi", "shutdown",
                                  "ip address 198.51.100.65 255.255.255.240", "ipv6 address 2001:db8:c::1/64", "end"]


def test_loopback_and_subinterface_create_on_the_router():
    lo = plan(request("l3-interface", "create", "Loopback901", {"vrf": "blue", "description": "netops-ios-static-routing vrf",
                                                                "ipv4-address": "198.51.100.17/28",
                                                                "ipv6-address": "2001:db8:3::1/64"}))
    assert lo["commands"] == ["configure terminal", "interface Loopback901", "vrf forwarding blue",
                              "description netops-ios-static-routing vrf", "ip address 198.51.100.17 255.255.255.240",
                              "ipv6 address 2001:db8:3::1/64", "end"]
    sub = plan(request("l3-interface", "create", "GigabitEthernet0/3.900", {
        "encapsulation": 900, "ipv4-address": "198.51.100.33/28", "ipv6-address": "2001:db8:1::1/64"}))
    assert sub["commands"][1:3] == ["interface GigabitEthernet0/3.900", "encapsulation dot1Q 900"]
    assert "no shutdown" not in sub["commands"]


@pytest.mark.parametrize("op,key,changes,text,message", [
    ("create", "GigabitEthernet0/3.901", {"encapsulation": 900}, OBJECTS, "already the 802.1Q VLAN"),
    ("create", "Loopback902", {"ipv4-address": "198.51.100.2/28"}, OBJECTS, "overlaps"),
    ("create", "Loopback902", {"vrf": "blue", "ipv4-address": "203.0.113.251/24"}, BASE["iosv"], "overlaps"),
    ("create", "Vlan901", {"encapsulation": 901}, BASE["iosv"], "subinterface only"),
    ("update", "GigabitEthernet0/1.10", {"description": "x1"}, BASE["iosv"], "outside the profile"),
    ("update", "Loopback901", {"vrf": "red"}, OBJECTS, "cannot be updated"),
])
def test_l3_refusals_before_any_write(op, key, changes, text, message):
    with pytest.raises(Rejected, match=message):
        plan(request("l3-interface", op, key, changes), text)


def test_svi_overlap_is_refused_before_ios_would_write_it_anyway():
    # measured: IOSvL2 answers "% A overlaps with Vlan10" and still writes the address on the shut SVI
    overlap = fixture("iosvl2", "admin-show-running-config-interface-Vlan901__overlap.txt")
    assert " ip address 203.0.113.5 255.255.255.0" in overlap.splitlines()
    with pytest.raises(Rejected, match="overlaps 203.0.113.0/24 of interface Vlan10"):
        plan(request("l3-interface", "create", "Vlan901", {"ipv4-address": "203.0.113.5/24"}), node="iosvl2")


def test_subinterface_of_a_protected_port_is_refused():
    with pytest.raises(Rejected) as caught:
        plan(request("l3-interface", "create", "GigabitEthernet0/3.900", {"encapsulation": 900}),
             protected={"interface": ["GigabitEthernet0/3"]})
    assert caught.value.reason_codes == ["port_protected"]


def test_the_device_refusals_of_ios_are_recognised():
    assert ios.cli_error("x\n% 198.51.100.0 overlaps with Loopback900\n").startswith("% 198.51.100.0 overlaps")
    answer = ("encapsulation dot1Q 900\n%Configuration of multiple subinterfaces of the same main\ninterface with the "
              "same VID (900) is not permitted.\nThis VID is already configured on GigabitEthernet0/3.900.\n")
    assert ios.cli_error(answer).startswith("%Configuration of multiple subinterfaces")


def test_check_account_interface_answers_of_ios():
    assert ios.ip_interface_state(fixture("iosv", "ro-show-ip-interface-Loopback901__objects.txt"), "Loopback901") == {
        "ipv4-address": "198.51.100.17 255.255.255.240", "vrf": "blue"}
    assert ios.ipv6_interface_state(fixture("iosv", "ro-show-ipv6-interface-GigabitEthernet0-3-900__objects.txt"),
                                    "GigabitEthernet0/3.900") == {"ipv6-address": "2001:db8:1::1/64"}
    assert ios.ipv6_interface_state(fixture("iosvl2", "ro-show-ipv6-interface-Vlan900__objects.txt"), "Vlan900") == {
        "ipv6-address": "2001:db8:c::1/64"}
    assert ios.ipv6_interface_state(fixture("iosvl2", "ro-show-ipv6-interface-Loopback900__objects.txt"),
                                    "Loopback900") == {}
    assert ios.ip_interface_state(fixture("iosv", "ro-show-ip-interface-Loopback900__no-ip.txt"), "Loopback900") == {}
    assert ios.encapsulation_state(fixture("iosv", "ro-show-interfaces-GigabitEthernet0-3-900__objects.txt"),
                                   "GigabitEthernet0/3.900") == {"encapsulation": "900"}
    with pytest.raises(Rejected, match="2 global IPv6"):
        ios.ipv6_interface_state(fixture("iosv", "ro-show-ipv6-interface-Loopback900__two-addresses.txt"),
                                 "Loopback900")
    with pytest.raises(Rejected, match="refused"):
        ios.ip_interface_state(fixture("iosv", "ro-show-ip-interface-GigabitEthernet0-3-900__deleted.txt"),
                               "GigabitEthernet0/3.900")
    deleted = fixture("iosv", "ro-show-interfaces-description__deleted.txt")
    assert ios.description_row(deleted, "GigabitEthernet0/3.900")["status"] == "deleted"
    assert ios.description_row(deleted, "Loopback900") is None
    assert ios.description_row(fixture("iosvl2", "ro-show-interfaces-description__deleted.txt"), "Vlan900") is None
    assert ios.description_row(fixture("iosvl2", "ro-show-interfaces-description__svi-bare.txt"), "Vlan900") == {
        "status": "admin down", "description": ""}
    # a subinterface under the shut Gi0/3 is admin down without an own shutdown line (measured)
    assert ios.description_row(fixture("iosv", "ro-show-interfaces-description__objects.txt"),
                               "GigabitEthernet0/3.900")["status"] == "admin down"


def test_vlan_macs_counts_the_rows_of_the_vlan():
    assert ios.vlan_macs(fixture("iosvl2", "admin-show-mac-address-table-vlan-10__baseline.txt"), "10") == 7
    assert ios.vlan_macs(fixture("iosvl2", "admin-show-mac-address-table-vlan-900__baseline.txt"), "900") == 0
    with pytest.raises(Rejected):
        ios.vlan_macs("% Invalid input detected at '^' marker.\n", "10")


# ---- live prechecks: management path and connected ports ----

@pytest.mark.parametrize("node,table,key,changes", [
    ("iosv", "static-route", "192.0.2.128/25", {"next-hop": "203.0.113.7"}),
    ("iosv", "l3-interface", "GigabitEthernet0/0.900", {"encapsulation": 900}),
    ("iosvl2", "l3-interface", "Vlan99", {"description": "x1"}),
])
def test_management_path_is_refused(node, table, key, changes):
    device = G62Ios(node)
    op = "update" if key == "Vlan99" else "create"
    p = plan(request(table, op, key, changes), node=node)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE[node], p, BASE[node])
    assert caught.value.reason_codes == ["port_management_interface"]


def test_svi_on_the_router_image_is_refused_before_any_write():
    device = G62Ios("iosv")
    refusal = (F.parent / "ios_c45/iosv/show-vlan-id-10__exec.txt").read_text()
    for command in ("show vlan id 1", "show vlan brief"):
        device.query_override[command] = refusal.replace("show vlan id 10", command)
    p = plan(request("l3-interface", "create", "Vlan900", {"description": "x1"}))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE["iosv"], p, BASE["iosv"])
    assert caught.value.reason_codes == ["port_unsupported_interface"]


def test_existing_subinterface_of_a_connected_port_is_not_changed():
    device = G62Ios("iosv")
    p = plan(request("l3-interface", "delete", "GigabitEthernet0/1.20"))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE["iosv"], p, BASE["iosv"])
    assert caught.value.reason_codes == ["port_lldp_neighbor"]
    # a description alone does not cut traffic
    described = plan(request("l3-interface", "update", "GigabitEthernet0/1.20", {"description": "x1"}))
    assert exec_ios.plan_prechecks(device, DEVICE["iosv"], described, BASE["iosv"]) == []
    # a new subinterface of the connected port only adds a VLAN tag
    new = plan(request("l3-interface", "create", "GigabitEthernet0/1.900", {"encapsulation": 900}))
    assert exec_ios.plan_prechecks(device, DEVICE["iosv"], new, BASE["iosv"]) == []
    assert any("new object" in check for check in new["prechecks"])


def test_svi_of_a_vlan_with_clients_is_not_changed():
    device = G62Ios("iosvl2")
    p = plan(request("l3-interface", "update", "Vlan10", {"ipv4-address": "203.0.113.3/24"}), node="iosvl2")
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE["iosvl2"], p, BASE["iosvl2"])
    assert caught.value.reason_codes == ["port_learned_mac"]
    assert "show mac address-table vlan 10" in device.queries
    free = plan(request("l3-interface", "delete", "Vlan900"), SWITCH_OBJECTS, node="iosvl2")
    assert exec_ios.plan_prechecks(G62Ios("iosvl2", SWITCH_OBJECTS), DEVICE["iosvl2"], free, SWITCH_OBJECTS) == []


def test_unreadable_mac_table_refuses_with_the_unreadable_code():
    device = G62Ios("iosvl2")
    device.query_override["show mac address-table vlan 10"] = "% Invalid input detected at '^' marker.\n"
    p = plan(request("l3-interface", "delete", "Vlan10"), node="iosvl2")
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE["iosvl2"], p, BASE["iosvl2"])
    assert caught.value.reason_codes == ["port_usage_unreadable"]


# ---- end to end through Admin: preview without a write, apply, readback, undo ----

def test_preview_writes_nothing(tmp_path):
    device = G62Ios("iosv")
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request(
        "static-route", "create", "vrf:blue:198.51.100.192/27", {"next-hop": "203.0.113.247"}))
    assert result["result"] == "ready", result
    assert device.applied_blocks == [] and device.lines == device.saved
    assert "show ip static route vrf blue" in device.check_queries


# ---- IOS-STATIC-ROUTING review regressions through Admin and the simulated CLI transport ----

@pytest.mark.parametrize("command", ["ip ospf authentication-key", "ip ospf message-digest-key 1 md5",
                                     "standby 1 authentication md5 key-string"])
def test_review_preview_withholds_unsupported_configuration_values(tmp_path, command):
    marker = "synthetic-test-value"
    key = "GigabitEthernet0/3.900"
    text = OBJECTS.replace("interface " + key + "\n", "interface " + key + "\n " + command + " " + marker + "\n")
    device = G62Ios("iosv", text)
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request(
        "l3-interface", "update", key, {"description": "test"}))
    assert result["result"] == "rejected"
    if marker in json.dumps(result):
        pytest.fail("preview exposed a value from unsupported interface configuration")


@pytest.mark.parametrize("op,changes", [("delete", {}), ("update", {"ipv4-address": "198.51.100.165/28"})])
def test_review_parent_up_without_discovery_requires_endpoint_impact(tmp_path, op, changes):
    device = G62Ios("iosv")
    device.query_override.update({"show lldp neighbors": "% LLDP is not enabled\n",
                                  "show cdp neighbors": "% CDP is not enabled\n",
                                  "show interfaces description": fixture("iosv", "ro-show-interfaces-description__baseline.txt")})
    key = "GigabitEthernet0/1.20"
    rt = runtime(tmp_path, device)
    refused = execute.preview(rt, "lab-ios", request("l3-interface", op, key, changes))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["endpoint_impact_required"]
    approved = parse_request(request_bytes(table="l3-interface", op=op, key=key, changes=changes, endpoint_impact=key))
    ready = execute.preview(rt, "lab-ios", approved)
    assert ready["result"] == "ready"
    assert any("Explicit endpoint impact accepted for " + key in item for item in ready["prechecks"])
    assert device.applied_blocks == []


def test_review_native_vlan_counts_as_an_occupied_vid(tmp_path):
    device = G62Ios("iosv", OBJECTS.replace(" encapsulation dot1Q 900\n", " encapsulation dot1Q 900 native\n"))
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request(
        "l3-interface", "create", "GigabitEthernet0/3.901", {"encapsulation": 900}))
    assert result["result"] == "rejected" and "already the 802.1Q VLAN" in " ".join(result["reasons"])
    assert device.applied_blocks == []


def test_review_cannot_delete_an_svi_that_undo_cannot_recreate(tmp_path):
    measured = fixture("iosvl2", "admin-show-running-config-interface-Vlan901__overlap.txt")
    block = measured[measured.index("interface Vlan901\n"):measured.index("\nend")]
    device = G62Ios("iosvl2", BASE["iosvl2"].replace("\nend", "\n" + block + "\n!\nend"))
    # The anonymised SSH peer shares the documentation /24 used by both SVIs. Avoid an unrelated management refusal.
    command = "show tcp brief"
    device.query_override[command] = device.query_override[command].replace("203.0.113.227", "198.51.100.227")
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request("l3-interface", "delete", "Vlan901"))
    assert result["result"] == "rejected" and "of interface Vlan10" in " ".join(result["reasons"])
    assert device.applied_blocks == []


def test_r3_delete_refuses_an_svi_whose_description_is_invalid_for_create(tmp_path):
    device = G62Ios("iosvl2", SWITCH_OBJECTS.replace(" description netops-ios-static-routing svi\n",
                                                    " description Hoste, budova A\n"))
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request("l3-interface", "delete", "Vlan900"))
    assert result["result"] == "rejected", result
    assert any("attribute description must match" in reason for reason in result["reasons"])
    assert device.applied_blocks == []


def test_r3_first_svi_uses_the_vlan_database_from_snapshot(tmp_path):
    class SwitchTransport(G62Ios):
        # Run the production snapshot collector with the simulated CLI as its transport.
        snapshot = DeviceAccess.snapshot
        device = SimpleNamespace(platform="ios")

        def _query(self, credential, command):
            if command == "show running-config":
                self.queries.append(command)
                return super().snapshot()
            return self.query(command)

    text = re.sub(r"^interface Vlan[0-9]+\n(?: [^\n]*\n)*!\n", "", BASE["iosvl2"], flags=re.MULTILINE)
    text = text.replace("interface GigabitEthernet1/3\n", "interface GigabitEthernet1/3\n no switchport\n"
                        " ip address 192.0.2.52 255.255.255.0\n")
    device = SwitchTransport("iosvl2", text)
    brief = "show ip interface brief"
    rows = device.query_override[brief].splitlines()
    device.query_override[brief] = "\n".join(
        next(row for row in rows if row.startswith("Vlan99")).replace("Vlan99", "GigabitEthernet1/3")
        if row.startswith("GigabitEthernet1/3") else row for row in rows if not row.startswith("Vlan"))
    device.query_override["show vlan brief"] = fixture("iosvl2", "admin-show-vlan-brief__baseline.txt")
    device.query_override["show vlan id 1"] = refused_description("autocommand").replace(
        "show interfaces description", "show vlan id 1")

    result = execute.preview(runtime(tmp_path, device), "lab-ios", request("l3-interface", "create", "Vlan900"))
    assert result["result"] == "ready", result
    assert device.queries.count("show vlan brief") == device.queries.count("show running-config") > 0
    assert "show vlan id 1" not in device.queries
    assert device.applied_blocks == []


@pytest.mark.parametrize("operation", ["preview-first", "undo-last"])
@pytest.mark.parametrize("probe", ["id", "brief"])
def test_svi_without_switchport_markers_uses_default_vlan_probe(tmp_path, operation, probe):
    class SwitchTransport(G62Ios):
        snapshot = DeviceAccess.snapshot
        device = SimpleNamespace(platform="ios")

        def _query(self, credential, command):
            if command == "show running-config":
                return super().snapshot()
            return self.query(command)

    # Derive a switch with implicit port modes and a routed management port from the IOSvL2 capture.
    text = re.sub(r"^interface Vlan[0-9]+\n(?: [^\n]*\n)*!\n", "", BASE["iosvl2"], flags=re.MULTILINE)
    text = re.sub(r"^.*(?: switchport|vlan internal allocation).*\n", "", text, flags=re.MULTILINE)
    text = text.replace("interface GigabitEthernet1/3\n", "interface GigabitEthernet1/3\n"
                        " ip address 192.0.2.52 255.255.255.0\n")
    if operation == "undo-last":
        text = text.replace("\nend\n", "\ninterface Vlan900\n description only SVI\n shutdown\n!\nend\n")
    device = SwitchTransport("iosvl2", text)
    brief = "show ip interface brief"
    rows = device.query_override[brief].splitlines()
    management = next(row for row in rows if row.startswith("Vlan99")).replace("Vlan99", "GigabitEthernet1/3")
    device.query_override[brief] = "\n".join(management if row.startswith("GigabitEthernet1/3") else row
                                             for row in rows if not row.startswith("Vlan"))
    # Derive show vlan id 1 from the measured single-VLAN layout and the measured VLAN 1 brief row.
    vlan = (F.parent / "ios_c45/iosvl2/show-vlan-id-10__exec.txt").read_text()
    default = next(row for row in fixture("iosvl2", "admin-show-vlan-brief__baseline.txt").splitlines()
                   if row.startswith("1 "))
    device.query_override["show vlan id 1"] = re.sub(r"^10 +D10.*$", default, vlan, flags=re.MULTILINE).replace(
        "10   enet  100010", "1    enet  100001")
    if probe == "brief":
        device.query_override["show vlan id 1"] = refused_description("autocommand")
        device.query_override["show vlan brief"] = fixture("iosvl2", "admin-show-vlan-brief__baseline.txt")
    rt = runtime(tmp_path, device)
    assert not ios.load(device.snapshot(), device.firmware).has_vlan_database
    if operation == "preview-first":
        result = execute.preview(rt, "lab-ios", request("l3-interface", "create", "Vlan900"))
        assert result["result"] == "ready", result
        assert not device.applied_blocks
    else:
        before = ios.load(device.snapshot(), device.firmware).entries("l3-interface")["Vlan900"].attributes
        record = approved_apply(rt, "lab-ios", request("l3-interface", "delete", "Vlan900"))
        assert record["result"] == "confirmed", (record["reason"], steps(record))
        assert "Vlan900" not in ios.load(device.snapshot(), device.firmware).interfaces
        result = execute.undo(rt, record["change_id"], "restore the only SVI")
        assert result["result"] == "confirmed", (result["reason"], steps(result))
        assert ios.load(device.snapshot(), device.firmware).entries("l3-interface")["Vlan900"].attributes == before
    assert "show vlan id 1" in device.queries
    assert ("show vlan brief" in device.queries) == (probe == "brief")


def refused_description(case):
    directory = F.parent / "ios_c45" / "iosv"
    if case == "authorization":
        return "% Authorization failed.\n"
    name, old = {"autocommand": ("exec__ro-show-running-config-denied__rc0.txt",
                                 "show running-config interface GigabitEthernet0/2"),
                 "invalid": ("show-archive-config-rollback-timer__ro.txt", "show archive config rollback timer")}[case]
    return (directory / name).read_text().replace(old, "show interfaces description")


@pytest.mark.parametrize("case", ["autocommand", "invalid", "authorization"])
def test_review_refused_description_is_not_absent_in_preview(tmp_path, case):
    device = G62Ios("iosv")
    device.check_override = {"show interfaces description": refused_description(case)}
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request("l3-interface", "create", "Loopback900"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_usage_unreadable"]
    assert device.applied_blocks == []


def test_review_refused_description_after_delete_triggers_rollback(tmp_path):
    device = G62Ios("iosv", OBJECTS)
    rt = runtime(tmp_path, device)
    before = list(device.lines)

    def refuse_after_delete(fake, commands):
        if "no interface Loopback900" in commands:
            fake.check_override = {"show interfaces description": refused_description("autocommand")}

    device.on_apply = refuse_after_delete
    result = approved_apply(rt, "lab-ios", request("l3-interface", "delete", "Loopback900"))
    assert result["result"] == "reverted" and "check_identity_failed" in steps(result)
    assert "check_identity_passed" not in steps(result) and device.lines == before


def test_review_catalyst_svi_does_not_depend_on_image_prefix(tmp_path):
    device = G62Ios("iosvl2", SWITCH_OBJECTS)
    version = fixture("iosvl2", "admin-show-version__baseline.txt")
    version = re.sub(r"Cisco IOS Software, .+? Software \([^)]+\)",
                     "Cisco IOS Software, C3560 Software (C3560-IPSERVICESK9-M)", version, count=1)
    device.query_override["show version"] = version
    result = execute.preview(runtime(tmp_path, device), "lab-ios", request(
        "l3-interface", "update", "Vlan900", {"description": "Catalyst SVI"}))
    assert result["result"] == "ready"
    assert device.applied_blocks == []


CREATES = [
    ("iosv", request("static-route", "create", "198.51.100.128/26", {"next-hop": "203.0.113.7", "distance": 50})),
    ("iosv", request("static-route", "create", "vrf:blue:198.51.100.192/27", {"next-hop": "203.0.113.247"})),
    ("iosv", request("static-route", "create", "2001:db8:a::/64", {"next-hop": "2001:db8:7::7"})),
    ("iosv", request("static-route", "create", "vrf:blue:2001:db8:b::/64", {"next-hop": "2001:db8:8::7", "distance": 9})),
    ("iosv", request("l3-interface", "create", "Loopback900", {"description": "netops-ios-static-routing test",
                                                               "ipv4-address": "198.51.100.1/28",
                                                               "ipv6-address": "2001:db8:2::1/64"})),
    ("iosv", request("l3-interface", "create", "Loopback901", {"vrf": "blue", "ipv4-address": "198.51.100.17/28",
                                                               "ipv6-address": "2001:db8:3::1/64"})),
    ("iosv", request("l3-interface", "create", "GigabitEthernet0/3.900", {"encapsulation": 900,
                                                                          "ipv4-address": "198.51.100.33/28"})),
    ("iosvl2", request("static-route", "create", "198.51.100.0/25", {"next-hop": "203.0.113.1"})),
    ("iosvl2", request("l3-interface", "create", "Vlan900", {"description": "netops-ios-static-routing svi",
                                                             "ipv4-address": "198.51.100.65/28",
                                                             "ipv6-address": "2001:db8:c::1/64"})),
    ("iosvl2", request("l3-interface", "create", "Loopback900", {"ipv4-address": "198.51.100.81/28"})),
]


@pytest.mark.parametrize("node,req", CREATES, ids=lambda item: item if isinstance(item, str) else item.key)
def test_create_is_confirmed_read_back_and_undone_to_the_baseline(tmp_path, node, req):
    device = G62Ios(node)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    record = approved_apply(rt, "lab-ios", req)
    assert record["result"] == "confirmed", (record["reason"], steps(record), record.get("postcheck_differences"))
    assert device.applied_blocks[0][0].startswith("configure terminal revert timer")
    assert device.applied_blocks[1] == record["plan"]["commands"]
    assert "check_identity_passed" in steps(record) and device.timer is None
    back = execute.undo(rt, record["change_id"], "IOS-STATIC-ROUTING return")
    assert back["result"] == "confirmed", (back["reason"], steps(back), back.get("postcheck_differences"))
    assert device.lines == before


@pytest.mark.parametrize("node,text,req", [
    ("iosv", ROUTES, request("static-route", "update", "198.51.100.128/26", {"next-hop": "203.0.113.8"})),
    ("iosv", ROUTES, request("static-route", "update", "198.51.100.0/25", {"distance": 20})),
    ("iosv", ROUTES, request("static-route", "delete", "vrf:blue:2001:db8:b::/64")),
    ("iosv", OBJECTS, request("l3-interface", "update", "Loopback900", {"ipv6-address": "2001:db8:2::5/64",
                                                                        "admin-state": "disabled"})),
    ("iosv", OBJECTS, request("l3-interface", "update", "Loopback901", {"ipv4-address": None})),
    ("iosv", OBJECTS, request("l3-interface", "delete", "GigabitEthernet0/3.900")),
    ("iosvl2", SWITCH_OBJECTS, request("l3-interface", "update", "Vlan900", {"admin-state": "enabled"})),
    ("iosvl2", SWITCH_OBJECTS, request("l3-interface", "delete", "Vlan900")),
], ids=lambda item: item.key if hasattr(item, "key") else "text" if "\n" in str(item) else str(item))
def test_update_and_delete_on_the_measured_objects_are_undone(tmp_path, node, text, req):
    device = G62Ios(node, text)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    record = approved_apply(rt, "lab-ios", req)
    assert record["result"] == "confirmed", (record["reason"], steps(record), record.get("postcheck_differences"))
    assert device.applied_blocks[1] == record["plan"]["commands"]
    back = execute.undo(rt, record["change_id"], "IOS-STATIC-ROUTING return")
    assert back["result"] == "confirmed", (back["reason"], steps(back), back.get("postcheck_differences"))
    # IOS sorts recreated routes and interfaces itself; the fake appends them, so the lines are compared as a set
    assert sorted(line for line in device.lines if line != "!") == sorted(line for line in before if line != "!")


def test_undo_of_an_own_subinterface_on_a_connected_port_is_allowed(tmp_path):
    device = G62Ios("iosv")
    rt = runtime(tmp_path, device)
    record = approved_apply(rt, "lab-ios", request("l3-interface", "create", "GigabitEthernet0/1.900",
                                                  {"encapsulation": 900, "ipv4-address": "198.51.100.49/28"}))
    assert record["result"] == "confirmed", (record["reason"], steps(record), record.get("postcheck_differences"))
    refused = execute.preview(rt, "lab-ios", request("l3-interface", "delete", "GigabitEthernet0/1.900",
                                                     request_id="req-ios-static-routing-0002"))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["port_lldp_neighbor"]
    back = execute.undo(rt, record["change_id"], "IOS-STATIC-ROUTING return")
    assert back["result"] == "confirmed", (back["reason"], steps(back), back.get("postcheck_differences"))
    assert "interface GigabitEthernet0/1.900" not in device.lines


def test_a_same_vid_refusal_during_the_write_is_returned_by_the_timer(tmp_path):
    device = G62Ios("iosv", OBJECTS)
    rt = runtime(tmp_path, device)
    before = list(device.lines)

    def taken(fake, block):
        # someone creates Gi0/3.901 with VLAN 901 right after the plan; IOS refuses the second subinterface
        if block[:2] == ["configure terminal", "interface GigabitEthernet0/3.902"]:
            fake.lines += ["interface GigabitEthernet0/3.901", " encapsulation dot1Q 901"]
    device.on_apply = taken
    record = approved_apply(rt, "lab-ios", request("l3-interface", "create", "GigabitEthernet0/3.902",
                                                  {"encapsulation": 901}))
    assert record["result"] in ("reverted", "unknown"), (record["result"], steps(record))
    assert "change_failed" in steps(record)
    assert device.lines == before
