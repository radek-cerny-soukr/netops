"""1.0.12 G80 (XE-M026 static routes, XE-M027 L3 interfaces) on IOL XE 17.18.2 over real anonymised answers.

The fixtures (fixtures/ios_g80) were captured on the GNS3 router d-iolxe (port 2257) by independent CLI sessions of
the write account and the privilege-1 check account (task netops-20261117-454, task-evidence/g80) and anonymised
with a fixed table (task-evidence/g80/anon_g80.py); the test objects use 198.51.100.0/24 and 2001:db8:80::/48.
G80Ios is FakeIos with that running configuration; it changes the configuration lines and answers the check
account in the measured shapes (upper-case IPv6, "deleted" subinterfaces, the IOS overlap refusal).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ios import FakeIos
from test_ios import make_runtime, steps

from netops_admin import engine, exec_ios, execute, ios
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

F = Path(__file__).parent / "fixtures" / "ios_g80"
FW = "17.18.2"
DEVICE = SimpleNamespace(platform="iosxe", firmware=FW)


def fixture(name):
    return (F / name).read_text()


BASELINE = fixture("admin-show-running-config__baseline.txt")
OBJECTS = fixture("admin-show-running-config__objects.txt")
# measured 454-r2: VRF netops-g80-v6 with only address-family ipv6 and Loopback8082 in it (IPv6 only)
V6_VRF = fixture("admin-show-running-config__v6-vrf.txt")
V6_VRF_ONLY = V6_VRF.replace("!\ninterface Loopback8082\n description netops-g80 v6\n vrf forwarding netops-g80-v6\n"
                             " no ip address\n ipv6 address 2001:DB8:82::1/64\n", "")


def request(table, op, key, changes=None, request_id="req-g80-0001"):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {}, request_id=request_id))


def plan(req, text=BASELINE):
    return engine.build_plan("iosxe", text.encode(), req, firmware=FW)


# ---- the fake router ----

def _vrf_route(header, vrf):
    words = header.split()
    return words[:2] == ["ip", "route"] and ((words[2:3] == ["vrf"] and words[3:4] == [vrf]) if vrf
                                             else words[2:3] != ["vrf"])


class G80Ios(FakeIos):
    def __init__(self, text=BASELINE):
        super().__init__("iolxe")
        self.header = text[:text.index("Building configuration...")]
        self.lines = text[text.index("Building configuration..."):].rstrip("\n").split("\n")
        self.saved = list(self.lines)
        self.hostname = "host01"
        self.deleted = set()
        self.query_override = {"show tcp brief": fixture("admin-show-tcp-brief__baseline.txt"),
                               "show ip interface brief": fixture("admin-show-ip-interface-brief__baseline.txt")}

    # configuration lines of routes and L3 interfaces (the rest is FakeIos)
    def _line(self, line, mode):
        words = line.split()
        current = mode[0]
        if current == "exec" or words == ["end"]:
            return super()._line(line, mode)
        if words[:2] in (["ip", "route"], ["ipv6", "route"]) or words[:3] in (["no", "ip", "route"],
                                                                              ["no", "ipv6", "route"]):
            return self._route(words)
        if words[:1] == ["interface"] and len(words) == 2 and ios.L3_KEY.fullmatch(words[1]):
            if self.interface(words[1]) is None:
                self._create(words[1])
            mode[0] = "interface:" + words[1]
            return ""
        if words[:2] == ["no", "interface"] and len(words) == 3:
            start, end = self._block("interface " + words[2])
            del self.lines[start:end + 1]
            if ios.SUBINTERFACE.match(words[2]):
                self.deleted.add(words[2])
            return ""
        if words == ["exit"]:
            mode[0] = "config"
            return ""
        if current.startswith("interface:") and ios.L3_KEY.fullmatch(current.split(":", 1)[1]):
            return self._l3(current.split(":", 1)[1], words, line, mode)
        return super()._line(line, mode)

    def _route(self, words):
        remove = words[0] == "no"
        words = [word.upper() if ":" in word else word for word in (words[1:] if remove else words)]
        prefix_words = 4 if words[0] == "ip" else 3
        prefix_words += 2 if words[2:3] == ["vrf"] else 0
        own = " ".join(words[:prefix_words + 1])
        if remove:
            kept = [line for line in self.lines if not line.startswith(own + " ") and line != own]
            if len(kept) == len(self.lines):
                return "%No matching route to delete"
            self.lines = kept
            return ""
        same = [index for index, line in enumerate(self.lines) if line == own or line.startswith(own + " ")]
        text = " ".join(words)
        if same:
            self.lines[same[0]] = text
        else:
            last = max(index for index, line in enumerate(self.lines) if line.startswith(("ip route ", "ipv6 route ")))
            self.lines.insert(last + 1, text)
        return ""

    def _create(self, name):
        last = max(index for index, line in enumerate(self.lines) if line.startswith("interface "))
        _start, end = self._block(self.lines[last])
        self.lines[end:end] = ["!", "interface " + name, " no ip address"]
        self.deleted.discard(name)

    def _children(self, name):
        start, end = self._block("interface " + name)
        return start, end, self.lines[start + 1:end]

    def _l3(self, name, words, line, mode):
        start, end, children = self._children(name)
        if words[:2] == ["ip", "address"]:
            mine = ipaddress.IPv4Interface("%s/%s" % (words[2], words[3])).network
            snapshot = ios.load(self.snapshot(), self.firmware)
            for other, vrf, network in ios.interface_networks(snapshot, skip=name):
                if vrf == ios.vrf_of(snapshot, name) and network.version == 4 and network.overlaps(mine):
                    return "%% %s overlaps with %s" % (mine.network_address, other)
            children = [child for child in children if not child.strip().startswith(("ip address", "no ip address"))]
            children.insert(len([c for c in children if c.split()[0] in ("description", "vrf", "encapsulation")]),
                            " " + line.strip())
        elif words == ["no", "ip", "address"]:
            children = [child for child in children if not child.strip().startswith("ip address")]
            children.append(" no ip address")
        elif words[:2] == ["ipv6", "address"]:
            children.append(" ipv6 address " + words[2].upper())
        elif words[:3] == ["no", "ipv6", "address"]:
            children = [child for child in children if child.strip() != "ipv6 address " + words[3].upper()]
        elif words[:2] in (["vrf", "forwarding"], ["encapsulation", "dot1Q"]):
            children.insert(0, " " + line.strip())
        else:
            return super()._line(line, mode)
        self.lines[start + 1:end] = children
        return ""

    # the check account
    def check_query(self, command):
        self.check_queries.append(command)
        if self.check_override is not None and command in self.check_override:
            return self.check_override[command]
        snapshot = ios.load(self.snapshot(), self.firmware)
        match = re.fullmatch(r"show (ip static route|ipv6 static)(?: vrf (\S+))?", command)
        if match:
            return self._static(snapshot, match.group(1) == "ip static route", match.group(2))
        match = re.fullmatch(r"show (ip interface|ipv6 interface|interfaces) (\S+)", command)
        if match and ios.L3_KEY.fullmatch(match.group(2)):
            return self._l3_answer(snapshot, match.group(1), match.group(2))
        if command == "show interfaces description":
            rows = fixture("ro-show-interfaces-description__baseline.txt").rstrip("\n").split("\n")
            for name in list(snapshot.interfaces) + sorted(self.deleted):
                if not ios.L3_KEY.fullmatch(name) or name == "Loopback0":
                    continue
                lines = snapshot.interface_lines(name)
                parent = ios.SUBINTERFACE.match(name)
                # measured: a subinterface under a shut parent port shows admin down without an own shutdown line
                down = "shutdown" in lines or (parent is not None
                                               and "shutdown" in snapshot.interface_lines(parent.group(1)))
                status = "deleted" if name in self.deleted else "admin down" if down else "up"
                description = next((line[len("description "):] for line in lines if line.startswith("description ")),
                                   "")
                row = "%-31s%-15s%-9s%s" % (ios.short_name(name), status, "up" if status == "up" else "down",
                                            description)
                # IOS keeps one row per interface: a deleted subinterface stays "deleted" until it is created again
                # (the baseline capture already holds Et0/2.80 deleted by the measurement before it)
                same = [index for index, old in enumerate(rows) if old.split()[:1] == [ios.short_name(name)]]
                if same:
                    rows[same[0]] = row
                else:
                    rows.append(row)
            return "\n".join(rows) + "\n"
        return super().check_query(command)

    def _static(self, snapshot, four, vrf):
        if vrf is not None and ios.vrf_families(snapshot, vrf) is None:
            return fixture("ro-show-ip-static-route-vrf__baseline.txt" if four else "ro-show-ipv6-static-vrf__baseline.txt")
        header = fixture("ro-show-ip-static-route__baseline.txt" if four else "ro-show-ipv6-static__baseline.txt")
        header = header[:header.index("Static local RIB" if four else "IPv6 Static routes Table")]
        if four and not any(_vrf_route(block.header, vrf) for block in snapshot.blocks):
            return fixture("ro-show-ip-static-route-vrf__empty.txt")
        rows = ["Static local RIB for %s " % (vrf or "default"), ""] if four else \
            ["IPv6 Static routes Table - %s" % (vrf or "default")] + fixture("ro-show-ipv6-static__baseline.txt").split(
                "IPv6 Static routes Table - default\n", 1)[1].rstrip("\n").split("\n")
        for block in snapshot.blocks:
            words = block.header.split()
            if words[:2] != (["ip", "route"] if four else ["ipv6", "route"]):
                continue
            rest = words[2:]
            if (rest[:1] == ["vrf"]) != (vrf is not None) or (vrf is not None and rest[1] != vrf):
                continue
            rest = rest[2:] if vrf else rest
            if four:
                network = ipaddress.IPv4Network("%s/%s" % (rest[0], rest[1]))
                distance = rest[3] if len(rest) > 3 and rest[3].isdigit() else "1"
                rows.append("M  %s [%s/0] via %s [A]" % (network, distance, rest[2]))
            else:
                distance = rest[2] if len(rest) > 2 else "1"
                rows.append("*   %s via %s, distance %s" % (rest[0], rest[1], distance))
        return header + "\n".join(rows) + "\n"

    def _l3_answer(self, snapshot, kind, name):
        if name not in snapshot.interfaces:
            return fixture("ro-show-ip-interface-Loopback8080__baseline.txt").replace("Loopback8080", name)
        lines = snapshot.interface_lines(name)
        state = "administratively down, line protocol is down" if "shutdown" in lines else "up, line protocol is up"
        head = "\n\n\n%s is %s\n" % (name, state)
        vrf = ios.vrf_of(snapshot, name)
        if kind == "ip interface":
            address = next((line.split()[2:4] for line in lines if line.startswith("ip address ")), None)
            if address is None:
                return head + "  Internet protocol processing disabled\n"
            network = ipaddress.IPv4Interface("/".join(address))
            body = "  Internet address is %s\n  Broadcast address is 255.255.255.255\n" % network.with_prefixlen
            return head + body + ('  VPN Routing/Forwarding "%s"\n' % vrf if vrf else "")
        if kind == "ipv6 interface":
            found = [line.split()[2] for line in lines if line.startswith("ipv6 address ")]
            if not found:
                return "\n\n\n"
            rows = "".join("    %s, subnet is %s \n" % (item.split("/")[0], ipaddress.IPv6Interface(item).network
                                                          .compressed.upper())
                           for item in found)
            # measured (454-r2): the VRF is named here as well, also when IPv4 is disabled on the interface
            return head + "  IPv6 is enabled, link-local address is FE80::5300 \n" \
                          "  Global unicast address(es):\n" + rows + "  MTU is 1514 bytes\n" + (
                              '  VPN Routing/Forwarding "%s"\n' % vrf if vrf else "")
        vid = next((line.split()[2] for line in lines if line.startswith("encapsulation dot1Q ")), None)
        return head + "  Hardware is AmdP2, address is 0000.5e00.5320 (bia 0000.5e00.5320)\n" + (
            "  Encapsulation 802.1Q Virtual LAN, Vlan ID  %s.\n" % vid if vid else "  Encapsulation LOOPBACK\n")


def runtime(tmp_path, device):
    return make_runtime(tmp_path, device)


# ---- static routes: plans from the measured running configuration ----

def test_create_ipv4_route_renders_the_measured_line_and_its_inverse():
    p = plan(request("static-route", "create", "198.51.100.128/27", {"next-hop": "198.51.100.2"}))
    assert p["commands"] == ["configure terminal", "ip route 198.51.100.128 255.255.255.224 198.51.100.2", "end"]
    assert p["inverse"] == ["configure terminal", "no ip route 198.51.100.128 255.255.255.224 198.51.100.2", "end"]
    assert p["predicted"] == {"before": None, "after": {"next-hop": "198.51.100.2"}}


def test_routes_of_the_measured_configuration_with_vrf_ipv6_capitals_and_distance():
    entries = ios.load(OBJECTS, FW).entries("static-route")
    assert entries["198.51.100.128/27"].attributes == {"next-hop": "198.51.100.2", "distance": "50"}
    assert entries["vrf:netops-g80:198.51.100.160/27"].attributes == {"next-hop": "198.51.100.66"}
    assert entries["2001:db8:80:10::/64"].attributes == {"next-hop": "2001:db8:80::2"}
    assert entries["vrf:netops-g80:2001:db8:80:11::/64"].attributes == {"next-hop": "2001:db8:80:1::2",
                                                                       "distance": "9"}
    assert entries["198.51.100.240/28"].unsupported and entries["198.51.100.248/29"].unsupported


def test_distance_update_replaces_the_route_in_place_and_next_hop_change_adds_before_removing():
    distance = plan(request("static-route", "update", "198.51.100.128/27", {"distance": 20}), OBJECTS)
    assert distance["commands"] == ["configure terminal", "ip route 198.51.100.128 255.255.255.224 198.51.100.2 20",
                                    "end"]
    assert distance["inverse"] == ["configure terminal", "ip route 198.51.100.128 255.255.255.224 198.51.100.2 50",
                                   "end"]
    default = plan(request("static-route", "update", "198.51.100.128/27", {"distance": None}), OBJECTS)
    assert default["commands"][1] == "ip route 198.51.100.128 255.255.255.224 198.51.100.2"
    hop = plan(request("static-route", "update", "198.51.100.128/27", {"next-hop": "198.51.100.4"}), OBJECTS)
    assert hop["commands"] == ["configure terminal", "ip route 198.51.100.128 255.255.255.224 198.51.100.4 50",
                               "no ip route 198.51.100.128 255.255.255.224 198.51.100.2", "end"]
    assert hop["inverse"] == ["configure terminal", "ip route 198.51.100.128 255.255.255.224 198.51.100.2 50",
                              "no ip route 198.51.100.128 255.255.255.224 198.51.100.4", "end"]


def test_vrf_ipv6_route_create_and_delete_with_canonical_addresses():
    p = plan(request("static-route", "create", "vrf:netops-g80:2001:db8:80:12::/64",
                     {"next-hop": "2001:DB8:80:1::3", "distance": 9}), OBJECTS)
    assert p["commands"][1] == "ipv6 route vrf netops-g80 2001:db8:80:12::/64 2001:db8:80:1::3 9"
    deleted = plan(request("static-route", "delete", "vrf:netops-g80:2001:db8:80:11::/64"), OBJECTS)
    assert deleted["commands"][1] == "no ipv6 route vrf netops-g80 2001:db8:80:11::/64 2001:db8:80:1::2"
    assert deleted["inverse"][1] == "ipv6 route vrf netops-g80 2001:db8:80:11::/64 2001:db8:80:1::2 9"


@pytest.mark.parametrize("key,changes,text,message", [
    ("0.0.0.0/0", {"next-hop": "198.51.100.2"}, BASELINE, "protected"),
    ("vrf:netops-g80:0.0.0.0/0", {"next-hop": "198.51.100.66"}, OBJECTS, "default route"),
    ("vrf:netops-g80:198.51.100.192/27", {"next-hop": "198.51.100.66"}, BASELINE, "not defined"),
    ("vrf:mgmt-vrf:198.51.100.192/27", {"next-hop": "198.51.100.66"}, BASELINE, "management VRF"),
    ("198.51.100.192/27", {"next-hop": "2001:db8:80::2"}, BASELINE, "not an IPv4"),
    ("198.51.100.192/27", {"next-hop": "198.51.100.193"}, BASELINE, "lies in the destination"),
    ("198.51.100.192/27", {"next-hop": "fe80::1"}, BASELINE, "unicast next-hop"),
    ("198.51.100.193/27", {"next-hop": "198.51.100.2"}, BASELINE, "host bits"),
    ("2001:DB8:80:12::/64", {"next-hop": "2001:db8:80::2"}, BASELINE, "does not match"),
    ("2001:db8:80:12::/64", {"next-hop": "2001:db8:80::2", "distance": 255}, BASELINE, "1..254"),
])
def test_route_refusals_before_any_write(key, changes, text, message):
    with pytest.raises(Rejected, match=message):
        plan(request("static-route", "create", key, changes), text)


@pytest.mark.parametrize("key", ["198.51.100.240/28", "198.51.100.248/29"])
def test_interface_next_hop_and_named_route_are_outside_the_profile(key):
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("static-route", "update", key, {"distance": 5}), OBJECTS)
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("static-route", "delete", key), OBJECTS)


def test_a_second_next_hop_of_one_destination_is_outside_the_profile():
    text = OBJECTS.replace("ip route 198.51.100.128 255.255.255.224 198.51.100.2 50\n",
                           "ip route 198.51.100.128 255.255.255.224 198.51.100.2 50\n"
                           "ip route 198.51.100.128 255.255.255.224 198.51.100.3\n")
    with pytest.raises(Rejected, match="repeated next-hop"):
        plan(request("static-route", "delete", "198.51.100.128/27"), text)


def test_check_account_route_answers_of_the_device():
    objects = ios.static_route_state(fixture("ro-show-ip-static-route__objects.txt"), "198.51.100.128/27")
    assert objects == {"next-hop": "198.51.100.2", "distance": "50"}
    assert ios.static_route_state(fixture("ro-show-ip-static-route__baseline.txt"), "198.51.100.128/27") is None
    assert ios.static_route_state(fixture("ro-show-ip-static-route-vrf__objects.txt"),
                                  "vrf:netops-g80:198.51.100.160/27") == {"next-hop": "198.51.100.66", "distance": "1"}
    assert ios.static_route_state(fixture("ro-show-ipv6-static-vrf__objects.txt"),
                                  "vrf:netops-g80:2001:db8:80:11::/64") == {"next-hop": "2001:db8:80:1::2",
                                                                           "distance": "9"}
    # an existing VRF without static routes (measured live, run r1): only the code legend
    assert ios.static_route_state(fixture("ro-show-ip-static-route-vrf__empty.txt"),
                                  "vrf:netops-g80:198.51.100.160/27") is None
    assert ios.static_route_state(fixture("ro-show-ipv6-static-vrf__empty.txt"),
                                  "vrf:netops-g80:2001:db8:80:11::/64") is None
    with pytest.raises(Rejected, match="not a route through an address"):
        ios.static_route_state(fixture("ro-show-ip-static-route__objects.txt"), "198.51.100.240/28")
    with pytest.raises(Rejected, match="not recognised"):
        ios.static_route_state(fixture("ro-show-ip-static-route-vrf__baseline.txt"), "vrf:netops-g80:198.51.100.160/27")
    with pytest.raises(Rejected, match="not recognised"):
        ios.static_route_state(fixture("ro-show-ip-interface-Loopback8080__baseline.txt"), "198.51.100.128/27")


# ---- L3 interfaces ----

def test_l3_entries_of_the_measured_configuration():
    entries = ios.load(OBJECTS, FW).entries("l3-interface")
    assert entries["Loopback8080"].attributes == {"description": "netops-g80 test",
                                                  "ipv4-address": "198.51.100.1 255.255.255.192",
                                                  "ipv6-address": "2001:db8:80::1/64"}
    assert entries["Loopback8081"].attributes == {"vrf": "netops-g80", "ipv4-address": "198.51.100.65 255.255.255.192",
                                                  "ipv6-address": "2001:db8:80:1::1/64"}
    assert entries["Ethernet0/2.80"].attributes == {"encapsulation": "80",
                                                    "ipv4-address": "198.51.100.225 255.255.255.240"}
    assert entries["Loopback0"].unsupported and "Ethernet0/0" not in entries


def test_create_loopback_and_subinterface_render_the_measured_lines():
    lo = plan(request("l3-interface", "create", "Loopback8080", {
        "description": "netops-g80 test", "ipv4-address": "198.51.100.1/26", "ipv6-address": "2001:DB8:80::1/64"}))
    assert lo["commands"] == ["configure terminal", "interface Loopback8080", "description netops-g80 test",
                              "ip address 198.51.100.1 255.255.255.192", "ipv6 address 2001:db8:80::1/64", "end"]
    assert lo["inverse"] == ["configure terminal", "no interface Loopback8080", "end"]
    sub = plan(request("l3-interface", "create", "Ethernet0/2.80", {"encapsulation": 80,
                                                                    "ipv4-address": "198.51.100.225 255.255.255.240"}))
    assert sub["commands"][1:4] == ["interface Ethernet0/2.80", "encapsulation dot1Q 80",
                                    "ip address 198.51.100.225 255.255.255.240"]
    vrf = plan(request("l3-interface", "create", "Loopback8082", {"vrf": "netops-g80",
                                                                  "ipv4-address": "198.51.100.129/26"}), OBJECTS)
    assert vrf["commands"][1:4] == ["interface Loopback8082", "vrf forwarding netops-g80",
                                    "ip address 198.51.100.129 255.255.255.192"]


def test_update_replaces_ipv6_address_and_delete_recreates_the_subinterface():
    p = plan(request("l3-interface", "update", "Loopback8080", {"ipv6-address": "2001:db8:80::5/64",
                                                                "admin-state": "disabled"}), OBJECTS)
    assert p["commands"] == ["configure terminal", "interface Loopback8080", "shutdown",
                             "no ipv6 address 2001:db8:80::1/64", "ipv6 address 2001:db8:80::5/64", "end"]
    assert p["inverse"] == ["configure terminal", "interface Loopback8080", "no shutdown",
                            "no ipv6 address 2001:db8:80::5/64", "ipv6 address 2001:db8:80::1/64", "end"]
    removed = plan(request("l3-interface", "update", "Loopback8080", {"ipv4-address": None}), OBJECTS)
    assert removed["commands"][2:3] == ["no ip address"]
    assert removed["inverse"][2:3] == ["ip address 198.51.100.1 255.255.255.192"]
    deleted = plan(request("l3-interface", "delete", "Ethernet0/2.80"), OBJECTS)
    assert deleted["commands"] == ["configure terminal", "no interface Ethernet0/2.80", "end"]
    assert deleted["inverse"] == ["configure terminal", "interface Ethernet0/2.80", "encapsulation dot1Q 80",
                                  "ip address 198.51.100.225 255.255.255.240", "end"]


@pytest.mark.parametrize("op,key,changes,text,message", [
    ("update", "Loopback0", {"description": "x1"}, BASELINE, "outside the profile"),
    ("create", "Ethernet0/2.81", {"ipv4-address": "198.51.100.1/26"}, BASELINE, "needs encapsulation"),
    ("create", "Loopback8083", {"encapsulation": 80}, BASELINE, "subinterface only"),
    ("create", "Ethernet9/9.80", {"encapsulation": 80}, BASELINE, "parent interface"),
    ("create", "Loopback8082", {"ipv4-address": "198.51.100.10/24"}, OBJECTS, "overlaps"),
    ("create", "Loopback8082", {"ipv4-address": "192.0.2.200/32"}, BASELINE, "overlaps"),
    ("create", "Loopback8082", {"ipv6-address": "2001:db8:80::9/64"}, OBJECTS, "overlaps"),
    ("create", "Loopback8082", {"vrf": "netops-g80"}, BASELINE, "not defined"),
    ("create", "Loopback8082", {"ipv4-address": "198.51.100.0/26"}, BASELINE, "usable"),
    ("create", "Loopback8082", {"ipv6-address": "fe80::1/64"}, BASELINE, "usable"),
    ("update", "Ethernet0/2.80", {"encapsulation": 81}, OBJECTS, "cannot be updated"),
    ("update", "Loopback8081", {"vrf": "other"}, OBJECTS, "cannot be updated"),
    ("create", "Vlan80", {"ipv4-address": "198.51.100.1/26"}, BASELINE, "does not match"),
    ("create", "Loopback8080", {"description": "x1"}, OBJECTS, "already used"),
])
def test_l3_refusals_before_any_write(op, key, changes, text, message):
    with pytest.raises(Rejected, match=message):
        plan(request("l3-interface", op, key, changes), text)


def test_subinterface_admin_state_follows_the_parent_port():
    with pytest.raises(Rejected, match="follows its parent"):
        plan(request("l3-interface", "update", "Ethernet0/2.80", {"admin-state": "disabled"}), OBJECTS)
    shut = OBJECTS.replace(" encapsulation dot1Q 80\n", " encapsulation dot1Q 80\n shutdown\n")
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("l3-interface", "update", "Ethernet0/2.80", {"description": "x1"}), shut)
    # the measured check account answer: Et0/2.80 admin down under the shut Ethernet0/2, no own shutdown line
    device = G80Ios(OBJECTS)
    device.check_override = {"show interfaces description": fixture("ro-show-interfaces-description__objects.txt"),
                             "show ip interface Ethernet0/2.80": fixture("ro-show-ip-interface-Ethernet0-2.80__objects.txt"),
                             "show ipv6 interface Ethernet0/2.80": fixture(
                                 "ro-show-ipv6-interface-Ethernet0-2.80__objects.txt"),
                             "show interfaces Ethernet0/2.80": fixture("ro-show-interfaces-Ethernet0-2.80__objects.txt")}
    sub = plan(request("l3-interface", "update", "Ethernet0/2.80", {"description": "x1"}), OBJECTS)
    assert engine.observed_state(sub, exec_ios.observe(device, sub)) == sub["predicted"]["before"]


def test_a_referenced_interface_is_not_deleted():
    with pytest.raises(Rejected, match="referenced"):
        plan(request("l3-interface", "delete", "Loopback8080"), OBJECTS)


def test_the_device_refuses_an_overlapping_address_like_the_plan():
    assert ios.cli_error(fixture("config__ip-address-overlap.txt")).startswith("% 198.51.100.0 overlaps with")


def test_check_account_interface_answers_of_the_device():
    assert ios.ip_interface_state(fixture("ro-show-ip-interface-Loopback8081__objects.txt"), "Loopback8081") == {
        "ipv4-address": "198.51.100.65 255.255.255.192", "vrf": "netops-g80"}
    assert ios.ipv6_interface_state(fixture("ro-show-ipv6-interface-Loopback8080__objects.txt"), "Loopback8080") == {
        "ipv6-address": "2001:db8:80::1/64"}
    assert ios.ipv6_interface_state(fixture("ro-show-ipv6-interface-Ethernet0-2.80__objects.txt"),
                                    "Ethernet0/2.80") == {}
    assert ios.encapsulation_state(fixture("ro-show-interfaces-Ethernet0-2.80__objects.txt"),
                                   "Ethernet0/2.80") == {"encapsulation": "80"}
    with pytest.raises(Rejected, match="2 global IPv6"):
        ios.ipv6_interface_state(fixture("ro-show-ipv6-interface-Loopback8080__two-addresses.txt"), "Loopback8080")
    with pytest.raises(Rejected, match="refused"):
        ios.ip_interface_state(fixture("ro-show-ip-interface-Ethernet0-2.80__deleted.txt"), "Ethernet0/2.80")
    row = ios.description_row(fixture("ro-show-interfaces-description__sub-deleted.txt"), "Ethernet0/2.80")
    assert row["status"] == "deleted"
    row = ios.description_row(fixture("ro-show-interfaces-description__lo-shutdown.txt"), "Loopback8080")
    assert row == {"status": "admin down", "description": "netops-g80 test"}


def test_observe_reads_the_object_with_the_check_account():
    device = G80Ios(OBJECTS)
    device.check_override = {
        "show ip interface Loopback8080": fixture("ro-show-ip-interface-Loopback8080__objects.txt"),
        "show ipv6 interface Loopback8080": fixture("ro-show-ipv6-interface-Loopback8080__objects.txt"),
        "show interfaces description": fixture("ro-show-interfaces-description__objects.txt"),
        "show ip static route": fixture("ro-show-ip-static-route__objects.txt")}
    lo = plan(request("l3-interface", "update", "Loopback8080", {"description": "x1"}), OBJECTS)
    assert engine.observed_state(lo, exec_ios.observe(device, lo)) == lo["predicted"]["before"]
    route = plan(request("static-route", "update", "198.51.100.128/27", {"distance": 20}), OBJECTS)
    assert engine.observed_state(route, exec_ios.observe(device, route)) == route["predicted"]["before"]
    device.check_override["show interfaces description"] = fixture("ro-show-interfaces-description__sub-deleted.txt")
    sub = plan(request("l3-interface", "delete", "Ethernet0/2.80"), OBJECTS)
    assert exec_ios.observe(device, sub) is None


# ---- live prechecks: the management path (show tcp brief, show ip interface brief) ----

def test_default_route_through_management_does_not_refuse_other_routes():
    device = G80Ios()
    p = plan(request("static-route", "create", "198.51.100.128/27", {"next-hop": "198.51.100.2"}))
    assert exec_ios.plan_prechecks(device, DEVICE, p, BASELINE) == []
    assert any("does not touch the management interface (Ethernet0/0)" in check for check in p["prechecks"])


@pytest.mark.parametrize("table,op,key,changes", [
    ("static-route", "create", "192.0.2.128/25", {"next-hop": "203.0.113.1"}),
    ("static-route", "create", "203.0.113.160/28", {"next-hop": "192.0.2.1"}),
    ("static-route", "create", "203.0.113.166/32", {"next-hop": "192.0.2.2"}),
    ("l3-interface", "create", "Ethernet0/0.5", {"encapsulation": 5}),
    ("l3-interface", "create", "Loopback8082", {"ipv4-address": "203.0.113.166/32"}),
])
def test_management_path_is_refused(table, op, key, changes):
    device = G80Ios()
    try:
        p = plan(request(table, op, key, changes))
    except Rejected as exc:
        # the plan already refuses an address overlapping the management subnet or another interface
        assert "overlaps" in exc.reasons[0]
        return
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, BASELINE)
    assert caught.value.reason_codes == ["port_management_interface"]


def test_a_vrf_route_into_the_client_subnet_is_not_the_management_path():
    device = G80Ios(OBJECTS)
    p = plan(request("static-route", "create", "vrf:netops-g80:203.0.113.160/28", {"next-hop": "198.51.100.66"}),
             OBJECTS)
    assert exec_ios.plan_prechecks(device, DEVICE, p, OBJECTS) == []


# ---- end to end through Admin: preview without a write, apply, readback, undo ----

def test_preview_writes_nothing(tmp_path):
    device = G80Ios()
    result = execute.preview(runtime(tmp_path, device), "lab-ios",
                             request("static-route", "create", "198.51.100.128/27", {"next-hop": "198.51.100.2"}))
    assert result["result"] == "ready", result
    assert device.applied_blocks == [] and device.lines == device.saved
    assert "show ip static route" in device.check_queries


@pytest.mark.parametrize("req,undone", [
    (request("static-route", "create", "198.51.100.128/27", {"next-hop": "198.51.100.2", "distance": 50}), None),
    (request("static-route", "create", "2001:db8:80:10::/64", {"next-hop": "2001:db8:80::2"}), None),
    (request("l3-interface", "create", "Loopback8080", {"description": "netops-g80 test",
                                                        "ipv4-address": "198.51.100.1/26",
                                                        "ipv6-address": "2001:db8:80::1/64"}), None),
    (request("l3-interface", "create", "Ethernet0/2.80", {"encapsulation": 80,
                                                          "ipv4-address": "198.51.100.225/28"}), None),
])
def test_create_is_confirmed_read_back_and_undone_to_the_baseline(tmp_path, req, undone):
    device = G80Ios()
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab-ios", req)
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.applied_blocks[0][0].startswith("configure terminal revert timer")
    assert device.applied_blocks[1] == record["plan"]["commands"]
    assert "check_identity_passed" in steps(record) and device.timer is None
    back = execute.undo(rt, record["change_id"], "G80 return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert [line for line in device.lines if line != "!"] == [line for line in BASELINE[BASELINE.index(
        "Building configuration..."):].rstrip("\n").split("\n") if line != "!"]


@pytest.mark.parametrize("req", [
    request("static-route", "update", "198.51.100.128/27", {"next-hop": "198.51.100.4"}),
    request("static-route", "update", "vrf:netops-g80:2001:db8:80:11::/64", {"distance": None}),
    request("static-route", "delete", "vrf:netops-g80:198.51.100.160/27"),
    request("l3-interface", "update", "Loopback8081", {"ipv6-address": "2001:db8:80:1::5/64"}),
    request("l3-interface", "update", "Loopback8080", {"ipv4-address": "198.51.100.5/26", "admin-state": "disabled"}),
    request("l3-interface", "delete", "Ethernet0/2.80"),
], ids=lambda req: "%s-%s-%s" % (req.table, req.op, req.key))
def test_update_and_delete_on_the_measured_objects_are_undone(tmp_path, req):
    device = G80Ios(OBJECTS)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    record = execute.apply(rt, "lab-ios", req)
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert device.applied_blocks[1] == record["plan"]["commands"]
    back = execute.undo(rt, record["change_id"], "G80 return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    # IOS sorts recreated routes and interfaces itself; the fake appends them, so the lines are compared as a set
    assert sorted(line for line in device.lines if line != "!") == sorted(line for line in before if line != "!")


def test_a_device_refusal_during_the_write_is_returned_by_the_timer(tmp_path):
    device = G80Ios(OBJECTS)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    # the plan cannot see an address taken by someone right before the write; IOS refuses it (measured answer)
    def taken(fake, block):
        if block[:2] == ["configure terminal", "interface Loopback8082"]:
            index = fake.lines.index(" ip address 198.51.100.225 255.255.255.240")
            fake.lines[index] = " ip address 198.51.100.200 255.255.255.240"
    device.on_apply = taken
    record = execute.apply(rt, "lab-ios", request("l3-interface", "create", "Loopback8082",
                                                  {"ipv4-address": "198.51.100.193/28"}))
    assert record["result"] in ("reverted", "unknown"), (record["result"], steps(record))
    assert "change_failed" in steps(record)
    assert device.interface("Loopback8082") is None and device.lines == before


# ---- 454-r2: a VRF with only address-family ipv6 (the families follow the configured addresses) ----

def test_v6_only_vrf_fixture_holds_the_measured_objects():
    assert "interface Loopback8082" not in V6_VRF_ONLY and "vrf definition netops-g80-v6" in V6_VRF_ONLY
    assert ios.vrf_families(ios.load(V6_VRF, FW), "netops-g80-v6") == {6}
    assert ios.load(V6_VRF, FW).entries("l3-interface")["Loopback8082"].attributes == {
        "description": "netops-g80 v6", "vrf": "netops-g80-v6", "ipv6-address": "2001:db8:82::1/64"}


def test_ipv6_loopback_in_an_ipv6_only_vrf_is_planned_updated_deleted_and_recreated():
    created = plan(request("l3-interface", "create", "Loopback8082", {"vrf": "netops-g80-v6",
                                                                      "ipv6-address": "2001:db8:82::1/64"}),
                   V6_VRF_ONLY)
    assert created["commands"] == ["configure terminal", "interface Loopback8082", "vrf forwarding netops-g80-v6",
                                   "ipv6 address 2001:db8:82::1/64", "end"]
    changed = plan(request("l3-interface", "update", "Loopback8082", {"description": "x1"}), V6_VRF)
    assert changed["commands"] == ["configure terminal", "interface Loopback8082", "description x1", "end"]
    deleted = plan(request("l3-interface", "delete", "Loopback8082"), V6_VRF)
    # the inverse of the delete is the create of the original state; it passes the same checks
    assert deleted["inverse"] == ["configure terminal", "interface Loopback8082", "vrf forwarding netops-g80-v6",
                                  "description netops-g80 v6", "ipv6 address 2001:db8:82::1/64", "end"]
    recreated = plan(request("l3-interface", "create", "Loopback8082", {
        "vrf": "netops-g80-v6", "description": "netops-g80 v6", "ipv6-address": "2001:db8:82::1/64"}), V6_VRF_ONLY)
    assert recreated["commands"] == deleted["inverse"]


@pytest.mark.parametrize("changes,text", [
    ({"vrf": "netops-g80-v6", "ipv4-address": "198.51.100.129/26"}, V6_VRF_ONLY),
    ({"vrf": "netops-g80-v6", "ipv4-address": "198.51.100.129/26", "ipv6-address": "2001:db8:82::1/64"}, V6_VRF_ONLY),
])
def test_an_ipv4_address_in_an_ipv6_only_vrf_is_still_refused(changes, text):
    with pytest.raises(Rejected, match="no address-family ipv4"):
        plan(request("l3-interface", "create", "Loopback8083", changes), text)
    with pytest.raises(Rejected, match="no address-family ipv4"):
        plan(request("l3-interface", "update", "Loopback8082", {"ipv4-address": "198.51.100.129/26"}), V6_VRF)


def test_a_vrf_without_any_address_family_is_refused():
    bare = V6_VRF_ONLY.replace("vrf definition netops-g80-v6\n !\n address-family ipv6\n exit-address-family\n",
                               "vrf definition netops-g80-v6\n")
    assert ios.vrf_families(ios.load(bare, FW), "netops-g80-v6") == set()
    with pytest.raises(Rejected, match="no address-family"):
        plan(request("l3-interface", "create", "Loopback8082", {"vrf": "netops-g80-v6"}), bare)


def test_check_account_names_the_vrf_of_an_ipv6_only_interface():
    # measured: show ip interface names no VRF when IPv4 is disabled; show ipv6 interface does
    assert ios.ip_interface_state(fixture("ro-show-ip-interface-Loopback8082__v6-vrf.txt"), "Loopback8082") == {}
    assert ios.ipv6_interface_state(fixture("ro-show-ipv6-interface-Loopback8082__v6-vrf.txt"), "Loopback8082") == {
        "ipv6-address": "2001:db8:82::1/64", "vrf": "netops-g80-v6"}
    device = G80Ios(V6_VRF)
    device.check_override = {
        "show interfaces description": fixture("ro-show-interfaces-description__v6-vrf.txt"),
        "show ip interface Loopback8082": fixture("ro-show-ip-interface-Loopback8082__v6-vrf.txt"),
        "show ipv6 interface Loopback8082": fixture("ro-show-ipv6-interface-Loopback8082__v6-vrf.txt")}
    lo = plan(request("l3-interface", "update", "Loopback8082", {"description": "x1"}), V6_VRF)
    assert engine.observed_state(lo, exec_ios.observe(device, lo)) == lo["predicted"]["before"]


def test_check_account_vrf_answers_that_disagree_are_refused():
    six = fixture("ro-show-ipv6-interface-Loopback8081__objects.txt").replace('"netops-g80"', '"other"')
    device = G80Ios(OBJECTS)
    device.check_override = {
        "show interfaces description": fixture("ro-show-interfaces-description__objects.txt"),
        "show ip interface Loopback8081": fixture("ro-show-ip-interface-Loopback8081__objects.txt"),
        "show ipv6 interface Loopback8081": six}
    lo = plan(request("l3-interface", "update", "Loopback8081", {"description": "x1"}), OBJECTS)
    with pytest.raises(Rejected, match="VRF"):
        exec_ios.observe(device, lo)


def test_ipv6_only_vrf_loopback_create_update_undo_delete_undo(tmp_path):
    device = G80Ios(V6_VRF_ONLY)
    rt = runtime(tmp_path, device)
    before = sorted(line for line in device.lines if line != "!")
    created = execute.apply(rt, "lab-ios", request("l3-interface", "create", "Loopback8082", {
        "vrf": "netops-g80-v6", "description": "netops-g80 v6", "ipv6-address": "2001:db8:82::1/64"}))
    assert created["result"] == "confirmed", (created["reason"], steps(created))
    changed = execute.apply(rt, "lab-ios", request("l3-interface", "update", "Loopback8082", {"description": "x1"},
                                                   request_id="req-g80-0002"))
    assert changed["result"] == "confirmed", (changed["reason"], steps(changed))
    back = execute.undo(rt, changed["change_id"], "G80 return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    deleted = execute.apply(rt, "lab-ios", request("l3-interface", "delete", "Loopback8082",
                                                   request_id="req-g80-0003"))
    assert deleted["result"] == "confirmed", (deleted["reason"], steps(deleted))
    back = execute.undo(rt, deleted["change_id"], "G80 return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    snapshot = ios.load(device.snapshot(), FW)
    assert snapshot.entries("l3-interface")["Loopback8082"].attributes == {
        "description": "netops-g80 v6", "vrf": "netops-g80-v6", "ipv6-address": "2001:db8:82::1/64"}
    final = execute.apply(rt, "lab-ios", request("l3-interface", "delete", "Loopback8082",
                                                 request_id="req-g80-0004"))
    assert final["result"] == "confirmed", (final["reason"], steps(final))
    assert sorted(line for line in device.lines if line != "!") == before
