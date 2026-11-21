"""Cisco IOS and IOS XE plan adapter: interface description, admin state and access VLAN from show running-config.

One adapter serves both platforms (``ios`` for IOS 15.x, ``iosxe`` for IOS XE 17.x); their differences are data
of the device answers, not separate code. Measured on IOSv 15.9(3)M12 (router), IOSvL2 15.2(20200924:215240)
(switch), IOL XE 17.18.2 (router) and IOL-L2 XE 17.18.2 (switch) in the GNS3 lab (task netops-provoz-20261116-310,
ref/mereni-c4c5): ``show running-config`` over SSH exec answers "Building configuration...", "Current configuration :
N bytes", the top-level statements with their lines indented by one space, and "end". The running configuration
names only the release train ("version 15.9", "version 17.18"); the full firmware is the configured one, which the
prechecks compare with the live ``show version``. IOS creates a missing VLAN when a port is put into it (a VLAN of the
normal range only in vlan.dat, which the rollback does not remove) and accepts the management interface and VLAN, so
the plan and the live prechecks refuse both before anything is sent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from netops_admin import ios_acl, ios_services
from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)

PLATFORMS = ("ios", "iosxe")
BUILDING = "Building configuration..."
CURRENT = re.compile(r"^Current configuration : [0-9]+ bytes$")
VERSION = re.compile(r"^version ([0-9]+\.[0-9]+)$")
RELEASE = re.compile(r"^([0-9]+\.[0-9]+)[.(]")
# an SSH exec command that IOS refuses (unknown command or above the privilege of the account) answers this line
# with exit status 0 (measured, fixtures exec__*__rc0.txt)
EXEC_REFUSED = "Line has invalid autocommand"
# lines of the answer that change without a configuration change
VOLATILE_HEADER = (BUILDING, "Current configuration :", "! Last configuration change at",
                   "! NVRAM config last updated at", "! No configuration change since last restart")
INDENT = " "
ETHERNET = re.compile(r"^(?:Ethernet|FastEthernet|GigabitEthernet|TwoGigabitEthernet|FiveGigabitEthernet|"
                      r"TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE)"
                      r"[0-9]{1,2}(?:/[0-9]{1,3}){1,2}$")
MANAGEMENT_VRF = re.compile(r"^(?:ip )?vrf forwarding (\S+)$")
MANAGEMENT_VRF_NAME = re.compile(r"(?i)mgmt|management")
BANNER = re.compile(r"^banner \S+ (\S+)")
DEFAULT_VLAN = "1"
# VLANs 1002-1005 are the reserved FDDI/Token Ring VLANs (act/unsup in show vlan brief); no Ethernet access VLAN
RESERVED_VLANS = frozenset(("1002", "1003", "1004", "1005"))
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# 1.0.12 G61: the port bounce owns the shutdown line, the PoE tables the line "power inline auto|never|static [max N]"
# (IOS keeps one such line; "power inline port priority", "police" and the other power inline lines stay outside)
BOUNCE_TABLE = "port-bounce"
POE_TABLE = "inline-power"
POE_CYCLE_TABLE = "poe-cycle"
POE_TABLES = (POE_TABLE, POE_CYCLE_TABLE)
ACTION_TABLES = (BOUNCE_TABLE, POE_CYCLE_TABLE)
PORT_ACTION_TABLES = (BOUNCE_TABLE, POE_TABLE, POE_CYCLE_TABLE)
POWER_INLINE = re.compile(r"^(?:no )?power inline (auto|never|static)(?: max ([0-9]+))?$")
POE_MAX_RANGE = (4000, 90000)
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$")),
    BOUNCE_TABLE: (re.compile(r"^(?:no )?shutdown$"),),
    POE_TABLE: (POWER_INLINE,),
    POE_CYCLE_TABLE: (POWER_INLINE,),
    "vlan-membership": (re.compile(r"^(?:no )?switchport access vlan(?: [0-9]+)?$"),),
}
EXTENDED_MEMBERSHIP = (re.compile(r"^(?:no )?switchport (?:access vlan(?: [0-9]+)?|mode(?: .+)?|trunk (?:allowed vlan .+|native vlan [0-9]+|encapsulation \S+)|voice vlan(?: \S+)?)$"),)


def own_lines(table, platform):
    return EXTENDED_MEMBERSHIP if table == "vlan-membership" and platform in PLATFORMS else OWN_LINES.get(table, ())


TRUNK = re.compile(r"^switchport (?:mode (?!access$)\S+|trunk )")
LAG = re.compile(r"^channel-group ")
ROUTED = re.compile(r"^no switchport$")
IP_ADDRESS = re.compile(r"^ip address (?!$)")


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


class Block:
    def __init__(self, header: str, line: int):
        self.header = header
        self.line = line
        self.children = []


def release_of(firmware: str):
    """The release train that the running configuration names: 15.9 of 15.9(3)M12, 17.18 of 17.18.2."""
    match = RELEASE.match((firmware or "") + ".")
    return None if match is None else match.group(1)


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        if not firmware:
            raise Rejected(["an IOS running configuration names only its release train; the caller must state the "
                            "firmware"])
        lines = text.replace("\r", "").split("\n")
        filled = [line.strip() for line in lines if line.strip()]
        if any(line.startswith(EXEC_REFUSED) for line in filled[:3]):
            raise SnapshotRejected(["the device refused show running-config (%s)" % EXEC_REFUSED],
                                   SNAPSHOT_UNREADABLE)
        if len(filled) < 3 or filled[0] != BUILDING or CURRENT.match(filled[1]) is None:
            raise SnapshotRejected(["snapshot does not start with %r and the configuration size; it is not an IOS "
                                    "running configuration" % BUILDING], SNAPSHOT_UNREADABLE)
        if filled[-1] != "end":
            raise SnapshotRejected(["snapshot does not end with 'end'; the running configuration is cut off"],
                                   SNAPSHOT_INCOMPLETE)
        trains = [VERSION.match(line).group(1) for line in lines if VERSION.match(line.rstrip())]
        if len(trains) != 1:
            raise SnapshotRejected(["snapshot does not name the IOS release train in one version line"],
                                   SNAPSHOT_UNREADABLE)
        if release_of(firmware) != trains[0]:
            raise SnapshotRejected(["snapshot was taken on IOS %s, not on the configured %s" % (trains[0], firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        self.firmware = firmware
        self.platform = None
        self.vlans = {}
        self.has_vlan_database = False
        for line in lines:
            if line == "! netops-vlan-database":
                self.has_vlan_database = True
            match = re.fullmatch(r"! netops-vlan ([0-9]+) (\S+) (\S+)", line)
            if match:
                vid, name, status = match.groups()
                if vid in self.vlans:
                    raise SnapshotRejected(["duplicate VLAN in snapshot"], SNAPSHOT_UNREADABLE)
                entry = Entry(vid)
                entry.attributes["name"] = name
                if status != "active":
                    entry.unsupported.append("VLAN is not active")
                self.vlans[vid] = entry
        self.hostname = None
        self.inventory = None
        start = next(index for index, line in enumerate(lines) if line.strip() == BUILDING)
        lines = self.source_lines = lines[start:]
        self.lines = [line.rstrip() for line in lines if line.strip()]
        self.blocks, self.interfaces = [], {}
        current, banner = None, None
        for number, line in enumerate(lines, 1):
            stripped = line.rstrip()
            if banner is not None:
                if banner in stripped:
                    banner = None
                continue
            if not stripped.strip():
                continue
            if stripped.startswith("!") or stripped == "end":
                current = None
                continue
            if stripped.startswith(" ") or stripped.startswith("\t"):
                if current is None:
                    if stripped.strip().startswith("!"):
                        continue
                    raise SnapshotRejected(["line %d is indented outside any statement" % number],
                                           SNAPSHOT_UNREADABLE)
                current.children.append(stripped)
                continue
            if stripped in (BUILDING,) or CURRENT.match(stripped):
                continue
            current = Block(stripped, number)
            self.blocks.append(current)
            words = stripped.split()
            delimiter = BANNER.match(stripped)
            if delimiter is not None:
                rest = stripped[delimiter.end():]
                current = None
                if delimiter.group(1) not in rest:
                    banner = delimiter.group(1)
                continue
            if words[0] == "interface" and len(words) == 2:
                if words[1] in self.interfaces:
                    raise SnapshotRejected(["interface %s is listed twice" % words[1]], SNAPSHOT_UNREADABLE)
                self.interfaces[words[1]] = current
            elif words[0] == "hostname" and len(words) == 2:
                self.hostname = words[1]
        if banner is not None:
            raise SnapshotRejected(["a banner of the snapshot is not closed"], SNAPSHOT_UNREADABLE)
        if self.hostname is None:
            raise SnapshotRejected(["snapshot does not name the hostname"], SNAPSHOT_UNREADABLE)

    def entries(self, table: str):
        if table in ios_acl.TABLES:
            return ios_acl.entries(self, table, Entry)
        if table == "vlan":
            return self.vlans if self.has_vlan_database else None
        if table in ios_services.TABLES:
            return ios_services.entries(((block.line, block.header) for block in self.blocks), table, Entry)
        if table == ROUTE_TABLE:
            return static_routes(self)
        if table == L3_TABLE:
            return {name: l3_entry(name, block) for name, block in self.interfaces.items() if L3_KEY.fullmatch(name)}
        if table == MEMBER_TABLE:
            return member_entries(self)
        if table in DHCP_TABLES:
            return dhcp_entries(self, table)
        if table not in OWN_LINES:
            return None
        return {name: self._entry(table, name, block) for name, block in self.interfaces.items()}

    def _entry(self, table, name, block):
        entry = Entry(name)
        for child in block.children:
            line = child[len(INDENT):] if child.startswith(INDENT) and not child.startswith(INDENT + " ") else None
            if line is None:
                continue
            if table == "interface" and line.startswith("description "):
                _once(entry, "description", line[len("description "):], block)
            elif table == "interface" and line == "shutdown":
                _once(entry, "admin-state", "disabled", block)
            elif table == BOUNCE_TABLE and line == "shutdown":
                _once(entry, "admin-state", "disabled", block)
            elif table in POE_TABLES and POWER_INLINE.fullmatch(line) and not line.startswith("no "):
                found = POWER_INLINE.fullmatch(line)
                _once(entry, "mode", found.group(1), block)
                if found.group(2) is not None:
                    _once(entry, "max-milliwatts", found.group(2), block)
            elif table == "vlan-membership" and line.startswith("switchport access vlan "):
                _once(entry, "access-vlan", line.split()[-1], block)
        if table == "vlan-membership" and self.platform in PLATFORMS:
            allowed = None
            for child in block.children:
                line = child.strip()
                for prefix, attribute in (("switchport mode ", "mode"),
                        ("switchport trunk encapsulation ", "trunk-encapsulation"),
                        ("switchport trunk native vlan ", "native-vlan"),
                        ("switchport voice vlan ", "voice-vlan")):
                    if line.startswith(prefix):
                        _once(entry, attribute, line[len(prefix):], block)
                prefix = "switchport trunk allowed vlan "
                if line.startswith(prefix):
                    value = line[len(prefix):]
                    if value.startswith("add "):
                        allowed = vlan_numbers(allowed or "all") | vlan_numbers(value[4:])
                    elif value.startswith("remove "):
                        allowed = vlan_numbers(allowed or "all") - vlan_numbers(value[7:])
                    elif value.startswith("except "):
                        allowed = vlan_numbers("all") - vlan_numbers(value[7:])
                    else:
                        allowed = vlan_numbers(value)
            if allowed is not None:
                entry.attributes["allowed-vlans"] = vlan_text(allowed)
        return entry

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table == L3_TABLE:
            return l3_references(self, key)
        if table != "vlan":
            return []
        found = []
        for name in self.interfaces:
            lines = self.interface_lines(name)
            if name == "Vlan" + key or any(line in (
                    "switchport access vlan " + key, "switchport voice vlan " + key,
                    "switchport trunk native vlan " + key) for line in lines):
                found.append(name)
            if "switchport mode trunk" in lines:
                entry = self._entry("vlan-membership", name, self.interfaces[name])
                # IOS defaults to all, including VLANs not yet in the database.
                # Only a restricted allowed set is an explicit VLAN reference.
                allowed = entry.attributes.get("allowed-vlans", "all")
                if allowed != "all" and int(key) in vlan_numbers(allowed):
                    found.append(name)
        return sorted(set(found))

    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        block = self.interfaces.get(key)
        return [] if block is None else [child.strip() for child in block.children]

    def addressed(self, key: str) -> list:
        """The interface and its subinterfaces (key.N) that carry an IPv4 address in the running configuration."""
        found = []
        for name, block in self.interfaces.items():
            if name != key and not name.startswith(key + "."):
                continue
            if any(IP_ADDRESS.match(child.strip()) for child in block.children
                   if child.startswith(INDENT) and not child.startswith(INDENT + " ")):
                found.append(name)
        return sorted(found)

    def addresses(self) -> dict:
        """IPv4 addresses of the running configuration mapped to their interface (primary and secondary)."""
        found = {}
        for name, block in self.interfaces.items():
            for child in block.children:
                words = child.strip().split()
                if words[:2] == ["ip", "address"] and len(words) >= 4 and re.fullmatch(r"[0-9.]+", words[2]):
                    found[words[2]] = name
        return found

    def management_vrf(self, key: str) -> bool:
        for line in self.interface_lines(key):
            match = MANAGEMENT_VRF.match(line)
            if match is not None and MANAGEMENT_VRF_NAME.search(match.group(1)):
                return True
        return False

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        kept, inside = [], False
        if table in ios_acl.TABLES:
            kept = [line for line in ios_acl.without_object(self.lines, table, key)
                    if line and line != "!" and not line.startswith(VOLATILE_HEADER)]
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        if table in DHCP_TABLES:
            body = "\n".join(line for line in dhcp_unowned_lines(self.lines, table, key)
                             if line != "!" and not line.startswith(VOLATILE_HEADER))
            return hashlib.sha256(body.encode()).hexdigest()
        if table in ios_services.TABLES:
            return ios_services.rest_digest(self, table, key, VOLATILE_HEADER)
        if table in STATE_TABLES:
            return state_rest_digest(self, table, key)
        if table == MEMBER_TABLE:
            return member_rest_digest(self, key)
        if table == "vlan":
            kept = []
            own = False
            for line in self.lines:
                if line == "!" or line.startswith(VOLATILE_HEADER) or line.startswith("! netops-vlan " + key + " "):
                    continue
                if not line.startswith(" "):
                    own = line == "vlan " + key
                if not own:
                    kept.append(line)
            return hashlib.sha256("\n".join(kept).encode()).hexdigest()
        for line in self.lines:
            if line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if inside and line.startswith(INDENT) and not line.startswith(INDENT + " ") \
                    and any(pattern.match(line.strip()) for pattern in own_lines(table, self.platform)):
                continue
            kept.append(line)
        return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def _once(entry, name, value, block):
    if name in entry.attributes:
        entry.unsupported.append("line %d: repeated %s" % (block.line, name))
    entry.attributes[name] = value


def load(text: str, firmware: str | None) -> Snapshot:
    try:
        return Snapshot(text, firmware)
    except (SnapshotRejected, Rejected):
        raise
    except Exception as exc:
        raise SnapshotRejected(["snapshot does not parse: %s" % type(exc).__name__], SNAPSHOT_UNREADABLE) from None


def absent(snapshot, table: str, key: str) -> list:
    if table == ios_acl.ACL:
        return ["ACL %s is not in the running configuration; the change is refused" % key]
    if table == ios_acl.BINDING:
        return ["interface access-group %s is not a supported interface of the running configuration; the change is "
                "refused" % key]
    if table == ROUTE_TABLE:
        return ["static route %s is not in the running configuration; the change is refused" % key]
    if table == MEMBER_TABLE and key in snapshot.interfaces:
        return ["port %s is not a member of any channel-group; the change is refused" % key]
    return ["interface %s is not in the running configuration; the change is refused" % key]


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip():
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    if profile.table == MEMBER_TABLE:
        # the lines need the snapshot (a port-channel created or left empty); engine.build_plan renders render_member
        return []
    if profile.table in STATE_TABLES:
        return render_state(profile.table, key, None, attributes)
    if profile.table == "vlan":
        return ["configure terminal", "vlan " + key, "name " + _text(attributes["name"]), "end"]
    raise Rejected(["IOS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    if profile.table in STATE_TABLES or profile.table == MEMBER_TABLE:
        # the lines need the state before; engine.build_plan renders them with render_state
        return []
    if profile.table == "vlan":
        return ["configure terminal", "no vlan " + key, "end"]
    raise Rejected(["IOS %s objects are only updated" % profile.table])


def _line(name: str, value) -> str:
    if name == "description":
        return "no description" if value is None else "description %s" % _text(value)
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return "shutdown" if value == "disabled" else "no shutdown"
    if name in ("mode", "trunk-encapsulation"):
        if value is None or value in ("dynamic auto", "negotiate"):
            return "no switchport " + ("mode" if name == "mode" else "trunk encapsulation")
        return "switchport %s %s" % ("mode" if name == "mode" else "trunk encapsulation", _text(value))
    if name == "native-vlan":
        return "switchport trunk native vlan " + str(value or "1")
    if name == "allowed-vlans":
        return "switchport trunk allowed vlan " + vlan_text(vlan_numbers(value or "all"))
    if name == "voice-vlan":
        return "no switchport voice vlan" if value is None or value == "none" else "switchport voice vlan " + str(value)
    if name == "access-vlan":
        # the return to VLAN 1 names it: show running-config then shows no access VLAN line (the default)
        value = DEFAULT_VLAN if value is None else str(value)
        if not value.isdigit():
            raise Rejected(["access-vlan must be a VLAN number"])
        return "switchport access vlan %s" % value
    raise Rejected(["attribute %s is not known on IOS" % name])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure terminal, the interface, its lines and end.

    The lines run while the safeguard of Admin is pending (configure terminal revert timer, opened before); an expired
    timer returns the whole running configuration to the archive taken when the safeguard was opened."""
    if profile.table == "vlan":
        return ["configure terminal", "vlan " + key, "name " + _text(assign["name"]), "end"]
    if profile.table in STATE_TABLES or profile.table == MEMBER_TABLE or profile.table in POE_TABLES:
        # the lines need the whole state before and after; engine.build_plan renders them with render_state,
        # render_member or render_poe
        return []
    # Encapsulation must be selected before trunk mode; mode must leave trunk before resetting encapsulation.
    order = lambda name: (0 if name == "mode" and assign.get(name) != "trunk" else
                          1 if name == "trunk-encapsulation" else 2, name)
    lines = [_line(name, assign[name]) for name in sorted(assign, key=order)]
    lines += [_line(name, None) for name in sorted(remove)]
    if not lines:
        return []
    return ["configure terminal", "interface %s" % key] + lines + ["end"]


def poe_line(state) -> str | None:
    """The one "power inline" line of a PoE state (None: no line, the default auto without a maximum)."""
    state = state or {}
    mode = state.get("mode", "auto")
    if mode not in ("auto", "never", "static"):
        raise Rejected(["mode must be auto, never or static"])
    maximum = state.get("max-milliwatts")
    if mode == "never":
        if maximum is not None:
            raise Rejected(["max-milliwatts applies to the modes auto and static, not to never"])
        return "power inline never"
    if maximum is not None:
        if not str(maximum).isdigit() or not POE_MAX_RANGE[0] <= int(maximum) <= POE_MAX_RANGE[1]:
            raise Rejected(["max-milliwatts must be %d-%d" % POE_MAX_RANGE])
        return "power inline %s max %s" % (mode, maximum)
    return None if mode == "auto" else "power inline static"


def render_poe(key: str, state) -> list:
    """Lines that set the PoE mode of the port to the state: the line replaces the earlier one; the default state is
    written as the explicit "power inline auto" (the running configuration then shows no line)."""
    return ["configure terminal", "interface %s" % key, poe_line(state) or "power inline auto", "end"]


def poe_after(table: str, key: str, before, after, changes) -> dict:
    """The PoE state after the change as the device keeps it: "power inline never" replaces a line with a maximum, so
    the maximum is gone; the cycle takes the port off and returns it by its earlier line."""
    if table == POE_CYCLE_TABLE:
        if set(changes) != {"admin-state"} or changes["admin-state"] != "disabled":
            raise Rejected(["the PoE cycle takes the change admin-state=disabled only"], reason_codes=["action_unsupported"])
        if before.get("mode") == "never":
            raise Rejected(["PoE of port %s is configured never; a cycle needs it enabled" % key],
                           reason_codes=["poe_disabled"])
        return {"mode": "never"}
    after = dict(after)
    if after.get("mode") == "never":
        if "max-milliwatts" in changes and changes["max-milliwatts"] is not None:
            raise Rejected(["max-milliwatts applies to the modes auto and static, not to never"])
        after.pop("max-milliwatts", None)
    poe_line(after)
    return after


def interface_kind(snapshot, key: str) -> str:
    if snapshot is not None and snapshot.management_vrf(key):
        return "management"
    if ETHERNET.fullmatch(key):
        return "ethernet"
    return "other"


def disruptive(table: str, before, after) -> bool:
    """A change that can cut or restore traffic on the port: admin state in either direction or another access VLAN.

    Enabling a disabled uplink or port-channel member can bring back a loop, so admin up gets the same port checks
    as admin down; the description alone does not."""
    before, after = before or {}, after or {}
    if table == "interface":
        return after.get("admin-state", "enabled") != before.get("admin-state", "enabled")
    if table in PORT_ACTION_TABLES:
        return True  # a bounce or a PoE change cuts the link or the power of the device on the port
    return table == "vlan-membership" and before != after


def prechecks(snapshot, profile, op: str, key: str, after, *, before=None) -> list:
    if profile.table in ios_acl.TABLES:
        return []  # the ACL prechecks need the whole states before and after (engine.build_plan: ios_acl.prechecks)
    if profile.table in ios_services.TABLES:
        return []
    if profile.table == ROUTE_TABLE:
        return route_prechecks(snapshot, key, after)
    if profile.table == L3_TABLE:
        if op == "delete":
            return l3_prechecks(snapshot, "create", key, before)
        return l3_prechecks(snapshot, op, key, after)
    if profile.table == MEMBER_TABLE:
        return member_prechecks(snapshot, key, after)
    if profile.table in DHCP_TABLES:
        return dhcp_prechecks(snapshot, profile.table, key, after)
    if profile.table == "vlan":
        if key == "1" or key in RESERVED_VLANS or not 1 <= int(key) <= 4094:
            raise Rejected(["default or reserved VLAN cannot be changed"], reason_codes=["vlan_reserved"])
        block = next((block for block in snapshot.blocks if block.header == "vlan " + key), None)
        if block and any(not child.strip().startswith("name ") for child in block.children):
            raise Rejected(["VLAN holds configuration outside the name profile"])
        return []
    kind = interface_kind(snapshot, key)
    if kind == "management":
        raise Rejected(["interface %s is in a management VRF; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only physical Ethernet ports are changed" % key],
                       reason_codes=["port_unsupported_interface"])
    lines = snapshot.interface_lines(key)
    before = snapshot._entry(profile.table, key, snapshot.interfaces[key]).attributes if key in snapshot.interfaces \
        else {}
    if profile.table in POE_TABLES and after is not None:
        poe_line(after)
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of a port-channel; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        # G78/G60: trunk membership changes are planned (runtime prechecks require endpoint_impact); the state of a
        # trunk/uplink port on IOS stays refused (IOS-C001 is about occupied client access ports).
        if (snapshot.platform not in PLATFORMS or (snapshot.platform == "ios" and profile.table == "interface")) \
                and any(TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk or negotiates trunking; it is treated as an uplink and is not "
                            "changed" % key], reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
        addressed = snapshot.addressed(key)
        if addressed:
            raise Rejected(["interface %s carries an IPv4 address (%s); an interface in use for routing is not "
                            "changed" % (key, ", ".join(addressed))], reason_codes=["port_ip_address"])
    if profile.table == "vlan-membership":
        state = after or {}
        for attr in ("access-vlan", "native-vlan", "voice-vlan"):
            value = state.get(attr)
            if value is not None and value != "none" and (not str(value).isdigit() or not 1 <= int(value) <= 4094):
                raise Rejected(["%s must be a VLAN in 1..4094" % attr])
            if value in RESERVED_VLANS:
                raise Rejected(["reserved VLAN cannot be assigned"], reason_codes=["vlan_reserved"])
        mode = state.get("mode", "dynamic auto")
        if mode == "trunk" and state.get("trunk-encapsulation") != "dot1q":
            raise Rejected(["trunk mode requires trunk-encapsulation dot1q"])
        wanted = str(state.get("access-vlan", DEFAULT_VLAN))
        if wanted in RESERVED_VLANS:
            raise Rejected(["VLAN %s is a reserved VLAN (1002-1005), not an Ethernet access VLAN" % wanted],
                           reason_codes=["vlan_reserved"])
    return []


def snapshot_after(text: str, plan) -> str:
    """The running configuration with the planned state of the interface lines (for the audit prediction)."""
    key, table, state = plan["key"], plan["table"], plan["predicted"]["after"] or {}
    if table in ios_acl.TABLES:
        return ios_acl.snapshot_after(load(text, plan["firmware"]), plan)
    if table in DHCP_TABLES:
        return dhcp_snapshot_after(text, plan)
    if table in ios_services.TABLES:
        return ios_services.snapshot_after(load(text, plan["firmware"]), plan)
    if table in STATE_TABLES:
        return state_snapshot_after(text, plan)
    if table == MEMBER_TABLE:
        return member_snapshot_after(text, plan)
    if table == "vlan":
        result, inside = [], False
        for line in text.replace("\r", "").split("\n"):
            if line.startswith("! netops-vlan " + key + " "):
                continue
            if line and not line.startswith(" "):
                inside = line == "vlan " + key
            if not inside and line != "end":
                result.append(line)
        if plan["predicted"]["after"] is not None:
            result += ["! netops-vlan %s %s active" % (key, state["name"])]
            if int(key) > 1005:
                result += ["vlan " + key, " name " + state["name"], "!"]
        return "\n".join(result).rstrip() + "\nend\n"
    own = own_lines(table, plan["platform"])
    result, inside = [], False
    for line in text.replace("\r", "").split("\n"):
        if line and not line.startswith(" "):
            if inside and table in POE_TABLES:
                result.extend(INDENT + new for new in (poe_line(state),) if new is not None)
            elif inside:
                result.extend(INDENT + _line(name, value) for name, value in sorted(state.items()))
            inside = line.rstrip() == "interface %s" % key
            result.append(line)
            continue
        if inside and line.strip() and any(pattern.match(line.strip()) for pattern in own):
            continue
        result.append(line)
    return "\n".join(result)


def batch_snapshot(text, firmware, *, platform="ios"):
    """Give projected IOS stanzas the same order as live ones for batch readback.

    Order within ACLs, DNS resolvers, DHCP options and unmanaged stanzas is retained.
    """
    snapshot = load(text, firmware)
    snapshot.platform = platform
    movable = ("interface ", "vlan ", "ip access-list ", "ipv6 access-list ", "ip dhcp pool ",
               "ip dhcp excluded-address ", "ip route ", "ipv6 route ", "ntp server ", "logging host ",
               "ip host ", "ntp source ", "logging source-interface ", "logging trap", "no logging trap",
               "clock timezone ", "ip domain name ", "ip domain-name ", "ip name-server ")
    acl_stanzas, acl_bodies = ios_acl.batch_stanzas(snapshot, Entry)
    stanzas, owned = [], set()
    for block in snapshot.blocks:
        if not block.header.startswith(movable):
            continue
        children = acl_stanzas.get(block.header, block.children)
        header = block.header
        if header.startswith("interface "):
            # Scope-specific renderers place these independent lines at different positions in the stanza.
            ordered, remaining = [], []
            for line in children:
                value = line[1:]
                if value == "no shutdown" or (value == "no ip address" and L3_KEY.fullmatch(header[10:])):
                    continue
                if value.startswith("ipv6 address "):
                    line = re.sub(r"[0-9a-fA-F:]+/[0-9]+", lambda match: match[0].lower(), line)
                dest = ordered if value.startswith(("description ", "channel-group ", "ip helper-address ",
                                                     "ip access-group ", "ipv6 traffic-filter ", "ip address ",
                                                     "ipv6 address ", "encapsulation dot1Q ", "vrf forwarding ",
                                                     "ip vrf forwarding ", "switchport ")) \
                    or value in ("shutdown", "no shutdown") or POWER_INLINE.fullmatch(value) else remaining
                dest.append(line)
            children = remaining + sorted(ordered)
        # Use the header only as the key where line order has meaning across entries.
        if header.startswith("ip name-server "):
            order = "ip name-server"
        elif route := _route_line(header):
            order = "route " + route[0]
            if header.startswith("ipv6 route "):
                header = " ".join(word.lower() if ":" in word else word for word in header.split())
        else:
            order = header
        stanzas.append((order, [header, *children]))
        owned.add(block.line)
        cursor = block.line
        for _ in block.children:
            while not snapshot.source_lines[cursor].strip():
                cursor += 1
            owned.add(cursor + 1)
            cursor += 1

    head, vlan_notes, acl_notes = [], [], []
    configured_acls = {("ipv4", match[2]) for block in snapshot.blocks
                       if (match := ios_acl.V4_HEADER.fullmatch(block.header))}
    configured_acls.update(("ipv6", match[1]) for block in snapshot.blocks
                           if (match := ios_acl.V6_HEADER.fullmatch(block.header)))
    banner = None
    for number, raw in enumerate(snapshot.source_lines, 1):
        if number in owned:
            continue
        line = raw.rstrip()
        if banner is not None:
            head.append(line)
            if banner in line:
                banner = None
        elif match := BANNER.match(line):
            head.append(line)
            if match[1] not in line[match.end():]:
                banner = match[1]
        elif line.startswith(("! netops-vlan ", VLAN_DATABASE)):
            vlan_notes.append(line)
        elif line.startswith((ios_acl.LISTING_MARK, ios_acl.MARK)):
            if not configured_acls:
                continue
            if platform == "iosxe" and line.startswith(ios_acl.MARK):
                # The first configured ACL triggers an operational listing that also includes built-in ACLs.
                # Only configured ACLs are part of the configuration being projected and verified.
                listed = tuple(line[len(ios_acl.MARK):].split(" ", 2)[:2])
                if listed not in configured_acls:
                    continue
            prefix = " ".join(line.split(" ", 5)[:5])
            if prefix in acl_bodies:
                line = f"{prefix} {acl_bodies[prefix]}"
            acl_notes.append(line)
        elif line not in ("", "!", "end"):
            head.append(line)
    acl_notes.sort(key=lambda line: (0, line) if line.startswith(ios_acl.LISTING_MARK)
                   else (1, line[len(ios_acl.MARK):].split(" ", 2)[:2]))
    return "\n".join([*head, *(line for _, stanza in sorted(stanzas, key=lambda item: item[0]) for line in stanza),
                      *sorted(vlan_notes), *acl_notes, "end", ""])


# ---- answers of the device (measured fixtures, ref/mereni-c4c5/fixtures) ----

def cli_error(text: str):
    """A refused line of the interactive session: an IOS error starts with "% " (with a space), for example
    "% Invalid input detected at '^' marker." and the warning "% Access VLAN does not exist. Creating vlan N", which
    IOS performs anyway; "Command Rejected : Et0/1 is already part of channel-group 41, ..." (measured G81, capital
    R) refuses an EtherChannel line. "%No Rollback Confirmed Change pending" (no space) is information. A second revert timer
    is refused with "%Rollback Confirmed Change is already activated on a config"."""
    for line in text.replace("\r", "").split("\n")[1:]:
        stripped = line.strip()
        if stripped.startswith(("Command rejected", "Command Rejected", "Error:", "% ")) or stripped.startswith(ALREADY_ACTIVE) or stripped.startswith("%Archive") \
                or stripped.startswith(("%Rollback", "%Configuration of multiple subinterfaces")):
            return stripped[:100]
    return None


ALREADY_ACTIVE = "%Rollback Confirmed Change is already activated"
NO_PENDING = "%No Rollback Confirmed Change pending"
PRIVILEGE = re.compile(r"^Current privilege level is ([0-9]+)\s*$", re.MULTILINE)
VERSION_LINE = re.compile(r"^Cisco IOS Software(?P<xe> \[IOSXE\])?, (?P<family>[^(,]+?)? ?Software "
                          r"\((?P<image>[^)]+)\), (?:Experimental )?Version (?P<version>[^ ,]+)", re.MULTILINE)
XE_HEADER = re.compile(r"^[ \t]*Cisco IOS (?:XE Software\b|Software, IOS[ -]XE\b)", re.MULTILINE | re.IGNORECASE)
C9800_VERSION_LINE = re.compile(
    r"^Cisco IOS Software[^\n]*\b(?:C9800|CW9800)[-\w]* Software "
    r"\((?P<image>[^)]+)\), Version (?P<version>[^ ,\r\n]+)", re.MULTILINE | re.IGNORECASE,
)
# images measured as Layer 2 switches; every other measured image is a router (no switchport, no VLAN database)
SWITCH_IMAGES = ("vios_l2-", "X86_64BI_LINUX_L2-")
CLOCK = re.compile(r"^[*.]?([0-9]{1,2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)? (\S+) \S+ (\S+) ([0-9]{1,2}) ([0-9]{4})\s*$",
                   re.MULTILINE)
TIMER = {
    "configured": re.compile(r"^Time configured\(or reconfigured\): ([0-9:]+ \S+ \S+ \S+ [0-9]+ [0-9]{4})\s*$",
                             re.MULTILINE),
    "type": re.compile(r"^Timer type: (.+?)\s*$", re.MULTILINE),
    "minutes": re.compile(r"^Timer value: ([0-9]+) min\s*$", re.MULTILINE),
    "user": re.compile(r"^User: (\S+)\s*$", re.MULTILINE),
}
ARCHIVE_MAXIMUM = re.compile(r"^The maximum archive configurations allowed is ([0-9]+)\.\s*$", re.MULTILINE)
ARCHIVE_NEXT = re.compile(r"^The next archive file will be named (\S+?)<timestamp>-[0-9]+\s*$", re.MULTILINE)
ARCHIVE_RECENT = re.compile(r"^\s*[0-9]+\s+(\S+) <- Most Recent\s*$", re.MULTILINE)
ACCESS_VLAN = re.compile(r"^Access Mode VLAN:\s*([0-9]+)\b", re.MULTILINE)
ADMIN_MODE = re.compile(r"^Administrative Mode:\s*(.+?)\s*$", re.MULTILINE)
OPERATIONAL_MODE = re.compile(r"^Operational Mode:([^\r\n]*)", re.MULTILINE)
SWITCHPORT_NAME = re.compile(r"^Name:\s*(\S+)\s*$", re.MULTILINE)
SWITCHPORT_STATE = re.compile(r"^Switchport:\s*(\S+)\s*$", re.MULTILINE)
VLAN_MISSING = re.compile(r"^VLAN id ([0-9]+) not found in current VLAN database\s*$", re.MULTILINE)
MAC_ROW = re.compile(r"^\s*([0-9]+)\s+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\s+\S+\s+(\S+)", re.MULTILINE)
TCP_ROW = re.compile(r"^\S+\s+([0-9.]+)\.22\s+\S+\s+ESTAB\s*$", re.MULTILINE)
SHORT_NAMES = (("TenGigabitEthernet", "Te"), ("TwentyFiveGigE", "Twe"), ("FortyGigabitEthernet", "Fo"),
               ("HundredGigE", "Hu"), ("TwoGigabitEthernet", "Tw"), ("FiveGigabitEthernet", "Fi"),
               ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("Ethernet", "Et"), ("Port-channel", "Po"),
               ("Vlan", "Vl"), ("Loopback", "Lo"), ("Serial", "Se"))
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def refused(text: str) -> bool:
    """An SSH exec answer of a refused command (exit status 0) or an error line of IOS."""
    return any(line.strip().startswith((EXEC_REFUSED, "% Invalid input", "% Incomplete command",
                                        "% Ambiguous command"))
               for line in text.replace("\r", "").split("\n"))


def short_name(key: str) -> str:
    """The abbreviation IOS prints in tables: Gi0/2 for GigabitEthernet0/2, Et0/1 for Ethernet0/1."""
    for long, short in SHORT_NAMES:
        if key.startswith(long):
            return short + key[len(long):]
    return key


def cdp_name(key: str) -> str:
    """The form of show cdp neighbors: the first three letters of the type and the number (Gig 0/0, Eth 0/1)."""
    match = re.fullmatch(r"([A-Za-z-]+)([0-9].*)", key)
    return key if match is None else match.group(1)[:3] + match.group(2)


def unreadable(what: str):
    return Rejected(["the %s is not recognised" % what], reason_codes=["port_usage_unreadable"])


def privilege(text: str) -> int:
    match = PRIVILEGE.search(text)
    if match is None:
        raise Rejected(["the privilege level of the account is not readable"])
    return int(match.group(1))


def version(text: str) -> dict:
    controller = C9800_VERSION_LINE.search(text)
    if controller:
        return {"xe": True, "image": controller["image"], "version": controller["version"], "switch": False}
    match = VERSION_LINE.search(text)
    if match is None:
        raise Rejected(["the device does not report its IOS software version"])
    # Older XE releases name the OS separately from the IOSd version and image.
    return {"xe": match.group("xe") is not None or XE_HEADER.search(text) is not None,
            "image": match.group("image"), "version": match.group("version"),
            "switch": match.group("image").startswith(SWITCH_IMAGES)}


def archive(text: str) -> dict:
    """Archive settings of show archive: the maximum, the path prefix and the most recent archive (or None)."""
    maximum, path = ARCHIVE_MAXIMUM.search(text), ARCHIVE_NEXT.search(text)
    if maximum is None or path is None:
        raise Rejected(["the configuration archive is not configured (show archive); the revert timer needs it: "
                        "archive / path flash:netops-archive (IOS XE on IOL: unix:netops-archive) / maximum 14"],
                       reason_codes=["archive_not_configured"])
    recent = ARCHIVE_RECENT.search(text)
    return {"maximum": int(maximum.group(1)), "path": path.group(1),
            "recent": None if recent is None else recent.group(1)}


def unsaved(text: str) -> list:
    """Lines of show archive config differences nvram:startup-config system:running-config that differ.

    The self-signed certificate of IOS XE (crypto pki certificate chain TP-self-signed-...) differs permanently
    between the startup and the running configuration (measured on IOL XE 17.18.2) and is not an unsaved change."""
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n") if line.strip()]
    if not lines or lines[0].strip() != "!Contextual Config Diffs:":
        raise Rejected(["the difference of the startup and the running configuration is not readable"])
    found, certificate = [], False
    for line in lines[1:]:
        if line.strip() == "!No changes were found":
            continue
        if not line.startswith(" "):
            certificate = line.startswith("crypto pki certificate chain TP-self-signed-")
            if not certificate:
                found.append(line)
            continue
        if not certificate:
            found.append(line)
    return found


def table_rows(text: str, first_column: str) -> tuple:
    """Header column positions and the rows of a fixed-width IOS table whose header starts with first_column."""
    lines = text.replace("\r", "").split("\n")
    for index, line in enumerate(lines):
        if line.lstrip().startswith(first_column + " "):
            columns = [(match.group(0), match.start()) for match in re.finditer(r"\S+(?: \S+)?", line)]
            rows = [row for row in lines[index + 1:] if row.strip() and not set(row.strip()) <= {"-", " "}]
            return columns, rows
    return None, None


def description_row(text: str, key: str, *, include_protocol=False, require_table=False):
    """Status and description of show interfaces description (Interface, Status, Protocol, Description); the
    columns are taken by the header positions, because the status "admin down" holds a space."""
    lines = text.splitlines()
    header = next((line for line in lines if line.startswith("Interface ")), None)
    if header is None or header.split() != ["Interface", "Status", "Protocol", "Description"]:
        if require_table:
            raise unreadable("interface description table")
        return None
    status, protocol, start = header.index("Status"), header.index("Protocol"), header.index("Description")
    rows = [line for line in lines[lines.index(header) + 1:] if line.strip()]
    if require_table and (not rows or refused(text) or any(
            len(row[:status].split()) != 1 or not row[status:protocol].strip()
            or len(row[protocol:start].split()) != 1 or "--More--" in row for row in rows)):
        raise unreadable("interface description table")
    for row in rows:
        if row.split()[:1] == [short_name(key)]:
            found = {"status": row[status:protocol].strip(), "description": row[start:].strip()}
            if include_protocol:
                found["protocol"] = row[protocol:start].strip()
            return found
    return None


def lldp_ports(text: str, *, require_complete=False) -> set:
    """Local ports with an LLDP neighbor in show lldp neighbors; the Device ID column is cut to 20 characters and
    may run into the Local Intf column, so the columns are taken by the header positions."""
    stripped = text.strip()
    if stripped.startswith("% LLDP is not enabled"):
        return set()
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.startswith("Device ID") and "Local Intf" in line), None)
    if header is None or "Total entries displayed:" not in text:
        raise unreadable("LLDP neighbor list")
    start, end = header.index("Local Intf"), header.index("Hold-time")
    found = []
    for line in lines[lines.index(header) + 1:]:
        if not line.strip() or line.startswith("Total entries displayed"):
            continue
        local = line[start:end].strip()
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", local):
            raise unreadable("LLDP neighbor list")
        found.append(local)
    if require_complete and re.findall(r"^Total entries displayed:\s*([0-9]+)[ \t]*$", text.replace("\r", ""), re.M) != [str(len(found))]:
        raise unreadable("LLDP neighbor list")
    return set(found)


def cdp_ports(text: str, *, require_complete=False) -> set:
    """Local ports with a CDP neighbor (Gig 0/0, Eth 0/1); a long Device ID stands on its own line."""
    stripped = text.strip()
    if stripped.startswith("% CDP is not enabled"):
        return set()
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.startswith("Device ID") and "Local Intrfce" in line), None)
    if header is None or "Total cdp entries displayed" not in text:
        raise unreadable("CDP neighbor list")
    start, end = header.index("Local Intrfce"), header.index("Holdtme")
    found = []
    for line in lines[lines.index(header) + 1:]:
        if not line.strip() or line.startswith("Total cdp entries"):
            continue
        if len(line.split()) == 1 and not line.startswith(" "):
            continue  # a long Device ID on its own line; its columns follow on the next line
        if len(line.rstrip()) <= start or not line[start:end].strip():
            if require_complete:
                raise unreadable("CDP neighbor list")
            continue
        local = line[start:end].strip().replace(" ", "")
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", local):
            raise unreadable("CDP neighbor list")
        found.append(local)
    if require_complete and re.findall(r"^Total cdp entries displayed\s*:\s*([0-9]+)[ \t]*$", text.replace("\r", ""), re.M) != [str(len(found))]:
        raise unreadable("CDP neighbor list")
    return set(found)


def learned_macs(text: str, key: str, *, require_complete=False) -> int:
    """Unicast MAC addresses of the port in show mac address-table interface N (rows with a VLAN number)."""
    header = re.search(r"Vlan\s+Mac Address\s+Type\s+Ports", text)
    if "Mac Address Table" not in text or header is None:
        raise unreadable("MAC address table")
    if require_complete:
        rows, totals = [], []
        for line in text[header.end():].splitlines():
            if not line.strip() or re.fullmatch(r"[- \t]+", line):
                continue
            if total := re.fullmatch(r"Total Mac Addresses for this criterion:\s*([0-9]+)", line.strip(), re.I):
                totals.append(int(total[1]))
            elif not totals and (row := MAC_ROW.fullmatch(line.rstrip())):
                rows.append(row)
            else:
                raise unreadable("MAC address table")
        if totals and totals != [len(rows)]:
            raise unreadable("MAC address table")
        return sum(row[2] == short_name(key) for row in rows)
    return sum(1 for _vlan, port in MAC_ROW.findall(text) if port == short_name(key))


def vlan_macs(text: str, vid: str) -> int:
    """Unicast MAC addresses of the VLAN in show mac address-table vlan N (1.0.12 G62: an SVI in use)."""
    if "Mac Address Table" not in text or not re.search(r"Vlan\s+Mac Address\s+Type\s+Ports", text):
        raise unreadable("MAC address table")
    return sum(1 for vlan, _port in MAC_ROW.findall(text) if vlan == vid)


def switchport(text: str, key: str, *, allow_unassigned=False):
    """Mode and access VLAN of show interfaces N switchport; None when the device answers that it has none."""
    if refused(text):
        return None
    name, vlan, mode = SWITCHPORT_NAME.search(text), ACCESS_VLAN.search(text), ADMIN_MODE.search(text)
    state = SWITCHPORT_STATE.search(text)
    if name is None or state is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    if name.group(1) != short_name(key):
        raise Rejected(["the switchport answer names another interface"])
    if state.group(1) != "Enabled":
        return {"mode": "routed", "access-vlan": None}
    unassigned = allow_unassigned and "Access Mode VLAN: unassigned" in text.splitlines()
    if (vlan is None and not unassigned) or mode is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    return {"mode": mode.group(1), "access-vlan": vlan.group(1) if vlan else None}


def switchport_operational_mode(text: str, key: str, *, xe: bool) -> str:
    """Read the active mode separately from the configured mode used in membership readback."""
    modes = OPERATIONAL_MODE.findall(text)
    mode = modes[0].strip() if len(modes) == 1 else ""
    if not mode or (xe and mode not in ("static access", "trunk", "down")):
        raise unreadable("operational switchport mode of " + key)
    return mode


def vlan_exists(text: str, vlan: str) -> bool:
    missing = VLAN_MISSING.search(text)
    if missing is not None:
        if missing.group(1) != vlan:
            raise Rejected(["the VLAN answer names another VLAN"])
        return False
    for line in text.split("\n"):
        words = line.split()
        if words[:1] == [vlan] and len(words) >= 3 and words[2] == "active":
            return True
    raise Rejected(["the answer about VLAN %s is not recognised" % vlan])


def ip_interfaces(text: str) -> dict:
    """IPv4 address -> interface of show ip interface brief (also an address learned by DHCP)."""
    columns, rows = table_rows(text, "Interface")
    if columns is None or not columns[1][0].startswith("IP-Address"):
        raise unreadable("interface address list")
    found = {}
    for row in rows:
        words = row.split()
        if len(words) >= 2 and re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", words[1]):
            found[words[1]] = words[0]
    return found


def session_addresses(text: str) -> set:
    """Local IPv4 addresses of the established SSH connections in show tcp brief (the management addresses)."""
    if "Local Address" not in text or "Foreign Address" not in text:
        raise unreadable("TCP connection list")
    return set(TCP_ROW.findall(text.replace("\r", "")))


def users(text: str) -> tuple:
    """Own and other sessions of show users: rows that name a line (vty, con, aux), the own one marked '*'.

    The idle console of IOL (con 0 without a user) is not a session of someone else."""
    if "Line" not in text or "User" not in text:
        raise Rejected(["the session list is not readable"])
    rows = [line for line in text.replace("\r", "").split("\n")
            if re.match(r"^[ *]\s*[0-9]+ (?:vty|con|aux|tty) [0-9]+", line)]
    own = sum(1 for row in rows if row.startswith("*"))
    other = sum(1 for row in rows if not row.startswith("*")
                and not re.match(r"^\s+[0-9]+ con [0-9]+\s{2,}idle", row))
    return own, other


ARCHIVE_EVENT = re.compile(r"%ARCHIVE_DIFF-5-ROLLBK_CNFMD_CHG_([A-Z_]+): (.*)$")


def archive_events(text: str) -> list:
    """(event, text) of the ARCHIVE_DIFF log lines in the order of the log (oldest first)."""
    found = []
    for line in text.replace("\r", "").split("\n"):
        match = ARCHIVE_EVENT.search(line)
        if match is not None:
            found.append((match.group(1), match.group(2)))
    return found


def archive_outcome(events: list, archive_name: str, user: str):
    """What the log says about the revert timer of archive_name after its start: "fired" (rollback to it),
    "confirmed" (by the user), or None (another event, no event, or the lines are out of the log buffer)."""
    started = None
    for index, (event, text) in enumerate(events):
        if event == "START_ABSTIMER" and ("rollback to config %s in " % archive_name) in text:
            started = index
    if started is None:
        return None
    for event, text in events[started + 1:]:
        if event == "ROLLBACK_START":
            return "fired" if text.strip() == "Start rolling to: %s" % archive_name else None
        if event == "CONFIRM":
            return "confirmed" if text.startswith("User: %s:" % user) else None
        if event in ("BACKUP", "START_ABSTIMER"):
            return None
    return None

# G78: the database is a separate CLI source; normal-range VLANs are absent from show running-config.
VLAN_DATABASE = "! netops-vlan-database"

def vlan_numbers(value):
    if isinstance(value, set):
        return set(value)
    if str(value).lower() == "all":
        return set(range(1, 4095))
    if str(value).lower() == "none":
        return set()
    found = set()
    for part in str(value).split(","):
        if not re.fullmatch(r"[0-9]{1,4}(?:-[0-9]{1,4})?", part):
            raise Rejected(["allowed-vlans must be all, none or comma separated VLAN numbers/ranges"])
        ends = [int(word) for word in part.split("-")]
        lo, hi = ends[0], ends[-1]
        if not 1 <= lo <= hi <= 4094:
            raise Rejected(["VLAN ranges must lie in 1..4094"])
        found.update(range(lo, hi + 1))
    return found


def vlan_text(numbers):
    numbers = sorted(numbers)
    if not numbers:
        return "none"
    if numbers == list(range(1, 4095)):
        return "all"
    groups, start, last = [], numbers[0], numbers[0]
    for value in numbers[1:] + [None]:
        if value is not None and value == last + 1:
            last = value
            continue
        groups.append(str(start) if start == last else "%d-%d" % (start, last))
        start = last = value
    return ",".join(groups)


def vlan_database(text):
    """Strict show vlan brief table; no fabricated VLAN configuration or inferred device syntax."""
    lines = text.replace("\r", "").splitlines()
    header = next((n for n, line in enumerate(lines) if line.startswith("VLAN Name") and "Status" in line and "Ports" in line), None)
    if header is None or header + 1 >= len(lines) or not lines[header + 1].startswith("----"):
        raise unreadable("VLAN database")
    found = {}
    for line in lines[header + 2:]:
        if not line.strip() or line.startswith(" "):
            continue
        match = re.fullmatch(r"([0-9]+)\s+(\S+)\s+(active|act/unsup|suspended|suspend|shutdown)(?:\s+.*)?", line)
        if match is None or match[1] in found:
            raise unreadable("VLAN database")
        found[match[1]] = (match[2], match[3])
    if not {"1", "1002", "1003", "1004", "1005"} <= set(found):
        raise unreadable("incomplete VLAN database")
    return found


def with_vlan_database(config, listing):
    """Append marked, normalized source metadata as comments before end; the auditor ignores comments."""
    found = vlan_database(listing)
    if config.rstrip().splitlines()[-1] != "end":
        raise unreadable("running configuration")
    return config.rstrip()[:-3] + VLAN_DATABASE + "\n" + "\n".join(
        "! netops-vlan %s %s %s" % (vid, *found[vid]) for vid in sorted(found, key=int)) + "\nend\n"


def switchport_membership(text, key, *, allow_unassigned=False):
    shown = switchport(text, key, allow_unassigned=allow_unassigned)
    if shown is None or shown["mode"] == "routed":
        return None
    fields = {}
    for label, attr in (("Trunking Native Mode VLAN", "native-vlan"), ("Voice VLAN", "voice-vlan"),
                        ("Trunking VLANs Enabled", "allowed-vlans"),
                        ("Administrative Trunking Encapsulation", "trunk-encapsulation")):
        matches = re.findall(r"^" + label + r": (\S+)(?:[^\n]*)$", text.replace("\r", ""), re.MULTILINE)
        if len(matches) != 1:
            raise unreadable("incomplete switchport membership")
        fields[attr] = matches[0]
    modes = {"static access": "access", "trunk": "trunk", "dynamic auto": "dynamic auto", "dynamic desirable": "dynamic desirable"}
    if shown["mode"] not in modes:
        raise unreadable("unsupported switchport mode")
    fields.update({"mode": modes[shown["mode"]], "access-vlan": shown["access-vlan"]})
    fields["allowed-vlans"] = vlan_text(vlan_numbers(fields["allowed-vlans"]))
    return fields


# ---- 1.0.12 G61: link state and PoE state of one port (show interfaces N status, show power inline N) ----
PORT_STATUS = ("connected", "notconnect", "disabled", "err-disabled", "inactive", "monitoring", "suspended", "faulty",
               "routed", "sfp-config-mismatch", "xcvr-invalid")


def status_row(text: str, key: str):
    """The Status column of show interfaces N status (Port, Name, Status, Vlan, Duplex, Speed, Type) of the port, taken
    by the header positions because the Name column is empty or holds blanks; a refused or unrecognised answer is
    unreadable, a table without the port is None."""
    if refused(text):
        raise unreadable("link status of " + key)
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.startswith("Port ") and "Status" in line and "Vlan" in line), None)
    if header is None:
        raise unreadable("link status of " + key)
    start, end = header.index("Status"), header.index("Vlan")
    for line in lines[lines.index(header) + 1:]:
        if line.split()[:1] == [short_name(key)]:
            status = line[start:end].strip()
            if status not in PORT_STATUS:
                raise unreadable("link status of " + key)
            return status
    return None


def poe_row(text: str, key: str):
    """The row of port N in show power inline N: Admin (auto, off, static), Oper (on, off, faulty, power-deny, ...) and
    Max in milliwatts. None: the answer lists no row of the port (a port without PoE). A refused answer ('Invalid input',
    'Line has invalid autocommand') is None too: the caller turns it into poe_not_capable. Anything else that is not the
    table is unreadable."""
    if refused(text) or text.lstrip().startswith("% "):
        return None
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.split()[:3] == ["Interface", "Admin", "Oper"]), None)
    if header is None:
        raise unreadable("PoE state of " + key)
    for line in lines[lines.index(header) + 1:]:
        words = line.split()
        if words[:1] == [short_name(key)]:
            if len(words) < 4 or words[1] not in ("auto", "off", "static") or not words[2] or not re.fullmatch(
                    r"[0-9]+(?:\.[0-9]+)?", words[-1]):
                raise unreadable("PoE state of " + key)
            return {"admin": words[1], "oper": words[2], "max-milliwatts": str(round(float(words[-1]) * 1000))}
    return None


# ---- 1.0.12 G80: static routes (XE-M026) and L3 interfaces (XE-M027) of IOS XE ----
# 1.0.12 G62 (IOS-M025, IOS-M026): the same tables on IOS, measured on IOSv 15.9(3)M12 (router, d-iosv) and IOSvL2
# 15.2(20200924:215240) (switch, d-iosvl2), task netops-20261118-517, task-evidence/g62. The lines and answers are
# those of IOS XE with three measured differences: the router image has no SVI while the switch image has one (a new
# "interface Vlan<vid>" starts with "shutdown", so an enabled SVI is created with "no shutdown"); the legend of show
# ip static route reads "Codes in []: "; a second subinterface of a port with the same VID is refused with
# "%Configuration of multiple subinterfaces ..." (no space after %) and still created empty.
# Measured on IOL XE 17.18.2 (router, GNS3 d-iolxe, task netops-20261117-454, task-evidence/g80): "ip route [vrf V]
# NET MASK HOP [DISTANCE]" and "ipv6 route [vrf V] PREFIX HOP [DISTANCE]"; entering the same route with another
# distance replaces it, another next hop adds a second route, "no ip route ... HOP" removes that route only. The
# running configuration writes IPv6 addresses in capitals (2001:DB8:80::1/64); Admin compares them in the canonical
# lower-case form. "interface Loopback<n>" and "interface <ethernet>.<n>" with "encapsulation dot1Q <vid>", "vrf
# forwarding", "ip address", "ipv6 address" and "description" are accepted; "interface Vlan<vid>" is refused by the
# router image ("% Invalid input"), so an SVI is not a key of this table.
ROUTE_TABLE = "static-route"
L3_TABLE = "l3-interface"
DHCP_POOL = "dhcp-pool"
DHCP_RESERVATION = "dhcp-reservation"
DHCP_EXCLUSION = "dhcp-exclusion"
DHCP_RELAY = "dhcp-relay"
DHCP_TABLES = (DHCP_POOL, DHCP_RESERVATION, DHCP_EXCLUSION, DHCP_RELAY)
STATE_TABLES = (ROUTE_TABLE, L3_TABLE, *DHCP_TABLES)
BATCH_TABLES = frozenset(("interface", "vlan", "vlan-membership", "inline-power", "etherchannel-member",
                          *STATE_TABLES, *ios_acl.TABLES, *ios_services.TABLES))
VRF_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
# 1.0.12 G62: an SVI (interface Vlan<vid>) is a key of the IOS profile only (the IOS XE profile key_pattern refuses it)
SVI = re.compile(r"^Vlan([0-9]{1,4})$")
L3_KEY = re.compile(r"^(?:Loopback[0-9]{1,10}|Vlan[0-9]{1,4}|%s\.[0-9]{1,10})$" % ETHERNET.pattern[1:-1])
SUBINTERFACE = re.compile(r"^(%s)\.[0-9]{1,10}$" % ETHERNET.pattern[1:-1])
PEER_ROW = re.compile(r"^\S+[ \t]+([0-9.]+)\.22[ \t]+([0-9.]+)\.[0-9]+[ \t]+ESTAB[ \t]*$", re.MULTILINE)
L3_ORDER = ("description", "admin-state", "ipv4-address", "ipv6-address")


def batch_interface(table, key):
    if table in ("interface", "vlan-membership", POE_TABLE, L3_TABLE, MEMBER_TABLE):
        return key
    if table == ios_acl.BINDING:
        return key.rsplit(":", 2)[0]
    if table == DHCP_RELAY:
        return dhcp_interface(key)
    if table == "vlan":
        return "Vlan" + key
    return None


def batch_scope(request, protected):
    if request.table not in BATCH_TABLES:
        raise Rejected(["the IOS profile cannot be included in a reversible batch"], reason_codes=["action_unsupported"])
    interface = batch_interface(request.table, request.key)
    if interface is not None:
        guarded = {name.casefold() for name in (protected or {}).get("interface", ())}
        if {interface.casefold(), interface.split(".", 1)[0].casefold()} & guarded:
            raise Rejected(["interface %r is protected" % interface], reason_codes=["port_protected"])


def route_key(key: str) -> tuple:
    """(VRF or None, network) of a static-route key: [vrf:<name>:]<network>/<length> in the canonical form."""
    vrf, text = None, key
    if key.startswith("vrf:"):
        parts = key.split(":", 2)
        if len(parts) != 3 or not VRF_NAME.fullmatch(parts[1]):
            raise Rejected(["route key %r must be [vrf:<name>:]<network>/<length>" % key])
        vrf, text = parts[1], parts[2]
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise Rejected(["route key %r must be [vrf:<name>:]<network>/<length> without host bits" % key]) from None
    if route_name(vrf, network) != key:
        raise Rejected(["route key must be written as %s" % route_name(vrf, network)])
    return vrf, network


def route_name(vrf, network) -> str:
    return ("vrf:%s:" % vrf if vrf else "") + str(network)


def canonical_address(name: str, value) -> str:
    """The canonical value of next-hop (an address), ipv4-address ("A M") and ipv6-address ("addr/len", lower case)."""
    if not isinstance(value, str):
        raise Rejected(["attribute %s must be a string" % name])
    text = value.strip()
    try:
        if name == "next-hop":
            address = ipaddress.ip_address(text)
            if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_loopback:
                raise ValueError(text)
            return str(address)
        if name == "ipv4-address":
            parts = text.split()
            interface = ipaddress.IPv4Interface(parts[0] if len(parts) == 1 else "%s/%s" % tuple(parts))
            network = interface.network
            if len(parts) > 2 or not 8 <= network.prefixlen <= 32 or interface.ip.is_multicast or (
                    network.prefixlen <= 30 and interface.ip in (network.network_address, network.broadcast_address)):
                raise ValueError(text)
            return "%s %s" % (interface.ip, network.netmask)
        if name == "ipv6-address":
            interface = ipaddress.IPv6Interface(text)
            if interface.ip.is_link_local or interface.ip.is_multicast or interface.ip.is_unspecified \
                    or interface.network.prefixlen == 0:
                raise ValueError(text)
            return str(interface)
    except (ValueError, TypeError):
        raise Rejected(["attribute %s: %r is not a usable %s" % (
            name, value[:64], {"next-hop": "unicast next-hop address", "ipv4-address": "IPv4 host address with its "
                               "mask (/8 to /32)", "ipv6-address": "global IPv6 address with its prefix length"}[name])
                        ]) from None
    raise Rejected(["attribute %s is not an address attribute" % name])


def _route_line(header: str):
    """(key, words after the destination) of a static route line of the running configuration, or None."""
    words = header.split()
    if words[:2] not in (["ip", "route"], ["ipv6", "route"]):
        return None
    rest, vrf = words[2:], None
    if rest[:1] == ["vrf"] and len(rest) >= 2:
        vrf, rest = rest[1], rest[2:]
    try:
        if words[0] == "ip":
            if len(rest) < 3 or not re.fullmatch(r"[0-9.]+", rest[0]):
                return None
            network = ipaddress.IPv4Network("%s/%s" % (rest[0], rest[1]), strict=False)
            options = rest[2:]
        else:
            if len(rest) < 2 or "/" not in rest[0]:
                return None
            network = ipaddress.IPv6Network(rest[0], strict=False)
            options = rest[1:]
    except ValueError:
        return None
    return route_name(vrf, network), options


def static_routes(snapshot) -> dict:
    """static-route entries of the running configuration: next-hop and distance; a route through an interface, with
    a further option (name, tag, permanent, track) or a second next hop of the same destination is outside the
    profile."""
    found = {}
    for block in snapshot.blocks:
        parsed = _route_line(block.header)
        if parsed is None:
            continue
        key, options = parsed
        entry = found.setdefault(key, Entry(key))
        try:
            hop = str(ipaddress.ip_address(options[0]))
        except ValueError:
            entry.unsupported.append("line %d: next hop %s is not an address" % (block.line, options[0]))
            continue
        _once(entry, "next-hop", hop, block)
        rest = options[1:]
        if len(rest) == 1 and rest[0].isdigit():
            entry.attributes["distance"] = str(int(rest[0]))
        elif rest:
            entry.unsupported.append("line %d: route option %s" % (block.line, " ".join(rest)))
    return found


def l3_entry(name: str, block) -> Entry:
    entry = Entry(name)
    for line_number, child in enumerate(block.children, start=block.line + 1):
        # An unrecognised interface command can include authentication material. Report only its location.
        if not child.startswith(INDENT) or child.startswith(INDENT + " "):
            entry.unsupported.append("line %d: unsupported interface command" % line_number)
            continue
        try:
            if SUBINTERFACE.match(name) and child.strip() == "shutdown":
                # the check account sees the state of the parent port on a subinterface (measured: Et0/2.80 shows
                # admin down under a shut Ethernet0/2 without an own shutdown line), so it is outside the profile
                raise ValueError
            _l3_line(entry, child[len(INDENT):], block)
        except (ValueError, Rejected):
            entry.unsupported.append("line %d: unsupported interface command" % line_number)
    return entry


def _l3_line(entry, line: str, block) -> None:
    words = line.split()
    if line.startswith("description "):
        _once(entry, "description", line[len("description "):], block)
    elif line == "shutdown":
        _once(entry, "admin-state", "disabled", block)
    elif line in ("no ip address", "no shutdown"):
        # "no shutdown" is never shown by IOS; it appears only in the predicted snapshot of an SVI create (G62)
        return
    elif words[:2] == ["ip", "address"] and len(words) == 4:
        _once(entry, "ipv4-address", canonical_address("ipv4-address", "%s %s" % (words[2], words[3])), block)
    elif words[:2] == ["ipv6", "address"] and len(words) == 3 and "/" in words[2]:
        _once(entry, "ipv6-address", str(ipaddress.IPv6Interface(words[2])), block)
    elif words[:2] == ["encapsulation", "dot1Q"] and len(words) == 3 and words[2].isdigit():
        _once(entry, "encapsulation", words[2], block)
    elif words[:2] == ["vrf", "forwarding"] and len(words) == 3:
        _once(entry, "vrf", words[2], block)
    else:
        raise ValueError


def l3_references(snapshot, key: str) -> list:
    """Lines outside the own interface block that name the interface (a route through it, a routing protocol)."""
    pattern = re.compile(r"(?<![\w./-])%s(?![\w./-])" % re.escape(key))
    found = []
    for block in snapshot.blocks:
        if block.header == "interface " + key:
            continue
        found += [line.strip() for line in [block.header] + block.children if pattern.search(line)]
    return found


def vrf_of(snapshot, name: str):
    for line in snapshot.interface_lines(name):
        match = MANAGEMENT_VRF.match(line)
        if match is not None:
            return match.group(1)
    return None


def vrf_families(snapshot, name: str):
    """The address families of a defined VRF ({4, 6} of vrf definition, {4} of ip vrf) or None when undefined."""
    for block in snapshot.blocks:
        if block.header == "vrf definition " + name:
            children = [child.strip() for child in block.children]
            return {family for family, line in ((4, "address-family ipv4"), (6, "address-family ipv6"))
                    if line in children}
        if block.header == "ip vrf " + name:
            return {4}
    return None


def interface_networks(snapshot, skip=None) -> list:
    """(interface, VRF, network) of every IPv4 and IPv6 address of the running configuration."""
    found = []
    for name, block in snapshot.interfaces.items():
        if name == skip:
            continue
        vrf = vrf_of(snapshot, name)
        for child in block.children:
            words = child.split()
            try:
                if words[:2] == ["ip", "address"] and len(words) >= 4 and re.fullmatch(r"[0-9.]+", words[2]):
                    found.append((name, vrf, ipaddress.IPv4Interface("%s/%s" % (words[2], words[3])).network))
                elif words[:2] == ["ipv6", "address"] and len(words) >= 3 and "/" in words[2]:
                    found.append((name, vrf, ipaddress.IPv6Interface(words[2]).network))
            except ValueError:
                continue
    return found


def _vrf_check(snapshot, vrf, families) -> None:
    if vrf is None:
        return
    if MANAGEMENT_VRF_NAME.search(vrf):
        raise Rejected(["VRF %s is a management VRF; Admin never changes it" % vrf],
                       reason_codes=["port_management_interface"])
    defined = vrf_families(snapshot, vrf)
    if defined is None:
        raise Rejected(["VRF %s is not defined in the running configuration" % vrf])
    missing = sorted(set(families) - defined)
    if missing:
        raise Rejected(["VRF %s has no address-family %s" % (vrf, " ".join("ipv%d" % family for family in missing))])


def route_prechecks(snapshot, key: str, after) -> list:
    vrf, network = route_key(key)
    if network.prefixlen == 0:
        raise Rejected(["Admin never changes a default route; it carries the management path"],
                       reason_codes=["port_management_interface"])
    _vrf_check(snapshot, vrf, {network.version})
    if after is not None:
        hop = ipaddress.ip_address(after["next-hop"])
        if hop.version != network.version:
            raise Rejected(["next-hop %s is not an IPv%d address" % (after["next-hop"], network.version)])
        if hop in network:
            raise Rejected(["next-hop %s lies in the destination %s" % (after["next-hop"], network)])
        if network.version == 6 and int(after.get("distance", "1")) > 254:
            raise Rejected(["the distance of an IPv6 route lies in 1..254"])
    return []


def l3_prechecks(snapshot, op: str, key: str, after) -> list:
    if interface_kind(snapshot, key) == "management":
        raise Rejected(["interface %s is in a management VRF; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    parent = SUBINTERFACE.match(key)
    if parent is not None and parent.group(1) not in snapshot.interfaces:
        raise Rejected(["the parent interface %s is not in the running configuration" % parent.group(1)])
    if after is None:
        return []
    if parent is not None and "encapsulation" not in after:
        raise Rejected(["a subinterface needs encapsulation (the 802.1Q VLAN) when it is created"])
    if parent is not None and "admin-state" in after:
        raise Rejected(["the admin state of a subinterface follows its parent port %s; change the parent with the "
                        "interface table" % parent.group(1)])
    if parent is None and "encapsulation" in after:
        raise Rejected(["encapsulation applies to a subinterface only"])
    if parent is not None and op == "create":
        # measured G62 (IOSv 15.9): IOS refuses a second subinterface of the port with the same VID
        # ("%Configuration of multiple subinterfaces ... is not permitted") and still creates the empty subinterface
        encapsulation = ["encapsulation", "dot1Q", after["encapsulation"]]
        for name in snapshot.interfaces:
            if name != key and name.startswith(parent.group(1) + ".") and any(
                    line.split()[:3] == encapsulation for line in snapshot.interface_lines(name)):
                raise Rejected(["VLAN %s is already the 802.1Q VLAN of subinterface %s of the same port"
                                % (after["encapsulation"], name)])
    vrf = after.get("vrf")
    # the VRF needs the address families of the configured addresses (an IPv6-only interface lives in a VRF with
    # only address-family ipv6, measured 454-r2); without an address it needs at least one family
    families = {family for family, name in ((4, "ipv4-address"), (6, "ipv6-address")) if name in after}
    _vrf_check(snapshot, vrf, families)
    if vrf is not None and not families and not vrf_families(snapshot, vrf):
        raise Rejected(["VRF %s has no address-family" % vrf])
    own = []
    if "ipv4-address" in after:
        own.append(ipaddress.IPv4Interface("/".join(after["ipv4-address"].split())).network)
    if "ipv6-address" in after:
        own.append(ipaddress.IPv6Interface(after["ipv6-address"]).network)
    for name, other_vrf, network in interface_networks(snapshot, skip=key):
        if other_vrf == vrf and any(mine.version == network.version and mine.overlaps(network) for mine in own):
            raise Rejected(["the address of %s overlaps %s of interface %s" % (key, network, name)])
    return []


def render_state(table: str, key: str, before, after) -> list:
    """The lines that turn the state before into the state after (both whole states; None = absent)."""
    if table in DHCP_TABLES:
        return render_dhcp(table, key, before, after)
    if table == ROUTE_TABLE:
        vrf, network = route_key(key)
        words = ["ip" if network.version == 4 else "ipv6", "route"] + (["vrf", vrf] if vrf else [])
        words += [str(network.network_address), str(network.netmask)] if network.version == 4 else [str(network)]
        prefix = " ".join(words)
        lines = []
        if after is not None:
            # the same next hop with another distance replaces the route; a new next hop is added before the old
            # one is removed, so the destination stays reachable
            lines.append(" ".join([prefix, after["next-hop"]] + ([after["distance"]] if "distance" in after else [])))
        if before is not None and (after is None or before["next-hop"] != after["next-hop"]):
            lines.append("no %s %s" % (prefix, before["next-hop"]))
        return ["configure terminal"] + lines + ["end"]
    if after is None:
        return ["configure terminal", "no interface " + key, "end"]
    was, body = before or {}, []
    if before is None:
        if "vrf" in after:
            body.append("vrf forwarding " + after["vrf"])
        if "encapsulation" in after:
            body.append("encapsulation dot1Q %s" % after["encapsulation"])
        if SVI.match(key) and after.get("admin-state") != "disabled":
            # measured G62 (IOSvL2 15.2): a new SVI starts with shutdown; the default state is enabled
            body.append("no shutdown")
    for name in L3_ORDER:
        if after.get(name) == was.get(name):
            continue
        if name in ("description", "admin-state"):
            body.append(_line(name, after.get(name)))
        elif name == "ipv4-address":
            body.append("ip address " + after[name] if name in after else "no ip address")
        else:
            if name in was:
                body.append("no ipv6 address " + was[name])
            if name in after:
                body.append("ipv6 address " + after[name])
    return ["configure terminal", "interface " + key] + body + ["end"]


def _state_own(table: str, key: str, header: str) -> bool:
    if table == L3_TABLE:
        return header == "interface " + key
    parsed = _route_line(header)
    return parsed is not None and parsed[0] == key


def state_rest_digest(snapshot, table: str, key: str) -> str:
    kept, own = [], False
    for line in snapshot.lines:
        if line == "!" or line.startswith(VOLATILE_HEADER):
            continue
        if not line.startswith(" "):
            own = _state_own(table, key, line)
        if not own:
            kept.append(line)
    return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def state_snapshot_after(text: str, plan) -> str:
    key, table, after = plan["key"], plan["table"], plan["predicted"]["after"]
    result, own = [], False
    for line in text.replace("\r", "").split("\n"):
        if line and not line.startswith(" "):
            own = _state_own(table, key, line.rstrip())
        if not own and line.rstrip() != "end":
            result.append(line)
    if after is not None:
        lines = render_state(table, key, None, after)[1:-1]
        if table == L3_TABLE:
            result += [lines[0]] + [INDENT + line for line in lines[1:]] + ["!"]
        else:
            result += lines
    return "\n".join(result).rstrip() + "\nend\n"


# ---- answers of the check account (privilege 1) about G80 objects ----

def _check_refused(text: str, command: str):
    if refused(text):
        raise Rejected(["the check account was refused %s" % command])


def static_route_state(text: str, key: str):
    """The route of show ip static route [vrf V] / show ipv6 static [vrf V]: {next-hop, distance} or None."""
    vrf, network = route_key(key)
    lines = text.replace("\r", "").split("\n")
    if network.version == 4:
        if not any(line.startswith("Static local RIB for %s" % (vrf or "default")) for line in lines):
            # measured: a table without static routes answers only the code legend, without the RIB line; the
            # legend names the bracket codes "Codes in (): " on IOS XE 17.18 and "Codes in []: " on IOS 15 (G62)
            if any(line.startswith(("Codes in (): ", "Codes in []: ")) for line in lines) and not any(
                    re.match(r"^\S+\s+\S+/[0-9]+\s+\[", line) for line in lines):
                return None
            raise Rejected(["the static route list (show ip static route) is not recognised"])
        rows, current = [], None
        for line in lines:
            match = re.match(r"^\S+\s+(?:(\S+/[0-9]+)\s+)?\[([0-9]+)/[0-9]+\] via (\S+)", line)
            if match is None:
                continue
            current = match.group(1) or current
            if current == str(network):
                rows.append((match.group(3), match.group(2)))
    else:
        if not any(line.strip() == "IPv6 Static routes Table - %s" % (vrf or "default") for line in lines):
            raise Rejected(["the static route list (show ipv6 static) is not recognised"])
        rows = []
        for line in lines:
            words = line.replace("*", " ").split()
            if not words or "/" not in words[0]:
                continue
            if str(ipaddress.IPv6Network(words[0], strict=False)) != str(network):
                continue
            match = re.match(r"^\S+ via ([0-9A-Fa-f:]+), distance ([0-9]+)$", " ".join(words))
            if match is None:
                raise Rejected(["the static route %s is not a route through an address" % key])
            rows.append(match.groups())
    if not rows:
        return None
    if len(rows) > 1:
        raise Rejected(["the static route %s has %d next hops" % (key, len(rows))])
    hop, distance = rows[0]
    try:
        hop = str(ipaddress.ip_address(hop))
    except ValueError:
        raise Rejected(["the static route %s is not a route through an address" % key]) from None
    return {"next-hop": hop, "distance": distance}


def ip_interface_state(text: str, key: str) -> dict:
    """ipv4-address and vrf of show ip interface <key>."""
    _check_refused(text, "show ip interface " + key)
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n") if line.strip()]
    if not lines or not lines[0].startswith(key + " is "):
        raise Rejected(["the answer of show ip interface %s is not recognised" % key])
    state = {}
    for line in lines[1:]:
        match = re.match(r"^\s+Internet address is ([0-9.]+/[0-9]+)$", line)
        if match:
            state["ipv4-address"] = canonical_address("ipv4-address", match.group(1))
        elif re.match(r"^\s+Secondary address ", line):
            raise Rejected(["interface %s carries a secondary address" % key])
        match = re.match(r'^\s+VPN Routing/Forwarding "([^"]+)"$', line)
        if match:
            state["vrf"] = match.group(1)
    if "ipv4-address" not in state and not any("Internet protocol processing disabled" in line for line in lines):
        raise Rejected(["show ip interface %s names no address" % key])
    return state


def ipv6_interface_state(text: str, key: str) -> dict:
    """ipv6-address and vrf of show ipv6 interface <key> (an empty answer: no IPv6 on the interface).

    The VRF is read here as well: show ip interface names none when IPv4 is disabled (measured 454-r2)."""
    _check_refused(text, "show ipv6 interface " + key)
    if not text.strip():
        return {}
    lines = text.replace("\r", "").split("\n")
    if not lines[[line.strip() != "" for line in lines].index(True)].startswith(key + " is "):
        raise Rejected(["the answer of show ipv6 interface %s is not recognised" % key])
    found = re.findall(r"^\s+([0-9A-Fa-f:]+), subnet is [0-9A-Fa-f:]+/([0-9]+)", text, re.MULTILINE)
    if len(found) > 1:
        raise Rejected(["interface %s carries %d global IPv6 addresses" % (key, len(found))])
    state = {"ipv6-address": str(ipaddress.IPv6Interface("%s/%s" % found[0]))} if found else {}
    vrf = re.search(r'^\s+VPN Routing/Forwarding "([^"]+)"$', text.replace("\r", ""), re.MULTILINE)
    if vrf:
        state["vrf"] = vrf.group(1)
    return state


def encapsulation_state(text: str, key: str) -> dict:
    _check_refused(text, "show interfaces " + key)
    match = re.search(r"Encapsulation 802\.1Q Virtual LAN, Vlan ID\s+([0-9]+)\.", text)
    if match is None:
        raise Rejected(["show interfaces %s names no 802.1Q VLAN" % key])
    return {"encapsulation": match.group(1)}


def session_pairs(text: str) -> set[tuple[str, str]]:
    """Local and remote IPv4 addresses of established SSH connections in show tcp brief."""
    if "Local Address" not in text or "Foreign Address" not in text:
        raise unreadable("TCP connection list")
    try:
        return {(str(ipaddress.IPv4Address(local)), str(ipaddress.IPv4Address(remote)))
                for local, remote in PEER_ROW.findall(text.replace("\r", ""))}
    except ValueError:
        raise unreadable("TCP connection list") from None


def session_peers(text: str) -> set:
    return {peer for _, peer in session_pairs(text)}


def cef_egress(text: str, peer: str) -> set[str]:
    """Egress interfaces of one resolved IPv4 CEF prefix (including recursive and multipath entries)."""
    lines = text.split()
    try:
        prefix = ipaddress.IPv4Network(lines[0].rstrip(","))
        if ipaddress.IPv4Address(peer) not in prefix or "--More--" in text or "\x08" in text:
            raise ValueError
    except (ValueError, IndexError):
        raise unreadable("CEF route to the SSH peer") from None
    ports = set()
    recursive = False
    for line in text.splitlines():
        row = line.strip()
        if row.startswith("recursive via "):
            if recursive:
                raise unreadable("recursive CEF route to the SSH peer")
            recursive = True
        elif row.startswith(("attached to ", "nexthop ")):
            match = re.fullmatch(r"(?:attached to |nexthop [0-9.]+ )(\S+)", row)
            if match is None:
                raise unreadable("CEF route to the SSH peer")
            ports.add(clear_interface(match[1]))
            recursive = False
    if not ports or recursive:
        raise unreadable("CEF route to the SSH peer")
    return ports


# ---- 1.0.12 G81: EtherChannel/LACP membership of a physical port (XE-M028) ----
# Measured on IOL-L2 XE 17.18.2 (switch, GNS3 d-iolxe-l2, task netops-20261118-499-r2, task-evidence/g81/step2-capture):
# "channel-group N mode active|passive" (N 1-48, "interface port-channel ?" and "channel-group ?" answer <1-48>) on a
# port outside any group creates the missing port-channel ("Creating a port-channel interface Port-channel 41"; the
# running configuration gets an empty "interface Port-channel41" block); the same group with another mode is changed
# in place; another group is refused ("Command Rejected : Et0/1 is already part of channel-group 41, unbundle before
# adding to channel-group 42"), so a move is "no channel-group" (no group number: "no channel-group ?" answers only
# <cr>) and then the new group. "no channel-group" leaves the port-channel interface in place; "no interface
# Port-channelN" removes it together with the membership of every member port. The check account (privilege 1)
# reads "show interfaces <port> etherchannel" ("Etherchannel not enabled on this port" outside any group).
# 1.0.12 G63 (IOS-M027), IOSvL2 15.2(20200924:215240) (switch, GNS3 d-iosvl2, task netops-20261119-569,
# task-evidence/g63): the same lines and the same table serve classic IOS. Differences measured there: "channel-group ?"
# answers <1-255> but "interface port-channel ?" only <1-48> (a larger group is refused by the device with "Command
# rejected (Port-channel49, Gi1/1): Invalid group(slot) number" and nothing changes); a member in another group is moved
# directly (Admin still sends "no channel-group" first); "no channel-group" outside a group is silent; "no channel-group
# N" is "% Incomplete command", so only the bare form is used; the port keeps its own switchport lines (a mode or access
# VLAN mismatch only suspends it); removing a port-channel that still has members adds "shutdown" to each member, so
# Admin removes only a port-channel without members; the check account reads "Port state = Up Mstr Not-in-Bndl" for a
# member without a partner (IOS XE: "Down Not-in-Bndl"), so the bundle state, not the link word, decides.
MEMBER_TABLE = "etherchannel-member"
PORT_CHANNEL = "Port-channel"
CHANNEL_GROUP = re.compile(r"^channel-group ([0-9]+) mode (\S+)$")
LACP_MODES = ("active", "passive")
NOT_MEMBER = "Etherchannel not enabled on this port"


def member_entries(snapshot) -> dict:
    """Physical ports with a channel-group line: channel-group and LACP mode; PAgP or static modes and a
    channel-protocol line are outside the profile."""
    found = {}
    for name, block in snapshot.interfaces.items():
        if not ETHERNET.fullmatch(name):
            continue
        for child in block.children:
            line = child.strip()
            if not line.startswith(("channel-group ", "channel-protocol ")):
                continue
            entry = found.setdefault(name, Entry(name))
            match = CHANNEL_GROUP.match(line)
            if match is None or match.group(2) not in LACP_MODES:
                entry.unsupported.append("line %d: %s" % (block.line, line))
                continue
            _once(entry, "channel-group", match.group(1), block)
            _once(entry, "mode", match.group(2), block)
    return found


def group_members(snapshot, group: str) -> list:
    # Include static and PAgP members too: deleting the interface would detach them as well.
    return sorted(name for name in snapshot.interfaces
                  if any(line.split()[:2] == ["channel-group", str(group)]
                         for line in snapshot.interface_lines(name)))


def member_groups(before, after) -> list:
    return sorted({side["channel-group"] for side in (before, after) if side}, key=int)


MEMBER_ACCESS = re.compile(r"^switchport access vlan ([0-9]+)$")


def member_access_vlan(snapshot, key):
    vlans = [match.group(1) for value in snapshot.interface_lines(key) if (match := MEMBER_ACCESS.fullmatch(value))]
    if len(vlans) > 1:
        raise unreadable("access VLAN of " + key)
    return vlans[0] if vlans else None


def _member_lines(key, old, new, remove=None, vlan=None) -> list:
    body = ["interface " + key]
    if old and new and old["channel-group"] == new["channel-group"]:
        body.append("channel-group %s mode %s" % (new["channel-group"], new["mode"]))
    else:
        if old:
            body.append("no channel-group")
        if vlan is not None:
            body.append(vlan)
        if new:
            body.append("channel-group %s mode %s" % (new["channel-group"], new["mode"]))
        if remove is not None:
            body += ["exit", "no interface " + PORT_CHANNEL + remove]
    return ["configure terminal"] + body + ["end"]


def _access_command(vlan):
    return "no switchport access vlan" if vlan is None else "switchport access vlan " + vlan


def render_member(snapshot, key: str, before, after) -> tuple:
    """Plan the join and its exact inverse, including an explicit access VLAN alignment when needed."""
    source = before["channel-group"] if before else None
    target = after["channel-group"] if after else None
    if source == target:
        return _member_lines(key, before, after), _member_lines(key, after, before)
    # Leaving a group preserves its port-channel. Only the inverse may remove one created by this change.
    created = target if target and PORT_CHANNEL + target not in snapshot.interfaces else None
    set_vlan = restore_vlan = None
    if target and "switchport mode access" in snapshot.interface_lines(PORT_CHANNEL + target):
        old_vlan = member_access_vlan(snapshot, key)
        target_vlan = member_access_vlan(snapshot, PORT_CHANNEL + target)
        # IOL-L2 leaves a mismatched port's access VLAN untouched, so it need not be compatible with the bundle.
        # Align it before joining a configured access group to make the VLAN and its restoration explicit.
        if (old_vlan or DEFAULT_VLAN) != (target_vlan or DEFAULT_VLAN):
            set_vlan, restore_vlan = _access_command(target_vlan), _access_command(old_vlan)
    return (_member_lines(key, before, after, vlan=set_vlan),
            _member_lines(key, after, before, created, restore_vlan))


def member_scope_digest(snapshot, key, before, after) -> str:
    groups = member_groups(before, after)
    scope = [(key, snapshot.interface_lines(key))]
    for group in groups:
        name = PORT_CHANNEL + group
        scope.append((name, name in snapshot.interfaces, snapshot.interface_lines(name),
                      group_members(snapshot, group), l3_references(snapshot, name)))
    return hashlib.sha256(repr(scope).encode("utf-8")).hexdigest()


def member_prechecks(snapshot, key: str, after) -> list:
    kind = interface_kind(snapshot, key)
    if kind == "management":
        raise Rejected(["interface %s is in a management VRF; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only physical Ethernet ports join a port-channel"
                        % key], reason_codes=["port_unsupported_interface"])
    if key not in snapshot.interfaces:
        raise Rejected(absent(snapshot, MEMBER_TABLE, key))
    lines = snapshot.interface_lines(key)
    if any(TRUNK.match(line) for line in lines):
        raise Rejected(["port %s is a trunk or negotiates trunking; it is treated as an uplink and is not changed"
                        % key], reason_codes=["port_uplink"])
    if any(ROUTED.match(line) or line.startswith("ipv6 address ") for line in lines) or snapshot.addressed(key):
        raise Rejected(["port %s is a routed port; only Layer 2 port-channel membership is supported" % key],
                       reason_codes=["port_routed"])
    entry = member_entries(snapshot).get(key)
    before = entry.attributes if entry and not entry.unsupported else None
    for group in member_groups(before, after):
        name = PORT_CHANNEL + group
        if interface_kind(snapshot, name) == "management":
            raise Rejected(["%s is in a management VRF; Admin never changes it" % name],
                           reason_codes=["port_management_interface"])
        if (snapshot.addressed(name) or any(ROUTED.match(line) or line.startswith("ipv6 address ")
                                             for line in snapshot.interface_lines(name))):
            raise Rejected(["%s is a routed (Layer 3) port-channel; only Layer 2 membership is supported" % name],
                           reason_codes=["port_routed"])
        if name not in snapshot.interfaces and group_members(snapshot, group):
            raise unreadable("missing port-channel for group " + group)
    return []


def member_rest_digest(snapshot, key: str) -> str:
    """Hash all configuration except the member's channel-group command, including empty interfaces."""
    kept, own, port_channel = [], False, False
    for line in snapshot.lines:
        if line == "!" or line.startswith(VOLATILE_HEADER):
            continue
        if not line.startswith(INDENT):
            own = line == "interface " + key
            port_channel = re.fullmatch(r"interface Port-channel[0-9]+", line) is not None
        if port_channel or (own and line.strip().startswith("channel-group ")):
            continue
        kept.append(line)
    # IOS can place port-channel blocks by number, independently of their order of creation.
    for name in sorted(snapshot.interfaces):
        if re.fullmatch(r"Port-channel[0-9]+", name):
            kept += ["interface " + name] + snapshot.interfaces[name].children
    return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def member_snapshot_after(text: str, plan) -> str:
    """The running configuration after the planned lines (for the audit prediction)."""
    lines = text.replace("\r", "").split("\n")

    def block(name):
        if "interface " + name not in lines:
            return None
        start = lines.index("interface " + name)
        end = start + 1
        while end < len(lines) and lines[end].startswith(" "):
            end += 1
        return start, end

    current = None
    for command in plan["commands"][1:-1]:
        if command.startswith("interface "):
            current = command[len("interface "):]
        elif command == "exit":
            current = None
        elif command.startswith("no interface "):
            found = block(command[len("no interface "):])
            if found is not None:
                del lines[found[0]:found[1]]
        elif command == "no switchport access vlan" or MEMBER_ACCESS.fullmatch(command):
            start, end = block(current)
            children = lines[start + 1:end]
            index = next((n for n, line in enumerate(children)
                          if line.strip().startswith(("switchport ", "shutdown", "channel-group "))), len(children))
            children = [line for line in children if not MEMBER_ACCESS.fullmatch(line.strip())]
            if command != "no switchport access vlan":
                children.insert(index, INDENT + command)
            lines[start + 1:end] = children
        elif command == "no channel-group" or command.startswith("channel-group "):
            start, end = block(current)
            children = [line for line in lines[start + 1:end] if not line.strip().startswith("channel-group ")]
            if command != "no channel-group":
                children.append(INDENT + command)
            lines[start + 1:end] = children
            if command != "no channel-group":
                po = PORT_CHANNEL + command.split()[1]
                if block(po) is None:
                    first = next(index for index, line in enumerate(lines) if line.startswith("interface "))
                    lines[first:first] = ["interface " + po, "!"]
    return "\n".join(lines)


def etherchannel_port(text: str, key: str):
    """show interfaces <port> etherchannel: None outside any group, else channel-group, mode (lower case), protocol
    and the port state ("Down Not-in-Bndl" measured on a port without a link)."""
    if refused(text):
        raise Rejected(["the device refused show interfaces %s etherchannel" % key],
                       reason_codes=["port_usage_unreadable"])
    if text.strip() == NOT_MEMBER:
        return None
    state = re.search(r"^Port state\s+=\s+(.+?)\s*$", text, re.MULTILINE)
    group = re.search(r"^Channel group = ([0-9]+)\s+Mode = (\S+)", text, re.MULTILINE)
    protocol = re.search(r"Protocol =\s+(\S+)\s*$", text, re.MULTILINE)
    row = re.search(r"^%s\s" % re.escape(short_name(key)), text, re.MULTILINE)
    if state is None or group is None or protocol is None or row is None:
        raise unreadable("EtherChannel answer about %s" % key)
    return {"channel-group": group.group(1), "mode": group.group(2).lower(), "protocol": protocol.group(1),
            "state": state.group(1)}


def member_state(text: str, key: str):
    """The membership the check account reads (show interfaces <port> etherchannel) in the form of the table."""
    found = etherchannel_port(text, key)
    if found is None:
        return None
    if found["protocol"] != "LACP":
        raise Rejected(["port %s is in channel-group %s with protocol %s, not LACP"
                        % (key, found["channel-group"], found["protocol"])])
    return {"channel-group": found["channel-group"], "mode": found["mode"]}


# G65/G83: IOS and IOS XE put dynamic pools and manual reservations in the same named
# configuration mode. Refuse a name in use by the other kind or an empty pool.
DHCP_POOL_LINE = "ip dhcp pool "
DHCP_EXCLUSION_LINE = "ip dhcp excluded-address "
DHCP_RELAY_LINE = "ip helper-address "
DHCP_POOL_ATTRIBUTES = {
    DHCP_POOL: ("network", "default-router", "dns-server"),
    DHCP_RESERVATION: ("host", "hardware-address", "client-identifier"),
}
DHCP_CLIENT_ID = re.compile(r"(?:[0-9a-f]{4}\.)*(?:[0-9a-f]{2}|[0-9a-f]{4})")
DHCP_HARDWARE = re.compile(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})(?: (?:ethernet|ieee802))?")


def dhcp_address(value):
    address = ipaddress.IPv4Address(value)
    if address.is_multicast or address.is_unspecified or int(address) == 0xffffffff:
        raise ValueError("not a unicast IPv4 address")
    return address


def dhcp_value(name, value):
    words = value.split()
    if name == "host":
        address, mask = words
        host = ipaddress.IPv4Interface((address, mask))
        dhcp_address(address)
        if host.network.prefixlen < 31 and host.ip in (host.network.network_address, host.network.broadcast_address):
            raise ValueError("not a host address")
        return "%s %s" % (host.ip, host.netmask)
    if name == "network":
        address, mask = words
        network = ipaddress.IPv4Network((address, mask))
        return "%s %s" % (network.network_address, network.netmask)
    if name in ("default-router", "dns-server"):
        addresses = [dhcp_address(word) for word in words]
        if not 1 <= len(addresses) <= 8:
            raise ValueError("expected one to eight addresses")
        return " ".join(map(str, addresses))
    canonical = " ".join(words).lower()
    if name == "client-identifier" and DHCP_CLIENT_ID.fullmatch(canonical):
        return canonical
    if name == "hardware-address" and DHCP_HARDWARE.fullmatch(canonical):
        dhcp_hardware, *_ = canonical.split()
        digits = int(dhcp_hardware.replace(".", ""), 16)
        if digits and not (digits >> 40) & 1:
            return canonical
    raise ValueError("invalid hardware address or client identifier")


def dhcp_pool_entry(table, key, children):
    entry = Entry(key)
    for child in children:
        name, _, value = child.strip().partition(" ")
        if name not in DHCP_POOL_ATTRIBUTES[table] or not re.fullmatch(r" [^\s].*", child):
            entry.unsupported.append("DHCP pool option outside the profile")
            continue
        try:
            parsed = dhcp_value(name, value)
        except ValueError:
            entry.unsupported.append("invalid " + name)
            continue
        if name in entry.attributes:
            entry.unsupported.append("duplicate " + name)
        entry.attributes[name] = parsed
    fields = entry.attributes
    if table == DHCP_POOL and "network" not in fields:
        entry.unsupported.append("no primary IPv4 network")
    if table == DHCP_RESERVATION and ("host" not in fields or
                                     sum(name in fields for name in ("client-identifier", "hardware-address")) != 1):
        entry.unsupported.append("no complete manual binding with one identifier")
    return entry


def dhcp_exclusion_range(key):
    first, sep, last = key.partition("-")
    start, end = dhcp_address(first), dhcp_address(last if sep else first)
    if sep and start >= end:
        raise ValueError("range must have increasing addresses")
    return start, end


def dhcp_relay_entries(interface, children):
    entries = {}
    for child in children:
        line = child.strip()
        if not line.startswith(DHCP_RELAY_LINE):
            continue
        words = line[len(DHCP_RELAY_LINE):].split()
        index = {"vrf": 2, "global": 1}.get(words[0], 0)
        try:
            address = dhcp_address(words[index])
        except (IndexError, ValueError):
            raise dhcp_unreadable() from None
        key = "%s:%s" % (interface, address)
        if key in entries:
            entries[key].unsupported.append("multiple helpers for the same address")
        entry = entries.setdefault(key, Entry(key))
        if index or len(words) != 1:
            entry.unsupported.append("qualified helper address")
    return entries


def dhcp_relay_active(text, interface, helpers):
    link = re.match(re.escape(interface) + r" is (up|down|administratively down), line protocol is (up|down)\b",
                    text.lstrip())
    lines = [line.strip() for line in text.splitlines()]
    prefix = "Helper address is "
    rows = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if link is None or len(rows) != 1:
        raise dhcp_unreadable()
    row = rows[0]
    if not any(line.startswith("Directed broadcast forwarding is ") for line in lines[row + 1:]):
        raise dhcp_unreadable()
    if len(helpers) <= 1:
        expected = next(iter(helpers)).split(":", 1)[1] if helpers else "not set"
        if lines[row][len(prefix):] != expected:
            raise dhcp_unreadable()
    return link.groups() == ("up", "up")


def dhcp_entries(snapshot, table):
    if table == DHCP_RELAY:
        return {key: entry for name, block in snapshot.interfaces.items()
                for key, entry in dhcp_relay_entries(name, block.children).items()}
    entries = {}
    prefix = DHCP_EXCLUSION_LINE if table == DHCP_EXCLUSION else DHCP_POOL_LINE
    for block in snapshot.blocks:
        if not block.header.startswith(prefix):
            continue
        key = block.header[len(prefix):]
        if table == DHCP_EXCLUSION:
            if key.startswith("vrf "):
                continue
            key = "-".join(key.split())
            try:
                dhcp_exclusion_range(key)
            except ValueError:
                raise dhcp_unreadable() from None
            entry = Entry(key)
        else:
            entry = dhcp_pool_entry(table, key, block.children)
        if key in entries:
            raise dhcp_unreadable()
        entries[key] = entry
    return entries


def dhcp_interface(key):
    return key.split(":", 1)[0]


def dhcp_prechecks(snapshot, table, key, after):
    try:
        if table == DHCP_EXCLUSION:
            dhcp_exclusion_range(key)
        elif table == DHCP_RELAY:
            name, address = key.split(":", 1)
            dhcp_address(address)
            if name not in snapshot.interfaces:
                raise Rejected(["the relay interface does not exist"], reason_codes=["port_unsupported_interface"])
            if snapshot.management_vrf(name):
                raise Rejected(["the relay interface is in a management VRF"],
                               reason_codes=["port_management_interface"])
        elif after is not None:
            for name, value in after.items():
                if dhcp_value(name, value) != value:
                    raise ValueError("field is not in canonical IOS spelling")
            if table == DHCP_RESERVATION:
                if sum(name in after for name in ("client-identifier", "hardware-address")) != 1:
                    raise Rejected(["a reservation needs exactly one of hardware-address and client-identifier"])
                # IOS maintains the manual binding by address and identifier as well as by pool name.
                for block in snapshot.blocks:
                    if (not block.header.startswith(DHCP_POOL_LINE) or block.header == DHCP_POOL_LINE + key
                            or any(line.strip().startswith("vrf ") for line in block.children)):
                        continue
                    other = dhcp_pool_entry(table, block.header, block.children).attributes
                    same_host = other.get("host", "").split()[:1] == after["host"].split()[:1]
                    same_client = any(other.get(name, "").split()[:1] == after[name].split()[:1]
                                      for name in ("hardware-address", "client-identifier") if name in after)
                    if same_host or same_client:
                        raise Rejected(["the host address or identifier is already in another DHCP reservation"])
    except ValueError:
        raise Rejected(["invalid DHCP address, range or option format"]) from None
    return []


def render_dhcp(table, key, before, after):
    if table == DHCP_EXCLUSION:
        line = DHCP_EXCLUSION_LINE + key.replace("-", " ")
        commands = [line if after is not None else "no " + line]
    elif table == DHCP_RELAY:
        interface, address = key.split(":", 1)
        line = DHCP_RELAY_LINE + address
        commands = ["interface " + interface, line if after is not None else "no " + line]
    elif after is None:
        commands = ["no " + DHCP_POOL_LINE + key]
    else:
        old = before or {}
        commands = [DHCP_POOL_LINE + key]
        if table == DHCP_POOL and "network" in old and old["network"] != after["network"]:
            # IOSv refuses an overlapping replacement until the exact old subnet is removed.
            commands.append("no network " + old["network"])
        commands += ["no " + name for name in DHCP_POOL_ATTRIBUTES[table] if name in old and name not in after]
        commands += ["%s %s" % (name, after[name]) for name in DHCP_POOL_ATTRIBUTES[table]
                     if name in after and after[name] != old.get(name)]
    return ["configure terminal", *commands, "end"]


def dhcp_unowned_lines(lines, table, key):
    in_target = False
    heading = "interface " + dhcp_interface(key) if table == DHCP_RELAY else DHCP_POOL_LINE + key
    for line in lines:
        if line and not line.startswith(" "):
            if table == DHCP_EXCLUSION and line == DHCP_EXCLUSION_LINE + key.replace("-", " "):
                continue
            in_target = line == heading
            if in_target and table in DHCP_POOL_ATTRIBUTES:
                continue
        elif in_target:
            if table == DHCP_RELAY and line.strip() == DHCP_RELAY_LINE + key.split(":", 1)[1]:
                continue
            if table in DHCP_POOL_ATTRIBUTES:
                continue
        yield line


def dhcp_snapshot_after(text, plan):
    table, key, after = plan["table"], plan["key"], plan["predicted"]["after"]
    lines = list(dhcp_unowned_lines(text.replace("\r", "").rstrip().splitlines(), table, key))
    if after is not None:
        commands = render_dhcp(table, key, None, after)[1:-1]
        if table == DHCP_RELAY:
            lines.insert(lines.index(commands[0]) + 1, " " + commands[1])
        else:
            new = [commands[0], *(" " + line for line in commands[1:])]
            lines[-1:-1] = new + ["!"]
    return "\n".join(lines) + "\n"


def dhcp_unreadable():
    return Rejected(["IOS DHCP configuration readback was refused, incomplete or unrecognised"],
                    reason_codes=["ios_dhcp_readback_unreadable"])


def dhcp_readback(text, table, key):
    # 'end' is deliberately selected alongside the object. Its absence must
    # never be mistaken for a successfully read, absent object.
    lines = [line.rstrip() for line in text.replace("\r", "").splitlines() if line.strip()]
    if not lines or lines[-1] != "end":
        raise dhcp_unreadable()
    body = lines[:-1]
    if table == DHCP_RELAY:
        interface = dhcp_interface(key)
        if (len(body) < 4 or body[0] != BUILDING or not CURRENT.fullmatch(body[1])
                or body[2:4] != ["!", "interface " + interface]
                or any(not line.startswith(" ") for line in body[4:])):
            raise dhcp_unreadable()
        entry = dhcp_relay_entries(interface, body[4:]).get(key)
    elif not body:
        return None
    elif table == DHCP_EXCLUSION:
        if body != [DHCP_EXCLUSION_LINE + key.replace("-", " ")]:
            raise dhcp_unreadable()
        entry = Entry(key)
    else:
        if body[0] != DHCP_POOL_LINE + key:
            raise dhcp_unreadable()
        entry = dhcp_pool_entry(table, key, body[1:])
    if entry is not None and entry.unsupported:
        raise dhcp_unreadable()
    return None if entry is None else entry.attributes


# ---- 1.0.12 G67/G85: scoped operational clear over privileged EXEC ----
CLEAR_TABLES = ("port-counters", "fdb", "iparp", "neighbor-discovery")
WIRELESS_CLIENT = "wireless-client"
WIRELESS_FIRMWARE = ("17.3.5b",)
CLEAR_FIRMWARE = {
    "port-counters": ("15.9(3)M12", "17.18.2"),
    "fdb": ("15.2(20200924:215240)",),
    "iparp": ("17.18.2",),
    "neighbor-discovery": (),
}
CLEAR_MAC = re.compile(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", re.IGNORECASE)
CLEAR_MAC_INPUT = re.compile(r"(?:[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
                             r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2})", re.IGNORECASE)
CLEAR_INTERFACE = re.compile(r"[A-Za-z][A-Za-z-]*[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?")
CLEAR_COUNTER_NAMES = ("input_packets", "input_bytes", "output_packets", "output_bytes")
CLEAR_FDB_HEAD = re.compile(r"Vlan\s+Mac Address\s+Type\s+Ports")
CLEAR_FDB_TOTAL = re.compile(r"Total Mac Addresses for this criterion: ([0-9]+)")
CLEAR_ARP_HEAD = re.compile(r"Protocol\s+Address\s+Age \(min\)\s+Hardware Addr\s+Type\s+Interface")
CLEAR_ND_HEAD = re.compile(r"IPv6 Address\s+Age\s+Link-layer Addr\s+State\s+Interface")
WIRELESS_CLIENT_SUMMARY = "show wireless client summary"
WIRELESS_CLIENT_COUNT = re.compile(r"Number of (?:Local )?Clients:\s*(\d+)")
WIRELESS_CLIENT_HEADER = re.compile(r"MAC Address\s+AP Name\s+(?:WLAN|Type ID)\s+State\s+Protocol\s+Method\s+Role")
WIRELESS_CLIENT_ROW = re.compile(
    rf"({CLEAR_MAC.pattern}|(?:[0-9a-f]{{2}}:){{5}}[0-9a-f]{{2}})\s+(\S+)\s+"
    r"(?:WLAN\s+)?(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
WIRELESS_CLIENT_PAGER = re.compile(r"--More--|\ufffd|\x08|\x1b", re.IGNORECASE)


@dataclass(frozen=True)
class ClearTarget:
    table: str
    key: str
    read: str
    write: str
    port: str | None = None
    vrf: str | None = None


def clear_interface(value: str) -> str:
    """Expand IOS interface abbreviations for comparing operational and configuration output."""
    for long, short in SHORT_NAMES:
        if value.casefold().startswith(short.casefold()) and value[len(short):len(short) + 1].isdigit():
            return long + value[len(short):]
        if value.casefold().startswith(long.casefold()) and value[len(long):len(long) + 1].isdigit():
            return long + value[len(long):]
    return value


def clear_mac_address(value):
    if not (CLEAR_MAC.fullmatch(value) or CLEAR_MAC_INPUT.fullmatch(value)):
        return None
    digits = re.sub(r"[.:-]", "", value.lower())
    return ".".join(digits[offset:offset + 4] for offset in (0, 4, 8))


def clear_target(table: str, key: str, changes: dict) -> ClearTarget:
    if table == WIRELESS_CLIENT:
        mac = clear_mac_address(key)
        if not changes and mac and int(mac[:2], 16) % 2 == 0 and mac != "0000.0000.0000":
            return ClearTarget(table, mac, WIRELESS_CLIENT_SUMMARY, f"wireless client mac-address {mac} deauthenticate")
        raise Rejected(["wireless-client clear requires one unicast client MAC and empty changes"],
                       reason_codes=["clear_invalid_target"])
    if table == "port-counters" and not changes and CLEAR_INTERFACE.fullmatch(key):
        port = clear_interface(key)
        return ClearTarget(table, port, f"show interfaces {port}", f"clear counters {port}", port)
    if table == "fdb" and not changes:
        read = "show mac address-table dynamic"
        mac = clear_mac_address(key)
        if mac:
            return ClearTarget(table, mac, read, f"clear mac address-table dynamic address {mac}")
        if key.startswith("port:"):
            port = clear_interface(key[5:])
            if ETHERNET.fullmatch(port):
                return ClearTarget(table, "port:" + port, read, f"clear mac address-table dynamic interface {port}", port)
    if table in ("iparp", "neighbor-discovery"):
        vrf = changes.get("vrf")
        port = changes.get("interface")
        if (set(changes) <= {"vrf", "interface"} and
                ("vrf" not in changes or isinstance(vrf, str) and VRF_NAME.fullmatch(vrf)) and
                ("interface" not in changes or isinstance(port, str) and CLEAR_INTERFACE.fullmatch(port))):
            address_type = ipaddress.IPv4Address if table == "iparp" else ipaddress.IPv6Address
            try:
                address = str(address_type(key)) if "%" not in key else None
            except ValueError:
                address = None
            if address is not None:
                scope = f" vrf {vrf}" if vrf else ""
                if table == "iparp" and port is None:
                    return ClearTarget(table, address, "show ip arp" + scope, f"clear arp-cache{scope} {address}", vrf=vrf)
                if table == "neighbor-discovery" and bool(vrf) != bool(port):
                    port = clear_interface(port) if port else None
                    # IOSv takes the bare interface and address in the global table.
                    selector = f"vrf {vrf}" if vrf else port
                    return ClearTarget(table, address, "show ipv6 neighbors" + scope,
                                       f"clear ipv6 neighbors {selector} {address}", port, vrf)
    raise Rejected(["clear requires one IOS interface, one dynamic MAC or port:<interface>, one IPv4 address "
                    "with optional vrf, or one IPv6 address with vrf or interface"],
                   reason_codes=["clear_invalid_target"])


def clear_unreadable():
    return Rejected(["the IOS operational clear readback was refused, incomplete or unrecognized"],
                    reason_codes=["clear_readback_unreadable"])


def clear_active(target, observed):
    if target.table == "port-counters":
        return observed["link"][0].partition(" ")[0] == "up"
    if target.table == WIRELESS_CLIENT:
        return bool(observed["entries"])
    return any(row["dynamic"] for row in observed["entries"])


def _wireless_clear_observation(target, text):
    """Require a complete Catalyst 9800 client listing before selecting the approved MAC."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and re.fullmatch(r"Number of Excluded Clients:\s*\d+", lines[-1]):
        lines.pop()
    count = WIRELESS_CLIENT_COUNT.fullmatch(lines[0]) if lines else None
    if count is None or WIRELESS_CLIENT_PAGER.search(text):
        raise clear_unreadable()
    total = int(count[1])
    if total == 0 and len(lines) == 1:
        return {"entries": [], "other_entries": []}
    if (len(lines) < 3 or total != len(lines) - 3 or not WIRELESS_CLIENT_HEADER.fullmatch(lines[1])
            or not re.fullmatch(r"-+", lines[2])):
        raise clear_unreadable()
    entries, other_entries, seen = [], [], set()
    for line in lines[3:]:
        row = WIRELESS_CLIENT_ROW.fullmatch(line)
        if row is None:
            raise clear_unreadable()
        mac, ap, wlan, state, protocol, method, role = row.groups()
        dotted = clear_mac_address(mac)
        if dotted in seen:
            raise clear_unreadable()
        seen.add(dotted)
        compact = dotted.replace(".", "")
        canonical = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
        wlan_id = int(wlan)
        if dotted == target.key:
            entries.append(dict(mac=canonical, ap_name=ap, wlan_id=wlan_id, state=state, protocol=protocol,
                                method=method, role=role))
        else:
            other_entries.append({"mac": canonical})
    return {"entries": entries, "other_entries": other_entries}


def clear_observation(target: ClearTarget, text: str) -> dict:
    if refused(text) or "--More--" in text or "\ufffd" in text or any(line.lstrip().startswith("%") for line in text.splitlines()):
        raise clear_unreadable()
    if target.table == WIRELESS_CLIENT:
        return _wireless_clear_observation(target, text)
    if target.table == "port-counters":
        return _clear_counters(target, text.replace("\r", ""))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if target.table == "fdb":
        rows = _clear_fdb(lines)
        selected = [row for row in rows if row["port"] == target.port] if target.port else [
            row for row in rows if row["address"] == target.key]
    else:
        rows = _clear_neighbors(lines, target.table == "iparp")
        selected = [row for row in rows if row["address"] == target.key and
                    (target.port is None or row["port"] == target.port)]
    return {"entries": sorted(selected, key=lambda row: (row["address"], row["port"] or "", row.get("vlan", ""))),
            "other_entries": [clear_entry_identity(row) for row in rows if row not in selected]}


def _clear_counters(target, text):
    link = re.search(r"^(\S+) is (.+?), line protocol is (\S+)", text, re.MULTILINE)
    clearing = re.findall(r'^  Last clearing of "show interface" counters (\S+)[ \t]*$', text, re.MULTILINE)
    reads = re.findall(r"^ +([0-9]+) packets (input|output), ([0-9]+) bytes,", text, re.MULTILINE)
    if (link is None or clear_interface(link[1]) != target.port or len(clearing) != 1 or
            [direction for _, direction, _ in reads] != ["input", "output"]):
        raise clear_unreadable()
    counters = {}
    for packets, direction, size in reads:
        counters.update({direction + "_packets": int(packets), direction + "_bytes": int(size)})
    return {"port": target.port, "link": [link[2], link[3]], "last_clearing": clearing[0], "counters": counters}


def _clear_fdb(lines):
    if (len(lines) < 4 or lines[0] != "Mac Address Table" or not CLEAR_FDB_HEAD.fullmatch(lines[2]) or
            not re.fullmatch(r"-+", lines[1]) or not re.fullmatch(r"-+(?:\s+-+){3}", lines[3])):
        raise clear_unreadable()
    if len(lines) == 4:
        # IOSvL2 can omit the total when the criterion matches zero rows. The caller checks the count separately.
        return []
    count = CLEAR_FDB_TOTAL.fullmatch(lines[-1])
    if count is None or int(count[1]) != len(lines) - 5:
        raise clear_unreadable()
    rows = []
    for line in lines[4:-1]:
        vlan, mac, port = _clear_groups(r"([0-9]+)\s+(\S+)\s+DYNAMIC\s+(\S+)", line)
        if not CLEAR_MAC.fullmatch(mac) or not CLEAR_INTERFACE.fullmatch(port):
            raise clear_unreadable()
        rows.append({"address": mac.lower(), "port": clear_interface(port), "vlan": vlan, "dynamic": True})
    return rows


def clear_fdb_is_empty(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not re.fullmatch(r"Total Mac Address Space Available:\s*[0-9]+", lines.pop()):
        return False
    # IOL-L2 XE appends aggregate counts after the per-VLAN blocks.
    if len(lines) >= 3 and re.fullmatch(r"Total Dynamic Address Count\s*:\s*0", lines[-3]):
        static = re.fullmatch(r"Total Static\s+Address Count\s*:\s*([0-9]+)", lines[-2])
        used = re.fullmatch(r"Total Mac Address In Use\s*:\s*([0-9]+)", lines[-1])
        if not static or not used or static[1] != used[1]:
            return False
        del lines[-3:]
    elif not lines:
        return False
    if len(lines) % 5:
        return False
    return all(re.fullmatch(r"Mac Entries for Vlan [0-9]+:", lines[index])
               and re.fullmatch(r"-+", lines[index + 1])
               and re.fullmatch(r"Dynamic Address Count\s*:\s*0", lines[index + 2])
               and re.fullmatch(r"Static\s+Address Count\s*:\s*[0-9]+", lines[index + 3])
               and re.fullmatch(r"Total Mac Addresses\s*:\s*[0-9]+", lines[index + 4])
               for index in range(0, len(lines), 5))


def _clear_groups(pattern, line):
    match = re.fullmatch(pattern, line)
    if not match:
        raise clear_unreadable()
    return match.groups()


def _clear_neighbors(lines, ipv4):
    header = CLEAR_ARP_HEAD if ipv4 else CLEAR_ND_HEAD
    if not lines or not header.fullmatch(lines[0]):
        raise clear_unreadable()
    rows = []
    for line in lines[1:]:
        if ipv4:
            ip, age, mac, _kind, port = _clear_groups(r"Internet\s+(\S+)\s+([0-9]+|-)\s+(\S+)\s+(\S+)(?:\s+(\S+))?", line)
            dynamic = age != "-"
        else:
            ip, age, mac, state, port = _clear_groups(r"(\S+)\s+([0-9]+|-)\s+(\S+)\s+(\S+)\s+(\S+)", line)
            if state not in ("INCMP", "REACH", "STALE", "DELAY", "PROBE", "REACHABLE", "INCOMP", "DOWN", "STATIC"):
                raise clear_unreadable()
            dynamic = age != "-" and state != "STATIC"
        try:
            address = str((ipaddress.IPv4Address if ipv4 else ipaddress.IPv6Address)(ip))
        except ValueError:
            raise clear_unreadable() from None
        if (port is not None and not CLEAR_INTERFACE.fullmatch(port) or
                not CLEAR_MAC.fullmatch(mac) and mac.lower() not in ("incomplete", "-")):
            raise clear_unreadable()
        rows.append({"address": address, "port": clear_interface(port) if port else None, "mac": mac.lower(),
                     "dynamic": dynamic, "age": int(age) if age != "-" else None})
    return rows


def clear_entry_identity(row):
    return {field: value for field, value in row.items() if field != "age"}


def clear_counter_age(text):
    if text == "never":
        return float("inf")
    clock = re.fullmatch(r"([0-9]+):([0-5][0-9]):([0-5][0-9])", text)
    if clock:
        hours, minutes, seconds = map(int, clock.groups())
        return 3600 * hours + 60 * minutes + seconds
    units = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60}
    if re.fullmatch(r"(?:[0-9]+[ywdhm]){2}", text):
        return sum(int(n) * units[unit] for n, unit in re.findall(r"([0-9]+)([ywdhm])", text))
    return None


def clear_snapshot_digest(text):
    # IOS reports the configuration size and the last modification/saved times above the actual configuration.
    return hashlib.sha256("\n".join(line.rstrip() for line in text.splitlines()
                                   if line.strip() and not line.startswith(VOLATILE_HEADER)).encode("utf-8")).hexdigest()
