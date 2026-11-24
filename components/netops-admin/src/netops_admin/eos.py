"""Arista EOS plan adapter: interface description, admin state, speed, MTU and PoE, port VLAN membership and VLANs from
show running-config; the port bounce and the PoE cycle (1.0.12 eos port maintenance) as operations of their own tables.

Measured on cEOS 4.36.1F (verification, private measurement record): the running configuration is a
flat list of top-level statements, each followed by its own lines indented by three spaces and closed by a
line "!". The answer starts with "! Command: show running-config" and the device line, and ends with "end".
EOS creates a missing VLAN or interface without an error ("! Access VLAN does not exist. Creating vlan N",
"! Interface does not exist"), so the plan refuses both before anything is sent.
"""
from __future__ import annotations

import hashlib
import re

from netops_admin import eos_acl, eos_bgp, eos_dhcp, eos_l2, eos_l3, eos_routing, eos_services
from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)
from netops_admin.ios import vlan_numbers, vlan_text

PLATFORM = "eos"
COMMAND_LINE = "! Command: show running-config"
# measured over ssh exec (verification): the answer starts with the echo "> show running-config" and the header
# "! Command: show running-config at line 1"; in an interactive session the header has no "at line" part
COMMAND_HEADER = re.compile(r"^! Command: show running-config(?: at line [0-9]+)?$")
EXEC_ECHO = "> "
DEVICE_LINE = re.compile(r"^! device: (\S+) \(([^,()]+), EOS-([0-9]+\.[0-9]+\.[0-9]+[A-Z]*)(?:[-(\s][^\n]*)?\)\s*$",
                         re.MULTILINE)
# lines of the header that change without a configuration change
VOLATILE_HEADER = ("! Command:", "! Time:", "! Startup-config last modified")
INDENT = "   "
ETHERNET = re.compile(r"^Ethernet[1-9][0-9]{0,2}(?:/[1-9][0-9]{0,2}){0,2}$")
MANAGEMENT = re.compile(r"^Management[0-9]+(?:/[0-9]+)?$")
VLAN_HEADER = re.compile(r"^vlan ([0-9,-]+)$")
VLAN_RANGE = re.compile(r"^vlan ([1-9][0-9]{0,3})-([1-9][0-9]{0,3})$")
DEFAULT_VLAN = "1"
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# 1.0.12 eos port maintenance: tables changed only by their own operation (profiles.ACTIONS): the port bounce owns the shutdown line, the
# PoE cycle the line "poe disabled" (measured shutdown on cEOS 4.36.1F; poe disabled from the Arista EOS manual)
BOUNCE_TABLE = "port-bounce"
POE_TABLE = "inline-power"
INTERFACE_STATE_SCHEMA = 2
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$"), re.compile(r"^speed \S"),
                  re.compile(r"^mtu [0-9]+$"), re.compile(r"^poe disabled$")),
    BOUNCE_TABLE: (re.compile(r"^(?:no )?shutdown$"),),
    POE_TABLE: (re.compile(r"^poe disabled$"),),
    # 1.0.12 eos switchport admin: the whole membership of the port (measured on cEOS 4.36.1F, private measurement record)
    "vlan-membership": (re.compile(r"^(?:no )?switchport (?:access vlan|mode|trunk allowed vlan|trunk native vlan|"
                                   r"phone vlan)(?: .+)?$"),
                        re.compile(r"^(?:no )?dot1x (?:pae authenticator|port-control(?: .+)?|"
                                   r"mac based authentication)$")),
}
# 1.0.12 eos switchport admin (E04/E46): membership lines of show running-config and their attributes; any other switchport or dot1x
# line of the port is configuration outside the profile
MODES = {"switchport mode access": "access", "switchport mode trunk": "trunk",
         "switchport mode trunk phone": "trunk phone"}
DEFAULT_MODE = "access"
MEMBERSHIP_LINES = re.compile(r"^(?:switchport|dot1x) ")
# 1.0.12 eos switchport admin r2 (E05/E46): lines that EOS keeps on an access port after "switchport mode access" and does not use
# there (measured: fixtures/eos_g122/show-running-config-interfaces-Ethernet12__access-stale-phone.txt); they stay as
# they are and are compared as the rest of the configuration
PHONE_TRUNK = re.compile(r"^switchport phone trunk (?:tagged|untagged)$")
DOT1X_PAE = "dot1x pae authenticator"
DOT1X_AUTO = "dot1x port-control auto"
# 1.0.12 eos switchport admin (EP19): a port description is stored literally with any printable character (also diacritics);
# '?' opens the help of the interactive CLI, a control character or a tab is dropped and a trailing space is cut
DESCRIPTION_REFUSED = re.compile(r"[?\x00-\x1f\x7f-\x9f]")
VLAN_TABLE = "vlan"
VLAN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
TRUNK = re.compile(r"^switchport (?:mode (?!access$)\S+|trunk )")
LAG = re.compile(r"^channel-group ")
ROUTED = re.compile(r"^no switchport$")
# 1.0.12 eos port maintenance (E23): the speed values of "speed ?" and "speed auto ?" on cEOS 4.36.1F (private measurement record);
# a forced speed disables autonegotiation, "auto" enables it, "auto SPEED" advertises one speed. The value is allowed
# without a hardware entry for plain auto. Explicit rates require support in show interfaces N hardware.
# EOS refused "speed auto 1g" on a port without autonegotiation (probe2).
FORCED_SPEEDS = {"10mhalf": "10M/half", "10mfull": "10M/full", "100mhalf": "100M/half", "100mfull": "100M/full",
                 "1g": "1G/full", "10g": "10G/full", "25g": "25G/full", "40g-4": "40G-4/full", "50g-1": "50G-1/full",
                 "50g-2": "50G-2/full", "100g-1": "100G-1/full", "100g-2": "100G-2/full", "100g-4": "100G-4/full",
                 "200g-1": "200G-1/full", "200g-2": "200G-2/full", "200g-4": "200G-4/full", "400g-2": "400G-2/full",
                 "400g-4": "400G-4/full", "400g-8": "400G-8/full", "800g-4": "800G-4/full", "800g-8": "800G-8/full",
                 "1.6t-8": "1.6T-8/full"}
AUTO_SPEEDS = dict(FORCED_SPEEDS, **{"2.5g": "2.5G/full", "5g": "5G/full"})
SPEED_AUTO = "auto"


def legacy_interface_state(state):
    if state is None:
        return None
    return {name: value for name, value in state.items() if name not in {"speed", "mtu", "poe"}}


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []
        # eos switchport admin r2: left-over lines of an access port that EOS does not use (outside the profile state, kept as they are)
        self.leftover = []


class Block:
    def __init__(self, header: str, line: int):
        self.header = header
        self.line = line
        self.children = []


def firmware_of(text: str):
    match = DEVICE_LINE.search(text)
    return None if match is None else match.group(3)


def short_version(value: str) -> str:
    """The release part of an EOS image version: 4.36.1F of 4.36.1F-48405728.4361F (engineering build)."""
    return value.strip().split()[0].split("-")[0] if value and value.strip() else ""


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        lines = text.replace("\r", "").split("\n")
        while lines and (not lines[0].strip() or lines[0].startswith(EXEC_ECHO)):
            lines.pop(0)
        filled = [line for line in lines if line.strip()]
        if not filled or COMMAND_HEADER.match(filled[0].rstrip()) is None:
            raise SnapshotRejected(["snapshot does not start with %r; it is not an EOS running configuration"
                                    % COMMAND_LINE], SNAPSHOT_UNREADABLE)
        if filled[-1].rstrip() != "end":
            raise SnapshotRejected(["snapshot does not end with 'end'; the running configuration is cut off"],
                                   SNAPSHOT_INCOMPLETE)
        text = "\n".join(lines)
        found = firmware_of(text)
        if found is None:
            raise SnapshotRejected(["snapshot does not name the EOS release in its device line"],
                                   SNAPSHOT_UNREADABLE)
        if firmware and firmware != found:
            raise SnapshotRejected(["snapshot was taken on EOS %s, not on the configured %s" % (found, firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        self.firmware = found
        self.hostname = DEVICE_LINE.search(text).group(1)
        self.inventory = None
        self.lines = [line.rstrip() for line in lines]
        self.blocks, self.interfaces, self.vlans = [], {}, {DEFAULT_VLAN}
        # EOS groups consecutive VLANs with no configuration into one header, e.g. "vlan 3992-3993".
        self.default_vlan_ranges = {}
        self.vlan_blocks, self.vlan_lists = {}, set()
        lists = []
        current = None
        for number, line in enumerate(lines, 1):
            stripped = line.rstrip()
            if not stripped.strip():
                continue
            if stripped.startswith("!") or stripped == "end":
                if not stripped.startswith(" "):
                    current = None
                continue
            if stripped.startswith(" "):
                if current is None:
                    raise SnapshotRejected(["line %d is indented outside any statement" % number],
                                           SNAPSHOT_UNREADABLE)
                current.children.append(stripped)
                continue
            current = Block(stripped, number)
            self.blocks.append(current)
            words = stripped.split()
            if words[0] == "interface" and len(words) == 2:
                if words[1] in self.interfaces:
                    raise SnapshotRejected(["interface %s is listed twice" % words[1]], SNAPSHOT_UNREADABLE)
                self.interfaces[words[1]] = current
            elif words[0] == "hostname" and len(words) == 2:
                self.hostname = words[1]
            vlan = VLAN_HEADER.match(stripped)
            if vlan is not None:
                listed = _vlan_list(vlan.group(1))
                self.vlans |= listed
                if vlan.group(1).isdigit() and str(int(vlan.group(1))) == vlan.group(1):
                    self.vlan_blocks[vlan.group(1)] = current
                else:
                    lists.append((current, listed))
        seen = set(self.vlan_blocks)
        for block, listed in lists:
            match = VLAN_RANGE.fullmatch(block.header)
            if not block.children and match and 2 <= int(match[1]) < int(match[2]) <= 4094 and not seen & listed:
                self.default_vlan_ranges[block.line] = range(int(match[1]), int(match[2]) + 1)
            else:
                self.vlan_lists.update(listed)
            seen.update(listed)

    def entries(self, table: str):
        if table == eos_bgp.TABLE:
            return eos_bgp.entries(self, Entry)
        if table in eos_routing.TABLES:
            return eos_routing.entries(self, table, Entry)
        if table in eos_dhcp.TABLES:
            return eos_dhcp.entries(self, table, Entry)
        if table in eos_acl.TABLES:
            return eos_acl.entries(self, table, Entry)
        if table in eos_l3.TABLES:
            return eos_l3.entries(self, table, Entry)
        if table in eos_l2.TABLES:
            return eos_l2.entries(self, table, Entry)
        if table in eos_services.TABLES:
            return eos_services.entries(self, table, Entry)
        if table == VLAN_TABLE:
            return {vid: self._vlan_entry(vid) for vid in self.vlans if vid != DEFAULT_VLAN}
        if table not in OWN_LINES:
            return None
        return {name: self._entry(table, name, block) for name, block in self.interfaces.items()}

    def _vlan_entry(self, vid):
        entry = Entry(vid)
        if vid in self.vlan_lists:
            entry.unsupported.append("VLAN %s is configured in a VLAN list line" % vid)
        block = self.vlan_blocks.get(vid)
        for child in (block.children if block is not None else []):
            line = child.strip()
            if line.startswith("name ") and child.startswith(INDENT) and not child.startswith(INDENT + " "):
                _once(entry, "name", line[len("name "):], block)
            else:
                entry.unsupported.append("line %d: %s" % (block.line, line.split()[0]))
        return entry

    def _entry(self, table, name, block):
        entry = Entry(name)
        dot1x, phone_trunk = set(), []
        for child in block.children:
            line = child[len(INDENT):] if child.startswith(INDENT) and not child.startswith(INDENT + " ") else None
            if line is None:
                continue
            if table == "interface" and line.startswith("description "):
                _once(entry, "description", line[len("description "):], block)
            elif table in ("interface", BOUNCE_TABLE) and line == "shutdown":
                _once(entry, "admin-state", "disabled", block)
            elif table == "interface" and line.startswith("speed "):
                _once(entry, "speed", line[len("speed "):], block)
            elif table == "interface" and re.fullmatch(r"mtu [0-9]+", line):
                _once(entry, "mtu", line[len("mtu "):], block)
            elif table == "interface" and line == "poe disabled":
                _once(entry, "poe", "disabled", block)
            elif table == POE_TABLE and line == "poe disabled":
                _once(entry, "admin-state", "disabled", block)
            elif table == "vlan-membership" and PHONE_TRUNK.match(line):
                phone_trunk.append(line)
            elif table == "vlan-membership" and MEMBERSHIP_LINES.match(line):
                _membership(entry, line, block, dot1x)
        if table != "vlan-membership":
            return entry
        # eos switchport admin r2 (E05/E46): on an access port EOS ignores the phone trunk tagging and 802.1X without port-control
        # auto (the port is force-authorized, measured); they are tolerated as left-over lines, as before eos switchport admin
        access = entry.attributes.get("mode", DEFAULT_MODE) == DEFAULT_MODE
        for line in phone_trunk:
            if access:
                entry.leftover.append(line)
            else:
                entry.unsupported.append("line %d: %s" % (block.line, " ".join(line.split()[:3])))
        if dot1x == {"pae", "auto"}:
            entry.attributes["dot1x"] = "enabled"
        elif dot1x == {"pae"} and access:
            entry.leftover.append(DOT1X_PAE)
        elif dot1x:
            entry.unsupported.append("line %d: dot1x without both pae authenticator and port-control auto"
                                     % block.line)
        return entry

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        """Interfaces that name the VLAN: its SVI, an access, native or phone VLAN or an explicit allowed list (the
        default allowed list "all" of a trunk is no reference, as on IOS)."""
        if table != VLAN_TABLE:
            return []
        found = []
        for name, block in self.interfaces.items():
            if name == "Vlan" + key:
                found.append(name)
                continue
            entry = self._entry("vlan-membership", name, block)
            values = entry.attributes
            if key in (values.get("access-vlan"), values.get("native-vlan"), values.get("voice-vlan")) or (
                    "allowed-vlans" in values and int(key) in vlan_numbers(values["allowed-vlans"])):
                found.append(name)
        return sorted(found)

    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        block = self.interfaces.get(key)
        return [] if block is None else [child.strip() for child in block.children]

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        if table == eos_bgp.TABLE:
            kept = [line for line in eos_bgp.without_object(self.lines, key)
                    if line and line != "!" and not line.startswith(VOLATILE_HEADER)]
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        for scope in (eos_acl, eos_dhcp, eos_l3, eos_routing):
            if table not in scope.TABLES:
                continue
            kept = [line for line in scope.without_object(self.lines, table, key)
                    if line and line != "!" and not line.startswith(VOLATILE_HEADER)]
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        if table in eos_services.TABLES:
            kept = [line for line in eos_services.without_object(self.lines, table, key)
                    if line and line != "!" and not line.startswith(VOLATILE_HEADER)]
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        if table in eos_l2.TABLES:
            kept = [line for line in eos_l2.outside_lines(self, table, key)
                    if line and line != "!" and not line.startswith(VOLATILE_HEADER)]
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        kept, inside = [], False
        if table == VLAN_TABLE:
            vid = int(key) if key.isdecimal() else None
            for number, line in enumerate(self.lines, 1):
                if not line or line.startswith(VOLATILE_HEADER) or line == "!":
                    continue
                if not line.startswith(" "):
                    inside = line == "vlan %s" % key
                    members = self.default_vlan_ranges.get(number, ())
                    if vid in members:
                        kept.extend(_vlan_headers(set(members) - {vid}))
                        continue
                if not inside:
                    kept.append(line)
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        siblings = self.interface_lines(key)
        for line in self.lines:
            if not line or line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if inside and _own(table, line.strip(), siblings):
                continue
            kept.append(line)
        return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def _own(table: str, line: str, siblings) -> bool:
    """A line of the port that the profile state renders. A left-over "dot1x pae authenticator" without port-control
    auto (eos switchport admin r2) is not: it stays and is compared as the rest of the configuration."""
    if table == "vlan-membership" and line == DOT1X_PAE and DOT1X_AUTO not in siblings:
        return False
    return any(pattern.match(line) for pattern in OWN_LINES.get(table, ()))


def _membership(entry, line, block, dot1x):
    """One switchport or dot1x line of a port (canonical form of show running-config, measured on cEOS 4.36.1F)."""
    words = line.split()
    if line in MODES:
        _once(entry, "mode", MODES[line], block)
    elif words[:3] == ["switchport", "access", "vlan"] and len(words) == 4 and words[3].isdigit():
        _once(entry, "access-vlan", words[3], block)
    elif words[:4] == ["switchport", "trunk", "native", "vlan"] and len(words) == 5 and words[4].isdigit():
        _once(entry, "native-vlan", words[4], block)
    elif words[:3] == ["switchport", "phone", "vlan"] and len(words) == 4 and words[3].isdigit():
        _once(entry, "voice-vlan", words[3], block)
    elif words[:4] == ["switchport", "trunk", "allowed", "vlan"] and len(words) == 5 \
            and re.fullmatch(r"none|[0-9,-]+", words[4]):
        _once(entry, "allowed-vlans", vlan_text(vlan_numbers(words[4])), block)
    elif line == "dot1x pae authenticator":
        dot1x.add("pae")
    elif line == "dot1x port-control auto":
        dot1x.add("auto")
    elif line == "dot1x mac based authentication":
        _once(entry, "mab", "enabled", block)
    else:
        entry.unsupported.append("line %d: %s" % (block.line, " ".join(words[:3])))


def _once(entry, name, value, block):
    if name in entry.attributes:
        entry.unsupported.append("line %d: repeated %s" % (block.line, name))
    entry.attributes[name] = value


def _vlan_list(text: str) -> set:
    found = set()
    for part in text.split(","):
        if "-" in part:
            low, high = part.split("-", 1)
            if low.isdigit() and high.isdigit() and int(low) <= int(high):
                found |= {str(number) for number in range(int(low), int(high) + 1)}
        elif part.isdigit():
            found.add(str(int(part)))
    return found


def load(text: str, firmware: str | None) -> Snapshot:
    try:
        return Snapshot(text, firmware)
    except SnapshotRejected:
        raise
    except Exception as exc:
        raise SnapshotRejected(["snapshot does not parse: %s" % type(exc).__name__], SNAPSHOT_UNREADABLE) from None


def absent(snapshot, table: str, key: str) -> list:
    return ["interface %s is not in the running configuration; EOS would create it without an error, so the change "
            "is refused" % key]


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip():
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def _description(value: str) -> str:
    """EP19: a description of printable characters (diacritics too) that EOS stores literally (measured: '|', '!',
    '#', quotes, backslash and '$' are kept; '?', tab and control characters are not, a trailing space is cut)."""
    if DESCRIPTION_REFUSED.search(value) or not value.isprintable() or value != value.strip():
        raise Rejected(["the description %r cannot be written literally: EOS drops '?', tabs, control characters and "
                        "leading or trailing spaces" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    if profile.table == VLAN_TABLE:
        lines = ["name %s" % _vlan_name(attributes["name"])] if attributes.get("name") else []
        return ["configure terminal", "vlan %s" % _vlan_id(key)] + lines + ["end"]
    raise Rejected(["EOS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    if profile.table == VLAN_TABLE:
        return ["configure terminal", "no vlan %s" % _vlan_id(key), "end"]
    raise Rejected(["EOS %s objects are only updated" % profile.table])


def _vlan_id(key: str) -> str:
    if not key.isdigit() or str(int(key)) != key or not 2 <= int(key) <= 4094:
        raise Rejected(["VLAN %s is not a VLAN number 2..4094" % key], reason_codes=["vlan_reserved"])
    return key


def _vlan_name(value: str) -> str:
    # measured: name takes one ASCII word, cuts a longer name to 32 characters without an error
    if not VLAN_NAME.fullmatch(value or ""):
        raise Rejected(["a VLAN name is 1-32 ASCII letters, digits, '_', '.' or '-'"])
    return value


def _lines(name: str, value) -> list:
    """The interface lines of one attribute (dot1x needs two)."""
    if name == "dot1x":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["dot1x must be enabled or disabled"])
        if value == "enabled":
            return ["dot1x pae authenticator", "dot1x port-control auto"]
        return ["no dot1x port-control", "no dot1x pae authenticator"]
    return [_line(name, value)]


def _line(name: str, value) -> str:
    if name == "description":
        return "no description" if value is None else "description %s" % _description(value)
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return "shutdown" if value == "disabled" else "no shutdown"
    if name == "speed":
        return "no speed" if value is None else "speed %s" % _speed(value)
    if name == "mtu":
        if value is None:
            return "no mtu"
        if not str(value).isdigit() or not 68 <= int(value) <= 65535:
            raise Rejected(["mtu must be a number 68..65535"])
        return "mtu %d" % int(value)
    if name == "poe":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["poe must be enabled or disabled"])
        return "poe disabled" if value == "disabled" else "no poe disabled"
    if name == "access-vlan":
        if value is None or value == DEFAULT_VLAN:
            return "no switchport access vlan"
        if not str(value).isdigit():
            raise Rejected(["access-vlan must be a VLAN number"])
        return "switchport access vlan %s" % value
    if name == "mode":
        if value is None or value == DEFAULT_MODE:
            return "switchport mode access"
        if value not in ("trunk", "trunk phone"):
            raise Rejected(["mode must be access, trunk or trunk phone"])
        return "switchport mode %s" % value
    if name == "allowed-vlans":
        text = vlan_text(vlan_numbers(value or "all"))
        return "no switchport trunk allowed vlan" if text == "all" else "switchport trunk allowed vlan %s" % text
    if name in ("native-vlan", "voice-vlan"):
        command = "switchport trunk native vlan" if name == "native-vlan" else "switchport phone vlan"
        if value is None or (name == "native-vlan" and str(value) == DEFAULT_VLAN):
            return "no " + command
        if not str(value).isdigit() or not 1 <= int(value) <= 4094:
            raise Rejected(["%s must be a VLAN number" % name])
        return "%s %s" % (command, value)
    if name == "mab":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["mab must be enabled or disabled"])
        return "dot1x mac based authentication" if value == "enabled" else "no dot1x mac based authentication"
    raise Rejected(["attribute %s is not known on EOS" % name])


def _speed(value: str) -> str:
    words = str(value).split()
    if words == [SPEED_AUTO] or (len(words) == 1 and words[0] in FORCED_SPEEDS) \
            or (len(words) == 2 and words[0] == SPEED_AUTO and words[1] in AUTO_SPEEDS):
        return " ".join(words)
    raise Rejected(["speed %r is not an EOS speed: auto, auto SPEED or a forced speed such as 1g or 100mfull" % value])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure terminal, the interface (or VLAN), its lines and end.

    The lines run under the safeguard session that Admin opened before (configure session with commit timer); a
    commit timer that expires returns the whole running configuration to the checkpoint of that session (VLANs
    included, they live in the running configuration of EOS)."""
    if profile.table == VLAN_TABLE:
        name = assign.get("name")
        return ["configure terminal", "vlan %s" % _vlan_id(key),
                "name %s" % _vlan_name(name) if name else "no name", "end"]
    if profile.table in (BOUNCE_TABLE, POE_TABLE):
        # eos port maintenance: the operation owns one attribute, admin-state, rendered as its own line
        attribute = "admin-state" if profile.table == BOUNCE_TABLE else "poe"
        assign = {attribute: value for value in assign.values()}
        remove = [attribute for _name in remove]
    lines = [line for name, value in sorted(assign.items()) for line in _lines(name, value)]
    lines += [line for name in sorted(remove) for line in _lines(name, None)]
    if not lines:
        return []
    return ["configure terminal", "interface %s" % key] + lines + ["end"]


def interface_kind(key: str) -> str:
    if MANAGEMENT.fullmatch(key):
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
        # eos port maintenance (E06/E23): speed and PoE cut the link or the power of the device; the MTU of a port is changed with the
        # same checks, a routed port carries IP with it
        return any(after.get(name) != before.get(name) for name in ("admin-state", "speed", "mtu", "poe"))
    if table in (BOUNCE_TABLE, POE_TABLE):
        return True
    # eos switchport admin: every membership change (VLANs, mode, voice VLAN, 802.1X/MAB) can cut traffic of the port
    return table == "vlan-membership" and before != after


def trunk_change(before, after) -> bool:
    """A change of the mode or of a port that is or becomes a trunk: it needs endpoint_impact naming the port."""
    before, after = before or {}, after or {}
    return before.get("mode", DEFAULT_MODE) != after.get("mode", DEFAULT_MODE) \
        or after.get("mode", DEFAULT_MODE) != DEFAULT_MODE


def vlan_prechecks(snapshot, op: str, key: str, after) -> list:
    _vlan_id(key)
    if after and after.get("name"):
        _vlan_name(after["name"])
    if op == "delete" and "Vlan" + key in snapshot.interfaces:
        raise Rejected(["VLAN %s has the routed interface Vlan%s; it is not deleted" % (key, key)])
    return []


def membership_prechecks(before, after, undo=False) -> list:
    """The combinations EOS applies as configured (measured: the phone VLAN acts only in trunk phone mode, MAC based
    authentication only with 802.1X).

    eos switchport admin r2 (E05/E46): a phone VLAN or MAB that EOS left on the port without effect (it keeps them after "switchport
    mode access") is tolerated while the change keeps it and the mode, and the undo of its removal restores it; a
    change never creates such a state."""
    state, before = after or {}, before or {}

    def kept(*names):
        return all(state.get(name) == before.get(name) for name in names)

    if "voice-vlan" in state and state.get("mode") != "trunk phone" and not undo and not kept("voice-vlan", "mode"):
        raise Rejected(["voice-vlan needs mode trunk phone: EOS keeps a phone VLAN of another mode in the "
                        "configuration but does not use it"])
    if state.get("mab") == "enabled" and state.get("dot1x") != "enabled" and not undo and not kept("mab", "dot1x"):
        raise Rejected(["mab needs dot1x enabled"])
    if state.get("mode", DEFAULT_MODE) == DEFAULT_MODE and any(
            state.get(name) != before.get(name) for name in ("allowed-vlans", "native-vlan") if name in state):
        raise Rejected(["allowed-vlans and native-vlan apply to a trunk; set mode trunk or trunk phone, or remove "
                        "them"])
    return []


def prechecks(snapshot, profile, op: str, key: str, after, undo=False) -> list:
    """undo: the trusted undo path of execute (eos switchport admin r2): it restores the earlier state, also an allowed list with a VLAN
    that does not exist and a left-over phone VLAN."""
    if profile.table in eos_acl.TABLES | eos_dhcp.TABLES | eos_l2.TABLES | eos_l3.TABLES | eos_routing.TABLES \
            | eos_services.TABLES | {eos_bgp.TABLE}:
        return []
    if profile.table == VLAN_TABLE:
        return vlan_prechecks(snapshot, op, key, after)
    kind = interface_kind(key)
    if kind == "management":
        raise Rejected(["interface %s is a management interface; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only EthernetN ports are changed" % key],
                       reason_codes=["port_unsupported_interface"])
    lines = snapshot.interface_lines(key)
    entry = snapshot._entry(profile.table, key, snapshot.interfaces[key]) if key in snapshot.interfaces else None
    before = entry.attributes if entry is not None else {}
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of a port-channel; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        # eos switchport admin: the membership of a trunk is changed (the runtime checks require endpoint_impact); the admin state
        # of a trunk stays refused
        if profile.table != "vlan-membership" and any(TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk; a trunk is treated as an uplink and is not changed" % key],
                           reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
    if profile.table == "vlan-membership":
        membership_prechecks(before, after, undo)
        state = after or {}
        if entry is not None and entry.leftover and (
                state.get("mode", DEFAULT_MODE) != DEFAULT_MODE
                or any(state.get(name) != before.get(name) for name in ("dot1x", "mab"))):
            raise Rejected(["object %r holds configuration outside the profile: %s (EOS ignores these lines on an "
                            "access port; a change of the mode, 802.1X or MAB would use them, so remove them first)"
                            % (key, ", ".join(entry.leftover))])
        for vid in sorted(required_vlans(before, after, undo), key=int):
            if vid not in snapshot.vlans:
                raise Rejected(["VLAN %s does not exist in the running configuration; EOS would create it without an "
                                "error, so the change is refused" % vid], reason_codes=["vlan_missing"])
    return []


def interface_target(table: str, key: str):
    """The interface a profile key names, or None for an object that is not an interface (eos port ownership: batch protection)."""
    if table in ("interface", "vlan-membership", BOUNCE_TABLE, POE_TABLE, eos_l3.INTERFACE, eos_l2.CHANNEL,
                 eos_l2.MEMBER, eos_l2.MLAG_PORT, eos_l2.STP_PORT):
        return key
    if table == eos_routing.OSPF_INTERFACE:  # PROCESS:INTERFACE
        return key.split(":", 1)[-1]
    if table in (eos_acl.BINDING, eos_dhcp.RELAY, eos_l3.VARP):  # INTERFACE:... or INTERFACE
        return key.split(":", 1)[0]
    return None


def interface_protected(protected, interface: str) -> bool:
    names = {str(item).casefold() for item in (protected or {}).get("interface", ())}
    return bool({interface.casefold(), short_name(interface).casefold()} & names)


def required_vlans(before, after, undo=False) -> set:
    """VLANs that must exist: the access, native and voice VLAN after the change and VLANs newly added to an allowed
    list (a retained allowed VLAN may be missing, as on IOS). eos switchport admin r2 (E04): the undo restores an earlier allowed list,
    also with a VLAN that does not exist (EOS takes it without a warning and creates nothing, measured in
    private measurement record); only the trusted undo path of execute qualifies, as on IOS."""
    before, after = before or {}, after or {}
    found = {str(after.get("access-vlan", DEFAULT_VLAN))}
    found |= {str(after[name]) for name in ("native-vlan", "voice-vlan") if name in after}
    if "allowed-vlans" in after and not undo:
        added = vlan_numbers(after["allowed-vlans"]) - vlan_numbers(before.get("allowed-vlans", "all"))
        found |= {str(vid) for vid in added}
    return found


def snapshot_after(text: str, plan) -> str:
    """The running configuration with the planned state of the interface lines (for the audit prediction)."""
    key, table, state = plan["key"], plan["table"], plan["predicted"]["after"] or {}
    if table == eos_bgp.TABLE:
        return eos_bgp.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_routing.TABLES:
        return eos_routing.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_dhcp.TABLES:
        return eos_dhcp.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_acl.TABLES:
        return eos_acl.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_l3.TABLES:
        return eos_l3.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_services.TABLES:
        return eos_services.snapshot_after(load(text, plan["firmware"]), plan)
    if table in eos_l2.TABLES:
        return eos_l2.snapshot_after(load(text, plan["firmware"]), plan)
    if table == VLAN_TABLE:
        return _vlan_snapshot_after(text, key, plan["predicted"]["after"])
    lines = text.replace("\r", "").split("\n")
    header = "interface %s" % key
    siblings = []
    if header in (line.rstrip() for line in lines):
        start = [line.rstrip() for line in lines].index(header) + 1
        while start < len(lines) and lines[start].startswith(" "):
            siblings.append(lines[start].strip())
            start += 1
    result, inside = [], False
    for line in lines:
        if line and not line.startswith(" "):
            if inside:
                result.extend(INDENT + item for name, value in sorted(state.items())
                              for item in _lines("poe" if table == POE_TABLE else name, value))
            inside = line.rstrip() == header
            result.append(line)
            continue
        if inside and line.strip() and _own(table, line.strip(), siblings):
            continue
        result.append(line)
    return "\n".join(result)


def _vlan_snapshot_after(text: str, key: str, state) -> str:
    """Replace the VLAN in numeric order, merging or splitting adjacent default VLANs as EOS does."""
    snapshot = Snapshot(text, None)
    lines = snapshot.lines
    vid = int(key)
    name = (state or {}).get("name")
    merge = state is not None and not name
    default_members, replaced = set(), []
    insertion = lines.index("end")
    higher, last_vlan_end = False, None
    for block in snapshot.blocks:
        start = block.line - 1
        match = VLAN_HEADER.fullmatch(block.header)
        if match is None:
            if block.header.startswith("interface "):
                insertion = min(insertion, start)
            continue
        ids = _vlan_list(match[1])
        if ids and min(map(int, ids)) > vid:
            insertion = min(insertion, start)
            higher = True
        last_vlan_end = start + 1
        while last_vlan_end < len(lines) and (not lines[last_vlan_end] or lines[last_vlan_end].startswith(" ")):
            last_vlan_end += 1
        if last_vlan_end < len(lines) and lines[last_vlan_end] == "!":
            last_vlan_end += 1
        members = snapshot.default_vlan_ranges.get(block.line, ())
        if not block.children and match[1].isdigit() and 2 <= int(match[1]) <= 4094:
            members = (int(match[1]),)
        if block.header == "vlan %s" % key or vid in members or (merge and (vid - 1 in members or vid + 1 in members)):
            default_members.update(members)
            end = start + 1
            while end < len(lines) and (not lines[end] or lines[end].startswith(" ")):
                end += 1
            if end < len(lines) and lines[end] == "!":
                end += 1
            replaced.append((start, end))

    default_members.discard(vid)
    if merge:
        default_members.add(vid)
    headers = _vlan_headers(default_members)
    rendered = [line for header in headers for line in (header, "!")]
    if name:
        before = _vlan_headers({member for member in default_members if member < vid})
        position = 2 * len(before)
        rendered[position:position] = ["vlan %s" % key, INDENT + "name %s" % name, "!"]
    if replaced:
        insertion = replaced[0][0]
    elif last_vlan_end is not None and not higher:
        # a VLAN above all others follows the last VLAN block (measured on Arista cEOS 4.36.1F: before the aaa lines), not the
        # first interface; the rest of the next batch step is compared with this position
        insertion = last_vlan_end
    for start, end in reversed(replaced):
        del lines[start:end]
    lines[insertion:insertion] = rendered
    return "\n".join(lines)


def _vlan_headers(numbers: set) -> list:
    return ["vlan " + group for group in vlan_text(numbers).split(",")] if numbers else []


def default_vlan_name(key: str) -> str:
    return "VLAN%04d" % int(key)


def canonical_changes(table: str, key: str, changes: dict) -> dict:
    """eos switchport admin r2 (E05/E19): the explicit name VLANnnnn of VLAN nnnn is its default name. EOS stores no name line for it
    (measured, private measurement record) and show vlan shows it like a VLAN without a name, so it is planned
    as no name: preview, apply and readback agree."""
    if table in eos_routing.TABLES:
        return eos_routing.canonical_changes(table, key, changes)
    if table in eos_dhcp.TABLES:
        return eos_dhcp.canonical_changes(table, changes)
    if table in eos_acl.TABLES:
        return eos_acl.canonical_changes(table, key, changes)
    if table in eos_l3.TABLES:
        return eos_l3.canonical_changes(changes)
    if table == VLAN_TABLE and key.isdigit() and changes.get("name") == default_vlan_name(key):
        return dict(changes, name=None)
    return changes


def check_view(table: str, state):
    """eos switchport admin r2 (E05/E46): the part of a membership state that the check account (privilege 1) can read. EOS lists the
    phone VLAN only in trunk phone mode, and a port whose 802.1X is not enforced shows the default port control
    force-authorized, with which MAB has no effect (measured, fixtures/eos_g122). The write account reads the whole
    state in show running-config (postcheck); the check account compares this part of it."""
    if state is not None and table in eos_services.TABLES:
        return eos_services.check_view(table, state)
    if state is not None and table == "interface":
        # eos port maintenance (E06/E23, measured on cEOS 4.36.1F, private measurement record): the check account reads no configured
        # speed (show interfaces N status shows the operational one, which depends on the link partner), no MTU of a
        # switchport (show interfaces N shows the Ethernet MTU 9214 for any configured mtu) and no PoE (show poe is
        # Privileged EXEC in the Arista EOS manual; the check account got "% Invalid input"); the write account reads
        # them in show running-config (postcheck)
        return {name: value for name, value in state.items() if name not in ("speed", "mtu", "poe")}
    if state is not None and table == eos_l2.STP_PORT:
        # The operator confirms that the port remains inactive. Running-config carries its STP settings.
        return {}
    if state is not None and table == eos_l2.STP_VLAN and state.get("priority") == "32768":
        # The operational bridge priority is the same whether the default is configured or implicit.
        return {}
    if state is None or table != "vlan-membership":
        return state
    state = dict(state)
    if state.get("mode", DEFAULT_MODE) != "trunk phone":
        state.pop("voice-vlan", None)
    if state.get("dot1x") in (None, "disabled", "port-control force-authorized"):
        state.pop("dot1x", None)
        state.pop("mab", None)
    return state


# ---- answers of the device (measured fixtures, private measurement record) ----

def cli_error(text: str):
    """A refused line: an error ("% ...") or a warning that EOS would create something ("! ...")."""
    for line in text.replace("\r", "").split("\n")[1:]:
        stripped = line.strip()
        if stripped.startswith("% ") or stripped.startswith("! "):
            return stripped[:100]
    return None


PRIVILEGE = re.compile(r"^Current privilege level is ([0-9]+)\s*$", re.MULTILINE)
IMAGE_VERSION = re.compile(r"^Software image version:\s*(\S+)", re.MULTILINE)
HOSTNAME = re.compile(r"^Hostname:\s*(\S+)\s*$", re.MULTILINE)
MAC_TOTAL = re.compile(r"^Total Mac Addresses for this criterion:\s*([0-9]+)\s*$", re.MULTILINE)
ACCESS_VLAN = re.compile(r"^Access Mode VLAN:\s*([0-9]+)\b", re.MULTILINE)
ADMIN_MODE = re.compile(r"^Administrative Mode:\s*(.+?)\s*$", re.MULTILINE)
SWITCHPORT_NAME = re.compile(r"^Name:\s*(\S+)\s*$", re.MULTILINE)
# eos switchport admin: over ssh exec the answer ends with " at line 1" and exit status 1 (measured, private measurement record)
VLAN_MISSING = re.compile(r"^% VLAN ([0-9]+) not found in current VLAN database(?: at line [0-9]+)?\s*$", re.MULTILINE)


def short_name(key: str) -> str:
    """The abbreviation EOS prints in tables: Et10 for Ethernet10, Ma0 for Management0."""
    for long, short in (("Ethernet", "Et"), ("Management", "Ma"), ("Port-Channel", "Po")):
        if key.startswith(long):
            return short + key[len(long):]
    return key


def unreadable(what: str):
    return Rejected(["the %s is not recognised" % what], reason_codes=["port_usage_unreadable"])


def privilege(text: str) -> int:
    match = PRIVILEGE.search(text)
    if match is None:
        raise Rejected(["the privilege level of the write account is not readable"])
    return int(match.group(1))


def image_version(text: str) -> str:
    match = IMAGE_VERSION.search(text)
    if match is None:
        raise Rejected(["the device does not report its software image version"])
    return short_version(match.group(1))


def table_rows(text: str, first_column: str) -> tuple:
    """Header column positions and the rows of a fixed-width EOS table whose header starts with first_column."""
    lines = text.replace("\r", "").split("\n")
    for index, line in enumerate(lines):
        if line.startswith(first_column + " "):
            columns = [(match.group(0), match.start()) for match in re.finditer(r"\S+(?: \S+)?", line)]
            rows = [row for row in lines[index + 1:] if row.strip() and not set(row.strip()) <= {"-", " "}]
            return columns, rows
    return None, None


def lldp_ports(text: str) -> set:
    """Local ports with an LLDP neighbor in show lldp neighbors (measured layout: Port, Neighbor Device ID, ...)."""
    header = re.search(r"^Port\s+Neighbor Device ID\s+Neighbor Port ID\s+TTL\s*$", text, re.MULTILINE)
    if header is None:
        raise unreadable("LLDP neighbor list")
    found = set()
    for line in text[header.end():].split("\n"):
        words = line.split()
        if not words or set(line.strip()) <= {"-", " "}:
            continue
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*", words[0]) or not words[-1].isdigit():
            raise unreadable("LLDP neighbor list")
        found.add(words[0])
    return found


def learned_macs(text: str) -> int:
    """Unicast MAC addresses of the port in show mac address-table interface N (the first Total line)."""
    totals = MAC_TOTAL.findall(text)
    if "Mac Address Table" not in text or not totals:
        raise unreadable("MAC address table")
    return int(totals[0])


def switchport(text: str, key: str) -> dict:
    name = SWITCHPORT_NAME.search(text)
    vlan = ACCESS_VLAN.search(text)
    mode = ADMIN_MODE.search(text)
    if name is None or vlan is None or mode is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    if name.group(1) != short_name(key):
        raise Rejected(["the switchport answer names another interface"])
    return {"mode": mode.group(1), "access-vlan": vlan.group(1)}


def vlan_exists(text: str, vlan: str) -> bool:
    missing = VLAN_MISSING.search(text)
    if missing is not None:
        if missing.group(1) != vlan:
            raise Rejected(["the VLAN answer names another VLAN"])
        return False
    for line in text.split("\n"):
        words = line.split()
        if words[:1] == [vlan] and len(words) >= 3:
            return True
    raise Rejected(["the answer about VLAN %s is not recognised" % vlan])


ADMIN_MODES = {"static access": "access", "trunk": "trunk", "trunk phone": "trunk phone"}
NATIVE_VLAN = re.compile(r"^Trunking Native Mode VLAN:\s*([0-9]+)\b", re.MULTILINE)
ALLOWED_VLANS = re.compile(r"^Trunking VLANs Enabled:\s*(\S+)\s*$", re.MULTILINE)
PHONE_VLAN = re.compile(r"^Phone VLAN:\s*([0-9]+)\s*$", re.MULTILINE)
DOT1X_HEADER = re.compile(r"^Dot1X Information for (\S+)\s*$", re.MULTILINE)
DOT1X_CONTROL = re.compile(r"^Port control:\s*(\S+)\s*$", re.MULTILINE)
DOT1X_MAB = re.compile(r"^MAC-based authentication:\s*(enabled|disabled)\s*$", re.MULTILINE)


def membership(text: str, key: str) -> dict:
    """eos switchport admin: the membership of the port as the check account reads it in show interfaces N switchport (measured: the
    phone VLAN is listed only in trunk phone mode, where EOS uses it)."""
    shown = switchport(text, key)
    native, allowed = NATIVE_VLAN.search(text), ALLOWED_VLANS.search(text)
    if shown["mode"] not in ADMIN_MODES or native is None or allowed is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key],
                       reason_codes=["port_usage_unreadable"])
    state = {"mode": ADMIN_MODES[shown["mode"]], "access-vlan": shown["access-vlan"], "native-vlan": native.group(1),
             "allowed-vlans": vlan_text(vlan_numbers(allowed.group(1).lower()))}
    phone = PHONE_VLAN.search(text)
    if phone is not None:
        state["voice-vlan"] = phone.group(1)
    return state


def dot1x_state(text: str, key: str) -> dict:
    """eos switchport admin: 802.1X and MAB of the port in show dot1x interface N; the answer is empty for a port without 802.1X."""
    if not text.strip():
        return {}
    header = DOT1X_HEADER.search(text)
    control, mab = DOT1X_CONTROL.search(text), DOT1X_MAB.search(text)
    if header is None or header.group(1) != key or control is None or mab is None:
        raise Rejected(["the 802.1X answer about %s is not recognised" % key], reason_codes=["port_usage_unreadable"])
    state = {"dot1x": "enabled" if control.group(1) == "auto" else "port-control " + control.group(1)}
    if mab.group(1) == "enabled":
        state["mab"] = "enabled"
    return state


def vlan_state(text: str, vlan: str):
    """eos switchport admin: name and state of a VLAN in show vlan id N; None when the VLAN does not exist. A VLAN without a name
    line shows its default name VLANnnnn (an explicit name VLANnnnn stores no name line, eos switchport admin r2)."""
    missing = VLAN_MISSING.search(text)
    if missing is not None:
        if missing.group(1) != vlan:
            raise Rejected(["the VLAN answer names another VLAN"])
        return None
    for line in text.split("\n"):
        words = line.split()
        if words[:1] == [vlan] and len(words) >= 3:
            state = {} if words[1] == default_vlan_name(vlan) else {"name": words[1]}
            if words[2] != "active":
                state["status"] = words[2]
            return state
    raise Rejected(["the answer about VLAN %s is not recognised" % vlan])


def description_row(text: str, key: str):
    """Status, protocol and description of show interfaces N description, or None for another layout."""
    columns, rows = table_rows(text, "Interface")
    if columns is None or [name for name, _ in columns] != ["Interface", "Status", "Protocol", "Description"]:
        return None
    start = columns[3][1]
    for row in rows:
        if row.split()[:1] == [short_name(key)]:
            return {"status": row[columns[1][1]:columns[2][1]].strip(), "description": row[start:].strip()}
    return None


def status_row(text: str, key: str):
    """The Status column of show interfaces N status, or None for another layout."""
    columns, rows = table_rows(text, "Port")
    if columns is None or [name for name, _ in columns][:3] != ["Port", "Name", "Status"]:
        return None
    start, end = columns[2][1], columns[3][1] if len(columns) > 3 else None
    for row in rows:
        if row.split()[:1] == [short_name(key)]:
            return row[start:end].strip()
    return None


def connected_ports(text: str) -> set:
    """Read the connected interfaces from the EOS status table."""
    columns, rows = table_rows(text, "Port")
    if columns is None or [name for name, _ in columns][:4] != ["Port", "Name", "Status", "Vlan"]:
        raise unreadable("interface status table")
    start, end = columns[2][1], columns[3][1]
    found = {}
    for row in rows:
        if not row.strip():
            continue
        name = row.split()[0]
        value = row[start:end].strip()
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*", name) or not value or name in found:
            raise unreadable("interface status table")
        found[name] = value
    return {name for name, status in found.items() if name.startswith(("Et", "Po")) and status == "connected"}


def users(text: str) -> tuple:
    """Own and other sessions of show users: rows that start with a line number, the own one marked '*'."""
    rows = [line for line in text.replace("\r", "").split("\n") if re.match(r"^[ *]\s+[0-9]+ ", line)]
    if "Line" not in text or "User" not in text:
        raise Rejected(["the session list is not readable"])
    own = sum(1 for row in rows if row.startswith("*"))
    return own, len(rows) - own


SESSION_PREFIX = "netops-"
SESSION_NAME = re.compile(r"^netops-[0-9a-f]{12}$")


# ---- 1.0.12 eos port maintenance: answers about speed, MTU, PoE and the link of a port ----

HARDWARE_SPEEDS = re.compile(r"^\s*Speed/duplex:\s*(\S+)\s*$", re.MULTILINE | re.IGNORECASE)
ETHERNET_MTU = re.compile(r"^\s*Ethernet MTU ([0-9]+) bytes", re.MULTILINE)
# measured on cEOS 4.36.1F over ssh exec (private measurement record): show poe, show poe interface N and the
# interface line "poe disabled" answer this on a switch without PoE hardware
POE_UNAVAILABLE = "% Unavailable command (not supported on this hardware platform)"
POE_HEADER = re.compile(r"^\s*Port\s+Enabled\s+Enabled\s+Limit\s+Power\s+State\s+Class\s+Power\s+Current\s+Voltage"
                        r"\s+Temperature\s*$", re.MULTILINE)


def hardware_speeds(text: str, key: str) -> set:
    """eos port maintenance (E23): the speed/duplex list of port key in show interfaces N hardware (EXEC; measured on cEOS 4.36.1F:
    "Speed/duplex: 10M/half,...,1G/full(default),..."; the Arista EOS manual writes "Speed/Duplex:" and lists "auto"
    for autonegotiation). "(default)" marks the default speed of the port."""
    blocks, current = {}, None
    for line in text.replace("\r", "").split("\n"):
        if not line.strip() or line.startswith(EXEC_ECHO):
            continue
        if not line.startswith(" "):
            current = line.strip()
            blocks.setdefault(current, [])
        elif current is not None:
            blocks[current].append(line)
    found = HARDWARE_SPEEDS.findall("\n".join(blocks.get(key, ())))
    if len(found) != 1:
        raise Rejected(["the hardware answer about %s is not recognised" % key], reason_codes=["port_usage_unreadable"])
    return {item.replace("(default)", "") for item in found[0].split(",") if item}


def speed_supported(value: str, speeds: set) -> bool:
    """Plain auto is accepted even when the hardware list omits it; explicit rates need advertised support."""
    words = _speed(value).split()

    def listed(capability):
        plain = re.sub(r"-[0-9]+/", "/", capability)
        return capability in speeds or plain in speeds

    if words[0] != SPEED_AUTO:
        return listed(FORCED_SPEEDS[words[0]])
    return len(words) == 1 or (SPEED_AUTO in speeds and listed(AUTO_SPEEDS[words[1]]))


def ethernet_mtu(text: str, key: str) -> int:
    """eos port maintenance (E23): the Ethernet MTU of show interfaces N; on cEOS a larger mtu is refused ("% Max MTU for Ethernet12
    is 9214", private measurement record)."""
    found = ETHERNET_MTU.findall(text)
    if re.search(r"^%s is " % re.escape(key), text, re.MULTILINE) is None or len(found) != 1:
        raise Rejected(["the interface answer about %s is not recognised" % key], reason_codes=["port_usage_unreadable"])
    return int(found[0])


def poe_unavailable(status: int, text: str) -> bool:
    return status != 0 and POE_UNAVAILABLE in text


def poe_state(text: str, key: str) -> dict:
    """eos port maintenance (E06/E07): PSE enabled and port state of show poe interface N. Layout of the Arista EOS manual (Ethernet
    Ports, show poe; fixtures/eos_g123/PROVENANCE.md): the two-row header names Port, PSE Enabled, LLDP Enabled, Power
    Limit, Granted Power, Port State, Class, Power, Current, Voltage and Temperature, the row starts with the port
    number. A port that the answer does not list or another layout is unreadable, never "no PoE"."""
    header = POE_HEADER.search(text)
    if header is None:
        raise Rejected(["the PoE answer about %s is not recognised" % key], reason_codes=["poe_state_unreadable"])
    number = key[len("Ethernet"):] if key.startswith("Ethernet") else key
    rows = [line.split() for line in text[header.end():].split("\n")
            if line.strip() and not set(line.strip()) <= {"-", " "} and not line.rstrip().endswith(("#", ">"))]
    match = [words for words in rows if words[0] in (number, short_name(key), key)]
    if len(match) != 1 or len(match[0]) != 11 or match[0][1] not in ("True", "False"):
        raise Rejected(["the PoE answer does not list port %s" % key], reason_codes=["poe_state_unreadable"])
    words = match[0]
    return {"configured": "enabled" if words[1] == "True" else "disabled", "state": words[5].lower(),
            "class": words[6], "power": words[7]}


def link_state(text: str, key: str) -> str:
    """eos port maintenance (E08): the Status column of show interfaces N status as the check account reads it (measured: connected,
    disabled after shutdown and connected again right after no shutdown on cEOS)."""
    status = status_row(text, key)
    if status is None or not status:
        raise Rejected(["the status answer about %s is not recognised" % key], reason_codes=["port_usage_unreadable"])
    return status
