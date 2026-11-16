"""Arista EOS plan adapter: interface description, admin state and access VLAN from show running-config.

Measured on cEOSLab 4.36.1F (task netops-provoz-20261116-301, ref/c7-mereni): the running configuration is a
flat list of top-level statements, each followed by its own lines indented by three spaces and closed by a
line "!". The answer starts with "! Command: show running-config" and the device line, and ends with "end".
EOS creates a missing VLAN or interface without an error ("! Access VLAN does not exist. Creating vlan N",
"! Interface does not exist"), so the plan refuses both before anything is sent.
"""
from __future__ import annotations

import hashlib
import re

from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)

PLATFORM = "eos"
COMMAND_LINE = "! Command: show running-config"
# measured over ssh exec (task 304): the answer starts with the echo "> show running-config" and the header
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
DEFAULT_VLAN = "1"
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$")),
    "vlan-membership": (re.compile(r"^(?:no )?switchport access vlan(?: [0-9]+)?$"),),
}
TRUNK = re.compile(r"^switchport (?:mode (?!access$)\S+|trunk )")
LAG = re.compile(r"^channel-group ")
ROUTED = re.compile(r"^no switchport$")


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
        self.lines = [line.rstrip() for line in lines if line.strip()]
        self.blocks, self.interfaces, self.vlans = [], {}, {DEFAULT_VLAN}
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
                self.vlans |= _vlan_list(vlan.group(1))

    def entries(self, table: str):
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
            elif table == "vlan-membership" and line.startswith("switchport access vlan "):
                _once(entry, "access-vlan", line.split()[-1], block)
        return entry

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        return []

    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        block = self.interfaces.get(key)
        return [] if block is None else [child.strip() for child in block.children]

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        kept, inside = [], False
        for line in self.lines:
            if line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if inside and any(pattern.match(line.strip()) for pattern in OWN_LINES.get(table, ())):
                continue
            kept.append(line)
        return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


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


def render_create(profile, key: str, attributes: dict) -> list:
    raise Rejected(["EOS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    raise Rejected(["EOS %s objects are only updated" % profile.table])


def _line(name: str, value) -> str:
    if name == "description":
        return "no description" if value is None else "description %s" % _text(value)
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return "shutdown" if value == "disabled" else "no shutdown"
    if name == "access-vlan":
        if value is None or value == DEFAULT_VLAN:
            return "no switchport access vlan"
        if not str(value).isdigit():
            raise Rejected(["access-vlan must be a VLAN number"])
        return "switchport access vlan %s" % value
    raise Rejected(["attribute %s is not known on EOS" % name])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure terminal, the interface, its lines and end.

    The lines run under the safeguard session that Admin opened before (configure session with commit timer); a
    commit timer that expires returns the whole running configuration to the checkpoint of that session."""
    lines = [_line(name, value) for name, value in sorted(assign.items())]
    lines += [_line(name, None) for name in sorted(remove)]
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
        return after.get("admin-state", "enabled") != before.get("admin-state", "enabled")
    return table == "vlan-membership" and before.get("access-vlan", DEFAULT_VLAN) != after.get("access-vlan",
                                                                                                DEFAULT_VLAN)


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    kind = interface_kind(key)
    if kind == "management":
        raise Rejected(["interface %s is a management interface; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only EthernetN ports are changed" % key],
                       reason_codes=["port_unsupported_interface"])
    lines = snapshot.interface_lines(key)
    before = snapshot._entry(profile.table, key, snapshot.interfaces[key]).attributes if key in snapshot.interfaces \
        else {}
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of a port-channel; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        if any(TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk; a trunk is treated as an uplink and is not changed" % key],
                           reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
    if profile.table == "vlan-membership":
        wanted = (after or {}).get("access-vlan", DEFAULT_VLAN)
        if wanted not in snapshot.vlans:
            raise Rejected(["VLAN %s does not exist in the running configuration; EOS would create it without an "
                            "error, so the change is refused" % wanted], reason_codes=["vlan_missing"])
    return []


def snapshot_after(text: str, plan) -> str:
    """The running configuration with the planned state of the interface lines (for the audit prediction)."""
    key, table, state = plan["key"], plan["table"], plan["predicted"]["after"] or {}
    own = OWN_LINES.get(table, ())
    result, inside = [], False
    for line in text.replace("\r", "").split("\n"):
        if line and not line.startswith(" "):
            if inside:
                result.extend(INDENT + _line(name, value) for name, value in sorted(state.items()))
            inside = line.rstrip() == "interface %s" % key
            result.append(line)
            continue
        if inside and line.strip() and any(pattern.match(line.strip()) for pattern in own):
            continue
        result.append(line)
    return "\n".join(result)


# ---- answers of the device (measured fixtures, ref/c7-mereni/fixtures) ----

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
VLAN_MISSING = re.compile(r"^% VLAN ([0-9]+) not found in current VLAN database\s*$", re.MULTILINE)


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


def users(text: str) -> tuple:
    """Own and other sessions of show users: rows that start with a line number, the own one marked '*'."""
    rows = [line for line in text.replace("\r", "").split("\n") if re.match(r"^[ *]\s+[0-9]+ ", line)]
    if "Line" not in text or "User" not in text:
        raise Rejected(["the session list is not readable"])
    own = sum(1 for row in rows if row.startswith("*"))
    return own, len(rows) - own


SESSION_PREFIX = "netops-"
SESSION_NAME = re.compile(r"^netops-[0-9a-f]{12}$")
