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
import re

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
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$")),
    "vlan-membership": (re.compile(r"^(?:no )?switchport access vlan(?: [0-9]+)?$"),),
}
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
        self.hostname = None
        self.inventory = None
        start = next(index for index, line in enumerate(lines) if line.strip() == BUILDING)
        lines = lines[start:]
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
        for line in self.lines:
            if line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if inside and line.startswith(INDENT) and not line.startswith(INDENT + " ") \
                    and any(pattern.match(line.strip()) for pattern in OWN_LINES.get(table, ())):
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
    return ["interface %s is not in the running configuration; the change is refused" % key]


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip():
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    raise Rejected(["IOS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    raise Rejected(["IOS %s objects are only updated" % profile.table])


def _line(name: str, value) -> str:
    if name == "description":
        return "no description" if value is None else "description %s" % _text(value)
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return "shutdown" if value == "disabled" else "no shutdown"
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
    lines = [_line(name, value) for name, value in sorted(assign.items())]
    lines += [_line(name, None) for name in sorted(remove)]
    if not lines:
        return []
    return ["configure terminal", "interface %s" % key] + lines + ["end"]


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
    return table == "vlan-membership" and before.get("access-vlan", DEFAULT_VLAN) != after.get("access-vlan",
                                                                                                DEFAULT_VLAN)


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
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
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of a port-channel; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        if any(TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk or negotiates trunking; it is treated as an uplink and is not "
                            "changed" % key], reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
        addressed = snapshot.addressed(key)
        if addressed:
            raise Rejected(["interface %s carries an IPv4 address (%s); an interface in use for routing is not "
                            "changed" % (key, ", ".join(addressed))], reason_codes=["port_ip_address"])
    if profile.table == "vlan-membership":
        wanted = str((after or {}).get("access-vlan", DEFAULT_VLAN))
        if wanted in RESERVED_VLANS:
            raise Rejected(["VLAN %s is a reserved VLAN (1002-1005), not an Ethernet access VLAN" % wanted],
                           reason_codes=["vlan_reserved"])
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


# ---- answers of the device (measured fixtures, ref/mereni-c4c5/fixtures) ----

def cli_error(text: str):
    """A refused line of the interactive session: an IOS error starts with "% " (with a space), for example
    "% Invalid input detected at '^' marker." and the warning "% Access VLAN does not exist. Creating vlan N", which
    IOS performs anyway. "%No Rollback Confirmed Change pending" (no space) is information. A second revert timer
    is refused with "%Rollback Confirmed Change is already activated on a config"."""
    for line in text.replace("\r", "").split("\n")[1:]:
        stripped = line.strip()
        if stripped.startswith("% ") or stripped.startswith(ALREADY_ACTIVE) or stripped.startswith("%Archive") \
                or stripped.startswith("%Rollback"):
            return stripped[:100]
    return None


ALREADY_ACTIVE = "%Rollback Confirmed Change is already activated"
NO_PENDING = "%No Rollback Confirmed Change pending"
PRIVILEGE = re.compile(r"^Current privilege level is ([0-9]+)\s*$", re.MULTILINE)
VERSION_LINE = re.compile(r"^Cisco IOS Software(?P<xe> \[IOSXE\])?, (?P<family>[^(,]+?)? ?Software "
                          r"\((?P<image>[^)]+)\), (?:Experimental )?Version (?P<version>[^ ,]+)", re.MULTILINE)
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
    match = VERSION_LINE.search(text)
    if match is None:
        raise Rejected(["the device does not report its IOS software version"])
    return {"xe": match.group("xe") is not None, "image": match.group("image"), "version": match.group("version"),
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


def description_row(text: str, key: str):
    """Status and description of show interfaces description (Interface, Status, Protocol, Description); the
    columns are taken by the header positions, because the status "admin down" holds a space."""
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.startswith("Interface ")), None)
    if header is None or header.split() != ["Interface", "Status", "Protocol", "Description"]:
        return None
    status, protocol, start = header.index("Status"), header.index("Protocol"), header.index("Description")
    for row in lines[lines.index(header) + 1:]:
        if row.split()[:1] == [short_name(key)]:
            return {"status": row[status:protocol].strip(), "description": row[start:].strip()}
    return None


def lldp_ports(text: str) -> set:
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
    found = set()
    for line in lines[lines.index(header) + 1:]:
        if not line.strip() or line.startswith("Total entries displayed"):
            continue
        local = line[start:end].strip()
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", local):
            raise unreadable("LLDP neighbor list")
        found.add(local)
    return found


def cdp_ports(text: str) -> set:
    """Local ports with a CDP neighbor (Gig 0/0, Eth 0/1); a long Device ID stands on its own line."""
    stripped = text.strip()
    if stripped.startswith("% CDP is not enabled"):
        return set()
    lines = text.replace("\r", "").split("\n")
    header = next((line for line in lines if line.startswith("Device ID") and "Local Intrfce" in line), None)
    if header is None or "Total cdp entries displayed" not in text:
        raise unreadable("CDP neighbor list")
    start, end = header.index("Local Intrfce"), header.index("Holdtme")
    found = set()
    for line in lines[lines.index(header) + 1:]:
        if not line.strip() or line.startswith("Total cdp entries"):
            continue
        if len(line.split()) == 1 and not line.startswith(" "):
            continue  # a long Device ID on its own line; its columns follow on the next line
        if len(line.rstrip()) <= start or not line[start:end].strip():
            continue
        local = line[start:end].strip().replace(" ", "")
        if not re.fullmatch(r"[A-Za-z]+[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", local):
            raise unreadable("CDP neighbor list")
        found.add(local)
    return found


def learned_macs(text: str, key: str) -> int:
    """Unicast MAC addresses of the port in show mac address-table interface N (rows with a VLAN number)."""
    if "Mac Address Table" not in text:
        raise unreadable("MAC address table")
    return sum(1 for _vlan, port in MAC_ROW.findall(text) if port == short_name(key))


def switchport(text: str, key: str):
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
    if vlan is None or mode is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    return {"mode": mode.group(1), "access-vlan": vlan.group(1)}


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
