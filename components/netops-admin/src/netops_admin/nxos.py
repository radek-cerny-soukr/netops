"""Cisco NX-OS plan adapter: interface description, admin state and access VLAN from show running-config.

Measured on a Nexus 9000v (N9K-C9300v) with NX-OS 9.3(12) (GNS3 lab, task netops-provoz-20261116-314/317,
ref/mereni-c6): the running configuration starts with the header "!Command: show running-config", the lines
"!Running configuration last done at:" and "!Time:", then "version 9.3(12) Bios:version". Top-level statements are
followed by their own lines indented by two spaces; blocks are separated by empty lines and the answer has no
closing "end". A scheduler job is closed by the top-level line "end-job". NX-OS accepts a VLAN that does not exist
without a warning (the port becomes inactive) and refuses a reserved VLAN (3968-4094) with an error without "%",
so the plan refuses both before anything is sent. mgmt0 would accept description and shutdown, so the plan never
changes it.
"""
from __future__ import annotations

import hashlib
import re

from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)

PLATFORM = "nxos"
COMMAND_LINE = "!Command: show running-config"
# lines of the header that change without a configuration change
VOLATILE_HEADER = ("!Command:", "!Running configuration last done at:", "!Time:")
VERSION_LINE = re.compile(r"^version ([0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}[a-z]?\))(?: Bios:.*)?$")
# fixed lines NX-OS prints in every running configuration after the interfaces; a cut-off answer misses them
REQUIRED_LINES = (re.compile(r"^interface mgmt0$"), re.compile(r"^line vty$"), re.compile(r"^boot nxos \S+"))
INDENT = "  "
ETHERNET = re.compile(r"^Ethernet[1-9][0-9]{0,2}/[1-9][0-9]{0,2}(?:/[1-9][0-9]{0,2})?$")
MANAGEMENT = re.compile(r"^mgmt[0-9]+$", re.IGNORECASE)
VLAN_HEADER = re.compile(r"^vlan ([0-9,-]+)$")
DEFAULT_VLAN = "1"
# VLAN 3968-4094 are reserved on NX-OS 9.3 ("invalid vlan (reserved value)", measured with 3999)
RESERVED_VLANS = range(3968, 4095)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$")),
    "vlan-membership": (re.compile(r"^(?:no )?switchport access vlan(?: [0-9]+)?$"),),
}
TRUNK = re.compile(r"^switchport (?:mode (?!access$)\S+|trunk )")
LAG = re.compile(r"^channel-group ")
ROUTED = re.compile(r"^no switchport$")
SAFEGUARD_PREFIX = "netops-"
SCHEDULER_BLOCK = re.compile(r"^scheduler (?:job|schedule) name (\S+)$")
JOB_END = "end-job"


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
    for line in text.replace("\r", "").split("\n"):
        match = VERSION_LINE.match(line.rstrip())
        if match is not None:
            return match.group(1)
    return None


def safeguard_label(change_id: str) -> str:
    """The name of the checkpoint, scheduler job, scheduler schedule and bootflash file of one operation."""
    return SAFEGUARD_PREFIX + change_id[:12]


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        lines = [line.rstrip() for line in text.replace("\r", "").split("\n")]
        filled = [line for line in lines if line.strip()]
        if not filled or filled[0] != COMMAND_LINE:
            raise SnapshotRejected(["snapshot does not start with %r; it is not an NX-OS running configuration"
                                    % COMMAND_LINE], SNAPSHOT_UNREADABLE)
        found = firmware_of(text)
        if found is None:
            raise SnapshotRejected(["snapshot does not name the NX-OS release in its version line"],
                                   SNAPSHOT_UNREADABLE)
        if not all(any(pattern.match(line) for line in filled) for pattern in REQUIRED_LINES):
            raise SnapshotRejected(["snapshot misses interface mgmt0, line vty or boot nxos; the running "
                                    "configuration is cut off"], SNAPSHOT_INCOMPLETE)
        if firmware and firmware != found:
            raise SnapshotRejected(["snapshot was taken on NX-OS %s, not on the configured %s" % (found, firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        self.firmware = found
        self.hostname = None
        self.inventory = None
        self.lines = filled
        self.blocks, self.interfaces, self.vlans, self.scheduler = [], {}, {DEFAULT_VLAN}, {}
        current = None
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            if line.startswith("!"):
                current = None
                continue
            if line.startswith(" "):
                if current is None:
                    raise SnapshotRejected(["line %d is indented outside any statement" % number],
                                           SNAPSHOT_UNREADABLE)
                current.children.append(line)
                continue
            if line == JOB_END and current is not None and current.header.startswith("scheduler job name "):
                current.children.append(line)
                current = None
                continue
            current = Block(line, number)
            self.blocks.append(current)
            words = line.split()
            if words[0] == "interface" and len(words) == 2:
                if words[1] in self.interfaces:
                    raise SnapshotRejected(["interface %s is listed twice" % words[1]], SNAPSHOT_UNREADABLE)
                self.interfaces[words[1]] = current
            elif words[0] == "hostname" and len(words) == 2:
                self.hostname = words[1]
            scheduled = SCHEDULER_BLOCK.match(line)
            if scheduled is not None:
                self.scheduler.setdefault(scheduled.group(1), []).append(current)
            vlan = VLAN_HEADER.match(line)
            if vlan is not None:
                self.vlans |= _vlan_list(vlan.group(1))
        if not self.hostname:
            raise SnapshotRejected(["snapshot does not name the device hostname"], SNAPSHOT_UNREADABLE)

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

    def safeguard_names(self) -> list:
        """Names of the scheduler jobs and schedules that start with the Admin prefix."""
        return sorted(name for name in self.scheduler if name.startswith(SAFEGUARD_PREFIX))

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        """The configuration without the volatile header, the planned lines of the interface and the scheduler job
        and schedule of the own safeguard (they exist while the operation runs and are removed afterwards)."""
        own = safeguard_label(safeguard_id) if safeguard_id else None
        kept, inside, skipping = [], False, False
        for line in self.lines:
            if line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                if skipping and line == JOB_END:
                    continue
                scheduled = SCHEDULER_BLOCK.match(line)
                skipping = scheduled is not None and scheduled.group(1) == own
                if skipping:
                    continue
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if skipping:
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
    return ["interface %s is not in the running configuration of the switch; the change is refused" % key]


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip():
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    raise Rejected(["NX-OS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    raise Rejected(["NX-OS %s objects are only updated" % profile.table])


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
    raise Rejected(["attribute %s is not known on NX-OS" % name])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure terminal, the interface, its lines and end.

    The lines run after Admin installed the safeguard (checkpoint and a one-time scheduler job that rolls the whole
    running configuration back to it); configure session cannot be used, because NX-OS 9.3(12) offers neither
    description, shutdown nor switchport under an interface of a session."""
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


def reserved_vlan(value) -> bool:
    return str(value).isdigit() and int(value) in RESERVED_VLANS


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    kind = interface_kind(key)
    if kind == "management":
        raise Rejected(["interface %s is the management interface; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only EthernetX/Y ports are changed" % key],
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
        if reserved_vlan(wanted):
            raise Rejected(["VLAN %s is reserved on NX-OS (3968-4094)" % wanted], reason_codes=["vlan_reserved"])
        if wanted not in snapshot.vlans:
            raise Rejected(["VLAN %s does not exist in the running configuration; NX-OS would accept it without an "
                            "error and leave the port inactive, so the change is refused" % wanted],
                           reason_codes=["vlan_missing"])
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


# ---- answers of the device (measured fixtures, ref/mereni-c6/fixtures) ----

ERROR_LINES = (
    re.compile(r"^% "),                       # Invalid command, Incomplete command, Permission denied, Invalid number
    re.compile(r"at '\^' marker\.$"),         # reserved VLAN, Invalid range (no "%")
    re.compile(r"^Error: "),                  # scheduler: delete job/schedule failed: schedule in progress
    re.compile(r"^ERROR: "),                  # rollback log
    re.compile(r"^Rollback failed"),          # rollback running-config checkpoint ... atomic
    re.compile(r"^Verification failed"),      # atomic rollback that was undone
    re.compile(r"^Config(?:ure)? [Rr]eplace (?:operation )?failed"),
    re.compile(r"No such file or directory"),
)


def cli_error(text: str):
    """A refused line: the measured error forms of NX-OS 9.3(12), with and without "%".

    A carriage return ends a line too: the interactive session writes "\r" before every prompt, also right after
    the last output line when that line has no newline (read in task 318)."""
    for line in re.split(r"[\r\n]", text)[1:]:
        stripped = line.strip()
        if any(pattern.search(stripped) for pattern in ERROR_LINES):
            return stripped[:100]
    return None


NXOS_VERSION = re.compile(r"^\s*NXOS: version (\S+)\s*$", re.MULTILINE)
CLOCK = re.compile(r"^([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)? (\S+) [A-Z][a-z]{2} ([A-Z][a-z]{2}) "
                   r"([0-9]{1,2}) ([0-9]{4})\s*$", re.MULTILINE)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
FEATURE = re.compile(r"^(\S+)\s+[0-9]+\s+(enabled|disabled)(?:\s.*)?$", re.MULTILINE)
VLAN_MISSING = re.compile(r"^VLAN ([0-9]+) not found in current VLAN database\s*$", re.MULTILINE)
ACCESS_VLAN = re.compile(r"^\s*Access Mode VLAN:\s*([0-9]+)\b", re.MULTILINE)
OPERATIONAL_MODE = re.compile(r"^\s*Operational Mode:\s*(\S+)\s*$", re.MULTILINE)
SWITCHPORT = re.compile(r"^\s*Switchport:\s*(\S+)\s*$", re.MULTILINE)
SWITCHPORT_NAME = re.compile(r"^Name:\s*(\S+)\s*$", re.MULTILINE)
MAC_ROW = re.compile(r"^[*G+ ]?\s*\S+\s+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\s", re.MULTILINE)
MAC_HEADER = re.compile(r"^\s*VLAN\s+MAC Address\s+Type", re.MULTILINE)
LLDP_HEADER = re.compile(r"^Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID\s*$", re.MULTILINE)
LLDP_TOTAL = re.compile(r"^Total entries displayed:\s*([0-9]+)\s*$", re.MULTILINE)
SHORT_PORT = re.compile(r"^(?:Eth[0-9]+/[0-9]+(?:/[0-9]+)?|mgmt[0-9]+|Po[0-9]+)$")


def short_name(key: str) -> str:
    """The abbreviation NX-OS prints in tables: Eth1/48 for Ethernet1/48."""
    return "Eth" + key[len("Ethernet"):] if key.startswith("Ethernet") else key


def unreadable(what: str):
    return Rejected(["the %s is not recognised" % what], reason_codes=["port_usage_unreadable"])


def nxos_version(text: str) -> str:
    found = NXOS_VERSION.findall(text)
    if len(found) != 1:
        raise Rejected(["the device does not report its NX-OS version"])
    return found[0]


def clock(text: str):
    """Hour, minute, second, zone, month, day and year of show clock (a leading NTP warning line is ignored)."""
    found = CLOCK.findall(text.replace("\r", ""))
    if len(found) != 1 or found[0][4] not in MONTHS:
        raise Rejected(["the device clock answer is not recognised"])
    hour, minute, second, zone, month, day, year = found[0]
    return int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute), int(second), zone


def feature_state(text: str, name: str):
    states = [state for feature, state in FEATURE.findall(text.replace("\r", "")) if feature == name]
    return states[0] if states and all(state == states[0] for state in states) else None


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


def switchport(text: str, key: str) -> dict:
    """Switchport state, operational mode and access VLAN of show interface N switchport."""
    name = SWITCHPORT_NAME.search(text)
    enabled = SWITCHPORT.search(text)
    mode = OPERATIONAL_MODE.search(text)
    vlan = ACCESS_VLAN.search(text)
    if name is None or enabled is None or mode is None or vlan is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    if name.group(1) != key:
        raise Rejected(["the switchport answer names another interface"])
    return {"switchport": enabled.group(1), "mode": mode.group(1), "access-vlan": vlan.group(1)}


def table_rows(text: str, first_column: str) -> tuple:
    """Header column positions and the rows of the first fixed-width table whose header starts with first_column."""
    lines = text.replace("\r", "").split("\n")
    for index, line in enumerate(lines):
        if line.startswith(first_column + " "):
            columns = [(match.group(0), match.start()) for match in re.finditer(r"\S+", line)]
            rows = []
            for row in lines[index + 1:]:
                if not row.strip():
                    if rows:
                        break
                    continue
                if set(row.strip()) <= {"-", " "}:
                    continue
                rows.append(row)
            return columns, rows
    return None, None


def status_row(text: str, key: str):
    """Name, Status and Vlan columns of show interface N status, or None for another layout."""
    columns, rows = table_rows(text, "Port")
    if columns is None or [name for name, _ in columns][:4] != ["Port", "Name", "Status", "Vlan"]:
        return None
    starts = [start for _, start in columns]
    for row in rows:
        if row.split()[:1] == [short_name(key)]:
            return {"name": row[starts[1]:starts[2]].strip(), "status": row[starts[2]:starts[3]].strip(),
                    "vlan": row[starts[3]:starts[4]].strip() if len(starts) > 4 else row[starts[3]:].strip()}
    return None


def description_row(text: str, key: str):
    """The description of the port in show interface description (the Port/Type/Speed/Description table), "" for
    "--", or None when the port is not listed."""
    lines = text.replace("\r", "").split("\n")
    header = None
    for index, line in enumerate(lines):
        if line.split()[:4] == ["Port", "Type", "Speed", "Description"]:
            header = index
            break
    if header is None:
        return None
    start = lines[header].index("Description")
    for row in lines[header + 1:]:
        if row.split()[:1] == [short_name(key)]:
            if len(row.split()) < 4:
                return None
            value = row[start:].strip() if len(row) > start and row[start - 1] == " " else " ".join(row.split()[3:])
            return "" if value == "--" else value
    return None


def trunk_ports(text: str) -> set:
    """Ports listed in show interface trunk (the first column of its tables)."""
    if not re.search(r"^Port\s+Native\s+Status\s+Port\s*$", text, re.MULTILINE):
        raise unreadable("trunk list")
    found = set()
    for line in text.replace("\r", "").split("\n"):
        words = line.split()
        if words and SHORT_PORT.match(words[0]):
            found.add(words[0])
    return found


def lldp_ports(text: str) -> set:
    """Local ports with an LLDP neighbor (measured layout Device ID, Local Intf, Hold-time, Capability, Port ID;
    a long device ID is printed on its own line and the rest of the row on the next)."""
    header = LLDP_HEADER.search(text)
    total = LLDP_TOTAL.search(text)
    if header is None or total is None:
        raise unreadable("LLDP neighbor list")
    found, count = set(), 0
    for line in text[header.end():total.start()].split("\n"):
        words = line.split()
        if not words:
            continue
        local = [word for word in words[:2] if SHORT_PORT.match(word)]
        if not local:
            if len(words) == 1:
                continue  # a long device ID; the next line holds the local port
            raise unreadable("LLDP neighbor list")
        found.add(local[0])
        count += 1
    if count != int(total.group(1)):
        raise unreadable("LLDP neighbor list")
    return found


def learned_macs(text: str) -> int:
    """Rows of show mac address-table interface N (0 when only the legend and the header are printed)."""
    if MAC_HEADER.search(text) is None:
        raise unreadable("MAC address table")
    return len(MAC_ROW.findall(text))


def users(text: str) -> tuple:
    """Own and other sessions of show users: the own row ends with '*'."""
    lines = text.replace("\r", "").split("\n")
    if not lines or not any(line.split()[:2] == ["NAME", "LINE"] for line in lines):
        raise Rejected(["the session list is not readable"])
    rows = [line for line in lines if line.strip() and line.split()[:2] != ["NAME", "LINE"]]
    own = sum(1 for row in rows if row.rstrip().endswith("*"))
    return own, len(rows) - own


def user_accounts(text: str) -> list:
    """The user names of show user-account (lines user:NAME)."""
    return sorted(match.group(1) for match in re.finditer(r"^user:(\S+)\s*$", text, re.MULTILINE))
