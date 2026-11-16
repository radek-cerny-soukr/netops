"""Juniper Junos ELS plan adapter: interface description, admin state and access VLAN from the set-format
configuration (show configuration | display set).

Measured on vJunos-switch 26.2R1.7 (ELS, model ex9214; task netops-provoz-20261116-308, ref/mereni-c8): the
configuration is a flat list of "set ..." statements and starts with "set version <release>". A description with
a space is quoted ("description \"a b\""), without a space it is shown bare. Junos accepts the configuration of an
interface that does not exist (set interfaces ge-0/0/99 description ... is taken without an error) and checks a
VLAN given by name only at commit time, so the plan relies on the device reads of the execution adapter for both.
Interfaces are implicit keys: an unconfigured port is not in the configuration at all, its state is the default.
"""
from __future__ import annotations

import hashlib
import re

from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)

PLATFORM = "junos"
VERSION = re.compile(r"^set version (\S+)$")
HOST_NAME = re.compile(r"^set system host-name (\S+)$")
STATEMENT = re.compile(r"^(?:set|deactivate|protect) \S")
INTERFACE_LINE = re.compile(r"^(set|deactivate|protect) interfaces (\S+)(?: (.*))?$")
PHYSICAL = re.compile(r"^(?:ge|xe|et|mge)-[0-9]{1,2}/[0-9]{1,2}/[0-9]{1,3}$")
MANAGEMENT = re.compile(r"^(?:fxp|em|me|vme)[0-9]+(?:\.[0-9]+)?$")
DEFAULT_VLAN = "default"
SWITCHING = "unit 0 family ethernet-switching"
MEMBERS = SWITCHING + " vlan members"
ACCESS_MODE = SWITCHING + " interface-mode access"
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
VLAN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
# the change commit: Junos restarts the timer of the pending commit confirmed with every commit confirmed, so the
# change itself is committed with the same timer; 10 minutes is the device default of commit confirmed and the
# shortest timer that leaves room for two commits of up to 150 s, the readback and the confirmation (see
# exec_junos.py); the configuration requires safeguard_seconds = 600 for Junos devices
CONFIRM_MINUTES = 10
CHANGE_COMMENT = "netops-change"
CHANGE_COMMIT = 'commit confirmed %d comment "%s"' % (CONFIRM_MINUTES, CHANGE_COMMENT)
# first line of every interactive session: without a terminal width (the pty of Admin has none, so Junos takes 80
# columns) Junos scrolls a longer input line and redraws the prompt with the host name in the middle of the echo,
# which ends the line early for a prompt reader (measured in task 319: the echo of a 96-character line holds three
# redrawn prompts; with this session setting the echo stays one line). It sets the CLI session only, not the
# configuration.
SCREEN = "set cli screen-width 1024"
ENTER = "configure exclusive"
# must be empty: someone else's uncommitted change is never committed together with the planned one
COMPARE_EMPTY = "show | compare | no-more"
# shows the planned difference in the session transcript; it judges nothing
COMPARE = "show | compare"
LEAVE = "exit configuration-mode"
OWN_LINES = {
    "interface": (re.compile(r"^description(?: |$)"), re.compile(r"^disable$")),
    "vlan-membership": (re.compile(r"^" + re.escape(MEMBERS) + r"(?: |$)"),),
}
TRUNK = re.compile(r"^" + re.escape(SWITCHING) + r" interface-mode (?!access$)\S+")
LAG = re.compile(r"^(?:ether|gigether)-options 802\.3ad(?: |$)")
ROUTED = re.compile(r"^unit [0-9]+ family (?:inet|inet6|mpls|iso)(?: |$)")


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


def firmware_of(text: str):
    for line in text.replace("\r", "").split("\n"):
        match = VERSION.match(line.strip())
        if match is not None:
            return match.group(1)
    return None


def unquoted(value: str):
    """The value of a set statement: bare, or in double quotes without an escape (anything else is None)."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        inner = value[1:-1]
        return None if '"' in inner or "\\" in inner else inner
    return None if not value or '"' in value or "\\" in value or " " in value else value


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        raw = text.replace("\r", "")
        lines = [line.rstrip() for line in raw.split("\n")]
        filled = [line for line in lines if line.strip()]
        if not filled or any(line.startswith(("error:", "syntax error", "unknown command")) for line in filled):
            raise SnapshotRejected(["snapshot is empty or an error answer; it is not a Junos configuration"],
                                   SNAPSHOT_UNREADABLE)
        if VERSION.match(filled[0]) is None:
            raise SnapshotRejected(["snapshot does not start with 'set version'; it is not the set-format Junos "
                                    "configuration"], SNAPSHOT_UNREADABLE)
        strange = [number for number, line in enumerate(filled, 1) if STATEMENT.match(line) is None]
        if strange:
            raise SnapshotRejected(["line %d is not a set statement" % strange[0]], SNAPSHOT_UNREADABLE)
        if not raw.endswith("\n"):
            raise SnapshotRejected(["snapshot does not end with a line break; the configuration is cut off"],
                                   SNAPSHOT_INCOMPLETE)
        found = VERSION.match(filled[0]).group(1)
        if firmware and firmware != found:
            raise SnapshotRejected(["snapshot was taken on Junos %s, not on the configured %s" % (found, firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        self.firmware = found
        self.inventory = None
        self.lines = filled
        self.hostname = None
        self.vlans = {DEFAULT_VLAN}
        self.interfaces = {}
        self.deactivated = set()
        self.groups = False
        self.ranges = []
        for line in filled:
            host = HOST_NAME.match(line)
            if host is not None:
                self.hostname = host.group(1)
            words = line.split()
            if words[:2] == ["set", "vlans"] and len(words) >= 3:
                self.vlans.add(words[2])
            if words[:2] == ["set", "groups"] and " interfaces " in line:
                self.groups = True
            match = INTERFACE_LINE.match(line)
            if match is None:
                continue
            verb, name, rest = match.group(1), match.group(2), match.group(3) or ""
            if name == "interface-range":
                self.ranges.append(rest)
                continue
            if verb != "set":
                self.deactivated.add(name)
                continue
            self.interfaces.setdefault(name, []).append(rest)

    def entries(self, table: str):
        if table not in OWN_LINES:
            return None
        return {name: self._entry(table, name) for name in self.interfaces}

    def _entry(self, table, name):
        entry = Entry(name)
        lines = self.interfaces.get(name, [])
        # the members of a trunk are not an access VLAN; the plan refuses a trunk with its own reason code
        trunk = any(TRUNK.match(rest) for rest in lines)
        for rest in lines:
            if table == "interface" and rest.startswith("description "):
                value = unquoted(rest[len("description "):])
                if value is None:
                    entry.unsupported.append("description with quotes or escapes")
                else:
                    _once(entry, "description", value)
            elif table == "interface" and rest == "disable":
                _once(entry, "admin-state", "disabled")
            elif table == "vlan-membership" and rest.startswith(MEMBERS + " ") and not trunk:
                value = rest[len(MEMBERS) + 1:]
                if VLAN_NAME.fullmatch(value) is None:
                    entry.unsupported.append("VLAN member %s is not a VLAN name" % value[:20])
                else:
                    _once(entry, "access-vlan", value)
        entry.unsupported.extend(self.shared_configuration(name))
        return entry

    def shared_configuration(self, name) -> list:
        """Configuration that can reach the interface from elsewhere: Admin does not evaluate it."""
        found = []
        if name in self.deactivated:
            found.append("deactivated or protected statement")
        if self.groups:
            found.append("configuration groups for interfaces")
        for rest in self.ranges:
            words = rest.split()
            if words[1:3] == ["member", name] or words[1:2] == ["member-range"]:
                found.append("interface-range")
                break
        return found

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        return []

    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        return list(self.interfaces.get(key, []))

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        own = OWN_LINES.get(table, ())
        kept = []
        prefix = "set interfaces %s " % key
        for line in self.lines:
            if line.startswith(prefix) and any(pattern.match(line[len(prefix):]) for pattern in own):
                continue
            kept.append(line)
        return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def _once(entry, name, value):
    if name in entry.attributes:
        entry.unsupported.append("repeated %s" % name)
    entry.attributes[name] = value


def load(text: str, firmware: str | None) -> Snapshot:
    try:
        return Snapshot(text, firmware)
    except SnapshotRejected:
        raise
    except Exception as exc:
        raise SnapshotRejected(["snapshot does not parse: %s" % type(exc).__name__], SNAPSHOT_UNREADABLE) from None


def absent(snapshot, table: str, key: str) -> list:
    return ["interface %s is not in the configuration" % key]


def render_create(profile, key: str, attributes: dict) -> list:
    raise Rejected(["Junos %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    raise Rejected(["Junos %s objects are only updated" % profile.table])


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip() or '"' in value or "\\" in value or "?" in value:
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def _lines(key: str, name: str, value) -> list:
    base = "interfaces %s" % key
    if name == "description":
        return ["delete %s description" % base] if value is None else [
            'set %s description "%s"' % (base, _text(value))]
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return ["set %s disable" % base] if value == "disabled" else ["delete %s disable" % base]
    if name == "access-vlan":
        vlan = DEFAULT_VLAN if value is None else str(value)
        if VLAN_NAME.fullmatch(vlan) is None:
            raise Rejected(["access-vlan must be a VLAN name"])
        # set ... vlan members adds a member (measured: members [ default D3999 ]), so the old one is deleted first
        return ["delete %s %s" % (base, MEMBERS), "set %s %s %s" % (base, MEMBERS, vlan)]
    raise Rejected(["attribute %s is not known on Junos" % name])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure exclusive, an empty candidate, the set and delete lines, the
    difference and the commit confirmed that restarts the timer of the safeguard (exec_junos.py)."""
    lines = [line for name, value in sorted(assign.items()) for line in _lines(key, name, value)]
    lines += [line for name in sorted(remove) for line in _lines(key, name, None)]
    if not lines:
        return []
    return [SCREEN, ENTER, COMPARE_EMPTY] + lines + [COMPARE, CHANGE_COMMIT, LEAVE]


def interface_kind(key: str) -> str:
    if MANAGEMENT.fullmatch(key):
        return "management"
    if PHYSICAL.fullmatch(key):
        return "ethernet"
    return "other"


def disruptive(table: str, before, after) -> bool:
    """A change that can cut or restore traffic on the port: admin state in either direction or another access VLAN.

    Enabling a disabled uplink or LAG member can bring back a loop, so admin up gets the same port checks as admin
    down; the description alone does not."""
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
        raise Rejected(["interface %s is not a physical Ethernet port; only ge-, xe-, et- and mge- ports are changed"
                        % key], reason_codes=["port_unsupported_interface"])
    shared = snapshot.shared_configuration(key)
    if shared:
        raise Rejected(["object %r holds configuration outside the profile: %s" % (key, ", ".join(shared))])
    lines = snapshot.interface_lines(key)
    before = snapshot._entry(profile.table, key).attributes
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of an aggregated Ethernet interface; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        if any(TRUNK.match(line) for line in lines):
            raise Rejected(["port %s is a trunk; a trunk is treated as an uplink and is not changed" % key],
                           reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
    if profile.table == "vlan-membership":
        if ACCESS_MODE not in lines:
            raise Rejected(["port %s is not configured as an access port (%s)" % (key, ACCESS_MODE)],
                           reason_codes=["port_not_access"])
        wanted = (after or {}).get("access-vlan", DEFAULT_VLAN)
        if wanted not in snapshot.vlans:
            raise Rejected(["VLAN %s is not in the configuration; Junos checks a VLAN name only at commit time, so "
                            "the change is refused" % wanted], reason_codes=["vlan_missing"])
    return []


def snapshot_after(text: str, plan) -> str:
    """The set-format configuration with the planned state of the interface (for the audit prediction)."""
    key, table, state = plan["key"], plan["table"], plan["predicted"]["after"] or {}
    own = OWN_LINES.get(table, ())
    prefix = "set interfaces %s " % key
    kept = [line for line in text.replace("\r", "").split("\n")
            if line.strip() and not (line.startswith(prefix) and any(pattern.match(line[len(prefix):])
                                                                     for pattern in own))]
    added = []
    for name, value in sorted(state.items()):
        added += [line for line in _lines(key, name, value) if line.startswith("set ")]
    if table == "vlan-membership" and "access-vlan" not in state and (prefix + ACCESS_MODE) in kept:
        added.append(prefix + MEMBERS + " " + DEFAULT_VLAN)
    return "\n".join(kept + added) + "\n"


# ---- answers of the device (measured fixtures, ref/mereni-c8/fixtures) ----

BANNER = re.compile(r"^# commit confirmed will be rolled back in ")
PROMPT_TAIL = re.compile(r"^\S+@\S+[>#] ?$")
CONTEXT = re.compile(r"^\[edit(?: [^\]]*)?\]$")
ERROR = re.compile(r"^(?:error:|syntax error|unknown command|missing argument|invalid |ambiguous )", re.IGNORECASE)
DISCARD_WARNING = "warning: uncommitted changes will be discarded on exit"
NOT_FOUND_WARNING = "warning: statement not found"
FOREIGN_EDITORS = "Users currently editing the configuration"
FOREIGN_CHANGES = "The configuration has been changed but not committed"


def _body(text: str) -> tuple:
    """The echoed command and the answer rows of one interactive line, without the context line, the pending banner
    and the prompt that ends the answer."""
    rows = [row.rstrip() for row in re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "").split("\n")]
    echo = rows[0].strip() if rows else ""
    body = [row for row in rows[1:] if row.strip() and not BANNER.match(row.strip())
            and not CONTEXT.match(row.strip()) and not PROMPT_TAIL.match(row.strip())]
    return echo, body


def cli_error(text: str):
    """A refused line of the interactive session (the first row is the echo of the sent line).

    Measured: an error starts with "error:", "syntax error" or "unknown command" (an unknown word is marked by a
    caret row); a commit succeeded only with the row "commit complete" (a conflict answers with a warning and no
    commit); configure exclusive enters with one known warning; the shared configure and configure exclusive list
    other users in configuration mode and announce someone else's uncommitted change."""
    echo, body = _body(text)
    words = echo.split()
    for row in body:
        stripped = row.strip()
        if ERROR.match(stripped) or set(stripped) == {"^"}:
            return stripped[:100]
        if stripped.startswith(FOREIGN_EDITORS) or stripped.startswith(FOREIGN_CHANGES):
            return stripped[:100]
        if stripped.startswith("warning:"):
            if words[:2] == ["configure", "exclusive"] and stripped == DISCARD_WARNING:
                continue
            if words[:1] == ["delete"] and stripped == NOT_FOUND_WARNING:
                continue
            return stripped[:100]
    if words[:1] == ["commit"] and "commit complete" not in [row.strip() for row in body]:
        return "the commit did not answer 'commit complete'"
    if words[:1] == ["configure"] and "Entering configuration mode" not in [row.strip() for row in body]:
        return "configuration mode was not entered"
    if echo == SCREEN and body != ["Screen width set to 1024"]:
        return "the CLI screen width was not set"
    if echo == COMPARE_EMPTY and body:
        return "the candidate configuration holds uncommitted changes"
    return None


def answer_rows(text: str) -> list:
    """Rows of an exec answer without blank rows and without the banner of a pending commit confirmed."""
    return [row.rstrip() for row in text.replace("\r", "").split("\n")
            if row.strip() and not BANNER.match(row.strip())]


def refused_answer(text: str):
    for row in answer_rows(text):
        if ERROR.match(row.strip()):
            return row.strip()[:100]
    return None


RUNNING = re.compile(r"^Junos: (\S+)\s*$", re.MULTILINE)
CLI_USER = re.compile(r"^Current user: '([^']+)' class '([^']+)'\s*$", re.MULTILINE)
COMMIT_ROW = re.compile(r"^([0-9]+)\s+([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) UTC by (\S+) via (\S+)"
                        r"(?: (commit confirmed), rollback in ([0-9]+)mins)?\s*$")
MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.IGNORECASE)


def unreadable(what: str):
    return Rejected(["the %s is not recognised" % what], reason_codes=["port_usage_unreadable"])


def running_version(text: str) -> str:
    found = RUNNING.findall(text.replace("\r", ""))
    if len(found) != 1:
        raise Rejected(["the device does not report its Junos release"])
    return found[0]


def authorization(text: str) -> tuple:
    """Login, class and permission words of show cli authorization."""
    match = CLI_USER.search(text.replace("\r", ""))
    if match is None:
        raise Rejected(["the authorization of the write account is not readable"])
    words = set()
    for row in text.replace("\r", "").split("\n"):
        found = re.match(r"^\s{2,}([a-z][a-z-]*)\s*--", row)
        if found is not None:
            words.add(found.group(1))
    return match.group(1), match.group(2), words


class Commit:
    def __init__(self, index, at, user, via, confirmed, minutes):
        self.index, self.at, self.user, self.via = index, at, user, via
        self.confirmed, self.minutes = confirmed, minutes
        self.comment = None
        self.pending = False


def commits(text: str) -> list:
    """The commit history of show system commit, newest first: time (UTC), user, client, commit confirmed with its
    minutes, comment (the first indented row) and the row "rollback pending" of an unconfirmed commit confirmed."""
    found = []
    for row in text.replace("\r", "").split("\n"):
        if not row.strip() or BANNER.match(row.strip()):
            continue
        match = COMMIT_ROW.match(row)
        if match is not None:
            index = int(match.group(1))
            if index != len(found):
                raise Rejected(["the commit history is not numbered from 0"])
            found.append(Commit(index, match.group(2), match.group(3), match.group(4), bool(match.group(5)),
                                int(match.group(6)) if match.group(6) else None))
            continue
        if not row.startswith("    ") or not found:
            raise Rejected(["the commit history row %r is not recognised" % row.strip()[:40]])
        if row.strip() == "rollback pending":
            found[-1].pending = True
        elif found[-1].comment is None and not found[-1].pending:
            found[-1].comment = row.strip()
        else:
            raise Rejected(["the commit history holds an unexpected row"])
    if not found:
        raise Rejected(["the commit history is empty or not readable"])
    if any(commit.pending for commit in found[1:]):
        raise Rejected(["the commit history shows a pending rollback below the newest commit"])
    return found


def interface_row(text: str, key: str):
    """Admin and link state of the physical interface in show interfaces <if> terse (None for another answer)."""
    rows = answer_rows(text)
    if not rows or rows[0].split()[:3] != ["Interface", "Admin", "Link"]:
        return None
    for row in rows[1:]:
        words = row.split()
        if words[:1] == [key] and len(words) >= 3:
            return {"admin": words[1], "link": words[2]}
    return None


def description_of(text: str, key: str):
    """The description of the interface in show interfaces descriptions ("" when the interface is not listed: Junos
    lists only interfaces with a description; an empty answer means that no interface has one)."""
    rows = answer_rows(text)
    if not rows:
        return ""
    header = rows[0]
    if header.split()[:4] != ["Interface", "Admin", "Link", "Description"]:
        raise Rejected(["the description list is not recognised"])
    start = header.index("Description")
    for row in rows[1:]:
        if row.split()[:1] == [key]:
            return row[start:].strip() if len(row) > start else ""
    return ""


def switching(text: str, key: str):
    """VLAN rows of show ethernet-switching interface <if>: list of (VLAN name, tagging); None for an empty answer."""
    rows = answer_rows(text)
    if not rows:
        return None
    if not any(row.startswith("Routing") for row in rows):
        raise Rejected(["the ethernet-switching answer about %s is not recognised" % key])
    logical, vlans = False, []
    for row in rows:
        words = row.split()
        if not words or words[0] != "default-switch":
            continue
        if words[1] == key + ".0":
            logical = True
            continue
        if words[1].startswith(key + "."):
            raise Rejected(["the ethernet-switching answer names another unit of %s" % key])
        if words[-1] not in ("untagged", "tagged") or len(words) < 3 or not words[2].isdigit():
            raise Rejected(["the ethernet-switching answer about %s is not recognised" % key])
        vlans.append((words[1], words[-1]))
    if not logical:
        raise Rejected(["the ethernet-switching answer names another interface"])
    return vlans


def vlan_exists(text: str, name: str) -> bool:
    """show vlans <name>: measured empty answer for a missing VLAN, a row "default-switch <name> <tag>" otherwise."""
    rows = answer_rows(text)
    if not rows:
        return False
    if refused_answer(text) is not None:
        raise Rejected(["the answer about VLAN %s is a refusal" % name])
    return any(row.split()[1:2] == [name] and row.split()[:1] == ["default-switch"] for row in rows)


def lldp_ports(text: str) -> set:
    """Local interfaces with an LLDP neighbor in show lldp neighbors (empty answer: no neighbor)."""
    rows = answer_rows(text)
    if not rows:
        return set()
    if rows[0].split()[:2] != ["Local", "Interface"]:
        raise unreadable("LLDP neighbor list")
    return {row.split()[0] for row in rows[1:] if row.split()}


def learned_macs(text: str, key: str) -> int:
    """MAC addresses in show ethernet-switching table interface <if> (measured empty answer: the title only)."""
    if ("MAC database for interface %s" % key) not in text:
        raise unreadable("MAC table")
    return len(MAC.findall(text))


def users(text: str) -> int:
    """Rows of show system users (the ssh exec session of the reader is not listed, measured)."""
    rows = answer_rows(text)
    header = next((index for index, row in enumerate(rows) if row.split()[:2] == ["USER", "TTY"]), None)
    if header is None:
        raise Rejected(["the session list is not readable"])
    return len(rows) - header - 1


SESSION_PREFIX = "netops-"
