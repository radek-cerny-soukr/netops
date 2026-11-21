"""Juniper Junos ELS plan adapter: interface description and admin state, port VLAN membership (access VLAN, trunk
with tagged and native VLAN, voice VLAN) and VLANs (create, rename, description, delete) from the set-format
configuration (show configuration | display set).

Measured on vJunos-switch 26.2R1.7 (ELS, model ex9214; task netops-provoz-20261116-308, ref/mereni-c8; 1.0.12 G137,
task-evidence/g137): the configuration is a flat list of "set ..." statements and starts with "set version <release>".
A description with a space is quoted ("description \"a b\""), without a space it is shown bare. Junos accepts the
configuration of an interface that does not exist (set interfaces ge-0/0/99 description ... is taken without an
error) and checks a VLAN given by name only at commit time, so the plan relies on the device reads of the execution
adapter for both. Interfaces are implicit keys: an unconfigured port is not in the configuration at all, its state is
the default.

1.0.12 G137 (JP12): a port takes configuration from its own statements, from an interface-range that lists it and from
configuration groups applied at the top level or at the port. The adapter evaluates these sources itself (the
execution adapter compares the result with "show configuration interfaces <if> | display inheritance | display set"
of the device) and edits a VLAN statement of the port where it is configured: in the port, in the interface-range or
in the group. An edit of a source that also configures another port is refused with the list of those ports; a
statement configured in two sources, apply-groups-except, a group condition and other inheritance forms are refused.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from netops_admin import junos_filter as fltr
from netops_admin import junos_dhcp as dhcp
from netops_admin import junos_g140
from netops_admin import junos_routing as routing
from netops_admin import junos_srx as srx
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
INTERFACE_STATE_SCHEMA = 1
LINK_PARAMETERS = ("mtu", "speed", "auto-negotiation")
LINK_DEFAULTS = {"mtu": "1514", "speed": "auto", "auto-negotiation": "enabled"}
SWITCHING = "unit 0 family ethernet-switching"
MEMBERS = SWITCHING + " vlan members"
MODE = SWITCHING + " interface-mode"
ACCESS_MODE = MODE + " access"
NATIVE = "native-vlan-id"
VOIP = re.compile(r"^set switch-options voip interface (\S+)\.0 vlan (\S+)$")
LLDP_MED = re.compile(r"^set protocols lldp-med interface (\S+)(?: (enable|disable))?$")
INACTIVE_MED = re.compile(r"^inactive: (?:set )?(protocols lldp-med(?: .*)?)$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
VLAN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
# a VLAN statement of the VLAN table: vlan-id and description belong to the profile, l3-interface (the IRB) moves
# with a rename and blocks a delete; any other statement under the VLAN is outside the profile
VLAN_OWN = ("vlan-id ", "description ")
VLAN_IRB = "l3-interface "
VLAN_IRB_VALUE = re.compile(r"^irb\.[0-9]+$")
IRB_VLAN = re.compile(r"^set (?:groups \S+ )?(?:routing-instances \S+ )?vlans ([A-Za-z][A-Za-z0-9_.-]*) "
                      r"l3-interface irb\.[0-9]+$")
IRB_BINDING = re.compile(r"^set .* (?:l3-interface|routing-interface) irb\.[0-9]+$")
PORT_PATH = r"interfaces (?:interface-range \S+|\S+)|groups \S+ interfaces (?!interface-range )\S+"
VLAN_MEMBER = re.compile(r"^set (?P<path>" + PORT_PATH + r") " + re.escape(MEMBERS) + r" (?P<name>\S+)$")
PROTOCOL_VLAN = re.compile(r"^set (protocols (?:igmp-snooping|mld-snooping|vstp) vlan) (\S+)(?: .*)?$")
MSTP_VLAN = re.compile(r"^set (protocols mstp msti [0-9]+ vlan) (\S+)$")
CONFIG_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s"\[\];,]+')
DESCRIPTION_LINE = re.compile(r"^((?:set|deactivate|protect) (?:vlans \S+|(?:" + PORT_PATH
                              + r")(?: unit [0-9]+)?) description)(?: |$)")
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
BATCH_BASELINE = "show | display set | no-more"
BATCH_COMPARE = "show | compare rollback 0 | no-more"
BATCH_IMPACT_TABLES = ("vlan-membership", "irb", "vrrp", "system", "ntp-server", "syslog-host")
# the statements of a port that a table owns, by category (the rest of a "set" line after its source prefix)
CATEGORIES = {
    "interface": {"description": re.compile(r"^description(?: |$)"), "admin-state": re.compile(r"^disable$"),
                  "speed": re.compile(r"^speed(?: |$)"), "mtu": re.compile(r"^mtu(?: |$)"),
                  "auto-negotiation": re.compile(r"^ether-options (?:no-)?auto-negotiation$")},
    # 1.0.12 G138 (J11): the port bounce owns the disable statement of the port only
    "port-bounce": {"admin-state": re.compile(r"^disable$")},
    "vlan-membership": {"mode": re.compile(r"^" + re.escape(MODE) + r"(?: |$)"),
                        "members": re.compile(r"^" + re.escape(MEMBERS) + r"(?: |$)"),
                        "native": re.compile(r"^" + NATIVE + r"(?: |$)")},
}
# 1.0.12 G138: PoE is configured outside the interface (set poe interface <if> disable; J09 table poe, J10 table
# inline-power of the poe-cycle operation) and the port bounce (J11) has its own action table
POE_TABLE = "poe"
POE_CYCLE_TABLE = "inline-power"
BOUNCE_TABLE = "port-bounce"
POE_TABLES = (POE_TABLE, POE_CYCLE_TABLE)
CYCLE_TABLES = (BOUNCE_TABLE, POE_CYCLE_TABLE)
POE_ALL = ("all", "all-extended")
SPEEDS = ("10m", "100m", "1g", "10g", "auto")
MTU_RANGE = (256, 9192)
TRUNK = re.compile(r"^unit [0-9]+ family ethernet-switching interface-mode (?!access$)\S+")
LAG = re.compile(r"^(?:ether|gigether)-options 802\.3ad(?: |$)")
ROUTED = re.compile(r"^unit [0-9]+ family (?:inet|inet6|mpls|iso)(?: |$)")
INHERITANCE = re.compile(r"(?:^| )apply-groups(?:-except)?(?: |$)")
# 1.0.12 G137 JP17: the longest description Admin writes (the interactive line stays far below the screen width)
DESCRIPTION_MAX = 240
TRUNK_ATTRIBUTES = ("trunk-vlans", "native-vlan")
ACCESS_ATTRIBUTES = ("access-vlan", "voice-vlan")
# a voice VLAN alone leaves the data VLAN of the port as it is; every other membership change can cut the port
QUIET = ("voice-vlan",)


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


class Source:
    """Where a statement of a port is configured: the port itself, an interface-range or a configuration group.

    prefix is the path of the source in a set line ("interfaces ge-0/0/7", "interfaces interface-range R",
    "groups G interfaces <pattern>"), lines the rest of its set lines, scope the ports an edit of the source changes
    (None when a wildcard of a group applied at the top level makes the set not enumerable)."""

    def __init__(self, kind, name, prefix, lines, scope):
        self.kind, self.name, self.prefix, self.lines, self.scope = kind, name, prefix, list(lines), scope

    def describe(self) -> str:
        if self.kind == "interface":
            return "the port itself"
        if self.kind == "interface-range":
            return "interface-range %s" % self.name
        return "configuration group %s (%s)" % (self.name, self.prefix.split(" ", 3)[3])


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


def _pattern(target: str):
    """The wildcard of a group interface target (<ge-0/0/*>, shown with or without quotes) or None for a name."""
    bare = target[1:-1] if len(target) >= 2 and target[0] == target[-1] == '"' else target
    if len(bare) >= 2 and bare[0] == "<" and bare[-1] == ">":
        return bare[1:-1]
    return None


def _wildcard(pattern: str):
    """The Junos group wildcard as a regular expression: * any text, ? one character, [..] a class ([!..] negated)."""
    parts, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        end = pattern.find("]", index + 1) if char == "[" else -1
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        elif end > index + 1:
            body = pattern[index + 1:end]
            parts.append("[%s%s]" % ("^" if body.startswith("!") else "",
                                     re.sub(r"[\\\]^]", lambda match: "\\" + match.group(0), body.lstrip("!"))))
            index = end
        else:
            parts.append(re.escape(char))
        index += 1
    return re.compile("".join(parts))


def _matches(target: str, port: str) -> bool:
    pattern = _pattern(target)
    return target == port if pattern is None else _wildcard(pattern).fullmatch(port) is not None


def _port_number(port: str):
    match = re.fullmatch(r"([a-z]+-[0-9]+/[0-9]+/)([0-9]+)", port)
    return (match.group(1), int(match.group(2))) if match else None


_RANGE_COORDINATE = r"(?:[0-9]{1,3}|\*|\[[0-9]{1,3}(?:-[0-9]{1,3})?(?:,[0-9]{1,3}(?:-[0-9]{1,3})?)*\])"
_RANGE_MEMBER = re.compile(rf"([a-z]+)-({_RANGE_COORDINATE})/({_RANGE_COORDINATE})/({_RANGE_COORDINATE})")


def _range_coordinate_matches(pattern, number):
    if pattern == "*":
        # Junos defines * as 0–47 and may reject a commit on other port layouts.
        # Treat all coordinates as potentially covered for the protection check.
        return True
    for item in pattern.strip("[]").split(","):
        first, _, last = item.partition("-")
        if int(first) <= number <= int(last or first):
            return True
    return False


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
        strange = [number for number, line in enumerate(filled, 1)
                   if STATEMENT.match(line) is None and INACTIVE_MED.fullmatch(line) is None]
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
        self.vlan_lines = {}
        self.interfaces = {}
        self.deactivated = set()
        self.inactive = []
        self.ranges = {}
        self.group_interfaces = {}
        self.group_other = {}
        self.applied = []
        self.applied_interfaces = []
        self.port_groups = {}
        self.excepted = False
        self.voip = {}
        self.voip_other = []
        self.poe = {}
        self.poe_other = []
        for line in filled:
            host = HOST_NAME.match(line)
            if host is not None:
                self.hostname = host.group(1)
            words = line.split()
            if words[0] != "set":
                self.inactive.append(line)
            if words[:2] == ["set", "vlans"] and len(words) >= 3:
                self.vlans.add(words[2])
                if len(words) >= 4:
                    self.vlan_lines.setdefault(words[2], []).append(line.split(" ", 3)[3])
            if "apply-groups-except" in words:
                self.excepted = True
            if words[:2] == ["set", "apply-groups"] and len(words) == 3:
                self.applied.append(words[2])
            if words[:3] == ["set", "interfaces", "apply-groups"] and len(words) == 4:
                self.applied_interfaces.append(words[3])
                continue
            if words[:2] == ["set", "groups"] and len(words) >= 4:
                if words[3] == "interfaces" and len(words) >= 6:
                    self.group_interfaces.setdefault(words[2], []).append((words[4], line.split(" ", 5)[5]))
                else:
                    self.group_other.setdefault(words[2], set()).add(words[3])
            if words[:3] == ["set", "poe", "interface"] and len(words) >= 4:
                self.poe.setdefault(words[3], []).append(" ".join(words[4:]))
            elif words[1:2] == ["poe"] or (words[:2] == ["set", "groups"] and words[3:4] == ["poe"]):
                # deactivated or protected PoE statements, PoE of a configuration group and the PoE statements of
                # the controller (guard-band, management ...) are not evaluated
                self.poe_other.append(line)
            voip = VOIP.match(line)
            if voip is not None:
                self.voip.setdefault(voip.group(1), []).append(voip.group(2))
            elif words[:3] == ["set", "switch-options", "voip"]:
                self.voip_other.append(line)
            match = INTERFACE_LINE.match(line)
            if match is None:
                continue
            verb, name, rest = match.group(1), match.group(2), match.group(3) or ""
            if name == "interface-range":
                if verb != "set":
                    self.deactivated.add(rest.split()[0] if rest else name)
                    continue
                range_name, _space, range_rest = rest.partition(" ")
                data = self.ranges.setdefault(range_name, {"members": [], "member_ranges": [], "lines": [],
                                                           "unsupported": []})
                range_words = range_rest.split()
                if range_words[:1] == ["member"] and len(range_words) == 2:
                    data["members"].append(range_words[1])
                elif range_words[:1] == ["member-range"] and len(range_words) == 4 and range_words[2] == "to":
                    data["member_ranges"].append((range_words[1], range_words[3]))
                elif range_words[:1] in (["member"], ["member-range"]):
                    data["unsupported"].append("interface-range %s member form" % range_name)
                else:
                    data["lines"].append(range_rest)
                continue
            if verb != "set":
                self.deactivated.add(name)
                continue
            words = rest.split()
            if words[:1] == ["apply-groups"] and len(words) == 2:
                self.port_groups.setdefault(name, []).append(words[1])
                continue
            self.interfaces.setdefault(name, []).append(rest)

    def lldp_med_enabled(self, port):
        inactive = [line.removeprefix("deactivate ") for line in self.inactive if line.startswith("deactivate ")]
        inactive += [match.group(1) for line in self.inactive if (match := INACTIVE_MED.fullmatch(line))]
        settings = {}
        for line in self.lines:
            match = LLDP_MED.fullmatch(line)
            if match is None:
                continue
            path = line.removeprefix("set ")
            if any(path == prefix or path.startswith(prefix + " ") for prefix in inactive):
                continue
            target, setting = match.groups()
            settings[target] = settings.get(target, True) and setting != "disable"
        return settings.get(port, settings.get("all", False))

    # ---- sources of a port ----

    def range_members(self, name) -> list:
        data = self.ranges[name]
        members = list(data["members"])
        for first, last in data["member_ranges"]:
            start, end = _port_number(first), _port_number(last)
            if start is None or end is None or start[0] != end[0] or start[1] > end[1]:
                continue
            members += ["%s%d" % (start[0], number) for number in range(start[1], end[1] + 1)]
        return members

    def _range_unsupported(self, name) -> list:
        data = self.ranges[name]
        found = list(data["unsupported"])
        for first, last in data["member_ranges"]:
            start, end = _port_number(first), _port_number(last)
            if start is None or end is None or start[0] != end[0] or start[1] > end[1]:
                found.append("interface-range %s member-range %s to %s" % (name, first, last))
        if any(_pattern(member) is not None or not PHYSICAL.fullmatch(member) for member in data["members"]):
            found.append("interface-range %s member that is not a port name" % name)
        return found

    def configured(self, port) -> bool:
        """The port has statements of its own or of an interface-range (a wildcard group applies only to those)."""
        return port in self.interfaces or port in self.port_groups or any(
            port in self.range_members(name) for name in self.ranges)

    def _top_groups(self) -> list:
        return list(dict.fromkeys(self.applied + self.applied_interfaces))

    def _group_scope(self, group, target):
        ports = set()
        if group in self._top_groups():
            if _pattern(target) is not None:
                known = set(self.interfaces) | set(self.port_groups)
                for name in self.ranges:
                    known.update(self.range_members(name))
                known.update(other for item, _rest in sum(self.group_interfaces.values(), []) for other in [item]
                             if _pattern(other) is None)
                ports.update(port for port in known if PHYSICAL.fullmatch(port) and _matches(target, port))
            else:
                ports.add(target)
        ports.update(port for port, groups in self.port_groups.items() if group in groups and _matches(target, port))
        return sorted(ports)

    def _rename_range_ports(self, name, protected_ports) -> set:
        if not protected_ports:
            return set()
        data = self.ranges[name]
        patterns = [_RANGE_MEMBER.fullmatch(unquoted(member) or "") for member in data["members"]]
        if data["unsupported"] or any(pattern is None for pattern in patterns):
            raise Rejected(["the ports of a VLAN member interface-range cannot be determined"])
        for first, last in data["member_ranges"]:
            start, end = _port_number(first), _port_number(last)
            if start is None or end is None or start[0] != end[0] or start[1] > end[1]:
                raise Rejected(["the ports of a VLAN member interface-range cannot be determined"])
        ports = set(self.range_members(name)) & protected_ports
        for port in protected_ports - ports:
            family, coordinates = port.split("-", 1)
            values = [int(value) for value in coordinates.split("/")]
            if any(
                pattern[1] == family and all(_range_coordinate_matches(part, number)
                                             for part, number in zip(pattern.groups()[1:], values))
                for pattern in patterns
            ):
                ports.add(port)
        return ports

    def _rename_group_scope(self, group, target, protected_ports) -> set:
        """Conservatively identify the ports affected by rewriting a group VLAN member."""
        ports = set(self._group_scope(group, target))
        matching = {port for port in protected_ports if _matches(target, port)}
        if group in self._top_groups() and _pattern(target) is not None:
            for name in self.ranges:
                ports.update(self._rename_range_ports(name, matching - ports))
        for line in self.lines:
            if not line.startswith("set ") or "apply-groups " not in line:
                continue
            words = CONFIG_TOKEN.findall(line)
            if "apply-groups" not in words:
                continue
            leaf = words.index("apply-groups")
            path, groups = words[1:leaf], words[leaf + 1:]
            if group.strip('"') not in {value.strip('"') for value in groups}:
                continue
            if path in ([], ["interfaces"]) and groups == [group] and group in self._top_groups():
                continue
            if len(path) >= 2 and path[0] == "interfaces":
                port = path[1]
                if PHYSICAL.fullmatch(port):
                    if _matches(target, port):
                        ports.add(port)
                    continue
                if port == "interface-range" and len(path) >= 3 and path[2] in self.ranges:
                    ports.update(self._rename_range_ports(path[2], matching - ports))
                    continue
            raise Rejected(["the configuration group application scope cannot be determined"])
        return ports

    def sources(self, port) -> tuple:
        """The sources that configure the port and the inheritance forms the adapter does not evaluate."""
        found, unsupported = [], []
        if port in self.interfaces:
            found.append(Source("interface", port, "interfaces %s" % port, self.interfaces[port], [port]))
        for name in self.ranges:
            if port in self.range_members(name):
                unsupported += self._range_unsupported(name)
                found.append(Source("interface-range", name, "interfaces interface-range %s" % name,
                                    self.ranges[name]["lines"], sorted(self.range_members(name))))
        configured = self.configured(port)
        own = self.port_groups.get(port, [])
        for group in list(dict.fromkeys(self._top_groups() + own)):
            targets = {}
            for target, rest in self.group_interfaces.get(group, []):
                if not _matches(target, port):
                    continue
                if group not in own and _pattern(target) is not None and not configured:
                    continue
                targets.setdefault(target, []).append(rest)
            if not targets:
                continue
            if "when" in self.group_other.get(group, set()):
                unsupported.append("configuration group %s with a condition (when)" % group)
            for target, rests in targets.items():
                found.append(Source("group", group, "groups %s interfaces %s" % (group, target), rests,
                                    self._group_scope(group, target)))
        if self.excepted:
            unsupported.append("apply-groups-except")
        for source in found:
            if any(INHERITANCE.search(rest) for rest in source.lines):
                unsupported.append("apply-groups inside %s" % source.describe())
        return found, unsupported

    def owners(self, table, port) -> tuple:
        """The source of every category of statements of the table that is configured for the port, and the
        statements the adapter cannot place (a category configured in more than one source)."""
        found, unsupported = self.sources(port)
        owners = {}
        for category, pattern in CATEGORIES.get(table, {}).items():
            holding = [source for source in found if any(pattern.match(rest) for rest in source.lines)]
            if len(holding) > 1:
                unsupported.append("%s of %s is configured in %s" % (
                    category, port, " and ".join(source.describe() for source in holding)))
            elif holding:
                owners[category] = holding[0]
        return found, owners, unsupported

    def edit_source(self, table, port, category) -> Source:
        _found, owners, _unsupported = self.owners(table, port)
        return owners.get(category) or Source("interface", port, "interfaces %s" % port,
                                              self.interfaces.get(port, []), [port])

    def effective(self, port) -> list:
        """All statements of the port from every source (rest of the set line after the port path)."""
        found, _unsupported = self.sources(port)
        return [rest for source in found for rest in source.lines]

    # ---- tables ----

    def entries(self, table: str):
        if table == "vlan":
            return self._vlan_entries()
        if table in routing.TABLES:
            return routing.entries(self, table)
        if table in fltr.TABLES:
            return fltr.entries(self, table)
        if table in srx.TABLES:
            return srx.entries(self, table)
        if table in dhcp.TABLES:
            return dhcp.entries(self, table)
        if table in G145_TABLES:
            return g145_entries(self, table)
        if table in G139_TABLES:
            return l3_entries(self, table)
        if table == junos_g140.LAG:
            return junos_g140.lag_entries(self)
        if table in (junos_g140.RSTP, junos_g140.RSTP_PORT):
            return junos_g140.rstp_entries(self, table)
        if table in POE_TABLES:
            return {name: self._poe_entry(name) for name in sorted(self.poe) if name not in POE_ALL}
        if table not in CATEGORIES:
            return None
        names = set(self.interfaces) | set(self.port_groups)
        for name in self.ranges:
            names.update(self.range_members(name))
        for items in self.group_interfaces.values():
            names.update(target for target, _rest in items if _pattern(target) is None)
        return {name: self._entry(table, name) for name in sorted(names) if self.effective(name)
                or name in self.interfaces}

    def _poe_entry(self, name):
        """The PoE state of a port: disabled by its own statement. A disable of "all" or "all-extended", a
        deactivated or protected PoE statement and a PoE configuration group are not evaluated."""
        entry = Entry(name)
        for rest in self.poe.get(name, []):
            if rest == "disable":
                _once(entry, "admin-state", "disabled")
        if any("disable" in self.poe.get(everything, []) for everything in POE_ALL):
            entry.unsupported.append("poe interface all disabled")
        if any(line.startswith(("deactivate ", "protect ")) for line in self.poe_other):
            entry.unsupported.append("deactivated or protected PoE statement")
        if any(line.startswith("set groups ") for line in self.poe_other):
            entry.unsupported.append("PoE configuration group")
        return entry

    def _entry(self, table, name):
        if table in POE_TABLES:
            return self._poe_entry(name)
        entry = Entry(name)
        found, owners, unsupported = self.owners(table, name)
        lines = [rest for source in found for rest in source.lines]
        if table in ("interface", BOUNCE_TABLE):
            for category, source in owners.items():
                if source.kind != "interface":
                    unsupported.append("%s inherited from %s" % (category, source.describe()))
            for rest in self.interfaces.get(name, []):
                if table == "interface" and rest.startswith("description "):
                    value = unquoted(rest[len("description "):])
                    if value is None:
                        entry.unsupported.append("description with quotes or escapes")
                    else:
                        _once(entry, "description", value)
                elif rest == "disable":
                    _once(entry, "admin-state", "disabled")
                elif table == "interface" and rest.startswith("speed "):
                    if rest[len("speed "):] in SPEEDS:
                        _once(entry, "speed", rest[len("speed "):])
                    else:
                        entry.unsupported.append("speed %s" % rest[len("speed "):][:20])
                elif table == "interface" and re.fullmatch(r"mtu [0-9]+", rest):
                    _once(entry, "mtu", rest[len("mtu "):])
                elif table == "interface" and rest.startswith("mtu "):
                    entry.unsupported.append("mtu %s" % rest[len("mtu "):][:20])
                elif table == "interface" and rest in ("ether-options auto-negotiation",
                                                       "ether-options no-auto-negotiation"):
                    _once(entry, "auto-negotiation", "disabled" if "no-auto" in rest else "enabled")
        else:
            self._membership(entry, name, lines)
        entry.unsupported.extend(unsupported)
        entry.unsupported.extend(self.shared_configuration(name))
        return entry

    def _membership(self, entry, name, lines):
        modes = [rest[len(MODE) + 1:] for rest in lines if rest.startswith(MODE + " ")]
        members = [rest[len(MEMBERS) + 1:] for rest in lines if rest.startswith(MEMBERS + " ")]
        natives = [rest[len(NATIVE) + 1:] for rest in lines if rest.startswith(NATIVE + " ")]
        voices = self.voip.get(name, [])
        mode = modes[0] if len(modes) == 1 else None
        if len(modes) > 1:
            entry.unsupported.append("repeated interface-mode")
        wrong = [value for value in members if VLAN_NAME.fullmatch(value) is None or value in ("all", "none")]
        if wrong:
            entry.unsupported.append("VLAN member %s is not a VLAN name" % wrong[0][:20])
        if mode == "trunk":
            entry.attributes["mode"] = "trunk"
            if members and not wrong:
                entry.attributes["trunk-vlans"] = " ".join(sorted(members))
            if len(natives) == 1 and re.fullmatch(r"[1-9][0-9]{0,3}", natives[0]):
                entry.attributes["native-vlan"] = natives[0]
            elif natives:
                entry.unsupported.append("native-vlan-id %s" % natives[0][:10])
            if voices:
                entry.unsupported.append("voice VLAN on a trunk")
            return
        if mode not in (None, "access"):
            entry.unsupported.append("interface-mode %s" % mode[:20])
            return
        if natives:
            entry.unsupported.append("native-vlan-id on an access port")
        if not wrong:
            for value in members:
                _once(entry, "access-vlan", value)
        if len(voices) == 1 and VLAN_NAME.fullmatch(voices[0]):
            entry.attributes["voice-vlan"] = voices[0]
        elif voices:
            entry.unsupported.append("voice VLAN %s" % voices[0][:20])
        if voices and self.voip_other:
            entry.unsupported.append("switch-options voip outside the profile")

    def _vlan_entries(self) -> dict:
        found, seen = {}, {}
        for name, rests in self.vlan_lines.items():
            ids = [rest.split()[1] for rest in rests if rest.split()[:1] == ["vlan-id"] and len(rest.split()) == 2]
            if len(ids) != 1 or not re.fullmatch(r"[1-9][0-9]{0,3}", ids[0]):
                continue
            entry = Entry(ids[0])
            entry.attributes["name"] = name
            for rest in rests:
                if rest.startswith("description "):
                    value = unquoted(rest[len("description "):])
                    if value is None:
                        entry.unsupported.append("description with quotes or escapes")
                    else:
                        _once(entry, "description", value)
                elif rest.startswith(VLAN_IRB):
                    value = rest[len(VLAN_IRB):]
                    if VLAN_IRB_VALUE.fullmatch(value):
                        _once(entry, "l3-interface", value)
                    else:
                        entry.unsupported.append("unrecognised VLAN l3-interface")
                elif not rest.startswith(VLAN_OWN):
                    entry.unsupported.append("VLAN statement %s" % rest.split()[0])
            if any("vlans" in parts for parts in self.group_other.values()):
                entry.unsupported.append("VLAN configuration groups")
            if any(line.split()[1:3] == ["vlans", name] for line in self.inactive):
                entry.unsupported.append("deactivated or protected statement")
            seen.setdefault(ids[0], []).append(name)
            found[ids[0]] = entry
        for number, names in seen.items():
            if len(names) > 1:
                found[number].unsupported.append("VLAN ID %s is used by %s" % (number, ", ".join(sorted(names))))
        return found

    def vlan_name(self, key):
        entry = self._vlan_entries().get(key)
        return None if entry is None else entry.attributes["name"]

    def vlan_references(self, name) -> list:
        """Statements outside the VLAN itself naming it, classified by how they can be moved."""
        found = []
        for line in self.lines:
            if line.split()[:3] == ["set", "vlans", name]:
                continue
            description = DESCRIPTION_LINE.match(line)
            tokens = CONFIG_TOKEN.findall(description.group(1) if description else line)
            if not any(word.strip('"') == name for word in tokens):
                continue
            member, voip = VLAN_MEMBER.fullmatch(line), VOIP.fullmatch(line)
            protocol, mstp = PROTOCOL_VLAN.fullmatch(line), MSTP_VLAN.fullmatch(line)
            if member and member["name"] == name:
                found.append(("member", line))
            elif voip and voip[2] == name:
                found.append(("voip", line))
            elif protocol and protocol[2] == name:
                found.append(("protocol", protocol[1]))
            elif mstp and mstp[2] == name:
                found.append(("mstp", mstp[1]))
            else:
                found.append(("other", None))
        return found

    def rename_ports(self, name, protected) -> set:
        physical = {item: port for item in protected if PHYSICAL.fullmatch(port := item.partition(".")[0])}
        protected_ports = set(physical.values())
        ports = set()
        for kind, line in self.vlan_references(name):
            if kind == "voip":
                ports.add(VOIP.fullmatch(line)[1])
            if kind != "member":
                continue
            path = VLAN_MEMBER.fullmatch(line)["path"].split()
            if path[:2] == ["interfaces", "interface-range"]:
                if path[2] not in self.ranges:
                    raise Rejected(["the ports of a VLAN member interface-range cannot be determined"])
                ports.update(self._rename_range_ports(path[2], protected_ports - ports))
            elif path[0] == "groups":
                ports.update(self._rename_group_scope(path[1], path[3], protected_ports - ports))
            else:
                ports.add(path[1])
        return ports | {item for item, port in physical.items() if port in ports}

    def shared_configuration(self, name) -> list:
        """Configuration that can reach the interface in a way the adapter does not evaluate."""
        return ["deactivated or protected statement"] if name in self.deactivated else []

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        return []

    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        return self.effective(key)

    def own_lines(self, table, key) -> set:
        """The set lines of the snapshot that the planned object owns (left out of the rest digest)."""
        if table == "vlan":
            name = self.vlan_name(key)
            if name is None:
                return set()
            return {line for line in self.lines if line.split()[1:3] == ["vlans", name]}
        if table in routing.TABLES:
            return routing.own_lines(self, table, key)
        if table in fltr.TABLES:
            return fltr.own_lines(self, table, key)
        if table in srx.TABLES:
            return srx.own_lines(self, table, key)
        if table in dhcp.TABLES:
            return dhcp.own_lines(self, table, key)
        if table in G145_TABLES:
            return {line for line in self.lines if _g145_owner(line) == (table, key)}
        if table in G139_TABLES:
            return l3_own_lines(self, table, key)
        if table in junos_g140.TABLES:
            own = junos_g140.owned(self, table, key)
            if table == junos_g140.LAG:
                own.update(line for line in self.lines if line.startswith("set " + junos_g140.COUNT + " "))
            return own
        own = set()
        if table in POE_TABLES:
            return {line for line in self.lines if line == "set poe interface %s disable" % key}
        found, _unsupported = self.sources(key)
        patterns = CATEGORIES.get(table, {}).values()
        for source in found:
            prefix = "set %s " % source.prefix
            own.update(line for line in self.lines
                       if line.startswith(prefix) and any(pattern.match(line[len(prefix):]) for pattern in patterns))
        if table == "vlan-membership":
            own.update(line for line in self.lines if VOIP.match(line) and VOIP.match(line).group(1) == key)
        return own

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        own = self.own_lines(table, key)
        if table == VRRP_TABLE:
            kept = _without_vrrp_group(self.lines, own)
        else:
            kept = [line for line in self.lines if line not in own]
        if table == "vlan":
            # the references of a renamed VLAN follow its name: compared with the name of the VLAN ID replaced, and
            # unordered, because a moved reference is set again and Junos then lists it after the other members
            name = self.vlan_name(key)
            kept = sorted(" ".join("\x00vlan" if word == name else word for word in line.split()) for line in kept)
        if table in junos_g140.TABLES:
            kept.sort()
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
    if table in G139_TABLES:
        return ["%s %s is not in the configuration" % (table, key)]
    if table in routing.TABLES:
        return ["routing object %s is not in the configuration" % key]
    if table in fltr.TABLES:
        return ["firewall object %s is not in the configuration" % key]
    if table in srx.TABLES:
        return ["SRX %s %s is not in the configuration" % (table, key)]
    if table in dhcp.TABLES:
        return ["DHCP object %s is not in the configuration" % key]
    if table in G145_TABLES:
        return ["%s %s is not in the configuration" % (G145_NAMES[table], key)]
    if table == "vlan":
        return ["VLAN ID %s is not in the configuration" % key]
    return ["interface %s is not in the configuration" % key]


def render_create(profile, key: str, attributes: dict) -> list:
    if profile.table in G145_TABLES + G139_TABLES + routing.TABLES + fltr.TABLES + srx.TABLES + dhcp.TABLES:
        # rendered from the whole state (render_state)
        return []
    if profile.table == "vlan":
        return _session(_vlan_lines(None, key, None, attributes))
    raise Rejected(["Junos %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    if profile.table in ("vlan",) + G145_TABLES + G139_TABLES + routing.TABLES + fltr.TABLES + srx.TABLES + dhcp.TABLES:
        # the name is in the plan state; build_plan renders the delete from the state (render_state)
        return []
    raise Rejected(["Junos %s objects are only updated" % profile.table])


def text_value(value: str) -> str:
    """A description Junos stores and shows literally inside double quotes (1.0.12 G137 JP17, measured): any
    printable character of UTF-8 text, also diacritics, except the double quote and the backslash (Junos escapes
    them), the question mark (CLI help even inside quotes), control and format characters, the no-break space and
    leading or trailing blanks."""
    if (not value or value != value.strip() or '"' in value or "\\" in value or "?" in value
            or not value.isprintable()):
        raise Rejected(["the value %r cannot be written safely" % value[:40]])
    return value


def _text(value: str) -> str:
    return text_value(value)


def _lines(key: str, name: str, value, table: str = "interface") -> list:
    base = "interfaces %s" % key
    if table in POE_TABLES:
        if name != "admin-state" or value not in (None, "enabled", "disabled"):
            raise Rejected(["poe knows only admin-state enabled or disabled"])
        return ["set poe interface %s disable" % key] if value == "disabled" else [
            "delete poe interface %s disable" % key]
    if name == "speed":
        if value is None:
            return ["delete %s speed" % base]
        if value not in SPEEDS:
            raise Rejected(["speed must be one of %s" % ", ".join(SPEEDS)])
        return ["set %s speed %s" % (base, value)]
    if name == "mtu":
        if value is None:
            return ["delete %s mtu" % base]
        if not re.fullmatch(r"[0-9]{3,4}", str(value)) or not MTU_RANGE[0] <= int(value) <= MTU_RANGE[1]:
            raise Rejected(["mtu must be a number %d..%d" % MTU_RANGE])
        return ["set %s mtu %d" % (base, int(value))]
    if name == "auto-negotiation":
        if value is None:
            # one of the two statements exists; deleting the other is answered with the tolerated warning
            return ["delete %s ether-options auto-negotiation" % base,
                    "delete %s ether-options no-auto-negotiation" % base]
        if value not in ("enabled", "disabled"):
            raise Rejected(["auto-negotiation must be enabled or disabled"])
        return ["set %s ether-options %sauto-negotiation" % (base, "" if value == "enabled" else "no-")]
    if name == "description":
        return ["delete %s description" % base] if value is None else [
            'set %s description "%s"' % (base, _text(value))]
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return ["set %s disable" % base] if value == "disabled" else ["delete %s disable" % base]
    raise Rejected(["attribute %s is not known on Junos" % name])


def _typed(line: str) -> str:
    """A configuration line as it is typed: a group wildcard (shown as <ge-0/0/[89]>) is quoted, because the CLI reads
    "[" as the start of a set of values (measured: typed with quotes, shown without them by display set)."""
    return re.sub(r"^((?:set|delete) groups \S+ interfaces )(<\S+>)(?= |$)", r'\1"\2"', line)


def _session(lines, *, compare=COMPARE) -> list:
    return [SCREEN, ENTER, COMPARE_EMPTY] + [_typed(line) for line in lines] + [compare, CHANGE_COMMIT, LEAVE] \
        if lines else []


def batch_edits(lines):
    edits = lines[3:-3]
    if (lines[:3] != [SCREEN, ENTER, COMPARE_EMPTY]
            or lines[-3:] not in ([COMPARE, CHANGE_COMMIT, LEAVE], [BATCH_COMPARE, CHANGE_COMMIT, LEAVE])
            or not edits or any(line.partition(" ")[0] not in ("set", "delete", "rename", "insert") for line in edits)):
        raise Rejected(["the Junos profile does not render a reversible candidate edit"],
                       reason_codes=["action_unsupported"])
    return edits


def batch_commands(steps, field):
    edits = [line for step in steps for line in batch_edits(step[field])]
    return [SCREEN, ENTER, BATCH_BASELINE, *edits, BATCH_COMPARE, CHANGE_COMMIT, LEAVE]


def batch_snapshot_digest(snapshot):
    """Compare set-format content across CLI hierarchy ordering, preserving evaluation order where it matters."""
    ordered = {}
    for line in snapshot.lines:
        words = line.split()
        if words[:3] == ["set", "system", "name-server"]:
            ordered.setdefault("system name-server", []).append(line)
        for marker in ("term", "policy", "rule", "import", "export", "input-list", "output-list"):
            if marker not in words[1:-1]:
                continue
            index = words.index(marker, 1)
            scope = " ".join(words[:index + 1])
            if marker in ("term", "policy", "rule"):
                value = words[index + 1]
                ordered.setdefault(scope, {}).setdefault(value, None)
            else:
                ordered.setdefault(scope, []).append(line)
            break
    sequence = {scope: list(values) for scope, values in ordered.items()}
    body = json.dumps([sorted(snapshot.lines), sequence], sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(body.encode("ascii")).hexdigest()


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure exclusive, an empty candidate, the set and delete lines, the
    difference and the commit confirmed that restarts the timer of the safeguard (exec_junos.py). The VLAN and the
    VLAN membership tables are rendered from their whole state (render_state)."""
    if profile.table in STATE_TABLES:
        return []
    lines = [line for name, value in sorted(assign.items()) for line in _lines(key, name, value, profile.table)]
    lines += [line for name in sorted(remove) for line in _lines(key, name, None, profile.table)]
    return _session(lines)


# ---- tables rendered from the whole state before and after (1.0.12 G137) ----

ROUTE_TABLE, IRB_TABLE, VRRP_TABLE = "static-route", "irb", "vrrp"
G139_TABLES = (ROUTE_TABLE, IRB_TABLE, VRRP_TABLE)
STATE_TABLES = G139_TABLES + ("vlan", "vlan-membership", "system", "ntp-server", "syslog-host", *routing.TABLES, *fltr.TABLES, *srx.TABLES, *dhcp.TABLES)


def _configured_members(state) -> list:
    state = state or {}
    if state.get("mode") == "trunk":
        return sorted((state.get("trunk-vlans") or "").split())
    return [state["access-vlan"]] if "access-vlan" in state else []


def _members(state) -> list:
    members = _configured_members(state)
    if not members and (state or {}).get("mode", "access") == "access":
        return [DEFAULT_VLAN]
    return members


def membership_target(before, after, undo):
    """Keep the public reset-to-default behavior. Undo can also restore an absent membership statement."""
    if after.get("mode") == "trunk":
        if after.get("access-vlan") == DEFAULT_VLAN:
            after.pop("access-vlan")
    elif not undo and after.get("access-vlan", DEFAULT_VLAN) == DEFAULT_VLAN:
        if "access-vlan" in before or before.get("mode") == "trunk":
            after["access-vlan"] = DEFAULT_VLAN
        else:
            after.pop("access-vlan", None)


def _membership_edits(before, after) -> dict:
    before, after = before or {}, after or {}
    values = {
        "mode": (before.get("mode", "access"), after.get("mode", "access")),
        "members": (_configured_members(before), _configured_members(after)),
        "native": (before.get("native-vlan"), after.get("native-vlan")),
        "voice": (before.get("voice-vlan"), after.get("voice-vlan")),
    }
    return {category: pair for category, pair in values.items() if pair[0] != pair[1]}


def _membership_lines(snapshot, key, before, after, *, incremental=False) -> list:
    edits = _membership_edits(before, after)
    lines = []

    def prefix(category):
        return snapshot.edit_source("vlan-membership", key, category).prefix

    if "mode" in edits:
        lines.append("set %s %s %s" % (prefix("mode"), MODE, edits["mode"][1]))
    if "members" in edits:
        old, new = edits["members"]
        path = "%s %s" % (prefix("members"), MEMBERS)
        if incremental and before.get("mode") == after.get("mode") == "trunk":
            lines += ["delete %s %s" % (path, name) for name in old if name not in new]
            lines += ["set %s %s" % (path, name) for name in new if name not in old]
        else:
            if old:
                lines.append("delete " + path)
            lines += ["set %s %s" % (path, name) for name in new]
    if "native" in edits:
        value = edits["native"][1]
        lines.append("delete %s %s" % (prefix("native"), NATIVE) if value is None
                     else "set %s %s %s" % (prefix("native"), NATIVE, value))
    if "voice" in edits:
        value = edits["voice"][1]
        lines.append("delete switch-options voip interface %s.0" % key if value is None
                     else "set switch-options voip interface %s.0 vlan %s" % (key, value))
    return lines


def _vlan_lines(snapshot, key, before, after) -> list:
    if after is None:
        return ["delete vlans %s" % before["name"]]
    name = after["name"]
    if before is None:
        lines = ["set vlans %s vlan-id %s" % (name, key)]
        if after.get("description"):
            lines.append('set vlans %s description "%s"' % (name, text_value(after["description"])))
        return lines
    lines = []
    if before["name"] != name:
        lines.append("rename vlans %s to %s" % (before["name"], name))
        lines += _rename_references(snapshot.vlan_references(before["name"]), before["name"], name)
    if before.get("description") != after.get("description"):
        lines.append("delete vlans %s description" % name if after.get("description") is None
                     else 'set vlans %s description "%s"' % (name, text_value(after["description"])))
    return lines


def _rename_references(references, old, new) -> list:
    """The statements that name the renamed VLAN, moved to the new name in the same commit."""
    lines = []
    for kind, line in references:
        if kind in ("member", "voip"):
            path = line.removeprefix("set ").rsplit(" ", 1)[0]
        elif kind in ("protocol", "mstp"):
            path = line
        else:
            continue
        if kind in ("member", "mstp"):
            lines += ["delete %s %s" % (path, old), "set %s %s" % (path, new)]
        elif kind == "voip":
            lines.append("set %s %s" % (path, new))
        elif kind == "protocol":
            # The IGMP snooping CLI requires the VLAN hierarchy keyword after "to".
            destination = "vlan " + new if path == "protocols igmp-snooping vlan" else new
            lines.append("rename %s %s to %s" % (path, old, destination))
    return list(dict.fromkeys(lines))


def render_state(snapshot, table, key, before, after, restore=None, *, incremental_members=False) -> list:
    if table in G139_TABLES:
        return _session(l3_lines(snapshot, table, key, before, after))
    if table in routing.TABLES:
        return _session(routing.render(table, key, before, after))
    if table in fltr.TABLES:
        # a filter with several terms prints more rows than one CLI screen: the unpaged compare of G140
        return _session(fltr.render(table, key, before, after), compare=junos_g140.COMPARE)
    if table in srx.TABLES:
        return _session(srx.render(snapshot, table, key, before, after, restore))
    if table in dhcp.TABLES:
        return _session(dhcp.render(table, key, before, after))
    if table in G145_TABLES:
        return _session(g145_lines(table, key, before, after))
    if table == "vlan":
        return _session(_vlan_lines(snapshot, key, before, after))
    return _session(_membership_lines(snapshot, key, before, after, incremental=incremental_members))


def render_inverse(snapshot, table, key, before, after, *, incremental_members=False) -> list:
    """The inverse of a state plan, rendered against the configuration after the change: the references of a renamed
    VLAN are then those of the new name."""
    if table == "vlan" and before is not None and after is not None and before.get("name") != after.get("name"):
        lines = ["rename vlans %s to %s" % (after["name"], before["name"])]
        lines += _rename_references(snapshot.vlan_references(before["name"]), after["name"], before["name"])
        if before.get("description") != after.get("description"):
            lines.append("delete vlans %s description" % before["name"] if before.get("description") is None
                         else 'set vlans %s description "%s"' % (before["name"], text_value(before["description"])))
        return _session(lines)
    return render_state(snapshot, table, key, after, before, incremental_members=incremental_members)


def interface_kind(key: str) -> str:
    if MANAGEMENT.fullmatch(key):
        return "management"
    if PHYSICAL.fullmatch(key):
        return "ethernet"
    return "other"


def disruptive(table: str, before, after) -> bool:
    """A change that can cut or restore traffic on the port: admin state in either direction or another VLAN
    membership of the port (a voice VLAN alone keeps the data VLAN of the port).

    Enabling a disabled uplink or LAG member can bring back a loop, so admin up gets the same port checks as admin
    down; the description alone does not."""
    before, after = before or {}, after or {}
    if table in (BOUNCE_TABLE, *POE_TABLES):
        return True
    if table == "interface":
        # 1.0.12 G138 (J23): speed, auto-negotiation and MTU restart the link of the port
        return (after.get("admin-state", "enabled") != before.get("admin-state", "enabled")
                or any(after.get(name) != before.get(name) for name in LINK_PARAMETERS))
    if table != "vlan-membership":
        return False
    names = set(before) | set(after)
    return any(before.get(name) != after.get(name) for name in names if name not in QUIET)


def origin(snapshot, table, key, edits) -> list:
    """The preview text about where the statements of the port come from and which ports an edit changes."""
    _found, owners, _unsupported = snapshot.owners(table, key)
    texts = []
    for category, source in sorted(owners.items()):
        if source.kind == "interface" or category not in edits:
            continue
        texts.append("%s of %s is inherited from %s; the change edits it there and applies to %s"
                     % (category, key, source.describe(), ", ".join(source.scope or [key])))
    return texts


def _check_membership(snapshot, key, after):
    after = after or {}
    if after.get("mode", "access") == "trunk":
        if not after.get("trunk-vlans"):
            raise Rejected(["a trunk needs trunk-vlans (the tagged VLANs)"])
        wrong = [name for name in ACCESS_ATTRIBUTES if name in after]
        if wrong:
            raise Rejected(["a trunk has no %s: remove it in the same request (null)" % ", ".join(wrong)])
    else:
        wrong = [name for name in TRUNK_ATTRIBUTES if name in after]
        if wrong:
            raise Rejected(["an access port has no %s: remove it in the same request (null)" % ", ".join(wrong)])
    names = _members(after) + ([after["voice-vlan"]] if after.get("voice-vlan") else [])
    missing = sorted({name for name in names if name not in snapshot.vlans})
    if missing:
        raise Rejected(["VLAN %s is not in the configuration; Junos checks a VLAN name only at commit time, so the "
                        "change is refused" % ", ".join(missing)], reason_codes=["vlan_missing"])
    if after.get("native-vlan") is not None:
        number = after["native-vlan"]
        name = snapshot.vlan_name(number)
        if name is None:
            raise Rejected(["native VLAN %s is not a VLAN ID of the configuration" % number],
                           reason_codes=["vlan_missing"])
        if name not in _members(after):
            # measured: a native-vlan-id whose VLAN is not a member is committed but the port does not carry it
            raise Rejected(["the native VLAN %s (%s) must be one of the trunk-vlans" % (number, name)])
    if after.get("voice-vlan"):
        if after["voice-vlan"] == after.get("access-vlan", DEFAULT_VLAN):
            raise Rejected(["the voice VLAN must differ from the access VLAN"])
        if not snapshot.lldp_med_enabled(key):
            raise Rejected(["LLDP-MED is not enabled on %s (set protocols lldp-med interface %s or all); a phone "
                            "would not learn its voice VLAN, so the change is refused" % (key, key)])


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table in G139_TABLES:
        l3_prechecks(snapshot, profile.table, key, after)
        return []
    if profile.table in G145_TABLES:
        return g145_prechecks(snapshot, profile.table, op, key, after)
    if profile.table == "vlan":
        return _vlan_prechecks(snapshot, op, key, after)
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
    entry = snapshot._entry(profile.table, key)
    if entry.unsupported:
        raise Rejected(["object %r holds configuration outside the profile: %s" % (key, ", ".join(entry.unsupported))])
    before = entry.attributes
    if profile.table == "vlan-membership" or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of an aggregated Ethernet interface; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        # Preserve the static refusal for admin state. Other disruptive operations also check port use at the device.
        if (profile.table == "interface" and (after or {}).get("admin-state", "enabled") != before.get(
                "admin-state", "enabled") and any(TRUNK.match(line) for line in lines)):
            raise Rejected(["port %s is a trunk; a trunk is treated as an uplink and is not changed" % key],
                           reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
    if profile.table == "vlan-membership":
        if not any(line.startswith(MODE + " ") for line in lines):
            raise Rejected(["port %s is not configured as a switching port (%s access or trunk)" % (key, MODE)],
                           reason_codes=["port_not_access"])
        _check_membership(snapshot, key, after)
        _found, owners, _unsupported = snapshot.owners(profile.table, key)
        edits = _membership_edits(before, after)
        for category, source in sorted(owners.items()):
            others = [port for port in (source.scope if source.scope is not None else ["?"]) if port != key]
            if category in edits and source.kind != "interface" and others:
                raise Rejected(["%s of %s is inherited from %s, which also configures %s; Admin edits the source "
                                "of the statement, so the change would reach those ports too and is refused"
                                % (category, key, source.describe(), ", ".join(others))],
                               reason_codes=["inherited_shared"])
    return []


def notes(snapshot, table, op, key, before, after) -> list:
    """Preview texts of a state plan: the origin of inherited statements and what a VLAN change keeps."""
    if table in routing.TABLES + srx.TABLES + dhcp.TABLES:
        return []
    if table in fltr.TABLES:
        return fltr.notes(table, after)
    if table in G145_TABLES:
        return g145_notes(snapshot, table, op, key, before, after)
    if table == "vlan-membership":
        return origin(snapshot, table, key, _membership_edits(before, after))
    if table != "vlan":
        return []
    if op == "create":
        return ["VLAN ID %s and name %s are unused in the configuration" % (key, after["name"])]
    name = before["name"]
    if op == "delete":
        return ["VLAN %s is not named by any port, IRB or other statement" % name]
    if after["name"] == name:
        return []
    irb = before.get("l3-interface")
    moved = {(kind, line) for kind, line in snapshot.vlan_references(name) if kind != "other"}
    return ["rename keeps VLAN ID %s%s; references moved to the new name: %d"
            % (key, " and its IRB %s" % irb if irb else "", len(moved))]


def _vlan_prechecks(snapshot, op, key, after) -> list:
    entries = snapshot._vlan_entries()
    current = entries.get(key)
    texts = []
    if op != "delete":
        name = after["name"]
        if name.casefold() in ("default", "all", "none"):
            raise Rejected(["VLAN name %s is reserved" % name], reason_codes=["vlan_name_reserved"])
        if (current is None or current.attributes["name"] != name) and name in snapshot.vlans:
            raise Rejected(["VLAN name %s is already used in the configuration" % name])
    if op == "create":
        return texts
    name = current.attributes["name"]
    references = snapshot.vlan_references(name)
    if op == "delete":
        numeric = sum(line.endswith(" %s %s" % (NATIVE, key)) for line in snapshot.lines)
        used = len(references) + numeric + ("l3-interface" in current.attributes)
        if used:
            raise Rejected(["VLAN %s (ID %s) is used by %d statements; remove them first" % (name, key, used)],
                           reason_codes=["vlan_in_use"])
        return texts
    if after["name"] != name:
        other = sum(kind == "other" for kind, _line in references)
        if other:
            raise Rejected(["VLAN %s is named by %d statements Admin does not move with a rename" % (name, other)],
                           reason_codes=["vlan_in_use"])
    return texts


def snapshot_after(text: str, plan) -> str:
    """The set-format configuration with the planned lines applied (for the audit prediction): set adds a statement
    (a single value replaces the old one), delete removes a statement and everything below it, rename moves a
    VLAN."""
    if plan["table"] in routing.TABLES + fltr.TABLES:
        snapshot = load(text, plan["firmware"])
        module = routing if plan["table"] in routing.TABLES else fltr
        lines = module.predicted_lines(snapshot, plan["table"], plan["key"], plan["predicted"]["after"])
        return "\n".join(lines) + "\n"
    if plan["table"] in srx.TABLES:
        snapshot = load(text, plan["firmware"])
        lines = srx.predicted_lines(snapshot, plan["table"], plan["key"], plan["predicted"]["after"])
        return "\n".join(lines) + "\n"
    if plan["table"] in dhcp.TABLES:
        snapshot = load(text, plan["firmware"])
        lines = dhcp.predicted_lines(snapshot, plan["table"], plan["key"], plan["predicted"]["after"])
        return "\n".join(lines) + "\n"
    lines = [line for line in text.replace("\r", "").split("\n") if line.strip()]
    for command in plan["commands"]:
        words = command.split()
        if words[:1] == ["set"] and words[1:2] != ["cli"]:
            lines = _predict_set(lines, command)
        elif words[:1] == ["delete"]:
            target = "set " + command[len("delete "):]
            lines = [line for line in lines if line != target and not line.startswith(target + " ")]
        elif words[:1] == ["rename"]:
            if words[1:4] == ["protocols", "igmp-snooping", "vlan"] and words[-3:-1] == ["to", "vlan"]:
                words.pop(-2)
            if words[-2:-1] != ["to"]:
                continue
            old = " ".join(["set", *words[1:-2]])
            new = " ".join(["set", *words[1:-3], words[-1]])
            lines = [new + line[len(old):] if line == old or line.startswith(old + " ") else line for line in lines]
    return "\n".join(lines) + "\n"


AUTONEG = re.compile(r"^set (interfaces \S+) ether-options (?:no-)?auto-negotiation$")
# 1.0.12 G145 r2: the message selectors "<facility> <severity>" of a remote host: the facilities of "set system syslog host <ip> ?"
# (measured, task-evidence/g145/probe1/help.txt); "any" is the severity of all facilities, each other facility has an
# attribute "severity-<facility>"
SYSLOG_FACILITIES = ("authorization", "change-log", "conflict-log", "daemon", "dfc", "external", "firewall", "ftp",
                     "interactive-commands", "kernel", "ntp", "pfe", "security", "user")
SINGLE = re.compile(r"^(set chassis aggregated-devices ethernet device-count"
                    r"|set protocols rstp (?:bridge-priority|interface \S+ cost)"
                    r"|set interfaces \S+ ether-options 802\.3ad"
                    r"|set .*? (?:description|vlan-id|native-vlan-id|interface-mode|speed|mtu)"
                    r"|set switch-options voip interface \S+ vlan"
                    r"|set system (?:host-name|domain-name)"
                    r"|set system syslog host \S+ (?:any|port|facility-override|" + "|".join(SYSLOG_FACILITIES) + r")) ")


def _predict_set(lines, command) -> list:
    if re.fullmatch(r"set protocols rstp bridge-priority [0-9]+", command):
        number = int(command.split()[-1])
        if number:
            command = "set protocols rstp bridge-priority %dk" % (number // 1024)
    shown = re.sub(r' description "([^" ]*)"$', r" description \1", command)
    if MEMBERS + " " in shown:
        return lines if shown in lines else lines + [shown]
    toggle = AUTONEG.fullmatch(shown)
    if toggle is not None:
        # measured (task netops-20261119-559): the two statements replace each other
        kept = [line for line in lines if not AUTONEG.fullmatch(line) or AUTONEG.fullmatch(line)[1] != toggle[1]]
        return kept + [shown]
    single = SINGLE.match(shown) or L3_SINGLE.match(shown)
    if single is not None:
        head = single.group(1) + " "
        kept = [line for line in lines if not line.startswith(head)]
        return kept + [shown]
    return lines if shown in lines else lines + [shown]


# ---- 1.0.12 G139: static routes, IRB and IPv4 VRRP on IRB ----

ROUTE_ROW = re.compile(r"(routing-options (?:rib (inet6?\.0) )?static route) (\S+)(?: (.*))?")
IRB_ROW = re.compile(r"interfaces irb unit ([0-9]+)(?: (.*))?")
IRB_ADDRESS = re.compile(r"family (inet6?) address (\S+)(?: (.*))?")
VRRP_ROW = re.compile(r"vrrp-group ([0-9]+)(?: (.*))?")
IRB_FAMILIES = {"inet": "ipv4-address", "inet6": "ipv6-address"}
ROUTE_DEFAULT_PREFERENCE = "5"


def route_network(key):
    try:
        network = ipaddress.ip_network(key)
        if key == str(network):
            return network
    except ValueError:
        pass
    raise Rejected(["use a canonical network prefix for the static route"], reason_codes=["junos_l3_scope"])


def _l3_values(entry, tail, keywords):
    name, _, value = (tail or "").partition(" ")
    if name in keywords and value and len(value.split()) == 1:
        try:
            value = l3_changes("", entry.name, {name: value})[name]
        except Rejected:
            entry.unsupported.append("invalid L3 address")
        else:
            _once(entry, name, value)
    else:
        entry.unsupported.append("statement outside the L3 profile")


def _l3_set_rows(snapshot):
    return [row[4:] for row in snapshot.lines if row.startswith("set ")]


L3_SINGLE = re.compile(r"^(set (?:routing-options .+ preference|interfaces irb .+ vrrp-group [0-9]+ priority"
                       r"|vlans \S+ l3-interface)) ")


def l3_changes(table, key, changes):
    """Canonical addresses also keep the predicted and saved representations identical."""
    if table == ROUTE_TABLE:
        route_network(key)
    for name, value in changes.items():
        if value is not None and name in ("preference", "priority") and not re.fullmatch(r"[0-9]+", value):
            raise Rejected([f"{name} is not an integer"], reason_codes=["junos_l3_scope"])
        if name not in ("next-hop", "ipv4-address", "ipv6-address", "virtual-address"):
            continue
        if value is None:
            continue
        try:
            if "%" in value:
                raise ValueError
            if name in IRB_FAMILIES.values():
                parser = ipaddress.IPv4Interface if name == "ipv4-address" else ipaddress.IPv6Interface
            else:
                parser = ipaddress.IPv4Address if name == "virtual-address" else ipaddress.ip_address
            address = parser(value)
            if name == "ipv6-address" and address.ip.is_link_local:
                raise ValueError
            changes[name] = str(address)
        except ValueError:
            raise Rejected([f"{name} has an invalid IP address or prefix length"],
                           reason_codes=["junos_l3_scope"]) from None
    return changes


def l3_entries(snapshot, table):
    entries = {}
    for row in _l3_set_rows(snapshot):
        if table == ROUTE_TABLE and (match := ROUTE_ROW.fullmatch(row)):
            _, rib, prefix, tail = match.groups()
            try:
                network = ipaddress.ip_network(prefix)
            except ValueError:
                continue
            entry = entries.setdefault(str(network), Entry(str(network)))
            if rib != ("inet6.0" if network.version == 6 else None):
                entry.unsupported.append("static route in a different RIB hierarchy")
            else:
                _l3_values(entry, tail, ("next-hop", "preference"))
        elif table != ROUTE_TABLE and (match := IRB_ROW.fullmatch(row)):
            unit, tail = match.groups()
            irb = "irb." + unit
            address = IRB_ADDRESS.fullmatch(tail or "")
            if table == IRB_TABLE:
                entry = entries.setdefault(irb, Entry(irb))
                if address and address[3] is None:
                    _l3_values(entry, IRB_FAMILIES[address[1]] + " " + address[2], IRB_FAMILIES.values())
                else:
                    entry.unsupported.append("statement outside the IRB profile")
            elif address and address[1] == "inet" and (vrrp := VRRP_ROW.fullmatch(address[3] or "")):
                key = irb + ":" + vrrp[1]
                entry = entries.setdefault(key, Entry(key))
                if vrrp[2] in ("preempt", "no-preempt"):
                    _once(entry, "preempt", "enabled" if vrrp[2] == "preempt" else "disabled")
                else:
                    _l3_values(entry, vrrp[2], ("virtual-address", "priority"))
    if table == IRB_TABLE:
        for name, lines in snapshot.vlan_lines.items():
            for line in lines:
                if line.startswith(VLAN_IRB) and VLAN_IRB_VALUE.fullmatch(irb := line[len(VLAN_IRB):]):
                    entry = entries.setdefault(irb, Entry(irb))
                    if VLAN_NAME.fullmatch(name):
                        _once(entry, "vlan", name)
                    else:
                        entry.unsupported.append("unsupported name of linked VLAN")
    return entries


def l3_own_lines(snapshot, table, key):
    if table == ROUTE_TABLE:
        return {row for row in snapshot.lines if row.startswith("set ")
                and (route := ROUTE_ROW.fullmatch(row[4:])) and route[3] == key}
    irb, _, number = key.partition(":")
    unit = "set interfaces irb unit " + irb[4:]
    if table == IRB_TABLE:
        return {row for row in snapshot.lines if row == unit or row.startswith(unit + " ")
                or re.fullmatch(r"set vlans \S+ l3-interface " + re.escape(irb), row)}
    group = re.compile(re.escape(unit) + r" family inet address \S+ vrrp-group " + number + r"(?: .*)?")
    return {row for row in snapshot.lines if group.fullmatch(row)}


def _without_vrrp_group(lines, owned):
    # display set emits the bare address only when the address has no children.
    # Keep it in the digest wherever removing the managed group leaves it as a leaf.
    others = [line for line in lines if line not in owned]
    inserted = set()
    kept = []
    for row in lines:
        if row not in owned:
            kept.append(row)
            continue
        address = row.split(" vrrp-group ", 1)[0]
        if address not in inserted and not any(other == address or other.startswith(address + " ") for other in others):
            kept.append(address)
            inserted.add(address)
    return kept


def irb_addresses(snapshot, key, family):
    prefix = "interfaces irb unit " + key[4:] + " "
    return {address[2] for row in _l3_set_rows(snapshot) if row.startswith(prefix)
            and (address := IRB_ADDRESS.fullmatch(row[len(prefix):])) and address[1] == family}


def _vrrp_path(snapshot, key):
    irb, group = key.split(":")
    local = irb_addresses(snapshot, irb, "inet")
    if len(local) != 1:
        raise Rejected(["the IRB must have exactly one configured IPv4 address for VRRP"],
                       reason_codes=["junos_l3_scope"])
    address, = local
    try:
        canonical = ipaddress.IPv4Interface(address)
    except ValueError:
        raise Rejected(["the local VRRP address is not recognised"], reason_codes=["junos_l3_scope"]) from None
    return f"interfaces irb unit {irb[4:]} family inet address {canonical} vrrp-group {group}", canonical


def _leaf_edits(path, attributes, before, after):
    lines = []
    for name in attributes:
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        replaces = name in ("preference", "priority")
        if old is not None and (new is None or not replaces):
            lines.append(f"delete {path} {name}" + ("" if replaces else " " + old))
        if new is not None:
            lines.append("set " + path + " " + name + " " + new)
    return lines


def l3_lines(snapshot, table, key, before, after):
    old, new = before or {}, after or {}
    if table == ROUTE_TABLE:
        family = route_network(key).version
        rib = " rib inet6.0" if family == 6 else ""
        path = f"routing-options{rib} static route {key}"
        if after is None:
            return ["delete " + path]
        return _leaf_edits(path, ("next-hop", "preference"), old, new)
    if table == VRRP_TABLE:
        path, _ = _vrrp_path(snapshot, key)
        if after is None:
            return ["delete " + path]
        edits = _leaf_edits(path, ("virtual-address", "priority"), old, new)
        modes = {"enabled": "preempt", "disabled": "no-preempt"}
        if old.get("preempt") != new.get("preempt"):
            if "preempt" in old:
                edits.append(f"delete {path} {modes[old['preempt']]}")
            if "preempt" in new:
                edits.append(f"set {path} {modes[new['preempt']]}")
        return edits
    path = "interfaces irb unit " + key[4:]
    edits = []
    if old.get("vlan") != new.get("vlan") and "vlan" in old:
        edits.append(f"delete vlans {old['vlan']} l3-interface")
    if after is None:
        edits.append("delete " + path)
        return edits
    for family, attribute in IRB_FAMILIES.items():
        family_path = f"{path} family {family}"
        if attribute in old and attribute not in new:
            edits.append("delete " + family_path)
        else:
            edits.extend(_leaf_edits(family_path, ("address",),
                                     {"address": old.get(attribute)}, {"address": new.get(attribute)}))
    if old.get("vlan") != new.get("vlan") and "vlan" in new:
        edits.append(f"set vlans {new['vlan']} l3-interface {key}")
    return edits


def _paths_intersect(first, second):
    return first == second or first.startswith(second + " ") or second.startswith(first + " ")


def _l3_scope(snapshot, paths, hierarchies):
    # Inspect applied groups as well as local ancestors and descendants. Never modify inherited or inactive values.
    rows = _l3_set_rows(snapshot)
    applied = {row.split()[-1] for row in rows if "apply-groups" in row.split()[:-1]}
    for row in rows:
        if re.search(r"(?:^| )apply-groups(?:-except)? ", row) and any(
                _paths_intersect(row.split(" apply-groups", 1)[0], path) for path in paths):
            raise Rejected(["the L3 object uses configuration inheritance"], reason_codes=["junos_l3_scope"])
        words = row.split()
        if words[:1] == ["groups"] and len(words) > 2 and words[2] in hierarchies and words[1] in applied:
            raise Rejected(["a configuration group can affect this L3 object"], reason_codes=["junos_l3_scope"])
    if any(_paths_intersect(row.partition(" ")[2], path) for row in snapshot.inactive for path in paths):
        raise Rejected(["the L3 object has inactive or protected statements"], reason_codes=["junos_l3_scope"])


def l3_prechecks(snapshot, table, key, after):
    state = after or {}
    if table == ROUTE_TABLE:
        network = route_network(key)
        prefix = f"static route {key}"
        _l3_scope(snapshot, ["routing-options " + prefix,
                             f"routing-options rib inet{6 if network.version == 6 else ''}.0 " + prefix],
                  {"routing-options"})
        if after is not None:
            try:
                hop = ipaddress.ip_address(state["next-hop"])
                if hop.version != network.version or hop.is_unspecified or hop.is_multicast:
                    raise ValueError
            except (ValueError, KeyError):
                raise Rejected(["next-hop must be an IP address in the route's family"],
                               reason_codes=["junos_l3_scope"]) from None
        return
    irb = key.split(":")[0]
    unit_path = "interfaces irb unit " + irb[4:]
    if table == VRRP_TABLE:
        group_path, local = _vrrp_path(snapshot, key)
        _l3_scope(snapshot, [group_path, unit_path], {"interfaces", "vlans"})
        if after is not None:
            address = local
            vip = ipaddress.IPv4Address(state["virtual-address"])
            priority = int(state.get("priority", "100"))
            if vip not in address.network or (vip == address.ip) != (priority == 255):
                raise Rejected(["the VRRP address must be on the IRB subnet, with priority 255 only for the owner"],
                               reason_codes=["junos_l3_scope"])
        return
    bindings = l3_entries(snapshot, IRB_TABLE).get(key)
    vlan_names = {state.get("vlan"), bindings.attributes.get("vlan") if bindings else None} - {None}
    _l3_scope(snapshot, [unit_path, *("vlans " + name for name in vlan_names)], {"interfaces", "vlans"})
    for row in _l3_set_rows(snapshot):
        if re.fullmatch(r"(?:routing-instances|bridge-domains|protocols) .+ " + re.escape(key), row):
            raise Rejected(["the IRB is referenced outside the profile"], reason_codes=["junos_l3_scope"])
    if after is None:
        return
    if not any(name in state for name in IRB_FAMILIES.values()):
        raise Rejected(["an IRB needs at least one address"], reason_codes=["junos_l3_scope"])
    vlan = state.get("vlan")
    if vlan is not None:
        if vlan == DEFAULT_VLAN or vlan not in snapshot.vlan_lines:
            raise Rejected(["the target VLAN must already exist and must not be the default VLAN"],
                           reason_codes=["vlan_missing"])
        attached = [line[len(VLAN_IRB):] for line in snapshot.vlan_lines[vlan] if line.startswith(VLAN_IRB)]
        if attached and attached != [key]:
            raise Rejected(["the target VLAN already has a different L3 interface"], reason_codes=["junos_l3_scope"])


# ---- 1.0.12 G145 (J31-J33): NTP servers, syslog hosts, DNS and the host name ----
#
# Measured on vJunos-switch 26.2R1.7 (d-vjunos, task-evidence/g145/probe1-3): every statement is one display set line,
# "set system ntp server <ip>" with "prefer" on the same line (no bare line beside it; deleting "prefer" leaves the
# bare line), "set system ntp source-address <ip>" is a list (a second address is added, not replaced), "set system
# syslog host <ip> any|port|facility-override <value>" are single values (a set replaces the old one), the
# name-servers keep their order of entry (a deleted and set again server moves to the end), an IPv6 address typed in
# upper case is shown in lower case, deleting the last statement of a server or a host removes it (no empty
# container is left), and the CLI prompt shows the new host name right after the commit, in the same session.

SYSTEM_TABLE, NTP_TABLE, SYSLOG_TABLE = "system", "ntp-server", "syslog-host"
G145_TABLES = (SYSTEM_TABLE, NTP_TABLE, SYSLOG_TABLE)
G145_NAMES = {SYSTEM_TABLE: "system", NTP_TABLE: "NTP server", SYSLOG_TABLE: "syslog host"}
SYSTEM_KEY = "system"
NTP_SERVER = re.compile(r"^set system ntp server (\S+)(?: (.*))?$")
NTP_SOURCE = re.compile(r"^set system ntp source-address (\S+)(?: (.*))?$")
SYSLOG_HOST = re.compile(r"^set system syslog host (\S+)(?: (.*))?$")
NAME_SERVER = re.compile(r"^set system name-server (\S+)(?: (.*))?$")
DOMAIN_NAME = re.compile(r"^set system domain-name (\S+)$")
# 1.0.12 G145 r2: the pattern of the host-name attribute (profiles/junos-system.json); a configured name outside it is
# refused before a change, so the undo of a confirmed change can always return the name read from the device
HOST_NAME_VALUE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                             r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
SYSLOG_OWN = {"any": "severity", "port": "port", "facility-override": "facility-override",
              **{name: "severity-" + name for name in SYSLOG_FACILITIES}}
# what the profile attributes of the system table are made of; any other statement of the system stanza stays
SYSTEM_ATTRIBUTES = ("host-name", "domain-name", "name-servers", "ntp-source-address")


def canonical_address(value: str) -> str:
    """A unicast IPv4 or IPv6 address as Junos shows it (IPv6 compressed in lower case, measured)."""
    import ipaddress
    try:
        if not isinstance(value, str) or value != value.strip() or "%" in value:
            raise ValueError(value)
        address = ipaddress.ip_address(value)
    except ValueError:
        raise Rejected(["%r is not an IPv4 or IPv6 address" % str(value)[:60]]) from None
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        raise Rejected(["%s is not a usable unicast address" % address])
    return str(address)


def canonical_addresses(value) -> str:
    """The ordered name-server list of a request (a list or a space separated text) as a space separated text."""
    items = value.split() if isinstance(value, str) else value
    if not isinstance(items, list) or not items or len(items) > 8:
        raise Rejected(["name-servers must be a list of 1 to 8 addresses"])
    found = [canonical_address(item) for item in items]
    if len(set(found)) != len(found):
        raise Rejected(["name-servers lists an address twice"])
    return " ".join(found)


def _g145_owner(line: str):
    """(table, key) of a set line that a G145 object owns, or None."""
    for pattern, table in ((NTP_SERVER, NTP_TABLE), (SYSLOG_HOST, SYSLOG_TABLE)):
        match = pattern.match(line)
        if match is not None:
            return table, match.group(1)
    if (HOST_NAME.match(line) or DOMAIN_NAME.match(line) or NAME_SERVER.match(line) or NTP_SOURCE.match(line)):
        return SYSTEM_TABLE, SYSTEM_KEY
    return None


def _g145_foreign(snapshot) -> list:
    """Configuration that can reach the G145 statements in a way the adapter does not evaluate: groups that configure
    the system stanza, apply-groups inside it, and deactivated or protected system statements."""
    found = []
    if any("system" in parts for parts in snapshot.group_other.values()):
        found.append("system configuration from groups")
    if any(line.startswith("set system ") and " apply-groups" in line for line in snapshot.lines):
        found.append("apply-groups in the system stanza")
    return found


def _inactive_for(snapshot, prefix: str) -> bool:
    rows = [line.split(" ", 1)[1] if " " in line else "" for line in snapshot.inactive]
    return any(row == prefix or row.startswith(prefix + " ") or prefix.startswith(row + " ") and row.startswith("system")
               for row in rows)


def g145_entries(snapshot, table: str) -> dict:
    foreign = _g145_foreign(snapshot)
    if table == SYSTEM_TABLE:
        entry = Entry(SYSTEM_KEY)
        servers, sources = [], []
        for line in snapshot.lines:
            host = HOST_NAME.match(line)
            domain = DOMAIN_NAME.match(line)
            server = NAME_SERVER.match(line)
            source = NTP_SOURCE.match(line)
            if host is not None:
                _once(entry, "host-name", host.group(1))
                if len(host.group(1)) > 63 or not HOST_NAME_VALUE.fullmatch(host.group(1)):
                    entry.unsupported.append("host-name outside the profile pattern")
            elif line.startswith("set system host-name "):
                entry.unsupported.append("host-name with quotes")
            elif domain is not None:
                _once(entry, "domain-name", domain.group(1))
            elif line.startswith("set system domain-name "):
                entry.unsupported.append("domain-name with quotes")
            elif server is not None:
                if server.group(2):
                    entry.unsupported.append("name-server %s %s" % (server.group(1), server.group(2).split()[0]))
                servers.append(server.group(1))
            elif source is not None:
                if source.group(2):
                    entry.unsupported.append("ntp source-address %s %s" % (source.group(1), source.group(2).split()[0]))
                sources.append(source.group(1))
        if servers:
            entry.attributes["name-servers"] = " ".join(servers)
        if len(sources) > 1:
            entry.unsupported.append("%d ntp source-addresses" % len(sources))
        elif sources:
            entry.attributes["ntp-source-address"] = sources[0]
        if any(_inactive_for(snapshot, "system " + word) for word in ("host-name", "domain-name", "name-server",
                                                                       "ntp source-address", "ntp")):
            entry.unsupported.append("deactivated or protected statement")
        entry.unsupported.extend(foreign)
        return {SYSTEM_KEY: entry}
    pattern = NTP_SERVER if table == NTP_TABLE else SYSLOG_HOST
    found = {}
    for line in snapshot.lines:
        match = pattern.match(line)
        if match is None:
            continue
        name, rest = match.group(1), match.group(2) or ""
        entry = found.get(name)
        if entry is None:
            entry = found[name] = Entry(name)
            entry.unsupported.extend(foreign)
            word = "ntp server" if table == NTP_TABLE else "syslog host"
            if _inactive_for(snapshot, "system %s %s" % (word, name)):
                entry.unsupported.append("deactivated or protected statement")
        words = rest.split()
        if table == NTP_TABLE:
            if words == ["prefer"]:
                _once(entry, "prefer", "yes")
            elif words:
                entry.unsupported.append("ntp server %s" % words[0])
        elif len(words) == 2 and words[0] in SYSLOG_OWN:
            _once(entry, SYSLOG_OWN[words[0]], words[1])
        else:
            entry.unsupported.append("syslog host statement %s" % (words[0] if words else "without a facility"))
    return found


def g145_lines(table, key, before, after) -> list:
    """The set and delete lines from the state before to the state after; only what differs is written."""
    before, after = before, after
    if table == NTP_TABLE:
        path = "system ntp server %s" % key
        if after is None:
            return ["delete " + path]
        if before is None:
            return ["set %s%s" % (path, " prefer" if after.get("prefer") == "yes" else "")]
        if before.get("prefer") == after.get("prefer"):
            return []
        return ["set %s prefer" % path if after.get("prefer") == "yes" else "delete %s prefer" % path]
    if table == SYSLOG_TABLE:
        path = "system syslog host %s" % key
        if after is None:
            return ["delete " + path]
        lines = []
        for word, name in SYSLOG_OWN.items():
            old, new = (before or {}).get(name), after.get(name)
            if old == new:
                continue
            lines.append("delete %s %s" % (path, word) if new is None else "set %s %s %s" % (path, word, new))
        return lines
    before, after = before or {}, after or {}
    lines = []
    if before.get("host-name") != after.get("host-name"):
        lines.append("set system host-name %s" % after["host-name"])
    if before.get("domain-name") != after.get("domain-name"):
        lines.append("delete system domain-name" if after.get("domain-name") is None
                     else "set system domain-name %s" % after["domain-name"])
    old, new = before.get("ntp-source-address"), after.get("ntp-source-address")
    if old != new:
        # a list on Junos: a set adds a second address, so the old one is deleted (measured)
        lines += (["delete system ntp source-address %s" % old] if old else []) + (
            ["set system ntp source-address %s" % new] if new else [])
    old, new = (before.get("name-servers") or "").split(), (after.get("name-servers") or "").split()
    if old != new:
        # the order is the order of entry: the servers from the first difference on are deleted and set again in the
        # wanted order (measured: a set server goes to the end), the common head stays untouched
        same = 0
        while same < min(len(old), len(new)) and old[same] == new[same]:
            same += 1
        lines += ["delete system name-server %s" % name for name in old[same:]]
        lines += ["set system name-server %s" % name for name in new[same:]]
    return lines


def g145_prechecks(snapshot, table, op, key, after) -> list:
    if table == SYSTEM_TABLE:
        if key != SYSTEM_KEY:
            raise Rejected(["the system table has the one key %r" % SYSTEM_KEY])
        source = (after or {}).get("ntp-source-address")
        if source and source != canonical_address(source):
            raise Rejected(["ntp-source-address must be written as %s" % canonical_address(source)])
        return []
    if canonical_address(key) != key:
        raise Rejected(["the key must be written as %s, the form Junos shows" % canonical_address(key)])
    if table == SYSLOG_TABLE and after is not None and not any(
            after.get(name) for name in SYSLOG_OWN.values() if name.startswith("severity")):
        # 1.0.12 G145 r2: a remote host selects its messages by "any <severity>" or "<facility> <severity>"
        raise Rejected(["a syslog host %s needs severity or a severity-<facility> (one message selector at least)"
                        % ("create" if op == "create" else "update")])
    return []


def g145_notes(snapshot, table, op, key, before, after) -> list:
    texts = []
    if table == SYSTEM_TABLE:
        before, after = before or {}, after or {}
        if before.get("host-name") != after.get("host-name"):
            texts.append("the CLI prompt shows the new host name %s right after the commit; Admin accepts the old "
                         "and the new name in its sessions" % after.get("host-name"))
        if before.get("name-servers") != after.get("name-servers"):
            texts.append("name-servers in order after the change: %s" % (after.get("name-servers") or "none"))
        return texts
    other = sorted(name for name in g145_entries(snapshot, table) if name != key)
    texts.append("other %ss stay unchanged: %s" % (G145_NAMES[table], ", ".join(other) or "none"))
    return texts


# ---- answers of the device (measured fixtures, ref/mereni-c8/fixtures) ----

BANNER = re.compile(r"^# commit confirmed will be rolled back in ")
PROMPT_TAIL = re.compile(r"^\S+@\S+[>#] ?$")
CONTEXT = re.compile(r"^\[edit(?: [^\]]*)?\]$")
# 1.0.12 G145: a value outside its range ("Value 70000 is not within range (0..65535) at '70000'", measured)
ERROR = re.compile(r"^(?:error:|syntax error|unknown command|missing argument|invalid |ambiguous "
                   r"|value \S+ is not within range)", re.IGNORECASE)
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
# G136: after "request system configuration rescue save" the history lists the rescue configuration as a row of its
# own (measured on vJunos-switch 26.2R1.7: "rescue  2026-11-19 02:10:53 UTC by <user> via cli"); it is no commit
RESCUE_ROW = re.compile(r"^rescue\s+[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC by \S+ via \S+\s*$")
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
        if not row.strip() or BANNER.match(row.strip()) or RESCUE_ROW.match(row):
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


def vlan_tags(text: str) -> dict:
    """VLAN ID -> name of show vlans (measured rows "default-switch <name> <tag>" with the member ports below)."""
    rows = answer_rows(text)
    if refused_answer(text) is not None or not rows or rows[0].split()[:3] != ["Routing", "instance", "VLAN"]:
        raise Rejected(["the VLAN list is not recognised"])
    found = {}
    for row in rows[1:]:
        words = row.split()
        if words[:1] == ["default-switch"]:
            if len(words) < 3 or not words[2].isdigit():
                raise Rejected(["the VLAN list is not recognised"])
            found[words[2]] = words[1]
    if not found:
        raise Rejected(["the VLAN list contains no VLAN rows"], reason_codes=[SNAPSHOT_INCOMPLETE])
    return found


VLAN_PORT = re.compile(r"^\s+(\S+?)\*?,(tagged|untagged),(access|trunk)\s*$")


def _extensive(text: str, name: str) -> list:
    rows = answer_rows(text)
    if refused_answer(text) is not None or not any(row.split()[:4] == ["VLAN", "Name:", name, "State:"]
                                                   for row in rows):
        raise Rejected(["the answer about VLAN %s is not recognised" % name])
    return rows


def vlan_port_mode(text: str, key: str):
    """The mode of the port in show vlans <name> extensive ("    ge-0/0/2.0*,untagged,access"; None when the port is
    not listed)."""
    rows = answer_rows(text)
    for row in rows:
        match = VLAN_PORT.match(row)
        if match is not None and match.group(1) == key + ".0":
            return match.group(3)
    if not any(row.startswith("VLAN Name: ") for row in rows):
        raise Rejected(["the VLAN answer is not recognised"])
    return None


def vlan_detail(text: str, name: str) -> dict:
    """Ports and learned MAC addresses of the VLAN in show vlans <name> extensive."""
    rows = _extensive(text, name)
    ports = [VLAN_PORT.match(row).group(1) for row in rows if VLAN_PORT.match(row)]
    count = [row.split(":", 1)[1].strip() for row in rows if row.startswith("Total MAC count:")]
    if len(count) != 1 or not count[0].isdigit():
        raise Rejected(["the answer about VLAN %s has no MAC count" % name])
    return {"interfaces": ports, "macs": int(count[0])}


def lldp_ports(text: str) -> set:
    """Local interfaces with an LLDP neighbor in show lldp neighbors (empty answer: no neighbor)."""
    rows = answer_rows(text)
    if not rows:
        return set()
    if rows[0].split()[:2] != ["Local", "Interface"]:
        raise unreadable("LLDP neighbor list")
    return {row.split()[0].split(".", 1)[0] for row in rows[1:] if row.split()}


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


# ---- 1.0.12 G138: PoE answer and the link of a port ----

POE_ROW = re.compile(r"^(Administrative status|Operational status)\s*:\s*(\S+)\s*$")
POE_POWERED = ("on", "powered-up")


def poe_state(text: str, key: str):
    """show poe interface <if> of an EX switch (Juniper EX documentation, fixtures/junos_g138/PROVENANCE.md): the
    block "PoE interface : <if>", "Administrative status : Enabled|Disabled" and "Operational status : ON|OFF|...".
    None when the device has no PoE controller for the port (vJunos answers only a warning): not capable. A block
    that names another port or lacks one of the two lines is unreadable (Rejected)."""
    rows = answer_rows(text)
    if not [row for row in rows if not row.startswith("warning:")]:
        return None
    found = {}
    named = None
    for row in rows:
        match = POE_ROW.match(row.strip())
        if match is not None:
            found[match.group(1)] = match.group(2)
        elif row.strip().startswith("PoE interface") and ":" in row and "status" not in row:
            named = row.split(":", 1)[1].strip()
    if named != key or set(found) != {"Administrative status", "Operational status"} \
            or found["Administrative status"] not in ("Enabled", "Disabled"):
        raise Rejected(["the PoE answer for %s is incomplete or unrecognised" % key],
                       reason_codes=["port_usage_unreadable"])
    return {"configured": found["Administrative status"].lower(),
            "state": "powered" if found["Operational status"].lower() in POE_POWERED else found["Operational status"].lower()}


def check_view(table: str, state):
    """The configuration-shaped part of the check account readback. Link parameters are checked separately."""
    if state is None:
        return state
    if table == ROUTE_TABLE:
        return {"preference": ROUTE_DEFAULT_PREFERENCE, **state}
    if table == VRRP_TABLE:
        return {"priority": "100", "preempt": "enabled", **state}
    if table == "interface":
        return {name: value for name, value in state.items() if name not in LINK_PARAMETERS}
    return state


def link_parameters(text: str, key: str) -> dict:
    """Read the physical interface's media fields, excluding logical units and link-partner values."""
    rows = answer_rows(text)
    if (not rows or not rows[0].startswith("Physical interface: %s," % key)
            or refused_answer(text) is not None or "---(more" in text.lower()):
        return {}
    media = []
    for row in rows[1:]:
        if row.lstrip().startswith(("Logical interface ", "Physical interface: ")):
            break
        if row.lstrip().startswith("Link-level type:"):
            media.append(row)
    if len(media) != 1:
        return {}
    fields = {}
    for field, name in (("MTU", "mtu"), ("Speed", "speed"), ("Auto-negotiation", "auto-negotiation")):
        values = re.findall(r"(?:^|,)\s*" + field + r":\s*([^,]+)", media[0])
        if len(values) == 1:
            fields[name] = values[0].strip().lower()
    speed = re.fullmatch(r"([0-9]+)\s*([mg])bps", fields.get("speed", ""))
    if speed:
        mbps = int(speed[1]) * (1000 if speed[2] == "g" else 1)
        fields["speed"] = "%dg" % (mbps // 1000) if mbps % 1000 == 0 else "%dm" % mbps
    return fields


def physical_up(text: str) -> list:
    """The physical Ethernet ports whose link is up in show interfaces terse (rows "ge-0/0/1  up  up")."""
    ports = []
    for row in answer_rows(text):
        words = row.split()
        if len(words) >= 3 and PHYSICAL.fullmatch(words[0]) and words[1:3] == ["up", "up"]:
            ports.append(words[0])
    return ports
