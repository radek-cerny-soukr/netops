from __future__ import annotations

import hashlib
import re

from netops_auditor import l1_exos

from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected
from netops_admin import membership

OWN_ATTRIBUTES = ("tag", "description")
DEFAULT_RECOVERY = ("configure", "sys-recovery-level", "switch", "reset")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SECRET_SUBJECTS = ("snmp", "snmpv3")
SECRET_WORDS = ("community", "encrypted", "password", "shared-secret")
FREE_TEXT = ("description", "description-string", "display-string", "syscontact", "syslocation", "sysname")
KEYWORDS = SECRET_SUBJECTS + SECRET_WORDS + FREE_TEXT


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        if not firmware:
            raise Rejected(["an ExtremeXOS configuration does not name its firmware; the caller must state it"])
        self.firmware = firmware
        self.inventory = None
        try:
            self.configuration = l1_exos.parse(text)
        except l1_exos.ParseError as exc:
            raise SnapshotRejected(["snapshot does not parse: %s" % exc], SNAPSHOT_UNREADABLE) from None
        if "vlan" not in self.configuration.modules:
            raise SnapshotRejected(["snapshot holds no vlan module; it is not a complete configuration"],
                                   SNAPSHOT_INCOMPLETE)
        self.commands = _without_safeguards(self.configuration.commands)
        self.vlans = {}
        for command in self.commands:
            if command.starts_with("create", "vlan") and len(command.tokens) >= 3:
                entry = self.vlans.setdefault(command.tokens[2], Entry(command.tokens[2]))
                if len(command.tokens) != 3:
                    entry.unsupported.append("line %d: create options" % command.line)
        self.ports, self.port_lists, self.inline_power = {}, [], {}
        for command in self.commands:
            if _is_port_disabled(command) or _is_poe_disabled(command):
                port = command.tokens[-1]
                table = self.ports if _is_port_disabled(command) else self.inline_power
                if not port.isdigit():
                    # a list disables several ports in one line: only the ports it names are refused
                    try:
                        listed = membership.ports(port)
                    except Exception:
                        self.port_lists.append("line %d" % command.line)
                        continue
                    for member in listed:
                        table.setdefault(member, Entry(member)).unsupported.append(
                            "line %d: %s on a port list" % (command.line, " ".join(command.tokens[:-1])))
                    continue
                entry = table.setdefault(port, Entry(port))
                if "admin-state" in entry.attributes:
                    entry.unsupported.append("line %d: repeated admin-state" % command.line)
                entry.attributes["admin-state"] = "disabled"
        for command in self.commands:
            if _is_display_string(command):
                port = command.tokens[2]
                if not port.isdigit():
                    self.port_lists.append("line %d" % command.line)
                    continue
                entry = self.ports.setdefault(port, Entry(port))
                if "display-string" in entry.attributes:
                    entry.unsupported.append("line %d: repeated display-string" % command.line)
                entry.attributes["display-string"] = " ".join(command.tokens[4:])
        for command in self.commands:
            owner = self._owner(command)
            if owner is not None:
                entry, name, value = owner
                if name in entry.attributes:
                    entry.unsupported.append("line %d: repeated %s" % (command.line, name))
                entry.attributes[name] = value

    def _entry(self, name: str):
        folded = name.casefold()
        for key, entry in self.vlans.items():
            if key.casefold() == folded:
                return entry
        return None

    def _owner(self, command):
        tokens = command.tokens
        if len(tokens) == 5 and tokens[:2] == ("configure", "vlan") and tokens[3] in OWN_ATTRIBUTES:
            entry = self._entry(tokens[2])
            if entry is not None:
                return entry, tokens[3], tokens[4]
        return None

    def _is_own(self, command, key: str) -> bool:
        folded = key.casefold()
        tokens = command.tokens
        if command.starts_with("create", "vlan") and len(tokens) >= 3 and tokens[2].casefold() == folded:
            return True
        owner = self._owner(command)
        return owner is not None and owner[0].name.casefold() == folded

    def _mentions(self, command, key: str) -> bool:
        folded = key.casefold()
        tokens = command.tokens if folded in KEYWORDS else _named_tokens(command)
        return any(token.casefold() == folded for token in tokens)

    def entries(self, table: str):
        if table == "vlan-membership":
            result = {}
            for port, attrs in membership.states(self).items():
                entry = Entry(port)
                entry.attributes = attrs
                result[port] = entry
            return result
        if table in ("ports", "inline-power"):
            if self.port_lists:
                raise Rejected(["port settings (display string, disabled port or inline power) are set on port lists"
                                " (%s); they cannot be evaluated per port" % ", ".join(self.port_lists)])
            return dict(self.ports if table == "ports" else self.inline_power)
        if table != "vlan":
            return None
        return dict(self.vlans)

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table in ("ports", "vlan-membership", "inline-power"):
            return []
        return sorted(
            "line %d (module %s)" % (command.line, command.module or "-")
            for command in self.commands
            if self._mentions(command, key) and not self._is_own(command, key)
        )

    def in_use(self, key: str) -> bool:
        return any(self._mentions(command, key) for command in self.commands)

    def tags(self) -> set:
        return {entry.attributes["tag"] for entry in self.vlans.values() if "tag" in entry.attributes}

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        commands = tuple(command for command in _without_safeguards(self.configuration.commands, safeguard_id=safeguard_id)
                         if not _default_recovery(command))
        if table == "vlan-membership":
            return membership.rest_digest(self, key, commands)
        if table == "inline-power":
            lines = [command.text for command in commands if not port_owned(command, table, key)]
            return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        if table == "ports":
            kept = tuple(command for command in commands if not port_owned(command, table, key))
            if self.inventory is not None:
                return membership.rest_digest(self, None, kept)
            lines = [command.text for command in kept]
        else:
            lines = [command.text for command in commands if not self._is_own(command, key)]
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _named_tokens(command) -> tuple:
    folded = tuple(token.casefold() for token in command.tokens)
    if folded[1:2] and folded[1] in SECRET_SUBJECTS:
        return ()
    kept = []
    for index, token in enumerate(command.tokens):
        if folded[index] in FREE_TEXT:
            break
        if index == 0 or folded[index - 1] not in SECRET_WORDS:
            kept.append(token)
    return tuple(kept)


def _without_safeguards(commands, safeguard_id=True) -> tuple:
    names = set(safeguard_names(safeguard_id).values()) if isinstance(safeguard_id, str) else set()
    def own(name):
        return bool(SAFEGUARD_NAME.fullmatch(name)) if safeguard_id is True else name in names
    kept, inside = [], False
    for command in commands:
        tokens = command.tokens
        if inside:
            inside = command.text.strip() != "."
            continue
        if command.module == "upm" and tokens[:3] == ("create", "upm", "profile") and len(tokens) == 4 \
                and own(tokens[3]):
            inside = True
            continue
        if command.module == "upm" and len(tokens) >= 4 and tokens[1:3] == ("upm", "timer") \
                and own(tokens[3]):
            continue
        kept.append(command)
    return tuple(kept)


def _default_recovery(command) -> bool:
    return tuple(token.casefold() for token in command.tokens) == DEFAULT_RECOVERY


def _is_display_string(command) -> bool:
    tokens = command.tokens
    return len(tokens) >= 5 and tokens[:2] == ("configure", "ports") and tokens[3] == "display-string"


def _is_port_disabled(command) -> bool:
    # show configuration prints a disabled port as "disable port N" (singular) in module vlan, whatever the
    # spelling of the command was (measured on 33.7.1.6-patch1-11, X435-8P-4S and X440-G2-12p-10G4)
    return len(command.tokens) == 3 and command.tokens[:2] == ("disable", "port") and command.module == "vlan"


def _is_poe_disabled(command) -> bool:
    # "disable inline-power ports N" keeps its plural spelling and sits in module poe (same measurement)
    return (len(command.tokens) == 4 and command.tokens[:3] == ("disable", "inline-power", "ports")
            and command.module == "poe")


def port_owned(command, table: str, key: str) -> bool:
    """The configuration line belongs to the per-port object of the table (display string or admin state)."""
    if table == "inline-power":
        return _is_poe_disabled(command) and command.tokens[3] == key
    return ((_is_display_string(command) and command.tokens[2] == key)
            or (_is_port_disabled(command) and command.tokens[2] == key))


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def port_order(port: str) -> tuple:
    return tuple(int(part) for part in port.split(":"))


def absent(snapshot, table: str, key: str) -> list:
    if table == "vlan-membership":
        if key in membership.lag_ports(snapshot):
            return [membership.LAG_REFUSAL]
        if snapshot.inventory is not None:
            if key not in snapshot.inventory:
                return ["port %s is not reported by the switch" % key]
            return [membership.NATIVE_REFUSAL]
    return ["object %r does not exist" % key]


def _text(value: str, spaces=True) -> str:
    if '"' in value or "\\" in value or CONTROL.search(value) or (not spaces and any(c.isspace() for c in value)):
        raise Rejected(["the value %r cannot be written safely: quotes, backslashes and control characters"
                        " are not supported" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    lines = ["create vlan %s tag %s" % (key, attributes["tag"])]
    if "description" in attributes:
        lines.append('configure vlan %s description "%s"' % (key, _text(attributes["description"])))
    return lines


ADMIN_STATES = ("enabled", "disabled")


def _admin_state(prefix: str, key: str, value: str) -> str:
    if value not in ADMIN_STATES:
        raise Rejected(["admin-state must be enabled or disabled"])
    return "%s %s %s" % ("disable" if value == "disabled" else "enable", prefix, key)


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    if profile.table == "vlan-membership":
        return []
    if profile.table == "inline-power":
        lines = [_admin_state("inline-power ports", key, value) for name, value in assign.items()]
        return lines + [_admin_state("inline-power ports", key, "enabled") for _name in remove]
    if profile.table == "ports":
        lines = []
        for name, value in assign.items():
            if name == "admin-state":
                lines.append(_admin_state("ports", key, value))
            else:
                lines.append("configure ports %s display-string %s" % (key, _text(value, spaces=False)))
        for name in remove:
            lines.append(_admin_state("ports", key, "enabled") if name == "admin-state"
                         else "unconfigure ports %s display-string" % key)
        return lines
    lines = []
    if "description" in assign:
        lines.append('configure vlan %s description "%s"' % (key, _text(assign["description"])))
    if "description" in remove:
        lines.append("unconfigure vlan %s description" % key)
    return lines


def render_delete(profile, key: str) -> list:
    return ["delete vlan %s" % key]


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table in ("ports", "inline-power") and snapshot.inventory is not None and key not in snapshot.inventory:
        return ["port %s is not reported by the switch" % key]
    if profile.table in ("ports", "inline-power"):
        port_state_prechecks(snapshot, profile, key, after)
    if profile.table == "vlan-membership":
        return membership.prechecks(snapshot, key, membership.states(snapshot).get(key, {}), after)
    if op == "create" and after is not None and after.get("tag") in snapshot.tags():
        return ["tag %s is already used by another VLAN" % after["tag"]]
    return []


# admin-state of ports and the inline-power cycle are measured only on this firmware (X435-8P-4S and
# X440-G2-12p-10G4, 33.7.1.6-patch1-11); the display string keeps the wider scope of the ports profile
PORT_ACTION_FIRMWARE = ("33.7.1.6",)


def _disabling(snapshot, table: str, key: str, after) -> bool:
    entries = snapshot.ports if table == "ports" else snapshot.inline_power
    before = entries.get(key).attributes if key in entries else {}
    return (after or {}).get("admin-state") == "disabled" and before.get("admin-state") != "disabled"


def touches_admin_state(snapshot, table: str, key: str, after) -> bool:
    entries = snapshot.ports if table == "ports" else snapshot.inline_power
    before = entries.get(key).attributes if key in entries else {}
    return (after or {}).get("admin-state", "enabled") != before.get("admin-state", "enabled")


def port_state_prechecks(snapshot, profile, key: str, after) -> None:
    if not touches_admin_state(snapshot, profile.table, key, after):
        return
    if snapshot.firmware not in PORT_ACTION_FIRMWARE:
        raise Rejected(["%s is measured only on ExtremeXOS %s, not on %s"
                        % ("the port admin state" if profile.table == "ports" else "the inline-power cycle",
                           ", ".join(PORT_ACTION_FIRMWARE), snapshot.firmware)],
                       reason_codes=["port_action_not_measured"])
    if profile.table == "inline-power":
        return
    if not _disabling(snapshot, profile.table, key, after):
        return
    if not vlan_module_closed(snapshot):
        raise Rejected(["the configuration ends inside its vlan module; VLAN and link aggregation membership of port %s "
                        "cannot be read completely" % key], reason_codes=["port_usage_unreadable"])
    if key in membership.lag_ports(snapshot):
        raise Rejected(["port %s belongs to a link aggregation; disabling it is refused" % key],
                       reason_codes=["port_lag_member"])
    _vlans, members, _descriptions = membership.model(snapshot)
    tagged = sorted(members.get(key, {}).get("tagged", ()))
    if tagged:
        raise Rejected(["port %s carries tagged VLANs (%d); a trunk is treated as an uplink and is not disabled"
                        % (key, len(tagged))], reason_codes=["port_uplink"])


def vlan_module_closed(snapshot) -> bool:
    """VLAN membership and link aggregation are read from the vlan module of show configuration; it is complete
    only when the switch printed another module after it (a dump cut off inside the vlan module is not)."""
    modules = list(snapshot.configuration.modules)
    return "vlan" in modules and modules.index("vlan") < len(modules) - 1


def management_vlan_member(snapshot, key: str, names) -> bool:
    folded = {name.casefold() for name in names or ()}
    if not folded:
        return False
    _vlans, members, _descriptions = membership.model(snapshot)
    modes = members.get(key, {})
    return any(name.casefold() in folded for mode in modes.values() for name in mode)


QUERY_LLDP = "show lldp neighbors"
QUERY_FDB = "show fdb"
LLDP_HEADER = re.compile(r"^Port\s+Chassis ID\s+Port ID\s+TTL\s+Age\s+System Name\s*$", re.MULTILINE)
LLDP_ROW = re.compile(r"^([1-9][0-9]*(?::[1-9][0-9]*)?)\s+\S", re.MULTILINE)
FDB_HEADER = re.compile(r"^MAC\s+VLAN Name\( Tag\)\s+Age\s+Flags\s+Port / Virtual Port List\s*$", re.MULTILINE)
FDB_ROW = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}[^\S\n]+\S+\(\d{4}\)[^\S\n]+\d+[^\S\n]+"
                     r"(?:[A-Za-z][^\S\n]+)*?([0-9][0-9:,-]*(?:,[^\S\n]*[0-9][0-9:,-]*)*)[^\S\n]*$", re.MULTILINE)
FDB_TOTAL = re.compile(r"^Total:\s+(\d+)\s", re.MULTILINE)


LLDP_SEPARATOR = re.compile(r"^={3,}$")
LLDP_NOTE = "NOTE: The Chassis ID and/or Port ID might be truncated to fit the screen."


def _lldp_unreadable(reason: str):
    return Rejected(["the LLDP neighbor list %s" % reason], reason_codes=["port_usage_unreadable"])


def lldp_ports(text: str) -> set:
    """Ports with an LLDP neighbor in show lldp neighbors; an unrecognised or incomplete answer is refused.

    The list counts as complete only in the measured layout (33.7.1.6, X435 and X440): the header, a separator,
    the rows, the closing separator and the closing NOTE line. A list cut off anywhere before the NOTE, even
    after valid rows, is refused instead of being read as "no neighbor"."""
    header = LLDP_HEADER.search(text)
    if header is None:
        raise _lldp_unreadable("is not recognised")
    lines = [line.rstrip() for line in text[header.end():].splitlines()]
    lines = [line for line in lines if line.strip()]
    if not lines or not LLDP_SEPARATOR.match(lines[0]):
        raise _lldp_unreadable("has no separator under the header")
    closing = next((index for index in range(1, len(lines)) if LLDP_SEPARATOR.match(lines[index])), None)
    if closing is None:
        raise _lldp_unreadable("is cut off (no closing separator)")
    trailer = lines[closing + 1:]
    if trailer != [LLDP_NOTE]:
        raise _lldp_unreadable("is cut off or ends in an unknown way (no closing NOTE line)")
    found = set()
    for line in lines[1:closing]:
        match = LLDP_ROW.match(line)
        if match is None:
            raise _lldp_unreadable("holds a row that is not recognised")
        found.add(match.group(1))
    return found


FDB_SEPARATOR = re.compile(r"^-{3,}\s*$", re.MULTILINE)


def fdb_ports(text: str) -> set:
    """Ports with learned MAC addresses in show fdb; the list is complete only with its separator under the header
    and the closing Total line after the last row, and the row count must equal that Total."""
    header = FDB_HEADER.search(text)
    if header is None:
        raise Rejected(["the forwarding database is not recognised"], reason_codes=["port_usage_unreadable"])
    separator = FDB_SEPARATOR.search(text, header.end())
    if separator is not None and text[header.end():separator.start()].strip():
        separator = None
    total = FDB_TOTAL.search(text)
    rows = list(FDB_ROW.finditer(text))
    if separator is None or total is None or int(total.group(1)) != len(rows) \
            or any(row.start() < separator.end() or row.end() > total.start() for row in rows):
        raise Rejected(["the forwarding database is incomplete"], reason_codes=["port_usage_unreadable"])
    found = set()
    for row in rows:
        try:
            found |= membership.ports(row.group(1).replace(" ", ""))
        except Exception:
            raise Rejected(["the forwarding database names a port list that is not recognised"],
                           reason_codes=["port_usage_unreadable"]) from None
    return found


PORT_STATES = {"E": "enabled", "D": "disabled", "F": "disabled by link-flap detection", "L": "disabled by licensing"}
LINK_STATES = {"A": "active", "R": "ready", "NP": "not present", "L": "loopback"}


def port_configuration(text: str, key: str):
    """Port State and Link State of show ports N configuration no-refresh, or None when not recognised."""
    if "Port Configuration" not in text:
        return None
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == key and words[2] in PORT_STATES:
            return {"port_state": PORT_STATES[words[2]], "link_state": LINK_STATES.get(words[3], words[3])}
    return None


SAFEGUARD_PREFIX = "netops"
SAFEGUARD_NAME = re.compile(r"^netops[0-9a-f]{6}[pt]$")
ERROR_PREFIXES = ("%%", "Error:", "ERROR:")
QUERY_SWITCH = "show switch"
QUERY_VERSION = "show version"
QUERY_PROFILES = "show upm profile"
QUERY_TIMERS = "show upm timers"
QUERY_PORTS = "show ports no-refresh"
PORT_ROW = re.compile(r"^([1-9][0-9]*(?::[1-9][0-9]*)?)\s", re.MULTILINE)
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SWITCH_CLOCK_FORMAT = "%a %b %d %H:%M:%S %Y"
SWITCH_TIME = re.compile(r"^Current Time:\s+(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s*$", re.MULTILINE)
SYSNAME = re.compile(r"^SysName:\s+(\S+)\s*$", re.MULTILINE)
IMAGE_VERSION = re.compile(r"^Image\s*:\s*ExtremeXOS version (\S+)", re.MULTILINE)
TIMER_ROW = re.compile(r"^(\S+)\s+(\S+)\s+([edop]+)(?:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?\s*$", re.MULTILINE)
UPM_SEPARATOR = re.compile(r"\s*(?:={3,}|-{3,})\s*")
PROFILE_BEGIN = "Profile Contents Begin"
PROFILE_END = "Profile Contents Ends"


def cli_error(text: str):
    for line in text.splitlines()[1:]:
        stripped = line.strip()
        if stripped.startswith(ERROR_PREFIXES):
            return stripped[:80]
    return None


def safeguard_names(change_id: str) -> dict:
    base = SAFEGUARD_PREFIX + change_id[:6]
    return {"profile": base + "p", "timer": base + "t"}


EXPANDED = "$("
EXPANDED_REFUSAL = "text with $( cannot be restored as a literal value by the timed safeguard"


def safeguard_script(inverse):
    if any(EXPANDED in line for line in inverse):
        raise Rejected([EXPANDED_REFUSAL])
    return ["configure cli mode persistent", "configure cli mode scripting ignore-error"] + [line.strip() for line in inverse]


def render_safeguard(change_id: str, inverse: list, seconds: int) -> list:
    names = safeguard_names(change_id)
    steps = [("ask", "create upm profile %s" % names["profile"], b"Start typing")]
    steps.extend(("raw", line) for line in safeguard_script(inverse))
    steps.extend((
        ".",
        "create upm timer %s" % names["timer"],
        "configure upm timer %s profile %s" % (names["timer"], names["profile"]),
        "configure upm timer %s after %d" % (names["timer"], seconds),
    ))
    return steps


def render_safeguard_removal(change_id: str) -> list:
    names = safeguard_names(change_id)
    return ["delete upm timer %s" % names["timer"], "delete upm profile %s" % names["profile"]]


def profile_contents(text: str):
    if PROFILE_BEGIN not in text or PROFILE_END not in text:
        return None
    body = text.split(PROFILE_BEGIN, 1)[1].split(PROFILE_END, 1)[0]
    return [line.strip() for line in body.splitlines() if line.strip() and not set(line.strip()) <= {"*"}]


def timer_row(text: str, timer: str):
    for match in TIMER_ROW.finditer(text):
        if match.group(1) == timer:
            return {"profile": match.group(2), "flags": match.group(3), "next": match.group(4)}
    return None


def upm_listing_complete(text: str, kind: str) -> bool:
    count = re.search(r"^[^\S\n]*Number of UPM %s:\s*(\d{1,9})\s*$" % kind, text, re.MULTILINE)
    if count is None:
        return False
    lines = text.splitlines()
    separators = [index for index, line in enumerate(lines) if UPM_SEPARATOR.fullmatch(line)]
    rows = [line for line in lines[separators[1] + 1:separators[2]] if line.strip()] if len(separators) >= 3 else []
    declared = int(count.group(1))
    return not rows if declared == 0 else len(rows) >= declared


def listed_names(text: str) -> list:
    names = []
    for line in text.splitlines():
        words = line.split()
        if words and words[0].startswith(SAFEGUARD_PREFIX):
            names.append(words[0])
    return names


def switch_field(pattern, text: str, label: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise Rejected(["the switch does not report its %s" % label])
    return " ".join(match.group(1).split())


ACCOUNT_COMMANDS = (("create", "account"), ("configure", "account"), ("create", "sshd2"), ("configure", "sshd2"))


def account_fingerprint(snapshot) -> str:
    lines = sorted(command.text.strip() for command in snapshot.commands if command.tokens[:2] in ACCOUNT_COMMANDS)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def accounts(snapshot) -> list:
    names = set()
    for command in snapshot.commands:
        tokens = command.tokens
        if tokens[:2] == ("create", "account") and len(tokens) >= 4:
            names.add(tokens[3])
        elif tokens[:2] == ("configure", "account") and len(tokens) >= 3:
            names.add(tokens[2])
    return sorted(names)


VLAN_HEADER = re.compile(r"^VLAN Interface with name (\S+) created", re.MULTILINE)
VLAN_TAG = re.compile(r"802\.1Q Tag (\d+)")
VLAN_DESCRIPTION = re.compile(r"^[^\S\n]*Description:\s*(.*)$", re.MULTILINE)
VLAN_ABSENT = "Invalid numeric list"
NO_DESCRIPTION = "None"


def shown_vlan(text: str, key: str):
    header = VLAN_HEADER.search(text)
    if header is None:
        if VLAN_ABSENT in text:
            return None
        raise Rejected(["the check account answer about VLAN %s is not recognised" % key])
    if header.group(1) != key:
        raise Rejected(["the check account answer names another VLAN"])
    attributes = {}
    tag = VLAN_TAG.search(text)
    if tag is not None:
        attributes["tag"] = tag.group(1)
    description = VLAN_DESCRIPTION.search(text)
    if description is not None and description.group(1).rstrip() != NO_DESCRIPTION:
        attributes["description"] = description.group(1).rstrip()
    return attributes


QUERY_SESSIONS = "show session"
SESSION_ROW = re.compile(r"^[^\S\n]*(\*?)\d+\s+\w{3} \w{3} +\d", re.MULTILINE)


def foreign_sessions(text: str) -> int:
    rows = SESSION_ROW.findall(text)
    if not rows:
        raise Rejected(["the session list is not readable"])
    return sum(1 for marker in rows if marker != "*")


PORT_HEADER = re.compile(r"^Port:\s+(\d+)(?:\((.*)\))?:?\s*$", re.MULTILINE)
PORT_ABSENT = "Invalid port number"
ADMIN_STATE_LINE = re.compile(r"^[^\S\n]*Admin state:\s+(Enabled|Disabled)\b", re.MULTILINE)


def shown_port(text: str, key: str, admin_state=False):
    header = PORT_HEADER.search(text)
    if header is None:
        if PORT_ABSENT in text:
            return None
        raise Rejected(["the check account answer about port %s is not recognised" % key])
    if header.group(1) != key:
        raise Rejected(["the check account answer names another port"])
    attributes = {"display-string": header.group(2)} if header.group(2) else {}
    state = ADMIN_STATE_LINE.findall(text)
    if admin_state and len(state) != 1:
        raise Rejected(["the check account answer about port %s shows no admin state" % key])
    if state and state[0] == "Disabled":
        attributes["admin-state"] = "disabled"
    return attributes


POE_NOT_CAPABLE = re.compile(r"\bPort (\S+) is not inline-power capable\b")
POE_INFO_HEADER = re.compile(r"^Port\s+State\s+Class\s+Volts\s+Curr\s+Power\s+Fault\s*$", re.MULTILINE)
POE_DETAIL = {
    "configured": re.compile(r"^Configured Admin State:\s*(enabled|disabled)\s*$", re.MULTILINE),
    "state": re.compile(r"^Inline Power State\s*:\s*(\S+)\s*$", re.MULTILINE),
    "class": re.compile(r"^PD Class\s*:[^\S\n]*(\S*)\s*$", re.MULTILINE),
    "power": re.compile(r"^Measured Power\s*:\s*([0-9.]+ W)\s*$", re.MULTILINE),
    "fault": re.compile(r"^Fault Status\s*:\s*(.*?)\s*$", re.MULTILINE),
}
POE_DETAIL_HEADER = re.compile(r"^Port (\S+)\s*$", re.MULTILINE)


class NotInlinePower(Rejected):
    pass


def poe_info(text: str, key: str) -> dict:
    """The row of port N in show inline-power info ports N (measured format), or a coded refusal."""
    refused = POE_NOT_CAPABLE.search(text)
    if refused is not None:
        if refused.group(1) != key:
            raise Rejected(["the inline-power answer names another port"], reason_codes=["poe_state_unreadable"])
        raise NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    if POE_INFO_HEADER.search(text) is None:
        raise Rejected(["the switch gives no inline-power table for port %s; the platform may have no PoE" % key],
                       reason_codes=["poe_unsupported"])
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 7 and words[0] == key:
            return {"state": words[1], "class": words[2], "power_watts": words[5], "fault": " ".join(words[6:])}
    raise Rejected(["the inline-power table holds no row for port %s" % key], reason_codes=["poe_state_unreadable"])


# measured (ref 171, X435 port 9 and X440 port 13): show inline-power info ports N on a port without PoE ends
# with exit status 250 and prints only this line
POE_NOT_CAPABLE_RC = 250


def poe_not_capable_answer(rc, text: str, key: str) -> bool:
    """True only for the measured refusal of a port without PoE: exit status 250 and the single line."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return rc == POE_NOT_CAPABLE_RC and lines == ["Port %s is not inline-power capable" % key]


def poe_detail(text: str, key: str) -> dict:
    """show inline-power info detail ports N: the configured admin state and the inline power state."""
    refused = POE_NOT_CAPABLE.search(text)
    if refused is not None and refused.group(1) == key:
        raise NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    header = POE_DETAIL_HEADER.search(text)
    if header is None or header.group(1) != key:
        raise Rejected(["the inline-power detail of port %s is not recognised" % key],
                       reason_codes=["poe_state_unreadable"])
    found = {}
    for name, pattern in POE_DETAIL.items():
        values = pattern.findall(text)
        if len(values) != 1:
            if name in ("configured", "state"):
                raise Rejected(["the inline-power detail of port %s shows no %s" % (key, name)],
                               reason_codes=["poe_state_unreadable"])
            continue
        found[name] = values[0]
    return found


def switch_ports(text: str) -> list:
    found = set(PORT_ROW.findall(text)) if "Port Summary" in text else set()
    if not found:
        raise Rejected(["the port list of the switch is not recognised"])
    return sorted(found, key=port_order)

def vlan_absent_from_list(text, key):
    if not all(word in text for word in ("Name", "VID", "Protocol", "Ports", "Flags")):
        return False
    total = re.search(r"^Total number of VLAN\(s\) : (\d+)\s*$", text, re.MULTILINE)
    if total is None:
        return False
    rows = re.findall(r"^([A-Za-z][A-Za-z0-9_-]{0,31})\s+([0-9]{1,4})\s+.+$", text, re.MULTILINE)
    names = [name for name, _tag in rows]
    if len(names) != int(total[1]) or len(set(names)) != len(names):
        return False
    folded = key.casefold()
    return not any(name.casefold() == folded or (len(name) >= 15 and folded.startswith(name.casefold()))
                   for name in names)
