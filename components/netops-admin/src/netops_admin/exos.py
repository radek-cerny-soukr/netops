from __future__ import annotations

import hashlib
import re

from netops_auditor import l1_exos

from netops_admin.errors import Rejected
from netops_admin import membership

OWN_ATTRIBUTES = ("tag", "description")


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
        try:
            self.configuration = l1_exos.parse(text)
        except l1_exos.ParseError as exc:
            raise Rejected(["snapshot does not parse: %s" % exc]) from None
        if "vlan" not in self.configuration.modules:
            raise Rejected(["snapshot holds no vlan module; it is not a complete configuration"])
        self.commands = _without_safeguards(self.configuration.commands)
        self.vlans = {}
        for command in self.commands:
            if command.starts_with("create", "vlan") and len(command.tokens) >= 3:
                entry = self.vlans.setdefault(command.tokens[2], Entry(command.tokens[2]))
                if len(command.tokens) != 3:
                    entry.unsupported.append("line %d: create options" % command.line)
        self.ports, self.port_lists = {}, []
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
        return any(token.casefold() == folded for token in command.tokens)

    def entries(self, table: str):
        if table == "vlan-membership":
            result = {}
            for port, attrs in membership.states(self).items():
                entry = Entry(port)
                entry.attributes = attrs
                result[port] = entry
            return result
        if table == "ports":
            if self.port_lists:
                raise Rejected(["display strings are set on port lists (%s); they cannot be evaluated per port"
                                % ", ".join(self.port_lists)])
            return dict(self.ports)
        if table != "vlan":
            return None
        return dict(self.vlans)

    def entry_state(self, entry):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table in ("ports", "vlan-membership"):
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
        commands = _without_safeguards(self.configuration.commands, safeguard_id=safeguard_id)
        if table == "vlan-membership":
            return membership.rest_digest(self, key, commands)
        if table == "ports":
            lines = [command.text for command in commands
                     if not (_is_display_string(command) and command.tokens[2] == key)]
        else:
            lines = [command.text for command in commands if not self._is_own(command, key)]
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


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


def _is_display_string(command) -> bool:
    tokens = command.tokens
    return len(tokens) >= 5 and tokens[:2] == ("configure", "ports") and tokens[3] == "display-string"


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def render_create(profile, key: str, attributes: dict) -> list:
    lines = ["create vlan %s tag %s" % (key, attributes["tag"])]
    if "description" in attributes:
        lines.append('configure vlan %s description "%s"' % (key, attributes["description"]))
    return lines


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    if profile.table == "vlan-membership":
        return []
    if profile.table == "ports":
        lines = ["configure ports %s display-string %s" % (key, value) for value in assign.values()]
        return lines + ["unconfigure ports %s display-string" % key for _name in remove]
    lines = []
    if "description" in assign:
        lines.append('configure vlan %s description "%s"' % (key, assign["description"]))
    if "description" in remove:
        lines.append("unconfigure vlan %s description" % key)
    return lines


def render_delete(profile, key: str) -> list:
    return ["delete vlan %s" % key]


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table == "vlan-membership":
        return membership.prechecks(snapshot, key, membership.states(snapshot).get(key, {}), after)
    if op == "create" and after is not None and after.get("tag") in snapshot.tags():
        return ["tag %s is already used by another VLAN" % after["tag"]]
    return []


SAFEGUARD_PREFIX = "netops"
SAFEGUARD_NAME = re.compile(r"^netops[0-9a-f]{6}[pt]$")
ERROR_PREFIXES = ("%%", "Error:", "ERROR:")
QUERY_SWITCH = "show switch"
QUERY_VERSION = "show version"
QUERY_PROFILES = "show upm profile"
QUERY_TIMERS = "show upm timers"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SWITCH_CLOCK_FORMAT = "%a %b %d %H:%M:%S %Y"
SWITCH_TIME = re.compile(r"^Current Time:\s+(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s*$", re.MULTILINE)
SYSNAME = re.compile(r"^SysName:\s+(\S+)\s*$", re.MULTILINE)
IMAGE_VERSION = re.compile(r"^Image\s*:\s*ExtremeXOS version (\S+)", re.MULTILINE)
TIMER_ROW = re.compile(r"^(\S+)\s+(\S+)\s+([edop]+)(?:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?\s*$", re.MULTILINE)
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


def safeguard_script(inverse):
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
VLAN_DESCRIPTION = re.compile(r"^\s*Description:\s*(.*?)\s*$", re.MULTILINE)
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
    if description is not None and description.group(1) != NO_DESCRIPTION:
        attributes["description"] = description.group(1)
    return attributes


QUERY_SESSIONS = "show session"
SESSION_ROW = re.compile(r"^\s*(\*?)\d+\s+\w{3} \w{3} +\d", re.MULTILINE)


def foreign_sessions(text: str) -> int:
    rows = SESSION_ROW.findall(text)
    if not rows:
        raise Rejected(["the session list is not readable"])
    return sum(1 for marker in rows if marker != "*")


PORT_HEADER = re.compile(r"^Port:\s+(\d+)(?:\((.*)\))?:?\s*$", re.MULTILINE)
PORT_ABSENT = "Invalid port number"


def shown_port(text: str, key: str):
    header = PORT_HEADER.search(text)
    if header is None:
        if PORT_ABSENT in text:
            return None
        raise Rejected(["the check account answer about port %s is not recognised" % key])
    if header.group(1) != key:
        raise Rejected(["the check account answer names another port"])
    return {"display-string": header.group(2)} if header.group(2) else {}

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
