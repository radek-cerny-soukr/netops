from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from netops_auditor import l1_fortios

from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_SCOPE_UNSUPPORTED,
                                 SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected)

HEADER = re.compile(
    r"^#config-version=[A-Z0-9]+-([0-9]+\.[0-9]+\.[0-9]+)-FW-build([0-9]+)-[0-9]+:opmode=[0-9]+:vdom=([0-9]+)"
)
MULTI_VDOM_SECTIONS = ("vdom", "global")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
NOT_FOUND = "entry is not found in table"
UNNAMED_PARTS = ("password", "passwd", "passphrase", "pwd", "secret", "psk", "key", "community", "token",
                 "comment", "description")
UNNAMED_ATTRIBUTES = {("system snmp community",): ("name",)}


def _named_values(node):
    for name, attr in node.attrs.items():
        folded = name.casefold()
        if any(part in folded for part in UNNAMED_PARTS) or name in UNNAMED_ATTRIBUTES.get(node.path[:1], ()):
            continue
        yield name, attr.values


def parse_snapshot(text: str):
    try:
        return l1_fortios.parse(text)
    except l1_fortios.TruncatedError as exc:
        raise SnapshotRejected(["snapshot is cut off: %s" % exc], SNAPSHOT_INCOMPLETE) from None
    except l1_fortios.ParseError as exc:
        raise SnapshotRejected(["snapshot does not parse: %s" % exc], SNAPSHOT_UNREADABLE) from None


def _repetitions(text: str) -> dict:
    found, stack, entries, attributes = {}, [()], set(), set()
    for number, raw in l1_fortios.logical_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = l1_fortios.tokenize(line)
        if not tokens:
            continue
        command = tokens[0]
        if command == "config":
            stack.append(stack[-1] + (" ".join(tokens[1:]),))
        elif command == "edit":
            path = stack[-1] + (tokens[1] if len(tokens) > 1 else "",)
            if path in entries:
                found.setdefault(path, []).append("line %d: repeated edit" % number)
            entries.add(path)
            stack.append(path)
        elif command in ("set", "unset") and len(tokens) > 1:
            if (stack[-1], tokens[1]) in attributes:
                found.setdefault(stack[-1], []).append("line %d: repeated %s" % (number, tokens[1]))
            attributes.add((stack[-1], tokens[1]))
        elif command in ("next", "end") and len(stack) > 1:
            stack.pop()
    return found


class Snapshot:
    def __init__(self, text: str, firmware: str | None = None):
        first = text.lstrip("﻿").split("\n", 1)[0].strip()
        match = HEADER.match(first)
        if match is None:
            raise SnapshotRejected(["snapshot does not identify its firmware: the #config-version header is missing"],
                                   SNAPSHOT_INCOMPLETE)
        self.firmware = "%s build%s" % (match.group(1), match.group(2))
        if firmware is not None and firmware != self.firmware:
            raise SnapshotRejected(["snapshot firmware %r differs from the expected %r" % (self.firmware, firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        if match.group(3) != "0":
            raise SnapshotRejected(["snapshot has VDOMs enabled; only single-VDOM configurations are evaluated"],
                                   SNAPSHOT_SCOPE_UNSUPPORTED)
        self.root = parse_snapshot(text)
        self._text = text
        self._repeated = None
        present = [name for name in MULTI_VDOM_SECTIONS if name in self.root.sub]
        if present:
            raise SnapshotRejected(["snapshot holds %s sections that this profile does not evaluate" % ", ".join(present)],
                                   SNAPSHOT_SCOPE_UNSUPPORTED)

    def _walk(self):
        stack = [self.root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(node.sub.values())
            stack.extend(node.entries.values())

    def entries(self, table: str):
        if table == "system dhcp server/reserved-address":
            servers = self.root.section("system dhcp server")
            if servers is None:
                return None
            result = {}
            for sid, server in servers.entries.items():
                section = server.section("reserved-address")
                if section is not None:
                    result.update({sid + ":" + rid: node for rid, node in section.entries.items()})
            return result
        section = self.root.sub.get(table)
        if section is None:
            return None
        return dict(section.entries)

    def entry_state(self, entry, lists=()):
        attributes = {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}
        unsupported = ["%s: a list item holds whitespace" % name for name in lists
                       if name in entry.attrs and any(any(c.isspace() for c in item) for item in entry.attrs[name].values)]
        if entry.sub or entry.entries:
            unsupported.append("nested configuration")
        unsupported.extend("unset %s" % name for name, attr in entry.attrs.items() if attr.unset)
        if self._repeated is None:
            self._repeated = _repetitions(self._text)
        unsupported.extend(self._repeated.get(entry.path, ()))
        return attributes, unsupported

    def references(self, table: str, key: str) -> list:
        if table == "system dhcp server/reserved-address":
            return []
        folded = key.casefold()
        found = []
        for node in self._walk():
            if node.path[:2] == (table, key):
                continue
            for name, values in _named_values(node):
                if any(token.casefold() == folded for token in values):
                    found.append("%s: %s" % (" / ".join(node.path) or "(top)", name))
        return sorted(found)

    def in_use(self, key: str) -> bool:
        folded = key.casefold()
        for node in self._walk():
            if any(entry.casefold() == folded for entry in node.entries):
                return True
            for _name, values in _named_values(node):
                if any(token.casefold() == folded for token in values):
                    return True
        return False

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        own_names = safeguard_names(safeguard_id) if safeguard_id else {}
        target = (table, key)
        if table == "system dhcp server/reserved-address":
            sid, rid = key.split(":")
            target = ("system dhcp server", sid, "reserved-address", rid)
        ignore = {("system automation-" + kind, name) for kind, name in own_names.items()}
        if safeguard_id:
            ignore |= {("system " + kind, name) for kind, name in webhook_names(safeguard_id).items()}
        def canonical(node):
            attrs = {}
            for name, attr in sorted(node.attrs.items()):
                values = list(attr.values)
                volatile = ((node.path[:1] == ("vpn certificate local",) and name in ("password", "private-key"))
                            or (node.path[:1] == ("wireless-controller vap",) and name == "sae-password"))
                if volatile and len(values) == 2 and values[0] == "ENC":
                    values = ["ENC", "<opaque-ciphertext>"]
                attrs[name] = [values, attr.unset]
            children = {}
            for name, section in sorted(node.sub.items()):
                body = canonical(section)
                if (name.startswith("system automation-") or name in ("reserved-address", "system api-user")) and not any(body.values()):
                    continue
                children[name] = body
            items = []
            unordered = node.path in (("firewall address",), ("firewall addrgrp",)) or node.path[-1:] == ("reserved-address",)
            source = sorted(node.entries.items()) if unordered else node.entries.items()
            for name, entry in source:
                if entry.path == target:
                    continue
                if len(node.path) == 1 and (node.path[0], name) in ignore:
                    continue
                items.append([name, canonical(entry)])
            return {"attributes": attrs, "sections": children, "entries": items}
        text = json.dumps(canonical(self.root), sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("ascii")).hexdigest()


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def absent(snapshot, table: str, key: str) -> list:
    return ["object %r does not exist" % key]


GROUP_MEMBERS = ("member", "exclude-member")


def _group_members(entries) -> dict:
    return {name: {item.casefold() for attribute in GROUP_MEMBERS if attribute in entry.attrs
                   for item in entry.attrs[attribute].values}
            for name, entry in (entries or {}).items()}


def member_closure(entries, names) -> set:
    groups = {name.casefold(): members for name, members in _group_members(entries).items()}
    found, pending = set(), [name.casefold() for name in names]
    while pending:
        for item in groups.get(pending.pop(), ()):
            if item not in found:
                found.add(item)
                pending.append(item)
    return found


def containing_groups(entries, key: str) -> set:
    groups = _group_members(entries)
    found, pending = set(), [key.casefold()]
    while pending:
        inner = pending.pop()
        for name, members in groups.items():
            if inner in members and name not in found:
                found.add(name)
                pending.append(name.casefold())
    return found


def typed(line: str) -> str:
    return line.replace("?", "\x16?")


def _quoted(value: str) -> str:
    if CONTROL.search(value):
        raise Rejected(["a value holds a control character and cannot be written safely"])
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def _value(profile, name: str, value: str) -> str:
    if profile.attributes[name].type == "name-list":
        return " ".join(_quoted(item) for item in value.split())
    if profile.attributes[name].type == "text":
        return _quoted(value)
    return value


def _context(profile, key):
    if profile.table == "system dhcp server/reserved-address":
        sid, rid = key.split(":")
        return ["config system dhcp server", "edit " + sid, "config reserved-address"], rid, ["end", "next", "end"]
    return ["config " + profile.table], _quoted(key), ["end"]


def render_create(profile, key: str, attributes: dict) -> list:
    prefix, local_key, suffix = _context(profile, key)
    lines = prefix + ["    edit " + local_key]
    for name in sorted(attributes):
        lines.append("        set %s %s" % (name, _value(profile, name, attributes[name])))
    return lines + ["    next"] + suffix


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    prefix, local_key, suffix = _context(profile, key)
    lines = prefix + ["    edit " + local_key]
    for name in sorted(assign):
        lines.append("        set %s %s" % (name, _value(profile, name, assign[name])))
    for name in sorted(remove):
        lines.append("        unset %s" % name)
    return lines + ["    next"] + suffix


def render_delete(profile, key: str) -> list:
    prefix, local_key, suffix = _context(profile, key)
    return prefix + ["    delete " + local_key] + suffix


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table == "firewall addrgrp":
        if not after or not after.get("member", "").split():
            return ["a static address group must retain at least one member"]
        known = set(snapshot.entries("firewall address") or {}) | set(snapshot.entries("firewall addrgrp") or {})
        if set(after["member"].split()) - known:
            return ["the group names a member missing from the visible snapshot"]
    if profile.table == "system dhcp server/reserved-address":
        sid, rid = key.split(":")
        if any(int(v) > 4294967295 for v in (sid, rid)):
            return ["DHCP IDs exceed the supported range"]
        servers = snapshot.root.section("system dhcp server")
        server = None if servers is None else servers.entries.get(sid)
        if server is None or server.value("status", "enable") != "enable" or server.value("server-type", "regular") != "regular":
            return ["the DHCP server must exist, be enabled and have regular type"]
        if after:
            try:
                gateway = ipaddress.IPv4Address(server.value("default-gateway", ""))
                network = ipaddress.IPv4Network(str(gateway) + "/" + server.value("netmask", ""), strict=False)
                address = ipaddress.IPv4Address(after["ip"])
                if address not in network or address in (network.network_address, network.broadcast_address, gateway):
                    return ["the reservation must be a usable address in the DHCP subnet"]
            except (ValueError, KeyError):
                return ["the DHCP reservation subnet cannot be evaluated"]
    return []


POLICYID_MAX = 4294967294
SAFEGUARD_SCRIPT_LIMIT = 1023
POLICY_REFERENCES = (
    ("srcaddr", ("firewall address", "firewall addrgrp"), ("all",)),
    ("dstaddr", ("firewall address", "firewall addrgrp"), ("all",)),
    ("service", ("firewall service custom", "firewall service group"), ()),
    ("schedule", ("firewall schedule onetime", "firewall schedule recurring", "firewall schedule group"),
     ("always",)),
)
MISSING_OBJECT = "the policy names an object missing from the visible snapshot"
SDWAN_DEFAULT_ZONE = "virtual-wan-link"


def _entry_names(snapshot, table):
    entries = snapshot.entries(table)
    return set() if entries is None else set(entries)


def _entry_names_ordered(snapshot, table):
    return list(snapshot.entries(table) or {})


def sdwan_zones(snapshot) -> dict:
    node = snapshot.root.section("system sdwan")
    if node is None:
        return {"zones": set(), "members": {}}
    zones = node.section("zone")
    members = node.section("members")
    mapping = {}
    for entry in () if members is None else members.entries.values():
        interface = entry.value("interface")
        if interface:
            mapping[interface] = entry.value("zone", SDWAN_DEFAULT_ZONE)
    return {"zones": set() if zones is None else set(zones.entries), "members": mapping}


def protected_closure(snapshot, protected) -> set:
    folded = {name.casefold() for name in protected}
    interfaces = snapshot.entries("system interface") or {}
    switches = snapshot.entries("system switch-interface") or {}
    changed = True
    while changed:
        changed = False
        for name, entry in list(interfaces.items()) + list(switches.items()):
            if name.casefold() in folded:
                continue
            parent = entry.value("interface")
            related = ([parent] if parent else []) + list(entry.values("member"))
            if any(item.casefold() in folded for item in related):
                folded.add(name.casefold())
                changed = True
    return folded


def protected_exposure(snapshot, protected, names) -> list:
    closure = protected_closure(snapshot, protected)
    blocked = set(closure) | {"any"}
    for name, entry in (snapshot.entries("system zone") or {}).items():
        if any(item.casefold() in closure for item in entry.values("interface")):
            blocked.add(name.casefold())
    sdwan = sdwan_zones(snapshot)
    for interface, zone in sdwan["members"].items():
        if interface.casefold() in closure:
            blocked.add(zone.casefold())
    return sorted(name for name in names if name.casefold() in blocked)


def safeguard_script_length(inverse: list) -> int:
    return len("\n".join(_escaped(line) for line in _script_lines(inverse)).encode("utf-8"))


def policy_prechecks(snapshot, profile, op, key, before, after, inverse, protected) -> list:
    reasons = []
    if op == "create" and int(key) > POLICYID_MAX:
        reasons.append("the policy id exceeds %d" % POLICYID_MAX)
    guarded = (protected or {}).get("system interface", [])
    known_interfaces = _entry_names(snapshot, "system interface")
    for name in guarded:
        if name not in known_interfaces:
            reasons.append("protected interface %s is missing from the snapshot" % name)
    if after:
        for attribute, tables, extra in POLICY_REFERENCES:
            known = set(extra).union(*(_entry_names(snapshot, table) for table in tables))
            if any(name not in known for name in after.get(attribute, "").split()):
                reasons.append(MISSING_OBJECT)
                break
        interfaces = known_interfaces | _entry_names(snapshot, "system zone") | sdwan_zones(snapshot)["zones"]
        for attribute in ("srcintf", "dstintf"):
            if any(name not in interfaces and name != "any" for name in after.get(attribute, "").split()):
                if MISSING_OBJECT not in reasons:
                    reasons.append(MISSING_OBJECT)
    if guarded and not reasons:
        names = []
        for side in (before, after):
            for attribute in ("srcintf", "dstintf"):
                names.extend((side or {}).get(attribute, "").split())
        touched = protected_exposure(snapshot, guarded, names)
        if touched:
            reasons.append("the policy touches the management path of the protected interfaces: %s"
                           % ", ".join(repr(name) for name in sorted(set(touched))))
    if op == "delete" and list(_entry_names_ordered(snapshot, "firewall policy"))[-1:] != [key]:
        reasons.append("the policy is no longer the last policy; recreating it would change the policy order")
    if safeguard_script_length(inverse) > SAFEGUARD_SCRIPT_LIMIT:
        reasons.append("the inverse exceeds the safeguard script limit")
    return reasons


SAFEGUARD_PREFIX = "netops-sg-"
CLOCK_LINE = re.compile(r"^System time: (\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s*$", re.MULTILINE)
CLOCK_FORMAT = "%a %b %d %H:%M:%S %Y"
TRIGGER_FORMAT = "%Y-%m-%d %H:%M:%S"
ERROR_MARKERS = (
    "Command fail", "command parse error", "Unknown action", "entry is not found",
    "object set operator error", "discard the setting", "value parse error",
)
QUERY_CLOCK = "get system status"
QUERY_ADMINS = "show system admin"
QUERY_STITCHES = "show system automation-stitch"


def safeguard_names(change_id: str) -> dict:
    base = SAFEGUARD_PREFIX + change_id[:12]
    return {"action": base + "-a", "trigger": base + "-t", "stitch": base + "-s"}


def _script_lines(inverse: list) -> list:
    if any("%%" in line for line in inverse):
        raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
    return [line.strip() for line in inverse]


def _escaped(line: str) -> str:
    return line.replace("\\", "\\\\").replace('"', '\\"')


def render_safeguard(change_id: str, inverse: list, fire_at: str) -> list:
    names = safeguard_names(change_id)
    script = [_escaped(line) for line in _script_lines(inverse)]
    lines = ["config system automation-action", 'edit "%s"' % names["action"], "set action-type cli-script"]
    lines.append('set script "' + script[0])
    lines.extend(script[1:-1])
    lines.append(script[-1] + '"')
    lines.extend(("next", "end"))
    lines.extend((
        "config system automation-trigger", 'edit "%s"' % names["trigger"], "set trigger-type scheduled",
        "set trigger-frequency once", "set trigger-datetime %s" % fire_at, "next", "end",
        "config system automation-stitch", 'edit "%s"' % names["stitch"], "set status enable",
        'set trigger "%s"' % names["trigger"], "config actions", "edit 1",
        'set action "%s"' % names["action"], "next", "end", "next", "end",
    ))
    return lines


SAFEGUARD_PARTS = ("stitch", "trigger", "action")


def render_safeguard_removal(change_id: str, parts=SAFEGUARD_PARTS) -> list:
    names = safeguard_names(change_id)
    lines = []
    for part in parts:
        lines.extend(("config system automation-%s" % part, 'delete "%s"' % names[part], "end"))
    return lines


def safeguard_queries(change_id: str) -> dict:
    names = safeguard_names(change_id)
    return {
        "action": "show system automation-action %s" % names["action"],
        "trigger": "show system automation-trigger %s" % names["trigger"],
        "stitch": "show system automation-stitch %s" % names["stitch"],
    }


def _single_entry(text: str, section: str, name: str):
    try:
        root = l1_fortios.parse(text)
    except l1_fortios.ParseError:
        return None
    node = root.sub.get(section)
    if node is None:
        return None
    return node.entries.get(name)


def safeguard_state(change_id: str, answers: dict, inverse: list, fire_at: str) -> list:
    names = safeguard_names(change_id)
    problems = []
    action = _single_entry(answers.get("action", ""), "system automation-action", names["action"])
    trigger = _single_entry(answers.get("trigger", ""), "system automation-trigger", names["trigger"])
    stitch = _single_entry(answers.get("stitch", ""), "system automation-stitch", names["stitch"])
    if action is None or action.value("action-type") != "cli-script":
        problems.append("safeguard action is missing or not a cli-script")
    elif action.value("script") != "\n".join(_script_lines(inverse)):
        problems.append("safeguard script differs from the planned inverse")
    if not _scheduled_once(trigger, fire_at):
        problems.append("safeguard trigger is missing or not set to fire once at the planned time")
    if stitch is None or stitch.value("trigger") != names["trigger"] or stitch.value("status", "enable") != "enable":
        problems.append("safeguard stitch is missing, disabled or bound to another trigger")
    elif stitch.section("actions") is None or not any(
        entry.value("action") == names["action"] for entry in stitch.section("actions").entries.values()
    ):
        problems.append("safeguard stitch does not run the planned action")
    return problems


def _answers_not_found(text: str) -> bool:
    try:
        return any(line.strip() == NOT_FOUND for _number, line in l1_fortios.logical_lines(text))
    except l1_fortios.ParseError:
        return False


def _entry_absent(text: str, section: str, name: str) -> bool:
    if _answers_not_found(text):
        return True
    try:
        root = l1_fortios.parse(text)
    except l1_fortios.ParseError:
        return False
    node = root.sub.get(section)
    return node is not None and name not in node.entries


def safeguard_absent(change_id: str, answers: dict) -> bool:
    names = safeguard_names(change_id)
    return all(
        _entry_absent(answers.get(kind, ""), section, names[kind])
        for kind, section in (("action", "system automation-action"), ("trigger", "system automation-trigger"),
                              ("stitch", "system automation-stitch"))
    )


def _scheduled_once(trigger, fire_at: str) -> bool:
    return (trigger is not None and trigger.value("trigger-type", "event-based") == "scheduled"
            and trigger.value("trigger-frequency") == "once" and trigger.value("trigger-datetime") == fire_at)


def leftover_safeguards(text: str) -> list:
    try:
        root = l1_fortios.parse(text)
    except l1_fortios.ParseError as exc:
        raise Rejected(["automation stitches cannot be read: %s" % exc]) from None
    node = root.sub.get("system automation-stitch")
    if node is None:
        return []
    return sorted(name for name in node.entries if name.startswith(SAFEGUARD_PREFIX))


WEBHOOK_FROM = (8, 0, 1)
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
WEBHOOK_PARTS = ("stitch", "trigger", "action", "user", "profile")
WEBHOOK_SECTIONS = {"stitch": "system automation-stitch", "trigger": "system automation-trigger",
                    "action": "system automation-action", "user": "system api-user", "profile": "system accprofile"}
REST_KEYS = {"firewall policy": "policyid", "firewall address": "name", "firewall addrgrp": "name"}
ACCPROFILE_NONE = ("secfabgrp", "ftviewgrp", "authgrp", "sysgrp", "netgrp", "loggrp", "vpngrp", "utmgrp", "wifi")
API_KEY = re.compile(r"^New API key:[ \t]*([0-9A-Za-z]+)[ \t\r]*$", re.MULTILINE)
QUERY_GLOBAL = "show system global"
HTTPS_PORT = "443"


def _percent(text: str) -> str:
    return "".join(chr(byte) if chr(byte) in UNRESERVED else "%%%02X" % byte for byte in text.encode("utf-8"))


def webhook_firmware(firmware: str) -> bool:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+) build[0-9]+", firmware or "")
    return match is not None and tuple(int(part) for part in match.groups()) >= WEBHOOK_FROM


def snapshot_firmware(text: str):
    match = HEADER.match(text.lstrip("﻿").split("\n", 1)[0].strip())
    return None if match is None else "%s build%s" % (match.group(1), match.group(2))


def webhook_names(change_id: str) -> dict:
    base = SAFEGUARD_PREFIX + change_id[:12]
    return {"api-user": base + "-u", "accprofile": base + "-p"}


def webhook_part_names(change_id: str) -> dict:
    names = dict(safeguard_names(change_id))
    own = webhook_names(change_id)
    names.update(user=own["api-user"], profile=own["accprofile"])
    return names


def webhook_prechecks(snapshot, address: str, credential_kind) -> list:
    reasons = []
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        reasons.append("the webhook safeguard needs the device address as an IPv4 address, not a host name")
        address = None
    if address is not None:
        holder = None
        for name, entry in (snapshot.entries("system interface") or {}).items():
            values = list(entry.values("ip"))
            if values[:1] == [address]:
                holder = (name, entry)
                break
        if holder is None:
            reasons.append("the webhook safeguard calls the device at %s, but no interface holds that address" % address)
        elif "https" not in holder[1].values("allowaccess"):
            reasons.append("the webhook safeguard needs https in allowaccess of interface %s" % holder[0])
    if credential_kind != "password":
        reasons.append("the webhook safeguard needs a password write credential: FortiOS asks for the administrator"
                       " password when it generates the API key")
    for section in ("system api-user", "system accprofile"):
        for name in sorted(snapshot.entries(section) or {}):
            if name.startswith(SAFEGUARD_PREFIX):
                reasons.append("a safeguard of an earlier operation is still installed: %s" % name)
    return reasons


WEBHOOK_WRITE_PROFILE = "super_admin"


def write_account_profile(snapshot, login):
    entry = (snapshot.entries("system admin") or {}).get(login)
    return None if entry is None else entry.value("accprofile")


def write_permission(login, profile) -> list:
    if profile is None:
        return ["the webhook safeguard cannot find the write account %s in system admin; on FortiOS 8.0.1 and later"
                " it needs access profile super_admin" % login]
    if profile != WEBHOOK_WRITE_PROFILE:
        return ["the webhook safeguard needs the write account %s with access profile super_admin on FortiOS 8.0.1"
                " and later (only super_admin may create the API user of the safeguard); %s has access profile %s"
                % (login, login, profile)]
    return []


def _rest_value(profile, name, values):
    attribute = profile.attributes.get(name)
    if attribute is not None and attribute.type == "name-list":
        return [{"name": item} for item in values]
    return " ".join(values)


def rest_inverse(profile, op: str, key: str, inverse: list, address: str) -> dict:
    field = REST_KEYS.get(profile.table)
    if field is None:
        raise Rejected(["the webhook safeguard has no REST inverse for table %s" % profile.table])
    assign, removed = {}, []
    for line in inverse:
        tokens = l1_fortios.tokenize(line.strip())
        if tokens[:1] == ["set"] and len(tokens) > 2:
            assign[tokens[1]] = _rest_value(profile, tokens[1], tokens[2:])
        elif tokens[:1] == ["unset"]:
            removed.append(tokens[1])
    path = "api/v2/cmdb/" + profile.table.replace(" ", "/")
    item = path + "/" + _percent(key)
    if op == "create":
        method, uri, body = "delete", item, None
    elif op == "update":
        for name in removed:
            attribute = profile.attributes.get(name)
            assign[name] = attribute.default if attribute is not None and attribute.default is not None else ""
        method, uri, body = "put", item, assign
    else:
        assign[field] = int(key) if field == "policyid" else key
        method, uri, body = "post", path, assign
    text = "" if body is None else json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text.encode("ascii")) > SAFEGUARD_SCRIPT_LIMIT:
        raise Rejected(["the inverse exceeds the safeguard request body limit"])
    if "%%" in text:
        raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
    return {"method": method, "uri": "%s/%s" % (address, uri), "body": text}


def render_webhook_identity(change_id: str, address: str) -> list:
    names = webhook_names(change_id)
    lines = ["config system accprofile", 'edit "%s"' % names["accprofile"], "set fwgrp read-write"]
    lines.extend("set %s none" % group for group in ACCPROFILE_NONE)
    lines.extend(("next", "end", "config system api-user", 'edit "%s"' % names["api-user"],
                  'set accprofile "%s"' % names["accprofile"], "config trusthost", "edit 1",
                  "set type ipv4-trusthost", "set ipv4-trusthost %s 255.255.255.255" % address, "next", "end",
                  ("password", "next"), "end"))
    return lines


def render_key_request(change_id: str) -> str:
    return 'execute api-user generate-key "%s"' % webhook_names(change_id)["api-user"]


def api_key(text: str) -> str:
    found = API_KEY.findall(text or "")
    if len(found) != 1:
        raise Rejected(["the device did not return one API key for the safeguard"])
    return found[0]


def admin_sport(text: str) -> str:
    try:
        node = l1_fortios.parse(text).sub.get("system global")
    except l1_fortios.ParseError:
        raise Rejected(["the HTTPS administration port cannot be read"]) from None
    if node is None:
        raise Rejected(["the HTTPS administration port cannot be read"])
    port = node.value("admin-sport", HTTPS_PORT)
    if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
        raise Rejected(["the HTTPS administration port cannot be read"])
    return port


def render_webhook_safeguard(change_id: str, request: dict, port: str, token: str, fire_at: str) -> list:
    names = safeguard_names(change_id)
    if not re.fullmatch(r"[0-9A-Za-z]+", token):
        raise Rejected(["the device did not return one API key for the safeguard"])
    lines = ["config system automation-action", 'edit "%s"' % names["action"], "set action-type webhook",
             "set protocol https", "set method %s" % request["method"], "set uri %s" % _quoted(request["uri"]),
             "set port %s" % port, "set verify-host-cert disable"]
    if request["body"]:
        lines.append("set http-body %s" % _quoted(request["body"]))
    lines.extend(("config http-headers", "edit 1", 'set key "Authorization"', 'set value "Bearer %s"' % token,
                  "next", "end", "next", "end"))
    lines.extend((
        "config system automation-trigger", 'edit "%s"' % names["trigger"], "set trigger-type scheduled",
        "set trigger-frequency once", "set trigger-datetime %s" % fire_at, "next", "end",
        "config system automation-stitch", 'edit "%s"' % names["stitch"], "set status enable",
        'set trigger "%s"' % names["trigger"], "config actions", "edit 1",
        'set action "%s"' % names["action"], "next", "end", "next", "end",
    ))
    return lines


def render_webhook_removal(change_id: str, parts=WEBHOOK_PARTS) -> list:
    names = webhook_part_names(change_id)
    lines = []
    for part in parts:
        delete = 'delete "%s"' % names[part]
        lines.extend(("config " + WEBHOOK_SECTIONS[part], ("password", delete) if part == "user" else delete, "end"))
    return lines


def webhook_queries(change_id: str) -> dict:
    names = webhook_part_names(change_id)
    queries = safeguard_queries(change_id)
    queries["action"] = "show full-configuration system automation-action %s" % names["action"]
    queries["user"] = "show system api-user %s" % names["user"]
    queries["profile"] = "show system accprofile %s" % names["profile"]
    return queries


def webhook_state(change_id: str, answers: dict, request: dict, port: str, token: str, fire_at: str,
                  address: str) -> list:
    names = webhook_part_names(change_id)
    entries = {part: _single_entry(answers.get(part, ""), WEBHOOK_SECTIONS[part], names[part]) for part in WEBHOOK_PARTS}
    problems = []
    action = entries["action"]
    expected = {"action-type": "webhook", "protocol": "https", "method": request["method"], "uri": request["uri"],
                "port": port, "verify-host-cert": "disable", "http-body": request["body"]}
    if action is None or any(action.value(name, "") != value for name, value in expected.items()):
        problems.append("safeguard action is missing or differs from the planned request")
    else:
        headers = action.section("http-headers")
        rows = [] if headers is None else list(headers.entries.values())
        if len(rows) != 1 or rows[0].value("key") != "Authorization" or rows[0].value("value") != "Bearer " + token:
            problems.append("safeguard action does not carry exactly the planned authorization header")
    trigger, stitch = entries["trigger"], entries["stitch"]
    if not _scheduled_once(trigger, fire_at):
        problems.append("safeguard trigger is missing or not set to fire once at the planned time")
    if stitch is None or stitch.value("trigger") != names["trigger"] or stitch.value("status", "enable") != "enable":
        problems.append("safeguard stitch is missing, disabled or bound to another trigger")
    elif stitch.section("actions") is None or [
        entry.value("action") for entry in stitch.section("actions").entries.values()
    ] != [names["action"]]:
        problems.append("safeguard stitch does not run the planned action alone")
    user, profile = entries["user"], entries["profile"]
    hosts = None if user is None else user.section("trusthost")
    trusted = [] if hosts is None else [list(entry.values("ipv4-trusthost")) for entry in hosts.entries.values()]
    if user is None or user.value("accprofile") != names["profile"] or trusted != [[address, "255.255.255.255"]]:
        problems.append("safeguard API user is missing or not limited to the device address")
    if profile is None or profile.value("fwgrp") != "read-write" or any(
            profile.value(group, "none") != "none" for group in ACCPROFILE_NONE):
        problems.append("safeguard access profile is missing or grants more than fwgrp read-write")
    return problems


def webhook_absent(change_id: str, answers: dict, parts=WEBHOOK_PARTS) -> bool:
    names = webhook_part_names(change_id)
    return all(_entry_absent(answers.get(part, ""), WEBHOOK_SECTIONS[part], names[part]) for part in parts)


def clock_text(text: str) -> str:
    match = CLOCK_LINE.search(text)
    if match is None:
        raise Rejected(["the device clock cannot be read from the system status"])
    return " ".join(match.group(1).split())


def _admin_table(text: str):
    try:
        root = l1_fortios.parse(text)
    except l1_fortios.ParseError as exc:
        raise Rejected(["the administrator table cannot be read: %s" % exc]) from None
    node = root.sub.get("system admin")
    if node is None:
        raise Rejected(["the administrator table is not visible to the write account"])
    return node


def visible_admins(text: str) -> list:
    return sorted(_admin_table(text).entries)


def admin_fingerprint(text: str, snapshot_text=None, immutable_profiles=()) -> str:
    if immutable_profiles not in ((), ("super_admin",)):
        raise Rejected(["only the documented immutable super_admin role may be omitted from a schema profile export"])
    table = _admin_table(text)
    body = {name: {attr: [list(value.values), value.unset] for attr, value in sorted(entry.attrs.items())}
            for name, entry in sorted(table.entries.items())}
    if snapshot_text is not None:
        tree = parse_snapshot(snapshot_text)
        section = tree.section("system accprofile")
        names = {entry.value("accprofile") for entry in table.entries.values() if entry.value("accprofile")}
        def profile_state(node):
            return {"attrs": {k: [list(v.values), v.unset] for k, v in node.attrs.items()},
                    "sub": {k: profile_state(v) for k, v in node.sub.items()},
                    "entries": {k: profile_state(v) for k, v in node.entries.items()}}
        mutable = names - set(immutable_profiles)
        if mutable and (section is None or mutable - set(section.entries)):
            missing = sorted(mutable if section is None else mutable - set(section.entries))
            raise Rejected(["an administrator access profile is not visible in the snapshot: " + ", ".join(missing)])
        body = {"accounts": body, "profiles": {name: profile_state(section.entries[name]) for name in mutable}}
        if names & set(immutable_profiles):
            body["immutable_profiles"] = sorted(names & set(immutable_profiles))
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


def cli_error(text: str):
    answer = text.split("\n", 1)[1] if "\n" in text else ""
    for marker in ERROR_MARKERS:
        if marker in answer:
            return marker
    return None


NOT_FOUND = "entry is not found in table"


def shown_object(text: str, table: str, key: str):
    if table == "system dhcp server/reserved-address":
        sid, rid = key.split(":")
        start = text.find("config system dhcp server")
        if start < 0:
            raise Rejected(["the check account cannot read the DHCP server"])
        tree = l1_fortios.parse(text[start:])
        servers = tree.section("system dhcp server")
        server = None if servers is None else servers.entries.get(sid)
        if server is None:
            raise Rejected(["the check account cannot see the DHCP server"])
        section = server.section("reserved-address")
        entry = None if section is None else section.entries.get(rid)
        return None if entry is None else {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}
    if _answers_not_found(text):
        return None
    start = text.find("config %s" % table)
    if start < 0:
        raise Rejected(["the check account answer holds no %s section" % table])
    try:
        root = l1_fortios.parse(text[start:])
    except l1_fortios.ParseError as exc:
        raise Rejected(["the check account answer does not parse: %s" % exc]) from None
    section = root.sub.get(table)
    entry = None if section is None else section.entries.get(key)
    if entry is None:
        raise Rejected(["the check account answer names no object %s" % key])
    return {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}


QUERY_SESSIONS = "get system admin list"
SYSTEM_SESSIONS = ("Fortimanager_Access",)


def foreign_sessions(text: str, own: set) -> int:
    lines = text.splitlines()
    header = next((index for index, line in enumerate(lines)
                   if "username" in line.split() and "profile" in line.split()), None)
    if header is None:
        raise Rejected(["the administrator session list is not readable"])
    count = 0
    for line in lines[header + 1:]:
        words = line.split()
        if not words or (len(words) > 1 and words[1] in ("$", "#")) or words[0].endswith(("$", "#")):
            continue
        if words[0] not in own and words[0] not in SYSTEM_SESSIONS:
            count += 1
    return count
