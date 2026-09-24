from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from netops_auditor import l1_fortios

from netops_admin.errors import Rejected

HEADER = re.compile(
    r"^#config-version=[A-Z0-9]+-([0-9]+\.[0-9]+\.[0-9]+)-FW-build([0-9]+)-[0-9]+:opmode=[0-9]+:vdom=([0-9]+)"
)
MULTI_VDOM_SECTIONS = ("vdom", "global")


class Snapshot:
    def __init__(self, text: str, firmware: str | None = None):
        first = text.lstrip("﻿").split("\n", 1)[0].strip()
        match = HEADER.match(first)
        if match is None:
            raise Rejected(["snapshot does not identify its firmware: the #config-version header is missing"])
        self.firmware = "%s build%s" % (match.group(1), match.group(2))
        if firmware is not None and firmware != self.firmware:
            raise Rejected(["snapshot firmware %r differs from the expected %r" % (self.firmware, firmware)])
        if match.group(3) != "0":
            raise Rejected(["snapshot has VDOMs enabled; only single-VDOM configurations are evaluated"])
        try:
            self.root = l1_fortios.parse(text)
        except l1_fortios.ParseError as exc:
            raise Rejected(["snapshot does not parse: %s" % exc]) from None
        present = [name for name in MULTI_VDOM_SECTIONS if name in self.root.sub]
        if present:
            raise Rejected(["snapshot holds %s sections that this profile does not evaluate" % ", ".join(present)])

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

    def entry_state(self, entry):
        attributes = {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}
        unsupported = []
        if entry.sub or entry.entries:
            unsupported.append("nested configuration")
        unsupported.extend("unset %s" % name for name, attr in entry.attrs.items() if attr.unset)
        return attributes, unsupported

    def references(self, table: str, key: str) -> list:
        if table == "system dhcp server/reserved-address":
            return []
        folded = key.casefold()
        found = []
        for node in self._walk():
            if node.path[:2] == (table, key):
                continue
            for name, attr in node.attrs.items():
                if any(token.casefold() == folded for token in attr.values):
                    found.append("%s: %s" % (" / ".join(node.path) or "(top)", name))
        return sorted(found)

    def in_use(self, key: str) -> bool:
        folded = key.casefold()
        for node in self._walk():
            if any(entry.casefold() == folded for entry in node.entries):
                return True
            for attr in node.attrs.values():
                if any(token.casefold() == folded for token in attr.values):
                    return True
        return False

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        own_names = safeguard_names(safeguard_id) if safeguard_id else {}
        target = (table, key)
        if table == "system dhcp server/reserved-address":
            sid, rid = key.split(":")
            target = ("system dhcp server", sid, "reserved-address", rid)
        ignore = {("system automation-" + kind, name) for kind, name in own_names.items()}
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
                if (name.startswith("system automation-") or name == "reserved-address") and not any(body.values()):
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


def _quoted(value: str) -> str:
    return '"%s"' % value


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


def render_safeguard_removal(change_id: str) -> list:
    names = safeguard_names(change_id)
    return [
        "config system automation-stitch", 'delete "%s"' % names["stitch"], "end",
        "config system automation-trigger", 'delete "%s"' % names["trigger"], "end",
        "config system automation-action", 'delete "%s"' % names["action"], "end",
    ]


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
    if trigger is None or trigger.value("trigger-frequency") != "once" or trigger.value("trigger-datetime") != fire_at:
        problems.append("safeguard trigger is missing or not set to fire once at the planned time")
    if stitch is None or stitch.value("trigger") != names["trigger"] or stitch.value("status", "enable") != "enable":
        problems.append("safeguard stitch is missing, disabled or bound to another trigger")
    elif stitch.section("actions") is None or not any(
        entry.value("action") == names["action"] for entry in stitch.section("actions").entries.values()
    ):
        problems.append("safeguard stitch does not run the planned action")
    return problems


def safeguard_absent(change_id: str, answers: dict) -> bool:
    names = safeguard_names(change_id)
    return all(
        _single_entry(answers.get(kind, ""), section, names[kind]) is None
        for kind, section in (("action", "system automation-action"), ("trigger", "system automation-trigger"),
                              ("stitch", "system automation-stitch"))
    )


def leftover_safeguards(text: str) -> list:
    try:
        root = l1_fortios.parse(text)
    except l1_fortios.ParseError as exc:
        raise Rejected(["automation stitches cannot be read: %s" % exc]) from None
    node = root.sub.get("system automation-stitch")
    if node is None:
        return []
    return sorted(name for name in node.entries if name.startswith(SAFEGUARD_PREFIX))


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


def admin_fingerprint(text: str, snapshot_text=None) -> str:
    table = _admin_table(text)
    body = {name: {attr: [list(value.values), value.unset] for attr, value in sorted(entry.attrs.items())}
            for name, entry in sorted(table.entries.items())}
    if snapshot_text is not None:
        tree = l1_fortios.parse(snapshot_text)
        section = tree.section("system accprofile")
        names = {entry.value("accprofile") for entry in table.entries.values() if entry.value("accprofile")}
        def profile_state(node):
            return {"attrs": {k: [list(v.values), v.unset] for k, v in node.attrs.items()},
                    "sub": {k: profile_state(v) for k, v in node.sub.items()},
                    "entries": {k: profile_state(v) for k, v in node.entries.items()}}
        if names and (section is None or names - set(section.entries)):
            raise Rejected(["an administrator access profile is not visible in the snapshot"])
        body = {"accounts": body, "profiles": {name: profile_state(section.entries[name]) for name in names}}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


def cli_error(text: str):
    for marker in ERROR_MARKERS:
        if marker in text:
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
    if NOT_FOUND in text:
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
