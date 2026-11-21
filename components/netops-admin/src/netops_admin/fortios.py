from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, replace

from netops_auditor import l1_fortios

from netops_admin.config import NAT_TABLES
from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_SCOPE_UNSUPPORTED,
                                 SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected, StateUnreadable)
from netops_admin.profiles import LIST_TYPES, firmware_support
from netops_admin.request import (
    FORTIOS_POLICY_LIST_FIELDS, FORTIOS_PORT_VLAN_LISTS, FORTIOS_VLAN_NAME,
    canonical_value, group_members_text, list_items,
)

VIP_TABLE, POOL_TABLE = NAT_TABLES
VIP_GROUP_TABLE = "firewall vipgrp"
ISDB_TABLE = "firewall internet-service-name"

HEADER = re.compile(
    r"^#config-version=[A-Z0-9]+-([0-9]+\.[0-9]+\.[0-9]+)-FW-build([0-9]+)-[0-9]+:opmode=[0-9]+:vdom=([0-9]+)"
)
MANAGED_SWITCH = "switch-controller managed-switch"
SWITCH_PORT = MANAGED_SWITCH + "/ports"
SWITCH_BOUNCE = "port-bounce"
SWITCH_POE_CYCLE = "poe-cycle"
SWITCH_PORT_TABLES = (SWITCH_PORT, SWITCH_BOUNCE, SWITCH_POE_CYCLE)
SWITCH_BASE_FIELDS = frozenset(("description", "status"))
SWITCH_CYCLE_FIELDS = SWITCH_BASE_FIELDS | {"poe-status"}
SWITCH_VLAN_FIELDS = FORTIOS_PORT_VLAN_LISTS | {"vlan", "allowed-vlans-all"}
SWITCH_PORT_FIELDS = SWITCH_BASE_FIELDS | SWITCH_VLAN_FIELDS | {"poe-status"}
SWITCH_PORT_STATE_SCHEMA = "fortios-managed-port/2"
SWITCH_OPTIONS = {"status": ("up", "down"), "poe-status": ("enable", "disable"),
                  "allowed-vlans-all": ("enable", "disable")}
MULTI_VDOM_SECTIONS = ("vdom", "global")
SESSION_TABLE = "sessions"
SESSION_FIRMWARE = (("FortiGate-60F", "7.6.8 build3744"),)
SESSION_FILTER = "diagnose sys session filter"
SESSION_LIST = "diagnose sys session list"
SESSION_CLEAR = "diagnose sys session clear"
SESSION_CHECKSUM = "diagnose sys ha checksum show"
SESSION_STATE_MASK = "80000100"  # EXPECT (f31) and local sessions must stay out of the device's filter.
SESSION_SELECTORS = {"src": "source ip", "dst": "dest ip", "sport": "source port",
                     "dport": "dest port", "proto": "proto"}
SESSION_FILTER_FIELDS = frozenset((*SESSION_SELECTORS.values(), "vd", "sintf", "dintf", "proto-state",
                                  "NAT'd source ip", "NAT'd source port", "policy id", "expire", "duration",
                                  "state1", "state2"))
SESSION_TUPLE = re.compile(r"(?m)^hook=(pre|post) dir=org act=(?:noop|snat|dnat) "
                           r"([0-9.]+):([0-9]+)->([0-9.]+):([0-9]+)\([0-9.]+:[0-9]+\)[ \t]*$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
NOT_FOUND = "entry is not found in table"
# 1.0.12 G20: tables that live one level down in another table, keyed "<parent key>:<child id>". The parent key of a
# DHCP server is its numeric id, that of a DNS zone its name. A request may also name the child by what the operator
# knows (resolve_nested_key): "<interface>@<mac>" for a DHCP reservation, "<zone>@<hostname>" for a DNS entry.
DHCP_TABLE = "system dhcp server/reserved-address"
DNS_TABLE = "system dns-database/dns-entry"
NESTED = {DHCP_TABLE: ("system dhcp server", "reserved-address"), DNS_TABLE: ("system dns-database", "dns-entry")}
MAC_TEXT = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


def split_nested(table: str, key: str) -> tuple:
    parent, _, child = key.rpartition(":")
    return parent, child


UNNAMED_PARTS = ("password", "passwd", "passphrase", "pwd", "secret", "psk", "key", "community", "token",
                 "comment", "description")
UNNAMED_ATTRIBUTES = {("system snmp community",): ("name",)}


def _session_ip(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
        raise ValueError("expected a unicast host")
    return str(address)


@dataclass(frozen=True)
class SessionTarget:
    key: str
    operands: dict

    def commands(self, firmware):
        # The FortiOS 7.x session filter takes range endpoints; 8.x accepts a single value.
        repeat = int(firmware.split(".", 1)[0]) < 8
        return [
            SESSION_FILTER + " vd 0",
            SESSION_FILTER + " session-state1 00000000 " + SESSION_STATE_MASK,
            *(f"{SESSION_FILTER} {name} {value}" + (f" {value}" if repeat else "")
              for name, value in self.operands.items()),
        ]


def clear_target(key, changes):
    """Use src:IPv4 or dst:IPv4 and optional src/dst, sport, dport and proto in changes."""
    field, _, address = key.partition(":")
    try:
        if (field not in ("src", "dst") or field in changes
                or changes.keys() - SESSION_SELECTORS.keys()):
            raise ValueError
        operands = {field: _session_ip(address)}
        for name, value in changes.items():
            if name in ("src", "dst"):
                if not isinstance(value, str):
                    raise ValueError
                operands[name] = _session_ip(value)
            elif type(value) is int and 1 <= value <= (255 if name == "proto" else 65535):
                operands[name] = value
            else:
                raise ValueError
        if {"sport", "dport"} & operands.keys() and operands.get("proto") not in (6, 17):
            raise ValueError
    except ValueError:
        raise Rejected(["a session clear needs src:IPv4 or dst:IPv4, optional opposite IPv4, and TCP or UDP"
                        " (proto 6 or 17) when selecting ports"], reason_codes=["clear_invalid_target"]) from None
    return SessionTarget(key, {name: operands[name] for name in SESSION_SELECTORS if name in operands})


def clear_filter_matches(text, target=None):
    lines = text.strip().splitlines()
    if not lines or lines[0] != "session filter:":
        return False
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.strip().partition(":")
        if not colon or name in fields:
            return False
        fields[name] = value.strip()
    if not SESSION_FILTER_FIELDS <= fields.keys():
        return False
    if target is not None:
        if (fields.pop("vd") != "0"
                or not re.fullmatch(r"\(0{1,8} mask:80000100\)", fields.pop("state1"))):
            return False
        for name, value in target.operands.items():
            value = str(value)
            if fields.pop(SESSION_SELECTORS[name]) not in (value, f"{value}-{value}"):
                return False
    return all(value == "any" for value in fields.values())


def clear_observation(target, text):
    """Read only stable identifiers and the original tuple from a complete, scoped session listing."""
    def unreadable():
        return Rejected(["the FortiOS session listing is incomplete or unrecognised"],
                        reason_codes=["clear_readback_unreadable"])

    lines = text.strip().splitlines()
    total = re.fullmatch(r"total session:? ([0-9]{1,8})[ \t]*", lines[-1]) if lines else None
    if total is None:
        raise unreadable()
    prefix, *blocks = re.split(r"(?m)^(?=session info:)", "\n".join(lines[:-1]))
    if prefix.strip() or len(blocks) != int(total[1]):
        raise unreadable()
    entries = {}
    for block in blocks:
        serial = re.findall(r"(?m)^serial=([0-9a-fA-F]{8})(?= )", block)
        protocol = re.match(r"session info: (?:[^\n]+ )?proto=([0-9]{1,3}) ", block)
        state = re.findall(r"(?m)^state=([^\n]*)", block)
        policy = re.findall(r"(?m)^misc=[^\n]*\bpolicy_id=([0-9]+) [^\n]*\bvd=([0-9]+)(?=\s|$)", block)
        paths = re.findall(
            r"(?m)^orgin->sink: org pre->post, reply pre->post dev=([0-9]+)->([0-9]+)/([0-9]+)->([0-9]+)(?= |$)",
            block,
        )
        hooks = SESSION_TUPLE.findall(block)
        original = [row[1:] for row in hooks if row[0] == "pre"] or [row[1:] for row in hooks]
        if (len(serial) != 1 or protocol is None or len(state) != 1 or len(policy) != 1 or len(original) != 1):
            raise unreadable()
        policy_id, vdom = map(int, policy[0])
        if ({"local", "f31"} & set(state[0].split()) or policy_id in (0, 0xffffffff) or vdom != 0
                or len(paths) != 1):
            raise Rejected(["a listed FortiOS session is outside the permitted forwarded scope"],
                           reason_codes=["clear_protected_target"])
        src, sport, dst, dport = original[0]
        try:
            item = {"src": _session_ip(src), "dst": _session_ip(dst), "sport": int(sport), "dport": int(dport),
                    "proto": int(protocol[1]), "policy_id": policy_id,
                    "interface_indices": [int(index) for index in paths[0]]}
            if (not 1 <= item["proto"] <= 255 or item["sport"] > 65535 or item["dport"] > 65535
                    or serial[0].lower() in entries):
                raise ValueError
        except ValueError:
            raise unreadable() from None
        if any(item[name] != value for name, value in target.operands.items()):
            raise Rejected(["the FortiOS session listing contains an entry outside the requested filter"],
                           reason_codes=["clear_scope_unverified"])
        entries[serial[0].lower()] = item
    return {"filter": dict(target.operands), "entries": [dict(serial=serial, **entries[serial])
                                                         for serial in sorted(entries)]}


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
        if table in SWITCH_PORT_TABLES:
            switches = self.root.section(MANAGED_SWITCH)
            if switches is None:
                return None
            return {f"{serial}:{port}": node for serial, switch in switches.entries.items()
                    if (ports := switch.section("ports")) is not None for port, node in ports.entries.items()}
        if table in NESTED:
            parent_table, child_table = NESTED[table]
            parents = self.root.section(parent_table)
            if parents is None:
                # a FortiGate without any DNS zone omits the section; the prechecks then name the missing zone
                return {} if table == DNS_TABLE else None
            result = {}
            for pid, parent in parents.entries.items():
                section = parent.section(child_table)
                if section is not None:
                    result.update({pid + ":" + cid: node for cid, node in section.entries.items()})
            return result
        section = self.root.sub.get(table)
        if section is None:
            # Abbreviated show omits empty tables. The live check account independently proves target absence.
            return {} if table in (GROUP_TABLE, POLICY_TABLE, PHASE2_TABLE, *NAT_TABLES) else None
        return dict(section.entries)

    def policy_order(self):
        section = self.root.section(POLICY_TABLE)
        return [] if section is None else policy_order(section, self._text)

    def entry_state(self, entry, lists=()):
        unsupported = ["%s: a list item holds whitespace" % name for name in lists
                       if name in entry.attrs and _list_has_unsupported_whitespace(entry, name, entry.attrs[name].values)]
        if entry.sub or entry.entries:
            unsupported.append("nested configuration")
        unsupported.extend("unset %s" % name for name, attr in entry.attrs.items() if attr.unset)
        if self._repeated is None:
            self._repeated = _repetitions(self._text)
        unsupported.extend(self._repeated.get(entry.path, ()))
        if entry.path[:1] == (MANAGED_SWITCH,) and entry.path[-2:-1] == ("ports",):
            for parent in (entry.path[:2], entry.path[:3]):
                unsupported.extend(self._repeated.get(parent, ()))
            return switch_port_state(entry), unsupported
        return _shown_attributes(entry), unsupported

    def references(self, table: str, key: str) -> list:
        if table in NESTED:
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

    def rest_digest(self, table: str, key: str, safeguard_id=None, *,
                    include_empty_group=False, omit_empty_policy=False, switch_port_g18=False,
                    ignore_uuid=frozenset(), batch=False) -> str:
        own_names = safeguard_names(safeguard_id) if safeguard_id else {}
        target = (table, key)
        if table in NESTED:
            parent, child = split_nested(table, key)
            target = (NESTED[table][0], parent, NESTED[table][1], child)
        port_target = table in SWITCH_PORT_TABLES
        if port_target:
            serial, port = key.split(":")
            target = (MANAGED_SWITCH, serial, "ports", port)
        port_fields = (SWITCH_PORT_FIELDS if switch_port_g18 else
                       SWITCH_CYCLE_FIELDS if table == SWITCH_POE_CYCLE else SWITCH_BASE_FIELDS)
        ignore = {("system automation-" + kind, name) for kind, name in own_names.items()}
        if safeguard_id:
            ignore |= {("system " + kind, name) for kind, name in webhook_names(safeguard_id).items()}
        def canonical(node):
            attrs = {}
            for name, attr in sorted(node.attrs.items()):
                if port_target and node.path == target and name in port_fields:
                    continue
                if name == "uuid" and node.path in ignore_uuid:
                    # 1.0.12 G24: the identity the device gave an object created by an earlier step of the batch
                    continue
                values = list(attr.values)
                volatile = ((node.path[:1] == ("vpn certificate local",) and name in ("password", "private-key"))
                            or (node.path[:1] == ("wireless-controller vap",) and name == "sae-password"))
                if volatile and len(values) == 2 and values[0] == "ENC":
                    values = ["ENC", "<opaque-ciphertext>"]
                elif batch and len(values) > 1:
                    # a step of a batch compares the objects other steps wrote: the order of their member values is
                    # the order Admin wrote them in, never one the device keeps
                    values = sorted(values, key=lambda item: (item.casefold(), item))
                attrs[name] = [values, attr.unset]
            children = {}
            for name, section in sorted(node.sub.items()):
                body = canonical(section)
                if section.path == (GROUP_TABLE,) and not any(body.values()) and not include_empty_group:
                    continue
                if section.path == (POLICY_TABLE,) and not any(body.values()) and omit_empty_policy:
                    continue
                if section.path in ((PHASE2_TABLE,), (VIP_TABLE,), (POOL_TABLE,)) and not any(body.values()):
                    continue
                if (name.startswith("system automation-") or name in ("reserved-address", "dns-entry", "system api-user")) and not any(body.values()):
                    continue
                children[name] = body
            if include_empty_group and not node.path:
                children.setdefault(GROUP_TABLE, {"attributes": {}, "sections": {}, "entries": []})
            items = []
            unordered = (node.path in (("firewall address",), ("firewall addrgrp",), (VIP_TABLE,), (POOL_TABLE,))
                         or node.path[-1:] in (("reserved-address",), ("dns-entry",)))
            source = sorted(node.entries.items()) if unordered else node.entries.items()
            for name, entry in source:
                if entry.path == target and not port_target:
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
ADDRESS_TABLE = "firewall address"
GROUP_TABLE = "firewall addrgrp"
ADDRESS_TABLES = (ADDRESS_TABLE, GROUP_TABLE)
# With no explicit type, FortiOS uses ipmask and omits the type in its normal show output.
ADDRESS_FIELDS = {"ipmask": ("subnet",), "fqdn": ("fqdn",), "iprange": ("start-ip", "end-ip"),
                  "mac": ("macaddr",), "geography": ("country",), "interface-subnet": ("interface",)}
INTERFACE_SUBNET = "interface-subnet"
G21_FIRMWARE = "7.6.8 build3744"


def _group_members(entries) -> dict:
    return {name: {item.casefold() for attribute in GROUP_MEMBERS if attribute in entry.attrs
                   for item in entry.attrs[attribute].values}
            for name, entry in (entries or {}).items()}


def _list_has_unsupported_whitespace(entry, name, values) -> bool:
    quoted_names = ((name == "member" and entry.path[:1] == (GROUP_TABLE,))
                    or (name in FORTIOS_PORT_VLAN_LISTS and entry.path[:1] == (MANAGED_SWITCH,))
                    or (name in FORTIOS_POLICY_LIST_FIELDS and entry.path[:1] == (POLICY_TABLE,)))
    allowed = " " if quoted_names else ""
    return any(c.isspace() and c != allowed for item in values for c in item)


def _shown_attributes(entry) -> dict:
    attributes = {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}
    if entry.path[:1] == (GROUP_TABLE,) and "member" in attributes:
        attributes["member"] = group_members_text(entry.attrs["member"].values)
    if entry.path[:1] == (POLICY_TABLE,):
        for name in attributes.keys() & FORTIOS_POLICY_LIST_FIELDS:
            attributes[name] = group_members_text(entry.attrs[name].values)
    return attributes


def member_closure(entries, names) -> set:
    groups = {name.casefold(): members for name, members in _group_members(entries).items()}
    found, pending = set(), [name.casefold() for name in names]
    while pending:
        for item in groups.get(pending.pop(), ()):
            if item not in found:
                found.add(item)
                pending.append(item)
    return found


def group_members(state) -> set:
    return {item.casefold() for item in l1_fortios.tokenize((state or {}).get("member", ""))}


def group_policy_use(snapshot, key: str, protected) -> tuple:
    """1.0.12 G24 r2 (705-rv finding 1): the policies that name an address group (or a group that holds it) in srcaddr
    or dstaddr. Returns (protected policy IDs from the inventory, active policy IDs); a member change of the group
    changes the traffic these policies match although their own record stays the same."""
    names = {key.casefold()} | {name.casefold() for name in containing_groups(snapshot.entries(GROUP_TABLE), key)}
    guarded = {str(item) for item in (protected or {}).get(POLICY_TABLE, ())}
    used, active = [], []
    for policy_id, entry in (snapshot.entries(POLICY_TABLE) or {}).items():
        addresses = entry.values("srcaddr") + entry.values("dstaddr")
        if not any(item.casefold() in names for item in addresses):
            continue
        used.append(policy_id)
        if entry.value("status", "enable") == "enable":
            active.append(policy_id)
    return sorted(item for item in used if item in guarded), active


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
    if profile.table == VIP_TABLE and name == "mappedip":
        return _quoted(value)
    if profile.table in SWITCH_PORT_TABLES and name in SWITCH_OPTIONS:
        return value
    if profile.attributes[name].type in LIST_TYPES:
        return " ".join(_quoted(item) for item in list_items(profile.attributes[name], value, profile.platform))
    if profile.attributes[name].type == "text":
        if profile.table == PHASE2_TABLE and name in PHASE2_OPTIONS:
            return value
        return _quoted(value)
    return value


def _context(profile, key):
    if profile.table in SWITCH_PORT_TABLES:
        serial, port = key.split(":")
        return ["config " + MANAGED_SWITCH, "edit " + _quoted(serial), "config ports"], _quoted(port), ["end", "next", "end"]
    if profile.table == DHCP_TABLE:
        sid, rid = split_nested(profile.table, key)
        return ["config system dhcp server", "edit " + sid, "config reserved-address"], rid, ["end", "next", "end"]
    if profile.table == DNS_TABLE:
        zone, entry_id = split_nested(profile.table, key)
        return ["config system dns-database", "edit " + _quoted(zone), "config dns-entry"], entry_id, ["end", "next", "end"]
    return ["config " + profile.table], _quoted(key), ["end"]


# 1.0.12 G19: measured on FortiGate-60F 7.6.8 build3744 (task 439): a VLAN created without a role inherits role lan
# from its parent (show lists "set role lan"), and role lan with an address makes FortiOS create the firewall address
# "<name> address" (type interface-subnet) that blocks the delete of the VLAN (-23, used by 1 entry). Created with
# role undefined, the VLAN has no such address, show omits the role and the delete succeeds.
INTERFACE_CREATE_FIXED = {"role": "undefined"}

POLICY_CONTROLS = ("action", "srcintf", "dstintf", "nat", "ippool", "utm-status", "internet-service")
POLICY_OPTIONAL_TOGGLES = ("nat", "ippool", "utm-status", "internet-service")
VIP_CONTROLS = ("portforward",)


def _write_order(table, names):
    controls = POLICY_CONTROLS if table == POLICY_TABLE else VIP_CONTROLS if table == VIP_TABLE else ()
    return [*(name for name in controls if name in names), *sorted(set(names) - set(controls))]


def render_create(profile, key: str, attributes: dict) -> list:
    prefix, local_key, suffix = _context(profile, key)
    lines = prefix + ["    edit " + local_key]
    values = {name: _value(profile, name, value) for name, value in attributes.items()}
    if profile.table == INTERFACE_TABLE:
        values.update((name, _quoted(value)) for name, value in INTERFACE_CREATE_FIXED.items())
    if profile.table == PHASE2_TABLE:
        # Establish the parent before setting any selector options, and PFS before the DH groups.
        for name in ("phase1name", "pfs"):
            if name in values:
                lines.append("        set %s %s" % (name, values.pop(name)))
    if profile.table == ADDRESS_TABLE and "type" in values:
        lines.append("        set type " + values.pop("type"))
        if attributes["type"] == INTERFACE_SUBNET:
            values.pop("subnet", None)
        elif attributes["type"] == "iprange":
            # Establish the address family before setting the bounds.
            if "start-ip" in values:
                lines.append("        set start-ip " + values.pop("start-ip"))
    if profile.table == POLICY_TABLE:
        if attributes.get("action", "deny") == "deny":
            for name in ("nat", "utm-status"):
                if attributes.get(name) == "disable":
                    values.pop(name)
        if attributes.get("nat") != "enable" and attributes.get("ippool") == "disable":
            values.pop("ippool")
    if profile.table == VIP_TABLE and attributes.get("portforward") != "enable" and attributes.get("protocol") == "tcp":
        values.pop("protocol")
    for name in _write_order(profile.table, values):
        lines.append("        set %s %s" % (name, values[name]))
    return lines + ["    next"] + suffix


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    prefix, local_key, suffix = _context(profile, key)
    lines = prefix + ["    edit " + local_key]
    # Restoring these defaults is an unset before changing the surrounding CLI context.
    defaults = POLICY_OPTIONAL_TOGGLES if profile.table == POLICY_TABLE else ("protocol",) if profile.table == VIP_TABLE else ()
    resets = {name for name in defaults if name in assign and assign[name] == profile.attributes[name].default}
    assign = {name: value for name, value in assign.items() if name not in resets}
    remove = set(remove) | resets
    if profile.table == POLICY_TABLE:
        early = remove & {*POLICY_CONTROLS, *POLICY_PROFILES, *POLICY_ISDB_FIELDS, "poolname", "groups", "users"}
        if assign.get("internet-service") == "enable":
            early.update(remove & {"dstaddr", "service"})
    else:
        early = remove if profile.table == VIP_TABLE else set()
    if early:
        # Unset dependent fields before disabling the CLI context that exposes them.
        lines.extend("        unset " + name for name in reversed(_write_order(profile.table, early)))
    if profile.table == SWITCH_PORT:
        unset_lists = {name for name in FORTIOS_PORT_VLAN_LISTS if assign.get(name) == ""}
        assign = {name: value for name, value in assign.items() if name not in unset_lists}
        remove |= unset_lists
        # Disable wildcard carriage before editing the lists, and enable it after editing them.
        wildcard = assign.pop("allowed-vlans-all", None)
        if wildcard == "disable":
            lines.append("        set allowed-vlans-all disable")
        if "untagged-vlans" in remove:
            lines.append("        unset untagged-vlans")
            remove.remove("untagged-vlans")
    for name in _write_order(profile.table, assign):
        lines.append("        set %s %s" % (name, _value(profile, name, assign[name])))
    for name in sorted(remove - early):
        lines.append("        unset %s" % name)
    if profile.table == SWITCH_PORT and wildcard == "enable":
        lines.append("        set allowed-vlans-all enable")
    return lines + ["    next"] + suffix


def render_delete(profile, key: str) -> list:
    prefix, local_key, suffix = _context(profile, key)
    return prefix + ["    delete " + local_key] + suffix


PHASE1_TABLE = "vpn ipsec phase1-interface"
PHASE2_TABLE = "vpn ipsec phase2-interface"
IPSEC_TUNNEL = "ipsec-tunnel"
IPSEC_RECOVERY_KIND = "fortios-ipsec-recovery"
IPSEC_FIRMWARE = ("7.6.8 build3744",)
PHASE2_OPTIONS = ("proposal", "dhgrp", "pfs", "auto-negotiate")
PHASE2_SUBNETS = ("src-subnet", "dst-subnet")
ANY_IPV4 = "0.0.0.0 0.0.0.0"
PHASE2_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}")
PHASE1_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
PHASE2_COUNT = re.compile(r"proxyid_num=(\d+)(?:\s+[^\r\n]*)?")
PHASE2_STATUS = re.compile(
    r"proxyid=([A-Za-z0-9_.-]+) proto=\d+ sa=(\d+) ref=\d+ serial=([0-9a-fA-F]{1,8})(?: [A-Za-z0-9_-]+)*"
)
PHASE2_SA = re.compile(r"SA:\s+ref=\d+ options=[0-9a-f]+ type=[0-9a-f]+ soft=\d+ mtu=\d+ "
                       r"expire=(\d+)/[0-9A-Za-z]+ replaywin=\d+")


def ipsec_refused(message, code="fortios_ipsec_target_invalid"):
    return Rejected([message], reason_codes=[code])


def ipsec_parent(snapshot, key, parent, protected):
    protected = protected or {}
    interfaces = snapshot.entries("system interface") or {}
    management = set(protected.get("system interface", ())) | set(protected.get("interface", ()))
    protected_names = {name.casefold() for names in protected.values() for name in names}
    tunnel_interface = interfaces.get(parent)
    phase1 = (snapshot.entries(PHASE1_TABLE) or {}).get(parent)
    if not management or not any(name in interfaces for name in management):
        raise ipsec_refused("IPsec changes need a visible protected management interface", "fortios_ipsec_protected")
    if (not isinstance(parent, str) or not PHASE1_NAME.fullmatch(parent)
            or phase1 is None or tunnel_interface is None or tunnel_interface.value("type") != "tunnel"):
        raise ipsec_refused("the Phase 1 and its tunnel interface must exist in the current configuration")
    if (protected_names.intersection((key.casefold(), parent.casefold()))
            or {"ssh", "https"}.intersection(tunnel_interface.values("allowaccess"))):
        raise ipsec_refused("the IPsec selector or its tunnel interface is protected", "fortios_ipsec_protected")
    return phase1


def phase2_copy(snapshot, profile, changes, source):
    if not isinstance(source, str) or not PHASE2_NAME.fullmatch(source):
        raise ipsec_refused("copy-from must name one existing IPv4 Phase 2 selector")
    entry = snapshot.entries(PHASE2_TABLE).get(source)
    if entry is None:
        raise ipsec_refused("the Phase 2 copy source does not exist")
    attributes, unsupported = snapshot.entry_state(entry)
    if unsupported or attributes.keys() - profile.attributes.keys():
        raise ipsec_refused("the Phase 2 copy source has attributes outside the IPv4 selector profile")
    if changes.get("pfs") == "disable":
        attributes.pop("dhgrp", None)
    selectors = {name: ANY_IPV4 for name in PHASE2_SUBNETS}
    return {**selectors, **attributes, **changes}


def phase2_prechecks(snapshot, op, key, state, protected, impact):
    parent = state.get("phase1name")
    ipsec_parent(snapshot, key, parent, protected)
    if impact != key:
        raise ipsec_refused("Phase 2 changes require endpoint_impact naming the selector", "fortios_ipsec_impact_required")
    if state.get("pfs") == "disable" and "dhgrp" in state:
        raise ipsec_refused("DH groups require PFS on the Phase 2 selector")
    if op != "create":
        return
    selectors = tuple(state.get(name, ANY_IPV4) for name in PHASE2_SUBNETS)
    for entry in snapshot.entries(PHASE2_TABLE).values():
        if (entry.value("phase1name") == parent
                and all(entry.value(side + "-addr-type", "subnet") == "subnet" for side in ("src", "dst"))
                and tuple(entry.value(name, ANY_IPV4) for name in PHASE2_SUBNETS) == selectors):
            raise ipsec_refused("the Phase 1 already has this source and destination selector pair")


def ipsec_target(request):
    if (set(request.changes) != {"phase1name"} or not isinstance(request.changes["phase1name"], str)
            or not PHASE1_NAME.fullmatch(request.changes["phase1name"]) or not PHASE2_NAME.fullmatch(request.key)):
        raise ipsec_refused("IPsec recovery needs one Phase 2 key and its phase1name")
    if request.endpoint_impact != request.key:
        raise ipsec_refused("IPsec recovery requires endpoint_impact naming the selector", "fortios_ipsec_impact_required")
    return (request.key, request.changes["phase1name"])


def ipsec_target_prechecks(snapshot, target, protected):
    key, parent = target
    phase1 = ipsec_parent(snapshot, key, parent, protected)
    selector = snapshot.entries(PHASE2_TABLE).get(key)
    if phase1.value("type", "static") != "static" or selector is None or selector.value("phase1name") != parent:
        raise ipsec_refused("the selector must belong to the named static Phase 1")


def ipsec_observation(text, target, *, lifetimes=False):
    key, parent = target
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    count = PHASE2_COUNT.fullmatch(lines[0]) if lines else None
    unreadable = "the Phase 2 operational readback is incomplete or ambiguous"
    rows = {}
    current = None
    for line in lines[1:]:
        row = PHASE2_STATUS.fullmatch(line)
        if row is not None and row[1] not in rows:
            current = rows[row[1]] = (int(row[2]), row[3], [])
            continue
        sa = PHASE2_SA.fullmatch(line) if lifetimes else None
        if sa is None or current is None:
            raise ipsec_refused(unreadable, "clear_readback_unreadable")
        current[2].append(int(sa[1]))
    if (count is None or int(count[1]) != len(rows) or key not in rows
            or (lifetimes and any(total != len(expiries) for total, _, expiries in rows.values()))):
        raise ipsec_refused(unreadable, "clear_readback_unreadable")
    total, serial, expiries = rows[key]
    return {"phase1": parent, "phase2": key, "serial": serial, "up": total > 0,
            **({"sa_expiry_seconds": sorted(expiries)} if lifetimes else {})}


def ipsec_recovery_commands(before):
    verbs = ("down", "up") if before["up"] else ("up",)
    suffix = "%s %s" % (before["phase2"], before["phase1"])
    # The site-to-site form addresses the selector by both configured names.
    return ["diagnose vpn tunnel %s %s" % (verb, suffix) for verb in verbs]


SERVICE_TABLE = "firewall service custom"
SERVICE_PORTS = ("tcp-portrange", "udp-portrange")
PORT_RANGE = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")


def _port_range(value: str) -> bool:
    parts = value.split(":")
    if len(parts) > 2:
        return False
    for part in parts:
        match = PORT_RANGE.fullmatch(part)
        if match is None:
            return False
        low = int(match.group(1))
        high = low if match.group(2) is None else int(match.group(2))
        if not 1 <= low <= high <= 65535:
            return False
    return True


def service_prechecks(snapshot, key: str, after) -> list:
    reasons = []
    states = [] if after is None else [after]
    entry = (snapshot.entries(SERVICE_TABLE) or {}).get(key)
    if entry is not None:
        states.append({name: entry.value(name) for name in SERVICE_PORTS if entry.value(name) is not None})
    if after is not None and not any(after.get(name) for name in SERVICE_PORTS):
        reasons.append("a TCP/UDP/SCTP service needs tcp-portrange or udp-portrange")
    for state in states:
        for name in SERVICE_PORTS:
            value = state.get(name)
            if value is not None and not _port_range(value):
                reason = ("%s %r is not one port range low[-high][:low[-high]] with ports 1-65535 and low <= high"
                          % (name, value))
                if reason not in reasons:
                    reasons.append(reason)
    return reasons


def protected_interfaces(snapshot, protected) -> set:
    protected = protected or {}
    guarded = set(protected.get(INTERFACE_TABLE, ())) | set(protected.get("interface", ()))
    return protected_closure(snapshot, guarded)


def dhcp_protected(snapshot, key: str, protected) -> list:
    """A reservation of the DHCP server of a protected system interface (or of an interface built on it) changes the
    address of a client on the management path; Admin never changes it (checklist item 20e)."""
    servers = snapshot.root.section("system dhcp server")
    server = None if servers is None else servers.entries.get(split_nested(DHCP_TABLE, key)[0])
    if server is None:
        return []
    interface = server.value("interface", "")
    if interface.casefold() in protected_interfaces(snapshot, protected):
        return ["the DHCP server serves interface %s on the management path (protected system interface); Admin never"
                " changes its reservations" % interface]
    return []


def dns_prechecks(snapshot, key: str, after) -> list:
    zone, entry_id = split_nested(DNS_TABLE, key)
    if int(entry_id) > 4294967295:
        return ["DNS entry IDs exceed the supported range"]
    zones = snapshot.root.section("system dns-database")
    node = None if zones is None else zones.entries.get(zone)
    if node is None:
        return ["the DNS zone %s does not exist in the snapshot; Admin changes entries of an existing zone only" % zone]
    if node.value("status", "enable") != "enable" or node.value("type", "primary") != "primary":
        return ["the DNS zone %s must be an enabled primary zone" % zone]
    section = node.section("dns-entry")
    current = None if section is None else section.entries.get(entry_id)
    if current is not None and current.value("type", "A") not in ("A", "PTR"):
        return ["entry %s of the zone has type %s; Admin changes only A and PTR entries" % (entry_id, current.value("type"))]
    if after:
        if after.get("type", "A") == "PTR" and "." not in after.get("hostname", ""):
            return ["a PTR entry needs a host name with a domain"]
        for other, entry in ({} if section is None else section.entries).items():
            if other != entry_id and (entry.value("type", "A"), entry.value("hostname"), entry.value("ip")) == (
                    after.get("type", "A"), after.get("hostname"), after.get("ip")):
                return ["the entry duplicates entry %s of the zone" % other]
    return []


def resolve_nested_key(snapshot, table: str, key: str, op: str, changes: dict) -> tuple:
    """Turn "<interface>@<mac>" (DHCP reservation) or "<zone>@<hostname>" (DNS entry) into the stored key
    "<parent>:<id>". A create takes the next free id and carries the named MAC or host name as its attribute; an
    update or a delete needs exactly one matching object. Any other key is returned unchanged."""
    if table not in NESTED or "@" not in key:
        return key, changes
    name, _, ident = key.partition("@")
    parent_table, child_table = NESTED[table]
    attribute = "mac" if table == DHCP_TABLE else "hostname"
    wanted = ident.lower() if table == DHCP_TABLE else ident.casefold()
    parents = snapshot.root.section(parent_table)
    if table == DHCP_TABLE:
        found = [] if parents is None else [pid for pid, node in parents.entries.items()
                                            if node.value("interface") == name]
        if len(found) != 1:
            raise Rejected(["interface %s has %s" % (name, "no DHCP server" if not found else
                                                      "several DHCP servers; name the reservation by server and id")])
        parent = found[0]
    else:
        parent = name if parents is not None and name in parents.entries else None
        if parent is None:
            raise Rejected(["the DNS zone %s does not exist in the snapshot" % name])
    section = parents.entries[parent].section(child_table)
    entries = {} if section is None else section.entries
    matching = [cid for cid, node in entries.items() if (node.value(attribute) or "").casefold() == wanted]
    given = changes.get(attribute)
    if op == "create":
        if given is not None and given.casefold() != wanted:
            raise Rejected(["%s in the changes differs from the %s in the key" % (attribute, attribute)])
        if table == DHCP_TABLE and matching:
            raise Rejected(["the MAC %s is already reserved on interface %s (reservation %s)" % (ident, name, matching[0])])
        number = max([int(cid) for cid in entries if cid.isdigit()] + [0]) + 1
        return "%s:%d" % (parent, number), {**changes, attribute: ident.lower() if table == DHCP_TABLE else ident}
    if attribute in changes:
        raise Rejected(["%s is part of the key %r; to change it address the object by its numeric key" % (attribute, key)])
    if len(matching) != 1:
        raise Rejected(["%s %s names %s; address the object by its numeric key %s:<id>" % (
            "interface" if table == DHCP_TABLE else "zone", name,
            "no object with %s %s" % (attribute, ident) if not matching else "several objects with %s %s" % (attribute, ident),
            parent)])
    return "%s:%s" % (parent, matching[0]), changes


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table == SERVICE_TABLE:
        return service_prechecks(snapshot, key, after)
    if profile.table == DHCP_TABLE:
        sid, rid = split_nested(profile.table, key)
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
    if profile.table == DNS_TABLE:
        return dns_prechecks(snapshot, key, after)
    return []


def _address_fields(profile, state, *, creating=False) -> list:
    kind = state.get("type", "ipmask")
    required = ADDRESS_FIELDS.get(kind)
    if required is None:
        return ["address type %s is outside the profile" % kind]
    allowed = {"type", "comment", *required}
    if kind == INTERFACE_SUBNET and not creating:
        allowed.add("subnet")
    if set(state) - allowed:
        return ["address type %s does not accept %s" % (kind, ", ".join(sorted(set(state) - allowed)))]
    missing = [name for name in required if name not in state]
    # Normal show omits the subnet when an ipmask uses the default 0.0.0.0/0.
    if missing and (kind != "ipmask" or creating):
        return ["%s needs %s" % ("create" if creating else "address type " + kind, ", ".join(missing))]
    try:
        for name in required:
            if name in state:
                value = state[name].split() if profile.attributes[name].type in LIST_TYPES else state[name]
                canonical_value(profile.attributes[name], value, profile.platform)
    except Rejected as exc:
        return exc.reasons
    if kind == "iprange" and ipaddress.IPv4Address(state["start-ip"]) > ipaddress.IPv4Address(state["end-ip"]):
        return ["start-ip must be less than or equal to end-ip"]
    return []


def address_prechecks(snapshot, profile, op, key, before, after, changes) -> list:
    if profile.table == ADDRESS_TABLE:
        if op == "create":
            return _address_fields(profile, {name: value for name, value in changes.items() if value is not None},
                                   creating=True)
        problems = _address_fields(profile, before)
        if before.get("type") == INTERFACE_SUBNET:
            if "subnet" in changes:
                return ["the subnet of an interface-subnet address is derived from its interface"]
            if not problems and op == "delete" and before.get("subnet") != _interface_subnet(snapshot, before["interface"]):
                return ["the interface subnet cannot be recreated with its current configured subnet"]
        return problems or (_address_fields(profile, after) if after is not None else [])
    state = before if op == "delete" else after
    members = set(l1_fortios.tokenize(state.get("member", "")))
    if not members or (before is not None and not before.get("member")):
        return ["a static address group must retain at least one member"]
    groups = snapshot.entries(GROUP_TABLE)
    known = set(snapshot.entries(ADDRESS_TABLE) or {}) | set(groups or {})
    if key in members or key.casefold() in member_closure(groups, members):
        return ["the group cannot include itself directly or through another group"]
    if members - known:
        return ["the group names a member missing from the visible snapshot"]
    return []


def _interface_subnet(snapshot, name) -> str:
    entry = (snapshot.entries(INTERFACE_TABLE) or {}).get(name)
    network = _network(entry.value("ip", "")) if entry is not None and entry.value("mode", "static") == "static" else None
    if network is None or network.prefixlen == 0:
        raise Rejected(["interface %r has no static IPv4 subnet in the visible snapshot" % name])
    return "%s %s" % (network.network_address, network.netmask)


def predict_interface_subnet(snapshot, key, state) -> None:
    if "interface" not in state:
        raise Rejected(["create needs interface"])
    name = state["interface"]
    for other, entry in (snapshot.entries(ADDRESS_TABLE) or {}).items():
        if other != key and entry.value("type") == INTERFACE_SUBNET and entry.value("interface") == name:
            raise Rejected(["interface %r already has an interface-subnet address object" % name])
    state["subnet"] = _interface_subnet(snapshot, name)


def address_support(profile, firmware, op, before, after) -> dict:
    if profile.table == ADDRESS_TABLE:
        new_operation = any(state is not None and state.get("type", "ipmask") != "ipmask"
                            for state in (before, after))
    else:
        new_operation = op != "update" or before.get("comment") != after.get("comment")
    measured_profile = replace(profile, versions=(G21_FIRMWARE,)) if new_operation else profile
    return firmware_support(measured_profile, firmware)


INTERFACE_TABLE = "system interface"
ROUTE_TABLE = "router static"
NETWORK_TABLES = (INTERFACE_TABLE, ROUTE_TABLE)
# allowaccess beyond ping (https, ssh, http, telnet, fgfm, snmp, fabric, ...) marks a management interface
UNMANAGED_ACCESS = ("ping",)
SEQ_NUM_MAX = 4294967295


def _network(text):
    parts = (text or "").split()
    if len(parts) != 2:
        return None
    try:
        return ipaddress.IPv4Interface("%s/%s" % tuple(parts)).network
    except ValueError:
        return None


def network_prechecks(snapshot, profile, op, key, before, after, protected) -> list:
    """G19: system interface and router static never touch the management path: the protected interfaces, the
    interfaces built on them, the interfaces carrying them, an interface with administrative access, the default
    route, a route through a protected interface or into its subnet or into the destination of a route that leaves
    through a protected interface."""
    reasons = []
    guarded = (protected or {}).get(INTERFACE_TABLE, [])
    interfaces = snapshot.entries(INTERFACE_TABLE) or {}
    if not guarded:
        reasons.append("changes of %s need protected system interface (the management path) in the device"
                       " configuration" % profile.table)
    for name in guarded:
        if name not in interfaces:
            reasons.append("protected interface %s is missing from the snapshot" % name)
    if reasons:
        return reasons
    closure = protected_closure(snapshot, guarded)
    shown = sorted(name for name in interfaces if name.casefold() in closure)
    protected_nets = [(name, _network(interfaces[name].value("ip"))) for name in shown]
    protected_nets = [(name, net) for name, net in protected_nets if net is not None]
    if profile.table == INTERFACE_TABLE:
        if key.casefold() in closure:
            reasons.append("interface %s is on the management path (protected system interface); Admin never changes"
                           " it" % key)
        elif op != "create":
            carried = sorted(name for name in shown if name.casefold() in protected_closure(snapshot, [key])
                             and name.casefold() != key.casefold())
            if carried:
                reasons.append("interface %s carries the protected interfaces %s; Admin never changes it"
                               % (key, ", ".join(carried)))
        for side in (before, after):
            access = set(str((side or {}).get("allowaccess", "")).split()) - set(UNMANAGED_ACCESS)
            if access:
                reasons.append("interface %s allows administrative access (%s); Admin never changes a management"
                               " interface" % (key, " ".join(sorted(access))))
                break
        if op == "create":
            parent = after.get("interface", "")
            if parent not in interfaces:
                reasons.append("the parent interface %s is missing from the snapshot" % parent)
            elif parent.casefold() in closure:
                reasons.append("the parent interface %s is on the management path (protected system interface)"
                               % parent)
        address = (after or {}).get("ip")
        net = _network(address)
        if net is not None and address != (before or {}).get("ip"):
            for name, entry in interfaces.items():
                other = _network(entry.value("ip"))
                if name != key and other is not None and other.overlaps(net):
                    reasons.append("ip %s overlaps the subnet of interface %s" % (address, name))
                    break
    else:
        if op == "create" and int(key) > SEQ_NUM_MAX:
            reasons.append("the route sequence number exceeds %d" % SEQ_NUM_MAX)
        routes = snapshot.entries(ROUTE_TABLE) or {}
        # a default route through the management path stays protected by itself (its device and its dst refuse any
        # change of it); every destination overlaps 0.0.0.0/0, so it does not refuse the other routes
        guarded_routes = [(seq, _network(entry.value("dst", "0.0.0.0 0.0.0.0"))) for seq, entry in routes.items()
                          if seq != key and entry.value("device", "").casefold() in closure]
        guarded_routes = [(seq, net) for seq, net in guarded_routes if net is None or net.prefixlen != 0]
        for side in (before, after):
            if not side:
                continue
            device = side.get("device", "")
            dst = _network(side.get("dst", "0.0.0.0 0.0.0.0"))
            if device.casefold() in closure:
                reasons.append("the route leaves through interface %s on the management path (protected system"
                               " interface)" % device)
            if dst is None or dst.prefixlen == 0:
                reasons.append("Admin never changes a default route")
                continue
            for name, net in protected_nets:
                if dst.overlaps(net):
                    reasons.append("the route destination %s overlaps the subnet of protected interface %s"
                                   % (dst, name))
            for seq, net in guarded_routes:
                if net is not None and dst.overlaps(net):
                    reasons.append("the route destination %s overlaps route %s that leaves through the management"
                                   " path" % (dst, seq))
        if after and after.get("device") not in interfaces:
            reasons.append("the route names an interface missing from the snapshot")
    return list(dict.fromkeys(reasons))


POLICY_TABLE = "firewall policy"
POLICYID_MAX = 4294967294
SAFEGUARD_SCRIPT_LIMIT = 1023
POLICY_REFERENCES = (
    ("srcaddr", ("firewall address", "firewall addrgrp"), ("all",)),
    ("dstaddr", ("firewall address", "firewall addrgrp", VIP_TABLE, VIP_GROUP_TABLE), ("all",)),
    ("srcaddr6", ("firewall address6", "firewall addrgrp6"), ("all", "all6")),
    ("dstaddr6", ("firewall address6", "firewall addrgrp6"), ("all", "all6")),
    ("service", ("firewall service custom", "firewall service group"), ()),
    ("schedule", ("firewall schedule onetime", "firewall schedule recurring", "firewall schedule group"),
     ("always",)),
    ("poolname", (POOL_TABLE,), ()),
    ("groups", ("user group",), ()),
    ("users", ("user local",), ()),
    ("internet-service-group", ("firewall internet-service-group",), ()),
    ("internet-service-custom", ("firewall internet-service-custom",), ()),
    ("internet-service-custom-group", ("firewall internet-service-custom-group",), ()),
)
POLICY_PROFILES = {
    "ssl-ssh-profile": ("firewall ssl-ssh-profile", ("no-inspection", "certificate-inspection", "deep-inspection")),
    "webfilter-profile": ("webfilter profile", ("default",)),
    "av-profile": ("antivirus profile", ()),
    "ips-sensor": ("ips sensor", ()),
    "application-list": ("application list", ()),
    "dnsfilter-profile": ("dnsfilter profile", ()),
}
POLICY_ISDB_FIELDS = ("internet-service-name", "internet-service-group",
                      "internet-service-custom", "internet-service-custom-group")
POLICY_MATCH_FIELDS = {"srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service", "internet-service", *POLICY_ISDB_FIELDS}
G23_POLICY_FIELDS = {*POLICY_PROFILES, *POLICY_ISDB_FIELDS, "ippool", "poolname", "groups", "users",
                     "srcaddr6", "dstaddr6", "internet-service"}
MISSING_OBJECT = "the policy names an object missing from the visible snapshot"
SDWAN_DEFAULT_ZONE = "virtual-wan-link"


def _entry_names(snapshot, table):
    entries = snapshot.entries(table)
    return set() if entries is None else set(entries)


def valid_policy_id(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None and int(value) <= POLICYID_MAX


def policy_order(section, text):
    if (section is None or section.attrs or section.sub or "--More--" in text
            or not all(valid_policy_id(key) for key in section.entries)
            or any(path[:1] == (POLICY_TABLE,) for path in _repetitions(text))):
        raise Rejected(["the policy order could not be read completely"], reason_codes=["fortios_policy_order_unreadable"])
    return list(section.entries)


def policy_move_digest(entry):
    def body(node):
        return (
            sorted((name, attr.values, attr.unset) for name, attr in node.attrs.items()),
            sorted((name, body(child)) for name, child in node.sub.items()),
            [(name, body(child)) for name, child in node.entries.items()],
        )
    return hashlib.sha256(json.dumps(body(entry), ensure_ascii=True).encode("ascii")).hexdigest()


def policy_position(op, changes):
    attributes = dict(changes)
    positions = {name: attributes.pop(name) for name in ("before", "after") if name in attributes}
    if (len(positions) > 1 or (op == "move" and (not positions or attributes))
            or (positions and op not in ("create", "move"))):
        raise Rejected(["a policy move requires exactly one of before or after; creation may also specify one"])
    position = next(iter(positions.items()), None)
    if position is not None:
        direction, anchor = position
        anchor = str(anchor) if type(anchor) is int else anchor
        if not valid_policy_id(anchor):
            raise Rejected(["the position anchor must be a valid policy ID"])
        position = direction, anchor
    return attributes, position


def valid_policy_uuid(value):
    return isinstance(value, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value
    ) is not None


def require_policy_uuid(value):
    if not valid_policy_uuid(value):
        raise Rejected(["the original firewall policy UUID is unavailable; its identity cannot be restored"])
    return value.lower()


def policy_restore_attributes(profile, before):
    attributes = {name: value for name, value in before.items() if name != "uuid"}
    for name, attribute in profile.attributes.items():
        if attribute.required_on_create:
            attributes.setdefault(name, attribute.default)
    if attributes.get("action") == "deny":
        attributes.setdefault("logtraffic", "disable")
    return attributes


def policy_support(profile, snapshot, op, changes, before, after):
    destinations = {name for state in (before, after)
                    for name in l1_fortios.tokenize((state or {}).get("dstaddr", ""))}
    vip_reference = destinations & (_entry_names(snapshot, VIP_TABLE) | _entry_names(snapshot, VIP_GROUP_TABLE))
    measured_here = (op in ("delete", "move") or op == "create" and changes.get("status") == "enable"
                     or changes.keys() & ({"before", "after", "nat", "utm-status"} | G23_POLICY_FIELDS)
                     or vip_reference)
    measured = replace(profile, versions=("7.6.8 build3744",)) if measured_here else profile
    return firmware_support(measured, snapshot.firmware)


def position_at(order, key):
    index = order.index(key)
    if index + 1 < len(order):
        return "before", order[index + 1]
    if index:
        return "after", order[index - 1]
    return None


def render_move(key, position):
    return ["config firewall policy", "    move %s %s %s" % (key, *position), "end"]


def render_policy_create(profile, key, attributes, position, *, uuid=None):
    staged = position is not None and attributes.get("status", "enable") == "enable"
    initial = {**attributes, "status": "disable"} if staged else attributes
    lines = render_create(profile, key, initial)
    if uuid is not None:
        lines.insert(-2, "        set uuid " + require_policy_uuid(uuid))
    if position is not None:
        lines.extend(render_move(key, position))
    if staged:
        lines.extend(render_update(profile, key, {"status": "enable"}, []))
    return lines


def plan_policy_order(snapshot, key, op, position, undo_plan):
    order = snapshot.policy_order()
    remaining = [item for item in order if item != key]
    previous = (undo_plan or {}).get("policy_order")
    if previous is not None and (undo_plan["op"] in ("create", "delete", "move")):
        previous_ids = set(previous["after"])
        if [item for item in order if item in previous_ids] != previous["after"]:
            raise Rejected(["the original policy order changed before undo"], reason_codes=["fortios_policy_order_changed"])
        if op in ("create", "move"):
            position = position_at(previous["before"], key)
            if position is None and remaining:
                position = "before", remaining[0]
        if undo_plan["op"] == "move" and (
            policy_move_digest(snapshot.entries(POLICY_TABLE)[key]) != undo_plan["policy_move_sha256"]
        ):
            raise Rejected(["the moved firewall policy changed before undo"], reason_codes=["fortios_policy_order_changed"])
    if position is not None and position[1] not in remaining:
        raise Rejected(["the policy position anchor is missing or is the policy being changed"],
                       reason_codes=["fortios_policy_order_changed"])
    after = list(order)
    if op == "delete":
        after = remaining
    elif op in ("create", "move"):
        after = remaining
        index = len(after) if position is None else after.index(position[1]) + (position[0] == "after")
        after.insert(index, key)
        if op == "move" and order == after:
            raise Rejected(["the policy is already in that position"])
    return {"before": order, "after": after}, position


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


def check_cli_inverse(inverse: list) -> None:
    if safeguard_script_length(inverse) > SAFEGUARD_SCRIPT_LIMIT:
        raise Rejected(["the inverse exceeds the safeguard script limit"], reason_codes=["safeguard_script_limit"])


def _usable_nat_ip(text):
    try:
        host = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (host.is_unspecified or host.is_multicast or host.is_loopback or int(host) == 0xffffffff)


def _management_ipv4_addresses(interfaces, guarded):
    addresses = set()
    for name, interface in interfaces.items():
        managed = name.casefold() in guarded or bool(set(interface.values("allowaccess")) - set(UNMANAGED_ACCESS))
        secondary = interface.section("secondaryip")
        for entry in (interface, *(secondary.entries.values() if secondary is not None else ())):
            if managed or set(entry.values("allowaccess")) - set(UNMANAGED_ACCESS):
                addresses.update(ipaddress.IPv4Address(ip) for ip in entry.values("ip")[:1] if _usable_nat_ip(ip))
    return addresses


def nat_prechecks(snapshot, table, key, before, after, protected, impact):
    vip = table == VIP_TABLE
    binding = "extintf" if vip else "associated-interface"
    interfaces = snapshot.entries(INTERFACE_TABLE) or {}
    configured = set((protected or {}).get(INTERFACE_TABLE, ())) | set((protected or {}).get("interface", ()))
    if {name.casefold() for name in configured} - {name.casefold() for name in interfaces}:
        raise Rejected(["a protected interface cannot be evaluated from the snapshot"],
                       reason_codes=["fortios_nat_protected"])
    guarded = protected_interfaces(snapshot, protected or {})
    states = [side for side in (before, after) if side is not None]
    names = [side[binding] for side in states if side.get(binding)]
    if guarded and protected_exposure(snapshot, guarded, names):
        raise Rejected(["the NAT object touches a protected interface"],
                       reason_codes=["fortios_nat_protected"])
    if vip:
        guarded_ips = _management_ipv4_addresses(interfaces, guarded)
    else:
        guarded_ips = {ipaddress.IPv4Address(ip) for name, entry in interfaces.items()
                       if name.casefold() in guarded for ip in entry.values("ip")[:1] if _usable_nat_ip(ip)}
    valid_bindings = set(interfaces) | ({"any"} if vip else set())
    for side in states:
        if side.get(binding) is not None and side[binding] not in valid_bindings:
            return ["the NAT object names an interface missing from the snapshot"]
        if vip:
            ports = {"extport", "mappedport"}
            if side.get("portforward") == "enable" and any(
                not re.fullmatch(r"[1-9][0-9]{0,4}", side.get(name, "")) or int(side[name]) > 65535 for name in ports
            ):
                return ["VIP port forwarding requires individual ports in 1..65535"]
            if side.get("portforward") != "enable" and side.keys() & (ports | {"protocol"}):
                return ["VIP protocol and ports require portforward enable"]
            endpoints = (side.get("extip"), side.get("mappedip"))
            if not all(_usable_nat_ip(ip) for ip in endpoints):
                return ["the VIP needs nonzero unicast external and mapped IPv4 addresses"]
            if guarded_ips & {ipaddress.IPv4Address(ip) for ip in endpoints}:
                raise Rejected(["the VIP uses a management address"],
                               reason_codes=["fortios_nat_protected"])
        else:
            start, end = side.get("startip"), side.get("endip")
            if not (_usable_nat_ip(start) and _usable_nat_ip(end)):
                return ["the IP pool needs an ascending range of unicast IPv4 addresses"]
            low, high = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            if low > high:
                return ["the IP pool needs an ascending range of unicast IPv4 addresses"]
            if any(low <= ip <= high for ip in guarded_ips):
                raise Rejected(["the IP pool contains the address of a protected interface"],
                               reason_codes=["fortios_nat_protected"])
    changed = {field for field in (before or {}).keys() | (after or {}).keys()
               if (before or {}).get(field) != (after or {}).get(field)}
    arp = any(side.get("arp-reply", "enable") == "enable" for side in states)
    if arp and changed - {"comment", "comments"} and impact != key:
        raise Rejected(["changing an ARP-enabled NAT object requires endpoint_impact naming the object"],
                       reason_codes=["fortios_nat_impact_required"])
    return []


def _policy_match(after):
    internet = after.get("internet-service") == "enable"
    selectors = after.keys() & set(POLICY_ISDB_FIELDS)
    if internet:
        if (not after.get("srcaddr") or not selectors or any(not after[name] for name in selectors)
                or after.keys() & {"dstaddr", "service", "srcaddr6", "dstaddr6"}):
            return ["Internet Service policy needs srcaddr and an Internet Service selector without destination addresses or service"]
    elif selectors:
        return ["Internet Service selectors require internet-service enable"]
    elif (not after.get("service") or not (after.get("srcaddr") or after.get("srcaddr6"))
          or ("srcaddr" in after) != ("dstaddr" in after)
          or ("srcaddr6" in after) != ("dstaddr6" in after)):
        return ["policy needs matching source and destination address families and a service"]
    return []


def _policy_vip_bindings(snapshot, destinations, guarded_ips):
    vips = snapshot.entries(VIP_TABLE)
    groups = snapshot.entries(VIP_GROUP_TABLE) or {}
    names = set(destinations)
    bindings = set()
    for key in names & groups.keys():
        group = groups[key]
        bindings.add(group.value("interface", "any"))
        if any(member not in vips for member in group.values("member")):
            raise Rejected(["the members of a destination VIP group cannot be verified"])
    names.update(member for key in names & groups.keys() for member in groups[key].values("member"))
    for key in names & vips.keys():
        vip = vips[key]
        bindings.add(vip.value("extintf", "any"))
        mapped = vip.values("mappedip")
        if not mapped:
            raise Rejected(["the mapped addresses of a destination VIP cannot be verified"],
                           reason_codes=["fortios_nat_protected"])
        for value in mapped:
            first, separator, last = value.partition("-")
            last = last if separator else first
            if not (_usable_nat_ip(first) and _usable_nat_ip(last)):
                raise Rejected(["the mapped addresses of a destination VIP cannot be verified"],
                               reason_codes=["fortios_nat_protected"])
            low, high = ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
            if low > high or any(low <= address <= high for address in guarded_ips):
                raise Rejected(["a destination VIP maps to a management address or an invalid range"],
                               reason_codes=["fortios_nat_protected"])
    return bindings - {"any"}


def policy_prechecks(snapshot, op, before, after, protected, *, impact=None, order=None, key=None) -> list:
    reasons = []
    protected = protected or {}
    guarded = set(protected.get("system interface", ())) | set(protected.get("interface", ()))
    known_interfaces = _entry_names(snapshot, "system interface")
    for name in sorted(guarded):
        if name not in known_interfaces:
            reasons.append("protected interface %s is missing from the snapshot" % name)
    if after and op != "move":
        if before is None or any(before.get(name) != after.get(name) for name in POLICY_MATCH_FIELDS):
            reasons.extend(_policy_match(after))
        for attribute, tables, extra in POLICY_REFERENCES:
            known = set(extra).union(*(_entry_names(snapshot, table) for table in tables))
            value = after.get(attribute)
            if value is None:
                continue
            names = [value] if attribute == "schedule" else l1_fortios.tokenize(value)
            if not names or any(name not in known for name in names):
                reasons.append(MISSING_OBJECT)
                break
        interfaces = known_interfaces | _entry_names(snapshot, "system zone") | sdwan_zones(snapshot)["zones"]
        for attribute in ("srcintf", "dstintf"):
            if any(name not in interfaces and name != "any" for name in l1_fortios.tokenize(after.get(attribute, ""))):
                if MISSING_OBJECT not in reasons:
                    reasons.append(MISSING_OBJECT)
        settings = snapshot.root.section("system settings")
        if after.get("nat") == "enable" and settings is not None and settings.value("central-nat") == "enable":
            reasons.append("policy NAT is unavailable when central NAT is enabled")
        pool = after.get("ippool") == "enable"
        if pool and (after.get("nat") != "enable" or not after.get("poolname")):
            reasons.append("ippool enable requires nat enable and poolname")
        if "poolname" in after and not pool:
            reasons.append("poolname requires ippool enable")
        utm = after.get("utm-status") == "enable"
        if after.get("action", "deny") != "accept" and (
                utm or after.get("nat") == "enable" or after.keys() & {"groups", "users"}):
            reasons.append("UTM, NAT and user authentication require action accept")
        for field, (table, builtins) in POLICY_PROFILES.items():
            if field in after and not utm:
                reasons.append("%s requires utm-status enable" % field)
            if field in after and after[field] not in _entry_names(snapshot, table).union(builtins):
                reasons.append(MISSING_OBJECT)
    active = any(state is not None and state.get("status", "enable") == "enable" for state in (before, after))
    traffic_attributes = set(before or {}) | set(after or {})
    traffic_attributes -= {"name", "comments", "logtraffic"}
    affects_traffic = op != "update" or any((before or {}).get(field) != (after or {}).get(field)
                                             for field in traffic_attributes)
    if active and affects_traffic and impact is None:
        raise Rejected(["an active firewall policy change requires endpoint_impact naming its policy ID"],
                       reason_codes=["fortios_policy_impact_required"])
    activates = (op == "update" and before is not None and before.get("status") == "disable"
                 and after is not None and after.get("status", "enable") == "enable")
    if order is not None and (activates or (active and op in ("create", "move"))):
        before_ids = order["before"]
        start = before_ids.index(key) if key in before_ids else len(before_ids)
        stop = order["after"].index(key)
        others = [item for item in before_ids if item != key]
        entries = snapshot.entries(POLICY_TABLE)
        crossed = others[stop:] if activates else others[min(start, stop):max(start, stop)]
        for other in crossed:
            node = entries[other]
            names = node.values("srcintf") + node.values("dstintf")
            if other in protected.get(POLICY_TABLE, ()) or (guarded and protected_exposure(snapshot, guarded, names)):
                reasons.append("the new policy order crosses a protected policy")
                break
    if not reasons:
        guarded_ips = _management_ipv4_addresses(snapshot.entries(INTERFACE_TABLE) or {},
                                                  protected_interfaces(snapshot, protected))
        names = []
        for side in (before, after):
            for attribute in ("srcintf", "dstintf"):
                names.extend(l1_fortios.tokenize((side or {}).get(attribute, "")))
            names.extend(_policy_vip_bindings(snapshot, l1_fortios.tokenize((side or {}).get("dstaddr", "")),
                                              guarded_ips))
        touched = protected_exposure(snapshot, guarded, names) if guarded else ()
        if touched:
            reasons.append("the policy touches the management path of the protected interfaces: %s"
                           % ", ".join(repr(name) for name in sorted(set(touched))))
    return list(dict.fromkeys(reasons))


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
REST_KEYS = {"firewall policy": "policyid", "firewall address": "name", "firewall addrgrp": "name",
             "firewall service custom": "name", DHCP_TABLE: "id", DNS_TABLE: "id", PHASE2_TABLE: "name",
             VIP_TABLE: "name", POOL_TABLE: "name"}
# a nested table is reached under its parent: <parent path>/<parent key>/<child table>/<child id> (read with GET on
# FortiOS 7.6.8 build3744 and 8.0.2 build0251, 2026-11-20)
REST_PATHS = {"firewall policy": "firewall/policy", "firewall address": "firewall/address",
              "firewall addrgrp": "firewall/addrgrp", "firewall service custom": "firewall.service/custom",
              DHCP_TABLE: "system.dhcp/server", DNS_TABLE: "system/dns-database", PHASE2_TABLE: "vpn.ipsec/phase2-interface",
              VIP_TABLE: "firewall/vip", POOL_TABLE: "firewall/ippool"}
ACCPROFILE_NONE = ("secfabgrp", "ftviewgrp", "authgrp", "sysgrp", "netgrp", "loggrp", "vpngrp", "utmgrp", "wifi")
REST_PERMISSION = {DNS_TABLE: "sysgrp", PHASE2_TABLE: "vpngrp"}
API_KEY = re.compile(r"^New API key:[ \t]*([0-9A-Za-z]+)[ \t\r]*$", re.MULTILINE)
QUERY_GLOBAL = "show system global"
HTTPS_PORT = "443"


def _percent(text: str) -> str:
    return "".join(chr(byte) if chr(byte) in UNRESERVED else "%%%02X" % byte for byte in text.encode("utf-8"))


def webhook_firmware(firmware: str) -> bool:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+) build[0-9]+", firmware or "")
    return match is not None and tuple(int(part) for part in match.groups()) >= WEBHOOK_FROM


# T1 (G00): a technical incompatibility, not an untested version. From 8.0.1 the safeguard is the webhook, which
# returns the change through the REST API; a table without a REST inverse cannot be returned there, and the
# cli-script safeguard cannot run configuration commands on these builds.
NO_REST_INVERSE = "safeguard_no_rest_inverse"


def webhook_refusal(profile, firmware):
    if not webhook_firmware(firmware) or (profile.table in REST_PATHS and profile.table in REST_KEYS):
        return None
    return ("table %s cannot be changed on FortiOS %s: from 8.0.1 Admin returns a change through the webhook"
            " safeguard (the REST API of the device), and the webhook safeguard has no REST inverse for this table;"
            " the cli-script safeguard of earlier FortiOS versions cannot run configuration commands on these builds"
            " (technical limit, not an untested version)" % (profile.table, firmware))


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
    if profile.table == VIP_TABLE and name == "mappedip":
        return [{"range": item} for item in values]
    if profile.table == VIP_TABLE and name in ("extport", "mappedport"):
        return values[0]
    if attribute is not None and attribute.type == "name-list":
        return [{"name": item} for item in values]
    if attribute is not None and attribute.type == "mac-address-list":
        return [{"macaddr": item} for item in values]
    if attribute is not None and attribute.type == "integer":
        return int(values[0])
    return " ".join(values)


def rest_inverse(profile, op: str, key: str, inverse: list, address: str) -> dict:
    field = REST_KEYS.get(profile.table)
    if field is None or profile.table not in REST_PATHS:
        raise Rejected(["the webhook safeguard has no REST inverse for table %s" % profile.table],
                       reason_codes=["safeguard_no_rest_inverse"])
    assign, removed, move = {}, [], None
    for line in inverse:
        tokens = l1_fortios.tokenize(line.strip())
        if tokens[:1] == ["set"] and len(tokens) > 2:
            assign[tokens[1]] = _rest_value(profile, tokens[1], tokens[2:])
        elif tokens[:1] == ["unset"]:
            removed.append(tokens[1])
        elif tokens[:2] == ["move", key] and len(tokens) == 4 and tokens[2] in ("before", "after") and valid_policy_id(tokens[3]):
            move = tokens[2:]
    path = "api/v2/cmdb/" + REST_PATHS[profile.table]
    child_id = key
    if profile.table in NESTED:
        parent, child_id = split_nested(profile.table, key)
        path = "%s/%s/%s" % (path, _percent(parent), NESTED[profile.table][1])
    item = path + "/" + _percent(child_id)
    if op == "create":
        method, uri, body = "delete", item, None
    elif op == "move" and move is not None:
        method, uri, body = "put", "%s?action=move&%s=%s" % (item, *move), None
    elif op == "update":
        for name in removed:
            attribute = profile.attributes.get(name)
            if attribute is not None and attribute.default is not None:
                assign[name] = _rest_value(profile, name, [attribute.default])
            elif attribute is not None and attribute.type in LIST_TYPES:
                assign[name] = []
            elif profile.table == VIP_TABLE and name in ("extport", "mappedport"):
                assign[name] = "0-65535"
            else:
                assign[name] = ""
        method, uri, body = "put", item, assign
    else:
        if op == "move" or move is not None:
            raise Rejected(["the timed REST safeguard cannot recreate and reposition a policy in one request"],
                           reason_codes=["safeguard_no_rest_inverse"])
        assign[field] = int(child_id) if field in ("policyid", "id") else key
        method, uri, body = "post", path, assign
    text = "" if body is None else json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text.encode("ascii")) > SAFEGUARD_SCRIPT_LIMIT:
        raise Rejected(["the inverse exceeds the safeguard request body limit"])
    if "%%" in text:
        raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
    return {"method": method, "uri": "%s/%s" % (address, uri), "body": text}


def webhook_permissions(table):
    write_group = REST_PERMISSION.get(table, "fwgrp")
    return {group: "read-write" if group == write_group else "none" for group in ("fwgrp", *ACCPROFILE_NONE)}


def render_webhook_identity(change_id: str, address: str, table=POLICY_TABLE) -> list:
    names = webhook_names(change_id)
    lines = ["config system accprofile", 'edit "%s"' % names["accprofile"]]
    lines.extend("set %s %s" % item for item in webhook_permissions(table).items())
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
                  address: str, table=POLICY_TABLE) -> list:
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
    if profile is None or any(profile.value(group, "none") != mode
                              for group, mode in webhook_permissions(table).items()):
        problems.append("safeguard access profile is missing or differs from the REST table permissions")
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


def switch_port_state(entry):
    result = {}
    for name in SWITCH_PORT_FIELDS:
        attr = entry.attrs.get(name)
        if attr is None:
            continue
        if name in FORTIOS_PORT_VLAN_LISTS:
            valid = (not attr.unset and all(FORTIOS_VLAN_NAME.fullmatch(item) for item in attr.values)
                     and len(attr.values) == len({item.casefold() for item in attr.values}))
            if valid:
                result[name] = group_members_text(attr.values)
                continue
        elif (not attr.unset and len(attr.values) == 1
              and (name not in SWITCH_OPTIONS or attr.value() in SWITCH_OPTIONS[name])
              and (name != "vlan" or FORTIOS_VLAN_NAME.fullmatch(attr.value()))):
            result[name] = attr.value()
            continue
        raise StateUnreadable(["the managed switch port has an ambiguous " + name])
    return result


def shown_switch_port(text, key):
    serial, port = key.split(":")
    if not text.strip().startswith("config " + MANAGED_SWITCH) or "--More--" in text:
        raise Rejected(["the check account cannot read the managed switch"], reason_codes=["state_unreadable"])
    try:
        root = parse_snapshot(text)
    except SnapshotRejected:
        raise Rejected(["the managed switch port configuration is incomplete"], reason_codes=["state_unreadable"]) from None
    switches = root.section(MANAGED_SWITCH)
    switch = None if switches is None else switches.entries.get(serial)
    ports = None if switch is None else switch.section("ports")
    entry = None if ports is None else ports.entries.get(port)
    if entry is None or entry.sub or _repetitions(text):
        raise Rejected(["the managed switch port configuration is incomplete"], reason_codes=["state_unreadable"])
    return switch_port_state(entry)


def protect_switch_port(key, entry, protected):
    port = key.split(":")[1]
    names = {name.casefold() for name in (protected or {}).get("interface", ())}
    flags = ("fortilink-port", "stacking-port", "p2p-port", "mclag-icl-port")
    if (port.casefold() in names or key.casefold() in names
            or any(entry.value(name, "0") != "0" for name in flags)
            or entry.value("isl-local-trunk-name", "")):
        raise Rejected(["the managed switch port is protected"], reason_codes=["port_protected"])


def switch_vlan_prechecks(snapshot, key, before, after, protected):
    changed = {name for name in SWITCH_VLAN_FIELDS if before.get(name) != after.get(name)}
    if not changed:
        return
    serial, port = key.split(":")
    switch = snapshot.root.section(MANAGED_SWITCH).entries[serial]
    entry = switch.section("ports").entries[port]
    if entry.value("access-mode", "static") != "static" or entry.value("port-policy", ""):
        raise Rejected(["VLAN membership is controlled by a port policy"], reason_codes=["port_protected"])
    interfaces = snapshot.entries(INTERFACE_TABLE) or {}
    link = switch.value("fsw-wan1-peer")
    parent = interfaces.get(link)
    if parent is None or parent.value("fortilink") != "enable":
        raise StateUnreadable(["the switch FortiLink interface is unknown"])
    guarded = protected or {}
    protected_names = {name.casefold() for table in ("interface", INTERFACE_TABLE)
                       for name in guarded.get(table, ())}
    management_protocols = {"https", "ssh", "http", "telnet"}
    for name, node in interfaces.items():
        if node.value("interface") == link and management_protocols.intersection(node.values("allowaccess")):
            protected_names.add(name.casefold())
    for field in changed:
        affected = _switch_vlan_names(before, field) ^ _switch_vlan_names(after, field)
        if field == "allowed-vlans-all":
            affected = {name for name, node in interfaces.items()
                        if node.value("interface") == link and node.value("vlanid")}
        for name in affected:
            if name.casefold() in protected_names:
                raise Rejected(["the VLAN change affects a protected interface"], reason_codes=["port_management_vlan"])
            node = interfaces.get(name)
            vlan_id = "" if node is None else node.value("vlanid", "")
            if node is None or node.value("interface") != link or not vlan_id.isdecimal() or not 1 <= int(vlan_id) <= 4094:
                raise Rejected(["VLAN %r is not an interface on the switch FortiLink" % name],
                               reason_codes=["fortiswitch_vlan_invalid"])
    if not before.get("vlan") or not after.get("vlan"):
        raise StateUnreadable(["the port has no readable native VLAN to restore"])
    if after.get("allowed-vlans-all", "disable") == "disable" and (
        _switch_vlan_names(after, "untagged-vlans") - _switch_vlan_names(after, "allowed-vlans") -
        _switch_vlan_names(after, "vlan")
    ):
        raise Rejected(["untagged VLANs must also be allowed or native"], reason_codes=["fortiswitch_vlan_invalid"])


def _switch_vlan_names(state, field):
    if field in FORTIOS_PORT_VLAN_LISTS:
        return set(l1_fortios.tokenize(state.get(field, "")))
    return {state[field]} if field == "vlan" and field in state else set()


def switch_poe_reset(key):
    serial, port = key.split(":")
    return f"execute switch-controller poe-reset {serial} {port}"


def shown_object(text: str, table: str, key: str):
    if table in NESTED:
        parent_table, child_table = NESTED[table]
        parent_key, child_key = split_nested(table, key)
        start = text.find("config " + parent_table)
        if start < 0:
            if table == DNS_TABLE and _answers_not_found(text):
                raise Rejected(["the check account cannot see the DNS zone"])
            raise Rejected(["the check account cannot read %s" % parent_table])
        tree = l1_fortios.parse(text[start:])
        parents = tree.section(parent_table)
        parent = None if parents is None else parents.entries.get(parent_key)
        if parent is None:
            raise Rejected(["the check account cannot see %s %s" % (parent_table, parent_key)])
        section = parent.section(child_table)
        entry = None if section is None else section.entries.get(child_key)
        return None if entry is None else {name: attr.value() for name, attr in entry.attrs.items() if not attr.unset}
    exact_read = table in (*ADDRESS_TABLES, POLICY_TABLE, PHASE2_TABLE, *NAT_TABLES, ISDB_TABLE)
    if exact_read:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        # FortiOS can report the CMDB lookup code after the absence marker.
        if lines in ([NOT_FOUND], [NOT_FOUND, "Command fail. Return code -3"]):
            return None
    elif _answers_not_found(text):
        return None
    start = text.find("config %s" % table)
    if start < 0:
        raise Rejected(["the check account answer holds no %s section" % table])
    try:
        root = l1_fortios.parse(text[start:])
    except (l1_fortios.ParseError, l1_fortios.TruncatedError) as exc:
        if table == POLICY_TABLE:
            raise Rejected(["the policy could not be read completely"],
                           reason_codes=["fortios_policy_order_unreadable"]) from None
        raise Rejected(["the check account answer does not parse: %s" % exc]) from None
    section = root.sub.get(table)
    entry = None if section is None else section.entries.get(key)
    if entry is None:
        raise Rejected(["the check account answer names no object %s" % key])
    if exact_read:
        list_fields = FORTIOS_POLICY_LIST_FIELDS if table == POLICY_TABLE else ("member", "macaddr")
        if (NOT_FOUND in text[:start] or "--More--" in text or len(section.entries) != 1 or entry.sub
                or _repetitions(text[start:]).get(entry.path)
                or any(attr.unset or (name in list_fields and _list_has_unsupported_whitespace(entry, name, attr.values))
                       for name, attr in entry.attrs.items())):
            raise Rejected(["the check account returned incomplete or ambiguous configuration of %s" % key])
    if table in (*NAT_TABLES, ISDB_TABLE):
        mandatory = ("extip", "mappedip", "extintf") if table == VIP_TABLE else ("startip", "endip")
        if table == ISDB_TABLE:
            mandatory = ()
        if (set(root.sub) != {table} or text[:start].strip()
                or text[start:].splitlines().count("config " + table) != 1
                or any(not entry.value(name) for name in mandatory)):
            raise Rejected(["the check account returned incomplete NAT object configuration"])
    if table == PHASE2_TABLE and (set(root.sub) != {table} or not entry.value("phase1name")):
        raise ipsec_refused("the check account returned incomplete Phase 2 configuration", "clear_readback_unreadable")
    return _shown_attributes(entry)


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
