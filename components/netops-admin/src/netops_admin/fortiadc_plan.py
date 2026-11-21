"""FortiADC planning adapter of the common Admin engine (engine.ADAPTERS["fortiadc"]).

The snapshot of a FortiADC is not the whole configuration: Admin composes it from the firmware line of
``get system status`` and the listings of pools with their members, virtual servers, real servers and
administrators (see ``exec_fortiadc.snapshot``). The rest digest covers these sections outside the planned change.
"""
from __future__ import annotations

import hashlib
import re

from netops_admin import fortiadc
from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected

TABLE = "load-balance pool/pool_member"
POOLS = "load-balance pool"
MEMBERS = "pool_member"
VIRTUAL_SERVERS = "load-balance virtual-server"
REAL_SERVERS = "load-balance real-server"
ADMINS = "system admin"
SECTIONS = (POOLS, VIRTUAL_SERVERS, REAL_SERVERS, ADMINS)
CERT_GROUP, CERT_MEMBER, CERT_TABLE = fortiadc.CERT_GROUP, fortiadc.CERT_MEMBER, fortiadc.CERT_TABLE
OPTIONAL_SECTIONS = (CERT_GROUP, CERT_TABLE)
HEADER = "#netops-fortiadc-snapshot firmware="
VERSION = re.compile(r"(?m)^Version:[ \t]+FortiADC-\S+ v([0-9]+\.[0-9]+\.[0-9]+),build([0-9]{4})\b")
FIRMWARE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+ build[0-9]{4}")
PROMPTS = re.compile(r"^(?:[^\s#$]+ [#$] ?)+")
# profile attribute names are request attribute names (lowercase letters, digits and hyphens); the device spells
# the member port, weight and cookie with underscores
DEVICE_NAMES = {"pool-member-service-port": "pool_member_service_port", "pool-member-weight": "pool_member_weight",
                "pool-member-cookie": "pool_member_cookie"}
PROFILE_NAMES = {value: key for key, value in DEVICE_NAMES.items()}
QUOTED = ("real-server", "pool-member-cookie", "fqdn")
ORDER = ("real-server", "pool-member-service-port", "pool-member-cookie", "pool-member-weight",
         "type", "ip", "fqdn", "status")
SERVER_TABLES = (VIRTUAL_SERVERS, REAL_SERVERS)
INACTIVE = ("disable", "maintain")
DEFAULT_PORT = "80"
ADMIN_FIELDS = ("is-system-admin", "access-profile", "trusted-hosts", "trusted-hosts6", "vdom", "password")


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


def firmware_of(status_text: str) -> str:
    lines = status_text.replace("\r", "").split("\n")
    found = VERSION.findall("\n".join(PROMPTS.sub("", line) for line in lines))
    if len(found) != 1:
        raise Rejected(["the device does not report one FortiADC firmware version"])
    return "%s build%s" % found[0]


def listing(text: str, command: str) -> str:
    """The configuration listing of a show answer: prompts, pager marks and the lines around the block removed."""
    lines = fortiadc.PAGER.sub("", text).replace("\r", "").split("\n")
    start = None
    for index, line in enumerate(lines):
        bare = PROMPTS.sub("", line)
        if bare.startswith("config "):
            lines[index], start = bare, index
            break
    end = max((index for index, line in enumerate(lines) if line.strip() == "end"), default=-1)
    if start is None or end < start:
        raise Rejected(["the answer to %s is not a configuration listing" % command])
    return "\n".join(lines[start:end + 1])


def default_cookie(member: str) -> str:
    return "rs%s" % member


def split_key(key: str) -> tuple:
    pool, _sep, member = key.rpartition(":")
    return pool, member


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        lines = text.replace("\r", "").split("\n")
        if not lines or not lines[0].startswith(HEADER) or not FIRMWARE.fullmatch(lines[0][len(HEADER):]):
            raise SnapshotRejected(["snapshot is not a FortiADC Admin snapshot (no firmware line)"], SNAPSHOT_UNREADABLE)
        self.firmware = lines[0][len(HEADER):]
        if firmware and firmware != self.firmware:
            raise Rejected(["the FortiADC runs %s, not the configured %s" % (self.firmware, firmware)])
        self.inventory = None
        self.rows = []
        self.members = {}
        self.cert_members = {}
        self.pools = []
        self.blocks = {section: {} for section in (*SECTIONS, *OPTIONAL_SECTIONS)}
        self.sections = []
        self._parse(lines[1:])
        missing = [section for section in SECTIONS if section not in self.sections]
        if missing:
            raise SnapshotRejected(["snapshot holds no %s section; it is not a complete FortiADC Admin snapshot"
                                    % ", ".join(missing)], SNAPSHOT_INCOMPLETE)

    def _parse(self, lines) -> None:
        stack = []
        for raw in lines:
            try:
                words = fortiadc._words(raw)
            except Rejected:
                raise SnapshotRejected(["snapshot does not parse: malformed quoting"], SNAPSHOT_UNREADABLE) from None
            if not words:
                continue
            head = words[0]
            if head == "config" and len(words) > 1:
                if stack and stack[-1][0] != "edit":
                    raise SnapshotRejected(["snapshot does not parse: misplaced config"], SNAPSHOT_UNREADABLE)
                stack.append(("config", " ".join(words[1:])))
                if len(stack) == 1:
                    if stack[0][1] in self.sections:
                        raise SnapshotRejected(["snapshot repeats section %s" % stack[0][1]], SNAPSHOT_UNREADABLE)
                    self.sections.append(stack[0][1])
                self.rows.append((tuple(stack), " ".join(words)))
                continue
            if head == "edit" and len(words) == 2:
                if not stack or stack[-1][0] != "config":
                    raise SnapshotRejected(["snapshot does not parse: misplaced edit"], SNAPSHOT_UNREADABLE)
                stack.append(("edit", words[1]))
                self._entered(stack)
                self.rows.append((tuple(stack), " ".join(words)))
                continue
            if head in ("next", "end") and len(words) == 1:
                kind = "edit" if head == "next" else "config"
                if not stack or stack[-1][0] != kind:
                    raise SnapshotRejected(["snapshot does not parse: unbalanced block"], SNAPSHOT_UNREADABLE)
                self.rows.append((tuple(stack), head))
                stack.pop()
                continue
            if head in ("set", "unset") and len(words) >= 2 and stack and stack[-1][0] == "edit":
                self._attribute(stack, head, words)
                self.rows.append((tuple(stack), " ".join(words)))
                continue
            raise SnapshotRejected(["snapshot does not parse: unexpected line"], SNAPSHOT_UNREADABLE)
        if stack:
            raise SnapshotRejected(["snapshot does not parse: unbalanced block"], SNAPSHOT_UNREADABLE)

    def _entered(self, stack) -> None:
        if len(stack) == 2 and stack[0][1] in self.blocks:
            block = self.blocks[stack[0][1]]
            if stack[1][1] in block:
                raise SnapshotRejected(["snapshot lists %s %s twice" % (stack[0][1], stack[1][1])], SNAPSHOT_UNREADABLE)
            block[stack[1][1]] = {}
            if stack[0][1] == POOLS:
                self.pools.append(stack[1][1])
        if _member_path(stack):
            key = "%s:%s" % (stack[1][1], stack[3][1])
            if key in self.members:
                raise SnapshotRejected(["snapshot lists pool member %s twice" % key], SNAPSHOT_UNREADABLE)
            self.members[key] = Entry(key)

        if _cert_path(stack):
            key = "%s:%s" % (stack[1][1], stack[3][1])
            if key in self.cert_members:
                raise SnapshotRejected(["snapshot repeats a certificate group member"], SNAPSHOT_UNREADABLE)
            self.cert_members[key] = Entry(key)

    def _attribute(self, stack, head, words) -> None:
        if len(stack) == 2 and stack[0][1] in self.blocks and head == "set" and len(words) > 2:
            section, name = stack[0][1], stack[1][1]
            attributes = self.blocks[section][name]
            if section in SERVER_TABLES and words[1] in attributes:
                raise SnapshotRejected(["snapshot lists an attribute of %s %s twice" % (section, name)],
                                       SNAPSHOT_UNREADABLE)
            attributes[words[1]] = " ".join(words[2:])
        if _cert_path(stack) and words[1] == "local-cert":
            entry = self.cert_members["%s:%s" % (stack[1][1], stack[3][1])]
            if (head != "set" or len(words) != 3 or not fortiadc.CERT_NAME.fullmatch(words[2])
                    or "local-cert" in entry.attributes):
                entry.unsupported.append("unverified local-cert")
            else:
                entry.attributes["local-cert"] = words[2]
        member = _member_of(stack)
        if member is None:
            return
        entry = self.members["%s:%s" % member]
        if len(stack) != 4 or head != "set" or len(words) < 3:
            entry.unsupported.append(" ".join(words[:2]) if len(stack) == 4 else "nested %s" % stack[4][1])
            return
        name = PROFILE_NAMES.get(words[1], words[1])
        if name == "pool-member-cookie" and " ".join(words[2:]) == default_cookie(stack[3][1]):
            # the device gives a member without a cookie the cookie rsN (measured 7.6.7 build0676, task 306):
            # it is the default of member N, like a default value that show leaves out
            return
        if name in entry.attributes:
            entry.unsupported.append("repeated %s" % words[1])
            return
        entry.attributes[name] = " ".join(words[2:])

    def entries(self, table: str):
        if table == TABLE:
            return dict(self.members)
        if table == CERT_MEMBER:
            if CERT_GROUP not in self.sections:
                return None
            for entry in self.cert_members.values():
                if "local-cert" not in entry.attributes and not entry.unsupported:
                    entry.unsupported.append("missing local-cert")
            return dict(self.cert_members)
        if table not in SERVER_TABLES or table not in self.sections:
            return None
        complex_servers = {path[1][1] for path, line in self.rows if path[0] == ("config", REAL_SERVERS)
                           and (len(path) > 2 or len(path) == 2 and line.startswith("unset "))}
        entries = {}
        for name, attributes in self.blocks[table].items():
            entry = Entry(name)
            if table == VIRTUAL_SERVERS:
                # Only status is writable. The other fields stay in the rest digest.
                entry.attributes = {field: attributes[field] for field in ("status",) if field in attributes}
            else:
                entry.attributes = attributes
                if name in complex_servers:
                    entry.unsupported.append("non-scalar real-server configuration")
            if attributes.get("status", fortiadc.DEFAULT_STATUS) not in fortiadc.STATUSES:
                entry.unsupported.append("unknown status")
            entries[name] = entry
        return entries

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table == REAL_SERVERS:
            return sorted(name for name, entry in self.members.items()
                          if entry.attributes.get("real-server", "").casefold() == key.casefold())
        return []

    def in_use(self, key: str) -> bool:
        return False

    def pool_members(self, pool: str) -> dict:
        return {key.rpartition(":")[2]: entry for key, entry in self.members.items() if key.rpartition(":")[0] == pool}

    def admins(self) -> dict:
        return dict(self.blocks[ADMINS])

    def virtual_servers(self) -> dict:
        return dict(self.blocks[VIRTUAL_SERVERS])

    def real_servers(self) -> dict:
        return dict(self.blocks[REAL_SERVERS])

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        if table == TABLE:
            pool, member = split_key(key)
            target = (("config", POOLS), ("edit", pool), ("config", MEMBERS), ("edit", member))
        else:
            target = (("config", table), ("edit", key))
        if table == CERT_MEMBER:
            group, member = split_key(key)
            target = (("config", CERT_GROUP), ("edit", group), ("config", "group_member"), ("edit", member))
        if table in (VIRTUAL_SERVERS, CERT_MEMBER):
            field = "status" if table == VIRTUAL_SERVERS else "local-cert"
            kept = ["%d %s" % (len(path), line) for path, line in self.rows
                    if path != target or not (line.startswith("set " + field + " ") or line == "unset " + field)]
        else:
            kept = ["%d %s" % (len(path), line) for path, line in self.rows if path[:len(target)] != target]
        return hashlib.sha256(("%s\n" % self.firmware + "\n".join(kept)).encode("utf-8")).hexdigest()


def _member_path(stack) -> bool:
    return (len(stack) == 4 and stack[0] == ("config", POOLS) and stack[1][0] == "edit"
            and stack[2] == ("config", MEMBERS) and stack[3][0] == "edit")


def _member_of(stack):
    if len(stack) >= 4 and _member_path(stack[:4]):
        return stack[1][1], stack[3][1]
    return None


def _cert_path(stack) -> bool:
    return (len(stack) == 4 and stack[0] == ("config", CERT_GROUP) and stack[1][0] == "edit"
            and stack[2] == ("config", "group_member") and stack[3][0] == "edit")


def parse_listing(text: str) -> Snapshot:
    """One section listing (for example the pool listing the check account reads), parsed like a snapshot."""
    parsed = Snapshot.__new__(Snapshot)
    parsed.firmware, parsed.inventory = None, None
    parsed.rows, parsed.members, parsed.pools, parsed.sections = [], {}, [], []
    parsed.cert_members = {}
    parsed.blocks = {section: {} for section in (*SECTIONS, *OPTIONAL_SECTIONS)}
    parsed._parse(text.replace("\r", "").split("\n"))
    return parsed


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def absent(snapshot, table: str, key: str) -> list:
    if table == CERT_MEMBER:
        return ["the certificate group or member is absent"]
    if table in SERVER_TABLES:
        return ["%s %s is not configured" % (table.removeprefix("load-balance "), key)]
    pool, member = split_key(key)
    if pool not in snapshot.pools:
        return ["pool %s is not configured" % pool]
    return ["pool %s has no member %s" % (pool, member)]


def _prefix(key: str) -> list:
    pool, member = split_key(key)
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "edit %s" % member]


def _set(name: str, value: str) -> str:
    return ("set %s \"%s\"" if name in QUOTED else "set %s %s") % (DEVICE_NAMES.get(name, name), value)


def _ordered(names) -> list:
    return sorted(names, key=lambda name: (ORDER.index(name) if name in ORDER else len(ORDER), name))


def render_create(profile, key: str, attributes: dict) -> list:
    sets = [_set(name, attributes[name]) for name in _ordered(attributes) if attributes[name] is not None]
    if profile.table == REAL_SERVERS:
        return ["config " + REAL_SERVERS, 'edit "%s"' % key] + sets + ["next", "end"]
    return _prefix(key) + sets + ["next", "end", "next", "end"]


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    if profile.table == CERT_MEMBER:
        group, member = split_key(key)
        return ["config " + CERT_GROUP, 'edit "%s"' % group, "config group_member", "edit " + member,
                'set local-cert "%s"' % assign["local-cert"], "next", "end", "next", "end"]
    lines = [_set(name, assign[name]) for name in _ordered(assign)]
    for name in _ordered(remove):
        attribute = profile.attributes.get(name)
        default = None if attribute is None else attribute.default
        if name == "pool-member-cookie":
            default = default_cookie(split_key(key)[1])
        lines.append(_set(name, default) if default is not None else "unset %s" % DEVICE_NAMES.get(name, name))
    if profile.table in SERVER_TABLES:
        return ["config " + profile.table, 'edit "%s"' % key] + lines + ["next", "end"]
    return _prefix(key) + lines + ["next", "end", "next", "end"]


def render_delete(profile, key: str) -> list:
    if profile.table == REAL_SERVERS:
        return ["config " + REAL_SERVERS, 'delete "%s"' % key, "end"]
    pool, member = split_key(key)
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "delete %s" % member,
            "end", "next", "end"]


def _port(state) -> str:
    return (state or {}).get("pool-member-service-port", DEFAULT_PORT)


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table == CERT_MEMBER:
        before = snapshot.cert_members[key].attributes["local-cert"]
        certificates = snapshot.blocks[CERT_TABLE]
        if before not in certificates or after["local-cert"] not in certificates:
            raise Rejected(["both the current and replacement certificates must be installed"],
                           reason_codes=["fortiadc_certificate_missing"])
        return []
    if profile.table == VIRTUAL_SERVERS:
        return []
    if profile.table == REAL_SERVERS:
        if after is None:
            members = snapshot.references(REAL_SERVERS, key)
            if members:
                return ["real server %s is referenced by pool members %s" % (key, ", ".join(members))]
            return []
        address_type = after.get("type", "ip")
        if address_type == "ip" and after.get("ip") not in (None, "0.0.0.0") and "fqdn" not in after:
            return []
        if address_type == "fqdn" and after.get("fqdn") and "ip" not in after:
            return []
        return ["a static real server needs an IPv4 address with type ip, or a hostname with type fqdn"]
    pool, member = split_key(key)
    reasons = []
    if pool not in snapshot.pools:
        return ["pool %s is not configured" % pool]
    members = snapshot.pool_members(pool)
    if op == "create":
        if (after or {}).get("status") not in INACTIVE:
            reasons.append("a new pool member is created with status disable (or maintain); enable it with a"
                           " separate update after its health check is up")
        real_server = (after or {}).get("real-server")
        if real_server not in snapshot.real_servers():
            reasons.append("the real server %s is not configured on the device" % real_server)
        if any(entry.attributes.get("real-server") == real_server and _port(entry.attributes) == _port(after)
               for entry in members.values()):
            reasons.append("the real server %s with port %s is already a member of pool %s"
                           % (real_server, _port(after), pool))
    elif op == "delete":
        entry = members.get(member)
        status = None if entry is None else entry.attributes.get("status", "enable")
        if status not in INACTIVE:
            reasons.append("only a pool member with status disable or maintain is removed; disable it first")
        if len(members) <= 1:
            reasons.append("the last member of a pool is never removed")
    elif op == "update":
        before = members.get(member)
        if before is not None and _port(before.attributes) != _port(after):
            real_server = after.get("real-server")
            if any(number != member and entry.attributes.get("real-server") == real_server
                   and _port(entry.attributes) == _port(after) for number, entry in members.items()):
                reasons.append("the real server %s with port %s is already a member of pool %s"
                               % (real_server, _port(after), pool))
    if (after or {}).get("pool-member-cookie") == default_cookie(member):
        reasons.append("the cookie %s is the one the device gives member %s by default; omit it on create or clear it"
                       % (default_cookie(member), member))
    return reasons
