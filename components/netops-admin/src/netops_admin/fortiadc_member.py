from __future__ import annotations

import re

from netops_admin import fortiadc
from netops_admin.errors import Rejected

PORT = re.compile(r"[1-9][0-9]{0,4}")
REAL_SERVER_COMMAND = "show load-balance real-server"
WEIGHT = re.compile(r"[1-9][0-9]{0,2}")
RESTORABLE = (("real-server", '"%s"', fortiadc.POOL), ("status", "%s", re.compile(r"disable|maintain")),
              ("pool_member_service_port", "%s", PORT), ("pool_member_cookie", '"%s"', fortiadc.POOL),
              ("pool_member_weight", "%s", WEIGHT))


def render_add(pool: str, member: str, real_server: str, port: str) -> list:
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "edit %s" % member,
            'set real-server "%s"' % real_server, "set pool_member_service_port %s" % port,
            "set status disable", "next", "end", "next", "end"]


def render_remove(pool: str, member: str) -> list:
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "delete %s" % member,
            "end", "next", "end"]


def render_create(pool: str, member: str, entry: dict) -> list:
    sets = [("set %s " + form) % (key, entry[key]) for key, form, _ in RESTORABLE if key in entry]
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "edit %s" % member] + sets \
        + ["next", "end", "next", "end"]


def _unrestorable(entry: dict) -> list:
    known = {key: pattern for key, _, pattern in RESTORABLE}
    return sorted(key for key, value in entry.items() if key not in known or known[key].fullmatch(value) is None)


def parse_members(text: str, pool: str) -> dict:
    stack, members, current = [], {}, None
    pool_seen = False
    for raw in text.replace("\r", "").splitlines():
        words = fortiadc._words(raw)
        if not words:
            continue
        head = words[0]
        if head == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif head == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if len(stack) == 2 and stack[0] == ("config", "load-balance pool") and words[1] == pool:
                pool_seen = True
            if len(stack) == 4 and stack[:3] == [("config", "load-balance pool"), ("edit", pool),
                                                  ("config", "pool_member")]:
                if words[1] in members:
                    raise fortiadc._unreadable("duplicate entry")
                current = members[words[1]] = {}
        elif head in ("next", "end") and len(words) == 1:
            kind = "edit" if head == "next" else "config"
            if not stack or stack[-1][0] != kind:
                raise fortiadc._unreadable("unbalanced block")
            stack.pop()
        elif head == "set" and len(words) > 2 and stack and stack[-1][0] == "edit":
            if len(stack) == 4 and stack[1] == ("edit", pool) and stack[2] == ("config", "pool_member"):
                if words[1] in current:
                    raise fortiadc._unreadable("duplicate attribute")
                current[words[1]] = " ".join(words[2:])
        else:
            raise fortiadc._unreadable("unexpected line")
    if stack:
        raise fortiadc._unreadable("unbalanced block")
    if not pool_seen:
        raise Rejected(["the pool is not listed by the device"])
    return members


def _members(access, pool: str) -> dict:
    return parse_members(fortiadc._listing(access, pool), pool)


def _members_back(access, pool: str):
    try:
        return _members(access, pool)
    except Rejected:
        return None


def _real_server_exists(access, real_server: str) -> bool:
    try:
        text = access.query(REAL_SERVER_COMMAND)
    except Exception:
        raise Rejected(["the real servers cannot be read"]) from None
    return real_server in fortiadc._blocks(text, "load-balance real-server")


def _users(access, pool: str) -> list:
    try:
        servers = fortiadc._blocks(access.query(fortiadc.VS_COMMAND), "load-balance virtual-server")
    except Rejected:
        raise
    except Exception:
        raise Rejected(["the virtual servers cannot be read"]) from None
    return sorted(name for name, attributes in servers.items() if attributes.get("load-balance-pool") == pool)


def _write(access, spec, steps: list):
    try:
        access.apply(steps, spec)
    except Exception as exc:
        return "write failed (%s)" % type(exc).__name__
    return None


def _check(pool, member, real_server=None, port=None):
    if not isinstance(pool, str) or fortiadc.POOL.fullmatch(pool) is None:
        raise Rejected(["the pool name is not valid"])
    if not isinstance(member, str) or fortiadc.MEMBER.fullmatch(member) is None:
        raise Rejected(["the member must be a pool member number"])
    if real_server is not None and (not isinstance(real_server, str)
                                    or fortiadc.POOL.fullmatch(real_server) is None):
        raise Rejected(["the real server name is not valid"])
    if port is not None and (not isinstance(port, str) or PORT.fullmatch(port) is None or int(port) > 65535):
        raise Rejected(["the service port must be a number from 1 to 65535"])


def _matches(entry: dict, real_server: str, port: str) -> bool:
    return entry.get("real-server") == real_server and entry.get("pool_member_service_port") == port \
        and entry.get("status") == "disable"


def add(access, pool: str, member: str, real_server: str, port: str) -> dict:
    _check(pool, member, real_server, port)
    spec = fortiadc.prompt_spec(fortiadc._hostname(access))
    before = _members(access, pool)
    if member in before:
        raise Rejected(["the member number is already used in the pool"])
    if any(entry.get("real-server") == real_server and entry.get("pool_member_service_port") == port
           for entry in before.values()):
        raise Rejected(["the real server with this port is already a member of the pool"])
    if not _real_server_exists(access, real_server):
        raise Rejected(["the real server is not configured on the device"])
    steps = render_add(pool, member, real_server, port)
    record = {"operation": "pool-member-add", "pool": pool, "member": member, "real_server": real_server,
              "service_port": port, "requested": "disable",
              "preview": {"commands": steps, "existing_members": sorted(before, key=int),
                          "virtual_servers": _users(access, pool),
                          "inverse": render_remove(pool, member)}}
    failure = _write(access, spec, steps)
    after = _members_back(access, pool)
    others = None if after is None else {key: value for key, value in after.items() if key != member}
    if failure is None and after is not None and member in after and others == before \
            and _matches(after[member], real_server, port):
        return dict(record, result="confirmed", after="disable")
    record["reason"] = failure or ("read-back differs" if after is not None else "read-back unreadable")
    if after is None or member in after:
        _write(access, spec, render_remove(pool, member))
        after = _members_back(access, pool)
    restored = after == before
    return dict(record, result="rolled_back" if restored else "unknown", after=None if restored else "unverified")


def remove(access, pool: str, member: str) -> dict:
    _check(pool, member)
    spec = fortiadc.prompt_spec(fortiadc._hostname(access))
    before = _members(access, pool)
    if member not in before:
        raise Rejected(["the member is not in the pool"])
    if before[member].get("status") not in ("disable", "maintain"):
        raise Rejected(["only a disabled or maintained member can be removed"])
    if len(before) == 1:
        raise Rejected(["the last member of a pool is never removed"])
    unrestorable = _unrestorable(before[member])
    if unrestorable or "real-server" not in before[member]:
        raise Rejected(["the member has settings that cannot be restored: %s" % (", ".join(unrestorable)
                                                                                 or "no real-server")])
    steps = render_remove(pool, member)
    inverse = render_create(pool, member, before[member])
    record = {"operation": "pool-member-remove", "pool": pool, "member": member,
              "preview": {"commands": steps, "existing_members": sorted(before, key=int),
                          "virtual_servers": _users(access, pool), "member_before": dict(before[member]),
                          "inverse": inverse}}
    failure = _write(access, spec, steps)
    after = _members_back(access, pool)
    expected = {key: value for key, value in before.items() if key != member}
    if failure is None and after == expected:
        return dict(record, result="confirmed", after="absent")
    record["reason"] = failure or ("read-back differs" if after is not None else "read-back unreadable")
    if after is None or member not in after:
        restore = _write(access, spec, inverse)
        record["restore"] = {"attempted": True, "write": restore or "ok"}
        after = _members_back(access, pool)
    else:
        record["restore"] = {"attempted": False}
    return dict(record, result="rolled_back" if after == before else "unknown",
                after="present" if after == before else "unverified")
