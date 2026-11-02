from __future__ import annotations

import re

from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

STATUSES = ("enable", "disable", "maintain")
DEFAULT_STATUS = "enable"
POOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
MEMBER = re.compile(r"[1-9][0-9]{0,8}")
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOSTNAME_LINE = re.compile(r"(?m)^Hostname:[ \t]+(\S+)[ \t]*$")
PAGER = re.compile(r"--More-- \r {1,256}\r")
TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"(?=[ \t]|$)|([^\s"\\]+)(?=[ \t]|$)')
EXIT = {"confirmed": 0, "unchanged": 0, "rolled_back": 4, "unknown": 7}
REFUSALS = (
    (re.compile(r"command fail", re.IGNORECASE), "command failed"),
    (re.compile(r"command parse error", re.IGNORECASE), "command parse error"),
    (re.compile(r"unknown action", re.IGNORECASE), "unknown action"),
    (re.compile(r"value parse error", re.IGNORECASE), "value parse error"),
)


def cli_error(text: str):
    for pattern, label in REFUSALS:
        if pattern.search(text):
            return label
    return None


def prompt_spec(hostname: str) -> PromptSpec:
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"# ",), continuation=None, error=cli_error)


def exit_code(record: dict) -> int:
    return EXIT[record["result"]]


def show_command(pool: str) -> str:
    return "show load-balance pool %s" % pool


def render(pool: str, member: str, status: str) -> list:
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "edit %s" % member,
            "set status %s" % status, "next", "end", "next", "end"]


def _unreadable(why: str) -> Rejected:
    return Rejected(["the pool listing cannot be read (%s)" % why])


def _lines(text: str) -> list:
    return PAGER.sub("", text).replace("\r", "").splitlines()


def _words(raw: str) -> list:
    words, at = [], 0
    while True:
        while at < len(raw) and raw[at] in " \t":
            at += 1
        if at == len(raw):
            return words
        match = TOKEN.match(raw, at)
        if match is None:
            raise _unreadable("malformed quoting")
        words.append(match.group(2) if match.group(1) is None else match.group(1))
        at = match.end()


def parse_status(text: str, pool: str, member: str) -> str:
    target = (("config", "load-balance pool"), ("edit", pool), ("config", "pool_member"), ("edit", member))
    stack, seen, status = [], set(), None
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        head = words[0]
        if head == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif head == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if tuple(stack) in seen:
                raise _unreadable("duplicate entry")
            seen.add(tuple(stack))
        elif head in ("next", "end") and len(words) == 1:
            kind = "edit" if head == "next" else "config"
            if not stack or stack[-1][0] != kind:
                raise _unreadable("unbalanced block")
            stack.pop()
        elif head == "set" and len(words) > 2 and stack and stack[-1][0] == "edit":
            if tuple(stack) == target and words[1] == "status":
                if status is not None:
                    raise _unreadable("duplicate status")
                status = " ".join(words[2:])
        else:
            raise _unreadable("unexpected line")
    if stack:
        raise _unreadable("unbalanced block")
    if target not in seen:
        raise Rejected(["the pool or the member is not listed by the device"])
    status = DEFAULT_STATUS if status is None else status
    if status not in STATUSES:
        raise _unreadable("unknown status")
    return status


HEALTH_STATES = ("UP", "DOWN")
VS_COMMAND = "show load-balance virtual-server"
HEALTH_REFUSALS = re.compile(r"parsing error|command fail|permission|not authorized|unknown action|invalid", re.IGNORECASE)
AVAILABILITY = re.compile(r"\bavailability:[ \t]*([A-Za-z]+)")
MEMBER_ID = re.compile(r"\bid:[ \t]*([0-9]+)\b")
HC_STATE = re.compile(r"\bhc_state:[ \t]*([A-Za-z]+)")


def vs_stat_command(vs: str) -> str:
    return "diagnose server-load-balance vs_stat vdom root vs %s" % vs


def _health_unreadable(why: str) -> Rejected:
    return Rejected(["the health of the pool members cannot be read (%s); the change is refused" % why])


def parse_vs_stat(text: str) -> dict:
    if HEALTH_REFUSALS.search(text):
        raise _health_unreadable("vs_stat was refused")
    lines = text.replace("\r", "").splitlines()
    if len([1 for line in lines if AVAILABILITY.search(line)]) != 1:
        raise _health_unreadable("vs_stat output is not recognised")
    states, current = {}, None
    for line in lines:
        found = MEMBER_ID.search(line)
        if found:
            current = int(found.group(1))
        state = HC_STATE.search(line)
        if state is None:
            continue
        if current is None or current in states or state.group(1).upper() not in HEALTH_STATES:
            raise _health_unreadable("vs_stat member list is not recognised")
        states[current] = state.group(1).upper()
    if not states:
        raise _health_unreadable("vs_stat lists no members")
    return states


def read_health(access, vs: str) -> dict:
    try:
        text = access.diagnose_query(vs_stat_command(vs))
    except Exception:
        raise _health_unreadable("vs_stat query failed") from None
    return {number: state == "UP" for number, state in parse_vs_stat(text).items()}


def _blocks(text: str, section: str) -> dict:
    stack, blocks, current = [], {}, None
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        head = words[0]
        if head == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif head == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if tuple(stack) == (("config", section), ("edit", words[1])):
                if words[1] in blocks:
                    raise _unreadable("duplicate entry")
                current = blocks[words[1]] = {}
        elif head in ("next", "end") and len(words) == 1:
            kind = "edit" if head == "next" else "config"
            if not stack or stack[-1][0] != kind:
                raise _unreadable("unbalanced block")
            stack.pop()
        elif head == "set" and len(words) > 2 and stack and stack[-1][0] == "edit":
            if len(stack) == 2 and stack[0] == ("config", section):
                current[words[1]] = " ".join(words[2:])
        else:
            raise _unreadable("unexpected line")
    if stack:
        raise _unreadable("unbalanced block")
    return blocks


def _member_numbers(text: str, pool: str) -> list:
    numbers, stack = [], []
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        if words[0] == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif words[0] == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if len(stack) == 4 and stack[2] == ("config", "pool_member"):
                numbers.append(words[1])
        elif words[0] in ("next", "end") and stack:
            stack.pop()
    return numbers


def prechecks(access, pool: str, member: str, status: str, listing: str) -> None:
    try:
        servers = _blocks(access.query(VS_COMMAND), "load-balance virtual-server")
    except Rejected:
        raise
    except Exception:
        raise Rejected(["the virtual servers cannot be read"]) from None
    users = []
    for name, attributes in servers.items():
        if attributes.get("content-routing", "disable") != "disable" or attributes.get("schedule-pool-list"):
            raise Rejected(["the virtual server %s selects pools by content routing or schedule; "
                            "the pool use cannot be evaluated" % name])
        if attributes.get("load-balance-pool") == pool:
            users.append(name)
    if not users:
        raise Rejected(["no virtual server uses the pool; the effect of the change cannot be evaluated"])
    numbers = _member_numbers(listing, pool)
    statuses = {number: parse_status(listing, pool, number) for number in numbers}
    statuses[member] = status
    for vs in users:
        health = read_health(access, vs)
        if not any(state == "enable" and health.get(int(number), False) for number, state in statuses.items()):
            raise Rejected(["the change would leave virtual server %s without a healthy enabled member" % vs])


def _hostname(access) -> str:
    try:
        found = HOSTNAME_LINE.findall(access.query("get system status").replace("\r", ""))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None
    if len(found) != 1 or HOSTNAME.fullmatch(found[0]) is None:
        raise Rejected(["the device hostname cannot be established"])
    return found[0]


def _listing(access, pool: str) -> str:
    try:
        return access.query(show_command(pool))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None


def _read(access, pool: str, member: str) -> str:
    return parse_status(_listing(access, pool), pool, member)


def _readback(access, pool: str, member: str):
    try:
        return _read(access, pool, member)
    except Rejected:
        return None


def _write(access, spec, pool: str, member: str, status: str):
    try:
        access.apply(render(pool, member, status), spec)
    except Exception as exc:
        return "write failed (%s)" % type(exc).__name__
    return None


def run(access, pool: str, member: str, status: str) -> dict:
    if not isinstance(pool, str) or POOL.fullmatch(pool) is None:
        raise Rejected(["the pool name is not valid"])
    if not isinstance(member, str) or MEMBER.fullmatch(member) is None:
        raise Rejected(["the member must be a pool member number"])
    if status not in STATUSES:
        raise Rejected(["the status must be one of: %s" % ", ".join(STATUSES)])
    spec = prompt_spec(_hostname(access))
    listing = _listing(access, pool)
    before = parse_status(listing, pool, member)
    record = {"pool": pool, "member": member, "requested": status, "before": before}
    if before == status:
        return dict(record, result="unchanged", after=before)
    prechecks(access, pool, member, status, listing)
    failure = _write(access, spec, pool, member, status)
    after = _readback(access, pool, member)
    if failure is None and after == status:
        return dict(record, result="confirmed", after=after)
    record["reason"] = failure or ("read-back differs" if after is not None else "read-back unreadable")
    if after != before:
        _write(access, spec, pool, member, before)
        after = _readback(access, pool, member)
    return dict(record, result="rolled_back" if after == before else "unknown", after=after)
