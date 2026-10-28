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
    for raw in text.replace("\r", "").splitlines():
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


def _hostname(access) -> str:
    try:
        found = HOSTNAME_LINE.findall(access.query("get system status").replace("\r", ""))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None
    if len(found) != 1 or HOSTNAME.fullmatch(found[0]) is None:
        raise Rejected(["the device hostname cannot be established"])
    return found[0]


def _read(access, pool: str, member: str) -> str:
    try:
        text = access.query(show_command(pool))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None
    return parse_status(text, pool, member)


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
    before = _read(access, pool, member)
    record = {"pool": pool, "member": member, "requested": status, "before": before}
    if before == status:
        return dict(record, result="unchanged", after=before)
    failure = _write(access, spec, pool, member, status)
    after = _readback(access, pool, member)
    if failure is None and after == status:
        return dict(record, result="confirmed", after=after)
    record["reason"] = failure or ("read-back differs" if after is not None else "read-back unreadable")
    if after != before:
        _write(access, spec, pool, member, before)
        after = _readback(access, pool, member)
    return dict(record, result="rolled_back" if after == before else "unknown", after=after)
