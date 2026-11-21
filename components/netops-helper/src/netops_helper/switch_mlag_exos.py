"""Structured summaries of the ExtremeXOS ``show mlag peer`` and ``show mlag ports`` captures.

Each summary is derived only from the text of its own query: no I/O, no device metadata,
no other query and no correlation between the two views.  Values are reported as the
device printed them; nothing here is a health, consistency, traffic or pairing verdict.
``state`` says how much of the modelled output was read:

* ``measured`` - every modelled field of this one capture was read (an explicit
  ``Number of Multi-switch Link Aggregation Groups : 0`` with an empty table is a read
  empty member list); this is parsed data, not health;
* ``partial``  - something was read but a field, a peer/member, the table, the count or the
  capture itself is missing, unknown, ambiguous, malformed or contradicted;
* ``unparsed`` - nothing of the modelled output was read (blank, prompt, refusal, unknown).

The peer header alone is not an explicit count of zero peers: it is ``partial`` with
``peer_details`` missing.  Member rows are read only between the two separator lines;
header, legend and footer lines are never members and the member count is never derived
from the number of rows.
"""
from __future__ import annotations

import re
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_PROMPT_PREFIX = r"(?:\*[ \t]*)?[A-Za-z0-9][A-Za-z0-9_.:/()-]*[ \t]*[#>][ \t]*"
_PROMPT = re.compile(rf"^[ \t]*{_PROMPT_PREFIX}$")
_ECHO = {
    "peer": re.compile(rf"^[ \t]*(?:{_PROMPT_PREFIX})?show[ \t]+mlag[ \t]+peers?[ \t]*$", re.I),
    "ports": re.compile(rf"^[ \t]*(?:{_PROMPT_PREFIX})?show[ \t]+mlag[ \t]+ports?[ \t]*$", re.I),
}
_INTEGER = re.compile(r"[0-9]{1,10}")
# Not a reported value: nothing was verified.
_UNKNOWN = frozenset({"unknown", "n/a", "na", "none", "null", "-", "?"})
_PLACEHOLDER_ADDRESSES = frozenset({"0.0.0.0", "::", "0:0:0:0:0:0:0:0"})

# --- show mlag peer -------------------------------------------------------------------------
_PEER_HEADER = re.compile(r"^[ \t]*Multi-switch Link Aggregation Peers[ \t]*:[ \t]*$", re.I)
# A second "label : value" pair on a line starts after a run of at least two blanks.
# A label has single blanks only, so a value followed by a wide gap is never taken for a label.
# Only the whole blank run is tried (lookbehind, possessive): a later start in the same run ends at the same label,
# so the splits are unchanged and split() no longer retries every suffix of a long run (quadratic).
_PAIR_SPLIT = re.compile(r"(?<![ \t])[ \t]{2,}+(?=[A-Za-z](?:[A-Za-z0-9.()/_-]|[ \t](?![ \t]))*?[ \t]*:(?:[ \t]|$))")
# Label: text before the first ":" without edge blanks, single or repeated spaces inside; value: the rest without
# edge blanks.  Possessive and non-overlapping (no lazy class over blanks before [ \t]*), so linear time.
_PAIR = re.compile(r"^[ \t]*+([A-Za-z](?: *+[A-Za-z0-9.()/_-])*+)[ \t]*+:[ \t]*+((?:[ \t]*+[^ \t\n])*+)[ \t]*+$")
_PEER_START = "mlag peer"
_PEER_LABELS = {
    "vlan": "vlan",
    "virtual router": "virtual_router",
    "local ip address": "local_address",
    "peer ip address": "peer_address",
    "mlag ports": "configured_groups",
    "checkpoint status": "checkpoint_status",
}
_PEER_FIELDS = ("name", "vlan", "virtual_router", "local_address", "peer_address", "configured_groups",
                "checkpoint_status")

# --- show mlag ports ------------------------------------------------------------------------
_SEPARATOR = re.compile(r"^[ \t]*={10,}[ \t]*$")
_COUNT = re.compile(r"^[ \t]*Number of Multi-switch Link Aggregation Groups[ \t]*:[ \t]*(.*?)[ \t]*$", re.I)
_TABLE_HEADER = re.compile(r"^[ \t]*(?:MLAG[ \t]+Local[ \t]+Link[ \t]+Remote\b|Id[ \t]+Port[ \t]+State[ \t]+Link\b)")
_LEGEND = re.compile(r"^[ \t]*(?:Local Link State|Remote Link|Number of Multi-switch Link Aggregation Groups)"
                     r"[ \t]*:", re.I)
_MEMBER_FIELDS = ("id", "local_port", "local_link_state", "remote_link", "peer_name", "peer_status",
                  "local_fail_count", "remote_fail_count")
_LOCAL_STATES = frozenset({"A", "D", "R", "NP"})
_REMOTE_LINKS = frozenset({"Up", "Down", "N/A", "Virtual"})


def _lines(text: Any, kind: str) -> list[str]:
    """CRLF/ANSI framing removed; this query's command echo and bare prompt lines dropped."""
    if not isinstance(text, str):
        return []
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return [line for line in text.split("\n")
            if not _ECHO[kind].match(line) and not _PROMPT.match(line)]


def _reported(value: str | None) -> str | None:
    """The printed value, or None when empty, unknown or a redaction marker."""
    if not value or value.lower() in _UNKNOWN or "redacted" in value.lower():
        return None
    return value


def _count(value: str | None) -> int | None:
    """A non-negative integer as printed, else None (malformed, unknown, redacted)."""
    return int(value) if value is not None and _INTEGER.fullmatch(value) else None


def _pairs(line: str) -> list[tuple[str, str]]:
    """The "label : value" items of one line, each value bounded by the next label."""
    found = []
    for segment in _PAIR_SPLIT.split(line):
        pair = _PAIR.match(segment)
        if pair is not None:
            found.append((" ".join(pair.group(1).lower().split()), pair.group(2)))
    return found


def _finish(result: dict[str, Any], missing: list[str], read_any: bool, capture_state: str | None) -> dict[str, Any]:
    if not read_any:
        result["state"] = "unparsed"
    elif not missing:
        result["state"] = "measured"
    else:
        result["state"] = "partial"
    if capture_state != "ok":
        if result["state"] == "measured":
            result["state"] = "partial"
        missing.append("capture")
    result["missing_fields"] = missing
    return result


def summarize_peer(text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    """``show mlag peer``: one entry per ``MLAG Peer`` block, required labels read exactly."""
    header = orphan = alternate = False
    blocks: list[tuple[dict[str, str], dict[str, int]]] = []
    for line in _lines(text, "peer"):
        if _PEER_HEADER.match(line):
            header = True
            continue
        if line.strip().casefold() == "alternate path information:":
            alternate = True
            continue
        for label, value in _pairs(line):
            if label == _PEER_START:
                blocks.append(({"name": value}, {"name": 1}))
                alternate = False
                continue
            if alternate:
                continue  # the keepalive path repeats the primary checkpoint's VLAN and IP labels
            key = _PEER_LABELS.get(label)
            if key is None:
                continue  # other management fields are not modelled and do not spoil the capture
            if not blocks:
                orphan = True  # a modelled field outside any MLAG Peer block is never attributed
                continue
            raw, seen = blocks[-1]
            seen[key] = seen.get(key, 0) + 1
            raw[key] = value

    peers: list[dict[str, Any]] = []
    missing: list[str] = []
    for index, (raw, seen) in enumerate(blocks):
        peer: dict[str, Any] = {}
        for key in _PEER_FIELDS:
            item = _reported(raw.get(key)) if seen.get(key) == 1 else None  # a duplicated label is ambiguous
            if key in ("local_address", "peer_address") and item is not None and item.lower() in _PLACEHOLDER_ADDRESSES:
                item = None  # placeholder, not a verified address
            if key == "configured_groups":
                item = _count(item)
            peer[key] = item
        peer["missing_fields"] = [key for key in _PEER_FIELDS if peer[key] is None]
        missing.extend(f"peers[{index}].{key}" for key in peer["missing_fields"])
        peers.append(peer)
    if not peers:
        missing.insert(0, "peer_details")  # a header alone is not an explicit zero
    return _finish({"state": "partial", "peers": peers}, missing, header or orphan or bool(peers), capture_state)


def _member(tokens: list[str]) -> dict[str, Any]:
    member: dict[str, Any] = {
        "id": _count(tokens[0]),
        "local_port": _reported(tokens[1]),
        "local_link_state": tokens[2] if tokens[2] in _LOCAL_STATES else None,
        "remote_link": tokens[3] if tokens[3] in _REMOTE_LINKS else None,  # N/A: remote state not verified
        "peer_name": _reported(tokens[4]),
        "peer_status": _reported(tokens[5]),
        "local_fail_count": _count(tokens[6]),
        "remote_fail_count": _count(tokens[7]),
    }
    return member


def summarize_ports(text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    """``show mlag ports``: members only between the two separator lines; explicit footer count."""
    separators = 0
    header = in_rows = False
    rows: list[str] = []
    counts: list[str] = []
    for line in _lines(text, "ports"):
        if _SEPARATOR.match(line):
            separators += 1
            in_rows = separators == 1
            continue
        count = _COUNT.match(line)
        if count is not None:
            counts.append(count.group(1))
            in_rows = False
            continue
        if separators == 0:
            header = header or _TABLE_HEADER.match(line) is not None
        elif in_rows and _LEGEND.match(line):
            in_rows = False  # a cut table without its closing separator ends at the legend
        elif in_rows and line.strip():
            rows.append(line)
    table = separators >= 2
    configured = _count(counts[0]) if len(counts) == 1 else None  # a duplicated count is ambiguous

    members: list[dict[str, Any]] = []
    ragged = 0
    for row in rows:
        tokens = row.split()
        if len(tokens) != len(_MEMBER_FIELDS):
            ragged += 1  # wrapped, quoted or damaged row: never guessed
            continue
        members.append(_member(tokens))
    ids = [member["id"] for member in members if member["id"] is not None]
    duplicated = {value for value in ids if ids.count(value) > 1}
    for member in members:
        if member["id"] in duplicated:
            member["id"] = None  # an ambiguous member id, the rest of the row is kept
        member["missing_fields"] = [key for key in _MEMBER_FIELDS if member[key] is None]

    missing: list[str] = []
    if not table:
        missing.append("table")
    if configured is None:
        missing.append("configured_groups")
    if not table or ragged or duplicated or configured is None or configured != len(rows):
        missing.append("members")  # the member list is not proven complete
    for index, member in enumerate(members):
        missing.extend(f"members[{index}].{key}" for key in member["missing_fields"])
    read_any = header or separators > 0 or bool(counts)
    return _finish({"state": "partial", "configured_groups": configured, "members": members},
                   missing, read_any, capture_state)


def payload(platform: str, query: str, text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    """The additive ssh_read key; only for extreme_exos/mlag_peer and extreme_exos/mlag_ports."""
    if platform == "extreme_exos" and query == "mlag_peer":
        return {"mlag": summarize_peer(text, capture_state)}
    if platform == "extreme_exos" and query == "mlag_ports":
        return {"mlag": summarize_ports(text, capture_state)}
    return {}
