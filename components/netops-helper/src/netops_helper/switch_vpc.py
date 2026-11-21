"""Structured summary of one NX-OS ``show vpc brief`` capture.

The summary is derived only from the text it is given: no I/O, no other query.
It keeps the reported status text and never infers traffic or health from the
role, keep-alive or link state.  ``state`` says how much of the documented
format was recognized, not whether the vPC domain is healthy:

* ``measured`` - every modelled field and both tables were recognized, or a
  table was explicitly absent (``peer link not configured`` / ``0`` vPCs);
* ``partial`` - something was recognized but a field, a table row or the
  capture itself is missing, malformed or unknown;
* ``unparsed`` - nothing of the documented format was recognized.
"""
from __future__ import annotations

import re
from typing import Any

# Header metadata, matched on the exact label only (no substring matching).
_LABELS = {
    "vpc domain id": "domain_id",
    "peer status": "peer_status",
    "vpc keep-alive status": "keepalive_status",
    "vpc role": "role",
    "configuration consistency status": "consistency_status",
    "configuration inconsistency reason": "consistency_reason",
    "number of vpcs configured": "configured_vpcs",
}
_INTEGER_FIELDS = frozenset({"domain_id", "configured_vpcs"})
_FIELD_ORDER = ("domain_id", "peer_status", "keepalive_status", "role",
                "consistency_status", "consistency_reason", "configured_vpcs")

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Label: text before the first ":" without edge blanks, spaces only inside; value: the rest without edge blanks.
# Possessive and non-overlapping (no lazy class over blanks before [ \t]*), so linear time.
_KEY_VALUE = re.compile(r"^[ \t]*+([A-Za-z](?: *+[A-Za-z0-9()/._-])*+)[ \t]*+:[ \t]*+((?:[ \t]*+[^ \t\n])*+)[ \t]*+$")
_ECHO = re.compile(r"^[ \t]*(?:\S*[#>][ \t]*)?show[ \t]+vpc[ \t]+br(?:i(?:e(?:f)?)?)?[ \t]*$", re.I)
_PROMPT = re.compile(r"^[ \t]*[A-Za-z0-9][A-Za-z0-9_.:/()-]*[#>][ \t]*$")
_SEPARATOR = re.compile(r"^[ \t]*[-‐-―─━]+(?:[ \t]+[-‐-―─━]+)*[ \t]*$")
_LEGEND = re.compile(r"^[ \t]*(?:Legend:|\(\*\) - local vPC is down, forwarding via vPC peer-link)[ \t]*$")
_FOOTER = re.compile(r"^[ \t]*Please check \"show vpc consistency-parameters vpc <vpc-num>\"")
_INTEGER = re.compile(r"[0-9]{1,10}")
_MAX_ROW = 1024

_PEER_LINK_SECTION = "vpc peer-link status"
_MEMBER_SECTION = "vpc status"
_SECTIONS = {_PEER_LINK_SECTION: "peer_links", _MEMBER_SECTION: "members"}
_COLUMNS = {
    "peer_links": ["id", "port", "status", "active", "vlans"],
    "members": ["id", "port", "status", "consistency", "reason", "active", "vlans"],
}
_VLANS = r"(?:-|[0-9]{1,4}(?:-[0-9]{1,4})?(?:,[0-9]{1,4}(?:-[0-9]{1,4})?)*)"
_PORT = r"[A-Za-z][A-Za-z0-9/.:-]{0,31}"
_WORD = r"[A-Za-z][A-Za-z0-9*()_-]{0,31}"
# Only the documented per-vPC Consistency values; a Reason word can never stand in for a missing value.
_CONSISTENCY = r"(?:success|failed)"
_ROWS = {
    "peer_links": re.compile(rf"^[ \t]*([0-9]{{1,6}})[ \t]+({_PORT})[ \t]+({_WORD})[ \t]+({_VLANS})[ \t]*$"),
    "members": re.compile(rf"^[ \t]*([0-9]{{1,6}})[ \t]+({_PORT})[ \t]+({_WORD})[ \t]+({_CONSISTENCY})"
                          rf"[ \t]+(\S+(?:[ \t]\S+)*?)[ \t]+({_VLANS})[ \t]*$"),
}
_ROW_KEYS = {
    "peer_links": ("id", "port", "status", "active_vlans"),
    "members": ("id", "port", "status", "consistency", "reason", "active_vlans"),
}


def _lines(text: str) -> list[str]:
    """CRLF/ANSI framing removed; command echo and bare prompt lines dropped."""
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return [line for line in text.split("\n") if not _ECHO.match(line) and not _PROMPT.match(line)]


def summarize(text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    fields: dict[str, str | None] = {}
    seen: dict[str, int] = {}
    tables: dict[str, dict[str, Any]] = {}
    unrecognized = False
    current: dict[str, Any] | None = None

    for line in _lines(text if isinstance(text, str) else ""):
        stripped = line.strip()
        if len(line) > _MAX_ROW:  # no documented line is this long; never searched
            if current is not None:
                current["malformed"] = True
            else:
                unrecognized = True
            continue
        section = _SECTIONS.get(" ".join(stripped.lower().split()))
        if section is not None:
            if section in tables:  # a repeated table is not merged or guessed
                tables[section]["malformed"] = True
                current = None
                continue
            current = tables[section] = {"name": section, "header": False, "rows": [], "malformed": False}
            continue
        if _FOOTER.match(line) or stripped in (
                "consistency reason of down vpc and for type-2 consistency reasons for", "any vpc."):
            current = None
            continue
        if not stripped:
            if current is not None and (current["header"] or current["rows"]):
                current = None  # a blank line ends a table once its column header was seen
            continue
        if current is not None:
            name = current["name"]
            if _SEPARATOR.match(line):
                continue
            if not current["header"]:
                if stripped.lower().split() == _COLUMNS[name]:
                    current["header"] = True
                    if name == "members":  # column starts, for a Reason wrapped onto the next line
                        current["reason_at"] = line.lower().find("reason")
                        current["vlans_at"] = line.lower().find("active vlans")
                else:
                    current["malformed"] = True
                continue
            reason_at = current.get("reason_at", -1)
            if (current.get("wrap") and 0 < reason_at < current["vlans_at"] and not line[:reason_at].strip()
                    and len(line.rstrip()) <= current["vlans_at"]):
                # NX-OS wraps a long Reason inside its own column, e.g. `Compatibility check` / `failed for MTU`.
                current["rows"][-1]["reason"] += " " + " ".join(line.split())
                continue
            current["wrap"] = False
            match = _ROWS[name].match(line)
            if match is None:
                current["malformed"] = True
                continue
            row: dict[str, Any] = dict(zip(_ROW_KEYS[name], match.groups()))
            row["id"] = int(row["id"])
            current["rows"].append(row)
            current["wrap"] = name == "members"
            continue
        if _LEGEND.match(line) or _SEPARATOR.match(line):
            continue
        pair = _KEY_VALUE.match(line)
        if pair is None:
            unrecognized = True
            continue
        key = _LABELS.get(" ".join(pair.group(1).lower().split()))
        if key is None:
            continue  # other documented metadata is not modelled here
        seen[key] = seen.get(key, 0) + 1
        fields[key] = pair.group(2) or None

    result: dict[str, Any] = {"state": "partial"}
    missing: list[str] = []
    for key in _FIELD_ORDER:
        value: Any = fields.get(key) if seen.get(key) == 1 else None  # a duplicated label is ambiguous
        if value is not None and key in _INTEGER_FIELDS:
            value = int(value) if _INTEGER.fullmatch(value) else None
        result[key] = value
    for key in _FIELD_ORDER:
        if result[key] is None and (key != "consistency_reason" or seen.get(key)
                                    or (result["consistency_status"] or "").lower() != "success"):
            missing.append(key)

    absent = {
        "peer_links": (result["peer_status"] or "").lower() == "peer link not configured",
        "members": result["configured_vpcs"] == 0,
    }
    for name in ("peer_links", "members"):
        table = tables.get(name)
        rows = table["rows"] if table else []
        if table and table["malformed"]:
            result[name] = rows
            missing.append(name)
        elif rows and absent[name]:  # rows contradict the reported absence
            result[name] = rows
            missing.append(name)
        elif rows:
            result[name] = rows
            if name == "members" and result["configured_vpcs"] not in (None, len(rows)):
                missing.append(name)
        elif absent[name]:
            result[name] = []  # documented absence: zero rows is a measured zero
        else:
            result[name] = None
            missing.append(name)
    if unrecognized:
        missing.append("unrecognized_lines")

    recognized = any(seen.values()) or any(table["rows"] for table in tables.values())
    if not recognized:
        result["state"] = "unparsed"
    elif not missing:
        result["state"] = "measured"
    if capture_state != "ok":
        if result["state"] == "measured":
            result["state"] = "partial"
        missing.append("capture")
    result["missing_fields"] = missing
    return result


def consistency(text, capture_state):
    """Read the NX-OS per-vPC and per-interface fixed-width consistency table."""
    rows = {}
    unknown = False
    columns = None
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _SEPARATOR.fullmatch(line) or stripped in (
                "Legend:", "Type 1 : vPC will be suspended in case of mismatch"):
            continue
        header = re.fullmatch(r"Name +(?P<type>Type) +(?P<local>Local Value) +(?P<peer>Peer Value) *", line)
        if header and columns is None:
            columns = [header.start(key) for key in ("type", "local", "peer")]
            continue
        if columns is None:
            unknown = True
            continue
        kind, local, peer = columns
        name, type_id, local_value, peer_value = (piece.strip() for piece in
                                                  (line[:kind], line[kind:local], line[local:peer], line[peer:]))
        # NX-OS wraps the LAG ID across multiple lines in both columns.
        if not name and not type_id and current == "lag-id" and local_value and peer_value:
            rows[current]["local"] += " " + local_value
            rows[current]["peer"] += " " + peer_value
        elif name and name not in rows and type_id in ("1", "2", "-") and local_value and peer_value:
            current = name
            rows[name] = {"type": type_id, "local": local_value, "peer": peer_value}
        else:
            current = None
            unknown = True
    if not rows:
        state = "empty" if capture_state == "empty" else "unparsed"
    else:
        state = "partial" if unknown or capture_state != "ok" else "measured"
    return {"state": state, "parameters": rows}


def compare(observations, vpc_id):
    """Correlate both peers: local values against the other device's view, each device's local against peer
    value, the per-vPC and global consistency (``success``) and the peer adjacency.  ``matched`` only when none
    of these differs."""
    result = {"vpc_id": vpc_id, "state": "incomplete", "peers": observations, "differences": []}
    briefs = [item["vpc"] for item in observations]
    consistency_tables = [item["consistency"] for item in observations]
    if any(item.get("state") != "measured" for item in (*briefs, *consistency_tables)):
        return result
    first, second = briefs
    if first["domain_id"] != second["domain_id"]:
        result.update(state="different_domain", differences=["domain_id"])
        return result
    member_rows = [[row for row in item["members"] if row["id"] == vpc_id] for item in briefs]
    if any(len(rows) != 1 for rows in member_rows):
        return result
    for item, rows in zip(observations, member_rows):
        item["member"] = rows[0]
    left, right = (item["parameters"] for item in consistency_tables)
    differences = []
    for name in sorted(left.keys() | right.keys()):
        a, b = left.get(name), right.get(name)
        # Cross-check between the peers, and on each device its own local and peer value: a mismatch NX-OS
        # reports (also mirrored on both peers, e.g. MTU 1500/9000 and 9000/1500) is a vPC inconsistency.
        if (a is None or b is None or (a["type"], a["local"], a["peer"]) != (b["type"], b["peer"], b["local"])
                or a["local"] != a["peer"] or b["local"] != b["peer"]):
            differences.append("parameter:" + name)
    for field in ("status", "consistency", "active_vlans"):
        if member_rows[0][0][field] != member_rows[1][0][field] or (
                field == "consistency" and any(rows[0][field].lower() != "success" for rows in member_rows)):
            differences.append("member:" + field)
    for field in ("peer_status", "keepalive_status", "consistency_status"):
        expected = {"peer_status": "peer adjacency formed ok", "consistency_status": "success"}.get(field)
        if first[field] != second[field] or (
                expected is not None and any(item[field].lower() != expected for item in briefs)):
            differences.append("peer:" + field)
    roles = {item["role"].split(",")[0].strip().lower() for item in briefs}
    if roles != {"primary", "secondary"}:
        differences.append("peer:role")
    result.update(state="different" if differences else "matched", differences=differences)
    return result
