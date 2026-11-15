"""Structured member list of one Arista EOS ``show mlag interfaces`` capture.

Private building block: no I/O, no other query, no registry or public query wiring.
The summary is derived only from the text it is given.  Each member comes from one
table row; nothing is taken from ``show mlag detail`` (no global MLAG state, no
port counts) and no health, forwarding, consistency or neighbor verdict is made.
``state`` says how much of the modelled output was read:

* ``measured`` - the table header, its dash separator and at least one row were read
  and every row gave every required member field; this is parsed data, not health;
* ``partial``  - something was read but the table, a member field, a row or the
  capture itself is missing, unknown, ambiguous, damaged or malformed;
* ``unparsed`` - no table header was read (blank, prompt, refusal, unknown text).

A header and separator without rows are not a proven empty list: ``partial`` with
``members`` missing.  The one line ``No MLAG ports configured`` (and nothing else), which
cEOS 4.36.1F prints instead of the table when no MLAG port is configured (live 178), is
the complete empty table: ``measured`` with ``members: []`` and nothing missing.  Any
other text without a header stays ``unparsed``.

Row layout.  The published table is not aligned with its header, so rows are neither
cut at fixed offsets nor split at every blank (a description has blanks).  A row is
split into cells at runs of two or more blanks and the cells are placed with the
header label columns:

* the three cells starting at or after the ``local`` label column are the tail
  ``local``, ``remote`` and ``status``; exactly three single-token cells are required;
* at most one single-token cell (the id) may start before the ``desc`` label column;
* the cells in between are the description and the state.  The last of them is the
  state only when it is a single token separated by two or more blanks that starts at
  or after the ``state`` label column.  A word of a free-text description is therefore
  never moved into an empty state column; the state is then missing.

A row that does not fit this layout (missing tail cell, extra cell, overlong line) is
not a member and is never guessed: the member list is reported incomplete and the
other rows are kept.
"""
from __future__ import annotations

import re
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_PROMPT_PREFIX = r"[A-Za-z0-9][A-Za-z0-9_.:/()-]*[ \t]*[#>][ \t]*"
_PROMPT = re.compile(rf"^[ \t]*{_PROMPT_PREFIX}$")
_ECHO = re.compile(rf"^[ \t]*(?:{_PROMPT_PREFIX})?show[ \t]+mlag[ \t]+int(?:e(?:r(?:f(?:a(?:c(?:e(?:s)?)?)?)?)?)?)?"
                   r"[ \t]*$", re.I)
_OTHER_COMMAND = re.compile(rf"^[ \t]*{_PROMPT_PREFIX}\S")
_ROW_START = re.compile(r"^[ \t]*[0-9]{1,10}[ \t]{2,}\S")  # an id cell and a cell separator: a table row
_HEADER = re.compile(r"^[ \t]*mlag[ \t]+desc[ \t]+state[ \t]+local[ \t]+remote[ \t]+status[ \t]*$", re.I)
_SEPARATOR = re.compile(r"^[ \t]*-+(?:[ \t]+-+){5}[ \t]*$")
_PRE_HEADER = re.compile(r"^[ \t]*local/remote[ \t]*$", re.I)
_NO_PORTS = re.compile(r"^[ \t]*No MLAG ports configured[ \t]*$")
_LABEL = re.compile(r"\S+")
_CELL = re.compile(r"\S+(?:[ \t]\S+)*")  # cells are separated by two or more blanks
_INTEGER = re.compile(r"[0-9]{1,10}")
_PORT = re.compile(r"Po[0-9]{1,6}")
_STATES = frozenset({"disabled", "inactive", "active-full", "active-partial"})
_LINK = frozenset({"up", "down"})  # "-", "N/A" and anything else are not a reported link status
_MAX_LINE = 1024
_COLUMNS = ("mlag", "desc", "state", "local", "remote", "status")
_MEMBER_FIELDS = ("id", "state", "local_port", "remote_port", "local_status", "remote_status")


def _lines(text: Any) -> list[str]:
    """CRLF/ANSI framing removed; this command's echo and bare prompt lines dropped."""
    if not isinstance(text, str):
        return []
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return [line.expandtabs(8) for line in text.split("\n") if not _ECHO.match(line) and not _PROMPT.match(line)]


def _columns(header: str, separator: str) -> dict[str, int] | None:
    """Label start columns, or None when a label does not lie inside its dash column."""
    labels = list(_LABEL.finditer(header))
    dashes = list(_LABEL.finditer(separator))
    if len(labels) != len(_COLUMNS) or len(dashes) != len(_COLUMNS):
        return None
    for label, dash in zip(labels, dashes):
        if not dash.start() <= label.start() < dash.end():
            return None
    return {name: label.start() for name, label in zip(_COLUMNS, labels)}


def _member(line: str, columns: dict[str, int]) -> dict[str, Any] | None:
    """One member from one row, or None when the row does not fit the table layout."""
    if len(line) > _MAX_LINE or _SEPARATOR.match(line):
        return None
    cells = [(match.start(), match.group()) for match in _CELL.finditer(line)]
    lead = [cell for cell in cells if cell[0] < columns["desc"]]
    middle = [cell for cell in cells if columns["desc"] <= cell[0] < columns["local"]]
    tail = [cell for cell in cells if cell[0] >= columns["local"]]
    if len(lead) > 1 or len(tail) != 3 or any(" " in value for _, value in lead + tail):
        return None  # a missing, extra or merged cell: the columns cannot be assigned
    state = None
    if middle and " " not in middle[-1][1] and middle[-1][0] >= columns["state"]:
        state = middle.pop()[1]  # an own state cell, never a description word
    description = None
    if middle:
        start = middle[0][0]
        end = middle[-1][0] + len(middle[-1][1])
        description = line[start:end]
    status = tail[2][1].split("/")
    local_status, remote_status = status if len(status) == 2 else (None, None)
    member: dict[str, Any] = {
        "id": int(lead[0][1]) if lead and _INTEGER.fullmatch(lead[0][1]) else None,
        "description": description,
        "state": state if state in _STATES else None,
        "local_port": tail[0][1] if _PORT.fullmatch(tail[0][1]) else None,
        "remote_port": tail[1][1] if _PORT.fullmatch(tail[1][1]) else None,
        "local_status": local_status if local_status in _LINK else None,
        "remote_status": remote_status if remote_status in _LINK else None,
    }
    return member


def summarize(text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    lines = _lines(text)
    content = [line for line in lines if line.strip()]
    if len(content) == 1 and len(content[0]) <= _MAX_LINE and _NO_PORTS.match(content[0]):
        # The device's own complete answer for no configured MLAG port: an empty member list, not unparsed.
        missing_empty: list[str] = []
        if capture_state != "ok":
            missing_empty.append("capture")
        return {"state": "measured" if capture_state == "ok" else "partial", "members": [],
                "missing_fields": missing_empty}
    headers = 0
    table = True
    damaged = 0
    members: list[dict[str, Any]] = []
    columns: dict[str, int] | None = None
    in_rows = False
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if len(line) <= _MAX_LINE and _HEADER.match(line):
            headers += 1
            in_rows = False
            columns = None
            following = lines[index] if index < len(lines) else ""
            if len(following) <= _MAX_LINE and _SEPARATOR.match(following):
                index += 1
                columns = _columns(line, following)
            if columns is None:
                table = False  # no separator or labels outside their columns: rows not interpretable
            else:
                in_rows = True
            continue
        if not in_rows:
            continue  # text outside the table (refusal, pre-header line) is not member data
        if _OTHER_COMMAND.match(line) and not _ROW_START.match(line):
            in_rows = False  # the next command's echo ends this output; a row (even damaged) is never an echo
            continue
        if not line.strip() or (len(line) <= _MAX_LINE and _PRE_HEADER.match(line)):
            continue
        member = _member(line, columns)
        if member is None:
            damaged += 1  # never silently skipped
            continue
        members.append(member)

    ids = [member["id"] for member in members if member["id"] is not None]
    duplicated = {value for value in ids if ids.count(value) > 1}
    for member in members:
        if member["id"] in duplicated:
            member["id"] = None  # an ambiguous member id, the rest of the row is kept
        member["missing_fields"] = [key for key in _MEMBER_FIELDS if member[key] is None]

    missing: list[str] = []
    if headers != 1 or not table:
        missing.append("table")
    if missing or damaged or duplicated or not members:
        missing.append("members")  # the member list is not proven complete
    for position, member in enumerate(members):
        missing.extend(f"members[{position}].{key}" for key in member["missing_fields"])

    if headers == 0:
        state = "unparsed"
    elif missing:
        state = "partial"
    else:
        state = "measured"
    if capture_state != "ok":
        if state == "measured":
            state = "partial"
        missing.append("capture")
    return {"state": state, "members": members, "missing_fields": missing}
