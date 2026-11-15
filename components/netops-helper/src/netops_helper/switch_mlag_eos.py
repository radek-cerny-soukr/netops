"""Structured summary of one Arista EOS ``show mlag detail`` capture.

The summary is derived only from the text it is given: no I/O, no other query.
It reports raw scalar values as the device printed them and never infers
health, role, neighbor, traffic or operability from them.  ``state`` says how
much of the modelled output was read, not whether the MLAG is healthy:

* ``measured`` - every modelled field was read from the text (or is a count
  that proves the member list empty); this is parsed data, not health;
* ``partial``  - something was read but a field, section, the member list or
  the capture itself is missing, empty, unknown, ambiguous or malformed;
* ``unparsed`` - nothing of the modelled output was read.

This query prints no member port names.  ``members`` is ``[]`` only when the
explicit ``Configured`` count is 0 and no other read count contradicts it,
otherwise ``None`` and listed as missing; ports are never invented.

Sections and labels are matched whole and per section: ``state`` of
``MLAG Status`` and ``State`` of ``MLAG Detailed Status`` are different fields.
"""
from __future__ import annotations

import re
from typing import Any

from . import switch_mlag_eos_interfaces

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ECHO = re.compile(r"^[ \t]*(?:\S*[#>][ \t]*)?show[ \t]+mlag[ \t]+det(?:a(?:i(?:l)?)?)?[ \t]*$", re.I)
_PROMPT = re.compile(r"^[ \t]*[A-Za-z0-9][A-Za-z0-9_.:/()-]*[#>][ \t]*$")
# A section heading has its colon attached to the title; value lines have " :".
_HEADING = re.compile(r"^[ \t]*([A-Za-z](?:[A-Za-z0-9 -]*[A-Za-z0-9])?):[ \t]*$")
# Label: a letter, then blank-separated non-blank label characters (no tab), trailing blanks excluded; value:
# the rest of the line without leading/trailing spaces and tabs.  Possessive and non-overlapping, so the
# match is linear: same groups as the former lazy spelling, which backtracked quadratically (task 136).
_KEY_VALUE = re.compile(r"^[ \t]*+([A-Za-z](?: *+[A-Za-z0-9()/._-])*+)[ \t]*+:[ \t]*+((?:[ \t]*+[^ \t\n])*+)[ \t]*+$")
_INTEGER = re.compile(r"[0-9]{1,10}")
_MAX_LINE = 1024

_SECTIONS = {
    "mlag configuration": "configuration",
    "mlag status": "status",
    "mlag ports": "ports",
    "mlag detailed status": "detailed",
}
_LABELS = {
    ("configuration", "domain-id"): "domain_id",
    ("configuration", "local-interface"): "local_interface",
    ("configuration", "peer-address"): "peer_address",
    ("configuration", "peer-link"): "peer_link",
    ("configuration", "peer-config"): "peer_config",
    ("status", "state"): "operational_state",
    ("status", "negotiation status"): "negotiation_status",
    ("status", "peer-link status"): "peer_link_status",
    ("status", "local-int status"): "local_interface_status",
    ("ports", "disabled"): "ports.disabled",
    ("ports", "configured"): "ports.configured",
    ("ports", "inactive"): "ports.inactive",
    ("ports", "active-partial"): "ports.active_partial",
    ("ports", "active-full"): "ports.active_full",
    ("detailed", "state"): "detailed_state",
    ("detailed", "peer state"): "peer_state",
}
_SCALARS = ("domain_id", "operational_state", "detailed_state", "peer_state", "peer_address", "peer_link",
            "local_interface", "peer_link_status", "local_interface_status", "negotiation_status", "peer_config")
_PORTS = ("disabled", "configured", "inactive", "active_partial", "active_full")
# Not a reported value: nothing was verified.
_UNKNOWN = frozenset({"unknown", "n/a", "na", "none", "null", "-"})
_PLACEHOLDER_ADDRESSES = frozenset({"0.0.0.0", "::", "0:0:0:0:0:0:0:0"})


def _lines(text: str) -> list[str]:
    """CRLF/ANSI framing removed; command echo and bare prompt lines dropped."""
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return [line for line in text.split("\n") if not _ECHO.match(line) and not _PROMPT.match(line)]


def _reported(value: str) -> str | None:
    """The printed value, or None when empty, unknown or a redaction marker."""
    if not value or value.lower() in _UNKNOWN or "redacted" in value.lower():
        return None
    return value


def summarize(text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    raw: dict[str, str] = {}
    seen: dict[str, int] = {}
    section: str | None = None
    for line in _lines(text if isinstance(text, str) else ""):
        if len(line) > _MAX_LINE:  # no modelled line is this long; never searched
            continue
        heading = _HEADING.match(line)
        if heading is not None:
            section = _SECTIONS.get(" ".join(heading.group(1).lower().split()))
            continue
        pair = _KEY_VALUE.match(line)
        if pair is None or section is None:
            continue
        key = _LABELS.get((section, " ".join(pair.group(1).lower().split())))
        if key is None:
            continue  # other management fields are not modelled and do not spoil the capture
        seen[key] = seen.get(key, 0) + 1
        raw[key] = pair.group(2)

    def value(key: str) -> str | None:
        return _reported(raw[key]) if seen.get(key) == 1 else None  # a duplicated label is ambiguous

    result: dict[str, Any] = {"state": "partial"}
    missing: list[str] = []
    for key in _SCALARS:
        item = value(key)
        if key == "peer_address" and item is not None and item.lower() in _PLACEHOLDER_ADDRESSES:
            item = None  # placeholder, not a verified peer
        result[key] = item
    ports: dict[str, int | None] = {}
    for name in _PORTS:
        item = value(f"ports.{name}")
        ports[name] = int(item) if item is not None and _INTEGER.fullmatch(item) else None
    result["ports"] = ports
    for key in _SCALARS:
        if result[key] is None:
            missing.append(key)
    missing.extend(f"ports.{name}" for name in _PORTS if ports[name] is None)

    others = [count for name, count in ports.items() if name != "configured" and count is not None]
    if ports["configured"] == 0 and not any(others):
        result["members"] = []  # explicit zero configured and no contradicting count
    else:
        result["members"] = None  # this query prints no member port names
        missing.append("members")

    if not any(result[key] is not None for key in _SCALARS) and all(count is None for count in ports.values()):
        result["state"] = "unparsed"
    elif not missing:
        result["state"] = "measured"
    if capture_state != "ok":
        if result["state"] == "measured":
            result["state"] = "partial"
        missing.append("capture")
    result["missing_fields"] = missing
    return result


def payload(platform: str, query: str, text: str, capture_state: str | None = "ok") -> dict[str, Any]:
    """The additive ssh_read key; only for arista_eos/mlag_detail and arista_eos/mlag_interfaces."""
    if platform == "arista_eos" and query == "mlag_detail":
        return {"mlag": summarize(text, capture_state)}
    if platform == "arista_eos" and query == "mlag_interfaces":
        return {"mlag_members": switch_mlag_eos_interfaces.summarize(text, capture_state)}
    return {}
