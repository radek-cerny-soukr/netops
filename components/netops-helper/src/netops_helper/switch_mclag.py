from __future__ import annotations

import re
from typing import Any

MCLAG_QUERIES = frozenset({"switch_mclag_icl", "switch_trunk_status", "switch_mclag_consistency"})

_PORT = re.compile(r"port[1-9][0-9]{0,2}")
_SERIAL = re.compile(r"S[A-Z0-9]{11,15}")
_TRUNK = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,34}")
_WORD = re.compile(r"[A-Z]{1,16}")
_NOT_SUPPORTED = re.compile(r"(?m)^switch:S[A-Z0-9]{11,15} does not support MCLAG feature![ \t]*\r?$")
_TRUNK_NOT_FOUND = re.compile(r"(?m)^[ \t]*>>>>\S+ TRUNK NOT FOUND ON LOCAL SWITCH<<<<[ \t]*\r?$")
_FIELD = re.compile(r"(?m)^[ \t]+([A-Za-z][A-Za-z -]*?)[ \t]{2,}(\S[^\r\n]*?)[ \t]*\r?$")
_CHECK = re.compile(r'(?m)^[ \t]*\*\* Comparing "(switch\.[a-z.-]{1,40})" config[ \t]+\.+([^\r\n]*?)[ \t]*\r?$')
_TRUNK_HEAD = re.compile(r"(?m)^[ \t]*Trunk Name:[ \t]+(\S+)[ \t]*\r?$")
_SWITCH_HEAD = re.compile(r"(?m)^Managed Switch[ \t]*:[ \t]*S[A-Z0-9]{11,15}[ \t]")
_TRUNK_INFO = re.compile(r"(?m)^Switch Trunk Information\b")
_ANSWER_END = re.compile(r"\n[ \t]*\r?\n[ \t\r\n]*\Z")
_STP_STATES = frozenset({"FORWARDING", "LEARNING", "LISTENING", "BLOCKING", "DISCARDING"})
_LAG_FIELDS = ("local ports", "local inactive ports", "peer ports", "peer inactive ports")
_STP_FIELDS = (("local", "local active-lag ports", "local active ports"),
               ("peer", "remote active-lag ports", "remote active ports"))


def not_supported(query: str, text: str) -> bool:
    return query in MCLAG_QUERIES and _NOT_SUPPORTED.search(text) is not None


def summarize(query: str, text: str, parameters: dict[str, str] | None) -> dict[str, Any]:
    if _NOT_SUPPORTED.search(text):
        return {"state": "not_supported"}
    if query == "switch_mclag_icl":
        return _icl(text)
    if query == "switch_trunk_status":
        return _trunk(text, (parameters or {}).get("mclag_trunk", ""))
    return _consistency(text)


def _fields(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, value in _FIELD.findall(text):
        found.setdefault(key.strip().lower(), value)
    return found


def _match(pattern: re.Pattern[str], value: str | None) -> str | None:
    return value if value is not None and pattern.fullmatch(value) else None


def _ports(value: str | None) -> list[str] | None:
    if value is None:
        return None
    value = value.replace("<--", "").strip()
    if value == "none":
        return []
    tokens = [token for token in re.split(r"[\s,]+", value) if token]
    return tokens if tokens and all(_PORT.fullmatch(token) for token in tokens) else None


def _icl(text: str) -> dict[str, Any]:
    fields = _fields(text)
    if "peer-serial-number" not in fields and "icl-ports" not in fields:
        ended = _SWITCH_HEAD.search(text) and _ANSWER_END.search(text)
        return {"state": "not_configured" if ended else "incomplete"}
    peer = _match(_SERIAL, fields.get("peer-serial-number"))
    if peer is None:
        return {"state": "incomplete"}
    name = re.search(r"(?m)^(\S+)[ \t]*\r?\n[ \t]+icl-ports[ \t]", text)
    return {
        "state": "configured",
        "icl_trunk": _match(_TRUNK, name.group(1) if name else None),
        "icl_ports": _match(re.compile(r"[0-9][0-9,-]{0,63}"), fields.get("icl-ports")),
        "local_serial": _match(_SERIAL, fields.get("local-serial-number")),
        "peer_serial": peer,
        "split_brain": _match(re.compile(r"Enabled|Disabled"), fields.get("split-brain")),
    }


def _trunk(text: str, wanted: str) -> dict[str, Any]:
    if not _TRUNK.fullmatch(wanted):
        return {"state": "not_found", "trunk": None}
    if not _TRUNK_INFO.search(text):
        return {"state": "incomplete", "trunk": wanted}
    heads = list(_TRUNK_HEAD.finditer(text))
    blocks = [(head.group(1), text[head.start():heads[index + 1].start() if index + 1 < len(heads) else len(text)])
              for index, head in enumerate(heads)]
    for name, block in blocks:
        if name != wanted:
            continue
        mode = re.search(r"(?m)^[ \t]*Mode:[^(\r\n]*\(([^)\r\n]*)\)", block)
        flags = set(mode.group(1).split(",")) if mode else set()
        role = "icl" if "mclag-icl" in flags else "mclag" if "mclag" in flags else "lag"
        status = re.search(r"(?m)^status:[ \t]+(up|down)[ \t]*\r?$", block)
        members = [
            {"port": port, "status": state}
            for port, state in re.findall(r"(?m)^slave:[ \t]+(port[1-9][0-9]{0,2})[ \t]*\r?\n[ \t]+status:[ \t]+([a-z]{1,16})[ \t]*\r?$", block)
        ]
        trunk_status = status.group(1) if status else None
        missing = [member["port"] for member in members if member["status"] != "up"]
        if not _complete_block(block):
            state = "incomplete"
        elif trunk_status == "up":
            state = "degraded" if missing else "ok"
        else:
            state = "down"
        return {"state": state, "trunk": wanted, "role": role, "trunk_status": trunk_status,
                "members": members, "missing_members": missing}
    listed = blocks and _ANSWER_END.search(text) and all(_complete_block(block) for _, block in blocks)
    return {"state": "not_found" if listed else "incomplete", "trunk": wanted}


def _complete_block(block: str) -> bool:
    status = re.search(r"(?m)^status:[ \t]+(up|down)[ \t]*\r?$", block)
    count = re.search(r"(?m)^ports:[ \t]+([0-9]{1,3})[ \t]*\r?$", block)
    members = re.findall(r"(?m)^slave:[ \t]+port[1-9][0-9]{0,2}[ \t]*\r?\n[ \t]+status:[ \t]+[a-z]{1,16}[ \t]*\r?$", block)
    return bool(status and count and members and int(count.group(1)) == len(members))


def _consistency(text: str) -> dict[str, Any]:
    if _TRUNK_NOT_FOUND.search(text):
        return {"state": "not_found"}
    checks = {section: (result if re.fullmatch(r"[A-Za-z]{1,16}", result) else "unreadable")
              for section, result in _CHECK.findall(text)}
    if not checks:
        return {"state": "incomplete"}
    fields = _fields(text)
    lag = {key: _ports(fields.get(key)) for key in _LAG_FIELDS}
    lag_state = _match(_WORD, fields.get("lag state"))
    stp = {side: {"active_lag_ports": _ports(fields.get(ports_key)),
                  "state": fields.get(state_key) if fields.get(state_key) in _STP_STATES else None}
           for side, ports_key, state_key in _STP_FIELDS}
    unreadable = sorted([key for key, value in lag.items() if value is None]
                        + ([] if lag_state else ["lag state"])
                        + [key for side, ports_key, state_key in _STP_FIELDS
                           for key, value in ((ports_key, stp[side]["active_lag_ports"]), (state_key, stp[side]["state"]))
                           if value is None])
    missing = ([{"side": "local", "port": port} for port in lag["local inactive ports"] or []]
               + [{"side": "peer", "port": port} for port in lag["peer inactive ports"] or []])
    not_forwarding = [side for side in ("local", "peer") if stp[side]["state"] not in (None, "FORWARDING")]
    stp_blocked = [{"side": side, "port": port} for side in not_forwarding
                   for port in stp[side]["active_lag_ports"] or []]
    if any(result != "OK" for result in checks.values()):
        state = "inconsistent"
    elif unreadable:
        state = "incomplete"
    elif lag_state != "UP" or not _carries_traffic(lag, stp):
        state = "down"
    elif missing or not_forwarding:
        state = "degraded"
    else:
        state = "ok"
    return {
        "state": state, "config_checks": checks, "unreadable_fields": unreadable,
        "local_ports": lag["local ports"], "local_inactive_ports": lag["local inactive ports"],
        "peer_ports": lag["peer ports"], "peer_inactive_ports": lag["peer inactive ports"],
        "lag_state": lag_state, "missing_members": missing,
        "stp_state": {side: stp[side]["state"] for side in ("local", "peer")},
        "stp_blocked": stp_blocked,
    }


def _carries_traffic(lag: dict[str, list[str] | None], stp: dict[str, dict[str, Any]]) -> bool:
    usable = (set(lag["local ports"] or []) - set(lag["local inactive ports"] or [])) | (
        set(lag["peer ports"] or []) - set(lag["peer inactive ports"] or []))
    active = [port for side in ("local", "peer") for port in stp[side]["active_lag_ports"] or []]
    return bool(usable and active)
