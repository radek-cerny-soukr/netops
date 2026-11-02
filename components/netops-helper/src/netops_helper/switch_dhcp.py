from __future__ import annotations

import ipaddress
import re
from typing import Any

DHCP_BINDINGS_QUERY = "switch_dhcp_bindings"

_SECTION = re.compile(r"(Client db|Server db|Client6 db|Server6 db):[ \t]*")
_HEADER = re.compile(r"[ \t]*Flags[ \t]+MAC Address[ \t]+VLAN[ \t]+Client IP\b.*")
_LEGEND = re.compile(r"Flags: S \(Static\), A \(ARP Monitor\), D \(DHCP Monitor\)[ \t]*")
_IPV4 = r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
_TIME = r"[0-9]{1,5}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}"
_ROW = re.compile(
    r"[ \t]*(?:([SAD]{1,3})[ \t]+)?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})[ \t]+([0-9]{1,4})[ \t]+(" + _IPV4 + r")"
    r"[ \t]+(" + _TIME + r")[ \t]+(" + _TIME + r")[ \t]+([A-Za-z0-9_][A-Za-z0-9_.-]{0,34})"
    r"(?:[ \t]+\S+)*?[ \t]+(" + _IPV4 + r")[ \t]*"
)


def summarize(text: str, start: int, end: int) -> dict[str, Any]:
    section = None
    seen: list[str] = []
    header = legend = ipv6 = False
    total = unreadable = 0
    bindings: list[dict[str, Any]] = []
    position = 0
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        heading = _SECTION.fullmatch(line)
        if heading:
            section = heading.group(1)
            seen.append(section)
            continue
        if _LEGEND.fullmatch(line):
            legend = True
            section = None
            continue
        if not line.strip() or section is None:
            continue
        if section == "Client6 db":
            ipv6 = True
            continue
        if section != "Client db":
            continue
        if not header and _HEADER.fullmatch(line):
            header = True
            continue
        binding = _binding(line)
        if binding is None:
            unreadable += 1
            continue
        total += 1
        if start <= line_start < end:
            bindings.append(binding)
    complete = legend and (header or not total + unreadable) and seen[:2] == ["Client db", "Server db"]
    state = "incomplete" if not complete or unreadable else "ok" if total else "empty"
    return {"state": state, "total_bindings": total, "unreadable_rows": unreadable,
            "ipv6_rows_present": ipv6, "bindings": bindings}


def _binding(line: str) -> dict[str, Any] | None:
    row = _ROW.fullmatch(line)
    if row is None:
        return None
    flags, mac, vlan, ip, lease, expiry, port, server = row.groups()
    if not 1 <= int(vlan) <= 4094 or not _ipv4(ip) or not _ipv4(server):
        return None
    return {"flags": flags or "", "mac": mac.lower(), "vlan": int(vlan), "ip": ip,
            "lease": lease, "expiry": expiry, "port": port, "server_ip": server}


def _ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True
