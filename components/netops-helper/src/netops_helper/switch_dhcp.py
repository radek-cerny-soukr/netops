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


_EOS_RELAY_COUNTS = re.compile(
    r"(All (?:Req|Resp)|[A-Za-z][A-Za-z0-9./-]*)[ \t]+"
    r"([0-9]{1,20})[ \t]+([0-9]{1,20})[ \t]+([0-9]{1,20})(?:[ \t]+(.+))?"
)


def eos_relay_counters(text: str) -> dict[str, Any]:
    """Read complete EOS relay counter rows without treating truncated rows as zeros."""
    rows = []
    globals_seen = set()
    incomplete = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line in {"DHCP Packets", "Dhcp Packets"}:
            continue
        columns = line.replace("|", " ").split()
        if (columns and columns[0] in {"Globals", "Interface"}
                and columns[1:] == ["Rcvd", "Fwdd", "Drop", "Last", "Cleared"]):
            continue
        if set(line) <= {"-", "|", " "} or columns == ["Dhcp", "Packets"]:
            continue
        match = _EOS_RELAY_COUNTS.fullmatch(line.replace("|", " ").strip())
        if match is None:
            incomplete = True
            continue
        interface, received, forwarded, dropped, cleared = match.groups()
        if interface in {"All Req", "All Resp"}:
            globals_seen.add(interface)
        rows.append({"interface": interface, "received": int(received), "forwarded": int(forwarded),
                     "dropped": int(dropped), "last_cleared": cleared})
    return {"complete": not incomplete and globals_seen == {"All Req", "All Resp"}, "rows": rows}


def junos_dhcp_status(query: str, text: str) -> str | None:
    """Distinguish a Junos DHCP refusal, an empty table and an incomplete listing."""
    if query not in {"dhcp_server_bindings", "dhcp_relay_bindings",
                     "dhcp_server_statistics", "dhcp_relay_statistics"}:
        return None
    output = text.strip()
    if re.fullmatch(r"error: the (?:dhcp|jdhcp) subsystem is not running", output, re.I):
        return "not_applicable"
    if query.endswith("_statistics"):
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        sections = {}
        current = None
        for line in lines:
            if line == "Offer Delay:" or re.fullmatch(r"(?:Packets|Messages) (?:dropped|received|sent|forwarded):", line):
                if line in sections:
                    return "unparsed"
                current = line
                sections[current] = set()
                continue
            cells = line.rsplit(maxsplit=1)
            if current is None or len(cells) != 2 or not re.fullmatch(r"[0-9]{1,20}", cells[1]):
                return "unparsed"
            label = cells[0].removesuffix(":")
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 /()._-]{0,95}", label):
                return "unparsed"
            sections[current].add(label)
        received = sections.get("Messages received:", sections.get("Packets received:", set()))
        sent_section = next((name for name in ("Messages sent:", "Packets sent:", "Packets forwarded:")
                             if name in sections), "")
        sent = sections.get(sent_section, set())
        required_received = {"BOOTREQUEST", "DHCPDECLINE", "DHCPDISCOVER", "DHCPINFORM", "DHCPRELEASE", "DHCPREQUEST"}
        required_sent = {"BOOTREPLY", "DHCPOFFER", "DHCPACK", "DHCPNAK"}
        force_renew = {"DHCPFORCERENEW"}
        lease_responses = {"DHCPLEASEACTIVE", "DHCPLEASEUNASSIGNED", "DHCPLEASEUNKNOWN", "DHCPLEASEQUERYDONE"}
        lease_requests = {"DHCPLEASEQUERY", "DHCPBULKLEASEQUERY"}
        if query == "dhcp_server_statistics":
            required_received |= lease_requests
            required_sent |= force_renew | lease_responses
        else:
            required_received |= lease_responses
        if ("Total" not in sections.get("Packets dropped:", ()) or not required_received <= received
                or not required_sent <= sent):
            return "unparsed"
        if "Offer Delay:" in sections and not {"DELAYED", "INPROGRESS", "TOTAL"} <= sections["Offer Delay:"]:
            return "unparsed"
        if (sent_section != "Packets forwarded:" and "Packets forwarded:" in sections
                and not {"Total", "BOOTREQUEST", "BOOTREPLY"} <= sections["Packets forwarded:"]):
            return "unparsed"
        if query == "dhcp_relay_statistics":
            extended_sent = force_renew | lease_requests
            if "DHCPACTIVELEASEQUERY" in received:
                extended_sent |= lease_responses | {"DHCPACTIVELEASEQUERY"}
            if not extended_sent <= sent:
                # The short EX listing and a clipped extended listing can have the same counters.
                return "needs_count"
    elif query == "dhcp_relay_bindings" and output:
        lines = output.splitlines()
        if not re.fullmatch(r"IP address\s+Session [Ii][Dd]\s+Hardware address\s+Expires\s+State\s+Interface(?:\s+.*)?",
                            lines[0].strip(), re.I):
            return "unparsed"
        for line in lines[1:]:
            if line.strip() and not re.fullmatch(
                rf"[ \t]*{_IPV4}\s+\d+\s+[0-9a-f:]+\s+\d+\s+[A-Z][A-Z_-]+\s+\S+(?:\s+\S+)*[ \t]*",
                line, re.I,
            ):
                return "unparsed"
    elif output:
        blocks = re.split(r"(?mi)(?=^[ \t]*Client IP Address:[ \t]+\S+)", output)
        for block in filter(str.strip, blocks):
            address = re.match(rf"(?i)^[ \t]*Client IP Address:[ \t]+({_IPV4})[ \t]*\r?\n", block)
            state = re.search(r"(?mi)^[ \t]*State:[ \t]+(\w+)(?:\([^\r\n()]+\))?[ \t]*$", block)
            if not address or not _ipv4(address[1]) or not state:
                return "unparsed"
            if state[1].upper() == "BOUND" and not all(
                re.search(rf"(?mi)^[ \t]*{field}:[ \t]+\S", block)
                for field in ("Lease Expires", "Session Id", "Client Pool Name")
            ):
                return "unparsed"
    return None


_SNOOPING_BINDING_HEADER = re.compile(r"MacAddress\s+IpAddress\s+Lease(?:\(Sec\)|Sec)\s+Type\s+(?:BD|VLAN)\s+Interface", re.I)
_SNOOPING_BINDING_TOTAL = re.compile(r"Total (?:number of )?(?:(?:DHCP snooping )?bindings|entries):\s*(\d+)", re.I)


def nxos_bindings(text, normalize_port):
    return _snooping_bindings(text, normalize_port, require_total=False, platform="NX-OS")


def ios_snooping_bindings(text, normalize_port):
    return _snooping_bindings(text, normalize_port, require_total=True, platform="IOS")


def _snooping_bindings(text, normalize_port, *, require_total, platform):
    from .normalization import normalize_mac

    rows, unknown = [], []
    header = None
    total = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or re.fullmatch(r"[- ]+", line):
            continue
        if _SNOOPING_BINDING_HEADER.fullmatch(line):
            header = number
            continue
        count = _SNOOPING_BINDING_TOTAL.fullmatch(line)
        if count:
            if require_total and total is not None:
                unknown.append({"line": number, "text": raw})
            total = int(count[1])
            continue
        try:
            mac, ip, lease, kind, vlan, interface = line.split()
            static = kind.lower() == "static"
            infinite = static and lease.lower() == "infinite"
            if header is None or not ((lease.isdecimal() or infinite) and vlan.isdecimal() and 1 <= int(vlan) <= 4094):
                raise ValueError
            row = {"mac": normalize_mac(mac), "ip": str(ipaddress.IPv4Address(ip)), "type": kind,
                   "vlan_id": int(vlan), "lease_seconds": None if infinite else int(lease),
                   "interface": normalize_port(interface)}
            if static:
                row["static"] = True
            rows.append(row)
        except ValueError:
            unknown.append({"line": number, "text": raw})
    if header is None or require_total and total is None or total is not None and total != len(rows):
        unknown.append({"line": 1, "text": f"{platform} binding header or row total could not be verified"})
    return rows, unknown


def nxos_snooping(text):
    patterns = {
        "enabled": r"^Switch DHCP snooping is (enabled|disabled)$",
        "configured_vlans": r"^DHCP snooping is configured on the following VLANs:\n([0-9,-]+|none)$",
        "operational_vlans": r"^DHCP snooping is operational on the following VLANs:\n([0-9,-]+|none)$",
        "option_82": r"^Insertion of Option 82 is (enabled|disabled)$",
        "verify_mac": r"^Verification of MAC address is (enabled|disabled)$",
    }
    clean = "\n".join(line.strip() for line in text.splitlines())
    fields = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, clean, re.M)
        if match:
            value = match[1]
            fields[name] = value == "enabled" if name in {"enabled", "option_82", "verify_mac"} else value
    header = re.search(r"(?m)^Interface\s+Trusted$", clean)
    trusted = []
    if header:
        for line in clean[header.end():].splitlines():
            if not line or re.fullmatch(r"[- ]+", line):
                continue
            match = re.fullmatch(r"(\S+)\s+(Yes|No)", line)
            if not match:
                return fields | {"trusted_interfaces": trusted}, False
            if match[2] == "Yes":
                trusted.append(match[1])
    return fields | {"trusted_interfaces": trusted}, bool(header and len(fields) == len(patterns))


def nxos_relay(text):
    enabled = re.search(r"(?m)^DHCP relay service is (enabled|disabled)\s*$", text)
    header = re.search(r"(?m)^[ \t]*Interface[ \t]+Relay Address[ \t]+VRF Name[ \t]*$", text)
    fields = {"enabled": enabled[1] == "enabled" if enabled else None, "helpers": []}
    if not enabled or not header:
        return fields, False
    for raw in text[header.end():].splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"[- ]+", line):
            continue
        match = re.fullmatch(rf"(\S+)\s+({_IPV4})(?:\s+(\S+))?", line)
        if not match or not _ipv4(match[2]):
            return fields, False
        fields["helpers"].append({"interface": match[1], "address": match[2], "vrf": match[3]})
    return fields, True


_NXOS_DHCP_MESSAGES = {"Discover", "Offer", "Request", "Ack", "Release", "Decline", "Inform", "Nack"}
_NXOS_DHCP_SECTIONS = {"DHCP L2 Forwarding:", "DHCP L3 FWD:", "Non DHCP:", "DROP:"}
_NXOS_DHCP_TOTALS = {"Total Packets Received", "Total Packets Forwarded", "Total Packets Dropped"}
_NXOS_SNOOPING_DROPS = {"Received on untrusted port", "Source mac validation failed",
                        "Binding entry validation Failed", "Packet Malformed"}
_NXOS_RELAY_DROPS = {"DHCP Relay not enabled", "Interface error", "Tx failure towards server",
                     "Tx failure towards client", "Packet Malformed", "Relay Trusted port not configured"}


def nxos_dhcp_counters(text, *, relay):
    messages, sections = {}, {}
    section = None
    complete = True
    matrix = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"-+", line) or line in {
            "receives DHCP request packet with destination ip as broadcast",
            "address. If request is unicast it will be HW switched",
        } or line.startswith("*  -  These counters will show correct value"):
            continue
        if re.fullmatch(r"Message Type\s+Rx\s+Tx\s+Drops", line):
            matrix = True
            continue
        if line in _NXOS_DHCP_SECTIONS and line not in sections:
            section = line
            sections[section] = {}
            continue
        message = re.fullmatch(r"([A-Za-z]+)(?:\(\*?\))?\s+(\d+)\s+(\d+)\s+(\d+)", line)
        if section is None and matrix and message and message[1] not in messages and (
            message[1] in _NXOS_DHCP_MESSAGES or message[1] == "Total"
        ):
            messages[message[1]] = dict(zip(("received", "forwarded", "dropped"), map(int, message.groups()[1:])))
            continue
        label, separator, count = line.partition(":")
        label, count = label.rstrip(), count.strip()
        if (section is not None and separator and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 /()-]*", label)
                and re.fullmatch(r"[0-9]{1,20}", count) and label not in sections[section]):
            sections[section][label] = int(count)
        else:
            complete = False
    total = messages.pop("Total", None)
    complete = (
        complete and set(messages) == _NXOS_DHCP_MESSAGES and total is not None
        and all(sum(row[key] for row in messages.values()) == value for key, value in total.items())
        and _NXOS_DHCP_TOTALS <= sections.get("DHCP L3 FWD:" if relay else "DHCP L2 Forwarding:", {}).keys()
        and _NXOS_DHCP_TOTALS <= sections.get("Non DHCP:", {}).keys()
        and (_NXOS_RELAY_DROPS if relay else _NXOS_SNOOPING_DROPS) <= sections.get("DROP:", {}).keys()
    )
    return {"messages": messages, "total": total, "forwarding": sections.get("DHCP L3 FWD:" if relay else "DHCP L2 Forwarding:", {}),
            "non_dhcp": sections.get("Non DHCP:", {}), "drop_reasons": sections.get("DROP:", {})}, complete


_NXOS_DAI_REQUIRED = {
    "ARP Req Forwarded", "ARP Res Forwarded", "ARP Req Dropped", "ARP Res Dropped", "DHCP Drops", "DHCP Permits",
    "SMAC Fails-ARP Req", "SMAC Fails-ARP Res", "DMAC Fails-ARP Res", "IP Fails-ARP Req", "IP Fails-ARP Res",
}


def nxos_dai(text, vlan_id):
    rows = {}
    counters = None
    complete = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"-+", line):
            continue
        header = re.fullmatch(r"Vlan\s*:\s*(\d+)", line)
        if header:
            vlan = int(header[1])
            if not 1 <= vlan <= 4094 or vlan in rows or vlan_id is not None and vlan != int(vlan_id):
                complete = False
                counters = None
            else:
                counters = rows[vlan] = {}
            continue
        label, separator, count = line.partition("=")
        label, count = label.rstrip(), count.strip()
        if (counters is not None and separator and re.fullmatch(r"[A-Za-z][A-Za-z -]*", label)
                and re.fullmatch(r"[0-9]{1,20}", count) and label not in counters):
            counters[label] = int(count)
        else:
            complete = False
    result = [{"vlan_id": vlan, "counters": counters} for vlan, counters in rows.items()]
    return result, complete and bool(rows) and all(_NXOS_DAI_REQUIRED <= row.keys() for row in rows.values())


# 1.0.12 G20 (FP-12): `execute dhcp lease-list` without an interface prints every lease, one section per DHCP server
# interface. Measured on FortiGate-60F 7.6.8 build3744 (tests/fixtures/real/fortinet/fortigate60f_7.6.8_g20): the
# section name is the interface, then the header `IP MAC-Address Hostname VCI SSID AP SERVER-ID Expiry`, then one row
# per lease. The IP and MAC are separated by tabs; the remaining columns are 20 characters wide counted from the first
# character after the blanks that follow the MAC, so an empty VCI/SSID/AP cell is only blanks.
FORTIOS_LEASES_QUERY = "dhcp_leases_all"
_LEASE_SECTION = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@ /:-]{0,34}")
_LEASE_HEADER = re.compile(
    r"[ \t]+IP[ \t]+MAC-Address[ \t]+Hostname {12}VCI {17}SSID {16}AP {18}SERVER-ID {11}Expiry[ \t]*")
_LEASE_ROW = re.compile(r"[ \t]+(" + _IPV4 + r")[ \t]+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\t(.*)")
_LEASE_COLUMNS = ("hostname", "vci", "ssid", "ap", "server_id")
_LEASE_WIDTH = 20
_LEASE_EXPIRY = re.compile(r"[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}")


def fortios_leases(text: str, start: int, end: int) -> dict[str, Any]:
    """Normalize the all-interface FortiOS lease list; a line of another shape makes the state incomplete.

    Only leases whose row starts inside [start, end) of the UTF-8 output (the ssh_read page) are returned; the
    counts cover the whole output. An empty output is a legitimate empty lease table, not an error.
    """
    section = None
    headed: set[str] = set()
    per_interface: dict[str, int] = {}
    leases: list[dict[str, Any]] = []
    unreadable = total = position = 0
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        if not line[0].isspace():
            if _LEASE_SECTION.fullmatch(line.rstrip()):
                section = line.rstrip()
                per_interface.setdefault(section, 0)
            else:
                section = None
                unreadable += 1
            continue
        if section is not None and _LEASE_HEADER.fullmatch(line):
            headed.add(section)
            continue
        row = _LEASE_ROW.fullmatch(line)
        lease = _lease(section, row) if row is not None and section in headed else None
        if lease is None:
            unreadable += 1
            continue
        total += 1
        per_interface[section] += 1
        if start <= line_start < end:
            leases.append(lease)
    complete = not unreadable and set(per_interface) <= headed
    return {"state": "incomplete" if not complete else "ok" if total else "empty",
            "total_leases": total, "unreadable_lines": unreadable,
            "interfaces": [{"interface": name, "leases": count} for name, count in per_interface.items()],
            "leases": leases}


def _lease(interface, row) -> dict[str, Any] | None:
    ip, mac, rest = row.groups()
    if not _ipv4(ip):
        return None
    # The columns are blank padded; a cell filling its 20 characters would run into the next one.
    width = _LEASE_WIDTH * len(_LEASE_COLUMNS)
    cells = [rest[index * _LEASE_WIDTH:(index + 1) * _LEASE_WIDTH] for index in range(len(_LEASE_COLUMNS))]
    expiry = rest[width:].strip()
    if len(rest) <= width or any(not cell.endswith(" ") for cell in cells) or not _LEASE_EXPIRY.fullmatch(expiry):
        return None
    values = {name: cell.strip() or None for name, cell in zip(_LEASE_COLUMNS, cells)}
    if values["server_id"] is None or not values["server_id"].isdigit():
        return None
    return {"interface": interface, "ip": ip, "mac": mac.lower(), "hostname": values["hostname"],
            "vci": values["vci"], "ssid": values["ssid"], "ap": values["ap"],
            "server_id": int(values["server_id"]), "expiry": expiry}
