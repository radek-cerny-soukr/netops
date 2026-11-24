"""Cisco NX-OS targeted clear (1.0.12 nxos targeted clear): interface counters, one dynamic MAC or the MACs of one port, one ARP
or IPv6 neighbor entry in a named VRF.

Syntax verified on a Nexus 9000v (N9K-C9300v) with NX-OS 9.3(12) by the interactive help of the device (nothing was
executed for the help): `clear counters interface ethernet <slot/port>`, `clear mac address-table dynamic address
<mac>` (four MAC spellings), `clear mac address-table dynamic interface ethernet <slot/port>`, `clear ip arp <ip> vrf
<vrf>` and `clear ipv6 neighbor <ip> [<interface>] vrf <vrf>`. The selectors that clear a whole table (`all`, a bare
`clear ip arp`, `vrf all`, a VLAN, a VXLAN peer) are never rendered: every target is one explicit object.

The reads are the show commands of the check account: `show interface <if>` (the counters and the line `Last
clearing of "show interface" counters`), `show mac address-table address|interface`, `show ip arp <ip> vrf <vrf>`
and `show ipv6 neighbor <ip> vrf <vrf>`. The IPv6 neighbor rows are the documented layout (Cisco Nexus 9000 NX-API
CLI reference 9.3(x), IPv6 commands); the lab has IPv6 disabled everywhere, so the row layout of that table was not
measured. An unrecognised row makes the readback unreadable, never a success.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected

TABLES = ("port-counters", "mac-address-table", "ip-arp", "ipv6-neighbor")
FIRMWARE = ("9.3(12)",)
KIND = "nxos-clear"
ETHERNET = re.compile(r"(?i)Eth(?:ernet)?([1-9][0-9]{0,2}/[1-9][0-9]{0,2}(?:/[1-9][0-9]{0,2})?)")
SVI = re.compile(r"(?i)Vlan([1-9][0-9]{0,3})")
VRF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
MAC = re.compile(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}")
COUNTER_NAMES = ("rx_unicast", "rx_multicast", "rx_broadcast", "rx_packets", "rx_bytes",
                 "tx_unicast", "tx_multicast", "tx_broadcast", "tx_packets", "tx_bytes")
CLEARING = "last_clearing"
ERROR_LINES = ("Invalid", "% ", "Cmd exec error", "Syntax error", "ERROR", "Error")


@dataclass(frozen=True)
class Target:
    key: str
    scope: str
    value: str
    read: str
    write: str
    vrf: str | None = None
    interface: str | None = None


def ethernet(name: str):
    """Ethernet1/2 for Eth1/2, ethernet1/2 and Ethernet1/2; None for any other name."""
    match = ETHERNET.fullmatch(name.strip()) if isinstance(name, str) else None
    return None if match is None else "Ethernet" + match.group(1)


def mac(text: str):
    """The dotted spelling of a unicast MAC address in any of the four NX-OS spellings, or None."""
    if not isinstance(text, str) or not re.fullmatch(r"(?i)[0-9a-f]{4}(\.[0-9a-f]{4}){2}|(?:[0-9a-f]{2}([:-]))"
                                                       r"(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}", text):
        return None
    digits = re.sub(r"[^0-9a-f]", "", text.lower())
    if int(digits[1], 16) & 1 or digits == "0" * 12:
        return None
    return ".".join(digits[index:index + 4] for index in range(0, 12, 4))


def _vrf(changes: dict) -> str:
    vrf = changes.get("vrf", "default")
    if not isinstance(vrf, str) or not VRF.fullmatch(vrf) or vrf.casefold() == "all":
        raise Rejected(["clear requires one named VRF (not all)"], reason_codes=["clear_invalid_target"])
    return vrf


def target(table: str, key: str, changes: dict) -> Target:
    """Render only the verified selectors, each with one explicit object."""
    if table == "port-counters" and not changes and ethernet(key):
        port = ethernet(key)
        return Target(port, "interface", port, "show interface " + port, "clear counters interface " + port)
    if table == "mac-address-table" and not changes:
        address = mac(key)
        if address:
            return Target(address, "mac", address, "show mac address-table address " + address,
                          "clear mac address-table dynamic address " + address)
        scope, _, value = key.partition(":")
        if scope == "interface" and ethernet(value):
            port = ethernet(value)
            return Target("interface:" + port, "interface", port, "show mac address-table interface " + port,
                          "clear mac address-table dynamic interface " + port)
    if table == "ip-arp" and set(changes) <= {"vrf"}:
        vrf = _vrf(changes)
        try:
            ip = ipaddress.ip_address(key)
        except ValueError:
            ip = None
        if ip is not None and ip.version == 4 and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback
                                                      or ip == ipaddress.ip_address("255.255.255.255")):
            return Target(str(ip), "ip", str(ip), "show ip arp %s vrf %s" % (ip, vrf),
                          "clear ip arp %s vrf %s" % (ip, vrf), vrf)
    if table == "ipv6-neighbor" and set(changes) <= {"vrf", "interface"}:
        vrf = _vrf(changes)
        interface = changes.get("interface")
        name = None
        if interface is not None:
            name = ethernet(interface) or ("Vlan" + SVI.fullmatch(interface.strip()).group(1)
                                           if isinstance(interface, str) and SVI.fullmatch(interface.strip()) else None)
            if name is None:
                raise Rejected(["clear of an IPv6 neighbor names an Ethernet or Vlan interface"],
                               reason_codes=["clear_invalid_target"])
        try:
            ip = ipaddress.ip_address(key)
        except ValueError:
            ip = None
        if (ip is not None and ip.version == 6 and "%" not in key
                and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)):
            return Target(str(ip), "ip", str(ip), "show ipv6 neighbor %s vrf %s" % (ip, vrf),
                          "clear ipv6 neighbor %s%s vrf %s" % (ip, "" if name is None else " " + name, vrf), vrf, name)
    raise Rejected(["clear requires one Ethernet port, one MAC address or interface:<port>, or one address of the"
                    " table's family in a named VRF"], reason_codes=["clear_invalid_target"])


def unreadable():
    return Rejected(["the scoped NX-OS readback is incomplete or unrecognised"],
                    reason_codes=["clear_readback_unreadable"])


def _clean(text: str) -> list:
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n")]
    if any(line.strip().startswith(ERROR_LINES) for line in lines):
        raise unreadable()
    return lines


def observation(table: str, tgt: Target, text: str) -> dict:
    lines = _clean(text)
    if table == "port-counters":
        return _counters(lines, tgt.value)
    entries = {"mac-address-table": _macs, "ip-arp": _arp, "ipv6-neighbor": _neighbors}[table](lines, tgt)
    return {"scope": tgt.scope, "target": tgt.value, "vrf": tgt.vrf,
            "entries": sorted(entries, key=lambda entry: tuple(str(value) for value in entry.values()))}


def _counters(lines, port: str) -> dict:
    first = re.fullmatch(r"(Ethernet\S+) is (up|down)(?: \(.*\))?", lines[0].strip()) if lines else None
    if first is None or first.group(1) != port:
        raise unreadable()
    clearing = [re.fullmatch(r'\s*Last clearing of "show interface" counters (\S.*?)\s*', line) for line in lines]
    clearing = [match.group(1) for match in clearing if match]
    sections = {name: [i for i, line in enumerate(lines) if line.strip() == name] for name in ("RX", "TX")}
    if len(clearing) != 1 or any(len(index) != 1 for index in sections.values()) or sections["RX"][0] > sections["TX"][0]:
        raise unreadable()
    counters = {}
    for direction, begin, end in (("rx", sections["RX"][0], sections["TX"][0]), ("tx", sections["TX"][0], len(lines))):
        block = "\n".join(lines[begin:end])
        kinds = re.search(r"(\d+) unicast packets\s+(\d+) multicast packets\s+(\d+) broadcast packets", block)
        total = re.search(r"(\d+) %s packets\s+(\d+) bytes" % ("input" if direction == "rx" else "output"), block)
        if kinds is None or total is None:
            raise unreadable()
        values = (*kinds.groups(), *total.groups())
        counters.update(zip((direction + "_" + name for name in ("unicast", "multicast", "broadcast", "packets",
                                                                  "bytes")), map(int, values)))
    return {"port": port, "link": first.group(2), "counters": {**counters, CLEARING: clearing[0]}}


MAC_ROW = re.compile(r"^([*G+COR~() ]*?)\s*(\d+|-)\s+(" + MAC.pattern + r")\s+(\S+)\s+(\S+)\s+([TF])\s+([TF])\s+(\S+)$",
                     re.IGNORECASE)


def _macs(lines, tgt: Target) -> list:
    header = next((i for i, line in enumerate(lines) if re.match(r"\s*VLAN\s+MAC Address\s+Type", line)), None)
    if header is None or header + 1 >= len(lines) or not re.fullmatch(r"-+(?:\+-+)+", lines[header + 1].strip()):
        raise unreadable()
    entries = []
    for line in lines[header + 2:]:
        if not line.strip():
            continue
        row = MAC_ROW.fullmatch(line)
        if row is None:
            raise unreadable()
        flags, vlan, address, kind, age, _secure, _ntfy, port = row.groups()
        shown = address.lower() if tgt.scope == "mac" else port
        if shown != (tgt.value if tgt.scope == "mac" else "Eth" + tgt.value[len("Ethernet"):]):
            raise unreadable()
        entries.append({"mac": address.lower(), "vlan": vlan, "port": port, "flags": flags.replace(" ", ""),
                        "age": int(age) if age.isascii() and age.isdecimal() else None,
                        "dynamic": kind.lower() == "dynamic"})
    return entries


def _table_rows(lines, title, total_label, columns):
    start = next((i for i, line in enumerate(lines) if re.fullmatch(title, line.strip())), None)
    if start is None or start + 2 >= len(lines):
        raise unreadable()
    count = re.fullmatch(r"Total number of entries: (\d+)", lines[start + 1].strip())
    if count is None or lines[start + 2].split() != columns:
        raise unreadable()
    return int(count.group(1)), [line for line in lines[start + 3:] if line.strip()]


def _seconds(age: str):
    """Seconds of an entry age HH:MM:SS, None for a static entry ("-")."""
    if age == "-":
        return None
    if ":" not in age:      # an entry younger than a second is printed as seconds with a fraction: 0.333114
        return int(float(age))
    hours, minutes, seconds = map(int, age.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def _arp(lines, tgt: Target) -> list:
    total, rows = _table_rows(lines, r"IP ARP Table(?: for all contexts)?", "entries",
                              "Address Age MAC Address Interface Flags".split())
    entries = []
    for line in rows:
        row = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)\s+(\d\d:\d\d:\d\d|\d+\.\d+|-)\s+(" + MAC.pattern + r"|INCOMPLETE)\s+(\S+)"
                           r"(?:\s+(\S.*))?", line.strip(), re.IGNORECASE)
        if row is None or row.group(1) != tgt.value:
            raise unreadable()
        address, age, hardware, interface, flags = row.groups()
        entries.append({"address": address, "mac": hardware.lower(), "interface": interface,
                        "flags": (flags or "").strip(), "age": _seconds(age),
                        "dynamic": age != "-" and hardware.upper() != "INCOMPLETE" and not flags})
    if total != len(entries):
        raise unreadable()
    return entries


def _neighbors(lines, tgt: Target) -> list:
    total, rows = _table_rows(lines, r"IPv6 Adjacency Table for VRF \S+", "entries",
                              "Address Age MAC Address Pref Source Interface Flags".split())
    joined, pending = [], None
    for line in rows:
        words = line.split()
        if pending is not None:
            joined.append(pending + " " + line.strip())
            pending = None
        elif len(words) == 1:
            pending = words[0]   # a long address stands alone, the rest of the row follows
        else:
            joined.append(line.strip())
    if pending is not None:
        raise unreadable()
    entries = []
    for line in joined:
        row = re.fullmatch(r"(\S+)\s+(\d\d:\d\d:\d\d|\d+\.\d+|-)\s+(" + MAC.pattern + r"|INCOMPLETE)\s+(\d+)\s+(\S+)\s+(\S+)"
                           r"(?:\s+(\S.*))?", line, re.IGNORECASE)
        if row is None:
            raise unreadable()
        address, age, hardware, _pref, source, interface, flags = row.groups()
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise unreadable() from None
        if address != tgt.value:
            raise unreadable()
        entries.append({"address": address, "mac": hardware.lower(), "interface": interface, "source": source,
                        "flags": (flags or "").strip(), "age": _seconds(age),
                        "dynamic": age != "-" and source == "icmpv6" and hardware.upper() != "INCOMPLETE" and not flags})
    if total != len(entries):
        raise unreadable()
    return entries


def config_digest(text: str) -> str:
    """The running configuration without its volatile header lines and blank lines: what the clear must not change."""
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n")
             if line.strip() and not line.startswith(("!Command:", "!Running configuration last done at:", "!Time:"))]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


# the readback of the counters: they fell, or stay within what a few control frames can add before the read
COUNTER_TOLERANCE_PACKETS = 64
COUNTER_TOLERANCE_BYTES = COUNTER_TOLERANCE_PACKETS * 1522


def _cleared(name, before, after) -> bool:
    limit = COUNTER_TOLERANCE_BYTES if name.endswith("bytes") else COUNTER_TOLERANCE_PACKETS
    return after < before or after <= limit


AGE_ALLOWANCE_SECONDS = 2


def _core(entry) -> dict:
    """The entry without its age, which changes between two reads."""
    return {name: value for name, value in entry.items() if name != "age"}


def _static(entry) -> bool:
    return not entry["dynamic"]


def _order(entry):
    return tuple(sorted(_core(entry).items(), key=lambda item: item[0]))


def stable(state):
    """The state bound into plan_sha256: without counters, entry ages and clearing times (they move on their own)."""
    if not isinstance(state, dict):
        return state
    state = {name: value for name, value in state.items() if name != "counters"}
    if "entries" in state:
        state["entries"] = [_core(entry) for entry in state["entries"]]
    return state


def _mac_identity(entry):
    return entry["vlan"], entry["mac"], entry["port"]


def readback(plan, observed, elapsed=0, *, since_send=None):
    """What the clear guarantees, not an idle table: the counters fell (and the line `Last clearing` names a time),
    or the selected dynamic entries are gone or learned again by live traffic (marked `relearned`, with its age)
    while every other entry of the scope stays. NX-OS refreshes a cleared ARP or ND entry at once (measured on 9.3(12):
    the age is 0 within a second), so an entry that is still there must be younger than an untouched entry would be:
    its age before the clear plus the elapsed seconds (less a 2 s allowance). Returns (matches, readback)."""
    before = plan["predicted"]["before"]
    if plan["table"] == "port-counters":
        old, new = before["counters"], observed["counters"]
        age = new[CLEARING]
        age = _seconds(age) if re.fullmatch(r"\d+:\d{2}:\d{2}", age) else None
        unchanged_nonzero = any(old[name] for name in COUNTER_NAMES) and all(
            old[name] == new[name] for name in COUNTER_NAMES)
        return (observed["port"] == before["port"] and observed["link"] == before["link"]
                and age is not None and since_send is not None and age < since_send and not unchanged_nonzero
                and all(_cleared(name, old[name], new[name]) for name in COUNTER_NAMES)), observed
    scope = all(observed[name] == before[name] for name in ("scope", "target", "vrf"))
    kept = sorted((_core(entry) for entry in before["entries"] if _static(entry)), key=_order)
    seen = sorted((_core(entry) for entry in observed["entries"] if _static(entry)), key=_order)
    ages = {entry["address"]: entry.get("age") for entry in before["entries"] if entry["dynamic"] and "address" in entry}
    mac_ages = {_mac_identity(entry): entry.get("age") for entry in before["entries"]
                if entry["dynamic"] and "address" not in entry}
    entries, younger = [], True
    for entry in observed["entries"]:
        relearned = False
        if entry["dynamic"] and "address" in entry:
            previous = ages.get(entry["address"])
            relearned = (entry["age"] is not None and previous is not None
                         and entry["age"] < previous + elapsed - AGE_ALLOWANCE_SECONDS)
        elif entry["dynamic"]:
            identity = _mac_identity(entry)
            previous = mac_ages.get(identity)
            age = entry.get("age")
            relearned = identity not in mac_ages or (
                previous is not None and age is not None and since_send is not None
                and age < previous and age < since_send)
        if entry["dynamic"] and not relearned:
            younger = False
        entries.append(dict(entry, relearned=relearned))
    return scope and seen == kept and younger, dict(observed, entries=entries)


def prediction(table: str, tgt: Target, before: dict):
    """The state after the clear and the lines of the preview that name its scope."""
    if table == "port-counters":
        counters = dict.fromkeys(COUNTER_NAMES, 0)
        return (dict(before, counters={**counters, CLEARING: "just now"}),
                ["port %s: all %d traffic counters are reset" % (tgt.value, len(COUNTER_NAMES))])
    entries = before["entries"]
    dynamic = [entry for entry in entries if entry["dynamic"]]
    if not dynamic:
        raise Rejected(["the selected scope has no learned entry to clear"], reason_codes=["clear_no_entry"])
    if tgt.scope in ("mac", "ip") and len(dynamic) != 1:
        raise Rejected(["the selected address matches multiple learned entries"], reason_codes=["clear_ambiguous_entry"])
    if tgt.scope in ("mac", "ip") and len(entries) != 1:
        raise Rejected(["the selected address has other entries that the clear could remove"],
                       reason_codes=["clear_ambiguous_entry"])
    return (dict(before, entries=[entry for entry in entries if not entry["dynamic"]]),
            ["%s %s: %d learned (dynamic) entries will be cleared, %d other entries stay"
             % (table, tgt.key, len(dynamic), len(entries) - len(dynamic))])
