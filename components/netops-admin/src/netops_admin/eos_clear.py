"""Arista EOS targeted clear (1.0.12 eos targeted clear): the counters of one Ethernet port, one dynamic MAC address, one ARP or IPv6
neighbor entry and one BGP soft refresh of one neighbor.

Syntax verified on cEOS 4.36.1F by the interactive help of the device (`?`, nothing was executed for the help;
private measurement record) and then by one clear of every kind on a lab object:

* `clear counters <interface>` (the optional keyword `session` clears only the view of one CLI session and is never
  rendered);
* `clear mac address-table dynamic vlan <1-4094> address <H.H.H>`: the form `clear mac address-table dynamic address
  <mac>` of the plan row is NOT accepted by EOS 4.36.1F (`% Unrecognized command`), the address filter exists only
  behind `vlan`, so the VLAN of the learned entry is part of the command;
* `clear arp <A.B.C.D>` and `clear arp vrf <vrf> <A.B.C.D>`;
* `clear ipv6 neighbors [vrf <vrf>] <interface> <A:B:C:D:E:F:G:H>`: the plan row `clear ipv6 neighbors <ipv6>` is NOT
  a form of EOS 4.36.1F, the interface comes first and without it the command clears the interface's whole table;
* `clear ip bgp <A.B.C.D> soft in|out` (the default VRF; both directions together and `vrf` are not rendered).

The selectors that clear a whole table (`clear counters` alone, `clear arp`, `clear mac address-table dynamic`,
`clear ip bgp *`, a VLAN or an interface scope) are never rendered: every target is one explicit object.

The reads are `show` commands of the check account in JSON (`show mac address-table address <mac> | json`, `show ip arp
vrf <vrf> <ip> | json`, `show ipv6 neighbors vrf <vrf> <ip> | json`, `show ip bgp neighbors <ip> | json`) and the text of
`show interfaces <port>` for the counters (the JSON of that command has no time of the last clearing). An unrecognised
shape makes the readback unreadable, never a success.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected

COUNTERS = "port-counters"
MAC = "mac-address-table"
ARP = "ip-arp"
ND = "ipv6-neighbor"
BGP = "bgp-refresh"
TABLES = (COUNTERS, MAC, ARP, ND, BGP)
FIRMWARE = ("4.36.1F",)
KIND = "eos-clear"
DEFAULT_VRF = "default"
ETHERNET = re.compile(r"(?i)(?:Ethernet|Et)([1-9][0-9]{0,3}(?:/[1-9][0-9]{0,3}){0,2})")
SVI = re.compile(r"(?i)Vlan([1-9][0-9]{0,3})")
PORT_CHANNEL = re.compile(r"(?i)(?:Port-Channel|Po)([1-9][0-9]{0,5})")
VRF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}")
DOTTED = re.compile(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}")
ABBREVIATIONS = {"Vl": "Vlan", "Et": "Ethernet", "Po": "Port-Channel", "Lo": "Loopback", "Ma": "Management",
                 "Tu": "Tunnel", "Vx": "Vxlan"}
COUNTER_NAMES = ("in_packets", "in_bytes", "in_broadcast", "in_multicast", "in_errors",
                 "out_packets", "out_bytes", "out_broadcast", "out_multicast", "out_errors")
DIRECTIONS = ("in", "out")


@dataclass(frozen=True)
class Target:
    key: str
    scope: str
    value: str
    read: str
    write: str | None
    vrf: str | None = None
    interface: str | None = None
    vlan: str | None = None
    direction: str | None = None


def unreadable():
    return Rejected(["the scoped EOS readback is incomplete or unrecognised"], reason_codes=["clear_readback_unreadable"])


def invalid(message="clear requires one Ethernet port, one MAC address, one address of the table's family or one BGP "
                    "neighbor with its direction"):
    return Rejected([message], reason_codes=["clear_invalid_target"])


def ethernet(name):
    """Ethernet1/2 for Et1/2, ethernet1/2 and Ethernet1/2; None for any other name."""
    match = ETHERNET.fullmatch(name.strip()) if isinstance(name, str) else None
    return None if match is None else "Ethernet" + match.group(1)


def interface_name(name):
    """The EOS name of an Ethernet, Vlan or Port-Channel interface in any of its short forms, else None."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    for pattern, prefix in ((ETHERNET, "Ethernet"), (SVI, "Vlan"), (PORT_CHANNEL, "Port-Channel")):
        match = pattern.fullmatch(name)
        if match:
            return prefix + match.group(1)
    return None


def mac(text):
    """The dotted spelling of a unicast MAC address in any of the usual spellings, or None."""
    if not isinstance(text, str) or not re.fullmatch(r"(?i)[0-9a-f]{4}(\.[0-9a-f]{4}){2}|(?:[0-9a-f]{2}([:-]))"
                                                       r"(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}", text):
        return None
    digits = re.sub(r"[^0-9a-f]", "", text.lower())
    if int(digits[1], 16) & 1 or digits == "0" * 12:
        return None
    return ".".join(digits[index:index + 4] for index in range(0, 12, 4))


def _vrf(changes):
    vrf = changes.get("vrf", DEFAULT_VRF)
    if not isinstance(vrf, str) or not VRF.fullmatch(vrf) or vrf.casefold() == "all":
        raise invalid("clear requires one named VRF (not all)")
    if vrf.casefold() == "management":
        raise Rejected(["the selected clear scope includes a protected object: VRF management carries the management"
                        " interface"], reason_codes=["clear_protected_target"])
    return vrf


def _address(key, version):
    try:
        ip = ipaddress.ip_address(key.strip()) if isinstance(key, str) and "%" not in key else None
    except ValueError:
        ip = None
    if (ip is None or ip.version != version or ip.is_unspecified or ip.is_multicast or ip.is_loopback
            or ip == ipaddress.ip_address("255.255.255.255" if version == 4 else "::")):
        return None
    return ip


def target(table, key, changes) -> Target:
    """Render only the verified selectors, each with one explicit object. The write command of a MAC address and of
    an IPv6 neighbor needs the learned entry (its VLAN, its interface): resolve() completes it."""
    if table == COUNTERS and not changes and ethernet(key):
        port = ethernet(key)
        return Target(port, "interface", port, "show interfaces " + port, "clear counters " + port)
    if table == MAC and set(changes) <= {"vlan"}:
        address = mac(key)
        vlan = changes.get("vlan")
        if vlan is not None and (not isinstance(vlan, str) or not re.fullmatch(r"[1-9][0-9]{0,3}", vlan)
                                 or not 1 <= int(vlan) <= 4094):
            raise invalid("clear of a MAC address names its VLAN as a number from 1 to 4094")
        if address:
            return Target(address, "mac", address, "show mac address-table address %s | json" % address, None,
                          vlan=vlan)
    if table == ARP and set(changes) <= {"vrf"}:
        ip, vrf = _address(key, 4), _vrf(changes)
        if ip is not None:
            return Target(str(ip), "ip", str(ip), "show ip arp vrf %s %s | json" % (vrf, ip),
                          "clear arp %s" % ip if vrf == DEFAULT_VRF else "clear arp vrf %s %s" % (vrf, ip), vrf)
    if table == ND and set(changes) <= {"vrf", "interface"}:
        ip, vrf = _address(key, 6), _vrf(changes)
        name = None
        if "interface" in changes:
            name = interface_name(changes["interface"])
            if name is None:
                raise invalid("clear of an IPv6 neighbor names an Ethernet, Vlan or Port-Channel interface")
        if ip is not None:
            return Target(str(ip), "ip", str(ip), "show ipv6 neighbors vrf %s %s | json" % (vrf, ip), None, vrf, name)
    if table == BGP and set(changes) == {"direction"} and changes["direction"] in DIRECTIONS:
        ip = _address(key, 4)
        if ip is not None:
            return Target(str(ip), "peer", str(ip), "show ip bgp neighbors %s | json" % ip,
                          "clear ip bgp %s soft %s" % (ip, changes["direction"]), DEFAULT_VRF,
                          direction=changes["direction"])
    raise invalid()


def _json(text):
    try:
        data = json.loads(text)
    except ValueError:
        raise unreadable() from None
    if not isinstance(data, dict) or "errors" in data:
        raise unreadable()
    return data


def _count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise unreadable()
    return value


def _clean(text):
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n")]
    if any(line.startswith("%") or line.startswith("> ") for line in lines) or "--More--" in text:
        raise unreadable()
    return lines


def _clearing_seconds(text):
    """Seconds since the last clearing of the counters: None for `never`."""
    if text == "never":
        return None
    match = re.fullmatch(r"(?:(\d+) days?, )?(\d+):(\d{2}):(\d{2}) ago", text)
    if match is None:
        raise unreadable()
    days, hours, minutes, seconds = (int(value or 0) for value in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def _counters(text, port):
    lines = _clean(text)
    head = re.fullmatch(r"(Ethernet\S+) is (.+?), line protocol is (\S+)(?: \((\S+)\))?", lines[0]) if lines else None
    if head is None or head.group(1) != port:
        raise unreadable()
    body = "\n".join(lines[1:])

    def one(pattern):
        found = re.findall(pattern, body, re.MULTILINE)
        if len(found) != 1:
            raise unreadable()
        return found[0]

    clearing = _clearing_seconds(one(r'^\s*Last clearing of "show interface" counters (.+?)\s*$'))
    in_packets, in_bytes = one(r"^\s*(\d+) packets input, (\d+) bytes$")
    in_broadcast, in_multicast = one(r"^\s*Received (\d+) broadcasts, (\d+) multicast$")
    in_errors = one(r"^\s*(\d+) input errors, \d+ CRC, \d+ alignment, \d+ symbol, \d+ input discards$")
    out_packets, out_bytes = one(r"^\s*(\d+) packets output, (\d+) bytes$")
    out_broadcast, out_multicast = one(r"^\s*Sent (\d+) broadcasts, (\d+) multicast$")
    out_errors = one(r"^\s*(\d+) output errors, \d+ collisions$")
    values = (in_packets, in_bytes, in_broadcast, in_multicast, in_errors,
              out_packets, out_bytes, out_broadcast, out_multicast, out_errors)
    return {"port": port, "link": head.group(4) or head.group(3), "clearing": clearing,
            "counters": dict(zip(COUNTER_NAMES, map(int, values)))}


def _l3_and_port(text):
    """('Vlan3931', 'Ethernet5') of the interface column `Vlan3931, Ethernet5`; the port is None for `not learned` and
    for an interface that has no port part (`Management0`)."""
    if not isinstance(text, str):
        raise unreadable()
    parts = [part.strip() for part in text.split(",")]
    if not 1 <= len(parts) <= 2 or not all(parts):
        raise unreadable()
    first = re.fullmatch(r"([A-Za-z-]+?)(\d+(?:/\d+){0,2})", parts[0])
    if first is None:
        raise unreadable()
    l3 = ABBREVIATIONS.get(first.group(1), first.group(1)) + first.group(2)
    port = None
    if len(parts) == 2 and parts[1] != "not learned":
        second = re.fullmatch(r"([A-Za-z-]+?)(\d+(?:/\d+){0,2})", parts[1])
        if second is None:
            raise unreadable()
        port = ABBREVIATIONS.get(second.group(1), second.group(1)) + second.group(2)
    return l3, port


def neighbor_entries(data, key, *, address_filter=None):
    rows, total, static = data.get(key), data.get("totalEntries"), data.get("staticEntries")
    if not isinstance(rows, list) or _count(total) != len(rows) or _count(static) > len(rows):
        raise unreadable()
    entries = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("address"), str) or not isinstance(
                row.get("hwAddress"), str) or not DOTTED.fullmatch(row["hwAddress"].lower()):
            raise unreadable()
        try:
            address = str(ipaddress.ip_address(row["address"]))
        except ValueError:
            raise unreadable() from None
        if address_filter is not None and address != address_filter:
            raise unreadable()
        l3, port = _l3_and_port(row.get("interface"))
        age = row.get("age")
        # a static entry has no age (measured on 4.36.1F: ARP and neighbor entries made by configuration)
        entries.append({"address": address, "mac": row["hwAddress"].lower(), "interface": l3, "port": port,
                        "age": None if age is None else _count(age), "dynamic": age is not None})
    if static != sum(1 for entry in entries if not entry["dynamic"]):
        raise unreadable()
    return entries


def _macs(data, tgt):
    unicast, multicast = data.get("unicastTable"), data.get("multicastTable")
    if (not isinstance(unicast, dict) or not isinstance(unicast.get("tableEntries"), list)
            or not isinstance(multicast, dict) or multicast.get("tableEntries") != []):
        raise unreadable()
    entries = []
    for row in unicast["tableEntries"]:
        if not isinstance(row, dict):
            raise unreadable()
        digits = row.get("macAddress")
        address = mac(digits) if isinstance(digits, str) else None
        vlan, kind, port = row.get("vlanId"), row.get("entryType"), row.get("interface")
        moved = row.get("lastMove")
        if (address != tgt.value or isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094
                or not isinstance(kind, str) or not isinstance(port, str) or not port
                or (moved is not None and (isinstance(moved, bool) or not isinstance(moved, (int, float))))):
            raise unreadable()
        entries.append({"mac": address, "vlan": str(vlan), "port": port, "dynamic": kind == "dynamic",
                        "type": kind, "last_move": moved})
    return entries


def _bgp(data, tgt):
    vrfs = data.get("vrfs")
    if not isinstance(vrfs, dict) or not isinstance(vrfs.get(DEFAULT_VRF), dict):
        raise unreadable()
    peers = vrfs[DEFAULT_VRF].get("peerList")
    if not isinstance(peers, list) or len(peers) > 1:
        raise unreadable()
    if not peers:
        return None
    peer = peers[0]
    try:
        if not isinstance(peer, dict) or str(ipaddress.ip_address(peer["peerAddress"])) != tgt.value:
            raise unreadable()
        out = peer["outMessageStats"]
        capability = peer["neighborCapabilities"]["routeRefreshCap"]
        state, event, asn = peer["state"], peer["lastEvent"], peer["asn"]
        if not all(isinstance(value, str) for value in (state, event, asn)) or not isinstance(capability, dict):
            raise unreadable()
        counters = {name: _count(out[field]) for name, field in (
            ("route_refreshes", "rtRefreshes"), ("begin_refreshes", "beginOfRtRefreshes"), ("updates", "updates"))}
        return {"peer": tgt.value, "vrf": DEFAULT_VRF, "asn": asn, "state": state,
                "transitions": _count(peer["establishedTransitions"]), "last_event": event,
                "route_refresh": capability.get("enabled") is True, "counters": counters}
    except (KeyError, TypeError, ValueError):
        raise unreadable() from None


def observation(table, tgt, text):
    if table == COUNTERS:
        return _counters(text, tgt.value)
    data = _json(text)
    if table == BGP:
        peer = _bgp(data, tgt)
        return {"scope": tgt.scope, "target": tgt.value, "vrf": tgt.vrf, "neighbor": peer}
    entries = (_macs(data, tgt) if table == MAC else
               neighbor_entries(data, "ipV4Neighbors" if table == ARP else "ipV6Neighbors", address_filter=tgt.value))
    return {"scope": tgt.scope, "target": tgt.value, "vrf": tgt.vrf,
            "entries": sorted(entries, key=lambda entry: tuple(str(value) for value in entry.values()))}


def config_digest(text):
    """What the clear must not change: the running configuration."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# the readback of the counters: they fell, or stay within what a few control frames can add before the read
COUNTER_TOLERANCE_PACKETS = 64
COUNTER_TOLERANCE_BYTES = COUNTER_TOLERANCE_PACKETS * 1522
CLEARING_ALLOWANCE_SECONDS = 2
AGE_ALLOWANCE_SECONDS = 2
# the message counters of a BGP neighbor follow the refresh with a delay (measured live: the first read right after the
# command still showed the old begin-of-refresh counter of a soft out), so the readback asks again for a few seconds
BGP_READBACK_ATTEMPTS = 6
BGP_READBACK_WAIT_SECONDS = 2


def _cleared(name, before, after):
    limit = COUNTER_TOLERANCE_BYTES if name.endswith("bytes") else COUNTER_TOLERANCE_PACKETS
    return after < before or after <= limit


def _core(entry):
    """The entry without what moves on its own: age and the learning time."""
    return {name: value for name, value in entry.items() if name not in ("age", "last_move")}


def _unselected_mac_entries(entries, vlan):
    # A dynamic entry can move ports without a clear. Keep requiring its presence in the same VLAN.
    return sorted((entry["vlan"], entry["type"], "" if entry["dynamic"] else entry["port"])
                  for entry in entries if entry["vlan"] != vlan or not entry["dynamic"])


def stable(state):
    """The state bound into plan_sha256: without counters, ages and learning times (they move on their own)."""
    if not isinstance(state, dict):
        return state
    state = {name: value for name, value in state.items() if name not in ("counters", "clearing")}
    if "entries" in state:
        state["entries"] = [_core(entry) for entry in state["entries"]]
    if state.get("neighbor"):
        state["neighbor"] = {name: value for name, value in state["neighbor"].items()
                             if name not in ("counters", "last_event")}
    return state


def _selected(before, tgt_vlan):
    return [entry for entry in before["entries"] if entry["dynamic"] and (tgt_vlan is None or entry["vlan"] == tgt_vlan)]


def prediction(table, tgt, before):
    """(state after the clear, the lines of the preview that name its scope, the command that is sent)."""
    if table == COUNTERS:
        zero = dict.fromkeys(COUNTER_NAMES, 0)
        return (dict(before, counters=zero, clearing=0),
                ["port %s: all %d traffic counters are reset" % (tgt.value, len(COUNTER_NAMES))], tgt.write)
    if table == BGP:
        neighbor = before["neighbor"]
        if neighbor is None:
            raise Rejected(["the BGP neighbor does not exist in the default VRF"], reason_codes=["clear_no_entry"])
        if neighbor["state"] != "Established":
            raise Rejected(["the BGP neighbor is not Established"], reason_codes=["clear_no_entry"])
        if tgt.direction == "in" and not neighbor["route_refresh"]:
            raise Rejected(["the BGP neighbor does not support route refresh, soft in cannot be proven"],
                           reason_codes=["clear_invalid_target"])
        return (dict(before), ["BGP neighbor %s (AS %s): soft %s refresh, the session stays Established"
                               % (tgt.value, neighbor["asn"], tgt.direction)], tgt.write)
    entries = before["entries"]
    dynamic = _selected(before, tgt.vlan) if table == MAC else [entry for entry in entries if entry["dynamic"]]
    if not dynamic:
        raise Rejected(["the selected scope has no learned entry to clear"], reason_codes=["clear_no_entry"])
    if len(dynamic) != 1:
        raise Rejected(["the selected address matches multiple learned entries; name the VLAN" if table == MAC
                        else "the selected address matches multiple learned entries"],
                       reason_codes=["clear_ambiguous_entry"])
    chosen = dynamic[0]
    if table == MAC:
        command = "clear mac address-table dynamic vlan %s address %s" % (chosen["vlan"], tgt.value)
        remaining = [entry for entry in entries if entry is not chosen]
        scope = ["MAC address %s in VLAN %s: the learned (dynamic) entry on %s is cleared, %d other entries stay"
                 % (tgt.value, chosen["vlan"], chosen["port"], len(remaining))]
        return dict(before, vlan=chosen["vlan"], entries=remaining), scope, command
    if len(entries) != 1:
        raise Rejected(["the selected address has other entries that the clear could remove"],
                       reason_codes=["clear_ambiguous_entry"])
    if table == ND:
        if tgt.interface is not None and tgt.interface != chosen["interface"]:
            raise Rejected(["the IPv6 neighbor is learned on %s, not on %s" % (chosen["interface"], tgt.interface)],
                           reason_codes=["clear_invalid_target"])
        command = "clear ipv6 neighbors %s%s %s" % ("" if tgt.vrf == DEFAULT_VRF else "vrf %s " % tgt.vrf,
                                                    chosen["interface"], tgt.value)
    else:
        command = tgt.write
    scope = ["%s %s: the learned (dynamic) entry on %s is cleared, 0 other entries stay"
             % (table, tgt.key, chosen["interface"])]
    return dict(before, entries=[]), scope, command


def readback(plan, observed, elapsed=0, *, since_send=None):
    """What the clear guarantees, not an idle table. Counters: the line `Last clearing of ... counters` names a time
    that is not older than the command was (a stale or unchanged clearing time is a failure) and no counter grew
    beyond what a few control frames add. MAC, ARP and ND: the selected entry is gone, or learned again by live
    traffic (marked `relearned`): a MAC entry with a newer learning time, an ARP or ND entry younger than an untouched
    entry would be (its age before the clear plus the elapsed seconds, less a 2 s allowance); every other entry of the
    scope stays. BGP: the session stayed Established with the same number of transitions and the counter of the
    message the refresh sends grew. Returns (matches, readback)."""
    before = plan["predicted"]["before"]
    if plan["table"] == COUNTERS:
        old, new = before["counters"], observed["counters"]
        age, previous = observed["clearing"], before["clearing"]
        unchanged_nonzero = any(old[name] for name in COUNTER_NAMES) and all(old[name] == new[name]
                                                                             for name in COUNTER_NAMES)
        return (observed["port"] == before["port"] and observed["link"] == before["link"]
                and age is not None and since_send is not None and age <= since_send + CLEARING_ALLOWANCE_SECONDS
                and (previous is None or age < previous) and not unchanged_nonzero
                and all(_cleared(name, old[name], new[name]) for name in COUNTER_NAMES)), observed
    if plan["table"] == BGP:
        return _bgp_readback(plan, before, observed), observed
    scope = all(observed[name] == before[name] for name in ("scope", "target", "vrf"))
    if plan["table"] == MAC:
        removed = plan["predicted"]["after"]["vlan"]
        old = next(entry for entry in before["entries"] if entry["dynamic"] and entry["vlan"] == removed)
        kept = _unselected_mac_entries(before["entries"], removed)
        seen = _unselected_mac_entries(observed["entries"], removed)
        entries, younger = [], True
        for entry in observed["entries"]:
            relearned = False
            if entry["vlan"] == removed and entry["dynamic"]:
                relearned = (entry["last_move"] is not None and old["last_move"] is not None
                             and entry["last_move"] > old["last_move"])
                younger = younger and relearned
            entries.append(dict(entry, relearned=relearned))
        return scope and seen == kept and younger, dict(observed, entries=entries)
    old = before["entries"][0]
    entries, younger = [], True
    for entry in observed["entries"]:
        relearned = (entry["dynamic"] and entry["age"] is not None and old["age"] is not None
                     and entry["age"] < old["age"] + elapsed - AGE_ALLOWANCE_SECONDS)
        younger = younger and relearned
        entries.append(dict(entry, relearned=relearned))
    return scope and younger, dict(observed, entries=entries)


def _bgp_readback(plan, before, observed):
    old, new = before["neighbor"], observed["neighbor"]
    if new is None or not all(observed[name] == before[name] for name in ("scope", "target", "vrf")):
        return False
    if (new["asn"] != old["asn"] or new["state"] != "Established" or new["transitions"] != old["transitions"]):
        return False
    before_counters, after_counters = old["counters"], new["counters"]
    if plan["commands"][0].endswith(" soft in"):
        return after_counters["route_refreshes"] > before_counters["route_refreshes"]
    return (after_counters["begin_refreshes"] > before_counters["begin_refreshes"]
            or (after_counters["updates"] > before_counters["updates"]
                and new["last_event"] == "SoftResetOut" and old["last_event"] != "SoftResetOut"))
