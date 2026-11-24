"""Targeted operational clear on Junos ELS (1.0.12 junos targeted clear: J34 counters, J35 MAC, J36 ARP/ND, J37 BGP refresh).

A clear changes no configuration and has no undo. It follows the clear flow of ExtremeXOS (engine.build_clear_plan,
execute._execute_clear): live preview, the approved plan_sha256, one command for exactly one object, readback against
the state BEFORE the command, no safeguard. Measured on vJunos-switch 26.2R1.7 (ref: private measurement record):

* the commands differ from the first notes of the plan: the MAC is positional ("clear ethernet-switching table
  <mac>", the keyword "address" is read as a MAC and refused) and the IPv6 neighbor needs the keyword host
  ("clear ipv6 neighbors host <ipv6>"); "clear arp hostname <ip>" answers "<ip>  deleted";
* the counters of a port: "Statistics last cleared: Never" turns into a time stamp, the traffic counters fall;
* a MAC and an ARP entry did NOT come back by themselves on a quiet host (no immediate relearning as on NX-OS), a
  relearned MAC shows a later "Time:" in "show ethernet-switching table <mac> extensive", a relearned ARP entry
  a larger "TTE" (seconds before expiry) than before the clear;
* BGP is not running on the lab switch (no licence): the answers of the BGP and ND readbacks are adapted from the
  Juniper CLI Reference (derived fixtures, PROVENANCE.md of tests/fixtures/junos_g146); an unrecognised line is
  clear_readback_unreadable, never a success. Junos does not clear a neighbor in the reachable state (documented), so
  such an ND entry is refused as nothing to clear.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from netops_admin import junos
from netops_admin.errors import Rejected

PORT_COUNTERS, FDB, ARP, ND, BGP = "port-counters", "fdb", "arp", "neighbor-discovery", "bgp-neighbor-refresh"
TABLES = (PORT_COUNTERS, FDB, ARP, ND, BGP)
FIRMWARE = ("26.2R1.7",)
KIND = "junos-clear"
MAC_TEXT = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
BGP_MODES = ("soft-inbound", "soft")
COUNTER_NAMES = ("input_bytes", "output_bytes", "input_packets", "output_packets")
# counters that were small before the clear may count control traffic sent between the clear and the readback
TOLERANCE_PACKETS = 64
TOLERANCE_BYTES = TOLERANCE_PACKETS * 1522
NOT_CLEARED = "not cleared since the start"


@dataclass(frozen=True)
class ClearTarget:
    table: str
    key: str
    read: str
    write: str
    mode: str | None = None


def _invalid(why):
    return Rejected([why], reason_codes=["clear_invalid_target"])


def clear_target(table: str, key: str, changes: dict) -> ClearTarget:
    """Render only the documented selectors of one object; everything else is refused before the device is read."""
    if table not in TABLES:
        raise _invalid("clear on Junos takes port-counters, fdb, arp, neighbor-discovery or bgp-neighbor-refresh")
    if table == BGP:
        if set(changes) != {"mode"} or changes["mode"] not in BGP_MODES:
            raise _invalid("a BGP refresh needs changes {\"mode\": \"soft-inbound\" or \"soft\"}")
    elif changes:
        raise _invalid("this clear takes no changes")
    if table == PORT_COUNTERS:
        if not junos.PHYSICAL.fullmatch(key):
            raise _invalid("clear counters takes one physical Ethernet port such as ge-0/0/1")
        return ClearTarget(table, key, "show interfaces %s extensive | no-more" % key,
                           "clear interfaces statistics %s" % key)
    if table == FDB:
        if not MAC_TEXT.fullmatch(key) or int(key[:2], 16) & 1 or key.lower() == "00:00:00:00:00:00":
            raise _invalid("clear fdb takes one unicast MAC address")
        mac = key.lower()
        return ClearTarget(table, mac, "show ethernet-switching table %s extensive | no-more" % mac,
                           "clear ethernet-switching table %s" % mac)
    version = 6 if table == ND else 4
    ip = _plain_ip(key, version)
    if table == ARP:
        return ClearTarget(table, ip, "show arp no-resolve expiration-time hostname %s | no-more" % ip,
                           "clear arp hostname %s" % ip)
    if table == ND:
        return ClearTarget(table, ip, "show ipv6 neighbors host %s | no-more" % ip,
                           "clear ipv6 neighbors host %s" % ip)
    return ClearTarget(table, _plain_ip(key, None), "show bgp neighbor %s | no-more" % _plain_ip(key, None),
                       "clear bgp neighbor %s %s" % (_plain_ip(key, None), changes["mode"]), changes["mode"])


def _plain_ip(key, version) -> str:
    try:
        ip = ipaddress.ip_address(key)
    except ValueError:
        raise _invalid("clear requires one plain IP address") from None
    if (ip.version == 6 and ip.scope_id is not None) or ip.compressed != key.lower():
        raise _invalid("clear requires one plain IP address")
    if (version is not None and ip.version != version) or ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise _invalid("clear requires one unicast IPv%d address" % (version or ip.version))
    return str(ip)


def _unreadable(what="the readback of the clear target"):
    return Rejected(["%s is incomplete or unrecognised" % what], reason_codes=["clear_readback_unreadable"])


def _rows(text: str) -> list:
    return junos.answer_rows(text)


def _checked(text: str) -> list:
    rows = _rows(text)
    if any(junos.ERROR.match(row.strip()) or row.strip().lower().startswith("warning: ") and "license" not in row.lower()
           for row in rows):
        raise _unreadable()
    if any("(more" in row.lower() for row in rows):
        raise _unreadable()
    return rows


# ---- port counters (show interfaces <if> extensive) ----

PHYSICAL_ROW = re.compile(r"^Physical interface: (\S+), (Enabled|Disabled), Physical link is (Up|Down)\s*$")
CLEARED_ROW = re.compile(r"^\s+Statistics last cleared: (Never|([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) UTC"
                         r" \([^()]*ago\))\s*$")
COUNTER_ROW = re.compile(r"^\s+(Input|Output)\s+(bytes|packets)\s*:\s+([0-9]+)\s+[0-9]+ (?:bps|pps)\s*$")


def counters_observation(text: str, port: str) -> dict:
    for row in _rows(text):
        if row.strip() == "error: device %s not found" % port:
            raise Rejected(["interface %s does not exist on the switch" % port], reason_codes=["port_missing"])
    rows = _checked(text)
    head = PHYSICAL_ROW.match(rows[0]) if rows else None
    if head is None or head[1] != port:
        raise _unreadable()
    physical = []
    for row in rows[1:]:
        if row.lstrip().startswith("Logical interface"):
            break
        physical.append(row)
    cleared = [CLEARED_ROW.match(row) for row in physical]
    cleared = [match for match in cleared if match]
    start = next((index for index, row in enumerate(physical) if row.strip() == "Traffic statistics:"), None)
    if len(cleared) != 1 or start is None:
        raise _unreadable()
    found = [COUNTER_ROW.match(row) for row in physical[start + 1:start + 5]]
    if None in found or [(m[1], m[2]) for m in found] != [("Input", "bytes"), ("Output", "bytes"),
                                                           ("Input", "packets"), ("Output", "packets")]:
        raise _unreadable()
    return {"port": port, "admin": head[2].lower(), "link": head[3].lower(),
            "cleared": NOT_CLEARED if cleared[0][1] == "Never" else cleared[0][2],
            "counters": dict(zip(COUNTER_NAMES, (int(match[3]) for match in found)))}


# ---- learned MAC (show ethernet-switching table <mac> extensive) ----

def fdb_observation(text: str, mac: str) -> dict:
    rows = _checked(text)
    entries, current = [], None
    for row in rows:
        stripped = row.strip()
        if stripped.startswith("MAC address:"):
            if stripped.split(":", 1)[1].strip().lower() != mac:
                raise _unreadable()
            current = {}
            entries.append(current)
        elif current is None:
            raise _unreadable()
        elif (found := re.fullmatch(r"VLAN name: (\S+), VLAN ID: ([0-9]+)", stripped)):
            current["vlan"] = found[1]
        elif stripped.startswith("Learning interface:"):
            current["interface"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("MAC flags:"):
            current["flags"] = stripped.split(":", 1)[1].strip()
        elif (found := re.fullmatch(r"Time: ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) UTC", stripped)):
            current["learned"] = found[1]
    result = []
    for entry in entries:
        if not {"vlan", "interface", "flags"} <= set(entry):
            raise _unreadable()
        tokens = set(re.split(r"[ ,]+", entry["flags"]))
        dynamic = "D" in tokens and tokens <= {"D", "L", "SE"}
        if dynamic and "learned" not in entry:
            raise _unreadable()
        result.append({"vlan": entry["vlan"], "interface": entry["interface"], "dynamic": dynamic,
                       "learned": entry.get("learned", "")})
    return {"mac": mac, "entries": sorted(result, key=lambda entry: (entry["vlan"], entry["interface"]))}


# ---- ARP (show arp no-resolve expiration-time hostname <ip>) ----

ARP_HEADER = ["MAC", "Address", "Address", "Interface", "TTE", "Flags"]
ARP_ROW = re.compile(r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(\S+)\s+(\S+)(?: \[(\S+)\])?\s+(?:([0-9]+)\s+)?(\S+)\s*$")


def arp_observation(text: str, ip: str) -> dict:
    rows = _checked(text)
    footer = [row for row in rows if row.startswith("Total entries:")]
    rows = [row for row in rows if not row.startswith("Total entries:")]
    entries = []
    if rows:
        if rows[0].split() != ARP_HEADER:
            raise _unreadable()
        for row in rows[1:]:
            found = ARP_ROW.match(row)
            if found is None or found[2] != ip:
                raise _unreadable()
            entries.append({"mac": found[1], "interface": found[3], "port": found[4] or "",
                            "dynamic": found[6] == "none" and found[5] is not None,
                            "tte": int(found[5]) if found[5] is not None else -1})
    if footer and footer != ["Total entries: %d" % len(entries)]:
        raise _unreadable()
    return {"ip": ip, "entries": sorted(entries, key=lambda entry: (entry["interface"], entry["mac"]))}


# ---- IPv6 neighbor (show ipv6 neighbors host <ipv6>; derived from the CLI Reference) ----

ND_HEADER = ["IPv6", "Address", "Linklayer", "Address", "State", "Exp", "Rtr", "Secure", "Interface"]
ND_STATES = ("reachable", "stale", "delay", "probe", "incomplete", "unreachable", "down", "up")


def nd_observation(text: str, ip: str) -> dict:
    rows = _checked(text)
    footer = [row for row in rows if row.startswith("Total entries:")]
    rows = [row for row in rows if not row.startswith("Total entries:")]
    entries = []
    if rows:
        if rows[0].split() != ND_HEADER:
            raise _unreadable()
        for row in rows[1:]:
            fields = row.split()
            try:
                address = str(ipaddress.ip_address(fields[0]))
            except (ValueError, IndexError):
                raise _unreadable() from None
            if len(fields) != 7 or address != ip or fields[2] not in ND_STATES or not fields[3].isdigit():
                raise _unreadable()
            entries.append({"mac": fields[1].lower(), "state": fields[2], "interface": fields[6],
                            "port": "", "dynamic": True})
    if footer and footer != ["Total entries: %d" % len(entries)]:
        raise _unreadable()
    return {"ip": ip, "entries": sorted(entries, key=lambda entry: (entry["interface"], entry["mac"]))}


# ---- BGP neighbor (show bgp neighbor <ip>; derived from the CLI Reference, BGP is unlicensed on the lab switch) ----

BGP_LICENSE = "Warning: License key missing; requires 'BGP' license"
BGP_PEER = re.compile(r"^Peer: (\S+?)(?:\+[0-9]+)?\s+AS ([0-9]+)\s+Local:", re.MULTILINE)
BGP_STATES = ("Idle", "Active", "Connect", "OpenSent", "OpenConfirm", "Established")


def bgp_observation(text: str, ip: str):
    """None when BGP is not running; otherwise the state, the flap counter and the message counters of the peer."""
    rows = [row for row in _rows(text) if row.strip() != BGP_LICENSE]
    answer = "\n".join(rows)
    if answer.strip() == "BGP is not running":
        return None
    if not rows or junos.refused_answer(answer) or "(more" in answer.lower():
        raise _unreadable()
    peers = list(BGP_PEER.finditer(answer))
    if len(peers) != 1 or str(ipaddress.ip_address(peers[0][1])) != ip:
        raise _unreadable()
    if not re.search(r"^\s*Group:\s*\S+\s+Routing-Instance:\s*master\s*$", answer, re.MULTILINE):
        raise _unreadable()
    state = re.findall(r"(?<!Last )\bState:\s*(%s)\b" % "|".join(BGP_STATES), answer)
    flaps = re.findall(r"^\s*Number of flaps:\s*([0-9]+)\s*$", answer, re.MULTILINE)
    output = re.findall(r"^\s*Output messages:\s+Total\s+([0-9]+)\s+Updates\s+([0-9]+)\s+Refreshes\s+([0-9]+)\s+Octets\s+[0-9]+\s*$",
                        answer, re.MULTILINE)
    advertised = re.findall(r"^\s*Advertised prefixes:\s*([0-9]+)\s*$", answer, re.MULTILINE)
    if len(state) != 1 or len(flaps) != 1 or len(output) != 1:
        raise _unreadable()
    return {"peer": ip, "state": state[0], "flaps": int(flaps[0]),
            "refresh_capable": "Peer supports Refresh capability" in answer,
            "advertised": sum(map(int, advertised)),
            "output_updates": int(output[0][1]), "output_refreshes": int(output[0][2])}


# ---- the plan: prediction, scope, readback ----

def observe(table: str, target: ClearTarget, text: str):
    if table == PORT_COUNTERS:
        return counters_observation(text, target.key)
    if table == FDB:
        return fdb_observation(text, target.key)
    if table == ARP:
        return arp_observation(text, target.key)
    if table == ND:
        return nd_observation(text, target.key)
    return bgp_observation(text, target.key)


def prediction(table: str, target: ClearTarget, before: dict):
    """(after, scope texts); the refusals that need no device are raised here."""
    if table == PORT_COUNTERS:
        after = dict(before, cleared="a new time stamp after the clear", counters=dict.fromkeys(COUNTER_NAMES, 0))
        return after, ["port %s: the traffic counters are reset (last cleared now: %s)" % (target.key, before["cleared"])]
    if table == BGP:
        if before is None:
            raise Rejected(["BGP is not running on the switch, so peer %s has nothing to refresh" % target.key],
                           reason_codes=["clear_no_entry"])
        if before["state"] != "Established":
            raise Rejected(["BGP peer %s is %s; a route refresh needs an established session" % (target.key, before["state"])],
                           reason_codes=["clear_no_entry"])
        if target.mode == "soft-inbound" and not before["refresh_capable"]:
            raise Rejected(["BGP peer %s does not report the Refresh capability" % target.key],
                           reason_codes=["clear_no_entry"])
        if target.mode == "soft" and not before["advertised"]:
            raise Rejected(["BGP peer %s has no advertised prefix to send again" % target.key],
                           reason_codes=["clear_no_entry"])
        return dict(before), ["peer %s stays established (%d flaps); %s sends %s" % (
            target.key, before["flaps"], target.mode,
            "a route refresh and re-evaluates the import policy" if target.mode == "soft-inbound"
            else "all routes to the peer again after the export policy")]
    entries = before["entries"]
    dynamic = [entry for entry in entries if entry["dynamic"]]
    if not dynamic:
        raise Rejected(["the selected address has no learned (dynamic) entry to clear"], reason_codes=["clear_no_entry"])
    if len(entries) != 1:
        raise Rejected(["the selected address matches %d entries (other VLANs, instances or static entries)" % len(entries)],
                       reason_codes=["clear_ambiguous_entry"])
    if table == ND and dynamic[0]["state"] == "reachable":
        raise Rejected(["Junos does not clear a neighbor in the reachable state; nothing would change"],
                       reason_codes=["clear_no_entry"])
    after = dict(before, entries=[])
    return after, ["%s %s: 1 learned entry on %s will be cleared" % (table, target.key, dynamic[0]["interface"])]


def stable(table: str, state):
    """The part of a state that the plan digest binds: what changes by itself between the preview and the apply
    (counters, time stamps, TTE, message counters) is left out."""
    if state is None:
        return None
    if table == PORT_COUNTERS:
        return {name: state[name] for name in ("port", "admin", "link")}
    if table == BGP:
        return {name: state[name] for name in ("peer", "state", "flaps", "refresh_capable")}
    if table == ARP:
        return {"ip": state["ip"], "entries": [{k: v for k, v in entry.items() if k != "tte"} for entry in state["entries"]]}
    return state


def _counter_cleared(name, before, after) -> bool:
    limit = TOLERANCE_BYTES if name.endswith("bytes") else TOLERANCE_PACKETS
    return after < before or after <= limit


def readback(plan, observed):
    """(matches, readback): the proof is relative to the state BEFORE the command, never an idle table alone."""
    table, before = plan["table"], plan["predicted"]["before"]
    if table == PORT_COUNTERS:
        return (observed["port"] == before["port"] and observed["link"] == before["link"]
                and observed["cleared"] != before["cleared"] and observed["cleared"] != NOT_CLEARED
                and all(_counter_cleared(name, before["counters"][name], observed["counters"][name])
                        for name in COUNTER_NAMES)), observed
    if table == BGP:
        mode = plan["commands"][0].rsplit(" ", 1)[1]
        # The general UPDATE count cannot distinguish an outbound clear from ordinary advertisements.
        return (mode == "soft-inbound" and observed is not None and observed["state"] == "Established"
                and observed["flaps"] == before["flaps"]
                and observed["output_refreshes"] > before["output_refreshes"]), observed
    if table in (ARP, ND):
        # Entry lifetimes and reachability also change during ordinary protocol activity.
        return bool(before["entries"]) and not observed["entries"], observed
    entries = []
    for entry in observed["entries"]:
        old = before["entries"][0]
        fresh = entry["dynamic"] and entry["vlan"] == old["vlan"] and entry["learned"] > old["learned"]
        entries.append(dict(entry, relearned=True) if fresh else dict(entry, relearned=False, status="incomplete"))
    return all(entry["relearned"] for entry in entries) and len(entries) <= 1, dict(observed, entries=entries)
