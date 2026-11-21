"""Junos SRX preflight (platform capability, management path) and readback for the G143 profiles."""

from __future__ import annotations

import ipaddress
import re

from . import junos, junos_srx as srx
from .access import AccessError
from .errors import Rejected

CAPABILITY = "show security zones | no-more"
ZONE_ROW = re.compile(r"(Security zone|Functional zone): (\S+)")


def _unreadable(what):
    return Rejected(["Junos SRX %s readback is incomplete or unrecognised" % what],
                    reason_codes=["junos_srx_readback_unreadable"])


def _read_failure(exc, what):
    if isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("timeout", "timed out")):
        raise Rejected(["Junos SRX %s timed out" % what], reason_codes=["junos_srx_read_timeout"]) from None
    raise _unreadable(what) from None


def scoped_path(table, key):
    parts = key.split("@")
    if table == srx.ZONE:
        return "security zones security-zone " + key
    if table == srx.ADDRESS:
        return "security address-book global address " + key
    if table == srx.ADDRESS_SET:
        return "security address-book global address-set " + key
    if table == srx.POLICY:
        return "security policies from-zone %s to-zone %s policy %s" % tuple(parts)
    if table == srx.NAT_POOL:
        return "security nat destination pool " + key
    return srx.NAT[table] + parts[0]


def capability(access):
    """The device must know the `security` hierarchy: SRX answers `show security zones`, a switch refuses it."""
    text = access.query(CAPABILITY)
    if junos.refused_answer(text) is not None:
        raise Rejected(["the device has no security zones (show security zones is refused); the SRX profiles apply "
                        "to Junos SRX only"], reason_codes=["junos_srx_unsupported"])
    if "---(more" in text.lower():
        raise _unreadable("capability")
    return text


def _flow_ingress(access, peer, address, port):
    query = (f"show security flow session source-prefix {peer}/{peer.max_prefixlen} "
             f"destination-prefix {address}/{address.max_prefixlen} destination-port {port} protocol tcp | no-more")
    answer = access.query(query)
    if junos.refused_answer(answer) is not None or "(more" in answer.lower():
        raise ValueError("unreadable SSH flows")
    blocks = [block for block in re.split(r"(?m)^[ \t]+(?=(?:In|Out):)", answer) if block.startswith("In:")]
    totals = re.findall(r"(?m)^[ \t]*Total sessions: ([0-9]+)[ \t]*\r?$", answer)
    if not blocks or totals != [str(len(blocks))]:
        raise ValueError("missing or incomplete SSH flows")
    interfaces = set()
    for block in blocks:
        row = re.match(r"In: (\S+)/[0-9]+ --> (\S+)/([0-9]+);tcp,.*?\bIf: ([^,\s]+)", block, re.S)
        if (row is None or ipaddress.ip_address(row[1]) != peer or ipaddress.ip_address(row[2]) != address
                or row[3] != port or not srx.IFL.fullmatch(row[4])):
            raise ValueError("SSH flow does not identify its ingress interface")
        interfaces.add(row[4])
    return interfaces


def _interface_zones(snapshot):
    zones = {}
    for line in snapshot.lines:
        row = re.match(r"set security zones security-zone (\S+) interfaces (\S+)(?: |$)", line)
        if row:
            zones.setdefault(row[2], set()).add(row[1])
    return zones


def _management(access, device, plan, snapshot):
    from .exec_junos import SSH_CONNECTIONS, _interface_addresses, _ssh_connections

    table, key = plan["table"], plan["key"]
    if table == srx.POLICY:
        source, destination, _name = key.split("@")
        if "junos-host" not in (source, destination):
            return
    ports = {line.split()[-1] for line in snapshot.lines if re.fullmatch(r"set system services ssh port [0-9]+", line)}
    if len(ports) > 1:
        raise ValueError("ambiguous SSH port")
    port = next(iter(ports), "22")
    sockets = _ssh_connections(access.query(SSH_CONNECTIONS), port)
    if device.check_address and device.check_address != device.address:
        sockets.update(_ssh_connections(access.check_query(SSH_CONNECTIONS), port))
    if not sockets:
        raise ValueError("no management connection")
    terse = access.query("show interfaces terse | no-more")
    if not terse.startswith("Interface ") or "(more" in terse.lower():
        raise ValueError("invalid local interface addresses")
    local = _interface_addresses(terse)
    zones = _interface_zones(snapshot)
    ingress, endpoints = set(), set()
    for address, peer in sorted(sockets, key=lambda pair: (str(pair[0]), str(pair[1]))):
        if address not in local:
            raise ValueError("missing local SSH address")
        if all(srx.MANAGEMENT.fullmatch(ifl) for ifl in local[address]):
            continue
        endpoints.update(local[address])
        ingress.update(_flow_ingress(access, peer, address, port))
    if any(len(zones.get(ifl, ())) != 1 for ifl in ingress):
        raise ValueError("missing or ambiguous SSH ingress zone")
    if table == srx.POLICY:
        if any(zones[ifl] & {source, destination} for ifl in ingress):
            raise Rejected(["the self-traffic policy intersects an SSH management zone"],
                           reason_codes=["junos_srx_management"])
        return
    after = plan["predicted"]["after"] or {}
    kept = set(after.get("interfaces", "").split())
    services = set(after.get("host-inbound-services", "").split())
    for ifl in sorted(ingress | endpoints):
        if key in zones.get(ifl, ()) and (ifl not in kept or not services & {"ssh", "all"}):
            raise Rejected(["the change would cut the management connection through %s in zone %s" % (ifl, key)],
                           reason_codes=["junos_srx_management"])


def prechecks(access, device, plan, snapshot_text):
    table = plan["table"]
    try:
        capability(access)
        if table in (srx.ZONE, srx.POLICY):
            _management(access, device, plan, junos.load(snapshot_text, plan["firmware"]))
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "preflight")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise Rejected(["the Junos management path could not be established"],
                       reason_codes=["junos_srx_readback_unreadable"]) from None
    plan["prechecks"].append("the device has the security hierarchy; the management connection stays in its zone"
                             if table == srx.ZONE else "the device has the security hierarchy")
    return []


def _zone_interfaces(text, key):
    rows = [row.rstrip() for row in junos.answer_rows(text)]
    if not rows or ZONE_ROW.fullmatch(rows[0].strip()) is None or ZONE_ROW.fullmatch(rows[0].strip())[2] != key:
        raise ValueError("zone identity")
    bound = [row.split(":", 1)[1].strip() for row in rows if row.strip().startswith("Interfaces bound:")]
    marker = [index for index, row in enumerate(rows) if row.strip() == "Interfaces:"]
    if len(bound) != 1 or len(marker) != 1 or not bound[0].isdigit():
        raise ValueError("zone interface summary")
    names = [row.strip() for row in rows[marker[0] + 1:]]
    if len(names) != int(bound[0]) or not all(srx.IFL.fullmatch(name) for name in names):
        raise ValueError("zone interface list")
    return " ".join(sorted(names))


def observe(access, plan, operational):
    from .exec_junos import _check_identity, _read

    table, key = plan["table"], plan["key"]
    try:
        rows = [row for row in junos.answer_rows(_read(
            access, "show configuration %s | display set | no-more" % scoped_path(table, key))) if row.strip()]
        if any(not row.startswith("set security ") for row in rows):
            raise _unreadable("configuration")
        names = [row for row in junos.answer_rows(_read(access, "show configuration system host-name | display set"))
                 if row.strip()]
        _check_identity(access, names)
        scoped = junos.load("set version %s\n" % plan["firmware"] + "".join(row + "\n" for row in rows), None)
        entry = srx.entries(scoped, table).get(key)
        if entry is None:
            # a NAT rule-set read also holds the other rules of the set
            rule = " rule %s " % key.split("@")[-1]
            if any(rule in row + " " for row in rows) if table in srx.NAT else rows:
                raise _unreadable("configuration")
            return None
        if entry.unsupported:
            raise _unreadable("configuration of the object")
        if table == srx.ZONE:
            # The check account confirms the interfaces the zone really holds (show security zones <zone>).
            seen = _zone_interfaces(access.check_query("show security zones %s" % key), key)
            if seen != entry.attributes.get("interfaces", ""):
                raise _unreadable("zone interfaces")
        return dict(entry.attributes)
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "readback")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise _unreadable("operational") from None
