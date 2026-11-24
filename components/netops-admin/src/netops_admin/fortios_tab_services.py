"""1.0.13 A1-S FortiOS tables (system dhcp server, system dhcp server/ip-range, system dns, log syslogd setting).

Registered in fortios_tables.MODULES as TABLES = {table: TableHooks(...)}. The shared code (engine, execute,
exec_fortios, fortios) plans, renders, reads back and returns the changes; this module adds what is particular to the
services (design A, sections 1-3):

- the attributes Admin never manages (excluded): DDNS with its TSIG key, DHCP options, VCI matching, TFTP and boot
  file of a DHCP server; DNS over TLS/HTTPS, its certificate and host name, FQDN cache, source address of DNS; syslog
  over TLS, its certificate, custom fields and interface binding. A plan refuses any change, by attribute name only,
  when an object it reads carries one: the target, the parent server of a range and every DHCP server on the same
  interface (the overlap check reads them);
- DNS changes only while the effective protocol is cleartext, syslog only while it does not run over TLS;
- a DHCP address range lies inside the subnet of its interface and the netmask of its server, holds neither the
  network, broadcast, interface nor gateway address, overlaps no other range on that interface and no VIP or IP pool
  address (fortios_dhcp_range_conflict);
- a DHCP server is deleted only disabled and without ranges or reservations; the last range of an enabled server is
  never deleted (fortios_dhcp_server_in_use);
- endpoint_impact (the key, "-" for a singleton) for every change of an enabled DHCP server or of its ranges, for
  enabling or disabling a server, for every change of the DNS servers, for disabling syslog or moving the target of an
  enabled syslog: its server, port or transport mode (fortios_service_impact_required). The profile updates neither
  port nor mode: on end FortiOS 7.6.8 asks to confirm a port other than the default of the mode, a question the Admin
  write does not answer (measured live), so the target moves by server only.

The undo of a stored plan skips the endpoint_impact requirement (the original change carried it) and the rule that an
apply never leaves system dns without a primary server (the undo returns exactly the state before), but keeps every
scope and conflict check. So the apply of a range update or delete also checks the range its undo would restore: a
conflict made outside Admin (a VIP over the range) refuses the change before the write, Admin never confirms a change
its stored plan cannot return.
"""
from __future__ import annotations

import ipaddress

from netops_admin import fortios
from netops_admin.errors import Rejected
from netops_admin.fortios_tables import TableHooks

SERVER = "system dhcp server"
RANGE = "system dhcp server/ip-range"
DNS = "system dns"
SYSLOG = "log syslogd setting"
CHILDREN = ("ip-range", "reserved-address")

DHCP_EXCLUDED = ("ddns-*", "options", "vci-*", "tftp-server", "filename")
DNS_EXCLUDED = ("ssl-certificate", "dns-over-tls", "server-hostname", "fqdn-*", "source-ip")
SYSLOG_EXCLUDED = ("certificate", "enc-algorithm", "ssl-min-proto-version", "custom-field-name", "interface")
DNS_SERVERS = ("primary", "secondary", "ip6-primary", "ip6-secondary")
SYSLOG_TARGET = ("server", "port", "mode")

SCOPE = "fortios_service_scope"
IMPACT = "fortios_service_impact_required"
CONFLICT = "fortios_dhcp_range_conflict"
IN_USE = "fortios_dhcp_server_in_use"
SERVICE = dict(preview_code="fortios_service_preview_required", readback_code="fortios_service_readback_unreadable")


def _refuse(reason: str, code: str) -> Rejected:
    return Rejected([reason], reason_codes=[code])


def _effective(profile, state, name):
    """The value FortiOS applies: the shown value, else the measured default of the profile."""
    if state and name in state:
        return state[name]
    attribute = profile.attributes.get(name)
    return None if attribute is None else attribute.default


def _changed(before, after) -> set:
    before, after = before or {}, after or {}
    return {name for name in set(before) | set(after) if before.get(name) != after.get(name)}


def _address(text):
    try:
        return ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return None


def _servers(snapshot) -> dict:
    return snapshot.root.section(SERVER).entries if snapshot.root.section(SERVER) is not None else {}


def _ranges(node) -> dict:
    """The address ranges of a parsed DHCP server: range id -> (start, end) (None for an unreadable bound)."""
    section = node.section("ip-range")
    if section is None:
        return {}
    return {rid: (_address(entry.value("start-ip", "")), _address(entry.value("end-ip", "")))
            for rid, entry in section.entries.items()}


def _reservations(node) -> list:
    section = node.section("reserved-address")
    return [] if section is None else [_address(entry.value("ip", "")) for entry in section.entries.values()]


def _same_interface(snapshot, interface: str) -> dict:
    wanted = (interface or "").casefold()
    return {sid: node for sid, node in _servers(snapshot).items()
            if wanted and node.value("interface", "").casefold() == wanted}


def _interface(snapshot, name: str):
    """(interface address, interface network) of a static IPv4 interface of the snapshot; refused otherwise."""
    entry = (snapshot.entries(fortios.INTERFACE_TABLE) or {}).get(name)
    parts = [] if entry is None else entry.value("ip", "").split()
    if entry is None or entry.value("mode", "static") != "static" or len(parts) != 2:
        raise _refuse("interface %s has no static IPv4 subnet in the snapshot; the DHCP server needs one" % name, SCOPE)
    try:
        interface = ipaddress.IPv4Interface("%s/%s" % tuple(parts))
    except ValueError:
        raise _refuse("interface %s has no static IPv4 subnet in the snapshot; the DHCP server needs one"
                      % name, SCOPE) from None
    if interface.network.prefixlen >= 31:
        raise _refuse("interface %s has no host subnet for DHCP clients" % name, SCOPE)
    return interface.ip, interface.network


def _server_network(profile, state, address, network):
    """The client subnet of a server: the interface subnet, narrowed by the netmask of the server when it is set."""
    netmask = _effective(profile, state, "netmask")
    if not netmask or netmask == "0.0.0.0":
        return network
    try:
        served = ipaddress.IPv4Network("%s/%s" % (address, netmask), strict=False)
    except ValueError:
        raise _refuse("netmask %s is not a valid IPv4 netmask" % netmask, CONFLICT) from None
    if not served.subnet_of(network):
        raise _refuse("netmask %s reaches beyond the subnet %s of the interface" % (netmask, network), CONFLICT)
    return served


def _nat_addresses(snapshot) -> list:
    """(name, first, last) of the external VIP addresses and the IP pool ranges of the snapshot."""
    found = []
    for name, entry in (snapshot.entries("firewall vip") or {}).items():
        for text in entry.value("extip", "").split():
            first, _, last = text.partition("-")
            found.append(("VIP " + name, _address(first), _address(last or first)))
    for name, entry in (snapshot.entries("firewall ippool") or {}).items():
        first = entry.value("startip", "")
        found.append(("IP pool " + name, _address(first), _address(entry.value("endip", "") or first)))
    return [item for item in found if item[1] is not None and item[2] is not None]


def _check_range(snapshot, profile_server, server_state, server_id, rid, start, end) -> None:
    """Design A 3: the range lies inside the client subnet of its server, holds no network, broadcast, interface or
    gateway address, overlaps no other range on the same interface and no VIP or IP pool address."""
    interface = (server_state or {}).get("interface", "")
    address, network = _interface(snapshot, interface)
    served = _server_network(profile_server, server_state, address, network)
    if start is None or end is None or start > end:
        raise _refuse("range %s needs start-ip <= end-ip" % rid, CONFLICT)
    if start not in served or end not in served:
        raise _refuse("range %s - %s lies outside the subnet %s served on interface %s" % (start, end, served, interface),
                      CONFLICT)
    gateway = _address(_effective(profile_server, server_state, "default-gateway") or "")
    blocked = {served.network_address: "network", served.broadcast_address: "broadcast", address: "interface"}
    if gateway is not None and gateway != ipaddress.IPv4Address("0.0.0.0"):
        blocked.setdefault(gateway, "default gateway")
    for value, label in sorted(blocked.items()):
        if start <= value <= end:
            raise _refuse("range %s - %s holds the %s address %s" % (start, end, label, value), CONFLICT)
    for sid, node in sorted(_same_interface(snapshot, interface).items()):
        for other, (first, last) in sorted(_ranges(node).items()):
            if (sid, other) == (server_id, rid):
                continue
            if first is None or last is None:
                raise _refuse("DHCP server %s holds a range Admin cannot read" % sid, CONFLICT)
            if start <= last and first <= end:
                raise _refuse("range %s - %s overlaps range %s of DHCP server %s on interface %s"
                              % (start, end, other, sid, interface), CONFLICT)
    for name, first, last in _nat_addresses(snapshot):
        if start <= last and first <= end:
            raise _refuse("range %s - %s holds the address of %s" % (start, end, name), CONFLICT)


def _enabled(profile, state) -> bool:
    return state is not None and _effective(profile, state, "status") == "enable"


def _parent(snapshot, key: str):
    sid, _rid = fortios.split_nested(RANGE, key)
    node = _servers(snapshot).get(sid)
    if node is None:
        raise _refuse("DHCP server %s does not exist in the snapshot" % sid, SCOPE)
    return sid, node


def _parent_state(snapshot, node):
    state, _unsupported = snapshot.entry_state(node)
    return state


# ------------------------------------------------------------------------------------------- excluded configuration

def server_scope(snapshot, profile, op, key, changes) -> list:
    """Every DHCP server on the interface of the target (the overlap check reads them, their ranges included)."""
    if op == "create":
        interface = (changes or {}).get("interface") or ""
    else:
        node = _servers(snapshot).get(key)
        interface = "" if node is None else node.value("interface", "")
    return _interface_scope(snapshot, interface)


def range_scope(snapshot, profile, op, key, changes) -> list:
    node = _servers(snapshot).get(fortios.split_nested(RANGE, key)[0])
    return [] if node is None else _interface_scope(snapshot, node.value("interface", ""))


def _interface_scope(snapshot, interface) -> list:
    from netops_admin.fortios_tables import excluded_names, hooks
    item = hooks(SERVER)
    names = set()
    for node in _same_interface(snapshot, interface).values():
        names.update(excluded_names(item, [*node.attrs, *node.sub]))
        section = node.section("ip-range")
        for entry in ([] if section is None else section.entries.values()):
            names.update(excluded_names(item, [*entry.attrs, *entry.sub]))
    return sorted(names)


def dns_scope(snapshot, profile, op, key, changes) -> list:
    """DoT and DoH are out of scope: a shown protocol other than cleartext refuses any change (named only)."""
    section = snapshot.root.sub.get(DNS)
    protocol = None if section is None else section.value("protocol", "")
    return ["protocol"] if protocol and protocol != "cleartext" else []


# ------------------------------------------------------------------------------------------- prechecks

def server_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    fortios.dhcp_server_protected(snapshot, before, after, protected)
    node = _servers(snapshot).get(key)
    if op == "delete":
        held = [name for name in CHILDREN
                if node is not None and node.section(name) is not None and node.section(name).entries]
        if _enabled(profile, before) or held:
            raise _refuse("DHCP server %s is deleted only disabled and without address ranges or reservations%s"
                          % (key, " (it holds %s)" % ", ".join(held) if held else ""), IN_USE)
        return []
    address, network = _interface(snapshot, after.get("interface", ""))
    served = _server_network(profile, after, address, network)
    gateway = _address(_effective(profile, after, "default-gateway") or "")
    if gateway is not None and gateway != ipaddress.IPv4Address("0.0.0.0") and (
            gateway not in served or gateway in (served.network_address, served.broadcast_address)):
        raise _refuse("default-gateway %s lies outside the subnet %s served on interface %s"
                      % (gateway, served, after.get("interface")), CONFLICT)
    if node is not None and op == "update":
        for rid, (first, last) in sorted(_ranges(node).items()):
            _check_range(snapshot, profile, after, key, rid, first, last)
        for reserved in _reservations(node):
            if reserved is None or reserved not in served:
                raise _refuse("a reservation of DHCP server %s would lie outside the subnet %s" % (key, served),
                              CONFLICT)
    changed = _changed(before, after)
    if op == "update" and changed and (_enabled(profile, before) or _enabled(profile, after)) \
            and impact is None and not undo:
        raise _refuse("DHCP server %s is or becomes enabled: the change alters the addresses its clients get;"
                      " endpoint_impact naming the server is required" % key, IMPACT)
    return []


def range_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    from netops_admin import profiles
    sid, node = _parent(snapshot, key)
    rid = fortios.split_nested(RANGE, key)[1]
    server_profile = profiles.load_profiles().get(("fortios", SERVER))
    if server_profile is None:
        raise _refuse("the profile of the DHCP server is not loaded; its ranges cannot be checked", SCOPE)
    state = _parent_state(snapshot, node)
    fortios.dhcp_server_protected(snapshot, state, state, protected)
    enabled = _enabled(server_profile, state)
    if op == "delete":
        if enabled and set(_ranges(node)) == {rid}:
            raise _refuse("range %s is the last address range of the enabled DHCP server %s" % (key, sid), IN_USE)
    else:
        _check_range(snapshot, server_profile, state, sid, rid, _address(after.get("start-ip", "")),
                     _address(after.get("end-ip", "")))
    if before is not None and not undo:
        # the undo restores this range under the same checks: refuse now what the undo would refuse
        try:
            _check_range(snapshot, server_profile, state, sid, rid, _address(before.get("start-ip", "")),
                         _address(before.get("end-ip", "")))
        except Rejected as exc:
            raise Rejected(["the undo of this change would restore a range Admin refuses (%s); resolve it first"
                            % "; ".join(exc.reasons)], reason_codes=exc.reason_codes) from None
    if enabled and impact is None and not undo:
        raise _refuse("DHCP server %s is enabled: a change of its address range alters the addresses its clients"
                      " get; endpoint_impact naming the range is required" % sid, IMPACT)
    return []


def dns_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    for state in (before, after):
        if _effective(profile, state, "protocol") != "cleartext":
            raise _refuse("system dns uses DNS over TLS or HTTPS, which Admin does not manage", SCOPE)
    primary = _effective(profile, after, "primary")
    if not undo and (not primary or primary == "0.0.0.0"):
        raise _refuse("system dns would have no primary DNS server", SCOPE)
    if _changed(before, after) & set(DNS_SERVERS) and impact is None and not undo:
        raise _refuse("a change of the DNS servers alters name resolution of the FortiGate; endpoint_impact naming"
                      " the key - is required", IMPACT)
    return []


def _tls(profile, state) -> bool:
    return _effective(profile, state, "mode") == "reliable" and (state or {}).get("enc-algorithm", "disable") != "disable"


def syslog_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    for state in (before, after):
        if _tls(profile, state):
            raise _refuse("log syslogd setting sends over TLS, which Admin does not manage", SCOPE)
    source = (after or {}).get("source-ip")
    if source and source != "0.0.0.0" and source != (before or {}).get("source-ip"):
        owners = [name for name, entry in (snapshot.entries(fortios.INTERFACE_TABLE) or {}).items()
                  if entry.value("ip", "").split()[:1] == [source]]
        if not owners:
            raise _refuse("source-ip %s is no interface address of the snapshot" % source, SCOPE)
        if {name.casefold() for name in owners} & fortios.protected_interfaces(snapshot, protected):
            raise _refuse("source-ip %s belongs to a protected interface" % source, SCOPE)
    was = _enabled(profile, before) and bool(_effective(profile, before, "server"))
    disabled = not _enabled(profile, after) or not _effective(profile, after, "server")
    moved = [name for name in SYSLOG_TARGET
             if str(_effective(profile, before, name) or "") != str(_effective(profile, after, name) or "")]
    if was and (disabled or moved) and impact is None and not undo:
        raise _refuse("the change stops or moves the active syslog target (%s); endpoint_impact naming the key - is"
                      " required" % (", ".join(moved) or "status"), IMPACT)
    return []


TABLES = {
    SERVER: TableHooks(SERVER, rest_path="system.dhcp/server", rest_key="id", rest_permission="netgrp",
                       child_sections=CHILDREN, impact=True, excluded=DHCP_EXCLUDED, excluded_check=server_scope,
                       prechecks=server_prechecks, **SERVICE),
    RANGE: TableHooks(RANGE, kind="nested", parent=(SERVER, "ip-range"), rest_path="system.dhcp/server",
                      rest_key="id", rest_permission="netgrp", impact=True, excluded=DHCP_EXCLUDED,
                      excluded_check=range_scope, prechecks=range_prechecks, **SERVICE),
    DNS: TableHooks(DNS, kind="singleton", rest_permission="sysgrp", impact=True, excluded=DNS_EXCLUDED,
                    excluded_check=dns_scope, prechecks=dns_prechecks, **SERVICE),
    SYSLOG: TableHooks(SYSLOG, kind="singleton", rest_permission="loggrp", impact=True, excluded=SYSLOG_EXCLUDED,
                       prechecks=syslog_prechecks, **SERVICE),
}
