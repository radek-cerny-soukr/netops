"""1.0.12 G144 (J29, J30): Junos DHCP address pools, host reservations and DHCP relay groups.

Four tables, each a set-format stanza of the configuration (measured on vJunos-switch 26.2R1.7, task-evidence/g144):

- ``dhcp-pool`` (key: pool name): ``set access address-assignment pool <p> family inet network <prefix>``.
- ``dhcp-reservation`` (key: ``<pool>@<host>``): ``... family inet host <h> hardware-address <mac>`` and ``ip-address``.
- ``dhcp-relay-server`` (key: server group name): ``set forwarding-options dhcp-relay server-group <g> <ip>`` (a set
  of addresses, Junos lists them in ascending order).
- ``dhcp-relay-group`` (key: relay group name): ``set forwarding-options dhcp-relay group <g> active-server-group <sg>``
  and ``interface <irb.unit>``.

Junos itself refuses (commit check) a host address outside the pool network, a host without hardware address or without
IP address, a duplicate reserved address, an overlapping pool network, an unknown server group and an interface that
already belongs to another relay group. It accepts a relay interface that does not exist, a network with host bits and
upper case MAC letters (shown in lower case), so Admin checks those itself. Any other statement of these stanzas
(ranges, DHCP attributes, relay overrides, IPv6) is outside the profile: such an object is left untouched.
"""

from __future__ import annotations

import ipaddress
import re

from .errors import Rejected

POOL, RESERVATION, SERVER, GROUP = "dhcp-pool", "dhcp-reservation", "dhcp-relay-server", "dhcp-relay-group"
TABLES = (POOL, RESERVATION, SERVER, GROUP)
NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
MAC = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
IRB = re.compile(r"^irb\.[0-9]{1,5}$")
SCOPE = "junos_dhcp_scope"
DEPENDENCY = "junos_dhcp_dependency"
POOL_PATH = ("access", "address-assignment", "pool")
RELAY_PATH = ("forwarding-options", "dhcp-relay")
MAX_SERVERS = 8


def _address(value, what):
    try:
        if not isinstance(value, str) or value != value.strip():
            raise ValueError(value)
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise Rejected(["%s must be a unicast IPv4 address" % what], reason_codes=[SCOPE]) from None
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local \
            or address == ipaddress.IPv4Address("255.255.255.255"):
        raise Rejected(["%s must be a unicast IPv4 address" % what], reason_codes=[SCOPE])
    return address


def _network(value):
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        raise Rejected(["network must be an IPv4 prefix"], reason_codes=[SCOPE]) from None
    if str(network) != value:
        raise Rejected(["network must be written as %s, the prefix without host bits" % network],
                       reason_codes=[SCOPE])
    if not 8 <= network.prefixlen <= 30:
        raise Rejected(["a DHCP pool network needs a prefix length from 8 to 30"], reason_codes=[SCOPE])
    return network


def canonical_changes(table, changes):
    """Typed values in the form Junos shows (the prediction and the readback must be identical)."""
    result = dict(changes)
    if changes.get("network") is not None:
        result["network"] = str(_network(changes["network"]))
    if changes.get("hardware-address") is not None:
        mac = changes["hardware-address"]
        if not isinstance(mac, str) or not MAC.fullmatch(mac) or int(mac[:2], 16) & 1 or set(mac) <= set("0:"):
            raise Rejected(["hardware-address must be a unicast MAC address aa:bb:cc:dd:ee:ff"], reason_codes=[SCOPE])
        result["hardware-address"] = mac.lower()
    if changes.get("ip-address") is not None:
        result["ip-address"] = str(_address(changes["ip-address"], "ip-address"))
    if changes.get("servers") is not None:
        values = [_address(item, "a DHCP server address") for item in str(changes["servers"]).split()]
        if not values or len(values) > MAX_SERVERS or len(set(values)) != len(values):
            raise Rejected(["servers must hold 1 to %d distinct addresses" % MAX_SERVERS], reason_codes=[SCOPE])
        result["servers"] = " ".join(str(item) for item in sorted(values))
    return result


# ---- parsing the set lines ----

def _owner(words, table):
    """(key, rest of the statement) of a statement that one of the tables owns, or None."""
    if tuple(words[:3]) == POOL_PATH and len(words) >= 4:
        pool, rest = words[3], words[4:]
        if table == POOL:
            return pool, rest
        if table == RESERVATION and rest[:3] == ["family", "inet", "host"] and len(rest) >= 4:
            return pool + "@" + rest[3], rest[4:]
        return None
    if tuple(words[:2]) == RELAY_PATH:
        rest = words[2:]
        if table == SERVER and len(rest) >= 2 and rest[0] == "server-group":
            return rest[1], rest[2:]
        if table == GROUP and len(rest) >= 2 and rest[0] == "group":
            return rest[1], rest[2:]
    return None


def _statements(lines, table):
    for line in lines:
        verb, *words = line.split()
        owner = _owner(words, table)
        if owner:
            yield verb, owner[0], owner[1]


def own_lines(snapshot, table, key):
    owned = set()
    for line in snapshot.lines:
        verb, *words = line.split()
        owner = _owner(words, table)
        if verb != "set" or owner is None or owner[0] != key:
            continue
        # a pool owns its network only: the hosts of the pool are reservations
        if table == POOL and owner[1][:3] != ["family", "inet", "network"]:
            continue
        owned.add(line)
    return owned


def _fill(entry, name, value):
    if name in entry.attributes:
        entry.unsupported.append("repeated %s" % name)
    entry.attributes[name] = value


def entries(snapshot, table):
    from .junos import Entry

    if table == SERVER:
        return _server_entries(snapshot)
    found = {}
    for verb, key, rest in _statements(snapshot.lines, table):
        if table == POOL and rest[:3] == ["family", "inet", "host"]:
            continue
        entry = found.setdefault(key, Entry(key))
        if verb != "set":
            entry.unsupported.append("inactive or protected DHCP statement")
        elif table == POOL:
            if len(rest) == 4 and rest[:3] == ["family", "inet", "network"]:
                _fill(entry, "network", rest[3])
            else:
                entry.unsupported.append("DHCP pool statement outside the profile")
        elif table == RESERVATION:
            if len(rest) == 2 and rest[0] in ("hardware-address", "ip-address"):
                _fill(entry, rest[0], rest[1])
            else:
                entry.unsupported.append("DHCP host statement outside the profile")
        elif len(rest) == 2 and rest[0] in ("active-server-group", "interface"):
            _fill(entry, rest[0], rest[1])
        else:
            entry.unsupported.append("DHCP relay group statement outside the profile")
    return found


def _server_entries(snapshot):
    """Server groups: every statement is one IPv4 address under the group name."""
    from .junos import Entry

    found = {}
    addresses = {}
    for line in snapshot.lines:
        verb, *words = line.split()
        if tuple(words[:2]) != RELAY_PATH or words[2:3] != ["server-group"] or len(words) < 4:
            continue
        entry = found.setdefault(words[3], Entry(words[3]))
        if verb != "set" or len(words) != 5:
            entry.unsupported.append("inactive, protected or optioned DHCP server statement")
            continue
        try:
            addresses.setdefault(words[3], []).append(ipaddress.IPv4Address(words[4]))
        except ValueError:
            entry.unsupported.append("DHCP server address that is not IPv4")
    for name, entry in found.items():
        servers = addresses.get(name, [])
        if len(set(servers)) != len(servers):
            entry.unsupported.append("repeated DHCP server address")
        if servers:
            entry.attributes["servers"] = " ".join(str(item) for item in sorted(servers))
    return found


def _pool_network(snapshot, pool):
    """The network of a pool from its single network statement, or None (a pool with other statements keeps its
    reservations editable)."""
    found = [words[-1] for words in (line.split() for line in snapshot.lines)
             if words[0] == "set" and tuple(words[1:4]) == POOL_PATH and words[4:5] == [pool]
             and words[5:8] == ["family", "inet", "network"] and len(words) == 9]
    if len(found) != 1:
        return None
    try:
        return ipaddress.IPv4Network(found[0])
    except ValueError:
        return None


def _hosts(snapshot, pool):
    return {key.partition("@")[2]: entry for key, entry in entries(snapshot, RESERVATION).items()
            if key.partition("@")[0] == pool}


# ---- rendering ----

def _path(table, key):
    if table == POOL:
        return "access address-assignment pool %s" % key
    if table == RESERVATION:
        pool, _, host = key.partition("@")
        return "access address-assignment pool %s family inet host %s" % (pool, host)
    if table == SERVER:
        return "forwarding-options dhcp-relay server-group %s" % key
    return "forwarding-options dhcp-relay group %s" % key


def render(table, key, before, after):
    path = _path(table, key)
    if after is None:
        return ["delete " + path]
    before = before or {}
    lines = []
    if table == POOL:
        if before.get("network") != after["network"]:
            lines.append("set %s family inet network %s" % (path, after["network"]))
    elif table == RESERVATION:
        for name in ("hardware-address", "ip-address"):
            if before.get(name) != after[name]:
                lines.append("set %s %s %s" % (path, name, after[name]))
    elif table == SERVER:
        old, new = before.get("servers", "").split(), after["servers"].split()
        # add first so the group survives a replacement of all of its addresses
        lines += ["set %s %s" % (path, item) for item in new if item not in old]
        lines += ["delete %s %s" % (path, item) for item in old if item not in new]
    else:
        if before.get("interface") not in (None, after["interface"]):
            lines.append("delete %s interface %s" % (path, before["interface"]))
        if before.get("interface") != after["interface"]:
            lines.append("set %s interface %s" % (path, after["interface"]))
        if before.get("active-server-group") != after["active-server-group"]:
            lines.append("set %s active-server-group %s" % (path, after["active-server-group"]))
    return lines


# ---- plan checks ----

def _scope_refusal(snapshot):
    for line in snapshot.lines:
        verb, *words = line.split()
        if verb == "set" and words[:1] == ["groups"] and len(words) > 3 and (
                tuple(words[2:4]) == (POOL_PATH[0], POOL_PATH[1]) or tuple(words[2:4]) == RELAY_PATH):
            return "DHCP configuration from configuration groups"
        if tuple(words[:2]) in ((POOL_PATH[0], POOL_PATH[1]), RELAY_PATH) and (
                verb != "set" or "apply-groups" in words):
            return "inactive, protected or inherited DHCP configuration"
    return None


def _active_server_group(snapshot, key):
    for line in snapshot.lines:
        words = line.split()
        if words[:3] != ["set", *RELAY_PATH]:
            continue
        options = words[5:] if words[3:4] == ["group"] else words[3:]
        if options == ["active-server-group", key]:
            return True
    return False


def _active_local_server(snapshot):
    # The configured listener can select a pool through the incoming interface, giaddr or pool match options.
    return any(line.startswith("set ") and re.search(
        r"\bsystem services dhcp-local-server (?!dhcpv6\b).*?\binterface \S+", line)
        for line in snapshot.lines)


def prechecks(snapshot, table, key, before, after, protected, impact, undo):
    problem = _scope_refusal(snapshot)
    if problem:
        raise Rejected([problem + " needs a separate change"], reason_codes=[SCOPE])
    if table == POOL:
        _pool_prechecks(snapshot, key, after)
        active = _active_local_server(snapshot)
    elif table == RESERVATION:
        _reservation_prechecks(snapshot, key, after)
        active = _active_local_server(snapshot)
    elif table == SERVER:
        active = _active_server_group(snapshot, key)
        if after is None and active:
            raise Rejected(["the server group is used by a relay"], reason_codes=[DEPENDENCY])
    else:
        _relay_prechecks(snapshot, key, before, after, protected)
        active = any(state and state.get("interface") for state in (before, after))
    if active and before != after and not undo and impact != key:
        raise Rejected(["changing DHCP on a configured service needs endpoint_impact for %s" % key],
                       reason_codes=["endpoint_impact_required"])
    return []


def _relay_prechecks(snapshot, key, before, after, protected):
    from .junos import IRB_TABLE, l3_entries

    guarded = {name.casefold() for name in (protected or {}).get("interface", ())}
    for state in (before, after):
        interface = (state or {}).get("interface")
        if interface and {interface.casefold(), "irb"} & guarded:
            raise Rejected(["the relay interface is protected by the inventory"], reason_codes=["port_protected"])
    if after is None:
        return
    servers = _server_entries(snapshot).get(after["active-server-group"])
    if servers is None or servers.unsupported:
        raise Rejected(["the relay group needs a configured server group"], reason_codes=[DEPENDENCY])
    interface = after["interface"]
    if not IRB.fullmatch(interface):
        raise Rejected(["a relay group interface must be an IRB unit irb.<n>"], reason_codes=[SCOPE])
    if interface not in l3_entries(snapshot, IRB_TABLE):
        raise Rejected(["the relay interface %s is not configured" % interface], reason_codes=[DEPENDENCY])
    if any(other != key and entry.attributes.get("interface") == interface
           for other, entry in entries(snapshot, GROUP).items()):
        raise Rejected(["the interface already belongs to another relay group"], reason_codes=[SCOPE])


def _pool_prechecks(snapshot, key, after):
    hosts = [name for name in entries(snapshot, RESERVATION) if name.partition("@")[0] == key]
    if after is None:
        if hosts:
            raise Rejected(["the pool holds %d reservations; delete them first" % len(hosts)],
                           reason_codes=[DEPENDENCY])
        return []
    network = ipaddress.IPv4Network(after["network"])
    for pool, entry in entries(snapshot, POOL).items():
        other = entry.attributes.get("network")
        if pool != key and other and ipaddress.IPv4Network(other).overlaps(network):
            raise Rejected(["the network overlaps with pool %s" % pool], reason_codes=[SCOPE])
    for name in hosts:
        address = entries(snapshot, RESERVATION)[name].attributes.get("ip-address")
        if address is None or ipaddress.IPv4Address(address) not in network:
            raise Rejected(["a reservation of the pool lies outside the new network"], reason_codes=[DEPENDENCY])
    return []


def _reservation_prechecks(snapshot, key, after):
    pool, _, _host = key.partition("@")
    network = _pool_network(snapshot, pool)
    if network is None:
        raise Rejected(["the pool %s needs one configured IPv4 network" % pool], reason_codes=[DEPENDENCY])
    if after is None:
        return []
    address = ipaddress.IPv4Address(after["ip-address"])
    if address not in network or address in (network.network_address, network.broadcast_address):
        raise Rejected(["the address lies outside the usable hosts of pool %s (%s)" % (pool, network)],
                       reason_codes=[SCOPE])
    for other, entry in _hosts(snapshot, pool).items():
        if other == key.partition("@")[2]:
            continue
        for name in ("hardware-address", "ip-address"):
            if entry.attributes.get(name) == after[name]:
                raise Rejected(["the %s is already reserved for host %s" % (name, other)], reason_codes=[SCOPE])
    return []


def predicted_lines(snapshot, table, key, after):
    keep = [line for line in snapshot.lines if line not in own_lines(snapshot, table, key)]
    return keep if after is None else keep + render(table, key, None, after)
