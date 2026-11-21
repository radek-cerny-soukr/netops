"""Reversible ExtremeXOS link configuration managed by Admin."""

from __future__ import annotations

import hashlib
import ipaddress
import re

from netops_admin import membership
from netops_admin.errors import Rejected

LINK = "port-link"
LAG = "sharing"
STPD = "stpd"
STP_PORT = "stpd-port"
PEER = "mlag-peer"
BINDING = "mlag-port"
JUMBO = "jumbo-frame-size"
ELRP = "elrp"
MODULE = {LINK: "vlan", LAG: "vlan", STPD: "stp", STP_PORT: "stp",
          PEER: "vsm", BINDING: "vsm", JUMBO: "vlan", ELRP: "elrp"}
TABLES = frozenset(MODULE)
JUMBO_DEFAULT = "9216"
STP_LINK_DEFAULT = "auto"
PRIORITY_DEFAULT = "32768"
PORT = membership.PORT_NUMBER

LINK_LINE = re.compile(
    r"configure ports (\S+) auto (on|off)(?: speed ([0-9]+))?(?: duplex (half|full))?"
)


def refuse(message, code="exos_link_scope"):
    raise Rejected([message], reason_codes=[code])


def _put(entry, name, value, command):
    if name in entry.attributes:
        entry.unsupported.append("line %d: repeated %s" % (command.line, name))
    entry.attributes[name] = value


def _port_set(value, snapshot):
    try:
        found = membership.ports(value, snapshot.inventory)
    except ValueError:
        refuse("a configured port list cannot be evaluated", "port_usage_unreadable")
    if not found or (snapshot.inventory is not None and found - snapshot.inventory):
        refuse("a configured port list does not match the switch inventory", "port_usage_unreadable")
    return found


def _record(snapshot, table, command):
    """Return (key, attributes) for a line owned by the table."""
    t = command.tokens
    if command.upm_profile:
        return []
    if table == LINK:
        if t[:2] == ("configure", "ports") and t[3:4] in (("auto",), ("medium",)):
            m = LINK_LINE.fullmatch(" ".join(t))
            keys = _port_set(t[2], snapshot)
            if m is None or len(keys) != 1:
                return [(key, None) for key in keys]
            _, mode, speed, duplex = m.groups()
            state = {"autonegotiation": "enabled" if mode == "on" else "disabled"}
            state.update({k: v for k, v in (("speed", speed), ("duplex", duplex)) if v is not None})
            return [(t[2], state)]
        if t[:3] == ("enable", "jumbo-frame", "ports"):
            if len(t) != 4:
                read_error("the jumbo port list is incomplete")
            keys = _port_set(t[3], snapshot)
            return [(key, {"jumbo-frame": "enabled"}) for key in keys]
    if table == JUMBO and t[:2] == ("configure", "jumbo-frame-size"):
        return [("global", {"size": t[2]} if len(t) == 3 and t[2].isdigit() else None)]
    if table == ELRP and t[:3] == ("configure", "elrp-client", "periodic") and len(t) >= 4:
        params = t[3:] if t[3] != "vlan" else t[4:]
        if not params:
            read_error("an ELRP session has no VLAN")
        key = params[0]
        if (len(params) in (6, 7) and params[1] == "ports" and params[3] == "interval"
                and params[4].isdigit()):
            interval, suffix = params[4], params[5:]
            if suffix == ("milliseconds", "log") and interval.endswith("000"):
                interval, suffix = interval[:-3], ("seconds", "log")
            if interval and suffix in (("log",), ("seconds", "log")):
                return [(key, {"ports": " ".join(sorted(_port_set(params[2], snapshot))), "interval": interval})]
        return [(key, None)]
    if table == LAG and t[:2] == ("enable", "sharing") and len(t) >= 3:
        if t[3:4] not in (("grouping",), ("group",)) or len(t) < 5:
            return [(t[2], None)]
        options = t[5:]
        algorithm = None
        if options in (("lacp",), ()):
            algorithm = "L2"
        elif len(options) in (3, 4) and options[:2] == ("algorithm", "address-based"):
            algorithm = options[2]
        if algorithm not in ("L2", "L3_L4") or options[-1:] != ("lacp",):
            return [(t[2], None)]
        return [(t[2], {"members": " ".join(sorted(_port_set(t[4], snapshot))), "algorithm": algorithm})]
    if table == LAG and t[:2] == ("configure", "sharing") and len(t) >= 3 and PORT.fullmatch(t[2]):
        return [(t[2], None)]
    if table == STPD:
        if t[:2] == ("create", "stpd") and len(t) == 3:
            return [(t[2], {})]
        if t[:2] == ("configure", "stpd") and len(t) >= 5 and t[3] == "priority":
            return [(t[2], {"priority": t[4]} if t[5:] in ((), ("extended-system-id", "0")) else None)]
    if table == STP_PORT and t[:2] == ("configure", "stpd") and t[3:4] == ("ports",) and len(t) >= 7:
        field, value, port_list = t[4:7]
        if field in ("link-type", "cost", "edge-safeguard", "bpdu-restrict"):
            values = {field: value}
            if field in ("edge-safeguard", "bpdu-restrict"):
                values[field] = {"enable": "enabled", "disable": "disabled"}.get(value, value)
            if t[7:] == ("bpdu-restrict",) and field == "edge-safeguard":
                values["bpdu-restrict"] = "enabled"
            elif t[7:]:
                values = None
            keys = _port_set(port_list, snapshot)
            return [(t[2] + ":" + port, values if len(keys) == 1 else None) for port in keys]
    if table == PEER and t[1:3] == ("mlag", "peer") and len(t) >= 4:
        if t[0] == "create" and len(t) == 4:
            return [(t[3], {})]
        if t[0] == "configure" and t[4:5] == ("ipaddress",):
            if len(t) == 6:
                return [(t[3], {"peer-ip": t[5]})]
            if len(t) == 8 and t[6] == "vr":
                return [(t[3], {"peer-ip": t[5], "vr": t[7]})]
        return [(t[3], None)]
    if table == BINDING and t[:3] == ("enable", "mlag", "port") and len(t) >= 4 and PORT.fullmatch(t[3]):
        if len(t) == 8 and t[4] == "peer" and t[6] == "id":
            return [(t[3], {"peer": t[5], "mlag-id": t[7]})]
        return [(t[3], None)]
    return []


def entries(snapshot, table, entry_class):
    complete(snapshot, table)
    result = {"s0": entry_class("s0")} if table == STPD else {}
    for command in snapshot.commands:
        for key, fields in _record(snapshot, table, command):
            entry = result.setdefault(key, entry_class(key))
            if fields is None:
                entry.unsupported.append("line %d: %s settings outside the profile" % (command.line, table))
            else:
                for name, value in fields.items():
                    _put(entry, name, value, command)
    return result


def complete(snapshot, table):
    if MODULE[table] not in snapshot.configuration.modules:
        refuse("the %s configuration module is missing" % MODULE[table], "port_usage_unreadable")


def _same(key, other):
    return key.casefold() == other.casefold()


def _owned(snapshot, table, key, command):
    records = _record(snapshot, table, command)
    if table == STPD and command.tokens[:2] == ("create", "stpd"):
        return False
    if table == LINK and len(records) > 1:
        return False
    return any(values is not None and _same(key, other) for other, values in records)


def lag_members(state):
    return set((state or {}).get("members", "").split())


def lag_memberships(snapshot, scope, members, require_default):
    """Compare the Default VLAN after accounting for EXOS hiding physical LAG members."""
    _vlans, current, _descriptions = membership.model(snapshot)
    state = {}
    for port, modes in current.items():
        if port in members:
            if modes["tagged"] or modes["untagged"] - {membership.DEFAULT_VLAN}:
                if require_default:
                    refuse("a physical LAG member has unexpected VLAN membership")
            else:
                continue
        if port in scope or any(modes.values()):
            state[port] = {kind: sorted(names) for kind, names in modes.items() if names}
    return state


def rest_digest(snapshot, table, key, commands, scope=(), expected=None, require_default=True):
    if table == LAG and scope:
        physical = lag_members(expected) - {key}
        modes = lag_memberships(snapshot, scope, physical, require_default)
        # The master and free members must return to Default on detach. The engine
        # verifies both sides directly, so their Default entries can share a digest.
        # An algorithm-only update instead retains any other VLAN memberships.
        for port in scope:
            if modes.get(port) == {"untagged": [membership.DEFAULT_VLAN]}:
                del modes[port]
            elif require_default:
                if port in modes:
                    refuse("all LAG ports must use only the Default VLAN")
                if port not in physical:
                    refuse("the Default VLAN membership of a LAG port cannot be established")
            elif port not in physical:
                modes.setdefault(port, {})
        kept = [command.text for command in commands if not _owned(snapshot, table, key, command)
                and not membership.default_rendering(snapshot, command)
                and not (command.tokens[:2] == ("configure", "vlan") and command.tokens[3:5] == ("add", "ports"))]
        body = repr((kept, sorted(modes.items())))
    elif table == LINK:
        # EXOS serializes all enabled jumbo ports together.
        kept = []
        jumbo = set()
        for command in commands:
            if command.tokens[:3] == ("enable", "jumbo-frame", "ports"):
                jumbo.update(_port_set(command.tokens[3], snapshot) - {key})
            elif not _owned(snapshot, table, key, command):
                kept.append(command.text)
        body = repr((kept, sorted(jumbo)))
    else:
        body = "\n".join(command.text for command in commands if not _owned(snapshot, table, key, command))
    return hashlib.sha256(body.encode()).hexdigest()


def _link_command(key, state):
    mode = "off" if state.get("autonegotiation") == "disabled" else "on"
    extras = "".join(" %s %s" % (name, state[name]) for name in ("speed", "duplex") if name in state)
    return "configure ports %s auto %s%s" % (key, mode, extras)


def _member_list(ports):
    return ",".join(sorted(ports, key=lambda port: tuple(map(int, port.split(":")))))


def _sharing(key, state):
    algorithm = state.get("algorithm", "L2")
    option = "" if algorithm == "L2" else " algorithm address-based " + algorithm
    return "enable sharing %s grouping %s%s lacp" % (key, _member_list(lag_members(state)), option)


def _bind(key, state):
    return "enable mlag port %s peer %s id %s" % (key, state["peer"], state["mlag-id"])


def _stp_port(key, before, after):
    domain, port = key.split(":", 1)
    prefix = "configure stpd %s ports" % domain
    lines = []
    old_link, link = (state.get("link-type", STP_LINK_DEFAULT) for state in (before, after))
    old_guard, guard = (state.get("edge-safeguard") == "enabled" for state in (before, after))
    old_bpdu, bpdu = (state.get("bpdu-restrict") == "enabled" for state in (before, after))
    if old_bpdu and not bpdu and guard:
        lines.append(f"{prefix} bpdu-restrict disable {port}")
    if old_guard and not guard:
        lines.append(f"{prefix} edge-safeguard disable {port}")
    if old_link != link:
        if "link-type" in after:
            lines.append(f"{prefix} link-type {link} {port}")
        else:
            lines.append(f"unconfigure stpd {domain} ports link-type {port}")
    if not old_guard and guard:
        lines.append(f"{prefix} edge-safeguard enable {port}")
    if not old_bpdu and bpdu:
        lines.append(f"{prefix} bpdu-restrict enable {port}")
    if before.get("cost") != after.get("cost"):
        lines.append(f"{prefix} cost {after.get('cost', 'auto')} {port}")
    return lines


def render(table, key, before, after):
    if table == LINK:
        old, new = _link_command(key, before), _link_command(key, after)
        lines = [new] if old != new else []
        if before.get("jumbo-frame") != after.get("jumbo-frame"):
            verb = "enable" if after.get("jumbo-frame") == "enabled" else "disable"
            lines.insert(0 if verb == "disable" else len(lines), f"{verb} jumbo-frame ports {key}")
        return lines
    if table == LAG:
        if before is None:
            return [_sharing(key, after)]
        old, new = lag_members(before), lag_members(after)
        detached = (old - new) - {key}
        if after is None:
            lines = [f"disable sharing {key}"]
        else:
            lines = [f"configure sharing {key} {verb} ports {_member_list(ports)}"
                     for verb, ports in (("delete", detached), ("add", new - old)) if ports]
            if before.get("algorithm") != after.get("algorithm"):
                lines.append("configure sharing %s algorithm address-based %s" % (key, after.get("algorithm", "L2")))
        if detached:
            # X440-G2 removes a physical member from Default on join and
            # leaves it without a native VLAN after it is detached.
            lines.append("configure vlan %s add ports %s untagged" % (membership.DEFAULT_VLAN, _member_list(detached)))
        return lines
    if table == JUMBO:
        return ["configure jumbo-frame-size %s" % after.get("size", JUMBO_DEFAULT)]
    if table == ELRP:
        lines = [f"unconfigure elrp-client {key}"] if before is not None else []
        if after is not None:
            lines.append("configure elrp-client periodic %s ports %s interval %s seconds log" % (
                key, _member_list(after["ports"].split()), after["interval"]))
        return lines
    if table == STPD:
        return ["configure stpd %s priority %s" % (key, after.get("priority", PRIORITY_DEFAULT))]
    if table == STP_PORT:
        return _stp_port(key, before, after)
    if table == BINDING:
        return ([f"disable mlag port {key}"] if before is not None else []) + (
            [_bind(key, after)] if after is not None else [])
    if after is None:
        return [f"delete mlag peer {key}"]
    peer = after.get("peer-ip")
    lines = [f"create mlag peer {key}"] if before is None else []
    if peer:
        lines.append("configure mlag peer %s ipaddress %s vr %s" % (key, peer, after.get("vr", "VR-Default")))
    elif before:
        lines.append(f"unconfigure mlag peer {key} ipaddress")
    return lines


def port_scope(snapshot, table, key, before, after, entry_class):
    if table in (LINK, BINDING):
        scope = {key}
    elif table == LAG:
        scope = lag_members(before) | lag_members(after)
    elif table == STP_PORT:
        scope = {key.split(":", 1)[1]}
    elif table == JUMBO:
        scope = set().union(*(_port_set(cmd.tokens[3], snapshot) for cmd in snapshot.commands
                              if not cmd.upm_profile and cmd.tokens[:3] == ("enable", "jumbo-frame", "ports")))
    elif table == ELRP:
        scope = set((before or {}).get("ports", "").split()) | set((after or {}).get("ports", "").split())
    else:
        scope = set()
        if table == STPD:
            _vlans, members, _descriptions = membership.model(snapshot)
            vlan_names = domain_vlans(snapshot, key)
            scope.update(port for port, modes in members.items()
                         if vlan_names.intersection(modes["tagged"] | modes["untagged"]))
            if _same(key, "s0"):
                scope.update(snapshot.inventory or ())
        else:
            _vlans, members, _descriptions = membership.model(snapshot)
            links = set()
            for state in (before, after):
                if state and "peer-ip" in state:
                    links.add(peer_vlan(snapshot, state))
            scope.update(port for port, modes in members.items()
                         if links.intersection(modes["tagged"] | modes["untagged"]))
    groups = membership.lag_groups(snapshot)
    if table in (LINK, STP_PORT) and any(scope & group for group in groups):
        refuse("the port is already a member of a LAG", "port_lag_member")
    if table == BINDING:
        if any(key in group and key not in entries(snapshot, LAG, entry_class) for group in groups):
            refuse("MLAG binding must use the logical port of a LAG", "port_lag_member")
    if table != LAG:
        scope.update(set().union(*(group for group in groups if scope & group)))
    return scope


def domain_vlans(snapshot, key):
    result = set()
    for command in snapshot.commands:
        t = command.tokens
        if len(t) >= 6 and t[:2] == ("enable", "stpd") and _same(key, t[2]) and t[3:5] == ("auto-bind", "vlan"):
            result.update(t[5].split(","))
            continue
        if t[:2] != ("configure", "stpd") or len(t) < 5 or not _same(key, t[2]) or t[3] != "add":
            continue
        index = 5 if t[4] == "vlan" else 4
        if len(t) < index + 3 or t[index + 1] != "ports":
            refuse("an STP VLAN binding cannot be evaluated", "port_usage_unreadable")
        result.update(t[index].split(","))
    return result


def stpd_scope_vlans(snapshot, key, port_vlans):
    vlans = {name.casefold() for name in domain_vlans(snapshot, key)}
    return vlans | port_vlans if _same(key, "s0") else vlans


def peer_vlan(snapshot, state):
    from netops_admin import exos

    address = ipaddress.IPv4Address(state["peer-ip"])
    vr = state.get("vr", "VR-Default")
    found = set()
    for name, network in exos.vlan_interfaces(snapshot).items():
        if network["vr"].casefold() != vr.casefold():
            continue
        for interface in network["ipv4"]:
            if (address in interface.network and address not in
                    (interface.ip, interface.network.network_address, interface.network.broadcast_address)):
                found.add(name)
    if len(found) != 1:
        refuse("the peer needs a unique directly connected ISC VLAN")
    return found.pop()


def validate(snapshot, table, key, before, after, protected, entry_class):
    complete(snapshot, table)
    scope = port_scope(snapshot, table, key, before, after, entry_class)
    if snapshot.inventory is None or scope - snapshot.inventory:
        refuse("the port scope is absent from the switch inventory", "port_usage_unreadable")
    _vlans, members, _descriptions = membership.model(snapshot)
    guarded = {item.casefold() for values in (protected or {}).values() for item in values}
    vlans = {name.casefold() for port in scope for names in members.get(port, {}).values() for name in names}
    if table == STPD:
        vlans = stpd_scope_vlans(snapshot, key, vlans)
    if guarded.intersection({key.casefold(), *scope, *vlans}) or "mgmt" in vlans:
        refuse("the change affects a protected port, VLAN or object", "port_protected")

    mlag = {} if table == STPD else entries(snapshot, BINDING, entry_class)
    if (scope if table != BINDING else scope - {key}).intersection(mlag):
        refuse("the change affects an existing MLAG binding")

    if table == LINK and after.get("autonegotiation") == "disabled":
        if not all(after.get(name) for name in ("speed", "duplex")):
            refuse("forced link mode requires both speed and duplex")

    if table == LAG:
        requested = lag_members(after)
        if after is not None and (key not in requested or any(not PORT.fullmatch(port) for port in requested)):
            refuse("the requested LAG must include its logical port")
        if any(scope & group for group in membership.lag_groups(snapshot) if key not in group):
            refuse("a requested member already belongs to another LAG", "port_lag_member")
        switching = (lag_members(before) ^ requested) - {key}
        for command in snapshot.commands:
            t = command.tokens
            if (switching and t[:2] == ("configure", "qosscheduler") and "ports" in t
                    and _port_set(t[t.index("ports") + 1], snapshot) & switching):
                refuse("changing membership would discard a configured QoS scheduler")

    if table == ELRP:
        if any(not PORT.fullmatch(port) or key not in
               (members.get(port, {}).get("tagged", set()) | members.get(port, {}).get("untagged", set()))
               for port in scope):
            refuse("every ELRP port must belong to the named VLAN")

    if table == STPD:
        values = (int(state.get("priority", PRIORITY_DEFAULT)) for state in (before, after))
        if any(value not in range(0, 61441, 4096) for value in values):
            refuse("the current and requested bridge priorities must be multiples of 4096")

    if table == STP_PORT:
        domain = key.split(":", 1)[0]
        if not any(_same(domain, name) for name in entries(snapshot, STPD, entry_class)):
            refuse("the STP domain does not exist")
        if any(after.get(name) == "enabled" for name in ("bpdu-restrict", "edge-safeguard")):
            if after.get("link-type") != "edge":
                refuse("edge safeguard and BPDU restrict require an edge port")
            if after.get("bpdu-restrict") == "enabled" and after.get("edge-safeguard") != "enabled":
                refuse("BPDU restrict requires edge safeguard")

    if table == PEER:
        if after and "vr" in after and "peer-ip" not in after:
            refuse("an MLAG peer VR requires a peer IP address")
        if any(_same(binding.attributes.get("peer", ""), key) for binding in mlag.values()):
            refuse("the MLAG peer already has port bindings")
        current = entries(snapshot, PEER, entry_class)
        for state in (before, after):
            if not state or not state.get("peer-ip"):
                continue
            vlan = peer_vlan(snapshot, state)
            if vlan.casefold() in guarded or vlan.casefold() == "mgmt" or not scope:
                refuse("the MLAG peer requires an unprotected ISC VLAN with known member ports")
            for name, other in current.items():
                if not _same(name, key) and "peer-ip" in other.attributes and peer_vlan(snapshot, other.attributes) == vlan:
                    refuse("the ISC VLAN is already used by another MLAG peer")

    if table == BINDING:
        peers = entries(snapshot, PEER, entry_class)
        for state in (before, after):
            if state:
                name = state["peer"]
                if name.casefold() in guarded or name not in peers or "peer-ip" not in peers[name].attributes:
                    refuse("the selected MLAG peer is protected or has no configured address")
                if any(port != key and entry.attributes.get("mlag-id") == state["mlag-id"]
                       for port, entry in mlag.items()):
                    refuse("the MLAG ID is already used by another local port")
    return scope


def prediction(snapshot, table, key, state, before):
    kept = [command for command in snapshot.commands if not _owned(snapshot, table, key, command)]
    added = []
    if table == LINK:
        jumbo = set()
        retained = []
        for command in kept:
            if command.tokens[:3] == ("enable", "jumbo-frame", "ports"):
                jumbo.update(_port_set(command.tokens[3], snapshot) - {key})
            else:
                retained.append(command)
        kept = retained
        if (state or {}).get("jumbo-frame") == "enabled":
            jumbo.add(key)
        if state and _link_command(key, state) != _link_command(key, {}):
            added.append(_link_command(key, state))
        if jumbo:
            added.append("enable jumbo-frame ports " + _member_list(jumbo))
    elif table == LAG:
        before_members, after_members = lag_members(before), lag_members(state)
        if before_members != after_members:
            _vlans, members, _descriptions = membership.model(snapshot)
            default = {port for port, modes in members.items() if membership.DEFAULT_VLAN in modes["untagged"]}
            default.update((before_members - after_members) - {key})
            default.difference_update(after_members - {key})
            kept = [cmd for cmd in kept if not (
                cmd.tokens[:2] == ("configure", "vlan") and cmd.tokens[2:5] == (membership.DEFAULT_VLAN, "add", "ports")
                and cmd.tokens[-1] == "untagged")]
            if default:
                added.append("configure vlan %s add ports %s untagged" % (membership.DEFAULT_VLAN, _member_list(default)))
        if state is not None:
            added.append(_sharing(key, state))
    elif table in (STPD, JUMBO):
        if state:
            added = render(table, key, {}, state)
    elif table == STP_PORT:
        added = render(table, key, {}, state or {})
    elif state is not None:
        added = render(table, key, None, state)
    return "\n".join(membership.modular(snapshot, kept, added, module=MODULE[table])) + "\n"


def read_error(message):
    refuse(message, "port_usage_unreadable")


def link_readback(config, information, key):
    if "Port Configuration" not in config or "Flow Cntrl:" not in config or len(re.findall(r"^={10,} *$", config, re.M)) != 2:
        read_error("the port configuration table is incomplete")
    rows = re.findall(r"^[ \t]*(\S+)[ \t]+\S+[ \t]+[DEL][ \t]+(?:[ARL]|NP)[ \t]+(ON|OFF)"
                      r"(?:[ \t]+(?:ON|OFF))?[ \t]+(AUTO|[0-9]+)(?:[ \t]+[0-9]+)?[ \t]+(AUTO|FULL|HALF)\b",
                      config, re.M | re.I)
    port = re.search(r"^Port:[ \t]*" + re.escape(key) + r"(?:\(([^)]+)\):?)?[ \t]*$", information, re.M)
    if len(rows) != 1 or port is None or rows[0][0].rstrip(">") not in (key, (port.group(1) or "")[:8]):
        read_error("the configured speed and duplex of the requested port could not be established")
    jumbo = re.findall(r"^\s*Jumbo:\s*(Enabled|Disabled)\b", information, re.M)
    if len(jumbo) != 1:
        read_error("the port's jumbo setting could not be established")
    mode, speed, duplex = (value.lower() for value in rows[0][1:])
    state = {"autonegotiation": "enabled" if mode == "on" else "disabled", "jumbo-frame": jumbo[0].lower()}
    state.update({name: value for name, value in (("speed", speed), ("duplex", duplex)) if value != "auto"})
    return state


def _table(text, heading, total):
    lines = text.splitlines()
    bounds = [index for index, line in enumerate(lines) if re.fullmatch(r"={10,}\s*", line)]
    count = re.findall(total + r"\s*:\s*(\d+)\s*$", text, re.M)
    if heading not in text or len(bounds) != 2 or len(count) != 1:
        read_error("the %s table is incomplete" % heading)
    return [line.split() for line in lines[bounds[0] + 1:bounds[1]] if line.strip()], int(count[0])


def sharing_readback(text, key, configured):
    rows, total = _table(text, "Load Sharing Monitor", "Number of load sharing trunks")
    groups = {}
    master = None
    for row in rows:
        if len(row) < 4 or not PORT.fullmatch(row[-4]):
            read_error("the load sharing member rows cannot be evaluated")
        if len(row) >= 8:
            mode = row[2] if PORT.fullmatch(row[1]) or row[1] == "-" else row[1]
            master = row[0]
            if (not PORT.fullmatch(master) or mode.casefold() not in ("lacp", "static", "health", "health-check")
                    or master in groups):
                read_error("the load sharing group row cannot be evaluated")
            groups[master] = (mode.upper(), set(), set())
        if master is None or row[-4] in groups[master][1]:
            read_error("a load sharing group member is missing its logical port or is repeated")
        groups[master][1].add(row[-4])
        groups[master][2].update(token for token in row[:-4] if token in ("L2", "L3", "L3_L4", "custom"))
    if len(groups) != total:
        read_error("the load sharing rows do not match the reported trunk count")
    if key not in groups:
        return None
    mode, members, algorithms = groups[key]
    if mode != "LACP" or configured is None or len(algorithms) > 1:
        read_error("the load sharing type and configured algorithm cannot be established")
    algorithm = next(iter(algorithms), configured.get("algorithm", "L2"))
    return {"members": " ".join(sorted(members)), "algorithm": algorithm}


def bindings_readback(text):
    rows, total = _table(text, "MLAG", "Number of Multi-switch Link Aggregation Groups")
    if len(rows) != total or any(len(row) != 8 or not row[0].isdigit() or not PORT.fullmatch(row[1]) for row in rows):
        read_error("the MLAG port rows do not match the reported group count")
    result = {row[1]: {"mlag-id": row[0], "peer": row[4]} for row in rows}
    if len(result) != total:
        read_error("the MLAG port table repeats a local port")
    return result


def peers_readback(text):
    if "Multi-switch Link Aggregation Peers:" not in text or re.search(r"^\s*(?:%%|Error:)", text, re.M):
        read_error("the MLAG peers cannot be read")
    peers = {}
    blocks = re.split(r"^MLAG Peer\s*:\s*(\S+)\s*$", text, flags=re.M)
    if not blocks[1:] and blocks[0].strip() != "Multi-switch Link Aggregation Peers:":
        read_error("the empty MLAG peer list could not be established")
    for name, block in zip(blocks[1::2], blocks[2::2]):
        path = re.findall(r"^VLAN\s*:\s*(\S+)\s+Virtual Router\s*:\s*(\S+)", block, re.M)
        addresses = re.findall(r"^Local IP Address\s*:.*?Peer IP Address\s*:\s*(\S+)", block, re.M)
        statuses = re.findall(r"^Checkpoint Status\s*:\s*(\S+)", block, re.M)
        counts = re.findall(r"^MLAG ports[ \t]*:[ \t]*(\d+)\b", block, re.M)
        alternate = re.search(r"^Alternate path information:[ \t]*$", block, re.M)
        if (name in peers or len(statuses) != 1 or len(counts) != 1 or not path or len(path) != len(addresses)
                or "Authentication" not in block or (alternate and len(path) != 2)):
            read_error("an MLAG peer row is incomplete")
        vr, address = path[0][1], addresses[0]
        attrs = {} if address in ("0.0.0.0", "None") else {"peer-ip": address, "vr": vr}
        peers[name] = (attrs, statuses[0], {vlan.casefold() for vlan, _vr in path}, int(counts[0]))
    return peers


def stpd_readback(text, key):
    pattern = r"^Bridge Priority\s*:\s*(\d+)\s+Bridge Priority Mode:"
    values = re.findall(pattern, text, re.M)
    if len(values) != 1 or not re.search(r"^Stpd:[ \t]+" + re.escape(key) + r"[ \t]+Stp:", text, re.M | re.I):
        read_error("the STP domain priority could not be established")
    return {"priority": values[0]}


def stp_port_readback(text, detail, key, configured):
    domain, port = key.split(":", 1)
    row = re.findall(r"^\s*" + re.escape(port) + r"\s+\S+\s+\S+\s+(\d+)\s+(\S+)\s+", text, re.M)
    identity = rf"^Stpd:[ \t]+{re.escape(domain)}[ \t]+Port:[ \t]+{re.escape(port)}[ \t]+"
    guard = re.findall(r"^Edge Port Safe Guard[ \t]+:[ \t]+(Enabled|Disabled)\s*$", detail, re.M)
    bpdu = re.findall(r"^BPDU Restrict[ \t]+:[ \t]+(Enabled|Disabled)\s*$", detail, re.M)
    if (len(row) != 1 or not re.search(r"^Total Ports:\s*1\s*$", text, re.M) or "Config type" not in text
            or not re.search(identity, detail, re.M) or len(guard) != 1 or len(bpdu) != 1
            or "Participating Vlans:" not in detail):
        read_error("the requested port's STP state is incomplete")
    cost, flags = row[0]
    types = {"a": "auto", "b": "broadcast", "p": "point-to-point", "e": "edge"}
    if flags != "e--------" and (len(flags) != 10 or flags[2] not in types):
        read_error("the STP port flags cannot be evaluated")
    # A disabled domain suppresses the configured type flag.
    state = {"link-type": types.get(flags[2], configured.get("link-type", STP_LINK_DEFAULT)),
             "edge-safeguard": guard[0].lower(), "bpdu-restrict": bpdu[0].lower()}
    if "cost" in configured:
        state["cost"] = cost
    return state


def elrp_readback(text, key, inventory):
    lines = text.splitlines()
    bounds = [index for index, line in enumerate(lines) if re.fullmatch(r"-{10,}\s*", line)]
    count = re.findall(r"^Number of ELRP sessions:\s*(\d+)\s*$", text, re.M)
    if len(bounds) != 2 or len(count) != 1 or "Action :" not in text:
        read_error("the ELRP session list is incomplete")
    rows = [line.split() for line in lines[bounds[0] + 1:bounds[1]] if line.strip()]
    if any(len(row) < 2 for row in rows) or len(rows) != int(count[0]):
        read_error("the ELRP session rows do not match the reported count")
    selected = [row for row in rows if _same(row[1], key)]
    if not selected:
        return None
    if len(selected) != 1:
        read_error("the ELRP session for the VLAN is ambiguous")
    row = selected[0]
    if (len(row) not in (9, 10) or row[0] != "CLI" or row[4:6] != ["0", "Yes"]
            or not all(value.isdigit() for value in row[6:8])
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", row[3])
            or not re.fullmatch(r"[PLTCEI]+|-", row[8])):
        read_error("the periodic ELRP session attributes are incomplete")
    try:
        ports = membership.ports(row[2].lower(), inventory)
    except ValueError:
        read_error("the ELRP port list cannot be evaluated")
    if not ports or ports - inventory:
        read_error("the ELRP port list does not match the switch inventory")
    interval = row[3].rstrip("0").rstrip(".") if "." in row[3] else row[3]
    return {"ports": " ".join(sorted(ports)), "interval": interval, "action": row[8]}


def stpd_ports(text, key, snapshot):
    headline = rf"^Stpd:[ \t]+{re.escape(key)}[ \t]+Stp:[ \t]+\S+[ \t]+Number of Ports:[ \t]+(\d+)"
    count = re.findall(headline, text, re.M)
    values = re.findall(r"^Ports:[ \t]+(.*)$", text, re.M)
    if len(count) != 1 or len(values) > 1 or "Participating Vlans:" not in text:
        read_error("the STP domain port inventory is incomplete")
    total = int(count[0])
    if total == 0 and (not values or values[0].strip() in ("(none)", "None", "")):
        return set()
    if not values:
        read_error("the STP domain output does not identify its ports")
    ports = _port_set(values[0].strip(), snapshot)
    if len(ports) != total:
        read_error("the STP domain ports do not match their reported count")
    return ports
