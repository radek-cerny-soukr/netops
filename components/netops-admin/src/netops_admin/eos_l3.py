"""EOS static routes, L3 interfaces and first-hop redundancy configuration."""
from __future__ import annotations

import ipaddress
import re

from .errors import Rejected
from .ios import route_key, route_name

ROUTE = "static-route"
INTERFACE = "l3-interface"
ROUTING = "ip-routing"
VRRP = "vrrp"
VARP = "varp"
VARP_MAC = "varp-mac"
TABLES = frozenset((ROUTE, INTERFACE, ROUTING, VRRP, VARP, VARP_MAC))
GATEWAYS = frozenset((VRRP, VARP))
SVI = re.compile(r"Vlan([1-9][0-9]{0,3})")
ROUTE_LINE = re.compile(r"(ip|ipv6) route (?:vrf (\S+) )?(\S+)(?: (.*))?")
ROUTING_COMMANDS = {"ipv4": "ip routing", "ipv6": "ipv6 unicast-routing"}
ROUTING_LINE = re.compile(r"(no )?(ip routing|ipv6 unicast-routing)(?: vrf (\S+))?")
MAC_COMMAND = "ip virtual-router mac-address "
MAC_LINE = re.compile(re.escape(MAC_COMMAND) + r"((?:[\da-f]{2}:){5}[\da-f]{2}|[\da-f]{4}(?:\.[\da-f]{4}){2})",
                      re.IGNORECASE)
VARP_COMMAND = "ip virtual-router address "
VRRP_LINE = re.compile(r"vrrp ([1-9][0-9]{0,2}) (.+)")
INTERFACE_COMMANDS = {"description": "description ", "vrf": "vrf ",
                      "ipv4-address": "ip address ", "ipv6-address": "ipv6 address "}
INDENT = "   "


def target(table, key):
    return key.split(":", 1)[0] if table == VRRP else key


def canonical_changes(changes):
    values = dict(changes)
    if values.get("vrf") == "default":
        values["vrf"] = None
    for name in ("next-hop", "ipv4-address", "ipv6-address", "virtual-ip", "mac-address"):
        value = values.get(name)
        if value is None:
            continue
        try:
            if name == "mac-address":
                mac = value.lower().replace(":", "").replace(".", "")
                if len(mac) != 12 or int(mac, 16) == 0 or int(mac[:2], 16) & 1:
                    raise ValueError
                values[name] = ":".join(mac[n:n + 2] for n in range(0, 12, 2))
            elif name in ("ipv4-address", "ipv6-address"):
                if "/" not in value or "%" in value:
                    raise ValueError
                address = ipaddress.ip_interface(value)
                version = 4 if name == "ipv4-address" else 6
                if address.version != version or address.ip.is_unspecified or address.ip.is_multicast:
                    raise ValueError
                values[name] = str(address)
            else:
                address = ipaddress.ip_address(value)
                if (address.is_unspecified or address.is_multicast or address.is_loopback
                        or address.is_link_local or (name == "virtual-ip" and address.version != 4)):
                    raise ValueError
                values[name] = str(address)
        except ValueError:
            raise Rejected(["%s must be a valid unicast address in the profile format" % name]) from None
    return values


def _route_parts(line):
    match = ROUTE_LINE.fullmatch(line)
    if match is None:
        return None
    family, vrf, prefix, options = match.groups()
    try:
        network = ipaddress.ip_network(prefix)
    except ValueError:
        return None
    if (family == "ip") != (network.version == 4):
        return None
    return route_name(None if vrf == "default" else vrf, network), network, (options or "").split()


def _set(entry, name, value):
    if name in entry.attributes:
        entry.unsupported.append("multiple %s values" % name)
    entry.attributes[name] = value


def _interface_entry(entry, children, is_svi):
    for line in children:
        if line == "no switchport" and not is_svi:
            _set(entry, "mode", "routed")
        elif line == "shutdown":
            _set(entry, "admin-state", "disabled")
        elif line in ("no shutdown", "switchport"):
            # EOS omits these defaults in the measured platform.
            entry.unsupported.append("explicit interface default")
        else:
            for name, prefix in INTERFACE_COMMANDS.items():
                if line.startswith(prefix):
                    value = line[len(prefix):]
                    try:
                        if name.endswith("-address"):
                            value = canonical_changes({name: value})[name]
                    except Rejected:
                        entry.unsupported.append("unsupported %s" % name)
                    else:
                        _set(entry, name, value)
                    break


def _gateway_entry(entries, factory, name, children, table):
    for line in children:
        match = VRRP_LINE.fullmatch(line) if table == VRRP else None
        if match:
            key, value = name + ":" + match[1], match[2]
            entry = entries.setdefault(key, factory(key))
            if value.startswith("ipv4 ") and len(value.split()) == 2:
                _set(entry, "virtual-ip", value.split()[1])
            elif value.startswith("priority-level ") and len(value.split()) == 2:
                _set(entry, "priority", value.split()[1])
            else:
                entry.unsupported.append("additional VRRP settings")
        elif table == VARP and line.startswith(VARP_COMMAND):
            entry = entries.setdefault(name, factory(name))
            value = line[len(VARP_COMMAND):]
            if len(value.split()) == 1 and "/" not in value:
                _set(entry, "virtual-ip", value)
            else:
                entry.unsupported.append("VARP prefix or additional settings")


def entries(snapshot, table, factory, key=None):
    found = {}
    if table == INTERFACE or table in GATEWAYS:
        for name in snapshot.interfaces:
            if key is not None and name != target(table, key):
                continue
            svi = SVI.fullmatch(name) is not None
            if table == INTERFACE and (svi or name.startswith("Ethernet")):
                entry = found.setdefault(name, factory(name))
                _interface_entry(entry, snapshot.interface_lines(name), svi)
            elif svi and table in GATEWAYS:
                _gateway_entry(found, factory, name, snapshot.interface_lines(name), table)
        return found
    vrfs = vrf_names(snapshot)
    if table == ROUTING:
        found = {vrf: factory(vrf) for vrf in vrfs}
    if table == VARP_MAC:
        found = {"global": factory("global")}
    for block in snapshot.blocks:
        line = block.header
        if table == ROUTE and (route := _route_parts(line)):
            route_id, network, options = route
            entry = found.setdefault(route_id, factory(route_id))
            try:
                hop = canonical_changes({"next-hop": options[0]})["next-hop"]
                if (ipaddress.ip_address(hop).version != network.version or len(options) > 2
                        or (len(options) == 2 and not options[1].isdigit())):
                    raise ValueError
            except (ValueError, IndexError, Rejected):
                entry.unsupported.append("route has an interface next hop or additional options")
                continue
            _set(entry, "next-hop", hop)
            if len(options) == 2:
                _set(entry, "distance", options[1])
        if table == ROUTING and (routing := ROUTING_LINE.fullmatch(line)):
            disabled, command, vrf = routing.groups()
            entry = found.get(vrf or "default")
            if entry is not None:
                family = "ipv4" if command == ROUTING_COMMANDS["ipv4"] else "ipv6"
                _set(entry, family, "disabled" if disabled else "enabled")
        if table == VARP_MAC and (mac := MAC_LINE.fullmatch(line)):
            _set(found["global"], "mac-address", canonical_changes({"mac-address": mac[1]})["mac-address"])
    return found


def vrf_names(snapshot):
    return {"default"} | {block.header.split()[2] for block in snapshot.blocks
                          if re.fullmatch(r"vrf instance \S+", block.header)}


def _own_interface(table, key, line):
    if table == INTERFACE:
        return (line in ("no switchport", "switchport", "shutdown", "no shutdown")
                or line.startswith(tuple(INTERFACE_COMMANDS.values())))
    if table == VRRP:
        return line.startswith("vrrp " + key.split(":")[1] + " ")
    return line.startswith(VARP_COMMAND)


def _own_global(table, key, line):
    if table == ROUTE:
        route = _route_parts(line)
        return route is not None and route[0] == key
    if table == ROUTING:
        routing = ROUTING_LINE.fullmatch(line)
        return routing is not None and (routing[3] or "default") == key
    return MAC_LINE.fullmatch(line) is not None


def without_object(lines, table, key, *, keep_svi_header=False):
    """Use a stable comparison when EOS inserts or removes a block separator."""
    header = "interface " + target(table, key)
    in_target = False
    for line in lines:
        if not line.startswith(" "):
            in_target = line == header
            if table == INTERFACE and SVI.fullmatch(key) and in_target and not keep_svi_header:
                continue
            if table not in GATEWAYS and table != INTERFACE and _own_global(table, key, line):
                continue
        if in_target and line.startswith(" ") and _own_interface(table, key, line.strip()):
            continue
        yield line


def _route_command(key, state, *, remove=False):
    vrf, network = route_key(key)
    command = ["ipv6" if network.version == 6 else "ip", "route"]
    if vrf:
        command += ["vrf", vrf]
    command += [str(network), state["next-hop"]]
    if not remove and "distance" in state:
        command.append(state["distance"])
    return ("no " if remove else "") + " ".join(command)


def config_lines(table, key, state):
    if table == ROUTE:
        return [_route_command(key, state)]
    if table == ROUTING:
        suffix = "" if key == "default" else " vrf " + key
        commands = [command + suffix for name, command in ROUTING_COMMANDS.items() if name in state]
        if key != "default" and "ipv4" not in state:
            commands.insert(0, "no ip routing" + suffix)
        return commands
    if table == VARP_MAC:
        return [MAC_COMMAND + state["mac-address"]] if state else []
    if table == VARP:
        return [VARP_COMMAND + state["virtual-ip"]]
    if table == VRRP:
        prefix = "vrrp " + key.split(":")[1] + " "
        return ([prefix + "priority-level " + state["priority"]] if "priority" in state else []) + [
            prefix + "ipv4 " + state["virtual-ip"]]
    lines = ["no switchport"] if state.get("mode") == "routed" else []
    lines.extend(command + state[name] for name, command in INTERFACE_COMMANDS.items() if name in state)
    if state.get("admin-state") == "disabled":
        lines.append("shutdown")
    return lines


def _interface_updates(before, after):
    commands = []
    old_mode, new_mode = before.get("mode"), after.get("mode")
    if old_mode != new_mode and new_mode == "routed":
        commands.append("no switchport")
    for name, command in INTERFACE_COMMANDS.items():
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        if old and (new is None or name == "ipv6-address"):
            commands.append("no " + (command + old if name == "ipv6-address" else command.rstrip()))
        if new:
            commands.append(command + new)
    if old_mode != new_mode and new_mode is None:
        commands.append("switchport")
    if before.get("admin-state") != after.get("admin-state"):
        commands.append("shutdown" if "admin-state" in after else "no shutdown")
    return commands


def render(table, key, before, after):
    old, new = before or {}, after or {}
    if table == ROUTE:
        commands = config_lines(table, key, new) if new else []
        if old and old["next-hop"] != new.get("next-hop"):
            commands.append(_route_command(key, old, remove=True))
    elif table == ROUTING:
        suffix = "" if key == "default" else " vrf " + key
        commands = [("" if name in new else "no ") + command + suffix
                    for name, command in ROUTING_COMMANDS.items() if old.get(name) != new.get(name)]
    elif table == VARP_MAC:
        commands = config_lines(table, key, new) if new else ["no " + MAC_COMMAND + old["mac-address"]]
    else:
        header = "interface " + target(table, key)
        if table == INTERFACE and after is None:
            commands = ["no " + header]
        elif table == INTERFACE:
            commands = [header] + _interface_updates(old, new)
        elif table == VARP:
            commands = [header]
            if old:
                commands.append("no " + VARP_COMMAND + old["virtual-ip"])
            if new:
                commands.extend(config_lines(table, key, new))
        else:
            commands = [header]
            prefix = "vrrp " + key.split(":")[1]
            if not new:
                commands.append("no " + prefix)
            else:
                if old.get("priority") != new.get("priority"):
                    commands.append(prefix + " priority-level " + new["priority"] if "priority" in new
                                    else "no " + prefix + " priority-level")
                if old.get("virtual-ip") != new.get("virtual-ip"):
                    commands.append(prefix + " ipv4 " + new["virtual-ip"])
    return ["configure terminal", *commands, "end"]


def snapshot_after(snapshot, plan):
    table, key = plan["table"], plan["key"]
    state = plan["predicted"]["after"]
    header = "interface " + target(table, key)
    lines = list(without_object(snapshot.lines, table, key, keep_svi_header=state is not None))
    if state is None:
        return "\n".join(lines)
    if table == INTERFACE and SVI.fullmatch(key):
        # The block header is excluded from the comparison but needed in the prediction.
        if header not in lines:
            lines[lines.index("end"):lines.index("end")] = [header, "!"]
    if table == INTERFACE or table in GATEWAYS:
        index = lines.index(header) + 1
        lines[index:index] = [INDENT + line for line in config_lines(table, key, state)]
    else:
        index = lines.index("end")
        lines[index:index] = config_lines(table, key, state)
    return "\n".join(lines)


def _check_vrf(snapshot, vrf, protected):
    if vrf not in vrf_names(snapshot):
        raise Rejected(["VRF %s does not exist" % vrf])
    if vrf.casefold() in {name.casefold() for name in protected.get("vrf", ())}:
        raise Rejected(["VRF %s is protected" % vrf], reason_codes=["port_protected"])


def interface_vrf(snapshot, key):
    return next((line[4:] for line in snapshot.interface_lines(key) if line.startswith("vrf ")), "default")


def _interface_prechecks(snapshot, key, op, before, after):
    lines = snapshot.interface_lines(key)
    svi = SVI.fullmatch(key)
    if not svi:
        if op != "update" or key not in snapshot.interfaces:
            raise Rejected(["a physical Ethernet interface can only be updated"])
        if any(line.startswith("channel-group ") for line in lines):
            raise Rejected(["the port belongs to a port-channel"], reason_codes=["port_lag_member"])
        if any(line.startswith(("switchport trunk ", "switchport mode trunk")) for line in lines):
            raise Rejected(["the port is a trunk"], reason_codes=["port_uplink"])
        changing_link = any(before.get(name) != after.get(name)
                            for name in ("mode", "ipv4-address", "ipv6-address", "admin-state"))
        if changing_link and any(
                not _own_interface(INTERFACE, key, line) and not line.startswith(("mtu ", "speed "))
                for line in lines):
            raise Rejected(["changing the port would affect configuration outside the L3 profile"])
        if any(name in after for name in ("ipv4-address", "ipv6-address", "vrf")) and after.get("mode") != "routed":
            raise Rejected(["an Ethernet port must be routed to hold L3 settings"])
    elif "mode" in (after or {}):
        raise Rejected(["an SVI has no switchport mode"])
    if any(line.startswith(("ip address ", "ipv6 address ")) and not
           any(line == name + " " + value for name, value in (
               ("ip address", (before or {}).get("ipv4-address", "")),
               ("ipv6 address", (before or {}).get("ipv6-address", ""))))
           for line in lines):
        raise Rejected(["the interface holds additional or unsupported IP addresses"])
    if op == "delete":
        if any(not _own_interface(INTERFACE, key, line) for line in lines):
            raise Rejected(["the SVI has configuration outside the L3 profile"])
        reference = re.compile(r"(?<![\w/.-])(?:%s|Vlan %s)(?![\w/.-])" % (key, svi[1]), re.IGNORECASE)
        if any(reference.search(line) for block in snapshot.blocks
               if block.header != "interface " + key and not re.fullmatch(r"vlan [0-9,-]+", block.header)
               for line in (block.header, *block.children) if not line.lstrip().startswith("description ")):
            raise Rejected(["the SVI is referenced in the configuration"])
    if after is not None:
        for name in ("ipv4-address", "ipv6-address"):
            if name not in after or (before or {}).get(name) == after[name]:
                continue
            address = ipaddress.ip_interface(after[name])
            if address.version == 4 and address.network.prefixlen < 31 and address.ip in (
                    address.network.network_address, address.network.broadcast_address):
                raise Rejected(["the interface address is the network or broadcast address"])
            vrf = after.get("vrf", "default")
            for other in snapshot.interfaces:
                if other == key or interface_vrf(snapshot, other) != vrf:
                    continue
                for line in snapshot.interface_lines(other):
                    if line.startswith(INTERFACE_COMMANDS[name]):
                        try:
                            existing = ipaddress.ip_interface(line.split()[2])
                        except ValueError:
                            continue
                        if address.network.overlaps(existing.network):
                            raise Rejected(["the interface address overlaps %s in VRF %s" % (other, vrf)])
        if (before or {}).get("ipv4-address") != after.get("ipv4-address") and any(
                line.startswith(("vrrp ", VARP_COMMAND)) for line in lines):
            raise Rejected(["remove the gateway configuration before changing its SVI IPv4 address"])


def prechecks(snapshot, table, key, op, before, after, protected):
    protected = protected or {}
    if table == ROUTE:
        vrf, network = route_key(key)
        if vrf == "default":
            raise Rejected(["omit vrf:default: from a route in the default VRF"])
        _check_vrf(snapshot, vrf or "default", protected)
        if after and ipaddress.ip_address(after["next-hop"]).version != network.version:
            raise Rejected(["the route and its next hop must use the same address family"])
        return
    if table == ROUTING:
        _check_vrf(snapshot, key, protected)
        return
    if table == VARP_MAC:
        if any(line.startswith((VARP_COMMAND, "ipv6 virtual-router address ", "ip address virtual ",
                                "ipv6 address virtual "))
               for name in snapshot.interfaces for line in snapshot.interface_lines(name)):
            raise Rejected(["the global virtual MAC is in use by a virtual router"])
        return
    name = target(table, key)
    svi = SVI.fullmatch(name)
    guarded = {item.casefold() for field in ("interface", "ports", INTERFACE, VARP, VRRP)
               for item in protected.get(field, ())}
    if name.casefold() in guarded or (svi and svi[1] in {str(vid) for vid in protected.get("vlan", ())}):
        raise Rejected(["the affected interface or VLAN is protected"], reason_codes=["port_protected"])
    if svi and (not 1 <= int(svi[1]) <= 4094 or svi[1] not in snapshot.vlans):
        raise Rejected(["the VLAN of %s does not exist" % name], reason_codes=["vlan_missing"])
    vrf = interface_vrf(snapshot, name)
    _check_vrf(snapshot, (after or {}).get("vrf", vrf), protected)
    if table == INTERFACE:
        _interface_prechecks(snapshot, key, op, before, after)
        return
    if table == VRRP and not 1 <= int(key.split(":")[1]) <= 255:
        raise Rejected(["VRRP group must be between 1 and 255"])
    if name not in snapshot.interfaces:
        raise Rejected(["the gateway requires an existing SVI"])
    if before is not None and "virtual-ip" not in before:
        raise Rejected(["existing gateway has no restorable primary IPv4 address"])
    if after is None:
        return
    lines = snapshot.interface_lines(name)
    for line in lines:
        if (table == VRRP and line.startswith(VARP_COMMAND)
                or table == VARP and line.startswith("vrrp ")):
            raise Rejected(["the SVI already has a different gateway protocol"])
    ipv4 = next((line.split()[2] for line in lines if line.startswith("ip address ")), "")
    try:
        interface = ipaddress.IPv4Interface(ipv4)
    except ValueError:
        raise Rejected(["the gateway requires a static IPv4 address on the SVI"]) from None
    address = ipaddress.IPv4Address(after["virtual-ip"])
    if address not in interface.network or address in (interface.ip, interface.network.network_address,
                                                       interface.network.broadcast_address):
        raise Rejected(["the gateway must use a free host address within the SVI subnet"])
    if table == VARP and not any(MAC_LINE.fullmatch(block.header) for block in snapshot.blocks):
        raise Rejected(["configure the global VARP MAC before adding a gateway"])
