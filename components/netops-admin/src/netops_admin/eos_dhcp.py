"""Scoped EOS IPv4 DHCP changes."""
from __future__ import annotations

import ipaddress
import json
import re

from netops_admin.errors import Rejected

RELAY = "dhcp-relay"
POOL = "dhcp-pool"
TABLES = {RELAY, POOL}
SERVER = "dhcp server"
INDENT = "   "
HELPER = re.compile(r"ip helper-address (\S+)(?: vrf (\S+))?")
SVI = re.compile(r"Vlan([1-9][0-9]{0,3})")
READBACK = "eos_dhcp_readback_unreadable"
RELAY_SHOW = "show ip dhcp relay | json"
SERVER_SHOW = "show dhcp server ipv4 | json"


def refuse(message, code=READBACK):
    return Rejected([message], reason_codes=[code])


def relay_key(key):
    interface, target = key.split(":")
    try:
        address = ipaddress.IPv4Address(target)
    except ValueError:
        raise refuse("the relay target must be an IPv4 address", "dhcp_invalid_target") from None
    if address.is_multicast or address.is_unspecified or address.is_loopback or int(address) == 0xffffffff:
        raise refuse("the relay target must be a unicast IPv4 address", "dhcp_invalid_target")
    return interface, str(address)


def entries(snapshot, table, factory):
    if table == POOL:
        return _pool_entries(snapshot, factory)
    found = {}
    for interface in snapshot.interfaces:
        if not SVI.fullmatch(interface):
            continue
        for line in snapshot.interface_lines(interface):
            if not line.startswith("ip helper-address "):
                continue
            address = line.split()[2]
            key = f"{interface}:{address}"
            if key in found:
                found[key].unsupported.append("duplicate IPv4 helper options")
                continue
            entry = found[key] = factory(key)
            match = HELPER.fullmatch(line)
            if match is None:
                entry.unsupported.append("unsupported IPv4 helper options")
            elif match[2]:
                entry.attributes["vrf"] = match[2]
    return found


def _helper_line(target, state):
    return f"ip helper-address {target}" + (f" vrf {state['vrf']}" if "vrf" in state else "")


def render(table, key, before, after, *, drop_parent=False):
    if table == POOL:
        return _render_pool(key, before, after, drop_parent)
    interface, target = relay_key(key)
    lines = ["configure terminal", "interface " + interface]
    if before is not None:
        lines.append("no ip helper-address " + target)
    if after is not None:
        lines.append(_helper_line(target, after))
    return [*lines, "end"]


def without_object(lines, table, key):
    if table == POOL:
        start, end = _pool_span(lines, key)
        kept = lines[:start] + lines[end:] if start is not None else list(lines)
        # The parent can be created by the first subnet. Its presence is checked separately.
        return [line for line in kept if line != SERVER and line.strip() != "!"]
    interface, target = relay_key(key)
    header = "interface " + interface
    prefix = "ip helper-address " + target
    kept, inside = [], False
    for line in lines:
        if line and not line.startswith(" "):
            inside = line == header
        if not (inside and (line.strip() == prefix or line.strip().startswith(prefix + " "))):
            kept.append(line)
    return kept


def snapshot_after(snapshot, plan):
    key, table = plan["key"], plan["table"]
    state = plan["predicted"]["after"]
    if table == POOL:
        return _pool_snapshot_after(snapshot.lines, key, state, "no dhcp server" in plan["commands"])
    lines = without_object(snapshot.lines, table, key)
    if state is not None:
        interface, target = relay_key(key)
        index = lines.index("interface " + interface) + 1
        lines.insert(index, "   " + _helper_line(target, state))
    return "\n".join(lines)


def _protected(interface, vrf, protected):
    if any(interface.casefold() in {str(name).casefold() for name in protected.get(table, ())}
           for table in ("interface", "l3-interface", "ports", "vlan-membership")):
        raise refuse("the DHCP SVI is protected", "port_protected")
    if interface[4:] in {str(vlan) for vlan in protected.get("vlan", ())}:
        raise refuse("the DHCP VLAN is protected", "port_management_vlan")
    if vrf.casefold() in {str(name).casefold() for name in protected.get("vrf", ())}:
        raise refuse("the DHCP SVI belongs to a protected VRF", "port_management_interface")


def prechecks(snapshot, table, key, before, after, protected, *, impact=None, undo=False):
    if table == POOL:
        _pool_prechecks(snapshot, key, before, after, protected or {}, impact, undo)
        return
    interface, address = relay_key(key)
    lines = snapshot.interface_lines(interface)
    if interface not in snapshot.interfaces or interface[4:] not in snapshot.vlans:
        raise refuse("DHCP relay requires an existing VLAN and SVI", "dhcp_invalid_target")
    if not any(line.startswith("ip address ") for line in lines):
        raise refuse("DHCP relay requires an IPv4 address on the SVI", "dhcp_invalid_target")
    vrf = next((line[4:] for line in lines if line.startswith("vrf ")), "default")
    _protected(interface, vrf, protected or {})
    requested_vrf = (after or {}).get("vrf")
    if requested_vrf:
        vrfs = {block.header.removeprefix("vrf instance ") for block in snapshot.blocks
                if block.header.startswith("vrf instance ")}
        if requested_vrf not in vrfs | {"default"}:
            raise refuse("the relay target VRF does not exist", "dhcp_invalid_target")
        if requested_vrf.casefold() in {str(item).casefold() for item in (protected or {}).get("vrf", ())}:
            raise refuse("the relay target VRF is protected", "port_management_interface")
    own = _helper_line(address, before or {})
    existing = any(line.startswith(("ip helper-address ", "ipv6 helper-address ", "ipv6 dhcp relay ",
                                    "dhcp server ipv4"))
                   and (not undo or line != own) for line in lines)
    existing |= global_relay(snapshot) or any(
        network.overlaps(local) for local in _interface_ipv4_networks(lines)
        for network in _pool_networks(snapshot, vrf)
    )
    if existing and impact != key:
        raise refuse("the SVI already has DHCP or relay. endpoint_impact must name the request key",
                     "endpoint_impact_required")


def operational_relay(text, key):
    interface, target = relay_key(key)
    try:
        content = json.loads(text)
        interfaces = content["configuredInterfaces"]
        if not isinstance(interfaces, dict) or type(content["activeState"]) is not bool:
            raise ValueError
        if interface not in interfaces:
            return None
        row = interfaces[interface]
        helpers = row["helpers"]
        if (not isinstance(helpers, list) or type(row["disabledV4"]) is not bool
                or type(row["usingGlobalModeServersV4"]) is not bool):
            raise ValueError
        found = []
        for helper in helpers:
            address = ipaddress.ip_address(helper["serverAddr"])
            vrf = helper["vrf"]
            if not isinstance(vrf, str) or not vrf:
                raise ValueError
            if str(address) == target:
                found.append(vrf)
        if not found:
            return None
        if len(found) != 1 or not content["activeState"] or row["disabledV4"] or row["usingGlobalModeServersV4"]:
            raise ValueError
        return {"vrf": found[0]} if found[0] != "default" else {}
    except (ValueError, KeyError, TypeError):
        raise refuse("EOS IPv4 DHCP relay readback is incomplete or inconsistent") from None


def canonical_changes(table, changes):
    if table == RELAY and changes.get("vrf") == "default":
        # The default target VRF is implicit in running-config.
        return {**changes, "vrf": None}
    if table == POOL and changes.get("reservations") is not None:
        try:
            return {**changes, "reservations": _reservation_text(_reservations(changes["reservations"]))}
        except (ValueError, TypeError):
            raise refuse("reservations must be distinct unicast MAC=IPv4 pairs", "dhcp_invalid_target") from None
    return changes


def global_relay(snapshot):
    return any(block.header == "dhcp relay" and any(line.strip().startswith("server ") for line in block.children)
               for block in snapshot.blocks)


def _interface_ipv4_networks(lines):
    networks = set()
    for line in lines:
        if match := re.fullmatch(r"ip address (\S+)(?: secondary)?", line):
            try:
                networks.add(ipaddress.IPv4Interface(match[1]).network)
            except ValueError:
                continue  # e.g. "ip address dhcp"
    return networks


def _pool_networks(snapshot, vrf="default"):
    server = SERVER if vrf == "default" else f"{SERVER} vrf {vrf}"
    for block in snapshot.blocks:
        if block.header != server:
            continue
        for line in block.children:
            if match := re.fullmatch(r"   subnet (\S+)", line):
                try:
                    network = ipaddress.ip_network(match[1])
                except ValueError:
                    raise refuse("EOS DHCP subnet configuration is not readable") from None
                if network.version == 4:
                    yield network


def pool_interface(snapshot, key):
    try:
        network = ipaddress.IPv4Network(key)
    except ValueError:
        raise refuse("the DHCP pool key must be a canonical IPv4 network prefix", "dhcp_invalid_target") from None
    if str(network) != key:
        raise refuse("the DHCP pool key must be a canonical IPv4 network prefix", "dhcp_invalid_target")
    candidates = []
    for name in snapshot.interfaces:
        if not SVI.fullmatch(name) or name[4:] not in snapshot.vlans:
            continue
        lines = snapshot.interface_lines(name)
        if any(line.startswith("vrf ") for line in lines):
            continue
        if network in _interface_ipv4_networks(lines):
            candidates.append(name)
    if len(candidates) != 1:
        raise refuse("the DHCP pool must match exactly one existing SVI in the default VRF", "dhcp_invalid_target")
    return candidates[0], network


def _pool_prechecks(snapshot, key, before, after, protected, impact, undo):
    interface, network = pool_interface(snapshot, key)
    _protected(interface, "default", protected)
    lines = snapshot.interface_lines(interface)
    if global_relay(snapshot) or any(line.startswith(("ip helper-address ", "ip dhcp relay ")) for line in lines):
        raise refuse("the DHCP pool SVI already has IPv4 relay", "eos_dhcp_conflict")
    if any(other != network and other.overlaps(network) for other in _pool_networks(snapshot)):
        raise refuse("another EOS DHCP pool overlaps this SVI", "eos_dhcp_conflict")
    if SERVER not in snapshot.lines and any(block.header.startswith(SERVER + " ") for block in snapshot.blocks):
        raise refuse("another VRF already uses the DHCP server and the default section cannot be created reversibly",
                     "eos_dhcp_conflict")
    if impact != key and not (undo and after is None):
        raise refuse("the DHCP pool targets an existing SVI. endpoint_impact must name the request key",
                     "endpoint_impact_required")
    if after is None:
        return
    try:
        gateway = ipaddress.IPv4Address(after["default-gateway"]) if "default-gateway" in after else None
        reservations = {ipaddress.IPv4Address(value) for value in _reservations(after.get("reservations")).values()}
        ip_range = _ip_range(after["range"]) if "range" in after else None
        used = reservations | ({gateway} if gateway is not None else set())
        if ip_range:
            start, end = ip_range
            used.update(ip_range)
            if gateway is not None and start <= gateway <= end:
                raise ValueError
        if any(address not in network or address in (network.network_address, network.broadcast_address)
               for address in used) or gateway in reservations:
            raise ValueError
    except ValueError:
        raise refuse("the range, gateway and reservations must use valid hosts in the pool",
                     "dhcp_invalid_target") from None


def _mac(value):
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", value):
        raise ValueError
    digits = value.replace(".", "").replace(":", "").lower()
    if not int(digits, 16) or int(digits[:2], 16) & 1:
        raise ValueError
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def _reservations(value):
    found = {}
    if value is None:
        return found
    for pair in value.split(","):
        address, ip = pair.split("=")
        mac, ip = _mac(address.strip()), str(ipaddress.IPv4Address(ip.strip()))
        if mac in found or ip in found.values():
            raise ValueError
        found[mac] = ip
    return found


def _reservation_text(values):
    return ",".join(f"{mac}={ip}" for mac, ip in sorted(values.items()))


def _ip_range(text):
    start, end = map(ipaddress.IPv4Address, text.split())
    if start > end:
        raise ValueError
    return start, end


def _lease_components(seconds):
    if type(seconds) not in (float, int) or not 60 <= seconds <= 172886340 or seconds % 60:
        raise ValueError
    return str(int(seconds) // 60)


def _lease_command(value):
    hours, minutes = divmod(int(value), 60)
    days, hours = divmod(hours, 24)
    return f"lease time {days} days {hours} hours {minutes} minutes"


def _pool_span(lines, key):
    if SERVER in lines:
        for index in range(lines.index(SERVER) + 1, len(lines)):
            line = lines[index]
            if line and not line.startswith(" "):
                break
            if line == f"{INDENT}subnet {key}":
                end = index + 1
                while end < len(lines) and lines[end].startswith(INDENT * 2):
                    end += 1
                return index, end
    return None, None


def _pool_attrs(lines):
    values, bindings = {}, []
    mac = None
    for line in lines:
        if not line.strip() or line.strip() == "!":
            continue
        if match := re.fullmatch(r"      (range|default-gateway) (.+)", line):
            name, value = match.groups()
            if name in values:
                raise ValueError
            values[name] = " ".join(map(str, _ip_range(value))) if name == "range" else str(ipaddress.IPv4Address(value))
        elif match := re.fullmatch(r"      lease time (\d+) days (\d+) hours (\d+) minutes", line):
            if "lease-minutes" in values:
                raise ValueError
            days, hours, minutes = map(int, match.groups())
            values["lease-minutes"] = _lease_components((days * 1440 + hours * 60 + minutes) * 60)
        elif line == "      reservations" and mac is None and not bindings:
            continue
        elif match := re.fullmatch(r"         mac-address (\S+)", line):
            if mac is not None:
                raise ValueError
            mac = _mac(match[1])
        elif (match := re.fullmatch(r"            ipv4-address (\S+)", line)) and mac is not None:
            bindings.append(f"{mac}={match[1]}")
            mac = None
        else:
            raise ValueError
    if mac is not None:
        raise ValueError
    if bindings:
        values["reservations"] = _reservation_text(_reservations(",".join(bindings)))
    return values


def _pool_entries(snapshot, factory):
    entries = {}
    for network in _pool_networks(snapshot):
        key = str(network)
        if key in entries:
            raise refuse("EOS returned duplicate pool definitions")
        entry = entries[key] = factory(key)
        start, end = _pool_span(snapshot.lines, key)
        try:
            entry.attributes.update(_pool_attrs(snapshot.lines[start + 1:end]))
        except ValueError:
            entry.unsupported.append("unsupported EOS DHCP subnet attributes")
    return entries


def _pool_delta(before, after):
    old, new = before or {}, after or {}
    commands = []
    if old.get("range") != new.get("range"):
        if "range" in old:
            commands.append("no range " + old["range"])
        if "range" in new:
            commands.extend(("range " + new["range"], "exit"))
    if old.get("lease-minutes") != new.get("lease-minutes"):
        commands.append(_lease_command(new["lease-minutes"]) if "lease-minutes" in new else "no lease time")
    if old.get("default-gateway") != new.get("default-gateway"):
        commands.append("default-gateway " + new["default-gateway"] if "default-gateway" in new else "no default-gateway")
    prior, wanted = _reservations(old.get("reservations")), _reservations(new.get("reservations"))
    if prior != wanted:
        commands.append("reservations")
        # Remove changed bindings before adding their replacements so the IP is available for a different MAC.
        commands.extend("no mac-address " + mac for mac in prior if prior[mac] != wanted.get(mac))
        for mac, ip in wanted.items():
            if prior.get(mac) != ip:
                commands.extend(("mac-address " + mac, "ipv4-address " + ip, "exit"))
        commands.append("exit")
    return commands


def _render_pool(key, before, after, drop_parent):
    if after is None:
        body = ["no " + SERVER] if drop_parent else [SERVER, "no subnet " + key]
    else:
        body = [SERVER, "subnet " + key, *_pool_delta(before, after)]
    return ["configure terminal", *body, "end"]


def _pool_snapshot_after(original, key, state, drop_parent):
    lines = list(original)
    start, end = _pool_span(lines, key)
    if start is not None:
        del lines[start:end]
    if drop_parent:
        lines.remove(SERVER)
    if state is not None:
        if SERVER not in lines:
            lines.insert(lines.index("end"), SERVER)
        rows = [INDENT + "subnet " + key]
        if "reservations" in state:
            rows.append(INDENT * 2 + "reservations")
            for mac, ip in _reservations(state["reservations"]).items():
                rows.extend((INDENT * 3 + "mac-address " + mac, INDENT * 4 + "ipv4-address " + ip))
        if "range" in state:
            rows.append(INDENT * 2 + "range " + state["range"])
        if "lease-minutes" in state:
            rows.append(INDENT * 2 + _lease_command(state["lease-minutes"]))
        if "default-gateway" in state:
            rows.append(INDENT * 2 + "default-gateway " + state["default-gateway"])
        index = lines.index(SERVER) + 1
        lines[index:index] = rows
    return "\n".join(lines)


def drop_created_parent(snapshot, key, undo_plan):
    if undo_plan is None or "no dhcp server" not in undo_plan["inverse"]:
        return False
    start, end = _pool_span(snapshot.lines, key)
    parent = snapshot.lines.index(SERVER)
    siblings = []
    for index in range(parent + 1, len(snapshot.lines)):
        line = snapshot.lines[index]
        if line and not line.startswith(" "):
            break
        if line.strip() and line.strip() != "!" and not start <= index < end:
            siblings.append(line)
    if siblings or any(block.header.startswith(SERVER + " ") for block in snapshot.blocks):
        raise refuse("the DHCP server contains configuration added outside the original pool",
                     "eos_dhcp_conflict")
    return True


def pool_parent_matches(snapshot, plan, side):
    commands = plan["commands"] if side == "after" else plan["inverse"]
    return (SERVER in snapshot.lines) == ("no dhcp server" not in commands)


def operational_pool(text, key):
    try:
        content = json.loads(text)["vrfs"]["default"]
        server = content["ipv4Server"]
        subnets = server["ipv4Subnets"]
        if (content["addressFamily"] != "ipv4" or not isinstance(subnets, dict)
                or not isinstance(server["ipv4Interfaces"], dict) or type(server["ipv4ServerActive"]) is not bool):
            raise ValueError
        if key not in subnets:
            return None
        subnet = subnets[key]
        if (subnet["subnet"] != key or type(subnet["activeLeases"]) is not int
                or any(subnet.get(field) for field in ("disabled", "disabledReason", "disableReason"))):
            raise ValueError
        result = {}
        ranges = subnet["ranges"]
        if not isinstance(ranges, list) or len(ranges) > 1:
            raise ValueError
        for row in ranges:
            start, end = _ip_range(row["startRangeAddress"] + " " + row["endRangeAddress"])
            if row["totalLeases"] != int(end) - int(start) + 1:
                raise ValueError
            result["range"] = f"{start} {end}"
        gateway = ipaddress.IPv4Address(subnet["defaultGateway"])
        if not gateway.is_unspecified:
            result["default-gateway"] = str(gateway)
        if "leaseDuration" in subnet:
            result["lease-minutes"] = _lease_components(subnet["leaseDuration"])
        rows = subnet.get("reservationsMacAddress", {})
        if not isinstance(rows, dict):
            raise ValueError
        pairs = []
        for mac, row in rows.items():
            if _mac(mac) != _mac(row["macAddress"]):
                raise ValueError
            pairs.append(f"{mac}={row['ipv4Address']}")
        if pairs:
            result["reservations"] = _reservation_text(_reservations(",".join(pairs)))
        return result
    except (ValueError, KeyError, TypeError):
        raise refuse("EOS IPv4 DHCP server readback is incomplete or inconsistent") from None
