"""ExtremeXOS configuration of OSPF, OSPFv3 and IPv4 unicast BGP in VR-Default."""
from __future__ import annotations

import ipaddress
import re

from netops_admin import membership
from netops_admin.errors import Rejected

AREA = "ospf-area"
INTERFACE = "ospf-interface"
OSPF = "ospf"
BGP = "bgp"
PEER = "bgp-neighbor"
TABLES = (AREA, INTERFACE, OSPF, BGP, PEER)
OSPF_PROTOCOLS = ("ospf", "ospfv3")
DEFAULT_VR = "VR-Default"
BACKBONE = "0.0.0.0"
POLICIES = {"import-policy": "in", "export-policy": "out"}
VLAN_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
POLICY_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")


def refuse(message):
    raise Rejected([message], reason_codes=["exos_routing_scope"])


def read_error(message):
    raise Rejected([message], reason_codes=["exos_routing_readback_unreadable"])


def protocol(table, key):
    return BGP if table in (BGP, PEER) else key.split(":", 1)[0]


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        refuse("the area or peer must be an IPv4 address in dotted decimal")


def as_number(value):
    # The display format may be ASPLAIN or ASDOT, independently of the input.
    parts = value.split(".")
    if not all(part.isascii() and part.isdecimal() for part in parts):
        raise ValueError("invalid AS number")
    if len(parts) == 1 and int(parts[0]) <= 4294967295:
        return str(int(parts[0]))
    if len(parts) == 2 and all(int(part) <= 65535 for part in parts):
        high, low = map(int, parts)
        return str(high * 65536 + low)
    raise ValueError("invalid AS number")


def _ospf_line(proto, line):
    match line:
        case ("enable",) | ("disable",):
            return OSPF, proto, {"admin-state": line[0] + "d"}
        case ("create", "area", area):
            return AREA, f"{proto}:{ipv4(area)}", {}
        case ("configure", "add", "vlan", vlan, *options):
            if proto == "ospfv3" and options[:2] == ["instance-id", "0"]:
                options = options[2:]
            match options:
                case ["area", area, *mode] if VLAN_NAME.fullmatch(vlan):
                    if mode[:2] == ["link-type", "auto"]:
                        mode = mode[2:]
                    if mode in ([], ["passive"]):
                        return INTERFACE, f"{proto}:{vlan}", {"area": ipv4(area), "passive": "yes" if mode else "no"}
        case ("configure", "vlan", vlan, "cost", cost):
            if VLAN_NAME.fullmatch(vlan) and (cost == "automatic" or cost.isdecimal() and 1 <= int(cost) <= 65535):
                return INTERFACE, f"{proto}:{vlan}", {"cost": cost}
    return None


def _bgp_line(line):
    match line:
        case ("configure", "AS-number", value):
            return BGP, DEFAULT_VR, {"local-as": as_number(value)}
        case ("create", "neighbor", peer, "remote-AS-number", value):
            remote_as = as_number(value)
            if remote_as != "0":
                return PEER, ipv4(peer), {"remote-as": remote_as}
        case ("enable" | "disable", "neighbor", peer):
            return PEER, ipv4(peer), {"admin-state": line[0] + "d"}
        case ("configure", "neighbor", peer, *options):
            if options[:2] == ["address-family", "ipv4-unicast"]:
                options = options[2:]
            if len(options) == 3 and options[0] == "route-policy" and POLICY_NAME.fullmatch(options[2]):
                for attr, direction in POLICIES.items():
                    if options[1] == direction:
                        return PEER, ipv4(peer), {attr: options[2]}
    return None


def _decode(command, proto):
    if command.module != proto or command.upm_profile or command.tokens[1:2] != (proto,):
        return None
    try:
        line = (command.tokens[0], *command.tokens[2:])
        return _bgp_line(line) if proto == BGP else _ospf_line(proto, line)
    except (ValueError, Rejected):
        return None


def require_module(snapshot, table, key):
    proto = protocol(table, key)
    modules = snapshot.configuration.modules
    if proto not in modules or modules[-1] == proto or snapshot.configuration.unterminated_upm:
        read_error(f"the {proto} configuration module is incomplete")


def _module(snapshot, proto):
    return (command for command in snapshot.commands if command.module == proto and not command.upm_profile)


def entries(snapshot, table, entry_type):
    result = {}
    protocols = (BGP,) if table in (BGP, PEER) else OSPF_PROTOCOLS
    for proto in protocols:
        # The sibling OSPF version may be absent on some devices. The selected module is checked against its own key.
        if proto not in snapshot.configuration.modules:
            continue
        if table == proto or table == OSPF:
            key = DEFAULT_VR if proto == BGP else proto
            result[key] = entry_type(key)
        for command in _module(snapshot, proto):
            decoded = _decode(command, proto)
            if decoded is None or decoded[0] != table:
                continue
            _, key, attributes = decoded
            entry = result.setdefault(key, entry_type(key))
            if entry.attributes.keys() & attributes.keys():
                entry.unsupported.append(f"line {command.line}: repeated routing setting")
            entry.attributes.update(attributes)
    for entry in result.values():
        attributes = entry.attributes
        if attributes.get("cost") == "automatic":
            attributes.pop("cost")
        if attributes.get("local-as") == "0":
            attributes.pop("local-as")
        for attr in POLICIES:
            if attributes.get(attr, "").casefold() == "none":
                attributes.pop(attr)
        required = {INTERFACE: "area", PEER: "remote-as"}.get(table)
        if required and required not in attributes:
            entry.unsupported.append(f"no supported {required} found")
    return result


def owns(command, table, key):
    decoded = _decode(command, protocol(table, key))
    return decoded is not None and decoded[:2] == (table, key)


def precheck(snapshot, table, key, before, after, entry_type):
    proto = protocol(table, key)
    name = key.split(":", 1)[-1]
    if table in (AREA, PEER):
        ipv4(name)
    if table == AREA and name == BACKBONE:
        refuse("the built-in backbone area cannot be created or removed")
    if table == INTERFACE and name.casefold() == "all":
        refuse("an OSPF request must name a single VLAN")
    for command in _module(snapshot, proto):
        tokens = {token.casefold() for token in command.tokens[2:]}
        if command.tokens[:3] == ("configure", proto, "routerid") and len(command.tokens) == 4:
            continue
        if _decode(command, proto) is None and (
                table in (OSPF, BGP) or name.casefold() in tokens or "all" in tokens or tokens & {"vr", "vrf"}):
            refuse(f"line {command.line} has {proto} settings outside this routing profile")
    if table == AREA and after is None:
        if any(name in command.tokens[2:] and not owns(command, table, key) for command in _module(snapshot, proto)):
            refuse("the OSPF area still has routing settings or interfaces")
    if table == INTERFACE and after:
        area = after["area"]
        if area != BACKBONE and f"{proto}:{area}" not in entries(snapshot, AREA, entry_type):
            refuse("the requested OSPF area does not exist")
    if table == BGP and entries(snapshot, PEER, entry_type):
        refuse("the local AS can only change while BGP has no neighbors")
    if table == PEER and after:
        if any(after.get(attr, "").casefold() in ("all", "none") for attr in POLICIES):
            refuse("a named BGP policy is required; remove the attachment with null")


def _ospf_membership(proto, vlan, state):
    suffix = " passive" if state.get("passive") == "yes" else ""
    return f"configure {proto} add vlan {vlan} area {state['area']}{suffix}"


def _ospf_commands(proto, vlan, before, after):
    reattach = before is None or after is None or any(
        before.get(attr) != after.get(attr) for attr in ("area", "passive"))
    lines = []
    old_cost = (before or {}).get("cost")
    new_cost = (after or {}).get("cost")
    if after is None and old_cost is not None:
        lines.append(f"configure {proto} vlan {vlan} cost automatic")
    if reattach and before is not None:
        lines.append(f"configure {proto} delete vlan {vlan}")
    if after is None:
        return lines
    if reattach:
        lines.append(_ospf_membership(proto, vlan, after))
    if old_cost != new_cost:
        lines.append(f"configure {proto} vlan {vlan} cost {new_cost or 'automatic'}")
    return lines


def _peer_commands(peer, before, after):
    if after is None:
        return [f"delete bgp neighbor {peer}"]
    lines = []
    if before is None:
        lines.append(f"create bgp neighbor {peer} remote-AS-number {after['remote-as']}")
    before = before or {}
    for attr, direction in POLICIES.items():
        if before.get(attr) != after.get(attr):
            lines.append(f"configure bgp neighbor {peer} route-policy {direction} {after.get(attr, 'none')}")
    if before.get("admin-state") != after.get("admin-state"):
        action = "enable" if after.get("admin-state") == "enabled" else "disable"
        lines.append(f"{action} bgp neighbor {peer}")
    return lines


def render(table, key, before, after):
    proto = protocol(table, key)
    if table == AREA:
        action = "create" if after is not None else "delete"
        return [f"{action} {proto} area {key.split(':', 1)[1]}"]
    if table == INTERFACE:
        return _ospf_commands(proto, key.split(":", 1)[1], before, after)
    if table == OSPF:
        action = "enable" if after.get("admin-state") == "enabled" else "disable"
        return [f"{action} {proto}"]
    if table == BGP:
        return [f"configure bgp AS-number {after.get('local-as', '0')}"]
    return _peer_commands(key, before, after)


def prediction(snapshot, table, key, state):
    proto = protocol(table, key)
    kept = [command for command in snapshot.commands if not owns(command, table, key)]
    if table == OSPF:
        added = [f"enable {proto}"] if state else []
    elif table == BGP:
        added = [f"configure bgp AS-number {state['local-as']}"] if state else []
    else:
        added = render(table, key, None, state) if state is not None else []
    return "\n".join(membership.modular(snapshot, kept, added, module=proto)) + "\n"


def ospf_status(text, proto):
    state = re.findall(rf"(?m)^{proto}\s*:\s*(Enabled|Disabled)\b", text, re.IGNORECASE)
    footer = (r"(?m)^# of Inter-VR Exports:\s*\d+\s*$" if proto == OSPF else
              r"(?m)^\s+host-mobility\s+(?:Enabled|Disabled)\b")
    if len(state) != 1 or not re.search(footer, text):
        read_error("the OSPF process status is incomplete")
    return {"admin-state": state[0].lower()}


def ospf_areas(text, proto):
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    if len(rows) < 3 or not rows[0].startswith("AREA ID ") or not rows[1].startswith("Metric ABR"):
        read_error("the OSPF area table is incomplete")
    result = {}
    numeric_fields = 6 if proto == "ospfv3" else 5
    row = re.compile(r"(\S+)\s+(\S+)\s+\S+\s+\S+" + r"\s+\d+" * (numeric_fields - 1) + r"\s+0x[0-9a-f]+")
    for line in rows[2:]:
        match = row.fullmatch(line)
        if match is None:
            read_error("an OSPF area row is incomplete")
        area, kind = match.groups()
        try:
            area = str(ipaddress.IPv4Address(area))
        except ValueError:
            read_error("the OSPF area table contains an invalid area")
        if area in result:
            read_error("the OSPF area table has duplicate entries")
        result[area] = kind
    if result.get(BACKBONE) != "NORM":
        read_error("the OSPF area table has no backbone")
    return result


def ospf_interface(text, proto, vlan):
    if proto == OSPF:
        identity = re.findall(r"(?m)^Interface\([^\n]+\):\s+\S+\s+Vlan:\s+(\S+)\s+OSPF:\s+(ENABLED|DISABLED)\s+Router:\s+\S+", text)
        details = re.findall(r"(?m)^AreaId:\s+(\S+)\s+RtId:[^\n]+\s+Passive:\s+(Yes|No)\s*$", text)
        costs = re.findall(r"(?m)^Cost:\s+(\d+)/([AC])\s+Priority:", text)
    else:
        identity = re.findall(r"(?m)^Interface\s*:\s*(\S+)\s+Enabled\s*:\s*(ENABLED|DISABLED)\s*$", text)
        area = re.findall(r"(?m)^Router\s*:\s*\S+\s+AreaID\s*:\s*(\S+)\s*$", text)
        passive = re.findall(r"(?m)^Passive\s*:\s*(Yes|No)\s+Cost\s*:\s*(\d+)/([AC])\s*$", text)
        details = [(area[0], passive[0][0])] if len(area) == len(passive) == 1 else []
        costs = [passive[0][1:]] if details else []
        if re.findall(r"(?m)\bInstance ID\s*:\s*(\d+)\s*$", text) != ["0"]:
            read_error("the selected OSPFv3 interface instance is unknown")
    if (len(identity) != 1 or len(details) != 1 or len(costs) != 1 or identity[0][0] != vlan
            or not re.search(r"(?m)^Neighbors:\s*$", text)):
        read_error("the selected OSPF interface is incomplete or ambiguous")
    enabled = identity[0][1] == "ENABLED"
    area, passive = details[0]
    cost, cost_kind = costs[0]
    if not enabled:
        if cost_kind == "C" or passive == "Yes":
            read_error("the VLAN has OSPF settings without area membership")
        return None
    try:
        state = {"area": str(ipaddress.IPv4Address(area)), "passive": passive.lower()}
    except ValueError:
        read_error("the selected OSPF interface reports an invalid area")
    if cost_kind == "C":
        state["cost"] = cost
    return state


def bgp_status(text):
    enabled = re.findall(r"(?m)^Enabled\s*:\s*(Yes|No)\s+OperStatus\s*:\s*\S+", text)
    asn = re.findall(r"(?m)^RouterId\s*:\s*\S+\s+AS\s*:\s*([0-9.]+)\s*$", text)
    if len(enabled) != 1 or len(asn) != 1 or not re.search(r"(?m)^\s*l2vpn-evpn\s*:\s*(Enabled|Disabled)\s*$", text):
        read_error("the BGP process status is incomplete")
    try:
        return enabled[0] == "Yes", as_number(asn[0])
    except ValueError:
        read_error("the BGP process reports an invalid local AS")


def bgp_peers(text):
    total = re.findall(r"(?m)^\s*Total Peers\s*:\s*(\d+)\s*$", text)
    start = re.search(r"(?m)^\s*Peer\s+AS\s+Weight\s+State\s+InMsgs[^\n]*\n-+\s*$", text)
    end = re.search(r"(?m)^Flags:\s+\(d\) disabled, \(e\) enabled,", text)
    if len(total) != 1 or start is None or end is None or end.start() < start.end():
        read_error("the BGP peer summary is incomplete")
    lines = [line.strip() for line in text[start.end():end.start()].splitlines() if line.strip()]
    if len(lines) != int(total[0]) or not re.search(r"(?m)^\s*Enabled\s*:\s*\d+\s+Disabled\s*:\s*\d+\s*$", text):
        read_error("the BGP peer summary does not match its total")
    peers = {}
    for line in lines:
        row = re.fullmatch(r"([EI][de][m-][r-])\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\d+\s+\d+\s+\(\s*\d+\s*\)\s+\S+", line)
        if row is None:
            read_error("a BGP peer row is incomplete")
        flags, address, remote_as = row.groups()
        try:
            address = str(ipaddress.ip_address(address))
            remote_as = as_number(remote_as)
        except ValueError:
            read_error("a BGP peer row has an invalid address or AS")
        if address in peers:
            read_error("the BGP peer summary repeats a peer")
        peers[address] = {"remote-as": remote_as, "admin-state": "enabled" if flags[1] == "e" else "disabled"}
    return peers


def bgp_peer(text, peer, summary):
    identity = re.findall(r"(?m)^[EI]BGP Peer\s*:\s*(\S+)\s+AS\s*:\s*(\S+)\s*$", text)
    enabled = re.findall(r"(?m)^Enabled\s*:\s*(Yes|No)\s+OperStatus\s*:\s*\S+", text)
    unicast = re.findall(r"(?m)^Policy for NLRI Type ipv4-unicast\s*\n([\s\S]*?)(?=^Policy for NLRI Type )", text)
    if len(identity) != 1 or identity[0][0] != peer or len(enabled) != 1 or len(unicast) != 1:
        read_error("the selected BGP peer details are incomplete")
    try:
        remote_as = as_number(identity[0][1])
    except ValueError:
        read_error("the selected BGP peer reports an invalid AS")
    state = {"remote-as": remote_as, "admin-state": "enabled" if enabled[0] == "Yes" else "disabled"}
    if state != summary:
        read_error("the BGP peer summary and detailed state differ")
    for attr, direction in POLICIES.items():
        policy = re.findall(rf"(?m)^\s+{direction.title()} Policy\s*:\s*(\S+)\s*$", unicast[0])
        if len(policy) != 1 or POLICY_NAME.fullmatch(policy[0]) is None:
            read_error("the BGP peer IPv4 unicast policy fields are incomplete")
        if policy[0].casefold() != "none":
            state[attr] = policy[0]
    return state
