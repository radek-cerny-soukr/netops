"""EOS port-channel, MLAG and spanning-tree profile state and rendering."""

import re

from netops_admin.errors import Rejected
from netops_admin.ios import vlan_numbers, vlan_text

CHANNEL = "port-channel"
MEMBER = "port-channel-member"
MLAG_PORT = "mlag-port"
MLAG_PEER = "mlag-peer"
STP_PORT = "stp-port"
STP_VLAN = "stp-vlan"
TABLES = {CHANNEL, MEMBER, MLAG_PORT, MLAG_PEER, STP_PORT, STP_VLAN}
ETHERNET = r"Ethernet[1-9][0-9]{0,2}(?:/[1-9][0-9]{0,2}){0,2}"
CHANNEL_NAME = r"Port-Channel[1-9][0-9]{0,5}"
VLAN_NAME = r"Vlan[1-9][0-9]{0,3}"
GROUP = re.compile(r"channel-group ([1-9][0-9]{0,5}) mode (active|passive|on)")
VLAN_PRIORITY = re.compile(r"spanning-tree vlan(?:-id)? ([0-9,-]+) priority ([0-9]{1,5})")
MLAG_HEADER = "mlag configuration"
INDENT = "   "
FIELDS = {
    CHANNEL: {"description": ("description", r".+")},
    MLAG_PORT: {"mlag-id": ("mlag", r"[1-9][0-9]{0,3}")},
    MLAG_PEER: {
        "local-interface": ("local-interface", VLAN_NAME),
        "peer-address": ("peer-address", r"[0-9.]+"),
        "peer-link": ("peer-link", r"(?:%s|%s)" % (CHANNEL_NAME, ETHERNET)),
    },
    STP_PORT: {
        "portfast": ("spanning-tree portfast", r"edge|normal|network"),
        "bpdu-guard": ("spanning-tree bpduguard", r"enable|disable"),
        "cost": ("spanning-tree cost", r"[1-9][0-9]{0,8}"),
    },
}


def _owned(table, line):
    if table == MEMBER:
        return line == "channel-group" or line.startswith("channel-group ")
    if table == MLAG_PEER and line.startswith("peer-address heartbeat"):
        return False
    if table == STP_PORT and line in {"spanning-tree portfast auto", "no spanning-tree portfast auto"}:
        return False
    if table == STP_PORT and line.startswith("spanning-tree bpduguard rate-limit "):
        return False
    return any(line == prefix or line.startswith(prefix + " ") for prefix, _ in FIELDS[table].values())


def parse_lines(table, lines):
    """Parse just the profile's statements. Unrelated lines stay in the snapshot digest."""
    state, unsupported = {}, []
    for line in lines:
        if not _owned(table, line):
            continue
        if table == MEMBER:
            match = GROUP.fullmatch(line)
            values = {"group": match[1], "mode": match[2]} if match else {}
        elif table == STP_PORT and line == "spanning-tree portfast":
            values = {"portfast": "edge"}
        else:
            values = {}
            for name, (prefix, pattern) in FIELDS[table].items():
                value = line.removeprefix(prefix + " ")
                if value != line and re.fullmatch(pattern, value):
                    values[name] = value
                    break
        if not values or state.keys() & values.keys():
            unsupported.append("unexpected or duplicate %s statement" % table)
        state.update(values)
    return state, unsupported


def vlan_priorities(lines):
    priorities = {}
    for line in lines:
        if not re.match(r"spanning-tree vlan(?:-id)? \S+ priority(?: |$)", line):
            continue
        match = VLAN_PRIORITY.fullmatch(line)
        try:
            numbers = vlan_numbers(match[1]) if match else set()
        except Rejected:
            numbers = set()
        if (not numbers or any(vid < 1 or vid > 4094 for vid in numbers)
                or int(match[2]) > 61440 or int(match[2]) % 4096 or numbers & priorities.keys()):
            raise Rejected(["EOS per-VLAN spanning-tree priority is incomplete or ambiguous"],
                           reason_codes=["eos_l2_readback_unreadable"])
        priorities.update(dict.fromkeys(numbers, match[2]))
    return priorities


def peer_lines(snapshot):
    blocks = [block for block in snapshot.blocks if block.header == MLAG_HEADER]
    if len(blocks) > 1:
        raise Rejected(["EOS MLAG configuration is ambiguous"], reason_codes=["eos_l2_readback_unreadable"])
    return [line.strip() for block in blocks for line in block.children]


def peer_settings(snapshot):
    peer, ambiguous = parse_lines(MLAG_PEER, peer_lines(snapshot))
    if ambiguous:
        raise Rejected(["the EOS peer-link configuration is ambiguous"], reason_codes=["eos_l2_readback_unreadable"])
    return peer


def entries(snapshot, table, entry_type):
    if table == STP_VLAN:
        priorities = vlan_priorities(snapshot.lines)
        result = {}
        for vid in snapshot.vlans:
            entry = entry_type(vid)
            if int(vid) in priorities:
                entry.attributes["priority"] = priorities[int(vid)]
            result[vid] = entry
        return result
    if table == MLAG_PEER:
        sources = {"global": peer_lines(snapshot)}
    else:
        pattern = {
            CHANNEL: CHANNEL_NAME, MEMBER: ETHERNET, MLAG_PORT: CHANNEL_NAME,
            STP_PORT: "(?:%s|%s)" % (ETHERNET, CHANNEL_NAME),
        }[table]
        sources = {name: snapshot.interface_lines(name) for name in snapshot.interfaces if re.fullmatch(pattern, name)}
    result = {}
    for name, lines in sources.items():
        entry = entry_type(name)
        entry.attributes, entry.unsupported = parse_lines(table, lines)
        if table == CHANNEL and any(not _owned(CHANNEL, line) for line in lines):
            entry.unsupported.append("the channel has configuration outside this profile")
        result[name] = entry
    return result


def member_ports(snapshot, group):
    result = set()
    for name in snapshot.interfaces:
        if not re.fullmatch(ETHERNET, name):
            continue
        for line in snapshot.interface_lines(name):
            if re.match(r"channel-group %s(?: |$)" % group, line):
                result.add(name)
    return result


def groups(before, after):
    return {"Port-Channel" + side["group"] for side in (before, after) if side and "group" in side}


def affected_interfaces(snapshot, table, key, before, after):
    if table == STP_VLAN:
        return {"Vlan" + key}
    if table == MLAG_PEER:
        affected = {side[attr] for side in (before, after) if side
                    for attr in ("peer-link", "local-interface") if attr in side}
    else:
        affected = {key}
    if table == MEMBER:
        affected |= groups(before, after)
    for name in tuple(affected):
        if re.fullmatch(CHANNEL_NAME, name):
            affected.update(member_ports(snapshot, name.removeprefix("Port-Channel")))
    return affected


def protected_interfaces(protected):
    return {name.casefold() for scope in ("interface", "ports", "vlan-membership", *TABLES, "l3-interface")
            for name in protected.get(scope, ())}


def prechecks(snapshot, table, key, before, after, protected):
    affected = affected_interfaces(snapshot, table, key, before, after)
    guarded = protected_interfaces(protected)
    guarded_vlans = {"Vlan" + vid for vid in protected.get("vlan", ())}
    if any(name.casefold() in guarded or name in guarded_vlans for name in affected):
        raise Rejected(["an interface or VLAN affected by the change is protected"], reason_codes=["port_protected"])
    peer = peer_settings(snapshot)
    if table != MLAG_PEER and affected & {peer.get("peer-link"), peer.get("local-interface")}:
        raise Rejected(["the change touches the MLAG peer link or its control VLAN"], reason_codes=["port_uplink"])
    for name in affected:
        if table != STP_VLAN and name != key and name not in snapshot.interfaces:
            raise Rejected(["referenced interface %s does not exist" % name], reason_codes=["eos_l2_dependency"])
    if table == CHANNEL and affected - {key}:
        raise Rejected(["the Port-Channel has configured members"], reason_codes=["port_lag_member"])
    if table == CHANNEL and after is None:
        monitor_target = re.compile(r"(?<!\S)%s(?!\S)" % key)
        if any(name.startswith(key + ".") for name in snapshot.interfaces) or any(
                line.startswith("monitor session ") and monitor_target.search(line) for line in snapshot.lines):
            raise Rejected(["the Port-Channel has subinterfaces or monitoring references"],
                           reason_codes=["eos_l2_dependency"])
    if table == MEMBER:
        if after and set(after) != {"group", "mode"}:
            raise Rejected(["group and mode must be set together or both removed"],
                           reason_codes=["eos_l2_dependency"])
        for channel in groups(before, after):
            if any(line.startswith("mlag ") for line in snapshot.interface_lines(channel)):
                raise Rejected(["the Port-Channel belongs to MLAG"], reason_codes=["port_uplink"])
        if after:
            for port in member_ports(snapshot, after["group"]) - {key}:
                state, unknown = parse_lines(MEMBER, snapshot.interface_lines(port))
                if unknown or state.get("mode") != after["mode"]:
                    raise Rejected(["existing members use a different channel-group mode"],
                                   reason_codes=["eos_l2_dependency"])
    if table == STP_PORT:
        if any(_owned(MEMBER, line) for line in snapshot.interface_lines(key)):
            raise Rejected(["spanning tree must be changed on the logical interface"], reason_codes=["port_lag_member"])
    if table == MLAG_PORT:
        if not peer.get("peer-link") or not peer.get("local-interface") or not peer.get("peer-address"):
            raise Rejected(["MLAG peer settings are incomplete"], reason_codes=["eos_l2_dependency"])
        if after and "mlag-id" in after:
            wanted = "mlag " + after["mlag-id"]
            if any(wanted in snapshot.interface_lines(name) for name in snapshot.interfaces if name != key):
                raise Rejected(["the MLAG ID already belongs to another local Port-Channel"],
                               reason_codes=["eos_l2_dependency"])
    if table == MLAG_PEER:
        for side in (before, after):
            if side and side.get("peer-link") and not re.fullmatch(CHANNEL_NAME, side["peer-link"]):
                raise Rejected(["the peer-link profile supports Port-Channel interfaces"],
                               reason_codes=["eos_l2_dependency"])
    if table == STP_VLAN:
        if "spanning-tree mode rapid-pvst" not in snapshot.lines:
            raise Rejected(["VLAN bridge priority requires Rapid-PVST"], reason_codes=["eos_stp_mode"])
        for line in snapshot.lines:
            if line.startswith("no spanning-tree vlan-id ") and int(key) in vlan_numbers(line.split()[-1]):
                raise Rejected(["spanning tree is disabled on the VLAN"], reason_codes=["eos_stp_mode"])
        if after and int(after["priority"]) % 4096:
            raise Rejected(["bridge priority must be a multiple of 4096"], reason_codes=["eos_l2_dependency"])


def render(table, key, before, after):
    """Render only changed attributes and always detach before moving a member."""
    previous, wanted = before or {}, after or {}
    if table == CHANNEL and after is None:
        return ["configure terminal", "no interface " + key, "end"]
    if table == MEMBER:
        lines = []
        if previous and previous != wanted:
            lines.append("no channel-group")
        if wanted:
            lines.append("channel-group %(group)s mode %(mode)s" % wanted)
    elif table == STP_VLAN:
        prefix = "spanning-tree vlan-id %s priority" % key
        line = prefix + " " + wanted["priority"] if wanted else "no " + prefix
        return ["configure terminal", line, "end"]
    else:
        lines = []
        for name, (prefix, _) in FIELDS[table].items():
            if previous.get(name) == wanted.get(name):
                continue
            lines.append(prefix + " " + wanted[name] if name in wanted else "no " + prefix)
    context = MLAG_HEADER if table == MLAG_PEER else "interface " + key
    return ["configure terminal", context, *lines, "end"]


def outside_lines(snapshot, table, key):
    if table == STP_VLAN:
        priorities = vlan_priorities(snapshot.lines)
        priorities.pop(int(key), None)
        return [line for line in snapshot.lines if not VLAN_PRIORITY.fullmatch(line)] + _priority_lines(priorities)
    header = MLAG_HEADER if table == MLAG_PEER else "interface " + key
    result = []
    inside = False
    for line in snapshot.lines:
        if line == header:
            inside = True
            if table != CHANNEL and (table != MLAG_PEER or any(
                    not _owned(table, child) for child in peer_lines(snapshot))):
                result.append(line)
        elif inside and line.startswith(INDENT):
            if table != CHANNEL and not _owned(table, line.strip()):
                result.append(line)
        else:
            inside = False
            result.append(line)
    return result


def _priority_lines(priorities):
    by_value = {}
    for vid, value in priorities.items():
        by_value.setdefault(value, set()).add(vid)
    return ["spanning-tree vlan-id %s priority %s" % ("1-4094" if len(numbers) == 4094 else vlan_text(numbers), value)
            for value, numbers in sorted(by_value.items())]


def snapshot_after(snapshot, plan):
    """Patch the restricted config statements for the existing pre-write auditor."""
    table, key = plan["table"], plan["key"]
    after = plan["predicted"]["after"]
    if table == STP_VLAN:
        priorities = vlan_priorities(snapshot.lines)
        priorities.pop(int(key), None)
        if after:
            priorities[int(key)] = after["priority"]
        lines = [line for line in snapshot.lines if not VLAN_PRIORITY.fullmatch(line)]
        index = next(i for i, line in enumerate(lines) if line == "end")
        lines[index:index] = _priority_lines(priorities)
        return "\n".join(lines)
    header = MLAG_HEADER if table == MLAG_PEER else "interface " + key
    preserved = peer_lines(snapshot) if table == MLAG_PEER else snapshot.interface_lines(key)
    children = [line for line in preserved if not _owned(table, line)]
    if after:
        children.extend(render(table, key, {}, after)[2:-1])
    replacement = [header, *(INDENT + line for line in children)]
    if after is None or (table == MLAG_PEER and not children):
        replacement = []
    lines = list(snapshot.lines)
    if header in lines:
        start = lines.index(header)
        end = start + 1
        while end < len(lines) and lines[end].startswith(INDENT):
            end += 1
        lines[start:end] = replacement
    elif replacement:
        end = lines.index("end")
        lines[end:end] = [*replacement, "!"]
    return "\n".join(lines)
