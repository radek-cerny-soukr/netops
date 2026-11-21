"""Direct IPv4 eBGP neighbors in the default VRF on Arista EOS."""
from __future__ import annotations

import ipaddress
import re

from netops_admin import eos_routing

TABLE = "bgp-neighbor"
ROUTER = re.compile(r"router bgp ([1-9][0-9]*)")
NEIGHBOR = re.compile(r"   ( +)?neighbor (\S+) (.+)")
REMOTE_AS = re.compile(r"remote-as ([1-9][0-9]*)")
POLICY = re.compile(rf"route-map ({eos_routing.NAME}) (in|out)")


def asn(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value) or int(value) >= 4294967295:
        raise ValueError
    return value


def target(key):
    try:
        local, peer = key.split(":", 1)
        return asn(local), ipaddress.IPv4Address(peer)
    except ValueError:
        raise eos_routing.refuse("use a valid local AS and IPv4 neighbor as AS:ADDRESS") from None


def router(snapshot):
    return next((block for block in snapshot.blocks if ROUTER.fullmatch(block.header)), None)


def entries(snapshot, factory):
    block = router(snapshot)
    found = {}
    if block is None:
        return found
    local = block.header.split()[-1]
    for line in block.children:
        match = NEIGHBOR.fullmatch(line)
        if match is None:
            continue
        indent, peer, command = match.groups()
        key = f"{local}:{peer}"
        entry = found.setdefault(key, factory(key))
        if indent:
            entry.unsupported.append("nested BGP neighbor configuration")
        elif remote := REMOTE_AS.fullmatch(command):
            eos_routing.set_attribute(entry, "remote-as", remote[1])
        elif policy := POLICY.fullmatch(command):
            eos_routing.set_attribute(entry, f"route-map-{policy[2]}", policy[1])
        else:
            entry.unsupported.append("unsupported BGP neighbor configuration")
    return found


def connected_interface(snapshot, peer):
    interfaces = set()
    for interface in snapshot.interfaces:
        lines = snapshot.interface_lines(interface)
        if any(line.startswith("vrf ") for line in lines):
            continue
        for line in lines:
            match = re.fullmatch(r"ip address (\S+/\d+)(?: secondary)?", line)
            if match is None:
                continue
            address = ipaddress.IPv4Interface(match[1])
            if (peer != address.ip and peer in address.network and
                    (address.network.prefixlen >= 31 or peer not in (address.network.network_address,
                                                                     address.network.broadcast_address))):
                interfaces.add(interface)
    if len(interfaces) != 1:
        raise eos_routing.refuse("the IPv4 eBGP peer needs one directly connected default-VRF interface")
    return interfaces.pop()


def prechecks(snapshot, key, before, after, protected, impact, undo_plan):
    local, peer = target(key)
    block = router(snapshot)
    if "ip routing" not in snapshot.lines or peer.is_multicast or peer.is_loopback or peer.is_unspecified:
        raise eos_routing.refuse("the eBGP profile requires IPv4 routing and a unicast neighbor")
    if block is not None and (block.header != f"router bgp {local}" or any(
            line.strip().startswith(("bgp listen ", "no bgp default ipv4-unicast"))
            for line in block.children)):
        raise eos_routing.refuse("the existing BGP router does not provide the requested default-VRF AS scope")
    eos_routing.protect_interfaces({connected_interface(snapshot, peer)}, protected or {})
    if str(peer) in {str(value) for value in (protected or {}).get(TABLE, ())}:
        raise eos_routing.refuse("the BGP neighbor is protected", "port_protected")
    header = f"router bgp {local}"
    drop_parent = (undo_plan is not None and after is None and f"no {header}" in undo_plan["inverse"])
    if drop_parent and (block is None or list(without_peer(block.children, header, key))):
        raise eos_routing.refuse("the BGP router created with the peer now contains other configuration")
    undo_create = undo_plan is not None and undo_plan["op"] == "create" and after is None
    if before is not None and impact != key and not undo_create:
        raise eos_routing.refuse("changing an existing BGP neighbor requires endpoint_impact naming AS:ADDRESS",
                                 "endpoint_impact_required")
    if after is not None:
        try:
            if asn(after.get("remote-as")) == local:
                raise ValueError
        except ValueError:
            raise eos_routing.refuse("the peer must specify a valid, different remote AS for eBGP") from None
        maps = {match[1] for entry in snapshot.blocks if (match := eos_routing.POLICY.fullmatch(entry.header))}
        if any(after[attr] not in maps for attr in ("route-map-in", "route-map-out") if attr in after):
            raise eos_routing.refuse("the BGP neighbor refers to a missing route-map")
    return drop_parent, block is None


def without_peer(lines, header, key):
    local, peer = key.split(":", 1)
    for line in lines:
        if line and not line.startswith(" "):
            header = line
        match = NEIGHBOR.fullmatch(line)
        if not (header == f"router bgp {local}" and match and not match[1] and match[2] == peer):
            yield line


def without_object(lines, key):
    local, _ = key.split(":", 1)
    return (line for line in without_peer(lines, "", key) if line != f"router bgp {local}")


def render(key, before, after, *, drop_parent=False):
    local, peer = key.split(":", 1)
    header = f"router bgp {local}"
    stem = f"neighbor {peer}"
    if after is None:
        return [f"no {header}"] if drop_parent else [header, f"no {stem}", "exit"]
    before = before or {}
    lines = [header]
    if before.get("remote-as") != after["remote-as"]:
        lines.append(f"{stem} remote-as {after['remote-as']}")
    for side in ("in", "out"):
        field = f"route-map-{side}"
        if before.get(field) == after.get(field):
            continue
        if field in after:
            lines.append(f"{stem} route-map {after[field]} {side}")
        else:
            lines.append(f"no {stem} route-map {before[field]} {side}")
    return [*lines, "exit"] if len(lines) > 1 else []


def snapshot_after(snapshot, plan):
    key = plan["key"]
    local, _ = key.split(":", 1)
    header = f"router bgp {local}"
    lines = list(without_peer(snapshot.lines, "", key))
    if f"no {header}" in plan["commands"]:
        lines.remove(header)
    after = plan["predicted"]["after"]
    if after is not None:
        if header not in lines:
            index = lines.index("end")
            lines[index:index] = [header, "!"]
        index = lines.index(header) + 1
        lines[index:index] = ["   " + command for command in render(key, None, after)[1:-1]]
    return "\n".join(lines)


def parent_matches(snapshot, plan, expect):
    local, _ = plan["key"].split(":", 1)
    header = f"router bgp {local}"
    absent = (f"no {header}" in plan["commands"] if expect == "after"
              else f"no {header}" in plan["inverse"])
    return (header not in snapshot.lines) == absent


def observe(data, key):
    local, peer = key.split(":", 1)
    vrfs = data["vrfs"]
    if not isinstance(vrfs, dict):
        raise ValueError
    if "default" not in vrfs:
        return None
    neighbors = vrfs["default"]["peerList"]
    if not isinstance(neighbors, list):
        raise ValueError
    rows = [item for item in neighbors if item["peerAddress"] == peer]
    if not rows:
        return None
    row, = rows
    if asn(row["localAsn"]) != local or row["linkType"] != "external" or row["vrf"] != "default":
        raise ValueError
    result = {"remote-as": asn(row["asn"])}
    for suffix, side in (("Inbound", "in"), ("Outbound", "out")):
        field = f"routeMap{suffix}"
        value = row[field]
        if not isinstance(value, str) or (value and
                (not re.fullmatch(eos_routing.NAME, value) or row[field + "Defined"] is not True)):
            raise ValueError
        if value:
            result[f"route-map-{side}"] = value
    return result
