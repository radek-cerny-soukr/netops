"""Scoped OSPFv2 configuration and IPv4 prefix policies on Arista EOS."""
from __future__ import annotations

import ipaddress
import re

from netops_admin.errors import Rejected

OSPF_PROCESS = "ospf-process"
OSPF_NETWORK = "ospf-network"
OSPF_INTERFACE = "ospf-interface"
PREFIX_LIST = "ip-prefix-list"
ROUTE_MAP = "route-map"
OSPF_TABLES = {OSPF_PROCESS, OSPF_NETWORK, OSPF_INTERFACE}
TABLES = OSPF_TABLES | {PREFIX_LIST, ROUTE_MAP}

NAME = r"[A-Za-z][A-Za-z0-9_.-]{0,63}"
PROCESS = re.compile(r"router ospf ([0-9]+)")
NETWORK = re.compile(r"network (\S+) area (\S+)")
POLICY = re.compile(rf"route-map ({NAME}) (permit|deny) ([0-9]+)")
PREFIX = re.compile(rf"ip prefix-list ({NAME}) (.+)")
RULE = re.compile(r"seq ([0-9]+) (permit|deny) (\S+)")
MATCH = re.compile(rf"match ip address prefix-list ({NAME})")
ROUTER_ID = re.compile(r"router-id (\S+)")
COST = re.compile(r"ip ospf cost ([0-9]+)")
PASSIVE = re.compile(r"(no )?passive-interface (\S+)")
# EOS 4.36.1F prints this implicit configuration line when creating an instance.
DEFAULT_MAX_LSA = "max-lsa 12000"


def refuse(message, code="eos_routing_unsupported"):
    return Rejected([message], reason_codes=[code])


def area_id(value):
    return str(ipaddress.IPv4Address(int(value) if str(value).isdecimal() else value))


def parse_rules(value):
    rules = {}
    for rule in value.split(","):
        matched = RULE.fullmatch("seq " + rule.strip())
        if matched is None:
            raise ValueError
        seq, action, prefix = matched.groups()
        seq = int(seq)
        if seq in rules or not 0 <= seq <= 65535:
            raise ValueError
        rules[seq] = f"{action} {ipaddress.IPv4Network(prefix)}"
    return rules


def rule_text(rules):
    return ", ".join(f"{seq} {rules[seq]}" for seq in sorted(rules))


def canonical_changes(table, key, changes):
    try:
        if table in OSPF_TABLES:
            process = key.partition(":")[0]
            if not 1 <= int(process) <= 65535:
                raise ValueError
        if table == OSPF_NETWORK:
            prefix = key.partition(":")[2]
            if str(ipaddress.IPv4Network(prefix)) != prefix:
                raise ValueError
        if table == ROUTE_MAP and int(key.rsplit(":", 1)[1]) > 65535:
            raise ValueError
        changes = dict(changes)
        for name, convert in (("area", area_id), ("router-id", ipaddress.IPv4Address),
                              ("rules", lambda value: rule_text(parse_rules(value)))):
            if changes.get(name) is not None:
                changes[name] = str(convert(changes[name]))
        return changes
    except (ValueError, TypeError):
        raise refuse("invalid EOS routing process, network, area, or policy entry") from None


def process_blocks(snapshot):
    return {match[1]: block for block in snapshot.blocks if (match := PROCESS.fullmatch(block.header))}


def set_attribute(entry, name, value):
    if name in entry.attributes:
        entry.unsupported.append("duplicate routing attribute")
    entry.attributes[name] = value


def policy_entries(snapshot, table, factory):
    found = {}
    rules = {}
    for block in snapshot.blocks:
        if table == PREFIX_LIST and (match := PREFIX.fullmatch(block.header)):
            name, line = match.groups()
            entry = found.setdefault(name, factory(name))
            try:
                new = parse_rules(line.removeprefix("seq "))
                previous = rules.setdefault(name, {})
                if previous.keys() & new.keys():
                    raise ValueError
                previous.update(new)
            except ValueError:
                entry.unsupported.append("unsupported prefix-list entry")
        if table == ROUTE_MAP and (match := POLICY.fullmatch(block.header)):
            name, action, seq = match.groups()
            key = f"{name}:{seq}"
            entry = found.setdefault(key, factory(key))
            set_attribute(entry, "action", action)
            for child in block.children:
                if match_list := MATCH.fullmatch(child.strip()):
                    set_attribute(entry, "prefix-list", match_list[1])
                else:
                    entry.unsupported.append("unsupported route-map clause")
    for name, members in rules.items():
        found[name].attributes["rules"] = rule_text(members)
    return found


def ospf_entries(snapshot, table, factory):
    found = {}
    for process, block in process_blocks(snapshot).items():
        if table == OSPF_PROCESS:
            entry = found[process] = factory(process)
            for child in block.children:
                if match := ROUTER_ID.fullmatch(child.strip()):
                    set_attribute(entry, "router-id", match[1])
            continue
        if table == OSPF_NETWORK:
            for child in block.children:
                if match := NETWORK.fullmatch(child.strip()):
                    key = f"{process}:{match[1]}"
                    entry = found.setdefault(key, factory(key))
                    set_attribute(entry, "area", match[2])
            continue
        passive = {match[2]: "disabled" if match[1] else "enabled"
                   for child in block.children if (match := PASSIVE.fullmatch(child.strip()))}
        for interface in snapshot.interfaces:
            key = f"{process}:{interface}"
            entry = found[key] = factory(key)
            if interface in passive:
                entry.attributes["passive"] = passive[interface]
            for line in snapshot.interface_lines(interface):
                if match := COST.fullmatch(line):
                    set_attribute(entry, "cost", match[1])
    return found


def entries(snapshot, table, factory):
    return (ospf_entries if table in OSPF_TABLES else policy_entries)(snapshot, table, factory)


def owns(table, key, header, line):
    if table == PREFIX_LIST:
        match = PREFIX.fullmatch(header)
        return bool(match and match[1] == key)
    if table == ROUTE_MAP:
        match = POLICY.fullmatch(header)
        return bool(match and f"{match[1]}:{match[3]}" == key)
    if table == OSPF_PROCESS:
        return header == f"router ospf {key}" and (line == header or line.strip() == DEFAULT_MAX_LSA
                                                   or ROUTER_ID.fullmatch(line.strip()) is not None)
    process, target = key.split(":", 1)
    if table == OSPF_NETWORK:
        return header == f"router ospf {process}" and line.strip().startswith(f"network {target} area ")
    if header == f"router ospf {process}":
        return line.strip() in {f"passive-interface {target}", f"no passive-interface {target}"}
    return header == f"interface {target}" and COST.fullmatch(line.strip()) is not None


def without_object(lines, table, key):
    header = ""
    for line in lines:
        if line and not line.startswith(" "):
            header = line
        if not owns(table, key, header, line):
            yield line


def state_lines(table, key, state):
    if table == PREFIX_LIST:
        rules = parse_rules(state["rules"])
        return [f"ip prefix-list {key} seq {seq} {rules[seq]}" for seq in sorted(rules)]
    if table == ROUTE_MAP:
        name, seq = key.rsplit(":", 1)
        lines = [f"route-map {name} {state['action']} {seq}"]
        if "prefix-list" in state:
            lines.append(f"   match ip address prefix-list {state['prefix-list']}")
        return lines
    if table == OSPF_PROCESS:
        lines = [f"router ospf {key}"]
        if "router-id" in state:
            lines.append(f"   router-id {state['router-id']}")
        return [*lines, "   " + DEFAULT_MAX_LSA]
    raise ValueError(table)


def snapshot_after(snapshot, plan):
    table, key = plan["table"], plan["key"]
    after = plan["predicted"]["after"]
    lines = list(without_object(snapshot.lines, table, key))
    if after is None:
        return "\n".join(lines)
    if table not in (OSPF_NETWORK, OSPF_INTERFACE):
        end = lines.index("end")
        return "\n".join([*lines[:end], *state_lines(table, key, after), "!", *lines[end:]])
    process, target = key.split(":", 1)
    at = lines.index(f"router ospf {process}") + 1
    if table == OSPF_NETWORK:
        lines.insert(at, f"   network {target} area {after['area']}")
    else:
        if "passive" in after:
            lines.insert(at, "   " + passive_command(target, after["passive"]))
        if "cost" in after:
            at = lines.index(f"interface {target}") + 1
            lines.insert(at, f"   ip ospf cost {after['cost']}")
    return "\n".join(lines)


def passive_command(interface, state):
    stem = {None: "default passive-interface", "enabled": "passive-interface", "disabled": "no passive-interface"}
    return f"{stem[state]} {interface}"


def render(table, key, before, after):
    old, new = before or {}, after or {}
    if table == OSPF_PROCESS:
        if after is None:
            return [f"no router ospf {key}"]
        return [*(line.strip() for line in state_lines(table, key, after) if line.strip() != DEFAULT_MAX_LSA),
                "exit"]
    if table == OSPF_NETWORK:
        process, prefix = key.split(":", 1)
        commands = [f"router ospf {process}"]
        if old:
            commands.append(f"no network {prefix} area {old['area']}")
        if new:
            commands.append(f"network {prefix} area {new['area']}")
        return [*commands, "exit"]
    if table == OSPF_INTERFACE:
        process, interface = key.split(":", 1)
        commands = []
        if old.get("passive") != new.get("passive"):
            commands.extend([f"router ospf {process}", passive_command(interface, new.get("passive")), "exit"])
        if old.get("cost") != new.get("cost"):
            cost = f"ip ospf cost {new['cost']}" if "cost" in new else "no ip ospf cost"
            commands.extend([f"interface {interface}", cost, "exit"])
        return commands
    if table == PREFIX_LIST:
        old_rules = parse_rules(old["rules"]) if old else {}
        new_rules = parse_rules(new["rules"]) if new else {}
        removed = [seq for seq in sorted(old_rules) if old_rules[seq] != new_rules.get(seq)]
        added = [seq for seq in sorted(new_rules) if new_rules[seq] != old_rules.get(seq)]
        return ([f"no ip prefix-list {key} seq {seq}" for seq in removed]
                + [f"ip prefix-list {key} seq {seq} {new_rules[seq]}" for seq in added])
    name, seq = key.rsplit(":", 1)
    if after is None:
        return [f"no route-map {name} {old['action']} {seq}"]
    commands = [f"route-map {name} {new['action']} {seq}"]
    if old.get("prefix-list") != new.get("prefix-list"):
        if "prefix-list" in old:
            commands.append(f"no match ip address prefix-list {old['prefix-list']}")
        if "prefix-list" in new:
            commands.append(f"match ip address prefix-list {new['prefix-list']}")
    return [*commands, "exit"]


def addresses(snapshot, interface):
    lines = snapshot.interface_lines(interface)
    if any(line.startswith("vrf ") for line in lines):
        return set()
    return {ipaddress.IPv4Interface(words[2]).ip for line in lines
            if (words := line.split())[:2] == ["ip", "address"] and len(words) >= 3 and "/" in words[2]}


def network_interfaces(snapshot, network):
    return {interface for interface in snapshot.interfaces
            if any(address in network for address in addresses(snapshot, interface))}


def process_networks(block):
    return {ipaddress.IPv4Network(match[1], strict=False): match[2] for line in block.children
            if (match := NETWORK.fullmatch(line.strip()))}


def affected_interfaces(snapshot, table, key):
    process, _, target = key.partition(":")
    blocks = process_blocks(snapshot)
    if table == OSPF_PROCESS:
        return set()
    if process not in blocks:
        raise refuse("the selected default-VRF OSPF process is missing")
    networks = process_networks(blocks[process])
    if table == OSPF_NETWORK:
        prefix = ipaddress.IPv4Network(target)
        if any(prefix.overlaps(other) for other in networks if other != prefix):
            raise refuse("overlapping OSPF networks obscure the effective area")
        interfaces = network_interfaces(snapshot, prefix)
    else:
        interfaces = {target} if addresses(snapshot, target) else set()
        matching = [network for network in networks
                    if any(address in network for address in addresses(snapshot, target))]
        if len(matching) != 1:
            raise refuse("the interface needs exactly one matching OSPF network in the process")
    if not interfaces:
        raise refuse("the OSPF network needs an addressed interface in the default VRF")
    for interface in interfaces:
        own_addresses = addresses(snapshot, interface)
        if (any(line.startswith(("ip ospf area ", "ip ospf disabled")) for line in snapshot.interface_lines(interface))
                or any(any(address in network for address in own_addresses)
                       for pid, block in blocks.items() if pid != process for network in process_networks(block))):
            raise refuse("the interface has an explicit area, is disabled, or belongs to another OSPF process")
    return interfaces


def policy_references(snapshot, name, references):
    for block in snapshot.blocks:
        if isinstance(references, re.Pattern) and references.fullmatch(block.header):
            continue
        for line in (block.header, *block.children):
            if name.casefold() in {token.casefold() for token in line.split()}:
                yield block, line.strip()


def check_map_detached(snapshot, name):
    pattern = re.compile(rf"route-map {re.escape(name)} (?:permit|deny) [0-9]+")
    if any(policy_references(snapshot, name, pattern)):
        raise refuse("the route-map is referenced by another object", "eos_routing_policy_in_use")


def check_policy(snapshot, table, key, after, protected):
    name = key.split(":", 1)[0]
    guarded = {value.casefold() for value in protected.get(table, ())}
    if name.casefold() in guarded:
        raise refuse("the routing policy is protected", "eos_routing_policy_in_use")
    if table == ROUTE_MAP:
        check_map_detached(snapshot, name)
        if after is not None and "prefix-list" in after:
            prefix_list = after["prefix-list"]
            if not any((match := PREFIX.fullmatch(block.header)) and match[1] == prefix_list
                       for block in snapshot.blocks):
                raise refuse("the route-map refers to a missing IPv4 prefix-list")
        return
    pattern = re.compile(rf"ip prefix-list {re.escape(name)} .+")
    for block, line in policy_references(snapshot, name, pattern):
        match = POLICY.fullmatch(block.header)
        if after is None or match is None or MATCH.fullmatch(line) is None:
            raise refuse("the prefix-list is referenced by another object", "eos_routing_policy_in_use")
        check_map_detached(snapshot, match[1])


def protect_interfaces(interfaces, protected, management_vlans=()):
    vlans = {str(value) for value in (*protected.get("vlan", ()), *management_vlans)}
    if any(interface.startswith("Vlan") and interface[4:] in vlans for interface in interfaces):
        raise refuse("the routing interface is on a management or protected VLAN", "port_management_vlan")
    guarded = {name.casefold() for field in ("interface", "ports", "l3-interface")
               for name in protected.get(field, ())}
    if any(interface.casefold() in guarded or interface.startswith("Management") for interface in interfaces):
        raise refuse("the routing interface is protected", "port_protected")


def prechecks(snapshot, table, key, before, after, protected):
    if table not in OSPF_TABLES:
        check_policy(snapshot, table, key, after, protected)
        return
    process = key.partition(":")[0]
    if any(block.header.startswith(f"router ospf {process} vrf ") for block in snapshot.blocks):
        raise refuse("this OSPF process is configured in a non-default VRF")
    block = process_blocks(snapshot).get(process)
    if table == OSPF_PROCESS:
        if any(line.strip().startswith("ip ospf area ") for interface in snapshot.interfaces.values()
               for line in interface.children):
            raise refuse("interface area configuration can depend on the OSPF instance")
        if block is not None and ("router-id" not in (before or {}) or any(
                line.strip() != DEFAULT_MAX_LSA and not ROUTER_ID.fullmatch(line.strip()) for line in block.children)):
            raise refuse("the OSPF process holds configuration outside the selected object")
        return
    if process.casefold() in {name.casefold() for name in protected.get(OSPF_PROCESS, ())}:
        raise refuse("the OSPF process is protected", "port_protected")
    if table == OSPF_INTERFACE and block is not None and any(
            line.strip() == "passive-interface default" for line in block.children):
        raise refuse("an OSPF passive default needs a separate configuration change")
    protect_interfaces(affected_interfaces(snapshot, table, key), protected)
