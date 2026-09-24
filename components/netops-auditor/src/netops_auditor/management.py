from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from .engine import check

RULES = {
    "fortios": {
        "address-unused": ("info", "firewall address"),
        "address-policy": ("medium", "firewall address"),
        "group-empty": ("medium", "firewall addrgrp"),
        "group-dangling": ("high", "firewall addrgrp"),
        "group-cycle": ("high", "firewall addrgrp"),
        "dhcp-conflict": ("high", "system dhcp server"),
        "dhcp-subnet": ("high", "system dhcp server"),
    },
    "exos": {
        "vlan-empty": ("info", "vlan"),
        "vlan-policy": ("medium", "vlan"),
        "port-policy": ("high", "vlan"),
        "port-native": ("high", "vlan"),
        "port-description": ("low", "ports"),
    },
}
POLICY_FIELDS = {
    "fortios": {"address_networks", "dhcp_networks", "protected_groups"},
    "exos": {"vlan_tags", "port_vlans", "protected_ports", "management_vlans", "description_glob"},
}
MAX_POLICY_BYTES = 262144


class PolicyError(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise PolicyError(message)


def _names(value):
    return isinstance(value, list) and len(value) <= 4096 and all(
        isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item)
        for item in value
    ) and len(value) == len(set(value))


def _networks(value):
    _require(isinstance(value, list) and value and len(value) <= 1024, "networks must be a nonempty list")
    for item in value:
        _require(isinstance(item, str), "network must be a string")
        try:
            net = ipaddress.ip_network(item, strict=True)
        except ValueError:
            raise PolicyError("invalid policy network") from None
        _require(net.version == 4, "only IPv4 policy networks are supported")


def validate_policy(data, platform):
    _require(platform in RULES, "unsupported policy platform")
    _require(isinstance(data, dict), "policy must be an object")
    _require(set(data) <= {"version", "platform", "required_rules"} | POLICY_FIELDS[platform],
             "unknown policy fields")
    _require(type(data.get("version")) is int and data["version"] == 1, "policy version must be 1")
    _require(data.get("platform") == platform, "policy platform mismatch")
    required = data.get("required_rules", [])
    _require(_names(required) and set(required) <= set(RULES[platform]), "unknown required rules")
    for field in ("protected_groups", "protected_ports", "management_vlans"):
        if field in data:
            _require(_names(data[field]), "invalid protected object list")
    if "address_networks" in data:
        _networks(data["address_networks"])
    if "dhcp_networks" in data:
        _require(isinstance(data["dhcp_networks"], dict) and len(data["dhcp_networks"]) <= 4096,
                 "dhcp_networks must map server IDs to networks")
        for server, networks in data["dhcp_networks"].items():
            _require(isinstance(server, str) and re.fullmatch(r"[1-9][0-9]{0,9}", server), "invalid DHCP server ID")
            _networks(networks)
    if "vlan_tags" in data:
        ranges = data["vlan_tags"]
        _require(isinstance(ranges, list) and 0 < len(ranges) <= 4096, "vlan_tags must be nonempty")
        for pair in ranges:
            _require(isinstance(pair, list) and len(pair) == 2 and all(type(v) is int for v in pair)
                     and 1 <= pair[0] <= pair[1] <= 4094, "invalid VLAN tag range")
    if "port_vlans" in data:
        mapping = data["port_vlans"]
        _require(isinstance(mapping, dict) and len(mapping) <= 4096, "invalid port_vlans")
        for port, modes in mapping.items():
            _require(isinstance(port, str) and re.fullmatch(r"[1-9][0-9]{0,3}(?::[1-9][0-9]{0,3})?", port),
                     "invalid policy port")
            _require(isinstance(modes, dict) and set(modes) == {"tagged", "untagged"}
                     and all(_names(names) for names in modes.values()), "invalid port VLAN allowlist")
    if "description_glob" in data:
        _require(isinstance(data["description_glob"], str) and 0 < len(data["description_glob"]) <= 128,
                 "description_glob must be a bounded glob")
    return json.loads(json.dumps(data))


def load_policy(path, platform):
    p = Path(path)
    if p.stat().st_size > MAX_POLICY_BYTES:
        raise PolicyError("policy is too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate policy field")
            result[key] = value
        return result
    return validate_policy(json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique), platform)


def policy_digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def entries(tree, name):
    section = tree.section(name)
    return {} if section is None else section.entries


def walk(tree):
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.sub.values())
        stack.extend(node.entries.values())


def ports(value):
    result = set()
    for item in value.split(","):
        if re.fullmatch(r"[1-9][0-9]{0,3}(?::[1-9][0-9]{0,3})?", item):
            result.add(item)
            continue
        match = re.fullmatch(r"(?:(\d+):)?(\d+)-(?:([0-9]+):)?(\d+)", item)
        if not match or match[3] not in (None, match[1]):
            raise PolicyError("unsupported port list")
        start, end = int(match[2]), int(match[4])
        if not 1 <= start <= end <= 4096:
            raise PolicyError("invalid port range")
        result.update(("%s:" % match[1] if match[1] else "") + str(n) for n in range(start, end + 1))
    if len(result) > 4096:
        raise PolicyError("port list is too large")
    return result


def exos_model(tree):
    vlans, descriptions, members = {}, {}, {}
    inside = False
    for command in tree.commands:
        t = command.tokens
        if inside:
            if t == (".",):
                inside = False
            continue
        if t[:3] == ("create", "upm", "profile"):
            inside = True
            continue
        if t[:2] == ("create", "vlan") and len(t) >= 3:
            vlans.setdefault(t[2], {})
            if len(t) == 5 and t[3] == "tag":
                vlans[t[2]]["tag"] = t[4]
        elif t[:2] == ("configure", "vlan") and len(t) >= 5:
            name = t[2]
            vlans.setdefault(name, {})
            if t[3] == "tag" and len(t) == 5:
                vlans[name]["tag"] = t[4]
            elif t[3:5] == ("add", "ports") and len(t) == 7 and t[6] in ("tagged", "untagged"):
                for port in ports(t[5]):
                    members.setdefault(port, {"tagged": set(), "untagged": set()})[t[6]].add(name)
            elif t[3:5] == ("add", "ports"):
                raise PolicyError("unsupported VLAN membership form")
        elif t[:2] == ("configure", "ports") and len(t) == 5 and t[3] == "display-string":
            for port in ports(t[2]):
                descriptions[port] = t[4]
    if inside:
        raise PolicyError("unterminated UPM profile")
    return vlans, members, descriptions


def _hit(key, section, line, code, count=1):
    return {"object_key": key, "section": section, "line": line or 0,
            "evidence": {"code": code, "count": count}}


def _network(value):
    parts = value.split()
    return ipaddress.IPv4Network("/".join(parts), strict=False)



def _cyclic_edges(graph):
    edges = {key: members & graph.keys() for key, members in graph.items()}
    reverse = {key: set() for key in graph}
    for key, members in edges.items():
        for member in members:
            reverse[member].add(key)
    seen, order = set(), []
    for key in edges:
        if key in seen:
            continue
        stack = [(key, False)]
        while stack:
            node, finishing = stack.pop()
            if finishing:
                order.append(node)
            elif node not in seen:
                seen.add(node)
                stack.append((node, True))
                stack.extend((child, False) for child in edges[node] if child not in seen)
    components = {}
    for key in reversed(order):
        if key in components:
            continue
        pending = [key]
        while pending:
            node = pending.pop()
            if node in components:
                continue
            components[node] = key
            pending.extend(reverse[node] - components.keys())
    return {(key, member) for key, members in edges.items() for member in members
            if components[key] == components[member]}


def _fortios(name, tree, policy):
    addresses = entries(tree, "firewall address")
    groups = entries(tree, "firewall addrgrp")
    if name == "address-unused":
        for key, node in addresses.items():
            if key in ("all", "none"):
                continue
            referenced = any(key in attr.values for other in walk(tree)
                             if other.path[:2] != ("firewall address", key) for attr in other.attrs.values())
            if not referenced:
                yield _hit("firewall address/" + key, "firewall address", node.line, "no-visible-reference")
    elif name == "address-policy":
        allowed = [ipaddress.ip_network(n) for n in policy.get("address_networks", [])]
        for key, node in addresses.items():
            if node.value("type", "ipmask") != "ipmask" or not allowed:
                continue
            try:
                network = _network(node.value("subnet", "0.0.0.0 0.0.0.0"))
            except ValueError:
                yield _hit("firewall address/" + key, "firewall address", node.line, "invalid-subnet")
                continue
            if not any(network.subnet_of(n) for n in allowed):
                yield _hit("firewall address/" + key, "firewall address", node.line, "outside-address-policy")
    elif name.startswith("group-"):
        graph = {key: set(node.values("member")) for key, node in groups.items()
                 if node.value("type", "default") == "default"}
        cyclic_edges = _cyclic_edges(graph) if name == "group-cycle" else set()
        for key, node in groups.items():
            if key not in graph:
                continue
            members = graph[key]
            prefix = "firewall addrgrp/" + key
            if name == "group-empty" and not members:
                yield _hit(prefix, "firewall addrgrp", node.line, "empty-static-group")
            if name == "group-dangling":
                for member in sorted(members - set(addresses) - set(groups) - {"all"}):
                    yield _hit(prefix + "/member/" + member, "firewall addrgrp", node.line, "missing-member")
            if name == "group-cycle":
                for member in sorted(members):
                    if (key, member) in cyclic_edges:
                        yield _hit(prefix + "/member/" + member, "firewall addrgrp", node.line, "membership-cycle")
    elif name.startswith("dhcp-"):
        for sid, server in entries(tree, "system dhcp server").items():
            if server.value("status", "enable") == "disable":
                continue
            reservations = entries(server, "reserved-address")
            active = [(key, node) for key, node in reservations.items()
                      if node.value("action", "reserved") == "reserved"
                      and node.value("type", "mac") == "mac"]
            for key, node in active:
                prefix = "system dhcp server/" + sid + "/reserved-address/" + key
                if name == "dhcp-conflict":
                    for other_key, other in active:
                        if key >= other_key:
                            continue
                        same_ip = node.value("ip") and node.value("ip") == other.value("ip")
                        mac = re.sub("[:-]", "", node.value("mac", "")).lower()
                        other_mac = re.sub("[:-]", "", other.value("mac", "")).lower()
                        if same_ip or (mac and mac == other_mac):
                            yield _hit(prefix + "/conflict/" + other_key, "system dhcp server", node.line,
                                       "reservation-conflict")
                else:
                    try:
                        address = ipaddress.IPv4Address(node.value("ip", ""))
                        networks = policy.get("dhcp_networks", {}).get(sid)
                        subnet = _network(server.value("default-gateway", "") + " " +
                                          server.value("netmask", ""))
                        allowed = [ipaddress.IPv4Network(n) for n in networks] if networks else [subnet]
                        valid = (address in subnet and address not in (subnet.network_address, subnet.broadcast_address)
                                 and any(address in net for net in allowed))
                        valid = valid and str(address) != server.value("default-gateway")
                    except ValueError:
                        yield _hit(prefix, "system dhcp server", node.line, "subnet-not-evaluable")
                        continue
                    if not valid:
                        yield _hit(prefix, "system dhcp server", node.line, "reservation-outside-subnet")


def _exos(name, tree, policy):
    vlans, members, descriptions = exos_model(tree)
    if name == "vlan-empty":
        used = {v for modes in members.values() for values in modes.values() for v in values}
        for vlan in sorted(set(vlans) - used - {"Default", "Mgmt"}):
            yield _hit("vlan/" + vlan, "vlan", 0, "no-visible-ports")
    elif name == "vlan-policy":
        ranges = policy.get("vlan_tags", [])
        for vlan, attrs in vlans.items():
            if ranges and (not attrs.get("tag", "").isdigit() or
                           not any(lo <= int(attrs["tag"]) <= hi for lo, hi in ranges)):
                yield _hit("vlan/" + vlan, "vlan", 0, "tag-outside-policy")
    elif name == "port-policy":
        for port, modes in members.items():
            allowed = policy.get("port_vlans", {}).get(port)
            if allowed is None:
                continue
            for mode, names in modes.items():
                for vlan in sorted(names - set(allowed[mode])):
                    yield _hit("ports/" + port + "/" + mode + "/" + vlan, "vlan", 0,
                               "membership-outside-policy")
    elif name == "port-native":
        for port in sorted(set(members) | set(policy.get("port_vlans", {}))):
            native = members.get(port, {}).get("untagged", set())
            if len(native) > 1 or (port in policy.get("port_vlans", {}) and len(native) != 1):
                yield _hit("ports/" + port, "vlan", 0, "native-vlan-count", len(native))
    elif name == "port-description":
        pattern = policy.get("description_glob")
        if pattern:
            for port, description in descriptions.items():
                if not fnmatch.fnmatchcase(description, pattern):
                    yield _hit("ports/" + port, "ports", 0, "description-policy")


def hits(platform, name, tree, policy=None):
    policy = policy or {}
    yield from (_fortios if platform == "fortios" else _exos)(name, tree, policy)


def coverage(platform, tree, policy=None):
    policy = policy or {}
    result = {}
    for name, (_, section) in RULES[platform].items():
        ready = section in tree.sub if platform == "fortios" else "vlan" in tree.modules
        field = {"address-policy": "address_networks", "vlan-policy": "vlan_tags",
                 "port-policy": "port_vlans", "port-description": "description_glob"}.get(name)
        if platform == "fortios" and ("vdom" in tree.sub or "global" in tree.sub):
            result[name] = "not-evaluated"
        elif field and field not in policy:
            result[name] = "not-configured"
        elif not ready:
            result[name] = "not-evaluated"
        elif name == "group-dangling" and "firewall address" not in tree.sub:
            result[name] = "not-evaluated"
        else:
            result[name] = "evaluated"
    return result


def _register(platform, name):
    def evaluate(tree, policy=None):
        yield from hits(platform, name, tree, policy)
    evaluate.__name__ = "management_" + platform + "_" + name.replace("-", "_")
    check(evaluate.__name__, contextual=True)(evaluate)
    globals()[evaluate.__name__] = evaluate


for _platform, _rules in RULES.items():
    for _name in _rules:
        _register(_platform, _name)
