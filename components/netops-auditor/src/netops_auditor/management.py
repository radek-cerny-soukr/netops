from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re

from .engine import EVALUATED, NOT_EVALUATED, UNSUPPORTED, check
from .inputs import InputError, read_regular

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
POLICY_FIELD = {"address-policy": "address_networks", "vlan-policy": "vlan_tags",
                "port-policy": "port_vlans", "port-description": "description_glob"}
POLICY_NOT_CONFIGURED = "policy-not-configured"
SCOPE_REASON = "fortios.scope.vdom-unsupported"
PORT = r"[1-9][0-9]{0,3}(?::[1-9][0-9]{0,3})?"
ALL_PORTS = "all"
MEMBERSHIP_LIST = "membership-list"
MEMBERSHIP_FORM = "membership-form"
DESCRIPTION_LIST = "description-list"
UNRESOLVED = {
    MEMBERSHIP_LIST: ("unresolved-port-list", "unsupported port list"),
    MEMBERSHIP_FORM: ("unsupported-membership-form", "unsupported VLAN membership form"),
    DESCRIPTION_LIST: ("unresolved-port-list", "unsupported port list"),
}
EXOS_NEEDS = {
    "port-policy": (MEMBERSHIP_LIST, MEMBERSHIP_FORM),
    "port-native": (MEMBERSHIP_LIST, MEMBERSHIP_FORM),
    "port-description": (DESCRIPTION_LIST,),
}


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
    try:
        data = read_regular(path, MAX_POLICY_BYTES)
    except InputError as error:
        raise PolicyError("policy is %s" % error) from None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate policy field")
            result[key] = value
        return result
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except RecursionError:
        raise PolicyError("policy nesting is too deep") from None
    return validate_policy(document, platform)


def policy_digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


UNNAMED_PARTS = ("password", "passwd", "passphrase", "pwd", "secret", "psk", "key", "community", "token",
                 "comment", "description")
UNNAMED_ATTRIBUTES = {("system snmp community",): ("name",)}


def named_values(node):
    for name, attr in node.attrs.items():
        folded = name.casefold()
        if any(part in folded for part in UNNAMED_PARTS) or name in UNNAMED_ATTRIBUTES.get(node.path[:1], ()):
            continue
        yield from attr.values


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


def _port_order(port):
    slot, _, number = port.rpartition(":")
    return int(slot) if slot else 0, int(number)


def _slot_range(match, inventory):
    if not inventory or match[1] is None or match[3] is None:
        raise PolicyError("unsupported port list")
    first, last = "%s:%s" % (match[1], match[2]), "%s:%s" % (match[3], match[4])
    if first not in inventory or last not in inventory or _port_order(first) > _port_order(last):
        raise PolicyError("port range outside the port inventory")
    return {port for port in inventory if _port_order(first) <= _port_order(port) <= _port_order(last)}


def ports(value, inventory=None):
    result = set()
    for item in value.split(","):
        if re.fullmatch(PORT, item):
            result.add(item)
            continue
        if item == ALL_PORTS and inventory:
            result.update(inventory)
            continue
        match = re.fullmatch(r"(?:([0-9]+):)?([0-9]+)-(?:([0-9]+):)?([0-9]+)", item)
        if not match:
            raise PolicyError("unsupported port list")
        if match[3] not in (None, match[1]):
            result.update(_slot_range(match, inventory))
            continue
        start, end = int(match[2]), int(match[4])
        if not 1 <= start <= end <= 4096:
            raise PolicyError("invalid port range")
        result.update(("%s:" % match[1] if match[1] else "") + str(n) for n in range(start, end + 1))
    if len(result) > 4096:
        raise PolicyError("port list is too large")
    return result


def port_inventory(tree):
    found = set()
    for command in tree.active:
        t = command.tokens
        if len(t) == 6 and t[0] == "configure" and t[1].casefold() == "vr" and t[3] in ("add", "delete") \
                and t[4] == "ports":
            try:
                found |= ports(t[5])
            except PolicyError:
                return None
    return frozenset(found) or None


def _exos_view(tree, inventory=None, strict=False):
    vlans, descriptions, members, populated, unresolved = {}, {}, {}, set(), set()

    def expand(value, kind):
        try:
            return ports(value, inventory)
        except PolicyError:
            if strict:
                raise
            unresolved.add(kind)
            return set()

    for command in tree.active:
        t = command.tokens
        if t[:2] == ("create", "vlan") and len(t) >= 3:
            vlans.setdefault(t[2], {})
            if len(t) == 5 and t[3] == "tag":
                vlans[t[2]]["tag"] = t[4]
        elif t[:2] == ("configure", "vlan") and len(t) >= 5:
            name = t[2]
            vlans.setdefault(name, {})
            if t[3] == "tag" and len(t) == 5:
                vlans[name]["tag"] = t[4]
            elif t[3:5] == ("add", "ports"):
                populated.add(name)
                if len(t) == 7 and t[6] in ("tagged", "untagged"):
                    for port in expand(t[5], MEMBERSHIP_LIST):
                        members.setdefault(port, {"tagged": set(), "untagged": set()})[t[6]].add(name)
                elif strict:
                    raise PolicyError(UNRESOLVED[MEMBERSHIP_FORM][1])
                else:
                    unresolved.add(MEMBERSHIP_FORM)
        elif t[:2] == ("configure", "ports") and len(t) == 5 and t[3] == "display-string":
            for port in expand(t[2], DESCRIPTION_LIST):
                descriptions[port] = t[4]
    if strict and tree.unterminated_upm:
        raise PolicyError("unterminated UPM profile")
    return vlans, members, descriptions, populated, unresolved


def exos_model(tree, inventory=None):
    vlans, members, descriptions, _populated, _unresolved = _exos_view(tree, inventory, strict=True)
    return vlans, members, descriptions


def _exos_content(tree) -> bool:
    return any(
        command.tokens[:2] in (("create", "vlan"), ("configure", "vlan"))
        or (command.tokens[:2] == ("configure", "ports") and "display-string" in command.tokens)
        for command in tree.active
    )


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
        owners = {}
        for other in walk(tree):
            for value in named_values(other):
                seen = owners.setdefault(value, set())
                if len(seen) < 2:
                    seen.add(other.path[:2])
        for key, node in addresses.items():
            if key in ("all", "none"):
                continue
            if not owners.get(key, set()) - {("firewall address", key)}:
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
    if tree.unterminated_upm:
        raise PolicyError("unterminated UPM profile")
    vlans, members, descriptions, populated, unresolved = _exos_view(tree, port_inventory(tree))
    for kind in EXOS_NEEDS.get(name, ()):
        if kind in unresolved:
            raise PolicyError(UNRESOLVED[kind][1])
    if name == "vlan-empty":
        for vlan in sorted(set(vlans) - populated - {"Default", "Mgmt"}):
            yield _hit("vlan/" + vlan, "vlan", 0, "no-visible-ports")
    elif name == "vlan-policy":
        ranges = policy.get("vlan_tags", [])
        for vlan, attrs in vlans.items():
            tag = attrs.get("tag", "")
            if ranges and (not (tag.isascii() and tag.isdigit()) or
                           not any(lo <= int(tag) <= hi for lo, hi in ranges)):
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


def _fortios_status(name, tree, policy) -> tuple:
    if "vdom" in tree.sub or "global" in tree.sub:
        return UNSUPPORTED, SCOPE_REASON
    if POLICY_FIELD.get(name) and POLICY_FIELD[name] not in policy:
        return NOT_EVALUATED, POLICY_NOT_CONFIGURED
    if RULES["fortios"][name][1] not in tree.sub:
        return NOT_EVALUATED, "section-missing"
    if name == "group-dangling" and "firewall address" not in tree.sub:
        return NOT_EVALUATED, "section-missing"
    return EVALUATED, ""


def _exos_status(name, tree, policy) -> tuple:
    if tree.unterminated_upm:
        return NOT_EVALUATED, "unterminated-upm-profile"
    if POLICY_FIELD.get(name) and POLICY_FIELD[name] not in policy:
        return NOT_EVALUATED, POLICY_NOT_CONFIGURED
    if not _exos_content(tree):
        return NOT_EVALUATED, "no-vlan-content"
    unresolved = _exos_view(tree, port_inventory(tree))[4]
    for kind in EXOS_NEEDS.get(name, ()):
        if kind in unresolved:
            return NOT_EVALUATED, UNRESOLVED[kind][0]
    return EVALUATED, ""


def rule_status(platform, name, tree, policy=None) -> tuple:
    return (_fortios_status if platform == "fortios" else _exos_status)(name, tree, policy or {})


def coverage(platform, tree, policy=None):
    result = {}
    for name in RULES[platform]:
        state, reason = rule_status(platform, name, tree, policy)
        if state == EVALUATED:
            result[name] = "evaluated"
        elif reason == POLICY_NOT_CONFIGURED:
            result[name] = "not-configured"
        else:
            result[name] = "not-evaluated"
    return result


def _register(platform, name):
    def evaluate(tree, policy=None):
        yield from hits(platform, name, tree, policy)

    def status(tree, policy=None):
        return rule_status(platform, name, tree, policy)
    evaluate.__name__ = "management_" + platform + "_" + name.replace("-", "_")
    check(evaluate.__name__, contextual=True, status=status)(evaluate)
    globals()[evaluate.__name__] = evaluate


for _platform, _rules in RULES.items():
    for _name in _rules:
        _register(_platform, _name)
