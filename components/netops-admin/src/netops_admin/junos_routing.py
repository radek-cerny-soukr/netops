"""Junos OSPF interface, routing policy, and BGP configuration profiles."""

from __future__ import annotations

import ipaddress
import re

from .errors import Rejected

OSPF = {"ospf-interface": "ospf", "ospf3-interface": "ospf3"}
PREFIX_LIST = "prefix-list"
POLICY = "route-policy"
GROUP = "bgp-group"
NEIGHBOR = "bgp-neighbor"
BGP_TABLES = (GROUP, NEIGHBOR)
TABLES = (*OSPF, PREFIX_LIST, POLICY, *BGP_TABLES)
NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
TERM = re.compile(fr"({NAME}):({NAME}|-):(accept|reject)")
BGP_FIELDS = ("type", "peer-as", "import", "export")
POLICY_FIELDS = ("import", "export")
BGP_PRESERVED = {"description", "local-address", "family", "authentication-key", "hold-time",
                 "multihop", "mtu-discovery", "bfd-liveness-detection"}


def _names(values):
    return bool(values) and len(set(values)) == len(values) and all(re.fullmatch(NAME, v) for v in values)


def _terms(value):
    terms = {}
    for item in value.split():
        match = TERM.fullmatch(item)
        if not match or match[1] in terms:
            raise ValueError("invalid or duplicate policy term")
        terms[match[1]] = (match[2], match[3])
    if not terms:
        raise ValueError("empty policy")
    return terms


def _prefixes(value):
    prefixes = [ipaddress.ip_network(item) for item in value.split() if "/" in item]
    if not prefixes or len(prefixes) != len(value.split()) or len(set(prefixes)) != len(prefixes):
        raise ValueError("invalid or duplicate prefix")
    if len({prefix.version for prefix in prefixes}) != 1:
        raise ValueError("a Junos prefix list must use one address family")
    return " ".join(map(str, sorted(prefixes)))


def canonical_changes(table, changes):
    """Normalize typed values without sorting ordered policy and BGP lists."""
    result = dict(changes)
    if table in OSPF and "area" in changes:
        try:
            result["area"] = str(ipaddress.IPv4Address(changes["area"]))
        except ValueError:
            raise Rejected(["OSPF area must be a dotted IPv4 area ID"]) from None
    try:
        if table == PREFIX_LIST and "prefixes" in changes:
            result["prefixes"] = _prefixes(changes["prefixes"])
        if table == POLICY and "terms" in changes:
            result["terms"] = " ".join(changes["terms"].split())
            _terms(result["terms"])
        for field in POLICY_FIELDS:
            if table in BGP_TABLES and changes.get(field) is not None:
                values = changes[field].split()
                if not _names(values):
                    raise ValueError("invalid or duplicate BGP policy name")
                result[field] = " ".join(values)
    except ValueError as exc:
        raise Rejected(["invalid Junos routing attribute: %s" % exc]) from None
    return result


def _owner(words, table):
    if table in OSPF and words[:3] == ["protocols", OSPF[table], "area"]:
        if len(words) >= 6 and words[4] == "interface":
            return words[5], words[3:4] + words[6:]
    if table in (PREFIX_LIST, POLICY):
        stanza = "prefix-list" if table == PREFIX_LIST else "policy-statement"
        if len(words) >= 3 and words[:2] == ["policy-options", stanza]:
            return words[2], words[3:]
    if len(words) >= 4 and table in BGP_TABLES and words[:3] == ["protocols", "bgp", "group"]:
        if table == GROUP:
            return words[3], words[4:]
        if len(words) >= 6 and words[4] == "neighbor":
            return words[3] + "@" + words[5], words[6:]
    return None


def _entries_lines(lines, table):
    for line in lines:
        verb, *words = line.split()
        owner = _owner(words, table)
        if owner:
            yield line, verb, *owner


def own_lines(snapshot, table, key):
    return {line for line, verb, name, rest in _entries_lines(snapshot.lines, table)
            if verb == "set" and name == key
            and (table not in BGP_TABLES or not rest or rest[0] in BGP_FIELDS)}


def _scalar(entry, name, value):
    if name in entry.attributes and entry.attributes[name] != value:
        raise ValueError("multiple values")
    entry.attributes[name] = value


def _ospf(entry, rest):
    _scalar(entry, "area", str(ipaddress.IPv4Address(rest[0])))
    leaf = rest[1:]
    if leaf == ["passive"]:
        _scalar(entry, "passive", "yes")
    elif len(leaf) == 2 and leaf[0] == "metric" and leaf[1].isdigit() and 1 <= int(leaf[1]) <= 65535:
        _scalar(entry, "metric", leaf[1])
    elif leaf:
        raise ValueError("unsupported interface option")


def _bgp(entry, table, rest):
    if not rest or rest[0] in BGP_PRESERVED or (table == GROUP and rest[0] == "neighbor"):
        return
    field, *values = rest
    if field in POLICY_FIELDS:
        values = [value for value in values if value not in ("[", "]")]
        values = entry.attributes.get(field, "").split() + values
        if not _names(values):
            raise ValueError("unsupported BGP policy expression")
        entry.attributes[field] = " ".join(values)
    elif field == "type" and table == GROUP and values in (["internal"], ["external"]):
        _scalar(entry, field, values[0])
    elif field == "peer-as" and len(values) == 1 and values[0].isdigit() and 1 <= int(values[0]) <= 4294967295:
        _scalar(entry, field, values[0])
    else:
        raise ValueError("unsupported BGP option")


def _policy_term(terms, rest):
    if len(rest) < 4 or rest[0] != "term" or not re.fullmatch(NAME, rest[1]):
        raise ValueError("unsupported policy statement")
    name, leaf = rest[1], rest[2:]
    fields = terms.setdefault(name, {})
    if len(leaf) == 3 and leaf[:2] == ["from", "prefix-list"] and re.fullmatch(NAME, leaf[2]):
        field, value = "prefix-list", leaf[2]
    elif len(leaf) == 2 and leaf[0] == "then" and leaf[1] in ("accept", "reject"):
        field, value = "action", leaf[1]
    else:
        raise ValueError("unsupported policy match or action")
    if field in fields:
        raise ValueError("multiple policy matches or actions")
    fields[field] = value


def entries(snapshot, table):
    from .junos import Entry

    found = {}
    terms = {}
    prefixes = {}
    for _line, verb, key, rest in _entries_lines(snapshot.lines, table):
        entry = found.setdefault(key, Entry(key))
        try:
            if verb != "set":
                raise ValueError("inactive or protected routing statement")
            if table in OSPF:
                _ospf(entry, rest)
            elif table == PREFIX_LIST:
                if len(rest) != 1:
                    raise ValueError("unsupported prefix-list option")
                prefixes.setdefault(key, []).append(rest[0])
            elif table == POLICY:
                _policy_term(terms.setdefault(key, {}), rest)
            else:
                _bgp(entry, table, rest)
        except ValueError:
            entry.unsupported.append("routing configuration outside the profile")
    for key, values in prefixes.items():
        try:
            found[key].attributes["prefixes"] = _prefixes(" ".join(values))
        except ValueError:
            found[key].unsupported.append("invalid or duplicate configured prefix")
    for key, values in terms.items():
        if all("action" in fields for fields in values.values()):
            found[key].attributes["terms"] = " ".join(
                f"{name}:{fields.get('prefix-list', '-')}:{fields['action']}" for name, fields in values.items()
            )
        else:
            found[key].unsupported.append("incomplete policy term")
    return found


def _path(table, key, state):
    if table in OSPF:
        return f"protocols {OSPF[table]} area {state['area']} interface {key}"
    if table == PREFIX_LIST:
        return f"policy-options prefix-list {key}"
    if table == POLICY:
        return f"policy-options policy-statement {key}"
    group, _, address = key.partition("@")
    base = f"protocols bgp group {group}"
    return base if table == GROUP else f"{base} neighbor {address}"


def _policy_lines(path, before, after):
    old, new = (_terms(state["terms"]) if state else {} for state in (before, after))
    lines = [f"delete {path} term {name}" for name in old if name not in new]
    order = [name for name in old if name in new]
    for name, (prefix, action) in new.items():
        old_prefix, old_action = old.get(name, ("-", None))
        term = f"{path} term {name}"
        if prefix != old_prefix:
            if old_prefix != "-":
                lines.append(f"delete {term} from prefix-list {old_prefix}")
            if prefix != "-":
                lines.append(f"set {term} from prefix-list {prefix}")
        if action != old_action:
            if old_action:
                lines.append(f"delete {term} then {old_action}")
                if prefix == "-":
                    order.remove(name)
            lines.append(f"set {term} then {action}")
        if name not in order:
            order.append(name)
    for index, name in enumerate(new):
        if name != order[index]:
            lines.append(f"insert {path} term {name} before term {order[index]}")
            order.remove(name)
            order.insert(index, name)
    return lines


def _ospf_lines(path, before, after):
    lines = []
    if before.get("passive") != after.get("passive"):
        verb = "set" if after.get("passive") == "yes" else "delete"
        lines.append(f"{verb} {path} passive")
    if before.get("metric") != after.get("metric"):
        metric = after.get("metric")
        lines.append(f"set {path} metric {metric}" if metric else f"delete {path} metric")
    if set(after) == {"area"}:
        lines.append(f"set {path}")
    return lines


def render(table, key, before, after):
    if after is None:
        return [f"delete {_path(table, key, before)}"]
    path = _path(table, key, after)
    if table in OSPF:
        if before and before["area"] != after["area"]:
            return [f"delete {_path(table, key, before)}", *_ospf_lines(path, {}, after)]
        return _ospf_lines(path, before or {}, after)
    if table == POLICY:
        return _policy_lines(path, before, after)
    before = before or {}
    if table == PREFIX_LIST:
        old = before.get("prefixes", "").split()
        new = after["prefixes"].split()
        # Add first so the named object survives a replacement of all of its entries.
        return [f"set {path} {prefix}" for prefix in new if prefix not in old] + [
            f"delete {path} {prefix}" for prefix in old if prefix not in new
        ]
    lines = []
    for field in BGP_FIELDS:
        old, new = before.get(field), after.get(field)
        if old == new:
            continue
        # An ordered policy list is replaced explicitly. AS and type are single-valued.
        if old is not None and (new is None or field in POLICY_FIELDS):
            lines.append(f"delete {path} {field}")
        if new is not None:
            values = new if len(new.split()) == 1 else f"[ {new} ]"
            lines.append(f"set {path} {field} {values}")
    if not after:
        lines.append(f"set {path}")
    return lines


def predicted_lines(snapshot, table, key, after):
    keep = [line for line in snapshot.lines if line not in own_lines(snapshot, table, key)]
    if after is None:
        return keep
    return keep + render(table, key, None, after)


def _word_references(snapshot, key, owned):
    # Policy names can also appear in routing instances, firewall filters and policy expressions.
    reference = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(key) + r"(?![A-Za-z0-9_-])")
    return any(line not in owned and reference.search(line) for line in snapshot.lines)


def _inherited_scope(snapshot, table):
    root = ("policy-options" if table in (PREFIX_LIST, POLICY)
            else "protocols " + (OSPF[table] if table in OSPF else "bgp"))
    for line in snapshot.lines:
        if re.match(rf"^(?:set|deactivate|protect) groups \S+ {root}(?: |$)", line):
            return True
        if not line.startswith(("set " + root, "deactivate " + root, "protect " + root)):
            continue
        if " apply-groups" in line or (not line.startswith("set ") and line == line.split()[0] + " " + root):
            return True
    return False


def prechecks(snapshot, table, key, before, after, protected, impact, undo):
    if _inherited_scope(snapshot, table):
        raise Rejected(["inherited, inactive or protected routing configuration needs a separate change"],
                       reason_codes=["junos_routing_scope"])
    if table in OSPF:
        paths = {_path(table, key, state).rsplit(" interface ", 1)[0] for state in (before, after) if state}
        if any(f"{verb} {path}" in snapshot.lines for verb in ("deactivate", "protect") for path in paths):
            raise Rejected(["the OSPF area is inactive or protected"], reason_codes=["junos_routing_scope"])
        if after and before != after and "set " + _path(table, key, after).rsplit(" interface ", 1)[0] in snapshot.lines:
            raise Rejected(["the existing empty OSPF area cannot be restored by the interface profile"],
                           reason_codes=["junos_routing_scope"])
        physical, _ = key.rsplit(".", 1)
        guarded = {name.casefold() for name in (protected or {}).get("interface", ())}
        if re.fullmatch(r"(?:fxp|em|me|vme)[0-9]+", physical) or {key.casefold(), physical.casefold()} & guarded:
            raise Rejected(["the OSPF interface is protected for management or by inventory"],
                           reason_codes=["port_protected"])
        protocol = OSPF[table]
        if any(re.match(rf"^(?:set|deactivate|protect) protocols {protocol} area \S+ interface all(?: |$)", line)
               for line in snapshot.lines):
            raise Rejected(["the OSPF wildcard interface makes the change scope ambiguous"],
                           reason_codes=["junos_routing_scope"])
        return []
    if table in (PREFIX_LIST, POLICY):
        if before is not None and _word_references(snapshot, key, own_lines(snapshot, table, key)):
            raise Rejected(["the routing definition is referenced by other configuration"],
                           reason_codes=["junos_routing_dependency"])
        if table == POLICY and after:
            lists = entries(snapshot, PREFIX_LIST)
            if any(name != "-" and (name not in lists or lists[name].unsupported)
                   for name, _action in _terms(after["terms"]).values()):
                raise Rejected(["a policy term needs a configured literal prefix list"],
                               reason_codes=["junos_routing_dependency"])
        return []
    group, _, address = key.partition("@")
    groups = entries(snapshot, GROUP)
    if after is None and any(verb == "set" and name == key and rest and rest[0] in BGP_PRESERVED
                             for _line, verb, name, rest in _entries_lines(snapshot.lines, table)):
        raise Rejected(["the BGP object has other settings that cannot be restored by this profile"],
                       reason_codes=["junos_routing_scope"])
    guarded = (protected or {}).get(GROUP, ())
    if any(name.casefold() == group.casefold() for name in guarded):
        raise Rejected(["the BGP group is protected"], reason_codes=["junos_routing_management"])
    if table == NEIGHBOR:
        try:
            if str(ipaddress.ip_address(address)) != address:
                raise ValueError("noncanonical")
        except ValueError:
            raise Rejected(["the BGP neighbor must use a canonical IP address"]) from None
        if group not in groups or groups[group].unsupported:
            raise Rejected(["the BGP neighbor requires a supported configured group"],
                           reason_codes=["junos_routing_dependency"])
        neighbors = entries(snapshot, NEIGHBOR)
        if after is None and not any(other != key and other.startswith(group + "@") for other in neighbors):
            if not any(verb == "set" and name == group and (not rest or rest[0] != "neighbor")
                       for _line, verb, name, rest in _entries_lines(snapshot.lines, GROUP)):
                raise Rejected(["deleting the last neighbor would also remove its implicit BGP group"],
                               reason_codes=["junos_routing_scope"])
        if any(other != key and other.endswith("@" + address) for other in neighbors):
            raise Rejected(["the BGP neighbor address already belongs to another group"],
                           reason_codes=["junos_routing_dependency"])
    elif after is None and any(name.startswith(group + "@") for name in entries(snapshot, NEIGHBOR)):
        raise Rejected(["the BGP group has configured neighbors"], reason_codes=["junos_routing_dependency"])
    if before is not None and any(before.get(field) != (after or {}).get(field) for field in POLICY_FIELDS):
        if not undo and impact != key:
            raise Rejected(["changing policies on an existing BGP group or neighbor needs endpoint_impact"],
                           reason_codes=["endpoint_impact_required"])
    policies = entries(snapshot, POLICY)
    guarded_policies = {name.casefold() for name in (protected or {}).get(POLICY, ())}
    for field in POLICY_FIELDS:
        old = (before or {}).get(field, "").split()
        new = (after or {}).get(field, "").split()
        if old != new and any(name.casefold() in guarded_policies for name in old + new):
            raise Rejected(["the BGP attachment references a protected policy"], reason_codes=["junos_routing_scope"])
        if any(name not in policies or policies[name].unsupported for name in new):
            raise Rejected(["BGP import and export need configured prefix policies"],
                           reason_codes=["junos_routing_dependency"])
    if table == GROUP and after and after.get("type") == "external" and "peer-as" not in after:
        raise Rejected(["an external BGP group requires peer-as"])
    return []
