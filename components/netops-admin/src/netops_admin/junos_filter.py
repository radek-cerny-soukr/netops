"""Junos firewall filter, term/counter and interface binding profiles (1.0.12 G142, J26)."""

from __future__ import annotations

import ipaddress
import re

from .errors import Rejected

FILTER = "firewall-filter"
BINDING = "filter-binding"
TABLES = (FILTER, BINDING)
FAMILIES = ("inet", "inet6")
DIRECTIONS = ("input", "output")
ACTIONS = ("accept", "discard", "reject")
NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
# Junos limits a counter name to 24 characters.
COUNTER = r"[A-Za-z0-9][A-Za-z0-9_-]{0,23}"
LOGICAL = r"([A-Za-z][A-Za-z0-9/:_-]*)\.([0-9]{1,5})"
TERM = re.compile(fr"({NAME}),([0-9A-Fa-f:./]+|-),({COUNTER}|-),({'|'.join(ACTIONS)})")
MANAGEMENT = re.compile(r"(?:fxp|em|me|vme)[0-9]+")


def split_key(key):
    """Return (name or logical interface, family) of a filter or binding key."""
    name, _, family = key.rpartition("@")
    return name, family


def _terms(value):
    terms = {}
    for item in value.split():
        match = TERM.fullmatch(item)
        if not match or match[1] in terms:
            raise ValueError("invalid or duplicate firewall term")
        terms[match[1]] = (match[2], match[3], match[4])
    if not terms:
        raise ValueError("empty firewall filter")
    return terms


def _source(value, family):
    if value == "-":
        return value
    try:
        network = ipaddress.ip_network(value)
    except ValueError:
        raise ValueError("invalid source prefix %s" % value) from None
    if network.version != (6 if family == "inet6" else 4):
        raise ValueError("source prefix %s does not belong to family %s" % (value, family))
    return str(network)


def canonical_changes(table, key, changes):
    """Normalize typed values. The order of terms is the evaluation order and is kept."""
    result = dict(changes)
    name, family = split_key(key)
    try:
        if table == FILTER and changes.get("terms") is not None:
            terms = _terms(" ".join(changes["terms"].split()))
            result["terms"] = " ".join(
                ",".join((term, _source(source, family), counter, action))
                for term, (source, counter, action) in terms.items())
        if table == BINDING:
            if not re.fullmatch(LOGICAL, name):
                raise ValueError("invalid logical interface %s" % name)
            for direction in DIRECTIONS:
                if changes.get(direction) is not None and not re.fullmatch(NAME, changes[direction]):
                    raise ValueError("invalid filter name")
    except ValueError as exc:
        raise Rejected(["invalid Junos firewall attribute: %s" % exc]) from None
    return result


def _path(table, key):
    name, family = split_key(key)
    if table == FILTER:
        return f"firewall family {family} filter {name}"
    interface, unit = re.fullmatch(LOGICAL, name).groups()
    return f"interfaces {interface} unit {unit} family {family} filter"


def _owner(words, table):
    if table == FILTER and len(words) >= 5 and words[:2] == ["firewall", "family"] and words[3] == "filter" \
            and words[2] in FAMILIES:
        return f"{words[4]}@{words[2]}", words[5:]
    if (table == BINDING and len(words) >= 7 and words[0] == "interfaces" and words[2] == "unit"
            and words[4] == "family" and words[5] in FAMILIES and words[6] == "filter"):
        return f"{words[1]}.{words[3]}@{words[5]}", words[7:]
    return None


def _entries_lines(lines, table):
    for line in lines:
        verb, *words = line.split()
        owner = _owner(words, table)
        if owner:
            yield line, verb, *owner


def own_lines(snapshot, table, key):
    return {line for line, _verb, name, _rest in _entries_lines(snapshot.lines, table) if name == key}


def _term_leaf(terms, rest):
    if len(rest) < 3 or rest[0] != "term" or not re.fullmatch(NAME, rest[1]):
        raise ValueError("unsupported filter statement")
    fields = terms.setdefault(rest[1], {})
    leaf = rest[2:]
    if len(leaf) == 3 and leaf[:2] == ["from", "source-address"]:
        field, value = "source", leaf[2]
    elif len(leaf) == 3 and leaf[:2] == ["then", "count"] and re.fullmatch(COUNTER, leaf[2]):
        field, value = "counter", leaf[2]
    elif len(leaf) == 2 and leaf[0] == "then" and leaf[1] in ACTIONS:
        field, value = "action", leaf[1]
    else:
        raise ValueError("unsupported filter match or action")
    if field in fields:
        raise ValueError("multiple filter matches or actions")
    fields[field] = value


def entries(snapshot, table):
    from .junos import Entry

    found, terms = {}, {}
    for _line, verb, key, rest in _entries_lines(snapshot.lines, table):
        entry = found.setdefault(key, Entry(key))
        try:
            if verb != "set":
                raise ValueError("inactive or protected firewall statement")
            if table == FILTER:
                _term_leaf(terms.setdefault(key, {}), rest)
            elif len(rest) == 2 and rest[0] in DIRECTIONS and re.fullmatch(NAME, rest[1]):
                if rest[0] in entry.attributes:
                    raise ValueError("multiple filters in one direction")
                entry.attributes[rest[0]] = rest[1]
            else:
                raise ValueError("unsupported interface filter option")
        except ValueError:
            entry.unsupported.append("firewall configuration outside the profile")
    for key, values in terms.items():
        family = split_key(key)[1]
        try:
            if not all("action" in fields for fields in values.values()):
                raise ValueError("incomplete firewall term")
            found[key].attributes["terms"] = " ".join(
                ",".join((name, _source(fields.get("source", "-"), family), fields.get("counter", "-"),
                          fields["action"])) for name, fields in values.items())
        except ValueError:
            found[key].unsupported.append("incomplete or invalid firewall term")
    return found


def _term_lines(path, name, term):
    source, counter, action = term
    base = f"{path} term {name}"
    lines = [f"set {base} from source-address {source}"] if source != "-" else []
    if counter != "-":
        lines.append(f"set {base} then count {counter}")
    return lines + [f"set {base} then {action}"]


def _filter_lines(path, before, after):
    old, new = (_terms(state["terms"]) if state else {} for state in (before, after))
    lines = [f"delete {path} term {name}" for name in old if name not in new]
    order = [name for name in old if name in new and old[name] == new[name]]
    for name, term in new.items():
        if old.get(name) == term:
            continue
        if name in old:
            # A replaced term is written again as a whole; the insert below restores its place.
            lines.append(f"delete {path} term {name}")
        lines.extend(_term_lines(path, name, term))
        order.append(name)
    for index, name in enumerate(new):
        if order[index] != name:
            lines.append(f"insert {path} term {name} before term {order[index]}")
            order.remove(name)
            order.insert(index, name)
    return lines


def render(table, key, before, after):
    path = _path(table, key)
    if table == FILTER:
        if after is None:
            return [f"delete {path}"]
        return _filter_lines(path, before, after)
    before = before or {}
    lines = []
    for direction in DIRECTIONS:
        old, new = before.get(direction), (after or {}).get(direction)
        if old == new:
            continue
        lines.append(f"set {path} {direction} {new}" if new else f"delete {path} {direction}")
    return lines


def predicted_lines(snapshot, table, key, after):
    keep = [line for line in snapshot.lines if line not in own_lines(snapshot, table, key)]
    if after is None:
        return keep
    return keep + render(table, key, None, after)


def _inherited_scope(snapshot):
    for line in snapshot.lines:
        if re.match(r"^(?:set|deactivate|protect) groups \S+ (?:firewall|interfaces .* filter)(?: |$)", line):
            return True
        if line.startswith(("set apply-groups", "set firewall apply-groups")) or " apply-groups" in line:
            return True
        if re.match(r"^(?:deactivate|protect) firewall(?: |$)", line):
            return True
    return False


def bound_interfaces(snapshot, name, family):
    """The logical interfaces that name the filter, from supported binding statements."""
    found = entries(snapshot, BINDING)
    return sorted(key for key, entry in found.items() if key.endswith("@" + family)
                  and name in (entry.attributes.get(direction) for direction in DIRECTIONS))


def _references(snapshot, name, owned):
    reference = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
    return [line for line in snapshot.lines if line not in owned and reference.search(line)]


def _protect_interface(name, protected):
    interface, unit = re.fullmatch(LOGICAL, name).groups()
    guarded = {item.casefold() for item in protected.get("interface", ())}
    if MANAGEMENT.fullmatch(interface) or (interface == "lo0" and unit == "0") or {
            name.casefold(), interface.casefold()} & guarded:
        raise Rejected(["the interface is a management or protected interface"], reason_codes=["port_protected"])


def prechecks(snapshot, table, key, before, after, protected, impact, undo):
    protected = protected or {}
    name, family = split_key(key)
    if _inherited_scope(snapshot):
        raise Rejected(["inherited, inactive or protected firewall configuration needs a separate change"],
                       reason_codes=["junos_filter_scope"])
    if table == FILTER:
        if name.casefold() in {item.casefold() for item in protected.get(FILTER, ())}:
            raise Rejected(["the firewall filter is protected"], reason_codes=["junos_filter_scope"])
        if before is None:
            return []
        bound = bound_interfaces(snapshot, name, family)
        owned = own_lines(snapshot, table, key)
        for interface in bound:
            _protect_interface(split_key(interface)[0], protected)
            owned |= own_lines(snapshot, BINDING, interface)
        if _references(snapshot, name, owned):
            raise Rejected(["the firewall filter is referenced by other configuration"],
                           reason_codes=["junos_filter_dependency"])
        if after is None and bound:
            raise Rejected(["the firewall filter is bound to %s; remove the binding first" % ", ".join(bound)],
                           reason_codes=["junos_filter_dependency"])
        if bound and not undo and impact != key:
            raise Rejected(["changing a filter that is bound to %s needs endpoint_impact" % ", ".join(bound)],
                           reason_codes=["endpoint_impact_required"])
        return []
    _protect_interface(name, protected)
    if after is not None:
        interface, unit = re.fullmatch(LOGICAL, name).groups()
        if not any(after.get(direction) for direction in DIRECTIONS):
            raise Rejected(["a binding needs an input or output filter; delete the binding to remove it"])
        filters = entries(snapshot, FILTER)
        for direction in DIRECTIONS:
            used = after.get(direction)
            if used is not None and (f"{used}@{family}" not in filters or filters[f"{used}@{family}"].unsupported):
                raise Rejected(["a bound filter must be a configured %s filter handled by this profile" % family],
                               reason_codes=["junos_filter_dependency"])
        owned = own_lines(snapshot, table, key)
        prefix = f"set interfaces {interface} unit {unit} family {family}"
        if before is None and not any(line != prefix and line not in owned and line.startswith(prefix + " ")
                                      or line == prefix and line not in owned for line in snapshot.lines):
            raise Rejected(["the logical interface has no configured %s family" % family],
                           reason_codes=["junos_filter_dependency"])
    changed = any((before or {}).get(direction) != (after or {}).get(direction) for direction in DIRECTIONS)
    if changed and not undo and impact != key:
        raise Rejected(["changing an interface filter binding needs endpoint_impact"],
                       reason_codes=["endpoint_impact_required"])
    return []


def notes(table, after):
    """Preview texts: a Junos filter ends with an implicit discard."""
    if table != FILTER or after is None:
        return []
    last = list(_terms(after["terms"]).values())[-1]
    if last[0] != "-":
        return ["the last term matches only a source prefix: other packets are discarded by the implicit "
                "final discard of a Junos filter"]
    return []
