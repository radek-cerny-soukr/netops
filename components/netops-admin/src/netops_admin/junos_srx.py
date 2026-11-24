"""Junos SRX security zones, global address book, security policies and NAT (1.0.12 junos srx security: J27, J28, J49).

State is read from the set-format configuration only. The statements follow the Juniper documentation of
`security zones`, `security address-book global`, `security policies` and `security nat`
(tests/fixtures/junos_g143/PROVENANCE.md); there is no SRX in the lab, so the object model is deliberately small:
anything outside it makes the object "outside the profile" and the change is refused.
"""

from __future__ import annotations

import ipaddress
import re

from .errors import Rejected

ZONE = "security-zone"
ADDRESS = "address-book-address"
ADDRESS_SET = "address-book-set"
POLICY = "security-policy"
NAT_SOURCE = "nat-source-rule"
NAT_POOL = "nat-destination-pool"
NAT_DESTINATION = "nat-destination-rule"
TABLES = (ZONE, ADDRESS, ADDRESS_SET, POLICY, NAT_SOURCE, NAT_POOL, NAT_DESTINATION)
LIST_ATTRIBUTES = {"interfaces", "host-inbound-services", "addresses", "source-addresses",
                   "destination-addresses", "applications"}
NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}"
IFL = re.compile(r"[a-z][a-z0-9-]*[0-9]+(?:/[0-9]+){0,2}\.[0-9]+")
MANAGEMENT = re.compile(r"(?:fxp|em|me|vme)[0-9]+(?:\.[0-9]+)?")
SERVICE = re.compile(r"[a-z0-9-]{1,40}")
BUILTIN_ADDRESS = ("any", "any-ipv4", "any-ipv6")
ZONE_PRESERVED = ("description", "screen", "tcp-rst", "application-tracking")
ACTIONS = ("permit", "deny", "reject")
SECURITY = "set security "
ZONES = "security zones security-zone "
BOOK = "security address-book global "
POLICIES = "security policies from-zone "
NAT = {NAT_SOURCE: "security nat source rule-set ", NAT_DESTINATION: "security nat destination rule-set "}
POOLS = "security nat destination pool "


def reject(message, code="junos_srx_scope"):
    raise Rejected([message], reason_codes=[code])


# ---- canonical values ----

def _names(value, pattern=NAME):
    values = value.split()
    if not values or len(set(values)) != len(values) or not all(re.fullmatch(pattern, item) for item in values):
        raise ValueError("invalid or duplicate name list")
    return " ".join(sorted(values))


def prefix_text(value, *, host_only=False):
    """The form Junos shows: a single address is a /32 or /128 prefix."""
    network = ipaddress.ip_network(value if "/" in value else value + ("/128" if ":" in value else "/32"),
                                   strict=True)
    if host_only and network.num_addresses != 1:
        raise ValueError("a single address is required")
    return str(network)


def canonical_changes(table, changes):
    result = dict(changes)
    try:
        for name, value in changes.items():
            if value is None:
                continue
            if name == "interfaces":
                result[name] = _names(value, IFL.pattern)
            elif name == "host-inbound-services":
                result[name] = _names(value, SERVICE.pattern)
            elif name in LIST_ATTRIBUTES:
                result[name] = _names(value)
            elif name in ("prefix", "source-address", "destination-address") or (name == "address" and table == NAT_POOL):
                result[name] = prefix_text(value, host_only=name == "address")
    except ValueError as exc:
        raise Rejected(["invalid Junos SRX attribute %s: %s" % (name, exc)]) from None
    return result


def split_key(table, key):
    """(parts) of a compound key: policy FROM@TO@NAME, NAT RULESET@RULE."""
    parts = key.split("@")
    if table == POLICY and len(parts) == 3 and all(re.fullmatch(NAME, part) for part in parts):
        return parts
    if table in (NAT_SOURCE, NAT_DESTINATION) and len(parts) == 2 and all(re.fullmatch(NAME, part) for part in parts):
        return parts
    if table in (ZONE, ADDRESS, ADDRESS_SET, NAT_POOL) and len(parts) == 1 and re.fullmatch(NAME, key):
        return parts
    raise Rejected(["the key does not name a %s (policy FROM@TO@POLICY, NAT RULESET@RULE)" % table])


# ---- reading the set-format configuration ----

def _put(entry, name, value):
    if name in entry.attributes and entry.attributes[name] != value:
        raise ValueError("multiple values")
    entry.attributes[name] = value


def _append(entry, name, value):
    values = entry.attributes.get(name, "").split()
    if value in values:
        raise ValueError("repeated value")
    entry.attributes[name] = " ".join(sorted([*values, value]))


def _rows(snapshot, root):
    """(verb, rest words) of every line below `root` (a path string with a trailing space)."""
    for line in snapshot.lines:
        verb, _, path = line.partition(" ")
        if path.startswith(root):
            yield verb, path[len(root):].split()
        elif root.startswith(path + " ") and verb != "set":
            yield verb, []


def _zone_entries(snapshot, found):
    from .junos import Entry

    for verb, words in _rows(snapshot, ZONES):
        if not words:
            continue
        entry = found.setdefault(words[0], Entry(words[0]))
        rest = words[1:]
        try:
            if verb != "set":
                raise ValueError("inactive or protected zone statement")
            if not rest or rest[0] in ZONE_PRESERVED:
                continue
            if len(rest) == 2 and rest[0] == "interfaces" and IFL.fullmatch(rest[1]):
                _append(entry, "interfaces", rest[1])
            elif (len(rest) == 3 and rest[:2] == ["host-inbound-traffic", "system-services"]
                  and SERVICE.fullmatch(rest[2])):
                _append(entry, "host-inbound-services", rest[2])
            else:
                raise ValueError("unsupported zone statement")
        except ValueError:
            entry.unsupported.append("zone configuration outside the profile")
    return found


def _book_entries(snapshot, table, found):
    from .junos import Entry

    for verb, words in _rows(snapshot, BOOK):
        if len(words) < 2 or words[0] not in ("address", "address-set"):
            continue
        kind, name, rest = words[0], words[1], words[2:]
        if (kind == "address") != (table == ADDRESS):
            continue
        entry = found.setdefault(name, Entry(name))
        try:
            if verb != "set":
                raise ValueError("inactive or protected address book statement")
            if table == ADDRESS and len(rest) == 1:
                _put(entry, "prefix", prefix_text(rest[0]))
            elif table == ADDRESS_SET and len(rest) == 2 and rest[0] == "address" and re.fullmatch(NAME, rest[1]):
                _append(entry, "addresses", rest[1])
            else:
                raise ValueError("unsupported address book statement")
        except ValueError:
            entry.unsupported.append("address book configuration outside the profile")
    return found


def policy_order(snapshot):
    """The policies of each zone pair in configured order: {(from, to): [name, ...]}."""
    order = {}
    for line in snapshot.lines:
        words = line.split()
        if (words[:1] == ["set"] and " ".join(words[1:3]) == "security policies" and len(words) >= 8
                and words[3] == "from-zone" and words[5] == "to-zone" and words[7] == "policy" and len(words) >= 9):
            names = order.setdefault((words[4], words[6]), [])
            if words[8] not in names:
                names.append(words[8])
    return order


def _policy_entries(snapshot, found):
    from .junos import Entry

    for verb, words in _rows(snapshot, POLICIES):
        if len(words) < 4 or words[1] != "to-zone" or words[3] != "policy" or len(words) < 5:
            continue
        key = "@".join((words[0], words[2], words[4]))
        entry = found.setdefault(key, Entry(key))
        rest = words[5:]
        try:
            if verb != "set":
                raise ValueError("inactive or protected policy statement")
            if len(rest) == 3 and rest[0] == "match" and rest[1] in ("source-address", "destination-address",
                                                                    "application"):
                attribute = {"source-address": "source-addresses", "destination-address": "destination-addresses",
                             "application": "applications"}[rest[1]]
                if not re.fullmatch(NAME, rest[2]):
                    raise ValueError("invalid name")
                _append(entry, attribute, rest[2])
            elif len(rest) == 2 and rest[0] == "then" and rest[1] in ACTIONS:
                _put(entry, "action", rest[1])
            else:
                raise ValueError("unsupported policy statement")
        except ValueError:
            entry.unsupported.append("policy configuration outside the profile")
    for entry in found.values():
        if not entry.unsupported and not {"source-addresses", "destination-addresses", "applications",
                                          "action"} <= set(entry.attributes):
            entry.unsupported.append("incomplete policy")
    return found


def _nat_entries(snapshot, table, found):
    from .junos import Entry

    root = NAT[table]
    zones = {}
    rules = {}
    for verb, words in _rows(snapshot, root):
        if len(words) < 2:
            continue
        ruleset, rest = words[0], words[1:]
        if verb != "set":
            rules.setdefault(ruleset, {}).setdefault(None, []).append("inactive or protected NAT statement")
            continue
        if rest[0] == "from" and len(rest) == 3 and rest[1] == "zone":
            zones.setdefault(ruleset, {}).setdefault("from", []).append(rest[2])
        elif table == NAT_SOURCE and rest[0] == "to" and len(rest) == 3 and rest[1] == "zone":
            zones.setdefault(ruleset, {}).setdefault("to", []).append(rest[2])
        elif rest[0] == "rule" and len(rest) >= 3:
            rules.setdefault(ruleset, {}).setdefault(rest[1], []).append(rest[2:])
        else:
            rules.setdefault(ruleset, {}).setdefault(None, []).append("unsupported rule-set statement")
    for ruleset, named in rules.items():
        problems = named.pop(None, [])
        for rule, statements in named.items():
            key = ruleset + "@" + rule
            entry = found.setdefault(key, Entry(key))
            entry.unsupported.extend(problems)
            declared = zones.get(ruleset, {})
            if len(declared.get("from", [])) != 1 or (table == NAT_SOURCE and len(declared.get("to", [])) != 1):
                entry.unsupported.append("rule-set zone binding outside the profile")
            else:
                entry.attributes["from-zone"] = declared["from"][0]
                if table == NAT_SOURCE:
                    entry.attributes["to-zone"] = declared["to"][0]
            for words in statements:
                try:
                    _nat_statement(entry, table, words)
                except ValueError:
                    entry.unsupported.append("NAT rule configuration outside the profile")
            required = ({"source-address", "translation"} if table == NAT_SOURCE
                        else {"destination-address", "pool"})
            if not entry.unsupported and not required <= set(entry.attributes):
                entry.unsupported.append("incomplete NAT rule")
    return found


def _nat_statement(entry, table, words):
    if len(words) == 3 and words[0] == "match" and words[1] in ("source-address", "destination-address"):
        if table == NAT_DESTINATION and words[1] != "destination-address":
            raise ValueError("unsupported destination NAT match")
        _put(entry, words[1], prefix_text(words[2]))
    elif table == NAT_SOURCE and words == ["then", "source-nat", "interface"]:
        _put(entry, "translation", "interface")
    elif table == NAT_SOURCE and words == ["then", "source-nat", "off"]:
        _put(entry, "translation", "off")
    elif table == NAT_DESTINATION and len(words) == 4 and words[:3] == ["then", "destination-nat", "pool"]:
        _put(entry, "pool", words[3])
    else:
        raise ValueError("unsupported NAT statement")


def _pool_entries(snapshot, found):
    from .junos import Entry

    for verb, words in _rows(snapshot, POOLS):
        if not words:
            continue
        entry = found.setdefault(words[0], Entry(words[0]))
        try:
            if verb != "set" or len(words) != 3 or words[1] != "address":
                raise ValueError("unsupported pool statement")
            _put(entry, "address", prefix_text(words[2], host_only=True))
        except ValueError:
            entry.unsupported.append("destination pool configuration outside the profile")
    return found


def entries(snapshot, table):
    if table == ZONE:
        return _zone_entries(snapshot, {})
    if table in (ADDRESS, ADDRESS_SET):
        return _book_entries(snapshot, table, {})
    if table == POLICY:
        return _policy_entries(snapshot, {})
    if table == NAT_POOL:
        return _pool_entries(snapshot, {})
    return _nat_entries(snapshot, table, {})


def ruleset_peers(snapshot, table, key):
    ruleset = key.split("@")[0]
    return sorted(other for other in entries(snapshot, table) if other != key and other.startswith(ruleset + "@"))


def _nat_rule_order(snapshot, table, ruleset):
    prefix = [ruleset, "rule"]
    return list(dict.fromkeys(words[2] for verb, words in _rows(snapshot, NAT[table])
                              if verb == "set" and words[:2] == prefix and len(words) >= 3))


def _nat_anchor(commands, path):
    prefix = f"insert {path} before rule "
    return next((line[len(prefix):] for line in commands if line.startswith(prefix)), None)


def nat_order_matches(snapshot, plan, expect):
    """Check the position of a created or restored rule as well as its attributes."""
    commands = {("create", "after"): "commands", ("delete", "before"): "inverse"}.get((plan["op"], expect))
    if commands is None:
        return True
    table = plan["table"]
    ruleset, rule = plan["key"].split("@")
    path = f"{NAT[table]}{ruleset} rule {rule}"
    order = _nat_rule_order(snapshot, table, ruleset)
    anchor = _nat_anchor(plan[commands], path)
    if rule not in order:
        return False
    following = order[order.index(rule) + 1:]
    return anchor == (following[0] if following else None)


def own_lines(snapshot, table, key):
    result = set()
    parts = key.split("@")
    if table == ZONE:
        prefix = "set " + ZONES + key
        for line in snapshot.lines:
            if line == prefix:
                result.add(line)
            elif line.startswith(prefix + " "):
                words = line[len(prefix) + 1:].split()
                if (words[:1] == ["interfaces"] and len(words) == 2) or (
                        words[:2] == ["host-inbound-traffic", "system-services"] and len(words) == 3):
                    result.add(line)
        return result
    if table in (ADDRESS, ADDRESS_SET):
        kind = "address " if table == ADDRESS else "address-set "
        prefix = "set " + BOOK + kind + key
        return {line for line in snapshot.lines if line == prefix or line.startswith(prefix + " ")}
    if table == POLICY:
        prefix = "set %s%s to-zone %s policy %s" % (POLICIES, parts[0], parts[1], parts[2])
        return {line for line in snapshot.lines if line == prefix or line.startswith(prefix + " ")}
    if table == NAT_POOL:
        prefix = "set " + POOLS + key
        return {line for line in snapshot.lines if line == prefix or line.startswith(prefix + " ")}
    ruleset, rule = parts
    prefix = "set %s%s " % (NAT[table], ruleset)
    sole = not ruleset_peers(snapshot, table, key)
    for line in snapshot.lines:
        if line.startswith(prefix + "rule %s " % rule) or line == prefix + "rule " + rule:
            result.add(line)
        elif sole and line.startswith(prefix) and line[len(prefix):].split()[:1] in (["from"], ["to"]):
            result.add(line)
    return result


# ---- rendering ----

def _delta(path, old, new, lines):
    old, new = set((old or "").split()), set((new or "").split())
    lines.extend("delete %s %s" % (path, name) for name in sorted(old - new))
    lines.extend("set %s %s" % (path, name) for name in sorted(new - old))


def render(snapshot, table, key, before, after, restore=None):
    before_state = before or {}
    parts = key.split("@")
    lines = []
    if table == ZONE:
        path = ZONES + key
        if after is None:
            return ["delete " + path]
        if not after:
            lines.append("set " + path)
        _delta(path + " interfaces", before_state.get("interfaces"), after.get("interfaces"), lines)
        _delta(path + " host-inbound-traffic system-services", before_state.get("host-inbound-services"),
               after.get("host-inbound-services"), lines)
        if before is None and after:
            lines.insert(0, "set " + path)
        return lines
    if table == ADDRESS:
        path = BOOK + "address " + key
        return ["delete " + path] if after is None else (
            ["set %s %s" % (path, after["prefix"])] if before_state.get("prefix") != after["prefix"] else [])
    if table == ADDRESS_SET:
        path = BOOK + "address-set " + key
        if after is None:
            return ["delete " + path]
        _delta(path + " address", before_state.get("addresses"), after.get("addresses"), lines)
        return lines
    if table == NAT_POOL:
        path = POOLS + key
        return ["delete " + path] if after is None else (
            ["set %s address %s" % (path, after["address"])] if before_state.get("address") != after["address"] else [])
    if table == POLICY:
        path = "%s%s to-zone %s policy %s" % (POLICIES, *parts)
        if after is None:
            return ["delete " + path]
        _delta(path + " match source-address", before_state.get("source-addresses"), after["source-addresses"], lines)
        _delta(path + " match destination-address", before_state.get("destination-addresses"),
               after["destination-addresses"], lines)
        _delta(path + " match application", before_state.get("applications"), after["applications"], lines)
        if before_state.get("action") != after["action"]:
            if before_state.get("action"):
                lines.append("delete %s then %s" % (path, before_state["action"]))
            lines.append("set %s then %s" % (path, after["action"]))
        if before is None:
            # A policy restored by an inverse goes back before the policy that followed it: the inverse of a delete
            # names it from the configuration before the delete, the undo (`restore`) from that inverse.
            names = policy_order(snapshot).get((parts[0], parts[1]), [])
            anchors = [line.rsplit(" before policy ", 1)[1] for line in restore or ()
                       if line.startswith("insert %s " % path) and " before policy " in line]
            if parts[2] in names and names.index(parts[2]) + 1 < len(names):
                anchors = [names[names.index(parts[2]) + 1]]
            if anchors and anchors[0] in names and anchors[0] != parts[2]:
                lines.append("insert %s before policy %s" % (path, anchors[0]))
        return lines
    ruleset, rule = parts
    base = NAT[table] + ruleset
    path = "%s rule %s" % (base, rule)
    if after is None:
        return ["delete " + (path if ruleset_peers(snapshot, table, key) else base)]
    zones = [("from zone", "from-zone")] + ([("to zone", "to-zone")] if table == NAT_SOURCE else [])
    if not ruleset_peers(snapshot, table, key):
        for word, name in zones:
            if before_state.get(name) != after[name]:
                if before_state.get(name):
                    lines.append("delete %s %s %s" % (base, word, before_state[name]))
                lines.append("set %s %s %s" % (base, word, after[name]))
    match = ("source-address", "destination-address") if table == NAT_SOURCE else ("destination-address",)
    for name in match:
        if before_state.get(name) != after.get(name):
            if before_state.get(name):
                lines.append("delete %s match %s" % (path, name))
            if after.get(name):
                lines.append("set %s match %s %s" % (path, name, after[name]))
    if table == NAT_SOURCE and before_state.get("translation") != after["translation"]:
        if before_state.get("translation"):
            lines.append("delete %s then source-nat" % path)
        lines.append("set %s then source-nat %s" % (path, after["translation"]))
    if table == NAT_DESTINATION and before_state.get("pool") != after["pool"]:
        if before_state.get("pool"):
            lines.append("delete %s then destination-nat" % path)
        lines.append("set %s then destination-nat pool %s" % (path, after["pool"]))
    if before is None:
        order = _nat_rule_order(snapshot, table, ruleset)
        anchor = _nat_anchor(restore or (), path)
        if anchor is not None and anchor not in order:
            reject("the original NAT rule position can no longer be restored", "junos_srx_dependency")
        if rule in order:
            following = order[order.index(rule) + 1:]
            anchor = following[0] if following else None
        if anchor is not None:
            lines.append(f"insert {path} before rule {anchor}")
    return lines


def predicted_lines(snapshot, table, key, after):
    keep = [line for line in snapshot.lines if line not in own_lines(snapshot, table, key)]
    if after is None:
        return keep
    lines = [line for line in render(snapshot, table, key, None, after) if line.split()[0] == "set"]
    return keep + lines


# ---- checks ----

def _references(snapshot, name, skip):
    word = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])")
    return [line for line in snapshot.lines
            if line not in skip and line.split(" ", 1)[1:2] and line.split(" ", 1)[1].startswith(
                ("security policies", "security address-book", "security nat")) and word.search(line)]


def _foreign(snapshot):
    for line in snapshot.lines:
        words = line.split()
        if words[0] == "set" and words[1:2] == ["groups"] and len(words) > 4 and words[3] == "security":
            return True
        if words[0] != "set" and words[1:2] == ["security"] and len(words) == 2:
            return True
        if words[1:2] == ["security"] and "apply-groups" in words:
            return True
    return False


def _supported(found, name, what):
    entry = found.get(name)
    if entry is None or entry.unsupported:
        reject("%s %s is not configured in a supported form" % (what, name), "junos_srx_dependency")


def prechecks(snapshot, table, key, before, after, protected, impact, undo):
    split_key(table, key)
    if _foreign(snapshot):
        reject("inherited, inactive or protected security configuration needs a separate change")
    protected = protected or {}
    guarded = {name.casefold() for name in protected.get(table, ())}
    if key.casefold() in guarded or key.split("@")[-1].casefold() in guarded:
        raise Rejected(["the SRX object %s is protected" % key], reason_codes=["port_protected"])
    own = own_lines(snapshot, table, key)
    if table == ZONE:
        _zone_checks(snapshot, key, before, after, protected)
    elif table in (ADDRESS, ADDRESS_SET):
        _book_checks(snapshot, table, key, before, after, own)
    elif table == POLICY:
        _policy_checks(snapshot, key, after)
    elif table == NAT_POOL:
        if before is not None and after is None and any(
                entry.attributes.get("pool") == key for entry in entries(snapshot, NAT_DESTINATION).values()):
            reject("the destination pool is used by a NAT rule", "junos_srx_dependency")
    else:
        _nat_checks(snapshot, table, key, before, after)
    if before is not None and not undo and impact != key and _boundary_change(snapshot, table, key, before, after, own):
        raise Rejected(["changing an existing SRX %s changes a security boundary; endpoint_impact must name %s"
                        % (table, key)], reason_codes=["endpoint_impact_required"])
    return []


def _boundary_change(snapshot, table, key, before, after, own):
    if table in (ADDRESS, ADDRESS_SET):
        return bool(_references(snapshot, key, own))
    if table == NAT_POOL:
        return any(entry.attributes.get("pool") == key for entry in entries(snapshot, NAT_DESTINATION).values())
    return True


def _zone_checks(snapshot, key, before, after, protected):
    zones = entries(snapshot, ZONE)
    ports = set((before or {}).get("interfaces", "").split()) | set((after or {}).get("interfaces", "").split())
    guarded = {name.casefold() for name in protected.get("interface", ())}
    for ifl in sorted(ports):
        if MANAGEMENT.fullmatch(ifl):
            raise Rejected(["interface %s is reserved for management" % ifl],
                           reason_codes=["port_management_interface"])
        if ifl.casefold() in guarded or ifl.rsplit(".", 1)[0].casefold() in guarded:
            raise Rejected(["interface %s is protected" % ifl], reason_codes=["port_protected"])
    for ifl in sorted(set((after or {}).get("interfaces", "").split()) - set((before or {}).get("interfaces", "").split())):
        for name, entry in zones.items():
            if name != key and ifl in entry.attributes.get("interfaces", "").split():
                reject("interface %s already belongs to zone %s" % (ifl, name), "junos_srx_dependency")
        if not any(line.startswith("set interfaces %s unit %s " % tuple(ifl.rsplit(".", 1))) for line in snapshot.lines):
            reject("interface %s has no configured logical unit" % ifl, "junos_srx_dependency")
    if after is None and _zone_references(snapshot, key):
        reject("security zone %s is used by policies or NAT" % key, "junos_srx_dependency")
    if after is None and any(
            line.startswith("set " + ZONES + key + " ") and line.split()[5:6] and line.split()[5] in ZONE_PRESERVED
            for line in snapshot.lines):
        reject("the zone has other settings that cannot be restored by this profile")


def _zone_references(snapshot, zone):
    word = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(zone) + r"(?![A-Za-z0-9_.-])")
    for line in snapshot.lines:
        text = line.split(" ", 1)[-1]
        if text.startswith(("security policies from-zone", "security nat")) and word.search(
                re.sub(r" (?:policy|rule|rule-set|pool) \S+", "", text)):
            return True
    return False


def _book_checks(snapshot, table, key, before, after, own):
    other = ADDRESS_SET if table == ADDRESS else ADDRESS
    if before is None and key in entries(snapshot, other):
        reject("name %s is already used in the global address book" % key, "junos_srx_dependency")
    if after is None and _references(snapshot, key, own):
        reject("%s %s is referenced by policies, sets or NAT" % (table, key), "junos_srx_dependency")
    if table == ADDRESS_SET and after:
        found = entries(snapshot, ADDRESS)
        for name in after["addresses"].split():
            _supported(found, name, "address")


def _address_names(snapshot):
    result = {name for name, entry in entries(snapshot, ADDRESS).items() if not entry.unsupported}
    result |= {name for name, entry in entries(snapshot, ADDRESS_SET).items() if not entry.unsupported}
    return result


def _zone_names(snapshot):
    return {name for name, entry in entries(snapshot, ZONE).items() if not entry.unsupported} | {"junos-host"}


def _applications(snapshot):
    names = set()
    for line in snapshot.lines:
        words = line.split()
        if words[:2] == ["set", "applications"] and len(words) >= 4 and words[2] in ("application", "application-set"):
            names.add(words[3])
    return names


def _policy_checks(snapshot, key, after):
    from_zone, to_zone, _name = key.split("@")
    zones = _zone_names(snapshot)
    missing = [zone for zone in (from_zone, to_zone) if zone not in zones]
    if missing:
        reject("security zone %s is not configured" % missing[0], "junos_srx_dependency")
    if after is None:
        return
    known = _address_names(snapshot) | set(BUILTIN_ADDRESS)
    for attribute in ("source-addresses", "destination-addresses"):
        for name in after[attribute].split():
            if name not in known:
                reject("address %s is not in the global address book" % name, "junos_srx_dependency")
    known_apps = _applications(snapshot)
    for name in after["applications"].split():
        if name != "any" and not name.startswith("junos-") and name not in known_apps:
            reject("application %s is not predefined or configured" % name, "junos_srx_dependency")


def _nat_checks(snapshot, table, key, before, after):
    ruleset = key.split("@")[0]
    base = "set %s%s " % (NAT[table], ruleset)
    peers = ruleset_peers(snapshot, table, key)
    zone_lines = [line for line in snapshot.lines if line.startswith(base) and line[len(base):].split()[:1] in (["from"], ["to"])]
    if not peers and zone_lines and before is None:
        reject("the NAT rule-set %s exists without rules" % ruleset)
    if after is None:
        return
    zones = _zone_names(snapshot)
    for name in ("from-zone", "to-zone"):
        if name in after and after[name] not in zones:
            reject("security zone %s is not configured" % after[name], "junos_srx_dependency")
    found = entries(snapshot, table)
    for other in peers:
        for name in ("from-zone", "to-zone"):
            if name in after and found[other].attributes.get(name) != after[name]:
                reject("the NAT rule-set %s is shared with rule %s; its zones cannot differ" % (ruleset, other))
    if table == NAT_DESTINATION:
        _supported(entries(snapshot, NAT_POOL), after["pool"], "destination pool")
