"""Configuration state for Junos Ethernet aggregates and ELS rapid spanning tree."""
from __future__ import annotations

import re

from netops_admin import junos
from netops_admin.errors import Rejected


LAG = "lag"
RSTP = "rstp"
RSTP_PORT = "rstp-interface"
TABLES = (LAG, RSTP, RSTP_PORT)
AE = re.compile(r"ae(?:0|[1-9][0-9]{0,3})")
AE_LINE = re.compile(r"set interfaces (ae[0-9]+)(?: (.*))?")
MEMBER = re.compile(r"set interfaces (\S+) ether-options 802\.3ad (ae[0-9]+)")
MODE = re.compile(r"aggregated-ether-options lacp (active|passive)")
COUNT = "chassis aggregated-devices ethernet device-count"
RSTP_PATH = "protocols rstp"
RSTP_INTERFACE = RSTP_PATH + " interface "
RSTP_OWN = {"edge": "edge", "cost": "cost", "bridge-priority": "bridge-priority",
            "bpdu-block-on-edge": "bpdu-block-on-edge"}
SWITCHING = "unit 0 family ethernet-switching"
BRIDGE_DEFAULT = "32768"
# A multi-stanza LAG candidate can exceed the terminal height. Use a distinct command from
# the existing pre-edit empty-candidate assertion (which rejects any output).
COMPARE = "show | compare rollback 0 | no-more"


def reject(message):
    raise Rejected([message], reason_codes=["junos_link_configuration_unsupported"])


def port_name(key):
    return key.removesuffix(".0")


def members(state):
    return set((state or {}).get("members", "").split())


def prefix_matches(line, path):
    return line == path or line.startswith(path + " ")


def bridge_priority(value):
    number = int(value[:-1]) * 1024 if value.endswith("k") else int(value)
    if not 0 <= number <= 61440 or number % 4096:
        reject("Junos bridge-priority must be a multiple of 4096 in 0..61440")
    return str(number)


def lag_entries(snapshot):
    entries = {}
    groups = {}
    for line in snapshot.lines:
        aggregate = AE_LINE.fullmatch(line)
        member = MEMBER.fullmatch(line)
        if aggregate:
            key, tail = aggregate.groups()
            entry = entries.setdefault(key, junos.Entry(key))
            if tail == SWITCHING:
                entry.attributes["switching"] = "enabled"
            elif not tail:
                entry.attributes["empty-aggregate"] = "enabled"
            elif mode := MODE.fullmatch(tail):
                junos._once(entry, "lacp-mode", mode[1])
        elif member:
            port, key = member.groups()
            entries.setdefault(key, junos.Entry(key))
            groups.setdefault(key, set()).add(port)
    for key, ports in groups.items():
        entries[key].attributes["members"] = " ".join(sorted(ports))
    return entries


def _rstp_attribute(tail, port):
    if tail == ("edge" if port else "bpdu-block-on-edge"):
        return tail, "enabled"
    name, _, value = tail.partition(" ")
    if port and name == "cost" and value.isdecimal() and 1 <= int(value) <= 200000000:
        return name, str(int(value))
    if not port and name == "bridge-priority" and re.fullmatch(r"[0-9]+k?", value):
        return name, bridge_priority(value)
    return None


def rstp_entries(snapshot, table):
    entries = {}
    is_port = table == RSTP_PORT
    for line in snapshot.lines:
        if is_port:
            if not line.startswith("set " + RSTP_INTERFACE):
                continue
            key, _, tail = line[len("set " + RSTP_INTERFACE):].partition(" ")
        else:
            if not prefix_matches(line, "set " + RSTP_PATH):
                continue
            key, tail = RSTP, line[len("set " + RSTP_PATH):].strip()
        value = _rstp_attribute(tail, is_port)
        if value:
            junos._once(entries.setdefault(key, junos.Entry(key)), *value)
        elif not tail:
            entries.setdefault(key, junos.Entry(key)).attributes["empty-stanza"] = "enabled"
    return entries


def owned(snapshot, table, key):
    if table == LAG:
        root = "set interfaces " + key
        return {line for line in snapshot.lines if line == root or line == root + " " + SWITCHING
                or (line.startswith(root + " ") and MODE.fullmatch(line[len(root) + 1:]))
                or ((member := MEMBER.fullmatch(line)) and member[2] == key)}
    is_port = table == RSTP_PORT
    root = "set " + (RSTP_INTERFACE + key if is_port else RSTP_PATH)
    return {line for line in snapshot.lines if line == root or (is_port and line == "set " + RSTP_PATH)
            or (line.startswith(root + " ") and _rstp_attribute(line[len(root) + 1:], is_port))}


def rstp_root(snapshot):
    lines = [line for line in snapshot.lines if prefix_matches(line, "set " + RSTP_PATH)]
    if not lines:
        return "absent"
    return "empty" if lines == ["set " + RSTP_PATH] else "configured"


def rstp_layout(snapshot, table, key, after, original):
    own = owned(snapshot, table, key)
    port_root = "set " + RSTP_INTERFACE + key
    others = [line for line in snapshot.lines if line.startswith("set " + RSTP_PATH + " ") and line not in own]
    current = rstp_root(snapshot)
    if others or (after and not after.get("empty-stanza")) or (after and table == RSTP_PORT):
        wanted = "configured"
    elif after:
        wanted = "empty"
    elif original is not None and original["after"] != original["before"]:
        wanted = original["before"]
    else:
        wanted = "absent"
    return {"before": current, "after": wanted}, any(prefix_matches(line, port_root) for line in others)


def capacity(snapshot):
    lines = [line for line in snapshot.lines if prefix_matches(line, "set " + COUNT)]
    if len(lines) > 1 or (lines and not re.fullmatch(r"[0-9]+", lines[0][len(COUNT) + 5:])):
        reject("Junos aggregate device-count is not a single integer")
    return lines[0].split()[-1] if lines else None


def capacity_plan(snapshot, key, after, original):
    current = capacity(snapshot)
    wanted = current
    if original is not None and original["before"] != original["after"]:
        if current != original["after"]:
            reject("Junos aggregate capacity changed since the original operation")
        wanted = original["before"]
        if any(int(other[2:]) >= int(wanted or 0) for other in lag_entries(snapshot) if other != key):
            reject("Another Junos aggregate needs the capacity allocated by the original operation")
    elif after is not None and int(key[2:]) >= int(current or 0):
        wanted = str(int(key[2:]) + 1)
    return {"before": current, "after": wanted}


def _inheritance(snapshot, key, keyword):
    sources, unsupported = snapshot.sources(key)
    if unsupported or key in snapshot.deactivated or any(
            keyword in line.split() for source in sources if source.kind != "interface" for line in source.lines):
        reject("Junos interface %s has inherited, inactive or protected %s configuration" % (key, keyword))
    return [line for source in sources for line in source.lines]


def _port(key):
    key = port_name(key)
    if junos.MANAGEMENT.fullmatch(key):
        raise Rejected(["interface %s is reserved for management" % key], reason_codes=["port_management_interface"])
    if not junos.PHYSICAL.fullmatch(key):
        raise Rejected(["interface %s is not a physical Ethernet port" % key],
                       reason_codes=["port_unsupported_interface"])
    return key


def _lag_checks(snapshot, key, before, after, op, undo):
    if any("aggregated-devices" in line.split() and not prefix_matches(line, "set " + COUNT)
           for line in snapshot.lines if line.startswith(("deactivate ", "protect ", "set groups "))):
        reject("Inherited, inactive or protected Junos aggregate capacity cannot be changed safely")
    _inheritance(snapshot, key, "aggregated-ether-options")
    # Refuse inherited or unsupported membership of this aggregate even when the ports are not named in the request.
    direct = owned(snapshot, LAG, key)
    for line in snapshot.lines:
        if "802.3ad" in line.split() and key in line.split() and line not in direct:
            reject("Junos aggregate %s has membership outside the direct ether-options configuration" % key)
    configured = [tail for tail in snapshot.interfaces.get(key, [])
                  if tail and tail != SWITCHING and not MODE.fullmatch(tail)]
    if any(prefix_matches(tail, "aggregated-ether-options lacp") for tail in configured) and (
            "lacp-mode" not in (before or {}) or "lacp-mode" not in (after or {})):
        reject("The existing Junos LACP subtree requires an explicit mode and must be preserved")
    if op == "delete":
        reference = re.compile(r"(?<!\S)" + re.escape(key) + r"(?:\.\d+)?(?!\S)")
        if any(reference.search(line) for line in snapshot.lines if line not in direct):
            reject("Junos aggregate %s has configuration or references outside the LAG profile" % key)
    if after is not None:
        if op == "create" and not undo:
            if "lacp-mode" not in after:
                reject("Creating a Junos LAG requires lacp-mode active or passive")
            after["switching"] = "enabled"
        if after.get("empty-aggregate") and (after.get("lacp-mode") or after.get("switching") or configured):
            after.pop("empty-aggregate")
        if not after and op == "update" and not configured:
            after["empty-aggregate"] = "enabled"
    for state in (before, after):
        if members(state) and "lacp-mode" not in state:
            reject("Junos aggregates with members require LACP for independent operational readback")
    for key_port in sorted(members(before) | members(after)):
        _port(key_port)
        lines = _inheritance(snapshot, key_port, "802.3ad")
        if any(junos.LAG.match(line) and line != "ether-options 802.3ad " + key for line in lines):
            raise Rejected(["interface %s already belongs to another aggregate" % key_port],
                           reason_codes=["port_lag_member"])
        if key_port in members(after) - members(before) and any(
                line.startswith(("unit ", "native-vlan-id ")) for line in lines):
            reject("New Junos LAG member %s must have no logical units or native VLAN" % key_port)


def edge_ports(snapshot):
    result = set()
    for line in snapshot.lines:
        if line.startswith("set " + RSTP_INTERFACE) and line.endswith(" edge"):
            result.add(_port(line.split()[4]))
    return result


def prepare(snapshot, table, key, before, after, op, undo, impact):
    if table == LAG:
        _lag_checks(snapshot, key, before, after, op, undo)
        return
    if any("rstp" in line.split() and (
            line.startswith(("deactivate protocols ", "protect protocols ", "set groups "))
            or line.startswith("set protocols rstp apply-groups")) for line in snapshot.lines):
        reject("Inherited, inactive or protected RSTP configuration cannot be changed safely")
    if table == RSTP_PORT:
        port = _port(key)
        forms = rstp_entries(snapshot, table)
        other_key = port if key != port else port + ".0"
        if other_key in forms:
            reject("RSTP already configures this interface as %s" % other_key)
        lines = _inheritance(snapshot, port, "802.3ad")
        if any(junos.LAG.match(line) for line in lines):
            raise Rejected(["RSTP runs on the aggregate rather than its member %s" % port],
                           reason_codes=["port_lag_member"])
    else:
        if before.get("bridge-priority") != after.get("bridge-priority"):
            if impact != key:
                raise Rejected(["Changing bridge priority requires endpoint_impact naming rstp"],
                               reason_codes=["junos_rstp_impact_required"])
            if "bridge-priority" in after:
                after["bridge-priority"] = bridge_priority(after["bridge-priority"])
        if before.get("bpdu-block-on-edge") != after.get("bpdu-block-on-edge"):
            edge_ports(snapshot)  # Explicit edge interfaces must be individually protectable.
    if after.get("empty-stanza") and len(after) > 1:
        after.pop("empty-stanza")


def _set(path, value):
    return "set " + path + (" " + value if value else "")


def _lag_lines(key, before, after):
    root = "interfaces " + key
    old, new = before or {}, after or {}
    lines = ["delete interfaces %s ether-options 802.3ad" % port for port in sorted(members(old) - members(new))]
    if after is None:
        return [*lines, "delete " + root]
    if new.get("switching") and not old.get("switching"):
        lines.append(_set(root + " " + SWITCHING, None))
    if old.get("lacp-mode") != new.get("lacp-mode"):
        path = root + " aggregated-ether-options lacp"
        if old.get("lacp-mode"):
            lines.append("delete " + path + (" " + old["lacp-mode"] if new.get("lacp-mode") else ""))
        if new.get("lacp-mode"):
            lines.append(_set(path, new["lacp-mode"]))
    lines.extend(_set("interfaces %s ether-options 802.3ad" % port, key)
                 for port in sorted(members(new) - members(old)))
    if new.get("empty-aggregate") and not old.get("empty-aggregate"):
        lines.append(_set(root, None))
    return lines


def render(table, key, before, after, reservation=None, *, rstp=None, other_port_settings=False):
    if table == LAG:
        lines = _lag_lines(key, before, after)
        old, new = reservation["before"], reservation["after"]
        if int(new or 0) > int(old or 0):
            lines.insert(0, _set(COUNT, new))
        elif old != new:
            lines.append(_set(COUNT, new) if new is not None else "delete " + COUNT)
        return junos._session(lines, compare=COMPARE)
    path = RSTP_INTERFACE + key if table == RSTP_PORT else RSTP_PATH
    if rstp["after"] == "absent":
        return junos._session(["delete " + RSTP_PATH], compare=COMPARE)
    if rstp["after"] == "empty" and table == RSTP_PORT:
        return junos._session(["delete " + RSTP_PATH, _set(RSTP_PATH, None)], compare=COMPARE)
    if not after and table == RSTP_PORT and not other_port_settings:
        return junos._session(["delete " + path], compare=COMPARE)
    lines = []
    for attr in ("edge", "cost", "bpdu-block-on-edge", "bridge-priority"):
        if before.get(attr) == after.get(attr):
            continue
        item = path + " " + RSTP_OWN[attr]
        if attr not in after:
            lines.append("delete " + item)
        else:
            lines.append(_set(item, after[attr] if after[attr] != "enabled" else None))
    if after.get("empty-stanza") and not before.get("empty-stanza"):
        lines.append(_set(path, None))
    return junos._session(lines, compare=COMPARE)


def affected_ports(snapshot, table, key, before, after):
    if table == LAG:
        return members(before) | members(after)
    if table == RSTP_PORT:
        return {port_name(key)}
    if before.get("bpdu-block-on-edge") != after.get("bpdu-block-on-edge"):
        return edge_ports(snapshot)
    return set()


def protect(snapshot, table, key, before, after, protected):
    ports = (edge_ports(snapshot) if table == RSTP and before != after
             else affected_ports(snapshot, table, key, before, after))
    names = ports | {key}
    if table == LAG:
        names.add(key + ".0")
    elif table in (RSTP_PORT, RSTP):
        names.update(port + ".0" for port in ports)
    guarded = {name.casefold() for name in (protected or {}).get(table, ())}
    guarded.update(name.casefold() for name in (protected or {}).get("interface", ()))
    for name in sorted(names):
        if name.casefold() in guarded:
            raise Rejected(["Junos interface or object %s is protected" % name], reason_codes=["port_protected"])
