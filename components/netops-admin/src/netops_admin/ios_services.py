"""Global IOS NTP, syslog and DNS profiles."""
from __future__ import annotations

import hashlib
import ipaddress
import re

from netops_admin.errors import Rejected

SYSTEM = "system-services"
NTP = "ntp-server"
SYSLOG = "syslog-host"
HOST = "static-host"
TABLES = frozenset((SYSTEM, NTP, SYSLOG, HOST))
SERVERS = {NTP: "ntp server", SYSLOG: "logging host"}
SOURCES = ("ntp-source", "logging-source")
INTERFACE = r"[A-Za-z][A-Za-z-]*[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?"
DOMAIN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
TRAP = r"(?:emergencies|alerts|critical|errors|warnings|notifications|informational|debugging|disabled)"
ZONE = r"[A-Za-z][A-Za-z0-9+-]{0,6} (?:-?(?:[0-9]|1[0-4]))(?: [0-5]?[0-9])?"
SETTINGS = {
    "ntp-source": ("ntp source", INTERFACE),
    "logging-source": ("logging source-interface", INTERFACE),
    "trap": ("logging trap", TRAP),
    "timezone": ("clock timezone", ZONE),
    "domain-name": ("ip domain name", DOMAIN),
    "name-servers": ("ip name-server", r"[0-9.]+(?: [0-9.]+){0,5}"),
}
READ = ("show running-config | include ^hostname |^clock timezone |^ntp (server|source) "
        "|^logging (host|source-interface|trap)( |$)|^no logging trap$"
        "|^ip domain.name |^ip name-server |^ip host |^end$")


def address(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _match(table, line):
    if table == SYSTEM:
        if line == "no logging trap":
            return "trap", "disabled"
        for name, (command, pattern) in SETTINGS.items():
            if name == "domain-name" and line.startswith("ip domain-name "):
                line = command + line[len("ip domain-name"):]
            if not line.startswith(command + " "):
                continue
            value = line[len(command) + 1:]
            if name == "name-servers" and value.startswith("vrf "):
                continue
            if name == "logging-source" and " vrf " in value:
                continue
            return name, value if re.fullmatch(pattern, value) else None
        if line == "logging trap":
            return "trap", "informational"
        return None

    prefix = SERVERS.get(table, "ip host") + " "
    if not line.startswith(prefix):
        return None
    key, _, options = line[len(prefix):].partition(" ")
    if key == "vrf":
        return None
    if table == HOST:
        return key, {"address": address(options)} if address(options) else None
    if table == NTP and key == "ip":
        key, _, options = options.partition(" ")
    return key, {} if not options and address(key) else None


def _settings(lines, entry):
    resolvers = []
    for number, line in lines:
        found = _match(SYSTEM, line)
        if found is None:
            continue
        name, value = found
        if name == "name-servers" and value and all(address(item) for item in value.split()):
            resolvers.extend(value.split())
        elif value is None or name == "name-servers" or name in entry.attributes:
            entry.unsupported.append(f"unsupported {name} setting at line {number}")
        else:
            entry.attributes[name] = canonical(name, value)
    if resolvers:
        if len(set(resolvers)) != len(resolvers) or len(resolvers) > 6:
            entry.unsupported.append("unsupported global resolver list")
        entry.attributes["name-servers"] = " ".join(resolvers)


def entries(lines, table, entry_type):
    if table == SYSTEM:
        entry = entry_type(SYSTEM)
        _settings(lines, entry)
        return {SYSTEM: entry}

    result = {}
    for number, line in lines:
        found = _match(table, line)
        if found is None:
            continue
        key, attrs = found
        duplicate = key in result
        entry = result.setdefault(key, entry_type(key))
        if attrs is None or duplicate:
            entry.unsupported.append(f"unsupported {table} settings at line {number}")
        else:
            entry.attributes.update(attrs)
    return result


def canonical(name, value):
    if name == "timezone":
        zone, hours, *minutes = value.split()
        return f"{zone} {hours} {int(minutes[0]) if minutes else 0}"
    return value


def changes(values):
    return {name: canonical(name, value) if value is not None else None for name, value in values.items()}


def _servers(before, after):
    old, new = before.split(), after.split()
    shared = 0
    for current, desired in zip(old, new):
        if current != desired:
            break
        shared += 1
    removed, added = old[shared:], new[shared:]
    return (["no ip name-server " + " ".join(removed)] if removed else []) + (
        ["ip name-server " + " ".join(added)] if added else [])


def _command(name, value):
    prefix = SETTINGS[name][0]
    if name == "trap":
        if not value:
            return "default logging trap"
        if value == "disabled":
            return "no logging trap"
    return (f"{prefix} {value}" if value else f"no {prefix}")


def render(table, key, before, after):
    if table in SERVERS:
        if address(key) != key:
            raise Rejected(["server key must be a canonical IPv4 address"])
        command = f"{SERVERS[table]} {key}"
        return [command if after is not None else "no " + command]
    if table == HOST:
        command = "ip host " + key
        if after is None:
            return ["no " + command]
        return (["no " + command] if before is not None else []) + [f"{command} {after['address']}"]

    commands = []
    for name in SETTINGS:
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        if name == "name-servers":
            values = (new or "").split()
            if len(set(values)) != len(values) or any(address(value) != value for value in values):
                raise Rejected(["name-servers needs distinct canonical IPv4 addresses"])
            commands.extend(_servers(old or "", new or ""))
        elif name == "logging-source" and new is None:
            commands.append("no logging source-interface " + old)
        else:
            commands.append(_command(name, new))
    return commands


def sources(before, after):
    return {state[name] for name in SOURCES if before.get(name) != after.get(name)
            for state in (before, after) if name in state}


def prechecks(snapshot, table, before, after, protected, *, impact, undo):
    last_target = (table in SERVERS and after is None and len(snapshot.entries(table)) == 1
                   or table == SYSTEM and before.get("name-servers") and not after.get("name-servers"))
    if last_target and not (impact or undo):
        raise Rejected(["removing the last %s target requires endpoint_impact naming the key"
                        % ("DNS resolver" if table == SYSTEM else table)],
                       reason_codes=["endpoint_impact_required"])
    if snapshot.platform == "iosxe" and not (impact or undo):
        if table in SERVERS and after is None:
            raise Rejected(["removing a configured service target requires endpoint_impact naming the key"],
                           reason_codes=["endpoint_impact_required"])
        if table == SYSTEM:
            removed_resolvers = set(before.get("name-servers", "").split()) - set(after.get("name-servers", "").split())
            ntp_source_changed = before.get("ntp-source") != after.get("ntp-source")
            logging_changed = any(before.get(name) != after.get(name) for name in ("logging-source", "trap"))
            if (removed_resolvers or (ntp_source_changed and snapshot.entries(NTP))
                    or (logging_changed and snapshot.entries(SYSLOG))):
                raise Rejected(["changing a configured service target requires endpoint_impact naming the key"],
                               reason_codes=["endpoint_impact_required"])
    if table != SYSTEM:
        return
    guarded = {name.casefold() for name in (protected or {}).get("interface", ())}
    for source in sorted(sources(before or {}, after or {})):
        name = source.split(".", 1)[0]
        if {source.casefold(), name.casefold()} & guarded:
            raise Rejected(["a service source references a protected interface"], reason_codes=["port_protected"])
        if source not in snapshot.interfaces:
            raise Rejected(["a service source interface is absent"], reason_codes=["port_unsupported_interface"])
        if snapshot.management_vrf(source):
            raise Rejected(["a service source references a management VRF"], reason_codes=["port_management_interface"])


def without_object(snapshot, table, key):
    owned = set()
    for block in snapshot.blocks:
        found = _match(table, block.header)
        if found is not None and (table == SYSTEM or found[0] == key):
            owned.add(block.line)
    return [line for number, line in enumerate(snapshot.source_lines, 1) if number not in owned]


def rest_digest(snapshot, table, key, volatile):
    remaining = (line.rstrip() for line in without_object(snapshot, table, key))
    return hashlib.sha256("\n".join(line for line in remaining
                                     if line.strip() and line != "!" and not line.startswith(volatile)).encode()).hexdigest()


def snapshot_after(snapshot, plan):
    table, key = plan["table"], plan["key"]
    lines = without_object(snapshot, table, key)
    after = plan["predicted"]["after"]
    if after is not None:
        added = render(table, key, {}, after)
        end = max(index for index, line in enumerate(lines) if line.strip() == "end")
        lines[end:end] = added
    return "\n".join(lines)


def observe(access, table, key, entry_type):
    """The privileged readback uses a scoped command, because IOS privilege 1 cannot read configuration."""
    from netops_admin import ios
    from netops_admin.access import AccessError

    try:
        status, text = access.query_status(READ)
    except AccessError as exc:
        reason = "ios_service_read_timeout" if re.search(r"timeout|timed out|within", str(exc), re.I) else "ios_service_read_unreadable"
        raise Rejected(["IOS service configuration read failed"], reason_codes=[reason]) from None
    lines = [line for line in text.splitlines() if line.strip()]
    if (not lines or lines[-1] != "end" or status != 0 or ios.refused(text) or "--More--" in text or "\ufffd" in text
            or sum(bool(re.fullmatch(r"hostname \S+", line)) for line in lines) != 1):
        raise Rejected(["IOS service configuration read is incomplete"], reason_codes=["ios_service_read_unreadable"])
    entry = entries(enumerate(lines, 1), table, entry_type).get(key)
    if entry is None:
        return None
    if entry.unsupported:
        raise Rejected(["IOS service configuration contains unsupported settings"],
                       reason_codes=["ios_service_read_unreadable"])
    return entry.attributes
