"""EOS NTP, syslog and DNS configuration and operational state."""
from __future__ import annotations

import ipaddress
import json
import re

from netops_admin.errors import Rejected

NTP = "ntp-server"
SYSLOG = "syslog-host"
DNS = "dns-server"
SYSTEM = "system-services"
TABLES = frozenset({NTP, SYSLOG, DNS, SYSTEM})

DEFAULT_VRF = "default"
VRF = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}"
INTERFACE = r"(?:Ethernet|Loopback|Management|Port-Channel|Vlan)[0-9]+(?:/[0-9]+){0,2}(?:\.[0-9]+)?"
DOMAIN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
FACILITY = r"(?:auth|cron|daemon|kern|local[0-7]|lpr|mail|news|sys(?:9|1[0-4])|syslog|user|uucp)"
SEVERITY = r"(?:emergencies|alerts|critical|errors|warnings|notifications|informational|debugging|disabled)"
SERVER_LINES = {
    NTP: re.compile(rf"^ntp server (?:(?:vrf ({VRF})) )?(\S+)(?: (.*))?$"),
    SYSLOG: re.compile(rf"^logging (?:vrf ({VRF}) )?host (\S+)(?: (.*))?$"),
    DNS: re.compile(rf"^ip name-server (?:vrf ({VRF}) )?(\S+)(?: (.*))?$"),
}
LEGACY_DOMAIN_COMMAND = "ip domain-name "
SYSTEM_LINES = {
    "domain-name": ("dns domain", DOMAIN, None),
    "facility": ("logging facility", FACILITY, "local4"),
    "trap": ("logging trap", SEVERITY, "informational"),
}

SHOW_NTP = "show ntp associations | json"
SHOW_SYSLOG = "show logging"
SHOW_DNS = "show ip name-server | json"
SHOW_HOSTS = "show hosts | json"


def refusal(message, code="eos_service_unsupported"):
    return Rejected([message], reason_codes=[code])


def address(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def server_key(vrf, host):
    host = address(host) or host
    return host if vrf in (None, DEFAULT_VRF) else f"{vrf}/{host}"


def key_parts(key):
    vrf, _, host = key.rpartition("/")
    return vrf or DEFAULT_VRF, host


def _server_options(table, extra):
    if not extra:
        return {}
    if table == NTP and re.fullmatch(rf"source {INTERFACE}", extra):
        return {"source": extra.removeprefix("source ")}
    if table == DNS and re.fullmatch(r"priority (?:[0-9]|1[0-5])", extra):
        return {"priority": extra.removeprefix("priority ")}
    return None


def _server(line, table):
    match = SERVER_LINES[table].fullmatch(line)
    if match:
        vrf, host, extra = match.groups()
        return server_key(vrf, host), _server_options(table, extra)
    return None


def _system(line):
    if line == "no logging trap":
        return "trap", "disabled"
    if line.startswith(LEGACY_DOMAIN_COMMAND):
        domain = line.removeprefix(LEGACY_DOMAIN_COMMAND)
        return "domain-name", domain if re.fullmatch(DOMAIN, domain) else None
    for name, (command, pattern, _default) in SYSTEM_LINES.items():
        if line.startswith(command + " "):
            value = line[len(command) + 1:]
            # 'logging trap system ...' controls a separate buffer and is outside the remote trap level.
            if name == "trap" and value.startswith("system "):
                continue
            return name, value if re.fullmatch(pattern, value) else None
    return None


def entries(snapshot, table, entry_type):
    if table == SYSTEM:
        entry = entry_type(SYSTEM)
        for block in snapshot.blocks:
            setting = _system(block.header)
            if setting is None:
                continue
            name, value = setting
            if value is None or block.children or name in entry.attributes:
                entry.unsupported.append(f"unsupported {name} setting at line {block.line}")
            else:
                entry.attributes[name] = value
        return {SYSTEM: entry}

    result = {}
    for block in snapshot.blocks:
        found = _server(block.header, table)
        if found is None:
            continue
        key, options = found
        duplicate = key in result
        entry = result.setdefault(key, entry_type(key))
        if duplicate or options is None or block.children:
            entry.unsupported.append(f"unsupported {table} options at line {block.line}")
        else:
            entry.attributes.update(options)
    return result


def without_object(lines, table, key):
    for line in lines:
        if table == SYSTEM:
            if _system(line) is not None:
                continue
        else:
            found = _server(line, table)
            if found is not None and found[0] == key:
                continue
        yield line


def _command(table, key):
    vrf, host = key_parts(key)
    scope = "" if vrf == DEFAULT_VRF else f"vrf {vrf} "
    if table == NTP:
        return f"ntp server {scope}{host}"
    if table == SYSLOG:
        return f"logging {scope}host {host}"
    # EOS writes the default VRF explicitly in running-config.
    return f"ip name-server vrf {vrf} {host}"


def _server_line(table, key, state):
    command = _command(table, key)
    if table == NTP and "source" in state:
        return command + " source " + state["source"]
    if table == DNS and "priority" in state:
        return command + " priority " + state["priority"]
    return command


def _system_lines(before, after):
    lines = []
    for name, (command, _pattern, _default) in SYSTEM_LINES.items():
        if before.get(name) == after.get(name):
            continue
        if name not in after:
            lines.append("default " + command)
        elif name == "trap" and after[name] == "disabled":
            lines.append("no logging trap")
        else:
            lines.append(command + " " + after[name])
    return lines


def render(table, key, before, after):
    if table == SYSTEM:
        commands = _system_lines(before, after)
    else:
        commands = [] if before is None else ["no " + _command(table, key)]
        if after is not None:
            commands.append(_server_line(table, key, after))
    return ["configure terminal", *commands, "end"]


def snapshot_after(snapshot, plan):
    table, key = plan["table"], plan["key"]
    state = plan["predicted"]["after"]
    lines = list(without_object(snapshot.lines, table, key))
    end = lines.index("end")
    if table == SYSTEM:
        lines[end:end] = _system_lines({}, state)
    elif state is not None:
        lines[end:end] = [_server_line(table, key, state)]
    return "\n".join(lines)


def prechecks(snapshot, table, key, before, after, impact, *, undo_create=False):
    if table == SYSTEM:
        if before.get("domain-name") != after.get("domain-name") and any(
                block.header.startswith(LEGACY_DOMAIN_COMMAND) for block in snapshot.blocks):
            raise refusal("the domain uses a legacy running-config statement whose exact inverse is unsupported")
        needs_impact = True
    else:
        vrf, host = key_parts(key)
        if address(host) != host or key != server_key(vrf, host):
            raise refusal("use a canonical IP address, optionally preceded by a non-default VRF and '/'")
        vrfs = {block.header.removeprefix("vrf instance ") for block in snapshot.blocks
                if block.header.startswith("vrf instance ")} | {DEFAULT_VRF}
        if vrf not in vrfs:
            raise refusal("the requested VRF is missing from running-config")
        peers = snapshot.entries(table)
        if table == NTP and any(key_parts(peer)[0] != vrf for peer in peers):
            raise refusal("EOS requires every NTP server to use the same VRF")
        source = (after or {}).get("source")
        if source is not None:
            lines = snapshot.interface_lines(source)
            source_vrfs = [line.removeprefix("vrf ") for line in lines if line.startswith("vrf ")]
            if source not in snapshot.interfaces or (source_vrfs or [DEFAULT_VRF]) != [vrf]:
                raise refusal("the NTP source interface must exist in the server VRF")
        needs_impact = before is not None or (table in (NTP, DNS)
                                            and any(key_parts(peer)[0] == vrf for peer in peers))
    if needs_impact and not undo_create and impact != key:
        raise refusal("changing a configured service or its server set requires endpoint_impact naming the request key",
                      "endpoint_impact_required")


def check_view(table, state):
    if table == SYSTEM:
        # The operational CLI shows effective defaults while the snapshot records explicit configuration.
        return {name: state.get(name, default) for name, (_, _, default) in SYSTEM_LINES.items()
                if name in state or default is not None}
    if table == NTP:
        # Associations report the peer address, but do not report the source interface.
        return {}
    return state


def unreadable(command):
    return refusal(f"the EOS check account did not return a complete {command} answer",
                   "eos_service_readback_unreadable")


def json_answer(text, command):
    try:
        value = json.loads(text)
    except ValueError:
        raise unreadable(command) from None
    if not isinstance(value, dict) or "errors" in value:
        raise unreadable(command)
    return value


def ntp_state(text, key):
    peers = json_answer(text, SHOW_NTP).get("peers")
    if not isinstance(peers, dict):
        raise unreadable(SHOW_NTP)
    hosts = set()
    for peer in peers.values():
        host = address(peer.get("peerIpAddr")) if isinstance(peer, dict) else None
        if host is None:
            raise unreadable(SHOW_NTP)
        hosts.add(host)
    return {} if key_parts(key)[1] in hosts else None


def dns_state(text, key):
    answer = json_answer(text, SHOW_DNS)
    rows = answer.get("nameServerConfigs")
    views = (answer.get("v4NameServers"), answer.get("v6NameServers"))
    if not isinstance(rows, list) or not all(isinstance(view, list) for view in views):
        raise unreadable(SHOW_DNS)
    seen, default, configured = {}, [set(), set()], [set(), set()]
    for row in rows:
        if not isinstance(row, dict):
            raise unreadable(SHOW_DNS)
        host, vrf, priority = address(row.get("ipAddr")), row.get("vrf"), row.get("priority")
        if not host or not isinstance(vrf, str) or not re.fullmatch(VRF, vrf) or type(priority) is not int:
            raise unreadable(SHOW_DNS)
        name = server_key(vrf, host)
        if name in seen or not 0 <= priority <= 15:
            raise unreadable(SHOW_DNS)
        seen[name] = {"priority": str(priority)} if priority else {}
        family = int(":" in host)
        configured[family].add(host)
        if vrf == DEFAULT_VRF:
            default[family].add(host)
    for view, default_hosts, all_hosts in zip(views, default, configured):
        projected = {address(host) for host in view}
        if len(projected) != len(view) or not default_hosts <= projected <= all_hosts:
            raise unreadable(SHOW_DNS)
    return seen.get(key)


def logging_state(text):
    header = text.split("\nFacility ", 1)[0]
    trap = re.search(rf"^Trap logging: (?:level ({SEVERITY})|(disabled))\s*$", header, re.M)
    facility = re.search(rf"^Syslog facility: ({FACILITY})\s*$", header, re.M)
    if (not header.startswith("Syslog logging: ") or not trap or not facility
            or not re.search(r"^    inactive:", header, re.M)):
        raise unreadable(SHOW_SYSLOG)
    seen = {}
    for line in header.splitlines():
        if not line.lstrip().startswith("Logging to"):
            continue
        found = re.fullmatch(rf"\s+Logging to '(\S+)' port ([0-9]+) in VRF ({VRF}) via (udp|tcp|tls)", line)
        if not found:
            raise unreadable(SHOW_SYSLOG)
        host, port, vrf, protocol = found.groups()
        seen.setdefault(server_key(vrf, host), []).append((port, protocol))
    return {"trap": trap[1] or trap[2], "facility": facility[1]}, seen


def domain_state(text):
    domain = json_answer(text, SHOW_HOSTS).get("domainName")
    if not isinstance(domain, str) or (domain and not re.fullmatch(DOMAIN, domain)):
        raise unreadable(SHOW_HOSTS)
    return {"domain-name": domain} if domain else {}


def observe(access, table, key):
    from netops_admin.access import AccessError

    def read(command):
        try:
            status, text = access.check_query_status(command)
        except AccessError as exc:
            message = str(exc).lower()
            if any(marker in message for marker in ("timeout", "timed out", "did not finish within")):
                raise refusal("the EOS check account read timed out", "eos_service_read_timeout") from None
            raise unreadable(command) from None
        if status != 0:
            raise unreadable(command)
        return text

    if table == NTP:
        return ntp_state(read(SHOW_NTP), key)
    if table == DNS:
        return dns_state(read(SHOW_DNS), key)
    settings, destinations = logging_state(read(SHOW_SYSLOG))
    if table == SYSTEM:
        settings.update(domain_state(read(SHOW_HOSTS)))
        return settings
    target = destinations.get(key)
    if target is None:
        return None
    if target != [("514", "udp")]:
        raise unreadable(SHOW_SYSLOG)
    return {}
