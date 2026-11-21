"""Profiles and independent operational readback for ExtremeXOS management services."""

import hashlib
import ipaddress
import re

from netops_admin import membership
from netops_admin.errors import Rejected

NTP_SERVER = "ntp-server"
NTP = "ntp"
SNTP = "sntp-server"
SYSLOG = "syslog-target"
DNS = "dns-server"
SUFFIX = "dns-suffix"
NAME = "system-name"
TABLES = (NTP_SERVER, NTP, SNTP, SYSLOG, DNS, SUFFIX, NAME)
MODULES = {NTP_SERVER: "ntp", NTP: "ntp", SNTP: "netTools", SYSLOG: "ems",
           DNS: "netTools", SUFFIX: "netTools", NAME: "devmgr"}
VERSIONS = ("33.6.1.14", "33.7.1.6")
VR = r"[A-Za-z][A-Za-z0-9_-]{0,31}"
LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST = rf"{LABEL}(?:\.{LABEL})*"
SYSTEM_NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
FACILITY = r"local[0-7]"
SEVERITIES = ("critical", "error", "warning", "notice", "info", "debug-summary", "debug-verbose", "debug-data")
SYSLOG_FORMAT = ("format timestamp seconds date Mmm-dd event-name none priority host-name tag-name").split()
DEFAULT_SEVERITY = "debug-data"
DEFAULT_VR = "VR-Default"


def refuse(message, code="exos_service_scope"):
    raise Rejected([message], reason_codes=[code])


def unreadable(table):
    refuse("The ExtremeXOS operational output for %s is incomplete or unsupported" % table,
           "exos_service_readback_unreadable")


def _ip(value):
    if "%" in value:
        raise ValueError("scoped address")
    addr = ipaddress.ip_address(value)
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError("non-unicast address")
    return str(addr)


def _server(value):
    try:
        return _ip(value)
    except ValueError:
        if re.fullmatch(HOST, value) and not re.fullmatch(r"[0-9.]+", value) and len(value) <= 253:
            return value
        refuse("The SNTP server must be a unicast address or DNS hostname")


def _key_parts(table, key):
    if table == SYSLOG:
        vr, address, port, facility = key.split("/")
        return vr, _ip(address), str(int(port)), facility
    vr, address = key.split("/")
    return vr, _ip(address)


def _syslog_key(target, vr, facility):
    if target.startswith("["):
        match = re.fullmatch(r"\[(.+)\]:(\d+)", target)
        if match is None:
            raise ValueError("invalid syslog destination")
        address, port = match.groups()
    else:
        address, port = target.rsplit(":", 1)
    return "%s/%s/%d/%s" % (vr, _ip(address), int(port), facility)


def _with_vr(tokens):
    if len(tokens) >= 2 and tokens[-2].casefold() == "vr":
        return tokens[:-2], tokens[-1]
    return tokens, DEFAULT_VR


def line(table, command):
    """Return the managed key, attribute and value represented by a configuration line."""
    tokens = command.tokens
    lower = tuple(token.casefold() for token in tokens)
    if table == NTP_SERVER and lower[:4] == ("configure", "ntp", "server", "add"):
        values, vr = _with_vr(tokens[4:])
        if not values:
            raise ValueError("missing NTP server")
        try:
            address = _ip(values[0])
        except ValueError:
            address = values[0]
        return f"{vr}/{address}", None, len(values) == 1
    if table == NTP and lower in (("enable", "ntp"), ("disable", "ntp")):
        return DEFAULT_VR, "admin-state", lower[0] + "d"
    if table == NTP and lower[0:1] in (("enable",), ("disable",)) and lower[1:3] == ("ntp", "vr") and len(tokens) == 4:
        return tokens[3], "admin-state", lower[0] + "d"
    if table == SNTP and lower[:2] == ("configure", "sntp-client") and lower[2:3] in (("primary",), ("secondary",)):
        values, vr = _with_vr(tokens[3:])
        if len(values) != 1:
            raise ValueError("invalid SNTP server")
        return lower[2], "server", (_server(values[0]), vr)
    if table == DNS and lower[:4] == ("configure", "dns-client", "add", "name-server"):
        values, vr = _with_vr(tokens[4:])
        if len(values) != 1:
            raise ValueError("invalid DNS resolver")
        return f"{vr}/{_ip(values[0])}", None, True
    if table == SUFFIX and lower[:4] == ("configure", "dns-client", "add", "domain-suffix") and len(tokens) == 5:
        return tokens[4], None, True
    if table == NAME and lower[:3] == ("configure", "snmp", "sysname") and len(tokens) == 4:
        return NAME, "sysname", tokens[3]
    if table == SYSLOG:
        return _syslog_line(tokens, lower)
    return None


def _syslog_line(tokens, lower):
    if lower[:3] == ("configure", "syslog", "add"):
        start, kind = 3, "add"
    elif lower[:4] == ("configure", "log", "target", "syslog"):
        start, kind = 4, "config"
    elif lower[:1] in (("enable",), ("disable",)) and lower[1:4] == ("log", "target", "syslog"):
        start, kind = 4, lower[0]
    else:
        return None
    target = tokens[start]
    rest = tokens[start + 1:]
    vr = DEFAULT_VR
    if rest[:1] == ("vr",) and len(rest) >= 2:
        vr, rest = rest[1], rest[2:]
    if not rest or not re.fullmatch(FACILITY, rest[0]):
        raise ValueError("unqualified syslog target")
    key = _syslog_key(target, vr, rest[0])
    opts = list(rest[1:])
    if kind == "add":
        return key, None, not opts
    if kind in ("enable", "disable"):
        return key, "enabled", "yes" if kind == "enable" and not opts else "no" if not opts else None
    if opts[:2] == ["filter", "DefaultFilter"]:
        opts = opts[2:]
    if len(opts) in (2, 3) and opts[0] == "severity" and opts[1].lower() in SEVERITIES:
        if len(opts) == 2 or opts[2] == "only":
            return key, "severity", opts[1].lower() + ("-only" if len(opts) == 3 else "")
    return key, None, opts in (SYSLOG_FORMAT, ["match", "Any"])


def entries(snapshot, table, entry_type):
    if MODULES[table] not in snapshot.configuration.modules:
        refuse("The ExtremeXOS snapshot is missing the management service module")
    found = {}
    for command in snapshot.commands:
        if command.module != MODULES[table] or command.upm_profile:
            continue
        try:
            item = line(table, command)
        except (ValueError, IndexError):
            refuse("The ExtremeXOS snapshot holds an unrecognised management service line")
        if item is None:
            continue
        key, attribute, value = item
        entry = found.setdefault(key, entry_type(key))
        if (attribute is None and value is not True) or (attribute is not None and value is None):
            entry.unsupported.append("line %d: options outside the profile" % command.line)
        elif attribute is not None:
            if attribute in entry.attributes:
                entry.unsupported.append("line %d: duplicate option" % command.line)
            if table == SNTP:
                entry.attributes["server"], entry.attributes["vr"] = value
            else:
                entry.attributes[attribute] = value
    return found


def owned(table, key, command):
    if command.module != MODULES[table] or command.upm_profile:
        return False
    try:
        item = line(table, command)
    except (ValueError, IndexError):
        return False
    return item is not None and item[0] == key


def rest_digest(table, key, commands):
    kept = "\n".join(command.text for command in commands if not owned(table, key, command))
    return hashlib.sha256(kept.encode()).hexdigest()


def validate(snapshot, table, key, before, after, *, impact, undo):
    entries_by_key = snapshot.entries(table)
    vr = None
    if table in (NTP_SERVER, DNS, SYSLOG):
        try:
            parts = _key_parts(table, key)
            vr = parts[0]
            if "/".join(parts) != key or (table == SYSLOG and not 1 <= int(parts[2]) <= 65535):
                raise ValueError("noncanonical key")
        except ValueError:
            refuse("Use the canonical IP, VR and, for syslog, UDP port and facility in the key")
        if table == NTP_SERVER and any(other != key and other.split("/")[1] == parts[1]
                                       for other in entries_by_key):
            refuse("ExtremeXOS deletes an NTP server by address, which must be unique across VRs")
    elif table == NTP:
        vr = key
        if after and any(command.tokens == ("enable", "sntp-client") for command in snapshot.commands):
            refuse("Disable the active SNTP client separately before enabling NTP")
    elif table == SNTP:
        if not before or not after:
            refuse("An existing SNTP slot with a restorable server and VR is required")
        _server(after["server"])
        _server(before["server"])
        vr = after["vr"]
    elif table == SUFFIX and not re.fullmatch(HOST, key):
        refuse("The DNS suffix must be a valid domain")
    elif table == NAME and not all(re.fullmatch(SYSTEM_NAME, (state or {}).get("sysname", "")) for state in (before, after)):
        refuse("Both the current and requested system names must be usable ExtremeXOS prompt names")

    if vr is not None:
        from netops_admin.exos import virtual_routers
        if vr not in virtual_routers(snapshot):
            refuse("The requested VR is not present in the ExtremeXOS configuration")
    if before is not None and after is None and table in (DNS, SUFFIX) and key != next(reversed(entries_by_key)):
        refuse("ExtremeXOS appends restored DNS entries. Remove the last configured entry to preserve order on undo")

    last = table in (NTP_SERVER, DNS) and after is None and sum(
        configured.startswith(vr + "/") for configured in entries_by_key) == 1
    syslog_interruption = table == SYSLOG and before is not None and (
        after is None or (before.get("enabled") == "yes" and after.get("enabled") != "yes"))
    ntp_disabled = table == NTP and before and not after
    if (last or syslog_interruption or ntp_disabled or table in (SNTP, NAME)) and not (impact or undo):
        refuse("Approve endpoint_impact naming this management service before changing it", "exos_service_impact_required")


def _syslog_cli(key):
    vr, address, port, facility = _key_parts(SYSLOG, key)
    return f"{address} udp-port {port} vr {vr} {facility}"


def render(table, key, before, after):
    if table in (NTP_SERVER, DNS):
        vr, address = _key_parts(table, key)
        if table == DNS:
            return [f"configure dns-client {'add' if after is not None else 'delete'} name-server {address} vr {vr}"]
        return [f"configure ntp server add {address} vr {vr}" if after is not None
                else f"configure ntp server delete {address}"]
    if table == SUFFIX:
        return [f"configure dns-client {'add' if after is not None else 'delete'} domain-suffix {key}"]
    if table == NTP:
        return [f"{'enable' if after else 'disable'} ntp vr {key}"]
    if table == SNTP:
        return [f"configure sntp-client {key} {after['server']} vr {after['vr']}"]
    if table == NAME:
        return [f'configure snmp sysName "{after["sysname"]}"']
    target = _syslog_cli(key)
    if after is None:
        return [f"configure syslog delete {target}"]
    commands = [f"configure syslog add {target}"] if before is None else []
    old, new = before or {}, after
    severity = new.get("severity", DEFAULT_SEVERITY)
    if severity != old.get("severity", DEFAULT_SEVERITY):
        base, only = (severity[:-5], " only") if severity.endswith("-only") else (severity, "")
        commands.append(f"configure log target syslog {target} severity {base}{only}")
    if old.get("enabled", "no") != new.get("enabled", "no"):
        verb = "enable" if new.get("enabled") == "yes" else "disable"
        commands.append(f"{verb} log target syslog {target}")
    return commands


def prediction(snapshot, table, key, state):
    kept = [command for command in snapshot.commands if not owned(table, key, command)]
    lines = [] if state is None or (table == NTP and not state) else render(table, key, None, state)
    return "\n".join(membership.modular(snapshot, kept, lines, module=MODULES[table])) + "\n"


def _rows(text):
    return [line.strip() for line in text.splitlines() if line.strip()]


def _ntp_state(text, table, key):
    rows = _rows(text)
    if table == NTP:
        if (len(rows) != 4 or any(not row.startswith(label) for row, label in zip(
                rows, ("NTP ", "Authentication ", "Broadcast-Client ", "VR ")))
                or rows[-1].split(":", 1)[-1].strip() != key):
            unreadable(table)
        mode = rows[0].split(":", 1)[-1].strip().lower()
        if mode not in ("enabled", "disabled"):
            unreadable(table)
        return {"admin-state": mode}
    if (len(rows) < 3 or rows[0].split() != ["VR", "Name", "Name", "IP", "Address", "Type", "Flags", "Key", "Ver"]
            or not re.fullmatch(r"={12,}", rows[1]) or not rows[-1].startswith("Flags:")):
        unreadable(table)
    found = False
    for row in rows[2:-1]:
        cells = row.split()
        if len(cells) != 7 or cells[3] not in ("Server", "Peer"):
            unreadable(table)
        vr, name = cells[:2]
        try:
            name = _ip(name)
        except ValueError:
            pass
        if f"{vr}/{name}" == key and cells[3] == "Server":
            if found:
                unreadable(table)
            found = True
    return {} if found else None


def _dns_state(text, table, key):
    rows = iter(_rows(text))
    for kind, label, expected in (("suffixes", "Domain Suffix", SUFFIX), ("servers", "Name Server", DNS)):
        header = re.fullmatch(r"Number of domain " + kind + r": (\d{1,2})", next(rows, ""))
        if header is None:
            unreadable(table)
        keys = []
        for index in range(int(header[1])):
            row = re.fullmatch(rf"{label} {index}:\s+(\S+)(?:\s+({VR}))?(?:\s+(\(DHCP\)))?", next(rows, ""))
            if row is None or (expected == DNS) != bool(row[2]):
                unreadable(table)
            if not row[3]:
                keys.append(row[1] if expected == SUFFIX else f"{row[2]}/{_ip(row[1])}")
        if expected == table:
            found = keys.count(key)
            if found > 1:
                unreadable(table)
    if next(rows, None) is not None:
        unreadable(table)
    return {} if found else None


def _syslog_state(text, key):
    rows = _rows(text)
    if len(rows) % 7:
        unreadable(SYSLOG)
    seen = {}
    for index in range(0, len(rows), 7):
        target, enabled, filt, match, severity, fmt, port_type = rows[index:index + 7]
        name = re.fullmatch(rf"Log Target\s*:\s*syslog; (\S+) \(vr ({VR})\), ({FACILITY})", target)
        enabled = re.fullmatch(r"Enabled\s*:\s*(yes|no)", enabled)
        severity = re.fullmatch(r"Severity\s*:\s*([\w-]+) \((through Critical|only)\)", severity, re.I)
        if (name is None or enabled is None or severity is None or not filt.startswith("Filter Name")
                or not match.startswith("Match regex") or not fmt.startswith("Format")
                or not port_type.startswith("Port Type")):
            unreadable(SYSLOG)
        identity = _syslog_key(*name.groups())
        if identity in seen:
            unreadable(SYSLOG)
        if not re.fullmatch(r"Port Type\s*:\s*UDP", port_type):
            if identity == key:
                unreadable(SYSLOG)
            continue
        seen[identity] = {"enabled": enabled[1], "severity": severity[1].lower() +
                          ("-only" if severity[2].lower() == "only" else "")}
    return seen.get(key)


def _sntp_state(text, key):
    rows = _rows(text)
    if (len(rows) < 4 or not re.fullmatch(r"SNTP client is (enabled|disabled)", rows[0])
            or rows[-3] != "Replies not received to requests:"
            or not re.fullmatch(r"from Primary server:\s+\d+", rows[-2])
            or not re.fullmatch(r"from Secondary server:\s+\d+", rows[-1])):
        unreadable(SNTP)
    matches = [row for row in rows if row.startswith(key.title() + " server:")]
    if len(matches) != 1:
        unreadable(SNTP)
    value = matches[0].partition(":")[2].split()
    if not value:
        return None
    if len(value) != 2 or not re.fullmatch(VR, value[1]):
        unreadable(SNTP)
    return {"server": _server(value[0]), "vr": value[1]}


def observe(access, table, key):
    from netops_admin import exos
    from netops_admin.access import AccessError
    command = {NTP_SERVER: "show ntp server", NTP: "show ntp vr " + key, SNTP: "show sntp-client",
               SYSLOG: "show log configuration target syslog", DNS: "show dns-client",
               SUFFIX: "show dns-client", NAME: "show switch"}[table]
    try:
        status, text = access.check_query_status(command)
    except AccessError as exc:
        if "timeout" in str(exc).casefold() or "timed out" in str(exc).casefold():
            refuse("ExtremeXOS operational read timed out", "exos_service_read_timeout")
        unreadable(table)
    if status or exos.cli_error(text) is not None:
        unreadable(table)
    try:
        if table in (NTP, NTP_SERVER):
            return _ntp_state(text, table, key)
        if table in (DNS, SUFFIX):
            return _dns_state(text, table, key)
        if table == SYSLOG:
            return _syslog_state(text, key)
        if table == SNTP:
            return _sntp_state(text, key)
        names = exos.SYSNAME.findall(text)
        if len(names) != 1 or not re.fullmatch(SYSTEM_NAME, names[0]):
            unreadable(table)
        return {"sysname": names[0]}
    except (ValueError, IndexError):
        unreadable(table)
