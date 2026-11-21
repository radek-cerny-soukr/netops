"""Safe projections of Junos management configuration and the messages log."""

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from xml.etree import ElementTree as ET

from .query_catalog.junos import CONFIG_PATHS, LOG_HISTORY_LINES, log_window


_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,252}")
_SELECTORS = frozenset({
    "any", "authorization", "change-log", "conflict-log", "daemon", "dfc", "external",
    "firewall", "ftp", "interactive-commands", "kernel", "ntp", "pfe", "security", "user",
})
_SEVERITIES = frozenset({
    "any", "none", "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
})


def _address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _text(node, name):
    value = node.find(name)
    return (value.text or "").strip() if value is not None and not len(value) else ""


def config_projection(query, output):
    """Allow only reviewed fields. Never expose the original XML or arbitrary values."""
    if not output.strip():
        return []
    if "<!" in output:
        raise ValueError("invalid Junos XML")
    try:
        root = ET.fromstring(output.strip())
    except ET.ParseError:
        raise ValueError("invalid Junos XML") from None
    if root.tag != "rpc-reply" or root.find("rpc-error") is not None:
        raise ValueError("unrecognized Junos configuration response")
    configuration = root.find("configuration")
    if configuration is None:
        cli = root.find("cli")
        if len(root) == 1 and cli is not None and len(cli) == 1 and cli.find("banner") is not None:
            return []
        raise ValueError("missing Junos configuration response")
    system = configuration.find("system")
    if system is None:
        if len(configuration):
            raise ValueError("unrecognized Junos configuration path")
        return []
    path = CONFIG_PATHS[query]
    if any(node.tag != path for node in system):
        raise ValueError("unrecognized Junos configuration path")
    records = []
    for node in system.findall(path):
        inactive = any(key.endswith("}inactive") or key == "inactive" for key in node.attrib)
        if query == "authentication_order":
            method = (node.text or "").strip()
            if method not in {"password", "radius", "tacplus", "ldap", "saml"} or len(node):
                raise ValueError("unrecognized Junos authentication method")
            records.append({"method": method, "inactive": inactive})
        elif query == "syslog_status":
            records.extend(_syslog_destinations(node, inactive))
        else:
            records.append(_server(node, inactive))
    return records


def _server(node, inactive):
    address = _address(_text(node, "name"))
    if address is None:
        raise ValueError("unrecognized Junos server address")
    record = {"address": address, "inactive": inactive}
    for field in ("port", "accounting-port", "timeout", "retry"):
        value = _text(node, field)
        if re.fullmatch(r"[0-9]{1,5}", value):
            record[field.replace("-", "_")] = int(value)
    source = _address(_text(node, "source-address"))
    if source:
        record["source_address"] = source
    instance = _text(node, "routing-instance")
    if _NAME.fullmatch(instance):
        record["routing_instance"] = instance
    return record


def _syslog_destinations(syslog, inactive):
    for node in syslog:
        if node.tag not in {"host", "file", "console", "user"}:
            continue
        name = _text(node, "name")
        if node.tag != "console" and not (_NAME.fullmatch(name) or node.tag == "user" and name == "*"):
            raise ValueError("unrecognized Junos syslog destination")
        # Junos configuration XML uses <contents><name>facility</name><severity/></contents>.
        selectors = []
        for content in node.findall("contents"):
            facility = _text(content, "name")
            levels = [child.tag for child in content if child.tag in _SEVERITIES]
            if facility not in _SELECTORS or len(levels) != 1:
                raise ValueError("unrecognized Junos syslog selector")
            selectors.append({"facility": facility, "severity": levels[0]})
        yield {"kind": node.tag, "name": name or None, "selectors": selectors,
               "explicit_priority": node.find("explicit-priority") is not None,
               "structured_data": node.find("structured-data") is not None,
               "inactive": inactive or any(key.endswith("}inactive") or key == "inactive" for key in node.attrib)}


_SNMP_PERIODS = {"1 minute", "5 minutes", "15 minutes"}
_SNMP_REQUIRED_COUNTERS = {
    "Input:": {"Packets", "Bad community names", "Bad community uses", "ASN parse errors", "Traps"},
    "V3 Input:": {
        "Unknown security models", "Invalid messages", "Unknown pdu handlers", "Unavailable contexts",
        "Unknown contexts", "Unsupported security levels", "Not in time windows", "Unknown user names",
        "Unknown engine ids", "Wrong digests", "Decryption errors",
    },
    "Output:": {"Packets", "Too bigs", "No such names", "Bad values", "General errors", "Get requests",
                "Get nexts", "Set requests", "Get responses", "Traps"},
    "Performance:": {"Average response time(ms)"},
    "Number of requests dispatched to subagents in last:": _SNMP_PERIODS,
    "Number of responses dispatched to NMS in last:": _SNMP_PERIODS,
}
_SNMP_GROUPS = _SNMP_REQUIRED_COUNTERS.keys() | {"V3 Output:"}
_SNMP_BASE_GROUPS = {"Input:", "V3 Input:", "Output:"}
_SNMP_COUNTERS = {
    "Bad versions", "Read onlys", "Total request varbinds", "Total requests varbinds", "Total set varbinds",
    "Silent drops", "Proxy drops", "Commit pending drops", "Throttle drops", "Duplicate request drops",
}.union(*_SNMP_REQUIRED_COUNTERS.values())


def snmp_counters(text):
    """Project numeric counters and report whether the extended footer was captured."""
    if not text.rstrip(" \t").endswith(("\n", "\r")):
        raise ValueError("unterminated Junos SNMP counter line")
    counts = {}
    group = None
    for line in (line.strip() for line in text.splitlines() if line.strip()):
        if line == "SNMP statistics:" and group is None:
            continue
        if line in _SNMP_GROUPS and line not in counts:
            group = line
            counts[group] = {}
            continue
        if group is None:
            raise ValueError("missing Junos SNMP counter section")
        for counter in line.removesuffix(",").split(","):
            name, _, value = counter.strip().partition(":")
            value = value.strip()
            if name not in _SNMP_COUNTERS or not re.fullmatch(r"[0-9]{1,20}(?:\.[0-9]{1,6})?", value):
                raise ValueError("unrecognized Junos SNMP counter")
            counts[group][name] = float(value) if "." in value else int(value)
    if (not _SNMP_BASE_GROUPS <= counts.keys() or not all(counts.values())
            or any(not _SNMP_REQUIRED_COUNTERS[section] <= counts[section].keys()
                   for section in counts.keys() & _SNMP_REQUIRED_COUNTERS.keys())):
        raise ValueError("incomplete Junos SNMP counters")
    records = [{"section": group.removesuffix(":"),
                "counters": {re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_"): value
                             for name, value in counters.items()}}
               for group, counters in counts.items()]
    return records, _SNMP_REQUIRED_COUNTERS.keys() <= counts.keys()


def session_projection(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    count = re.search(r"\b(\d+) users?,\s+load averages?:", lines[0]) if lines else None
    if not count or len(lines) < 2 or lines[1].split() != ["USER", "TTY", "FROM", "LOGIN@", "IDLE", "WHAT"]:
        raise ValueError("missing Junos user session header")
    if int(count[1]) != len(lines) - 2:
        raise ValueError("Junos user count does not match listing")
    sessions = []
    for line in lines[2:]:
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            raise ValueError("incomplete Junos session")
        login, tty, remote, started, idle = fields[:5]
        sessions.append({"user": login, "tty": tty, "from": remote, "login_at": started, "idle": idle})
    return sessions


def dns_output_complete(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if any(re.fullmatch(r"Host \S+ not found: [0-9]+\([A-Z]+\)", line) for line in lines):
        return len(lines) == 1
    return bool(lines) and all(
        re.fullmatch(r"\S+ (?:has (?:IPv6 )?address|is an alias for|mail is handled by \d+) \S+\.?", line)
        for line in lines
    )


_CLOCK = re.compile(r"(?m)^Current time:\s+(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) ([^\s]+)[ \t]*$")
_MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CLASSIC_HEADER = (
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):"
    r"(?P<second>\d{2})(?:\.(?P<millisecond>\d{3}))?(?:\.(?P<year>\d{4}))?\s+"
    r"(?P<host>[A-Za-z0-9_.-]+)[ \t]+"
)
_CLASSIC = re.compile(
    _CLASSIC_HEADER + r"(?P<process>[A-Za-z0-9_.@/-]+)(?:\[\d+\])?"
    r"(?P<separator>:[ \t]*|[ \t]+)(?P<body>.*)"
)
_CLASSIC_REPEAT = re.compile(_CLASSIC_HEADER + r"last message repeated [1-9][0-9]* times")
_FORWARDING_NODE = re.compile(r"(?:fpc|re)[0-9]{1,4}")
_PRIORITY = re.compile(r"%[A-Z][A-Z0-9_]*-([0-7])(?:-([A-Z][A-Z0-9_]*))?:\s*")
_TAG = re.compile(r"([A-Z][A-Z0-9_]*):\s*")
# RFC 5424 section 6.3: adjacent elements and quoted, escaped parameter values.
_SD_NAME = r"[\x21\x23-\x3c\x3e-\x5c\x5e-\x7e]{1,32}"
_SD_VALUE = r'(?:[^"\\\]]++|\\["\\\]]|\\(?!["\\\]]))*+'
_SD_ELEMENT = rf'\[{_SD_NAME}(?: {_SD_NAME}="{_SD_VALUE}")*+\]'
_STRUCTURED = re.compile(
    r"<(?P<priority>\d{1,3})>1 (?P<time>\d{4}-\d\d-\d\dT\S+) "
    r"(?P<host>[A-Za-z0-9_.-]+) (?P<process>[A-Za-z0-9_.@/-]+) (?:\d+|-) "
    rf"(?P<tag>[A-Z][A-Z0-9_]*|-) (?:-|(?:{_SD_ELEMENT})++)(?: (?P<body>.*))?"
)
_PORT = re.compile(
    r"(?<![A-Za-z0-9_./:-])"
    r"(?:[a-z][a-z0-9]*-\d{1,3}/\d{1,3}/\d{1,3}(?::\d{1,3})?|(?:ae|irb|reth|lo|fxp|em|me)\d{1,5})"
    r"(?:\.\d{1,5})?(?![A-Za-z0-9_/:-]|\.\d)"
)
_SSHD_EVENTS = (
    ("Accepted ", "sshd_authentication_accepted"),
    ("Received disconnect from ", "sshd_disconnect_received"),
    ("Disconnected from ", "sshd_session_disconnected"),
    ("error: PAM: Authentication error", "sshd_pam_authentication_error"),
    ("Connection closed by authenticating user ", "sshd_connection_closed_preauth"),
)
_UNTAGGED_LEVEL = re.compile(r"(error|fatal|warning|notice|info|debug):")
_LOG_REORDER_TOLERANCE = timedelta(seconds=5)


def device_clock(text):
    matches = _CLOCK.findall(text)
    if len(set(matches)) != 1:
        raise ValueError("Junos device clock could not be read")
    date, clock, zone = matches[0]
    return datetime.fromisoformat(date + "T" + clock), zone


def _log_record(line, now, clock_zone):
    match = _STRUCTURED.fullmatch(line)
    if match:
        moment = datetime.fromisoformat(match["time"])
        if int(match["priority"]) > 191 or moment.tzinfo is None:
            raise ValueError("invalid syslog priority or time zone")
        if clock_zone in {"UTC", "GMT"}:
            moment = moment.astimezone(timezone.utc)
        elif moment.utcoffset() == timedelta(0):
            # The UTC representation cannot be mapped to an unknown local offset.
            raise ValueError("Junos clock offset is unavailable")
        body = (match["body"] or "").removeprefix("\ufeff")
        return (moment.replace(tzinfo=None), match["host"], match["process"],
                int(match["priority"]) % 8, match["tag"], body)
    match = _CLASSIC.fullmatch(line)
    repeated = not match or not (match["separator"].startswith(":") or _FORWARDING_NODE.fullmatch(match["process"]))
    if repeated:
        match = _CLASSIC_REPEAT.fullmatch(line)
    if not match or match["month"] not in _MONTHS:
        raise ValueError("unrecognized Junos log line")
    parts = [_MONTHS[match["month"]], *(int(match[name]) for name in ("day", "hour", "minute", "second"))]
    year = int(match["year"]) if match["year"] else now.year
    if not match["year"] and (parts[0], parts[1]) > (now.month, now.day):
        year -= 1
    moment = datetime(year, *parts, int(match["millisecond"] or 0) * 1000)
    if repeated:
        return moment, match["host"], "syslogd", None, "syslog_message_repeated", ""
    body = match["body"]
    priority = _PRIORITY.match(body)
    tag = _TAG.match(body)
    return (moment, match["host"], match["process"], int(priority[1]) if priority else None,
            priority[2] if priority else tag[1] if tag else None, body)


def json_lines(records):
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)


def log_history(text, parameters, clock, clock_zone, *, truncated, date_reference=None, clock_verified=True):
    start, end = log_window(parameters)
    date_reference = date_reference or clock
    lines = [line for line in text.splitlines() if line.strip()]
    unknown = missing_severity = 0
    first = last = None
    in_order = True
    within_tolerance = True
    latest = None
    records = []
    port_filter = parameters.get("interface")
    severity_filter = parameters.get("severity")
    for line in lines:
        try:
            moment, host, process, severity, tag, body = _log_record(line, date_reference, clock_zone)
        except ValueError:
            unknown += 1
            continue
        if last is not None and moment < last:
            in_order = False
        if latest is None or moment > latest:
            latest = moment
        elif latest - moment > _LOG_REORDER_TOLERANCE:
            within_tolerance = False
        first = first or moment
        last = moment
        if not start <= moment < end:
            continue
        ports = sorted(set(_PORT.findall(body)))
        if port_filter and not any(port == port_filter or port.startswith(port_filter + ".") for port in ports):
            continue
        if severity_filter is not None and severity is None:
            missing_severity += 1
            continue
        if severity_filter is not None and severity != int(severity_filter):
            continue
        event = tag if tag != "-" else None
        if event is None and process == "sshd":
            event = next((name for prefix, name in _SSHD_EVENTS if body.startswith(prefix)), None)
        if event is None:
            level = _UNTAGGED_LEVEL.match(body)
            event = f"untagged_{level[1]}" if level else "untagged"
        records.append({"time": moment.isoformat(), "host": host, "process": process, "severity": severity,
                        "event": event, "interfaces": ports})
    # A row omitted before the tail may be newer than its first row by up to the reorder tolerance.
    # The device clock is sampled before messages; later entries may be in the same capture.
    complete = (not truncated and clock_verified and not unknown and not missing_severity and within_tolerance
                and first is not None and start - first > _LOG_REORDER_TOLERANCE and end <= clock)
    return json_lines(records), {
        "source": "messages", "scope": "current_file", "device_time_zone": clock_zone,
        "start": parameters["start"], "end": parameters["end"], "scanned_lines": len(lines),
        "max_lines": LOG_HISTORY_LINES, "matched": len(records), "unparsed_lines": unknown,
        "missing_severity": missing_severity, "chronological": in_order, "complete": complete,
        "first_time": first.isoformat() if first else None, "last_time": last.isoformat() if last else None,
    }
