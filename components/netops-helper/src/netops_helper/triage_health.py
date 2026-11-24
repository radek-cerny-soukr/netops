from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

from .query_catalog.arista import LOG_WINDOW_QUERIES as EOS_LOG_WINDOW_QUERIES
from .query_catalog.extreme import LOG_SEVERITIES as EXOS_LOG_SEVERITIES
from .sanitize import EXOS_LOG_EMPTY, EXOS_LOG_ENTRY, EXOS_LOG_TOTAL

# Tested identities of triage_health and triage_vpn (startup, decision of 2026-11-17): not a gate. On another model or
# build the triage runs with firmware_support "untested" and a warning; a reply of an unknown shape is reported as
# unparsed or missing (verdict incomplete), as on a tested identity.
IDENTITIES = frozenset({
    ("FortiGate-60F", "7.6.8", "3744"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
STEPS = (
    ("identity", "system_status"),
    ("resources", "conserve_state"),
    ("resources", "performance"),
    ("sessions", "session_stats"),
    ("ha", "ha_status"),
    ("ha", "ha_checksum"),
    ("ntp", "ntp_status"),
    ("updates", "autoupdate_versions"),
    ("links", "physical_interfaces"),
    ("links", "sdwan_health"),
)
PLANNED_READS = len(STEPS)
REQUIRED = frozenset({"system_status", "conserve_state", "performance", "session_stats", "ha_status",
                      "ntp_status", "autoupdate_versions", "physical_interfaces"})
REASONS = frozenset({"timeout", "truncated", "empty", "unsupported", "permission_denied",
                     "device_cli_error", "transport_error", "unparsed", "not_applicable", "vdom_unverified",
                     "vdom_membership_unverified", "vdom_admin_global_scope_unavailable"})
VERDICTS = frozenset({"fault_found", "no_fault_in_checked_data", "incomplete"})

EXTENDER_MODEM_QUERY = "extender_modem_status"
_MODEM_SIGNAL_FIELDS = frozenset({"signal_strength", "rssi", "signal_rsrq", "signal_rsrp",
                                  "lte_sinr", "lte_rssi", "current_snr", "wireless_signal"})
_MODEM_OTHER_FIELDS = frozenset({
    "physical_port", "manufacture", "product", "model", "revision", "pin_status", "service",
    "profile", "nai", "home_addr", "primary_ha", "secondary_ha", "aaa_spi", "ha_spi", "activation_status",
    "roaming_status", "usim_status", "oma_dm_version", "plmn", "lte_rs_throughput", "lte_ts_throughput",
    "lte_physical_cellid", "modem_type", "drc_cdma_evdo", "wireless_operator", "operating_mode",
    "profile 1", "profile 2", "profile 13", "profile 15",
})


def fortiextender_modem_status(output):
    """Project documented modem fields before any device text is cached or returned."""
    modems = {}
    started, ended = set(), set()
    current = 0
    identifiers_redacted = False
    incomplete = False
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if heading := re.fullmatch(r"Modem ([01]):", line):
            current = int(heading[1])
            incomplete |= current in modems
            modems.setdefault(current, {})
            continue
        label, separator, value = line.partition(":")
        label, value = label.strip().lower(), value.strip()
        identifier = re.sub(r"[^a-z0-9]", "", label)
        if separator and any(word in identifier for word in ("imei", "iccid", "imsi", "phone", "msisdn")):
            identifiers_redacted = True
            continue
        fields = modems.setdefault(current, {})
        if not separator or current in ended:
            incomplete = True
        elif label == "usb_wan_mac":
            if re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
                ended.add(current)
            else:
                incomplete = True
        elif label in _MODEM_OTHER_FIELDS:
            if label == "physical_port":
                incomplete |= current in started or not value
                started.add(current)
        elif label in fields:
            incomplete = True
        elif label in _MODEM_SIGNAL_FIELDS:
            if value == "N/A":
                fields[label] = None
            elif match := re.fullmatch(r"([+-]?[0-9]{1,3}(?:\.[0-9]{1,2})?)(?: (dB[mM]?))?", value):
                fields[label] = {"value": float(match[1]) if "." in match[1] else int(match[1]), "unit": match[2]}
            else:
                incomplete = True
        elif label == "connection_status" and value.lower() in {"connected", "disconnected"}:
            fields[label] = value.lower()
        elif label == "band" and (value == "N/A" or re.fullmatch(r"[BbNn][0-9]{1,3}", value)):
            fields[label] = None if value == "N/A" else value.upper()
        else:
            incomplete = True
    complete = (not incomplete and bool(modems) and set(modems) == started == ended
                and all({"connection_status", "signal_strength", "rssi"} <= fields.keys() for fields in modems.values()))
    return {
        "status": "ok" if complete else "incomplete",
        "complete": complete,
        "identifiers_redacted": identifiers_redacted,
        "modems": [{"index": index, **fields} for index, fields in sorted(modems.items()) if fields],
    }


def missing_read(step, answer, reasons=REASONS):
    """The missing entry of a failed read; a transport failure and a read refused to a per-VDOM administrator
    keep their class and fixed advice."""
    reason = answer.get("reason") if isinstance(answer, dict) else None
    item = {"step": step, "reason": reason if reason in reasons else "device_cli_error"}
    if reason in ("timeout", "transport_error", "vdom_admin_global_scope_unavailable") and \
            isinstance(answer.get("error_code"), str):
        item.update(error_code=answer["error_code"], error=answer.get("error"))
    return item


class UnsupportedPlatform(ValueError):
    pass


def vdom_scope(text):
    """The VDOM scope the status names: vdom_mode and vdom; an unverified status gives vdom None.

    A status without exactly one VDOM mode and current VDOM line is unverified (never taken for no-VDOM).
    """
    from .fortios_vdom import VdomRefused, scope
    try:
        return scope(text)
    except VdomRefused as refused:
        return refused.scope or {"vdom_mode": "unverified", "vdom": None}


def in_vdom(found, answer):
    """A read counts only for a verified scope; in multi-VDOM only when read in the session VDOM context."""
    if found is None or found.get("vdom") is None:
        return False
    return found["vdom_mode"] == "disable" or answer.get("vdom") == found["vdom"]


def vdom_fields(found):
    """Additive result fields: the VDOM mode and the VDOM the checked data belongs to (null when not known)."""
    return {"vdom_mode": found["vdom_mode"] if found else None, "vdom": found["vdom"] if found else None}


def multi_vdom(found):
    return bool(found) and found.get("vdom_mode") == "multiple" and found.get("vdom") is not None


def ports_of_vdom(ports, answer, vdom):
    """The physical ports of one VDOM and the count of the others, owners from `show system interface`.

    Measured (verification): `get system interface physical` lists the ports of every VDOM in any VDOM context.
    The engine reads `show system interface` (set vdom) in the same context and passes `interface_vdoms`;
    without it, or for a port it does not name, None (the ports are not assigned to the VDOM).
    """
    owners = answer.get("interface_vdoms")
    if not isinstance(owners, dict) or any(port["name"] not in owners for port in ports):
        return None
    kept = [port for port in ports if owners[port["name"]] == vdom]
    return kept, len(ports) - len(kept)


class Unparsed(ValueError):
    pass


def _junos_alarms(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines == ["No alarms currently active"]:
        return []
    count = re.fullmatch(r"(\d+) alarms? currently active", lines[0]) if lines else None
    if (not count or len(lines) < 2 or lines[1].split() != ["Alarm", "time", "Class", "Description"]
            or len(lines) - 2 != int(count[1])):
        raise Unparsed()
    alarms = []
    for line in lines[2:]:
        item = re.fullmatch(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+)\s+(\w+)\s+(.+)", line)
        if not item:
            raise Unparsed()
        alarms.append({"time": item[1], "class": item[2], "description": item[3].strip('"')})
    return alarms


def _junos_routing_engine(text):
    engines = []
    for block in re.split(r"(?m)^Routing Engine status:[ \t]*$", text)[1:]:
        for slot in re.split(r"(?m)(?=^[ \t]+Slot \d+:)", block):
            if not slot.strip():
                continue
            position = re.search(r"(?m)^[ \t]*Slot (\d+):", slot)
            memory = int(_once(r"^[ \t]*Memory utilization[ \t]+(\d{1,3}) percent[ \t]*$", slot))
            cpu = re.search(
                r"(?m)^[ \t]*(5 min CPU utilization|CPU utilization):[ \t]*\n"
                r"(?:[ \t]+\w+[ \t]+\d{1,3} percent[ \t]*\n)*?"
                r"[ \t]+Idle[ \t]+(\d{1,3}) percent[ \t]*$", slot,
            )
            if not cpu or memory > 100 or int(cpu[2]) > 100:
                raise Unparsed()
            engines.append({"slot": int(position[1]) if position else None, "memory_used_percent": memory,
                            "cpu_used_percent": 100 - int(cpu[2]),
                            "cpu_sample": "5_minutes" if cpu[1].startswith("5 min") else "reported"})
    if not engines:
        raise Unparsed()
    return engines


def _junos_environment(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or lines[0].split() != ["Class", "Item", "Status", "Measurement"]:
        raise Unparsed()
    rows = []
    for line in lines[1:]:
        columns = re.split(r"[ \t]{2,}", line, maxsplit=2)
        if len(columns) < 2 or columns[1].lower() not in {
            "ok", "testing", "failed", "check", "abnormal", "alarm", "absent", "present", "offline", "online",
        }:
            raise Unparsed()
        rows.append({"item": columns[0], "status": columns[1].lower(),
                     "measurement": columns[2] if len(columns) == 3 else None})
    return rows


def _junos_ntp(text):
    state = _once(r"^associd=0 status=[0-9a-fA-F]{4} \w+, (sync_\w+),", text)
    stratum = int(_once(r"\bstratum=(\d{1,2}),", text))
    if stratum > 16:
        raise Unparsed()
    return {"synchronized": state not in {"sync_unspec", "sync_alarm"} and 1 <= stratum < 16,
            "stratum": stratum, "source": state}


def junos_checks(profile, tool, read, clock, parsers, parameters=None):
    """Read enrolled Junos facts and keep each observed result when another step fails."""
    from netops_core import tested
    from . import normalization
    from .query_catalog.junos import TESTED_G134

    identity = read("version", None)
    if not identity.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the Junos identity read failed")
    try:
        ident = normalization.parse_identity(profile, identity["text"])
    except normalization.IdentityError:
        raise UnsupportedPlatform("config_platform_not_supported: Junos identity could not be read") from None
    support = tested.support("Junos", ident["os_version"], TESTED_G134, model=ident["model"], function=tool)
    sources = {"version": {"query": "version", "content_sha256": identity["content_sha256"], "captured_at": _utc(clock())}}
    missing = []
    parsed = {}
    for query, parser in parsers.items():
        moment = clock()
        answer = read(query, (parameters or {}).get(query))
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
            continue
        sources[query] = {"query": query, "content_sha256": answer["content_sha256"], "captured_at": _utc(moment)}
        try:
            parsed[query] = parser(answer["text"])
        except (Unparsed, ValueError):
            missing.append({"step": query, "reason": "empty" if not answer["text"].strip() else "unparsed"})
    result = {"ok": True, "platform": profile, "identity": ident, "checked": ["version", *parsed],
              "missing": missing, "sources": sources, **firmware_fields(support)}
    return result, parsed


def junos_verdict(result, findings):
    result["findings"] = findings
    result["verdict"] = ("incomplete" if result["missing"] else
                         "fault_found" if findings else "no_fault_in_checked_data")
    return result


def run_junos(profile, read, clock):
    result, parsed = junos_checks(profile, "triage_health", read, clock, {
        "routing_engine": _junos_routing_engine, "environment": _junos_environment,
        "system_alarms": _junos_alarms, "chassis_alarms": _junos_alarms, "ntp_status": _junos_ntp,
    })
    result["chain"] = parsed
    findings = []

    def add(rule, query, fact):
        findings.append({"rule": rule, "fact": fact, "sources": [result["sources"][query]]})

    for query in ("system_alarms", "chassis_alarms"):
        for alarm in parsed.get(query, ()):
            add("active_alarm", query, alarm)
    for engine in parsed.get("routing_engine", ()):
        if engine["memory_used_percent"] >= 90:
            add("high_memory_utilization", "routing_engine", engine)
        if engine["cpu_sample"] == "5_minutes" and engine["cpu_used_percent"] >= 90:
            add("high_cpu_utilization", "routing_engine", engine)
    for item in parsed.get("environment", ()):
        if item["status"] in {"failed", "check", "abnormal", "alarm"}:
            add("environment_fault", "environment", item)
    if "ntp_status" in parsed and not parsed["ntp_status"]["synchronized"]:
        add("ntp_not_synchronized", "ntp_status", parsed["ntp_status"])
    return junos_verdict(result, findings)


def _once(pattern, text):
    found = re.findall(pattern, text, re.M)
    if len(found) != 1:
        raise Unparsed()
    return found[0]


def _lines(text):
    return [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]


def identity(text):
    """The FortiOS identity of the status read; only an unreadable identity or another product is refused."""
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    from .fortios_diagnostics import well_formed
    if not well_formed(found):
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required")
    if not found[0].startswith(platforms.PRODUCT_HARDWARE["fortios"]):
        raise UnsupportedPlatform("config_platform_not_supported: the target is not a FortiOS product")
    return {"product": found[0], "version": found[1], "build": found[2]}


def firmware_support(ident, tested, function):
    """firmware_support of a triage identity against its tested identities (netops_core.tested; never a refusal)."""
    from .fortios_diagnostics import fortios_support
    return fortios_support((ident["product"], ident["version"], ident["build"]), tested, function)


def firmware_fields(support):
    """firmware_support and, outside the tested versions, one warnings[] item (code firmware_untested)."""
    from netops_core import tested
    warning = tested.warning(support)
    return {"firmware_support": support, **({"warnings": [warning]} if warning else {})}


_CONSERVE = {
    "mode": r"^memory conserve mode:\s+(on|off)\s*$",
    "used": r"^memory used:\s+\d+ MB\s+(\d+)% of total RAM\s*$",
    "freeable": r"^memory freeable:\s+\d+ MB\s+(\d+)% of total RAM\s*$",
    "extreme": r"^memory used \+ freeable threshold extreme:\s+\d+ MB\s+(\d+)% of total RAM\s*$",
    "red": r"^memory used threshold red:\s+\d+ MB\s+(\d+)% of total RAM\s*$",
    "green": r"^memory used threshold green:\s+\d+ MB\s+(\d+)% of total RAM\s*$",
}
_CONSERVE_OTHER = re.compile(r"^total RAM:\s+\d+ MB\s*$")


def conserve(text):
    values = {name: _once(pattern, text) for name, pattern in _CONSERVE.items()}
    known = [re.compile(p) for p in _CONSERVE.values()] + [_CONSERVE_OTHER]
    for line in _lines(text):
        if line.strip() and not any(p.match(line) for p in known):
            raise Unparsed()
    result = {"memory_conserve_mode": values["mode"]}
    for name in ("used", "freeable", "extreme", "red", "green"):
        result[name + "_percent"] = int(values[name])
    return result


def performance(text):
    cpu = _once(r"^CPU states:\s+\d+% user\s+\d+% system\s+\d+% nice\s+(\d+)% idle\b", text)
    memory = _once(r"^Memory:\s+\d+k total,\s+\d+k used \(([\d.]+)%\)", text)
    return {"cpu_idle_percent": int(cpu), "memory_used_percent": float(memory)}


def session_stats(text):
    result = {}
    for name in ("session_count", "setup_rate", "memory_tension_drop", "extreme_low_mem"):
        result[name] = int(_once(r"(?<![\w])" + name + r"=(\d+)\b", text))
    return result


def ha_status(text):
    lines = _lines(text)
    heads = [index for index, line in enumerate(lines) if line.startswith("HA Health Status:")]
    if len(heads) != 1:
        raise Unparsed()
    value = lines[heads[0]].split(":", 1)[1].strip()
    warnings = []
    for line in lines[heads[0] + 1:]:
        if not line[:1].isspace():
            break
        if line.strip():
            warnings.append(line.strip())
    if not value and not warnings:
        raise Unparsed()
    mode = _once(r"^Mode:[ \t]*(\S[^\n]*?)\s*$", text)
    return {"mode": mode, "health_status": value if value else None, "warnings": warnings}


def ha_checksum(text):
    members = {}
    current = None
    block = None
    for line in _lines(text):
        stripped = line.strip()
        header = re.fullmatch(r"=+ (\S+) =+", stripped)
        if header:
            current = header.group(1)
            if current in members:
                raise Unparsed()
            members[current] = {}
            block = None
            continue
        if current is None or not stripped:
            continue
        if stripped in ("checksum", "debugzone"):
            block = stripped
            continue
        row = re.fullmatch(r"([A-Za-z0-9_.-]+): ((?:[0-9a-f]{2} ){15}[0-9a-f]{2})", stripped)
        if block == "checksum" and row:
            members[current][row.group(1)] = row.group(2)
    if len(members) < 2 or any(not {"global", "all"} <= set(rows) for rows in members.values()):
        raise Unparsed()
    return {"members": members}


def ntp_status(text):
    found = _once(r"^synchronized: (yes|no), ntpsync: (enabled|disabled)\b", text)
    servers = [{"server": name, "address": address, "state": state} for name, address, state in
               re.findall(r"(?m)^[^\S\n]*ipv[46] server\(([^)\s]*)\)\s+([0-9A-Fa-f:.]+)\s+--\s+([a-z]+)", text)]
    return {"synchronized": found[0], "ntpsync": found[1], "servers": servers}


def _expiry(value):
    if value == "n/a":
        return None
    try:
        return datetime.strptime(" ".join(value.split()), "%a %b %d %Y").date()
    except ValueError:
        raise Unparsed() from None


def autoupdate_versions(text):
    lines = _lines(text)
    packages = []
    for index, line in enumerate(lines):
        if re.fullmatch(r"-{3,}", line.strip()) and index and lines[index - 1].strip():
            packages.append({"package": lines[index - 1].strip(), "start": index + 1})
    if not packages:
        raise Unparsed()
    result = []
    for number, item in enumerate(packages):
        end = packages[number + 1]["start"] - 2 if number + 1 < len(packages) else len(lines)
        body = "\n".join(lines[item["start"]:end])
        fields = {}
        for key, label in (("version", "Version"), ("contract_expiry", "Contract Expiry Date"),
                           ("last_update_attempt", "Last Update Attempt"), ("result", "Result")):
            matches = re.findall(r"(?m)^" + label + r":[ \t]*(\S[^\n]*?)\s*$", body)
            if len(matches) > 1:
                raise Unparsed()
            fields[key] = matches[0] if matches else None
        if item["package"] == "FDS Address" and fields["version"] is None:
            continue
        if fields["contract_expiry"] is not None:
            _expiry(fields["contract_expiry"])
        result.append({"package": item["package"], **fields})
    return result


def physical_interfaces(text):
    ports = []
    for line in _lines(text):
        stripped = line.strip()
        name = re.fullmatch(r"==\[([^\]]+)\]", stripped)
        if name:
            ports.append({"name": name.group(1), "status": None, "speed": None})
            continue
        if not ports:
            continue
        status = re.fullmatch(r"status: (up|down)", stripped)
        if status:
            if ports[-1]["status"] is not None:
                raise Unparsed()
            ports[-1]["status"] = status.group(1)
        speed = re.fullmatch(r"speed: (.+)", stripped)
        if speed:
            ports[-1]["speed"] = speed.group(1)
    if not ports or any(port["status"] is None for port in ports):
        raise Unparsed()
    return ports


def _metric(name, rest):
    found = re.search(name + r"\(([\d.]+)%?\)", rest)
    return float(found.group(1)) if found else None


SDWAN_NOT_RUNNING = ("SD-WAN health monitor is not running.", "SD-WAN daemon is not running.")


def sdwan_health(text):
    members = []
    check = None
    for line in _lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        head = re.fullmatch(r"Health Check\(([^()]+)\):", stripped)
        if head:
            check = head.group(1)
            continue
        seq = re.fullmatch(r"Seq\((\d+)(?: ([^()]+))?\): state\((alive|dead)\)(.*)", stripped)
        if not seq or check is None:
            raise Unparsed()
        rest = seq.group(4)
        members.append({"health_check": check, "seq": int(seq.group(1)), "member": seq.group(2),
                        "state": seq.group(3), "packet_loss": _metric("packet-loss", rest),
                        "latency": _metric("latency", rest), "jitter": _metric("jitter", rest)})
    if not members:
        raise Unparsed()
    return members


PARSERS = {
    "conserve_state": conserve, "performance": performance, "session_stats": session_stats,
    "ha_status": ha_status, "ha_checksum": ha_checksum, "ntp_status": ntp_status,
    "autoupdate_versions": autoupdate_versions, "physical_interfaces": physical_interfaces,
    "sdwan_health": sdwan_health,
}


def _utc(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def findings_for(parsed, sources, captured):
    found = []

    def add(rule, query, obj, fact):
        found.append({"id": rule, "layer": "runtime", "object": obj, "fact": fact, "sources": [sources[query]]})

    data = parsed.get("conserve_state")
    if data:
        if data["memory_conserve_mode"] == "on":
            add("F-CONSERVE-ON", "conserve_state", "memory", "memory conserve mode: on")
        if data["used_percent"] >= data["red_percent"]:
            add("F-MEM-RED", "conserve_state", "memory",
                "memory used %d%% >= threshold red %d%%" % (data["used_percent"], data["red_percent"]))
        if data["used_percent"] + data["freeable_percent"] >= data["extreme_percent"]:
            add("F-MEM-EXTREME", "conserve_state", "memory",
                "memory used + freeable %d%% >= threshold extreme %d%%" % (
                    data["used_percent"] + data["freeable_percent"], data["extreme_percent"]))
    data = parsed.get("ha_status")
    if data and (data["health_status"] != "OK" or data["warnings"]):
        add("F-HA-STATUS", "ha_status", "ha",
            "HA Health Status: " + "; ".join(([data["health_status"]] if data["health_status"] else []) + data["warnings"]))
    data = parsed.get("ha_checksum")
    if data:
        members = data["members"]
        for row in ("global", "all"):
            values = {name: rows[row] for name, rows in members.items()}
            if len(set(values.values())) > 1:
                add("F-HA-CHECKSUM", "ha_checksum", "ha:" + row,
                    "checksum %s differs between members %s" % (row, ", ".join(sorted(values))))
    data = parsed.get("ntp_status")
    if data and data["ntpsync"] == "enabled" and data["synchronized"] == "no":
        add("F-NTP-UNSYNC", "ntp_status", "ntp", "synchronized: no, ntpsync: enabled")
    for item in parsed.get("autoupdate_versions") or ():
        expiry = item["contract_expiry"]
        if expiry is not None and expiry != "n/a" and _expiry(expiry) < captured["autoupdate_versions"].date():
            add("F-UPDATE-EXPIRED", "autoupdate_versions", "update:" + item["package"],
                "Contract Expiry Date: " + expiry)
    for member in parsed.get("sdwan_health") or ():
        if member["state"] == "dead":
            add("F-SDWAN-DEAD", "sdwan_health", "sdwan:%s:%d" % (member["health_check"], member["seq"]),
                "state(dead)")
    return found


_NEXT = {
    "F-CONSERVE-ON": ("hardware_memory", "memory detail behind conserve mode"),
    "F-MEM-RED": ("hardware_memory", "memory detail behind the red threshold"),
    "F-MEM-EXTREME": ("hardware_memory", "memory detail behind the extreme threshold"),
    "F-HA-CHECKSUM": ("ha_checksum", "Admin Guide: synchronization can take minutes; repeat the checksum read"),
}


def run(read, clock):
    started = clock()
    missing = []
    parsed = {}
    sources = {}
    captured = {}
    checked = []
    first = read("system_status")
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    support = firmware_support(ident, IDENTITIES, "triage_health")
    scope = vdom_scope(first["text"])
    multiple = multi_vdom(scope)
    data_scopes = {}
    other_vdom_ports = None
    ha_reason = None
    for area, query in STEPS[1:]:
        if query == "ha_checksum":
            if ha_reason is not None:
                # The refused ha_status's reason, with its error_code and error when it has them (review).
                missing.append({**ha_reason, "step": query})
                continue
            if (parsed["ha_status"]["mode"] or "").lower() == "standalone":
                missing.append({"step": query, "reason": "not_applicable"})
                continue
        moment = clock()
        answer = read(query)
        captured[query] = moment
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
        elif not in_vdom(scope, answer):
            missing.append({"step": query, "reason": "vdom_unverified"})
        elif not answer["text"].strip():
            missing.append({"step": query, "reason": "not_applicable" if query == "sdwan_health" else "empty"})
        elif query == "sdwan_health" and answer["text"].strip() in SDWAN_NOT_RUNNING:
            missing.append({"step": query, "reason": "not_applicable"})
        else:
            sources[query] = {"call": "triage_health", "query": query,
                              "content_sha256": answer["content_sha256"], "captured_at": _utc(moment)}
            try:
                parsed[query] = PARSERS[query](answer["text"])
            except Unparsed:
                missing.append({"step": query, "reason": "unparsed"})
            else:
                from .fortios_vdom import DATA_SCOPES
                data_scope = DATA_SCOPES.get(query, answer.get("data_scope", "vdom"))
                if multiple and data_scope in ("all_vdoms", "unverified"):
                    # A listing of every VDOM: only the ports assigned to this VDOM are its links.
                    assigned = ports_of_vdom(parsed[query], answer, scope["vdom"]) \
                        if query == "physical_interfaces" else None
                    if assigned is None:
                        del parsed[query]
                        sources.pop(query, None)
                        missing.append({"step": query, "reason": "vdom_membership_unverified"})
                        continue
                    parsed[query], other_vdom_ports = assigned
                    data_scope = "vdom"
                if multiple:
                    data_scopes[query] = data_scope
                checked.append(query)
        if query == "ha_status" and "ha_status" not in parsed:
            ha_reason = {key: value for key, value in missing[-1].items() if key in ("reason", "error_code", "error")}
    findings = findings_for(parsed, sources, captured)
    if multiple:
        for item in findings:
            # Each finding names the scope of the data it was found in (device-wide or this VDOM).
            item["data_scope"] = data_scopes.get(item["sources"][0]["query"], "vdom")
    gaps = [item for item in missing if item["reason"] != "not_applicable"]
    absent = [query for query in REQUIRED - {"system_status"} if query not in parsed]
    if gaps or absent:
        verdict = "incomplete"
    elif findings:
        verdict = "fault_found"
    else:
        verdict = "no_fault_in_checked_data"
    conserve_data = parsed.get("conserve_state")
    ha = parsed.get("ha_status")
    chain = {
        "resources": {"conserve": conserve_data, "performance": parsed.get("performance")},
        "sessions": parsed.get("session_stats"),
        "ha": {"mode": ha["mode"] if ha else None,
               "health_status": ha["health_status"] if ha else None,
               "warnings": ha["warnings"] if ha else None,
               "checksum": parsed.get("ha_checksum")},
        "ntp": parsed.get("ntp_status"),
        "updates": parsed.get("autoupdate_versions"),
        "links": {"physical": parsed.get("physical_interfaces"), "sdwan": parsed.get("sdwan_health")},
    }
    if multiple:
        # Multi-VDOM: every part names the scope of its data; device-wide counters are not data of the VDOM.
        if chain["sessions"] is not None:
            chain["sessions"] = {**chain["sessions"], "data_scope": data_scopes["session_stats"]}
        if other_vdom_ports is not None:
            chain["links"]["other_vdom_ports"] = other_vdom_ports
    next_steps = []
    for item in findings:
        step = _NEXT.get(item["id"])
        if step and not any(existing["arguments"]["query"] == step[0] for existing in next_steps):
            next_steps.append({"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": step[0]},
                               "why": step[1]})
    return {
        "ok": True,
        "identity": ident,
        **vdom_fields(scope),
        **({"data_scopes": {"system_status": "device", **data_scopes}} if multiple else {}),
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "chain": chain,
        "findings": findings,
        "hypotheses": [],
        "next_steps": next_steps,
        "missing": missing,
        "checked": ["system_status"] + checked,
        "verdict": verdict,
        **firmware_fields(support),
    }


# --- sensors crashlog (1.0.12): hardware sensors and crash log of a FortiGate (ssh_read objects, not triage steps) ---------
# Measured with a read-only account on FortiGate-80F 8.0.2 build0251, 2026-11-17 (fixture g13_20261117). They are
# not steps of run(): a new step would need a new query grant on every enrolled target and change the read count.
SENSORS_QUERY = "hardware_sensors"
CRASH_LOG_QUERY = "crash_log"
_SENSOR_HEAD = re.compile(r"[ \t]*\[HW monitor sensors\][ \t]*")
_SENSOR_LINE = re.compile(r"[ \t]*(\d+)[ \t]+(\S.*?)[ \t]*\.{2,}[ \t]+(\S.*?)[ \t]*")
_SENSOR_READING = re.compile(r"(-?\d+(?:\.\d+)?)[ \t]+([A-Za-z%]+)")
# Linear form (verification): the label ends on a non-blank character and the value starts and ends on a character that
# is not space/tab, so no neighbouring unbounded quantifiers share characters (was lazy label + lazy value).
_SENSOR_DETAIL = re.compile(r"[ \t]+([A-Za-z](?:[A-Za-z /-]*[A-Za-z/-])?)[ \t]*:[ \t]*((?:[^ \t\n](?:[^\n]*[^ \t\n])?)?)[ \t]*")


def _key(label):
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def hardware_sensors(text, start, end):
    """Parse `execute sensor detail` (80F / FortiOS 8.0.2 build0251).

    `[HW monitor sensors]`, then per sensor `<n> <name> ....  <reading>` and indented `<label> : <value>` lines
    (Type, Sensor status, Alarm, Value, thresholds such as Upper critical). Only the sensors the model reports are
    listed. Sensors whose line starts in [start, end) of the UTF-8 output are returned; counts cover the whole
    output. A line of another shape or a missing header make the state incomplete; a sensor the device prints
    without an Alarm line keeps alarm null (counted in sensors_without_alarm_line).
    """
    sensors, page, current, unreadable, position, header = [], [], None, 0, 0, False
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        if _SENSOR_HEAD.fullmatch(line):
            header = True
            continue
        head = _SENSOR_LINE.fullmatch(line)
        detail = _SENSOR_DETAIL.fullmatch(line) if head is None and current is not None else None
        if head:
            reading = _SENSOR_READING.fullmatch(head[3])
            current = {"index": int(head[1]), "name": head[2], "reading": head[3],
                       "value": float(reading[1]) if reading else None, "unit": reading[2] if reading else None,
                       "absent": head[3].upper().startswith("ABSENT"),
                       "type": None, "sensor_status": None, "alarm": None, "thresholds": {}}
            sensors.append(current)
            if start <= line_start < end:
                page.append(current)
        elif detail:
            key, value = _key(detail[1]), detail[2].rstrip(" \t")
            if key == "type":
                current["type"] = value
            elif key == "sensor_status":
                current["sensor_status"] = value
            elif key == "alarm" and value.lower() in ("yes", "no"):
                current["alarm"] = value.lower() == "yes"
            elif "critical" in key or "threshold" in key:
                try:
                    current["thresholds"][key] = float(value)
                except ValueError:
                    unreadable += 1
            elif key != "value":
                unreadable += 1
        else:
            unreadable += 1
    # Measured: the 80F prints no Alarm line for two of its temperature sensors; alarm stays null there.
    no_alarm_line = sum(1 for sensor in sensors if sensor["alarm"] is None)
    state = "incomplete" if unreadable or (sensors and not header) else "ok" if sensors else "empty"
    return {"state": state, "total_sensors": len(sensors), "unreadable_lines": unreadable,
            "sensors_without_alarm_line": no_alarm_line,
            "alarms": [sensor["name"] for sensor in sensors if sensor["alarm"]],
            "absent": [sensor["name"] for sensor in sensors if sensor["absent"]],
            "sensors": page}


_CRASH_ENTRY = re.compile(r"(\d+): (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: (.*?))?[ \t]*")
_CRASH_INTERVAL = re.compile(r"[ \t]*Crash log interval is (\d+) seconds[ \t]*")
_CRASH_MAX = re.compile(r"[ \t]*Max crash log line number: (\d+)[ \t]*")
_CRASH_KILLED = re.compile(r"the killed daemon is (\S+?): (?:pid=\d+ )?status=(0x[0-9a-fA-F]+)")


def crash_log(text, start, end):
    """Parse `diagnose debug crashlog read` (80F / FortiOS 8.0.2 build0251).

    Every line is `<n>: <YYYY-MM-DD hh:mm:ss> <text>`; a long record continues on further numbered lines. The
    trailer names the crash log interval and the maximum line number. Entries whose line starts in [start, end)
    are returned; the counts and the per-daemon kill summary cover the whole output. No entry is `empty` (a read
    the device refused never reaches this parser: ssh_read reports it as an error). A line of another shape makes
    the state incomplete. Times are the device wall clock and need not be in order (clock changes, HA members).
    """
    entries, page, unreadable, position = 0, [], 0, 0
    interval = maximum = first = last = None
    kills = {}
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        entry = _CRASH_ENTRY.fullmatch(line)
        if entry:
            entries += 1
            message = entry[3] or ""
            first = first or entry[2]
            last = entry[2]
            killed = _CRASH_KILLED.search(message)
            if killed:
                item = kills.setdefault(killed[1], {"daemon": killed[1], "count": 0, "nonzero_status": 0,
                                                    "last_time": None})
                item["count"] += 1
                item["nonzero_status"] += int(killed[2], 16) != 0
                item["last_time"] = entry[2]
            if start <= line_start < end:
                page.append({"line": int(entry[1]), "time": entry[2], "text": message})
            continue
        found = _CRASH_INTERVAL.fullmatch(line) or _CRASH_MAX.fullmatch(line)
        if found and found.re is _CRASH_INTERVAL and interval is None:
            interval = int(found[1])
        elif found and found.re is _CRASH_MAX and maximum is None:
            maximum = int(found[1])
        else:
            unreadable += 1
    state = "incomplete" if unreadable else "ok" if entries else "empty"
    return {"state": state, "total_lines": entries, "unreadable_lines": unreadable,
            "first_time": first, "last_time": last, "interval_seconds": interval, "max_lines": maximum,
            "full": bool(maximum) and entries >= maximum,
            "daemon_kills": sorted(kills.values(), key=lambda item: (-item["count"], item["daemon"])),
            "entries": page,
            "time_note": "Times are the FortiGate wall clock without a time zone, in the order the log stores them."}


# --- eos health (1.0.12, EP09/EP10): EOS log history and health summaries of ssh_read (not triage steps) -----------
# Measured on cEOS 4.36.1F (GNS3 netops-emulated environment, 2026-11-18, fixture g120_ceos_4.36.1F). Like sensors crashlog these are structured
# views of single catalogue reads; the raw redacted output stays in untrusted_device_output.
EOS_SEVERITIES = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational",
                  "debugging")
_EOS_LOG_LINE = re.compile(r"([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^\s:]+): (.*)")
_EOS_LOG_TAG = re.compile(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+): ?(.*)")
_EOS_LOG_INTERFACE = (
    r"((?:Ethernet|Port-Channel|Management|Recirc-Channel)\d+(?:/\d+){0,2}(?:\.\d+)?"
    r"|(?:Vlan|Loopback|Vxlan|Tunnel)\d+)(?![\w/-]|\.\d)")
# Match local interface fields in the EOS message formats, keeping neighbor-supplied text out of the captures.
_EOS_LOG_LOCAL_FIELDS = {
    "ETH": re.compile(r"Failed to (?:poll link status|set pause parameters) on interface " + _EOS_LOG_INTERFACE),
    "LAG": re.compile(r"Interface " + _EOS_LOG_INTERFACE + r" has (?:joined|left) " + _EOS_LOG_INTERFACE),
    "LINEPROTO": re.compile(r"Line protocol on Interface " + _EOS_LOG_INTERFACE),
    "LLDP": re.compile(r'LLDP neighbor with chassisId \S+ and portId "(?:[^"\\]|\\.)*" '
                       r"(?:added|timed out) on interface " + _EOS_LOG_INTERFACE),
    "SPANTREE": re.compile(r"(?:Interface |MSTP region border detected on )" + _EOS_LOG_INTERFACE),
}
_HELPER_NOTE = re.compile(r"\[netops-helper: [^\]]*\]")


# IOS and IOS XE health counters and operational detail. The process commands include a
# long per-process table. Their summaries below use the independent CLI totals.
_XE_NUMBER = r"[+-]?\d+(?:\.\d*)?"
_XE_CPU = re.compile(
    r"(?m)^CPU utilization for five seconds: (\d+)%(?:/(\d+)%)?; "
    r"one minute: (\d+)%; five minutes: (\d+)%\s*$"
)
_XE_POOL = re.compile(r"(?m)^([^\n]+?) Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)[ \t]*$")
_XE_FAN = re.compile(r"(?i)(?:(?:Switch|Device) \d+:? )?FAN(?:[ -]+\S+)? is (.+)")
_XE_TEMP = re.compile(r"^(?:([A-Za-z][\w /-]{0,63}) )?Temperature Value:[ \t]*(-?\d+) Degree Celsius$", re.I)
_XE_POWER = re.compile(r"\d+[A-Z]\s+\S+\s+\S+\s+(.+?)\s{2,}\S+\s+\S+\s+[\d/]+")


def xe_cpu(text):
    found = _XE_CPU.search(text)
    if not found:
        return None
    five, interrupt, minute, five_minutes = (int(value) if value is not None else None for value in found.groups())
    return {"five_seconds_percent": five, "interrupt_percent": interrupt, "one_minute_percent": minute,
            "five_minutes_percent": five_minutes, "five_seconds_minus_five_minutes_pp": five - five_minutes}


def xe_memory(text):
    pools = {}
    for match in _XE_POOL.finditer(text):
        name, total, used, free = match.groups()
        total, used, free = int(total), int(used), int(free)
        if not total or used + free != total or name in pools:
            return None
        pools[name] = {"total_bytes": total, "used_bytes": used, "free_bytes": free,
                       "used_percent": round(100 * used / total, 2)}
    return pools if "Processor" in pools else None


def xe_environment(text):
    fans, temperatures, power_supplies = [], [], []
    unparsed = 0
    for line in map(str.strip, text.splitlines()):
        if match := _XE_FAN.fullmatch(line):
            fans.append({"name": line[:match.start(1)].removesuffix(" is "), "state": match[1]})
        elif match := _XE_TEMP.fullmatch(line):
            temperatures.append({"name": match[1] or "Temperature", "celsius": int(match[2])})
        elif match := re.fullmatch(r"Temp:\s*(\S+)\s+(\S+)\s+(\S+)\s+(-?\d+) Celsius", line):
            temperatures.append({"name": match[1], "location": match[2], "state": match[3], "celsius": int(match[4])})
        elif match := _XE_POWER.fullmatch(line):
            power_supplies.append({"slot": line.split()[0], "state": match[1]})
        elif match := re.fullmatch(r"(\d+)\s+Built-in\s{2,}(Good|Bad)", line, re.I):
            power_supplies.append({"slot": match[1], "state": match[2]})
        elif match := re.fullmatch(r"(\d+[A-Z])\s+Not Present", line, re.I):
            power_supplies.append({"slot": match[1], "state": "Not Present"})
        elif match := re.fullmatch(r"(?:System )?Temperature State:\s*(\S+)", line, re.I):
            if temperatures:
                temperatures[-1]["state"] = match[1]
            else:
                unparsed += 1
        elif line and not re.match(
                r"(?:[- ]+$|(?:(?:Switch|Device) \d+:? )?(?:SYSTEM )?TEMPERATURE is |(?:Yellow|Red) Threshold\s*:|SW\s+PID\s+Serial#"
                r"|SW\s+Status\s+RPS Name|\d+\s+<>\s+<>$|Sensor List:|Sensor\s+Location\s+State\s+Reading)", line, re.I):
            unparsed += 1
    if not (fans or temperatures or power_supplies):
        return None
    return {"fans": fans, "temperatures": temperatures, "power_supplies": power_supplies,
            "complete": bool(fans and temperatures and power_supplies and not unparsed), "unparsed_lines": unparsed}


def xe_platform_resources(text):
    resources = []
    unparsed = 0
    for line in map(str.strip, text.splitlines()):
        if not line or re.match(r"Resource\s+Usage|[- ]+$|\*?\s*[HWC] - |.*(?:RP|ESP)\d?,.*Slot", line):
            continue
        columns = re.split(r"[ \t]{2,}", line)
        if len(columns) == 6 and columns[-1] in {"H", "W", "C"}:
            resources.append(dict(zip(("resource", "usage", "maximum", "warning", "critical", "state"), columns)))
        else:
            unparsed += 1
    return {"resources": resources, "complete": not unparsed, "unparsed_lines": unparsed} if resources else None


_XE_NTP_HEADER = re.compile(r"address\s+ref clock\s+st\s+when\s+poll\s+reach\s+delay\s+offset\s+disp")
_XE_NTP_LEGEND = re.compile(
    r"\*\s+(?:primary \(synced\)|sys\.peer),(?:\s*[*#+x-]\s++[^\s,][^,]*,)+\s*~\s+configured"
)
_XE_NTP_CANDIDATE = re.compile(r",\s*([+-])\s+candidate(?=,)")
_XE_NTP_PEER = re.compile(
    rf"([*#+\-~]*)(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+([0-3]?[0-7]{{1,2}})\s+"
    rf"({_XE_NUMBER})\s+({_XE_NUMBER})\s+([+-]?\d+(?:\.\d*)?)"
)


def xe_ntp_status(text):
    if text.strip() == "%NTP is not enabled.":
        return {"enabled": False, "synchronized": False}
    clock = re.search(
        r"(?m)^Clock is (synchronized|unsynchronized), stratum (\d+)"
        r"(?:, reference assoc id \d+)?"
        r"(?:, (?:reference is (\S[^\r\n]*?)|no reference clock))?[ \t]*$", text)
    if not clock:
        return None
    offset = re.search(rf"(?m)^clock offset is ({_XE_NUMBER}) msec\b", text)
    synchronized = clock[1] == "synchronized"
    return {"enabled": True, "synchronized": synchronized, "stratum": int(clock[2]),
            "reference": clock[3], "offset_ms": float(offset[1]) if offset else None,
            "complete": not synchronized or bool(offset and clock[3])}


def xe_ntp_associations(text, *, include_candidate=True):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return {"peers": [], "complete": True, "unparsed_lines": 0}
    if not _XE_NTP_HEADER.fullmatch(lines[0]):
        return None
    peers, unparsed = [], 0
    legend = False
    candidate_marks = {"-"}  # Cisco's documented legend uses - candidate.
    for line in lines[1:]:
        if _XE_NTP_LEGEND.fullmatch(line):
            legend = True
            candidate_marks = set(_XE_NTP_CANDIDATE.findall(line))
            continue
        match = _XE_NTP_PEER.fullmatch(line)
        if not match or int(match[7], 8) > 255 or legend:
            unparsed += 1
            continue
        marks, address, reference, stratum, when, poll, reach, delay, offset, dispersion = match.groups()
        register = int(reach, 8)
        peer = {"address": address, "reference": reference, "stratum": int(stratum), "when": when,
                "poll_seconds": int(poll), "reach_octal": reach, "successful_polls": register.bit_count(),
                "reachable": bool(register), "configured": "~" in marks, "selected": "*" in marks,
                "selection_mark": marks.replace("~", ""), "delay_ms": float(delay),
                "offset_ms": float(offset), "dispersion_ms": float(dispersion)}
        peers.append(peer)
    if include_candidate:
        for peer in peers:
            peer["candidate"] = bool(candidate_marks.intersection(peer["selection_mark"]))
    return {"peers": peers, "complete": legend and unparsed == 0, "unparsed_lines": unparsed}


XE_HEALTH_QUERIES = ("version", "cpu", "memory", "environment", "platform_resources", "ntp_status", "ntp_associations")
C9800_HA_QUERIES = ("c9800_redundancy", "c9800_chassis_rmi")


IOS_HEALTH_QUERIES = tuple(query for query in XE_HEALTH_QUERIES if query != "platform_resources")
IOS_HEALTH_TESTED = ("15.9(3)M12", "15.2(20200924:215240)")
XE_HEALTH_TESTED = ("17.18.2",)


def run_ios_health(profile, read, clock, *, check_c9800_ha=False):
    """Summarize the IOS family resource and NTP readings available to the account."""
    from netops_core import tested
    from .normalization import IdentityError, parse_identity

    captured_at = _utc(clock())
    fields, missing, sources, findings = {}, [], [], []
    parsers = {"cpu": xe_cpu, "memory": xe_memory, "environment": xe_environment,
               "platform_resources": xe_platform_resources, "ntp_status": xe_ntp_status,
               "ntp_associations": lambda text: xe_ntp_associations(text, include_candidate=profile == "cisco_xe")}
    identity = None
    version_text = ""
    for query in IOS_HEALTH_QUERIES if profile == "cisco_ios" else XE_HEALTH_QUERIES:
        answer = read(query)
        if not answer["ok"]:
            missing.append(missing_read(query, answer))
        else:
            sources.append({key: answer[key] for key in ("query", "content_sha256", "total_bytes")})
            if query == "version":
                version_text = answer["text"]
                try:
                    identity = parse_identity(profile, version_text)
                except IdentityError:
                    pass
                if not identity or not identity.get("uptime"):
                    missing.append({"step": query, "reason": "unparsed"})
            else:
                summary = parsers[query](answer["text"])
                if summary is not None:
                    fields[query] = summary
                if summary is None or not summary.get("complete", True):
                    missing.append({"step": query, "reason": "unparsed"})
        if query == "version" and identity is None:
            break

    ntp = fields.pop("ntp_status", {})
    if associations := fields.pop("ntp_associations", None):
        ntp["peers"] = associations["peers"]
        ntp["associations_complete"] = associations["complete"]
        if any(not peer["reachable"] for peer in associations["peers"]):
            findings.append({"rule": "ntp_peer_unreachable", "query": "ntp_associations"})
        if ntp.get("synchronized") and associations["complete"] and not any(
                peer["selected"] and peer["reachable"] for peer in associations["peers"]):
            missing.append({"step": "ntp_associations", "reason": "unparsed"})
    if ntp.get("enabled") and not ntp["synchronized"]:
        findings.append({"rule": "ntp_not_synchronized", "query": "ntp_status"})
    if ntp.get("enabled") is False:
        findings.append({"rule": "ntp_disabled", "query": "ntp_status"})
    if ntp:
        fields["ntp"] = ntp
    if any(item["state"] in {"W", "C"} for item in fields.get("platform_resources", {}).get("resources", [])):
        findings.append({"rule": "platform_resource_threshold", "query": "platform_resources"})
    environment = fields.get("environment", {})
    if (any(item.get("state", "").upper() in {"YELLOW", "RED", "WARNING", "CRITICAL"}
            for item in environment.get("temperatures", []))
            or any(item["state"].upper() not in {"OK", "GOOD", "NOT PRESENT"}
                   for item in environment.get("fans", []) + environment.get("power_supplies", []))):
        findings.append({"rule": "environment_alarm", "query": "environment"})
    os_name, versions = (("IOS", IOS_HEALTH_TESTED) if profile == "cisco_ios"
                         else ("IOS XE", XE_HEALTH_TESTED))
    if check_c9800_ha and identity:
        from netops_core.c9800 import CONTROLLER_IMAGE, DOCUMENTED_RELEASES
        from .triage_wifi import c9800_ha

        if CONTROLLER_IMAGE.search(version_text):
            ha = c9800_ha(read, identity["os_version"])
            fields["ha"] = ha["ha"]
            missing.extend(ha["missing"])
            sources.extend(ha["sources"])
            if ha["ha"]["state"] == "degraded":
                findings.append({"rule": "c9800_ha_degraded", "query": "c9800_redundancy"})
            versions = DOCUMENTED_RELEASES
        else:
            missing.append({"step": "ha", "reason": "identity_unverified"})
    support = (firmware_fields(tested.support(os_name, identity["os_version"], versions,
                                  model=identity["model"], function="triage_health")) if identity else {})
    return {"ok": identity is not None, "captured_at": captured_at, "identity": identity, **fields, **support,
            "sources": sources, "missing": missing, "complete": not missing, "findings": findings,
            "verdict": "incomplete" if missing else "fault_found" if findings else "no_fault_in_checked_data"}


EXOS_HEALTH_QUERIES = ("version", "switch", "memory", "cpu_monitoring", "temperature",
                       "fans", "power", "stacking", "mlag_peer", "ntp")
# Match the sensor label by words so malformed whitespace is scanned only once per separator.
_EXOS_TEMPERATURE = re.compile(
    r"(\S++(?:\s++\S++)*?\s++:\s++\S++)\s+(-?\d+(?:\.\d+)?)\s+(\w+)\s+-?\d+\s+-?\d+\s*-\s*-?\d+\s+-?\d+")
_EXOS_STACK_ROW = re.compile(r"(\*?)([\da-f:]{17})\s+(\d+|-)\s+(\S+)\s+(\S+)\s+([C-][A-][O-])", re.I)


def _exos_match(pattern, text):
    matches = list(re.finditer(pattern, text, re.M))
    return matches[0] if len(matches) == 1 else None


def _exos_memory(text):
    fields = {}
    for key, label in (("total", "Total DRAM"), ("system", "System"), ("user", "User"), ("free", "Free")):
        matches = re.findall(rf"(?m)^\s*{label}[ \t]+\(KB\):[ \t]*(\d+)[ \t]*$", text)
        if len(matches) != 1:
            return None
        fields[key + "_kb"] = int(matches[0])
    total = fields["total_kb"]
    if not total or total != fields["system_kb"] + fields["user_kb"] + fields["free_kb"]:
        return None
    return {**fields, "used_percent": round(100 * (total - fields["free_kb"]) / total, 2)}


def _exos_cpu(text):
    row = _exos_match(r"(?m)^System[ \t]+([\d.]+(?:[ \t]+[\d.]+){9})[ \t]*$", text)
    if row is None:
        return None
    try:
        values = [float(value) for value in row[1].split()[:8]]
    except ValueError:
        return None
    if any(not 0 <= value <= 100 for value in values):
        return None
    return dict(zip(("five_seconds_percent", "ten_seconds_percent", "thirty_seconds_percent",
                     "one_minute_percent", "five_minutes_percent", "thirty_minutes_percent",
                     "one_hour_percent", "max_percent"), values))


def _exos_temperatures(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 3 or not lines[0].startswith("Field Replaceable Units") or not lines[1].startswith("---"):
        return [], False
    rows = [_EXOS_TEMPERATURE.fullmatch(line) for line in lines[2:]]
    return [{"sensor": row[1], "celsius": float(row[2]), "state": row[3]} for row in rows if row], all(rows)


def _exos_hardware(text, header):
    blocks = re.split(rf"(?m)^({header}) information:[ \t]*$", text)
    entries = []
    for name, block in zip(blocks[1::2], blocks[2::2]):
        state = _exos_match(r"(?m)^[ \t]*State[ \t]*:[ \t]*(\S[^\n]*)$", block)
        if state:
            entries.append({"name": name, "state": state[1].strip()})
    return entries, bool(entries) and len(entries) == len(blocks) // 2 and not blocks[0].strip()


def _exos_stacking(text):
    setting = _exos_match(r"(?m)^stacking-support:[ \t]+(Enabled|Disabled)[ \t]+(Enabled|Disabled)[ \t]*$", text)
    if setting and setting[2] == "Disabled":
        return {"configured": setting[1], "enabled": False}, "Flags:" in text
    topology = _exos_match(r"(?m)^Active Topology is a (.+)$", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not topology or len(lines) < 6 or not lines[2].startswith("Node MAC Address") or not lines[3].startswith("--"):
        return None, False
    end = next((index for index, line in enumerate(lines[4:], 4) if line.startswith("* - Indicates")), len(lines))
    rows = [_EXOS_STACK_ROW.fullmatch(line) for line in lines[4:end]]
    nodes = [{"mac": row[2], "slot": int(row[3]) if row[3] != "-" else None, "state": row[4],
              "role": row[5], "flags": row[6], "local": bool(row[1])} for row in rows if row]
    complete = end < len(lines) and all(rows) and sum(node["local"] for node in nodes) == 1
    return {"enabled": True, "active_topology": topology[1], "nodes": nodes}, complete


def exos_firmware(identity, version_text, function):
    from netops_core import tested

    version = identity["os_version"]
    image = re.escape(version)
    patch = _exos_match(rf"^Image[ \t]*:[ \t]*ExtremeXOS version {image}[ \t]+({image}-patch[\w.-]+)\b",
                        version_text)
    return firmware_fields(tested.support(
        "ExtremeXOS", patch[1] if patch else version, ("33.6.1.14", "33.7.1.6-patch1-11"),
        model=identity["model"], function=function,
    ))


def run_exos(read, clock):
    from . import normalization
    from .switch_mlag_exos import summarize_peer

    captured_at = _utc(clock())
    fields, sources, missing, findings = {}, [], [], []
    identity = None

    def record(query, condition, rule):
        if condition:
            findings.append({"query": query, "rule": rule})

    for query in EXOS_HEALTH_QUERIES:
        answer = read(query)
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
            if query == "version":
                break
            continue
        text = answer["text"]
        complete = True
        if query == "version":
            try:
                identity = normalization.parse_identity("extreme_exos", text)
            except normalization.IdentityError:
                missing.append({"step": query, "reason": "unparsed"})
                break
            version_text = text
            sources.append(normalization.source_record(query, text, "ok"))
            continue
        if query == "switch":
            try:
                normalization.supplement_identity(identity, query, text)
            except normalization.IdentityError:
                complete = False
            state = _exos_match(r"(?m)^Current State:[ \t]*(\S+)[ \t]*$", text)
            data = {"state": state[1]} if state else None
            complete = complete and bool(identity["model"] and identity["uptime"])
            record(query, state and state[1] != "OPERATIONAL", "switch_not_operational")
        elif query == "memory":
            data = _exos_memory(text)
            record(query, data and data["used_percent"] >= 90, "memory_utilization_high")
        elif query == "cpu_monitoring":
            data = _exos_cpu(text)
            record(query, data and data["five_minutes_percent"] >= 90, "sustained_cpu_utilization_high")
        elif query == "temperature":
            data, complete = _exos_temperatures(text)
            record(query, any(sensor["state"] != "Normal" for sensor in data), "temperature_alarm")
        elif query in {"fans", "power"}:
            header = r"Slot-\d+ FanTray" if query == "fans" else r"PowerSupply \d+"
            data, complete = _exos_hardware(text, header)
            normal = {"Empty", "Operational" if query == "fans" else "Powered On"}
            record(query, any(device["state"] not in normal for device in data), "hardware_alarm")
        elif query == "stacking":
            data, complete = _exos_stacking(text)
            record(query, data and any(node["state"] != "Active" or "O" in node["flags"]
                                       for node in data.get("nodes", [])), "stack_node_outside_active_topology")
        elif query == "mlag_peer":
            data = summarize_peer(text)
            complete = data["state"] == "measured"
            record(query, any(peer["checkpoint_status"] == "Down" for peer in data["peers"]), "mlag_checkpoint_down")
        else:  # show ntp reports the global administrative state only.
            state = _exos_match(r"(?m)^NTP[ \t]*:[ \t]*(Enabled|Disabled)[ \t]*$", text)
            data = {"enabled": state[1] == "Enabled", "synchronized": None} if state else None
            if state and data["enabled"]:
                missing.append({"step": query, "reason": "ntp_synchronization_unreported"})
            record(query, state and not data["enabled"], "ntp_disabled")
        if data is not None:
            fields[query] = data
        sources.append(normalization.source_record(query, text, "ok" if data is not None and complete else "incomplete"))
        if data is None or not complete:
            missing.append({"step": query, "reason": "unparsed"})

    support = exos_firmware(identity, version_text, "triage_health") if identity else {}
    return {"ok": identity is not None, "captured_at": captured_at, "identity": identity, **fields, **support,
            "sources": sources, "missing": missing, "complete": not missing, "findings": findings,
            "verdict": "incomplete" if missing else "fault_found" if findings else "no_fault_in_checked_data"}


_EXOS_LOG_LEVELS = dict(zip(("Crit", "Erro", "Warn", "Noti", "Info", "Summ", "Verb", "Data"), EXOS_LOG_SEVERITIES))
_EXOS_LOG_PORT = re.compile(r"(?i)\bport[ \t]+([0-9]+(?:(?::[0-9]+){1,2}|/[0-9]+)?)(?![\w:/.-])")


def exos_log_clock(text):
    times = re.findall(r"(?m)^Current Time:[ \t]*(.*)$", text)
    if len(times) != 1:
        return None
    try:
        return datetime.strptime(times[0].strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def exos_log_oldest(text):
    """Require a complete unfiltered listing before using its oldest timestamp."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    declared = EXOS_LOG_TOTAL.fullmatch(lines[-1]) if lines else None
    if not declared or len(lines) < 2 or int(declared[1]) != len(lines) - 1:
        return None
    stamps = []
    for line in lines[:-1]:
        entry = EXOS_LOG_ENTRY.fullmatch(line)
        if entry is None:
            return None
        stamp = entry["stamp"]
        try:
            stamps.append(datetime.strptime(stamp, "%m/%d/%Y %H:%M:%S.%f" if "." in stamp
                                           else "%m/%d/%Y %H:%M:%S"))
        except ValueError:
            return None
    return min(stamps)


def exos_log_history(text, parameters, capture_state, limit, *, withheld, clock, oldest):
    """Project redacted records and check both ends of the requested window."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    declared = EXOS_LOG_TOTAL.fullmatch(lines[-1]) if lines else None
    records = lines[:-1] if declared else lines
    empty = not lines or lines == [EXOS_LOG_EMPTY]
    if empty:
        records = []
    selected, unreadable, port_unverified = [], 0, False
    by_severity = dict.fromkeys(EXOS_LOG_SEVERITIES, 0)
    interface = parameters.get("interface")
    for row in records:
        entry = EXOS_LOG_ENTRY.fullmatch(row)
        level = _EXOS_LOG_LEVELS.get(entry["level"]) if entry else None
        if not level:
            unreadable += 1
            continue
        if interface and interface not in _EXOS_LOG_PORT.findall(entry["body"]):
            port_unverified |= entry["body"] == "<REDACTED>"
            continue
        selected.append(row)
        by_severity[level] += 1
    dropped = max(0, len(selected) - limit)
    count_matches = bool(declared and int(declared[1]) == len(records))
    begin = datetime.fromisoformat(parameters["begin_date"] + "T" + parameters["begin_time"])
    end = datetime.fromisoformat(parameters["end_date"] + "T" + parameters["end_time"])
    reasons = []
    if capture_state not in {"ok", "empty"} or not (empty or count_matches) or unreadable:
        reasons.append("log_capture_incomplete")
    if withheld:
        reasons.append("unrecognized_log_content")
    if port_unverified:
        reasons.append("redacted_port_reference")
    if dropped:
        reasons.append("log_record_limit")
    if clock is None:
        reasons.append("device_clock_unavailable")
    elif end > clock:
        reasons.append("window_end_after_device_clock")
    if oldest is None:
        reasons.append("buffer_bounds_unavailable")
    elif oldest >= begin:
        reasons.append("window_start_not_retained")
    complete = not reasons
    return "".join(row + "\n" for row in selected[:limit]), {
        "status": ("ok" if selected else "empty") if complete else "incomplete",
        "complete": complete, "source": parameters["source"], "coverage": "retained_device_log",
        "archive_correlation": "external_archive_unavailable", "time_basis": "device_local_time",
        "interface_match": "explicit_local_port_reference" if interface else None,
        "device_messages": int(declared[1]) if declared else 0 if empty else None,
        "selected_messages": len(selected), "unreadable_lines": unreadable,
        "dropped_messages": dropped, "by_severity": by_severity,
        "incomplete_reasons": reasons,
    }


_XE_GROUP = re.compile(r"(\S+) - Group (\d+)(?: \(v(?:ersion )?(\d+)\))?(?: - Address-Family (IPv[46]))?")
_XE_TRACK_OBJECT = re.compile(r"Track object (\d+) state (\S+)(?: decrement (\d+)| shutdown)?", re.I)
_XE_TRACK_PORT = re.compile(r"Track interface (\S+) state (\S+)(?: decrement (\d+))?", re.I)
_XE_CHANGES = re.compile(r"(\d+) (?:state )?changes?, last (?:state )?change (.+)", re.I)
_XE_FHRP_LABELS = {
    "state": r"State is (.+)", "virtual_ip": r"Virtual IP address is (\S+)(?: .+)?",
    "advertisement_interval": r"Advertisement interval is (.+)",
    "peer_advertisement_interval": r"Master Advertisement interval is (.+)",
    "master_down_interval": r"Master Down interval is (.+)",
    "state_duration": r"State duration (.+)", "state_change_reason": r"State change reason is (.+)",
    "active_router": r"Active router is (.+)", "standby_router": r"Standby router is (.+)",
    "master_router": r"Master Router is (.+)",
    "priority": r"Priority(?: is)? (\d+)(?: \((?:configured|default) \d+\))?",
}
_XE_FHRP_OTHER = re.compile(
    r"(?:Authentication\b|Auth(?:entication)?\s+digest\b|(?:Active |Local )?Virtual MAC address\b"
    r"|MAC address is |Next hello sent in |Preemption\b|min delay is |Group name is |BFD enabled|FLAGS:"
    r"|Tloc preference configured)", re.I
)


_FHRP_AUTH = re.compile(r"^([ \t]*)(auth(?:entication)?|key[- ]chain)\b", re.I)
_FHRP_AFTER_AUTH = re.compile(
    r"(?:Hello time [^,]+, hold time .+|Hellotime [^,]+, holdtime .+|"
    r"Local state is \w+, priority \d+(?: .+)?|Priority \d+, Configured \d+|"
    r"Advertisement interval \d+|(?:Active |Local )?Virtual MAC address(?: is|:)? [0-9a-f.:-]+(?: .+)?|"
    r"Next hello (?:sent )?in \S+(?: .+)?|FLAGS: [0-9/]+|----- Detailed information -----|"
    r"Group State transition:|Virtual secondary IP addresses:)", re.I,
)


def xe_redact_fhrp(text):
    """Withhold authentication fields and unknown continuation rows before paging."""
    from .sanitize import strip_terminal_controls

    lines = []
    auth_indent = None
    continuation_hidden = False
    text = strip_terminal_controls(text)
    for raw in text.splitlines():
        line = raw.strip()
        expanded = raw.expandtabs()
        indent = len(expanded) - len(expanded.lstrip())
        if match := _FHRP_AUTH.match(raw):
            auth_indent = indent if auth_indent is None else min(auth_indent, indent)
            continuation_hidden = False
            lines.append(match[0] + " <REDACTED>")
            if line.endswith("--More--"):
                lines.append("--More--")
        elif auth_indent is None or line == "--More--":
            lines.append(raw)
        elif indent <= auth_indent and (
            _XE_GROUP.fullmatch(line) or _NXOS_HSRP_GROUP.fullmatch(line) or _NXOS_VRRP_GROUP.fullmatch(line)
            or _FHRP_AFTER_AUTH.fullmatch(line) or _XE_CHANGES.fullmatch(line)
            or any(re.fullmatch(pattern, line, re.I) for pattern in _XE_FHRP_LABELS.values())
        ):
            auth_indent = None
            lines.append(raw)
        elif line and not continuation_hidden:
            lines.append("  <REDACTED>")
            continuation_hidden = True
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _xe_blocks(text, header, new, consume, required, title=None):
    records, current, unparsed = [], None, 0
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if title is not None:
        if not lines or lines[0] != title:
            return {"status": "unparsed", "complete": False, "records": [], "unparsed_lines": len(lines)}
        lines = lines[1:]
    for line in lines:
        if match := header.fullmatch(line):
            current = new(match)
            records.append(current)
        elif current is None or not consume(current, line):
            unparsed += 1
    complete = not unparsed and all(required <= record.keys() for record in records)
    status = ("ok" if records else "empty") if complete else ("incomplete" if records else "unparsed")
    return {"status": status, "complete": complete, "records": records, "unparsed_lines": unparsed}


def xe_gateway_detail(query, text):
    def start(match):
        return {"interface": match[1], "group": int(match[2]), "version": match[3],
                "address_family": match[4], "tracked_objects": [], "tracked_interfaces": []}

    def consume(group, line):
        if match := re.fullmatch(r"Hello time (.+?), hold time (.+)", line):
            group.update(hello_time=match[1], hold_time=match[2])
        elif match := _XE_TRACK_OBJECT.fullmatch(line):
            group["tracked_objects"].append({"id": int(match[1]), "state": match[2],
                                             "decrement": int(match[3]) if match[3] else None,
                                             "shutdown": line.lower().endswith(" shutdown")})
        elif match := _XE_TRACK_PORT.fullmatch(line):
            group["tracked_interfaces"].append({"interface": match[1], "state": match[2],
                                                 "decrement": int(match[3]) if match[3] else None})
        elif match := _XE_CHANGES.fullmatch(line):
            group.update(state_changes=int(match[1]), last_state_change=match[2])
        else:
            for field, pattern in _XE_FHRP_LABELS.items():
                if match := re.fullmatch(pattern, line, re.I):
                    group[field] = int(match[1]) if field == "priority" else match[1]
                    return True
            return bool(_XE_FHRP_OTHER.match(line))
        return True

    required = {"state", "virtual_ip", "priority"}
    required |= {"hello_time", "hold_time", "active_router", "standby_router"} if query == "hsrp_detail" else {
        "advertisement_interval", "master_down_interval", "master_router"}
    return _xe_blocks(text, _XE_GROUP, start, consume, required)


_XE_TRACK_HEADER = re.compile(r"Track (\d+)")
_XE_TRACK_TYPE = re.compile(r"(?:IP SLA \d+ (?:state|reachability)|Interface .+|IP route .+|List .+|Stub-object.*)", re.I)
_XE_TRACK_STATE = re.compile(r"(?:State|Reachability|Line protocol|IP routing|Boolean (?:AND|OR)|Threshold) is (\S+)(?: .+)?", re.I)
_XE_TRACK_CONSUMER = re.compile(r"(?:HSRP|VRRP(?:v3)?|Static IP Routing|Track List|EEM|GLBP).+", re.I)


def xe_tracking(text):
    def consume(item, line):
        if match := _XE_TRACK_STATE.fullmatch(line):
            item["state"] = match[1]
        elif _XE_TRACK_TYPE.fullmatch(line):
            item["type"] = line
            sla = re.match(r"IP SLA (\d+)", line, re.I)
            item["ip_sla_id"] = int(sla[1]) if sla else None
        elif match := _XE_CHANGES.fullmatch(line):
            item.update(state_changes=int(match[1]), last_state_change=match[2])
        elif match := re.fullmatch(r"Latest operation return code: (.+)", line):
            item["latest_return_code"] = match[1]
        elif match := re.fullmatch(r"Latest RTT \(millisecs\) (\d+)", line):
            item["latest_rtt_ms"] = int(match[1])
        elif line == "Tracked by:":
            item["tracked_by"] = []
        elif "tracked_by" in item and _XE_TRACK_CONSUMER.fullmatch(line):
            item["tracked_by"].append(line)
        elif not re.fullmatch(r"(?:Delay up \d+(?: secs)?(?:,? down \d+(?: secs)?)?|Delay down \d+(?: secs)?"
                              r"|object \d+ (?:Up|Down)(?: .+)?)", line, re.I):
            return False
        return True

    return _xe_blocks(text, _XE_TRACK_HEADER, lambda match: {"id": int(match[1])}, consume, {"type", "state"})


_XE_SLA_FIELDS = {
    "Latest RTT": "latest_rtt", "Latest operation start time": "last_started",
    "Latest operation return code": "return_code", "Number of successes": "successes",
    "Number of failures": "failures", "Operation time to live": "time_to_live",
}


def xe_ip_sla(text):
    def consume(item, line):
        label, separator, value = line.partition(": ")
        field = _XE_SLA_FIELDS.get(label)
        if not separator or field is None or not value or field in item:
            return False
        if field in {"successes", "failures"}:
            if not re.fullmatch(r"\d+", value):
                return False
            item[field] = int(value)
        else:
            item[field] = value
        if field == "latest_rtt":
            match = re.fullmatch(r"(\d+) milliseconds", value)
            item["latest_rtt_ms"] = int(match[1]) if match else None
        return True

    return _xe_blocks(text, re.compile(r"IPSLA operation id: (\d+)"),
                      lambda match: {"id": int(match[1])}, consume, set(_XE_SLA_FIELDS.values()),
                      title="IPSLAs Latest Operation Statistics")


XE_DETAIL_KEYS = {"hsrp_detail": "hsrp", "vrrp_detail": "vrrp",
                  "object_tracking": "object_tracking", "ip_sla_statistics": "ip_sla"}


def xe_detail(query, text, capture_state):
    if query == "ip_sla_statistics":
        summary = xe_ip_sla(text)
    elif query == "object_tracking":
        summary = xe_tracking(text)
    else:
        summary = xe_gateway_detail(query, text)
    if capture_state not in {"ok", "empty"}:
        summary.update(status=capture_state or "incomplete", complete=False)
    return {XE_DETAIL_KEYS[query]: summary, "complete": summary["complete"], "status": summary["status"]}


_XE_CLOCK_DATE = re.compile(
    r"(?m)^[*.]?(\d\d:\d\d:\d\d(?:\.\d+)?) \S+ [A-Z][a-z]{2} ([A-Z][a-z]{2})\s+(\d+) (\d{4})[ \t]*$"
)
_XE_LOG_BUFFER = re.compile(r"(?m)^Log Buffer \(\d+ bytes\):[ \t]*$")
_XE_LOG_ENTRY = re.compile(
    r"(?:(?:\d+): )?[*.]?(?:([0-9]{4}) )?([A-Z][a-z]{2})\s+(\d{1,2}) "
    r"(\d\d:\d\d:\d\d(?:\.\d{1,6})?)(?: ([A-Za-z][A-Za-z0-9+_-]*))?:\s*"
    r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):\s*(.*)"
)
_XE_LOG_INTERFACE = {
    ("LINK", "UPDOWN"): re.compile(r"Interface ([\w./-]+), changed state to "),
    ("LINK", "CHANGED"): re.compile(r"Interface ([\w./-]+), changed state to "),
    ("LINEPROTO", "UPDOWN"): re.compile(r"Line protocol on Interface ([\w./-]+), changed state to "),
}
_XE_MONTHS = {name: number for number, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def _xe_log_clock(clock):
    if clock.get("ok") and (found := _XE_CLOCK_DATE.search(clock["text"])):
        try:
            return datetime.fromisoformat(f"{found[4]}-{_XE_MONTHS[found[2]]:02d}-{int(found[3]):02d}T{found[1]}")
        except (KeyError, ValueError):
            pass
    return None


def _xe_log_stamp(entry, anchor):
    year, month, day, time, _ = entry.groups()[:5]
    if not (year or anchor) or month not in _XE_MONTHS:
        return None
    month, day = _XE_MONTHS[month], int(day)
    if not year:
        # The clock and buffer can use different zones. A single day of grace at
        # the year boundary prevents December/January UTC records shifting a year.
        boundary = anchor + timedelta(days=1)
        year = boundary.year - ((month, day) > (boundary.month, boundary.day))
    try:
        return datetime.fromisoformat(f"{int(year):04d}-{month:02d}-{day:02d}T{time}")
    except ValueError:
        return None


def xe_log_history(text, parameters, clock, capture_state, limit, *, profile="cisco_xe"):
    from .query_catalog.cisco import xe_log_window
    from .read_policy import _canonical_cisco_ios_interface, _canonical_cisco_xe_interface

    start, end = xe_log_window(parameters)
    anchor = _xe_log_clock(clock)
    interface = parameters.get("interface")
    canonical_interface = (_canonical_cisco_ios_interface if profile == "cisco_ios"
                           else _canonical_cisco_xe_interface)
    scoped_interface = canonical_interface(interface, False) if interface else None
    severity = EOS_SEVERITIES.index(parameters.get("severity", "debugging"))
    selected, stamps = [], []
    scanned = unreadable = selected_count = 0
    by_severity = dict.fromkeys(EOS_SEVERITIES, 0)
    marker = _XE_LOG_BUFFER.search(text)
    if marker is not None:
        for line in text[marker.end():].splitlines():
            if not line.strip():
                continue
            scanned += 1
            entry = _XE_LOG_ENTRY.fullmatch(line)
            stamp = _xe_log_stamp(entry, anchor) if entry else None
            if stamp is None:
                unreadable += 1
                continue
            stamps.append(stamp)
            level = int(entry[7])
            if not start <= stamp < end or level > severity:
                continue
            if scoped_interface:
                pattern = _XE_LOG_INTERFACE.get((entry[6], entry[8]))
                port = pattern.match(entry[9]) if pattern else None
                if not port or canonical_interface(port[1], False) != scoped_interface:
                    continue
            selected_count += 1
            by_severity[EOS_SEVERITIES[level]] += 1
            selected.append(line)
    oldest = min(stamps, default=None)
    newest = max(stamps, default=None)
    dropped = max(0, selected_count - limit)
    starts_after_buffer = oldest is not None and oldest < start
    complete = bool(marker and capture_state == "ok" and not unreadable and not dropped
                    and starts_after_buffer and anchor is not None and end <= anchor)
    coverage = {
        "status": ("ok" if selected_count else "empty") if complete else "incomplete",
        "complete": complete, "source": "device_log_buffer", "archive_correlation": "external_archive_unavailable",
        "time_basis": "device_log_timestamp_as_printed", "clock_reason": None if anchor else clock.get("reason", "unparsed"),
        "interface_match": "local_link_or_line_protocol" if interface else None,
        "buffer_start": oldest.isoformat() if oldest else None, "buffer_end": newest.isoformat() if newest else None,
        "requested_start_covered": starts_after_buffer, "scanned_lines": scanned,
        "unreadable_lines": unreadable, "selected_messages": selected_count, "dropped_messages": dropped,
        "by_severity": by_severity,
    }
    return "".join(line + "\n" for line in selected[-limit:]), coverage


def _eos_log_local_interfaces(tag):
    pattern = _EOS_LOG_LOCAL_FIELDS.get(tag[1]) if tag else None
    match = pattern.match(tag[4]) if pattern else None
    return match.groups() if match else ()


def eos_filter_log_interface(text, interface):
    """Select complete messages whose local interface fields identify the requested interface."""
    selected, unreadable = [], 0
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        found = _EOS_LOG_LINE.fullmatch(line)
        if not found:
            unreadable += 1
            continue
        tag = _EOS_LOG_TAG.fullmatch(found[4])
        if interface in _eos_log_local_interfaces(tag):
            selected.append(raw)
    return "".join(selected), unreadable


def eos_log_summary(text, start, end, parameters=None, *, dropped_lines=0, unreadable=0):
    """Summarize `show logging last|time-range ... threshold <severity>` (cEOS 4.36.1F).

    One message per line `<Mon dd hh:mm:ss> <host> <process>: %<FACILITY>-<severity>-<MNEMONIC>: <text>`, oldest
    first, no header. Counts cover the newest 200 selected lines across pages. Entries are those whose line
    starts in [start, end) of the page. Truncation and unrecognized lines make the state incomplete. A timestamped
    line without a %FACILITY-n-MNEMONIC tag is kept with severity null. Empty output is a valid empty selection.
    """
    total, untagged, position = 0, 0, 0
    by_severity = {name: 0 for name in EOS_SEVERITIES}
    by_interface, entries = {}, []
    first = last = None
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode("utf-8"))
        line = raw.rstrip("\r\n")
        if not line.strip() or _HELPER_NOTE.fullmatch(line.strip()):
            continue
        found = _EOS_LOG_LINE.fullmatch(line)
        if not found:
            unreadable += 1
            continue
        total += 1
        first = first or found[1]
        last = found[1]
        tag = _EOS_LOG_TAG.fullmatch(found[4])
        severity = int(tag[2]) if tag else None
        if tag:
            by_severity[EOS_SEVERITIES[severity]] += 1
        else:
            untagged += 1
        message = tag[4] if tag else found[4]
        interfaces = sorted(set(_eos_log_local_interfaces(tag)))
        for name in interfaces:
            item = by_interface.setdefault(name, {"interface": name, "messages": 0, "first_time": found[1],
                                                  "last_time": None, "most_severe": None})
            item["messages"] += 1
            item["last_time"] = found[1]
            if severity is not None and (item["most_severe"] is None
                                         or severity < EOS_SEVERITIES.index(item["most_severe"])):
                item["most_severe"] = EOS_SEVERITIES[severity]
        if start <= line_start < end:
            entries.append({"time": found[1], "host": found[2], "process": found[3],
                            "facility": tag[1] if tag else None, "severity": EOS_SEVERITIES[severity] if tag else None,
                            "mnemonic": tag[3] if tag else None, "interfaces": interfaces, "text": message})
    state = "incomplete" if unreadable or dropped_lines else "ok" if total else "empty"
    window = {key: value for key, value in (parameters or {}).items()
              if key in ("minutes", "severity", "begin_date", "begin_time", "end_date", "end_time", "interface")}
    return {"state": state, "window": window, "total_messages": total, "unreadable_lines": unreadable,
            "dropped_lines": dropped_lines, "messages_without_severity": untagged, "first_time": first, "last_time": last,
            "by_severity": by_severity,
            "by_interface": sorted(by_interface.values(), key=lambda item: (-item["messages"], item["interface"])),
            "entries": entries,
            "time_note": "Times are the EOS device clock as printed, without a year; the window was applied by the "
                         "switch in its own clock and time zone."}


_TOP_LOAD = re.compile(r"top - \S+ up .*load average: ([\d.]+), ([\d.]+), ([\d.]+)\s*")
_TOP_TASKS = re.compile(r"Tasks:\s+(\d+) total,\s+(\d+) running,\s+(\d+) sleeping,\s+(\d+) stopped,\s+(\d+) zombie\s*")
_TOP_CPU = re.compile(r"%Cpu\(s\):\s*" + r",\s*".join(r"([\d.]+) " + key for key in
                                                       ("us", "sy", "ni", "id", "wa", "hi", "si", "st")) + r"\s*")
_TOP_MEM = re.compile(r"(KiB|MiB) Mem :\s+([\d.]+) total,\s+([\d.]+) free,\s+([\d.]+) used,\s+([\d.]+) buff/cache\s*")
_TOP_SWAP = re.compile(r"(KiB|MiB) Swap:\s+([\d.]+) total,\s+([\d.]+) free,\s+([\d.]+) used\.\s+([\d.]+) avail Mem\s*")
_TOP_HEAD = re.compile(r"\s*PID\s+USER\s+PR\s+NI\s+VIRT\s+RES\s+SHR\s+S\s+%CPU\s+%MEM\s+TIME\+\s+COMMAND\s*")
_TOP_ROW = re.compile(r"\s*(\d+)\s+(\S+)\s+(\S+)\s+(-?\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([A-Z])\s+([\d.]+)\s+([\d.]+)"
                      r"\s+(\S+)\s+(\S.*?)\s*")
CPU_IDLE_MIN_PERCENT = 10.0
MEMORY_AVAILABLE_MIN_PERCENT = 10.0


def eos_cpu(text):
    """Structure `show processes top once` (cEOS 4.36.1F, procps top batch frame): load, tasks, CPU states,
    memory and the five busiest processes. Findings use fixed limits: CPU idle below 10 %, available memory below
    10 % of total, zombie processes. The frame is one snapshot as the switch prints it, not an average."""
    lines = _lines(text)
    found = {}
    for name, pattern in (("load", _TOP_LOAD), ("tasks", _TOP_TASKS), ("cpu", _TOP_CPU), ("mem", _TOP_MEM),
                          ("swap", _TOP_SWAP), ("head", _TOP_HEAD)):
        hits = [index for index, line in enumerate(lines) if pattern.fullmatch(line)]
        if len(hits) != 1:
            return {"state": "unparsed", "findings": []}
        found[name] = (hits[0], pattern.fullmatch(lines[hits[0]]))
    rows, unreadable = [], 0
    for line in lines[found["head"][0] + 1:]:
        if not line.strip():
            continue
        row = _TOP_ROW.fullmatch(line)
        if not row:
            unreadable += 1
            continue
        rows.append({"pid": int(row[1]), "user": row[2], "cpu_percent": float(row[9]), "memory_percent": float(row[10]),
                     "command": row[12]})
    load, tasks, cpu, mem, swap = (found[name][1] for name in ("load", "tasks", "cpu", "mem", "swap"))
    scale = 1 / 1024 if mem[1] == "KiB" else 1
    memory = {"total_mib": round(float(mem[2]) * scale, 1), "free_mib": round(float(mem[3]) * scale, 1),
              "used_mib": round(float(mem[4]) * scale, 1), "buff_cache_mib": round(float(mem[5]) * scale, 1),
              "available_mib": round(float(swap[5]) * (1 / 1024 if swap[1] == "KiB" else 1), 1)}
    cpu_states = dict(zip(("user", "system", "nice", "idle", "iowait", "hardware_irq", "software_irq", "steal"),
                          (float(value) for value in cpu.groups())))
    task_counts = dict(zip(("total", "running", "sleeping", "stopped", "zombie"), (int(value) for value in tasks.groups())))
    findings = []
    if cpu_states["idle"] < CPU_IDLE_MIN_PERCENT:
        findings.append({"id": "F-EOS-CPU-BUSY", "fact": "CPU idle %.1f %% < %.0f %%" % (cpu_states["idle"], CPU_IDLE_MIN_PERCENT)})
    if memory["total_mib"] and memory["available_mib"] * 100 / memory["total_mib"] < MEMORY_AVAILABLE_MIN_PERCENT:
        findings.append({"id": "F-EOS-MEMORY-LOW", "fact": "available memory %.1f of %.1f MiB < %.0f %%" % (
            memory["available_mib"], memory["total_mib"], MEMORY_AVAILABLE_MIN_PERCENT)})
    if task_counts["zombie"]:
        findings.append({"id": "F-EOS-ZOMBIE", "fact": "%d zombie processes" % task_counts["zombie"]})
    return {"state": "incomplete" if unreadable or len(rows) != task_counts["total"] else "ok",
            "load_average": [float(value) for value in load.groups()], "tasks": task_counts,
            "cpu_percent": cpu_states, "memory": memory, "process_count": len(rows), "unreadable_lines": unreadable,
            "top_processes": sorted(rows, key=lambda row: (-row["cpu_percent"], row["pid"]))[:5],
            "findings": findings}


def eos_reload_cause(text):
    """Structure `show reload cause` (cEOS 4.36.1F): titled sections underlined with dashes. The Reload Cause
    section is required; Recommended Action and Debugging Information are listed when present."""
    lines = _lines(text)
    sections, current = {}, None
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        if re.fullmatch(r"-+", line.strip()):
            if current is None or sections[current]:
                return {"state": "unparsed", "causes": []}
            continue
        title = re.fullmatch(r"(\S[^:]*):", line.strip())
        if title and index + 1 < len(lines) and re.fullmatch(r"-+", lines[index + 1].strip()):
            current = title[1]
            if current in sections:
                return {"state": "unparsed", "causes": []}
            sections[current] = []
            continue
        if current is None:
            return {"state": "unparsed", "causes": []}
        sections[current].append(line.strip())
    if "Reload Cause" not in sections:
        return {"state": "unparsed", "causes": []}
    known = {"Reload Cause", "Recommended Action", "Debugging Information"}
    return {"state": "ok" if set(sections) <= known else "incomplete",
            "causes": sections["Reload Cause"],
            "recommended_action": sections.get("Recommended Action") or [],
            "debugging_information_lines": len(sections.get("Debugging Information", ())),
            "other_sections": sorted(set(sections) - known)}


def eos_ntp_status(text):
    """Structure `show ntp status`. `NTP is disabled.` is measured on cEOS 4.36.1F; the synchronized form
    `synchronized to NTP server (<address>) at stratum <n>` and the state word `unsynchronised` follow the Arista
    Switch Administration Commands guide (https://www.arista.com/en/um-eos/eos-switch-administration-commands)."""
    body = [line.strip() for line in _lines(text) if line.strip()]
    if body == ["NTP is disabled."]:
        return {"state": "ok", "enabled": False, "synchronized": None, "server": None, "stratum": None, "findings": []}
    head = body[0] if body else ""
    found = re.fullmatch(r"synchroni[sz]ed to (?:NTP server|local clock) ?(?:\(([0-9A-Fa-f:.]+)\))? at stratum (\d+)", head)
    if found:
        return {"state": "ok", "enabled": True, "synchronized": True, "server": found[1], "stratum": int(found[2]),
                "findings": []}
    if re.fullmatch(r"unsynchroni[sz]ed\b.*", head):
        return {"state": "ok", "enabled": True, "synchronized": False, "server": None, "stratum": None,
                "findings": [{"id": "F-EOS-NTP-UNSYNC", "fact": head}]}
    return {"state": "unparsed", "enabled": None, "synchronized": None, "server": None, "stratum": None, "findings": []}


_EOS_ENVIRONMENT_FIELDS = {
    "System temperature status is": "temperature_status",
    "Action on overheat": "action_on_overheat",
    "Recovery mode when power-cycle upon overheat": "overheat_recovery_mode",
    "Restrict recovery when ambient temperature is at or above": "overheat_recovery_limit",
    "System cooling status is": "cooling_status",
    "Number of cooling zones is": "cooling_zones",
}
_EOS_NO_POWER_SUPPLIES = re.compile(r"% There seem to be no power supplies connected\.(?: at line \d+)?")


def eos_environment(text):
    """Extract available environment fields from the cEOS 4.36.1F capture."""
    fields, unreadable = {}, 0
    for raw in _lines(text):
        line = raw.strip()
        if not line or line == "> show system environment all":
            continue
        if _EOS_NO_POWER_SUPPLIES.fullmatch(line):
            fields["power_supplies_present"] = False
            continue
        label, _, value = line.partition(":")
        key = _EOS_ENVIRONMENT_FIELDS.get(label)
        value = value.strip()
        if not key or not value or key in fields or (key == "cooling_zones" and not re.fullmatch(r"[0-9]{1,9}", value)):
            unreadable += 1
            continue
        fields[key] = int(value) if key == "cooling_zones" else value
    state = "unparsed" if not fields else "incomplete"
    if not unreadable and {"temperature_status", "cooling_status"} <= fields.keys() and "power_supplies_present" not in fields:
        state = "ok"
    return {"state": state, **fields, "unreadable_lines": unreadable}


def eos_health_payload(query, text, capture_state, start=0, end=0, parameters=None, line_limit=None, unreadable=0):
    """The structured eos health object of one EOS ssh_read; only a complete capture is summarized as measured."""
    if query in EOS_LOG_WINDOW_QUERIES:
        dropped = line_limit["total_lines"] - line_limit["returned_lines"] if line_limit else 0
        summary = eos_log_summary(text, start, end, parameters, dropped_lines=dropped, unreadable=unreadable)
        key = "log_summary"
    elif query == "cpu":
        summary, key = eos_cpu(text), "cpu_summary"
    elif query == "reload_cause":
        summary, key = eos_reload_cause(text), "reload_cause_summary"
    elif query == "ntp_status":
        summary, key = eos_ntp_status(text), "ntp_summary"
    elif query == "environment":
        summary, key = eos_environment(text), "environment_summary"
    else:
        return {}
    if capture_state not in (None, "ok", "empty") and summary["state"] in ("ok", "empty"):
        summary["state"] = "incomplete"
    return {key: summary}


# Unleashed reports controller resources and current AP roles separately from radio mesh topology.
_RUCKUS_HEALTH_FIELDS = {
    "System Overview": {"Uptime": "uptime"},
    "Devices Overview": {"Number of APs": "ap_count"},
    "Memory Utilization": {"Used Bytes": "used_kb", "Free Bytes": "free_kb",
                           "Used Percentage": "used_percent", "Free Percentage": "free_percent"},
    "Dedicated Master": {"Status": "enabled"},
    "Smart Redundancy": {"Status": "enabled", "Local Connect Status": "local_status",
                         "Peer Connect Status": "peer_status", "Peer IP Address": "peer_ip"},
}
_RUCKUS_HEALTH_NUMBERS = {"ap_count": r"(\d+)", "used_kb": r"(\d+)\s*\(kB\)",
                         "free_kb": r"(\d+)\s*\(kB\)", "used_percent": r"(\d+)%", "free_percent": r"(\d+)%"}
_RUCKUS_REBOOT = re.compile(r"Activities= AP\[[^\]]*?(" + r"(?:[\da-f]{2}:){5}[\da-f]{2}"
                            r")\] warm boot successfully,\s*last reboot reason \[([^\]]+)\]\.?", re.IGNORECASE)
_RUCKUS_REJOIN = re.compile(r"Activities= AP\[[^\]]*?(" + r"(?:[\da-f]{2}:){5}[\da-f]{2}"
                            r")\] joins with uptime \[\d+\] s and last disconnected reason \[([^\]]+)\]\.?",
                            re.IGNORECASE)
_RUCKUS_AP_REFERENCE = r"(?:AP\[[^\[\]]+\]|[\w:.-]+)"
_RUCKUS_MESH_DISCONNECT = re.compile(
    rf"(?:Activities\s*=\s*)?Mesh (?P<ap>{_RUCKUS_AP_REFERENCE}) disconnects from "
    rf"(?P<root_ap>{_RUCKUS_AP_REFERENCE})", re.IGNORECASE)


def _ruckus_system_health(text):
    from . import wifi_parse

    data = {section: {} for section in _RUCKUS_HEALTH_FIELDS}
    unparsed = []
    for number, path, key, value in wifi_parse._ruckus_walk(text):
        if len(path) != 1 or path[0] not in data or value is None:
            continue
        fields = data[path[0]]
        field = _RUCKUS_HEALTH_FIELDS[path[0]].get(key)
        if field is None:
            continue
        pattern = _RUCKUS_HEALTH_NUMBERS.get(field)
        match = re.fullmatch(pattern, value) if pattern else None
        if not value or value == "\0" or field in fields or (pattern and match is None):
            unparsed.append(number)
        else:
            fields[field] = int(match[1]) if match else value
    return data, unparsed


def _ruckus_ap_history(history):
    """Most recent retained reboot and rejoin with an explicit reason, by AP MAC."""
    observations = {}
    for event in history:
        if not event["time"]:
            continue
        for label, pattern in (("last_reported_restart", _RUCKUS_REBOOT), ("last_reported_rejoin", _RUCKUS_REJOIN)):
            match = pattern.fullmatch(event["message"] or "")
            if match:
                observations.setdefault(match[1].lower(), {}).setdefault(
                    label, {"time": event["time"], "reason": match[2]})
    return observations


def _ruckus_mesh_disconnects(history):
    """Retained mesh-to-root disconnections, including APs absent from current inventory."""
    disconnects = []
    for event in history:
        match = _RUCKUS_MESH_DISCONNECT.fullmatch(event["message"] or "")
        if match and event["time"]:
            disconnects.append({"time": event["time"], "severity": event["severity"], **match.groupdict()})
    return disconnects


def run_ruckus(read, clock, enabled_queries):
    from . import wifi_parse, triage_wifi

    started = clock()
    missing, findings, checked, sources = [], [], [], {}

    def get(query):
        if query not in enabled_queries:
            missing.append({"step": query, "reason": "not_enabled"})
            return None
        moment = clock()
        answer = read(query)
        if not answer.get("ok") or answer.get("absent"):
            missing.append(missing_read(query, answer))
            return None
        sources[query] = {"call": "triage_health", "query": query,
                          "content_sha256": answer["content_sha256"], "captured_at": _utc(moment)}
        return answer["text"]

    def parse(query):
        text = get(query)
        if text is None:
            return None
        result = wifi_parse.summarize_ruckus(query, text)
        if result["unparsed_count"] or result.get("incomplete"):
            missing.append({"step": query, "reason": "unparsed" if result["unparsed_count"] else "incomplete",
                            "lines": result["unparsed"]})
        else:
            checked.append(query)
        return result["records"]

    identity, system = {}, {}
    sysinfo = get("system_info")
    if sysinfo is not None:
        try:
            identity = triage_wifi.ruckus_identity(sysinfo)
        except UnsupportedPlatform:
            pass
        system, lines = _ruckus_system_health(sysinfo)
        if lines or not identity or not system["System Overview"].get("uptime") or (
                system["Devices Overview"].get("ap_count") is None
                or len(system["Memory Utilization"]) != len(_RUCKUS_HEALTH_FIELDS["Memory Utilization"])):
            missing.append({"step": "system_info", "reason": "incomplete", "lines": lines[:20]})
        else:
            checked.append("system_info")
    support = triage_wifi.ruckus_support(identity, "triage_health")

    aps = parse("access_points")
    ethernet = parse("ethernet_info")
    event_query = "events_activities" if "events_activities" in enabled_queries else "events"
    events = parse(event_query)
    history = _ruckus_ap_history(events or [])
    mesh = parse("mesh_topology")

    master_macs = [ap["mac"] for ap in aps or [] if ap["mac"] and (ap["role"] or "").lower() == "master"]
    reported_count = system.get("Devices Overview", {}).get("ap_count")
    expected_master = identity.get("mac")
    dedicated = system.get("Dedicated Master") or {}
    dedicated_enabled = dedicated.get("enabled") == "Enabled"
    redundancy = system.get("Smart Redundancy") or None
    if dedicated_enabled and redundancy is None:
        missing.append({"step": "system_info", "reason": "incomplete",
                        "detail": "Dedicated Master is enabled but Smart Redundancy status is unavailable"})
    elif redundancy and redundancy.get("enabled") == "Enabled":
        local, peer = redundancy.get("local_status"), redundancy.get("peer_status")
        if not redundancy.get("peer_ip") or {local, peer} != {"Active", "Standby"}:
            missing.append({"step": "system_info", "reason": "incomplete",
                            "detail": "Smart Redundancy does not report an active and a standby endpoint"})
    inventory_complete = "access_points" in checked and "system_info" in checked
    if inventory_complete and (reported_count != len(aps) or master_macs != [expected_master]):
        inventory_complete = False
        missing.append({"step": "access_points", "reason": "incomplete",
                        "detail": "AP count or master MAC differs between system and AP inventory"})

    for ap in aps or []:
        observations = history.get(ap["mac"], {})
        ap["last_reported_restart"] = observations.get("last_reported_restart")
        ap["last_reported_rejoin"] = observations.get("last_reported_rejoin")
        ap["active_wired_ports"] = [port["interface"] for port in ap["lan_ports"]
                                   if port["interface"] and (port["logical_link"] or "").lower() == "up"]
        if not (ap["role"] and ap["mesh"] and ap.get("poe_mode") and ap["lan_ports"]
                and all(port["interface"] and port["physical_link"] for port in ap["lan_ports"])):
            missing.append({"step": "access_points", "reason": "incomplete",
                            "detail": "A listed AP lacks role, mesh, PoE or LAN link facts", "mac": ap["mac"]})
        # Dedicated Master runs as a controller with its radios disabled.
        is_dedicated_master = dedicated_enabled and expected_master is not None and ap["mac"] == expected_master
        if not ap["radios"] and not is_dedicated_master:
            missing.append({"step": "access_points", "reason": "incomplete",
                            "detail": "A listed AP lacks radio blocks", "mac": ap["mac"]})

    if inventory_complete and "mesh_topology" in checked:
        inventory = {ap["mac"] for ap in aps}
        if any(row["mac"] not in inventory for row in mesh):
            missing.append({"step": "mesh_topology", "reason": "incomplete",
                            "detail": "Mesh topology contains an AP absent from the AP inventory"})
        if any(row["role"] == "mesh" and row["uplink_db"] is None for row in mesh):
            missing.append({"step": "mesh_topology", "reason": "incomplete",
                            "detail": "One or more mesh members do not report uplink signal"})
        if not mesh and any((ap["mesh"] or "").lower() in {"root ap", "mesh ap"} for ap in aps):
            missing.append({"step": "mesh_topology", "reason": "incomplete",
                            "detail": "An AP has an explicit mesh role but the topology lists no APs"})

    master = next((ap for ap in aps or [] if ap["mac"] == expected_master and ap["mac"] in master_macs), None)
    if inventory_complete and "ethernet_info" in checked and master is not None:
        port_status = {row["interface"]: row["physical_link"].lower() for row in ethernet}
        if any(port_status.get(port["interface"]) != port["physical_link"].split()[0].lower()
               for port in master["lan_ports"] if port["physical_link"]):
            missing.append({"step": "ethernet_info", "reason": "incomplete",
                            "detail": "Master Ethernet link states differ between the Ethernet read and AP inventory"})
        elif (master["lan_ports"] and not master["active_wired_ports"]
              and all(state == "down" for state in port_status.values())
              and (master["mesh"] or "").lower() == "disabled"):
            findings.append({"rule": "no_master_wired_link", "severity": "fault", "mac": expected_master,
                             "sources": [sources[query] for query in ("access_points", "ethernet_info")]})

    return {
        "ok": sysinfo is not None, "platform": "ruckus_unleashed", "identity": identity or None,
        "started_at": _utc(started), "finished_at": _utc(clock()),
        "chain": {
            "resources": {"uptime": system.get("System Overview", {}).get("uptime"),
                          "memory": system.get("Memory Utilization") or None},
            "ethernet": {"controller_mac": expected_master, "ports": ethernet},
            "access_points": aps, "reported_ap_count": reported_count,
            "master": {"macs": master_macs, "dedicated": dedicated or None,
                       "smart_redundancy": redundancy},
            "mesh_topology": mesh,
            "mesh_disconnect_events": _ruckus_mesh_disconnects(events) if events is not None else None,
        },
        "unavailable_metrics": ["CPU utilization", "Ethernet error counters", "member firmware versions"],
        "checked": checked, "missing": missing, "findings": findings, "sources": sources,
        "verdict": "incomplete" if missing else "fault_found" if findings else "no_fault_in_checked_data",
        **firmware_fields(support),
    }


NXOS_HEALTH_QUERIES = ("version", "system_resources", "environment", "modules", "processes_cpu",
                       "ntp_status", "ntp_associations")
_NXOS_LOAD = re.compile(r"(?m)^Load average:\s+1 minute: (\d+(?:\.\d+)?)\s+5 minutes: (\d+(?:\.\d+)?)\s+15 minutes: (\d+(?:\.\d+)?)$")
_NXOS_CPU = re.compile(r"(?m)^CPU states\s*:\s+(\d+(?:\.\d+)?)% user,\s+(\d+(?:\.\d+)?)% kernel,\s+(\d+(?:\.\d+)?)% idle$")
_NXOS_MEMORY = re.compile(r"(?m)^Memory usage:\s+(\d+)K total,\s+(\d+)K used,\s+(\d+)K free$")
_NXOS_TREND = re.compile(r"(?m)^CPU utilization for five seconds: (\d+)%/(\d+)%; one minute: (\d+)%; five minutes: (\d+)%$")
_NXOS_PROCESS = re.compile(r"\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+(?:\.\d+)?)%\s+(\S+)\s*")
_NXOS_MODULE = re.compile(r"(\d+)\s+(\d+)\s+(.+?)\s{2,}(\S+)\s{2,}(.+?)\s*")
_NXOS_NTP_STATUS = re.compile(r"Distribution\s*:\s*(Enabled|Disabled)\s+Last operational state:\s*([^\n]+)")
_NXOS_NTP_PEER = re.compile(r"([*+=-]?)(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+([0-7]{1,3})\s+"
                            r"(\d+\.\d+)\s*([\w.-]*)")


def nxos_resources(text):
    data = {}
    if load := _NXOS_LOAD.search(text):
        data["load_average"] = dict(zip(("one_minute", "five_minutes", "fifteen_minutes"), map(float, load.groups())))
    if cpu := _NXOS_CPU.search(text):
        data["cpu_percent"] = dict(zip(("user", "kernel", "idle"), map(float, cpu.groups())))
    if memory := _NXOS_MEMORY.search(text):
        data["memory_kib"] = dict(zip(("total", "used", "free"), map(int, memory.groups())))
    if state := re.search(r"(?m)^Current memory status:\s+(\S+)\s*$", text):
        data["memory_status"] = state[1]
    return data, len(data) == 4


def nxos_cpu_trend(text):
    processes = [{"pid": int(row[1]), "cpu_one_second_percent": float(row[2]), "process": row[3]}
                 for line in text.splitlines() if (row := _NXOS_PROCESS.fullmatch(line))]
    data = {"top_processes": sorted(processes, key=lambda row: -row["cpu_one_second_percent"])[:5]}
    trend = _NXOS_TREND.search(text)
    if trend:
        data.update(dict(zip(("five_seconds_percent", "interrupt_five_seconds_percent", "one_minute_percent",
                              "five_minutes_percent"), map(int, trend.groups()))))
    table = text.split("CPU util", 1)[0]
    row_count = sum(line.lstrip()[:1].isdigit() for line in table.splitlines())
    return data, bool(processes and trend) and row_count == len(processes)


def nxos_modules(text):
    rows = []
    first_table = text.strip().split("\n\n", 1)[0].splitlines()
    if len(first_table) < 2 or not first_table[0].startswith("Mod Ports "):
        return rows, False
    for line in first_table[2:]:
        if row := _NXOS_MODULE.fullmatch(line):
            rows.append({"slot": int(row[1]), "ports": int(row[2]), "model": row[4], "state": row[5].removesuffix(" *")})
    header = re.search(r"(?m)^Mod[ \t]+Online Diag Status[ \t]*\n---[ \t]+-+[ \t]*\n", text)
    if not header:
        return rows, False
    diagnostic_lines = re.split(r"\n[ \t]*\n", text[header.end():], maxsplit=1)[0].splitlines()
    diagnostics = {}
    for line in diagnostic_lines:
        if match := re.fullmatch(r"[ \t]*(\d+)[ \t]+(Pass|Fail)[ \t]*", line, re.I):
            diagnostics[int(match[1])] = match[2]
    for row in rows:
        if row["slot"] in diagnostics:
            row["online_diagnostic_status"] = diagnostics[row["slot"]]
    return rows, (bool(rows) and len(rows) == len(first_table) - 2
                  and len(diagnostics) == len(diagnostic_lines) == len(rows)
                  and diagnostics.keys() == {row["slot"] for row in rows})


def nxos_environment(text):
    section = None
    tables = {"fan": [], "temperature": [], "power": []}
    unavailable = []
    unknown = 0
    for line in map(str.strip, text.splitlines()):
        if line in {"Fan:", "Temperature:", "Power Supply:"}:
            section = {"Fan:": "fan", "Temperature:": "temperature", "Power Supply:": "power"}[line]
        elif line == "Power Usage Summary:":
            section = "power_usage"
        elif line.startswith("No power info, as no System Controller Module"):
            unavailable.append("power")
        elif (not line.strip("- ") or line.startswith(
                ("Fan ", "Module   Sensor", "(Celsius)", "Voltage:", "Power ", "Supply ", "(Watts"))):
            continue
        elif section == "power_usage" and line.startswith("Total "):
            continue
        elif section == "temperature" and (row := re.fullmatch(
                r"(\d+)\s+(\S+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(\S+)", line)):
            tables[section].append({"module": int(row[1]), "sensor": row[2], "major_celsius": int(row[3]),
                                    "minor_celsius": int(row[4]), "current_celsius": int(row[5]), "state": row[6]})
        elif section == "power" and (row := re.fullmatch(
                r"(\d+)\s+(\S+)\s+(\d+) W\s+(\d+) W\s+(\d+) W\s+(.+)", line)):
            tables[section].append({"supply": int(row[1]), "model": row[2], "output_watts": int(row[3]),
                                    "input_watts": int(row[4]), "capacity_watts": int(row[5]), "state": row[6]})
        elif section == "fan" and (row := re.fullmatch(r"(\S+)\s+(?:(\S+)\s+)?(\S+)\s+(\S+)\s+(\S+)", line)):
            tables[section].append({"fan": row[1], "model": row[2], "direction": row[4], "state": row[5]})
        else:
            unknown += 1
    unavailable.extend(name for name, readings in tables.items() if not readings and name not in unavailable)
    return {**tables, "unavailable": unavailable, "unparsed_lines": unknown}, not unavailable and unknown == 0


def nxos_ntp(distribution, peer_status):
    result = {"synchronized": None, "offset_ms": None, "offset_status": "not_reported", "peers": []}
    status_match = _NXOS_NTP_STATUS.fullmatch(distribution.strip()) if distribution is not None else None
    if status_match:
        result.update(distribution=status_match[1].lower(), distribution_state=status_match[2])
    if peer_status is None:
        return result, False, bool(status_match)
    lines = peer_status.strip().splitlines()
    declared = re.fullmatch(r"Total peers\s*:\s*(\d+)", lines[0]) if lines else None
    unparsed = 0
    for line in lines[1:]:
        line = line.strip()
        if (not line or set(line) == {"-"} or line.startswith(("- selected for sync", "* - selected for sync",
                                                              "- - peer mode", "remote "))):
            continue
        peer = _NXOS_NTP_PEER.fullmatch(line)
        if not peer or int(peer[6], 8) > 255:
            unparsed += 1
            continue
        mark, remote, local, stratum, poll, reach, delay, vrf = peer.groups()
        result["peers"].append({"remote": remote, "local": local, "vrf": vrf or None, "stratum": int(stratum),
                                "poll_seconds": int(poll), "reach_octal": reach, "delay_ms": float(delay),
                                "reachable": bool(int(reach, 8)), "selected": mark == "*"})
    peers = result["peers"]
    complete = not lines or (declared is not None and int(declared[1]) == len(peers) and not unparsed)
    selected = [peer for peer in peers if peer["selected"]]
    if len(selected) > 1 or any(not peer["reachable"] or peer["stratum"] == 16 for peer in selected):
        complete = False
    if complete:
        result["synchronized"] = bool(selected)
    return result, complete, bool(status_match)


def run_nxos(read, clock):
    from netops_core import tested
    from .normalization import IdentityError, parse_identity

    captured_at = _utc(clock())
    identity = None
    fields, missing, sources, findings = {}, [], [], []
    ntp = {}
    parsers = {"system_resources": nxos_resources, "processes_cpu": nxos_cpu_trend,
               "modules": nxos_modules, "environment": nxos_environment}
    for query in NXOS_HEALTH_QUERIES:
        answer = read(query)
        if not answer["ok"]:
            missing.append(missing_read(query, answer))
        else:
            sources.append({key: answer[key] for key in ("query", "content_sha256", "total_bytes")})
            text = answer["text"]
            if query == "version":
                try:
                    identity = parse_identity("cisco_nxos", text)
                except IdentityError:
                    pass
                if not identity or not identity.get("uptime"):
                    missing.append({"step": query, "reason": "unparsed"})
            elif query in parsers:
                fields[query], complete = parsers[query](text)
                if not complete:
                    no_sensors = (query == "environment" and not fields[query]["unparsed_lines"]
                                  and len(fields[query]["unavailable"]) == 3 and "No power info" in text)
                    missing.append({"step": query, "reason": "not_applicable" if no_sensors else "unparsed"})
            else:
                ntp[query] = text
        if query == "version" and identity is None:
            break

    if ntp:
        fields["ntp"], peers_complete, status_complete = nxos_ntp(ntp.get("ntp_status"), ntp.get("ntp_associations"))
        for query, complete in (("ntp_status", status_complete), ("ntp_associations", peers_complete)):
            if query in ntp and not complete:
                missing.append({"step": query, "reason": "unparsed"})
        if peers_complete and not fields["ntp"]["synchronized"]:
            findings.append({"rule": "ntp_not_synchronized", "query": "ntp_associations"})
        if any(not peer["reachable"] for peer in fields["ntp"]["peers"]):
            findings.append({"rule": "ntp_peer_unreachable", "query": "ntp_associations"})
    if fields.get("system_resources", {}).get("memory_status", "OK") != "OK":
        findings.append({"rule": "memory_status", "query": "system_resources"})
    if any(row["state"].lower() not in {"ok", "active", "standby", "ha-standby"}
           or row.get("online_diagnostic_status", "").lower() == "fail" for row in fields.get("modules", [])):
        findings.append({"rule": "module_status", "query": "modules"})
    if any(row["state"].lower() not in {"ok", "none", "absent", "notpresent"} for name in ("fan", "temperature", "power")
           for row in fields.get("environment", {}).get(name, [])):
        findings.append({"rule": "environment_status", "query": "environment"})
    support = (firmware_fields(tested.support("NX-OS", identity["os_version"], ("9.3(12)",),
                                  model=identity["model"], function="triage_health")) if identity else {})
    return {"ok": identity is not None, "captured_at": captured_at, "identity": identity, **fields, **support,
            "sources": sources, "missing": missing, "complete": not missing, "findings": findings,
            "verdict": "incomplete" if missing else "fault_found" if findings else "no_fault_in_checked_data"}


_NXOS_LOG_ENTRY = re.compile(
    r"(?P<time>\d{4} [A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d(?:\.\d{1,6})?)\s+"
    r"(?:\S+\s+)?%(?P<facility>[A-Z\d_]+)-(?P<severity>[0-7])-(?P<event>[A-Z\d_]+):(?P<body>.*)"
)
_NXOS_LOG_IFACE = re.compile(r"(?<![\w/])(?P<kind>Ethernet|Eth|Port-channel|Po|Vlan|Vl|mgmt|Loopback|Lo|Tunnel|Tu)"
                            r"(?P<slot>\d+(?:/\d+)*(?:\.\d+)?)(?![\w/.-])", re.I)
_NXOS_LOG_PRIVATE = re.compile(
    r"(?i)\b(?:snmp-server[ \t]+user|auth|priv|pass(?:word|wd|phrase)|secret|key(?:-string)?|"
    r"community|authentication|token|credential|ENC|PSK)\b"
)
_NXOS_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def nxos_log_history(text, parameters, capture_state):
    from .query_catalog.cisco import nxos_log_window
    from .read_policy import LOG_SEVERITIES

    window = nxos_log_window(parameters)
    limit = int(parameters["count"])
    threshold = LOG_SEVERITIES.index(parameters["severity"]) if "severity" in parameters else 7
    aliases = {"eth": "ethernet", "po": "port-channel", "lo": "loopback", "vl": "vlan", "tu": "tunnel"}
    interface = parameters.get("interface", "").lower()
    events, timestamps = [], []
    unparsed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _NXOS_LOG_ENTRY.fullmatch(line)
        if not match:
            unparsed += 1
            continue
        try:
            year, month, day, time = match["time"].split()
            iso = f"{year}-{_NXOS_MONTHS.index(month) + 1:02d}-{int(day):02d}T{time}"
            timestamp = datetime.fromisoformat(iso)
        except ValueError:
            unparsed += 1
            continue
        timestamps.append(timestamp)
        body = match["body"]
        if match["facility"] in {"PARSER", "VSHD", "VSHD_MGR"} or _NXOS_LOG_PRIVATE.search(body):
            body = " <REDACTED>"
            line = line[:match.start("body")] + body
        ports = {aliases.get(kind.lower(), kind.lower()) + slot for kind, slot in _NXOS_LOG_IFACE.findall(body)}
        if (int(match["severity"]) > threshold or (interface and interface not in ports)
                or (window and not window[0] <= timestamp < window[1])):
            continue
        events.append(line)
    ordered = timestamps == sorted(timestamps)
    covered = (bool(timestamps) and timestamps[0] <= window[0] and timestamps[-1] >= window[1]
               if window else len(timestamps) < limit)
    ended_at_line_boundary = not text.strip() or text.endswith("\n")
    complete = capture_state in {"ok", "empty"} and not unparsed and ordered and covered and ended_at_line_boundary
    filtered = "\n".join(events) + ("\n" if events else "")
    return (filtered if text.strip() else text), {
        "source": "local_logfile", "requested_lines": limit, "scanned_events": len(timestamps),
        "matched_events": len(events), "unparsed_lines": unparsed, "complete": complete,
        "oldest": timestamps[0].isoformat() if timestamps else None,
        "newest": timestamps[-1].isoformat() if timestamps else None,
        "status": ("ok" if events else "empty") if complete else "incomplete",
    }


def nxos_logging_info(text, capture_state):
    state = re.search(r"(?mi)^Logging server:[ \t]+(enabled|disabled)\.?[ \t]*$", text)
    enabled = state[1].lower() == "enabled" if state else None
    targets, target = [], None
    unparsed = 0
    if enabled:
        for line in map(str.strip, text[state.end():].splitlines()):
            if not line:
                continue
            if line.startswith(("Logging ", "Facility")):
                break
            if match := re.fullmatch(r"\{([\w.:%-]+)\}", line):
                target = {"destination": match[1]}
                targets.append(target)
            elif target is not None and (row := re.fullmatch(
                    r"server (status|severity|facility|vrf|port|transport|forwarding):\s*(.+)", line, re.I)):
                target[row[1].lower()] = row[2]
            elif target is not None and line == "This server is temporarily unreachable":
                target["notice"] = line
            else:
                unparsed += 1
    complete = capture_state == "ok" and not unparsed and (
        enabled is False or (bool(targets) and all({"severity", "facility", "vrf", "port"} <= row.keys()
                                                  for row in targets)))
    return {"enabled": enabled, "destinations": targets, "complete": complete,
            "status": "ok" if complete else "incomplete"}


NXOS_GATEWAY_QUERIES = frozenset({"hsrp_detail", "vrrp_detail", "vrrpv3_detail", "object_tracking"})
_NXOS_HSRP_GROUP = re.compile(r"(\S+) - Group (\d+) \(HSRP-V(\d+)\) \((IPv[46])\)")
_NXOS_VRRP_GROUP = re.compile(r"(\S+) - Group (\d+)(?: - Address-Family (IPv[46])| \((IPV[46])\))?")
_NXOS_HSRP_HISTORY = re.compile(r"(\(\d+\)-\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+(.+)")
_NXOS_VRRP_TRANSITION = re.compile(r"(Init|Master|Backup) to (init|master|backup): (\d+)(?: \(Last change (.+)\))?")
_NXOS_GATEWAY_IGNORED = re.compile(
    r"(?:Auth(?:entication)?\b|Virtual (?:MAC|mac) address|Description is |Next hello |"
    r"Forwarding threshold|Preemption |IP redundancy name|VRRPv[23] Advertisements:|Group Discarded Packets:|"
    r"VRRPv2 incompatibility:|IP Address Owner conflicts:|Invalid address count:|"
    r"IP address configuration mismatch\s*:|Invalid Advert Interval:|Adverts received in Init state:|"
    r"Invalid group other reason:|Group State transition:|----- Detailed information -----|State History|"
    r"Time\s+Prev State\s+State\s+Event|-{3,})", re.I,
)


def nxos_gateway_detail(query, text, capture_state):
    def consume(record, line):
        if match := re.fullmatch(r"Local state is (\w+), priority (\d+)(?: .+)?", line):
            record.update(state=match[1], priority=int(match[2]))
        elif match := re.fullmatch(r"Priority (\d+), Configured (\d+)", line):
            record.update(priority=int(match[1]), configured_priority=int(match[2]))
        elif match := re.fullmatch(r"Advertisement interval (\d+)", line):
            record["advertisement_interval"] = match[1]
        elif match := re.fullmatch(r"Hellotime (.+), holdtime (.+)", line):
            record.update(hello_time=match[1], hold_time=match[2])
        elif match := _XE_CHANGES.fullmatch(line):
            record.update(state_changes=int(match[1]), last_state_change=match[2])
        elif match := _NXOS_HSRP_HISTORY.fullmatch(line):
            record.setdefault("history", []).append(dict(zip(("time", "previous", "current", "event"), match.groups())))
        elif match := _NXOS_VRRP_TRANSITION.fullmatch(line):
            record.setdefault("transitions", []).append(
                {"previous": match[1].lower(), "current": match[2], "count": int(match[3]), "last_change": match[4]})
        elif match := _XE_TRACK_OBJECT.fullmatch(line):
            record.setdefault("tracked_objects", []).append(
                {"id": int(match[1]), "state": match[2], "decrement": int(match[3]) if match[3] else None})
        elif match := _XE_TRACK_PORT.fullmatch(line):
            record.setdefault("tracked_interfaces", []).append(
                {"interface": match[1], "state": match[2], "decrement": int(match[3]) if match[3] else None})
        elif line == "Virtual secondary IP addresses:":
            record["secondary_addresses"] = []
        else:
            for label, pattern in _XE_FHRP_LABELS.items():
                if match := re.fullmatch(pattern, line, re.I):
                    record[label] = int(match[1]) if label == "priority" else match[1]
                    return True
            if "secondary_addresses" in record and re.fullmatch(r"[0-9a-f:.]+(?:/\d+)?", line, re.I):
                record["secondary_addresses"].append(line)
            else:
                return bool(_NXOS_GATEWAY_IGNORED.match(line))
        return True

    if query == "object_tracking":
        summary = xe_tracking(text)
    elif query == "hsrp_detail":
        summary = _xe_blocks(text, _NXOS_HSRP_GROUP,
                             lambda m: {"interface": m[1], "id": int(m[2]), "version": int(m[3]), "family": m[4]},
                             consume, {"state", "priority", "hello_time", "hold_time", "virtual_ip",
                                       "active_router", "standby_router"})
    else:
        summary = _xe_blocks(text, _NXOS_VRRP_GROUP,
                             lambda m: {"interface": m[1], "id": int(m[2]), "family": (m[3] or m[4] or "").lower() or None,
                                        "version": 3 if query == "vrrpv3_detail" else 2},
                             consume, {"state", "priority", "advertisement_interval", "virtual_ip", "master_router"})
    if capture_state not in {"ok", "empty"}:
        summary.update(status="incomplete" if capture_state == "truncated" else capture_state, complete=False)
    return summary
