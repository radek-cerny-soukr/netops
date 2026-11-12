from __future__ import annotations

from datetime import datetime, timezone
import re

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
                     "device_cli_error", "transport_error", "unparsed", "not_applicable"})
VERDICTS = frozenset({"fault_found", "no_fault_in_checked_data", "incomplete"})


def missing_read(step, answer, reasons=REASONS):
    """The missing entry of a failed read; a transport failure keeps its class and fixed advice."""
    reason = answer.get("reason") if isinstance(answer, dict) else None
    item = {"step": step, "reason": reason if reason in reasons else "device_cli_error"}
    if reason in ("timeout", "transport_error") and isinstance(answer.get("error_code"), str):
        item.update(error_code=answer["error_code"], error=answer.get("error"))
    return item


class UnsupportedPlatform(ValueError):
    pass


class Unparsed(ValueError):
    pass


def _once(pattern, text):
    found = re.findall(pattern, text, re.M)
    if len(found) != 1:
        raise Unparsed()
    return found[0]


def _lines(text):
    return [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]


def identity(text):
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    if found not in IDENTITIES:
        raise UnsupportedPlatform("config_platform_not_supported: triage_health is not qualified for this model and build")
    return {"product": found[0], "version": found[1], "build": found[2]}


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
    ha_reason = None
    for area, query in STEPS[1:]:
        if query == "ha_checksum":
            if ha_reason is not None:
                missing.append({"step": query, "reason": ha_reason})
                continue
            if (parsed["ha_status"]["mode"] or "").lower() == "standalone":
                missing.append({"step": query, "reason": "not_applicable"})
                continue
        moment = clock()
        answer = read(query)
        captured[query] = moment
        if not answer.get("ok"):
            missing.append(missing_read(query, answer))
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
                checked.append(query)
        if query == "ha_status" and "ha_status" not in parsed:
            ha_reason = missing[-1]["reason"]
    findings = findings_for(parsed, sources, captured)
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
    next_steps = []
    for item in findings:
        step = _NEXT.get(item["id"])
        if step and not any(existing["arguments"]["query"] == step[0] for existing in next_steps):
            next_steps.append({"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": step[0]},
                               "why": step[1]})
    return {
        "ok": True,
        "identity": ident,
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "chain": chain,
        "findings": findings,
        "hypotheses": [],
        "next_steps": next_steps,
        "missing": missing,
        "checked": ["system_status"] + checked,
        "verdict": verdict,
    }
