"""Arista EOS evidence for the Helper network overview."""

from collections import Counter
from decimal import Decimal
import re

from netops_core import tested

from .. import normalization, port_errors, switch_mlag_eos, switch_mlag_eos_interfaces, tables, triage_health
from .model import DeviceFacts, ReadSpec, missing, refused_lines

_PLATFORM = "arista_eos"
_DOWN = "interfaces.admin_up_down"
_ERRORS = "interfaces.with_errors"

_BASE = (
    ReadSpec("version", "version", ("version", "model", "uptime_seconds")),
    ReadSpec("cpu", "cpu", ("cpu", "memory")),
    ReadSpec("interfaces", "interfaces", (_DOWN,)),
    ReadSpec("mlag_detail", "mlag_detail", ("redundancy",)),
)
_HEALTH = (
    ReadSpec("interfaces_counters_errors", "interfaces_counters_errors", (_ERRORS,)),
    ReadSpec("environment", "environment", ("temperatures", "fans", "power")),
    ReadSpec("poe", "poe", ("poe",)),
)
_MLAG_BUCKETS = {"disabled": "disabled", "configured": "configured", "inactive": "inactive",
                 "active-partial": "active_partial", "active-full": "active_full"}
_HW_STATES = {"ok": "ok", "unknown": "unknown"}
_UPTIME_UNITS = {"week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def plan(scope):
    member_read = (ReadSpec("mlag_interfaces", "mlag_interfaces", ("redundancy",), requires=("mlag_detail",)),
                   ) if "mlag_interfaces" in scope.enabled_queries else ()
    return (*_BASE, *member_read, *_HEALTH)


def _identity(facts, text):
    try:
        identity = normalization.parse_identity(_PLATFORM, text)
    except normalization.IdentityError:
        return False
    version, model = identity["os_version"], identity["model"]
    facts.fields.update(version=version, model=model)
    facts.fields["firmware_support"] = tested.support(
        "Arista EOS", version, (("cEOSLab", "4.36.1F-48405728.4361F"),),
        model=model, function="network_overview",
    )
    uptime = identity["uptime"] or ""
    parts = re.split(r", (?:and )?| and ", uptime)
    values = [re.fullmatch(r"([0-9]{1,9}) (week|day|hour|minute|second)s?", part) for part in parts]
    if all(values) and len({item[2] for item in values}) == len(values):
        facts.fields["uptime_seconds"] = sum(int(item[1]) * _UPTIME_UNITS[item[2]] for item in values)
    return model is not None and "uptime_seconds" in facts.fields


def _resources(facts, text):
    # The health parser validates the whole top frame. Independently recover a
    # unique intact CPU or memory header when the process table is incomplete.
    cpu = [m for line in text.splitlines() if (m := triage_health._TOP_CPU.fullmatch(line))]
    mem = [m for line in text.splitlines() if (m := triage_health._TOP_MEM.fullmatch(line))]
    if len(cpu) == 1 and all(re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]+)?", value)
                             and float(value) <= 100 for value in cpu[0].groups()):
        facts.fields["cpu"] = {"used_pct": round(100 - float(cpu[0][4]), 3), "sample_seconds": None}
    if len(mem) == 1 and all(re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]+)?", mem[0][i]) for i in (2, 4)):
        unit = 1024 if mem[0][1] == "KiB" else 1024 ** 2
        total, used = (round(Decimal(mem[0][i]) * unit) for i in (2, 4))
        if 0 < total and used <= total:
            facts.fields["memory"] = {"used_pct": round(100 * used / total, 2), "total_bytes": total,
                                      "used_bytes": used}
    if not {"cpu", "memory"} <= facts.fields.keys():
        return False
    try:
        return triage_health.eos_cpu(text)["state"] == "ok"
    except ValueError:
        return False


def _interfaces(facts, text):
    rows, unknown = tables.cisco("interface", text, "eos")
    states = {}
    status_start = status_end = 0
    for line in text.splitlines():
        header = re.search(r"\bStatus\s+Vlan\s+Duplex\s+Speed\b", line)
        if line.startswith("Port ") and header:
            status_start, status_end = header.start(), header.start() + header[0].index("Vlan")
        elif status_end and (cells := line.split()):
            try:
                name = tables.port(cells[0])
            except ValueError:
                continue
            states.setdefault(name, []).append(line[status_start:status_end].strip().lower())
    admin_down = {"disabled"}
    link_down = {"notconnect", "notconnec", "errdisabled", "err-disabled", "err-disabl"}
    names = Counter(row["name"] for row in rows)
    down = []
    complete = bool(rows) and not unknown
    for row in rows:
        name = row["name"]
        reported = states.get(name, [])
        if len(reported) != 1 or names[name] != 1:
            complete = False
            continue
        state, = reported
        if state in link_down:
            down.append({"name": normalization.normalize_port(name)["name"], "read_ids": ["interfaces"]})
        elif state not in tables.STATUS_UP | admin_down:
            complete = False
    if down or complete:
        facts.fields["interfaces"]["admin_up_down"] = down
    return complete, {normalization.normalize_port(name)["name"] for name in names
                      if normalization.normalize_port(name)["kind"] == "physical"}


def _errors(facts, text, physical_ports):
    rows, unknown = port_errors.tabular(_PLATFORM, text)
    entries = []
    names = set()
    complete = bool(rows) and not unknown
    for row in rows:
        name = row["port"]
        names.add(name)
        counters = {key: row[key] for key in ("rx_errors", "tx_errors", "crc") if row[key] is not None}
        complete &= len(counters) == 3
        if any(counters.values()):
            entries.append({"name": name, "counters": counters, "counter_kind": "cumulative",
                            "read_ids": ["interfaces_counters_errors"]})
    if physical_ports - names:
        complete = False
    if entries or complete:
        facts.fields["interfaces"]["with_errors"] = entries
    return complete


def _mlag(facts, reads):
    details = reads["mlag_detail"]
    if details.status != "ok":
        return
    summary = switch_mlag_eos.summarize(details.text or "")
    ports, state = summary["ports"], summary["operational_state"]
    known_counts = all(count is not None for count in ports.values())
    if state == "Disabled" and known_counts and not any(ports.values()):
        item = {"kind": "mlag", "state": "standalone", "members": [], "read_ids": ["mlag_detail"]}
    elif state == "Active":
        signals = (summary["negotiation_status"], summary["peer_link_status"], summary["local_interface_status"])
        if signals == ("Connected", "Up", "Up"):
            status = "degraded" if ports["inactive"] or ports["active_partial"] else "ok"
        elif signals[0] == "Disconnected" or "Down" in signals[1:]:
            status = "degraded"
        else:
            status = "unknown"
        item = {"kind": "mlag", "state": status, "read_ids": ["mlag_detail"]}
        if summary["detailed_state"] in {"primary", "secondary"}:
            item["role"] = summary["detailed_state"]
        if not known_counts or status == "unknown" or summary["peer_state"] not in {"primary", "secondary"}:
            facts.incomplete_reads += ("mlag_detail",)
    else:
        facts.incomplete_reads += ("mlag_detail",)
        return
    facts.fields["redundancy"] = [item]
    members = reads.get("mlag_interfaces")
    if members is None:
        if item["state"] != "standalone":
            facts.missing.append(missing("redundancy", "source_limit", read_id="mlag_detail"))
        return
    if members.status != "ok":
        return
    payload = switch_mlag_eos_interfaces.summarize(members.text or "")
    rows = [row for row in payload["members"] if row["id"] is not None and row["local_port"]]
    counts = Counter(row["state"] for row in rows)
    consistent = known_counts and all(counts[key] == ports[bucket] for key, bucket in _MLAG_BUCKETS.items())
    if payload["state"] != "measured" or not consistent:
        facts.incomplete_reads += ("mlag_interfaces",)
    if rows or (consistent and payload["state"] == "measured"):
        item["members"] = [{"id": row["id"], "name": normalization.normalize_port(row["local_port"])["name"],
                            "state": row["state"], "local_status": row["local_status"],
                            "peer_status": row["remote_status"]} for row in rows]
        item["read_ids"].append("mlag_interfaces")


def _environment(facts, text):
    data = triage_health.eos_environment(text)
    for field, key, name in (("temperatures", "temperature_status", "System temperature"),
                             ("fans", "cooling_status", "Cooling zones")):
        if (state := _HW_STATES.get(data.get(key, "").lower())) is not None:
            item = {"name": name, "state": state}
            if field == "temperatures":
                item["kind"] = "system"
            facts.fields[field] = [item]
    if data.get("power_supplies_present") is False and facts.fields.get("model") == "cEOSLab":
        facts.fields["power"] = []
    return data.get("unreadable_lines") == 0 and all(field in facts.fields for field in ("temperatures", "fans", "power"))


def assemble(scope, reads):
    facts = DeviceFacts(
        {"interfaces": {"scope": "device", "admin_up_down": None, "with_errors": None}},
        [missing("fortiguard", "not_applicable"), missing("managed", "not_applicable")],
    )
    physical_ports = set()
    for read_id, read in reads.items():
        if read.status != "ok":
            continue
        text = read.text or ""
        if read_id == "version":
            complete = _identity(facts, text)
        elif read_id == "cpu":
            complete = _resources(facts, text)
        elif read_id == "interfaces":
            complete, physical_ports = _interfaces(facts, text)
        elif read_id == "interfaces_counters_errors":
            complete = _errors(facts, text, physical_ports)
        elif read_id == "environment":
            complete = _environment(facts, text)
        elif read_id == "poe":
            # The existing capture has no verified device-wide budget in watts.
            facts.missing.append(missing("poe", "source_limit", read_id=read_id))
            continue
        else:
            continue
        if not complete:
            facts.incomplete_reads += (read_id,)
    _mlag(facts, reads)
    if reads["version"].status == "ok":
        facts.missing.append(missing("licenses", "source_limit", read_id="version"))
    if facts.fields.get("model") == _CEOS_LAB:
        # The container image has no sensors, supplies or PSE ports and says so (measured on cEOSLab 4.36.1F).
        answered = {}
        for read_id, expected in (("environment", _CEOS_ENVIRONMENT), ("poe", _CEOS_POE)):
            lines = refused_lines(reads.get(read_id))
            if lines is not None and [line for line in lines if not line.startswith("> ")] == expected:
                answered[read_id] = "not_applicable"
        facts.answered_reads = answered
    return facts


_CEOS_LAB = "cEOSLab"
_CEOS_ENVIRONMENT = [
    "% There seem to be no power supplies connected. at line 1",
    "System temperature status is: Unknown",
    "Action on overheat: unknown",
    "Recovery mode when power-cycle upon overheat: not applicable",
    "Restrict recovery when ambient temperature is at or above: not applicable",
    "System cooling status is: Unknown",
    "Number of cooling zones is: 1",
]
_CEOS_POE = ["% Invalid input at line 1"]
