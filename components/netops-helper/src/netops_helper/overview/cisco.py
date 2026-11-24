"""Network overview adapter for Cisco IOS, IOS XE and NX-OS.

The adapter is pure: `plan` declares catalogue reads and `assemble` normalizes the
redacted output the frame collected. Existing parsers stay the source of truth for
CPU, memory, environment, interface counters and vPC. Only the PoE summary, the
StackWise member and stack-port tables, the interface admin header, the NX-OS
license usage table and the CPU/DRAM rows of the shared IOS XE platform resources
summary are interpreted here, each from a documented output form.
"""

from __future__ import annotations

import re

from .. import port_errors, tables, triage_health
from ..normalization import IdentityError, parse_identity
from . import model
from .model import ReadSpec, missing

IOS_TESTED = triage_health.IOS_HEALTH_TESTED
XE_TESTED = triage_health.XE_HEALTH_TESTED
NXOS_TESTED = ("9.3(12)",)
_OS_NAMES = {"cisco_ios": "IOS", "cisco_xe": "IOS XE", "cisco_nxos": "NX-OS"}
_COUNTERS = ("rx_errors", "crc", "tx_errors", "discards_in", "discards_out")


def _switch(scope):
    return not scope.device_types or "switch" in scope.device_types


def plan(scope):
    platform = scope.platform
    if platform == "cisco_nxos":
        return (
            ReadSpec("version", "version", ("version", "model", "uptime_seconds", "firmware_support")),
            ReadSpec("system_resources", "system_resources", ("cpu", "memory")),
            ReadSpec("interfaces", "interfaces", ("interfaces.admin_up_down",)),
            ReadSpec("vpc_status", "vpc_status", ("redundancy",)),
            ReadSpec("redundancy_status", "redundancy_status", ("redundancy",)),
            ReadSpec("interfaces_counters_errors", "interfaces_counters_errors", ("interfaces.with_errors",)),
            ReadSpec("environment", "environment", ("temperatures", "fans", "power")),
            ReadSpec("license_usage", "license_usage", ("licenses",)),
        )
    enabled = set(scope.enabled_queries)
    specs = [ReadSpec("version", "version", ("version", "model", "uptime_seconds", "firmware_support"))]
    if platform == "cisco_xe" and "platform_resources" in enabled:
        # The control-plane summary is preferred; `cpu` and `memory` are the fallback, planned only
        # when they are enrolled too, so an unenrolled fallback does not mark a covered metric missing.
        specs.append(ReadSpec("platform_resources", "platform_resources", ("cpu", "memory")))
        specs += [ReadSpec(query, query, (query,)) for query in ("cpu", "memory") if query in enabled]
    else:
        specs += [ReadSpec("cpu", "cpu", ("cpu",)), ReadSpec("memory", "memory", ("memory",))]
    specs.append(
        ReadSpec("interfaces_details", "interfaces_details", ("interfaces.admin_up_down", "interfaces.with_errors")))
    if _switch(scope):
        specs += [
            ReadSpec("stack_members", "stack_members", ("redundancy",)),
            ReadSpec("stack_ports", "stack_ports", ("redundancy",), requires=("stack_members",)),
        ]
    specs.append(ReadSpec("environment", "environment", ("temperatures", "fans", "power")))
    if _switch(scope):
        specs.append(ReadSpec("power_inline", "power_inline", ("poe",)))
    if platform == "cisco_xe" and {"c9800_redundancy", "c9800_chassis_rmi"} <= enabled:
        # Only an account enrolled for the wireless controller plans the controller HA pair, and only
        # after every other read: the frame cannot condition a step on the parsed controller image,
        # so these two never take the budget of an approved read (assemble discards them on other images).
        specs += [ReadSpec("c9800_redundancy", "c9800_redundancy", ("redundancy",)),
                  ReadSpec("c9800_chassis_rmi", "c9800_chassis_rmi", ("redundancy",),
                           requires=("c9800_redundancy",))]
    return tuple(specs)


# --- shared helpers ---------------------------------------------------------------------------------------------

_UPTIME_UNITS = {"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def uptime_seconds(text):
    """`1 week, 4 days, 5 hours, 39 minutes` (IOS) or `4 day(s), 9 hour(s), 47 minute(s), 56 second(s)` (NX-OS)."""
    if not isinstance(text, str) or not text.strip():
        return None
    total, seen = 0, set()
    for part in text.split(","):
        match = re.fullmatch(r"\s*(\d{1,6}) (year|week|day|hour|minute|second)(?:s|\(s\))?\s*", part)
        if not match or match[2] in seen:
            return None
        seen.add(match[2])
        total += int(match[1]) * _UPTIME_UNITS[match[2]]
    return total


def _usable(reads, key):
    read = reads.get(key)
    return read if read is not None and read.status in {"ok", "empty"} and read.text is not None else None


class _Facts:
    def __init__(self, scope, reads):
        self.scope, self.reads = scope, reads
        self.fields = {}
        self.missing = []
        self.incomplete = []
        self.answered = {}

    def need(self, field, reason, read_id=None):
        entry = missing(field, reason, **({"read_id": read_id} if read_id else {}))
        if entry not in self.missing:
            self.missing.append(entry)

    def bad(self, read_id):
        if read_id not in self.incomplete:
            self.incomplete.append(read_id)

    def failed(self, read_id):
        read = self.reads.get(read_id)
        return read is None or read.status not in {"ok", "empty", "incomplete"}

    def finish(self):
        # A null field the plan should have filled has a stated cause: the frame adds failed reads, the rest is
        # explained here. Optional values the source does not print (e.g. `cpu.sample_seconds`) and `managed`
        # of a platform without managed children are null without an entry (H0 contract).
        covered = {entry["field"] for entry in self.missing}
        for read in self.reads.values():
            if read.reason or read.spec.id in self.incomplete:
                covered.update(read.spec.fields)
        for field in model.FACT_FIELDS:
            if field in ("managed",):
                continue
            if self.fields.get(field) is None and field not in covered:
                self.need(field, "unparsed")
        interfaces = self.fields.get("interfaces")
        if interfaces:
            for key in ("admin_up_down", "with_errors"):
                name = "interfaces." + key
                if interfaces.get(key) is None and name not in covered:
                    self.need(name, "unparsed")
        return model.DeviceFacts(self.fields, self.missing, [], tuple(self.incomplete), self.answered)


def _identity(facts, platform):
    read = _usable(facts.reads, "version")
    if read is None:
        return None
    try:
        identity = parse_identity(platform, read.text)
    except IdentityError:
        facts.bad("version")
        return None
    from netops_core import tested

    tested_versions = {"cisco_ios": IOS_TESTED, "cisco_xe": XE_TESTED, "cisco_nxos": NXOS_TESTED}[platform]
    facts.fields["version"] = identity["os_version"]
    facts.fields["model"] = identity["model"]
    facts.fields["firmware_support"] = tested.support(
        _OS_NAMES[platform], identity["os_version"], tested_versions, model=identity["model"],
        function="network_overview")
    if identity["model"] is None:
        facts.need("model", "source_limit", "version")
    seconds = uptime_seconds(identity["uptime"])
    facts.fields["uptime_seconds"] = seconds
    if seconds is None:
        facts.need("uptime_seconds", "unparsed", "version")
    return identity


# --- IOS / IOS XE -----------------------------------------------------------------------------------------------

_MIB = 1024 * 1024


def platform_resources(text):
    """Control-plane CPU and DRAM rows of IOS XE `show platform resources`.

    Returns ({"cpu": ..., "memory": ...}, complete). A metric is present only when exactly one
    row reports it and the DRAM row agrees with itself (used / max against the printed percent).
    The table prints no sampling interval and MB in binary units like the rest of IOS XE.
    """
    summary = triage_health.xe_platform_resources(text)
    if summary is None:
        return {}, False
    metrics, complete = {}, summary["complete"]
    rows = {}
    for row in summary["resources"]:
        rows.setdefault(row["resource"], []).append(row)
    cpu, dram = rows.get("Control Processor", []), rows.get("DRAM", [])
    if len(cpu) == 1 and (match := re.fullmatch(r"(\d{1,3}(?:\.\d+)?)%", cpu[0]["usage"])):
        metrics["cpu"] = {"used_pct": float(match[1]), "sample_seconds": None}
    elif cpu:
        complete = False
    if len(dram) == 1:
        usage = re.fullmatch(r"(\d+)MB\((\d{1,3})%\)", dram[0]["usage"])
        maximum = re.fullmatch(r"(\d+)MB", dram[0]["maximum"])
        if usage and maximum and int(maximum[1]) and abs(100 * int(usage[1]) / int(maximum[1]) - int(usage[2])) < 1:
            used, total = int(usage[1]), int(maximum[1])
            metrics["memory"] = {"used_pct": round(100 * used / total, 2), "total_bytes": total * _MIB,
                                 "used_bytes": used * _MIB}
        else:
            complete = False
    elif dram:
        complete = False
    return metrics, complete


def _ios_cpu_memory(facts):
    if read := _usable(facts.reads, "platform_resources"):
        metrics, complete = platform_resources(read.text)
        if not complete:
            facts.bad("platform_resources")
        facts.fields.update(metrics)
        if len(metrics) == 2:
            return
    if "cpu" not in facts.fields and (read := _usable(facts.reads, "cpu")):
        cpu = triage_health.xe_cpu(read.text)
        if cpu is None:
            facts.bad("cpu")
        else:
            # The header names the window: "one minute".
            facts.fields["cpu"] = {"used_pct": cpu["one_minute_percent"], "sample_seconds": 60}
    if "memory" not in facts.fields and (read := _usable(facts.reads, "memory")):
        pools = triage_health.xe_memory(read.text)
        if pools is None:
            facts.bad("memory")
        else:
            main = pools["Processor"]
            facts.fields["memory"] = {"used_pct": main["used_percent"], "total_bytes": main["total_bytes"],
                                      "used_bytes": main["used_bytes"]}


_IOS_HEADER = re.compile(
    r"(\S+) is (up|down|administratively down|reset|deleted), line protocol is (up|down)(?: \([\w -]+\))?")


def without_deleted(text):
    """Drop the blocks of interfaces IOS still lists as deleted (measured on IOSv and IOL XE).

    The shared detail parser does not know the header, so the block's counter lines
    would otherwise land on the interface printed before it.
    """
    kept, skip = [], False
    for line in text.splitlines():
        if line[:1].strip():
            match = _IOS_HEADER.fullmatch(line.strip())
            skip = bool(match and match[2] == "deleted")
        if not skip:
            kept.append(line)
    return "\n".join(kept)


def _counter_rows(rows, read_id):
    entries = []
    for row in rows:
        counters = {key: row[key] for key in _COUNTERS if type(row.get(key)) is int}
        if any(value > 0 for value in counters.values()):
            entries.append({"name": row["port"], "counters": counters, "counter_kind": "cumulative",
                            "read_ids": [read_id]})
    return entries


def _ios_interfaces(facts):
    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    facts.fields["interfaces"] = interfaces
    read = _usable(facts.reads, "interfaces_details")
    if read is None:
        return
    text = without_deleted(read.text)
    headers = []
    for line in text.splitlines():
        if match := _IOS_HEADER.fullmatch(line.strip()):
            headers.append(match)
    rows, unknown = port_errors.ios_details(text)
    if not headers or len(headers) != len(rows) or unknown:
        facts.bad("interfaces_details")
        if not headers:
            return
    # Physical "down" with an enabled port is admin-up/link-down; "administratively down" is
    # the operator's choice and "reset"/"deleted" are not a link state.
    interfaces["admin_up_down"] = [
        {"name": port_errors.record(match[1])["port"], "read_ids": ["interfaces_details"]}
        for match in headers if match[2] == "down"]
    if len(headers) == len(rows):
        interfaces["with_errors"] = _counter_rows(rows, "interfaces_details")


def _ios_environment(facts):
    read = _usable(facts.reads, "environment")
    if read is None:
        return
    summary = triage_health.xe_environment(read.text)
    if summary is None:
        facts.bad("environment")
        return
    if not summary["complete"]:
        facts.bad("environment")

    def state(value):
        value = (value or "").strip().upper()
        if value in {"OK", "GOOD", "GREEN", "NORMAL"}:
            return "ok"
        if value in {"YELLOW", "WARNING", "MINOR"}:
            return "warning"
        if value in {"RED", "CRITICAL", "BAD", "FAULTY", "NOT FUNCTIONING", "FAIL", "FAILED", "MAJOR",
                     "NO INPUT POWER"}:
            return "failed"
        return "unknown"

    facts.fields["temperatures"] = [
        {"name": item["name"], "state": state(item.get("state")), "celsius": item["celsius"], "kind": "system",
         "read_ids": ["environment"]} for item in summary["temperatures"]]
    # A slot without a module (fan or supply) is absent, not failed.
    fans = [item for item in summary["fans"] if item["state"].strip().upper() != "NOT PRESENT"]
    supplies = [item for item in summary["power_supplies"] if item["state"].strip().upper() != "NOT PRESENT"]
    facts.fields["fans"] = [{"name": item["name"], "state": state(item["state"]), "read_ids": ["environment"]}
                            for item in fans]
    facts.fields["power"] = [{"name": item["slot"], "state": state(item["state"]), "read_ids": ["environment"]}
                             for item in supplies]
    # A printed state outside the known values is not classified as healthy (triage_health alarms on it too).
    printed = [*(item for item in summary["temperatures"] if item.get("state")), *fans, *supplies]
    if any(state(item["state"]) == "unknown" for item in printed):
        facts.bad("environment")


_POE_HEADER = re.compile(r"Module\s+Available\s+Used\s+Remaining")
_POE_UNITS = re.compile(r"\(Watts\)\s+\(Watts\)\s+\(Watts\)")
_POE_ROW = re.compile(r"(\d{1,2})\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)")


def poe_summary(text):
    """Module budget table of `show power inline` (Catalyst IOS / IOS XE).

    Returns (budget, complete). Members are summed only when every module row parsed
    and every row satisfies Available - Used = Remaining at the printed precision.
    """
    lines = [line.strip() for line in text.splitlines()]
    starts = [index for index, line in enumerate(lines) if _POE_HEADER.fullmatch(line)]
    if len(starts) != 1:
        return None, False
    index = starts[0] + 1
    if index >= len(lines) or not _POE_UNITS.fullmatch(lines[index]):
        return None, False
    index += 1
    while index < len(lines) and lines[index] and re.fullmatch(r"[- ]+", lines[index]):
        index += 1
    rows = []
    for line in lines[index:]:
        if not line or line.startswith("Interface"):
            break
        match = _POE_ROW.fullmatch(line)
        if not match:
            return None, False
        rows.append(tuple(float(value) for value in match.groups()[1:]))
    # The summary must agree with itself; a contradiction is not a budget.
    if not rows or any(abs(available - used - remaining) > 0.15 for available, used, remaining in rows):
        return None, False
    available = round(sum(row[0] for row in rows), 1)
    used = round(sum(row[1] for row in rows), 1)
    return {"budget_w": available, "used_w": used, "available_w": round(available - used, 1)}, True


def _ios_poe(facts):
    if not _switch(facts.scope):
        facts.fields["poe"] = None
        facts.need("poe", "source_limit")
        return
    read = _usable(facts.reads, "power_inline")
    if read is None:
        return
    budget, complete = poe_summary(read.text)
    facts.fields["poe"] = budget
    if not complete:
        facts.bad("power_inline")


_STACK_HEADER = re.compile(r"Switch#\s+Role\s+Mac Address\s+Priority\s+Version\s+State")
_STACK_ROW = re.compile(r"(\*?)\s*(\d{1,2})\s+(Active|Standby|Member)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})"
                        r"\s+(\d{1,2})\s+(\S+)\s+(\S.*?)", re.I)
_STACK_PORT_HEADER = re.compile(r"Sw#/Port#\s+Port Status\s+Neighbor\s+Cable Length\s+Link OK\s+Link Active"
                                r"\s+Sync OK\s+#Changes to LinkOK\s+In Loopback")
_STACK_PORT_ROW = re.compile(r"(\d{1,2})/(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(\d+)\s+(Yes|No)",
                             re.I)


def stack_members(text):
    """StackWise member table of `show switch`; returns (members, complete)."""
    header, members, complete = False, [], True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"-+", line) or line.startswith(("Switch/Stack Mac Address", "Mac persistency",
                                                                       "H/W", "Current")):
            continue
        if _STACK_HEADER.search(line):
            header = True
            continue
        match = _STACK_ROW.fullmatch(line)
        if header and match:
            members.append({"member": int(match[2]), "role": match[3].lower(), "state": match[7].strip(),
                            "local": bool(match[1])})
        else:
            complete = False
    if not header:
        return None, False
    return members, complete and bool(members) and sum(item["local"] for item in members) == 1


def stack_ports(text):
    """`show switch stack-ports summary`; returns (ports, complete)."""
    header, ports, complete = False, [], True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"-+", line):
            continue
        if _STACK_PORT_HEADER.fullmatch(line):
            header = True
            continue
        match = _STACK_PORT_ROW.fullmatch(line)
        if header and match:
            ports.append({"port": f"{match[1]}/{match[2]}", "status": match[3], "link_ok": match[6].lower() == "yes",
                          "link_active": match[7].lower() == "yes", "sync_ok": match[8].lower() == "yes"})
        else:
            complete = False
    if not header:
        return None, False
    return ports, complete and bool(ports)


def _ios_redundancy(facts, identity):
    redundancy = None
    if _switch(facts.scope) and (read := _usable(facts.reads, "stack_members")):
        members, complete = stack_members(read.text)
        if not complete:
            facts.bad("stack_members")
        if members is not None:
            local = next((item for item in members if item["local"]), None)
            entry = {"kind": "stack", "state": "unknown", "members": len(members), "read_ids": ["stack_members"]}
            if local is not None:
                entry["role"] = local["role"]
            if complete and len(members) == 1:
                entry["state"] = "standalone"
            elif complete:
                ready = all(item["state"].lower() == "ready" for item in members)
                ports_read = _usable(facts.reads, "stack_ports")
                ports, ports_complete = stack_ports(ports_read.text) if ports_read else (None, False)
                if ports is not None:
                    # Every member has its two stack ports in the table, and no row names another switch.
                    expected = {f"{item['member']}/{number}" for item in members for number in (1, 2)}
                    names = [port["port"] for port in ports]
                    ports_complete = ports_complete and len(names) == len(set(names)) and set(names) == expected
                if ports_read is not None:
                    entry["read_ids"].append("stack_ports")
                    if not ports_complete:
                        facts.bad("stack_ports")
                failed_port = any(not (port["status"].upper() == "OK" and port["link_ok"] and port["link_active"]
                                       and port["sync_ok"]) for port in ports or ())
                if not ready or failed_port:
                    entry["state"] = "degraded"
                elif ports_complete:
                    entry["state"] = "ok"
            redundancy = [entry]
    elif not _switch(facts.scope):
        facts.need("redundancy", "source_limit")
    if (facts.scope.platform == "cisco_xe" and identity is not None
            and "c9800_redundancy" in facts.reads and "c9800_chassis_rmi" in facts.reads):
        from netops_core.c9800 import CONTROLLER_IMAGE
        from ..triage_wifi import c9800_ha

        version = facts.reads["version"].text or ""
        if CONTROLLER_IMAGE.search(version):
            def read(query):
                answer = _usable(facts.reads, query)
                return {"ok": True, "text": answer.text} if answer else {"ok": False, "reason": "unavailable"}

            result = c9800_ha(read, identity["os_version"])
            state = {"synchronized": "ok", "degraded": "degraded"}.get(result["ha"]["state"], "unknown")
            redundancy = [*(redundancy or []), {"kind": "ha", "state": state,
                                                "read_ids": ["c9800_redundancy", "c9800_chassis_rmi"]}]
            if state == "unknown":
                facts.need("redundancy", "unparsed", "c9800_redundancy")
        else:
            facts.need("redundancy", "not_applicable", "c9800_redundancy")
    if redundancy is not None:
        facts.fields["redundancy"] = redundancy


def _ios_assemble(scope, reads):
    facts = _Facts(scope, reads)
    identity = _identity(facts, scope.platform)
    _ios_cpu_memory(facts)
    _ios_interfaces(facts)
    _ios_environment(facts)
    _ios_poe(facts)
    _ios_redundancy(facts, identity)
    # No license line appears in the documented `show version` of the supported images.
    facts.fields["licenses"] = None
    facts.need("licenses", "source_limit", "version" if "version" in reads else None)
    facts.fields["fortiguard"] = None
    facts.need("fortiguard", "not_applicable")
    facts.fields["managed"] = None
    return facts.finish()


# --- NX-OS ------------------------------------------------------------------------------------------------------

def _nxos_resources(facts):
    read = _usable(facts.reads, "system_resources")
    if read is None:
        return
    data, complete = triage_health.nxos_resources(read.text)
    if not complete:
        facts.bad("system_resources")
    if cpu := data.get("cpu_percent"):
        # The aggregate line has no sampling interval.
        facts.fields["cpu"] = {"used_pct": round(100 - cpu["idle"], 2), "sample_seconds": None}
    if memory := data.get("memory_kib"):
        if memory["total"] and memory["used"] + memory["free"] == memory["total"]:
            facts.fields["memory"] = {"used_pct": round(100 * memory["used"] / memory["total"], 2),
                                      "total_bytes": memory["total"] * 1024, "used_bytes": memory["used"] * 1024}
        else:
            facts.bad("system_resources")


# `show interface status`: notconnect is the explicit admin-up/link-down state.
_NXOS_LINK_DOWN = {"notconnect", "notconnec", "noconnect"}
_NXOS_NOT_LINK_DOWN = {"connected", "disabled", "err-disabled", "errdisabled", "err-disabl", "sfpabsent", "xcvrabsen",
                       "xcvrabsent", "suspended", "suspnd", "inactive", "noopermem", "channeldo", "suspndbyv",
                       "linkflape", "sfpinvali", "xcvrinval", "sfpinvalid", "monitoring"}


def nxos_status(text):
    """Return ([(port, status)], unknown_lines) of `show interface status`."""
    rows, unknown, starts = [], 0, []
    for raw in text.splitlines():
        value = raw.strip()
        if not value or re.fullmatch(r"[-= ]+", value):
            continue
        if re.match(r"Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed", value):
            starts = tables.columns(raw, "Name", "Status", "Vlan", "Duplex", "Speed")
            continue
        if not starts:
            unknown += 1
            continue
        name = raw[:starts[0]].strip()
        status = tables.cut(raw, starts, 1).lower()
        if not name or " " in name or not status or " " in status:
            unknown += 1
            continue
        rows.append((name, status))
    return rows, unknown


def _nxos_interfaces(facts):
    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    facts.fields["interfaces"] = interfaces
    if read := _usable(facts.reads, "interfaces"):
        rows, unknown = nxos_status(read.text)
        # A logical interface (SVI, loopback, tunnel) reports "down" without a link to classify.
        ambiguous = [status for name, status in rows if status not in _NXOS_LINK_DOWN | _NXOS_NOT_LINK_DOWN
                     and not (status == "down" and not name.lower().startswith("eth"))]
        if unknown or ambiguous or not rows:
            facts.bad("interfaces")
        if rows:
            interfaces["admin_up_down"] = [
                {"name": port_errors.record(name)["port"], "read_ids": ["interfaces"]}
                for name, status in rows if status in _NXOS_LINK_DOWN]
    if read := _usable(facts.reads, "interfaces_counters_errors"):
        rows, unknown = port_errors.tabular("cisco_nxos", read.text)
        if unknown or not rows:
            facts.bad("interfaces_counters_errors")
        if rows and not unknown:
            interfaces["with_errors"] = _counter_rows(rows, "interfaces_counters_errors")


def _nxos_environment(facts, virtual):
    read = _usable(facts.reads, "environment")
    if read is None:
        return
    data, complete = triage_health.nxos_environment(read.text)
    if data["unparsed_lines"]:
        facts.bad("environment")

    def state(value):
        value = value.strip().lower()
        return ("ok" if value in {"ok", "normal"} else "warning" if value in {"minor", "warning"}
                else "failed" if value in {"major", "failed", "fail", "shutdown"} else "unknown")

    tables_ = {
        "temperatures": [{"name": f"module {row['module']} {row['sensor']}", "state": state(row["state"]),
                          "celsius": row["current_celsius"], "kind": "system", "read_ids": ["environment"]}
                         for row in data["temperature"]],
        "fans": [{"name": row["fan"], "state": state(row["state"]), "read_ids": ["environment"]}
                 for row in data["fan"]],
        "power": [{"name": str(row["supply"]), "state": state(row["state"]),
                   "watts": row["output_watts"], "read_ids": ["environment"]} for row in data["power"]],
    }
    source = {"temperature": "temperatures", "fan": "fans", "power": "power"}
    for name, field in source.items():
        if name in data["unavailable"]:
            # The virtual Nexus prints the section headers without hardware rows.
            facts.fields[field] = None
            facts.need(field, "not_applicable" if virtual else "source_limit", "environment")
        else:
            facts.fields[field] = tables_[field]


# NX-OS 9.3(12) on a Nexus 9000v without `feature vpc`: the vPC commands do not exist until the
# feature is enabled (measured with the read-only account, exit status 16), so vPC does not apply to
# this switch. Only the same virtual image and exit status are recognized: on another model the same
# syntax error is not a measured statement about vPC and the read stays unparsed.
_NO_VPC_FEATURE = ["Syntax error while parsing 'show vpc brief'", "Cmd exec error."]
_NO_VPC_FEATURE_RC = 16


def _nxos_redundancy(facts, virtual):
    entries = []
    vpc = facts.reads.get("vpc_status")
    if virtual and vpc is not None and vpc.rc == _NO_VPC_FEATURE_RC and model.refused_lines(vpc) == _NO_VPC_FEATURE:
        facts.answered["vpc_status"] = "not_applicable"
    if read := _usable(facts.reads, "vpc_status"):
        from .. import switch_vpc

        summary = switch_vpc.summarize(read.text)
        if summary["state"] != "measured":
            facts.bad("vpc_status")
        if summary["state"] != "unparsed":
            peer = (summary.get("peer_status") or "").lower()
            alive = (summary.get("keepalive_status") or "").lower() == "peer is alive"
            consistent = (summary.get("consistency_status") or "").lower() == "success"
            # Every peer link up and every local vPC up with successful consistency (`down*`/`failed`
            # is a member forwarding over the peer link, as switch_vpc.compare reports it).
            links_up = all(row["status"].lower() == "up" for row in summary.get("peer_links") or ())
            members_up = all(row["status"].lower() == "up" and row["consistency"].lower() == "success"
                             for row in summary.get("members") or ())
            if summary["state"] != "measured":
                state = "unknown"
            elif peer == "peer adjacency formed ok" and alive and consistent and links_up and members_up:
                state = "ok"
            else:
                # A configured vPC domain without a formed, consistent peer or with a failed member is not redundant.
                state = "degraded"
            entry = {"kind": "vpc", "state": state, "read_ids": ["vpc_status"]}
            role = summary.get("role")
            if role and role.lower() not in {"none established"}:
                entry["role"] = role
            entries.append(entry)
    if read := _usable(facts.reads, "redundancy_status"):
        operational = re.findall(r"(?m)^\s*operational:\s*(\S.*?)\s*$", read.text)
        internal = re.findall(r"(?m)^\s*Internal state:\s*(\S.*?)\s*$", read.text)
        if len(operational) != 1 or not internal:
            facts.bad("redundancy_status")
        else:
            local = internal[0]
            if local == "Active with no standby" and operational[0] == "None":
                state = "standalone"
            elif local == "Active with HA standby":
                state = "ok"
            else:
                state = "unknown"
                facts.bad("redundancy_status")
            entries.append({"kind": "ha", "state": state, "role": "active" if local.startswith("Active") else None,
                            "read_ids": ["redundancy_status"]})
            if entries[-1]["role"] is None:
                entries[-1].pop("role")
    if entries:
        facts.fields["redundancy"] = entries


_LICENSE_HEADER = re.compile(r"Feature\s+Ins\s+Lic\s+Status\s+Expiry Date\s+Comments")


def nxos_licenses(text):
    """`show license usage`: installed features and features in use without a license."""
    header, rows, complete = False, [], True
    for raw in text.splitlines():
        line = raw.rstrip()
        value = line.strip()
        if not value or re.fullmatch(r"-+", value) or value == "Count":
            continue
        if _LICENSE_HEADER.match(value):
            header = True
            continue
        match = re.fullmatch(r"(\S+)\s+(Yes|No)\s+(\d+|-)\s+(Unused|In use)\s+(.*)", value)
        if not header or not match:
            complete = False
            continue
        rest = match[5].strip()
        if match[2] == "No" and match[4] == "Unused":
            if rest not in {"-", ""}:
                complete = False
            continue
        if rest in {"-", ""}:
            expiry, state = None, "valid" if match[2] == "Yes" else "unlicensed"
        elif match[2] == "No" and re.fullmatch(r"Honor Start(?: \d+[DHM])+", rest):
            # A feature in use under the honor model without an installed license.
            expiry, state = None, "unlicensed"
        elif rest.split()[0] == "Never":
            expiry, state = None, "perpetual"
        else:
            # A printed expiry date is not in the documented captures; do not guess its format.
            expiry, state = None, "unknown"
            complete = False
        rows.append({"name": match[1], "state": state, "expires_on": expiry})
    if not header:
        return None, False
    return rows, complete


def _nxos_assemble(scope, reads):
    facts = _Facts(scope, reads)
    identity = _identity(facts, scope.platform)
    virtual = bool(_usable(reads, "version")) and "Nexus 9000v is a demo version" in reads["version"].text
    _nxos_resources(facts)
    _nxos_interfaces(facts)
    _nxos_environment(facts, virtual)
    _nxos_redundancy(facts, virtual)
    if read := _usable(reads, "license_usage"):
        rows, complete = nxos_licenses(read.text)
        if not complete:
            facts.bad("license_usage")
        if rows is not None:
            facts.fields["licenses"] = [dict(row, read_ids=["license_usage"]) for row in rows]
    # Nexus switches in the supported scope have no PSE ports.
    facts.fields["poe"] = None
    facts.need("poe", "not_applicable", "version" if identity else None)
    facts.fields["fortiguard"] = None
    facts.need("fortiguard", "not_applicable")
    facts.fields["managed"] = None
    return facts.finish()


def assemble(scope, reads):
    if scope.platform == "cisco_nxos":
        return _nxos_assemble(scope, reads)
    return _ios_assemble(scope, reads)
