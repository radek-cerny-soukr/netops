"""Junos and Junos ELS evidence for the Helper network overview."""

from collections import Counter
import re

from netops_core import tested

from .. import junos_poe, normalization, port_errors, tables, triage_health
from ..query_catalog.junos import TESTED_G134
from .model import DeviceFacts, ReadSpec, missing, refused_lines

_ELS = "juniper_junos_els"
_DOWN = "interfaces.admin_up_down"
_ERRORS = "interfaces.with_errors"
_MEMBER_HEADING = re.compile(r"(?m)^(fpc|re)([0-9]+):[ \t]*$")
_PORT = re.compile(r"(?:ge|xe|et|fe|mge)-[0-9]+/[0-9]+/[0-9]+(?::[0-9]+)?")
_AGE = re.compile(r"(?:(\d+)d )?(\d{1,2}):([0-5]\d)(?::([0-5]\d))?")
_RE_STATUS = re.compile(r"(?m)^Routing Engine status:[ \t]*$")
_RE_SLOT = re.compile(r"(?m)^[ \t]+Slot ([0-9]+):[ \t]*$")
_ERROR_COUNTERS = ("rx_errors", "tx_errors", "crc")
_NO_POE = "warning: satellite-platform-management-process subsystem not running - not needed by configuration."


def plan(scope):
    specs = [
        ReadSpec("version", "version", ("version", "model")),
        ReadSpec("routing_engine", "routing_engine", ("cpu", "memory")),
        ReadSpec("interfaces", "interfaces", (_DOWN,)),
    ]
    if scope.platform == _ELS:
        specs += [ReadSpec("virtual_chassis", "virtual_chassis", ("redundancy",)),
                  ReadSpec("virtual_chassis_ports", "virtual_chassis_ports", ("redundancy",),
                           requires=("virtual_chassis",))]
    elif "firewall" in scope.device_types:
        specs.append(ReadSpec("chassis_cluster_status", "chassis_cluster_status", ("redundancy",)))
    return (*specs,
            ReadSpec("environment", "environment", ("temperatures", "fans", "power")),
            *((ReadSpec("poe_controller", "poe_controller", ("poe",)),) if scope.platform == _ELS else ()),
            ReadSpec("licenses", "licenses", ("licenses",)),
            ReadSpec("uptime", "uptime", ("uptime_seconds",)),
            *(ReadSpec(f"interface_details:{index}", "interface_details", (_ERRORS,), {"interface": interface})
              for index, interface in enumerate(scope.read_inventory.get("interfaces", ()), 1)
              if _PORT.fullmatch(interface)))


def _blocks(text, pattern):
    matches = list(pattern.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        yield match, text[match.end():end]


def _active_re(text):
    """Name the reported active RE, keeping the slot and member namespaces distinct."""
    engines = []
    sections = list(_blocks(text, _MEMBER_HEADING)) or [(None, text)]
    for member, section in sections:
        for _, heading in _blocks(section, _RE_STATUS):
            for slot, block in list(_blocks(heading, _RE_SLOT)) or [(None, heading)]:
                states = re.findall(r"(?m)^[ \t]+Current state[ \t]+(\S+)[ \t]*$", block)
                if states == ["Master"]:
                    selection = member.groups() if member else ("re", slot[1]) if slot else None
                    engines.append((selection, f"Routing Engine status:\n{block}"))
    return engines[0] if len(engines) == 1 else (None, None)


def _local(text, active_member):
    sections = list(_blocks(text, _MEMBER_HEADING))
    if not sections:
        return text
    matches = [block for member, block in sections if member.groups() == active_member]
    return matches[0] if len(matches) == 1 else None


def _identity(facts, text, platform):
    if text is None:
        return False
    try:
        ident = normalization.parse_identity(platform, text)
    except normalization.IdentityError:
        return False
    version, model = ident["os_version"], ident["model"]
    facts.fields.update(version=version, model=model)
    facts.fields["firmware_support"] = tested.support(
        "Junos", version, TESTED_G134, model=model, function="network_overview",
    )
    return model is not None


def _uptime(facts, text):
    if text is None:
        return False
    try:
        record = {"uptime": None}
        normalization.supplement_identity(record, "uptime", text)
    except normalization.IdentityError:
        return False
    age = _AGE.fullmatch(record["uptime"] or "")
    if age is None:
        return False
    days, hours, minutes, seconds = (int(value or 0) for value in age.groups())
    facts.fields["uptime_seconds"] = days * 86400 + hours * 3600 + minutes * 60 + seconds
    return True


def _resources(facts, active):
    if active is None:
        return False
    try:
        resource, = triage_health._junos_routing_engine(active)
    except triage_health.Unparsed:
        return False
    sample = 300 if resource["cpu_sample"] == "5_minutes" else None
    facts.fields["cpu"] = {"used_pct": resource["cpu_used_percent"], "sample_seconds": sample}
    facts.fields["memory"] = {"used_pct": resource["memory_used_percent"], "used_bytes": None, "total_bytes": None}
    return True


def _interfaces(facts, text):
    rows, unknown = tables.junos_interfaces(text)
    physical = [row for row in rows if _PORT.fullmatch(row["name"])]
    names = Counter(row["name"] for row in physical)
    down = [{"name": row["name"], "read_ids": ["interfaces"]} for row in physical
            if row["admin_status"] == "up" and row["oper_status"] == "down" and names[row["name"]] == 1]
    complete = bool(rows) and not unknown and all(count == 1 for count in names.values())
    if down or complete:
        facts.fields["interfaces"]["admin_up_down"] = down
    return complete


def _port_errors(facts, text, interface, read_id):
    # A logical section may repeat a label from the physical block. Keep only
    # the unique enrolled physical interface and its own input/output totals.
    block = re.split(r"(?m)^[ \t]*Logical interface ", text, maxsplit=1)[0]
    headers = re.findall(r"(?m)^Physical interface: ([^,]+),", block)
    if headers != [interface]:
        return False
    rows, _ = port_errors.junos(block)
    row, = rows
    if row["admin_status"] is None:
        return False
    counters = {key: row[key] for key in _ERROR_COUNTERS if row[key] is not None}
    if any(counters.values()):
        facts.fields["interfaces"]["with_errors"].append(
            {"name": row["port"], "counters": counters, "counter_kind": "cumulative", "read_ids": [read_id]},
        )
    return {"rx_errors", "tx_errors"} <= counters.keys()


def _environment(facts, text):
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or lines[0].split() != ["Class", "Item", "Status", "Measurement"]:
        return False
    categories = {"Temp": "temperatures", "Fans": "fans", "Power": "power"}
    states = {"ok": "ok", "testing": "warning", "check": "warning", "abnormal": "warning",
              "alarm": "failed", "failed": "failed", "offline": "failed", "online": "ok"}
    field = None
    complete = True
    for line in lines[1:]:
        if not line[0].isspace():
            category, _, line = line.partition(" ")
            field = categories.get(category)
        if field is None:
            complete = False
            continue
        try:
            row, = triage_health._junos_environment(f"{lines[0]}\n{line}")
        except triage_health.Unparsed:
            complete = False
            continue
        state = states.get(row["status"], "unknown")
        item = {"name": row["item"], "state": state}
        if field == "temperatures":
            measurement = re.fullmatch(r"(-?\d+) degrees C(?: / -?\d+ degrees F)?", row["measurement"] or "")
            if measurement:
                item["celsius"] = int(measurement[1])
        facts.fields.setdefault(field, []).append(item)
    return complete and all(field in facts.fields for field in categories.values())


def _poe(facts, text):
    if text.strip() == _NO_POE:
        facts.missing.append(missing("poe", "not_applicable", read_id="poe_controller"))
        return True
    data = junos_poe.parse("poe_controller", text, "ok")
    rows = data["records"]
    if (data["state"] != "measured" or len({row["controller"] for row in rows}) != len(rows)
            or any(row["power_w"] > row["max_power_w"] for row in rows)):
        return False
    budget = sum(row["max_power_w"] for row in rows)
    used = sum(row["power_w"] for row in rows)
    facts.fields["poe"] = {"budget_w": round(budget, 3), "used_w": round(used, 3),
                           "available_w": round(budget - used, 3)}
    return True


def _cluster(facts, text):
    data = tables.junos_cluster_status(text)
    if not data["records"]:
        return False
    groups = Counter(group["group"] for group in data["records"])
    complete = data["complete"] and all(count == 1 for count in groups.values())
    items = []
    for group in data["records"]:
        if groups[group["group"]] != 1:
            continue
        nodes = group["nodes"]
        roles = Counter(node["status"] for node in nodes)
        known_roles = all(role in {"primary", "secondary", "hold", "disabled"} for role in roles)
        if len(nodes) != 2 or len({node["node"] for node in nodes}) != 2 or not known_roles:
            state = "unknown"
            complete = False
        else:
            healthy = roles == {"primary": 1, "secondary": 1} and all(
                node["priority"] > 0 and not node["monitor_failures"] for node in nodes
            )
            state = "ok" if healthy else "degraded"
        items.append({"kind": "ha", "group": group["group"], "state": state,
                      "members": [{"name": node["node"], "role": node["status"] if known_roles else None}
                                  for node in nodes],
                      "read_ids": ["chassis_cluster_status"]})
    if items:
        facts.fields["redundancy"] = items
    return complete


def assemble(scope, reads):
    facts = DeviceFacts(
        {"interfaces": {"scope": "enrolled_interfaces", "admin_up_down": None, "with_errors": None}},
        [missing("fortiguard", "not_applicable"), missing("managed", "not_applicable"),
         missing(_ERRORS, "source_limit")],
    )
    routing_engine = reads["routing_engine"]
    member, active = _active_re(routing_engine.text or "") if routing_engine.status == "ok" else (None, None)
    errors = facts.fields["interfaces"]
    complete_port = False
    for read_id, read in reads.items():
        if read.status != "ok":
            continue
        text = read.text or ""
        if read_id == "version":
            complete = _identity(facts, _local(text, member), scope.platform)
        elif read_id == "uptime":
            complete = _uptime(facts, _local(text, member))
        elif read_id == "routing_engine":
            complete = _resources(facts, active)
        elif read_id == "interfaces":
            complete = _interfaces(facts, text)
        elif read_id == "environment":
            complete = _environment(facts, text)
        elif read_id == "poe_controller":
            complete = _poe(facts, text)
        elif read_id == "licenses":
            complete = [line.strip() for line in text.splitlines() if line.strip()] == [
                "License usage: none", "Licenses installed: none",
            ]
            if complete:
                facts.fields["licenses"] = []
        elif read_id == "chassis_cluster_status":
            complete = _cluster(facts, text)
        elif read_id in {"virtual_chassis", "virtual_chassis_ports"}:
            # The available ELS capture only reports a stopped VC subsystem,
            # which the shared transport classifies before it reaches here.
            complete = False
        elif read.spec.query == "interface_details":
            if errors["with_errors"] is None:
                errors["with_errors"] = []
            complete = _port_errors(facts, text, read.spec.parameters["interface"], read_id)
            complete_port |= complete
        else:
            continue
        if not complete:
            facts.incomplete_reads += (read_id,)
    if not complete_port and not errors["with_errors"]:
        errors["with_errors"] = None
    if "poe_controller" not in reads:
        known_router = facts.fields.get("model") == "mx480"
        facts.missing.append(missing("poe", "not_applicable" if known_router else "source_limit"))
    if not {"virtual_chassis", "chassis_cluster_status"} & reads.keys():
        facts.missing.append(missing("redundancy", "source_limit"))
    answered = {}
    version = reads["version"]
    simulated = version.status == "ok" and _SIMULATION.search(version.text or "") is not None
    virtual_chassis = reads.get("virtual_chassis")
    if (simulated and virtual_chassis is not None and virtual_chassis.rc == 0
            and refused_lines(virtual_chassis) == _NO_VIRTUAL_CHASSIS):
        # The standalone vJunos-switch runs no VC control process; its member ports are not read. On a
        # physical switch the same message can be a stopped process of a configured stack, so it stays unparsed.
        answered["virtual_chassis"] = "not_applicable"
    environment = reads.get("environment")
    if simulated and environment is not None and environment.rc == 0 and refused_lines(environment) == []:
        # The vJunos-switch image prints no chassis environment at all (measured on 26.2R1.7, exit status 0).
        # A failed read with empty stdout (its refusal on stderr is not kept) is not that answer.
        answered["environment"] = "not_applicable"
    facts.answered_reads = answered
    return facts


_NO_VIRTUAL_CHASSIS = ["error: the virtual-chassis-control subsystem is not running"]
_SIMULATION = re.compile(r"(?m)^JUNOS Simulation Package \[")
