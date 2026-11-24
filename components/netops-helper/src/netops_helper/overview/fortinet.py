"""FortiOS network overview adapter: the FortiGate, its FortiLink switches and its managed access points.

Every value comes from a read the frame executed for this alias. The adapter parses the redacted CLI text or
the redacted HTTPS monitor document only; it never opens a transport and never routes to an address or a
credential printed by the controller. Shapes are the measured FortiOS 8.0.2 (FortiGate-80F) and 7.6.8
(FortiGate-60F) outputs in the test fixtures; anything else is reported as unparsed instead of being guessed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re

from .. import fortiswitch_ports, switch_mclag, triage_health
from . import model

# Measured live with this adapter (FortiOS identity of the controller; firmware_support only warns elsewhere).
TESTED = (("FortiGate-80F", "8.0.2", "0251"),)
FUNCTION = "network_overview"

SWITCH_SLOT = "managed_switches"
INTERFACE_SLOT = "interfaces"
TRUNK_SLOT = "managed_switch_trunks"
# Detail reads of enrolled objects; the frame's per-target quota (30) bounds the whole plan.
MAX_ENROLLED_INTERFACES = 8
MAX_ENROLLED_SWITCHES = 8
LINK_TYPES = frozenset({"physical", "aggregate", "redundant", "hard-switch"})
_HEALTH_RATING = {"good": "ok", "fair": "warning", "poor": "failed"}


def _first(scope, *queries):
    """The first enrolled alternative; without one the primary query (the frame then reports policy_scope)."""
    return next((query for query in queries if query in scope.enabled_queries), queries[0])


def _enrolled(scope, slot, cap):
    """The enrolled objects that get detail reads, and how many enrolled objects beyond the cap get none."""
    items = tuple(scope.read_inventory.get(slot, ()))
    return items[:cap], max(0, len(items) - cap)


def plan(scope):
    """Fixed read order: identity, CPU/memory, interface state, redundancy, sensors, licences, enrolled detail."""
    specs = [
        model.ReadSpec("system_status", "system_status", ("version", "model", "licenses", "poe")),
        model.ReadSpec("performance", "performance", ("uptime_seconds", "cpu", "memory")),
        model.ReadSpec("system_interfaces", "system_interfaces", ("interfaces.admin_up_down",)),
        model.ReadSpec("link_state", _first(scope, "interface_list", "physical_interfaces"),
                       ("interfaces.admin_up_down",)),
        model.ReadSpec("ha_status", "ha_status", ("redundancy",)),
        model.ReadSpec("hardware_sensors", "hardware_sensors", ("temperatures", "fans", "power")),
        model.ReadSpec("autoupdate_versions", "autoupdate_versions", ("fortiguard",)),
    ]
    switches, _ = _enrolled(scope, SWITCH_SLOT, MAX_ENROLLED_SWITCHES)
    enabled = set(scope.enabled_queries)

    def switch_cli(query, serial):
        return model.ReadSpec(f"{query}:{serial}", query, ("managed",), {"managed_switch": serial})

    if scope.https_enrolled:
        specs += [model.ReadSpec(name, name, ("managed",), transport="https")
                  for name in ("switch_status", "switch_health", "managed_ap", "ap_status")]
    else:
        for serial in switches:
            specs += [switch_cli("managed_switch_status", serial), switch_cli("managed_switch_poe", serial)]
        specs.append(model.ReadSpec("wifi_ap_status", "wifi_ap_status", ("managed",)))
    for serial in switches:
        # One full port listing per switch serves the admin/link view and the error counters.
        specs.append(switch_cli("managed_switch_port_stats", serial))
    query = _first(scope, "interface_details", "interface_hardware")
    for name in _enrolled(scope, INTERFACE_SLOT, MAX_ENROLLED_INTERFACES)[0]:
        specs.append(model.ReadSpec(f"{query}:{name}", query, ("interfaces.with_errors",), {"interface": name}))
    if scope.https_enrolled:
        # A refused monitor does not hide what the permitted CLI reads show; only opted-in queries are planned.
        for serial in switches:
            specs += [switch_cli(query, serial) for query in ("managed_switch_status", "managed_switch_poe")
                      if query in enabled]
        if "wifi_ap_status" in enabled:
            specs.append(model.ReadSpec("wifi_ap_status", "wifi_ap_status", ("managed",)))
    trunks = tuple(scope.read_inventory.get(TRUNK_SLOT, ()))
    for serial in switches:
        # Stack and MCLAG state of an enrolled switch, only for queries the account has opted in to.
        if "managed_switch_stacking" in enabled:
            specs.append(switch_cli("managed_switch_stacking", serial))
        if "switch_mclag_icl" in enabled:
            icl = switch_cli("switch_mclag_icl", serial)
            specs.append(icl)
            if "switch_trunk_status" in enabled:
                specs += [model.ReadSpec(f"switch_trunk_status:{serial}:{trunk}", "switch_trunk_status", ("managed",),
                                         {"managed_switch": serial, "mclag_trunk": trunk}, requires=(icl.id,))
                          for trunk in trunks]
    return tuple(specs)


class _Facts:
    def __init__(self, reads):
        self.reads = reads
        self.fields = {}
        self.missing = []
        self.incomplete = set()
        self.answered = {}

    def usable(self, read_id):
        read = self.reads.get(read_id)
        return read is not None and read.status in ("ok", "empty") and (read.text is not None
                                                                        or read.document is not None)

    def lack(self, field, reason, read_id=None):
        entry = model.missing(field, reason, **({"read_id": read_id} if read_id else {}))
        if entry not in self.missing:
            self.missing.append(entry)

    def unparsed(self, read_id, field=None):
        self.incomplete.add(read_id)
        if field is not None:
            self.lack(field, "unparsed", read_id)


# --- FortiGate ------------------------------------------------------------------------------------------------

def _status(facts):
    """Identity: product, version and build; no host name or serial is published."""
    if not facts.usable("system_status"):
        return None
    text = facts.reads["system_status"].text
    try:
        ident = triage_health.identity(text)
    except triage_health.UnsupportedPlatform:
        facts.unparsed("system_status", "version")
        return None
    facts.fields["version"] = f"{ident['version']} build{ident['build']}"
    facts.fields["model"] = ident["product"]
    facts.fields["firmware_support"] = triage_health.firmware_support(ident, TESTED, FUNCTION)
    ha = re.findall(r"(?m)^Current HA mode:[ \t]*([a-z-]+)(?:,[ \t]*([a-z]+))?[ \t]*$", text)
    # Hardware FortiGate status has no licence lines; VM licence lines are not measured here.
    if "-VM" in ident["product"].upper():
        facts.lack("licenses", "source_limit", "system_status")
    else:
        facts.lack("licenses", "not_applicable", "system_status")
    if "POE" in ident["product"].upper():
        facts.lack("poe", "source_limit", "system_status")
    else:
        facts.lack("poe", "not_applicable", "system_status")
    return {"ha": ha[0] if len(ha) == 1 else None}


_UPTIME = re.compile(r"(?m)^Uptime:[ \t]+(\d+) days?,[ \t]+(\d+) hours?,[ \t]+(\d+) minutes?[ \t]*$")
_MEMORY = re.compile(r"(?m)^Memory:[ \t]+(\d+)k total,[ \t]+(\d+)k used \(([\d.]+)%\)")


def _performance(facts):
    if not facts.usable("performance"):
        return
    text = facts.reads["performance"].text
    try:
        parsed = triage_health.performance(text)
    except triage_health.Unparsed:
        facts.unparsed("performance")
        return
    memory = _MEMORY.findall(text)
    uptime = _UPTIME.findall(text)
    if len(memory) != 1 or len(uptime) != 1:
        facts.unparsed("performance")
        return
    total, used, percent = memory[0]
    days, hours, minutes = (int(value) for value in uptime[0])
    # The aggregate line has no sampling interval header, so sample_seconds stays null.
    facts.fields["cpu"] = {"used_pct": 100 - parsed["cpu_idle_percent"], "sample_seconds": None}
    facts.fields["memory"] = {"used_pct": float(percent), "total_bytes": int(total) * 1024,
                              "used_bytes": int(used) * 1024}
    facts.fields["uptime_seconds"] = ((days * 24 + hours) * 60 + minutes) * 60


_SYSTEM_INTERFACE = re.compile(r"name: (\S+)\s+.*?\bstatus: (up|down)\b.*?\btype: (\S+)")
_NETLINK_HEAD = re.compile(r"if=(\S+) .*")
_NETLINK_FLAGS = re.compile(r"ref=\d+ .*\bflags=([a-z ]+?)\s*$")


def _admin_states(text):
    """`get system interface`: one attribute line per interface; status is the configured admin state."""
    states, unknown = {}, 0
    for line in text.splitlines():
        value = line.strip()
        if not value or re.fullmatch(r"== \[ \S+ \]", value):
            continue
        found = _SYSTEM_INTERFACE.match(value)
        if found is None or found[1] in states:
            unknown += 1
            continue
        states[found[1]] = {"admin": found[2], "type": found[3]}
    return states, unknown


def _netlink_links(text):
    """`diagnose netlink interface list`: link is `run` (carrier) or `no_carrier`; anything else is unknown."""
    links, unknown, current = {}, 0, None
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        head = _NETLINK_HEAD.fullmatch(value)
        if head:
            current = head[1]
            if current in links:
                unknown += 1
            links[current] = None
            continue
        flags = _NETLINK_FLAGS.fullmatch(value)
        if flags and current is not None:
            words = value.split()
            if "no_carrier" in words:
                links[current] = "down"
            elif "run" in flags[1].split():
                links[current] = "up"
            continue
        if current is None:
            unknown += 1
    return links, unknown


def _physical_links(text):
    ports = triage_health.physical_interfaces(text)
    return {port["name"]: port["status"] for port in ports}, 0


def _interfaces(facts, omitted_interfaces):
    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    if facts.usable("system_interfaces") and facts.usable("link_state"):
        admin, unknown = _admin_states(facts.reads["system_interfaces"].text)
        if unknown or not admin:
            facts.unparsed("system_interfaces")
        else:
            link_read = facts.reads["link_state"]
            try:
                links, broken = (_netlink_links(link_read.text) if link_read.spec.query == "interface_list"
                                 else _physical_links(link_read.text))
            except triage_health.Unparsed:
                links, broken = {}, 1
            if broken or not links:
                facts.unparsed("link_state")
            else:
                down, uncovered = [], 0
                for name, state in sorted(admin.items()):
                    if state["type"] not in LINK_TYPES or state["admin"] != "up":
                        continue
                    if name not in links:
                        # e.g. a hardware switch or aggregate is not in `get system interface physical`
                        uncovered += 1
                        continue
                    if links[name] is None:
                        facts.unparsed("link_state")
                        down = None
                        break
                    if links[name] == "down":
                        down.append({"name": name, "read_ids": ["system_interfaces", "link_state"]})
                if down is not None:
                    interfaces["admin_up_down"] = down
                    if uncovered:
                        # Admin-up interfaces without a link row are not reported as up: narrower coverage.
                        facts.missing.append(model.missing("interfaces.admin_up_down", "source_limit",
                                                           read_id="link_state", omitted_count=uncovered))
    errors = []
    detail = [read for key, read in facts.reads.items() if key.startswith(("interface_details:", "interface_hardware:"))]
    facts.lack("interfaces.with_errors", "source_limit")
    if omitted_interfaces:
        # Enrolled interfaces beyond the detail cap are not read; their count stays visible.
        facts.missing.append(model.missing("interfaces.with_errors", "source_limit",
                                           omitted_count=omitted_interfaces))
    if detail:
        # The device-wide netlink list has no counter block on the measured firmware: enrolled ports only.
        interfaces["scope"] = "enrolled_interfaces"
        complete = True
        for read in detail:
            if not facts.usable(read.spec.id):
                complete = False
                continue
            counters = (_netlink_counters(read.text) if read.spec.query == "interface_details"
                        else _nic_counters(read.text))
            if counters is None:
                facts.unparsed(read.spec.id)
                complete = False
                continue
            if any(counters[key] for key in counters if "errors" in key):
                errors.append({"name": read.spec.parameters["interface"], "counters": counters,
                               "counter_kind": "cumulative", "read_ids": [read.spec.id]})
        interfaces["with_errors"] = errors if complete or errors else None
    facts.fields["interfaces"] = interfaces


_NETLINK_STAT = re.compile(r"stat: rxp=\d+ txp=\d+ rxb=\d+ txb=\d+ rxe=(\d+) txe=(\d+) rxd=(\d+) txd=(\d+) "
                           r"mc=\d+ collision=(\d+)(?: @ time=\d+)?")
_NETLINK_RX = re.compile(r"re: rxl=(\d+) rxo=(\d+) rxc=(\d+) rxf=(\d+) rxfi=(\d+) rxm=(\d+)")


def _netlink_counters(text):
    """`diagnose netlink interface list <port>`: cumulative error, drop and CRC counters of one interface."""
    stats = [found for line in text.splitlines() if (found := _NETLINK_STAT.fullmatch(line.strip()))]
    receive = [found for line in text.splitlines() if (found := _NETLINK_RX.fullmatch(line.strip()))]
    heads = [line for line in text.splitlines() if line.startswith("if=")]
    if len(stats) != 1 or len(receive) != 1 or len(heads) != 1:
        return None
    rxe, txe, rxd, txd, collisions = (int(value) for value in stats[0].groups())
    return {"input_errors": rxe, "output_errors": txe, "input_drops": rxd, "output_drops": txd,
            "collisions": collisions, "crc_errors": int(receive[0][3])}


def _nic_counters(text):
    """`diagnose hardware deviceinfo nic <port>`: only explicitly named error counters, otherwise unparsed."""
    values = dict(re.findall(r"(?m)^(Rx_Errors|Tx_Errors|Rx_CRC_Errors|Rx_Dropped|Tx_Dropped)\s*[:=]\s*(\d+)\s*$", text))
    if not {"Rx_Errors", "Tx_Errors"} <= set(values):
        return None
    result = {"input_errors": int(values["Rx_Errors"]), "output_errors": int(values["Tx_Errors"])}
    for name, key in (("Rx_CRC_Errors", "crc_errors"), ("Rx_Dropped", "input_drops"), ("Tx_Dropped", "output_drops")):
        if name in values:
            result[key] = int(values[name])
    return result


def _redundancy(facts, status):
    sources = [key for key in ("system_status", "ha_status") if facts.usable(key)]
    mode = (status or {}).get("ha")
    if mode is not None and mode[0] == "standalone":
        facts.fields["redundancy"] = [{"kind": "ha", "state": "standalone", "read_ids": ["system_status"]}]
        return
    if not facts.usable("ha_status"):
        return
    text = facts.reads["ha_status"].text
    try:
        parsed = triage_health.ha_status(text)
    except triage_health.Unparsed:
        facts.unparsed("ha_status")
        return
    if parsed["mode"].lower() == "standalone":
        facts.fields["redundancy"] = [{"kind": "ha", "state": "standalone", "read_ids": ["ha_status"]}]
        return
    members = re.findall(r"(?m)^number of member: (\d+)\s*$", text)
    health = parsed["health_status"]
    entry = {"kind": "ha", "state": "ok" if health == "OK" and not parsed["warnings"] else "degraded",
             "read_ids": sources}
    if mode is not None and mode[1]:
        entry["role"] = mode[1]
    if len(members) == 1:
        entry["members"] = int(members[0])
    facts.fields["redundancy"] = [entry]


_SENSOR_KIND = (("PSU", "power"), ("Temperature", "temperatures"), ("Fan", "fans"))


def _sensors(facts):
    if not facts.usable("hardware_sensors"):
        return
    parsed = triage_health.hardware_sensors(facts.reads["hardware_sensors"].text, 0, 1 << 30)
    if parsed["state"] != "ok":
        facts.unparsed("hardware_sensors")
        return
    found = {"temperatures": [], "fans": [], "power": []}
    for sensor in parsed["sensors"]:
        kind = next((field for prefix, field in _SENSOR_KIND if (sensor["type"] or "").startswith(prefix)), None)
        if kind is None:
            if not (sensor["type"] or "").startswith("Voltage"):
                facts.unparsed("hardware_sensors")
                return
            continue  # a voltage alone does not prove that a supply works
        if sensor["absent"]:
            continue  # an empty optional PSU slot is not a supply
        state = "unknown"
        if sensor["alarm"] is True:
            state = "failed" if kind == "power" else "warning"
        elif kind == "power" and sensor["reading"].strip().upper() == "OK" and sensor["alarm"] is False:
            state = "ok"
        elif kind != "power" and (sensor["sensor_status"] or "").lower() == "normal":
            state = "ok"
        entry = {"name": sensor["name"], "state": state, "read_ids": ["hardware_sensors"]}
        if kind == "temperatures" and sensor["unit"] == "C":
            entry["celsius"] = sensor["value"]
        found[kind].append(entry)
    for field, entries in found.items():
        if entries:
            facts.fields[field] = entries
        else:
            # The sensor list is the model's own complete answer: no such sensor on this model.
            facts.lack(field, "not_applicable", "hardware_sensors")


def _fortiguard(facts):
    if not facts.usable("autoupdate_versions"):
        return
    try:
        packages = triage_health.autoupdate_versions(facts.reads["autoupdate_versions"].text)
    except triage_health.Unparsed:
        facts.unparsed("autoupdate_versions")
        return
    entries = []
    for package in packages:
        expiry = package["contract_expiry"]
        if expiry is None:
            continue  # a package without a contract line has no FortiGuard contract to report
        if expiry == "n/a":
            entries.append({"name": package["package"], "state": "unknown", "expires_on": None,
                            "read_ids": ["autoupdate_versions"]})
            continue
        day = datetime.strptime(" ".join(expiry.split()), "%a %b %d %Y").date().isoformat()
        entries.append({"name": package["package"], "state": model.expiry_state(day), "expires_on": day,
                        "read_ids": ["autoupdate_versions"]})
    facts.fields["fortiguard"] = entries


# --- managed children -------------------------------------------------------------------------------------------

_OS_VERSION = re.compile(r"([A-Z0-9]+)-v(\d+\.\d+(?:\.\d+)?)-build(\d+)\b.*")
_CHILD_FIELDS = ("cpu", "memory", "temperatures", "fans", "power", "poe", "interfaces", "redundancy",
                 "licenses", "fortiguard")


def _child(kind, identifier):
    entry = {"kind": kind, "id": identifier, "model": None, "version": None, "uptime_seconds": None,
             "reported_state": None, **dict.fromkeys(_CHILD_FIELDS), "status": "partial", "read_ids": []}
    entry["interfaces"] = {"scope": "device", "admin_up_down": None, "with_errors": None}
    return entry


def _build(number):
    """REST prints `build069`, the CLI `build0069` for the same image: one public spelling."""
    return f"build{int(number):04d}"


def _os_version(value):
    """Platform code and version of a FortiSwitch/FortiAP image string (`S224EP-v8.0.1-build069,...`)."""
    found = _OS_VERSION.fullmatch(value) if isinstance(value, str) else None
    return (found[1], f"{found[2]} {_build(found[3])}") if found else (None, None)


def _rows(facts, read_id):
    """`results` of a verified monitor document, or None when the read is unusable or of another shape."""
    if not facts.usable(read_id):
        return None
    results = facts.reads[read_id].document.get("results")
    expected = dict if read_id == "ap_status" else list
    if not isinstance(results, expected) or (expected is list and not all(isinstance(row, dict) for row in results)):
        facts.unparsed(read_id)
        return None
    return results


def _number(value):
    return value if type(value) in (int, float) and value >= 0 else None


def _switches_https(facts, enrolled):
    status = _rows(facts, "switch_status")
    if status is None:
        return None
    health = _rows(facts, "switch_health")
    by_serial = {}
    for row in health or ():
        by_serial.setdefault(row.get("serial"), []).append(row)
    children, serials = [], []
    counts = _serial_counts(status, "serial")
    ambiguous = {serial for serial, count in counts.items() if count > 1}
    for row in status:
        serial = row.get("serial")
        if not isinstance(serial, str) or not serial or serial in ambiguous:
            # An ambiguous or anonymous row is not joined to anything, whatever the order of the rows.
            facts.unparsed("switch_status")
            continue
        serials.append(serial)
        child = _child("fortiswitch", serial)
        child["read_ids"].append("switch_status")
        child["model"], child["version"] = _os_version(row.get("os_version"))
        state = row.get("status")
        child["reported_state"] = state.lower() if isinstance(state, str) else None
        child["licenses"] = child["fortiguard"] = None
        child["_missing"] = [("licenses", "not_applicable", "switch_status"),
                             ("fortiguard", "not_applicable", "switch_status")]
        if child["model"] is None:
            child["_missing"].append(("version", "unparsed", "switch_status"))
        matches = by_serial.get(serial, [])
        if health is None or len(matches) != 1:
            if health is None:
                reason = facts.reads["switch_health"].reason or "unparsed"
            else:
                reason = "unparsed" if matches else "source_limit"
                if matches:
                    facts.unparsed("switch_health")
            fields = ("uptime_seconds", "cpu", "memory", "temperatures", "fans", "power")
            child["_missing"] += [(field, reason, "switch_health") for field in fields]
            # The PoE budget of an enrolled switch is also in its permitted CLI read.
            if not _cli_poe(facts, child):
                child["_missing"].append(("poe", reason, "switch_health"))
        else:
            _switch_health(child, matches[0], row)
        children.append(child)
    for serial in enrolled:
        if serial not in serials:
            child = _child("fortiswitch", serial)
            child["_missing"] = [("reported_state", "unparsed" if serial in ambiguous else "source_limit",
                                  "switch_status")]
            children.append(child)
    return children


def _serial_counts(rows, *keys):
    counts = {}
    for row in rows:
        serial = next((row.get(key) for key in keys if row.get(key)), None)
        if isinstance(serial, str):
            counts[serial] = counts.get(serial, 0) + 1
    return counts


def _switch_health(child, row, status_row):
    child["read_ids"].append("switch_health")
    summary = row.get("summary") if isinstance(row.get("summary"), dict) else {}

    def rated(name):
        item = summary.get(name)
        return item if isinstance(item, dict) else {}

    uptime = rated("uptime").get("value")
    child["uptime_seconds"] = uptime if type(uptime) is int and uptime >= 0 else None
    cpu, memory = _number(rated("cpu").get("value")), _number(rated("memory").get("value"))
    child["cpu"] = {"used_pct": cpu, "sample_seconds": None} if cpu is not None else None
    child["memory"] = {"used_pct": memory, "total_bytes": None, "used_bytes": None} if memory is not None else None
    for field, value in (("uptime_seconds", child["uptime_seconds"]), ("cpu", cpu), ("memory", memory)):
        if value is None:
            child["_missing"].append((field, "source_limit", "switch_health"))
    rating = _HEALTH_RATING.get(rated("temperature").get("rating"), "unknown")
    temperatures = []
    for item in row.get("temperature") or ():
        value = item.get("status") if isinstance(item, dict) else None
        if not (isinstance(value, dict) and value.get("unit") == "celsius" and _number(value.get("value")) is not None
                and isinstance(item.get("module"), str)):
            child["_missing"].append(("temperatures", "unparsed", "switch_health"))
            temperatures = None
            break
        temperatures.append({"name": item["module"], "state": rating, "celsius": value["value"],
                             "read_ids": ["switch_health"]})
    child["temperatures"] = temperatures or None
    if temperatures == []:
        child["_missing"].append(("temperatures", "source_limit", "switch_health"))
    fans = []
    for item in row.get("fan") or ():
        if not (isinstance(item, dict) and isinstance(item.get("module"), str)):
            fans = None
            break
        fans.append({"name": item["module"], "state": "ok" if item.get("status") == "OK" else "unknown",
                     "read_ids": ["switch_health"]})
        speed = item.get("speed")
        if isinstance(speed, dict) and speed.get("unit") == "rpm" and type(speed.get("value")) is int:
            fans[-1]["rpm"] = speed["value"]
        if fans[-1]["state"] == "unknown":
            child["_missing"].append(("fans", "unparsed", "switch_health"))
    child["fans"] = fans or None
    if not fans:
        child["_missing"].append(("fans", "unparsed" if fans is None else "source_limit", "switch_health"))
    power = []
    for item in row.get("psu") or ():
        if not (isinstance(item, dict) and isinstance(item.get("name"), str)):
            power = None
            break
        if item.get("connection") == "Not inserted" and "status" not in item:
            continue  # an empty optional supply slot
        power.append({"name": item["name"], "state": "ok" if item.get("status") == "OK" else "unknown",
                      "read_ids": ["switch_health"]})
        if power[-1]["state"] == "unknown":
            child["_missing"].append(("power", "unparsed", "switch_health"))
    child["power"] = power or None
    if not power:
        child["_missing"].append(("power", "unparsed" if power is None else "source_limit", "switch_health"))
    poe = row.get("poe")
    budget = status_row.get("max_poe_budget")
    if isinstance(poe, dict) and poe.get("unit") == "watts" and _number(poe.get("max_value")) is not None \
            and _number(poe.get("value")) is not None:
        total, used = float(poe["max_value"]), float(poe["value"])
        child["poe"] = {"budget_w": total, "used_w": round(used, 2), "available_w": round(total - used, 2)}
    elif poe is None and budget == 0:
        child["_missing"].append(("poe", "not_applicable", "switch_status"))
    else:
        child["_missing"].append(("poe", "source_limit", "switch_health"))


def _switch_ports(facts, child):
    read_id = f"managed_switch_port_stats:{child['id']}"
    if read_id not in facts.reads:
        return
    if not facts.usable(read_id):
        child["_missing"].append(("interfaces", facts.reads[read_id].reason or "unparsed", read_id))
        return
    text = facts.reads[read_id].text
    rows, unknown = fortiswitch_ports.parse("interface", text)
    errors, unknown_errors = fortiswitch_ports.parse("interface_errors", text)
    if unknown or unknown_errors or not rows or len(rows) != len(errors):
        facts.unparsed(read_id)
        child["_missing"].append(("interfaces", "unparsed", read_id))
        return
    child["read_ids"].append(read_id)
    down = [{"name": row["name"], "read_ids": [read_id]} for row in rows
            if row["admin_status"] == "up" and row["oper_status"] == "down"]
    with_errors = []
    for row in errors:
        counters = {"input_errors": row["rx_errors"], "output_errors": row["tx_errors"],
                    "input_drops": row["discards_in"], "output_drops": row["discards_out"]}
        if row["rx_errors"] or row["tx_errors"]:
            with_errors.append({"name": row["port"], "counters": counters, "counter_kind": "cumulative",
                                "read_ids": [read_id]})
    child["interfaces"] = {"scope": "device", "admin_up_down": down, "with_errors": with_errors}


def _reason(facts, read_id):
    """Why a planned read gave no value: its own reason, unparsed, or source_limit when it was not planned."""
    read = facts.reads.get(read_id)
    if read is None:
        return "source_limit"
    return read.reason or "unparsed"


def _cli_version(facts, child):
    """Model and version of an enrolled switch from `managed_switch_status`; True when published."""
    status_id = f"managed_switch_status:{child['id']}"
    if not facts.usable(status_id):
        return False
    version = re.findall(r"(?m)^Version: (FortiSwitch-\S+) v(\d+\.\d+(?:\.\d+)?),build(\d+)", facts.reads[status_id].text)
    if len(version) != 1:
        facts.unparsed(status_id)
        return False
    child["model"], child["version"] = version[0][0], f"{version[0][1]} {_build(version[0][2])}"
    child["read_ids"].append(status_id)
    return True


_VDOM_LINE = re.compile(r"Vdom: \S+")


def _cli_poe(facts, child):
    """PoE budget and draw of an enrolled switch from `managed_switch_poe`; True when published."""
    poe_id = f"managed_switch_poe:{child['id']}"
    lines = model.refused_lines(facts.reads.get(poe_id))
    if lines is not None and [line for line in lines if not _VDOM_LINE.fullmatch(line)] == [
            f"switch:{child['id']} is not PoE capable", "Command fail. Return code -7622"]:
        # FortiOS 7.6.8 answers this for a FortiSwitch-108E without PSE ports.
        facts.answered[poe_id] = "not_applicable"
        child["_missing"].append(("poe", "not_applicable", poe_id))
        return False
    if not facts.usable(poe_id):
        return False
    text = facts.reads[poe_id].text
    budget = re.findall(r"(?m)^Unit Power Budget: ([\d.]+)W\s*$", text)
    used = re.findall(r"(?m)^Unit Power Consumption: ([\d.]+)W\s*$", text)
    if len(budget) != 1 or len(used) != 1:
        facts.unparsed(poe_id)
        return False
    total, spent = float(budget[0]), float(used[0])
    child["poe"] = {"budget_w": total, "used_w": spent, "available_w": round(total - spent, 2)}
    child["read_ids"].append(poe_id)
    return True


def _switches_cli(facts, enrolled, state_reason=("source_limit", None)):
    children = []
    for serial in enrolled:
        child = _child("fortiswitch", serial)
        child["_missing"] = [("licenses", "not_applicable", None), ("fortiguard", "not_applicable", None)]
        _cli_version(facts, child)
        _cli_poe(facts, child)
        # Connection state, uptime, CPU, memory and sensors are only in the HTTPS monitors.
        child["_missing"].append(("reported_state", *state_reason))
        child["_missing"] += [(field, state_reason[0], state_reason[1]) for field in
                              ("uptime_seconds", "cpu", "memory", "temperatures", "fans", "power")]
        for field, query in (("version", "managed_switch_status"), ("poe", "managed_switch_poe")):
            if child[field] is None and not any(item[0] == field for item in child["_missing"]):
                child["_missing"].append((field, _reason(facts, f"{query}:{serial}"), f"{query}:{serial}"))
        children.append(child)
    return children


def _aps_https(facts, observed):
    rows = _rows(facts, "managed_ap")
    if rows is None:
        return None
    summary = _rows(facts, "ap_status")
    if summary is not None:
        active, down = summary.get("wtp_active"), summary.get("wtp_down")
        connected = sum(1 for row in rows if row.get("status") == "connected")
        if type(active) is not int or type(down) is not int or active + down != len(rows) or active != connected:
            facts.unparsed("managed_ap")  # the controller's own summary disagrees with the listed rows
            facts.unparsed("ap_status")
    children = []
    counts = _serial_counts(rows, "serial", "wtp_id")
    for row in rows:
        serial = row.get("serial") or row.get("wtp_id")
        if not isinstance(serial, str) or not serial or counts[serial] > 1:
            facts.unparsed("managed_ap")
            continue
        child = _child("fortiap", serial)
        child["read_ids"].append("managed_ap")
        child["model"], child["version"] = _os_version(row.get("os_version"))
        state = row.get("status")
        child["reported_state"] = state.lower() if isinstance(state, str) else None
        child["_missing"] = [(field, "not_applicable", "managed_ap") for field in ("redundancy", "licenses", "fortiguard")]
        # A FortiAP draws PoE; radio power and LLDP data are no PSE budget.
        child["_missing"].append(("poe", "not_applicable", "managed_ap"))
        if child["model"] is None:
            child["_missing"].append(("version", "unparsed", "managed_ap"))
        if child["reported_state"] != "connected":
            # A disconnected AP reports zero placeholders and old samples, not current metrics.
            child["_missing"] += [(field, "unreachable", "managed_ap") for field in
                                  ("uptime_seconds", "cpu", "memory", "temperatures", "interfaces")]
            children.append(child)
            continue
        reboot = row.get("last_reboot_time_raw")
        if type(reboot) is int and observed is not None and 0 < reboot <= observed:
            child["uptime_seconds"] = observed - reboot
        else:
            child["_missing"].append(("uptime_seconds", "source_limit", "managed_ap"))
        cpu, total, free = row.get("cpu_usage"), row.get("mem_total"), row.get("mem_free")
        if type(cpu) is int and 0 <= cpu <= 100:
            child["cpu"] = {"used_pct": cpu, "sample_seconds": None}
        else:
            child["_missing"].append(("cpu", "source_limit", "managed_ap"))
        if type(total) is int and type(free) is int and 0 <= free <= total and total > 0:
            # The unit of mem_total/mem_free is not documented: only the ratio is published.
            child["memory"] = {"used_pct": round(100 * (total - free) / total, 1), "total_bytes": None, "used_bytes": None}
        else:
            child["_missing"].append(("memory", "source_limit", "managed_ap"))
        sensors = row.get("sensors_temperatures")
        if isinstance(sensors, list) and sensors and all(_number(value) is not None for value in sensors):
            child["temperatures"] = [{"name": f"sensor{index}", "state": "unknown", "celsius": value,
                                      "read_ids": ["managed_ap"]} for index, value in enumerate(sensors, 1)]
        else:
            child["_missing"].append(("temperatures", "source_limit", "managed_ap"))
        child["_missing"] += [(field, "source_limit", "managed_ap") for field in ("fans", "power")]
        wired = row.get("wired")
        errors = []
        if isinstance(wired, list) and wired and all(isinstance(port, dict) for port in wired):
            for port in wired:
                values = {key: port.get(key) for key in ("errors_rx", "errors_tx", "dropped_rx", "dropped_tx")}
                if not isinstance(port.get("interface"), str) or any(type(v) is not int or v < 0 for v in values.values()):
                    errors = None
                    break
                if values["errors_rx"] or values["errors_tx"]:
                    errors.append({"name": port["interface"], "counter_kind": "cumulative", "read_ids": ["managed_ap"],
                                   "counters": {"input_errors": values["errors_rx"], "output_errors": values["errors_tx"],
                                                "input_drops": values["dropped_rx"], "output_drops": values["dropped_tx"]}})
        else:
            errors = None
        child["interfaces"]["with_errors"] = errors
        if errors is None:
            child["_missing"].append(("interfaces.with_errors", "unparsed", "managed_ap"))
        # The wired view has carrier and counters but no administrative state.
        child["_missing"].append(("interfaces.admin_up_down", "source_limit", "managed_ap"))
        children.append(child)
    return children


def _aps_cli(facts):
    if model.refused_lines(facts.reads.get("wifi_ap_status")) == []:
        # A controller without managed access points prints nothing (FortiOS 7.6.8 on a FortiGate-60F,
        # FortiOS 8.0.2 on a FortiGate-80F): a valid empty list.
        facts.answered["wifi_ap_status"] = "empty"
        return []
    if not facts.usable("wifi_ap_status"):
        return None
    from .. import wifi_parse
    parsed = wifi_parse.parse_wtp_status(facts.reads["wifi_ap_status"].text)
    if parsed.get("unparsed"):
        facts.unparsed("wifi_ap_status")
    children = []
    for record in parsed["records"]:
        child = _child("fortiap", record["serial"])
        child["read_ids"].append("wifi_ap_status")
        child["model"], child["version"] = _os_version(record.get("version"))
        state = record.get("state")
        child["reported_state"] = state.lower() if isinstance(state, str) else None
        child["_missing"] = [(field, "not_applicable", "wifi_ap_status") for field in ("redundancy", "licenses", "fortiguard", "poe")]
        child["_missing"] += [(field, "source_limit", "wifi_ap_status") for field in
                              ("uptime_seconds", "cpu", "memory", "temperatures", "fans", "power", "interfaces")]
        children.append(child)
    return children


def _stack_and_mclag(facts, child):
    """Stack and MCLAG state of one enrolled switch from its opted-in operational reads."""
    serial, entries = child["id"], []
    stack_id = f"managed_switch_stacking:{serial}"
    if stack_id in facts.reads:
        # The stack status shape of a stacking switch is not measured; the measured refusal of a
        # non-stacking switch reaches the adapter only as a refused read (no device text).
        if facts.usable(stack_id):
            facts.unparsed(stack_id)
        child["_missing"].append(("redundancy", _reason(facts, stack_id), stack_id))
    icl_id = f"switch_mclag_icl:{serial}"
    if icl_id in facts.reads:
        if not facts.usable(icl_id):
            child["_missing"].append(("redundancy", _reason(facts, icl_id), icl_id))
        else:
            icl = switch_mclag.summarize("switch_mclag_icl", facts.reads[icl_id].text, {"managed_switch": serial})
            if icl["state"] == "not_configured":
                entries.append({"kind": "mlag", "state": "standalone", "read_ids": [icl_id]})
            elif icl["state"] != "configured" or icl["icl_trunk"] is None:
                facts.unparsed(icl_id)
                child["_missing"].append(("redundancy", "unparsed", icl_id))
            else:
                entries.append(_icl_health(facts, child, icl_id, icl["icl_trunk"]))
    if stack_id not in facts.reads and icl_id not in facts.reads:
        child["_missing"].append(("redundancy", "source_limit", None))
    child["redundancy"] = entries or None
    child["read_ids"] += [read_id for entry in entries for read_id in entry["read_ids"]]


def _icl_health(facts, child, icl_id, trunk):
    """ICL health from the enrolled trunk read of the ICL trunk; a down trunk or member is degraded."""
    trunk_id = f"switch_trunk_status:{child['id']}:{trunk}"
    entry = {"kind": "mlag", "state": "unknown", "read_ids": [icl_id]}
    if trunk_id not in facts.reads:
        child["_missing"].append(("redundancy", "source_limit", icl_id))  # the ICL trunk is not enrolled
        return entry
    if not facts.usable(trunk_id):
        child["_missing"].append(("redundancy", _reason(facts, trunk_id), trunk_id))
        return entry
    state = switch_mclag.summarize("switch_trunk_status", facts.reads[trunk_id].text, {"mclag_trunk": trunk})
    if state["state"] not in ("ok", "degraded", "down") or state.get("role") != "icl":
        facts.unparsed(trunk_id)
        child["_missing"].append(("redundancy", "unparsed", trunk_id))
        return entry
    entry["state"] = "ok" if state["state"] == "ok" else "degraded"
    entry["read_ids"].append(trunk_id)
    return entry


def _managed(facts, scope):
    enrolled, omitted = _enrolled(scope, SWITCH_SLOT, MAX_ENROLLED_SWITCHES)
    observed = None
    if "managed_ap" in facts.reads and facts.reads["managed_ap"].observed_at:
        observed = int(datetime.fromisoformat(facts.reads["managed_ap"].observed_at.replace("Z", "+00:00"))
                       .astimezone(timezone.utc).timestamp())
    if scope.https_enrolled:
        switches = _switches_https(facts, enrolled)
        if switches is None:
            # Refused HTTPS keeps the enrolled children and the answers of permitted CLI reads.
            switches = _switches_cli(facts, enrolled, (_reason(facts, "switch_status"), "switch_status"))
        aps = _aps_https(facts, observed)
        if aps is None and "wifi_ap_status" in facts.reads:
            aps = _aps_cli(facts)
    else:
        facts.lack("managed", "rest_unavailable")
        switches, aps = _switches_cli(facts, enrolled), _aps_cli(facts)
    if omitted:
        # Enrolled switches beyond the detail cap get no read of their own; their count stays visible.
        facts.missing.append(model.missing("managed", "source_limit", omitted_count=omitted))
    for child in switches:
        _switch_ports(facts, child)
        if child["interfaces"]["admin_up_down"] is None and not any(item[0] == "interfaces" for item in child["_missing"]):
            child["_missing"].append(("interfaces", "source_limit", None))
        _stack_and_mclag(facts, child)
    children = sorted(switches, key=lambda item: item["id"]) + sorted(aps or [], key=lambda item: item["id"])
    published = []
    for index, child in enumerate(children[:model.MAX_DETAILS]):
        causes = child.pop("_missing")
        for field, reason, read_id in causes:
            facts.lack(f"managed[{index}].{field}", reason, read_id if read_id in facts.reads else None)
        child["status"] = "complete" if all(reason == "not_applicable" for _, reason, _ in causes) else "partial"
        child["read_ids"] = list(dict.fromkeys(child["read_ids"]))
        published.append(child)
    if len(children) > model.MAX_DETAILS:
        facts.missing.append(model.missing("managed", "output_limit", omitted_count=len(children) - model.MAX_DETAILS))
    return published


def assemble(scope, reads):
    facts = _Facts(reads)
    status = _status(facts)
    _performance(facts)
    _interfaces(facts, _enrolled(scope, INTERFACE_SLOT, MAX_ENROLLED_INTERFACES)[1])
    _redundancy(facts, status)
    _sensors(facts)
    _fortiguard(facts)
    facts.fields["managed"] = _managed(facts, scope)
    return model.DeviceFacts(facts.fields, facts.missing, [], tuple(sorted(facts.incomplete)), facts.answered)
