"""ExtremeXOS adapter for the read-only network overview (H2).

Only catalogue reads are planned. Every parser accepts the documented shape of
its own capture; an unknown or contradicted shape marks that read incomplete and
keeps the values that were read. The adapter performs no I/O.
"""

from __future__ import annotations

import re

from .. import normalization, tables, triage_health
from .. import exos_ports, optics
from ..switch_mlag_exos import summarize_peer, summarize_ports
from . import model

# Highest optical detail reads in one plan; enrolled ports only, never every port.
MAX_OPTICS = 8
VIRTUAL_MODELS = frozenset({"EXOS-VM"})
_STANDALONE = "redundancy-disabled"
# EXOS-VM 33.6.1.14 (measured with the read-only account): `show stacking` exits 250 with this
# statement and `show stacking-support` is not a command of the virtual switch.
_NO_STACKING = ["Method is not implemented on this platform."]
_NO_STACKING_SUPPORT = ['%% Unrecognized command:  "show stacking-support"', "%% Invalid input detected."]

_BASE = (
    model.ReadSpec("version", "version", ("version", "firmware_support")),
    model.ReadSpec("switch", "switch", ("model", "uptime_seconds")),
    model.ReadSpec("ports", "ports", ("interfaces.admin_up_down",)),
    model.ReadSpec("ports_rx_errors", "ports_rx_errors", ("interfaces.with_errors",)),
    model.ReadSpec("ports_tx_errors", "ports_tx_errors", ("interfaces.with_errors",)),
    model.ReadSpec("temperature", "temperature", ("temperatures",)),
    model.ReadSpec("fans", "fans", ("fans",)),
    model.ReadSpec("power", "power", ("power",)),
    model.ReadSpec("inline_power", "inline_power", ("poe",)),
    model.ReadSpec("cpu_monitoring", "cpu_monitoring", ("cpu",)),
    model.ReadSpec("memory", "memory", ("memory",)),
)
_REDUNDANCY = (
    model.ReadSpec("stacking", "stacking", ("redundancy",)),
    model.ReadSpec("stacking_support", "stacking_support", ("redundancy",)),
    model.ReadSpec("mlag_peer", "mlag_peer", ("redundancy",)),
    model.ReadSpec("mlag_ports", "mlag_ports", ("redundancy",), requires=("mlag_peer",)),
)
_LICENSES = model.ReadSpec("licenses", "licenses", ("licenses",))


def _optical_ports(scope):
    # H0 supplies a fixed inventory without live port media. EXOS has no
    # catalogue slot that uses the switches category. These entries record
    # known modules; the interface inventory still authorizes every port.
    enrolled = scope.read_inventory.get("interfaces", ())
    optical = {entry.removeprefix("optical-port:") for entry in scope.read_inventory.get("switches", ())
               if entry.startswith("optical-port:")}
    return tuple(port for port in enrolled if port in optical), len(enrolled) if not optical else 0


def plan(scope):
    """Reserve the first reads for identity, port errors, environment, and PoE."""
    redundancy = () if _STANDALONE in scope.read_inventory.get("switches", ()) else _REDUNDANCY
    base = (*_BASE, *redundancy, _LICENSES)
    if "interface_transceiver" not in scope.enabled_queries:
        return base
    ports, _ = _optical_ports(scope)
    return base + tuple(
        model.ReadSpec(f"interface_transceiver:{index}", "interface_transceiver", ("temperatures",),
                       parameters={"interface": port})
        for index, port in enumerate(ports[:MAX_OPTICS], 1)
    )


_UNITS = {"day": 86400, "hour": 3600, "minute": 60, "second": 1}


def uptime_seconds(text):
    """`System UpTime: 31 days 18 hours 36 minutes 3 seconds` as whole seconds."""
    if text is None:
        return None
    parts = re.findall(r"(\d+)\s+(day|hour|minute|second)s?\b", text)
    if not parts or re.sub(r"(\d+)\s+(day|hour|minute|second)s?\b", "", text).strip():
        return None
    units = [unit for _, unit in parts]
    if len(set(units)) != len(units):
        return None
    return sum(int(value) * _UNITS[unit] for value, unit in parts)


def _cpu(text):
    """The System row in the column that matches the printed monitoring interval."""
    interval = re.findall(r"(?m)^[ \t]*CPU Utilization Statistics - Monitored every (\d+) seconds[ \t]*$", text)
    columns = re.findall(r"(?m)^Process[ \t]+(\d+)[ \t]+10[ \t]+30[ \t]+1[ \t]+5[ \t]+30[ \t]+1[ \t]+Max\b", text)
    units = re.search(r"(?m)^[ \t]+secs[ \t]+secs[ \t]+secs[ \t]+min[ \t]+mins[ \t]+mins[ \t]+hour\b", text)
    data = triage_health._exos_cpu(text)
    if data is None or len(interval) != 1 or len(columns) != 1 or not units or interval[0] != columns[0]:
        return None
    return {"used_pct": data["five_seconds_percent"], "sample_seconds": int(interval[0])}


def _memory(text):
    data = triage_health._exos_memory(text)
    if data is None:
        return None
    total, free = data["total_kb"], data["free_kb"]
    return {"used_pct": data["used_percent"], "total_bytes": total * 1024, "used_bytes": (total - free) * 1024}


_PORT_ROW = re.compile(r"(\d+(?::\d+){0,2})\s+(?:(\S+)\s+)??(\(\d+\)|\S+)\s+([DEFL])\s+(A|R|NP|L|D|d|B)"
                       r"(?:\s+(\d+|-)\s+(HALF|FULL))?")
# Port State E is administratively enabled. Link A is active; Ready, ELSM, OAM and
# MACsec wait states carry no link. Not present and loopback are not down links.
_LINK_DOWN = frozenset({"R", "D", "d", "B"})


def _ports(text):
    states = {}

    def row(value):
        match = _PORT_ROW.fullmatch(value)
        if match is None:
            return None
        return [(match[1], match[4], match[5])]

    rows, unknown = tables.lines(text, row, tables.EXOS_HEADINGS["interface"])
    duplicate = False
    for name, admin, link in rows:
        duplicate = duplicate or name in states
        states[name] = (admin, link)
    return states, not unknown and not duplicate and bool(states) and "Port Summary" in text


_RX = ("rx_crc", "rx_over", "rx_under", "rx_frag", "rx_jabber", "rx_align", "rx_lost")
_TX = ("tx_collisions", "tx_late_collisions", "tx_deferred", "tx_errors", "tx_lost", "tx_parity")
# Collisions and deferrals are normal half-duplex events and are not error counters.
_NOT_ERRORS = frozenset({"tx_collisions", "tx_deferred"})
_ERROR_HEADINGS = {
    "rx": ("Port Rx Error Monitor", r"Port\s+Link\s+(?:Rx\s+){6}Rx",
           r"State\s+Crc\s+Over\s+Under\s+Frag\s+Jabber\s+Align\s+Lost"),
    "tx": ("Port Tx Error Monitor", r"Port\s+Link\s+(?:Tx\s+){5}Tx",
           r"State\s+Coll\s+Late coll\s+Deferred\s+Errors\s+Lost\s+Parity"),
}
_ERROR_LEGEND = (r"Link State: A-Active, R-Ready, NP-Port Not Present L-Loopback",
                 r"> indicates Port Display Name truncated past 8 characters")


def _errors(text, direction):
    names = _RX if direction == "rx" else _TX
    title, *headings = _ERROR_HEADINGS[direction]
    rows, seen_title, unknown = {}, False, False
    for raw in text.splitlines():
        value = raw.strip()
        if not value or re.fullmatch(r"[= ]+", value):
            continue
        if value == title:
            unknown = unknown or seen_title
            seen_title = True
            continue
        if any(re.fullmatch(pattern, value) for pattern in (*headings, *_ERROR_LEGEND)):
            continue
        match = re.fullmatch(r"(\d+(?::\d+){0,2})\s+(?:\S+\s+)?(?:A|R|NP|L)\s+(\d+(?:\s+\d+)*)", value)
        counts = match[2].split() if match else ()
        if match is None or len(counts) != len(names) or match[1] in rows:
            unknown = True
            continue
        rows[match[1]] = dict(zip(names, map(int, counts)))
    return rows, seen_title and not unknown and bool(rows)


_TEMPERATURE_STATES = {"Normal": "ok", "Warning": "warning"}
_FAN_STATES = {"Operational": "ok", "Failed": "failed"}
_POWER_STATES = {"Powered On": "ok", "Powered Off": "failed", "Failed": "failed"}


def _temperatures(text, read_id):
    rows, complete = triage_health._exos_temperatures(text)
    environment = optics.environment(text)
    entries = []
    for row in rows:
        state = _TEMPERATURE_STATES.get(row["state"])
        complete = complete and state is not None
        entries.append({"name": " ".join(row["sensor"].split()), "state": state or "unknown",
                        "celsius": row["celsius"], "kind": "system", "read_ids": [read_id]})
    if environment["state"] != "measured" or len(environment["temperatures"]) != len(rows):
        complete = False
    return entries, complete and bool(entries)


def _hardware(text, query):
    header = r"Slot-\d+ FanTray" if query == "fans" else r"PowerSupply \d+"
    members, complete = triage_health._exos_hardware(text, header)
    parts = re.split(rf"(?m)^({header}) information:[ \t]*$", text)
    blocks = dict(zip(parts[1::2], parts[2::2]))
    states = _FAN_STATES if query == "fans" else _POWER_STATES
    entries = []
    for member in members:
        if member["state"] == "Empty":
            continue  # An empty bay is not a member and not a failed part.
        state = states.get(member["state"])
        complete = complete and state is not None
        entry = {"name": member["name"], "state": state or "unknown", "read_ids": [query]}
        block = blocks.get(member["name"], "")
        if query == "power":
            usage = re.findall(r"(?m)^[ \t]*Power Usage[ \t]*:[ \t]*(\d+(?:\.\d+)?) W[ \t]*$", block)
            if len(usage) == 1:
                entry["watts"] = float(usage[0])
        entries.append(entry)
        if query == "fans":
            count = re.findall(r"(?m)^[ \t]*NumFan:[ \t]*(\d+)[ \t]*$", block)
            fans = re.findall(r"(?m)^[ \t]*(Fan-\d+):[ \t]*(\S+)(?:[ \t]+at[ \t]+(\d+)[ \t]+RPM)?[ \t]*$", block)
            if count and int(count[0]) != len(fans):
                complete = False
            for name, raw, rpm in fans:
                fan_state = states.get(raw)
                complete = complete and fan_state is not None
                fan = {"name": f"{member['name']} {name}", "state": fan_state or "unknown", "read_ids": [query]}
                if rpm:
                    fan["rpm"] = int(rpm)
                entries.append(fan)
    return entries, complete


def _poe(text):
    """`measured` with a budget, `not_operational` without one, or `unparsed`."""
    rows, unknown = exos_ports.parse("poe_budget", text)
    if len(rows) != 1 or unknown:
        return "unparsed", None
    row = rows[0]
    if row["state"] == "Not Operational":
        return "not_operational", None
    if row["power_w"] is None:
        return "unparsed", None
    budget, used = row["budget_w"], row["power_w"]
    return "measured", {"budget_w": budget, "used_w": used, "available_w": round(budget - used, 2)}


def _support(text):
    """Current stacking-support state (configured, current columns) or None."""
    match = triage_health._exos_match(
        r"^stacking-support:[ \t]+(Enabled|Disabled)[ \t]+(Enabled|Disabled)[ \t]*$", text)
    return None if match is None else match[2] == "Enabled"


def _stack(stacking_text, support_text):
    """Return entries, stacking complete, stacking_support complete."""
    support = None if support_text is None else _support(support_text)
    support_ok = support_text is None or support is not None
    if stacking_text is None:
        return [], False, support_ok
    data, ok = triage_health._exos_stacking(stacking_text)
    if data is None or not ok:
        return [], False, support_ok
    if data["enabled"] is False:
        agreed = support is not True
        return [{"kind": "stack", "state": "standalone", "read_ids": ["stacking"] + (
            ["stacking_support"] if support is False else [])}], agreed, support_ok and agreed
    nodes = data["nodes"]
    local = [node for node in nodes if node["local"]]
    healthy = all(node["state"] == "Active" and "A" in node["flags"] and "O" not in node["flags"] for node in nodes)
    entry = {"kind": "stack", "state": "ok" if healthy else "degraded", "members": len(nodes),
             "read_ids": ["stacking"]}
    if len(local) == 1:
        entry["role"] = local[0]["role"].lower()
    agreed = support is not False
    return [entry], agreed, support_ok and agreed


def _mlag(peer_text, ports_text):
    """Return entries, peer complete, ports complete.

    A healthy checkpoint and matching group count must agree with the live link
    states. A header alone proves no peer only with an explicit zero group count.
    """
    peer = summarize_peer(peer_text)
    ports = summarize_ports(ports_text) if ports_text is not None else None
    measured = ports is not None and ports["state"] == "measured"
    if peer["state"] == "unparsed":
        return [], False, ports is None or measured
    if not peer["peers"]:
        absent = peer["missing_fields"] == ["peer_details"] and measured and ports["configured_groups"] == 0
        return [], absent, absent or ports is None
    entries = []
    peer_complete = peer["state"] == "measured"
    ports_complete = ports is None or measured
    port_members = ports["members"] if measured else []
    peer_names = {item["name"] for item in peer["peers"]}
    known_peers = all(member["peer_name"] in peer_names for member in port_members)
    for item in peer["peers"]:
        status = item["checkpoint_status"]
        members = [member for member in port_members if member["peer_name"] == item["name"]]
        agreed = measured and known_peers and item["configured_groups"] == len(members)
        link_down = any(member["local_link_state"] in {"D", "R", "NP"} or member["remote_link"] == "Down"
                        or member["peer_status"] == "Down" for member in members)
        links_verified = all(member["remote_link"] != "N/A" and member["peer_status"] in {"Up", "Down"}
                             for member in members)
        if status == "Down" or link_down:
            state = "degraded"
        elif status == "Up" and agreed and links_verified:
            state = "ok"
        else:
            state = "unknown"
        if status not in {"Up", "Down"}:
            peer_complete = False
        if measured and not agreed:
            peer_complete = ports_complete = False  # The peer summary contradicts the port count.
        if not links_verified:
            ports_complete = False
        entry = {"kind": "mlag", "state": state, "read_ids": ["mlag_peer"]}
        if measured:
            entry["members"] = len(members)
            entry["read_ids"].append("mlag_ports")
        entries.append(entry)
    return entries, peer_complete, ports_complete


def _licenses(text):
    level = re.search(r"(?m)^Enabled License Level:[ \t]*\r?\n[ \t]+(\S[^\n]*?)[ \t]*$", text)
    packs = re.search(r"(?m)^Enabled Feature Packs:[ \t]*\r?\n[ \t]+(\S[^\n]*?)[ \t]*$", text)
    known = {line.strip() for line in text.splitlines() if line.strip()}
    expected = {"Enabled License Level:", "Enabled Feature Packs:"}
    if level:
        expected.add(level[1].strip())
    if packs:
        expected.add(packs[1].strip())
    if not level or not packs or known != expected:
        return [], False
    entries = [{"name": level[1].strip(), "state": "valid", "expires_on": None, "read_ids": ["licenses"]}]
    if packs[1].strip() != "None":
        entries.extend({"name": name.strip(), "state": "valid", "expires_on": None, "read_ids": ["licenses"]}
                       for name in packs[1].split(",") if name.strip())
    return entries, True


def _optic(text, port, read_id):
    result = optics.transceiver(text, port)
    if result["state"] in {"not_present", "unsupported"}:
        return None, True  # No module, or a copper port without DOM.
    if result["state"] not in {"measured", "partial"}:
        return None, False
    reading = result["readings"].get("temperature") or {}
    statuses = [item["status"] for item in result["readings"].values() if item["status"] is not None]
    if any("Alarm" in status for status in statuses):
        state = "failed"
    elif any("Warn" in status for status in statuses):
        state = "warning"
    elif statuses and all(status == "Normal" for status in statuses):
        state = "ok"
    else:
        state = "unknown"
    entry = {"name": f"port {port} transceiver", "state": state, "kind": "optic", "port": port,
             "read_ids": [read_id]}
    if reading.get("value") is not None:
        entry["celsius"] = reading["value"]
    return entry, result["state"] == "measured" and state != "unknown"


def assemble(scope, reads):
    fields, missing, incomplete = {}, [], []

    def text(key):
        read = reads.get(key)
        return read.text if read is not None and read.status in {"ok", "empty"} and read.text is not None else None

    identity = None
    version_text = text("version")
    if version_text is not None:
        try:
            identity = normalization.parse_identity("extreme_exos", version_text)
        except normalization.IdentityError:
            incomplete.append("version")
    if identity is not None:
        fields["version"] = identity["os_version"]
        if (switch := text("switch")) is not None:
            try:
                normalization.supplement_identity(identity, "switch", switch)
            except normalization.IdentityError:
                incomplete.append("switch")
            else:
                seconds = uptime_seconds(identity["uptime"])
                if identity["model"] is None or seconds is None:
                    incomplete.append("switch")
                fields["uptime_seconds"] = seconds
        fields["model"] = identity["model"]
        fields.update(triage_health.exos_firmware(identity, version_text, "network_overview"))
        fields.pop("warnings", None)
    elif text("switch") is not None:
        incomplete.append("switch")  # A model without a verified identity is not reported.

    for key, parser in (("cpu_monitoring", _cpu), ("memory", _memory)):
        if (value := text(key)) is not None:
            parsed = parser(value)
            fields["cpu" if key == "cpu_monitoring" else key] = parsed
            if parsed is None:
                incomplete.append(key)

    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    port_states, ports_complete = ({}, False)
    if (value := text("ports")) is not None:
        port_states, ports_complete = _ports(value)
        if not ports_complete:
            incomplete.append("ports")
        interfaces["admin_up_down"] = [
            {"name": name, "read_ids": ["ports"]}
            for name, (admin, link) in port_states.items() if admin == "E" and link in _LINK_DOWN
        ]
    counters, error_reads = {}, []
    for key, direction in (("ports_rx_errors", "rx"), ("ports_tx_errors", "tx")):
        if (value := text(key)) is None:
            continue
        rows, complete = _errors(value, direction)
        if not complete or (ports_complete and set(rows) != set(port_states)):
            incomplete.append(key)  # The table does not account for every port of the summary.
        error_reads.append((key, rows))
    if error_reads:
        if len(error_reads) == 2 and set(error_reads[0][1]) != set(error_reads[1][1]):
            incomplete.extend(key for key, _ in error_reads if key not in incomplete)
        for key, rows in error_reads:
            for name, values in rows.items():
                entry = counters.setdefault(name, {"name": name, "counters": {}, "counter_kind": "cumulative",
                                                   "read_ids": []})
                entry["counters"].update({field: value for field, value in values.items() if field not in _NOT_ERRORS})
                entry["read_ids"].append(key)
        interfaces["with_errors"] = [
            entry for entry in sorted(counters.values(), key=lambda item: _port_key(item["name"]))
            if any(value > 0 for value in entry["counters"].values())
        ]
    if interfaces["admin_up_down"] is not None:
        interfaces["admin_up_down"].sort(key=lambda item: _port_key(item["name"]))
    fields["interfaces"] = interfaces

    stack_text, support_text = text("stacking"), text("stacking_support")
    redundancy = []
    redundancy_read = stack_text is not None or support_text is not None
    entries, stack_complete, support_complete = _stack(stack_text, support_text)
    redundancy.extend(entries)
    if stack_text is not None and not stack_complete:
        incomplete.append("stacking")
    if support_text is not None and not support_complete:
        incomplete.append("stacking_support")
    if (peer_text := text("mlag_peer")) is not None:
        redundancy_read = True
        entries, peer_complete, ports_ok = _mlag(peer_text, text("mlag_ports"))
        redundancy.extend(entries)
        if not peer_complete:
            incomplete.append("mlag_peer")
        if not ports_ok:
            incomplete.append("mlag_ports")
    fields["redundancy"] = redundancy if redundancy_read else None
    if _STANDALONE in scope.read_inventory.get("switches", ()):
        missing.append(model.missing("redundancy", "not_applicable"))

    virtual = identity is not None and identity["model"] in VIRTUAL_MODELS
    answered = {}
    stacking = reads.get("stacking")
    if virtual and stacking is not None and stacking.rc == 250 and model.refused_lines(stacking) == _NO_STACKING:
        # The virtual switch states that it has no stacking; its support listing is then not a command either.
        # The statement was measured on EXOS-VM only: on a physical switch it is not proof of a standalone unit.
        answered["stacking"] = "not_applicable"
        stacking_support = reads.get("stacking_support")
        if (stacking_support is not None and stacking_support.rc == 254
                and model.refused_lines(stacking_support) == _NO_STACKING_SUPPORT):
            answered["stacking_support"] = "not_applicable"
    hardware = {}
    if (value := text("temperature")) is not None:
        hardware["temperatures"], complete = _temperatures(value, "temperature")
        if not complete:
            incomplete.append("temperature")
    for key in ("fans", "power"):
        if (value := text(key)) is not None:
            if key == "fans" and re.fullmatch(r"\s*FanTray information:\s+State:\s+Unsupported\s+NumFan:\s+0\s*", value):
                missing.append(model.missing("fans", "not_applicable", read_id="fans"))
                continue
            hardware[key], complete = _hardware(value, key)
            if not complete:
                incomplete.append(key)
    if (value := text("inline_power")) is not None:
        state, fields["poe"] = _poe(value)
        if state == "not_operational" and virtual:
            missing.append(model.missing("poe", "not_applicable", read_id="inline_power"))
        elif state != "measured":
            incomplete.append("inline_power")  # No measured budget from this capture.
    if "interface_transceiver" in scope.enabled_queries:
        ports, unclassified = _optical_ports(scope)
        omitted = max(0, len(ports) - MAX_OPTICS) + unclassified
        if omitted:
            missing.append(model.missing("temperatures", "source_limit", omitted_count=omitted))
    for key, read in reads.items():
        if read.spec.query != "interface_transceiver":
            continue
        value = text(key)
        if value is None:
            continue
        entry, complete = _optic(value, read.spec.parameters["interface"], key)
        if not complete:
            incomplete.append(key)
        if entry is not None:
            hardware.setdefault("temperatures", []).append(entry)
    if virtual:
        # The virtual switch prints simulated sensors and supplies; they are not hardware readings.
        for key, read_id in (("temperatures", "temperature"), ("fans", "fans"), ("power", "power")):
            if key in hardware:
                fields[key] = None
                missing.append(model.missing(key, "not_applicable", read_id=read_id))
                incomplete[:] = [item for item in incomplete if item != read_id]
    else:
        fields.update(hardware)

    if (value := text("licenses")) is not None:
        fields["licenses"], complete = _licenses(value)
        if not complete:
            incomplete.append("licenses")
    fields["fortiguard"] = None
    fields["managed"] = None
    missing.append(model.missing("fortiguard", "not_applicable"))
    missing.append(model.missing("managed", "not_applicable"))
    return model.DeviceFacts(fields, missing, [], tuple(dict.fromkeys(incomplete)), answered)


def _port_key(name):
    return tuple(int(part) for part in name.split(":"))
