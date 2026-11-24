"""Operational facts from the local Ruckus Unleashed controller and AP."""

import re
from collections import Counter

from .. import triage_health, triage_wifi, wifi_parse
from .model import DeviceFacts, ReadSpec, missing

LINK_STATE = "interfaces.admin_up_down"
LINK_ERRORS = "interfaces.with_errors"


def plan(scope):
    return (
        ReadSpec("system_info", "system_info", ("version", "model", "uptime_seconds", "memory", "cpu", "redundancy")),
        ReadSpec("ethernet_info", "ethernet_info", (LINK_STATE, LINK_ERRORS)),
        ReadSpec("access_points", "access_points", (LINK_STATE, "redundancy")),
    )


def _uptime(text):
    match = re.fullmatch(r"(?:(\d{1,8})d )?(?:(\d{1,8})h )?(\d{1,8})m", text or "")
    if match:
        days, hours, minutes = (int(value or 0) for value in match.groups())
        return ((days * 24 + hours) * 60 + minutes) * 60
    return None


def _memory(data):
    used, free = data.get("used_kb"), data.get("free_kb")
    if used is None or free is None or used + free == 0:
        return None
    percentage = 100 * used / (used + free)
    for key, expected in (("used_percent", percentage), ("free_percent", 100 - percentage)):
        if key in data and abs(data[key] - expected) > 1:
            return None
    return {"used_pct": round(percentage, 2), "total_bytes": (used + free) * 1024, "used_bytes": used * 1024}


def assemble(scope, reads):
    fields, incomplete = {}, set()
    unavailable = [missing(field, "source_limit") for field in ("temperatures", "fans", "power", "licenses")]
    unavailable.extend(missing(field, "not_applicable") for field in ("fortiguard", "managed"))

    def unparsed(field, read_id):
        incomplete.add(read_id)
        entry = missing(field, "unparsed", read_id=read_id)
        if entry not in unavailable:
            unavailable.append(entry)

    identity, info = {}, {}
    system = reads["system_info"]
    if system.status == "ok":
        info, unknown = triage_health._ruckus_system_health(system.text)
        rows = list(wifi_parse._ruckus_walk(system.text))
        keys = [key for _, path, key, _ in rows if path == ("System Overview",)]
        if keys.count("Model") == keys.count("Version") == 1:
            model, version = wifi_parse.ruckus_identity(system.text)
            release = re.fullmatch(r"(\d+(?:\.\d+)+) build (\d+)", version or "")
            if model and release:
                fields.update(model=model, version=version)
                macs = [value for _, path, key, value in rows
                        if path == ("System Overview",) and key == "MAC Address"]
                mac = macs[0] if len(macs) == 1 else None
                identity = {"product": model, "version": release[1], "build": release[2],
                            "mac": mac.lower() if mac and mac != "\0" else None}
                fields["firmware_support"] = triage_wifi.ruckus_support(identity, "network_overview")
        if not identity:
            unparsed("version", system.spec.id)
            unparsed("model", system.spec.id)

        for field, value in (("uptime_seconds", _uptime(info["System Overview"].get("uptime"))),
                             ("memory", _memory(info["Memory Utilization"]))):
            if value is None:
                unparsed(field, system.spec.id)
            else:
                fields[field] = value
        # The shared parser retains its first value when a key is repeated.
        invalid_lines = set(unknown)
        for number, path, _, _ in rows:
            if number in invalid_lines:
                field = {"System Overview": "uptime_seconds", "Memory Utilization": "memory"}.get(path[0], "redundancy")
                fields.pop(field, None)
                unparsed(field, system.spec.id)
        unavailable.append(missing("cpu", "source_limit", read_id=system.spec.id))

    unavailable.append(missing("poe", "not_applicable" if fields.get("model") == "r610" else "source_limit"))
    interfaces = {"scope": "device", "admin_up_down": None, "with_errors": None}
    fields["interfaces"] = interfaces
    ethernet = reads["ethernet_info"]
    links = {}
    if ethernet.status == "ok":
        result = wifi_parse.parse_ruckus_ethinfo(ethernet.text)
        ports = result["records"]
        link_keys = Counter((path, key) for _, path, key, value in wifi_parse._ruckus_walk(ethernet.text)
                            if len(path) == 2 and key in {"Interface", "Physical Link"} and value is not None)
        if (result["incomplete"] or result["unparsed_count"]
                or any(count != 1 for count in link_keys.values())
                or len({port["interface"] for port in ports}) != len(ports)
                or len({port["port"] for port in ports}) != len(ports)
                or any(port["physical_link"] not in {"up", "down"} for port in ports)):
            unparsed(LINK_STATE, ethernet.spec.id)
        else:
            links = {port["interface"]: port["physical_link"] for port in ports}
            if all(state == "up" for state in links.values()):
                interfaces["admin_up_down"] = []
            else:
                unavailable.append(missing(LINK_STATE, "source_limit", read_id=ethernet.spec.id))
        unavailable.append(missing(LINK_ERRORS, "source_limit", read_id=ethernet.spec.id))

    aps = reads["access_points"]
    local = None
    if aps.status in {"ok", "empty"}:
        result = wifi_parse.summarize_ruckus("access_points", aps.text or "")
        records = result["records"]
        matching = [row for row in records if identity.get("mac") and row["mac"] == identity["mac"]]
        local = matching[0] if len(matching) == 1 else None
        expected = info.get("Devices Overview", {}).get("ap_count")
        if result.get("incomplete") or result["unparsed_count"] or len({row["mac"] for row in records}) != len(records):
            unparsed("redundancy", aps.spec.id)
        elif system.status == "ok":
            if expected is None or (expected > 0 and not identity.get("mac")):
                unparsed("redundancy", system.spec.id)
            elif expected != len(records) or (expected > 0 and local is None):
                unparsed("redundancy", aps.spec.id)

        if local is not None and links:
            ap_links = {port["interface"]: port["physical_link"] for port in local["lan_ports"]
                        if port["interface"] is not None}
            if any(ap_links[name].split()[0].lower() != state for name, state in links.items() if ap_links.get(name)):
                unparsed(LINK_STATE, aps.spec.id)
                interfaces["admin_up_down"] = None

    if system.status == "ok":
        smart = info["Smart Redundancy"]
        role = (local["role"] or "").lower() if local else None
        if smart.get("enabled") == "Enabled" and missing("redundancy", "unparsed", read_id=system.spec.id) not in unavailable:
            local_state, peer_state = smart.get("local_status"), smart.get("peer_status")
            if smart.get("peer_ip") and {local_state, peer_state} == {"Active", "Standby"}:
                fields["redundancy"] = [{"kind": "ha", "state": "ok", "role": local_state.lower(),
                                         "read_ids": [system.spec.id]}]
            else:
                unparsed("redundancy", system.spec.id)
        elif role in {"master", "member"}:
            fields["redundancy"] = [{"kind": "ha", "state": "unknown", "role": role, "read_ids": [aps.spec.id]}]
        if not fields.get("redundancy") or fields["redundancy"][0]["state"] == "unknown":
            unavailable.append(missing("redundancy", "source_limit", read_id=system.spec.id))
    return DeviceFacts(fields, unavailable, incomplete_reads=tuple(sorted(incomplete)))
