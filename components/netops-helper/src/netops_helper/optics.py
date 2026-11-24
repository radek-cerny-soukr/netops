"""Transceiver DOM and EXOS temperature summaries over the redacted capture."""
from __future__ import annotations

import math
import re
from typing import Any

_METRICS = (
    ("temperature", "Temp (Celsius)", "C"),
    ("voltage", "Voltage AUX-1/Vcc (Volts)", "V"),
    ("tx_power", "Tx Power (dBm)", "dBm"),
    ("rx_power", "Rx Power (dBm)", "dBm"),
    ("tx_bias_current", "Tx Bias Current (mA)", "mA"),
)
_BY_LABEL = {label: (key, unit) for key, label, unit in _METRICS}
_THRESHOLDS = ("low_warn", "high_warn", "low_alarm", "high_alarm")
_PORT = re.compile(r"(?m)^Port[ \t]*:[ \t]*(\S+)[ \t]*\r?$")
_VALUE = re.compile(r"^[ \t]+(Temp \(Celsius\)|Voltage AUX-1/Vcc \(Volts\)|Tx Power \(dBm\)|Rx Power \(dBm\)"
                    r"|Tx Bias Current \(mA\))[ \t]*:[ \t]*(\S+)(?:[ \t]+Status[ \t]*:[ \t]*(\S[^\r\n]*?))?[ \t]*\r?$")
# A known metric header starts its block even when the value after it is empty or unreadable.
_HEAD = re.compile(r"^[ \t]+(Temp \(Celsius\)|Voltage AUX-1/Vcc \(Volts\)|Tx Power \(dBm\)|Rx Power \(dBm\)"
                   r"|Tx Bias Current \(mA\))[ \t]*:")
_STATUS = re.compile(r"[ \t]Status[ \t]*:[ \t]*(\S[^\r\n]*?)[ \t]*\r?$")
_UNASSIGNED = "thresholds.unassigned"
_THRESHOLD = re.compile(r"(Low|High) (Warn|Alarm) Threshold[ \t]*:[ \t]*(\S+)")
_TEMP_HEAD = re.compile(r"(?m)^Field Replaceable Units[ \t]+Temp \(C\)[ \t]+Status[ \t]+Min[ \t]+Normal[ \t]+Max[ \t]*\r?$")
_NUMBER = r"-?[0-9]+(?:\.[0-9]+)?"
_RANGE = re.compile(rf"({_NUMBER})-({_NUMBER})")


def _number(token: str) -> float | None:
    if not re.fullmatch(_NUMBER, token):
        return None
    value = float(token)
    return value if math.isfinite(value) else None


def _blank_metric(unit: str) -> dict[str, Any]:
    return {"value": None, "unit": unit, "status": None,
            "thresholds": dict.fromkeys(_THRESHOLDS), "availability": "missing"}


def _empty(state: str, interface: str) -> dict[str, Any]:
    return {"state": state, "interface": interface, "readings": {}, "missing_fields": []}


def transceiver(text: str, interface: str) -> dict[str, Any]:
    if not text.strip():
        return _empty("empty", interface)
    headers = _PORT.findall(text)
    if len(headers) != 1 or headers[0] != interface:
        return _empty("unparsed", interface)
    if re.search(r"(?m)^[ \t]*Transceiver is not present on this port[ \t]*\r?$", text):
        return _empty("not_present", interface)
    if re.search(r"(?m)^[ \t]*DDMI is not supported on this port[ \t]*\r?$", text):
        return _empty("unsupported", interface)
    readings = {key: _blank_metric(unit) for key, _, unit in _METRICS}
    seen: set[str] = set()
    missing: list[str] = []
    current = None
    thresholds_seen: set[str] = set()
    printed: dict[str, set[str]] = {}
    contested = False
    for line in text.splitlines():
        head = _HEAD.match(line)
        if head:
            key, unit = _BY_LABEL[head.group(1)]
            if key in seen:
                return _empty("unparsed", interface)  # duplicate metric block: never pick first/last
            seen.add(key)
            current, contested = key, False
            printed[key] = thresholds_seen = set()
            item = readings[key]
            match = _VALUE.match(line)
            if match is None:
                status = _STATUS.search(line[head.end():])
                item["status"] = status.group(1) if status else None
                missing.append(key + ".value")
                if status is None:
                    missing.append(key + ".status")
                continue
            token, status = match.group(2), match.group(3)
            item["status"] = status
            if status is None:
                missing.append(key + ".status")
            if token == "N/A":
                item["availability"] = "not_applicable"
            elif token == "-inf":
                item["availability"] = "undefined"
            elif (value := _number(token)) is not None:
                item["value"], item["availability"] = value, "available"
            else:
                missing.append(key + ".value")
            continue
        if not line.strip():
            current = None  # a blank line closes the block; later thresholds have no header of their own
            continue
        for kind, level, token in _THRESHOLD.findall(line):
            name = f"{kind.lower()}_{level.lower()}"
            if current is None:
                if _UNASSIGNED not in missing:
                    missing.append(_UNASSIGNED)
                continue
            if contested or name in thresholds_seen:
                # Unclear block boundary: withhold every threshold from here on instead of picking first/last.
                contested = True
                thresholds_seen.add(name)
                readings[current]["thresholds"][name] = None
                if f"{current}.{name}" not in missing:
                    missing.append(f"{current}.{name}")
                continue
            thresholds_seen.add(name)
            if token not in ("N/A", "-inf"):
                value = _number(token)
                if value is None:
                    missing.append(f"{current}.{name}")
                readings[current]["thresholds"][name] = value
    if not seen:
        return _empty("unparsed", interface)
    for key, _, _ in _METRICS:
        if key not in seen:
            missing.append(key)
        else:
            missing.extend(f"{key}.{name}" for name in _THRESHOLDS
                           if name not in printed[key] and f"{key}.{name}" not in missing)
    return {"state": "partial" if missing else "measured", "interface": interface,
            "readings": readings, "missing_fields": missing}


def environment(text: str) -> dict[str, Any]:
    if not text.strip():
        return {"state": "empty", "temperatures": [], "missing_fields": []}
    head = _TEMP_HEAD.search(text)
    if head is None:
        return {"state": "unparsed", "temperatures": [], "missing_fields": []}
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for number, line in enumerate(text[head.end():].splitlines(), 1):
        if not line.strip() or re.fullmatch(r"[- ]+", line.strip()):
            continue
        parts = line.split()
        if len(parts) < 6:
            missing.append(f"row{number}")
            continue
        component = " ".join(parts[:-5])
        temp, status, low, normal, high = parts[-5:]
        span = _RANGE.fullmatch(normal)
        values = [_number(temp), _number(low), _number(high)]
        if span is None or None in values:
            missing.append(f"row{number}")
            if span is None and values[0] is None:
                continue
        rows.append({
            "component": component, "value": values[0], "unit": "C", "status": status,
            "reported_limits": {"min": values[1], "normal_min": float(span.group(1)) if span else None,
                                "normal_max": float(span.group(2)) if span else None, "max": values[2]},
        })
    if not rows:
        return {"state": "unparsed", "temperatures": [], "missing_fields": missing}
    return {"state": "partial" if missing else "measured", "temperatures": rows, "missing_fields": missing}


# IOS `show interfaces <if> transceiver detail` (1.0.12 router ports): one table per metric, the value followed by
# the four thresholds; the device may mark the value (++ high alarm, + high warning, - low warning, -- low alarm).
_IOS_METRICS = (("temperature", "Temperature", "C"), ("voltage", "Voltage", "V"), ("tx_bias_current", "Current", "mA"),
                ("tx_power", "Transmit Power", "dBm"), ("rx_power", "Receive Power", "dBm"))
_IOS_FLAGS = {"++": "high_alarm", "+": "high_warning", "-": "low_warning", "--": "low_alarm"}
_IOS_PREAMBLE = (r"ITU Channel .*", r"Transceiver is (?:internally|externally) calibrated\.",
                 r"mA: ?milliamperes, dBm: ?decibels \(milliwatts\),.*", r"\+\+ ?: ?high alarm, .*",
                 r"A2D readouts \(if they differ\),? are reported in parentheses\.",
                 r"The threshold values are (?:un)?calibrated\.")
_IOS_HEAD = re.compile(r"High Alarm\s+High Warn\s+Low Warn\s+Low Alarm")
_IOS_VALUE = r"(-?[0-9]+(?:\.[0-9]+)?|N/A)"
_IOS_ROW = re.compile(r"(\S+)\s+" + _IOS_VALUE + r"(?:\s+(\+\+|--|\+|-))?(?:\s+\([^)]*\))?"
                      + r"\s+" + r"\s+".join([_IOS_VALUE] * 4))


def _ios_evaluate(value, thresholds):
    """Alarm/warning from the device's own thresholds; a boundary value counts as reached."""
    if value is None:
        return None
    for name, test in (("high_alarm", lambda limit: value >= limit), ("low_alarm", lambda limit: value <= limit),
                       ("high_warn", lambda limit: value >= limit), ("low_warn", lambda limit: value <= limit)):
        limit = thresholds.get(name)
        if limit is not None and test(limit):
            return {"high_warn": "high_warning", "low_warn": "low_warning"}.get(name, name)
    return "normal" if any(limit is not None for limit in thresholds.values()) else None


def ios_transceiver(text: str, interface: str, *, xe: bool = False) -> dict[str, Any]:
    from .normalization import normalize_port
    if not text.strip():
        return _empty("empty", interface)
    readings: dict[str, Any] = {}
    unknown: list[dict[str, Any]] = []
    metric = None
    port = None
    lines = text.splitlines()
    for number, raw in enumerate(lines, 1):
        value = raw.strip()
        if not value or re.fullmatch(r"[- ]+", value) or any(re.fullmatch(p, value) for p in _IOS_PREAMBLE):
            continue
        if _IOS_HEAD.search(value):
            metric = None
            continue
        found = [key for key, word, _ in _IOS_METRICS if word in value]
        if found and "Threshold" in value:
            metric = found[0]
            continue
        if re.fullmatch(r"Port\s+\(\S+\)(?:\s+\(\S+\)){4}", value):
            continue
        match = _IOS_ROW.fullmatch(value)
        if match and metric is not None and metric not in readings:
            try:
                name = normalize_port(match[1])["name"]
            except ValueError:
                unknown.append({"line": number, "text": raw})
                continue
            if port not in (None, name):
                return _empty("unparsed", interface)  # one port per read; two ports are never mixed
            port = name
            unit = next(unit for key, _, unit in _IOS_METRICS if key == metric)
            numbers = [None if token == "N/A" else float(token) for token in match.group(2, 4, 5, 6, 7)]
            thresholds = dict(zip(("high_alarm", "high_warn", "low_warn", "low_alarm"), numbers[1:]))
            readings[metric] = {"value": numbers[0], "unit": unit, "thresholds": thresholds,
                                "device_flag": _IOS_FLAGS.get(match[3]), "status": _ios_evaluate(numbers[0], thresholds),
                                "availability": "available" if numbers[0] is not None else "not_applicable"}
            continue
        unknown.append({"line": number, "text": raw})
    if port is None:
        return {**_empty("unparsed", interface), "unparsed": unknown}
    if interface and normalize_port(interface)["name"] != port:
        return _empty("unparsed", interface)
    # The Catalyst 9300 XE output may omit the bias-current table entirely.
    missing = [key for key, _, _ in _IOS_METRICS if key not in readings and not (xe and key == "tx_bias_current")]
    for key, _, unit in _IOS_METRICS:
        readings.setdefault(key, {**_blank_metric(unit), "device_flag": None})
    if unknown:
        missing.append("unparsed_lines")
    alarms = [f"{key}: {item['status']}" for key, item in readings.items() if item["status"] not in (None, "normal")]
    return {"state": "partial" if missing else "measured", "interface": port, "readings": readings,
            "alarms": alarms, "missing_fields": missing, "unparsed": unknown}


_NXOS_METRICS = {
    "Temperature": ("temperature", "C"),
    "Voltage": ("voltage", "V"),
    "Current": ("tx_bias_current", "mA"),
    "Tx Power": ("tx_power", "dBm"),
    "Rx Power": ("rx_power", "dBm"),
}
_NXOS_PORT = re.compile(r"(?m)^Ethernet[0-9]{1,3}/[0-9]{1,3}(?:/[0-9]{1,3})?[ \t]*$")
_NXOS_DOM_HEADING = re.compile(r"(?m)^[ \t]*SFP (?:Detail )?Diagnostics Information(?: \([^\n]+\))?[ \t]*$")
_NXOS_VALUE = rf"(?:{_NUMBER}[ \t]+(?:C|V|mA|dBm)|N/?A)"
_NXOS_METRIC = re.compile(
    r"^(Temperature|Voltage|Current|Tx Power|Rx Power)[ \t]+"
    + rf"({_NXOS_VALUE})(?:[ \t]+(\+\+?|--?))?[ \t]+"
    + r"[ \t]+".join([rf"({_NXOS_VALUE})"] * 4) + r"[ \t]*$"
)


def nxos_dom_not_applicable(text: str) -> bool:
    lines = text.strip().splitlines()
    return (len(lines) == 2 and _NXOS_PORT.fullmatch(lines[0]) is not None
            and lines[1].strip() == "transceiver is not applicable")


_NXOS_LANE = re.compile(r"(?m)^[ \t]*Lane Number:[ \t]*([0-9]{1,2})[ \t]+Network Lane[ \t]*$")
_NXOS_LANE_COUNT = re.compile(r"(?mi)^[ \t]*number of lanes[ \t]+([0-9]{1,2})[ \t]*$")
_NXOS_MODULE_METRICS = ("temperature", "voltage")


def _nxos_dom_block(text: str, first_line: int):
    """Rows of one DOM table (one lane); None when a row repeats or carries another unit."""
    heading = _NXOS_DOM_HEADING.search(text)
    if heading is None:
        return None
    readings = {key: _blank_metric(unit) for key, unit in _NXOS_METRICS.values()}
    seen, unknown = set(), []
    thresholds_order = ("high_alarm", "low_alarm", "high_warn", "low_warn")
    for index, line in enumerate(text[heading.end():].splitlines(), first_line + text.count("\n", 0, heading.end())):
        value = line.strip()
        if re.fullmatch(r'Current[ \t]+Alarms[ \t]+Warnings', value) or not value.startswith(tuple(_NXOS_METRICS)):
            continue
        match = _NXOS_METRIC.fullmatch(value)
        if match is None:
            unknown.append({"line": index, "text": line})
            continue
        key, unit = _NXOS_METRICS[match[1]]
        tokens = [match[n].split() for n in (2, 4, 5, 6, 7)]
        if key in seen or any(len(token) == 2 and token[1] != unit for token in tokens):
            return None
        seen.add(key)
        measured, *limits = [_number(token[0]) for token in tokens]
        thresholds = dict(zip(thresholds_order, limits))
        status = _ios_evaluate(measured, thresholds)
        if status == "normal" and None in limits:
            status = None
        readings[key] = {"value": measured, "unit": unit, "thresholds": thresholds,
                         "device_flag": _IOS_FLAGS.get(match[3]), "status": status,
                         "availability": "available" if measured is not None else "not_applicable"}
    return readings, seen, unknown


def nxos_transceiver(text: str, interface: str) -> dict[str, Any]:
    """Parse the single-interface NX-OS DOM table, in the units shown by the module.

    A multi-lane module (QSFP) prints one `Lane Number:<n> Network Lane` block per lane, each with the
    documented table (Cisco NX-OS 9.3(x)/10.6(x), see the nxos ports fixture PROVENANCE).  Every lane is kept in
    ``lanes``. If the device declares a lane count, it must match the number of lane blocks.
    A top-level reading summarizes identical values. Differing readings stay in ``lanes``.
    """
    from .normalization import normalize_port

    ports = _NXOS_PORT.findall(text)
    if len(ports) != 1:
        return _empty("unparsed" if text.strip() else "empty", interface)
    port = ports[0].strip()
    if interface and normalize_port(interface)["name"] != port:
        return _empty("unparsed", interface)
    if nxos_dom_not_applicable(text):
        return _empty("not_applicable", port)
    if re.search(r"(?mi)^[ \t]*(?:transceiver|sfp|qsfp) is not present[ \t]*$", text):
        return _empty("not_present", port)
    declarations = _NXOS_LANE_COUNT.findall(text)
    if len(declarations) > 1 or declarations and int(declarations[0]) == 0:
        return _empty("unparsed", port)
    lane_marks = list(_NXOS_LANE.finditer(text))
    if declarations and not lane_marks:
        return {**_empty("unparsed", port), "missing_fields": ["lanes"],
                "reason": f"NX-OS declares {declarations[0]} transceiver lanes but reports no DOM lane blocks"}
    lane_count_mismatch = bool(declarations) and len(lane_marks) != int(declarations[0])
    if len(lane_marks) <= 1 and not lane_count_mismatch:
        block = _nxos_dom_block(text, 1)
        if block is None:
            return _empty("unparsed", port)
        readings, seen, unknown = block
        missing = [key for key in readings if key not in seen]
        if unknown:
            missing.append("unparsed_lines")
        alarms = [f"{key}: {row['status']}" for key, row in readings.items() if row["status"] not in (None, "normal")]
        return {"state": "measured" if not missing else "partial" if seen else "unparsed",
                "interface": port, "readings": readings, "alarms": alarms, "missing_fields": missing,
                "unparsed": unknown}

    numbers = [int(mark[1]) for mark in lane_marks]
    if len(set(numbers)) != len(numbers):
        return _empty("unparsed", port)  # a repeated lane is never merged or guessed
    lanes, unknown, missing, alarms = [], [], [], []
    if lane_count_mismatch:
        missing.append("lanes")
    for mark, following in zip(lane_marks, lane_marks[1:] + [None]):
        segment = text[mark.end():following.start() if following else len(text)]
        line_number = text.count("\n", 0, mark.end()) + 1
        block = _nxos_dom_block(segment, line_number)
        if block is None:
            if not lane_count_mismatch:
                return _empty("unparsed", port)
            unknown.append({"line": line_number, "text": f"DOM table missing or unrecognized for lane {mark[1]}"})
            continue
        lane_readings, seen, lane_unknown = block
        unknown.extend(lane_unknown)
        lanes.append({"lane": int(mark[1]), "readings": lane_readings,
                      "missing_fields": [key for key in lane_readings
                                         if key not in seen and key not in _NXOS_MODULE_METRICS]})
        missing.extend(f"lane {mark[1]} {key}" for key in lanes[-1]["missing_fields"])
        alarms.extend(f"lane {mark[1]} {key}: {row['status']}" for key, row in lane_readings.items()
                      if row["status"] not in (None, "normal") and key not in _NXOS_MODULE_METRICS)
    readings = {}
    for key, unit in _NXOS_METRICS.values():
        shown = [lane["readings"][key] for lane in lanes if lane["readings"][key]["availability"] != "missing"]
        if shown and all(row == shown[0] for row in shown):
            readings[key] = shown[0]
            if key in _NXOS_MODULE_METRICS and shown[0]["status"] not in (None, "normal"):
                alarms.append(f"{key}: {shown[0]['status']}")
        else:
            readings[key] = _blank_metric(unit)
            if shown:
                readings[key]["availability"] = "per_lane"
            if key in _NXOS_MODULE_METRICS:
                if not shown:
                    missing.append(key)
                alarms.extend(f"lane {lane['lane']} {key}: {lane['readings'][key]['status']}" for lane in lanes
                              if lane["readings"][key]["status"] not in (None, "normal"))
    if unknown:
        missing.append("unparsed_lines")
    measured = any(row["availability"] != "missing" for lane in lanes for row in lane["readings"].values())
    return {"state": "incomplete" if lane_count_mismatch else "measured" if not missing else
            "partial" if measured else "unparsed",
            "interface": port, "readings": readings, "alarms": alarms, "missing_fields": missing,
            "unparsed": unknown, "lanes": lanes}


def payload(platform: str, query: str, text: str, parameters: dict[str, str] | None) -> dict[str, Any]:
    if platform.startswith("juniper_junos") and query == "interface_optics":
        return {"optics": junos_transceiver(text, (parameters or {}).get("interface", ""))}
    if platform == "cisco_nxos" and query == "interface_transceiver":
        return {"optics": nxos_transceiver(text, str((parameters or {}).get("interface", "")))}
    if platform in ("cisco_ios", "cisco_xe") and query == "interface_transceiver":
        return {"optics": ios_transceiver(text, str((parameters or {}).get("interface", "")), xe=platform == "cisco_xe")}
    if platform != "extreme_exos":
        return {}
    if query == "interface_transceiver":
        return {"optics": transceiver(text, str((parameters or {}).get("interface", "")))}
    if query == "temperature":
        return {"environment": environment(text)}
    return {}


_JUNOS_DOM = {
    'Laser bias current': ('tx_bias_current', 'mA'),
    'Laser output power': ('tx_power', 'dBm'),
    'Module temperature': ('temperature', 'degrees C'),
    'Module voltage': ('voltage', 'V'),
    'Receiver signal average optical power': ('rx_power', 'dBm'),
    'Laser rx power': ('rx_power', 'dBm'),
}


def junos_transceiver(text: str, interface: str) -> dict[str, Any]:
    """Read module-wide DOM values in the units printed by Junos."""
    if not text.strip():
        return _empty('empty', interface)
    if re.findall(r'(?m)^Physical interface:\s*(\S+)\s*$', text) != [interface]:
        return _empty('unparsed', interface)
    readings = {}
    alarms = []
    for line in text.splitlines():
        label, colon, value = line.strip().partition(':')
        label = label.rstrip()
        if re.fullmatch(r'Lane \d+.*', label):
            break   # lane-specific values are not module-wide values
        if not colon:
            continue
        if label.endswith((' alarm', ' warning')) and value.strip().lower() == 'on':
            alarms.append(label)
        if label not in _JUNOS_DOM:
            continue
        field, unit = _JUNOS_DOM[label]
        measurement = re.search(rf'(?<!\S)({_NUMBER})\s+{re.escape(unit)}(?:\s|$)', value)
        if measurement and (number := _number(measurement[1])) is not None:
            readings[field] = {'value': number, 'unit': 'C' if unit == 'degrees C' else unit}
    missing = sorted({field for field, _ in _JUNOS_DOM.values()} - readings.keys())
    return {'state': 'partial' if missing else 'measured', 'interface': interface,
            'readings': readings, 'missing_fields': missing, 'alarms': alarms}
