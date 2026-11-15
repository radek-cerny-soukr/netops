"""EXOS transceiver DOM and temperature summaries over the complete redacted capture."""
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


def payload(platform: str, query: str, text: str, parameters: dict[str, str] | None) -> dict[str, Any]:
    if platform != "extreme_exos":
        return {}
    if query == "interface_transceiver":
        return {"optics": transceiver(text, str((parameters or {}).get("interface", "")))}
    if query == "temperature":
        return {"environment": environment(text)}
    return {}
