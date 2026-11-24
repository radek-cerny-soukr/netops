"""Normalised records for the FortiOS wireless-controller reads measured on FortiGate-80F 8.0.2 build0251.

Every parser returns {"records": [...], "unparsed": [line numbers]}: a line the parser does not
recognise is reported, never guessed. Device text is untrusted data; values are only matched and
converted, never evaluated.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable

from netops_core import c9800 as _c9800

from .sanitize import RUCKUS_CONFIG_SECTIONS

MAX_UNPARSED_REPORTED = 20
_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_MAC_RE = re.compile(_MAC)


def _lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]


def _result(records: list[dict[str, Any]], unparsed: list[int], **extra: Any) -> dict[str, Any]:
    return {"records": records, "unparsed": unparsed[:MAX_UNPARSED_REPORTED], "unparsed_count": len(unparsed), **extra}


def _split(line: str) -> tuple[int, str, str] | None:
    """`    key : value` -> (indent, key, value); the key never contains a colon."""
    indent = len(line) - len(line.lstrip(" "))
    key, separator, value = line[indent:].partition(":")
    key = key.rstrip(" ")
    if not separator or not key or "\n" in value:
        return None
    return indent, key, value.strip()


def _int(value: str) -> int:
    if re.fullmatch(r"-?\d{1,18}", value) is None:
        raise ValueError(value)
    return int(value)


def _local_time(value: str) -> str:
    return datetime.strptime(" ".join(value.split()), "%a %b %d %H:%M:%S %Y").isoformat()


def _none_if(value: str, *empty: str) -> str | None:
    return None if value in empty else value


# --- get wireless-controller wtp-status ---------------------------------------------------------

_WTP_HEADER = re.compile(r"WTP: (\S+) +(\d+)-(\S+):(\d+)")
_AP_KEYS = {
    "vdom", "vap in user", "wtp-id", "region-code", "name", "mgmt_vlanid", "data-chan-sec", "mesh-uplink",
    "mesh-hop-count", "parent-wtp-id", "software-version", "local-ip-addr", "board-mac", "ble-mac", "join-time",
    "connection-state", "image-download-progress", "last-failure", "last-failure-param", "last-failure-time",
}
_LLDP_KEYS = {
    "local port", "chassis id", "sys name", "sys description", "capability", "port id", "port description",
    "MAU oper type", "ip", "vlan id",
}
_RADIO_INTS = {
    "detected_rogue_ap_num": "rogue_ap", "detected_rogue_infra_ap_num": "rogue_infra_ap",
    "country-code": "country_code", "client-count": "client_count", "max-vaps": "max_vaps", "oper-chan": "channel",
    "bandwidth-rx": "bandwidth_rx", "bandwidth-tx": "bandwidth_tx", "bytes-rx": "bytes_rx", "bytes-tx": "bytes_tx",
    "mac-err-rx": "mac_err_rx", "mac-err-tx": "mac_err_tx", "interfering-ap": "interfering_ap",
    "peak-sta-cnt": "peak_clients",
}
_RADIO_KEYS = set(_RADIO_INTS) | {
    "country-name", "base-bssid", "radio_max_rate_standard", "radio_max_rate", "oper-chutil-time", "oper-chutil-val",
    "oper-txpower", "tx-retries", "antenna RSSI",
}


def _new_radio(number: int, mode: str) -> dict[str, Any]:
    exists = mode != "Not Exist"
    return {"radio": number, "mode": mode, "exists": exists, "channel": None, "width_mhz": None,
            "tx_power_dbm": None, "tx_power_max_dbm": None, "client_count": None, "chutil_percent": None,
            "chutil_age_s": None, "chutil_interval_seconds": None, "tx_retries_percent": None, "rogue_ap": None, "rogue_infra_ap": None,
            "interfering_ap": None, "antenna_rssi": None, "base_bssid": None, "country": None}


def _radio_value(radio: dict[str, Any], key: str, value: str) -> None:
    if key in _RADIO_INTS:
        radio[_RADIO_INTS[key]] = _int(value)
    elif key == "country-name":
        radio["country"] = value
    elif key == "base-bssid":
        if _MAC_RE.fullmatch(value) is None:
            raise ValueError(value)
        radio["base_bssid"] = value.lower()
    elif key in ("radio_max_rate_standard", "radio_max_rate"):
        if re.fullmatch(r"\d+ mbps", value) is None:
            raise ValueError(value)
    elif key == "oper-chutil-time":
        found = re.fullmatch(r"(.+) \(age=(\d+)\)", value)
        if found is None:
            raise ValueError(value)
        _local_time(found.group(1))
        radio["chutil_age_s"] = int(found.group(2))
    elif key == "oper-chutil-val":
        found = re.fullmatch(r"(\d+) \(averaged for the last available (\d+) seconds data\)", value)
        if found is None:
            raise ValueError(value)
        radio["chutil_percent"] = int(found.group(1))
        radio["chutil_interval_seconds"] = int(found.group(2))
    elif key == "oper-txpower":
        found = re.fullmatch(r"(\d+) \(max allowed (\d+)\)", value)
        if found is None:
            raise ValueError(value)
        radio["tx_power_dbm"], radio["tx_power_max_dbm"] = int(found.group(1)), int(found.group(2))
    elif key == "tx-retries":
        found = re.fullmatch(r"(\d+)%", value)
        if found is None:
            raise ValueError(value)
        radio["tx_retries_percent"] = int(found.group(1))
    elif key == "antenna RSSI":
        found = re.fullmatch(r"(\d+(?: +\d+)*) +\(age=\d+\)", value)
        if found is None:
            raise ValueError(value)
        radio["antenna_rssi"] = [int(item) for item in found.group(1).split()]


def parse_wtp_status(text: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    ap: dict[str, Any] | None = None
    section = "ap"
    radio: dict[str, Any] | None = None
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        head = _WTP_HEADER.fullmatch(line)
        if head:
            ap = {"serial": head.group(1), "wtp_id": None, "name": None, "ip": head.group(3), "capwap_port": int(head.group(4)),
                  "state": None, "version": None, "board_mac": None, "join_time": None, "join_time_note": "SSH wall clock has no timezone; use wifi_aps_live for UTC join time", "uptime_s": None,
                  "last_failure": None, "vdom": None, "lldp": None, "radios": []}
            records.append(ap)
            section, radio = "ap", None
            continue
        pair = _split(line)
        if ap is None or pair is None:
            unparsed.append(number)
            continue
        indent, key, value = pair
        try:
            if indent == 2:
                if key == "LLDP":
                    section = "lldp"
                    ap["lldp"] = {"enabled": value.startswith("enabled")}
                elif key == "SNMP":
                    section = "snmp"
                elif key == "Temperature in Celsius":
                    section = "temperature"
                elif key == "wtp-wanlan-mode":
                    section = "ap"
                elif re.fullmatch(r"Radio [1-9]", key):
                    section = "radio"
                    radio = _new_radio(int(key[-1]), value)
                    ap["radios"].append(radio)
                else:
                    raise ValueError(key)
            elif indent == 4 and section == "ap":
                if key not in _AP_KEYS:
                    raise ValueError(key)
                if key == "wtp-id":
                    ap["wtp_id"] = value
                elif key == "name":
                    ap["name"] = _none_if(value, "")
                elif key == "local-ip-addr":
                    ap["ip"] = value
                elif key == "connection-state":
                    ap["state"] = value
                elif key == "software-version":
                    ap["version"] = value
                elif key == "board-mac":
                    ap["board_mac"] = value.lower()
                elif key == "join-time":
                    _local_time(value)  # validate wall clock; do not invent its timezone
                elif key == "last-failure":
                    ap["last_failure"] = _none_if(value, "0 -- N/A")
                elif key == "vdom":
                    ap["vdom"] = value
            elif indent == 4 and section == "lldp":
                if key not in _LLDP_KEYS:
                    raise ValueError(key)
                names = {"local port": "local_port", "chassis id": "chassis_id", "sys name": "system_name",
                         "port id": "port_id", "ip": "ip"}
                if key in names:
                    ap["lldp"][names[key]] = value
            elif indent == 4 and section == "radio" and radio is not None and radio["exists"]:
                if key not in _RADIO_KEYS:
                    raise ValueError(key)
                _radio_value(radio, key, value)
            else:
                raise ValueError(key)
        except ValueError:
            unparsed.append(number)
    for item in records:
        if item["wtp_id"] is not None and item["wtp_id"] != item["serial"]:
            unparsed.append(0)
    return _result(records, unparsed)


# --- get wireless-controller vap-status ---------------------------------------------------------

_VAP_KEYS = {"name", "vdom", "ssid", "downup_oper", "mesh backhaul", "local bridging", "local switching", "ip", "mac",
             "station info"}


def _yes_no(value: str) -> bool:
    if value not in ("yes", "no"):
        raise ValueError(value)
    return value == "yes"


def parse_vap_status(text: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    vap: dict[str, Any] | None = None
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        head = re.fullmatch(r"WLAN: (\S.*)", line)
        if head:
            vap = {"name": head.group(1), "ssid": None, "state": None, "vdom": None, "ip": None, "mac": None,
                   "clients_online": None, "clients_offline": None, "local_bridging": None, "local_switching": None,
                   "mesh_backhaul": None}
            records.append(vap)
            continue
        pair = _split(line)
        if vap is None or pair is None or pair[0] != 4 or pair[1] not in _VAP_KEYS:
            unparsed.append(number)
            continue
        _, key, value = pair
        try:
            if key == "ssid":
                vap["ssid"] = value
            elif key == "downup_oper":
                vap["state"] = value
            elif key == "vdom":
                vap["vdom"] = value
            elif key == "ip":
                vap["ip"] = value
            elif key == "mac":
                vap["mac"] = value.lower()
            elif key == "station info":
                found = re.fullmatch(r"(\d+)/(\d+)", value)
                if found is None:
                    raise ValueError(value)
                vap["clients_online"], vap["clients_offline"] = int(found.group(1)), int(found.group(2))
            elif key == "local bridging":
                vap["local_bridging"] = _yes_no(value)
            elif key == "local switching":
                vap["local_switching"] = _yes_no(value)
            elif key == "mesh backhaul":
                vap["mesh_backhaul"] = _yes_no(value)
        except ValueError:
            unparsed.append(number)
    return _result(records, unparsed)


# --- get wireless-controller scan ---------------------------------------------------------------

_SCAN_ROW = re.compile(
    r"(\S{4}) (\d+) ++(\S(?:.*?\S)?)? *+(" + _MAC + r") +(\d+) +(\d+(?:\.\d+)?)M +(-?\d+) +(-?\d+) +(\d+) +(\S+) +([YN]) +"
    r"(\d+) +(\d+) +(\S+)(?: +(.*))?"
)


def parse_scan(text: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    header = 0
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        if re.fullmatch(r"CMWF +VF +SSID +BSSID +CHAN +RATE +SIGNAL +NOISE +INT +CAPS +ACT +LIVE +AGE +WIRED *", line):
            header += 1
            continue
        if re.fullmatch(r" +\(dBm\) +\(dBm\) *", line):
            continue
        row = _SCAN_ROW.fullmatch(line)
        if row is None or not header:
            unparsed.append(number)
            continue
        rate = float(row.group(6))
        records.append({
            "ssid": row.group(3) or None, "bssid": row.group(4).lower(), "channel": int(row.group(5)),
            "rate_mbps": int(rate) if rate == int(rate) else rate, "signal_dbm": int(row.group(7)),
            "noise_dbm": int(row.group(8)), "beacon_interval": int(row.group(9)), "capabilities": row.group(10),
            "active": row.group(11) == "Y", "live_s": int(row.group(12)), "age_s": int(row.group(13)),
            "wired": row.group(14), "flags": row.group(1), "classification": row.group(1)[0],
            "vf": int(row.group(2)), "security": (row.group(15) or "").split(),
        })
    if header != 1:
        unparsed.append(0)
    return _result(records, unparsed)


# --- get wireless-controller status / statistics ------------------------------------------------

_PEAK = re.compile(r"(\d+)/(\d+)/(\d+)/(\d+)")


def _peaks(value: str) -> list[dict[str, int]]:
    items = [item.strip() for item in value.split(",")]
    result = []
    for item in items:
        found = _PEAK.fullmatch(item)
        if found is None:
            raise ValueError(item)
        result.append({"2.4G": int(found.group(1)), "5G": int(found.group(2)), "6G": int(found.group(3)),
                       "all": int(found.group(4))})
    return result


def parse_controller_status(text: str) -> dict[str, Any]:
    status: dict[str, Any] = {}
    unparsed: list[int] = []
    head = 0
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        if re.fullmatch(r"Wireless Controller *: *", line):
            head += 1
            continue
        pair = _split(line)
        if pair is None or not head:
            unparsed.append(number)
            continue
        _, key, value = pair
        try:
            if key in ("wtp-session-count", "wtp-active", "wtp-down", "wtp-rebooted"):
                status[key.replace("-", "_")] = _int(value)
            elif key == "client-count":
                found = re.fullmatch(r"(\d+)/(\d+)", value)
                if found is None:
                    raise ValueError(value)
                status["clients_online"], status["clients_offline"] = int(found.group(1)), int(found.group(2))
            elif re.fullmatch(r"client-peak-(?:qtr|hour|day) \(2\.4G/5G/6G/All\)", key):
                status[key.split(" ")[0].replace("-qtr", "-quarter").replace("-", "_")] = _peaks(value)
            elif key == "image-pushing":
                status["image_pushing"] = _yes_no(value)
            else:
                raise ValueError(key)
        except ValueError:
            unparsed.append(number)
    if head != 1 or "wtp_active" not in status:
        unparsed.append(0)
    return _result([status] if status else [], unparsed)


_STATISTICS_KEYS = {
    "wtp-session-count": "wtp_sessions", "wtp-session-count(RUN)": "wtp_sessions_running", "client-count": "clients",
    "client-count(OFFLINE)": "clients_offline", "sta-cap-count": "station_capability_records",
    "rogue-ap-count": "rogue_aps", "rogue-client-count": "rogue_clients", "ble-device-count": "ble_devices",
}


def parse_controller_statistics(text: str) -> dict[str, Any]:
    statistics: dict[str, Any] = {}
    unparsed: list[int] = []
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        pair = _split(line)
        try:
            if pair is None or pair[0] != 0 or pair[1] not in _STATISTICS_KEYS or _STATISTICS_KEYS[pair[1]] in statistics:
                raise ValueError(line)
            statistics[_STATISTICS_KEYS[pair[1]]] = _int(pair[2])
        except ValueError:
            unparsed.append(number)
    if "wtp_sessions" not in statistics:
        unparsed.append(0)
    return _result([statistics] if statistics else [], unparsed)


# --- get wireless-controller rf-analysis --------------------------------------------------------

_RF_ROW = re.compile(r" *(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+)%")
_RF_CONTROLLER = re.compile(r"Controller:(?: +(\S+))? *")
_RF_CONTROLLER_ROW = re.compile(r" *(\d+) +(\d+) *")


def parse_rf_analysis(text: str) -> dict[str, Any]:
    """Per-AP RF tables and the controller summary (`Controller:` block, channel and total RSSI, `controller_rows`)."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    current: dict[str, Any] | None = None
    header = False
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        head = _WTP_HEADER.fullmatch(line)
        controller = _RF_CONTROLLER.fullmatch(line)
        if head or controller:
            if head:
                current = {"wtp": head.group(1), "scope": "wtp", "ip": head.group(3), "channels": []}
            else:
                current = {"wtp": None, "scope": "controller", "ip": None, "controller": controller.group(1),
                           "controller_rows": []}
            records.append(current)
            header = False
            continue
        if re.fullmatch(r" *channel +rssi-total +rf-score +overlap-ap +interfere-ap +chan-utilization *", line):
            header = current is not None and current["scope"] == "wtp"
            continue
        if re.fullmatch(r" *channel +rssi_total *", line):
            header = current is not None and current["scope"] == "controller"
            continue
        if header and current["scope"] == "controller":
            controller_row = _RF_CONTROLLER_ROW.fullmatch(line)
            if controller_row is None:
                unparsed.append(number)
                continue
            current["controller_rows"].append({"channel": int(controller_row.group(1)),
                                               "rssi_total": int(controller_row.group(2))})
            continue
        row = _RF_ROW.fullmatch(line)
        if row is None or current is None or not header:
            unparsed.append(number)
            continue
        values = [int(group) for group in row.groups()]
        current["channels"].append({"channel": values[0], "rssi_total": values[1], "rf_score": values[2],
                                    "overlap_ap": values[3], "interfere_ap": values[4],
                                    "chan_utilization_percent": values[5]})
    return _result(records, unparsed)


# --- execute log display (wireless events) ------------------------------------------------------

_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)=("(?:[^"\\]|\\.)*"|[^\s"]+)')
_EVENT_LINE = re.compile(r"(\d+): (date=.*)")
_NA = ("N/A", "")


class UndatedEvent(ValueError):
    """The record carries neither a UTC offset nor an epoch, so its instant would be a guess."""


def _event_time(fields: dict[str, str]) -> str:
    moment = datetime.strptime(fields["date"] + " " + fields["time"], "%Y-%m-%d %H:%M:%S")
    zone = re.fullmatch(r"([+-])(\d{2})(\d{2})", fields.get("tz", ""))
    if zone is None:
        epoch = fields.get("eventtime", "")
        if re.fullmatch(r"[0-9]{19}", epoch):
            return datetime.fromtimestamp(int(epoch) / 1_000_000_000, timezone.utc).isoformat()
        raise UndatedEvent("event time has no UTC offset or epoch")
    offset = timedelta(hours=int(zone.group(2)), minutes=int(zone.group(3)))
    return moment.replace(tzinfo=timezone(-offset if zone.group(1) == "-" else offset)).isoformat()


def classify_logdesc(logdesc: str, reason: str = "", status: str = "", action: str = "") -> str:
    """Event class from the log description; only descriptions measured on the device are certain."""
    text = " ".join((logdesc, reason, status, action)).lower()
    if text.startswith("rogue ap") or "rogue" in text:
        return "rogue_ap"
    error = any(word in text for word in ("fail", "reject", "denied", "timeout", "no server response", "invalid", "unable", "error")) or status.lower() in {"failed", "failure", "deny"}
    if "dhcp" in text:
        return "client_error" if error or re.search(r"\bnak\b", text) else "client_dhcp"
    if not any(word in text for word in ("client", "station", "auth", "handshake")):
        return "other"
    if any(word in text for word in ("disassociat", "deauthenticat", "disconnect", "left", "removed", "deleted")):
        return "client_disconnect"
    if error:
        return "client_error"
    if "roam" in text:
        return "client_roam"
    if any(word in text for word in ("associat", "authenticat", "connected", "joined", "ip address", "added", "handshake succeeded", "handshake successful", "handshake completed")):
        return "client_connect"
    return "client_other"


def _field_int(fields: dict[str, str], key: str) -> int | None:
    value = fields.get(key)
    return int(value) if value is not None and re.fullmatch(r"-?\d{1,18}", value) else None


def _event_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    position = 0
    # Consume fields at the current cursor; searching every suffix of a long
    # malformed key would retry the same identifier quadratically.
    while position < len(body):
        if body[position].isspace():
            position += 1
            continue
        found = _KV.match(body, position)
        if found is None:
            raise ValueError("invalid event field")
        value = found.group(2)
        fields[found.group(1)] = value[1:-1].replace('\\"', '"') if value.startswith('"') else value
        position = found.end()
    if body[position:].strip():
        raise ValueError("trailing text")
    return fields


def _mac(fields: dict[str, str], key: str) -> str | None:
    value = fields.get(key)
    return value.lower() if value is not None and _MAC_RE.fullmatch(value) else None


def event_record(fields: dict, index: int) -> dict:
    """Common dated wireless event shape for SSH and REST."""
    if fields.get("subtype") != "wireless" or fields.get("type") != "event":
        raise ValueError("not a wireless event")
    fields = {k: str(v) for k, v in fields.items() if v is not None}
    logdesc = fields.get("logdesc", "")
    reason = _none_if(fields.get("reason", ""), *_NA)
    classification = classify_logdesc(logdesc, reason or "", fields.get("status", fields.get("authstatus", "")), fields.get("action", ""))
    auth_text = " ".join((logdesc, reason or "", fields.get("action", ""))).lower()
    # Independent of disconnect classification: reason text/codes can describe
    # an authentication failure even when logdesc only says deauthenticated.
    # These reason interpretations are heuristics, not a measured bad-PSK fixture.
    auth_context = any(word in re.sub(r"deauthenticat\w*|disassociat\w*", "", auth_text)
                       for word in ("auth", "associat", "handshake", "sae", "eap"))
    auth_error = any(word in auth_text for word in ("fail", "reject", "denied", "timeout", "invalid", "no longer valid", "unable", "error"))
    authentication_failure = (
        (auth_context and (auth_error or fields.get("status", fields.get("authstatus", "")).lower() in {"failed", "failure", "deny"}))
        or (reason or "").strip() in {"2", "15", "16", "23"})
    from .wifi_common import phy_band
    band = phy_band(fields.get("radioband", "").upper())
    band_source = "radioband" if band else None
    channel = _field_int(fields, "channel")
    # Primary channel numbers shared by 2.4/5 and 6 GHz remain ambiguous.
    # The measured client logs omit radioband, but channels 6, 116, 124 are unambiguous.
    if band is None and channel in {3, 4, 6, 7, 8, 10, 11, 12, 14}:
        band, band_source = "24ghz", "unambiguous_primary_channel"
    elif band is None and channel in {*range(36, 65, 4), *range(100, 145, 4)}:
        band, band_source = "5ghz", "unambiguous_primary_channel"
    return {
                "authentication_failure": authentication_failure, "band": band, "band_source": band_source,
                "index": index, "time": _event_time(fields), "logid": fields.get("logid"),
                "level": fields.get("level"), "logdesc": logdesc,
                "timeline_type": classification.removeprefix("client_"),
                "class": classification,
                "status": fields.get("status", fields.get("authstatus")), "action": _none_if(fields.get("action", ""), *_NA), "client_mac": (_mac(fields, "stamac") or _mac(fields, "mac")),
                "client_ip": _none_if(fields.get("srcip", ""), *_NA), "bssid": _mac(fields, "bssid"),
                "ssid": _none_if(fields.get("ssid", ""), *_NA), "vap": _none_if(fields.get("vap", ""), *_NA),
                "ap": _none_if(fields.get("ap", fields.get("sndetected", "")), *_NA),
                "radio": _field_int(fields, "radioid"), "channel": _field_int(fields, "channel"),
                "signal_dbm": _field_int(fields, "signal"), "snr": _field_int(fields, "snr"),
                "reason": reason, "message": fields.get("msg", "")[:200] or None,
                "security": _none_if(fields.get("security", ""), *_NA),
            }


def parse_events(text: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    undated = 0
    found_total = returned_total = None
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        count = re.fullmatch(r"(\d+) logs found\.", line)
        if count:
            found_total = int(count.group(1))
            continue
        count = re.fullmatch(r"(\d+) logs returned\.", line)
        if count:
            returned_total = int(count.group(1))
            continue
        if re.fullmatch(r'(?:100(?:\.0+)?|[1-9]?\d(?:\.\d+)?)% of logs (?:has|have) been searched\.', line):
            continue
        event = _EVENT_LINE.fullmatch(line)
        if event is None:
            unparsed.append(number)
            continue
        try:
            fields = _event_fields(event.group(2))
            if fields.get("subtype") != "wireless" or fields.get("type") != "event":
                raise ValueError("not a wireless event")
            records.append(event_record(fields, int(event.group(1))))
        except UndatedEvent:
            undated += 1  # only this record is left out; it is counted, never given a guessed time
        except (ValueError, KeyError):
            unparsed.append(number)
    return _result(records, unparsed, found=found_total, returned=returned_total, undated=undated)


def filter_events_by_mac(text: str, mac: str) -> tuple[str, dict[str, Any]]:
    """Keep only the event records of one MAC (client MAC or BSSID), applied to already redacted text.

    The device's own "N logs found." / "M logs returned." lines stay as they were: they describe
    the unfiltered batch, and the second number is how many lines were scanned.
    """
    headers: list[str] = []
    kept: list[str] = []
    scanned = 0
    for line in _lines(text):
        if re.fullmatch(r"\d+ logs (?:found|returned)\.", line):
            headers.append(line)
            continue
        event = _EVENT_LINE.fullmatch(line)
        if event is None:
            if line.strip():
                headers.append(line)  # unrecognised text stays visible as unparsed
            continue
        scanned += 1
        try:
            fields = _event_fields(event.group(2))
        except ValueError:
            headers.append(line)
            continue
        if mac in (_mac(fields, "stamac"), _mac(fields, "bssid")):
            kept.append(line)
    body = "\n".join(headers)
    if kept:
        body += "\n\n" + "\n\n".join(kept)
    return body + "\n", {"mac_literal": mac, "scanned_lines": scanned, "matched": len(kept)}


PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "wifi_ap_status": parse_wtp_status,
    "wifi_vap_status": parse_vap_status,
    "wifi_neighbors": parse_scan,
    "wifi_controller_status": parse_controller_status,
    "wifi_controller_statistics": parse_controller_statistics,
    "wifi_rf_analysis": parse_rf_analysis,
    "wifi_events": parse_events,
}


def summarize(query: str, text: str) -> dict[str, Any]:
    return PARSERS[query](text)


# --- Ruckus Unleashed `show` reads, measured on R610 on Ruckus Unleashed 200.15.6.212.27 ----------
#
# The output is an indented tree of `Section:` lines and `Key= value` (or `Key = value`) lines. A line that is
# neither (outside an event message) is reported as unparsed. Only listed fields are copied into records, so a
# configuration value such as a WLAN passphrase never reaches a record even when the device printed it.

# The tested R610 firmware in the five-part spelling Ruckus uses (release and build; `show sysinfo` prints them as
# `Version= <release> build <build>`).
RUCKUS_R610_RELEASE, RUCKUS_R610_BUILD = "200.15.6.212.27".rsplit(".", 1)
RUCKUS_NOT_FOUND = re.compile(r"(?m)^[ \t]*The entry '[^'\r\n]*' could not be found\. Please check the spelling, and then try again\.[ \t]*$")
_RUCKUS_EVENTS = "Last 300 Events/Activities"
_RUCKUS_REDACTED = re.compile(r"<REDACTED>|\[REDACTED\]|<REDACTED:credential#[1-9][0-9]*>|<PRIVATE-KEY-REDACTED>")
_RUCKUS_COUNT = re.compile(r"(\d+) pkts(?: / (\d+) bytes)?")


def _ruckus_items(text: str) -> list[tuple[int, int, str, str | None]]:
    """(line number, indent, key or text, value; None for a section heading, "" marker for free text)."""
    items: list[tuple[int, int, str, str | None]] = []
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if not items and body.startswith("show "):
            continue  # the device echo of the command
        key, separator, value = body.partition("=")
        if separator and key.strip():
            items.append((number, indent, key.strip(), value.strip()))
        elif body.endswith(":"):
            items.append((number, indent, body[:-1].strip(), None))
        elif _RUCKUS_REDACTED.search(body):
            # A secret line the redaction rewrote without its `=` (e.g. `Secret= x` -> `[REDACTED]`): a hidden
            # value, not unreadable text; parsers ignore it like any other unlisted field.
            items.append((number, indent, body, "<REDACTED>"))
        else:
            items.append((number, indent, body, "\0"))
    return items


def _ruckus_walk(text: str):
    """Yield (line number, section path, key, value) with the enclosing section headings of every line."""
    stack: list[tuple[int, str]] = []
    for number, indent, key, value in _ruckus_items(text):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(name for _, name in stack)
        if value is None:
            stack.append((indent, key))
        yield number, path, key, value


def _r_int(value: str | None) -> int | str | None:
    if value in (None, ""):
        return None
    return int(value) if re.fullmatch(r"\d{1,12}", value) else value


def _r_text(value: str | None) -> str | None:
    return value if value else None


def _r_mac(value: str | None) -> str | None:
    if not value:
        return None
    if _MAC_RE.fullmatch(value) is None:
        raise ValueError(value)
    return value.lower()


def _r_bool(value: str | None) -> bool | None:
    lowered = (value or "").lower()
    if lowered in ("yes", "enabled", "true"):
        return True
    if lowered in ("no", "disabled", "false"):
        return False
    return None


def _r_time(value: str | None) -> str | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y/%m/%d %H:%M:%S").isoformat()


def _r_band(radio: str) -> str | None:
    """`Radio a/n` (also a/n/ac) is the 5 GHz radio, `Radio b/g/n` the 2.4 GHz radio of the AP listing."""
    if radio.startswith("a/") or radio == "a":
        return "5g"
    if radio.startswith("b/g"):
        return "2.4g"
    return None


_RUCKUS_EVENT_FIELDS = {"Date/Time": ("time", _r_time), "Severity": ("severity", _r_text), "User": ("user", _r_text)}
_RUCKUS_EVENT_LABEL = re.compile(r"(" + "|".join(_RUCKUS_EVENT_FIELDS) + r")(?=[: \t]|$)")


def _ruckus_events(walk_items: list[tuple[int, tuple[str, ...], str, str | None]],
                   lines: list[str]) -> tuple[list[dict[str, Any]], list[int]]:
    """Events of a `Last 300 Events/Activities` block: one per `Activity:` directly under the block.

    Inside an activity the leading `Date/Time`, `Severity` and `User` lines are fields (each once, before the
    message). A malformed field delimiter in the header is reported without starting the message. Other
    lines are message text as printed, including when they contain `=` or end with a colon. A line outside
    an activity or a field the parser cannot read is
    reported as unparsed.
    """
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    unparsed: list[int] = []
    start = None

    def finish_event():
        if start is None:
            return
        event = events[-1]
        if re.fullmatch(r"Activities\s*=", event["message"] or ""):
            event["message"] = None
        if not event["message"] or seen != _RUCKUS_EVENT_FIELDS.keys():
            unparsed.append(start)

    for number, path, key, value in walk_items:
        if not path and value is None and key == _RUCKUS_EVENTS:
            continue  # the block heading itself (client detail passes it along)
        if value is None and key in {"Activity", "Activitiy"} and path == (_RUCKUS_EVENTS,):
            finish_event()
            events.append({"time": None, "severity": None, "user": None, "message": None})
            seen = set()
            start = number
            continue
        if not events or len(path) < 2:
            unparsed.append(number)
            continue
        event = events[-1]
        if value not in (None, "\0") and key in _RUCKUS_EVENT_FIELDS and key not in seen and event["message"] is None:
            seen.add(key)
            name, convert = _RUCKUS_EVENT_FIELDS[key]
            try:
                event[name] = convert(value)
                if key != "User" and event[name] is None:
                    unparsed.append(number)
            except ValueError:
                unparsed.append(number)
            continue
        text = lines[number - 1].strip()
        label = _RUCKUS_EVENT_LABEL.match(text)
        if event["message"] is None and label and label[1] not in seen:
            seen.add(label[1])
            unparsed.append(number)
            continue
        event["message"] = text if event["message"] is None else event["message"] + " " + text
    finish_event()
    return events, unparsed


_CLIENT_FIELDS = {
    "Mac Address": ("mac", _r_mac), "OS/Type": ("os_type", _r_text), "Host Name": ("hostname", _r_text),
    "User/IP": ("ip", _r_text), "Role": ("role", _r_text), "Access Point": ("ap_mac", _r_mac),
    "BSSID": ("bssid", _r_mac), "Connect Since": ("connected_since", _r_time), "Auth Method": ("auth_method", _r_text),
    "WLAN": ("wlan", _r_text), "VLAN": ("vlan_id", _r_int), "Channel": ("channel", _r_int),
    "Radio": ("radio", _r_text), "Signal": ("signal", _r_int), "Status": ("status", _r_text),
}
_CLIENT_COUNTERS = {
    "Received from client": ("rx_packets", "rx_bytes"), "Transmitted to client": ("tx_packets", "tx_bytes"),
    "Tx. drops due to retry failure": ("tx_retry_fail_drops", None),
}


def _new_client() -> dict[str, Any]:
    record: dict[str, Any] = {name: None for name, _ in _CLIENT_FIELDS.values()}
    for packets, octets in _CLIENT_COUNTERS.values():
        record[packets] = None
        if octets:
            record[octets] = None
    return record


def parse_ruckus_clients(text: str) -> dict[str, Any]:
    """`show current-active-clients all|mac <mac>`: one record per client and the events listed after them."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    event_items = []
    headings = 0
    for number, path, key, value in _ruckus_walk(text):
        if path[:1] == (_RUCKUS_EVENTS,) or (not path and key == _RUCKUS_EVENTS):
            event_items.append((number, path, key, value))
            continue
        if value is None:
            if key == "Clients":
                records.append(_new_client())
            elif key == "Current Active Clients" and not path:
                headings += 1
            else:
                unparsed.append(number)
            continue
        if not records or "Clients" not in path or value == "\0":
            unparsed.append(number)
            continue
        try:
            if key in _CLIENT_FIELDS:
                name, convert = _CLIENT_FIELDS[key]
                records[-1][name] = convert(value)
            elif key in _CLIENT_COUNTERS:
                found = _RUCKUS_COUNT.fullmatch(value)
                if found is None:
                    raise ValueError(value)
                packets, octets = _CLIENT_COUNTERS[key]
                records[-1][packets] = int(found.group(1))
                if octets:
                    records[-1][octets] = int(found.group(2)) if found.group(2) else None
        except ValueError:
            unparsed.append(number)
    events, event_unparsed = _ruckus_events(event_items, _lines(text))
    per_ap: dict[str, int] = {}
    per_wlan: dict[str, int] = {}
    for record in records:
        if record["ap_mac"]:
            per_ap[record["ap_mac"]] = per_ap.get(record["ap_mac"], 0) + 1
        if record["wlan"]:
            per_wlan[record["wlan"]] = per_wlan.get(record["wlan"], 0) + 1
    return _result(records, sorted(unparsed + event_unparsed), client_count=len(records),
                   clients_per_ap=per_ap, clients_per_wlan=per_wlan, events=events,
                   incomplete=headings != 1 or any(not row["mac"] for row in records))


def parse_ruckus_access_points(text: str, *, allow_empty: bool = False) -> dict[str, Any]:
    """`show ap all|mac <mac>|devname <name>`: identity, radios (channel, width, power) and LAN ports per AP."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    headings = []
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            headings.append((path, key))
            if path == ("AP", "ID") and key.isdigit():
                records.append({"mac": None, "name": None, "model": None, "role": None, "approved": None,
                                "location": None, "ip": None, "gateway": None, "mesh": None,
                                "netmask": None, "ip_mode": None, "protocol_mode": None, "lldp_status": None,
                                "radios": [], "lan_ports": []})
            elif records and key.startswith("Radio ") and len(path) == 3:
                radio = key[len("Radio "):]
                records[-1]["radios"].append({"radio": radio, "band": _r_band(radio), "channel": None,
                                              "width_mhz": None, "tx_power": None, "wlan_enabled": None})
            elif records and path[3:] == ("LAN Port",) and key.isdigit():
                records[-1]["lan_ports"].append({"port": int(key), "interface": None, "logical_link": None,
                                                 "physical_link": None, "label": None, "dot1x": None})
            elif not path[:2] == ("AP", "ID") and key not in ("AP", "ID"):
                unparsed.append(number)
            continue
        if not records or value == "\0" or len(path) < 3:
            unparsed.append(number)
            continue
        ap, section = records[-1], path[3:]
        try:
            if not section:
                field = {"MAC Address": "mac", "Device Name": "name", "Model": "model", "Device Role": "role",
                         "Location": "location"}.get(key)
                if field == "mac":
                    ap["mac"] = _r_mac(value)
                elif field:
                    ap[field] = _r_text(value)
                elif key == "Approved":
                    ap["approved"] = _r_bool(value)
                elif key == "PoE Mode":
                    ap["poe_mode"] = _r_text(value)
            elif section[0].startswith("Radio ") and ap["radios"]:
                radio = ap["radios"][-1]
                if key == "Channel":
                    radio["channel"] = _r_int(value)
                elif key == "Channelization":
                    radio["width_mhz"] = _r_int(value)
                elif key == "Tx. Power":
                    radio["tx_power"] = _r_text(value)
                elif key == "WLAN Services enabled":
                    radio["wlan_enabled"] = _r_bool(value)
            elif section == ("Network Setting",):
                # wireless path (RP09): management values as the AP prints them; no management VLAN is printed here.
                field = {"IP Address": "ip", "Gateway": "gateway", "Netmask": "netmask",
                         "Device IP Settings": "ip_mode", "Protocol mode": "protocol_mode"}.get(key)
                if field:
                    ap[field] = _r_text(value)
            elif section == ("Mesh",) and key == "Status":
                ap["mesh"] = _r_text(value)
            elif section == ("LLDP",) and key == "Status":
                ap["lldp_status"] = _r_text(value)
            elif section[0] == "LAN Port" and len(section) == 2 and ap["lan_ports"]:
                port = ap["lan_ports"][-1]
                field = {"Interface": "interface", "LogicalLink": "logical_link", "PhysicalLink": "physical_link",
                         "Label": "label", "Dot1x": "dot1x"}.get(key)
                if field:
                    port[field] = " ".join(value.split()) or None
        except ValueError:
            unparsed.append(number)
    empty_listing = allow_empty and (
        not headings or headings == [((), "AP"), (("AP",), "ID")])
    return _result(records, unparsed, ap_count=len(records),
                   incomplete=(not records and not empty_listing) or any(not row["mac"] for row in records))


def _ruckus_ap_inventory(text: str) -> dict[str, Any]:
    return parse_ruckus_access_points(text, allow_empty=True)


def parse_ruckus_ethinfo(text: str) -> dict[str, Any]:
    """`show ethinfo` (wireless path, RP09): the Ethernet ports of the device the CLI runs on (the master AP).

    One record per `Port N:` with interface, MAC, physical link and speed as printed. The output names no VLAN,
    tagging or LLDP neighbour, so none is stated.
    """
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            found = re.fullmatch(r"Port +(\d+)", key)
            if found and path == ("System Ethernet Overview",):
                records.append({"port": int(found.group(1)), "interface": None, "mac": None, "physical_link": None,
                                "speed": None})
            elif not (key == "System Ethernet Overview" and not path):
                unparsed.append(number)
            continue
        if not records or value == "\0" or len(path) != 2:
            unparsed.append(number)
            continue
        try:
            field = {"Interface": "interface", "Physical Link": "physical_link", "Speed": "speed"}.get(key)
            if key == "MAC Address":
                records[-1]["mac"] = _r_mac(value)
            elif field:
                records[-1][field] = _r_text(value)
            else:
                unparsed.append(number)
        except ValueError:
            unparsed.append(number)
    # `partial_ports`: ports printed without interface name or physical link state. On its own the read stays
    # incomplete then; wifi_triage judges only the AP uplink port (an unused LAN port may print no link).
    partial = [row["interface"] or "port %d" % row["port"] for row in records
               if not (row["interface"] and row["physical_link"])]
    return _result(records, unparsed, port_count=len(records), partial_ports=partial,
                   incomplete=not records or bool(partial))


_WLAN_FIELDS = {
    "NAME": "name", "SSID": "ssid", "Description": "description", "Type": "type", "Authentication": "authentication",
    "Encryption": "encryption", "Wlan Bind": "band", "L2/MAC": "l2_mac_acl",
}


def parse_ruckus_wlans(text: str) -> dict[str, Any]:
    """`show wlan all|name <name>`: the operational summary of every WLAN (SSID, VLAN, band, service state)."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            if path == ("WLAN Service", "ID") and key.isdigit():
                records.append({"id": int(key), **{name: None for name in _WLAN_FIELDS.values()},
                                "vlan_id": None, "dynamic_vlan": None, "service_enabled": None, "hidden": None,
                                "max_clients": None, "dhcp_relay_enabled": None})
            elif not path[:2] == ("WLAN Service", "ID") and key not in ("WLAN Service", "ID"):
                unparsed.append(number)
            continue
        if not records or value == "\0" or len(path) < 3:
            unparsed.append(number)
            continue
        if len(path) != 3:
            continue
        wlan = records[-1]
        if key == "Wlan Bind":
            wlan["band"] = {"2g": "2.4g", "5g": "5g"}.get(value, _r_text(value))
        elif key in _WLAN_FIELDS:
            wlan[_WLAN_FIELDS[key]] = _r_text(value)
        elif key == "VLAN-ID":
            wlan["vlan_id"] = _r_int(value)
        elif key == "DHCP relay":
            wlan["dhcp_relay_enabled"] = _r_bool(value)
            if wlan["dhcp_relay_enabled"] is None:
                unparsed.append(number)
        elif key == "Dynamic VLAN":
            wlan["dynamic_vlan"] = _r_bool(value)
        elif key == "Service":
            wlan["service_enabled"] = _r_bool(value)
        elif key == "Closed System":
            wlan["hidden"] = _r_bool(value)
        elif key == "Max. Clients":
            wlan["max_clients"] = _r_int(value)
    return _result(records, unparsed, wlan_count=len(records))


_PERFORMANCE_FIELDS = {
    "Estimated Capacity": "estimated_capacity", "Downlink": "downlink", "Uplink": "uplink",
    "RF pollution": "rf_pollution", "Authorized clients": "authorized_clients", "Other APs": "other_aps",
}
_STATION_FIELDS = ("estimated_capacity", "downlink", "uplink")


def parse_ruckus_performance(text: str) -> dict[str, Any]:
    """`show performance ap-radio2-4|ap-radio5|station mac <mac>`: the counters the device prints, unconverted.

    Units of capacity/downlink/uplink are not printed by the device and are therefore not stated here. On Ruckus
    Unleashed 200.15.6.212.27 the AP radio reads sometimes answer with the header and MAC only (measured 2026-11-17,
    a repeat seconds later had the counters): such a record keeps its counters None, `counters_reported` False and
    the result `incomplete` True, so an empty answer is never read as zero traffic.
    """
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            if key.startswith("Radio ") and path[:1] == ("AP performance",):
                radio = key[len("Radio "):]
                records.append({"mac": None, "radio": radio, "band": _r_band(radio),
                                **{name: None for name in _PERFORMANCE_FIELDS.values()}})
            elif key == "Station performance":
                records.append({"mac": None, "radio": None, "band": None,
                                **{name: None for name in _PERFORMANCE_FIELDS.values() if name in _STATION_FIELDS}})
            elif not (key == "AP performance" or (path == ("AP performance",) and key.isdigit())):
                unparsed.append(number)
            continue
        if not records or value == "\0":
            unparsed.append(number)
            continue
        try:
            if key == "MAC Address":
                records[-1]["mac"] = _r_mac(value)
            elif key in _PERFORMANCE_FIELDS and _PERFORMANCE_FIELDS[key] in records[-1]:
                records[-1][_PERFORMANCE_FIELDS[key]] = _r_int(value)
            else:
                unparsed.append(number)
        except ValueError:
            unparsed.append(number)
    for record in records:
        record["counters_reported"] = any(record[name] is not None for name in _PERFORMANCE_FIELDS.values()
                                          if name in record)
    return _result(records, unparsed, incomplete=not records or not all(item["counters_reported"] for item in records))


_ROGUE_FIELDS = {
    "Mac Address": ("mac", _r_mac), "Channel": ("channel", _r_int), "Radio": ("radio", _r_text),
    "Type": ("type", _r_text), "Encryption": ("encryption", _r_text), "SSID": ("ssid", _r_text),
    "Last Detected": ("last_detected", _r_time),
}
_ROGUE_LISTS = {"Current Active Rogue Devices": "active", "Known/Recognized Rogue Devices": "known",
                "User Blocked Rogue Devices": "blocked"}


def parse_ruckus_rogues(text: str) -> dict[str, Any]:
    """`show rogue-devices`: rogue APs per list (active, known/recognized, user blocked)."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    headings: list[str] = []
    seen: set[str] = set()
    sizes = dict.fromkeys(_ROGUE_LISTS.values(), 0)
    incomplete = False
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            if key in _ROGUE_LISTS and not path:
                headings.append(key)
            elif key == "Rogue Devices" and len(path) == 1 and path[0] in _ROGUE_LISTS:
                incomplete |= bool(records) and seen != _ROGUE_FIELDS.keys()
                bucket = _ROGUE_LISTS[path[0]]
                records.append({"list": bucket, **{name: None for name, _ in _ROGUE_FIELDS.values()}})
                sizes[bucket] += 1
                seen = set()
            else:
                unparsed.append(number)
            continue
        if (not records or len(path) != 2 or path[-1] != "Rogue Devices" or path[0] not in _ROGUE_LISTS
                or value == "\0" or key not in _ROGUE_FIELDS or key in seen):
            unparsed.append(number)
            continue
        seen.add(key)
        name, convert = _ROGUE_FIELDS[key]
        try:
            records[-1][name] = convert(value)
        except ValueError:
            unparsed.append(number)
    incomplete |= headings != list(_ROGUE_LISTS) or (bool(records) and seen != _ROGUE_FIELDS.keys())
    incomplete |= any(not item["mac"] for item in records)
    return _result(records, unparsed, active_count=sizes["active"], known_count=sizes["known"],
                   blocked_count=sizes["blocked"], incomplete=incomplete)


def parse_ruckus_events(text: str) -> dict[str, Any]:
    """`show events` and `show events-activities`: retained records, newest first."""
    items = list(_ruckus_walk(text))
    headings = sum(not path and value is None and key == _RUCKUS_EVENTS for _, path, key, value in items)
    unparsed = [number for number, path, key, value in items
                if not path and not (value is None and key == _RUCKUS_EVENTS)]
    events, event_unparsed = _ruckus_events([item for item in items if item[1]], _lines(text))
    return _result(events, sorted(set(unparsed + event_unparsed)),
                   incomplete=headings != 1 or len(events) > 300)


_MESH_HEADER = re.compile(r"Mesh Topology\([^()]+\):")
_MESH_MEMBER = re.compile(rf"(Root|Mesh) Access Points\s*=\s*({_MAC})")
_MESH_SIGNAL = re.compile(r"Signal \(dB\) Downlink\s*=\s*(-?\d+)?\s*/\s*Uplink\s*=\s*(-?\d+)?")


def parse_ruckus_mesh(text: str) -> dict[str, Any]:
    """Current members and signal according to the documented Unleashed mesh topology read."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    headers = 0
    seen: set[str] = set()
    incomplete = False
    for number, line in enumerate(_lines(text), 1):
        body = line.strip()
        if not body or body == "show mesh topology":
            continue
        if _MESH_HEADER.fullmatch(body):
            headers += 1
            continue
        member = _MESH_MEMBER.fullmatch(body)
        if member:
            incomplete |= bool(records) and seen != {"signal", "channel", "ip"}
            records.append({"role": member[1].lower(), "mac": member[2].lower(),
                            "downlink_db": None, "uplink_db": None, "channel": None, "ip": None})
            seen = set()
            continue
        if not records:
            unparsed.append(number)
            continue
        key, equals, value = body.partition("=")
        signal = _MESH_SIGNAL.fullmatch(body)
        if signal and "signal" not in seen:
            records[-1].update(downlink_db=int(signal[1]) if signal[1] else None,
                               uplink_db=int(signal[2]) if signal[2] else None)
            seen.add("signal")
        elif equals and key.strip() == "Description":
            continue
        elif equals and key.strip() in {"Channel", "IP Address"} and value.strip():
            field = "channel" if key.strip() == "Channel" else "ip"
            if field in seen:
                unparsed.append(number)
            else:
                records[-1][field] = value.strip()
                seen.add(field)
        else:
            unparsed.append(number)
    incomplete |= bool(records) and seen != {"signal", "channel", "ip"}
    return _result(records, unparsed, incomplete=incomplete or headers != 1)


_PING_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_PING_HEADER = re.compile(rf"PING (\S+) \(({_PING_IPV4})\):? (\d+)(?: data bytes|\(\d+\) bytes of data\.)")
_PING_REPLY = re.compile(
    rf"(\d+) bytes from ({_PING_IPV4}): (?:icmp_)?seq=(\d+) ttl=(\d+) time=(\d+(?:\.\d+)?) ms")
_PING_ERROR = re.compile(
    rf"From (?:{_PING_IPV4}|\S+ \({_PING_IPV4}\)):? icmp_seq=(\d{{1,9}}) "
    r"Destination (?:Host|Net|Protocol|Port) Unreachable")
_PING_TOTALS = re.compile(
    r"(\d{1,9}) packets transmitted, (\d{1,9}) (?:packets )?received,(?: \+?\d+ duplicates,)?(?: \+(\d{1,9}) errors,)? "
    r"(\d{1,3}(?:\.\d{1,9})?)% packet loss(?:, time \d+ms)?")
_PING_RTT = re.compile(
    r"(?:round-trip min/avg/max|rtt min/avg/max/mdev) = "
    r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)(?:/\d+(?:\.\d+)?)? ms")


def parse_ruckus_ping(text: str) -> dict[str, Any]:
    """`ping <ip>` (wireless path, R02): an echo probe sent from the Unleashed master AP.

    One record with the target, every reply (seq, ttl, time) and the device's own totals. Without the totals line
    the answer is `incomplete` (an interrupted or cut read is never read as loss). The source is the master AP
    management plane, not a client data path.
    """
    record: dict[str, Any] = {"target": None, "data_bytes": None, "replies": [], "transmitted": None,
                              "received": None, "loss_percent": None, "rtt_min_ms": None, "rtt_avg_ms": None,
                              "rtt_max_ms": None}
    unparsed: list[int] = []
    statistics_target = None
    error_seqs: list[int] = []
    reported_errors = 0
    for number, line in enumerate(_lines(text), 1):
        body = line.strip()
        if not body or (number == 1 and body.startswith("ping ")):
            continue
        header, reply = _PING_HEADER.fullmatch(body), _PING_REPLY.fullmatch(body)
        error = _PING_ERROR.fullmatch(body)
        totals, rtt = _PING_TOTALS.fullmatch(body), _PING_RTT.fullmatch(body)
        statistics = re.fullmatch(r"--- (\S+) ping statistics ---", body)
        if header and record["target"] is None:
            record["target"], record["data_bytes"] = header.group(2), int(header.group(3))
        elif reply and record["target"] is not None:
            record["replies"].append({"from": reply.group(2), "seq": int(reply.group(3)), "ttl": int(reply.group(4)),
                                      "time_ms": float(reply.group(5))})
        elif error and record["target"] is not None and statistics_target is None:
            error_seqs.append(int(error.group(1)))
        elif statistics and statistics_target is None:
            statistics_target = statistics.group(1)
        elif totals and statistics_target is not None and record["transmitted"] is None:
            record["transmitted"], record["received"] = int(totals.group(1)), int(totals.group(2))
            reported_errors = int(totals.group(3) or "0")
            loss = totals.group(4)
            record["loss_percent"] = float(loss) if "." in loss else int(loss)
        elif rtt and record["rtt_min_ms"] is None:
            record["rtt_min_ms"], record["rtt_avg_ms"], record["rtt_max_ms"] = (float(value) for value in rtt.groups())
        else:
            unparsed.append(number)
    warnings = _ping_warnings(record, unparsed, statistics_target, error_seqs, reported_errors)
    complete = not warnings
    return _result([record] if record["target"] is not None else [], unparsed, incomplete=not complete,
                   reachable=(record["received"] > 0) if complete else None, warnings=warnings,
                   vantage="master AP management plane (not a client data path)")


def _ping_warning(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _ping_warnings(record: dict[str, Any], unparsed: list[int], statistics_target: str | None,
                   error_seqs: list[int], reported_errors: int) -> list[dict[str, str]]:
    """Why a ping answer is not complete: readable causes instead of a silent `complete: false`."""
    warnings = []
    transmitted, received, replies = record["transmitted"], record["received"], record["replies"]
    if unparsed:
        warnings.append(_ping_warning("ping_unparsed_lines", "%d line(s) of the answer were not recognised" % len(unparsed)))
    if record["target"] is None:
        warnings.append(_ping_warning("ping_header_missing", "no PING header line names the target"))
    if transmitted is None:
        warnings.append(_ping_warning("ping_totals_missing", "no statistics totals for the target: the run was "
                                      "interrupted or the output is cut; this is not packet loss"))
        return warnings
    inconsistencies = []
    if statistics_target != record["target"]:
        inconsistencies.append("the statistics name another address than the header")
    if transmitted < 3:
        warnings.append(_ping_warning("ping_packet_count_untested", "the device reports fewer than three requests; "
                                      "the bounded probe may have been interrupted"))
    reply_seqs = {item["seq"] for item in replies}
    seqs = reply_seqs.union(error_seqs)
    if seqs and not (0 <= min(seqs) and max(seqs) < transmitted or
                     1 <= min(seqs) and max(seqs) <= transmitted):
        warnings.append(_ping_warning("ping_sequence_untested", "observed sequence numbers do not fit a zero-based "
                                      "or one-based run of %d requests" % transmitted))
    # Allow either whole-percent rounding convention.
    if (not 0 <= received <= transmitted or not 0 <= record["loss_percent"] <= 100
            or received != len(replies) or len(replies) != len(reply_seqs)
            or any(item["from"] != record["target"] for item in replies)
            or (transmitted and abs(transmitted * record["loss_percent"] - 100 * (transmitted - received)) >= transmitted)):
        inconsistencies.append("the totals (%d transmitted, %d received, %g%% loss) do not match %d listed replies "
                               "from the target" % (transmitted, received, record["loss_percent"], len(replies)))
    if reported_errors != len(error_seqs):
        inconsistencies.append("the reported %d ICMP errors do not match %d listed" % (reported_errors, len(error_seqs)))
    if inconsistencies:
        warnings.append(_ping_warning("ping_totals_inconsistent", ". ".join(inconsistencies)))
    return warnings


_RADIUS_BRANCHES = ("Primary RADIUS", "Secondary RADIUS", "Primary RADIUS Accounting", "Secondary RADIUS Accounting")
_L3_RULE_FIELDS = {"Description", "Type", "Source Address", "Source Port", "Destination Address",
                   "Destination Port", "Protocol"}


def _ruckus_record(identity: int | None = None) -> dict[str, Any]:
    return {"id": identity, "name": None, "settings": {}, "lists": {}}


def _ruckus_object_list(text: str, root: str, *, named: bool) -> dict[str, Any]:
    """Read the Root / ID / <number> tree and the documented substructures of each object."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    headings: list[tuple[tuple[str, ...], str]] = []
    for number, path, key, value in _ruckus_walk(text):
        if value is None:
            headings.append((path, key))
            if path == (root, "ID") and key.isdigit():
                records.append(_ruckus_record(int(key)))
            elif records and len(path) == 3 and path[:2] == (root, "ID") and path[2].isdigit():
                if (root, key) in {("L2/MAC ACL", "Stations"), ("L3/L4/IP ACL", "Rules")}:
                    records[-1]["lists"][key] = []
                elif root == "AAA" and key in _RADIUS_BRANCHES:
                    records[-1]["lists"][key] = {}
                else:
                    unparsed.append(number)
            elif (path, key) not in (((), root), ((root,), "ID")):
                unparsed.append(number)
            continue
        if not records or value == "\0" or path[:2] != (root, "ID") or not 3 <= len(path) <= 4 or not path[2].isdigit():
            unparsed.append(number)
            continue
        record = records[-1]
        if len(path) == 3:
            if root == "DHCP servers for DHCP relay agent" and key == "IP Address":
                addresses = record["settings"].setdefault(key, [])
                if value:
                    addresses.append(value)
            else:
                record["settings"][key] = value
                if key == "Name":
                    record["name"] = _r_text(value)
            continue

        branch = record["lists"].get(path[3])
        if root == "AAA" and isinstance(branch, dict):
            branch[key] = value
        elif root == "L2/MAC ACL" and branch is not None and key == "MAC Address" and value:
            try:
                branch.append(_r_mac(value))
            except ValueError:
                unparsed.append(number)
        elif root == "L3/L4/IP ACL" and branch is not None and key == "Order" and value.isdigit():
            branch.append({key: value})
        elif root == "L3/L4/IP ACL" and branch and key in _L3_RULE_FIELDS and key not in branch[-1]:
            branch[-1][key] = value
        else:
            unparsed.append(number)
    empty_listing = not headings or headings in ([((), root)], [((), root), ((root,), "ID")])
    incomplete_rules = any(not rule.get("Type") for r in records for rule in r["lists"].get("Rules", ()))
    return _result(records, unparsed, count=len(records),
                   incomplete=(not records and not empty_listing) or incomplete_rules
                   or (named and any(not r["name"] for r in records)))


def _ruckus_flat_list(text: str, root: str, first: str, fields: set[str]) -> dict[str, Any]:
    """Management ACLs and routes in the flat Unleashed 200.6 layout, or the later ID tree."""
    items = _ruckus_items(text)
    if len(items) < 2 or items[0][2:] != (root, None) or items[1][3] is None:
        return _ruckus_object_list(text, root, named=False)

    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    for number, _, key, value in items[1:]:
        if value in (None, "\0"):
            unparsed.append(number)
        elif key == first and value and (first != "ID" or value.isdigit()):
            record = _ruckus_record(int(value) if first == "ID" else None)
            records.append(record)
            if first == "Name":
                record["name"] = value
                record["settings"][key] = value
        elif records and key in fields and key not in records[-1]["settings"]:
            records[-1]["settings"][key] = value
            if key == "Name":
                records[-1]["name"] = _r_text(value)
        else:
            unparsed.append(number)

    def complete(record):
        settings = record["settings"]
        if root == "Static Route":
            return all(settings.get(key) for key in fields)
        restriction = {"range": "IP range", "single": "IP address"}.get(settings.get("Restriction Type"))
        return restriction is not None and bool(settings.get(restriction))

    return _result(records, unparsed, count=len(records), incomplete=any(not complete(r) for r in records))


def parse_ruckus_l2acls(text: str) -> dict[str, Any]:
    # The Unleashed CLI guide uses a colon here, while the R610 emits an equals sign.
    text = re.sub(r"(?m)^([ \t]*Restriction)[ \t]*:(?=[ \t]*\S)", r"\1=", text)
    return _ruckus_object_list(text, "L2/MAC ACL", named=True)


def parse_ruckus_mgmt_acls(text: str) -> dict[str, Any]:
    return _ruckus_flat_list(text, "Management ACL", "Name", {"Restriction Type", "IP range", "IP address"})


def parse_ruckus_l3acls(text: str) -> dict[str, Any]:
    return _ruckus_object_list(text, "L3/L4/IP ACL", named=True)


def parse_ruckus_aaa(text: str) -> dict[str, Any]:
    return _ruckus_object_list(text, "AAA", named=True)


def parse_ruckus_dhcp_relays(text: str) -> dict[str, Any]:
    return _ruckus_object_list(text, "DHCP servers for DHCP relay agent", named=False)


def parse_ruckus_static_routes(text: str) -> dict[str, Any]:
    return _ruckus_flat_list(text, "Static Route", "ID", {"Name", "IP subnet", "IP gateway"})


def parse_ruckus_config(text: str) -> dict[str, Any]:
    """wireless network services (RP08): `show config` after the section allowlist: one record per kept section with its settings.

    A settings path is the nested headings and the label joined by ` / `; repeated labels (station lists) are
    collected in order. Withheld sections are counted, not read. The result is `incomplete` when an allowlisted section
    emitted by the R610 is missing, including either of the two complete SNMP Trap blocks.
    """
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    withheld = 0
    for number, path, key, value in _ruckus_walk(text):
        if value is None and not path:
            records.append({"section": key, "settings": {}})
            continue
        if not path and value not in (None, "\0"):
            if not records or records[-1]["section"] != "(global)":
                records.append({"section": "(global)", "settings": {}})
            records[-1]["settings"][key] = value
            continue
        if value == "\0" and key.startswith("[section withheld]"):
            withheld += 1
            continue
        if not records or value is None or value == "\0":
            if value is None and records:
                continue  # nested heading
            unparsed.append(number)
            continue
        name = " / ".join(path[1:] + (key,))
        existing = records[-1]["settings"].get(name)
        records[-1]["settings"][name] = value if existing is None else (
            existing + [value] if isinstance(existing, list) else [existing, value])
    seen = Counter(record["section"] for record in records)
    # The R610 omits the Static Route section when no routes are configured. It prints separate
    # SNMP Trap blocks before and after the SNMPv3 agent even when the agents are disabled.
    missing = [name for name in RUCKUS_CONFIG_SECTIONS
               if name != "Static Route" and seen[name] < (2 if name == "SNMP Trap" else 1)]
    if "SNMP Trap" not in missing and any(
            not all(record["settings"].get(field) for field in ("Format", "Status"))
            for record in records if record["section"] == "SNMP Trap"):
        missing.append("SNMP Trap")
    return _result(records, unparsed, section_count=len(records), withheld_sections=withheld, missing_sections=missing,
                   incomplete=bool(missing))


def ruckus_identity(text: str) -> tuple[str | None, str | None]:
    """(model, version) from `show sysinfo` (`Model= r610`, `Version= <release> build <build>`); None when not printed."""
    found: dict[str, str] = {}
    for _, path, key, value in _ruckus_walk(text):
        if path == ("System Overview",) and key in ("Model", "Version") and value and value != "\0":
            found.setdefault(key, " ".join(value.split()))
    return found.get("Model"), found.get("Version")


RUCKUS_PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "clients": parse_ruckus_clients,
    "client_detail": parse_ruckus_clients,
    "access_points": _ruckus_ap_inventory,
    "access_point": parse_ruckus_access_points,
    "access_point_by_name": parse_ruckus_access_points,
    "wlans": parse_ruckus_wlans,
    "wlan": parse_ruckus_wlans,
    "radio_performance_24": parse_ruckus_performance,
    "radio_performance_5": parse_ruckus_performance,
    "client_performance": parse_ruckus_performance,
    "rogue_devices": parse_ruckus_rogues,
    "events": parse_ruckus_events,
    "events_activities": parse_ruckus_events,
    "mesh_topology": parse_ruckus_mesh,
    "ping": parse_ruckus_ping,
    "ethernet_info": parse_ruckus_ethinfo,
    "l2_acls": parse_ruckus_l2acls,
    "mgmt_acls": parse_ruckus_mgmt_acls,
    "l3_acls": parse_ruckus_l3acls,
    "aaa_servers": parse_ruckus_aaa,
    "dhcp_relays": parse_ruckus_dhcp_relays,
    "static_routes": parse_ruckus_static_routes,
    "config_settings": parse_ruckus_config,
}


def summarize_ruckus(query: str, text: str) -> dict[str, Any]:
    return RUCKUS_PARSERS[query](text)


# Catalyst 9800 operational reads (wireless controller).
_XE_MAC = _c9800.MAC
_XE_SEPARATOR = re.compile(r"-+(?:\s+-+)*")
_XE_AP_EXTENDED_HEADER = (
    r"AP Name\s+Slots\s+AP Model\s+Ethernet MAC\s+Radio MAC\s+Location\s+Country\s+IP Address\s+State"
)
_XE_AP_EXTENDED_ROW = (
    rf"(?P<name>\S+)\s+(?P<slots>\d+)\s+(?P<model>\S+)\s+(?P<ethernet_mac>{_XE_MAC})\s+"
    rf"(?P<radio_mac>{_XE_MAC})\s+(?P<location>.+?)\s+(?P<country>\S+)\s+(?P<ip>\S+)\s+"
    r"(?P<state>Not Registered|\S+)"
)
_XE_AP_JOIN_HEADER = r"Base MAC\s+Ethernet MAC\s+AP Name\s+IP Address\s+Status\s+Last Failure Phase\s+Last Disconnect Reason"
_XE_AP_JOIN_SPLIT = (
    r"Base MAC\s+Ethernet MAC\s+AP Name\s+IP Address\s+Status\s+Last\s+Last",
    r"Failure Phase\s+Disconnect Reason",
)
_XE_AP_JOIN_MAC = rf"(?:{_XE_MAC}|[0-9a-f]{{4}}\.xxxx\.xxxx)"
_XE_TABLES = {
    "c9800_aps": (
        r"AP Name\s+(?:Slots\s+)?AP Model\s+Ethernet MAC\s+Radio MAC\s+State(?:\s+IP Address\s+Location)?",
        rf"(?P<name>\S+)\s+(?:(?P<slots>\d+)\s+)?(?P<model>\S+)\s+(?P<ethernet_mac>{_XE_MAC})\s+"
        rf"(?P<radio_mac>{_XE_MAC})\s+(?P<state>Not Registered|\S+)(?:\s+(?P<ip>\S+)(?:\s+(?P<location>.+))?)?",
        r"Number of APs:\s*(\d+)", r"Global AP (?:Dot1x )?User Name:\s*.*",
    ),
    "c9800_ap_joins": (
        _XE_AP_JOIN_HEADER,
        rf"(?P<radio_mac>{_XE_AP_JOIN_MAC})\s+(?P<ethernet_mac>{_XE_AP_JOIN_MAC})\s+"
        r"(?P<name>\S+)\s+(?P<ip>\S+)\s+(?P<state>Not Joined|Joined)\s+"
        r"(?P<last_failure_phase>\S+)\s+(?P<last_disconnect_reason>.+)",
        r"Number of APs:\s*(\d+)", None,
    ),
    "c9800_radio_24": (
        r"AP Name\s+Mac Address\s+Slot\s+Admin State\s+Oper State\s+Width\s+Txpwr\s+Channel",
        rf"(?P<ap_name>\S+)\s+(?P<mac>{_XE_MAC})\s+(?P<slot>\d+)\s+(?P<admin_state>\S+)\s+"
        r"(?P<oper_state>\S+)\s+(?P<width>\d+|N/A|NA)\s+(?P<tx_power>\S+(?:\s+\(\d+ dBm\))?)\s+"
        r"(?P<channel>\([\d, ]+\)\*?|\((?:Sensor|Monitor)\)|N/A|NA|\d+\*?)",
        None, None,
    ),
    "c9800_radio_5": (
        r"AP Name\s+MAC Address\s+Admin State\s+Operation State\s+Channel\s+TxPower",
        rf"(?P<ap_name>\S+)\s+(?P<mac>{_XE_MAC})\s+(?P<admin_state>\S+)\s+(?P<oper_state>\S+)\s+"
        r"(?P<channel>\d+\*?)\s+(?P<tx_power>\d+\([ *]\))",
        None, None,
    ),
    "c9800_wlans": (
        r"WLAN\s+Profile Name\s+SSID(?:\s+VLAN)?\s+Status",
        r"(?P<wlan_id>\d+)\s+(?P<profile>\S+)\s+(?P<ssid>.+?)(?:\s+(?P<vlan_id>\d+))?\s+(?P<status>UP|DOWN)",
        r"Number of WLANs:\s*(\d+)", None,
    ),
    "c9800_ap_tags": (
        r"AP Name\s+AP Mac\s+Site Tag Name\s+Policy Tag Name\s+RF Tag Name\s+Misconfigured\s+Tag Source",
        rf"(?P<ap_name>\S+)\s+(?P<mac>{_XE_MAC})\s+(?P<site_tag>\S+)\s+(?P<policy_tag>\S+)\s+"
        r"(?P<rf_tag>\S+)\s+(?P<misconfigured>Yes|No)\s+(?P<source>\S+)",
        r"Number of APs:\s*(\d+)", None,
    ),
    "c9800_policy_profiles": (
        r"Policy Profile Name\s+Description\s+Status",
        None, r"Number of Policy Profiles:\s*(\d+)", None,
    ),
    "c9800_exclusions": (
        r" *(?P<mac>MAC Address) +(?P<description>Description) +(?P<reason>Exclusion Reason) +(?P<time>Time Remaining)",
        None, None, r" *Excluded Clients",
    ),
    "c9800_rogue_aps": (
        r"MAC Address\s+Classification\s+State\s+#APs\s+#Clients\s+Last Heard\s+Highest-RSSI-Det-AP\s+RSSI\s+Channel\s+Ch\.Width\s+GHz",
        rf"(?P<mac>{_XE_MAC})\s+(?P<classification>\S+)\s+(?P<state>.+?)\s+(?P<ap_count>\d+)\s+"
        rf"(?P<client_count>\d+)\s+(?P<last_heard>\S+\s+\S+)\s+(?P<detector_mac>{_XE_MAC})\s+"
        r"(?P<rssi>-?\d+)\s+(?P<channel>\d+)\s+(?P<width>\d+)\s+(?P<band>2\.4|5|6)",
        r"Total Number of Rogue APs\s*:\s*(\d+)",
        r"(?:Rogue (?:Location Discovery Protocol|Security Level|on wire Auto-Contain|using our SSID Auto-Contain|AP timeout|init timer)"
        r"|Validate rogue APs against AAA|Valid client on rogue AP Auto-Contain)\s*:\s*.+",
    ),
    "c9800_chassis_rmi": (
        r"Chassis#\s+Role\s+Mac Address\s+Priority\s+Version\s+State\s+IP\s+RMI-IP",
        rf"(?P<local>\*?)(?P<slot>\d+)\s+(?P<role>Active|Standby)\s+(?P<mac>{_XE_MAC})\s+"
        r"(?P<priority>\d+)\s+(?P<hardware_version>\S+)\s+(?P<state>\S+)\s+(?P<ip>\S+)\s+(?P<rmi_ip>\S+)",
        None, rf"Chassis/Stack Mac Address\s*:\s*{_XE_MAC} - Local Mac Address|Mac persistency wait time:\s*\S+|H/W\s+Current",
    ),
}


def _c9800_policy_profile_row(line):
    fields = line.rsplit(maxsplit=1)
    if len(fields) != 2 or not re.fullmatch(r"ENABLED|DISABLED", fields[1], re.I):
        return None
    name_and_description, status = fields
    profile, *description = name_and_description.split(maxsplit=1)
    result = {"profile": profile, "status": status}
    if description:
        result["description"] = description[0]
    return result


def _c9800_exclusion_row(line, columns):
    mac_start, description_start, reason_start, time_start = columns
    if (len(line) <= time_start or "\t" in line or line[:mac_start].strip(" ")
            or any(line[start - 1] != " " for start in columns[1:])):
        return None
    mac = line[mac_start:description_start].rstrip(" ")
    description = line[description_start:reason_start].rstrip(" ")
    reason = line[reason_start:time_start].rstrip(" ")
    remaining = line[time_start:].lstrip(" ")
    if (not re.fullmatch(_XE_MAC, mac, re.I) or description.startswith(" ")
            or not reason or reason.startswith(" ") or not re.fullmatch(r"[0-9]+", remaining)):
        return None
    return {"mac": mac, "description": description, "reason": reason, "remaining_seconds": remaining}


def _c9800_rows(query, lines):
    header, row, count, preamble = _XE_TABLES[query]
    if query == "c9800_radio_5" and any("Oper State" in line for line in lines):
        header, row, _, _ = _XE_TABLES["c9800_radio_24"]
    elif query == "c9800_radio_24" and any("Operation State" in line for line in lines):
        header, row, _, _ = _XE_TABLES["c9800_radio_5"]
    declared = None
    index = 0
    while index < len(lines):
        match = re.fullmatch(count, lines[index]) if count else None
        if match and declared is None:
            declared = int(match[1])
        elif not (preamble and re.fullmatch(preamble, lines[index], re.I)):
            break
        index += 1
    if declared == 0 and index == len(lines):
        return [], True, declared
    if index < len(lines) and query == "c9800_aps" and re.fullmatch(_XE_AP_EXTENDED_HEADER, lines[index], re.I):
        header, row = _XE_AP_EXTENDED_HEADER, _XE_AP_EXTENDED_ROW
    if (query == "c9800_ap_joins" and index + 1 < len(lines)
            and all(re.fullmatch(heading, line) for heading, line in zip(_XE_AP_JOIN_SPLIT, lines[index:index + 2]))):
        header = _XE_AP_JOIN_SPLIT[1]
        index += 1
    if index + 1 >= len(lines):
        return [], False, declared
    heading = re.fullmatch(header, lines[index], re.I)
    if not heading or not _XE_SEPARATOR.fullmatch(lines[index + 1].strip()):
        return [], False, declared
    if query == "c9800_wlans" and " VLAN " not in lines[index]:
        row = row.replace(r"(?:\s+(?P<vlan_id>\d+))?", "")
    columns = (tuple(heading.start(name) for name in ("mac", "description", "reason", "time"))
               if query == "c9800_exclusions" else ())
    records = []
    missing_mac = False
    for line in lines[index + 2:]:
        if columns:
            row_fields = _c9800_exclusion_row(line, columns)
        elif query == "c9800_policy_profiles":
            row_fields = _c9800_policy_profile_row(line)
        else:
            match = re.fullmatch(row, line, re.I)
            row_fields = match.groupdict() if match else None
        if row_fields is None:
            continue
        fields = {name: value for name, value in row_fields.items() if value is not None}
        for field, value in fields.items():
            if field == "mac" or field.endswith("_mac"):
                if not re.fullmatch(_XE_MAC, value, re.I):
                    fields[field] = None
                    missing_mac = True
                else:
                    fields[field] = _c9800.colon_mac(value)
            elif field in {"slots", "slot", "priority", "wlan_id", "vlan_id", "remaining_seconds",
                           "ap_count", "client_count", "rssi"}:
                fields[field] = int(value)
            elif field == "local":
                fields[field] = bool(value)
        records.append(fields)
    complete = (not missing_mac and len(records) == len(lines) - index - 2
                and (count is None or declared == len(records)))
    return records, complete, declared


def _c9800_client_detail(lines):
    fields = {
        "Client MAC Address": "mac", "Client IPv4 Address": "ip", "AP MAC Address": "ap_mac",
        "AP Name": "ap_name", "AP slot": "slot", "Client State": "state", "Policy Profile": "policy_profile",
        "Wireless LAN Id": "wlan_id", "Wireless LAN Name": "wlan", "Wireless LAN Network Name (SSID)": "ssid",
        "Authentication Algorithm": "authentication", "Authentication Method": "authentication_method",
        "WLAN Profile Name": "wlan", "Authentication Key Management": "key_management",
        "FlexConnect Data Switching": "data_switching", "Authorized": "authorized",
        "VLAN": "vlan", "RSSI": "rssi", "Radio Signal Strength Indicator": "rssi",
        "Channel": "channel", "Protocol": "protocol",
    }
    record = {}
    duplicates = set()
    policies = None
    for line in lines:
        if line in {"Local Policies:", "Server Policies:", "Resultant Policies:"}:
            policies = line
            continue
        if line == "Client Statistics:":
            policies = None
            continue
        label, separator, value = line.partition(":")
        key = fields.get(label.strip()) if separator else None
        if not key or not value.strip() or (key == "vlan" and policies in {"Local Policies:", "Server Policies:"}):
            continue
        value = value.strip()
        if key in {"mac", "ap_mac"}:
            if not re.fullmatch(_XE_MAC, value, re.I):
                continue
            value = _c9800.colon_mac(value)
        elif key in {"wlan_id", "slot", "rssi"}:
            match = re.fullmatch(r"(-?\d+)(?: dBm)?" if key == "rssi" else r"(\d+)", value)
            if not match:
                continue
            value = int(match[1])
        if key in record and record[key] != value:
            duplicates.add(key)
        record[key] = value
    for key in duplicates:
        del record[key]
    required = {"mac", "ap_mac", "ap_name", "state", "authentication", "wlan_id", "vlan", "rssi"}
    # Additional IOS XE detail sections and IPv6 continuation lines are reported verbatim by ssh_read.
    # A recognized client remains useful even when a documented excerpt omits RF or VLAN fields.
    incomplete_line = any(line in {".", "...", "[...]", "[…]"} or line.startswith("%") for line in lines)
    return [record] if "mac" in record else [], required <= record.keys() and not incomplete_line, None


def _c9800_load(lines):
    if (len(lines) < 3 or not re.fullmatch(r"WTP-Mac\s+AP-Name\s+Tot-Slots\s+Tot-Clients(?:\s+Slot\d+)+", lines[0])
            or not re.fullmatch(r"(?:Clients\s+Utilisation\(%\)\s*)+", lines[1])
            or not _XE_SEPARATOR.fullmatch(lines[2])):
        return [], False, None
    slots = [int(slot) for slot in re.findall(r"Slot(\d+)", lines[0])]
    records = []
    for line in lines[3:]:
        parts = line.split()
        if len(parts) != 4 + 2 * len(slots) or not re.fullmatch(_XE_MAC, parts[0], re.I):
            continue
        name, total_slots, total_clients = parts[1:4]
        if not (total_slots.isdecimal() and total_clients.isdecimal()
                and all(value.isdecimal() or value == "NA" for value in parts[4:])):
            continue
        radios = [{"slot": slot, "clients": int(clients), "utilization_percent": int(usage)}
                  for slot, clients, usage in zip(slots, parts[4::2], parts[5::2])
                  if clients.isdecimal() and usage.isdecimal() and 0 <= int(usage) <= 100]
        records.append(dict(mac=_c9800.colon_mac(parts[0]), ap_name=name, total_slots=int(total_slots),
                            total_clients=int(total_clients), radios=radios))
    complete = len(records) == len(lines) - 3 and all(
        row["total_slots"] == len(row["radios"]) and row["total_clients"] == sum(r["clients"] for r in row["radios"])
        for row in records)
    return records, complete, None


_C9800_PSK_COUNTER = re.compile(
    r"(?m)^([ \t]*)(Wrong PSK|EasyPSK PSK mismatch error|PSK failure|PSK mode failure)([ \t]*:[ \t]*[0-9]+[ \t]*\r?)$"
)


def c9800_preserve_numeric_counters(output):
    """Keep these documented numeric counter labels distinct from any credential fields."""
    return _C9800_PSK_COUNTER.sub(lambda match: match[1] + match[2].replace(" ", "_") + match[3], output)


def _c9800_counters(query, lines):
    details = query == "c9800_client_stats"
    heading = r"Total Number of Clients\s*:\s*(\d+)" if details else r"Total client delete reasons"
    match = re.fullmatch(heading, lines[0], re.I) if lines else None
    if match is None:
        return [], False, None
    total = int(match[1]) if details else None
    records = []
    section = None
    unknown = False
    for line in lines[1:]:
        if _XE_SEPARATOR.fullmatch(line) or re.fullmatch(r"Protocol\s+Client Count", line):
            continue
        if not details and line == "PC Analytics stats:":
            section = None
            continue
        if line in {"Protocol Statistics", "Controller deletes", "AP Deletes", "Informational Delete Reason",
                    "Client initiate delete"} or (not details and re.fullmatch(r"Report Type\s+(?:Processed|Dropped) Reports", line)):
            section = line
            continue
        name, _, count = line.partition(":")
        count = count.strip()
        if not name or not count.isdecimal() or section is None:
            unknown = True
            continue
        records.append(dict(section=section, name=name.rstrip(), count=int(count)))
    if details:
        complete = bool(records) and total == sum(row["count"] for row in records if row["section"] == "Protocol Statistics")
    else:
        complete = {"Controller deletes", "AP Deletes"} <= {row["section"] for row in records}
    return records, complete and not unknown, total


def _c9800_redundancy(lines):
    system, active, peer = {}, {}, {}
    sections = {"Redundant System Information :": system, "Current Processor Information :": active,
                "Peer Processor Information :": peer}
    destination = None
    for line in lines:
        if line in sections:
            destination = sections[line]
        elif destination is not None and " = " in line:
            key, value = line.split(" = ", 1)
            destination[key.strip()] = value.strip()
    if not system:
        return [], False, None
    mode = {key: system.get(label) for key, label in (
        ("hardware_mode", "Hardware Mode"), ("configured_mode", "Configured Redundancy Mode"),
        ("operating_mode", "Operating Redundancy Mode"), ("communications", "Communications"))}
    processors = []
    for role, values, location in (("active", active, "Active Location"), ("standby", peer, "Standby Location")):
        slot = re.fullmatch(r"slot (\d+)", values.get(location, ""))
        image = re.search(r", Version ([^, ]+)", values.get("Image Version", ""))
        if slot and image and values.get("Current Software state"):
            processors.append(dict(role=role, slot=int(slot[1]), version=image[1], state=values["Current Software state"]))
    return [{**mode, "processors": processors}], all(mode.values()) and len(processors) == 2, None


def _c9800_tag_detail(lines):
    tags = {}
    bindings = []
    section = None
    unknown = False
    for line in lines:
        if _XE_SEPARATOR.fullmatch(line):
            continue
        if line in {"Policy tag mapping", "Site tag mapping", "RF tag mapping"}:
            section = line
            continue
        if (re.fullmatch(r"Tag Type\s+Tag Name", line) or
                re.fullmatch(r"WLAN Profile Name\s+Policy Name\s+VLAN\s+Central Switching\s+IPv4 ACL\s+IPv6 ACL", line)):
            continue
        identity = re.fullmatch(r"(AP Name|AP Mac)\s*:\s*(\S+)", line)
        tag = re.fullmatch(r"(Policy Tag|RF Tag|Site Tag)\s+(\S+)", line)
        if identity:
            tags[identity[1]] = identity[2]
        elif tag and section is None:
            tags[tag[1]] = tag[2]
        elif section == "Policy tag mapping":
            mapping = re.fullmatch(r"(\S+)\s+(\S+)\s+(\S+)\s+(ENABLED|DISABLED)\s+"
                                   r"(Not Configured|\S+)\s+(Not Configured|\S+)", line)
            if mapping:
                wlan, profile, vlan, switching, _, _ = mapping.groups()
                bindings.append(dict(wlan=wlan, policy_profile=profile, vlan=vlan,
                                     central_switching=switching == "ENABLED"))
            else:
                unknown = True
        elif section in {"Site tag mapping", "RF tag mapping"} and ":" in line:
            label, _, value = line.partition(":")
            tags[label.strip()] = value.strip()
        else:
            unknown = True
    if "AP Name" not in tags or not re.fullmatch(_XE_MAC, tags.get("AP Mac", ""), re.I):
        return [], False, None
    record = {"name": tags.pop("AP Name"), "mac": _c9800.colon_mac(tags.pop("AP Mac")),
              "tags": tags, "bindings": bindings}
    complete = {"Policy Tag", "Site Tag", "RF Tag"} <= tags.keys() and section == "RF tag mapping"
    return [record], complete and not unknown, None


def summarize_c9800(query, output, *, status="ok"):
    """Normalize the supported displays without treating unrecognized output as an empty inventory."""
    if query == "c9800_exclusions":
        # Preserve horizontal offsets so malformed rows cannot merge the two text columns.
        lines = [line.rstrip(" ") for line in output.splitlines() if line.strip()]
    else:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
    if query == "c9800_clients":
        count, rows, complete = _c9800.client_summary(output)
    elif query in _XE_TABLES:
        rows, complete, count = _c9800_rows(query, lines)
    elif query == "c9800_client_detail":
        rows, complete, count = _c9800_client_detail(lines)
    elif query == "c9800_ap_tag_detail":
        rows, complete, count = _c9800_tag_detail(lines)
    elif query == "c9800_ap_load":
        rows, complete, count = _c9800_load(lines)
    elif query in {"c9800_client_stats", "c9800_client_deletes"}:
        rows, complete, count = _c9800_counters(query, lines)
    else:
        rows, complete, count = _c9800_redundancy(lines)
    complete = bool(complete and status == "ok" and not _c9800.PAGER.search(output))
    return {"records": rows, "reported_count": count, "complete": complete,
            "status": "ok" if complete else "incomplete"}


def c9800_ap(client, aps):
    """Use the controller AP name and cross-check the radio MAC whenever the client detail reports it."""
    matches = [ap for ap in aps if ap["name"] == client.get("ap_name")
               and (client.get("ap_mac") is None or ap["radio_mac"] == client["ap_mac"])]
    return matches[0] if len(matches) == 1 else None
