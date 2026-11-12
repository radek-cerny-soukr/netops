"""Normalised records for the FortiOS wireless-controller reads measured on FortiGate-80F 8.0.2 build0251.

Every parser returns {"records": [...], "unparsed": [line numbers]}: a line the parser does not
recognise is reported, never guessed. Device text is untrusted data; values are only matched and
converted, never evaluated.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable

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
