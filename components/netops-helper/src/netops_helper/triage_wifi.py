"""wifi_triage: one Wi-Fi client followed through the controller reads a read-only FortiOS account can make.

Qualified only for the FortiGate-80F 8.0.2 build0251 measurement behind wifi_parse. The verdict is
`fault_found` for a fault-level finding; RF is reported separately as incomplete, a concern or
no_rf_fault_found. The switch port behind the AP remains unverified; there is no healthy verdict.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

from . import wifi_parse
from .triage_health import REASONS, UnsupportedPlatform, _lines, _utc, missing_read

IDENTITIES = frozenset({("FortiGate-80F", "8.0.2", "0251")})
EVENT_LINES = 200
HISTORY_LIMIT = 20
MAX_RESULT_BYTES = 48_000
PLANNED_READS = 7
# `missing` keeps a stable machine `reason` and explains it in `detail`
RSSI_UNAVAILABLE = "rest_token_not_enrolled"
RSSI_DETAIL = ("live client RSSI and SNR come only from a read-only REST token; enroll one for this target "
               "(the SSH reads of a read-only account do not list them)")
LOCATE_NOT_CORRELATED = "not_correlated"
LOCATE_DETAIL = "this triage does not follow the client to its switch port; use locate_endpoint with the client MAC"
WIFI_REASONS = REASONS | {"not_in_window", "ip_not_in_arp", "ambiguous", "not_listed", "dependency_missing",
                          RSSI_UNAVAILABLE, LOCATE_NOT_CORRELATED}
# Helper heuristics, not vendor limits; every finding built on one says so in its fact text.
BUSY_PERCENT = 70
RETRY_PERCENT = 20
INTERFERING_APS = 5
STRONG_NEIGHBOR_DBM = -60
_MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
_ARP_ROW = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}) +(\S+) +([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}) +(\S+)")


def valid_mac(value: object) -> bool:
    return isinstance(value, str) and _MAC.fullmatch(value) is not None


def valid_ip(value: object) -> bool:
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def identity(text: str) -> dict[str, str]:
    from netops_core import platforms
    try:
        found = tuple(platforms.version_record(text))
    except platforms.VersionRecordError:
        raise UnsupportedPlatform("config_platform_not_supported: one exact FortiOS identity is required") from None
    if found not in IDENTITIES:
        raise UnsupportedPlatform("config_platform_not_supported: wifi_triage is qualified only for the measured model and build")
    return {"product": found[0], "version": found[1], "build": found[2]}


def arp_rows(text: str) -> list[dict[str, str]] | None:
    rows = []
    header = 0
    for line in _lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if re.fullmatch(r"Address +Age\(min\) +Hardware Addr +Interface", stripped):
            header += 1
            continue
        row = _ARP_ROW.fullmatch(stripped)
        if row is None or not header:
            return None
        rows.append({"address": row.group(1), "mac": row.group(3).lower(), "interface": row.group(4)})
    return rows if header == 1 else None


def _source(query: str, answer: dict[str, Any], moment: Any) -> dict[str, str]:
    return {"call": "wifi_triage", "query": query, "content_sha256": answer["content_sha256"],
            "captured_at": _utc(moment)}


def _event_order(record: dict[str, Any]) -> tuple[datetime, int]:
    moment = datetime.fromisoformat(record["time"])
    if moment.utcoffset() is None:
        raise ValueError("event time has no UTC offset")
    return moment.astimezone(timezone.utc), -record["index"]


def significant_history(events: list[dict[str, Any]], window: dict | None) -> dict[str, Any]:
    """Select diagnostic events from the retained window, never a newest-N slice."""
    chronological = list(reversed(events))
    transitions = {}
    previous = None
    for event in chronological:
        if event["class"] in ("client_connect", "client_roam") and event.get("ap"):
            if previous and previous["ap"] != event["ap"]:
                transitions[event["index"]] = {
                    "from_ap": previous["ap"], "to_ap": event["ap"],
                    "from_band": previous.get("band"), "to_band": event.get("band"),
                    "time": event["time"], "basis": "consecutive logged connections; AP change observed"}
            previous = {**event, "band": event.get("band") or (
                previous.get("band") if previous and previous["ap"] == event["ap"] else None)}
    latest_connection = next((e for e in events if e["class"] == "client_connect"), None)
    latest_dhcp = next((e for e in events if e["class"] == "client_dhcp"), None)
    failures = [e for e in events if e.get("authentication_failure")]
    selected = []
    for event in chronological:
        if (event["class"] in ("client_error", "client_disconnect", "client_roam")
                or event is latest_connection or event is latest_dhcp or event["index"] in transitions):
            selected.append({**event, **({"ap_change": transitions[event["index"]]} if event["index"] in transitions else {})})
    note = ("authentication failure found in retained history of this MAC" if failures else
            "no authentication failure in retained history of this MAC")
    if window is None:
        note = "authentication history unavailable for this MAC"
    elif not window.get("complete"):
        note += "; history window is bounded or incomplete, absence is not proof it never happened"
    groups = []
    fields = ("class", "logdesc", "reason", "status", "action", "ap", "radio", "band", "ap_change")
    for event in selected:
        if groups and not event.get("ap_change") and all(groups[-1].get(k) == event.get(k) for k in fields):
            previous = groups[-1]
            groups[-1] = {**event, "repetitions": previous.get("repetitions", 1) + 1,
                          "first_time": previous.get("first_time", previous["time"])}
        else:
            groups.append(event)
    # Reserve the latest connection/DHCP and one example of each important
    # diagnostic before filling remaining capacity with recent groups.
    required = set()
    for condition in (lambda e: latest_connection is not None and e["index"] == latest_connection["index"],
                      lambda e: latest_dhcp is not None and e["index"] == latest_dhcp["index"],
                      lambda e: e.get("authentication_failure"), lambda e: e.get("ap_change"),
                      lambda e: e["class"] == "client_error", lambda e: e["class"] == "client_disconnect"):
        index = next((i for i in reversed(range(len(groups))) if condition(groups[i])), None)
        if index is not None:
            required.add(index)
    retained = set(required)
    for index in reversed(range(len(groups))):
        if len(retained) >= HISTORY_LIMIT:
            break
        retained.add(index)
    timeline = [compact_event(e) for i, e in enumerate(groups) if i in retained]
    omitted = sum(e.get("repetitions", 1) for i, e in enumerate(groups) if i not in retained)
    return {"timeline": timeline, "timeline_limit": HISTORY_LIMIT,
            "timeline_total": len(selected), "timeline_omitted": omitted,
            "timeline_aggregated": sum(e.get("repetitions", 1) - 1 for i, e in enumerate(groups) if i in retained),
            "authentication_failure_count": len(failures),
            "authentication_failures": [e["index"] for e in failures[:HISTORY_LIMIT]],
            "authentication_failures_omitted": max(0, len(failures) - HISTORY_LIMIT),
            "authentication_note": note,
            "last_connection": compact_event(latest_connection), "last_dhcp": compact_event(latest_dhcp),
            "last_disconnect": compact_event(next((e for e in events if e["class"] == "client_disconnect"), None)),
            "last_ap": next((e["ap"] for e in events if e.get("ap")), None)}


def compact_event(event):
    """Diagnostic facts shared by summary and full; full adds the source hash."""
    if event is None:
        return None
    keys = ("index", "time", "class", "timeline_type", "logdesc", "reason", "status", "action", "ap", "radio",
            "channel", "band", "authentication_failure", "ap_change", "historical", "repetitions", "first_time", "level")
    return {k: event[k] for k in keys if event.get(k) is not None}


_REST_SUBCODES = frozenset({"tls_pin_mismatch", "tls_verification_failed", "http_status", "rate_limited", "timeout",
                            "egress_denied", "transport_or_response_error", "invalid_response"})
_REST_CODES = _REST_SUBCODES | {"unsupported", "tls_error", "authentication_failed", "authorization_failed",
                               "http_server_error", "invalid_json", "response_too_large", "unsupported_encoding",
                               "unparsed_envelope", "configuration", "transport_error"}


def _rest_failure_fields(answer: dict[str, Any]) -> dict[str, Any]:
    fields = {"detail": _rest_failure_detail(answer)}
    if answer.get("error_code") in _REST_CODES:
        fields["error_code"] = answer["error_code"]
    if type(answer.get("http_status")) is int:
        fields["http_status"] = answer["http_status"]
    return fields


def _rest_failure_detail(answer: dict[str, Any]) -> str:
    """Prefer precise fixed codes; never return device or exception text."""
    subcode = answer.get("error_code")
    if subcode not in _REST_CODES:
        subcode = answer.get("error_subcode")
    status = answer.get("http_status")
    if subcode not in _REST_CODES:
        return "REST read failed (%s)" % ("unsupported" if answer.get("error_code") == "unsupported" else "unknown cause")
    return "REST read failed: %s%s" % (subcode, " (HTTP %d)" % status if type(status) is int else "")


def run(read, clock, mac: str | None, ip: str | None, alias: str, live=None, *, name=None, event_read=None, thresholds=None, sample_live=None, enabled_queries=(), neighbor_read=None, pause=time.sleep, monotonic=time.monotonic) -> dict[str, Any]:
    from .wifi_policy import thresholds as checked_thresholds
    from .wifi_rest import checked_filters
    checked_filters(name=name)
    policy = checked_thresholds(thresholds)
    if sum(v is not None for v in (mac, ip, name)) != 1 or (mac is not None and not valid_mac(mac)) or (ip is not None and not valid_ip(ip)):
        raise ValueError("invalid_argument: exactly one of mac (lower-case aa:bb:cc:dd:ee:ff), ip (IPv4) or name (hostname) is required")
    started = clock()
    first = read("system_status", None)
    if not first.get("ok"):
        raise UnsupportedPlatform("config_platform_not_supported: the identity read failed")
    ident = identity(first["text"])
    checked = ["system_status"]
    missing: list[dict[str, Any]] = []
    sources: dict[str, dict[str, str]] = {}
    parsed: dict[str, Any] = {}

    def fetch(query: str, parameters: dict[str, str] | None, step: str | None = None) -> dict[str, Any] | None:
        moment = clock()
        answer = read(query, parameters)
        name = step or query
        if not answer.get("ok"):
            missing.append(missing_read(name, answer))
            return None
        if not answer["text"].strip():
            missing.append({"step": name, "reason": "empty"})
            return None
        sources[query] = _source(query, answer, moment)
        return answer

    def parse(query: str, answer: dict[str, Any] | None) -> list[dict[str, Any]] | None:
        if answer is None:
            return None
        result = wifi_parse.summarize(query, answer["text"])
        if result["unparsed_count"]:
            missing.append({"step": query, "reason": "unparsed"})
            return None
        checked.append(query)
        parsed[query + "_meta"] = {key: value for key, value in result.items() if key not in ("records", "unparsed")}
        return result["records"]

    # 1. the client's MAC (from the IP through the firewall's ARP table when needed)
    client_ip = ip
    client_mac = mac
    arp_interface = None
    if ip is not None:
        answer = fetch("arp_table", None)
        rows = arp_rows(answer["text"]) if answer is not None else None
        if answer is not None and rows is None:
            missing.append({"step": "arp_table", "reason": "unparsed"})
        elif rows is not None:
            checked.append("arp_table")
            found = [row for row in rows if row["address"] == ip and row["mac"] != "00:00:00:00:00:00"]
            macs = sorted({row["mac"] for row in found})
            if len(macs) == 1:
                client_mac = macs[0]
                arp_interface = found[0]["interface"]
            else:
                missing.append({"step": "arp_table", "reason": "ambiguous" if macs else "ip_not_in_arp",
                                "detail": ("the IP maps to several MACs in the ARP table" if macs else
                                           "the IP is not in the firewall ARP table (a client behind another gateway "
                                           "or an aged-out entry is not listed)")})
    live_client = None
    live_answer = None
    initial_answer = None
    initial_client = None
    last_observed_client = None
    sample_started = monotonic()
    client_samples = []
    if live is not None:
        live_answer = live()
        initial_answer = live_answer
        if live_answer.get("identity_missing"):
            missing.append(dict(live_answer["identity_missing"]))
        if live_answer.get("ok"):
            candidates = [row for row in live_answer["records"]
                          if (row.get("mac") == mac if mac is not None else row.get("ip") == ip if ip is not None
                              else row.get("hostname", "unknown") != "unknown" and row.get("hostname", "").casefold() == name.casefold())]
            if len(candidates) > 1:
                missing.append({"step": "client_identity", "reason": "ambiguous", "detail": "hostname matches multiple live clients; use MAC"})
            if len(candidates) == 1:
                live_client = candidates[0]
                initial_client = last_observed_client = live_client
                client_mac = live_client["mac"]
                client_ip = live_client.get("ip") or client_ip
                missing[:] = [item for item in missing if item["step"] != "arp_table"]
                checked.append("wifi_clients_rest")
        if live_client is None:
            item = {"step": "client_rssi", "sample": 1, "reason": "rest_unavailable" if not live_answer.get("ok") else
                    "dependency_missing" if name is not None and live_answer.get("identity_missing") else "not_listed"}
            if name is not None and live_answer.get("identity_missing"):
                item["detail"] = "hostname selection incomplete: device identity read failed; use MAC or restore REST identity permission"
            if not live_answer.get("ok"):
                item.update(_rest_failure_fields(live_answer))
            missing.append(item)
    def retain_sample(answer, selected):
        client_samples.append({"fetched_at": (selected or {}).get("fetched_at", (selected or {}).get("captured_at")) or _utc(clock()),
                               "status": "associated" if selected is not None else "not_associated" if answer.get("ok") else "unavailable",
                               **{key: (selected or {}).get(key) for key in ("ap_serial", "ap_id", "radio", "band", "channel", "rssi_dbm", "snr_db")},
                               "sources": answer.get("sources", [])})
        if not answer.get("ok"):
            client_samples[-1].update(_rest_failure_fields(answer))
        if selected is not None and (selected.get("rssi_dbm") is None or selected.get("snr_db") is None):
            missing.append({"step": "client_rssi", "sample": len(client_samples), "reason": "unparsed",
                            "detail": "REST station lacks RSSI or SNR"})
    if live_answer is not None:
        retain_sample(live_answer, live_client)
    if sample_live is not None and client_mac is not None:
        for _ in range(2):
            # Start successive station reads about three seconds apart; slow reads need no extra wait.
            pause(max(0.0, 3.0 - (monotonic() - sample_started)))
            sample_started = monotonic()
            live_answer = sample_live()
            candidates = [row for row in live_answer.get("records", []) if row.get("mac") == client_mac] if live_answer.get("ok") else []
            live_client = dict(candidates[0]) if len(candidates) == 1 else None
            if live_client is not None:
                # Additional reads carry only current station values. Enrichment
                # is reused once, never old signal values or station timestamps.
                if initial_client:
                    for key in ("hostname", "os", "vendor", "device_type", "identity_sources"):
                        live_client[key] = initial_client.get(key, live_client.get(key))
                    if live_client.get("ap_id") == initial_client.get("ap_id"):
                        for key in ("ap_serial", "ap_name", "ap", "ap_detail"):
                            if key in initial_client:
                                live_client[key] = initial_client[key]
                last_observed_client = live_client
            retain_sample(live_answer, live_client)
            if not live_answer.get("ok"):
                missing.append({"step": "client_rssi", "sample": len(client_samples), "reason": "rest_unavailable", **_rest_failure_fields(live_answer)})
            elif live_client is None:
                missing.append({"step": "client_rssi", "sample": len(client_samples), "reason": "not_listed"})
            if live_client is not None:
                client_ip = live_client.get("ip") or client_ip
    signal_samples = {"requested": 3 if sample_live is not None else 1 if live is not None else 0,
                      "collected": len(client_samples), "samples": client_samples,
                      "interval_seconds": 3 if sample_live is not None else None,
                      "note": "Controller snapshots; source measurement time and averaging interval are unknown."}
    for key in ("rssi_dbm", "snr_db"):
        values = [sample[key] for sample in client_samples if sample[key] is not None]
        signal_samples[key] = {"min": min(values) if values else None, "max": max(values) if values else None,
                               "last": client_samples[-1][key] if client_samples else None}

    # 2. REST selects the station before the 200-record bound; SSH filters its loaded batch locally.
    events = None
    window = None
    last = None
    client_events: list[dict[str, Any]] = []
    rest_history_available = False
    history_source = "wireless_batch_locally_filtered"
    if client_mac is not None:
        records = None
        meta = {}
        if event_read is not None:
            answer = event_read(client_mac)
            if answer.get("ok"):
                rest_history_available = True
                meta = answer["events"]
                records = meta["records"]
                if meta.get("unparsed_count") or meta.get("undated"):
                    missing.append({"step": "wifi_events", "reason": "unparsed", "detail": "log contains skipped or undated records"})
                sources["wifi_events"] = {**answer["sources"][0], "query": "wifi_events", "call": "wifi_triage"}
                checked.append("wifi_events_rest")
                history_source = meta.get("scope", "wireless_batch")
            else:
                missing.append({"step": "wifi_events_rest", "reason": "rest_unavailable", **_rest_failure_fields(answer)})
        if records is None:
            answer = fetch("wifi_events", {"lines": str(EVENT_LINES), "mac_literal": client_mac})
            records = parse("wifi_events", answer)
            meta = parsed.get("wifi_events_meta", {})
        if records is not None:
            events = records
            client_events = [item for item in records if item["client_mac"] == client_mac]
            window = {"requested_lines": meta.get("requested_lines", EVENT_LINES), "device_found": meta.get("found"),
                      "device_returned": meta.get("returned"), "client_records": len(client_events),
                      "undated_records": meta.get("undated", 0),
                      "from": min((item["time"] for item in records), key=lambda t: datetime.fromisoformat(t), default=None),
                      "to": max((item["time"] for item in records), key=lambda t: datetime.fromisoformat(t), default=None),
                      "scanned_records": len(records), "scope": history_source,
                      "filter_mac": meta.get("filter_mac"), "complete": meta.get("complete", False),
                      "unparsed_records": meta.get("unparsed_count", 0)}
            window["text"] = "History %s to %s: %s client events, %s records parsed of %s returned / %s found (%s; %s)." % (
                window["from"], window["to"], len(client_events), len(records), window["device_returned"],
                window["device_found"], history_source, "complete retained history" if window["complete"] else "bounded or incomplete window")
            if client_events:
                try:
                    client_events.sort(key=_event_order, reverse=True)
                    last = client_events[0]
                except (ValueError, TypeError, OverflowError):
                    missing.append({"step": "client_events", "reason": "ambiguous",
                                    "detail": "event times cannot be compared in UTC"})
            else:
                missing.append({"step": "client_events", "reason": "not_in_window",
                                "detail": "no client event in the returned %s history window (%s records)" % (
                                    history_source, meta.get("returned") if meta.get("returned") is not None else EVENT_LINES)})
    else:
        missing.append({"step": "wifi_events", "reason": "dependency_missing", "detail": "client MAC unknown"})

    last_ap_event = next((event for event in client_events if event.get("ap")), None)
    ap_serial = last_ap_event["ap"] if last_ap_event else None
    radio_number = last_ap_event["radio"] if last_ap_event else None
    vap_name = last_ap_event.get("vap") if last_ap_event else None
    broadcast_ssid = last_ap_event.get("ssid") if last_ap_event else None

    context_client = live_client or last_observed_client
    if context_client is not None:
        ap_serial = context_client.get("ap_serial") or context_client.get("ap_id")
        radio_number = context_client.get("radio")
        broadcast_ssid = context_client.get("ssid")
        # A current station's VAP id wins. A log id is usable only for the same
        # AP/radio and SSID; an older association must not select today's VAP.
        vap_name = context_client.get("vap_name") or (
            last_ap_event.get("vap") if last_ap_event and last_ap_event.get("ap") == ap_serial
            and last_ap_event.get("radio") == radio_number and last_ap_event.get("ssid") == broadcast_ssid else None)
    has_ap = last is not None or context_client is not None

    # 3. access point and radio
    ap = radio = None
    aps = None
    if has_ap:
        aps = parse("wifi_ap_status", fetch("wifi_ap_status", None))
    if aps is not None:
        ap = next((item for item in aps if item["serial"] == ap_serial), None)
        if ap is None:
            missing.append({"step": "ap_radio", "reason": "not_listed",
                            "detail": "the selected access point is not in wtp-status"})
        elif radio_number is not None:
            radio = next((item for item in ap["radios"] if item["radio"] == radio_number), None)
            if radio is None or not radio["exists"]:
                missing.append({"step": "ap_radio", "reason": "not_listed",
                                "detail": "radio %s of the access point is not reported" % radio_number})
                radio = None
        else:
            missing.append({"step": "ap_radio", "reason": "dependency_missing",
                            "detail": "the latest event has no radioid; radio and neighbor analysis depend on it"})
    elif has_ap:
        missing.append({"step": "ap_radio", "reason": "dependency_missing", "detail": "wifi_ap_status unavailable"})
    elif client_mac is not None and events is not None:
        missing.append({"step": "ap_radio", "reason": "dependency_missing", "detail": "no client event names an access point"})

    rest_ap = context_client.get("ap_detail") if context_client else None
    rest_ap_source = next((source for source in (initial_answer or {}).get("sources", [])
                           if source.get("endpoint", "").endswith("/managed_ap")), {})
    rest_radio = None
    if rest_ap:
        if ap is not None:
            ap["name"] = rest_ap.get("name") or ap.get("name")
        rest_radio = next((r for r in rest_ap.get("radio", []) if r.get("radio_id") == radio_number), None)
        if ap is None:
            ap = {"serial": rest_ap.get("serial"), "name": rest_ap.get("name"), "ip": rest_ap.get("local_addr"),
                  "state": rest_ap.get("connection_state"), "version": rest_ap.get("os_version"), "join_time": rest_ap.get("join_time"),
                  "join_time_note": None, "lldp": rest_ap.get("lldp"), "last_failure": None, "radios": []}
        if rest_radio:
            radio = {**(radio or {}), "radio": radio_number, "exists": True,
                     "channel": rest_radio.get("oper_chan"), "band": rest_radio.get("band"),
                     "channel_width_mhz": rest_radio.get("channel_width_mhz"),
                     "chutil_percent": rest_radio.get("channel_utilization_percent"),
                     "client_count": rest_radio.get("client_count"), "chutil_interval_seconds": None,
                     "fetched_at": rest_radio.get("fetched_at") or rest_ap_source.get("captured_at"),
                     "tx_retries_percent": rest_radio.get("tx_retries_percent"),
                     "interfering_ap": rest_radio.get("interfering_aps"),
                     "noise_dbm": rest_radio.get("noise_floor") or None,
                     "traffic_state": rest_radio.get("traffic_state"),
                     "measured_at": rest_radio.get("channel_utilization_timestamp"),
                     "dfs": rest_radio.get("dfs")}
            sources["wifi_ap_status"] = {**rest_ap_source, "query": "wifi_ap_status", "call": "wifi_triage"}
            missing[:] = [m for m in missing if m["step"] not in ("wifi_ap_status", "ap_radio")]
    if radio is not None and radio.get("noise_dbm") == 0:
        radio["noise_dbm"] = None

    # 4. virtual access point
    vap = None
    if has_ap:
        vaps = parse("wifi_vap_status", fetch("wifi_vap_status", None))
        if vaps is not None:
            candidates = [item for item in vaps if item["name"] == vap_name] if vap_name else [
                item for item in vaps if broadcast_ssid and item["ssid"] == broadcast_ssid]
            if not vap_name and rest_ap:
                assigned = next((entry.get("list") for entry in rest_ap.get("ssid", [])
                                 if entry.get("radio") == radio_number), None)
                if isinstance(assigned, list):
                    candidates = [item for item in candidates if item["name"] in assigned]
            vap = candidates[0] if len(candidates) == 1 else None
            if vap is None:
                missing.append({"step": "vap", "reason": "ambiguous" if len(candidates) > 1 else "not_listed",
                                "detail": "VAP id or SSID cannot be uniquely matched to vap-status for the selected AP/radio"})

    # 5. RF analysis of that access point and neighbours (controller scan)
    rf = None
    if ap is not None:
        records = parse("wifi_rf_analysis", fetch("wifi_rf_analysis", {"wtp_id": ap["serial"]}))
        if records is not None:
            table = next((item for item in records if item["wtp"] == ap["serial"]), None)
            if table is not None and radio is not None and radio["channel"]:
                rf = next((row for row in table["channels"] if row["channel"] == radio["channel"]), None)
            if rf is None:
                missing.append({"step": "rf_analysis", "reason": "not_listed",
                                "detail": "no RF row for the operating channel of the radio"})
    if rf is None and rest_radio is not None:
        # Background scan rows need not include the operating DFS channel.
        # Use counters of the selected AP/radio, never another AP's scan row.
        rf = {"source": "/api/v2/monitor/wifi/managed_ap", "scope": "operating_radio",
              "ap": ap["serial"], "radio": radio_number, "channel": radio.get("channel"),
              "channel_utilization_percent": radio.get("chutil_percent"),
              "tx_retries_percent": radio.get("tx_retries_percent"),
              "noise_dbm": radio.get("noise_dbm"), "interfering_aps": radio.get("interfering_ap"),
              "measured_at": radio.get("measured_at")}
        for gap in missing:
            if gap["step"] in ("rf_analysis", "wifi_rf_analysis"):
                gap.update(required_for_rf_verdict=False, alternative_source=rf["source"])
    neighbors = None
    if radio is not None and radio["channel"]:
        from .wifi_relevance import relevant, context_status, observation_signal, group_bssid
        contexts = [{"ap_id": ap["serial"], "ap_ids": [v for v in (ap["serial"], ap.get("name")) if v],
                     "radio": radio_number, "band": radio.get("band"), "channel": radio["channel"],
                     "channel_width_mhz": radio.get("channel_width_mhz")}]
        records = parse("wifi_neighbors", fetch("wifi_neighbors", None))
        neighbors = {"scan_entries": len(records) if records is not None else None,
                     "same_channel": sum(item["channel"] == radio["channel"] for item in records or []),
                     "strongest_same_channel_dbm": max((item["signal_dbm"] for item in records or []
                                                        if item["channel"] == radio["channel"]), default=None),
                     "relevant_entries": 0, "strongest_relevant_dbm": None,
                     "relevance_status": "observer_unavailable",
                     "scope": "SSH scan is controller-wide context; REST requires the selected AP observer and band/channel overlap"}
        if neighbor_read is not None:
            answer = neighbor_read()
            if not answer.get("ok"):
                neighbors["relevance_status"] = "context_read_failed"
                missing.append({"step": "wifi_neighbors_rest", "reason": "rest_unavailable", **_rest_failure_fields(answer)})
            else:
                for i, source in enumerate(answer.get("sources", [])):
                    sources["wifi_neighbors_rest_%d" % i] = source
                checked.append("wifi_neighbors_rest")
                rogue = answer["rogue"]
                observations = [(row, "rogue") for row in rogue]
                # Interfering rows have only BSSID and observers; join spectral
                # facts from the matching rogue observation, never invent them.
                observations += [({**row, "detected_by_wtp": item.get("wtps", [])}, "interfering")
                                 for item in answer["interfering"] for row in rogue if row.get("mac") == item.get("mac")]
                scoped = [(row, kind) for row, kind in observations if relevant(row, contexts, require_observer=True)]
                signals = [observation_signal(row, kind, contexts) for row, kind in scoped]
                neighbors.update(relevant_entries=len(group_bssid([row for row, _ in scoped], full=False)), relevance_status=context_status(contexts),
                                 strongest_relevant_dbm=max((v for v in signals if v > -151), default=None))

    # 6. rules
    findings: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    next_steps: list[dict[str, Any]] = []

    def add(rule: str, severity: str, layer: str, obj: str, fact: str, queries: list[str]) -> None:
        basis = [sources[query] for query in queries if query in sources]
        if rule in ("F-WIFI-WEAK-SIGNAL", "F-WIFI-LOW-SNR"):
            basis = [sample["sources"][0] for sample in client_samples if sample["sources"]]
        fetched = next((source.get("fetched_at", source.get("captured_at")) for source in basis), _utc(started))
        timing = "fetched at %s; source measurement time and interval unknown" % fetched
        if rule in ("F-WIFI-WEAK-SIGNAL", "F-WIFI-LOW-SNR") and client_samples:
            timing = "snapshots fetched from %s to %s; source measurement time and interval unknown" % (
                client_samples[0]["fetched_at"], client_samples[-1]["fetched_at"])
        if layer == "radio":
            count = (radio or {}).get("client_count")
            shared = "radio-wide, shared by %s clients, not specific to this client" % (count if count is not None else "unknown number of")
            if rule == "F-WIFI-RADIO-BUSY":
                interval = radio.get("chutil_interval_seconds")
                timing = "fetched at %s; channel utilization measured at %s; averaging interval %s" % (
                    fetched, radio.get("measured_at") or "unknown",
                    "%s seconds" % interval if interval is not None else "unknown")
                if radio.get("chutil_age_s") is not None and not radio.get("measured_at"):
                    timing += "; device reports measurement age %s seconds at fetch" % radio["chutil_age_s"]
            fact += "; " + shared
        findings.append({"id": rule, "severity": severity, "layer": layer, "object": obj, "fact": fact,
                         "text": "%s; %s; source %s. First step: %s." % (
                             fact, timing, ", ".join(source.get("endpoint", source.get("query", "unknown")) for source in basis) or "unknown",
                             "check distance and obstacles, compare another sample" if layer == "client" else
                             "compare another sample and check traffic on this AP/radio"),
                         "sources": basis})

    mac_object = "client:" + (client_mac or "unknown")
    rssi, snr = signal_samples["rssi_dbm"]["min"], signal_samples["snr_db"]["min"]
    last_rssi = signal_samples["rssi_dbm"]["last"]
    if rssi is not None and rssi < policy["weak_signal_dbm"]:
        severe = (rssi < policy["very_weak_signal_dbm"] and last_rssi is not None
                  and last_rssi < policy["very_weak_signal_dbm"])
        state = ("last snapshot unavailable or client absent" if last_rssi is None else
                 "weak at last snapshot" if last_rssi < policy["weak_signal_dbm"] else
                 "transient weakness; last snapshot recovered")
        add("F-WIFI-WEAK-SIGNAL", "fault" if severe else "warning", "client", mac_object,
            "Weak RSSI minimum %s dBm, last %s dBm across %d snapshots, threshold < %s dBm (operational heuristic); %s" % (
                rssi, last_rssi, len(client_samples),
                policy["very_weak_signal_dbm"] if severe else policy["weak_signal_dbm"], state), ["wifi_clients_rest"])
        findings[-1]["fault_level"] = severe
    if snr is not None and snr < policy["low_snr_db"]:
        add("F-WIFI-LOW-SNR", "warning", "client", mac_object,
            "Low SNR minimum %s dB, last %s dB across %d snapshots, threshold < %s dB (operational heuristic)" % (
                snr, signal_samples["snr_db"]["last"], len(client_samples), policy["low_snr_db"]), ["wifi_clients_rest"])
    if last is not None:
        stamp = "%s at %s%s" % (last["logdesc"], last["time"],
                                 (", reason " + last["reason"]) if last["reason"] else "")
        if last["class"] == "client_error":
            recovered = (last_observed_client is not None and last_observed_client.get("authentication") == "pass"
                         and last_observed_client.get("association_time") is not None
                         and datetime.fromisoformat(last["time"]) < datetime.fromisoformat(last_observed_client["association_time"]))
            add("F-WIFI-CLIENT-ERROR", "notice" if recovered else "fault", "client", mac_object,
                ("historical error, client connected at last observed association: " if recovered else "latest wireless event of the client: ") + stamp,
                ["wifi_events"])
            findings[-1]["historical"] = recovered
        elif last["class"] == "client_disconnect":
            add("F-WIFI-CLIENT-DISCONNECTED", "notice", "client", mac_object,
                "latest wireless event of the client is a disconnect: " + stamp, ["wifi_events"])
        later_errors = [item for item in client_events[1:] if item["class"] == "client_error"]
        if later_errors and last["class"] != "client_error":
            hypotheses.append({"id": "H-WIFI-EARLIER-ERROR", "basis": [sources["wifi_events"]],
                               "text": "an earlier client error event exists (%s at %s)" % (
                                   later_errors[0]["logdesc"], later_errors[0]["time"])})
    if last_observed_client is not None and last_observed_client.get("authentication") == "pass" and last_observed_client.get("association_time"):
        associated_at = datetime.fromisoformat(last_observed_client["association_time"])
        historical = [event for event in client_events if event["class"] == "client_error"
                      and datetime.fromisoformat(event["time"]) < associated_at]
        for event in historical:
            event["historical"] = True
        if historical and (last is None or last["class"] != "client_error"):
            add("F-WIFI-CLIENT-ERROR", "notice", "client", mac_object,
                "historical error, client connected at last observed association: %s at %s" % (historical[0]["logdesc"], historical[0]["time"]), ["wifi_events"])
            findings[-1]["historical"] = True
    if ap is not None:
        if ap["state"] is None:
            missing.append({"step": "ap_radio", "reason": "unparsed", "detail": "connection-state missing"})
        elif ap["state"] != "Connected":
            add("F-WIFI-AP-NOT-CONNECTED", "fault", "access_point", "ap:" + ap["serial"],
                "connection-state: %s" % ap["state"], ["wifi_ap_status"])
        if ap["last_failure"]:
            hypotheses.append({"id": "H-WIFI-AP-LAST-FAILURE", "basis": [sources["wifi_ap_status"]],
                               "text": "the access point reports last-failure %r" % ap["last_failure"]})
    if radio is not None:
        obj = "radio:%s/%d" % (ap["serial"], radio["radio"])
        if radio["channel"] is None:
            missing.append({"step": "ap_radio", "reason": "unparsed", "detail": "oper-chan missing"})
        elif radio["channel"] == 0:
            add("F-WIFI-RADIO-NOT-OPERATING", "fault", "radio", obj, "oper-chan: 0", ["wifi_ap_status"])
        elif last is not None and last["ap"] == ap_serial and last["channel"] is not None and last["channel"] != radio["channel"]:
            hypotheses.append({"id": "H-WIFI-CHANNEL-CHANGED", "basis": [sources["wifi_ap_status"], sources["wifi_events"]],
                               "text": "the client event was on channel %d, the radio now operates on channel %d "
                                       "(an automatic channel change or a different radio)" % (last["channel"], radio["channel"])})
        if radio["chutil_percent"] is not None and radio["chutil_percent"] >= policy["busy_percent"]:
            add("F-WIFI-RADIO-BUSY", "notice", "radio", obj,
                "channel utilisation %d%% (Helper threshold %d%%)" % (radio["chutil_percent"], policy["busy_percent"]),
                ["wifi_ap_status"])
        if radio["tx_retries_percent"] is not None and radio["tx_retries_percent"] >= policy["retry_percent"]:
            add("F-WIFI-RADIO-RETRIES", "notice", "radio", obj,
                "tx-retries %d%% (Helper threshold %d%%)" % (radio["tx_retries_percent"], policy["retry_percent"]),
                ["wifi_ap_status"])
        if radio["interfering_ap"] is not None and radio["interfering_ap"] >= policy["interfering_aps"]:
            add("F-WIFI-RADIO-INTERFERENCE", "notice", "radio", obj,
                "interfering-ap %d (Helper threshold %d)" % (radio["interfering_ap"], policy["interfering_aps"]),
                ["wifi_ap_status"])
    if vap is not None:
        if vap["state"] is None:
            missing.append({"step": "vap", "reason": "unparsed", "detail": "downup_oper missing"})
        elif vap["state"] != "up":
            add("F-WIFI-VAP-DOWN", "fault", "vap", "vap:" + vap["name"], "downup_oper: %s" % vap["state"], ["wifi_vap_status"])
    if neighbors and neighbors["strongest_relevant_dbm"] is not None \
            and neighbors["strongest_relevant_dbm"] >= policy["strong_neighbor_dbm"]:
        add("F-WIFI-STRONG-COCHANNEL-NEIGHBOR", "notice", "rf", "channel:%d" % radio["channel"],
            "a neighbor heard by this AP with relevant band/channel overlap has signal %d dBm (Helper threshold %d dBm)"
            % (neighbors["strongest_relevant_dbm"], policy["strong_neighbor_dbm"]), [key for key in sources if key.startswith("wifi_neighbors_rest_")])
    if ap is not None:
        next_steps.append({"tool": "ssh_read", "arguments": {"target": alias, "platform": "fortinet", "query": "wifi_ap_status",
                                                              "parameters": {"wtp_id": ap["serial"]}},
                           "why": "re-read only this access point (the id was listed by this target)"})
    if client_mac is not None:
        if not rest_history_available:
            if "wifi_events" in enabled_queries:
                next_steps.append({"tool": "ssh_read", "arguments": {"target": alias, "platform": "fortinet", "query": "wifi_events",
                                                                      "parameters": {"lines": str(EVENT_LINES), "mac_literal": client_mac}},
                                   "why": "REST history unavailable; enrolled SSH fallback scans at most %d global records and filters locally" % EVENT_LINES})
            else:
                next_steps.append({"tool": "target_scope", "arguments": {"target": alias},
                                   "why": "Enroll read-only REST history and certificate trust; station selection precedes the 200-row bound; SSH wifi_events is not enrolled"})
        next_steps.append({"tool": "locate_endpoint", "arguments": {"targets": [alias], "endpoint": client_mac},
                           "why": "find the wired side of the client (managed switch tables behind this FortiGate); "
                                  "add the enrolled switch targets of the path"})

    # 7. what no read-only path can answer
    if live is None:
        if name is not None:
            missing.append({"step": "client_identity", "reason": "dependency_missing",
                            "detail": "name selection requires read-only REST enrollment; use MAC for SSH-only triage"})
        missing.append({"step": "client_rssi", "reason": RSSI_UNAVAILABLE, "detail": RSSI_DETAIL})
    missing.append({"step": "locate_endpoint", "reason": LOCATE_NOT_CORRELATED, "detail": LOCATE_DETAIL,
                    "lldp_uplink": ap.get("lldp") if ap else None})

    observation = {
        "ap": (ap.get("name") or ap.get("serial")) if ap else (live_client.get("ap") if live_client else None),
        "radio": radio_number, "band": live_client.get("band") if live_client else (radio or {}).get("band"),
        "channel": (radio or {}).get("channel"), "channel_width_mhz": (radio or {}).get("channel_width_mhz"),
        "rssi_dbm": live_client.get("rssi_dbm") if live_client else None,
        "snr_db": live_client.get("snr_db") if live_client else None,
        "channel_utilization_percent": (radio or {}).get("chutil_percent"),
        "tx_retries_percent": (radio or {}).get("tx_retries_percent"),
        "noise_dbm": (radio or {}).get("noise_dbm"),
        "interfering_aps": (radio or {}).get("interfering_ap"),
        "radio_measured_at": (radio or {}).get("measured_at"),
        "captured_at": live_client.get("captured_at") if live_client else None,
        "fetched_at": live_client.get("fetched_at", live_client.get("captured_at")) if live_client else None,
        "measurement_age_note": "Client RSSI/SNR source gives no measurement timestamp; fetched_at is retrieval time, not measurement time.",
        "radio_measurement_age_note": "Radio metrics have no common measurement timestamp; only channel utilization may have one.",
        "channel_utilization_measured_at": (radio or {}).get("measured_at"),
        "channel_utilization_age_seconds": None,
        "measurement_age_seconds": None, "radio_measurement_age_seconds": None,
        "traffic_state": (radio or {}).get("traffic_state", "unknown"), "dfs": (radio or {}).get("dfs"),
    }
    now = clock()
    for stamp_key, age_key in (("channel_utilization_measured_at", "channel_utilization_age_seconds"),):
        if observation[stamp_key]:
            observation[age_key] = max(0, int((now - datetime.fromisoformat(observation[stamp_key])).total_seconds()))
    complete_rf = all(observation.get(k) is not None for k in (
        "ap", "radio", "band", "channel", "channel_width_mhz", "rssi_dbm", "snr_db",
        "channel_utilization_percent", "tx_retries_percent", "noise_dbm", "interfering_aps", "radio_measured_at"))
    if live_client is not None and radio is not None and live_client.get("channel") != radio.get("channel"):
        complete_rf = False
        missing.append({"step": "client_radio", "reason": "ambiguous",
                        "detail": "station and AP radio report different channels; repeat the read"})
    if not complete_rf:
        missing.append({"step": "rf_data", "reason": "dependency_missing", "detail": "RF data incomplete; check deciding operating-radio values in observation"})
    rf_rules = [f for f in findings if f["layer"] in ("radio", "rf") or f["id"] in ("F-WIFI-WEAK-SIGNAL", "F-WIFI-LOW-SNR")]
    rf_verdict = "incomplete" if not complete_rf else "rf_concern_found" if rf_rules else "no_rf_fault_found"
    findings_max_severity = max((f["severity"] for f in findings),
                                key=lambda value: {"notice": 1, "warning": 2, "fault": 3}[value], default=None)
    verdict = "fault_found" if findings_max_severity == "fault" else rf_verdict
    association_status = ("associated" if live_client is not None else
                          "not_associated" if live_answer is not None and live_answer.get("ok") and client_mac is not None else "unknown")
    cause_event = next((e for e in client_events if e["class"] in ("client_connect", "client_error", "client_disconnect")), None)
    historical_cause = (cause_event if cause_event and cause_event["class"] in ("client_error", "client_disconnect") else None)
    association = {"status": association_status,
                   "last_observed_status": "associated" if last_observed_client else None,
                   "last_observed_at": (last_observed_client or {}).get("fetched_at", (last_observed_client or {}).get("captured_at")),
                   "cause": ((historical_cause.get("reason") or historical_cause["logdesc"])
                             if historical_cause and not (historical_cause.get("reason") or "").lower().startswith("reserved ") else "unknown"),
                   "cause_event": compact_event(historical_cause),
                   "note": "Cause is a logged observation, not proof of why the client remains absent."}
    if association_status == "not_associated":
        verdict = "client_not_associated"
    client = {"mac": client_mac, "ip": client_ip, "ip_source": "argument" if ip is not None else None,
              "arp_interface": arp_interface, "association_status": association_status,
              **{k: (live_client or {}).get(k, "unknown") for k in ("hostname", "os", "vendor", "device_type")},
              "identity_sources": (live_client or {}).get("identity_sources", {})}
    client_state = {key: (live_client or {}).get(key) for key in (
        "rssi_dbm", "snr_db", "link_rx_mbps", "link_tx_mbps", "tx_retry_percentage", "tx_discard_percentage")}
    client_state.update(association_status=association_status, fetched_at=observation["fetched_at"],
                        measurement_age_seconds=None, measurement_age_note=observation["measurement_age_note"])
    radio_context = {"scope": "radio-wide", "client_count": (radio or {}).get("client_count"),
                     "association_context": "current_client_radio" if live_client else "last_observed_client_radio" if context_client else "last_logged_ap_radio",
                     "source": sources.get("wifi_ap_status"),
                     "fetched_at": (radio or {}).get("fetched_at") or sources.get("wifi_ap_status", {}).get("captured_at"),
                     "channel_utilization_percent": observation["channel_utilization_percent"],
                     "tx_retries_percent": observation["tx_retries_percent"],
                     "channel_utilization_measured_at": observation["channel_utilization_measured_at"],
                     "channel_utilization_age_seconds": observation["channel_utilization_age_seconds"],
                     "channel_utilization_interval_seconds": (radio or {}).get("chutil_interval_seconds"),
                     "tx_retries_interval_seconds": None, "tx_retries_measurement_age_seconds": None,
                     "note": "radio-wide, shared by %s clients, not specific to this client; retry measurement time and interval unknown" % (
                         (radio or {}).get("client_count") if (radio or {}).get("client_count") is not None else "unknown number of")}
    history = significant_history(client_events, window)
    chain = {
        "client": client, "association": association, "client_state": client_state, "radio_context": radio_context,
        "observation": observation, "signal_samples": signal_samples,
        "events": {"window": window,
                   "last_event": last,
                   "summary": history, "timeline": [dict(compact_event(event), source_sha256=sources.get("wifi_events", {}).get("content_sha256"))
                                                     for event in reversed(client_events)]},
        "access_point": None if ap is None else {
            **{key: ap[key] for key in ("serial", "name", "ip", "state", "version", "join_time", "join_time_note", "lldp")},
            # the SSH wtp-status has no name; the REST station row carries the one the controller knows
            "name": ap["name"] or (live_client.get("ap_name") if live_client is not None else None)},
        "radio": radio,
        "vap": vap,
        "rf": rf,
        "neighbors": neighbors,
        "live_client": None if live_client is None else {k: v for k, v in live_client.items() if k != "ap_detail"},
        "live_sources": live_answer.get("sources", []) if live_answer else [],
        "last_logged_signal_dbm": last["signal_dbm"] if last else None,
    }
    result = {
        "ok": True,
        "identity": ident,
        "target": alias,
        "client": client,
        "started_at": _utc(started),
        "finished_at": _utc(clock()),
        "vantage": {
            "kind": "device_cli_read", "device": alias, "packets_sent": False, "path": "FortiOS CLI over SSH + RO REST" if live is not None else "FortiOS CLI over SSH", "account": "read-only",
            "sees": "wireless events in the log, access point and radio counters, virtual access points, controller scan and RF tables",
            "does_not_see": "live client RSSI and the client list (diagnose wireless-controller is refused to read-only accounts), "
                            "the switch port behind the access point",
            "clock": "event times are device local time with the offset the device logs",
        },
        "chain": chain,
        "findings": findings,
        "hypotheses": hypotheses,
        "next_steps": next_steps,
        "missing": missing,
        "checked": checked,
        "verdict": verdict, "rf_verdict": rf_verdict, "findings_max_severity": findings_max_severity, "thresholds": policy,
    }

    if name is not None:
        result["identity_trust"] = "client_supplied"
    if live_client is not None:
        result["vantage"]["sees"] += ", live station association and signal from RO REST"
        result["vantage"]["does_not_see"] = "the switch port behind the access point"
    return result


def overview(result: dict[str, Any]) -> dict[str, Any]:
    """The verdict with its findings, gaps and the few chain facts that decide it; no sources, rows or prose."""
    chain = result["chain"]
    last = (chain["events"] or {}).get("last_event")
    live = chain.get("live_client")
    carried = {key: result[key] for key in ("error_code", "failed_step", "identity_trust") if key in result}
    return {
        **carried,
        "ok": result["ok"], "view": "summary", "target": result["target"], "identity": result["identity"],
        "client": result["client"], "started_at": result["started_at"], "finished_at": result["finished_at"],
        "verdict": result["verdict"], "rf_verdict": result["rf_verdict"], "findings_max_severity": result["findings_max_severity"],
        "findings": [{key: item[key] for key in ("id", "severity", "object", "fact", "text", "historical", "fault_level") if key in item} for item in result["findings"]],
        "missing": result["missing"], "checked": result["checked"],
        "chain": {
            "observation": chain["observation"], "association": chain["association"], "signal_samples": {**chain["signal_samples"],
                "samples": [{k: v for k, v in sample.items() if k != "sources"} for sample in chain["signal_samples"]["samples"]]},
            "client_state": chain["client_state"], "radio_context": {k: v for k, v in chain["radio_context"].items() if k != "source"},
            "events": {"window": chain["events"]["window"], **chain["events"]["summary"]},
            "last_event": None if last is None else {key: last.get(key) for key in (
                "time", "class", "ap", "radio", "channel", "vap", "signal_dbm", "reason")},
            "access_point": None if chain["access_point"] is None else {
                "name": chain["access_point"]["name"] or chain["access_point"]["serial"], "state": chain["access_point"]["state"]},
            "live_client": None if live is None else {key: live.get(key) for key in (
                "ssid", "radio", "band", "channel", "rssi_dbm", "snr_db", "link_rx_mbps", "link_tx_mbps",
                "bandwidth_rx", "bandwidth_tx", "tx_retry_percentage", "tx_discard_percentage", "idle_seconds")},
        },
    }


def validate_history(history_limit=100, history_offset=0):
    from .switch_pages import validate
    try:
        validate(history_limit, history_offset, MAX_RESULT_BYTES)
    except ValueError as error:
        raise ValueError(str(error).replace("limit", "history_limit").replace("offset", "history_offset")) from None


def full_page(result, history_limit=100, history_offset=0):
    """Bound the complete structured full response; continuations reread sources."""
    validate_history(history_limit, history_offset)
    events = result["chain"]["events"]
    rows = events["timeline"]
    result = {**result, "chain": {**result["chain"], "events": {**events, "timeline": []}}}
    timeline = result["chain"]["events"]["timeline"]
    total = len(rows)
    result["page"] = {"history_limit": history_limit, "history_offset": history_offset,
                      "max_bytes": MAX_RESULT_BYTES, "total": total, "returned": 0}
    def metadata():
        end = min(history_offset, total) + len(timeline)
        more = end < total
        result.update(truncated=more, next={"history_limit": history_limit, "history_offset": end} if more else None)
        result["page"]["returned"] = len(timeline)
    def size():
        return len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("utf-8"))
    def too_large(step):
        return {"ok": False, "target": result.get("target"), "error_code": "result_too_large",
                "failed_step": step, "truncated": True, "next": None,
                "error": "One history record or response metadata exceeds 48000 bytes; narrow the read"}
    metadata()
    if size() > MAX_RESULT_BYTES:
        return too_large("metadata")
    for row in rows[history_offset:history_offset + history_limit]:
        timeline.append(row)
        metadata()
        if size() > MAX_RESULT_BYTES:
            timeline.pop()
            metadata()
            return result if timeline else too_large("history")
    return result
