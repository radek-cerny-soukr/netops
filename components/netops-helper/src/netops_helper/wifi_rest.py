"""Bounded FortiOS Wi-Fi GET transport. No URL, method or server filter comes from a caller."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import math
import ipaddress
import re
import os
import subprocess
import sys
import socket
import ssl
import threading
import time
import types
import unicodedata
from urllib.parse import quote, unquote

from .proxy_sanitize import sanitize_object
from .wifi_common import phy_band as _phy_band

MONITOR = "/api/v2/monitor/wifi/"
DEVICES = "/api/v2/monitor/user/device/query"
WIRELESS_LOG = "/api/v2/log/memory/event/wireless?rows=200&filter=subtype%3D%3Dwireless"
PATHS = frozenset(MONITOR + name for name in (
    "client", "managed_ap", "ap_status", "rogue_ap", "interfering_ap"
)) | {DEVICES, WIRELESS_LOG}
_CLIENT_LOG_PREFIX = WIRELESS_LOG + "&filter=stamac%3D%3D"


def wireless_log_path(mac):
    """A typed station selector, never an arbitrary URL or filter expression."""
    checked_filters(mac=mac)
    if mac is None:
        raise ValueError("invalid_argument: client history requires a MAC")
    return _CLIENT_LOG_PREFIX + quote(mac, safe="")


def _log_mac(path):
    if isinstance(path, str) and path.startswith(_CLIENT_LOG_PREFIX):
        mac = unquote(path[len(_CLIENT_LOG_PREFIX):])
        try:
            return mac if wireless_log_path(mac) == path else None
        except ValueError:
            pass
    return None


def _allowed_path(path):
    return path in PATHS or _log_mac(path) is not None
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 10
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+")


def _read_chunk_size(response):
    """Chunk-size line as RFC 9112 defines it: hex digits, optional `;ext`, CRLF.

    http.client feeds the line to int(..., 16), which also accepts `+61`, `6_1`,
    `0x61`, surrounding blanks and `-0` (CVE-2026-103995). Same rule as the Auditor collector.
    """
    line = response.fp.readline(http.client._MAXLINE + 1)
    if len(line) > http.client._MAXLINE:
        raise http.client.LineTooLong("chunk size")
    size = line.removesuffix(b"\r\n").split(b";", 1)[0]
    if not line.endswith(b"\r\n") or _CHUNK_SIZE.fullmatch(size) is None:
        response._close_conn()
        raise ValueError("invalid chunk size")
    return int(size, 16)

_rate_lock = threading.Lock()
_rates = {}


class RestError(ValueError):
    """Only fixed diagnostic codes and a numeric HTTP status cross the tool boundary."""
    def __init__(self, code, message, *, http_status=None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def checked_pin(value):
    if value is not None and (not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None):
        raise ValueError("invalid certificate SHA-256 pin")
    return value


def checked_token(value):
    if value is not None and (not isinstance(value, str) or len(value) > 4096 or re.fullmatch(r"[A-Za-z0-9._~+/-]{8,4096}={0,2}", value) is None):
        raise ValueError("invalid FortiOS REST credential; value withheld")
    return value


def checked_filters(ssid=None, ap=None, mac=None, name=None):
    for field, value in (("SSID", ssid), ("AP", ap), ("name", name)):
        if value is not None and (not isinstance(value, str) or not 1 <= len(value.encode()) <= 128
                                  or any(unicodedata.category(c) in {"Cc", "Cf"} for c in value)):
            raise ValueError("invalid_argument: %s must be bounded printable text" % field)
    if mac is not None and (not isinstance(mac, str) or re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) is None):
        raise ValueError("invalid_argument: MAC must be lower-case aa:bb:cc:dd:ee:ff")


def _rate(auth):
    now = time.monotonic()
    policy = auth.fortios_rest_rate_limit
    with _rate_lock:
        key = (auth.alias, auth.host)
        # Drop inactive targets to keep long-running workers bounded.
        for old in list(_rates):
            if not _rates[old] or now - _rates[old][-1] >= 3600:
                del _rates[old]
        times = _rates.setdefault(key, deque())
        while times and now - times[0] >= policy["window_seconds"]:
            times.popleft()
        if len(times) >= policy["requests"]:
            raise RestError("rate_limited", "rate_limit: FortiOS REST target budget exhausted")
        times.append(now)


def _invalid_number(value):
    raise RestError("invalid_response", "fortios_rest_invalid_json_number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        _invalid_number(None)
    return number


def _check_numbers(document):
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            _invalid_number(None)


_DNS_PROGRAM = """import json,socket,sys
host,port=json.loads(sys.stdin.buffer.read(8192))
rows=socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM)
print(json.dumps(sorted({row[4][0] for row in rows})))
"""


def _resolve_addresses(auth, remaining):
    try:
        address = ipaddress.ip_address(auth.host)
    except ValueError:
        auth.require_dns()
    else:
        if address.version != 4:
            raise RestError("egress_denied", "egress_scope: REST requires IPv4")
        return (str(address),)
    # libc DNS has no enforceable per-call timeout. Isolate only the resolver
    # (no credentials) and kill/reap it before returning on timeout/cancellation.
    process = subprocess.Popen([sys.executable, "-I", "-B", "-c", _DNS_PROGRAM],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env={"PATH": os.defpath, "LC_ALL": "C"})
    try:
        try:
            output, _ = process.communicate(json.dumps([auth.host, auth.fortios_rest_port]).encode("utf-8"), timeout=remaining())
        except subprocess.TimeoutExpired:
            raise TimeoutError("FortiOS REST DNS deadline exceeded") from None
        remaining()
        if process.returncode or len(output) > 65536:
            raise RestError("transport_error", "fortios_rest_dns_failed")
        return tuple(str(ipaddress.IPv4Address(item)) for item in json.loads(output))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()


def get(auth, path, *, method="GET", addresses=None):
    """Authenticate TLS before sending the bearer; never follow redirects or use ambient proxies."""
    deadline = time.monotonic() + TIMEOUT
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("FortiOS REST deadline exceeded")
        return seconds

    if method != "GET" or not _allowed_path(path):
        raise ValueError("policy_scope: only fixed Wi-Fi GET endpoints are allowed")
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: FortiOS REST requires FortiOS")
    try:
        token = checked_token(auth.fortios_rest_token)
        pin = checked_pin(auth.fortios_rest_certificate_sha256)
    except ValueError:
        raise RestError("configuration", "FortiOS REST credential or certificate pin configuration is invalid") from None
    if token is None:
        raise RestError("configuration", "unsupported: enroll helper.fortios_rest_credential; see docs/fortios-wifi-rest.md")
    if pin is None and auth.tls_ca_certificate is None:
        raise RestError("configuration", "policy_scope: FortiOS REST requires a certificate pin or CA")
    from .inventory import checked_rest_port
    port = checked_rest_port(auth.fortios_rest_port)
    auth.require_tcp_port(port)
    if auth.tls_ca_certificate:
        from .inventory import _checked_tls_ca
        try:
            ca = _checked_tls_ca("FortiOS REST", auth.tls_ca_certificate)
            context = ssl.create_default_context(cafile=ca)
        except (ValueError, OSError):
            raise RestError("configuration", "FortiOS REST CA configuration is invalid") from None
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # exact DER certificate is checked before any HTTP bytes
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = None
    peer = None
    timer = None

    def expire():
        # Socket timeouts alone do not bound a peer that trickles HTTP header bytes.
        try:
            peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    try:
        if addresses is None:
            addresses = _resolve_addresses(auth, remaining)
        if not addresses or any(not auth.egress.allows_address(a) for a in addresses):
            raise RestError("egress_denied", "egress_scope: REST address outside target allowlist")
        _rate(auth)
        raw = socket.create_connection((addresses[0], port), timeout=remaining())
        try:
            peer = context.wrap_socket(raw, server_hostname=auth.host, do_handshake_on_connect=False)
            timer = threading.Timer(remaining(), expire)
            timer.daemon = True
            timer.start()
            peer.settimeout(remaining())
            peer.do_handshake()
        except BaseException:
            raw.close()
            raise
        if pin and not hmac.compare_digest(hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest(), pin):
            raise RestError("tls_pin_mismatch", "certificate_pin_mismatch")
        connection = http.client.HTTPSConnection(auth.host, port, timeout=remaining(), context=context)
        connection.sock = peer
        peer.settimeout(remaining())
        connection.request("GET", path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        response = connection.getresponse()
        if isinstance(response, http.client.HTTPResponse) and response.chunked:
            response._read_next_chunk_size = types.MethodType(_read_chunk_size, response)
        if response.status != 200:
            code = ("authentication_failed" if response.status == 401 else
                    "authorization_failed" if response.status == 403 else
                    "rate_limited" if response.status == 429 else
                    "http_server_error" if 500 <= response.status <= 599 else "http_status")
            raise RestError(code, "fortios_rest_http_%d" % response.status, http_status=response.status)
        if response.getheader("Content-Encoding", "identity") != "identity":
            raise RestError("unsupported_encoding", "fortios_rest_unsupported_encoding")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
            raise RestError("response_too_large", "fortios_rest_response_too_large")
        body = bytearray()
        while True:
            peer.settimeout(remaining())
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise RestError("response_too_large", "fortios_rest_response_too_large")
            if not chunk:
                break
        remaining()
        from .inventory import unique_object
        try:
            document = json.loads(body, object_pairs_hook=unique_object,
                                  parse_constant=_invalid_number, parse_float=_finite_float)
        except RestError:
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise RestError("invalid_json", "fortios_rest_invalid_json") from None
        # Remove explicit tokens even if a device echoes them under an unrelated key.
        return sanitize_object(document, (token, auth.secret))
    except (TimeoutError, socket.timeout):
        raise RestError("timeout", "FortiOS REST deadline exceeded") from None
    except ssl.SSLCertVerificationError:
        raise RestError("tls_verification_failed", "FortiOS REST certificate verification failed") from None
    except ssl.SSLError:
        raise RestError("timeout" if time.monotonic() >= deadline else "tls_error", "FortiOS REST TLS failed") from None
    except (OSError, http.client.HTTPException):
        raise RestError("timeout" if time.monotonic() >= deadline else "transport_error",
                        "fortios_rest_transport_error") from None
    finally:
        if timer is not None:
            timer.cancel()
        if connection is not None:
            connection.close()
        if peer is not None:
            peer.close()


def _number(row, key, low=None, high=None):
    value = row.get(key)
    if type(value) not in (int, float) or not float("-inf") < value < float("inf"):
        return None
    return value if (low is None or value >= low) and (high is None or value <= high) else None


def checked_rogue_filters(limit=100, min_signal=None):
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer from 1 to 500")
    if min_signal is not None and (type(min_signal) is not int or not -150 <= min_signal <= 0):
        raise ValueError("min_signal must be an integer dBm from -150 to 0")


def _utc(value):
    if type(value) not in (int, float) or not 0 < value < 253402300800:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _device_offset(row):
    # The device supplies both its local wall clock and the matching UTC epoch.
    for key in ("last_seen", "first_seen"):
        utc = _utc(row.get(key + "_utc"))
        try:
            local = datetime.strptime(row[key], "%Y-%m-%d %H:%M:%S")
            delta = local - datetime.fromisoformat(utc).replace(tzinfo=None)
            if abs(delta.total_seconds()) <= 14 * 3600 and delta.total_seconds() % 60 == 0:
                return timezone(delta)
        except (KeyError, TypeError, ValueError):
            pass
    return None


def _identity_text(value):
    return value if isinstance(value, str) and 0 < len(value.encode()) <= 128 and all(unicodedata.category(c) not in {"Cc", "Cf"} for c in value) else "unknown"


def _normalise(row, zone=None):
    if isinstance(row, list):
        return [_normalise(item, zone) for item in row]
    if not isinstance(row, dict):
        return row
    zone = _device_offset(row) or zone
    result = {}
    for key, value in row.items():
        if key in {"wtp_ip", "wtp_port"} or key.endswith(("_raw", "_utc")):
            continue
        if key in {"join_time", "last_reboot_time", "first_seen", "last_seen"}:
            moment = _utc(row.get(key + "_raw", row.get(key + "_utc")))
            if moment is None and zone is not None:
                try:
                    moment = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=zone).astimezone(timezone.utc).isoformat()
                except (ValueError, TypeError):
                    pass
            result[key] = moment  # never present an unzoned wall clock as UTC
        elif key.endswith("_timestamp"):
            result[key] = _utc(value)
        elif key in {"mem_free", "mem_total"}:
            result[key + "_kib"] = value
        elif key == "band":
            if value in ("24ghz", "5ghz", "6ghz"):
                result[key] = value
            else:
                result["phy_mode"] = value
                result[key] = _phy_band(str(value).upper())
        else:
            result[key] = _normalise(value, zone)
    if "radio_id" in result:
        for key, low, high in (("oper_chan", 0, 233), ("channel_utilization_percent", 0, 100),
                               ("tx_retries_percent", 0, 100), ("noise_floor", -150, -1),
                               ("client_count", 0, None), ("interfering_aps", 0, None)):
            result[key] = _number(result, key, low, high)
        result["channel_width_mhz"] = width_mhz(result.get("channel_bonding"))
        result["band"] = radio_band(result)
        result["measurement_age_seconds"] = None
        result["measurement_age_note"] = "No common radio measurement timestamp; channel_utilization_timestamp applies only to utilization, not retries."
        result["operating"] = bool(result.get("oper_chan"))
        result["traffic_state"] = "no_traffic" if result.get("bandwidth_rx") == result.get("bandwidth_tx") == 0 else "unknown" if result.get("bandwidth_rx") is None else "active"
    return result


def width_mhz(value):
    match = re.fullmatch(r"(20|40|80|160|320)(?:MHz)?", str(value))
    return int(match[1]) if match else None


def radio_band(row):
    mode = row.get("radio_type", "")
    return next((band for suffix, band in (("-2G", "24ghz"), ("-5G", "5ghz"), ("-6G", "6ghz"))
                 if isinstance(mode, str) and mode.endswith(suffix)), row.get("band"))


def real_radio(row):
    return row.get("mode") not in (None, "", "unknown", "Not Exist") and row.get("radio_type") not in (None, "", "unknown")


_AP_OVERVIEW = "name state connection_state clients os_version local_addr join_time cpu_usage fetched_at".split()
_RADIO_OVERVIEW = ("radio_id", "radio_type", "oper_chan", "client_count", "channel_utilization_percent",
                   "tx_retries_percent", "noise_floor", "interfering_aps", "detected_rogue_aps",
                   "channel_width_mhz", "band", "operating", "traffic_state", "channel_utilization_timestamp", "measurement_age_seconds", "channel_utilization_age_seconds")


def ap_overview(row):
    """One access point reduced to identity, state and the per-radio numbers an operator reads first."""
    result = {key: row[key] for key in _AP_OVERVIEW if key in row}
    result["name"] = row.get("name") or row.get("serial") or row.get("wtp_id")
    result["measurement_age_note"] = "Radio age unknown; retries have no timestamp."
    radios = row.get("radio")
    result["radios"] = [{key: radio[key] for key in _RADIO_OVERVIEW if key in radio}
                        for radio in radios if isinstance(radio, dict) and real_radio(radio)] if isinstance(radios, list) else []
    return result


def _ipv6(values):
    if not isinstance(values, list):
        values = [values]
    result = []
    for value in values:
        try:
            address = ipaddress.IPv6Address(value)
            if not address.is_unspecified and str(address) not in result:
                result.append(str(address))
        except (ValueError, TypeError):
            pass
    return result


def parse(path, document):
    return parse_counted(path, document)[0]


def parse_counted(path, document):
    """Return (records, unparsed_rows); only client rows can be skipped."""
    _check_numbers(document)
    if not _allowed_path(path) or not isinstance(document, dict) or document.get("status") != "success" \
            or document.get("http_method") != "GET" or document.get("vdom") != "root":
        raise RestError("unparsed_envelope", "fortios_rest_unparsed: expected successful root VDOM GET envelope")
    value = document.get("results")
    log_mac = _log_mac(path)
    if path == WIRELESS_LOG or log_mac is not None:
        from .wifi_parse import event_record, UndatedEvent
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise RestError("unparsed_envelope", "fortios_rest_unparsed: expected wireless log list")
        if log_mac is not None and any(row.get("subtype") != "wireless" or
                                      str(row.get("stamac", "")).lower() != log_mac for row in value):
            raise RestError("invalid_response", "fortios_rest_client_log_filter_not_applied")
        records, unparsed, undated = [], 0, 0
        for index, row in enumerate(value, 1):
            try:
                records.append(event_record(row, index))
            except UndatedEvent:
                undated += 1
            except (ValueError, KeyError, TypeError):
                unparsed += 1
        found = document.get("total_lines")
        complete = (type(found) is int and 0 <= found == len(value) and not unparsed and not undated
                    and document.get("ready") is True and document.get("percent_logs_processed") == 100)
        return {"records": records, "found": found, "returned": len(value),
                "requested_lines": 200, "scope": "client_records" if log_mac else "wireless_batch",
                "filter_mac": log_mac, "complete": complete,
                "undated": undated, "unparsed_count": unparsed}, unparsed
    if path == DEVICES:
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise RestError("unparsed_envelope", "fortios_rest_unparsed: expected device list")
        return [{k: row[k] for k in ("mac", "hostname", "os", "hardware_vendor", "hardware_type", "os_name") if k in row}
                for row in value], 0
    if path == MONITOR + "ap_status":
        if not isinstance(value, dict):
            raise RestError("unparsed_envelope", "fortios_rest_unparsed: expected AP summary")
        return {k: _number(value, k, 0) for k in value if k in {
            "wtp_session_count", "wtp_active", "wtp_down", "wtp_rebooted", "client_count"}}, 0
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise RestError("unparsed_envelope", "fortios_rest_unparsed: expected list of objects")
    fields = {
        "managed_ap": "name serial wtp_id state connection_state clients os_version ap_profile local_addr join_time join_time_raw last_reboot_time last_reboot_time_raw cpu_usage mem_free mem_total radio ssid lldp",
        "rogue_ap": "ssid mac channel band signal_strength noise encryption security_mode manufacturer bw channel_width channel_bonding first_seen first_seen_utc last_seen last_seen_utc detected_by_wtp is_managed",
        "interfering_ap": "mac wtps",
    }
    name = path.rsplit("/", 1)[-1]
    if name != "client":
        return [_normalise({k: row[k] for k in fields[name].split() if k in row}) for row in value], 0
    now = datetime.now(timezone.utc).timestamp()
    rows = []
    unparsed = 0
    for row in value:
        mac = row.get("mac")
        mac = mac.lower() if isinstance(mac, str) else mac
        try:
            if mac is None:
                raise ValueError("client MAC missing")
            checked_filters(mac=mac)
        except ValueError:
            unparsed += 1
            continue
        health = row.get("health")
        band = health.get("band") if isinstance(health, dict) else None
        band = band.get("value") if isinstance(band, dict) else None
        associated = _number(row, "association_time", 0, 253402300799)
        rows.append({
            "mac": mac, "ip": row.get("ip"), "ipv6": _ipv6(row.get("ip6", [])), "ssid": row.get("ssid"),
            "vap_name": row.get("vap_name") if isinstance(row.get("vap_name"), str) else None,
            "ap_id": row.get("wtp_id"), "ap_name": row.get("wtp_name"), "ap_serial": None,
            "radio": _number(row, "wtp_radio", 0), "band": band if band in ("24ghz", "5ghz", "6ghz") else None, "phy_mode": row.get("radio_type"),
            "channel": _number(row, "channel", 0), "rssi_dbm": _number(row, "signal", -150, 0), "snr_db": _number(row, "snr", -100, 150),
            "noise_dbm": _number(row, "noise", -150, -1),
            "hostname": _identity_text(row.get("host") or row.get("hostname")),
            "os": _identity_text(row.get("os")), "vendor": _identity_text(row.get("manufacturer")),
            "device_type": _identity_text(row.get("hardware_type")),
            "identity_sources": {key: MONITOR + "client" for key, value in {
                "hostname": row.get("host") or row.get("hostname"), "os": row.get("os"),
                "vendor": row.get("manufacturer"), "device_type": row.get("hardware_type")}.items() if _identity_text(value) != "unknown"},
            "link_rx_mbps": _number(row, "data_rxrate_bps", 0) / 1e6 if _number(row, "data_rxrate_bps", 0) is not None else None,
            "link_tx_mbps": _number(row, "data_txrate_bps", 0) / 1e6 if _number(row, "data_txrate_bps", 0) is not None else None,
            "bandwidth_rx": _number(row, "bandwidth_rx", 0), "bandwidth_tx": _number(row, "bandwidth_tx", 0),
            "tx_retry_percentage": _number(row, "tx_retry_percentage", 0, 100),
            "tx_discard_percentage": _number(row, "tx_discard_percentage", 0, 100),
            "idle_seconds": _number(row, "idle_time", 0),
            "association_time": _utc(associated),
            "connected_seconds": max(0, int(now-associated)) if type(associated) in (int, float) else None,
            "authentication": row.get("authentication"), "security": row.get("security_str"),
            "state": "associated",  # presence in the live station table, separate from authentication
        })
    return rows, unparsed


def enrich_identity(client, devices):
    matches = [d for d in devices if isinstance(d.get("mac"), str) and d["mac"].lower() == client["mac"]]
    if len(matches) == 1:
        for field, source in (("hostname", "hostname"), ("os", "os_name"), ("vendor", "hardware_vendor"), ("device_type", "hardware_type")):
            if client[field] == "unknown" and matches[0].get(source):
                client[field] = _identity_text(matches[0][source])
                if client[field] != "unknown":
                    client["identity_sources"][field] = DEVICES
