from __future__ import annotations

import ipaddress
import re
import threading
import time

RECIPE = "system_event_logs"
RECIPES = {
    "system_event_logs": ("event", "system"),
    "waf_attack_logs": ("attack", "waf"),
    "health_check_event_logs": ("event", "health_check"),
    "admin_event_logs": ("event", "admin"),
    "configuration_event_logs": ("event", "configuration"),
    "slb_http_traffic_logs": ("traffic", "slb_http"),
    "slb_layer4_traffic_logs": ("traffic", "slb_layer4"),
}
TRAFFIC_RECIPES = frozenset({"slb_http_traffic_logs", "slb_layer4_traffic_logs"})
VS_LOG_RECIPES = TRAFFIC_RECIPES | {"waf_attack_logs"}
LOG_PAGE_SIZE = 20
MAX_START_LINE = 8_000_000
STATE_RECIPES = {
    "session_list": "session",
    "persistence_list": "persistence",
}
STATE_FIELDS = {
    "persistence": ("source ip range", "source port range", "dest ip range", "dest port range", "virtual server"),
}
STATE_FIELDS["session"] = STATE_FIELDS["persistence"] + (
    "type", "protocol", "trans source ip range", "trans source port range", "trans dest ip range",
    "trans dest port range", "real server",
)
LIST_HEADERS = {
    "session": "client-ip/port virtual-server-ip/port local-ip/port real-server-ip/port protocol service state "
               "in-bytes out-bytes expire virtual-server-name real-server-name",
    "persistence": "client-ip/port virtual-server-ip/port local-ip/port real-server-ip/port protocol service expire "
                   "virtual-server-name real-server-name",
}
VIRTUAL_SERVER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
# Columns of one list row, measured on FortiADC-KVM 7.6.7 build0676 (FortiADC-KVM 7.6.7, 2026-11-17, verification) with HTTP, UDP
# DNS and source-address persistence traffic: the header names "protocol service" and every row prints the protocol
# number and the service name; a session row has 16 words, a persistence row 13 (no state and byte counters).
ROW_FIELDS = {
    "session": ("client_ip", "client_port", "virtual_server_ip", "virtual_server_port", "local_ip", "local_port",
                "real_server_ip", "real_server_port", "protocol", "service", "state", "in_bytes", "out_bytes",
                "expire", "virtual_server", "real_server"),
    "persistence": ("client_ip", "client_port", "virtual_server_ip", "virtual_server_port", "local_ip", "local_port",
                    "real_server_ip", "real_server_port", "protocol", "service", "expire", "virtual_server",
                    "real_server"),
}
_INTEGER_FIELDS = frozenset(("client_port", "virtual_server_port", "local_port", "real_server_port", "protocol",
                             "in_bytes", "out_bytes", "expire"))
_ADDRESS_FIELDS = frozenset(("client_ip", "virtual_server_ip", "local_ip", "real_server_ip"))
# Filter flags read back by `filter show` (measured 7.6.7 build0676): vs-name 1000, source-ip 10, both 1010. The
# device applies only the first quoted argument, so both filters go into one quoted argument and are read back.
FLAG_VIRTUAL_SERVER = "1000"
FLAG_VIRTUAL_SERVER_SOURCE = "1010"
# A filter value the device does not accept (measured: persistence `rs-name`, an invalid address) is answered with
# this line and leaves the filter unchanged.
FILTER_REFUSAL = re.compile(r"(?m)^[ \t]*'[^'\r\n]*' is invalid filter option or exceeded the maximum name length\.[ \t]*\r?$")
GET_STATUS = "get system status"
SHOW = "execute log filter show"
DISPLAY = "execute log display 0"
CLEAR = "execute log filter clear"
DISPLAY_REFUSAL = "Please set filter type and subtype firstly"
SEARCH_PENDING = frozenset({"begin to search logs", "has started searching log, please wait"})
DISPLAY_END = "display 20 lines log messages one time at most,you can tune the starline if you want to see more logs"
FOOTERS = frozenset({
    "begin to search logs",
    DISPLAY_END,
})
RECORD_START = re.compile(r"^date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2}(?: |$)")
RECORD_TIMESTAMP = re.compile(r"^date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2})")
LOG_FIELD = re.compile(r"(?<!\S)([a-z][a-z0-9_]*)=")
END_OF_METADATA = {
    # These tails can include HTTP credentials, request payloads or values from a configuration change.
    "waf_attack_logs": re.compile(r" (?:http_\w+|pkt_hdr|matched_part|msg|user_agent)="),
    "slb_http_traffic_logs": re.compile(r" (?:http_\w+|pkt_hdr|msg)="),
    "configuration_event_logs": re.compile(r" (?:cfgattr|msg)="),
}
ADMIN_HEADER = re.compile(
    r"[ \t]+(?:log_id=[0-9]{1,20}[ \t]+)?(?P<kind>type=event)(?=[ \t]|$)"
    r"(?:[ \t]+subtype=[A-Za-z0-9_-]{1,32})?(?:[ \t]+pri=[A-Za-z0-9_-]{1,16})?"
    r"(?:[ \t]+vd=[A-Za-z0-9_.-]{1,32})?(?:[ \t]+(?P<msg_id>msg_id=[0-9]{1,20})(?=[ \t]|$))?"
)
ADMIN_USER = re.compile(r"[ \t]+user[ \t]*=")
ADMIN_BOUNDARY = re.compile(r"(?<![ \t])[ \t]+(?:ui|msg)[ \t]*=")
ADMIN_DETAILS = re.compile(
    r"(?<![ \t])[ \t]+ui[ \t]*=[ \t]*(?P<ui_kind>[A-Za-z]{1,16})\((?P<host>[^\s=()]{1,64})\)"
    r"[ \t]+action[ \t]*=[ \t]*(?P<action>login|logout)[ \t]+status[ \t]*=[ \t]*(?P<status>success|failed)"
    r"[ \t]+reason[ \t]*=(?P<reason>.{0,256}?)[ \t]+logdesc[ \t]*=.{0,512}?[ \t]+msg[ \t]*="
)
ADMIN_SUCCESS = re.compile(
    r" user=(?P<user>[\w.@-]+) +ui=(?P<ui>[A-Za-z]+\([^\s=()]+\))"
    r" action=(?P<action>login|logout) status=success reason=none logdesc=[^=\r\n]+"
    r" msg=User (?P=user) +(?P=action)(?: successfully)? from (?P=ui)\.?"
)
SLB_CONFIG_OBJECT = re.compile(
    r" action=(?:add|del) cfgpath=load-balance (?:virtual-server|pool|content-routing)"
    r" cfgobj=name cfgattr=([A-Za-z0-9][A-Za-z0-9_.-]{0,62})(?= logdesc=|$)"
)
# Measured on FortiADC-KVM 7.6.7 build0676 (FortiADC-KVM 7.6.7, 2026-11-17, verification): a read profile (all six areas read)
# has no diagnose subtree at all (`diagnose ?` lists only <Enter>); every catalogue `diagnose server-load-balance ...`
# answers `Parsing error at 'server-load-balance'. err=1` and `Return code is -284`. A system administrator answers an
# unknown argument with the parsing error at that argument (`slb_load extra` -> `Parsing error at 'extra'`).
DIAGNOSE_NOT_PERMITTED_ADVICE = (
    "The FortiADC account profile has no diagnose commands (the device rejects the first word after diagnose); "
    "runtime server-load-balance reads need a system administrator enrolled as admin-bounded with role_boundary "
    "catalogue, or remove the diagnose queries from enabled_queries"
)
_RETURN_284 = re.compile(r"(?m)^[ \t]*Command fail\. Return code is -284 \(CLI parsing error\.\)[ \t]*\r?$")
INTERFACE_EXEC_WORDS = {
    "get system interface": "interface",
    "diagnose hardware get deviceinfo nic-detail": "hardware",
    "diagnose netlink interface list": "netlink",
    "diagnose netlink device": "netlink",
}
INTERFACE_EXEC_QUERIES = frozenset({"interface_list", "nic_detail_all", "interface_state_all", "interface_summary"})


def interface_exec_refusal(command, output, stderr=None):
    """Recognize the measured restricted-profile error split between exec stdout and stderr."""
    word = INTERFACE_EXEC_WORDS.get(command)
    if word is None or not _RETURN_284.search(output):
        return None
    match = re.search(r"(?m)^[ \t]*Parsing error at '%s'(?:\. err=1)?[ \t]*\r?$" % word,
                      output if stderr is None else stderr)
    return match[0].strip() if match else None


_INTERFACE_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}"
_CONFIG_INTERFACE = re.compile(r"(?m)^== \[ (" + _INTERFACE_NAME + r") \][ \t]*$")
_NIC_SETTINGS = re.compile(r"(?m)^Settings for (" + _INTERFACE_NAME + r"):[ \t]*$")
_NIC_COUNTER_NAME = re.compile(r"(?m)^Interface: (" + _INTERFACE_NAME + r")[ \t]*$")


def _interface_blocks(text, header):
    parts = header.split(text.replace("\r\n", "\n"))
    blocks = {}
    for name, block in zip(parts[1::2], parts[2::2]):
        fields = {}
        for line in block.splitlines():
            field, separator, value = line.partition(":")
            if separator:
                fields[field.strip()] = value.strip()
        blocks[name] = fields
    return blocks


def _interface_ip(value, address_type):
    value = value.strip()
    try:
        address_type(value)
    except ValueError:
        return None
    return value


def interface_summary(configuration, nic_detail):
    """Join measured FortiADC interface blocks, including NICs reported only by their counter header."""
    configured = _interface_blocks(configuration, _CONFIG_INTERFACE)
    physical = _interface_blocks(nic_detail, _NIC_SETTINGS)
    for name in _NIC_COUNTER_NAME.findall(nic_detail):
        physical.setdefault(name, {})
    rows = []
    for name in dict.fromkeys((*configured, *physical)):
        config = configured.get(name, {})
        nic = physical.get(name, {})
        status = config.get("status", "").strip()
        speed = re.fullmatch(r"(\d{1,8})Mb/s", nic.get("Speed", "").strip())
        fields = {
            "ipv4": _interface_ip(config.get("ip", ""), ipaddress.IPv4Interface),
            "ipv6": _interface_ip(config.get("ip6", ""), ipaddress.IPv6Interface),
            "admin_status": status if status in {"up", "down"} else None,
            "link_up": {"yes": True, "no": False}.get(nic.get("Link detected", "").strip()),
            "speed_mbps": int(speed[1]) if speed else None,
        }
        missing_sources = [source for source, entries in (("interface_list", configured), ("nic_detail_all", physical))
                           if name not in entries]
        missing_fields = [key for key, value in fields.items() if value is None]
        rows.append({"name": name, **fields, "complete": not missing_fields,
                     **({"missing_sources": missing_sources} if missing_sources else {}),
                     **({"missing_fields": missing_fields} if missing_fields else {})})
    return rows


def diagnose_refused(command, answer):
    """True when the device rejected the word right after `diagnose`: the profile has no diagnose (measured)."""
    if not isinstance(command, str) or not isinstance(answer, str):
        return False
    words = command.split()
    if len(words) < 2 or words[0] != "diagnose":
        return False
    first = re.compile(r"(?m)^[ \t]*Parsing error at '%s'\. err=1[ \t]*\r?$" % re.escape(words[1]))
    return first.search(answer) is not None and _RETURN_284.search(answer) is not None


CLI_REFUSAL = re.compile(
    r"(?mi)^[ \t]*(?:Command fail\. Return code is [+-]?\d+ \([^()\r\n]+\)"
    r"|command parse error[^\r\n]*|unknown action[^\r\n]*|permission denied[^\r\n]*)[ \t]*\r?$"
)


def client_range(source_address):
    """(first, last) IPv4 of a client filter: one unicast address or a canonical prefix (no network/broadcast)."""
    import ipaddress
    if not isinstance(source_address, str):
        raise ValueError("source_address must be one IPv4 address or a canonical IPv4 prefix")
    try:
        if "/" in source_address:
            network = ipaddress.IPv4Network(source_address, strict=True)
            if str(network) != source_address or network.prefixlen < 16:
                raise ValueError
            first, last = (network[0], network[-1]) if network.prefixlen >= 31 else (network[1], network[-2])
        else:
            first = last = ipaddress.IPv4Address(source_address)
            if str(first) != source_address:
                raise ValueError
    except ValueError:
        raise ValueError("source_address must be one IPv4 address or a canonical IPv4 prefix (/16 to /32)") from None
    if any(ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip == ipaddress.IPv4Address("255.255.255.255")
           for ip in (first, last)):
        raise ValueError("source_address must be a unicast client address")
    return str(first), str(last)


def validate(recipe, address, interface, count, timeout, max_bytes, source_address=None, *,
             since=None, until=None, start_line=None):
    if source_address is not None and recipe not in STATE_RECIPES and recipe not in VS_LOG_RECIPES:
        raise ValueError(f"{recipe} does not take a client source_address")
    if recipe in STATE_RECIPES:
        if any(value is not None for value in (since, until, start_line)):
            raise ValueError(f"{recipe} does not take a log page or time window")
        if not isinstance(address, str) or VIRTUAL_SERVER.fullmatch(address) is None or interface != "":
            raise ValueError(f"{recipe} takes an enrolled virtual server name and an empty interface")
        if source_address is not None:
            client_range(source_address)
        if type(count) is not int or not 1 <= count <= 50:
            raise ValueError(f"{recipe} count must be between 1 and 50")
        if type(timeout) is not int or not 1 <= timeout <= 10:
            raise ValueError(f"{recipe} timeout must be between 1 and 10 seconds")
        if type(max_bytes) is not int or not 1000 <= max_bytes <= 16384:
            raise ValueError(f"{recipe} output limit must be between 1000 and 16384 bytes")
        return
    if recipe not in RECIPES:
        raise ValueError("unknown FortiADC diagnostic recipe")
    if interface != "" or (address != "" and
            (recipe not in VS_LOG_RECIPES or not isinstance(address, str) or VIRTUAL_SERVER.fullmatch(address) is None)):
        raise ValueError(f"{recipe} requires an empty interface and accepts a virtual server only for WAF/traffic")
    if recipe in TRAFFIC_RECIPES and not address:
        raise ValueError(f"{recipe} requires an enrolled virtual server")
    if source_address is not None:
        try:
            if str(ipaddress.IPv4Address(source_address)) != source_address:
                raise ValueError
        except ValueError:
            raise ValueError("log source_address must be one canonical IPv4 address") from None
    log_window(since, until)
    if start_line is not None and (type(start_line) is not int or not 0 <= start_line <= MAX_START_LINE):
        raise ValueError(f"start_line must be a whole number from 0 to {MAX_START_LINE}")
    if type(count) is not int or not 1 <= count <= LOG_PAGE_SIZE:
        raise ValueError(f"{recipe} count must be between 1 and 20")
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise ValueError(f"{recipe} timeout must be between 1 and 20 seconds")
    if type(max_bytes) is not int or not 1000 <= max_bytes <= 16384:
        raise ValueError(f"{recipe} output limit must be between 1000 and 16384 bytes")


def log_window(since, until):
    from .fortios_diagnostics import valid_log_stamp

    if any(value is not None and not valid_log_stamp(value) for value in (since, until)):
        raise ValueError("a log time window requires valid YYYY-MM-DD HH:MM:SS timestamps")
    if since is not None and until is not None and since > until:
        raise ValueError("the log time window is reversed")


def authorize(auth, recipe, address="", source_address=None):
    if recipe not in RECIPES and recipe not in STATE_RECIPES:
        raise ValueError("unknown FortiADC diagnostic recipe")
    auth.require_ssh_query("fortiadc", "system_status")
    if recipe not in auth.read_inventory.get("diagnostic_recipes", ()):
        raise ValueError("diagnostic recipe is not enrolled for this target")
    if (recipe in STATE_RECIPES or (recipe in VS_LOG_RECIPES and address)) and (
            address not in auth.read_inventory.get("diagnostic_virtual_servers", ())):
        raise ValueError("virtual server is not enrolled for this target")
    if source_address is not None:
        # The client filter is an enrolled address or a prefix inside an enrolled lookup prefix, as for FortiOS.
        from .read_policy import enrolled_lookup
        try:
            enrolled_lookup(source_address, 4, auth.read_inventory)
        except ValueError:
            raise ValueError("client source_address is not enrolled for this target") from None


def _clean(text):
    if not isinstance(text, str):
        raise ValueError("FortiADC diagnostic response is invalid")
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _is_refusal(text):
    cleaned = _clean(text)
    return (cleaned.casefold() == DISPLAY_REFUSAL.casefold()
            or cleaned.casefold().startswith("please input the subtype correctly\n")
            or CLI_REFUSAL.search(cleaned) is not None)


def _event_rows(text):
    rows = []
    unknown = False
    for row in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        if not row.strip():
            continue
        if row.strip().casefold() in FOOTERS:
            continue
        if RECORD_START.match(row):
            rows.append(row)
        else:
            unknown = True
    return rows, unknown


def _admin_log_record(row):
    # Usernames and message text can both contain credentials and field-like strings. Construct the response
    # from recognized fields. Require a unique login/logout structure for status and a full success match for user.
    stamp = RECORD_TIMESTAMP.match(row)[0]
    header = ADMIN_HEADER.match(row, len(stamp))
    if header is None:
        return stamp, {}
    prefix = f"{stamp} {header['kind']}"
    if header["msg_id"] is None:
        return prefix, {}
    prefix += f" {header['msg_id']}"
    user = ADMIN_USER.match(row, header.end())
    if user is None:
        return prefix, {}
    boundary = ADMIN_BOUNDARY.search(row, user.end())
    details = ADMIN_DETAILS.match(row, boundary.start()) if boundary else None
    if details is None or ADMIN_DETAILS.search(row, details.start("ui_kind")):
        return prefix, {}

    action, status = details["action"], details["status"]
    record = {"action": action, "status": status}
    metadata = stamp + " " + " ".join(header[0].split())
    success = ADMIN_SUCCESS.fullmatch(row, header.end())
    if success is not None:
        record["user"] = success["user"]
        metadata += f" user={success['user']}"
    if details["ui_kind"] in ("SSH", "HTTP", "HTTPS", "GUI"):
        try:
            host = ipaddress.ip_address(details["host"])
        except ValueError:
            pass
        else:
            # IPv6 scope IDs can carry arbitrary text and are unnecessary here.
            if getattr(host, "scope_id", None) is None:
                metadata += f" ui={details['ui_kind']}({host})"
    metadata += f" action={action} status={status}"
    if details["reason"].strip() == "none":
        metadata += " reason=none"
    return metadata, record


def _log_metadata(recipe, row):
    """Keep the diagnostic metadata and withhold request data and configuration values."""
    boundary = END_OF_METADATA.get(recipe)
    if boundary is None:
        return row
    metadata = boundary.split(row, maxsplit=1)[0]
    if recipe == "slb_http_traffic_logs":
        # Fortinet's documented HTTP layout puts the return code after the request fields and the server last.
        tail = row[len(metadata):]
        before_server, _, server = tail.rpartition(" real_server=")
        _, _, after_return_code = before_server.rpartition(" http_retcode=")
        code = after_return_code.partition(" ")[0]
        if re.fullmatch(r"[0-9]{3}", code):
            metadata += f" http_retcode={code}"
        if VIRTUAL_SERVER.fullmatch(server):
            metadata += f" real_server={server}"
    if recipe == "configuration_event_logs":
        obj = SLB_CONFIG_OBJECT.search(row)
        if obj:
            metadata = metadata.removesuffix(" cfgobj=name") + f" cfgobj={obj[1]}"
    return metadata


def _record_matches(row, since, until, virtual_server, source_address):
    timestamp = RECORD_TIMESTAMP.match(row)
    stamp = f"{timestamp[1]} {timestamp[2]}"
    if (since is not None and stamp < since) or (until is not None and stamp > until):
        return False
    if not virtual_server and source_address is None:
        return True
    fields = list(LOG_FIELD.finditer(row))
    values = {
        key[1]: row[key.end():fields[index + 1].start() if index + 1 < len(fields) else len(row)].strip()
        for index, key in enumerate(fields) if key[1] in ("policy", "src")
    }
    return ((not virtual_server or values.get("policy") == virtual_server)
            and (source_address is None or values.get("src") == source_address))


def _filter_values(text):
    values = {}
    for row in _clean(text).splitlines():
        if not row.strip():
            continue
        key, separator, value = row.partition(":")
        key = key.strip()
        if not separator or key in values:
            raise ValueError("FortiADC filter readback is not recognized")
        values[key] = value.strip()
    return values


def _state_filter(family, flag, virtual_server="any", client=None):
    expected = {key: "any" for key in STATE_FIELDS[family]}
    expected["filter flag"] = flag
    expected["virtual server"] = virtual_server
    if client is not None:
        expected["source ip range"] = "%s - %s" % client
    return expected


def parse_rows(family, lines):
    """Rows of a session/persistence list as dicts; None when any row has another shape (nothing is guessed)."""
    import ipaddress
    fields = ROW_FIELDS[family]
    rows = []
    for line in lines:
        words = line.split()
        if len(words) != len(fields):
            return None
        row = dict(zip(fields, words))
        try:
            for key in _INTEGER_FIELDS & set(row):
                if not words[fields.index(key)].isdigit():
                    raise ValueError
                row[key] = int(row[key])
            for key in _ADDRESS_FIELDS:
                ipaddress.ip_address(row[key])
        except ValueError:
            return None
        rows.append(row)
    return rows


def _rows_match(rows, virtual_server, client):
    """Every row belongs to the selected virtual server and, with a client filter, to the client range."""
    import ipaddress
    low, high = (ipaddress.ip_address(client[0]), ipaddress.ip_address(client[1])) if client else (None, None)
    for row in rows:
        if row["virtual_server"] != virtual_server:
            return False
        if client is not None:
            address = ipaddress.ip_address(row["client_ip"])
            if address.version != 4 or not low <= address <= high:
                return False
    return True


def _bounded(shell, timeout, command=DISPLAY):
    fired = threading.Event()

    def interrupt():
        fired.set()
        try:
            shell.interrupt()
        except Exception:
            pass

    timer = threading.Timer(timeout, interrupt)
    timer.daemon = True
    timer.start()
    try:
        return shell.command(command, timeout + 3), fired.is_set()
    finally:
        timer.cancel()
        timer.join()


def _display_page(shell, start_line, timeout):
    command = f"execute log display {start_line}"
    deadline = time.monotonic() + timeout
    for attempt in range(2):
        response, timed_out = _bounded(shell, max(0, deadline - time.monotonic()), command)
        if timed_out or _clean(response).casefold() not in SEARCH_PENDING:
            return response, timed_out
        remaining = deadline - time.monotonic()
        if attempt or remaining <= 0.5:
            return response, False
        time.sleep(0.5)


def _restore(shell, baseline_show, baseline_display, *, verify_display=True):
    clear_ok = False
    show_ok = False
    display_ok = False
    if not getattr(shell, "ready", True):
        return False
    try:
        clear_ok = not _is_refusal(shell.command(CLEAR))
    except Exception:
        pass
    if not getattr(shell, "ready", True):
        return False
    try:
        show_ok = _clean(shell.command(SHOW)) == baseline_show
    except Exception:
        pass
    if not verify_display:
        return clear_ok and show_ok
    if not getattr(shell, "ready", True):
        return False
    try:
        display_readback = _clean(shell.command(DISPLAY))
        display_ok = _is_refusal(display_readback) and display_readback == baseline_display
    except Exception:
        pass
    return clear_ok and show_ok and display_ok


def run(shell, count, timeout, *, recipe=RECIPE, reconnect=None, start_line=0,
        since=None, until=None, virtual_server="", source_address=None):
    from .config_fortiadc import verify_identity

    log_type, log_subtype = RECIPES[recipe]
    admin_log = recipe == "admin_event_logs"
    # startup (H12): verify_identity refuses only an unreadable identity or another product; the caller reports a model
    # or build outside config_fortiadc.TESTED in firmware_support with a warning.
    identity = verify_identity(shell.command(GET_STATUS))[0]
    baseline_show = _clean(shell.command(SHOW))
    if baseline_show:
        raise ValueError("an existing FortiADC log filter cannot be replaced")
    baseline_display = _clean(shell.command(DISPLAY))
    if baseline_display.casefold() != DISPLAY_REFUSAL.casefold():
        raise ValueError("FortiADC display baseline did not match the empty-filter refusal")

    mutation_attempted = False
    timed_out = False
    state = "incomplete"
    full_text = ""
    selected_text = ""
    rows = []
    admin_records = []
    matches = []
    unknown = False
    cleanup_verified = True

    try:
        mutation_attempted = True
        step_text = shell.command(f"execute log filter type {log_type}")
        if _is_refusal(step_text):
            if not admin_log:
                full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the fixed {log_type} filter")
        step_text = shell.command(f"execute log filter subtype {log_subtype}")
        if _is_refusal(step_text):
            if not admin_log:
                full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the fixed {log_subtype} subtype")
        if _clean(step_text) not in ("", f"type#{log_type}\nsubtype#{log_subtype}"):
            raise ValueError("FortiADC did not echo the requested log filter")
        display, timed_out = _display_page(shell, start_line, timeout)
        if _is_refusal(display):
            if not admin_log:
                full_text = _clean(display)
            state = "device_refused"
        else:
            rows, unknown = _event_rows(display)
            if admin_log:
                safe_rows = [_admin_log_record(row) for row in rows]
                rows = [line for line, _ in safe_rows]
            else:
                rows = [_log_metadata(recipe, row) for row in rows]
            # A bare "begin to search logs" is also emitted while opening a log and does not prove an empty page.
            end_seen = _clean(display).splitlines()[-1:] == [DISPLAY_END]
            if not timed_out and not unknown and end_seen and 0 < len(rows) <= LOG_PAGE_SIZE:
                full_text = "\n".join(rows)
                matches = [index for index, row in enumerate(rows)
                           if _record_matches(row, since, until, virtual_server, source_address)]
                state = "data"
                selected_text = "\n".join(rows[index] for index in matches[:count])
                if admin_log:
                    admin_records = [(start_line + index, safe_rows[index][1]) for index in matches[:count]]
    except Exception:
        if state != "device_refused":
            state = "incomplete"
    finally:
        if mutation_attempted:
            cleanup_verified = _restore(shell, baseline_show, baseline_display)
            if not cleanup_verified and reconnect is not None:
                try:
                    with reconnect() as repair:
                        repair_identity = verify_identity(repair.command(GET_STATUS))[0]
                        if repair_identity == identity:
                            cleanup_verified = _restore(repair, baseline_show, baseline_display, verify_display=False)
                except Exception:
                    cleanup_verified = False
            if not cleanup_verified:
                state = "incomplete"

    next_start_line = None
    page_read = state == "data"
    count_truncated = page_read and len(matches) > count
    if page_read:
        if count_truncated:
            next_start_line = start_line + matches[count]
        elif len(rows) == LOG_PAGE_SIZE:
            next_start_line = start_line + len(rows)
        if next_start_line is not None:
            state = "more_pages"
            if next_start_line > MAX_START_LINE:
                next_start_line = None
    result = {
        "state": state,
        "ok": state in ("data", "more_pages") and cleanup_verified and not timed_out,
        "output": selected_text if page_read else full_text if state == "device_refused" else "",
        "raw_output": full_text,
        "line_count": len(selected_text.splitlines()) if page_read else 0,
        "identity": identity,
        "timed_out": timed_out,
        "cleanup": "verified" if cleanup_verified else "unverified",
        "loaded_records": len(rows),
        "returned_records": min(len(matches), count) if page_read else 0,
        "count_truncated": count_truncated,
        "next_start_line": next_start_line,
        "unrecognized_body": unknown,
    }
    if admin_log:
        result["admin_records"] = admin_records if page_read else []
    return result


def _restore_state(shell, clear, show, baseline_show):
    if not getattr(shell, "ready", True):
        return False
    try:
        if _is_refusal(shell.command(clear)):
            return False
    except Exception:
        return False
    if not getattr(shell, "ready", True):
        return False
    try:
        return _clean(shell.command(show)) == baseline_show
    except Exception:
        return False


def run_state_list(shell, recipe, virtual_server, count, timeout, *, reconnect=None, source_address=None):
    from .config_fortiadc import verify_identity

    family = STATE_RECIPES[recipe]
    if VIRTUAL_SERVER.fullmatch(virtual_server) is None:
        raise ValueError(f"{recipe} takes an enrolled virtual server name")
    client = client_range(source_address) if source_address is not None else None
    prefix = f"diagnose server-load-balance {family}"
    show = f"{prefix} filter show"
    if client is None:
        select = f"{prefix} filter 'vs-name {virtual_server}'"
        expected = _state_filter(family, FLAG_VIRTUAL_SERVER, virtual_server)
    else:
        source = client[0] if client[0] == client[1] else "%s %s" % client
        select = f"{prefix} filter 'vs-name {virtual_server} source-ip {source}'"
        expected = _state_filter(family, FLAG_VIRTUAL_SERVER_SOURCE, virtual_server, client)
    listing = f"{prefix} list"
    clear = f"{prefix} filter clear"
    identity = verify_identity(shell.command(GET_STATUS))[0]  # startup: untested builds are reported, not refused
    baseline_show = _clean(shell.command(show))
    if _filter_values(baseline_show) != _state_filter(family, "0"):
        raise ValueError(f"an existing FortiADC {family} filter is set; it is not replaced")

    timed_out = False
    state = "incomplete"
    full_text = ""
    selected_text = ""
    rows = []
    records = []
    mismatch = False
    unknown = False
    cleanup_verified = True

    try:
        step_text = shell.command(select)
        if _is_refusal(step_text) or FILTER_REFUSAL.search(_clean(step_text)):
            full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the {family} filter")
        if _filter_values(shell.command(show)) != expected:
            raise ValueError(f"FortiADC {family} filter readback did not select exactly the requested filter")
        full_text, timed_out = _bounded(shell, timeout, listing)
        full_text = full_text.replace("\r\n", "\n").replace("\r", "\n")
        if _is_refusal(full_text):
            state = "device_refused"
        else:
            lines = [row for row in full_text.splitlines() if row.strip()]
            unknown = not lines or lines[0].strip() != LIST_HEADERS[family]
            parsed = None if unknown else parse_rows(family, lines[1:])
            unknown = unknown or parsed is None
            if not unknown and not _rows_match(parsed, virtual_server, client):
                # A row outside the read-back filter: the list is not what was selected; nothing is returned.
                mismatch = True
            elif not timed_out and not unknown and "--More--" not in full_text:
                rows = lines[1:]
                records = parsed
                state = "data"
                selected_text = "\n".join(lines[:1] + rows[:count])
    except Exception:
        if state != "device_refused":
            state = "incomplete"
    finally:
        cleanup_verified = _restore_state(shell, clear, show, baseline_show)
        if not cleanup_verified and reconnect is not None:
            try:
                with reconnect() as repair:
                    if verify_identity(repair.command(GET_STATUS))[0] == identity:
                        cleanup_verified = _restore_state(repair, clear, show, baseline_show)
            except Exception:
                cleanup_verified = False
        if not cleanup_verified:
            state = "incomplete"

    return {
        "state": state,
        "ok": state == "data" and cleanup_verified and not timed_out,
        "output": selected_text if state == "data" else full_text,
        "raw_output": full_text,
        "identity": identity,
        "timed_out": timed_out,
        "cleanup": "verified" if cleanup_verified else "unverified",
        "virtual_server": virtual_server,
        "source_address": source_address,
        "filter_mismatch": mismatch,
        "records": records[:count] if state == "data" else [],
        "loaded_records": len(rows),
        "returned_records": min(len(rows), count) if state == "data" else 0,
        "count_truncated": state == "data" and len(rows) > count,
        "header_only": state == "data" and not rows,
        "unrecognized_body": unknown,
    }


def standby_status(text, *, complete=True):
    """Interpret only the measured 7.6.7 set/unset status replies, never infer a role."""
    match = re.fullmatch(r"HA failover-standby is (set|unset)\.", _clean(text)) if complete else None
    if match is None:
        return {"status": "incomplete"}
    return {"status": "complete", "forced_standby": match.group(1) == "set"}


# --- adc objects ADC-firewall routing: bounded packet capture (`diagnose sniffer packet`) ----------------------------------------------
# Measured on FortiADC-KVM 7.6.7 build0676 (FortiADC-KVM 7.6.7, 2026-11-17, verification): the syntax is
# `diagnose sniffer packet <interface> '<filter>' <verbose> <count> [a]`. Verbose 4 prints one header line per packet
# with the interface name and no payload; `a` prints absolute UTC time. The answer starts with `interfaces=[...]` and
# `filters=[...]`; when the count is reached the capture ends without a summary, an interrupt (Ctrl-C) ends it with
# `N packets received by filter` and `N packets dropped by kernel`. An unknown interface is answered with
# `pcap_open_live: ...`, an invalid filter with `pcap_compile: ...`; a profile without diagnose (read-only) with
# `Parsing error at 'sniffer'` and return code -284. Ctrl-C at an idle prompt makes the appliance print `exit` and
# close the session, so nothing is sent after the capture.
PACKET_CAPTURE = "packet_capture"
CAPTURE_MAX_PACKETS = 50
CAPTURE_MAX_SECONDS = 30
CAPTURE_VERBOSE = 4
CAPTURE_LINE = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) (\S+) -- "
    r"(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d{1,5}))? -> (\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d{1,5}))?: (.*)"
)
CAPTURE_SUMMARY = re.compile(r"(\d+) packets (received by filter|dropped by kernel)")
CAPTURE_DEVICE_REFUSAL = re.compile(r"(?m)^[ \t]*pcap_(?:open_live|compile): [^\r\n]*$")
CAPTURE_NOT_PERMITTED = (
    "The FortiADC account profile has no diagnose commands (the device rejected 'sniffer' with return code -284); "
    "packet_capture needs a system administrator account for this target, or remove packet_capture from "
    "diagnostic_recipes"
)


def _capture_ipv4(value, name):
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        address = None
    if (address is None or str(address) != value or address.is_multicast or address.is_unspecified
            or address.is_loopback or int(address) == 0xFFFFFFFF):
        raise ValueError(f"packet_capture {name} must be one canonical unicast IPv4 address")


def capture_filter(address, source_address=None, port=None):
    """The fixed capture filter: one host (client, virtual server or backend), optionally the pair of two hosts
    (client and virtual server, or appliance and backend) and one TCP/UDP port; nothing else reaches the device."""
    text = "host " + address if source_address is None else "host " + source_address + " and host " + address
    if port is not None:
        text += " and port " + str(port)
    return text


def validate_capture(address, interface, count, timeout, max_bytes, source_address=None, port=None):
    from .read_policy import validate_inventory_item
    _capture_ipv4(address, "address")
    if source_address is not None:
        _capture_ipv4(source_address, "source_address")
        if source_address == address:
            raise ValueError("packet_capture source_address must differ from address")
    try:
        if not isinstance(interface, str) or validate_inventory_item("interfaces", interface) != interface:
            raise ValueError
    except ValueError:
        raise ValueError("packet_capture requires one enrolled FortiADC interface name") from None
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("packet_capture destination_port must be a whole number from 1 to 65535")
    if type(count) is not int or not 1 <= count <= CAPTURE_MAX_PACKETS:
        raise ValueError(f"packet_capture count must be between 1 and {CAPTURE_MAX_PACKETS} packets")
    if type(timeout) is not int or not 1 <= timeout <= CAPTURE_MAX_SECONDS:
        raise ValueError(f"packet_capture timeout must be between 1 and {CAPTURE_MAX_SECONDS} seconds")
    if type(max_bytes) is not int or not 1000 <= max_bytes <= 16384:
        raise ValueError("packet_capture output limit must be between 1000 and 16384 bytes")


def authorize_capture(auth, address, interface, source_address=None):
    from .read_policy import enrolled_lookup
    auth.require_ssh_query("fortiadc", "system_status")
    if PACKET_CAPTURE not in auth.read_inventory.get("diagnostic_recipes", ()):
        raise ValueError("diagnostic recipe is not enrolled for this target")
    if interface not in auth.read_inventory.get("interfaces", ()):
        raise ValueError("capture interface is not enrolled for this target")
    for value in (address, source_address):
        if value is None:
            continue
        try:
            enrolled_lookup(value, 4, auth.read_inventory)
        except ValueError:
            raise ValueError("capture address is not enrolled for this target") from None


def parse_capture(text, interface, selector, hosts, port, count):
    """The packets of one capture answer; anything not measured makes it unrecognized, nothing is guessed."""
    lines = [line.rstrip() for line in _clean(text).splitlines()]
    result = {"packets": [], "records": [], "received": None, "dropped": None, "unrecognized": False,
              "header": False, "discarded_lines": 0, "interrupted": False}
    body = [line for line in lines if line.strip()]
    if body[:2] == ["interfaces=[%s]" % interface, "filters=[%s]" % selector]:
        result["header"] = True
        body = body[2:]
    seen_packets = 0
    for line in body:
        packet = CAPTURE_LINE.fullmatch(line)
        summary = CAPTURE_SUMMARY.fullmatch(line.strip())
        if packet:
            seen_packets += 1
            if result["received"] is not None or result["dropped"] is not None:
                result["unrecognized"] = True
            stamp, seen, source, source_port, destination, destination_port, detail = packet.groups()
            source_port = int(source_port) if source_port else None
            destination_port = int(destination_port) if destination_port else None
            if (seen_packets > count or seen != interface or not hosts <= {source, destination}
                    or (port is not None and port not in (source_port, destination_port))):
                result["discarded_lines"] += 1
                continue
            result["packets"].append(line)
            result["records"].append({
                "time_utc": stamp, "interface": seen, "source": source,
                "source_port": source_port, "destination": destination,
                "destination_port": destination_port, "detail": detail,
            })
        elif line.strip() == "^C":
            result["interrupted"] = True
        elif summary is not None:
            key = "received" if summary[2] == "received by filter" else "dropped"
            if result[key] is not None:
                result["unrecognized"] = True
            result[key] = int(summary[1])
        else:
            result["unrecognized"] = True
    return result


def _capture_bounded(shell, timeout, command):
    """Send the capture and interrupt it at the deadline only while it still runs (an idle Ctrl-C closes the session)."""
    fired = threading.Event()

    def interrupt():
        if getattr(shell, "ready", False):
            return
        fired.set()
        try:
            shell.interrupt()
        except Exception:
            pass

    timer = threading.Timer(timeout, interrupt)
    timer.daemon = True
    timer.start()
    try:
        return shell.command(command, timeout + 5), fired.is_set()
    finally:
        timer.cancel()
        timer.join()


def run_capture(shell, interface, address, count, timeout, *, source_address=None, port=None):
    from .config_fortiadc import verify_identity

    identity = verify_identity(shell.command(GET_STATUS))[0]
    selector = capture_filter(address, source_address, port)
    command = "diagnose sniffer packet %s '%s' %d %d a" % (interface, selector, CAPTURE_VERBOSE, count)
    answer = {"identity": identity, "command": command, "filter": selector, "timed_out": False, "packets": [],
              "records": [], "received": None, "dropped": None, "unrecognized_body": False, "discarded_lines": 0}
    text, timed_out = _capture_bounded(shell, timeout, command)
    answer["timed_out"] = timed_out
    hosts = {address} if source_address is None else {address, source_address}
    parsed = parse_capture(text, interface, selector, hosts, port, count)
    if not parsed["packets"] and not parsed["discarded_lines"]:
        if diagnose_refused(command, text):
            answer.update(state="permission_denied", raw_output=_RETURN_284.search(text)[0].strip())
            return answer
        if CAPTURE_DEVICE_REFUSAL.search(text) or _is_refusal(text):
            refusal_lines = {
                f"interfaces=[{interface}]", f"filters=[{selector}]",
                f"pcap_open_live: {interface}: No such device exists (SIOCGIFHWADDR: No such device) for {interface}",
                "pcap_compile: can't parse filter expression: syntax error",
            }
            answer.update(state="device_refused",
                          raw_output="\n".join(line for line in _clean(text).splitlines() if line in refusal_lines))
            return answer
    answer.update(packets=parsed["packets"], records=parsed["records"], received=parsed["received"],
                  dropped=parsed["dropped"], raw_output="\n".join(parsed["packets"]),
                  unrecognized_body=parsed["unrecognized"], discarded_lines=parsed["discarded_lines"])
    counters = (parsed["received"], parsed["dropped"])
    complete_count = (not timed_out and not parsed["interrupted"] and len(parsed["packets"]) == count
                      and counters == (None, None))
    deadline = timed_out and parsed["interrupted"] and None not in counters
    if parsed["received"] and not parsed["packets"]:
        answer["capture_summary"] = (
            f"the device reported {parsed['received']} packets received by the filter, but no packet lines were retained"
        )
        deadline = False
    elif timed_out and None in counters:
        answer["capture_summary"] = "the capture deadline expired without both device packet counters"
    if (not parsed["header"] or parsed["unrecognized"] or parsed["discarded_lines"]
            or not (complete_count or deadline)):
        answer["state"] = "incomplete"
    else:
        answer["state"] = "count_reached" if complete_count else "deadline_reached"
    return answer
