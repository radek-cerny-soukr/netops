from __future__ import annotations

import re
import threading

RECIPE = "system_event_logs"
RECIPES = {
    "system_event_logs": ("event", "system"),
    "waf_attack_logs": ("attack", "waf"),
}
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
GET_STATUS = "get system status"
SHOW = "execute log filter show"
DISPLAY = "execute log display 0"
CLEAR = "execute log filter clear"
DISPLAY_REFUSAL = "Please set filter type and subtype firstly"
FOOTERS = frozenset({
    "begin to search logs",
    "display 20 lines log messages one time at most,you can tune the starline if you want to see more logs",
})
RECORD_START = re.compile(r"^date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2}(?: |$)")
CLI_REFUSAL = re.compile(
    r"(?mi)^[ \t]*(?:Command fail\. Return code is [+-]?\d+ \([^()\r\n]+\)"
    r"|command parse error[^\r\n]*|unknown action[^\r\n]*|permission denied[^\r\n]*)[ \t]*\r?$"
)


def validate(recipe, address, interface, count, timeout, max_bytes):
    if recipe in STATE_RECIPES:
        if not isinstance(address, str) or VIRTUAL_SERVER.fullmatch(address) is None or interface != "":
            raise ValueError(f"{recipe} takes an enrolled virtual server name and an empty interface")
        if type(count) is not int or not 1 <= count <= 50:
            raise ValueError(f"{recipe} count must be between 1 and 50")
        if type(timeout) is not int or not 1 <= timeout <= 10:
            raise ValueError(f"{recipe} timeout must be between 1 and 10 seconds")
        if type(max_bytes) is not int or not 1000 <= max_bytes <= 16384:
            raise ValueError(f"{recipe} output limit must be between 1000 and 16384 bytes")
        return
    if recipe not in RECIPES:
        raise ValueError("unknown FortiADC diagnostic recipe")
    if address != "" or interface != "":
        raise ValueError(f"{recipe} takes empty address and interface")
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError(f"{recipe} count must be between 1 and 20")
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise ValueError(f"{recipe} timeout must be between 1 and 20 seconds")
    if type(max_bytes) is not int or not 1000 <= max_bytes <= 16384:
        raise ValueError(f"{recipe} output limit must be between 1000 and 16384 bytes")


def authorize(auth, recipe, address=""):
    if recipe not in RECIPES and recipe not in STATE_RECIPES:
        raise ValueError("unknown FortiADC diagnostic recipe")
    auth.require_ssh_query("fortiadc", "system_status")
    if recipe not in auth.read_inventory.get("diagnostic_recipes", ()):
        raise ValueError("diagnostic recipe is not enrolled for this target")
    if recipe in STATE_RECIPES and address not in auth.read_inventory.get("diagnostic_virtual_servers", ()):
        raise ValueError("virtual server is not enrolled for this target")


def _clean(text):
    if not isinstance(text, str):
        raise ValueError("FortiADC diagnostic response is invalid")
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _is_refusal(text):
    cleaned = _clean(text)
    return cleaned.casefold() == DISPLAY_REFUSAL.casefold() or CLI_REFUSAL.search(cleaned) is not None


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


def _state_filter(family, flag, virtual_server="any"):
    expected = {key: "any" for key in STATE_FIELDS[family]}
    expected["filter flag"] = flag
    expected["virtual server"] = virtual_server
    return expected


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


def _restore(shell, baseline_show, baseline_display):
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
    if not getattr(shell, "ready", True):
        return False
    try:
        display_readback = _clean(shell.command(DISPLAY))
        display_ok = _is_refusal(display_readback) and display_readback == baseline_display
    except Exception:
        pass
    return clear_ok and show_ok and display_ok


def run(shell, count, timeout, *, recipe=RECIPE, reconnect=None):
    from .config_fortiadc import verify_identity

    log_type, log_subtype = RECIPES[recipe]
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
    unknown = False
    cleanup_verified = True

    try:
        mutation_attempted = True
        step_text = shell.command(f"execute log filter type {log_type}")
        if _is_refusal(step_text):
            full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the fixed {log_type} filter")
        step_text = shell.command(f"execute log filter subtype {log_subtype}")
        if _is_refusal(step_text):
            full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the fixed {log_subtype} subtype")
        full_text, timed_out = _bounded(shell, timeout)
        full_text = full_text.replace("\r\n", "\n").replace("\r", "\n")
        if _is_refusal(full_text):
            state = "device_refused"
        else:
            rows, unknown = _event_rows(full_text)
            if timed_out or unknown or not rows or len(rows) > 20:
                state = "incomplete"
            else:
                state = "data"
                selected_text = "\n".join(rows[:count])
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
                            cleanup_verified = _restore(repair, baseline_show, baseline_display)
                except Exception:
                    cleanup_verified = False
            if not cleanup_verified:
                state = "incomplete"

    return {
        "state": state,
        "ok": state == "data" and cleanup_verified and not timed_out,
        "output": selected_text if state == "data" else full_text,
        "raw_output": full_text,
        "line_count": len((selected_text if state == "data" else full_text).splitlines()),
        "identity": identity,
        "timed_out": timed_out,
        "cleanup": "verified" if cleanup_verified else "unverified",
        "loaded_records": len(rows),
        "returned_records": min(len(rows), count) if state == "data" else 0,
        "count_truncated": state == "data" and len(rows) > count,
        "unrecognized_body": unknown,
    }


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


def run_state_list(shell, recipe, virtual_server, count, timeout, *, reconnect=None):
    from .config_fortiadc import verify_identity

    family = STATE_RECIPES[recipe]
    if VIRTUAL_SERVER.fullmatch(virtual_server) is None:
        raise ValueError(f"{recipe} takes an enrolled virtual server name")
    prefix = f"diagnose server-load-balance {family}"
    show = f"{prefix} filter show"
    select = f"{prefix} filter 'vs-name {virtual_server}'"
    listing = f"{prefix} list"
    clear = f"{prefix} filter clear"
    identity = verify_identity(shell.command(GET_STATUS))[0]
    baseline_show = _clean(shell.command(show))
    if _filter_values(baseline_show) != _state_filter(family, "0"):
        raise ValueError(f"an existing FortiADC {family} filter is set; it is not replaced")

    timed_out = False
    state = "incomplete"
    full_text = ""
    selected_text = ""
    rows = []
    unknown = False
    cleanup_verified = True

    try:
        step_text = shell.command(select)
        if _is_refusal(step_text):
            full_text = step_text
            state = "device_refused"
            raise ValueError(f"FortiADC refused the {family} virtual server filter")
        if _filter_values(shell.command(show)) != _state_filter(family, "1000", virtual_server):
            raise ValueError(f"FortiADC {family} filter readback did not select only the virtual server")
        full_text, timed_out = _bounded(shell, timeout, listing)
        full_text = full_text.replace("\r\n", "\n").replace("\r", "\n")
        if _is_refusal(full_text):
            state = "device_refused"
        else:
            lines = [row for row in full_text.splitlines() if row.strip()]
            unknown = not lines or lines[0].strip() != LIST_HEADERS[family]
            if not timed_out and not unknown and "--More--" not in full_text:
                rows = lines[1:]
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
        "loaded_records": len(rows),
        "returned_records": min(len(rows), count) if state == "data" else 0,
        "count_truncated": state == "data" and len(rows) > count,
        "header_only": state == "data" and not rows,
        "unrecognized_body": unknown,
    }
