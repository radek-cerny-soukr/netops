from __future__ import annotations

from datetime import datetime
import ipaddress
import re
import threading

from .read_policy import _canonical_fortios_interface

RECIPES = frozenset({"ping", "traceroute", "sniffer", "sessions", "flow", "logs"})
IDENTITIES = frozenset({
    ("FortiGate-VM64", "8.0.2", "0251"),
    ("FortiGate-VM64-KVM", "7.6.7", "3704"),
    ("FortiGate-VM64-KVM", "8.0.0", "0167"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
TUPLE_IDENTITIES = frozenset({
    ("FortiGate-VM64", "8.0.2", "0251"),
    ("FortiGate-60F", "7.6.8", "3744"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
RANGE_TUPLE_IDENTITIES = frozenset({("FortiGate-60F", "7.6.8", "3744")})
# IP prefix operands: existing 60F range grammar and the 80F probe of 2026-11-09.
PREFIX_RANGE_IDENTITIES = RANGE_TUPLE_IDENTITIES | frozenset({("FortiGate-80F", "8.0.2", "0251")})
TIMESTAMP_IDENTITIES = frozenset({
    ("FortiGate-VM64", "8.0.2", "0251"),
    ("FortiGate-60F", "7.6.8", "3744"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
REFUSAL = re.compile(r"(?mi)^(?:Command fail\.|command parse error|Unknown action|Permission denied)")
SESSION_FIELDS = frozenset({
    "vd", "sintf", "dintf", "proto", "proto-state", "source ip", "NAT'd source ip",
    "dest ip", "source port", "NAT'd source port", "dest port", "policy id",
    "expire", "duration", "state1", "state2",
})
FLOW_FIELDS = frozenset({"vf", "proto", "Host addr", "Host saddr", "Host daddr", "port", "sport", "dport"})
VDOM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}")
VDOM_MODES = {"Virtual domain configuration: disable": "disable",
              "Virtual domain configuration: multiple": "multiple"}


ADC_RECIPES = {"ping": "execute ping ", "traceroute": "execute traceroute ", "nslookup": "execute nslookup name ",
               "http_probe": "execute curl ", "health_check_verify": "execute health-check-verify health-check "}
ADC_TARGETS = {"nslookup": "diagnostic_names", "http_probe": "diagnostic_http_endpoints"}
ADC_HOST_EGRESS = {"ping": "require_icmp", "nslookup": "require_dns"}
ADC_PING_PACKETS = 5
LOG_FILTER_FIELDS = frozenset({
    "category", "device", "start-line", "view-lines", "max-checklines", "HA member",
    "log search mode", "pre-fetch-pages", "Oftp search string",
})


class UnsupportedPlatform(ValueError):
    pass


class ScopeRefused(ValueError):
    pass


class OptionRefused(ValueError):
    pass


REFUSABLE_OPTIONS = {
    "interface": "be bound to the enrolled interface",
    "device": "be bound to the enrolled interface",
    "source": "use the automatic source address",
}


class RestoreUnverified(ValueError):
    pass


class StepRefused(ValueError):
    def __init__(self, output):
        super().__init__("the device refused a diagnostic step")
        self.output = output


def status_identity(text):
    from .schema_read import CURRENT_VDOM
    from netops_core import platforms
    if (not isinstance(text, str) or len(text.encode("utf-8")) > 65536 or
            any(ord(c) < 32 and c not in "\n\r\t" for c in text) or "\ufffd" in text):
        raise ValueError("the diagnostic identity response is invalid")
    try:
        identity = platforms.version_record(text)
    except platforms.VersionRecordError:
        raise ValueError("one exact diagnostic identity is required") from None
    versions = [line for line in text.splitlines()
                if line.lstrip().casefold().startswith("version:")]
    domains = [value.strip() for value in CURRENT_VDOM.findall(text)]
    if len(versions) != 1:
        raise ValueError("one exact diagnostic identity is required")
    if len(domains) != 1 or not VDOM_NAME.fullmatch(domains[0]):
        raise UnsupportedPlatform("config_platform_not_supported: one verified current VDOM required")
    markers = [line for line in text.splitlines()
               if " ".join(line.split()).casefold().startswith("virtual domain configuration")]
    if len(markers) != 1 or markers[0] not in VDOM_MODES:
        raise UnsupportedPlatform("config_platform_not_supported: verified VDOM mode required")
    mode = VDOM_MODES[markers[0]]
    if mode == "disable" and domains != ["root"]:
        raise UnsupportedPlatform("config_platform_not_supported: verified root VDOM required")
    return identity, domains[0], mode


def _unicast_ipv4(address):
    if not isinstance(address, str):
        raise ValueError("a canonical unicast IPv4 address is required")
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        raise ValueError("a canonical unicast IPv4 address is required") from None
    if str(ip) != address or ip.is_multicast or ip.is_unspecified or int(ip) == 4294967295:
        raise ValueError("a canonical unicast IPv4 address is required")


def _filter_network(value, recipe):
    """The network of a canonical IPv4 prefix with unicast ends; only the sessions and flow filters take one."""
    from .read_policy import canonical_prefix
    if recipe not in ("sessions", "flow"):
        raise ValueError("a canonical unicast IPv4 address is required")
    try:
        network = canonical_prefix(value, 4)
    except ValueError:
        raise ValueError("a canonical unicast IPv4 prefix is required") from None
    for end in (network.network_address, network.broadcast_address):
        if end.is_multicast or end.is_unspecified or int(end) == 4294967295:
            raise ValueError("a canonical unicast IPv4 prefix is required")
    return network


def filter_operand(value):
    """The operand of a FortiOS session or flow filter: an address, or `first last` for a prefix."""
    if "/" not in value:
        return value
    network = ipaddress.IPv4Network(value)
    return str(network.network_address) + " " + str(network.broadcast_address)


def validate(recipe, address, interface, count, timeout, max_bytes, vdom=None, *,
             source_address=None, source_port=None, destination_port=None, protocol=None,
             any_source_port=False):
    if not isinstance(recipe, str) or recipe not in RECIPES:
        raise ValueError("unknown diagnostic recipe")
    if isinstance(address, str) and "/" in address:
        _filter_network(address, recipe)
    else:
        _unicast_ipv4(address)
    if not isinstance(interface, str) or _canonical_fortios_interface(interface) is None:
        raise ValueError("a concrete FortiOS interface is required")
    if vdom is not None and (not isinstance(vdom, str) or not VDOM_NAME.fullmatch(vdom)):
        raise ValueError("a valid VDOM name is required")
    tuple_values = (source_address, source_port, destination_port, protocol)
    if any_source_port and (recipe != "sessions" or source_port is not None or any(
            value is None for value in (source_address, destination_port, protocol))):
        raise ValueError("only the sessions recipe can leave the source port open, with the rest of the tuple")
    if any(value is not None for value in tuple_values):
        if recipe not in ("sessions", "sniffer", "flow") or any(
                value is None for value in (source_address, destination_port, protocol)) or (
                source_port is None and not any_source_port):
            raise ValueError("a complete TCP or UDP tuple is required")
        if isinstance(source_address, str) and "/" in source_address:
            _filter_network(source_address, recipe)
        else:
            try:
                source_ip = ipaddress.IPv4Address(source_address)
            except (ipaddress.AddressValueError, TypeError):
                raise ValueError("a canonical unicast IPv4 source address is required") from None
            if (str(source_ip) != source_address or source_ip.is_multicast or
                    source_ip.is_unspecified or int(source_ip) == 4294967295):
                raise ValueError("a canonical unicast IPv4 source address is required")
        if ((not any_source_port and (type(source_port) is not int or not 0 <= source_port <= 65535)) or
                type(destination_port) is not int or not 0 <= destination_port <= 65535 or
                type(protocol) is not int or protocol not in (6, 17)):
            raise ValueError("TCP or UDP session tuple fields are invalid")
    for value, low, high in ((count, 1, 3 if recipe == "traceroute" else 8),
                             (timeout, 1, 10), (max_bytes, 1000, 16000)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("diagnostic limits are invalid")


def authorize(auth, recipe, address, interface, vdom=None, *, source_address=None):
    auth.require_ssh_query("fortinet", "system_status")
    if not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified")
    if vdom is not None and vdom not in auth.read_inventory.get("diagnostic_vdoms",()):
        raise ValueError("diagnostic VDOM is not enrolled for this target")
    from .read_policy import enrolled_lookup
    for category, value in (("diagnostic_recipes", recipe), ("interfaces", interface)):
        if value not in auth.read_inventory.get(category, ()):
            raise ValueError("diagnostic scope is not enrolled for this target")
    for value in (address, source_address):
        if value is None:
            continue
        try:
            enrolled_lookup(value, 4, auth.read_inventory)
        except ValueError:
            raise ValueError("diagnostic scope is not enrolled for this target") from None


def fields(text):
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in result:
            raise ValueError("ambiguous diagnostic state")
        result[key] = value
    return result


def empty_filter(text, recipe):
    state = fields(text)
    if recipe == "sessions":
        if state.pop("session filter", None) != "":
            raise ValueError("an existing session filter cannot be replaced")
        extra = state.pop("ngfw id", "any")
        expected = SESSION_FIELDS
    else:
        extra = "any"
        expected = FLOW_FIELDS
    if set(state) != expected or extra != "any" or any(value != "any" for value in state.values()):
        raise ValueError("an existing diagnostic filter cannot be replaced")


SESSION_PATTERNS = (
    ("proto", r"\Asession info: proto=(\d+) "),
    ("proto_state", r"\A[^\n]* proto_state=(\d+) "),
    ("duration", r"\A[^\n]* duration=(\d+) "),
    ("expire", r"\A[^\n]* expire=(\d+) "),
    ("policy_id", r"(?m)^misc=\S+ policy_id=(\d+) "),
    ("dev", r"(?m)^orgin->sink: [^\n]* dev=(\d+->\d+/\d+->\d+) "),
    ("statistic", r"(?m)^statistic\(bytes/packets/allow_err\): (org=\d+/\d+/\d+ reply=\d+/\d+/\d+) "),
)
SESSION_HOOK = re.compile(r"(?m)^(hook=(?:pre|post) dir=(org|reply) act=(?:noop|snat|dnat) "
                          r"\d{1,3}(?:\.\d{1,3}){3}:\d+->\d{1,3}(?:\.\d{1,3}){3}:\d+"
                          r"\(\d{1,3}(?:\.\d{1,3}){3}:\d+\))[ \t]*$")
SESSION_TOTAL = re.compile(r"(?m)^total session:? (\d+)[ \t]*$")


def session_projection(text, count):
    blocks = re.split(r"(?m)^(?=session info:)", text)[1:]
    lines = []
    complete = True
    for block in blocks[:count]:
        values = {}
        missing = []
        for name, pattern in SESSION_PATTERNS:
            match = re.search(pattern, block)
            if match:
                values[name] = match.group(1)
            else:
                missing.append(name)
        head = ["session"] + [name + "=" + values[name] for name in
                              ("proto", "proto_state", "duration", "expire", "policy_id", "dev") if name in values]
        if "statistic" in values:
            head.append(values["statistic"])
        hooks = SESSION_HOOK.findall(block)
        if not any(direction == "org" for _, direction in hooks):
            missing.append("hook")
        lines.append(" ".join(head))
        lines.extend(line for line, _ in hooks)
        if missing:
            complete = False
            lines.append("incomplete=" + ",".join(missing))
    total = SESSION_TOTAL.search(blocks[-1] if blocks else text)
    if total:
        lines.append("total session: " + total.group(1))
    else:
        complete = False
        lines.append("incomplete=total")
    return "".join(line + "\n" for line in lines), complete, max(len(blocks) - count, 0)


def log_filter(text):
    state = fields(text)
    if set(state) != LOG_FILTER_FIELDS or not state["view-lines"].isdigit():
        raise ValueError("the current log filter is not a measured state")


LOG_FOUND = re.compile(r"(?m)^(\d+) logs found\.[ \t\r]*$")
LOG_RETURNED = re.compile(r"(?m)^(\d+) logs returned\.[ \t\r]*$")
LOG_TIME = re.compile(r"(?:^|\s)date=(\S+) time=(\S+)")


LOG_STAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")


def valid_log_stamp(value):
    if not isinstance(value, str) or not LOG_STAMP.fullmatch(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%d %H:%M:%S") == value


def log_window(recipe, since, until):
    if since is None and until is None:
        return None
    stamps = [value for value in (since, until) if value is not None]
    if recipe != "logs" or any(not valid_log_stamp(value) for value in stamps):
        raise ValueError("a log time window needs the logs recipe and a valid YYYY-MM-DD HH:MM:SS timestamp")
    if len(stamps) == 2 and since > until:
        raise ValueError("the log time window is reversed")
    return since, until


def log_read(output, baseline, address, count, window=None, timed_out=False):
    state = fields(baseline)
    result = {"state": "ok", "filter": state, "found": None, "returned": None, "loaded": None,
              "matched": None, "truncated": False, "time_range": None, "output": ""}
    if REFUSAL.search(output):
        result["state"] = "device_refused"
        return result
    if timed_out:
        result["state"] = "incomplete"
        return result
    found, returned = LOG_FOUND.search(output), LOG_RETURNED.search(output)
    if not found or not returned:
        result["state"] = "unsupported"
        return result
    result["found"], result["loaded"] = int(found.group(1)), int(returned.group(1))
    records = re.split(r"(?m)^(?=\d+: )", output)[1:]
    if result["loaded"] > result["found"]:
        result["state"] = "incomplete"
        return result
    if result["found"] == 0 and result["loaded"] == 0 and not records:
        result.update(state="empty", returned=0, matched=0)
        return result
    record_stamps = [LOG_TIME.search(record) for record in records]
    stamps = [" ".join(match.groups()) for match in record_stamps if match]
    if len(records) != result["loaded"] or len(stamps) != len(records) or any(
        not valid_log_stamp(stamp) for stamp in stamps
    ):
        result["state"] = "incomplete"
        return result
    stamps.sort()
    if stamps:
        result["time_range"] = [stamps[0], stamps[-1]]
    mark = re.compile(r"(?:^|\s)(?:srcip|dstip)=" + re.escape(address) + r"(?=\s|$)")
    since, until = window or (None, None)

    def inside(record):
        found = LOG_TIME.search(record)
        stamp = " ".join(found.groups()) if found else ""
        return (since is None or stamp >= since) and (until is None or "" < stamp <= until)

    matched = [record for record in records if mark.search(record) and inside(record)]
    kept = matched[:min(count, int(state["view-lines"]))]
    result.update(matched=len(matched), returned=len(kept), truncated=len(kept) < len(matched),
                  output="".join(kept))
    return result


def flow_filter(address, source_address=None, source_port=None, destination_port=None, protocol=None):
    if source_address is None:
        return "addr " + filter_operand(address) + " proto 1"
    return ("saddr " + filter_operand(source_address) + " sport " + str(source_port) + " daddr " + filter_operand(address) +
            " dport " + str(destination_port) + " proto " + str(protocol))


FLOW_TRACE_LINE = re.compile(
    r'(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?'
    r'id=\d+ trace_id=(\d+) (?:func=\S+ (?:line=\d+ )?)?msg="'
)


def flow_trace(output):
    traced = FLOW_TRACE_LINE.findall(output)
    return len(set(traced)), len(traced)


def _bounded(shell, command, timeout, grace=3):
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
        return (shell.listen(timeout + grace) if command is None else shell.command(command, timeout + grace)), fired.is_set()
    finally:
        timer.cancel()
        timer.join()


def _restore(shell, cleanup, display, baseline, recipe):
    errors = []
    for command in cleanup:
        try:
            shell.command(command)
        except Exception:
            errors.append(command)
    if display is not None and baseline is not None:
        try:
            if shell.command(display) != baseline:
                errors.append("state verification")
        except Exception:
            errors.append("state verification")
    if recipe == "flow" and "diagnose debug disable" in cleanup:
        try:
            if not re.search(r"(?mi)^debug output:[ \t]*disable[ \t]*$", shell.command("diagnose debug info")):
                errors.append("debug verification")
        except Exception:
            errors.append("debug verification")
    return not errors


def run(shell, recipe, address, interface, count, timeout, vdom=None, *, reconnect=None,
        source_address=None, source_port=None, destination_port=None, protocol=None, window=None,
        any_source_port=False):
    from netops_core import fortios
    identity, domain, mode = status_identity(shell.command("get system status"))
    if (recipe in ("sessions", "flow")
            and any(isinstance(value, str) and "/" in value for value in (address, source_address))
            and identity not in PREFIX_RANGE_IDENTITIES):
        raise OptionRefused("prefix_not_supported_on_identity: filter ranges are not measured for this hardware and build")
    if source_address is None:
        if identity not in IDENTITIES:
            raise ValueError("diagnostic recipes are not measured for this hardware and build")
    elif identity not in TUPLE_IDENTITIES:
        raise ValueError("TCP or UDP diagnostic tuples are not qualified for this hardware and build")
    if vdom is None and mode != "disable":
        raise UnsupportedPlatform("config_platform_not_supported: multi-VDOM diagnostics require an enrolled VDOM")
    if vdom is not None and vdom != domain:
        raise UnsupportedPlatform("config_platform_not_supported: the session is not scoped to the requested VDOM")
    try:
        interfaces=fortios.parse(shell.command('show full-configuration system interface "'+interface+'"')).section("system interface")
    except Exception:
        raise ValueError("the interface owner cannot be verified") from None
    owner = None
    if interfaces is not None and set(interfaces.entries)=={interface}:
        owner = interfaces.entries[interface].value("vdom")
    if owner is None:
        raise ValueError("the interface owner cannot be verified")
    if owner!=domain:
        raise ScopeRefused("the enrolled interface belongs to another VDOM")
    info = shell.command("diagnose netlink interface list " + interface)
    if not re.search(r"(?m)^if=" + re.escape(interface) + r"(?:\s|$)", info):
        raise ValueError("the enrolled interface is not visible in this session")
    cleanup = []
    baseline = None
    display = None
    try:
        if recipe in ("ping", "traceroute"):
            prefix = "execute " + recipe + "-options "
            display = prefix + "view-settings"
            baseline = shell.command(display)
            current = fields(baseline.split("Default Ping Options:", 1)[0])
            if recipe == "ping":
                settings = (("repeat-count", "Repeat Count", str(count)),
                            ("timeout", "Timeout", "1"), ("interval", "Interval", "1"),
                            ("data-size", "Data Size", "56"), ("adaptive-ping", "Adaptive Ping", "disable"),
                            ("interface", "Interface", interface), ("source", "Source Address", "auto"),
                            ("use-sdwan", "Use SD-WAN", "no"))
            else:
                settings = (("queries", "Number of probes per hop", str(count)),
                            ("device", "Device", interface), ("source", "Source Address", "auto"),
                            ("use-sdwan", "Use SD-WAN", "no"))
            for option, label, value in settings:
                previous = current.get(label)
                if previous is None or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", previous):
                    raise ValueError("diagnostic option state cannot be restored safely")
                if option == "source" and previous != "auto":
                    try:
                        ipaddress.IPv4Address(previous)
                    except ValueError:
                        raise ValueError("diagnostic source state is invalid") from None
                if option == "use-sdwan":
                    previous = {"no": "no", "disable": "no", "yes": "yes", "enable": "yes"}.get(previous)
                    if previous is None:
                        raise ValueError("diagnostic SD-WAN state is invalid")
                cleanup.insert(0, prefix + option + " " + previous)
                try:
                    shell.command(prefix + option + " " + value)
                except StepRefused as refusal:
                    if option not in REFUSABLE_OPTIONS or refusal.output != (
                            "command parse error before '" + option + "'\nCommand fail. Return code -61"):
                        raise
                    del cleanup[0]
                    prompt = getattr(shell, "prompt", b"")
                    secondary = isinstance(prompt, bytes) and re.search(rb"\(Secondary\) [#$] $", prompt)
                    where = "this HA secondary member" if secondary else "this session"
                    raise OptionRefused(
                        "FortiOS refused '" + prefix + option + "' on " + where + ", so " + recipe +
                        " could not " + REFUSABLE_OPTIONS[option] + " and was not run; the options it had set "
                        "were restored and verified." +
                        (" Run " + recipe + " on the HA primary." if where != "this session" else "")
                    ) from None
            command = "execute " + recipe + " " + address
        elif recipe == "sniffer":
            if source_address is None:
                selector = "host " + address + " and icmp"
            else:
                transport = "tcp" if protocol == 6 else "udp"
                selector = (transport + " and ((src host " + source_address +
                            " and src port " + str(source_port) + " and dst host " + address +
                            " and dst port " + str(destination_port) + ") or (src host " + address +
                            " and src port " + str(destination_port) + " and dst host " +
                            source_address + " and dst port " + str(source_port) + "))")
            command = 'diagnose sniffer packet ' + interface + ' "' + selector + '" 1 ' + str(count) + ' l'
        elif recipe == "logs":
            display = "execute log filter dump"
            baseline = shell.command(display)
            log_filter(baseline)
            command = "execute log display"
        else:
            if recipe == "flow":
                debug = shell.command("diagnose debug info")
                if not re.search(r"(?mi)^debug output:[ \t]*disable[ \t]*$", debug):
                    raise ValueError("active debugging cannot be replaced")
                if (identity not in TIMESTAMP_IDENTITIES
                        and re.search(r"(?mi)^console timestamp:[ \t]*enable[ \t]*$", debug)):
                    raise OptionRefused(
                        "FortiOS reports 'console timestamp: enable' in 'diagnose debug info', and the shape of "
                        "timestamped flow trace lines is not measured for this hardware and build; flow was not "
                        "run and nothing was changed. Run 'diagnose debug console timestamp disable' if that "
                        "console setting is not needed, or run the trace on the device.")
            display = "diagnose sys session filter" if recipe == "sessions" else "diagnose debug flow filter"
            baseline = shell.command(display)
            empty_filter(baseline, recipe)
            cleanup.append(display + " clear")
            if source_address is not None:
                for selector, value in (
                    ("src" if recipe == "sessions" else "saddr", source_address),
                    ("dst" if recipe == "sessions" else "daddr", address), ("sport", str(source_port)),
                    ("dport", str(destination_port)), ("proto", str(protocol)),
                ):
                    if any_source_port and selector == "sport":
                        continue
                    operand = filter_operand(value)
                    command_text = display + " " + selector + " " + operand
                    if (identity in RANGE_TUPLE_IDENTITIES and (recipe == "sessions" or selector != "proto")
                            and operand == value):
                        command_text += " " + value
                    shell.command(command_text)
            else:
                shell.command(display + (" dst " if recipe == "sessions" else " addr ") + filter_operand(address))
                shell.command(display + " proto 1")
            if recipe == "sessions":
                command = "diagnose sys session list"
            else:
                cleanup[0:0] = ["diagnose debug disable", "diagnose debug flow trace stop"]
                shell.command("diagnose debug flow trace start " + str(count))
                shell.command("diagnose debug enable")
                command = None
        output, timed_out = _bounded(shell, command, timeout)
        if recipe == "logs":
            output = log_read(output, baseline, address, count, window, timed_out)
        return output, timed_out, identity, domain
    finally:
        restored = _restore(shell, cleanup, display, baseline, recipe)
        if not restored:
            recovered = False
            if reconnect is not None and (cleanup or recipe == "logs"):
                try:
                    with reconnect() as repair:
                        repair_identity, repair_domain, repair_mode = status_identity(
                            repair.command("get system status")
                        )
                        if repair_identity == identity and repair_domain == domain and repair_mode == mode:
                            recovered = _restore(repair, cleanup, display, baseline, recipe)
                except Exception:
                    recovered = False
            if not recovered:
                raise RestoreUnverified("diagnostic state restoration could not be verified")


def adc_validate(recipe, address, interface, count, timeout, max_bytes, vdom=None, health_check=None):
    from .read_policy import validate_inventory_item
    if not isinstance(recipe, str) or recipe not in ADC_RECIPES:
        raise ValueError("unknown FortiADC diagnostic recipe")
    if recipe in ADC_TARGETS:
        try:
            if not isinstance(address, str) or validate_inventory_item(ADC_TARGETS[recipe], address) != address:
                raise ValueError
        except ValueError:
            raise ValueError("a canonical DNS name or HTTP endpoint is required") from None
    else:
        _unicast_ipv4(address)
    if vdom is not None:
        raise UnsupportedPlatform("config_platform_not_supported: VDOM selection is deferred")
    if recipe == "health_check_verify":
        try:
            if not isinstance(health_check, str) or validate_inventory_item("adc_health_checks", health_check) != health_check:
                raise ValueError
        except ValueError:
            raise ValueError("an enrolled FortiADC health check name is required") from None
        if interface != "" or type(count) is not int or not 1 <= count <= 5:
            raise ValueError("health_check_verify takes interface \"\" and count 1-5")
    elif interface != "" or type(count) is not int or count != 3 or health_check is not None:
        raise ValueError("FortiADC diagnostics take interface \"\" and count 3; ping always sends 5 packets")
    for value, low, high in ((timeout, 1, 60 if recipe in ("traceroute", "health_check_verify") else 10), (max_bytes, 1000, 16000)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("diagnostic limits are invalid")


def adc_authorize(auth, recipe, address, health_check=None):
    auth.require_ssh_query("fortiadc", "system_status")
    grants = [("diagnostic_recipes", recipe), (ADC_TARGETS.get(recipe, "addresses"), address)]
    if recipe == "health_check_verify":
        grants.append(("adc_health_checks", health_check))
    for name, value in grants:
        if value not in auth.read_inventory.get(name, ()):
            raise ValueError("diagnostic scope is not enrolled for this target")
    if recipe in ADC_HOST_EGRESS:
        getattr(auth, ADC_HOST_EGRESS[recipe])()


def adc_run(shell, recipe, address, timeout, count=3, health_check=None):
    from .config_fortiadc import verify_identity
    identity = verify_identity(shell.command("get system status"))[0]
    if recipe == "http_probe":
        current = fields(shell.command("execute curl-option view-settings").split("Default Curl Options:", 1)[0])
        if current.get("Header") != "auto" or current.get("Raw data") != "auto":
            raise ValueError("the appliance curl options add a header or body; http_probe needs Header and Raw data auto")
    if recipe == "health_check_verify":
        command = ADC_RECIPES[recipe] + health_check + " dest-address " + address + " count " + str(count)
    else:
        command = ADC_RECIPES[recipe] + address
    output, timed_out = _bounded(shell, command, timeout, 5)
    if timed_out:
        # The final interrupt echo belongs to Helper, not to the diagnostic answer.
        output = re.sub(r"\^C[ \t]*(?:\r?\n)*\Z", "", output)
    return output, timed_out, identity
