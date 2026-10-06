from __future__ import annotations

import ipaddress
import re
import threading

from .read_policy import _canonical_fortios_interface

RECIPES = frozenset({"ping", "traceroute", "sniffer", "sessions", "flow"})
IDENTITIES = frozenset({
    ("FortiGate-VM64-KVM", "7.6.7", "3704"),
    ("FortiGate-VM64-KVM", "8.0.0", "0167"),
})
REFUSAL = re.compile(r"(?mi)^(?:Command fail\.|command parse error|Unknown action|Permission denied)")
SESSION_FIELDS = frozenset({
    "vd", "sintf", "dintf", "proto", "proto-state", "source ip", "NAT'd source ip",
    "dest ip", "source port", "NAT'd source port", "dest port", "policy id",
    "expire", "duration", "state1", "state2",
})
FLOW_FIELDS = frozenset({"vf", "proto", "Host addr", "Host saddr", "Host daddr", "port", "sport", "dport"})


def validate(recipe, address, interface, count, timeout, max_bytes, vdom=None):
    if not isinstance(recipe, str) or recipe not in RECIPES:
        raise ValueError("unknown diagnostic recipe")
    if not isinstance(address, str):
        raise ValueError("a canonical unicast IPv4 address is required")
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        raise ValueError("a canonical unicast IPv4 address is required") from None
    if str(ip) != address or ip.is_multicast or ip.is_unspecified or int(ip) == 4294967295:
        raise ValueError("a canonical unicast IPv4 address is required")
    if not isinstance(interface, str) or _canonical_fortios_interface(interface) is None:
        raise ValueError("a concrete FortiOS interface is required")
    if vdom is not None and (not isinstance(vdom,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}",vdom)):
        raise ValueError("a canonical VDOM name is required")
    for value, low, high in ((count, 1, 3 if recipe == "traceroute" else 8),
                             (timeout, 1, 10), (max_bytes, 1000, 16000)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("diagnostic limits are invalid")


def authorize(auth, recipe, address, interface, vdom=None):
    auth.require_ssh_query("fortinet", "system_status")
    if not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified")
    if vdom is not None and vdom not in auth.read_inventory.get("diagnostic_vdoms",()):
        raise ValueError("diagnostic VDOM is not enrolled for this target")
    for category, value in (("diagnostic_recipes", recipe), ("addresses", address), ("interfaces", interface)):
        if value not in auth.read_inventory.get(category, ()):
            raise ValueError("diagnostic scope is not enrolled for this target")


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


def _bounded(shell, command, timeout):
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
        return (shell.listen(timeout + 3) if command is None else shell.command(command, timeout + 3)), fired.is_set()
    finally:
        timer.cancel()
        timer.join()


def run(shell, library, recipe, address, interface, count, timeout, vdom=None):
    from .schema_read import verify_status
    from netops_core import fortios
    current=verify_status(library, shell.command("get system status"))
    if library.identity not in IDENTITIES:
        raise ValueError("diagnostic recipes are not measured for this hardware and build")
    domain=current if vdom is None else vdom
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}",domain):
        raise ValueError("the current VDOM name cannot be selected safely")
    shell.navigate("config global")
    try:
        table=fortios.parse(shell.command("show full-configuration system vdom-property")).section("system vdom-property")
    except Exception:
        raise ValueError("the live VDOM inventory cannot be verified") from None
    if table is None or domain not in table.entries:
        raise ValueError("the enrolled VDOM does not exist")
    try:
        interfaces=fortios.parse(shell.command('show full-configuration system interface "'+interface+'"')).section("system interface")
    except Exception:
        raise ValueError("the interface owner cannot be verified") from None
    if interfaces is None or set(interfaces.entries)!={interface} or interfaces.entries[interface].value("vdom")!=domain:
        raise ValueError("the enrolled interface belongs to another VDOM")
    shell.navigate("end")
    shell.navigate("config vdom")
    shell.navigate('edit "' + domain + '"')
    current=verify_status(library,shell.command("get system status"))
    if current!=domain:
        raise ValueError("the selected VDOM could not be verified")
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
                shell.command(prefix + option + " " + value)
            command = "execute " + recipe + " " + address
        elif recipe == "sniffer":
            command = 'diagnose sniffer packet ' + interface + ' "host ' + address + ' and icmp" 1 ' + str(count) + ' l'
        else:
            display = "diagnose sys session filter" if recipe == "sessions" else "diagnose debug flow filter"
            baseline = shell.command(display)
            empty_filter(baseline, recipe)
            cleanup.append(display + " clear")
            shell.command(display + (" dst " if recipe == "sessions" else " addr ") + address)
            shell.command(display + " proto 1")
            if recipe == "sessions":
                command = "diagnose sys session list"
            else:
                debug = shell.command("diagnose debug info")
                if not re.search(r"(?mi)^debug output:[ \t]*disable[ \t]*$", debug):
                    raise ValueError("active debugging cannot be replaced")
                cleanup[0:0] = ["diagnose debug disable", "diagnose debug flow trace stop"]
                shell.command("diagnose debug flow trace start " + str(count))
                shell.command("diagnose debug enable")
                command = None
        output, timed_out = _bounded(shell, command, timeout)
        return output, timed_out
    finally:
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
        if errors:
            raise ValueError("diagnostic state restoration could not be verified")
