from __future__ import annotations

from datetime import datetime
import ipaddress
import re
import threading

from .read_policy import _canonical_fortios_interface

RECIPES = frozenset({"ping", "traceroute", "sniffer", "sessions", "flow", "logs"})
# Tested identities (startup, decision of 2026-11-17): these lists name the (model, version, build) each part of the
# recipes was tested on. They are not gates: on another identity the recipe runs and firmware_support() reports it
# as untested with a warning. Only the range syntax of a filter differs by version (T3, filter_range_repeats).
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
# The 60F 7.6.8 needs a single filter value as a range `value value`; the 80F 8.0.2 does not (probe 2026-11-09).
RANGE_TUPLE_IDENTITIES = frozenset({("FortiGate-60F", "7.6.8", "3744")})
# IP prefix operands: tested with the 60F range grammar and the 80F probe of 2026-11-09.
PREFIX_RANGE_IDENTITIES = RANGE_TUPLE_IDENTITIES | frozenset({("FortiGate-80F", "8.0.2", "0251")})
TIMESTAMP_IDENTITIES = frozenset({
    ("FortiGate-VM64", "8.0.2", "0251"),
    ("FortiGate-60F", "7.6.8", "3744"),
    ("FortiGate-80F", "8.0.2", "0251"),
})
# firewall health (FP-03, FP-04, FOS-P05): measured on the lab FortiGate-60F 7.6.8 b3744 on 2026-11-17 (verification) with a
# read-only account. Tested parts like the lists above, not gates: elsewhere they run with an untested warning.
G09_IDENTITIES = frozenset({("FortiGate-60F", "7.6.8", "3744")})
# Recipes measured without a tuple on identities outside IDENTITIES (FP-03). On the 60F 7.6.8 `execute log display`
# advances the session's log filter (start-line, an empty Filter line); a new session shows the filter as before,
# so the logs recipe verifies it through its reconnect, as built.
RECIPE_IDENTITIES = {"ping": G09_IDENTITIES, "traceroute": G09_IDENTITIES, "logs": G09_IDENTITIES,
                     "sessions": G09_IDENTITIES}
# ping and traceroute: an IPv6 target (ping6 / tracert6), a DNS name target and an explicit IPv4 source address.
PROBE_RECIPES = frozenset({"ping", "traceroute"})
IPV6_TARGET_IDENTITIES = G09_IDENTITIES
NAME_TARGET_IDENTITIES = G09_IDENTITIES
SOURCE_IDENTITIES = G09_IDENTITIES
# firewall resources (FP-01, FP-05, FP-06): measured on the lab FortiGate-60F 7.6.8 b3744 on 2026-11-17 (verification) with a read-only
# account: a log category with subtype/srcip/action fields, a session filter by source, destination port or policy,
# and sniffer filters by host, port and ARP, also on the interface any. Tested parts, not gates, as above.
G10_IDENTITIES = frozenset({("FortiGate-60F", "7.6.8", "3744")})
# FP-01: `execute log filter category <name>` and `execute log filter field <name> <value>`. Measured on the 60F: the
# filter lives in the SSH session only (a parallel and a later session read the filter as before), a new category
# drops the fields set before it, and view-lines takes 5-1000. verification: `field subtype sdwan` and `field policyid
# <n>` (traffic) shown as `( subtype "sdwan" )` and `( policyid "5" )`, measured on the same 60F.
LOG_CATEGORIES = ("traffic", "event", "utm-virus", "utm-webfilter", "utm-ips")
LOG_SUBTYPES = {"event": ("system", "vpn", "ha", "router", "user", "sdwan")}
LOG_ACTIONS = {"traffic": ("deny",)}
LOG_POLICY_CATEGORIES = ("traffic",)
LOG_TERM = re.compile(r'\( ([a-z]+) "([^"\\]*)" \)')
LOG_SEARCHED = re.compile(r"(?m)^(\d{1,3}(?:\.\d)?)% of logs has been searched\.[ \t\r]*$")
# FP-06: sniffer filters besides `host <address> and icmp` and the TCP/UDP tuple; printed with verbosity 4 (the
# interface name in every line, needed on the interface any).
SNIFFER_FILTERS = ("icmp", "host", "port", "arp")
SNIFFER_ANY = "any"
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
    """A real scope limit (VDOM, product kind); never a version or build (startup H19)."""


class ScopeRefused(ValueError):
    pass


class SourceNotLocal(ValueError):
    """An enrolled probe source is absent from the FortiGate's local addresses."""


class OptionRefused(ValueError):
    pass


REFUSABLE_OPTIONS = {
    "interface": "be bound to the enrolled interface",
    "device": "be bound to the enrolled interface",
    "source": "use the automatic source address",
    "source6": "use the automatic source address",
}


class RestoreUnverified(ValueError):
    pass


class PermissionRefused(ValueError):
    pass


DIAGNOSE_REFUSED = ("the account profile has no diagnose commands in this VDOM (FortiOS answered 'Unknown action 0', "
                    "as a read-only profile does); the sessions recipe needs an account whose profile permits diagnose")


def enter_vdom(shell, vdom):
    """Enter `config vdom` / `edit <vdom>` and answer the index of its verified `current vf=<vdom>:<index>` marker.

    Measured on the 60F 7.6.8: in multi-VDOM a global administrator's session reads no per-VDOM data outside
    this context, and `diagnose sys session list` inside it still lists every VDOM unless filtered by `vd`.
    """
    from .fortios_vdom import VdomRefused, context_index
    try:
        shell.navigate("config vdom")
        return context_index(shell.navigate("edit " + vdom), vdom)
    except (ValueError, VdomRefused):
        raise ScopeRefused("the session could not enter the verified context of the requested VDOM") from None


def leave_vdom(shell):
    """Leave the VDOM context entered by enter_vdom; the session closes next, so a failure is not an answer."""
    try:
        shell.navigate("end")
    except Exception:
        pass


def _diagnose(shell, command, context):
    """A diagnose step; in a verified VDOM context `Unknown action 0` is the profile's refusal (measured)."""
    try:
        return shell.command(command)
    except StepRefused as refusal:
        if context is not None and refusal.output.strip() == "Unknown action 0":
            raise PermissionRefused(DIAGNOSE_REFUSED) from None
        raise


class StepRefused(ValueError):
    def __init__(self, output):
        super().__init__("the device refused a diagnostic step")
        self.output = output


# A version record that is safe to compare and to show (ASCII digits, bounded): every model and build may run
# since startup, so a malformed or oversized record is refused as an unreadable identity instead.
_WELL_FORMED = (re.compile(r"[A-Za-z0-9_.+-]{1,64}"), re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}"),
                re.compile(r"[0-9]{4,6}"))


def well_formed(identity):
    return (isinstance(identity, tuple) and len(identity) == 3 and all(isinstance(part, str) for part in identity)
            and all(pattern.fullmatch(part) for pattern, part in zip(_WELL_FORMED, identity)))


def firmware_support(identity, recipe, *, tuple_given=False, prefix_given=False, timestamped=False, address=None,
                     source_given=False, filter_part=None):
    """firmware_support (netops_core.tested) of one recipe run: tested only when every part it uses was tested on
    this identity (the tuple, a prefix operand, timestamped flow trace lines, an IPv6 or DNS name target, an explicit
    source address, a firewall resources filter named by filter_part); never a refusal."""
    if filter_part is not None:
        tested = G10_IDENTITIES
    else:
        tested = TUPLE_IDENTITIES if tuple_given else IDENTITIES | RECIPE_IDENTITIES.get(recipe, frozenset())
    target = probe_target(address) if recipe in PROBE_RECIPES and address is not None else 4
    if prefix_given:
        tested = tested & PREFIX_RANGE_IDENTITIES
    if timestamped:
        tested = tested & TIMESTAMP_IDENTITIES
    if target == 6:
        tested = tested & IPV6_TARGET_IDENTITIES
    if target == "name":
        tested = tested & NAME_TARGET_IDENTITIES
    if source_given:
        tested = tested & SOURCE_IDENTITIES
    parts = [part for part, used in (("a TCP or UDP tuple", tuple_given), ("a prefix filter", prefix_given),
                                    ("console timestamps", timestamped), ("an IPv6 target", target == 6),
                                    ("a DNS name target", target == "name"),
                                    ("an explicit source address", source_given),
                                    (filter_part, filter_part is not None)) if used]
    function = "fortios_diagnostics " + recipe + (" with " + " and ".join(parts) if parts else "")
    return fortios_support(identity, tested, function)


def fortios_support(identity, tested, function):
    """firmware_support of a FortiOS (model, version, build) against tested identities of the same shape."""
    from netops_core import tested as tested_versions

    def shown(item):
        return item[1] + " build" + item[2]

    return tested_versions.support("FortiOS", shown(identity), sorted((item[0], shown(item)) for item in tested),
                                   model=identity[0], function=function)


def session_partial(recipe, source_address=None, source_port=None, destination_port=None, protocol=None,
                    policy_id=None, any_source_port=False):
    """FP-05: a sessions filter without the whole tuple: source address, destination port and/or policy, no protocol
    or source port (`diagnose sys session filter src|dport|policy`)."""
    return (recipe == "sessions" and source_port is None and protocol is None and not any_source_port
            and any(value is not None for value in (source_address, destination_port, policy_id)))


def filter_part(recipe, interface, *, log_category=None, partial=False, sniffer_filter=None, policy_id=None):
    """The firewall resources part a run uses, as firmware_support names it, or None."""
    if recipe == "logs" and log_category is not None:
        return "a log category filter"
    if partial or (recipe == "sessions" and policy_id is not None):
        return "a session filter by source, destination port or policy"
    if recipe == "sniffer" and (sniffer_filter not in (None, "icmp") or interface == SNIFFER_ANY):
        return "a host, port or ARP sniffer filter or the interface any"
    return None


def sniffer_selector(address, sniffer_filter, destination_port=None, protocol=None):
    """FP-06: the sniffer expression of a host, port or ARP filter (measured on the 60F 7.6.8)."""
    parts = ["arp"] if sniffer_filter == "arp" else []
    if address:
        parts.append("host " + address)
    if sniffer_filter == "port":
        parts.append({6: "tcp ", 17: "udp "}.get(protocol, "") + "port " + str(destination_port))
    return " and ".join(parts)


def filter_range_repeats(identity):
    """T3: the syntax variant of a single value in a session or flow filter tuple, chosen by the major version.

    Measured: the 60F 7.6.8 b3744 takes a single address or port as the range `value value`, the 80F 8.0.2 b0251
    takes `value`. FortiOS 7.x and older use the 7.6.8 form, 8.x and newer the 8.0.2 form; a refused form is still
    caught as a device refusal (REFUSAL) and the filter is cleared as before.
    """
    if identity in RANGE_TUPLE_IDENTITIES:
        return True
    major = identity[1].split(".", 1)[0]
    return major.isdigit() and int(major) < 8


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
    if not well_formed(identity):
        raise ValueError("one exact diagnostic identity is required")
    if not identity[0].startswith(platforms.PRODUCT_HARDWARE["fortios"]):
        raise UnsupportedPlatform("config_platform_not_supported: the target is not a FortiOS product")
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


def _unicast_ipv4(address, message="a canonical unicast IPv4 address is required"):
    if not isinstance(address, str):
        raise ValueError(message)
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        raise ValueError(message) from None
    if str(ip) != address or ip.is_multicast or ip.is_unspecified or int(ip) == 4294967295:
        raise ValueError(message)


def probe_target(address):
    """The kind of a ping or traceroute target (firewall health FP-04): 4 for a canonical unicast IPv4 address, 6 for a
    canonical unicast IPv6 address (execute ping6 / tracert6), "name" for a lower-case DNS name that FortiOS resolves
    itself (execute ping / traceroute <name>, IPv4)."""
    from .read_policy import validate_inventory_item
    if isinstance(address, str) and ":" in address:
        try:
            ip = ipaddress.IPv6Address(address)
        except ValueError:
            raise ValueError("a canonical unicast IPv6 address is required") from None
        if str(ip) != address or ip.is_multicast or ip.is_unspecified:
            raise ValueError("a canonical unicast IPv6 address is required")
        return 6
    try:
        if isinstance(address, str) and validate_inventory_item("diagnostic_names", address) == address:
            return "name"
    except ValueError:
        pass
    _unicast_ipv4(address, "a canonical unicast IPv4 or IPv6 address or a DNS name is required")
    return 4


def probe_source(shell, source_address):
    """An explicit source of ping or traceroute must be an address of this FortiGate (FOS-P05): measured on the 60F
    7.6.8, a foreign IPv4 source is accepted by ping-options and the ping then only reports 100% packet loss."""
    listing = shell.command("diagnose ip address list")
    if not re.search(r"(?m)^IP=" + re.escape(source_address) + r"->", listing):
        raise SourceNotLocal("the source address is not an address of this FortiGate (diagnose ip address list)")


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


def validate_filters(recipe, *, log_category=None, log_subtype=None, log_action=None, policy_id=None,
                     sniffer_filter=None):
    """The firewall resources filter arguments: each applies to one recipe and takes only the measured values."""
    if recipe != "logs" and any(value is not None for value in (log_category, log_subtype, log_action)):
        raise ValueError("log_category, log_subtype and log_action apply to the logs recipe only")
    if log_category is not None and log_category not in LOG_CATEGORIES:
        raise ValueError("log_category is one of " + ", ".join(LOG_CATEGORIES))
    if log_subtype is not None and log_subtype not in LOG_SUBTYPES.get(log_category, ()):
        raise ValueError("log_subtype is system, vpn, ha, router, user or sdwan and needs log_category event")
    if log_action is not None and log_action not in LOG_ACTIONS.get(log_category, ()):
        raise ValueError("log_action is deny and needs log_category traffic")
    if policy_id is not None and ((recipe != "sessions" and (recipe != "logs"
                                                              or log_category not in LOG_POLICY_CATEGORIES))
                                  or type(policy_id) is not int or not 1 <= policy_id <= 4294967294):
        raise ValueError("policy_id is a firewall policy number 1-4294967294 and applies to the sessions recipe and to "
                         "the logs recipe with log_category traffic only")
    if sniffer_filter is not None and (recipe != "sniffer" or sniffer_filter not in SNIFFER_FILTERS):
        raise ValueError("sniffer_filter is icmp, host, port or arp and applies to the sniffer recipe only")


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("destination_port is a whole number 1-65535")


def validate(recipe, address, interface, count, timeout, max_bytes, vdom=None, *,
             source_address=None, source_port=None, destination_port=None, protocol=None,
             any_source_port=False, log_category=None, log_subtype=None, log_action=None, policy_id=None,
             sniffer_filter=None):
    if not isinstance(recipe, str) or recipe not in RECIPES:
        raise ValueError("unknown diagnostic recipe")
    validate_filters(recipe, log_category=log_category, log_subtype=log_subtype, log_action=log_action,
                     policy_id=policy_id, sniffer_filter=sniffer_filter)
    partial = session_partial(recipe, source_address, source_port, destination_port, protocol, policy_id,
                              any_source_port)
    # firewall resources: an empty address means no address filter: logs of a category, sessions of a source, a sniffer port or ARP.
    open_address = address == "" and ((recipe == "logs" and log_category is not None)
                                      or (partial and source_address is not None)
                                      or (recipe == "sniffer" and sniffer_filter in ("port", "arp")))
    if open_address:
        pass
    elif recipe in PROBE_RECIPES:
        target = probe_target(address)
    elif isinstance(address, str) and "/" in address:
        _filter_network(address, recipe)
    else:
        _unicast_ipv4(address)
    if interface == SNIFFER_ANY and recipe == "sniffer":
        # FP-06: the interface any must be enrolled like an interface (authorize) and is scoped by an enrolled host
        # too; only ARP (no IP payload, the measured `any "arp"`) may run there without a host.
        if open_address and sniffer_filter != "arp":
            raise ValueError("the sniffer on the interface any needs an enrolled host address, except for arp")
    elif not isinstance(interface, str) or _canonical_fortios_interface(interface) is None:
        raise ValueError("a concrete FortiOS interface is required")
    if vdom is not None and (not isinstance(vdom, str) or not VDOM_NAME.fullmatch(vdom)):
        raise ValueError("a valid VDOM name is required")
    tuple_values = (source_address, source_port, destination_port, protocol)
    if any_source_port and (recipe != "sessions" or source_port is not None or any(
            value is None for value in (source_address, destination_port, protocol))):
        raise ValueError("only the sessions recipe can leave the source port open, with the rest of the tuple")
    if recipe in PROBE_RECIPES and source_address is not None and all(
            value is None for value in tuple_values[1:]) and not any_source_port:
        # FOS-P05: ping and traceroute from an explicit IPv4 source address of this FortiGate (wan-watch).
        if target == 6:
            raise ValueError("an explicit source address applies to an IPv4 or DNS name target only")
        _unicast_ipv4(source_address, "a canonical unicast IPv4 source address is required")
    elif partial:
        # FP-05: sessions of a source address (client), a destination port and/or a policy, any protocol.
        if source_address is not None:
            if "/" in source_address:
                _filter_network(source_address, recipe)
            else:
                _unicast_ipv4(source_address, "a canonical unicast IPv4 source address is required")
        if destination_port is not None:
            _port(destination_port)
        if address == "" and source_address is None:
            raise ValueError("a sessions filter needs an address or a source_address")
    elif recipe == "sniffer" and sniffer_filter not in (None, "icmp"):
        # FP-06: host, port (optionally TCP or UDP) or ARP; no source address or source port.
        if source_address is not None or source_port is not None or any_source_port:
            raise ValueError("a host, port or ARP sniffer filter takes no source address or source port")
        if sniffer_filter == "port":
            _port(destination_port)
            if protocol is not None and protocol not in (6, 17):
                raise ValueError("protocol of a sniffer port filter is 6 (TCP) or 17 (UDP)")
        elif destination_port is not None or protocol is not None:
            raise ValueError("destination_port and protocol apply to the sniffer port filter only")
    elif any(value is not None for value in tuple_values):
        if sniffer_filter is not None:
            raise ValueError("sniffer_filter icmp takes no TCP or UDP tuple")
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
    # The sniffer on the interface any (FP-06) spans every interface: like a named interface it runs only when the
    # target enrolls it (`any` in interfaces), also for ARP without an address (review finding 1).
    grants = [("diagnostic_recipes", recipe), ("interfaces", interface)]
    for category, value in grants:
        if value not in auth.read_inventory.get(category, ()):
            raise ValueError("diagnostic scope is not enrolled for this target")
    if interface == SNIFFER_ANY and recipe != "sniffer":
        raise ValueError("diagnostic scope is not enrolled for this target")
    for value in (address, source_address):
        if value is None or value == "":  # "" = no address filter (firewall resources, validate)
            continue
        if recipe in PROBE_RECIPES and probe_target(value) == "name":
            # A DNS name target (FP-04) is enrolled like a FortiADC nslookup name.
            if value not in auth.read_inventory.get("diagnostic_names", ()):
                raise ValueError("diagnostic scope is not enrolled for this target")
            continue
        try:
            enrolled_lookup(value, 6 if ":" in value else 4, auth.read_inventory)
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
# hook=pre|post: a forwarded session; hook=out|in: a local session of the FortiGate itself, e.g. its own ping
# (measured on the 60F 7.6.8: "hook=out dir=org", "hook=in dir=reply"). Any other shape stays incomplete.
SESSION_HOOK = re.compile(r"(?m)^(hook=(?:pre|post|out|in) dir=(org|reply) act=(?:noop|snat|dnat) "
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
              "matched": None, "truncated": False, "time_range": None, "searched_percent": None, "output": ""}
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
    searched = LOG_SEARCHED.search(output)
    if searched:
        # Measured on the 60F 7.6.8 (on-demand search): the device reports how much of the log it has searched so
        # far; "found" counts only that part, and no line means the whole log was searched.
        result["searched_percent"] = float(searched.group(1))
    records = re.split(r"(?m)^(?=\d+: )", output)[1:]
    if result["loaded"] > result["found"]:
        result["state"] = "incomplete"
        return result
    if result["found"] == 0 and result["loaded"] == 0 and not records:
        # An empty answer of a partial search is not an empty log (measured: 0 found at 30-65 % searched).
        partial = result["searched_percent"] is not None
        result.update(state="incomplete" if partial else "empty", truncated=partial, returned=0, matched=0)
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
    mark = re.compile(r"(?:^|\s)(?:srcip|dstip)=" + re.escape(address) + r"(?=\s|$)" if address else r"")
    since, until = window or (None, None)

    def inside(record):
        found = LOG_TIME.search(record)
        stamp = " ".join(found.groups()) if found else ""
        return (since is None or stamp >= since) and (until is None or "" < stamp <= until)

    matched = [record for record in records if mark.search(record) and inside(record)]
    kept = matched[:min(count, int(state["view-lines"]))]
    result.update(matched=len(matched), returned=len(kept), truncated=len(kept) < len(matched),
                  output="".join(kept))
    if not matched and result["searched_percent"] is not None:
        # Review finding 3: the loaded records of a partial search all fell outside the time window or the
        # address; the part of the log the device has not searched may hold matching records, so this is no empty
        # answer.
        result.update(state="incomplete", truncated=True)
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


def _log_filter_steps(address, count, log_category, log_subtype, log_action, policy_id=None):
    """FP-01: the session-scoped log filter steps and the field terms the device must then show in `Filter:`."""
    terms = [(name, value) for name, value in (("subtype", log_subtype), ("srcip", address or None),
                                                ("action", log_action),
                                                ("policyid", None if policy_id is None else str(policy_id)))
             if value is not None]
    steps = (["execute log filter category " + log_category]
             + ["execute log filter field " + name + " " + value for name, value in terms]
             + ["execute log filter view-lines " + str(max(5, count))])
    return steps, terms


def applied_log_filter(text, log_category, terms, view_lines):
    """The dump after the filter steps must show exactly the requested category, view-lines and field terms."""
    state = fields(text)
    shown = state.pop("Filter", "")
    if (set(state) != LOG_FILTER_FIELDS or state["category"] != log_category
            or state["view-lines"] != str(view_lines) or state["start-line"] != "1"
            or sorted(LOG_TERM.findall(shown)) != sorted(terms)
            or LOG_TERM.sub("", shown).replace("AND", "").strip()):
        raise ValueError("the device did not show the requested log filter")


def applied_session_filter(text, expected):
    """FP-05: the session filter after the steps shows each requested value (`a-a` or `a`, a prefix `first-last`)
    and nothing else."""
    state = fields(text)
    state.pop("session filter", None)
    state.pop("ngfw id", None)
    for label, value in expected.items():
        if state.pop(label, None) not in (value, value.replace(" ", "-"), value + "-" + value):
            raise ValueError("the device did not show the requested session filter")
    if any(value != "any" for value in state.values()):
        raise ValueError("the device did not show the requested session filter")


def run(shell, recipe, address, interface, count, timeout, vdom=None, *, reconnect=None,
        source_address=None, source_port=None, destination_port=None, protocol=None, window=None,
        any_source_port=False, support=None, log_category=None, log_subtype=None, log_action=None,
        close_with_operation=False,
        policy_id=None, sniffer_filter=None):
    """Run one bounded recipe. `support`, when a list, receives the firmware_support of the run (startup)."""
    from netops_core import fortios
    partial = session_partial(recipe, source_address, source_port, destination_port, protocol, policy_id,
                              any_source_port)
    part = filter_part(recipe, interface, log_category=log_category, partial=partial, sniffer_filter=sniffer_filter,
                       policy_id=policy_id)
    identity, domain, mode = status_identity(shell.command("get system status"))
    # startup: an identity outside the tested lists is not refused; firmware_support() reports it (support[0]).
    prefix_given = (recipe in ("sessions", "flow")
                    and any(isinstance(value, str) and "/" in value for value in (address, source_address)))
    probe = recipe in PROBE_RECIPES
    if support is not None:
        support[:] = [firmware_support(identity, recipe,
                                       tuple_given=source_address is not None and not probe and not partial,
                                       prefix_given=prefix_given, address=address,
                                       source_given=probe and source_address is not None, filter_part=part)]
    if vdom is None and mode != "disable":
        raise UnsupportedPlatform("config_platform_not_supported: multi-VDOM diagnostics require an enrolled VDOM")
    if vdom is not None and vdom != domain:
        raise UnsupportedPlatform("config_platform_not_supported: the session is not scoped to the requested VDOM")
    # Multi-VDOM sessions: read inside the verified VDOM context and filter by its index (measured, verification).
    context = enter_vdom(shell, domain) if mode == "multiple" and recipe == "sessions" else None
    if recipe == "sniffer" and interface == SNIFFER_ANY:
        # FP-06: the interface any has no owner to verify; it spans every interface, so only without VDOMs.
        if mode != "disable":
            raise ScopeRefused("the sniffer on the interface any is available only without VDOMs")
    else:
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
        info = _diagnose(shell, "diagnose netlink interface list " + interface, context)
        if not re.search(r"(?m)^if=" + re.escape(interface) + r"(?:\s|$)", info):
            raise ValueError("the enrolled interface is not visible in this session")
    if probe and source_address is not None:
        probe_source(shell, source_address)
    cleanup = []
    baseline = None
    display = None
    try:
        if recipe == "traceroute" and ":" in address:
            # FP-04: IPv6 traceroute is `execute tracert6` (FortiOS 7.6.8 has no traceroute6); it takes its
            # probes and interface as arguments and leaves no option state behind (measured 2026-11-17).
            command = "execute tracert6 -q " + str(count) + " -i " + interface + " " + address
        elif recipe in ("ping", "traceroute"):
            six = "6" if ":" in address else ""
            prefix = "execute " + recipe + six + "-options "
            display = prefix + "view-settings"
            baseline = shell.command(display)
            current = fields(baseline.split("Default Ping Options:", 1)[0])
            source = source_address or "auto"
            if recipe == "ping":
                settings = (("repeat-count", "Repeat Count", str(count)),
                            ("timeout", "Timeout", "1"), ("interval", "Interval", "1"),
                            ("data-size", "Data Size", "56"), ("adaptive-ping", "Adaptive Ping", "disable"),
                            ("interface", "Interface", interface), ("source" + six, "Source Address", source),
                            ("use-sdwan", "Use SD-WAN", "no"))
            else:
                settings = (("queries", "Number of probes per hop", str(count)),
                            ("device", "Device", interface), ("source", "Source Address", source),
                            ("use-sdwan", "Use SD-WAN", "no"))
            for option, label, value in settings:
                previous = current.get(label)
                shape = r"auto|[0-9A-Fa-f:.]{2,45}" if option == "source6" else r"[A-Za-z0-9_.-]{1,15}"
                if previous is None or not re.fullmatch(shape, previous):
                    raise ValueError("diagnostic option state cannot be restored safely")
                if option in ("source", "source6") and previous != "auto":
                    try:
                        (ipaddress.IPv6Address if six else ipaddress.IPv4Address)(previous)
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
                    reason = REFUSABLE_OPTIONS[option]
                    if option == "source" and source_address is not None:
                        reason = "use the requested source address"
                    raise OptionRefused(
                        "FortiOS refused '" + prefix + option + "' on " + where + ", so " + recipe +
                        " could not " + reason + " and was not run; the options it had set "
                        "were restored and verified." +
                        (" Run " + recipe + " on the HA primary." if where != "this session" else "")
                    ) from None
            # FP-04: ping6 also takes the interface as -I: measured on the 60F 7.6.8, a link-local target answers
            # only then ("connect: Invalid argument" with the interface option alone).
            command = ("execute ping6 -I " + interface + " " if six else "execute " + recipe + " ") + address
        elif recipe == "sniffer":
            verbosity = " 1 "
            if sniffer_filter not in (None, "icmp"):
                selector, verbosity = sniffer_selector(address, sniffer_filter, destination_port, protocol), " 4 "
            elif source_address is None:
                selector = "host " + address + " and icmp"
            else:
                transport = "tcp" if protocol == 6 else "udp"
                selector = (transport + " and ((src host " + source_address +
                            " and src port " + str(source_port) + " and dst host " + address +
                            " and dst port " + str(destination_port) + ") or (src host " + address +
                            " and src port " + str(destination_port) + " and dst host " +
                            source_address + " and dst port " + str(source_port) + "))")
            command = 'diagnose sniffer packet ' + interface + ' "' + selector + '"' + verbosity + str(count) + ' l'
        elif recipe == "logs":
            display = "execute log filter dump"
            baseline = shell.command(display)
            log_filter(baseline)
            applied = baseline
            if log_category is not None:
                # FP-01: the filter is session-scoped (measured); the reconnect below verifies it in a new session.
                steps, terms = _log_filter_steps(address, count, log_category, log_subtype, log_action, policy_id)
                for step in steps:
                    if shell.command(step).strip():
                        raise ValueError("the device refused a log filter step")
                applied = shell.command(display)
                applied_log_filter(applied, log_category, terms, max(5, count))
            command = "execute log display"
        else:
            if recipe == "flow":
                debug = shell.command("diagnose debug info")
                if not re.search(r"(?mi)^debug output:[ \t]*disable[ \t]*$", debug):
                    raise ValueError("active debugging cannot be replaced")
                if (support is not None
                        and re.search(r"(?mi)^console timestamp:[ \t]*enable[ \t]*$", debug)):
                    # Timestamped trace lines were tested on TIMESTAMP_IDENTITIES only; elsewhere a line of an
                    # unknown shape is not counted as a traced packet (flow_trace), and the warning says so.
                    support[:] = [firmware_support(identity, recipe, tuple_given=source_address is not None,
                                                   prefix_given=prefix_given, timestamped=True)]
            display = "diagnose sys session filter" if recipe == "sessions" else "diagnose debug flow filter"
            baseline = _diagnose(shell, display, context)
            empty_filter(baseline, recipe)
            cleanup.append(display + " clear")
            if partial:
                # FP-05: the client (src), the destination (dst), the destination port and the policy; any protocol.
                expected = {}
                for selector, label, value in (("src", "source ip", source_address), ("dst", "dest ip", address or None),
                                               ("dport", "dest port", destination_port),
                                               ("policy", "policy id", policy_id)):
                    if value is None:
                        continue
                    value = str(value)
                    operand = filter_operand(value)
                    shell.command(display + " " + selector + " " + operand +
                                  (" " + value if filter_range_repeats(identity) and operand == value else ""))
                    expected[label] = operand
                applied_session_filter(_diagnose(shell, display, context), expected)
            elif source_address is not None:
                expected = {}
                for selector, label, value in (
                    ("src" if recipe == "sessions" else "saddr", "source ip", source_address),
                    ("dst" if recipe == "sessions" else "daddr", "dest ip", address),
                    ("sport", "source port", str(source_port)), ("dport", "dest port", str(destination_port)),
                    ("proto", "proto", str(protocol)),
                    ("policy", "policy id", None if policy_id is None else str(policy_id)),
                ):
                    if (any_source_port and selector == "sport") or value is None:
                        continue
                    operand = filter_operand(value)
                    command_text = display + " " + selector + " " + operand
                    if (filter_range_repeats(identity) and (recipe == "sessions" or selector != "proto")
                            and operand == value):
                        command_text += " " + value
                    shell.command(command_text)
                    expected[label] = operand
                if policy_id is not None:
                    # Review finding 2: a policy with the whole tuple is a device filter too; the shown
                    # filter must hold every value (measured on the 60F: `policy id: 5-5` beside the tuple), as FP-05.
                    applied_session_filter(_diagnose(shell, display, context), expected)
            else:
                shell.command(display + (" dst " if recipe == "sessions" else " addr ") + filter_operand(address))
                shell.command(display + " proto 1")
            if recipe == "sessions":
                if context is not None:
                    shell.command(display + " vd " + str(context))
                command = "diagnose sys session list"
            else:
                cleanup[0:0] = ["diagnose debug disable", "diagnose debug flow trace stop"]
                shell.command("diagnose debug flow trace start " + str(count))
                shell.command("diagnose debug enable")
                command = None
        output, timed_out = _bounded(shell, command, timeout)
        if recipe == "logs":
            output = log_read(output, applied, address, count, window, timed_out)
        if context is not None:
            from .fortios_vdom import sessions_in_vdom
            if not sessions_in_vdom(output, context):
                raise ScopeRefused("a listed session does not belong to the requested VDOM")
        return output, timed_out, identity, domain
    finally:
        if recipe == "logs" and log_category is not None and close_with_operation:
            # The filter is session-local. The caller closes this SSH session
            # under the diagnostic lock, so a fresh session is unnecessary.
            restored = True
        else:
            restored = _restore(shell, cleanup, display, baseline, recipe)
        if context is not None and restored:
            leave_vdom(shell)
        if not restored:
            recovered = False
            if reconnect is not None and (cleanup or recipe == "logs"):
                try:
                    with reconnect() as repair:
                        repair_identity, repair_domain, repair_mode = status_identity(
                            repair.command("get system status")
                        )
                        if repair_identity == identity and repair_domain == domain and repair_mode == mode and (
                                context is None or enter_vdom(repair, domain) == context):
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
