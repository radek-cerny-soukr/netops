"""Junos running-configuration checks for the Auditor taxonomy."""

from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_network
import re

from .engine import EVALUATED, NOT_EVALUATED, check
from .management import SYSLOG_LEVELS
from .platforms import VISIBLE


SYSTEM = ("system",)
SERVICES = (*SYSTEM, "services")
SSH = (*SERVICES, "ssh")
RETRY = (*SYSTEM, "login", "retry-options")
ROOT = (*SYSTEM, "root-authentication")
AUTH_ORDER = (*SYSTEM, "authentication-order")
SNMP = ("snmp",)
USERS = (*SNMP, "v3", "usm", "local-engine", "user")
VACM = (*SNMP, "v3", "vacm")
NTP = (*SYSTEM, "ntp")
SYSLOG = (*SYSTEM, "syslog")
LLDP = ("protocols", "lldp")
SERVICE_PORTS = {"ssh": 22, "telnet": 23, "http": 80, "https": 443}
LEVELS = {level: rank for rank, level in enumerate((*SYSLOG_LEVELS, "any"))}
FACILITIES = frozenset({
    "any", "authorization", "change-log", "conflict-log", "daemon", "dfc", "external",
    "firewall", "ftp", "interactive-commands", "kernel", "ntp", "pfe", "security", "user",
})
AUTH_ALGORITHMS = frozenset({
    "authentication-md5", "authentication-sha", "authentication-sha224",
    "authentication-sha256", "authentication-sha384", "authentication-sha512",
})
PRIVACY_ALGORITHMS = frozenset({"privacy-des", "privacy-aes128", "privacy-aes192", "privacy-aes256",
                               "privacy-3des"})
SAFE_OBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")


@dataclass(frozen=True)
class Result:
    gap: str = ""
    hits: tuple = ()


def _hit(section, object_key, statement, state, count=None):
    evidence = {"state": state}
    if count is not None:
        evidence["count"] = count
    return {"section": section, "object_key": object_key, "line": statement.line if statement else 0,
            "evidence": evidence}


def _reason(tree, context, *sections):
    if tree.malformed is not None or context.snapshot is not None and not context.snapshot.complete:
        return "truncated"
    for section in sections:
        if section in tree.hidden:
            return "access-denied"
        if section in tree.inheritance:
            return "inheritance-unresolved"
        visibility = context.visibility(section)
        # A content marker on a restricted snapshot proves presence only.
        if visibility.state == VISIBLE and visibility.reason in ("verified-profile", "auxiliary-output"):
            continue
        return "visibility-unproven" if visibility.state == VISIBLE else visibility.reason
    return ""


def _register(name, *scope, applies=None, absence=False):
    """Register a probe; an absence check stays in scope of every offline file."""
    def register(probe):
        def status(tree, context):
            result = probe(tree, context)
            return (NOT_EVALUATED, result.gap) if result.gap else (EVALUATED, "")

        @check("junos_" + name, audit_context=True, status=status, applies=applies, partial=True,
               offline_scope=lambda tree: absence or tree.malformed is not None or any(
                   tree.matching(*path) or path[0] in tree.hidden or path[0] in tree.inheritance
                   for path in scope))
        def findings(tree, context):
            return probe(tree, context).hits

        return probe
    return register


def _entries(tree, path):
    """Return the active immediate objects in a hierarchy and their leaves in CLI order."""
    result = defaultdict(list)
    for row in tree.matching(*path):
        rest = row.tokens[len(path):]
        if rest and (not row.masked or rest[0] != "SECRET-DATA"):
            result[rest[0]].append((rest[1:], row))
    return result


def _leaf(tree, path):
    return next(((row.tokens[-1], row) for row in tree.matching(*path)
                 if len(row.tokens) == len(path) + 1 and row.tokens[-1] != "SECRET-DATA"), (None, None))


def _first(tree, path):
    return next(iter(tree.matching(*path)), None)


def _authentication_order(tree, path=AUTH_ORDER):
    return {token for row in tree.matching(*path) for token in row.tokens[len(path):]}



def _direct(tree, context, path, object_key):
    row = _first(tree, path)
    if row and row.tokens[len(path):] != ("SECRET-DATA",):
        return Result(hits=(_hit("system", object_key, row, "enabled"),))
    return Result(_reason(tree, context, "system"))


@_register("telnet_enabled", SERVICES)
def telnet_enabled(tree, context):
    return _direct(tree, context, (*SERVICES, "telnet"), "telnet")


@_register("http_enabled", SERVICES)
def http_enabled(tree, context):
    return _direct(tree, context, (*SERVICES, "web-management", "http"), "http")


@_register("lockout", SERVICES, RETRY)
def lockout(tree, context):
    remote = _first(tree, (*SERVICES, "telnet"))
    if not remote and not _first(tree, (*SSH, "no-passwords")):
        remote = _first(tree, SSH)
    if remote is None:
        return Result(_reason(tree, context, "system"))
    minutes, _ = _leaf(tree, (*RETRY, "lockout-period"))
    tries, row = _leaf(tree, (*RETRY, "tries-before-disconnect"))
    if minutes and minutes.isdecimal() and int(minutes) > 0:
        # Junos has a finite documented retry threshold when omitted.
        if tries is None or tries.isdecimal() and int(tries) > 0:
            return Result()
    if {"tacplus", "radius"}.intersection(
            _authentication_order(tree) | _authentication_order(tree, (*SSH, "authentication-order"))):
        return Result("external-lockout-unproven")
    gap = _reason(tree, context, "system")
    if minutes == "0" or not gap:
        return Result(hits=(_hit("system", "remote-login", row or remote, "no-timed-lockout"),))
    return Result(gap)


@_register("default_account", SSH, ROOT)
def default_account(tree, context):
    mode, row = _leaf(tree, (*SSH, "root-login"))
    if mode in ("deny", "deny-password") or _first(tree, (*SSH, "no-passwords")):
        return Result()
    if mode == "allow":
        password = _first(tree, (*ROOT, "encrypted-password"))
        if password and len(password.tokens) == len(ROOT) + 2:
            return Result(hits=(_hit("system", "root", row, "password-login-allowed"),))
        if _first(tree, ROOT) and (*ROOT, "encrypted-password") in tree.disabled:
            return Result()
        return Result(_reason(tree, context, "system") or "root-password-unproven")
    return Result(_reason(tree, context, "system"))


@_register("external_login", AUTH_ORDER, applies=lambda intent: intent.get("external_aaa_required"))
def external_login(tree, context):
    ssh_order = (*SSH, "authentication-order")
    order = _authentication_order(tree, ssh_order) or _authentication_order(tree)
    row = _first(tree, ssh_order) or _first(tree, AUTH_ORDER)
    gap = _reason(tree, context, "system")
    if not order.intersection({"tacplus", "radius"}):
        if gap:
            return Result(gap)
        return Result(hits=(_hit("system", "authentication-order", row,
                                 "external-backend-not-selected"),))
    hits = []
    for method in ("tacplus", "radius"):
        if method not in order:
            continue
        servers = _entries(tree, (*SYSTEM, method + "-server"))
        # Masks at a known secret leaf prove its presence, without exposing the value.
        if servers and all(any(rest[:1] == ("secret",) and len(rest) == 2 for rest, _ in rows)
                           for rows in servers.values()):
            continue
        if not gap:
            hits.append(_hit("system", method, row, "backend-without-server-secret"))
    return Result(gap, tuple(hits))


@_register("v1v2c_community", SNMP)
def v1v2c_community(tree, context):
    communities = _entries(tree, (*SNMP, "community"))
    row = _first(tree, (*SNMP, "community"))
    if row:
        # A keyed, masked community proves presence but may hide the count.
        masked = any(item.tokens[2:3] == ("SECRET-DATA",) and item.masked
                     for item in tree.matching(*SNMP, "community"))
        count = None if masked else len(communities)
        return Result(hits=(_hit("snmp", "communities", row, "legacy-communities-present", count),))
    return Result(_reason(tree, context, "snmp"))


def _snmp_key(leaves, algorithms, key, password):
    return any(len(path) == 3 and path[0] in algorithms and path[1] in (key, password) for path, _ in leaves)


@_register("v3_auth_priv", (*SNMP, "v3"))
def v3_auth_priv(tree, context):
    users = _entries(tree, USERS)
    access = _entries(tree, (*VACM, "access", "group"))
    mappings = _entries(tree, (*VACM, "security-to-group", "security-model", "usm", "security-name"))
    gap = _reason(tree, context, "snmp")
    if not users:
        if _first(tree, (*SNMP, "v3", "usm", "remote-engine")):
            return Result(gap or "snmp-engine-unproven")
        return Result(gap)
    weak = []
    for user, leaves in users.items():
        auth = _snmp_key(leaves, AUTH_ALGORITHMS, "authentication-key", "authentication-password")
        priv = _snmp_key(leaves, PRIVACY_ALGORITHMS, "privacy-key", "privacy-password")
        groups = {path[1] for path, _ in mappings.get(user, ()) if len(path) == 2 and path[0] == "group"}
        levels = {path[4] for group in groups for path, _ in access.get(group, ())
                  if len(path) >= 6 and path[1:4] in (("security-model", "usm", "security-level"),
                                                     ("security-model", "any", "security-level"))
                  and path[0] == "default-context-prefix"}
        explicit_weak = any(path[:1] in (("authentication-none",), ("privacy-none",)) for path, _ in leaves)
        if explicit_weak or levels.intersection({"none", "authentication"}) or (
                not gap and not (auth and priv and "privacy" in levels)):
            weak.append(leaves[0][1])
    hits = (_hit("snmp", "usm-users", weak[0], "auth-priv-not-enforced", len(weak)),) if weak else ()
    return Result(gap, hits)


def _ntp_sources(tree):
    return tuple((path[3], path[2], row) for kind in ("server", "peer")
                 for row in tree.matching(*NTP, kind) if len(path := row.tokens) >= 4
                 and path[3] != "SECRET-DATA")


@_register("no_ntp_source", NTP, absence=True)
def no_ntp_source(tree, context):
    disabled = _first(tree, (*NTP, "disable"))
    if _ntp_sources(tree) and not disabled:
        if "system" in tree.inheritance:
            return Result("inheritance-unresolved")
        return Result()
    gap = "" if disabled else _reason(tree, context, "system")
    if gap:
        return Result(gap)
    return Result(hits=(_hit("system", "ntp", disabled or _first(tree, NTP), "no-active-source"),))


@_register("ntp_auth", NTP, applies=lambda intent: intent.get("ntp_auth_required"))
def ntp_auth(tree, context):
    gap = _reason(tree, context, "system")
    sources = {(name, kind) for name, kind, _ in _ntp_sources(tree)}
    if _first(tree, (*NTP, "disable")) or not sources and not gap:
        # The source-presence check handles disabled or unconfigured NTP.
        return Result()
    hits = []
    for name, kind in sorted(sources):
        path = (*NTP, kind, name)
        rows = tree.matching(*path)
        if _first(tree, (*path, "nts")):
            # The committed, explicit NTS statement is capability evidence.
            continue
        key, _ = _leaf(tree, (*path, "key"))
        algorithm, _ = _leaf(tree, (*NTP, "authentication-key", key, "type"))
        value = _first(tree, (*NTP, "authentication-key", key, "value"))
        trusted = _first(tree, (*NTP, "trusted-key", key))
        if key and algorithm in ("md5", "sha1", "sha256") and value and trusted:
            continue
        if not gap and SAFE_OBJECT.fullmatch(name):
            instance, _ = _leaf(tree, (*path, "routing-instance"))
            object_key = f"{kind}/{name}" + (f"/{instance}" if instance and SAFE_OBJECT.fullmatch(instance) else "")
            hits.append(_hit("system", object_key, rows[0], "source-not-authenticated"))
    return Result(gap, tuple(hits))


def _syslog_targets(tree):
    return {host: rows for host, rows in _entries(tree, (*SYSLOG, "host")).items()
            if host not in ("other-routing-engine", "local", "localhost") and any(
                len(path) == 2 and path[0] in FACILITIES and path[1] in LEVELS for path, _ in rows)}


@_register("no_syslog_target", SYSLOG, absence=True)
def no_syslog_target(tree, context):
    if _syslog_targets(tree):
        return Result()
    gap = _reason(tree, context, "system")
    return Result(gap) if gap else Result(hits=(
        _hit("system", "syslog", _first(tree, SYSLOG), "no-remote-target"),))


@_register("syslog_level", SYSLOG, applies=lambda intent: "syslog_severity" in intent)
def syslog_level(tree, context):
    gap = _reason(tree, context, "system")
    required = LEVELS[context.intent["syslog_severity"]]
    hits = []
    for host, rows in _syslog_targets(tree).items():
        if any(path[:1] in (("match",), ("match-strings",)) for path, _ in rows):
            gap = gap or "syslog-filter-unproven"
            continue
        levels = {path[0]: LEVELS.get(path[1], -1) for path, _ in rows
                  if len(path) == 2 and path[0] in FACILITIES}
        if not _reason(tree, context, "system") and SAFE_OBJECT.fullmatch(host) and any(
                levels.get(facility, levels.get("any", -1)) < required for facility in ("authorization", "daemon")):
            hits.append(_hit("system", host, rows[0][1], "insufficient-facility-coverage"))
    return Result(gap, tuple(hits))


def _ports(intent, role=None, flag=None, value=True):
    return {name: settings for name, settings in intent.get("ports", {}).items()
            if (role is None or settings.get("role") == role) and (flag is None or settings.get(flag) == value)}


def _port_rows(tree, name):
    return tree.matching("interfaces", name)


def _disabled(tree, name, *, unit=True):
    paths = [("interfaces", name)]
    if unit:
        paths.append(("interfaces", name, "unit", "0"))
    return any(
        path in tree.disabled or _first(tree, (*path, "disable")) for path in paths)


PORT_NUMBER = re.compile(r"([a-z]+-[0-9]+/[0-9]+/)([0-9]+)")


def _range_member(name, rest):
    """Return whether an interface-range member statement can include a port."""
    port = PORT_NUMBER.fullmatch(name)
    if rest[:1] == ("member",) and len(rest) == 2:
        return rest[1] == name or any(mark in rest[1] for mark in "*[]")
    if rest[:1] == ("member-range",) and len(rest) == 4 and rest[2] == "to":
        low, high = PORT_NUMBER.fullmatch(rest[1]), PORT_NUMBER.fullmatch(rest[3])
        if not (port and low and high and low[1] == high[1]):
            # A range across slots or of other port names may include the port.
            return True
        return port[1] == low[1] and int(low[2]) <= int(port[2]) <= int(high[2])
    return False


def _in_range(tree, name):
    """A port in an interface-range takes settings the rules do not merge."""
    path = ("interfaces", "interface-range")
    return any(_range_member(name.partition(".")[0], row.tokens[len(path) + 1:])
               for row in tree.matching(*path))


def _switch_path(name):
    return ("interfaces", name, "unit", "0", "family", "ethernet-switching")


def _els(context, tree):
    return (context.snapshot is not None and context.snapshot.inventory_platform == "juniper_junos_els"
            or any(row.tokens[6:7] == ("interface-mode",)
                   and row.tokens[4:6] == ("family", "ethernet-switching")
                   for row in tree.matching("interfaces")))


def _l2_port(tree, context, name):
    path = _switch_path(name)
    gap = _reason(tree, context, "interfaces")
    if not _port_rows(tree, name) and ("interfaces", name) not in tree.disabled:
        return path, None, gap or "interface-unproven"
    if _disabled(tree, name):
        return path, "disabled", ""
    if _in_range(tree, name):
        return path, None, gap or "interface-range-unproven"
    if not _first(tree, path) or not _els(context, tree):
        return path, None, gap or "els-port-unproven"
    mode, _ = _leaf(tree, (*path, "interface-mode"))
    return path, mode or ("access" if not gap else None), gap


def _vlan_ids(tree):
    return {row.tokens[1]: int(row.tokens[3])
            for row in tree.matching("vlans") if len(row.tokens) == 4
            and row.tokens[2] == "vlan-id" and row.tokens[3].isdecimal()}


def _membership(tree, path, mode, ids, gap):
    members = {word for row in tree.matching(*path, "vlan", "members")
               for word in row.tokens[len(path) + 2:] if word not in ("[", "]")}
    if not members and mode == "access" and not gap and "default" in ids:
        members = {"default"}
    if members == {"all"} and mode == "trunk" and not gap:
        return set(ids.values())
    if not members or any(member not in ids and not member.isdecimal() for member in members):
        return None
    return {ids[member] if member in ids else int(member) for member in members}


@_register("edge_discovery", LLDP, applies=lambda intent: _ports(intent, "edge", "discovery_allowed", False))
def edge_discovery(tree, context):
    gap = ""
    hits = []
    if _first(tree, (*LLDP, "disable")):
        return Result()
    all_ports = _first(tree, (*LLDP, "interface", "all"))
    all_disabled = _first(tree, (*LLDP, "interface", "all", "disable"))
    for name in _ports(context.intent, "edge", "discovery_allowed", False):
        if _disabled(tree, name):
            continue
        if _in_range(tree, name):
            gap = gap or "interface-range-unproven"
            continue
        selected = next((row for port in (name, name + ".0")
                         if (row := _first(tree, (*LLDP, "interface", port)))), None)
        if any(_first(tree, (*LLDP, "interface", port, "disable")) for port in (name, name + ".0")):
            continue
        if selected:
            hits.append(_hit("protocols", name, selected, "lldp-enabled"))
        elif all_ports and not all_disabled and not _reason(tree, context, "protocols", "interfaces") and _port_rows(tree, name):
            hits.append(_hit("protocols", name, all_ports, "lldp-enabled"))
        else:
            gap = gap or _reason(tree, context, "protocols", "interfaces")
            if not _port_rows(tree, name):
                gap = gap or "interface-unproven"
    return Result(gap, tuple(hits))


@_register("bpdu_guard", ("protocols",), applies=lambda intent: _ports(intent, "edge"))
def bpdu_guard(tree, context):
    gap = ""
    hits = []
    for name in _ports(context.intent, "edge"):
        path, mode, port_gap = _l2_port(tree, context, name)
        if mode == "disabled":
            continue
        explicit = ("protocols", "layer2-control", "bpdu-block", "interface")
        if any(_first(tree, (*explicit, port)) for port in (name, name + ".0")):
            continue
        known = []
        for protocol in ("rstp", "mstp", "vstp"):
            branches = [("protocols", protocol)]
            if protocol == "vstp":
                branches = [("protocols", "vstp", "vlan", vlan)
                            for vlan in _entries(tree, ("protocols", "vstp", "vlan"))]
            for branch in branches:
                edge = next((row for port in (name, name + ".0", "all")
                             if (row := _first(tree, (*branch, "interface", port, "edge")))), None)
                if edge and not _first(tree, (*branch, "disable")) and not any(
                        _first(tree, (*branch, "interface", port, "disable")) for port in (name, name + ".0", "all")):
                    guard = _first(tree, ("protocols", protocol, "bpdu-block-on-edge"))
                    known.append((edge, guard))
        port_gap = port_gap or _reason(tree, context, "protocols")
        if known and all(guard for _, guard in known) and not port_gap:
            continue
        if port_gap or not known:
            gap = gap or port_gap or "stp-edge-unproven"
            continue
        hits.append(_hit("protocols", name, known[0][0], "edge-without-bpdu-guard"))
    return Result(gap, tuple(hits))


@_register("default_vlan", ("interfaces",), applies=lambda intent: _ports(intent, "edge", "default_vlan_allowed", False))
def default_vlan(tree, context):
    gap = ""
    hits = []
    ids = _vlan_ids(tree)
    for name in _ports(context.intent, "edge", "default_vlan_allowed", False):
        path, mode, port_gap = _l2_port(tree, context, name)
        if mode == "disabled":
            continue
        if mode != "access":
            gap = gap or port_gap or "access-mode-unproven"
            continue
        member_ids = _membership(tree, path, mode, ids, port_gap)
        if member_ids is None:
            gap = gap or port_gap or _reason(tree, context, "vlans") or "vlan-membership-unproven"
        elif 1 in member_ids:
            hits.append(_hit("interfaces", name, _first(tree, path), "access-vlan-one"))
        else:
            gap = gap or port_gap or _reason(tree, context, "vlans")
    return Result(gap, tuple(hits))


@_register("trunk_native", ("interfaces",), applies=lambda intent: any(
    "native_vlan" in port for port in _ports(intent, "trunk").values()))
def trunk_native(tree, context):
    gap = ""
    hits = []
    for name, settings in _ports(context.intent, "trunk").items():
        if "native_vlan" not in settings:
            continue
        path, mode, port_gap = _l2_port(tree, context, name)
        if mode == "disabled":
            continue
        if mode != "trunk":
            gap = gap or port_gap or "trunk-mode-unproven"
            continue
        native, row = _leaf(tree, ("interfaces", name, "native-vlan-id"))
        if native and native.isdecimal():
            if int(native) != settings["native_vlan"]:
                hits.append(_hit("interfaces", name, row, "native-vlan-differs"))
            else:
                members = _membership(tree, path, mode, _vlan_ids(tree), port_gap)
                if members is None:
                    gap = gap or port_gap or _reason(tree, context, "vlans") or "vlan-membership-unproven"
                elif int(native) not in members:
                    member_gap = port_gap or _reason(tree, context, "vlans")
                    if member_gap:
                        gap = gap or member_gap
                    else:
                        hits.append(_hit("interfaces", name, row, "native-vlan-not-member"))
        elif not port_gap and native is None:
            hits.append(_hit("interfaces", name, _first(tree, path), "untagged-not-admitted"))
        else:
            gap = gap or port_gap or "native-vlan-unproven"
    return Result(gap, tuple(hits))


@_register("dhcp_snooping", ("vlans",), applies=lambda intent: intent.get("dhcp_snooping_vlans"))
def dhcp_snooping(tree, context):
    gap = _reason(tree, context, "vlans", "interfaces")
    if not _els(context, tree):
        return Result(gap or "els-dhcp-mode-unproven")
    if gap:
        return Result(gap)
    if _first(tree, ("interfaces", "interface-range")):
        # Range members take VLAN membership the rule does not merge.
        return Result("interface-range-unproven")
    hits = []
    ids = _vlan_ids(tree)
    trusted = {name.removesuffix(".0") for name in context.intent.get("trusted_dhcp_ports", ())}
    names = _entries(tree, ("interfaces",))
    for number in context.intent["dhcp_snooping_vlans"]:
        vlans = [name for name, tag in ids.items() if tag == number]
        if len(vlans) != 1:
            gap = gap or "vlan-mapping-unproven"
            continue
        path = ("vlans", vlans[0], "forwarding-options", "dhcp-security")
        security = _first(tree, path)
        if not security:
            hits.append(_hit("vlans", str(number), _first(tree, path[:2]), "dhcp-security-absent"))
            continue
        overrides = defaultdict(set)
        for leaves in _entries(tree, (*path, "group")).values():
            roles = {leaf[1] for leaf, _ in leaves if leaf in (("overrides", "trusted"), ("overrides", "untrusted"))}
            for leaf, _ in leaves:
                if len(leaf) == 2 and leaf[0] == "interface":
                    overrides[leaf[1]].update(roles)
        mismatches = 0
        for name in names:
            switch, mode, _ = _l2_port(tree, context, name)
            if mode is None or mode == "disabled":
                continue
            membership = _membership(tree, switch, mode, ids, "")
            if membership is None or number not in membership:
                if membership is None:
                    gap = gap or "vlan-membership-unproven"
                continue
            if mode not in ("access", "trunk"):
                gap = gap or "dhcp-port-mode-unproven"
                continue
            roles = overrides[name + ".0"]
            if len(roles) > 1:
                gap = gap or "dhcp-port-trust-unproven"
                continue
            actual = "trusted" in roles if roles else mode == "trunk"
            mismatches += actual != (name in trusted)
        if mismatches:
            hits.append(_hit("vlans", str(number), security, "dhcp-trust-differs", mismatches))
    return Result(gap, tuple(hits))


@_register("storm_control", ("interfaces",), applies=lambda intent: _ports(intent, flag="storm_control_required"))
def storm_control(tree, context):
    gap = ""
    hits = []
    for name in _ports(context.intent, flag="storm_control_required"):
        path, mode, port_gap = _l2_port(tree, context, name)
        if mode == "disabled":
            continue
        if mode is None:
            gap = gap or port_gap
            continue
        profile, row = _leaf(tree, (*path, "storm-control"))
        scope = ("forwarding-options", "storm-control-profiles", profile, "all")
        exclusions = ("no-broadcast", "no-multicast", "no-unknown-unicast")
        if all(_first(tree, (*scope, exclusion)) for exclusion in exclusions):
            hits.append(_hit("interfaces", name, row, "storm-control-disabled"))
            continue
        limit = next((value for key in ("bandwidth-level", "bandwidth-percentage")
                      if (value := _leaf(tree, (*scope, key))[0])), None)
        if limit and limit.isdecimal() and int(limit) > 0:
            continue
        if profile == "default" and not _first(tree, scope[:3]) and not _reason(tree, context, "forwarding-options"):
            # This is an explicit attachment of the predefined ELS profile.
            continue
        gap = gap or port_gap or _reason(tree, context, "forwarding-options") or "storm-profile-unproven"
    return Result(gap, tuple(hits))


@_register("unused_up", ("interfaces",), applies=lambda intent: _ports(intent, "unused"))
def unused_up(tree, context):
    gap = ""
    hits = []
    for name in _ports(context.intent, "unused"):
        if _disabled(tree, name, unit=False):
            continue
        row = _first(tree, ("interfaces", name))
        port_gap = _reason(tree, context, "interfaces") or ("interface-range-unproven" if _in_range(tree, name) else "")
        if "." in name or not row or port_gap:
            gap = gap or port_gap or "physical-interface-unproven"
        else:
            hits.append(_hit("interfaces", name, row, "unused-port-not-disabled"))
    return Result(gap, tuple(hits))


def _subtract(intervals, cuts):
    for low, high in cuts:
        remaining = []
        for start, end in intervals:
            if end < low or high < start:
                remaining.append((start, end))
            else:
                if start < low:
                    remaining.append((start, low - 1))
                if end > high:
                    remaining.append((high + 1, end))
        intervals = remaining
    return intervals


def _interval(prefix):
    return int(prefix.network_address), int(prefix.broadcast_address)


def _term(leaves, family, port):
    matches = defaultdict(set)
    actions = set()
    for leaf, _ in leaves:
        if len(leaf) >= 3 and leaf[0] == "from":
            matches[leaf[1]].add(leaf[2:])
        elif len(leaf) >= 2 and leaf[0] == "then":
            actions.add(leaf[1])
        else:
            return None
    for keyword in ("protocol", "next-header"):
        if keyword in matches:
            values = {value for group in matches[keyword] for value in group if value not in ("[", "]")}
            if not values.intersection({"tcp", "6"}):
                return [], False
    for keyword in ("port", "destination-port"):
        if keyword not in matches:
            continue
        values = {value for group in matches[keyword] for value in group if value not in ("[", "]")}
        numbers = {SERVICE_PORTS.get(value, int(value) if value.isdecimal() else None) for value in values}
        if port not in numbers:
            if None in numbers or keyword == "port":
                return None
            return [], False
    if set(matches) - {"protocol", "next-header", "port", "destination-port", "source-address"}:
        return None
    sources = []
    for clause in matches.get("source-address", ()):
        if len(clause) != 1:
            return None
        try:
            network = ip_network(clause[0], strict=False)
        except ValueError:
            return None
        if network.version == family:
            sources.append(_interval(network))
    if not matches.get("source-address"):
        sources = [(0, 2 ** (32 if family == 4 else 128) - 1)]
    if "next" in actions or not actions.intersection({"accept", "discard", "reject"}):
        return None
    return sources, "accept" in actions


def _filter_covers(terms, family, port, expected):
    remaining = [(0, 2 ** (32 if family == 4 else 128) - 1)]
    allowed = []
    for leaves in terms.values():
        if not remaining:
            break
        decision = _term(leaves, family, port)
        if decision is None:
            return None
        matches, accept = decision
        if accept:
            allowed.extend((max(start, low), min(end, high)) for start, end in remaining
                           for low, high in matches if start <= high and low <= end)
        remaining = _subtract(remaining, matches)
    return not (_subtract(allowed, expected) or _subtract(expected, allowed))


def _management_services(tree):
    return {name: path for name, path in (
        ("ssh", SSH), ("telnet", (*SERVICES, "telnet")),
        ("http", (*SERVICES, "web-management", "http")),
        ("https", (*SERVICES, "web-management", "https")),
    ) if _first(tree, path)}


def _management_path(name):
    return name == "lo0" or re.fullmatch(r"(?:fxp|em|me|vme|re)[0-9]+", name) is not None


@_register("access_acl", ("interfaces", "lo0"), applies=lambda intent: intent.get("management_prefixes"))
def access_acl(tree, context):
    gap = _reason(tree, context, "system", "interfaces")
    services = _management_services(tree)
    if not services:
        return Result(gap)
    listeners = {name: {token for row in tree.matching(*path, "interface")
                        for token in row.tokens[len(path) + 1:] if token not in ("[", "]")}
                 for name, path in services.items()}
    prefixes = [ip_network(value) for value in context.intent["management_prefixes"]]
    requested = {interface.partition(".")[0] for bindings in listeners.values() for interface in bindings}
    paths = defaultdict(set)
    for name in _entries(tree, ("interfaces",)):
        if not (_management_path(name) or name in requested) or _disabled(tree, name):
            continue
        for statement in _port_rows(tree, name):
            tokens = statement.tokens
            if len(tokens) >= 6 and tokens[2] == "unit" and tokens[4] == "family" and tokens[5] in ("inet", "inet6"):
                paths[name].add((tokens[3], tokens[5]))
    if not paths:
        return Result(gap or "management-path-unproven")
    hits = []
    covered_listeners = set()
    for name, families in sorted(paths.items()):
        for unit, family in sorted(families):
            applicable = [service for service, bindings in listeners.items()
                          if bindings.intersection({name, name + "." + unit})
                          or not bindings and _management_path(name)]
            if not applicable:
                continue
            covered_listeners.update(applicable)
            path = ("interfaces", name, "unit", unit, "family", family)
            if not _first(tree, (*path, "address")):
                gap = gap or "management-address-unproven"
                continue
            version = 4 if family == "inet" else 6
            expected = [_interval(network) for network in prefixes if network.version == version]
            binding = (*path, "filter")
            filter_name, row = _leaf(tree, (*binding, "input"))
            if _first(tree, (*binding, "input-list")):
                gap = gap or "management-filter-chain-unproven"
                continue
            key = f"{name}.{unit}/{family}"
            if not filter_name:
                if not _reason(tree, context, "system", "interfaces"):
                    hits.append(_hit("interfaces", key, _first(tree, path), "no-input-filter"))
                continue
            firewall_gap = _reason(tree, context, "firewall")
            if firewall_gap or _reason(tree, context, "system", "interfaces"):
                gap = gap or firewall_gap
                continue
            terms = _entries(tree, ("firewall", "family", family, "filter", filter_name, "term"))
            if not terms:
                gap = gap or "management-filter-unproven"
                continue
            statuses = []
            for service in applicable:
                configured_port, _ = _leaf(tree, (*services[service], "port"))
                if configured_port is not None and not configured_port.isdecimal():
                    statuses.append(None)
                    continue
                port = SERVICE_PORTS[service] if configured_port is None else int(configured_port)
                statuses.append(_filter_covers(terms, version, port, expected))
            if False in statuses:
                hits.append(_hit("interfaces", key, row, "management-prefixes-differ"))
            if None in statuses:
                gap = gap or "management-filter-terms-unproven"
    if services.keys() - covered_listeners:
        gap = gap or "management-listener-path-unproven"
    if any(not bindings for bindings in listeners.values()):
        # An unbound service also answers on addressed in-band units (irb, routed ports);
        # only a loopback input filter of that family covers them.
        unfiltered = _in_band_families(tree) - {
            family for family in ("inet", "inet6")
            if _first(tree, ("interfaces", "lo0", "unit", "0", "family", family, "filter"))}
        if unfiltered:
            gap = gap or "in-band-management-unproven"
    return Result(gap, tuple(hits))


def _in_band_families(tree):
    return {row.tokens[5] for name in _entries(tree, ("interfaces",))
            if name != "interface-range" and not _management_path(name) and not _disabled(tree, name)
            for row in _port_rows(tree, name)
            if len(row.tokens) >= 7 and row.tokens[2] == "unit" and row.tokens[4] == "family"
            and row.tokens[5] in ("inet", "inet6") and row.tokens[6] == "address"}
