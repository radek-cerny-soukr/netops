"""Cisco NX-OS controls over parsed configuration and bounded exec evidence."""
from collections import defaultdict
from functools import partial
from ipaddress import ip_address, ip_network
import re

from .engine import EVALUATED, NOT_EVALUATED, check, section_missing
from .platforms import VISIBLE

UPLINK = re.compile(r"(?:Ethernet\d+/\d+(?:/\d+)?|port-channel\d+)", re.I)
PHYSICAL = re.compile(r"Ethernet\d+/\d+(?:/\d+)?", re.I)
LEVELS = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
LEVEL_ALIASES = {"emergencies": 0, "alerts": 1, "errors": 3, "warnings": 4,
                 "notifications": 5, "informational": 6, "debugging": 7}


def _matching(rows, *words):
    return tuple(row for row in rows if row.starts_with(*words))


def _last(rows, *words):
    return next((row for row in reversed(rows) if row.starts_with(*words)), None)


def _enabled(row, default=None):
    return default if row is None or row.mode == "default" else row.mode == "set"


def _value(row, index, default=None):
    return row.tokens[index] if row and row.mode == "set" and len(row.tokens) > index else default


def _number(value, low, high):
    return int(value) if value and re.fullmatch(r"[0-9]{1,5}", value) and low <= int(value) <= high else None


def _active(rows, prefix, fields=1):
    """Resolve repeated entries and keyed or family-wide removals in order."""
    result = {}
    size = len(prefix) + fields
    for row in _matching(rows, *prefix):
        key = row.tokens[len(prefix):size]
        if row.mode == "set" and len(row.tokens) >= size:
            result[key] = row
        elif row.mode != "set":
            for existing in tuple(result):
                if existing[:len(key)] == key:
                    del result[existing]
    return result


def _hit(section, row=None, obj="global", **evidence):
    return dict(section=section, line=row.line if row else 0, object_key=obj, evidence=evidence)


class Inputs:
    def __init__(self, tree, context):
        self.blocks = defaultdict(list)
        for row in tree.commands:
            self.blocks[row.parents].append(row)
        self.context = context
        self.config = self.children()
        self.intent = context.intent
        self.reason = ""

    def children(self, *parents):
        return self.blocks.get(parents, ())

    def full(self, section):
        status = self.context.visibility(section)
        snapshot = self.context.snapshot
        return (snapshot is not None and snapshot.complete and status.state == VISIBLE
                and status.reason == "verified-profile")

    def missing(self, section):
        if not self.reason:
            reason = self.context.visibility(section).reason
            self.reason = section_missing(section) if self.context.snapshot is None else (
                reason if reason not in {"content", "auxiliary-output", "verified-profile"} else "visibility-unproven")
        return ()

    def auxiliary(self, name):
        snapshot = self.context.snapshot
        if snapshot is not None and snapshot.complete and self.context.visibility(name).reason == "auxiliary-output":
            return snapshot.auxiliary.get(name, "")
        return ""

    @property
    def release_93(self):
        return bool(re.fullmatch(r"9\.3\(\d+\)", _value(_last(self.config, "version"), 1, "")))

    def feature(self, name):
        row = _last(self.config, "feature", name)
        if row and row.mode != "default":
            return _enabled(row)
        if self.release_93 and (row or self.full("feature")):
            return False
        return None

    def ports(self, predicate, pattern=UPLINK):
        # Only names assigned an audit role enter the result.
        rows = {row.tokens[1].lower(): row for row in _matching(self.config, "interface") if len(row.tokens) == 2}
        for name, policy in self.intent.get("ports", {}).items():
            if not predicate(policy) or not pattern.fullmatch(name):
                continue
            row = rows.get(name.lower())
            if row is None or row.mode != "set":
                self.missing("interface")
            else:
                yield row.tokens[1], policy, row, self.children(row.tokens)


def _register(probe, section, applies=None):
    def status(tree, context):
        inputs = Inputs(tree, context)
        tuple(probe(inputs))
        return (NOT_EVALUATED, inputs.reason) if inputs.reason else (EVALUATED, "")

    def findings(tree, context):
        return probe(Inputs(tree, context))

    check("nxos_" + probe.__name__, audit_context=True, status=status, partial=True,
          applies=applies, offline_scope=lambda tree: tree.section(section) is not None)(findings)


def telnet(a):
    enabled = a.feature("telnet")
    if enabled is None:
        return a.missing("feature")
    return (_hit("feature", _last(a.config, "feature", "telnet"), state="enabled"),) if enabled else ()


def http(a):
    feature = a.feature("nxapi")
    if feature is False:
        return ()
    row = next((row for row in reversed(a.config) if row.starts_with("nxapi", "http", "port")
                or row.tokens == ("nxapi", "http")), None)
    if feature is True and row and row.mode == "no":
        return ()
    port = _number(_value(row, 3), 1, 65535)
    if feature is True and port:
        return (_hit("nxapi", row, port=port),)
    listener = a.auxiliary("nxapi listener")
    if re.search(r"(?mi)^\s*NX-API\s+http(?:\s+server)?\s+is\s+disabled\b", listener):
        return ()
    match = re.search(r"(?mi)^\s*(?:NX-API\s+)?HTTP\s+Listen on port\s*:?\s*(\d+)\s*$", listener)
    if match and (port := _number(match[1], 1, 65535)):
        return (_hit("nxapi", row, port=port),)
    return a.missing("feature" if feature is None else "nxapi listener")


def idle_timeout(a):
    vty = _last(a.config, "line", "vty")
    local = a.children(vty.tokens) if vty and vty.mode == "set" else ()
    row = _last(local, "exec-timeout")
    if row and row.mode == "set":
        minutes = _number(_value(row, 1), 0, 65535)
        if minutes == 0:
            return (_hit("line vty", row, minutes=0),)
        if minutes is not None:
            return ()
    if a.release_93 and (row and row.mode != "set" or a.full("line vty")):
        return ()
    return a.missing("line vty")


def lockout(a):
    login = _last(a.config, "aaa", "authentication", "login", "default")
    method = _value(login, 4)
    row = _last(a.config, "aaa", "authentication", "rejected")
    if method == "none":
        return ()
    if row and row.mode == "set":
        words = row.tokens
        if len(words) == 8 and words[4::2] == ("in", "ban"):
            counts = tuple(_number(words[i], 0, 65535) for i in (3, 5, 7))
            if all(count is not None for count in counts):
                if all(counts):
                    return ()
                if method == "local":
                    return (_hit("aaa", row, state="disabled"),)
    # The command reference does not specify effective default blocking,
    # and an external provider may enforce its own policy.
    return a.missing("aaa")


def _acl_network(words, version):
    if words[:1] == ("any",):
        return ip_network("0.0.0.0/0" if version == 4 else "::/0"), words[1:]
    if words[:1] == ("host",) and len(words) > 1:
        return ip_network(words[1]), words[2:]
    if words and "/" in words[0]:
        return ip_network(words[0], strict=False), words[1:]
    if version == 4 and len(words) >= 2:
        mask = int(ip_address(words[1])) ^ 0xffffffff
        return ip_network(f"{words[0]}/{ip_address(mask)}", strict=False), words[2:]
    raise ValueError


def _remaining(networks, covered):
    for net in networks:
        if net.subnet_of(covered):
            continue
        yield from net.address_exclude(covered) if covered.subnet_of(net) else (net,)


def _acl_result(rows, expected, version):
    """Assess ordered address-only ACEs, including the implicit final deny."""
    if not rows:
        return None
    uncovered = [ip_network("0.0.0.0/0" if version == 4 else "::/0")]
    needed = list(expected)
    excess = False
    numbered = re.compile(r"[0-9]{1,10}")
    for row in sorted(rows, key=lambda item: int(item.tokens[0]) if numbered.fullmatch(item.tokens[0]) else item.line):
        words = row.tokens[1:] if numbered.fullmatch(row.tokens[0]) else row.tokens
        if not words or row.mode != "set":
            return None
        if words[0] in {"remark", "statistics"}:
            continue
        if words[0] not in {"permit", "deny"}:
            return None
        protocol = "ip" if version == 4 else "ipv6"
        try:
            if words[1:2] == (protocol,):
                source, rest = _acl_network(words[2:], version)
                if rest not in (("any",), ("any", "log")):
                    return None
            else:
                source, rest = _acl_network(words[1:], version)
                if rest not in ((), ("log",)):
                    return None
            if source.version != version:
                return None
        except ValueError:
            return None
        if words[0] == "permit":
            for net in uncovered:
                if net.overlaps(source):
                    extra = [net if net.subnet_of(source) else source]
                    for allowed in expected:
                        extra = list(_remaining(extra, allowed))
                    excess |= bool(extra)
            for net in uncovered:
                if net.overlaps(source):
                    needed = list(_remaining(needed, net if net.subnet_of(source) else source))
        uncovered = list(_remaining(uncovered, source))
    return not excess and not needed


def access_acl(a):
    vty = _last(a.config, "line", "vty")
    local = a.children(vty.tokens) if vty and vty.mode == "set" else ()
    prefixes = tuple(map(ip_network, a.intent["management_prefixes"]))
    for family, version in (("ip", 4), ("ipv6", 6)):
        expected = tuple(net for net in prefixes if net.version == version)
        if not expected:
            continue
        binding = next((row for row in reversed(local) if row.starts_with(family, "access-class")
                        and (row.tokens[3:4] == ("in",) or len(row.tokens) == 2)), None)
        acl = _value(binding, 2)
        section = family + " access-list"
        if not acl:
            if binding and binding.mode == "no" or a.full("line vty"):
                yield _hit("line vty", binding, family, state="unbound")
            else:
                a.missing("line vty")
            continue
        header = _last(a.config, family, "access-list", acl)
        if a.full(section):
            result = _acl_result(a.children(header.tokens), expected, version) if _enabled(header) else False
            if result is False:
                yield _hit(section, header or binding, family, state="prefix-mismatch")
            elif result is None:
                a.missing(section)
        else:
            a.missing(section)


def external_login(a):
    row = _last(a.config, "aaa", "authentication", "login", "default")
    method = _value(row, 4)
    if method in {"local", "none"} or ((row and row.mode != "set") or a.full("aaa")) and method is None and a.release_93:
        return (_hit("aaa", row, state="no-external-login"),)
    if method != "group" or len(row.tokens) < 6:
        return a.missing("aaa")
    groups = [name for name in row.tokens[5:] if name not in {"local", "none"}]
    unknown = False
    for group in groups:
        for kind, feature, command in (("radius", "radius", "radius-server"), ("tacacs+", "tacacs+", "tacacs-server")):
            header = _active(a.config, ("aaa", "group", "server", kind)).get((group,))
            if not _enabled(header):
                unknown |= not a.full("aaa")
                continue
            enabled = a.feature(feature)
            if enabled is False:
                continue
            members = _active(a.children(header.tokens), ("server",))
            hosts = _active(a.config, (command, "host"))
            if enabled is True and members.keys() & hosts.keys():
                return ()
            unknown |= enabled is None or not a.full("aaa")
    if unknown:
        return a.missing("aaa")
    return (_hit("aaa", row, state="no-usable-server"),)


def communities(a):
    if _enabled(_last(a.config, "snmp-server", "disable")):
        return ()
    rows = _active(a.config, ("snmp-server", "community"))
    enabled = [row for row in rows.values() if row.tokens[3:4] in (("group",), ("use-acl",), ("use-ipv4acl",),
                                                                      ("use-ipv6acl",))]
    if not a.full("snmp") and (a.context.live or not enabled):
        a.missing("snmp")
    if enabled:
        return (_hit("snmp", enabled[0], "communities", count=len(enabled)),)
    return ()


def _snmp_users(output):
    """Read the Auth and Priv fields of the documented operational table."""
    header = re.search(r"(?mi)^\s*User[ \t]+Auth[ \t]+Priv\b[^\n]*", output)
    if header is None:
        return
    for line in output[header.end():].splitlines():
        words = line.split()
        privacy = words[2].lower().split("(", 1)[0] if len(words) >= 3 else ""
        if len(words) >= 3 and words[1].lower() in {"none", "no", "md5", "sha", "sha-1", "sha-256",
                                                    "sha-384", "sha-512"} and privacy in {
                "none", "no", "des", "aes", "aes-128", "aes-192", "aes-256"}:
            yield words[0], words[1].lower(), privacy


def _snmp_security(row):
    words = row.tokens[3:]
    if words and words[0] != "auth":
        words = words[1:]  # optional CLI role
    if len(words) < 3 or words[0] != "auth":
        return None
    auth = words[1].lower()
    if auth not in {"md5", "sha", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512"}:
        return None
    privacy = words[3:]
    if privacy[:1] == ("auto",):
        privacy = privacy[1:]
    # auth and priv secrets occupy exactly one slot each, even when masked.
    if privacy[:1] != ("priv",):
        return auth, "none"
    if len(privacy) < 2:
        return None
    if (len(privacy) >= 3 and privacy[1] in {"aes-128", "aes-192", "aes-256"}
            and privacy[2] not in {"localizedkey", "localizedV2key", "engineID"}):
        return auth, privacy[1]
    return auth, "des"


def snmp_users(a):
    if _enabled(_last(a.config, "snmp-server", "disable")):
        return
    # Discard per-user modifiers and remote-engine users, which authenticate
    # notifications. A name-only removal still cancels a previous user.
    rows = tuple(row for row in _matching(a.config, "snmp-server", "user")
                 if "engineID" not in row.tokens[3:]
                 and row.tokens[3:4] not in (("enforcePriv",), ("use-acl",)))
    local = {key[0]: row for key, row in _active(rows, ("snmp-server", "user")).items()}
    output = a.auxiliary("snmp users")
    effective = {name: (auth, privacy) for name, auth, privacy in _snmp_users(output)}
    unknown = False
    counts = {}
    for name in local.keys() | effective.keys():
        row = local.get(name)
        pair = effective.get(name) or (_snmp_security(row) if row else None)
        if pair is None:
            unknown = True
            continue
        auth, privacy = pair
        if auth in {"none", "no"} or privacy not in {"aes", "aes-128", "aes-192", "aes-256"}:
            scheme = "des" if privacy == "des" else "no-auth-priv"
            line, count = counts.get(scheme, (row, 0))
            if row and (line is None or row.line < line.line):
                line = row
            counts[scheme] = line, count + 1
    if unknown or (a.context.live or not counts) and not a.full("snmp") and not re.search(
            r"(?mi)^\s*User\s+Auth\s+Priv\b", output):
        a.missing("snmp users")
    for scheme, (row, count) in counts.items():
        yield _hit("snmp", row, scheme, privacy=scheme, count=count)


def _option(row, name, offset):
    try:
        index = row.tokens.index(name, offset)
    except ValueError:
        return None
    return row.tokens[index + 1] if len(row.tokens) > index + 1 else None


def _external_host(value):
    try:
        address = ip_address(value)
        return not (address.is_unspecified or address.is_loopback or address.is_multicast)
    except ValueError:
        return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?", value, re.I)
                    and re.search(r"[a-z]", value, re.I))


def _destinations(rows, prefixes):
    active = {}
    for prefix in prefixes:
        for row in _matching(rows, *prefix):
            index = len(prefix)
            if len(row.tokens) <= index:
                continue
            host = row.tokens[index]
            if host == "dns-refresh-interval":
                continue
            vrf = _option(row, "use-vrf", index + 1) or "default"
            key = (prefix, host, vrf)
            if row.mode == "set":
                active[key] = row
            else:
                active.pop(key, None)
    return tuple(row for (_, host, _), row in active.items() if _external_host(host))


def _ntp(a):
    return _destinations(a.config, (("ntp", "server"), ("ntp", "peer")))


def ntp_source(a):
    if _ntp(a):
        return ()
    if a.full("ntp"):
        return (_hit("ntp", count=0),)
    return a.missing("ntp")


def ntp_auth(a):
    peers = _ntp(a)
    auth = _last(a.config, "ntp", "authenticate")
    if not peers:
        return () if a.full("ntp") else a.missing("ntp")
    if _enabled(auth) is False:
        return (_hit("ntp", auth, state="authentication-disabled"),)
    keys = {key for key, row in _active(a.config, ("ntp", "authentication-key")).items()
            if len(row.tokens) >= 5 and row.tokens[3] in {"md5", "aes128cmac"}}
    trusted = _active(a.config, ("ntp", "trusted-key"))
    failed = []
    for peer in peers:
        key = _option(peer, "key", 3)
        if not key or a.full("ntp") and (not _enabled(auth) or (key,) not in keys or (key,) not in trusted):
            failed.append(peer)
        elif not (_enabled(auth) and (key,) in keys and (key,) in trusted):
            a.missing("ntp")
    if failed:
        return (_hit("ntp", failed[0], state="unprotected-source", count=len(failed)),)
    return ()


def _syslog(a):
    return _destinations(a.config, (("logging", "server"),))


def syslog_target(a):
    if _syslog(a):
        return ()
    if a.full("logging"):
        return (_hit("logging", count=0),)
    return a.missing("logging")


def _severity(value):
    return _number(value, 0, 7) if value and value.isdigit() else (
        LEVELS.index(value) if value in LEVELS else LEVEL_ALIASES.get(value))


def syslog_level(a):
    expected = _severity(str(a.intent["syslog_severity"]))
    servers = _syslog(a)
    if not servers:
        return () if a.full("logging") else a.missing("logging")
    limits = []
    for row in servers:
        value = _value(row, 3)
        level = 5 if value in (None, "use-vrf", "facility", "port", "secure") and a.release_93 else _severity(value)
        if level is None:
            a.missing("logging")
        elif level < expected:
            limits.append((level, row))
    for row in _active(a.config, ("logging", "level")).values():
        level = _severity(_value(row, 3))
        if level is not None and level < expected:
            limits.append((level, row))
    if limits:
        level, row = min(limits, key=lambda item: item[0])
        return (_hit("logging", row, level=level, expected=expected, count=len(limits)),)
    return ()


def edge_discovery(a):
    cdp = _enabled(_last(a.config, "cdp", "enable"),
                   True if a.release_93 and a.full("global") else None)
    lldp = a.feature("lldp")
    for name, _, header, local in a.ports(lambda p: p["role"] == "edge" and p.get("discovery_allowed") is False):
        signals = []
        for protocol, global_state, row in (
            ("cdp", cdp, _last(local, "cdp", "enable")),
            ("lldp", lldp, _last(local, "lldp", "transmit")),
        ):
            enabled = _enabled(row, True if a.release_93 and a.full("interface") else None)
            if global_state is True and enabled is True:
                signals.append(protocol)
            elif global_state is not False and enabled is not False:
                a.missing("feature" if global_state is None else "interface")
        if signals:
            yield _hit("interface", header, name, protocols=",".join(signals))


def bpdu_guard(a):
    default = _enabled(_last(a.config, "spanning-tree", "port", "type", "edge", "bpduguard", "default"))
    if default is None and a.release_93 and a.full("global"):
        default = False
    for name, _, _, local in a.ports(lambda p: p["role"] == "edge"):
        row = _last(local, "spanning-tree", "bpduguard")
        port_type = _last(local, "spanning-tree", "port", "type")
        edge = _value(port_type, 3, _value(_last(a.config, "spanning-tree", "port", "type", "edge", "default"), 3))
        mode = _value(row, 2)
        if mode == "enable" or (mode != "disable" and default is True and edge == "edge"
                                and (a.full("interface") or row and row.mode == "default")):
            continue
        if mode == "disable" or a.full("interface") and (default is False or edge in {"network", "normal"}):
            yield _hit("interface", row or port_type, name, state="unprotected")
        else:
            a.missing("interface")


# NX-OS 9.3(x) prints neither the platform's Layer 2 default nor an enabled port; a bare
# Ethernet port in the Admin 9.3(12) capture is an access port in VLAN 1 and not shut down.
DEFAULTS_93 = {(): True, ("shutdown",): False}


def _system_default(a, *words):
    """State of exactly `[no] system default switchport [shutdown]`, or the proven 9.3 default."""
    row = next((row for row in reversed(a.config)
                if row.tokens == ("system", "default", "switchport", *words)), None)
    if row is not None and row.mode != "default":
        return row.mode == "set"
    return DEFAULTS_93[words] if a.release_93 and a.full("global") else None


def _switch_mode(a, local):
    sw = next((row for row in reversed(local) if row.tokens == ("switchport",)), None)
    if _enabled(sw) is False:
        return "routed"
    line = _last(local, "switchport", "mode")
    mode = _value(line, 2)
    if mode in {"access", "trunk"}:
        return mode
    if line is not None or not a.release_93:
        return None
    # A Layer 2 command proves a switchport; NX-OS prints every mode except access.
    if _enabled(sw) or _value(_last(local, "switchport", "access", "vlan"), 3):
        return "access"
    if a.full("interface"):
        layer2 = _system_default(a)
        if layer2 is not None:
            return "access" if layer2 else "routed"
    return None


def default_vlan(a):
    for name, _, header, local in a.ports(lambda p: p.get("default_vlan_allowed") is False and p["role"] == "edge"):
        row = _last(local, "switchport", "access", "vlan")
        vlan = _number(_value(row, 3), 1, 4094)
        if vlan is not None and vlan != 1:
            continue  # Not in VLAN 1 in any mode.
        mode = _switch_mode(a, local)
        if vlan is None and a.release_93 and (row and row.mode != "set" or a.full("interface")):
            vlan = 1
        if mode == "access" and vlan == 1:
            yield _hit("interface", row or header, name, vlan=1)
        elif mode == "access" and vlan is None or mode is None:
            a.missing("interface")


def trunk_native(a):
    for name, policy, _, local in a.ports(lambda p: p["role"] == "trunk" and "native_vlan" in p):
        mode = _switch_mode(a, local)
        row = _last(local, "switchport", "trunk", "native", "vlan")
        vlan = _number(_value(row, 4), 1, 4094)
        if vlan is None and a.release_93 and (row and row.mode != "set" or a.full("interface")):
            vlan = 1
        if mode == "trunk" and vlan is not None and vlan != policy["native_vlan"]:
            yield _hit("interface", row, name, vlan=vlan, expected=policy["native_vlan"])
        elif mode == "trunk" and vlan is None or mode is None:
            a.missing("interface")


def _vlans(text):
    result = set()
    for part in text.split(","):
        start, dash, end = part.partition("-")
        low, high = _number(start, 1, 4094), _number(end if dash else start, 1, 4094)
        if low is None or high is None or high < low:
            return None
        result.update(range(low, high + 1))
    return result


def dhcp_snooping(a):
    wanted = set(a.intent["dhcp_snooping_vlans"])
    feature = a.feature("dhcp")
    global_row = next((row for row in reversed(a.config) if row.tokens == ("ip", "dhcp", "snooping")), None)
    enabled = _enabled(global_row, False if a.release_93 and a.full("global") else None)
    if feature is False or enabled is False:
        yield _hit("global", global_row, state="disabled", count=len(wanted))
        return
    if not feature or not enabled:
        a.missing("global" if feature else "feature")
        return
    covered = set()
    removed = set()
    for row in _matching(a.config, "ip", "dhcp", "snooping", "vlan"):
        value = _vlans(row.tokens[4]) if len(row.tokens) == 5 else None
        if value is None:
            a.missing("global")
            continue
        if row.mode == "set":
            covered.update(value)
            removed.difference_update(value)
        else:
            covered.difference_update(value)
            removed.update(value)
    missing = wanted & removed
    if a.full("global") and not a.reason:
        missing = wanted - covered
    elif wanted - covered - removed:
        a.missing("global")
    if missing:
        yield _hit("global", global_row, state="unprotected-vlan", count=len(missing))
    trusted = {name.lower() for name in a.intent["trusted_dhcp_ports"]}
    ports = tuple(row for row in _matching(a.config, "interface") if _enabled(row) and len(row.tokens) == 2
                  and UPLINK.fullmatch(row.tokens[1]))
    found = set()
    for header in ports:
        name = header.tokens[1]
        allowed = name.lower() in trusted
        if allowed:
            found.add(name.lower())
        row = _last(a.children(header.tokens), "ip", "dhcp", "snooping", "trust")
        actual = _enabled(row, False if a.full("interface") else None)
        if actual is None and allowed:
            a.missing("interface")
        elif actual is not None and actual != allowed:
            yield _hit("interface", row or header, name, state="trust-mismatch", count=1)
    if trusted - found:
        a.missing("interface")


def storm_control(a):
    for name, _, header, local in a.ports(lambda p: p["role"] == "edge" and p.get("storm_control_required")):
        row = _last(local, "storm-control", "broadcast", "level")
        level = _value(row, 3)
        if level and re.fullmatch(r"\d{1,3}(?:\.\d{1,3})?", level):
            if float(level) < 100:
                continue
            if float(level) == 100:
                yield _hit("interface", row, name, state="ineffective")
                continue
        if a.release_93 and (row and row.mode != "set" or row is None and a.full("interface")):
            yield _hit("interface", row or header, name, state="disabled")
        else:
            a.missing("interface")


def unused_up(a):
    for name, _, header, local in a.ports(lambda p: p["role"] == "unused", PHYSICAL):
        row = _last(local, "shutdown")
        shutdown = _enabled(row)
        if shutdown is None and a.full("interface") and _switch_mode(a, local) in {"access", "trunk"}:
            shutdown = _system_default(a, "shutdown")
        if shutdown is False:
            yield _hit("interface", row or header, name, state="admin-up")
        elif shutdown is None:
            a.missing("interface")


def _intent(key, intent):
    return bool(intent.get(key))


def _port_intent(key, intent):
    return any(key in port for port in intent.get("ports", {}).values())


for probe, section, applies in (
    (telnet, "feature", None),
    (http, "nxapi", None),
    (idle_timeout, "line vty", None),
    (lockout, "aaa", None),
    (access_acl, "line vty", partial(_intent, "management_prefixes")),
    (external_login, "aaa", partial(_intent, "external_aaa_required")),
    (communities, "snmp", None),
    (snmp_users, "snmp", None),
    (ntp_source, "ntp", None),
    (ntp_auth, "ntp", partial(_intent, "ntp_auth_required")),
    (syslog_target, "logging", None),
    (syslog_level, "logging", lambda intent: "syslog_severity" in intent),
    (edge_discovery, "interface", partial(_port_intent, "discovery_allowed")),
    (bpdu_guard, "interface", lambda intent: any(p["role"] == "edge" for p in intent.get("ports", {}).values())),
    (default_vlan, "interface", partial(_port_intent, "default_vlan_allowed")),
    (trunk_native, "interface", partial(_port_intent, "native_vlan")),
    (dhcp_snooping, "global", lambda intent: bool(intent.get("dhcp_snooping_vlans")) and "trusted_dhcp_ports" in intent),
    (storm_control, "interface", partial(_port_intent, "storm_control_required")),
    (unused_up, "interface", lambda intent: any(p["role"] == "unused" for p in intent.get("ports", {}).values())),
):
    _register(probe, section, applies)
