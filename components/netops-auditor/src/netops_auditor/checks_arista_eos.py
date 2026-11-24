"""Configuration evidence for Arista EOS security controls."""
from __future__ import annotations

import ipaddress
import re

from .engine import EVALUATED, NOT_EVALUATED, check
from .management import SYSLOG_LEVELS
from .platforms import VISIBLE

PREFIX = "arista-eos."
SSH = "management ssh"
TELNET = "management telnet"
HTTP = "management api http-commands"
NAME = re.compile(r"[A-Za-z0-9_.:/-]{1,96}")
ETHERNET = re.compile(r"Ethernet[0-9]+(?:/[0-9]+)*")
PORT = re.compile(r"(?:Ethernet|Port-Channel)[0-9]+(?:/[0-9]+)*")


def _commands(tree, *words, parents=()):
    return (item for item in tree.matching(*words) if item.parents == parents)


def _last(tree, *words, parents=(), exact=False):
    return next((item for item in reversed(tree.matching(*words))
                 if item.parents == parents and (not exact or item.tokens == words)), None)


def _entries(tree, words, identity, parents=()):
    active = {}
    for item in _commands(tree, *words, parents=parents):
        key = identity(item.tokens)
        if key is not None:
            if item.mode == "set":
                active[key] = item
            else:
                active.pop(key, None)
    return active


def _verified(context, section):
    visibility = context.visibility(section)
    return (context.snapshot is not None and context.snapshot.complete
            and visibility.state == VISIBLE and visibility.reason == "verified-profile")


def _gap(context, section, reason):
    visibility = context.visibility(section)
    return visibility.reason if visibility.state != VISIBLE and visibility.reason != "visibility-unproven" else reason


def _toggle(tree, words, parents=(), default=None):
    item = _last(tree, *words, parents=parents, exact=True)
    if item is None:
        return default
    return default if item.mode == "default" else item.mode == "set"


def _hit(section, obj, reason, item=None, **evidence):
    return {"section": section, "object_key": obj, "line": item.line if item else 0,
            "evidence": {"reason": reason, **evidence}}


def _register(suffix, section, *, intent=None, scope=None):
    def register(inspect):
        def status(tree, context):
            outcomes = tuple(inspect(tree, context))
            gap = next((item for item in outcomes if isinstance(item, str)), None)
            if gap is not None and (context.live or context.intent or not any(
                    isinstance(item, dict) for item in outcomes)):
                return NOT_EVALUATED, _gap(context, section, gap)
            return EVALUATED, ""

        def findings(tree, context):
            return (item for item in inspect(tree, context) if isinstance(item, dict))

        check(PREFIX + suffix, audit_context=True, applies=intent, status=status, partial=True,
              offline_scope=scope or (lambda tree: tree.section(section) is not None))(findings)
        return inspect
    return register


def _scopes(tree, section):
    root = tuple(section.split())
    default = False
    for name, item in _entries(tree, ("vrf",), lambda words: words[1] if len(words) == 2 else None,
                               (root,)).items():
        if NAME.fullmatch(name):
            yield name, (root, item.tokens)
            if name == "default":
                default = True
    if not default:
        yield "default", (root,)


def _service(tree, context, section, *, http=False):
    root = tuple(section.split())
    header = _last(tree, *root, exact=True)
    if header and header.mode != "set":
        return
    verified = _verified(context, section)
    root_parents = (root,)
    root_down = _toggle(tree, ("shutdown",), root_parents)
    if root_down is True:
        return
    for scope, parents in _scopes(tree, section):
        shutdown = _last(tree, "shutdown", parents=parents, exact=True)
        down = _toggle(tree, ("shutdown",), parents, default=True if verified else None)
        if http:
            protocol = (_last(tree, "protocol", "http", parents=parents)
                        or _last(tree, "protocol", "http", parents=root_parents))
            if (protocol and protocol.mode != "set") or (verified and protocol is None):
                continue
            if down is False and protocol:
                yield _hit(section, scope, "http-listener-enabled", protocol)
            elif down is not True:
                yield "http-listener-unproven"
        elif down is False:
            yield _hit(section, scope, "telnet-listener-enabled", shutdown)
        elif down is None:
            yield "telnet-scope-unproven"


@_register("mgmt.telnet-enabled", TELNET)
def _telnet(tree, context):
    yield from _service(tree, context, TELNET)


@_register("mgmt.http-enabled", HTTP)
def _http(tree, context):
    yield from _service(tree, context, HTTP, http=True)


@_register("mgmt.idle-timeout", SSH)
def _idle_timeout(tree, context):
    root = (("management", "ssh"),)
    if _toggle(tree, ("shutdown",), root) is True:
        return
    timer = _last(tree, "idle-timeout", parents=root)
    if timer is None and not _verified(context, SSH):
        yield "ssh-idle-timeout-unproven"
    elif timer is None or timer.mode != "set" or timer.tokens == ("idle-timeout", "0"):
        yield _hit(SSH, "ssh", "idle-timeout-disabled", timer)
    elif len(timer.tokens) != 2 or not _positive_integer(timer.tokens[1]):
        yield "ssh-idle-timeout-unrecognized"


def _positive_integer(text):
    return text.isascii() and text.isdecimal() and len(text) <= 10 and int(text) > 0


LOGIN = ("aaa", "authentication", "login", "default")
LOCKOUT = ("aaa", "authentication", "policy", "lockout", "failure")


def _login_methods(tree, context):
    login = _last(tree, *LOGIN)
    if login and login.mode == "set":
        return login.tokens[len(LOGIN):]
    if login or _verified(context, "aaa"):
        return ("local",)
    return ()


@_register("mgmt.lockout", "aaa")
def _lockout(tree, context):
    rule = _last(tree, *LOCKOUT)
    if rule and rule.mode == "set":
        tail = rule.tokens[len(LOCKOUT):]
        valid = re.fullmatch(r"[1-9][0-9]* (?:(?:window [1-9][0-9]* )?duration [1-9][0-9]*|"
                             r"duration [1-9][0-9]* window [1-9][0-9]*)", " ".join(tail))
        if not valid:
            yield "lockout-policy-unrecognized"
        return
    methods = _login_methods(tree, context)
    if methods and methods[0] == "group":
        yield "external-lockout-unproven"
    elif methods == ("local",) and (rule or _verified(context, "aaa")):
        yield _hit("aaa", "local-login", "local-lockout-disabled", rule)
    elif methods != ("none",):
        yield "lockout-policy-unproven"


def _network(tokens, version):
    if not tokens:
        raise ValueError
    token = tokens[0]
    if token in ("any", "any4", "any6"):
        if token != "any" and token[-1] != str(version):
            raise ValueError
        return (ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0"), tokens[1:])
    if token == "host" and len(tokens) > 1:
        token, tokens = tokens[1], tokens[1:]
    net = ipaddress.ip_network(token, strict=False)
    if net.version != version:
        raise ValueError
    return net, tokens[1:]


def _without(network, exclusions):
    remaining = [network]
    for excluded in exclusions:
        next_remaining = []
        for part in remaining:
            if part.subnet_of(excluded):
                continue
            next_remaining.extend(part.address_exclude(excluded) if excluded.subnet_of(part) else [part])
        remaining = next_remaining
    return remaining


def _ssh_acl(tree, version, name, expected, port):
    family = "ip" if version == 4 else "ipv6"
    parents = ((family, "access-list", name),)
    entries = {}
    for item in (item for item in tree.commands if item.parents == parents):
        words = item.tokens
        sequence = int(words[0]) if _positive_integer(words[0]) else None
        if sequence is not None:
            words = words[1:]
        key = (0, sequence) if sequence is not None else (1, item.line)
        if item.mode == "set":
            entries[key] = words
        elif sequence is not None:
            entries.pop(key, None)
    header = _last(tree, *parents[0], exact=True)
    if not entries or not header or header.mode != "set":
        return None
    covered = []
    for _, words in sorted(entries.items()):
        if not words or words[0] in ("remark", "statistics", "counters"):
            continue
        decision, *tail = words
        if decision not in ("permit", "deny") or not tail:
            return None
        if tail[0] not in ("tcp", "ip", "ipv6"):
            return None
        protocol, *tail = tail
        try:
            src, tail = _network(tail, version)
            dest, tail = _network(tail, version)
        except ValueError:
            return None
        if dest.prefixlen:
            return None
        if protocol == "tcp" and len(tail) >= 2 and tail[0] == "eq":
            service = tail[1]
            tail = tail[2:]
            if service not in (str(port), "ssh" if port == 22 else str(port)):
                if service == "ssh" or _positive_integer(service):
                    continue
                return None
        if tuple(tail) not in ((), ("log",), ("log-input",)):
            return None
        if decision == "permit" and _without(src, [*covered, *expected]):
            return False
        covered.append(src)
        if src.prefixlen == 0:
            break
    return True


@_register("mgmt.access-acl", SSH, intent=lambda intent: bool(intent.get("management_prefixes")))
def _access_acl(tree, context):
    root = (("management", "ssh"),)
    if _toggle(tree, ("shutdown",), root) is True:
        return
    expected = [ipaddress.ip_network(item) for item in context.intent["management_prefixes"]]
    port_cmd = _last(tree, "server-port", parents=root)
    if port_cmd and port_cmd.mode == "set" and (
            len(port_cmd.tokens) != 2 or not _positive_integer(port_cmd.tokens[1])):
        yield "ssh-port-unrecognized"
        return
    port = int(port_cmd.tokens[1]) if port_cmd and port_cmd.mode == "set" else 22
    verified = _verified(context, SSH)
    for vrf, parents in _scopes(tree, SSH):
        if _toggle(tree, ("shutdown",), parents) is True:
            continue
        for family, version in (("ip", 4), ("ipv6", 6)):
            networks = [net for net in expected if net.version == version]
            if not networks:
                continue
            binding = None
            for item in (*_commands(tree, family, "access-group", parents=root),
                         *(() if parents == root else _commands(tree, family, "access-group", parents=parents))):
                words = item.tokens[2:]
                scope = vrf if item.parents != root else "default"
                if len(words) == 4 and words[1:3] == ("in", "vrf"):
                    scope = words[3]
                elif len(words) == 4 and words[1] == "vrf" and words[3] == "in":
                    scope = words[2]
                elif not (len(words) == 2 and words[1] == "in" or
                          item.mode != "set" and len(words) == 1):
                    continue
                if scope == vrf:
                    binding = item
            obj = f"{vrf}:ipv{version}"
            if binding is None and not verified:
                yield "ssh-acl-binding-unproven"
            elif binding is None or binding.mode != "set":
                yield _hit(SSH, obj, "ssh-acl-unbound", binding)
            else:
                result = _ssh_acl(tree, version, binding.tokens[2], networks, port)
                if result is False:
                    yield _hit(SSH, obj, "ssh-acl-admits-other-sources", binding)
                elif result is None or not _verified(context, family + " access-list"):
                    yield "ssh-acl-contents-unproven"


BUILTIN_GROUPS = {"tacacs+": "tacacs-server", "radius": "radius-server"}


@_register("aaa.external-login", "aaa", intent=lambda intent: intent.get("external_aaa_required") is True)
def _external_login(tree, context):
    methods = _login_methods(tree, context)
    if not methods:
        yield "login-methods-unproven"
    elif methods[0] in ("local", "none"):
        yield _hit("aaa", "default-login", "external-login-unused", _last(tree, *LOGIN))
    elif methods[0] == "group":
        groups = methods[1:-1] if methods[-1] == "local" else methods[1:]
        if not groups:
            yield "external-login-group-unproven"
        for group in groups:
            if group in BUILTIN_GROUPS:
                # The built-in group is every configured server of that protocol.
                header = _last(tree, "aaa", "authentication", "login", "default")
                backend = BUILTIN_GROUPS[group]
            else:
                header = next((item for item in _commands(tree, "aaa", "group", "server")
                               if item.mode == "set" and item.tokens[3:] in (
                                   ("tacacs+", group), ("radius", group))), None)
                if header is None:
                    yield "external-login-group-unproven"
                    continue
                backend = "tacacs-server" if header.tokens[3] == "tacacs+" else "radius-server"
            hosts = _entries(tree, (backend, "host"), lambda words: words[2] if len(words) > 2 else None)
            members = hosts if group in BUILTIN_GROUPS else _entries(
                tree, ("server",), lambda words: words[1] if len(words) > 1 else None, (header.tokens,))
            if not members or not members.keys() <= hosts.keys():
                if _verified(context, "aaa"):
                    yield _hit("aaa", "default-login", "external-login-server-missing", header)
                    return
                yield "external-login-server-unproven"
    else:
        yield "login-methods-unrecognized"


@_register("aaa.local-password-storage", "aaa")
def _password_storage(tree, context):
    accounts = _entries(tree, ("username",), lambda words: words[1] if len(words) > 2 and
                        any(word in ("secret", "nopassword", "password") for word in words[2:]) else None)
    for item in _commands(tree, "username"):
        if len(item.tokens) == 2 and item.mode != "set":
            if item.tokens[1] in accounts and item.line > accounts[item.tokens[1]].line:
                accounts.pop(item.tokens[1])
    if not _verified(context, "aaa"):
        yield "local-account-scope-unproven"
    for username, account in accounts.items():
        if not NAME.fullmatch(username):
            yield "local-account-identity-unrecognized"
            continue
        words = account.tokens[2:]
        if "secret" in words:
            tail = words[words.index("secret") + 1:]
            if len(tail) < 2 or tail[0] not in ("0", "5", "8", "9", "md5", "sha512"):
                yield "local-password-type-unproven"
            elif tail[0] == "0":
                yield _hit("aaa", username, "cleartext-password", account)
        elif "nopassword" in words:
            allow = _toggle(tree, ("aaa", "authentication", "policy", "local", "allow-nopassword-remote-login"),
                            default=False if _verified(context, "aaa") else None)
            methods = _login_methods(tree, context)
            console = _last(tree, "aaa", "authentication", "login", "console")
            local_console = console and console.mode == "set" and console.tokens[4:] == ("local",)
            if local_console or allow is True and "local" in methods:
                yield _hit("aaa", username, "passwordless-local-login", account)
            elif allow is None or allow and not methods or console is None and not _verified(context, "aaa"):
                yield "passwordless-login-policy-unproven"
        else:
            yield "local-password-type-unproven"


def _snmp_entries(tree, kind):
    return _entries(tree, ("snmp-server", kind), lambda words: words[2] if len(words) > 2 else None)


def _snmp_enabled(tree, context):
    if _snmp_entries(tree, "vrf"):
        return True
    if _verified(context, "snmp"):
        return _toggle(tree, ("snmp-server", "vrf", "default"), default=True)
    return None


@_register("snmp.v1v2c-community", "snmp")
def _snmp_community(tree, context):
    enabled = _snmp_enabled(tree, context)
    communities = _snmp_entries(tree, "community")
    if enabled is True and communities:
        yield _hit("snmp", "communities", "v1v2c-communities-configured",
                   next(iter(communities.values())), count=len(communities))
    elif enabled is None or enabled and not _verified(context, "snmp"):
        yield "snmp-communities-or-scope-unproven"


def _snmp_aux(context, username, group):
    if context.visibility("snmp users").state != VISIBLE or context.snapshot is None:
        return None
    text = context.snapshot.auxiliary.get("snmp users", "")
    for row in re.split(r"(?im)^\s*User name:\s*", text)[1:]:
        name, _, values = row.partition("\n")
        if name.strip() != username:
            continue
        fields = dict(re.findall(r"(?m)^\s*([\w ]+):[ \t]*([^\r\n]+)", values))
        if fields.get("Security model", "").lower() != "v3" or fields.get("Group name") != group:
            continue
        protocols = [fields.get(field, "").lower() for field in ("Authentication protocol", "Privacy protocol")]
        if all(protocols):
            return all(protocol not in ("none", "noauth", "nopriv", "not configured") for protocol in protocols)
    return None


@_register("snmp.v3-auth-priv", "snmp")
def _snmp_v3(tree, context):
    enabled = _snmp_enabled(tree, context)
    if enabled is not True:
        if enabled is None:
            yield "snmp-v3-scope-unproven"
        return
    groups = _snmp_entries(tree, "group")
    users = _snmp_entries(tree, "user")
    if not users and not _verified(context, "snmp"):
        yield "snmp-v3-users-unproven"
    weak = []
    for user in users.values():
        words = user.tokens
        if len(words) < 5 or words[4] != "v3":
            yield "snmp-user-security-unproven"
            continue
        group = groups.get(words[3])
        if not group or group.tokens[3:4] != ("v3",):
            yield "snmp-v3-group-unproven"
            continue
        level = group.tokens[4:5]
        tail = words[5:]
        auth = bool(re.match(r"^auth [^ ]+ .+ priv [^ ]+ .+$", " ".join(tail)))
        if not auth:
            auth = _snmp_aux(context, words[2], words[3])
        if level in (("auth",), ("noauth",)) or level == ("priv",) and auth is False:
            weak.append(user)
        elif level != ("priv",) or auth is None:
            yield _gap(context, "snmp users", "snmp-user-security-unproven")
    if weak:
        yield _hit("snmp", "users", "v3-auth-privacy-not-required", weak[0], count=len(weak))


def _scoped_value(words, offset):
    if words[offset:offset + 1] == ("vrf",):
        if len(words) <= offset + 2:
            return None
        return words[offset + 1], words[offset + 2], offset + 3
    if len(words) > offset:
        return "default", words[offset], offset + 1
    return None


def _ntp_key(words):
    parsed = _scoped_value(words, 2)
    return parsed[:2] if parsed else None


def _ntp_sources(tree):
    return _entries(tree, ("ntp", "server"), _ntp_key)


@_register("time.no-ntp-source", "ntp")
def _ntp_source(tree, context):
    if not _ntp_sources(tree):
        if _verified(context, "ntp"):
            yield _hit("ntp", "client", "ntp-source-missing")
        else:
            yield "ntp-client-sources-unproven"


@_register("time.ntp-auth", "ntp", intent=lambda intent: intent.get("ntp_auth_required") is True)
def _ntp_auth(tree, context):
    sources = _ntp_sources(tree)
    verified = _verified(context, "ntp")
    if not sources:
        if not verified:
            yield "ntp-client-sources-unproven"
        return
    enabled = _toggle(tree, ("ntp", "authenticate"), default=False if verified else None)
    keys = _entries(tree, ("ntp", "authentication-key"), lambda words: words[2] if len(words) > 2 else None)
    trusted = _entries(tree, ("ntp", "trusted-key"), lambda words: words[2] if len(words) > 2 else None)
    weak = {}
    for (vrf, _), source in sources.items():
        parsed = _scoped_value(source.tokens, 2)
        tail = source.tokens[parsed[2]:]
        index = tail.index("key") if "key" in tail else len(tail)
        key = tail[index + 1] if index + 1 < len(tail) else None
        if enabled is False or key is None and verified:
            weak.setdefault(vrf, []).append(source)
        elif enabled is None or key is None or key not in keys or key not in trusted or len(keys[key].tokens) < 5:
            if verified:
                weak.setdefault(vrf, []).append(source)
            else:
                yield "ntp-authentication-chain-unproven"
    for vrf, sources in weak.items():
        if NAME.fullmatch(vrf):
            yield _hit("ntp", vrf, "ntp-source-unauthenticated", sources[0], count=len(sources))


def _logging_hosts(tree):
    def identity(words):
        if len(words) >= 3 and words[1] == "host":
            return "default", words[2]
        if len(words) >= 5 and words[1] == "vrf" and words[3] == "host":
            return words[2], words[4]
        return None
    return _entries(tree, ("logging",), identity)


@_register("logging.no-syslog-target", "logging")
def _syslog_target(tree, context):
    if _toggle(tree, ("logging", "on")) is False:
        yield _hit("logging", "remote", "logging-disabled", _last(tree, "logging", "on", exact=True))
    elif not _logging_hosts(tree):
        if _verified(context, "logging"):
            yield _hit("logging", "remote", "syslog-target-missing")
        else:
            yield "syslog-targets-unproven"
    elif not (_toggle(tree, ("logging", "on")) is True or _verified(context, "logging")):
        yield "logging-effective-state-unproven"


EOS_LEVELS = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging")


@_register("logging.syslog-level", "logging", intent=lambda intent: "syslog_severity" in intent)
def _syslog_level(tree, context):
    enabled = _toggle(tree, ("logging", "on"))
    if enabled is False:
        return
    verified = _verified(context, "logging")
    targets = _logging_hosts(tree)
    if not targets:
        if not verified:
            yield "syslog-targets-unproven"
        return
    if enabled is None and not verified:
        yield "logging-effective-state-unproven"
        return
    expected = SYSLOG_LEVELS.index(context.intent["syslog_severity"])
    for vrf in sorted({vrf for vrf, _ in targets}):
        if not NAME.fullmatch(vrf):
            continue
        cmd = (_last(tree, "logging", "vrf", vrf, "trap") if vrf != "default" else None)
        cmd = cmd or _last(tree, "logging", "trap")
        level = cmd.tokens[-1] if cmd and cmd.mode == "set" else None
        if level in EOS_LEVELS:
            severity = EOS_LEVELS.index(level)
        elif level in tuple(map(str, range(8))):
            severity = int(level)
        elif level is None and (cmd or verified):
            severity = 6
        else:
            yield "syslog-trap-level-unproven"
            continue
        if severity < expected:
            yield _hit("logging", vrf, "syslog-trap-too-restrictive", cmd, level=severity)


def _selected(role, flag=None, value=None):
    return lambda intent: any(settings["role"] == role and (flag is None or flag in settings
                                                            and (value is None or settings[flag] is value))
                              for settings in intent.get("ports", {}).values())


def _interfaces(tree, context, role, flag=None, value=None, name_pattern=PORT):
    for name, settings in context.intent.get("ports", {}).items():
        if (settings["role"] != role or flag is not None
                and (flag not in settings or value is not None and settings[flag] is not value)):
            continue
        header = _last(tree, "interface", name, exact=True) if name_pattern.fullmatch(name) else None
        yield name, settings, header if header and header.mode == "set" else None


def _on_port(tree, header, *words):
    return _last(tree, *words, parents=(header.tokens,))


def _port_toggle(tree, header, *words, default=None):
    return _toggle(tree, words, (header.tokens,), default)


@_register("services.edge-discovery", "interface", intent=_selected("edge", "discovery_allowed", False))
def _discovery(tree, context):
    enabled = _toggle(tree, ("lldp", "run"), default=True if _verified(context, "global") else None)
    if enabled is False:
        return
    for name, _, header in _interfaces(tree, context, "edge", "discovery_allowed", False):
        transmit = (_port_toggle(tree, header, "lldp", "transmit",
                                default=True if _verified(context, "interface") else None) if header else None)
        if enabled is True and transmit is True:
            yield _hit("interface", name, "lldp-transmit-enabled", _on_port(tree, header, "lldp", "transmit") or header)
        elif transmit is not False:
            yield "lldp-port-transmit-unproven"


@_register("l2.bpdu-guard", "interface", intent=_selected("edge"))
def _bpdu_guard(tree, context):
    stp = _last(tree, "spanning-tree", "mode")
    global_guard = _toggle(tree, ("spanning-tree", "edge-port", "bpduguard", "default"),
                           default=False if _verified(context, "global") else None)
    verified = _verified(context, "interface")
    for name, _, header in _interfaces(tree, context, "edge"):
        if header is None:
            yield "edge-port-unproven"
            continue
        guard = _on_port(tree, header, "spanning-tree", "bpduguard")
        if stp and stp.mode == "set" and stp.tokens[2:] == ("none",):
            yield _hit("interface", name, "spanning-tree-disabled", stp)
        elif guard and guard.mode == "set" and guard.tokens[2:] == ("enable",):
            continue
        elif guard and guard.mode == "set" and guard.tokens[2:] == ("disable",):
            yield _hit("interface", name, "bpdu-guard-disabled", guard)
        elif guard or verified:
            portfast = _on_port(tree, header, "spanning-tree", "portfast")
            edge = portfast and portfast.mode == "set" and portfast.tokens[2:] in ((), ("edge",))
            if global_guard is False:
                yield _hit("interface", name, "bpdu-guard-disabled", guard or header)
            elif global_guard is not True or not edge:
                yield "effective-bpdu-guard-unproven"
        else:
            yield "effective-bpdu-guard-unproven"


def _switchport(tree, header, verified):
    switchport = _port_toggle(tree, header, "switchport")
    if switchport is False:
        return "routed"
    mode = _on_port(tree, header, "switchport", "mode")
    if mode and mode.mode == "set":
        return mode.tokens[2] if len(mode.tokens) == 3 else None
    return "access" if verified or mode else None


def _vlan_value(command, fallback):
    if command is None:
        return fallback
    if command.mode != "set":
        return 1
    token = command.tokens[-1]
    return int(token) if _positive_integer(token) and int(token) <= 4094 else None


@_register("l2.default-vlan", "interface", intent=_selected("edge", "default_vlan_allowed", False))
def _default_vlan(tree, context):
    verified = _verified(context, "interface")
    for name, _, header in _interfaces(tree, context, "edge", "default_vlan_allowed", False):
        mode = _switchport(tree, header, verified) if header else None
        if not mode:
            yield "access-port-mode-unproven"
        elif mode == "access" and _port_toggle(tree, header, "shutdown") is not True:
            vlan = _on_port(tree, header, "switchport", "access", "vlan")
            actual = _vlan_value(vlan, 1 if verified else None)
            if actual == 1 and _port_toggle(tree, header, "shutdown", default=False if verified else None) is False:
                yield _hit("interface", name, "edge-access-vlan-one", vlan or header, vlan=actual)
            elif actual in (1, None):
                yield "edge-vlan-membership-unproven"


@_register("l2.trunk-native", "interface", intent=_selected("trunk", "native_vlan"))
def _trunk_native(tree, context):
    verified = _verified(context, "interface")
    for name, settings, header in _interfaces(tree, context, "trunk", "native_vlan"):
        if header is None or _switchport(tree, header, verified) != "trunk":
            yield "trunk-mode-unproven"
            continue
        native = _on_port(tree, header, "switchport", "trunk", "native", "vlan")
        actual = 0 if native and native.mode == "set" and native.tokens[-1] == "tag" else _vlan_value(
            native, 1 if verified else None)
        expected = settings["native_vlan"]
        allowed = _on_port(tree, header, "switchport", "trunk", "allowed", "vlan")
        if allowed and allowed.mode == "set":
            values = _vlan_set(allowed.tokens[4:])
            if values is not None and expected not in values:
                evidence = {"expected_vlan": expected}
                if actual is not None:
                    evidence["vlan"] = actual if actual in values else 0
                yield _hit("interface", name, "expected-native-vlan-not-allowed", allowed, **evidence)
                continue
            if values is None or actual and actual not in values:
                actual = None if values is None else 0
        if actual is None:
            yield "trunk-native-vlan-unproven"
        elif actual != expected:
            yield _hit("interface", name, "trunk-native-vlan-mismatch", native or header,
                       vlan=actual, expected_vlan=expected)


def _vlan_set(words):
    if len(words) != 1:
        return None
    if words[0] == "none":
        return set()
    if words[0] == "all":
        return set(range(1, 4095))
    values = set()
    for item in words[0].split(","):
        if not re.fullmatch(r"[0-9]{1,4}(?:-[0-9]{1,4})?", item):
            return None
        first, _, last = item.partition("-")
        low, high = int(first), int(last or first)
        if not 1 <= low <= high <= 4094:
            return None
        values.update(range(low, high + 1))
    return values


@_register("l2.dhcp-snooping", "global", intent=lambda intent: bool(intent.get("dhcp_snooping_vlans")))
def _dhcp_snooping(tree, context):
    verified = _verified(context, "global")
    enabled = _toggle(tree, ("ip", "dhcp", "snooping"), default=False if verified else None)
    if enabled is not True:
        if enabled is False:
            yield _hit("global", "dhcp-snooping", "dhcp-snooping-disabled")
        else:
            yield "dhcp-snooping-mode-unproven"
        return
    configured, excluded = set(), set()
    for item in _commands(tree, "ip", "dhcp", "snooping", "vlan"):
        values = _vlan_set(item.tokens[4:])
        if values is None:
            yield "dhcp-snooping-vlan-list-unrecognized"
            return
        if item.mode == "set":
            configured.update(values)
            excluded.difference_update(values)
        else:
            configured.difference_update(values)
            excluded.update(values)
    for vlan in context.intent["dhcp_snooping_vlans"]:
        if vlan in excluded or verified and vlan not in configured:
            yield _hit("global", f"vlan:{vlan}", "dhcp-snooping-vlan-unprotected", vlan=vlan)
        elif vlan not in configured:
            yield "dhcp-snooping-vlan-scope-unproven"
            continue
        elif _toggle(tree, ("ip", "dhcp", "snooping", "bridging")) is not True:
            # Relay-mode snooping requires a working helper and Option 82 for this SVI.
            svi = (("interface", f"Vlan{vlan}"),)
            helper = _last(tree, "ip", "helper-address", parents=svi)
            option = _toggle(tree, ("ip", "dhcp", "snooping", "information", "option"),
                             default=True if verified else None)
            if not (helper and helper.mode == "set" and option is True):
                yield "dhcp-snooping-relay-mode-unproven"
    expected = context.intent.get("trusted_dhcp_ports")
    if expected is None:
        return
    active = {item.tokens[1]: item for item in _commands(tree, "interface")
              if item.mode == "set" and len(item.tokens) == 2 and PORT.fullmatch(item.tokens[1])}
    for name in sorted(active.keys() | set(expected)):
        header = active.get(name)
        trust = (_port_toggle(tree, header, "ip", "dhcp", "snooping", "trust", default=False if
                             _verified(context, "interface") else None) if header else None)
        if trust is None:
            yield "dhcp-snooping-port-trust-unproven"
        elif trust != (name in expected):
            yield _hit("interface", name, "dhcp-snooping-port-trust-mismatch", header)


@_register("l2.storm-control", "interface", intent=_selected("edge", "storm_control_required", True))
def _storm_control(tree, context):
    for name, _, header in _interfaces(tree, context, "edge", "storm_control_required", True):
        if header is None:
            yield "storm-control-port-unproven"
            continue
        cmd = _on_port(tree, header, "storm-control", "broadcast")
        if cmd is None and _verified(context, "interface"):
            # EOS prints no line for the default: broadcast traffic is not limited.
            yield _hit("interface", name, "broadcast-storm-control-disabled", header)
        elif cmd is None:
            yield "storm-control-limit-unproven"
        elif cmd.mode != "set":
            yield _hit("interface", name, "broadcast-storm-control-disabled", cmd)
        else:
            words = cmd.tokens[2:]
            if len(words) == 3 and words[:2] == ("level", "pps") and _positive_integer(words[2]):
                continue
            if (len(words) == 2 and words[0] == "level"
                    and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]+)?", words[1]) and float(words[1]) <= 100):
                if float(words[1]) == 100:
                    yield _hit("interface", name, "broadcast-storm-control-unlimited", cmd)
                continue
            yield "storm-control-limit-unproven"


@_register("ports.unused-up", "interface", intent=_selected("unused"))
def _unused(tree, context):
    verified = _verified(context, "interface")
    for name, _, header in _interfaces(tree, context, "unused", name_pattern=ETHERNET):
        shutdown = (_port_toggle(tree, header, "shutdown", default=False if verified else None)
                    if header else None)
        if shutdown is None:
            yield "unused-port-admin-state-unproven"
        elif not shutdown:
            yield _hit("interface", name, "unused-port-admin-up", _on_port(tree, header, "shutdown") or header)
