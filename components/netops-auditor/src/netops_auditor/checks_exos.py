from __future__ import annotations

import hashlib
import json
import re
from ipaddress import ip_network

from .engine import EVALUATED, NOT_EVALUATED, check
from .platforms import UNPROVEN, VISIBLE

SECTION_SNTP = "sntp-client"
SECTION_SYSLOG = "syslog"
SECTION_SNMP = "snmp"
SECTION_TELNET = "telnet"

TRIVIAL_COMMUNITIES = frozenset(("public", "private"))

_SNMP_COMMUNITY = ("configure", "snmp", "add", "community")
_SNMPV3_COMMUNITY = ("configure", "snmpv3", "add", "community")

_HEX = "hex"
_ENCRYPTED = "encrypted"
_NAME = "name"

_COMMUNITY_INDEX = "community index"
_COMMUNITY_NAME = "community name"
_COMMUNITY_STRING = "community string"

_DICTIONARY = "trivial"

_REASON_ABSENT = "no command"
_REASON_DEFAULT = "default enabled"
_REASON_EXPLICIT = "explicitly enabled"


def _snmp_candidates(tokens) -> list:
    if len(tokens) <= 5 or tokens[5] in (_HEX, _ENCRYPTED):
        return []
    return [(_COMMUNITY_STRING, tokens[5])]


def _snmpv3_candidates(tokens) -> list:
    candidates = []
    if len(tokens) > 4 and tokens[4] != _HEX:
        candidates.append((_COMMUNITY_INDEX, tokens[4]))
    for position in range(4, len(tokens) - 1):
        if tokens[position] != _NAME:
            continue
        following = tokens[position + 1]
        if following != _HEX:
            candidates.append((_COMMUNITY_NAME, following))
        break
    return candidates


def _community_candidates(command):
    if command.starts_with(*_SNMP_COMMUNITY):
        return _snmp_candidates(command.tokens)
    if command.starts_with(*_SNMPV3_COMMUNITY):
        return _snmpv3_candidates(command.tokens)
    return None


def _trivial(candidates) -> tuple:
    return tuple(where for where, value in candidates if value.lower() in TRIVIAL_COMMUNITIES)


def _status(configuration, policy=None) -> tuple:
    if configuration.unterminated_upm:
        return NOT_EVALUATED, "unterminated-upm-profile"
    return EVALUATED, ""


def _configured(configuration, *words) -> bool:
    return any(len(command.tokens) > len(words) for command in configuration.matching(*words))


@check("exos_no_sntp_client", status=_status)
def exos_no_sntp_client(configuration):
    if configuration.first("enable", "sntp-client") is not None:
        return
    if _configured(configuration, "configure", "sntp-client", "primary"):
        return
    if configuration.first("enable", "ntp") is not None:
        return
    if _configured(configuration, "configure", "ntp", "server", "add"):
        return
    yield {
        "object_key": SECTION_SNTP,
        "section": SECTION_SNTP,
        "line": 0,
        "evidence": {"reason": _REASON_ABSENT},
    }


@check("exos_no_syslog_target", status=_status)
def exos_no_syslog_target(configuration):
    if _configured(configuration, "configure", "syslog", "add"):
        return
    yield {
        "object_key": SECTION_SYSLOG,
        "section": SECTION_SYSLOG,
        "line": 0,
        "evidence": {"reason": _REASON_ABSENT},
    }


def _community_key(command):
    tokens = command.tokens
    if command.starts_with(*_SNMP_COMMUNITY):
        identity = ("snmp", tokens[4], tokens[5])
    elif tokens[4] == _HEX:
        identity = ("snmpv3", _HEX, tokens[5])
    else:
        identity = ("snmpv3", "plain", tokens[4])
    encoded = json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return "%s/community/%s" % (SECTION_SNMP, hashlib.sha256(encoded).hexdigest())


@check("exos_default_snmp_community", status=_status)
def exos_default_snmp_community(configuration):
    for command in configuration.active:
        candidates = _community_candidates(command)
        if candidates is None:
            continue
        matched = _trivial(candidates)
        if not matched:
            continue
        yield {
            "object_key": _community_key(command),
            "section": SECTION_SNMP,
            "line": command.line,
            "evidence": {
                "command": " ".join(command.tokens[:4]),
                "field": ", ".join(matched),
                "dictionary": _DICTIONARY,
            },
        }


@check("exos_telnet_enabled", status=_status)
def exos_telnet_enabled(configuration):
    state = None
    for command in configuration.active:
        if command.starts_with("disable", "telnet"):
            state = (False, command)
        elif command.starts_with("enable", "telnet"):
            state = (True, command)
    if state is None:
        yield {
            "object_key": SECTION_TELNET,
            "section": SECTION_TELNET,
            "line": 0,
            "evidence": {"reason": _REASON_DEFAULT},
        }
        return
    enabled, command = state
    if not enabled:
        return
    yield {
        "object_key": SECTION_TELNET,
        "section": SECTION_TELNET,
        "line": command.line,
        "evidence": {"reason": _REASON_EXPLICIT},
    }

from . import management

from .management import management_exos_vlan_empty
from .management import management_exos_vlan_policy
from .management import management_exos_port_policy
from .management import management_exos_port_native
from .management import management_exos_port_description


# New checks emit only operator-supplied or validated object identifiers and
# fixed evidence values. A missing decision preserves coverage gaps.
def _taxonomy(section, reason, *, intent=None, scope=None):
    def decorate(assess):
        def decisions(tree, context):
            if tree.unterminated_upm:
                return ()
            return assess(tree, context)

        def status(tree, context):
            if tree.unterminated_upm:
                return _status(tree)
            if any(problem is None for _, _, problem in decisions(tree, context)):
                visibility = context.visibility(section)
                return NOT_EVALUATED, reason if visibility.state in (VISIBLE, UNPROVEN) else visibility.reason
            return EVALUATED, ""

        @check(assess.__name__, audit_context=True, status=status, applies=intent, partial=True, offline_scope=scope)
        def findings(tree, context):
            for key, command, problem in decisions(tree, context):
                if problem:
                    yield {"object_key": key, "section": section, "line": command.line if command else 0,
                           "evidence": {"state": problem}}

        return findings

    return decorate


def _missing(key):
    return key, None, None


def _proven(context, section):
    return context.visibility(section).reason in ("verified-profile", "auxiliary-output")


# Defaults of settings that `show configuration` does not print, with the module that prints
# a changed value. Measured as `show configuration detail` lines missing from `show
# configuration` on ExtremeXOS 33.6.1.14 and 33.7.1.6-patch1-11 (the broadcast limit and port
# state from the port readback) and documented by the vendor. A default applies only when the
# collection proves that module complete; a file snapshot never has this proof.
_DEFAULTS = {
    "web http": ("thttpd", "enabled"),
    "cli idle-timeout": ("cfgmgr", "enabled"),  # 20 minutes
    "lockout-on-login-failures": ("aaa", "off"),
    "snmp access": ("snmpMaster", "disabled"),
    "edp ports": ("edp", "enabled"),
    "lldp ports": ("lldp", "enabled"),  # transmit and receive
    "ssh2 access-profile": ("exsshd", "none"),
    "port admin state": ("vlan", "enabled"),
    "rate-limit flood broadcast": ("vlan", "no-limit"),
}


def _default(context, setting):
    module, value = _DEFAULTS[setting]
    return value if _proven(context, module) else None


def _switch(tree, *forms):
    """Return the last enable/disable command with an exact command form."""
    return next((item for item in reversed(tree.active)
                 if item.tokens[0] in ("enable", "disable") and item.tokens[1:] in forms), None)


def _last(tree, *prefix):
    return next((item for item in reversed(tree.active) if item.starts_with(*prefix)), None)


def _option(tokens, name, default=None):
    try:
        return tokens[tokens.index(name) + 1]
    except (ValueError, IndexError):
        return default


def _has_any(tree, *prefixes):
    return any(tree.first(*prefix) is not None for prefix in prefixes)


@_taxonomy("thttpd", "http-listener-unproven",
           scope=lambda tree: "thttpd" in tree.modules or _has_any(tree, ("configure", "web", "http")))
def exos_http_enabled(tree, context):
    command = _switch(tree, ("web", "http"))
    if command is None:
        yield ("http", None, "enabled") if _default(context, "web http") == "enabled" else _missing("http")
    else:
        yield "http", command, "enabled" if command.tokens[0] == "enable" else ""


_IDLE_FORMS = (("cli", "idle-timeout"), ("idletimeout",))


@_taxonomy("cfgmgr", "idle-timeout-unproven",
           scope=lambda tree: any(tree.first("configure", *form) for form in _IDLE_FORMS))
def exos_idle_timeout(tree, context):
    command = _switch(tree, *_IDLE_FORMS)
    if command is None:
        enabled = _default(context, "cli idle-timeout") == "enabled"
        yield ("cli-idle-timeout", None, "") if enabled else _missing("cli-idle-timeout")
    else:
        yield "cli-idle-timeout", command, "disabled" if command.tokens[0] == "disable" else ""


@_taxonomy("aaa", "account-lockout-unproven", intent=lambda i: i.get("account_lockout_required"))
def exos_lockout(tree, context):
    settings = {}
    accounts = {"admin", "user"}
    administrators = {"admin"}
    for command in tree.active:
        tokens = command.tokens
        if command.starts_with("create", "account") and command.argument(2) in ("admin", "user") and len(tokens) >= 4:
            accounts.add(tokens[3])
            if tokens[2] == "admin":
                administrators.add(tokens[3])
        elif command.starts_with("delete", "account") and len(tokens) == 3:
            accounts.discard(tokens[2])
            administrators.discard(tokens[2])
            settings.pop(tokens[2], None)
        elif (command.starts_with("configure", "account") and len(tokens) == 6
              and tokens[3:5] == ("password-policy", "lockout-on-login-failures") and tokens[5] in ("on", "off")):
            if tokens[2] == "all":
                settings.clear()
            settings[tokens[2]] = command

    readback = context.snapshot.auxiliary.get("accounts password-policy", "") if context.snapshot else ""
    flags = _lockout_flags(readback)
    for name in context.intent["account_lockout_required"]:
        command = settings.get(name, settings.get("all") if name in accounts else None)
        if name in flags:
            yield name, command, "" if flags[name] else "disabled"
        elif command is None and name in accounts and _default(context, "lockout-on-login-failures") == "off":
            yield name, None, "disabled"
        elif command is None:
            yield _missing(name)
        elif command.tokens[-1] == "off":
            yield name, command, "disabled"
        elif name in administrators and not any(
                other != name and (policy := settings.get(other, settings.get("all")))
                and policy.tokens[-1] == "off" for other in administrators):
            # The device preserves at least one administrator from lockout.
            yield _missing(name)
        else:
            yield name, command, ""


def _lockout_flags(readback):
    if "Lockout Time Config:" not in readback or "Flags:" not in readback:
        return {}
    return {row[1]: "l" in row[2] for row in re.finditer(
        r"(?m)^\s*([A-Za-z0-9][\w.-]*) +(?:.*?) +(?:U|\d+) +(?:-|\d+) +([A-Za-z-]+) *$", readback)}


def _policy_prefixes(body):
    """Read source-only EXOS policy entries, in their actual evaluation order."""
    entries = re.findall(r"(?is)\bentry\s+\S+\s*\{\s*if\s*\{([^{}]*)\}\s*then\s*\{([^{}]*)\}\s*\}", body)
    if not entries or len(re.findall(r"(?im)^\s*entry\s+", body)) != len(entries):
        return None
    result = []
    for match, action in entries:
        source = re.fullmatch(r"\s*source-address\s+([^;\s]+)\s*;\s*", match, re.I)
        decision = re.fullmatch(r"\s*(permit|deny)\s*;\s*", action, re.I)
        if decision is None or (source is None and match.strip()):
            return None
        try:
            prefix = ip_network(source[1], strict=False) if source else None
        except ValueError:
            return None
        result.append((prefix, decision[1].lower()))
    return result


def _acl_restricts(entries, expected):
    for network in (ip_network("0.0.0.0/0"), ip_network("::/0")):
        unmatched = [network]
        for prefix, action in entries:
            if prefix is not None and prefix.version != network.version:
                continue
            next_unmatched = []
            for pending in unmatched:
                if prefix is not None and not prefix.overlaps(pending):
                    next_unmatched.append(pending)
                    continue
                matched = pending if prefix is None or pending.subnet_of(prefix) else prefix
                if action == "permit" and not any(matched.subnet_of(allowed) for allowed in expected
                                                  if matched.version == allowed.version):
                    return False
                if matched != pending:
                    next_unmatched.extend(pending.address_exclude(matched))
            unmatched = next_unmatched
        # The end of an EXOS access profile is an implicit deny.
    return True


@_taxonomy("exsshd", "ssh-access-profile-unproven", intent=lambda i: i.get("management_prefixes"))
def exos_access_acl(tree, context):
    binding = None
    enabled = None
    dynamic = False
    for command in tree.active:
        tokens = command.tokens
        if tokens[:2] in (("enable", "ssh2"), ("disable", "ssh2")):
            enabled = tokens[0] == "enable"
            switch = command
            if enabled and "access-profile" in tokens[2:]:
                binding, dynamic = command, False
        elif command.starts_with("configure", "ssh2", "access-profile"):
            binding, dynamic = command, command.argument(3) in ("add", "delete")
    if enabled is False:
        return
    profile = _option(binding.tokens, "access-profile") if binding else None
    if enabled and binding is None and _default(context, "ssh2 access-profile") == "none":
        yield "ssh", switch, "no-filter"
    elif not profile or dynamic:
        yield _missing("ssh")
    elif profile == "none":
        yield "ssh", binding, "no-filter"
    else:
        body = context.snapshot.auxiliary.get("ssh access-profile " + profile) if context.snapshot else None
        entries = _policy_prefixes(body) if body else None
        if entries is None:
            yield _missing("ssh")
        else:
            expected = tuple(ip_network(value, strict=False) for value in context.intent["management_prefixes"])
            yield "ssh", binding, "" if _acl_restricts(entries, expected) else "overbroad-filter"


@_taxonomy("aaa", "external-login-unproven", intent=lambda i: i.get("external_aaa_required"))
def exos_external_login(tree, context):
    families = (("radius", "mgmt-access"), ("tacacs",))
    effective = [_switch(tree, family) for family in families]
    active = False
    for family, command in zip(families, effective):
        if command is None or command.tokens[0] == "disable":
            continue
        active = True
        for kind in ("primary", "secondary"):
            server = _last(tree, "configure", *family, kind, "server")
            if (server and server.argument(len(family) + 3)
                    and _option(server.tokens[len(family) + 4:], "client-ip")):
                return
    if _proven(context, "aaa"):
        yield "external-login", next((item for item in effective if item), None), (
            "no-server" if active else "disabled")
    elif all(effective) and not active:
        yield "external-login", effective[-1], "disabled"
    else:
        yield _missing("external-login")


def _snmp_access(tree, version):
    return _switch(tree, ("snmp", "access"), ("snmp", "access", version))


def _snmp_scope(tree, version):
    return _snmp_access(tree, version) is not None


@_taxonomy("snmpMaster", "snmp-v1v2c-unproven", scope=lambda t: _snmp_scope(t, "snmp-v1v2c"))
def exos_v1v2c_community(tree, context):
    enabled = _snmp_access(tree, "snmp-v1v2c")
    if enabled is None:
        if _default(context, "snmp access") != "disabled":
            yield _missing("snmp-v1v2c")
        return
    if enabled.tokens[0] == "disable":
        return
    communities = _communities(tree)
    if communities:
        yield "snmp-v1v2c", communities[0], "community-access-enabled"
    elif not _proven(context, "snmpMaster"):
        yield _missing("snmp-v1v2c")


def _communities(tree):
    legacy, stored, switches = {}, {}, {}
    for command in tree.active:
        tokens = command.tokens
        if tokens[:2] == ("configure", "snmp") and command.argument(3) == "community":
            mode, value = tokens[4:5], tokens[5:]
            if mode not in (("readonly",), ("readwrite",)) or not value:
                continue
            identifier = value[:2] if value[0] in ("hex", "encrypted") else value[:1]
            if tokens[2] == "add":
                legacy[mode, identifier] = command
            elif tokens[2] == "delete" and identifier == ("all",):
                legacy = {key: entry for key, entry in legacy.items() if key[0] != mode}
            elif tokens[2] == "delete":
                legacy.pop((mode, identifier), None)
        elif tokens[:2] == ("configure", "snmpv3") and command.argument(3) == "community" and len(tokens) > 4:
            key = _snmp_name(tokens[4:])
            options = tokens[6 if tokens[4] == "hex" else 5:]
            if tokens[2] == "add" and key:
                name = _snmp_name(options[options.index("name") + 1:]) if "name" in options else None
                stored[key] = (name, _option(options, "user") in ("v1v2c_ro", "v1v2c_rw"), command)
            elif tokens[2] == "delete":
                if tokens[4] == "all":
                    stored.clear()
                    legacy.clear()
                elif tokens[4] == "name":
                    name = _snmp_name(options)
                    stored = {idx: entry for idx, entry in stored.items() if entry[0] != name}
                else:
                    stored.pop(key, None)
        elif tokens[:1] in (("enable",), ("disable",)) and tokens[1:3] == ("snmpv3", "community"):
            switches[_snmp_name(tokens[3:])] = tokens[0] == "enable"
    return [*legacy.values(), *(item for key, (_, usable, item) in stored.items()
                                if usable and switches.get(key, True))]


def _snmp_name(tokens):
    if tokens[:1] == ("hex",) and len(tokens) >= 2:
        try:
            return bytes.fromhex(tokens[1].replace(":", ""))
        except ValueError:
            return None
    return tokens[0].encode() if tokens else None


def _usm_users(tree):
    users, groups, accesses = {}, {}, {}
    for command in tree.active:
        tokens = command.tokens
        if tokens[:2] != ("configure", "snmpv3") or len(tokens) < 5 or tokens[2] not in ("add", "delete"):
            continue
        added = tokens[2] == "add"
        name = _snmp_name(tokens[4:])
        if name is None:
            continue
        options = tokens[6 if tokens[4] == "hex" else 5:]
        if tokens[3] == "user":
            if added:
                auth = _option(options, "authentication") not in (None, "none")
                priv = _option(options, "privacy") not in (None, "none")
                users[name] = (2 if auth and priv else int(auth), command)
            else:
                users.pop(name, None)
        elif _option(options, "sec-model", "usm") == "usm":
            if tokens[3] == "group" and "user" in options:
                user = _snmp_name(options[options.index("user") + 1:])
                if added:
                    groups[user] = name
                else:
                    groups.pop(user, None)
            elif tokens[3] == "access":
                level = _option(options, "sec-level", "noauth")
                if level not in ("noauth", "authnopriv", "priv"):
                    continue
                levels = accesses.setdefault(name, {})
                if added:
                    levels[("noauth", "authnopriv", "priv").index(level)] = (
                        _option(options, "read-view", "defaultUserView") not in ("", "none")
                        or _option(options, "write-view", "") not in ("", "none"))
                else:
                    levels.pop(("noauth", "authnopriv", "priv").index(level), None)
    return users, groups, accesses


@_taxonomy("snmpMaster", "snmp-usm-vacm-unproven", scope=lambda t: _snmp_scope(t, "snmpv3"))
def exos_v3_auth_priv(tree, context):
    enabled = _snmp_access(tree, "snmpv3")
    if enabled is None:
        if _default(context, "snmp access") != "disabled":
            yield _missing("snmpv3")
        return
    if enabled.tokens[0] == "disable":
        return
    users, groups, accesses = _usm_users(tree)
    unknown = not groups or not accesses
    checked = False
    for user, group in groups.items():
        if user not in users or group not in accesses:
            unknown = True
            continue
        level, command = users[user]
        usable = [minimum for minimum in accesses[group] if minimum <= level]
        checked = checked or bool(usable)
        if level < 2 and usable and accesses[group][max(usable)]:
            yield "snmpv3", command, "access-without-auth-privacy"
            return
    if unknown or (not checked and not _proven(context, "snmpMaster")):
        yield _missing("snmpv3")


@_taxonomy("ntp", "ntp-authentication-unproven", intent=lambda i: i.get("ntp_auth_required"))
def exos_ntp_auth(tree, context):
    auth = _switch(tree, ("ntp", "authentication"))
    sntp = _switch(tree, ("sntp-client",))
    ntp = {}
    for item in tree.active:
        tokens = item.tokens
        if tokens[0] in ("enable", "disable") and tokens[1:2] == ("ntp",):
            if len(tokens) == 2 or len(tokens) == 4 and tokens[2] == "vr":
                ntp[item.argument(3, "VR-Default")] = item
    if sntp and sntp.tokens[0] == "enable":
        # The two clients cannot operate at the same time. Conflicting
        # explicit enables do not establish which one took effect.
        if any(item.tokens[0] == "enable" for item in ntp.values()):
            yield _missing("ntp")
        else:
            yield "ntp", sntp, "sntp-only"
        return
    if auth and auth.tokens[0] == "disable":
        yield "ntp", auth, "disabled"
        return
    keys, trusted, sources = {}, {}, {}
    for command in tree.active:
        tokens = command.tokens
        if command.starts_with("create", "ntp", "key") and len(tokens) >= 6:
            keys[tokens[3]] = tokens[4] in ("md5", "sha256")
        elif command.starts_with("delete", "ntp", "key") and len(tokens) == 4:
            if tokens[3] == "all":
                keys.clear()
                trusted.clear()
            else:
                keys[tokens[3]] = trusted[tokens[3]] = False
        elif command.starts_with("configure", "ntp", "key") and len(tokens) == 5:
            trusted[tokens[3]] = tokens[4] == "trusted"
        elif tokens[:2] == ("configure", "ntp") and len(tokens) >= 5 and tokens[2] in ("peer", "server"):
            identity = (tokens[2], tokens[4], _option(tokens[5:], "vr", "VR-Default"))
            if tokens[3] == "add":
                sources[identity] = command
            elif tokens[3] == "delete":
                sources.pop(identity, None)
    if not sources or auth is None:
        if ntp and all(item.tokens[0] == "disable" for item in ntp.values()):
            yield "ntp", next(iter(ntp.values())), "disabled"
        else:
            yield _missing("ntp")
        return
    active = []
    unknown = False
    for (_, _, vr), item in sources.items():
        if vr not in ntp:
            unknown = True
        elif ntp[vr].tokens[0] == "enable":
            active.append(item)
    if not active and not unknown:
        yield "ntp", next(iter(ntp.values())), "disabled"
        return
    unprotected = next((item for item in active if (
        (key := _option(item.tokens[5:], "key")) is None or key == "0"
        or keys.get(key) is False or trusted.get(key) is False)), None)
    if unprotected is not None:
        yield "ntp", unprotected, "source-without-trusted-key"
    elif unknown or any(not keys.get(_option(item.tokens[5:], "key")) or
                        not trusted.get(_option(item.tokens[5:], "key")) for item in active):
        yield _missing("ntp")


_SYSLOG_LEVEL = {**dict(zip(management.SYSLOG_LEVELS, range(8))),
                 "informational": 6, "debug-summary": 7, "debug-verbose": 8, "debug-data": 9}
_FACILITY = re.compile(r"(?:local[0-7]|auth|security|lpr|netinfo|cron|news|syslog|user)")


def _log_target(tokens):
    if not tokens:
        return None, ()
    end = next((i for i, token in enumerate(tokens[1:], 1) if _FACILITY.fullmatch(token)), None)
    if end is None:
        return None, ()
    qualifiers = tokens[1:end]
    return (tokens[0], _option(qualifiers, "vr", "VR-Default"), tokens[end],
            _option(qualifiers, "udp-port", _option(qualifiers, "tls-port", ""))), tokens[end + 1:]


def _severity(tokens):
    level = _SYSLOG_LEVEL.get(_option(tokens, "severity", "").casefold())
    if level is None:
        return None
    return {level} if "only" in tokens else set(range(level + 1))


def _filter_status(tree, name, required, context):
    commands = tree.matching("configure", "log", "filter", name)
    defaults = name == "DefaultFilter"
    if not commands:
        return "" if defaults else None
    # Broad, unqualified event rules can establish complete coverage. For
    # a partial exclusion we can establish a gap but cannot count events.
    covered = set(range(10)) if defaults else set()
    unknown = False
    for item in commands:
        tokens = item.tokens[4:]
        if not tokens or tokens[0] not in ("add", "delete") or "events" not in tokens:
            unknown = True
            continue
        event = _option(tokens, "events")
        levels = _severity(tokens) or set(range(10))
        if "exclude" in tokens and tokens[0] == "add" and levels & required:
            if event == "all" and not any(word in tokens for word in ("match", "strict-match")):
                covered -= levels
            else:
                return "filter-excludes-required-events"
        elif event == "all" and not any(word in tokens for word in ("match", "strict-match")):
            covered = covered | levels if tokens[0] == "add" else covered - levels
        else:
            unknown = True
    if required <= covered and not unknown:
        return ""
    if not unknown and (defaults or _proven(context, "ems") or covered):
        return "filter-excludes-required-events"
    return None


@_taxonomy("ems", "syslog-target-or-filter-unproven", intent=lambda i: "syslog_severity" in i)
def exos_syslog_level(tree, context):
    targets, states, settings = {}, {}, {}
    for command in tree.active:
        tokens = command.tokens
        if tokens[:2] == ("configure", "syslog") and command.argument(2) in ("add", "delete"):
            key, _ = _log_target(tokens[3:])
            if key is None:
                continue
            if tokens[2] == "add":
                targets[key] = command
            else:
                targets.pop(key, None)
                settings.pop(key, None)
                states.pop(key, None)
        elif tokens[1:4] == ("log", "target", "syslog"):
            key, args = _log_target(tokens[4:])
            if command.argument(4) == "all":
                selected = tuple(targets)
                args = tokens[5:]
            else:
                selected = (key,) if key is not None else ()
            for target in selected:
                if tokens[0] in ("enable", "disable"):
                    states[target] = tokens[0] == "enable"
                elif tokens[0] == "configure":
                    filter_name, levels, _ = settings.get(target, ("DefaultFilter", None, command))
                    settings[target] = (_option(args, "filter", filter_name),
                                        _severity(args) if "severity" in args else levels, command)

    if not targets and not _proven(context, "ems"):
        yield _missing("syslog")
    required = set(range(_SYSLOG_LEVEL[context.intent["syslog_severity"]] + 1))
    unknown = False
    for key in targets:
        if states.get(key) is False:
            continue
        name, levels, command = settings.get(key, ("DefaultFilter", None, targets[key]))
        if key not in states or levels is None:
            unknown = True
            continue
        problem = "severity-too-narrow" if not required <= levels else _filter_status(tree, name, required, context)
        if problem:
            yield "syslog", command, problem
            return
        unknown = unknown or problem is None
    if unknown:
        yield _missing("syslog")


def _selected_ports(intent, role, flag=None, wanted=True):
    return tuple(port for port, attrs in intent.get("ports", {}).items()
                 if attrs["role"] == role and (flag is None or attrs.get(flag) is wanted))


def _port_range(value, inventory, observed):
    if value == "all":
        # "all" includes every known or explicitly selected port.
        return observed | (inventory or set())
    try:
        return management.ports(value, inventory)
    except management.PolicyError:
        return None


def _port_command(commands, port, forms, inventory, observed, *, skip_receive_disable=False):
    """Select the last applicable port command, retaining an unknown override."""
    for item in reversed(commands):
        if skip_receive_disable and item.starts_with("disable", "lldp") and item.argument(4) == "receive-only":
            continue
        for prefix, suffix, position in forms:
            if not item.starts_with(*prefix) or item.tokens[position + 1:position + 1 + len(suffix)] != suffix:
                continue
            value = item.argument(position)
            if value is None:
                continue
            members = _port_range(value, inventory, observed)
            if members is None or port in members:
                return item, members is not None
    return None, True


_EDP = tuple(((verb, "edp", "ports"), (), 3) for verb in ("enable", "disable"))
_LLDP = tuple(((verb, "lldp", "ports"), (), 3) for verb in ("enable", "disable"))
# The device prints a disabled port as `disable port <ports>`; the command also accepts `ports`.
_PORT_ADMIN = tuple(((verb, noun), (), 2) for verb in ("enable", "disable") for noun in ("ports", "port"))
_FLOOD = ((("configure", "ports"), ("rate-limit", "flood", "broadcast"), 2),)


@_taxonomy("edp", "edge-discovery-unproven",
           intent=lambda i: _selected_ports(i, "edge", "discovery_allowed", False))
def exos_edge_discovery(tree, context):
    selected = set(_selected_ports(context.intent, "edge", "discovery_allowed", False))
    inventory = management.port_inventory(tree)
    for port in sorted(selected):
        lldp, known_lldp = _port_command(tree.active, port, _LLDP, inventory, selected)
        edp, known_edp = _port_command(tree.active, port, _EDP, inventory, selected)
        # Disabling receive-only leaves transmission as it was. Enabling
        # receive-only replaces the old mode on the port.
        if known_lldp and lldp and lldp.tokens[0] == "disable" and lldp.argument(4) == "receive-only":
            lldp, known_lldp = _port_command(tree.active, port, _LLDP, inventory, selected, skip_receive_disable=True)
        lldp_tx = (lldp.tokens[0] == "enable" and lldp.argument(4) != "receive-only") if lldp else None
        edp_tx = edp.tokens[0] == "enable" if edp else None
        if edp is None and port in (inventory or ()) and "edp" in tree.modules and _default(context, "edp ports"):
            edp_tx = True
        if lldp is None and port in (inventory or ()) and "lldp" in tree.modules and _default(context, "lldp ports"):
            lldp_tx = True
        if known_edp and edp_tx:
            yield port, edp, "edp-transmitting"
        elif known_lldp and lldp_tx:
            yield port, lldp, "lldp-transmitting"
        elif not known_lldp or not known_edp or lldp_tx is None or edp_tx is None:
            yield _missing(port)


def _vlan_membership(tree, observed):
    inventory = management.port_inventory(tree)
    tags, members, sharing = {"default": 1}, {}, {}
    complete = True
    for item in tree.active:
        tokens = item.tokens
        if item.starts_with("enable", "sharing") and item.argument(3) == "grouping" and item.argument(4):
            ports = _port_range(tokens[4], inventory, observed)
            if ports is None:
                complete = False
            else:
                sharing[tokens[2]] = ports | {tokens[2]}
        elif item.starts_with("disable", "sharing") and len(tokens) >= 3:
            sharing.pop(tokens[2], None)
        elif item.starts_with("create", "vlan") and len(tokens) >= 3:
            tag = _option(tokens[3:], "tag", "")
            if tag.isdecimal():
                tags[tokens[2].casefold()] = int(tag)
        elif item.starts_with("delete", "vlan") and len(tokens) == 3:
            tags.pop(tokens[2].casefold(), None)
            members.pop(tokens[2].casefold(), None)
        elif item.starts_with("configure", "vlan") and len(tokens) >= 5:
            vlan = tokens[2].casefold()
            if tokens[3] == "tag" and tokens[4].isdecimal():
                tags[vlan] = int(tokens[4])
            elif tokens[3] in ("add", "delete") and tokens[4] == "ports" and len(tokens) >= 6:
                selection = _port_range(tokens[5], inventory, observed)
                if selection is None:
                    complete = False
                    continue
                by_port = members.setdefault(vlan, {})
                tag_mode = item.argument(6, "untagged") if tokens[3] == "add" else ""
                for port in selection:
                    by_port[port] = (tag_mode, item)
    return tags, members, sharing, complete


@_taxonomy("vlan", "physical-port-or-default-vlan-unproven",
           intent=lambda i: _selected_ports(i, "edge", "default_vlan_allowed", False))
def exos_default_vlan(tree, context):
    observed = set(_selected_ports(context.intent, "edge", "default_vlan_allowed", False))
    tags, vlans, sharing, complete = _vlan_membership(tree, observed)
    inventory = management.port_inventory(tree)
    for port in sorted(observed):
        if any(port in members for members in sharing.values()):
            continue
        admin, known = _port_command(tree.active, port, _PORT_ADMIN, inventory, observed)
        if known and admin and admin.tokens[0] == "disable":
            continue
        entries = [members[port] for name, members in vlans.items() if tags.get(name) == 1 and port in members]
        if not complete or not known:
            yield _missing(port)
        elif any(mode == "untagged" for mode, _ in entries):
            if admin and admin.tokens[0] == "enable":
                yield port, next(item for mode, item in entries if mode == "untagged"), "untagged-vlan-1"
            elif _proven(context, "vlan") and port in (inventory or ()):
                yield port, next(item for mode, item in entries if mode == "untagged"), "untagged-vlan-1"
            else:
                yield _missing(port)
        elif not entries:
            # An explicit untagged move establishes that the port left VLAN 1.
            moved = any(tags.get(name) not in (None, 1) and members.get(port, ("",))[0] == "untagged"
                        for name, members in vlans.items())
            if not moved:
                if _proven(context, "vlan") and port in (inventory or ()) and (
                        admin or _default(context, "port admin state") == "enabled"):
                    yield port, admin, "untagged-vlan-1"
                else:
                    yield _missing(port)


@_taxonomy("stp", "edge-stp-domain-or-protection-unproven", intent=lambda i: _selected_ports(i, "edge"))
def exos_bpdu_guard(tree, context):
    observed = set(_selected_ports(context.intent, "edge"))
    _, vlans, sharing, complete = _vlan_membership(tree, observed)
    inventory = management.port_inventory(tree)
    domains, protected = {}, {}
    for item in tree.matching("configure", "stpd"):
        tokens = item.tokens
        if len(tokens) >= 8 and tokens[3:5] in (("add", "vlan"), ("delete", "vlan")) and tokens[6] == "ports":
            vlan_members = vlans.get(tokens[5].casefold(), {})
            selection = _port_range(tokens[7], inventory, observed)
            if selection is None:
                complete = False
                continue
            state = domains.setdefault(tokens[2], {})
            for port in selection:
                if vlan_members.get(port, ("",))[0]:
                    state[port] = tokens[3] == "add"
        elif len(tokens) >= 7 and tokens[3:5] == ("ports", "bpdu-restrict"):
            selection = _port_range(tokens[6], inventory, observed)
            if selection is None:
                complete = False
                continue
            for port in selection:
                protected[tokens[2], port] = item
    for port in sorted(observed):
        if any(port in members for members in sharing.values()):
            continue
        states = {domain: _switch(tree, ("stpd", domain)) for domain, members in domains.items()
                  if members.get(port)}
        if not complete or not states or any(state is None for state in states.values()):
            yield _missing(port)
            continue
        active = [domain for domain, state in states.items() if state.tokens[0] == "enable"]
        for domain in active:
            item = protected.get((domain, port))
            if item is not None and item.tokens[5] == "disable" or item is None and _proven(context, "stp"):
                yield port, item, "bpdu-restrict-disabled"
                break
        else:
            if any((domain, port) not in protected for domain in active):
                yield _missing(port)


@_taxonomy("ipSecurity", "dhcp-vlan-members-or-trust-unproven", intent=lambda i: i.get("dhcp_snooping_vlans"))
def exos_dhcp_snooping(tree, context):
    selected = set(_selected_ports(context.intent, "edge"))
    tags, vlans, sharing, complete = _vlan_membership(tree, selected)
    inventory = management.port_inventory(tree)
    trusted = context.intent.get("trusted_dhcp_ports")
    for tag in sorted(context.intent["dhcp_snooping_vlans"]):
        vlan = next((name for name, number in tags.items() if number == tag), None)
        if trusted is None or not complete or vlan not in vlans:
            yield _missing(str(tag))
            continue
        for port, (mode, _) in sorted(vlans[vlan].items()):
            if not mode or port in trusted or any(port in members for members in sharing.values()):
                continue
            key = "%s/%s" % (tag, port)
            if port not in selected:
                yield _missing(key)
                continue
            forms = tuple(((verb, "ip-security", "dhcp-snooping", "vlan"), (), 6)
                          for verb in ("enable", "disable"))
            # VLAN names are case-insensitive and scopes can coexist.
            commands = tuple(item for item in tree.active
                             if (item.argument(4) or "").casefold() == vlan and item.argument(5) == "ports")
            item, known = _port_command(commands, port, forms, inventory, selected)
            if not known or item is None and not _proven(context, "ipSecurity"):
                yield _missing(key)
            elif item is None or item.tokens[0] == "disable" or (
                    _option(item.tokens[7:], "violation-action") != "drop-packet"):
                yield key, item, "dhcp-snooping-not-enforcing"


@_taxonomy("vlan", "broadcast-limit-or-port-capability-unproven",
           intent=lambda i: _selected_ports(i, "edge", "storm_control_required"))
def exos_storm_control(tree, context):
    observed = set(_selected_ports(context.intent, "edge", "storm_control_required"))
    inventory = management.port_inventory(tree)
    _, _, sharing, complete = _vlan_membership(tree, observed)
    for port in sorted(observed):
        if any(port in members for members in sharing.values()):
            yield _missing(port)
            continue
        item, known = _port_command(tree.active, port, _FLOOD, inventory, observed)
        limit = item.argument(6, "") if item else ""
        if not known or not complete:
            yield _missing(port)
        elif limit == "no-limit" or item is None and port in (inventory or ()) and (
                _default(context, "rate-limit flood broadcast") == "no-limit"):
            yield port, item, "broadcast-unlimited"
        elif not limit.isdecimal() or int(limit) <= 0:
            yield _missing(port)


@_taxonomy("vlan", "physical-port-admin-state-unproven", intent=lambda i: _selected_ports(i, "unused"))
def exos_unused_up(tree, context):
    observed = set(_selected_ports(context.intent, "unused"))
    inventory = management.port_inventory(tree)
    _, _, sharing, complete = _vlan_membership(tree, observed)
    for port in sorted(observed):
        if any(port in members for members in sharing.values()):
            yield _missing(port)
            continue
        item, known = _port_command(tree.active, port, _PORT_ADMIN, inventory, observed)
        enabled = item is None and port in (inventory or ()) and _default(context, "port admin state") == "enabled"
        if not known or not complete or item is None and not enabled:
            yield _missing(port)
        elif enabled or item.tokens[0] == "enable":
            yield port, item, "administratively-enabled"
