from __future__ import annotations

import hashlib
import json

from .engine import check

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


def _configured(configuration, *words) -> bool:
    return any(len(command.tokens) > len(words) for command in configuration.matching(*words))


@check("exos_no_sntp_client")
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


@check("exos_no_syslog_target")
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


@check("exos_default_snmp_community")
def exos_default_snmp_community(configuration):
    for command in configuration.commands:
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


@check("exos_telnet_enabled")
def exos_telnet_enabled(configuration):
    state = None
    for command in configuration.commands:
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
