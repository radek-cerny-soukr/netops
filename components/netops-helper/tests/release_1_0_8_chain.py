"""Verbatim copy of the released 1.0.8 credential chain (61e7de3, netops_helper/sanitize.py).

Test reference only, independent of the product module: the expressions, replacement
functions and order of ``_redact_credentials`` are copied unchanged; the span-tracking
helpers of ``netops.redaction_spans`` are replaced by their plain-string behaviour.
"""
# ruff: noqa
from __future__ import annotations

import re


class Marked(str):
    """Never instantiated here: the copy only runs on plain strings."""


def sub(pattern, replacement, value):
    return pattern.sub(replacement, value)


def replace(value, old, new):
    return value.replace(old, new)


def edits(value, changes):
    parts, cursor = [], 0
    for start, end, replacement in changes:
        parts.extend((value[cursor:start], replacement))
        cursor = end
    return ''.join(parts) + value[cursor:] if parts else value


_SECRET_LABELS = (
    r"(?:api|access)[_ -]?token|bearer|token|api[_ -]?key|password|passwd|secret|community"
)

_DOUBLE_QUOTED = r'"(?:\\[^\r\n]|[^"\\\r\n])*(?:"|[^\r\n]*)'

_SINGLE_QUOTED = r"'(?:\\[^\r\n]|[^'\\\r\n])*(?:'|[^\r\n]*)"

ASSIGNED_QUOTED_SECRET = re.compile(
    rf"""(?ix)
    (?P<prefix>(?<![\w-])["']?(?:{_SECRET_LABELS})["']?\s*[:=]\s*)
    (?:{_DOUBLE_QUOTED}|{_SINGLE_QUOTED})
    """
)

ASSIGNED_BARE_SECRET = re.compile(
    rf"""(?ix)
    (?P<prefix>(?<![\w-])["']?(?:{_SECRET_LABELS})["']?\s*[:=]\s*)
    [^\s,}}\]\r\n]+
    """
)

BEARER_SECRET = re.compile(r"(?i)(\bbearer[ \t]+)\S+")

SECRET_LABEL = re.compile(_SECRET_LABELS, re.I)

LABEL_CHUNK = 262144

LABEL_OVERLAP = 64

CISCO_ENABLE_SECRET = re.compile(
    r"(?im)(?<!\S)(enable[ \t]+(?:secret|password)(?:[ \t]+\d+)?[ \t]+)\S+"
)

CISCO_USER_SECRET = re.compile(
    r"(?im)^([^\S\n]*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)\S+"
)

SNMP_CLI_SECRET = re.compile(
    r"(?im)^([^\S\n]*(?:snmp-server\s+community|set\s+community)\s+)(?:" + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED + r"|\S+)"
)

SNMP_STATUS_SECRET = re.compile(
    r"(?i)(\bSNMP\s+community\s+string\s+(?:configured|is)\s*[:=]\s*)\S+"
)

COMMUNITY_VALUE_SECRET = re.compile(r"(?i)(\bcommunity[ \t]+)(?!string\b)\S+")

CISCO_TYPE7_SECRET = re.compile(r"(?im)(\b(?:key|key-string|md5|password)[ \t]+7[ \t]+)\S+")

PRESHARED_SECRET = re.compile(
    r"(?im)(\b(?:pre-shared-key|psksecret|psk|wpa-passphrase|bind-password)(?:[ \t]*[:=][ \t]*|[ \t]+))(?:"
    + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED + r"|\S+)"
)

DYNAMIC_PSK_STATE = re.compile(r"(?i)[ \t]*dynamic[ \t]+psk[ \t]*=[ \t]*(?:enabled|disabled)[ \t]*\r?")

RUCKUS_PASSPHRASE = re.compile(r"(?im)^([ \t]*passphrase[ \t]*=[ \t]*)[^\r\n]*")

CLI_OPTION_SECRET = re.compile(
    r"(?i)((?<!\S)--(?:password|passwd|secret|token|api-key|api-token|access-token)(?:=|[ \t]+))(?:"
    + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED + r"|\S+)"
)

SHADOW_HASH = re.compile(r"(?m)^([^:\r\n]+:)(?:[!*][^:\r\n]*|\$[^:\r\n]+)(?=:)")

FORTI_ENC = re.compile(r"\bENC\s+\S+")

PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)

def _replace_credential(match):
    value = match.group(0)[len(match.group(1)):]
    if _CREDENTIAL_MARKER.fullmatch(value):
        return match.group(0)
    return match.group(1) + '<REDACTED>'

def _replace_preshared(match: re.Match[str]) -> str:
    text = match.string
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    if DYNAMIC_PSK_STATE.fullmatch(text, start, len(text) if end < 0 else end):
        return match.group(0)
    if _CREDENTIAL_MARKER.fullmatch(match.group(0)[len(match.group(1)):]):
        return match.group(0)
    return match.group(1) + "<REDACTED>"

def _replace_quoted(match: re.Match[str]) -> str:
    return match.group("prefix") + '"<REDACTED>"'

def _quoted_only(replace):
    def apply(match: re.Match[str]) -> str:
        if match.string.startswith(('"', "'"), match.end(1)):
            return replace(match)
        return match.group(0)
    return apply

def _wtp_128_length_password_capability(match: re.Match[str]) -> bool:
    value = match.string
    start = value.rfind("\n", 0, match.start()) + 1
    end = value.find("\n", match.end())
    line = value[start:len(value) if end < 0 else end]
    return re.fullmatch(r"[ \t]*128-length passwd[ \t]*:[ \t]*enabled[ \t]*\r?", line) is not None

def _replace_bare(match: re.Match[str]) -> str:
    if _wtp_128_length_password_capability(match):
        return match.group(0)
    return match.group("prefix") + "<REDACTED>"

def _next_label(value: str, position: int, chunk: int) -> re.Match[str] | None:
    while position < len(value):
        found = SECRET_LABEL.search(value, position, min(len(value), position + chunk + LABEL_OVERLAP))
        if found is not None:
            return found
        position += chunk
    return None

def _assigned(pattern: re.Pattern[str], replace, value: str, chunk: int = LABEL_CHUNK) -> str:
    value = value if isinstance(value, Marked) else str.__str__(value)
    changes, cursor, position = [], 0, 0
    while True:
        label = _next_label(value, position, chunk)
        if label is None:
            break
        start = label.start()
        match = None
        if start - 1 >= cursor and value[start - 1] in "\"'":
            match = pattern.match(value, start - 1)
        if match is None:
            match = pattern.match(value, start)
        if match is None:
            position = start + 1
            continue
        changes.append((match.start(), match.end(), replace(match)))
        cursor = position = match.end()
    return edits(value, changes)

_CREDENTIAL_MARKER = re.compile(r'<REDACTED:credential#[1-9][0-9]*>')

def _redact_credentials(value: str, normalized: tuple[str, ...]) -> str:
    for secret in normalized:
        value = replace(value, secret, "<REDACTED>")
    value = sub(PRIVATE_PEM, "<PRIVATE-KEY-REDACTED>", value)
    # Quoted values go first, so that an ENC or bearer token cannot consume their closing quote.
    value = sub(SNMP_CLI_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sub(PRESHARED_SECRET, _quoted_only(_replace_preshared), value)
    value = sub(CLI_OPTION_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = _assigned(ASSIGNED_QUOTED_SECRET, _replace_quoted, value)
    value = sub(FORTI_ENC, "ENC <REDACTED>", value)
    value = sub(SHADOW_HASH, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(CISCO_ENABLE_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(CISCO_USER_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(SNMP_CLI_SECRET, _replace_credential, value)
    value = sub(SNMP_STATUS_SECRET, _replace_credential, value)
    value = sub(COMMUNITY_VALUE_SECRET, _replace_credential, value)
    value = sub(CISCO_TYPE7_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(PRESHARED_SECRET, _replace_preshared, value)
    value = sub(RUCKUS_PASSPHRASE, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(CLI_OPTION_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(BEARER_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
    value = _assigned(ASSIGNED_BARE_SECRET, _replace_bare, value)
    return value


def redact_1_0_8(text: str, secrets=()) -> str:
    """The 1.0.8 credential chain on plain text (the layer the product floor copies)."""
    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    return _redact_credentials(str(text), normalized)
