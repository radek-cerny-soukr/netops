"""Secret redaction for MCP responses and persistent audit metadata."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable


_SECRET_LABELS = (
    r"(?:api|access)[_ -]?token|bearer|token|api[_ -]?key|password|passwd|secret|community"
)
ASSIGNED_QUOTED_SECRET = re.compile(
    rf"""(?ix)
    (?P<prefix>(?<![\w-])["']?(?:{_SECRET_LABELS})["']?\s*[:=]\s*)
    (?:"[^"\r\n]*"|'[^'\r\n]*')
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
    r'(?im)^([^\S\n]*(?:snmp-server\s+community|set\s+community)\s+)(?:"[^"\r\n]*"|\S+)'
)
SNMP_STATUS_SECRET = re.compile(
    r"(?i)(\bSNMP\s+community\s+string\s+(?:configured|is)\s*[:=]\s*)\S+"
)
COMMUNITY_VALUE_SECRET = re.compile(r"(?i)(\bcommunity[ \t]+)(?!string\b)\S+")
CISCO_TYPE7_SECRET = re.compile(r"(?im)(\b(?:key|key-string|md5|password)[ \t]+7[ \t]+)\S+")
PRESHARED_SECRET = re.compile(
    r'(?im)(\b(?:pre-shared-key|psksecret|psk|wpa-passphrase|bind-password)(?:[ \t]*[:=][ \t]*|[ \t]+))(?:"[^"\r\n]*"|\S+)'
)
SHADOW_HASH = re.compile(r"(?m)^([^:\r\n]+:)(?:[!*][^:\r\n]*|\$[^:\r\n]+)(?=:)")
FORTI_ENC = re.compile(r"\bENC\s+\S+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)


def _replace_quoted(match: re.Match[str]) -> str:
    return match.group("prefix") + '"<REDACTED>"'


def _replace_bare(match: re.Match[str]) -> str:
    return match.group("prefix") + "<REDACTED>"


def _next_label(value: str, position: int, chunk: int) -> re.Match[str] | None:
    while position < len(value):
        found = SECRET_LABEL.search(value, position, min(len(value), position + chunk + LABEL_OVERLAP))
        if found is not None:
            return found
        position += chunk
    return None


def _assigned(pattern: re.Pattern[str], replace, value: str, chunk: int = LABEL_CHUNK) -> str:
    value = str.__str__(value)
    parts, cursor, position = [], 0, 0
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
        parts += [value[cursor:match.start()], replace(match)]
        cursor = position = match.end()
    if not parts:
        return value
    parts.append(value[cursor:])
    return "".join(parts)


def redact(text: object, secrets: Iterable[str] = (), limit: int | None = None) -> str:
    """Remove explicit credentials and key material while preserving diagnostic context."""
    value = str(text)
    for secret in sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True):
        value = value.replace(secret, "<REDACTED>")
    value = PRIVATE_PEM.sub("<PRIVATE-KEY-REDACTED>", value)
    value = FORTI_ENC.sub("ENC <REDACTED>", value)
    value = SHADOW_HASH.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = CISCO_ENABLE_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = CISCO_USER_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = SNMP_CLI_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = SNMP_STATUS_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = COMMUNITY_VALUE_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = CISCO_TYPE7_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = PRESHARED_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = BEARER_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = _assigned(ASSIGNED_QUOTED_SECRET, _replace_quoted, value)
    value = _assigned(ASSIGNED_BARE_SECRET, _replace_bare, value)
    if limit is not None and len(value) > limit:
        raise ValueError("redacted output exceeds the explicit limit")
    return value


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
