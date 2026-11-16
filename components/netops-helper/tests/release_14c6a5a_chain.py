"""Frozen copy of the main 14c6a5a response chain (netops_helper/sanitize.py), task 165-r4.

Test reference only, independent of the product module: the credential expressions,
replacement functions, ``_redact_credentials`` and the response flow
(``_settle_response``, ``_snmp_response``, ``redact_response``) are copied unchanged
(``ast.get_source_segment`` of ``git show 14c6a5a:.../sanitize.py``). The later layers
(proxy ``_sanitize_object``, product ``netops.redaction.redact``, SNMP context marking
and masking, terminal-control cleaning) are identical in 1.0.8 (61e7de3) and 14c6a5a
and are bound in ``bind_layers``; the proxy runs without the 1.0.10 rule
CISCO_TYPED_SECRET (``typed=False``, task 302-r3), its only rule change since 1.0.8. ``redact_response(text, secrets, helper=...)`` with the
1.0.8 credential copy is the complete 1.0.8 chain.
"""
# ruff: noqa
from __future__ import annotations

import json
import re

from netops.redaction_spans import Marked, edits, sub, replace, mask, loads, dumps


def bind_layers():
    """The later layers, unchanged since 1.0.8; bound at call time."""
    from netops_helper import sanitize, proxy_sanitize
    globals().update(_mark_snmp=sanitize._mark_snmp, _mask_snmp=sanitize._mask_snmp,
                     strip_terminal_controls=sanitize.strip_terminal_controls)


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

_LINE_CREDENTIAL = (r"(?:" + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED
                    + r"|(?:\\[^\r\n]?|[^\s\\])+)")

CISCO_USER_SECRET = re.compile(
    r"(?im)^([ \t]*username[ \t]+\S+(?:[ \t]+(?:privilege[ \t]+\d+|role[ \t]+\S+))*"
    r"[ \t]+(?:password|secret)(?:[ \t]+(?:\d+|sha512|sha256|md5)(?=[ \t]))?[ \t]+)" + _LINE_CREDENTIAL
)

AAA_SERVER_KEY = re.compile(
    r"(?im)^([ \t]*(?:tacacs|radius)-server[ \t]+key(?:[ \t]+[07](?=[ \t]))?[ \t]+)" + _LINE_CREDENTIAL
)

EXOS_ACCOUNT_SECRET = re.compile(
    r"(?im)^([ \t]*(?:configure[ \t]+account|create[ \t]+account[ \t]+(?:admin|user))[ \t]+\S+"
    r"[ \t]+encrypted[ \t]+)" + _LINE_CREDENTIAL
)

_ACCOUNT_SECRETS = (CISCO_USER_SECRET, AAA_SERVER_KEY, EXOS_ACCOUNT_SECRET)

_ACCOUNT_HINT = re.compile(r"(?i)username|(?:tacacs|radius)-server|account|\\u")

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

def _account_edits(text: str, cache: dict) -> list:
    """Account-rule edits of one decoded string as (start, end, replacement).

    Every rule match stays its own edit in the string's own offsets, so text between
    two edits (and any original range in it) is kept exactly; a nested JSON document
    is edited inside its own string tokens. Each distinct string is cleaned once.
    """
    if text not in cache:
        changes = []
        if _ACCOUNT_HINT.search(text):
            for pattern in _ACCOUNT_SECRETS:
                for match in pattern.finditer(text):
                    replacement = _replace_credential(match)
                    if replacement != match.group(0):
                        changes.append((match.start(), match.end(), replacement))
            if not changes:
                changes = _json_account_edits(text, cache)
        cache[text] = sorted(changes)
    return cache[text]

def _json_account_edits(text: str, cache: dict) -> list:
    """Translate the edits of each JSON string token into document offsets."""
    if text.lstrip()[:1] not in ("{", "["):
        return []
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(decoded, (dict, list)):
        return []
    from netops.redaction_spans import _JSON_STRING, _boundaries
    changes = []
    for token in _JSON_STRING.finditer(text):
        inner = _account_edits(json.loads(token.group()), cache)
        if inner:
            bounds, ascii_only = _boundaries(token.group()), token.group().isascii()
            changes.extend((token.start() + bounds[start], token.start() + bounds[end],
                            json.dumps(replacement, ensure_ascii=ascii_only)[1:-1])
                           for start, end, replacement in inner)
    return changes

def _account_credentials(value):
    """Account and AAA credential lines, also inside JSON string tokens.

    The rules are anchored to a CLI line start, which a JSON-escaped newline is not;
    only the matched credential text inside a string token is re-encoded, so the
    rest of the document and its original ranges are kept.
    """
    if not _ACCOUNT_HINT.search(value):
        return value
    for pattern in _ACCOUNT_SECRETS:
        value = sub(pattern, _replace_credential, value)
    try:
        changes = _json_account_edits(value, {})
    except RecursionError:
        raise ValueError('redaction could not be verified; output withheld') from None
    return edits(value, changes) if changes else value

def _redact_credentials(value: str, normalized: tuple[str, ...]) -> str:
    for secret in normalized:
        value = replace(value, secret, "<REDACTED>")
    value = sub(PRIVATE_PEM, "<PRIVATE-KEY-REDACTED>", value)
    # Quoted values go first, so that an ENC or bearer token cannot consume their closing quote.
    value = sub(SNMP_CLI_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sub(PRESHARED_SECRET, _quoted_only(_replace_preshared), value)
    value = sub(CLI_OPTION_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    # Before ENC/bearer/type-7 rules, which could split a quoted or escaped value.
    value = _account_credentials(value)
    value = _assigned(ASSIGNED_QUOTED_SECRET, _replace_quoted, value)
    value = sub(FORTI_ENC, "ENC <REDACTED>", value)
    value = sub(SHADOW_HASH, lambda match: match.group(1) + "<REDACTED>", value)
    value = sub(CISCO_ENABLE_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
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

def _settle_response(value, secrets, *, helper=False):
    """Run the pre-SNMP layers to a fixed point on the same document."""
    from netops.redaction import redact as product_redact
    from netops_helper.proxy_sanitize import _sanitize_object

    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    for _ in range(8):
        original = _redact_credentials(value, normalized) if helper else value
        cleaned = product_redact(_sanitize_object(original, secrets, typed=False), secrets)[0]
        if cleaned == value:
            return value
        value = cleaned
    raise ValueError('redaction could not be verified; output withheld')

_SIMPLE_SNMP_VALUE = re.compile(r"([\"']?)([A-Za-z0-9_-]+)\1")

_WORKER_ANCHOR_ENDS = ('password', 'passwd', 'secret', 'token', 'community',
                       'set', 'encrypted', 'passphrase', 'auth-pwd', 'priv-pwd')

def _needs_worker_before_mask(value, secrets):
    # A single alphanumeric CLI value cannot contain a worker rule's syntax or
    # remove a line boundary. Exclude even suffixes that could be an anchor for
    # a cross-line worker match; all complex values keep the complete raw floor.
    if secrets:
        return True
    if isinstance(value, Marked):
        for start, end, _ in value.spans:
            match = _SIMPLE_SNMP_VALUE.fullmatch(value[start:end])
            if match is None or match.group(2).lower().endswith(_WORKER_ANCHOR_ENDS):
                return True
    elif isinstance(value, dict):
        return any(_needs_worker_before_mask(key, secrets) or _needs_worker_before_mask(child, secrets)
                   for key, child in value.items())
    elif isinstance(value, list):
        return any(_needs_worker_before_mask(child, secrets) for child in value)
    return False

def _snmp_response(value, secrets, *, helper=False):
    # Context is captured before legacy rules can consume quotes or block headers.
    # Track only actual credential ranges through their unchanged legacy chain.
    from netops_helper.proxy_sanitize import _contains_snmp
    original = _mark_snmp(value) if _contains_snmp(value) else value
    if not helper:
        from netops_helper.proxy_sanitize import _sanitize_object
        cleaned = _sanitize_object(original, secrets, typed=False)
        if (isinstance(original, Marked) and original.spans and cleaned == original
                and not _needs_worker_before_mask(cleaned, secrets)):
            return _mask_snmp(cleaned)
    settled = _settle_response(original, secrets, helper=helper)
    for _ in range(8):
        cleaned = _mask_snmp(settled)
        if cleaned == settled:
            return cleaned
        # Legacy matches can remove a CR/newline and extend a community's
        # remaining line. Recheck only after a change, after preserving its floor.
        settled = _mark_snmp(_settle_response(cleaned, secrets, helper=helper))
    raise ValueError('redaction could not be verified; output withheld')

def redact_response(text: str, secrets: Iterable[str] = ()) -> str:
    """Capture original SNMP ranges and preserve the complete legacy secrecy floor.

    Preserve the raw-input floor before cleaning terminal controls; repeat the
    complete chain on the cleaned text so controls cannot disguise a label.
    """
    secrets = tuple(secrets)
    text = _snmp_response(text, secrets, helper=True)
    cleaned = strip_terminal_controls(text)
    return _snmp_response(cleaned, secrets, helper=True) if cleaned != text else text
