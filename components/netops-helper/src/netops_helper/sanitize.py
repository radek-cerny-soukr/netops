"""Secret redaction for MCP responses and persistent audit metadata."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable
from netops.redaction_spans import Marked, edits, sub, replace, mask, loads, dumps


_SECRET_LABELS = (
    r"(?:api|access)[_ -]?token|bearer|token|api[_ -]?key|password|passwd|secret|community"
)
# Escape-aware quoted values; an unclosed quote redacts to the end of the line.
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


# CSI and bounded, terminated ANSI strings on one line, then single ESC
# controls. An unfinished/overlong string loses only its ESC introducer.
ANSI_STRING_LIMIT = 4096
ANSI_CONTROL = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]"
    rf"|\][^\x07\x1b\r\n]{{0,{ANSI_STRING_LIMIT}}}(?:\x07|\x1b\\)"
    rf"|[PX^_][^\x1b\r\n]{{0,{ANSI_STRING_LIMIT}}}\x1b\\"
    r"|[ -/]*[0-~])"
)
C0_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f]")


def strip_terminal_controls(value: str) -> str:
    """Drop terminal escape sequences and C0 controls except newline and tab."""
    return sub(C0_CONTROL, "", sub(ANSI_CONTROL, "", value))



# FortiOS/FortiADC's SNMP `name` is the v1/v2c credential, not an object label.
_SNMP_CONTEXTS = {('system snmp community',), ('switch-controller snmp-community',),
    ('switch-controller managed-switch', 'snmp-community'), ('wireless-controller snmp', 'community')}
_SNMP_PREFIX = r'[ \t]*(?:\x1b\[[0-?]*[ -/]*[@-~][ \t]*)*'
_SET_COMMUNITY = re.compile(r'(?im)^(' + _SNMP_PREFIX + r'set[ \t]+community[ \t]+)[^\r\n]+')
_SNMP_VALUE = re.compile(r"(?:\"(?:\\[\s\S]|[^\"\\])*(?:\"|\Z)|'(?:[^'])*(?:'|\Z)|[^\r\n]*)[^\r\n]*")
_SNMP_LINE = re.compile(r'(?im)^(' + _SNMP_PREFIX + r')(config[ \t]+[^\r\n]+|end[ \t]*|set[ \t]+name[ \t]+)')
_CREDENTIAL_MARKER = re.compile(r'<REDACTED:credential#[1-9][0-9]*>')
_EXOS_COMMUNITY = re.compile(r'(?im)^(' + _SNMP_PREFIX + r'configure[ \t]+(?:snmp[ \t]+(?:add|delete)[ \t]+community[ \t]+(?:readonly|readwrite|<REDACTED>|\[REDACTED\])|snmpv3[ \t]+(?:add|delete)[ \t]+community)[ \t]+)[^\r\n]+')


def _snmp_spans(value):
    stack, spans, cursor = [], [], 0
    # A same-length view gives CR line starts the fast multiline anchor while
    # every captured position still indexes the untouched original string.
    lines = value.replace("\r", "\n")
    for match in _SNMP_LINE.finditer(lines):
        if match.start() < cursor:
            continue
        command = match.group(2).lower()
        if command.startswith('config'):
            stack.append(' '.join(command.split()[1:]))
        elif command.strip() == 'end':
            if stack:
                stack.pop()
        elif any(tuple(stack[-len(context):]) == context for context in _SNMP_CONTEXTS):
            found = _SNMP_VALUE.match(value, match.end())
            if found is not None:
                cursor = found.end()
                if not _CREDENTIAL_MARKER.fullmatch(found.group().strip()) and found.group().strip() != '<REDACTED>':
                    spans.append((match.end(), found.end(), None))
    for match in _EXOS_COMMUNITY.finditer(lines):
        credential = match.group()[len(match.group(1)):].strip()
        if credential != '<REDACTED>' and not _CREDENTIAL_MARKER.fullmatch(credential):
            spans.append((match.end(1), match.end(), 'community'))
    for match in _SET_COMMUNITY.finditer(lines):
        credential = match.group()[len(match.group(1)):].strip()
        if credential != '<REDACTED>' and not _CREDENTIAL_MARKER.fullmatch(credential):
            spans.append((match.end(1), match.end(), 'community'))
    return spans


def _mark_snmp(value):
    if isinstance(value, str):
        if value.lstrip()[:1] in ('{', '['):
            try:
                from .proxy_sanitize import _unique_pairs
                decoded = loads(value, object_pairs_hook=_unique_pairs)
            except (ValueError, RecursionError):
                decoded = None
            if isinstance(decoded, (dict, list)):
                # Keep the original serialization: only translate string-token ranges.
                from netops.redaction_spans import _JSON_STRING, _boundaries
                spans = []
                for token in _JSON_STRING.finditer(value):
                    child = _mark_snmp(loads(token.group()))
                    if isinstance(child, Marked):
                        bounds = _boundaries(token.group())
                        spans.extend((token.start() + bounds[a], token.start() + bounds[b], kind)
                                     for a, b, kind in child.spans)
                return Marked(value, spans) if spans else value
        spans = _snmp_spans(value)
        return Marked(value, spans) if spans else value
    if isinstance(value, dict):
        return {_mark_snmp(key): _mark_snmp(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_mark_snmp(child) for child in value]
    return value


def _mask_snmp(value):
    if isinstance(value, str):
        return mask(value)
    if isinstance(value, dict):
        return {_mask_snmp(key): _mask_snmp(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_mask_snmp(child) for child in value]
    return value


def redact_snmp_credentials(value: str) -> str:
    return _mask_snmp(_mark_snmp(value))


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


def redact(text: object, secrets: Iterable[str] = (), limit: int | None = None) -> str:
    """Redact credentials; control-bearing diagnostics need the complete chain."""
    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    value = str(text)
    from .proxy_sanitize import _contains_snmp
    if C0_CONTROL.search(value) or _contains_snmp(value):
        value = redact_response(value, normalized)
    else:
        value = _redact_credentials(value, normalized)
    if limit is not None and len(value) > limit:
        raise ValueError("redacted output exceeds the explicit limit")
    return value


def _settle_response(value, secrets, *, helper=False):
    """Run the pre-SNMP layers to a fixed point on the same document."""
    from netops.redaction import redact as product_redact
    from .proxy_sanitize import _sanitize_object

    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    for _ in range(8):
        original = _redact_credentials(value, normalized) if helper else value
        cleaned = product_redact(_sanitize_object(original, secrets), secrets)[0]
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
    from .proxy_sanitize import _contains_snmp
    original = _mark_snmp(value) if _contains_snmp(value) else value
    if not helper:
        from .proxy_sanitize import _sanitize_object
        cleaned = _sanitize_object(original, secrets)
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


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
