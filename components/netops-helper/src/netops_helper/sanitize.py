"""Secret redaction for MCP responses and persistent audit metadata."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Iterable
import bisect
from netops.redaction_spans import Marked, mask, dumps
from netops import redaction_spans as _spans


# Span operations of the response chain (task 165-r4). The same results as the
# generic ``netops.redaction_spans`` operations for credential ranges, in one
# windowed pass over the ranges, plus tracked kinds (``Track``). The proxy uses
# them too; the product layer gets them in ``_tracked_product``.
class Track:
    """Span kind that only follows characters.

    A tracked range never makes inserted text a credential: a replacement that
    consumes it gets a range of ``derived()`` (no range for None) instead of the
    None/'community' range of the credential kinds. ``shift(delta)`` is the kind of
    a piece that starts ``delta`` characters into the range.
    """
    __slots__ = ()

    def shift(self, delta):
        return self

    def derived(self):
        return None


def _touching(spans):
    """Indexes of ``spans`` meeting each window, for windows whose starts and ends
    never decrease, in the order of ``spans``; every range enters and leaves once."""
    order = sorted(range(len(spans)), key=lambda index: spans[index][0])
    active, following = [], 0

    def touching(start, end):
        nonlocal active, following
        while following < len(order) and spans[order[following]][0] < end:
            active.append(order[following])
            following += 1
        active = [index for index in active if spans[index][1] > start]
        return sorted(active) if len(active) > 1 else active

    return touching


def edits(value, changes):
    """``redaction_spans.edits`` in one pass over the ranges, with tracked kinds."""
    if not isinstance(value, Marked):
        return _spans.edits(value, changes)
    source = value.spans
    touching = _touching(source)
    parts, spans, cursor, offset = [], [], 0, 0

    def copy(start, end):
        nonlocal offset
        parts.append(value[start:end])
        for index in touching(start, end):
            left, right, kind = source[index]
            a, b = max(start, left), min(end, right)
            if a < b:
                spans.append((offset + a - start, offset + b - start,
                              kind.shift(a - left) if isinstance(kind, Track) else kind))
        offset += end - start

    for start, end, replacement in changes:
        copy(cursor, start)
        original = value[start:end]
        prefix = 0
        while prefix < min(len(original), len(replacement)) and original[prefix] == replacement[prefix]:
            prefix += 1
        suffix = 0
        while (suffix < min(len(original), len(replacement)) - prefix
               and original[-suffix - 1] == replacement[-suffix - 1]):
            suffix += 1
        copy(start, start + prefix)
        changed = replacement[prefix:len(replacement) - suffix if suffix else len(replacement)]
        if changed:
            touched = [source[index][2] for index in touching(start, end)
                       if source[index][0] < end and source[index][1] > start]
            inherited = [kind for kind in touched if not isinstance(kind, Track)]
            if inherited:
                spans.append((offset, offset + len(changed), 'community' if 'community' in inherited else None))
            for kind in dict.fromkeys(kind.derived() for kind in touched if isinstance(kind, Track)):
                if kind is not None:
                    spans.append((offset, offset + len(changed), kind))
        parts.append(changed)
        offset += len(changed)
        copy(end - suffix, end)
        cursor = end
    copy(cursor, len(value))
    return Marked(''.join(parts), spans)


def sub(pattern, replacement, value):
    if not isinstance(value, Marked):
        return pattern.sub(replacement, value)
    return edits(value, ((m.start(), m.end(), replacement(m) if callable(replacement) else m.expand(replacement))
                         for m in pattern.finditer(value)))


def replace(value, old, new):
    if not isinstance(value, Marked):
        return value.replace(old, new)
    def changes():
        cursor = 0
        while True:
            start = value.find(old, cursor)
            if start < 0:
                break
            yield start, start + len(old), new
            cursor = start + len(old)
    return edits(value, changes())


class _UnrepresentableFloor(RuntimeError):
    """Bypass invalid-JSON fallbacks until redact_response withholds the output."""


def loads(text, **kwargs):
    """``redaction_spans.loads`` in one pass over the ranges (tokens come in document order)."""
    value = json.loads(text, **kwargs)
    if not isinstance(text, Marked):
        return value
    floor = [(start, end, kind) for start, end, kind in text.spans if isinstance(kind, _Floor)]
    if floor:
        # Only string tokens can carry spans after decoding. A floor on numbers,
        # true/false/null or punctuation would be silently discarded, including
        # in recursively decoded JSON strings. Fail closed before that happens.
        floor_touching = _touching(floor)
        cursor = 0
        for token in _spans._JSON_STRING.finditer(text):
            if any(max(cursor, floor[index][0]) < min(token.start(), floor[index][1])
                   for index in floor_touching(cursor, token.start())):
                raise _UnrepresentableFloor
            cursor = token.end()
        if any(max(cursor, floor[index][0]) < min(len(text), floor[index][1])
               for index in floor_touching(cursor, len(text))):
            raise _UnrepresentableFloor
    tokens = iter(_spans._JSON_STRING.finditer(text))
    touching = _touching(text.spans)

    def walk(item):
        if isinstance(item, str):
            token = next(tokens)
            bounds = _spans._boundaries(token.group())
            spans = []
            for index in touching(token.start() + 1, token.end() - 1):
                start, end, kind = text.spans[index]
                a, b = max(start, token.start() + 1), min(end, token.end() - 1)
                if a < b:
                    spans.append((max(0, bisect.bisect_right(bounds, a - token.start()) - 1),
                                  bisect.bisect_left(bounds, b - token.start()), kind))
            return Marked(item, spans) if spans else item
        if isinstance(item, dict):
            return {walk(key): walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        return item
    return walk(value)


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
# One credential value on its own line: quoted (escape-aware, an unclosed quote
# runs to the end of the line) or bare with backslash-escaped characters.
_LINE_CREDENTIAL = (r"(?:" + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED
                    + r"|(?:\\[^\r\n]?|[^\s\\])+)")
# 1.0.8 rule, kept unchanged; it is used only by the 1.0.8 floor (_floor_1_0_8_ranges),
# which matches any whitespace (also NBSP, Unicode spaces and a line break) between tokens.
CISCO_USER_SECRET = re.compile(
    r"(?im)^([^\S\n]*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)\S+"
)
# `username NAME [privilege N] [role ROLE] password|secret [TYPE|ALGORITHM] VALUE`.
# The numeric type or algorithm name stays visible; the whole hash/value is the secret.
# Everything the 1.0.8 rule hid stays hidden through the 1.0.8 floor in _redact_credentials.
CISCO_USER_ACCOUNT_SECRET = re.compile(
    r"(?im)^([ \t]*username[ \t]+\S+(?:[ \t]+(?:privilege[ \t]+\d+|role[ \t]+\S+))*"
    r"[ \t]+(?:password|secret)(?:[ \t]+(?:\d+|sha512|sha256|md5)(?=[ \t]))?[ \t]+)" + _LINE_CREDENTIAL
)
# Standalone global AAA shared keys only; host-scoped `key 7` stays with CISCO_TYPE7_SECRET.
AAA_SERVER_KEY = re.compile(
    r"(?im)^([ \t]*(?:tacacs|radius)-server[ \t]+key(?:[ \t]+[07](?=[ \t]))?[ \t]+)" + _LINE_CREDENTIAL
)
# EXOS local accounts with an encrypted password.
EXOS_ACCOUNT_SECRET = re.compile(
    r"(?im)^([ \t]*(?:configure[ \t]+account|create[ \t]+account[ \t]+(?:admin|user))[ \t]+\S+"
    r"[ \t]+encrypted[ \t]+)" + _LINE_CREDENTIAL
)
_ACCOUNT_SECRETS = (CISCO_USER_ACCOUNT_SECRET, AAA_SERVER_KEY, EXOS_ACCOUNT_SECRET)
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
    return edits(value, _assigned_changes(pattern, replace, value, chunk))


def _assigned_changes(pattern: re.Pattern[str], replace, value: str, chunk: int = LABEL_CHUNK) -> list:
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
    return changes


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


def _redact_1_0_8(value: str, normalized: tuple[str, ...]) -> str:
    """The released 1.0.8 (61e7de3) ``_redact_credentials``, unchanged: the same
    expressions, replacements and order. Used only to compute the 1.0.8 floor."""
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


class _Origin(Track):
    """Original offset of the first character of a range copied unchanged from the input.

    A run claims ``end - start`` consecutive original characters; an atom (one
    character before JSON decoding) claims only its own, however its decoded and
    re-encoded form is written later.
    """
    __slots__ = ("offset", "atom")

    def __init__(self, offset: int, atom: bool = False):
        self.offset, self.atom = offset, atom

    def shift(self, delta):
        return self if self.atom or not delta else _Origin(self.offset + delta)


class _Floor(Track):
    """A character the complete 1.0.8 chain hides (original), or text a replacement
    inserted over one (derived)."""
    __slots__ = ("original",)

    def __init__(self, original: bool):
        self.original = original

    def derived(self):
        return _FLOOR_DERIVED


_FLOOR, _FLOOR_DERIVED = _Floor(True), _Floor(False)


def _tracks(value) -> tuple:
    if not isinstance(value, Marked):
        return ()
    return tuple(span for span in value.spans if isinstance(span[2], Track))


def _atomize(value):
    """Split origin runs of a JSON document into atoms before it is decoded.

    JSON decoding maps each original character to its decoded character, and an
    escape changes the width, so only one-character ranges keep their offsets.
    """
    if not isinstance(value, Marked) or str.lstrip(value)[:1] not in ("{", "["):
        return value
    if not any(isinstance(kind, _Origin) and not kind.atom for _, _, kind in value.spans):
        return value
    spans = []
    for start, end, kind in value.spans:
        if isinstance(kind, _Origin) and not kind.atom:
            spans.extend((index, index + 1, _Origin(kind.offset + index - start, True))
                         for index in range(start, end))
        else:
            spans.append((start, end, kind))
    return Marked(str.__str__(value), spans)


def _hidden_ranges(value: str, chain) -> list:
    """Original (start, end) ranges that ``chain`` does not copy into its output.

    The input is one origin run; every character still claimed by an origin range
    in the result is visible, every other one is hidden (also when the result is a
    plain string, e.g. a withheld document).
    """
    plain = str.__str__(value)
    if not plain:
        return []
    result = chain(Marked(plain, [(0, len(plain), _Origin(0))]))
    claimed = sorted(
        (kind.offset, kind.offset + (1 if kind.atom else end - start))
        for start, end, kind in (result.spans if isinstance(result, Marked) else ())
        if isinstance(kind, _Origin))
    hidden, cursor = [], 0
    for start, end in claimed:
        if start > cursor:
            hidden.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(plain):
        hidden.append((cursor, len(plain)))
    return hidden


def _floor_1_0_8_ranges(value: str, normalized: tuple[str, ...]) -> list:
    """Original-input ranges the released 1.0.8 credential rules (61e7de3) hide."""
    return _hidden_ranges(value, lambda marked: _redact_1_0_8(marked, normalized))


_REDACTION_TOKEN = re.compile(
    r"<REDACTED>|<PRIVATE-KEY-REDACTED>|<REDACTED:credential#[1-9][0-9]*>|\[REDACTED\]")
_TOKEN_TEXTS = ("<REDACTED>", "<PRIVATE-KEY-REDACTED>", "<REDACTED:credential#", "[REDACTED]")


def _surviving_floor(result) -> tuple:
    """Floor groups left in ``result``, joined as mask() joins ranges.

    A group with an original character is masked whole (like the 1.0.8 token over
    it); a group of derived (inserted) text only is kept when it is just redaction
    tokens or a piece of one (e.g. the `>` left by trimming `<REDACTED:credential#9>X`).
    """
    groups = []
    floor = sorted((span for span in result.spans if isinstance(span[2], _Floor)), key=lambda span: span[:2])
    for start, end, kind in floor:
        if groups and start <= groups[-1][1]:
            groups[-1][1] = max(end, groups[-1][1])
            groups[-1][2] = groups[-1][2] or kind.original
        else:
            groups.append([start, end, kind.original])
    return tuple((start, end, "community") for start, end, original in groups
                 if original or not _inserted_only(result[start:end]))


def _inserted_only(text: str) -> bool:
    for piece in _REDACTION_TOKEN.split(text):
        piece = piece.strip(" \t\r\n\"'")
        if piece and not any(piece in token for token in _TOKEN_TEXTS):
            return False
    return True


def _mask_floor(value) -> str:
    """Mask the floor ranges left after the last layer (one pass)."""
    groups = _surviving_floor(value) if isinstance(value, Marked) else ()
    return mask(Marked(str.__str__(value), groups)) if groups else str.__str__(value)


def _redact_credentials(value: str, normalized: tuple[str, ...]) -> str:
    """Current credential rules for ``redact`` (no later layer), never weaker than 1.0.8.

    The current rules run over the original input; the characters the 1.0.8 rules
    hide on the same input follow them as floor ranges and the surviving ones are
    masked at the end, so no rule loses an anchor to an earlier mask.
    """
    floor = _floor_1_0_8_ranges(value, normalized)
    if not floor:
        return _redact_current(value, normalized)
    plain = str.__str__(value)
    return _mask_floor(_redact_current(Marked(plain, [(start, end, _FLOOR) for start, end in floor]), normalized))


def _redact_current(value: str, normalized: tuple[str, ...]) -> str:
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


_TRACKED_PRODUCT = []


def _tracked_product():
    """The product redaction (``netops.redaction``) with this module's span operations.

    A private instance of the installed module file: the same code and expressions,
    only ``edits/sub/replace/loads/dumps`` carry tracked ranges in one pass. The
    imported product module itself is not changed.
    """
    if not _TRACKED_PRODUCT:
        import importlib.util
        from netops import redaction
        spec = importlib.util.spec_from_file_location("netops_helper._tracked_redaction", redaction.__file__)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.edits, module.sub, module.replace, module.loads, module.dumps = edits, sub, replace, loads, dumps
        _TRACKED_PRODUCT.append(module.redact)
    return _TRACKED_PRODUCT[0]


def _settle_response(value, secrets, *, helper=False, credentials=None):
    """Run the pre-SNMP layers to a fixed point on the same document."""
    from netops.redaction import redact as product_redact
    from .proxy_sanitize import _sanitize_object

    credentials = credentials or _redact_current
    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    for _ in range(8):
        original = credentials(value, normalized) if helper else value
        proxied = _atomize(_sanitize_object(_atomize(original), secrets))
        product = _tracked_product() if _tracks(proxied) else product_redact
        cleaned = product(proxied, secrets)[0]
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


def _mark_tracked(value):
    """``_mark_snmp`` that keeps the tracked (floor/origin) ranges of a string."""
    tracks = _tracks(value)
    if not tracks:
        return _mark_snmp(value)
    plain = str.__str__(value)
    marked = _mark_snmp(plain)
    return Marked(plain, (marked.spans if isinstance(marked, Marked) else ()) + tracks)


def _mask_tracked(value):
    """``_mask_snmp`` that keeps the tracked ranges of a string: the same text, the
    credential ranges masked exactly as ``mask`` masks them."""
    tracks = _tracks(value)
    if not tracks:
        return _mask_snmp(value)
    plain = str.__str__(value)
    regular = [span for span in value.spans if not isinstance(span[2], Track)]
    merged = []
    for start, end, kind in sorted(regular, key=lambda span: span[:2]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]),
                          'community' if 'community' in (kind, merged[-1][2]) else None)
        else:
            merged.append((start, end, kind))
    result = edits(Marked(plain, tracks), [
        (a, b, '<REDACTED>' if kind == 'community' else '<REDACTED:credential#%d>' % index)
        for index, (a, b, kind) in enumerate(merged, 1)])
    if str.__str__(result) != mask(Marked(plain, regular)):
        raise ValueError('redaction could not be verified; output withheld')
    return result


def _snmp_response(value, secrets, *, helper=False, credentials=None):
    # Context is captured before legacy rules can consume quotes or block headers.
    # Track only actual credential ranges through their unchanged legacy chain.
    from .proxy_sanitize import _contains_snmp
    original = _mark_tracked(value) if _contains_snmp(value) else value
    if not helper:
        from .proxy_sanitize import _sanitize_object
        cleaned = _sanitize_object(original, secrets)
        if (isinstance(original, Marked) and original.spans and cleaned == original
                and not _needs_worker_before_mask(cleaned, secrets)):
            return _mask_snmp(cleaned)
    settled = _settle_response(original, secrets, helper=helper, credentials=credentials)
    for _ in range(8):
        cleaned = _mask_tracked(settled)
        if cleaned == settled:
            return cleaned
        # Legacy matches can remove a CR/newline and extend a community's
        # remaining line. Recheck only after a change, after preserving its floor.
        settled = _mark_tracked(_settle_response(cleaned, secrets, helper=helper, credentials=credentials))
    raise ValueError('redaction could not be verified; output withheld')


def _response_chain(text, secrets, credentials):
    """The complete response chain (Helper credential rules, proxy, product, SNMP mask)."""
    text = _snmp_response(text, secrets, helper=True, credentials=credentials)
    cleaned = strip_terminal_controls(text)
    return _snmp_response(cleaned, secrets, helper=True, credentials=credentials) if cleaned != text else text


def _coverage(value) -> tuple:
    """Text and joined credential ranges per kind: all that later layers read."""
    ranges = {}
    for start, end, kind in sorted(value.spans if isinstance(value, Marked) else (), key=lambda span: span[:2]):
        joined = ranges.setdefault(kind, [])
        if joined and start <= joined[-1][1]:
            joined[-1][1] = max(end, joined[-1][1])
        else:
            joined.append([start, end])
    return str.__str__(value), sorted((repr(kind), joined) for kind, joined in ranges.items())


def redact_response(text: str, secrets: Iterable[str] = ()) -> str:
    """Capture original SNMP ranges and preserve the complete legacy secrecy floor.

    Preserve the raw-input floor before cleaning terminal controls; repeat the
    complete chain on the cleaned text so controls cannot disguise a label.

    The chain runs with the current credential rules. Where the released 1.0.8 rules
    give the same text and ranges at every Helper step, the complete 1.0.8 chain
    reaches the same result. Otherwise the characters the complete 1.0.8 chain
    hides are found by original offset and masked after the last layer of the
    current chain, which itself runs unchanged (task 165-r4).
    """
    secrets = tuple(secrets)
    differs = []

    def watched(value, normalized):
        result = _redact_current(value, normalized)
        if not differs and _coverage(_redact_1_0_8(value, normalized)) != _coverage(result):
            differs.append(True)
        return result

    result = _response_chain(text, secrets, watched)
    if not differs:
        return result
    floor = _hidden_ranges(text, lambda marked: _response_chain(marked, secrets, _redact_1_0_8))
    if not floor:
        return result
    if floor == [(0, len(text))]:
        # The released chain withheld the complete input (e.g. a JSON key with
        # `set password`). Keep that decision before JSON decoding can discard
        # floor ranges on numbers, booleans, null or document punctuation.
        return dumps('[REDACTED]')
    plain = str.__str__(text)
    try:
        tracked = _response_chain(Marked(plain, [(start, end, _FLOOR) for start, end in floor]), secrets, _redact_current)
    except _UnrepresentableFloor:
        raise ValueError('redaction could not be verified; output withheld') from None
    if str.__str__(tracked) != str.__str__(result):
        raise ValueError('redaction could not be verified; output withheld')
    return _mask_floor(tracked)


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
