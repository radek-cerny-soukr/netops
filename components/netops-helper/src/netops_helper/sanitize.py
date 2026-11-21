"""Secret redaction for MCP responses and persistent audit metadata."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Iterable
import bisect
from netops.redaction_spans import Marked, mask, dumps
from netops import redaction_spans as _spans

from .normalization import EOS_UNAVAILABLE_LINE


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
    changes = [(m.start(), m.end(), replacement(m) if callable(replacement) else m.expand(replacement))
               for m in pattern.finditer(value)]
    # Without a match the text and its ranges stay as they are (no copy of every range).
    return edits(value, changes) if changes else value


def replace(value, old, new):
    if not isinstance(value, Marked):
        return value.replace(old, new)
    if old not in value:
        return value
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
# Type of a Cisco IOS/IOS XE, NX-OS or Arista EOS secret/password (task 302-r2): a numeric
# type (IOS/XE 0/5/7/8/9, NX-OS 0/5, EOS 0/5/7), an algorithm name (EOS `sha512`, IOS XE
# `algorithm-type` names `md5`/`scrypt`/`sha256`, `pbkdf2`, `sha1`), or any other word directly
# followed by a crypt hash (`$...`). It is a type only when a value follows it.
_SECRET_WORD_TYPE = r"(?:sha512|sha256|sha1|scrypt|pbkdf2|md5)(?=[ \t]+\S)|[A-Za-z][\w-]*(?=[ \t]+\$)"
_SECRET_TYPE = r"\d+(?=[ \t]+\S)|" + _SECRET_WORD_TYPE
# `username NAME [privilege N] [role ROLE] [algorithm-type ALG] password|secret [TYPE] VALUE`.
# The type stays visible; the whole hash/value is the secret.
# Everything the 1.0.8 rule hid stays hidden through the 1.0.8 floor in _redact_credentials.
CISCO_USER_ACCOUNT_SECRET = re.compile(
    r"(?im)^([ \t]*username[ \t]+\S+(?:[ \t]+(?:privilege[ \t]+\d+|role[ \t]+\S+|algorithm-type[ \t]+\S+))*"
    r"[ \t]+(?:password|secret)(?:[ \t]+(?:" + _SECRET_TYPE + r"))?[ \t]+)" + _LINE_CREDENTIAL
)
# `enable [algorithm-type ALG] secret|password [level N] [TYPE] VALUE` (IOS/IOS XE, NX-OS, EOS),
# also after a prompt (`R1(config)#enable ...`) and inside JSON string tokens (task 302-r2).
# A known type stays visible and the next token is the value. Without a known type, a first
# token followed by another one may be an unknown type word or a value followed by a keyword
# (ASA `enable password HASH encrypted`): both tokens are hidden. CISCO_ENABLE_SECRET (the
# 1.0.8 rule) still runs afterwards; the floor of the 1.0.8 chain keeps everything it hid
# hidden, also what a later rule of that chain took after an anchor in the value (task 302-r6).
CISCO_ENABLE_ACCOUNT_SECRET = re.compile(
    r"(?im)(?<![^\s#>])(enable[ \t]+(?:algorithm-type[ \t]+\S+[ \t]+)?(?:secret|password)"
    r"(?:[ \t]+level[ \t]+\d+)?(?:[ \t]+(" + _SECRET_TYPE + r"))?[ \t]+)"
    r"(?(2)|(?P<first>" + _LINE_CREDENTIAL + r"[ \t]+(?=\S))?)(?P<last>" + _LINE_CREDENTIAL + ")"
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
# NX-OS `show snmp` includes the configured communities in an unlabelled first
# column. Hide whole rows: quoted values or spaces must not leave a secret tail.
NXOS_SNMP_COMMUNITY_TABLE = re.compile(
    r"(?im)^([ \t]*Community[ \t]+(?:Group|<REDACTED>)[ \t]*/[ \t]*Access\b[^\r\n]*\r?\n)"
    r"((?:[ \t]*[^ \t\r\n][^\r\n]*(?:\r?\n|$))+)"
)
_NXOS_SNMP_PAGER_SUFFIX = re.compile(r"(?i)--More--[ \t]*(?=\r?\n?\Z)")


def _mask_nxos_community_line(line: str) -> str:
    pager = _NXOS_SNMP_PAGER_SUFFIX.search(line)
    suffix = line[pager.start():] if pager else line[len(line.rstrip('\r\n')):]
    return '<REDACTED>' + suffix


def _mask_community_rows(match):
    return match.group(1) + ''.join(
        line if re.fullmatch(r'[- \t\r\n]+', line) else _mask_nxos_community_line(line)
        for line in match.group(2).splitlines(keepends=True)
    )


# NX-OS `show snmp` / `show snmp community` (task 490): NXOS_SNMP_COMMUNITY_TABLE only knows the 9.3(12) header.
# The community block is checked first: an empty table, the role notice or that exact header (optional underline,
# rows up to the first blank line) stay with the general rules; any other shape is masked line by line (fail-closed).
NXOS_SNMP_COMMUNITY_NOTE = "[netops-helper: unrecognized SNMP community-table format; all lines redacted]"
_NXOS_SNMP_KNOWN_HEADER = re.compile(
    r"[ \t]*Community[ \t]+(?:Group|<REDACTED>)[ \t]*/[ \t]*Access[ \t]+context[ \t]+acl_filter[ \t]*\r?")
_NXOS_SNMP_ROLE_NOTICE = re.compile(
    r"[ \t]*User does not have permission to view community (?:strings\.|<REDACTED>)[ \t]*\r?")
_NXOS_SNMP_BLOCK_START = re.compile(r"[ \t]*Max packetsize:[ \t]*\d+[ \t]*\r?")
_NXOS_SNMP_SECTION_RULE = re.compile(r"_{20,}[ \t]*\r?")
_NXOS_SNMP_SECTION_HEADING = re.compile(
    r"[ \t]*(?:SNMP USERS|NOTIFICATION TARGET USERS \(configured +for sending V3 Inform\))[ \t]*\r?")
_NXOS_SNMP_COMMUNITY_WORD = re.compile(r"(?i)[ \t]*community\b")
# Device status lines stay readable in a masked block, so a refusal or a pager stop is still recognized.
_NXOS_SNMP_STATUS_LINE = re.compile(
    r"(?i)[ \t]*(?:%[ \t]*(?:Authorization failed|Authorization denied|Permission denied|Access denied)\b[^\r\n]*"
    r"|%{1,2}[ \t]*(?:Unrecognized command|Incomplete command|Ambiguous command|Invalid command|Invalid input)\b[^\r\n]*"
    r"|Syntax error while parsing\b[^\r\n]*|Cmd exec error\.|\^|--More--|---\(more(?: [0-9]+%)?\)---"
    r"|Press <SPACE> to continue[^\r\n]*)[ \t]*\r?")


def _nxos_community_block_known(lines: list[str]) -> bool:
    body = [i for i, line in enumerate(lines) if line.strip()]
    if not body:
        return True
    first = lines[body[0]]
    if len(body) == 1 and _NXOS_SNMP_ROLE_NOTICE.fullmatch(first):
        return True
    if not _NXOS_SNMP_KNOWN_HEADER.fullmatch(first):
        return False
    rows_end = next((i for i in range(body[0] + 1, len(lines)) if not lines[i].strip()), len(lines))
    return all(i < rows_end for i in body)


# NX-OS 9.3(12) with a configured community prints no table but one labelled triple per community (task 490-r3,
# live d-nxos capture): `Community name:`, `Community groupname:`, `Context mapped:`. Only the name value is masked
# here; the group and the context stay. A missing, extra, reordered or split line is not this shape.
_NXOS_SNMP_NAME = re.compile(r"(?P<label>[ \t]*Community name:[ \t]*)(?P<value>\S[^\r\n]*)(?P<cr>\r?)")
_NXOS_SNMP_LABELLED = (
    _NXOS_SNMP_NAME,
    re.compile(r"[ \t]*Community groupname:[ \t]*\S*[ \t]*\r?"),
    re.compile(r"[ \t]*Context mapped:[ \t]*\S*[ \t]*\r?"),
)


def _nxos_community_block_labelled(lines: list[str]) -> list[str] | None:
    """The block with every community name value masked when it holds only blank lines and complete labelled
    triples (at least one); None for any other shape."""
    masked, expected = [], 0
    for line in lines:
        if not line.strip():
            if expected:
                return None
            masked.append(line)
            continue
        match = _NXOS_SNMP_LABELLED[expected].fullmatch(line)
        if not match:
            return None
        masked.append(match["label"] + "<REDACTED>" + match["cr"] if expected == 0 else line)
        expected = (expected + 1) % len(_NXOS_SNMP_LABELLED)
    return masked if not expected and any(line.strip() for line in lines) else None


_NXOS_SNMP_VALUE_LINE = re.compile(r"(?P<label>[ \t]*(?:Community groupname|Context mapped):[ \t]*)(?P<value>[^\r\n]*)")


def redact_short_nxos_community_values(text: str, secrets: Iterable[str]) -> str:
    """Mask community names below the general redaction floor (1-2 bytes, e.g. `ro`) without touching other text.

    The value of every `Community name:` line is masked; on the `Community groupname:` and `Context mapped:` lines
    only a whole whitespace-delimited token equal to the community is replaced, never part of another word."""
    short = {value for value in secrets if value}
    if not short:
        return text
    out = []
    for line in text.split("\n"):
        name = _NXOS_SNMP_NAME.fullmatch(line)
        if name and name["value"].rstrip(" \t") in short:
            line = name["label"] + "<REDACTED>" + name["cr"]
        else:
            other = _NXOS_SNMP_VALUE_LINE.fullmatch(line.rstrip("\r"))
            if other and short.intersection(other["value"].split()):
                value = re.sub(r"[^ \t]+", lambda token: "<REDACTED>" if token[0] in short else token[0], other["value"])
                line = other["label"] + value + line[len(line.rstrip("\r")):]
        out.append(line)
    return "\n".join(out)


def redact_nxos_snmp_communities(text: str, *, community_secrets: set[str] | None = None) -> tuple[str, bool]:
    """Fail-closed community block of NX-OS `show snmp` (after `Max packetsize:`, up to the next known section) or of
    `show snmp community` (no `Max packetsize:` line: the whole output). Returns (text, masked): a known table shape
    is returned unchanged and the labelled 9.3(12) shape with only its community name values masked, both with
    masked False; otherwise every non-blank line of the block except device status lines (refusal, syntax error,
    pager) becomes <REDACTED> behind one note line (masked True), and a `Community…` line outside the block makes
    the whole output the block. A block of status lines only (a refusal) is returned unchanged.
    If supplied, community_secrets collects labelled names from the entire output for general redaction."""
    lines = text.split("\n")
    if community_secrets is not None:
        for line in lines:
            match = _NXOS_SNMP_NAME.fullmatch(line)
            if match:
                community_secrets.add(match["value"].rstrip(" \t"))
    start = next((i + 1 for i, line in enumerate(lines) if _NXOS_SNMP_BLOCK_START.fullmatch(line)), None)
    if start is None:
        begin, end = 0, len(lines)
    else:
        begin = start
        # A table underline can look identical to the rule framing a section heading.
        end = next((i - 1 for i in range(start + 1, len(lines) - 1)
                    if _NXOS_SNMP_SECTION_HEADING.fullmatch(lines[i])
                    and _NXOS_SNMP_SECTION_RULE.fullmatch(lines[i - 1])
                    and _NXOS_SNMP_SECTION_RULE.fullmatch(lines[i + 1])), len(lines))
        if any(_NXOS_SNMP_COMMUNITY_WORD.match(line) for line in lines[:begin] + lines[end:]):
            begin, end = 0, len(lines)
    if _nxos_community_block_known(lines[begin:end]):
        return text, False
    labelled = _nxos_community_block_labelled(lines[begin:end])
    if labelled is not None:
        return "\n".join(lines[:begin] + labelled + lines[end:]), False
    masked = [line if not line.strip() or _NXOS_SNMP_STATUS_LINE.fullmatch(line)
              else _mask_nxos_community_line(line) for line in lines[begin:end]]
    if masked == lines[begin:end]:
        return text, False
    return "\n".join(lines[:begin] + [NXOS_SNMP_COMMUNITY_NOTE] + masked + lines[end:]), True

# G95 publishes only recognized operational fields. SNMP's credentials can
# appear outside the community table, including in user and notification rows.
_NX_G95_NAME = r"[A-Za-z0-9_.@+-]+"
_NX_G95_IPS = r"[0-9A-Fa-f:.]+(?:[ ,]+[0-9A-Fa-f:.]+)*"
_NX_G95_DATE = r"[0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]{1,6} [A-Z][a-z]{2} +[0-9]{1,2} [0-9]{4}"
_NX_G95_AAA_GROUP = rf"(?:local|none|group {_NX_G95_NAME})"
_NX_G95_AAA_COUNTER = (
    r"(?:failed transactions|sucessfull transactions|successful transactions|requests sent|"
    r"requests timed out|responses with no matching requests|responses not processed|"
    r"responses containing errors)"
)
_NX_G95_USERS_HEADER = r"NAME +LINE +TIME +IDLE +PID +COMMENT"
_NX_G95_USER_DATE = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2}"
_NX_G95_SESSION_HEADER = r"Name +Session Owner +Creation Time"
_NX_G95_SESSION_ROW = rf"{_NX_G95_NAME} +{_NX_G95_NAME} +{_NX_G95_DATE}"
_NX_G95_SESSION_COUNT = re.compile(r"Number of active configuration sessions = ([0-9]{1,10})")
_NX_G95_HOST_ROW = re.compile(rf"{_NX_G95_NAME}[ \t]+({_NX_G95_IPS})")
_NX_G95_DNS_HEADER = r"Host[ \t]+Address"
_NX_G95_DNS_VRF_HEADER = r"Vrf +Use-vrf +Token +Config"
_NX_G95_DNS_VRF_SERVER = re.compile(rf"{_NX_G95_NAME} +{_NX_G95_NAME} +name-server\(s\) +({_NX_G95_IPS})")
_NX_G95_SNMP_COUNTER = (
    r"[0-9]+ (?:SNMP packets (?:input|output)|Bad SNMP versions|"
    r"Encoding errors|Number of (?:requested|altered) variables|"
    r"(?:Get-request|Get-next|Set-request) PDUs|No such name PDU|Bad value PDU|Read Only PDU|"
    r"General errors|Get Responses|Unknown Context name|Access policy violation|Trap PDU|"
    r"Too big errors \(Maximum packet size [0-9]+\)|No such name errors|Bad values errors|"
    r"Get Requests|Get Next Requests|Set Requests|Silent drops)"
)
_NX_G95_AAA_STATS = (
    r"Server is not monitored",
    r"(?:Authentication|Accounting|Authorization) Statistics",
    rf"{_NX_G95_AAA_COUNTER}: [0-9]+",
)
_NX_G95_LINES = {
    "dns_hosts": (
        r"DNS lookup (?:enabled|disabled)",
        r"Name/address lookup (?:uses|does not use) domain service",
        rf"Name servers are +{_NX_G95_IPS}",
        rf"Vrf Name: {_NX_G95_NAME} +Default domain is {_NX_G95_NAME}",
        rf"(?:Default domain name|Domain names|Domain name servers) (?:is|are) {_NX_G95_NAME}",
        _NX_G95_DNS_HEADER,
    ),
    "snmp_statistics": (
        _NX_G95_SNMP_COUNTER,
        r"Max packetsize: [0-9]+",
        r"SNMP Tcp Authentication Flag *: (?:Enabled|Disabled)\.",
        r"SNMP protocol *: (?:Enabled|Disabled)",
    ),
    "snmp_engine_id": (
        r"Local SNMP engineID: \[Hex\] [0-9A-Fa-f]{10,64}",
        r"\[Dec\] [0-9]{1,3}(?::[0-9]{1,3}){4,31}",
    ),
    "aaa_authentication": (
        rf"(?:default|console|iscsi|dhchap): {_NX_G95_AAA_GROUP}(?: (?:local|none))*",
    ),
    "radius_statistics": _NX_G95_AAA_STATS,
    "tacacs_statistics": _NX_G95_AAA_STATS,
    "users": (
        _NX_G95_USERS_HEADER,
        rf"{_NX_G95_NAME} +(?:pts/[0-9]+|tty[0-9]+) +{_NX_G95_USER_DATE} +[0-9]{{2}}:[0-9]{{2}}"
        r" +(?:\.|old|[0-9:]+) +[0-9]+(?: +\([0-9a-fA-F:.]+\))?",
    ),
    "ssh_server": (r"ssh version [0-9]+ is (?:enabled|disabled)",),
    "configuration_sessions": (
        r"Session Manager Database:", r"-{20,}", _NX_G95_SESSION_HEADER, _NX_G95_SESSION_ROW,
        r"There are no active configuration sessions", _NX_G95_SESSION_COUNT.pattern,
    ),
}
_NX_G95_LINE = {query: re.compile("|".join(patterns)) for query, patterns in _NX_G95_LINES.items()}
_NX_G95_REQUIRED = {
    "dns_hosts": (r"DNS lookup (?:enabled|disabled)", _NX_G95_DNS_HEADER),
    "snmp_statistics": (r"[0-9]+ SNMP packets input", r"[0-9]+ SNMP packets output",
                        r"Max packetsize: [0-9]+", r"[0-9]+ Trap PDU", r"[0-9]+ Silent drops",
                        r"SNMP protocol *: (?:Enabled|Disabled)"),
    "snmp_engine_id": _NX_G95_LINES["snmp_engine_id"],
    "aaa_authentication": (r"default: .*", r"console: .*"),
    "radius_statistics": (r"Authentication Statistics", r"Accounting Statistics"),
    "tacacs_statistics": (r"Authentication Statistics", r"Authorization Statistics", r"Accounting Statistics"),
    "users": (_NX_G95_USERS_HEADER,),
    "ssh_server": _NX_G95_LINES["ssh_server"],
    "configuration_sessions": (r"Session Manager Database:", _NX_G95_SESSION_HEADER),
}
# Recognize raw and previously redacted copies of these two static counter labels.
_NX_G95_SNMP_COUNTER_NAME = re.compile(
    r"([0-9]+ (?:Unknown community|Illegal operation for community)) (?:name|<REDACTED>|\[redacted\])( supplied)?"
)
_NX_G95_PAGER = re.compile(r"(?i)(--More--|---\(more(?: [0-9]+%)?\)---|Press <SPACE> to continue)[^\n]*$")
_NX_G95_SYNTAX = re.compile(r"Syntax error while parsing '[^'\n]*'")


def _nxos_dns_addresses(value: str) -> bool:
    try:
        for address in re.split(r"[ ,]+", value):
            ipaddress.ip_address(address)
    except ValueError:
        return False
    return True


def nxos_management_output(query: str, output: str) -> tuple[str, bool]:
    """Return only recognized management fields and whether their capture is complete."""
    accepted = _NX_G95_LINE[query]
    fields = []
    complete = True
    in_snmp_config = False
    past_snmp_protocol = False
    in_dns_cache = False
    in_dns_vrf_table = False
    has_dns_vrf_server = False
    for line in strip_terminal_controls(output).split("\n"):
        value = line.strip()
        if not value:
            continue
        pager = _NX_G95_PAGER.search(value)
        if pager:
            fields.append("[redacted]" + pager[1])
            complete = False
        elif _NX_G95_SYNTAX.fullmatch(value):
            fields.append("Syntax error while parsing '[redacted]'")
        elif value in {"% Permission denied for the role", "Cmd exec error.", "RADIUS server not found"}:
            fields.append(value)
        elif query == "snmp_statistics" and value.startswith("SNMP Tcp Authentication Flag"):
            in_snmp_config = False
            if accepted.fullmatch(value):
                fields.append(value)
            else:
                fields.append("[redacted]")
                complete = False
        elif in_snmp_config or past_snmp_protocol:
            continue
        elif query == "snmp_statistics" and value.startswith(("sys contact:", "sys location:")):
            continue
        elif query == "snmp_statistics" and (counter := _NX_G95_SNMP_COUNTER_NAME.fullmatch(value)):
            # Use the same spelling as IOS management output so subsequent
            # generic credential redaction leaves the static label readable.
            fields.append(counter[1] + "-name" + (counter[2] or ""))
        elif query == "dns_hosts" and value.startswith("Name servers are ") and not _nxos_dns_addresses(
            value.removeprefix("Name servers are ").strip()
        ):
            fields.append("[redacted]")
            complete = False
        elif query == "dns_hosts" and in_dns_cache and (host := _NX_G95_HOST_ROW.fullmatch(value)):
            if _nxos_dns_addresses(host[1]):
                fields.append(value)
            else:
                fields.append("[redacted]")
                complete = False
        elif query == "dns_hosts" and re.fullmatch(_NX_G95_DNS_VRF_HEADER, value):
            fields.append(value)
            in_dns_vrf_table = True
        elif in_dns_vrf_table and (server := _NX_G95_DNS_VRF_SERVER.fullmatch(value)):
            has_dns_vrf_server = _nxos_dns_addresses(server[1])
            fields.append(value if has_dns_vrf_server else "[redacted]")
            complete = complete and has_dns_vrf_server
        elif in_dns_vrf_table and has_dns_vrf_server and line.startswith(" ") and _nxos_dns_addresses(value):
            fields.append(line.rstrip())
        elif accepted.fullmatch(value):
            fields.append(value)
            if query == "dns_hosts" and re.fullmatch(_NX_G95_DNS_HEADER, value):
                in_dns_cache = True
                in_dns_vrf_table = False
            if query == "snmp_statistics":
                if value.startswith("Max packetsize:"):
                    fields.append("[redacted]")
                    in_snmp_config = True
                past_snmp_protocol = value.startswith("SNMP protocol")
        else:
            fields.append("[redacted]")
            complete = False
    complete = complete and all(any(re.fullmatch(pattern, value) for value in fields)
                                for pattern in _NX_G95_REQUIRED[query])
    if query in ("radius_statistics", "tacacs_statistics") and complete:
        counters = re.split(r"(?:Authentication|Accounting|Authorization) Statistics\n", "\n".join(fields))[1:]
        complete = len(counters) == len(_NX_G95_REQUIRED[query]) and all(
            len(set(re.findall(rf"(?m)^({_NX_G95_AAA_COUNTER}): [0-9]+$", section))) == 7
            for section in counters
        )
    if query == "configuration_sessions":
        rows = sum(bool(re.fullmatch(_NX_G95_SESSION_ROW, field)) for field in fields)
        counts = [int(match[1]) for field in fields if (match := _NX_G95_SESSION_COUNT.fullmatch(field))]
        complete = complete and (counts == [rows] or (
            not rows and not counts and "There are no active configuration sessions" in fields))
    return "\n".join(fields) + ("\n" if fields else ""), complete


_ACCOUNT_SECRETS = (CISCO_USER_ACCOUNT_SECRET, CISCO_ENABLE_ACCOUNT_SECRET, AAA_SERVER_KEY, EXOS_ACCOUNT_SECRET, NXOS_SNMP_COMMUNITY_TABLE)
_ACCOUNT_REPLACE = {NXOS_SNMP_COMMUNITY_TABLE: _mask_community_rows, CISCO_ENABLE_ACCOUNT_SECRET: lambda match: _replace_enable(match)}
_ACCOUNT_HINT = re.compile(r"(?i)username|enable|(?:tacacs|radius)-server|account|community|\\u")
SNMP_CLI_SECRET = re.compile(
    r"(?im)^([^\S\n]*(?:snmp-server\s+community|set\s+community)\s+)(?:" + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED + r"|\S+)"
)
SNMP_STATUS_SECRET = re.compile(
    r"(?i)(\bSNMP\s+community\s+string\s+(?:configured|is)\s*[:=]\s*)\S+"
)
# Labels occasionally returned by management diagnostics; mask their complete value
# before the legacy community rule can consume just the word "name".
CISCO_MANAGEMENT_SECRET = re.compile(
    r"(?im)^([ \t]*(?:(?:SNMP[ \t]+)?community[ \t]+(?:name|string)|"
    r"(?:shared|encryption)[ \t]+(?:key|secret))[ \t]*[:=][ \t]*)[^\r\n]+"
)
# IOS / IOS XE management reads can include unexpected credential sections.
# Admit complete operational rows only. In particular, a missing table header
# must never turn a community, SNMPv3 key or shared secret into printable text.
_IOS_MGMT_ADDR = r"(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-f0-9]*:[a-f0-9:.]+)"
_IOS_MGMT_NAME = r"[a-z0-9_][a-z0-9_.@-]*"
_IOS_MGMT_DNS = r"[a-z0-9_][a-z0-9_.-]*"
_IOS_MGMT_HEX_ID = r"[a-f0-9]{10,64}"
_IOS_MGMT_REMOTE_HEADER = r"Remote Engine ID +IP-addr +Port"
_IOS_MGMT_REMOTE_ROW = rf"{_IOS_MGMT_HEX_ID} +(?:remote +)?{_IOS_MGMT_ADDR} +\d+"
_IOS_MGMT_TIME = r"(?:\d+(?:[wdhms]\d*)*|\d+:\d+(?::\d+)?)"
_IOS_RADIUS_COUNTER = (
    r"(?:(?:Maximum|Current) (?:inQ|waitQ|doneQ) length|Total responses seen|Packets (?:with|without) responses|"
    r"Access (?:Rejects|Accepts)|(?:Average|Maximum) response delay\(ms\)|Number of Radius timeouts|"
    r"Radius Timers (?:Started|Created|Create Failed|Stopped|Stop Failed|Outstanding|Added|Add Failed|Jitterred|Jitter Failed)|"
    r"Duplicate ID detects|Buffer Allocation Failures|Maximum Buffer Size \(bytes\)|"
    r"Malformed Responses|Bad Authenticators|Unknown Responses|<= 2ms|\d+-\d+m(?:s)?|>100ms)"
    r" *: +(?:NA|\d+)(?: +(?:NA|\d+)){0,2}"
)
_IOS_MGMT_ROWS = {
    "aaa_servers": (
        rf"(?:RADIUS|TACACS\+?): id \d+, priority \d+, host {_IOS_MGMT_ADDR}"
        rf"(?:, auth-port \d+, acct-port \d+|, port \d+)(?:, hostname {_IOS_MGMT_DNS})?",
        r"(?:State|Platform State from (?:SMD|WNCD \(\d+\)))[ ]*: current (?:UP|DOWN|DEAD|UNKNOWN)"
        r"(?:, duration \d+s, previous duration \d+s)?",
        r"(?:(?:SMD )?Platform )?Dead: total time \d+s, count \d+",
        r"Quarantined: (?:Yes|No)",
        r"(?:Authen|Author|Acct): request \d+, timeouts \d+, failover \d+, retransmission \d+",
    ),
    "radius_statistics": (
        r"Auth\. +Acct\. +Both", _IOS_RADIUS_COUNTER,
        r"Source Port Range: \(\d+ ports? only\)", r"\d+ +- +\d+",
        r"Last used Source Port/Identifier:", r"\d+/\d+",
        rf"Elapsed time since counters last cleared: {_IOS_MGMT_TIME}", r"Radius Latency Distribution:",
    ),
    "tacacs_statistics": (
        rf"Tacacs\+ Server(?: +- +(?:private|public))? *: +{_IOS_MGMT_ADDR}(?:/\d+)?",
        r"(?:Socket (?:opens|closes|aborts|errors|timeouts)|Failed Connect Attempts|"
        r"Total Packets (?:Sent|Recv)|Expected Replies) *: +\d+",
        r"No current connection",
    ),
    "snmp_statistics": (
        r"Chassis: [a-z0-9-]+", r"\d+ SNMP packets (?:input|output)",
        r"\d+ (?:Bad SNMP version errors|Unknown community name|Illegal operation for community name supplied|"
        r"Encoding errors|Number of (?:requested|altered) variables|(?:Get-(?:request|next|bulk)|Set-request|"
        r"Inform-request|Inform response|Response|Trap) PDUs|Timeouts|Drops|Responses with errors|"
        r"Too big errors(?: \(Maximum packet size \d+\))?|No such name errors|Bad values errors|General errors)",
        r"SNMP (?:logging|informs): (?:enabled|disabled)",
        r"SNMP Manager-role (?:input|output) packets",
        r"Informs in flight \d+/\d+ \(current/max\)",
        rf"Logging to {_IOS_MGMT_ADDR}(?:\.\d+)?(?:, \d+/\d+, \d+ sent, \d+ dropped\.)?",
        r"\d+ sent, \d+ in-flight, \d+ retries, \d+ failed, \d+ dropped",
        rf"Destination: {_IOS_MGMT_ADDR}(?:\.\d+)?",
    ),
    "snmp_engine_id": (
        rf"Local SNMP engineID: {_IOS_MGMT_HEX_ID}", _IOS_MGMT_REMOTE_HEADER,
    ),
    "dns_hosts": (
        rf"(?:Name lookup view:|Default domain is) {_IOS_MGMT_DNS}",
        r"(?:Default domain is not set|Name/address lookup uses (?:static mappings|domain service))",
        rf"Name servers are {_IOS_MGMT_ADDR}(?:[, ]+{_IOS_MGMT_ADDR})*",
        r"Codes: UN - unknown, EX - expired, OK - OK, \?\? - revalidate",
        rf"Domain list: {_IOS_MGMT_DNS}(?:, +{_IOS_MGMT_DNS})*",
        r"temp - temporary, perm - permanent", r"NA - Not Applicable None - Not defined",
        r"Host +(?:Port +)?Flags? +Age +Type +Address\(es\)",
        r"NAME +TTL +CLASS +TYPE +DATA/ADDRESS", r"-{5,}",
        rf"{_IOS_MGMT_DNS} +(?:(?:None|NA|\d+) +)?\((?:temp|perm), +(?:OK|EX|\?\?|UN)\)"
        rf" +(?:NA|\d+) +(?:IP|IPv6) +{_IOS_MGMT_ADDR}(?: +{_IOS_MGMT_ADDR})*",
        rf"{_IOS_MGMT_DNS} +\d+ +IN +(?:(?:A|AAAA) +{_IOS_MGMT_ADDR}|(?:CNAME|NS|PTR) +{_IOS_MGMT_DNS})",
        rf"{_IOS_MGMT_ADDR}(?: +{_IOS_MGMT_ADDR})*",
    ),
    "users": (
        r"Line +User +Host\(s\) +Idle +Location", r"Interface +User +Mode +Idle +Peer Address",
        rf"\*? *\d+ +(?:con|aux|vty|tty) +\d+ +(?:{_IOS_MGMT_NAME} +)?"
        rf"(?:idle|Virtual-Access\d+) +{_IOS_MGMT_TIME}(?: +(?:{_IOS_MGMT_ADDR}|{_IOS_MGMT_DNS}))?",
    ),
    "ssh_sessions": (
        r"Connection +Version +(?>Mode +)?Encryption +Hmac\s+State\s+Username",
        r"%?\s*No SSH(?:v[12])? server connections(?: running)?\.?",
        rf"\d+ +[12]\.\d +(?:(?:IN|OUT) +)?"
        r"(?:aes(?:128|192|256)-(?:cbc|ctr|gcm(?:@(?:openssh\.com|o))?)|3des(?:-cbc)?|chacha20-pol(?:y1305@openssh\.com)?|none)"
        r"(?: *(?:hmac-(?:sha1(?:-96)?|sha2-(?:256|512)|md5(?:-96)?)(?:-etm@openssh\.com)?|none))?"
        rf" +Session (?:started|closed)(?: +{_IOS_MGMT_NAME})?",
    ),
    "lines": (
        r"Tty +Typ +Tx/Rx +A +Modem +Roty +AccO +AccI +Uses +Noise +Overruns +Int",
        r"\*? *\d+ +(?:CTY|AUX|VTY|TTY) +(?:\d+/\d+ +)?(?:[-0-9]+ +){5}\d+ +\d+ +\d+/\d+ +[-0-9]+",
        r"Line\(s\) not in async mode -or- with no hardware support:", r"\d+(?:-\d+)?(?: *, *\d+(?:-\d+)?)*",
    ),
}
_IOS_MGMT_PATTERNS = {query: re.compile("|".join(f"(?:{row})" for row in rows), re.I)
                      for query, rows in _IOS_MGMT_ROWS.items()}
_IOS_MGMT_PAGER = re.compile(r"--[ ]*More[ ]*--|\(q(?:uit)?\s+to\s+abort\)", re.I)
_IOS_MGMT_HIDDEN = "[redacted]"
_IOS_MGMT_REFUSAL = re.compile(
    r"(?:%\s*(?:Invalid input detected|Incomplete command|Ambiguous command|Invalid command|"
    r"Authorization (?:failed|denied)|Permission denied|Access denied)|"
    r"Command authorization failed|Line has invalid autocommand)\b", re.I
)
_IOS_MGMT_REQUIRED = {
    "aaa_servers": (r"^(?:RADIUS|TACACS\+?): id", r"^ *State: current"),
    "radius_statistics": (r"^ *Auth\. +Acct\. +Both", r"^ *Total responses seen:", r"^ *Current doneQ length:"),
    "tacacs_statistics": (r"^Tacacs\+ Server", r"^ *Total Packets Recv:"),
    "snmp_statistics": (r"^ *\d+ SNMP packets input", r"^ *\d+ SNMP packets output", r"^ *\d+ Trap PDUs"),
    "snmp_engine_id": (r"^Local SNMP engineID:",),
    "dns_hosts": (r"^(?:Default domain is|Name servers are)", r"^(?:Host +(?:Port +)?Flags?|NAME +TTL)"),
    "users": (r"^ *Line +User +Host", r"^ *\*? *\d+ +(?:con|aux|vty|tty)"),
    "ssh_sessions": (r"^(?:Connection +Version|%? *No SSH)", r"^(?: *\d+ +[12]\.\d|%? *No SSH)"),
    "lines": (r"^ *Tty +Typ", r"^\s*\*? *\d+ +(?:CTY|VTY|TTY)"),
}


def redact_ios_management(query: str, output: str, *, classic_ios=False) -> tuple[str, bool]:
    """Return the safe CLI projection and whether its operational shape is complete."""
    rows = _IOS_MGMT_PATTERNS[query]
    safe = []
    incomplete = False
    remote_engines = False
    # Stop at a device pager. Neither its suffix nor wrapped text can reach a page.
    body = strip_terminal_controls(output.replace("\r\n", "\n"))
    pager = _IOS_MGMT_PAGER.search(body)
    if pager:
        body = body[:pager.start()]
    for line in body.splitlines(keepends=True):
        row = line.strip()
        if query == "snmp_engine_id" and re.fullmatch(_IOS_MGMT_REMOTE_HEADER, row, re.I):
            remote_engines = True
        remote_engine = remote_engines and re.fullmatch(_IOS_MGMT_REMOTE_ROW, row, re.I)
        refusal = _IOS_MGMT_REFUSAL.match(row)
        if refusal:
            reason = refusal[0]
            if reason.lower() == "line has invalid autocommand":
                reason = 'Line has invalid autocommand "[redacted]"'
            elif reason.lower() == "command authorization failed":
                reason += "."
            safe.append(reason + "\n")
        elif not row or rows.fullmatch(row) or remote_engine or (
                query in {"snmp_statistics", "snmp_engine_id"} and row == "%SNMP agent not enabled"):
            # Spell the numeric counters so the shared CLI credential redactor
            # cannot mistake literal counter labels for community values.
            if query == "snmp_statistics":
                line = line.replace("Unknown community name", "Unknown community-name")
                line = line.replace("Illegal operation for community name supplied",
                                    "Illegal operation for supplied community-name")
            safe.append(line)
        else:
            if query == "snmp_statistics" and row.startswith("Destination:"):
                destination = row.partition(",")[0]
                if rows.fullmatch(destination):
                    safe.append(destination + "\n")
            remote_engines = False
            if not safe or safe[-1] != _IOS_MGMT_HIDDEN + "\n":
                safe.append(_IOS_MGMT_HIDDEN + "\n")
            incomplete = True
    if pager:
        safe.append("\n--More--\n")
    projected = "".join(safe)
    complete = not incomplete and not pager and all(
        re.search(required, projected, re.I | re.M) for required in _IOS_MGMT_REQUIRED[query])
    if complete and classic_ios and query in {"aaa_servers", "tacacs_statistics"}:
        heading, required = _IOS_MGMT_REQUIRED[query]
        blocks = re.split(rf"(?={heading})", projected, flags=re.I | re.M)[1:]
        complete = all(re.search(required, block, re.I | re.M) for block in blocks)
    return projected, complete


_IOS_LOGGED_CONFIG = re.compile(r"(?im)%PARSER-[0-7]-CFGLOG_LOGGEDCMD:[ \t]*(?P<body>[^\r\n]*)")
_IOS_LOGGED_COMMAND = re.compile(
    r"(?im)%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:[^\r\n]*?"
    r"\b(?:logged command|executed command|command (?:executed|entered|logged))[ \t]*[:=][ \t]*(?P<body>[^\r\n]*)"
)
_IOS_LOG_COMMAND_SECRET = re.compile(
    r"(?i)(?<![\w-])(?:"
    r"(?:standby|vrrp)\b[^\r\n]*?[ \t]+authentication\b(?:[ \t]+(?:text|md5(?:[ \t]+key-string)?))?"
    r"|snmp-server[ \t]+user\b|(?:auth|priv|key(?:-string)?|password|secret|community)\b"
    r")(?P<separator>[ \t]*[:=][ \t]*|[ \t]+)\S[^\r\n]*"
)


def redact_ios_log_commands(output: str) -> str:
    """Remove command credentials from Cisco configuration audit messages."""
    def mask(message):
        body = message["body"]
        secret = _IOS_LOG_COMMAND_SECRET.search(body)
        if secret is None:
            return message[0]
        pager = _NXOS_SNMP_PAGER_SUFFIX.search(body)
        prefix = message[0][:message.start("body") - message.start()]
        return prefix + body[:secret.end("separator")] + "<REDACTED>" + ("\n" + pager[0].strip() if pager else "")

    return _IOS_LOGGED_CONFIG.sub(mask, _IOS_LOGGED_COMMAND.sub(mask, strip_terminal_controls(output)))


EXOS_LOG_ENTRY = re.compile(
    r"(?P<prefix>(?P<stamp>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?:\.\d{2})?) "
    r"<(?P<level>Crit|Erro|Warn|Noti|Info|Summ|Verb|Data|UNKNW):(?P<event>[A-Za-z0-9_.-]+)>[ \t]+)"
    r"(?P<body>\S.*)")
EXOS_LOG_TOTAL = re.compile(r"A total of (\d{1,7}) log messages? (?:was|were) displayed\.")
EXOS_LOG_EMPTY = "No log messages were displayed."
_EXOS_LOGGED_COMMAND = re.compile(
    r"(?i)\b(?:CLI[ -]command|command (?:executed|entered|logged)|(?:executed|entered|logged) command)\b"
    r"|\b(?:configure|config|create|enable)\b[^\r\n]*\b(?:account|community|snmpv3|password|passphrase|"
    r"secret|(?:shared|auth|privacy|pre-shared|authentication)[ -]key)\b"
)
_EXOS_SSH_USER = r"[A-Za-z0-9_@.\\*-]+"
_EXOS_SSH_SOURCE = r"[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?"
_EXOS_ATTEMPTED_USER = rf"(?P<attempted_user>{_EXOS_SSH_USER})"
_EXOS_SSH_LOGIN = re.compile(
    r"(?P<diagnostic>Msg from Master : (?:"
    rf"(?:(?:Did (?:key|password) authentication|Login passed) for user {_EXOS_SSH_USER}"
    rf"|Login failed for user {_EXOS_ATTEMPTED_USER})"
    rf"(?:[ \t]+through ssh)?[ \t]+\({_EXOS_SSH_SOURCE}\)"
    rf"|Found valid key for user {_EXOS_SSH_USER}))"
    r"(?:[ \t]+(?P<label>password|passphrase|secret|(?:private|shared)[ -]key)[ \t]*[:=][ \t]*.+)?")
_EXOS_FAILED_LOGIN = {
    "AAA.authFail": re.compile(
        rf"Login failed due to invalid username/password for user {_EXOS_ATTEMPTED_USER}"
        rf" through ssh \({_EXOS_SSH_SOURCE}\)"),
    "exsshd.KeyAuthFail": re.compile(
        rf"Key authentication failed for user {_EXOS_ATTEMPTED_USER}[ \t]+from {_EXOS_SSH_SOURCE}\."
        r" Key invalid/not configured to the user\."),
}
_EXOS_AAA_LOGIN = {
    "AAA.authPass": re.compile(rf"Login passed for user {_EXOS_SSH_USER} through ssh \({_EXOS_SSH_SOURCE}\)"),
    "AAA.logout": re.compile(rf"(?:Administrative|Non-administrative) account \({_EXOS_SSH_USER}\)"
                              rf" logout from ssh \({_EXOS_SSH_SOURCE}\)"),
}
# These event identifiers come from operational EXOS captures. An unfamiliar event may
# be an audit event, even when its CLI record header is recognized.
_EXOS_OPERATIONAL_EVENTS = frozenset({
    "DM.Info", "DM.Notice", "DM.Warning", "DOSProt.Init", "EAPS.DmnInfo",
    "EDP.PortVLANIdCfgMismatch", "EPM.UnexpctRebootDtect", "EPM.Upgrade.Fail", "EPM.Upgrade.State",
    "EPM.all_shutdown", "EPM.reboot", "EPM.start", "EPM.system_stable", "EPM.wd_warm_reset",
    "EPM.wdg_enable", "HAL.Card.Info", "HAL.Card.Warning", "HAL.Sys.Info", "HAL.Sys.Notice",
    "HAL.Sys.Warning", "NM.StrtProc", "NetTools.SNTP.SrvrNameNotRslved", "SNMP.Master.InitDone",
    "STP.DomainEnable", "STP.InBPDU.Drop", "cm.loadErr", "cm.sys.LoadApplCfgObjFail",
    "exsshd.CfgHostKeyAlgWeak", "exsshd.RejctConnKeyExchgFail",
    "licMgr.EnblFeatLcns", "lldp.MaxNbrsReached", "log.NVRAMFull", "log.serverStarted",
    "nl.init", "telnetd.info", "tftpd.info", "thttpd.CrtfctVld",
    "vlan.msgs.portLinkStateDown", "vlan.msgs.portLinkStateUp",
})
# Exact bodies of ordinary events that are not audit records (measured on EXOS-VM 33.6.1.14 boot and X435/X440
# 33.7.1.6): SSH host-key start-up messages and the telemetry agents that report a missing decoder component.
_EXOS_FIXED_BODIES = (
    ("AAA.LogSsh", re.compile(r"Msg from Master : Loaded Private Key of size [0-9]{1,5} from System")),
    ("AAA.LogSsh", re.compile(r"Msg from Master : Generating RSA-[0-9]{3,5} public key")),
    ("AAA.LogSsh", re.compile(r"Msg from Master : Existing host key with fingerprint SHA256(?::[0-9a-f]{2}){16,64} "
                              r"loaded successfully")),
    ("inlets.0", re.compile(r'NO MESSAGE DECODE; Missing component "inlets" v[0-9]{1,3}\.[0-9]{1,3}')),
    ("telegraf.0", re.compile(r'NO MESSAGE DECODE; Missing component "telegraf" v[0-9]{1,3}\.[0-9]{1,3}')),
)


def _exos_fixed_body(event: str, body: str) -> bool:
    return any(event == name and pattern.fullmatch(body) for name, pattern in _EXOS_FIXED_BODIES)


def _exos_redact_attempted_user(body: str, login: re.Match[str]) -> str:
    # A rejected user field can be a password typed into the wrong prompt.
    start, end = login.span("attempted_user")
    if start < 0:
        return body
    return body[:start] + "<user-redacted>" + body[end:]


def redact_exos_log_commands(output: str) -> tuple[str, bool]:
    """Return the safe projection and whether any unrecognized log content was withheld."""
    rows, incomplete = [], False
    text = strip_terminal_controls(output.replace("\r\n", "\n").replace("\r", "\n"))
    for line in text.splitlines():
        entry = EXOS_LOG_ENTRY.fullmatch(line)
        if entry is None:
            if not line.strip() or line == EXOS_LOG_EMPTY or EXOS_LOG_TOTAL.fullmatch(line):
                rows.append(line)
            else:
                rows.append("    <REDACTED>")
                incomplete = True
            continue
        event, body = entry["event"], entry["body"]
        if event == "AAA.LogSsh" and (login := _EXOS_SSH_LOGIN.fullmatch(body)):
            # Assignment punctuation would make the response-wide redactor remove the label too.
            credential = f" {login['label']} <REDACTED>" if login["label"] else ""
            diagnostic = _exos_redact_attempted_user(login["diagnostic"], login)
            rows.append(entry["prefix"] + diagnostic + credential)
        elif (failure := _EXOS_FAILED_LOGIN.get(event)) and (login := failure.fullmatch(body)):
            rows.append(entry["prefix"] + _exos_redact_attempted_user(body, login))
        elif _EXOS_LOGGED_COMMAND.search(body):
            rows.append(entry["prefix"] + "<REDACTED>")
        elif event in _EXOS_OPERATIONAL_EVENTS or _exos_fixed_body(event, body) or (
                event in _EXOS_AAA_LOGIN and _EXOS_AAA_LOGIN[event].fullmatch(body)):
            rows.append(line)
        else:
            rows.append(entry["prefix"] + "<REDACTED>")
            incomplete = True
    return "\n".join(rows) + ("\n" if text.endswith("\n") else ""), incomplete


COMMUNITY_VALUE_SECRET = re.compile(r"(?i)(\bcommunity[ \t]+)(?!string\b)\S+")
CISCO_TYPE7_SECRET = re.compile(r"(?im)(\b(?:key|key-string|md5|password)[ \t]+7[ \t]+)\S+")
PRESHARED_SECRET = re.compile(
    r"(?im)(\b(?:pre-shared-key|psksecret|psk|wpa-passphrase|bind-password)(?:[ \t]*[:=][ \t]*|[ \t]+))(?:"
    + _DOUBLE_QUOTED + "|" + _SINGLE_QUOTED + r"|\S+)"
)
_JUNOS_SA_KEY = re.compile(
    r"(?im)^([ \t]*(?:(?:authentication|auth|encryption|encrypt|integrity|session|inbound|outbound)"
    r"[ -]+)?(?:key(?:[ -]+(?:value|material))?|pre[ -]shared[ -]key|psk)[ \t]*[:=][ \t]*)[^\r\n]*"
)


def redact_junos_sa_keys(text: str) -> str:
    """Withhold any key-value labels before hashing or paging SRX SA output."""
    return _JUNOS_SA_KEY.sub(r"\g<1><REDACTED>", text)


# SA status normally prints algorithms, lifetimes and identifiers. Keep any unexpected
# labeled key material out of the raw output, hashes and subsequently derived records.
_CISCO_SA_SECRET = re.compile(
    r"(?i)(\b(?:(?:pre[- ]shared|auth(?:entication)?|enc(?:ryption)?|integrity|session|inbound|outbound)"
    r"[ -]+)?(?:key(?:[ -]+(?:value|material))?|psk(?:secret)?|SK_[A-Za-z]{1,4})[ \t]*[:=][ \t]*)"
    r"[^\r\n]*"
)
# A wrapped key can end immediately before a suffix, so consume the full hex run.
_CISCO_SA_HEX = r"(?:0x)?[0-9a-f]{2,}+"
_CISCO_SA_CONTINUATION = re.compile(rf"[ \t:\-]*+{_CISCO_SA_HEX}(?:[ \t:\-]++{_CISCO_SA_HEX})*+", re.I)


def redact_cisco_sa_keys(text: str) -> str:
    text = strip_terminal_controls(text.replace("\r\n", "\n"))

    def mask(match):
        pager = _NXOS_SNMP_PAGER_SUFFIX.search(match[0])
        return match[1] + "<REDACTED>" + ("\n" + pager[0].strip() if pager else "")

    lines = []
    in_key = False
    for line in text.split("\n"):
        if in_key and _NXOS_SNMP_PAGER_SUFFIX.fullmatch(line.strip()):
            lines.append(line)
            continue
        continuation = in_key and _CISCO_SA_CONTINUATION.match(line)
        if continuation:
            # Keep any public suffix on its own line so a terminal pager still counts after an LF.
            line = line[continuation.end():].lstrip(" \t")
            if not line:
                continue
        cleaned, labels = _CISCO_SA_SECRET.subn(mask, line)
        in_key = bool(labels or continuation)
        lines.append(cleaned)
    return "\n".join(lines)


# G14 (FP-09): FortiOS IPsec detail reads print live key material even to a read-only account (measured on a
# FortiGate-60F 7.6.8 build3744): `diagnose vpn ike gateway list` the IKE SA keys (`SK_ei: <hex>-<hex>-<hex>-<hex>`),
# `diagnose vpn tunnel list` the ESP keys (`esp=aes key=32 <hex>`, `ah=sha256 key=32 <hex>`) and
# `get vpn ipsec tunnel details` (`enc:  aes-cb  <hex>`, `auth: sha256  <hex>`). The value after the label is
# withheld whole; as a net for an unknown label any run of 32 or more hex digits (also split by `-`, `:` or one
# space) is withheld too. SPIs (8 hex digits) and IKE cookies (16) stay, the parser needs them.
_FORTIOS_SK_KEY = re.compile(r"(?im)^([ \t]*SK_[A-Za-z]{1,4}[ \t]*:[ \t]*)[^\r\n]*")
_FORTIOS_SA_KEY = re.compile(r"(?i)(\bkey=\d*[ \t]*)[0-9A-Fa-f][^\r\n]*")
_FORTIOS_SA_ALG_KEY = re.compile(r"(?im)^([ \t]*(?:enc|auth)[ \t]*:[ \t]+[A-Za-z0-9_-]+[ \t]+)[0-9A-Fa-f][^\r\n]*")
_FORTIOS_LABELED_KEY = re.compile(
    r"(?im)((?<![\w.-])(?:enc[ \t]+key|auth[ \t]+key|psksecret|psk)[ \t]*[:=][ \t]*"
    r"|^[ \t]*(?:set[ \t]+)?(?:psksecret|psk)[ \t]+(?![ \t]*[:=]))[^\r\n]*"
)
_LONG_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:[-: ]?[0-9A-Fa-f]{2}){15,}(?![0-9A-Za-z])")


# FortiOS queries whose output passes redact_fortios_ipsec_keys right after the device read.
FORTIOS_IPSEC_KEY_QUERIES = frozenset({"ike_gateway_detail", "ipsec_tunnel_detail"})


def redact_fortios_ipsec_keys(text: str) -> str:
    """Withhold IKE/IPsec key material of FortiOS IPsec detail output before hashing, paging or parsing."""
    text = _FORTIOS_LABELED_KEY.sub(r"\g<1><REDACTED>", text)
    text = _FORTIOS_SK_KEY.sub(r"\g<1><REDACTED>", text)
    text = _FORTIOS_SA_KEY.sub(r"\g<1><REDACTED>", text)
    text = _FORTIOS_SA_ALG_KEY.sub(r"\g<1><REDACTED>", text)
    return _LONG_HEX.sub("<REDACTED>", text)


DYNAMIC_PSK_STATE = re.compile(r"(?i)[ \t]*dynamic[ \t]+psk[ \t]*=[ \t]*(?:enabled|disabled)[ \t]*\r?")
RUCKUS_PASSPHRASE = re.compile(r"(?im)^([ \t]*passphrase[ \t]*=[ \t]*)[^\r\n]*")
# Ruckus Unleashed `show` trees (WLAN, AAA, mesh): one `Label = value` per line, values unquoted and possibly with
# spaces. Any label naming a key, passphrase, PSK, secret or password hides the whole rest of its line
# (`Key = …`, `RADIUS Key = …`, `SAE-Passphrase = …`, `Secret= …`, G110: `RO Community= …`, `Token= …`,
# `Authentication Pass Phrase= …`, `Privacy Phrase= …`); the `Dynamic PSK = Enabled|Disabled` state stays.
RUCKUS_SECRET_LINE = re.compile(
    r"(?im)^([ \t]*[^\r\n=:]*?\b(?:key|keys|passphrase|pass[ \t]+phrase|privacy[ \t]+phrase|psk|secret|password|passwd|community|token)\b[^\r\n=:]*?[ \t]*[=:][ \t]*)"
    r"([^\r\n]*?)[ \t]*(?=\r?$)"
)
_RUCKUS_SECRET_STATE = re.compile(
    r"(?i)[ \t]*(?:dynamic[ \t]+psk|guest[ \t]+friendly[ \t]+key)[ \t]*=[ \t]*(?:enabled|disabled)"
)

def redact_ruckus_secrets(value: str, secrets: Iterable[str] = ()) -> str:
    """Whole-value redaction of secret lines in Ruckus Unleashed output, before the general rules (G107 475-r2).

    The result has no terminal controls when the input had any: the line rule runs both on the text as read and
    on the text without ANSI sequences and C0 controls (475-r3), so a label split by them is still recognised.

    The known secrets (`secrets`, e.g. the login password, possibly spanning lines) are replaced first, as the
    general chain does: a line rule must never cut a known secret and leave its other lines unmatched.
    """
    for secret in sorted({item for item in secrets if len(item.encode("utf-8")) >= 3}, key=lambda item: (-len(item), item)):
        value = value.replace(secret, "<REDACTED>")
    # Use the equivalent ESC form so both encodings of C1 controls use the same ANSI grammar.
    value = _RUCKUS_C1_CONTROL.sub(lambda match: "\x1b" + chr(ord(match[0]) - 0x40), value)

    def replace(match: re.Match[str]) -> str:
        text = match.group(2)
        if not text or _MARKERS_ONLY.fullmatch(text):
            return match.group(0)
        # Only a suffix made up of ANSI controls and horizontal space may follow a public state.
        state = _RUCKUS_SECRET_STATE.match(match[0])
        if state and not ANSI_CONTROL.sub("", match[0][state.end():]).strip(" \t"):
            return match.group(0)
        return match.group(1) + "<REDACTED>"
    value = RUCKUS_SECRET_LINE.sub(replace, value)
    # A label is recognisable only once ANSI sequences and other controls are gone (475-r3): the line rule runs
    # again on that cleaned text, which is what the general chain and the response finally carry.
    cleaned = strip_terminal_controls(value)
    return RUCKUS_SECRET_LINE.sub(replace, cleaned) if cleaned != value else value
# G110 (RP08): `show config` of Unleashed holds PSKs, RADIUS secrets, the admin password, the network token and SNMP
# communities spread over many sections. Only these top-level sections are passed on (allowlist); every other block,
# including any section a later release adds, is replaced by one withheld marker, and the lines of the kept
# blocks still go through redact_ruckus_secrets (labels naming a key, secret, password, community, token, phrase).
RUCKUS_CONFIG_SECTIONS = (
    "Device IP Address", "Country Code", "Identity", "NTP", "Log", "Bonjour Service", "Telnet Server", "FTP Server",
    "IPv4 Management Interface", "Management ACL", "L2/MAC ACL", "AAA", "DHCP servers for DHCP relay agent",
    "Static Route", "SNMP Agent", "SNMP Trap", "SNMPV3 Agent",
)
RUCKUS_CONFIG_WITHHELD = "[section withheld]"


def ruckus_config_allowlist(value: str, secrets: Iterable[str] = ()) -> str:
    """The allowlisted sections of a Unleashed `show config` with secrets withheld (see RUCKUS_CONFIG_SECTIONS)."""
    cleaned = strip_terminal_controls(redact_ruckus_secrets(value, secrets))
    lines = cleaned.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    keep = True
    for number, line in enumerate(lines):
        if number == 0 and line.strip().startswith("show "):
            out.append(line)  # the device echo of the command
            continue
        if line and not line[0].isspace():
            heading = line.rstrip()
            name = heading[:-1] if heading.endswith(":") else None
            # `Protocol Mode= IPv4-Only` is a top-level setting, not a block heading.
            keep = name in RUCKUS_CONFIG_SECTIONS or ("=" in heading and heading.split("=", 1)[0].strip() == "Protocol Mode")
            if not keep:
                out.append(RUCKUS_CONFIG_WITHHELD + " " + (name or "setting"))
                continue
        if keep:
            out.append(line)
    return "\n".join(out)

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


_MARKER = r"(?:<REDACTED>|<REDACTED:credential#[1-9][0-9]*>|\[REDACTED\]|<PRIVATE-KEY-REDACTED>)"
_MARKERS_ONLY = re.compile(_MARKER + r"(?:[ \t]+" + _MARKER + r")*")
_MARKER_FIRST = re.compile("(" + _MARKER + r"[ \t]+)(.+)", re.S)


def _replace_enable(match):
    """CISCO_ENABLE_ACCOUNT_SECRET: a marker taken as the first of two tokens stays (task 302-r2).

    A later pass (the fixed point of the response chain) sees `enable secret <REDACTED>
    <REDACTED>`; joining both markers would let the 1.0.8 rule take what follows the
    last one (for example the closing quote of a JSON string). Otherwise the value is
    hidden whole; what a later rule of the 1.0.8 chain hid after it stays hidden through
    the floor of that chain (task 302-r6, _redact_credentials, redact_response).
    """
    value = match.group(0)[len(match.group(1)):]
    if _MARKERS_ONLY.fullmatch(value):
        return match.group(0)
    first = _MARKER_FIRST.fullmatch(value)
    if first:
        return match.group(1) + first.group(1) + "<REDACTED>"
    return _replace_credential(match)


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
    changes = _assigned_changes(pattern, replace, value, chunk)
    return edits(value, changes) if changes or not isinstance(value, Marked) else value


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
_RUCKUS_C1_CONTROL = re.compile(r"[\x80-\x9f]")


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
    is edited inside its own string tokens only. Each distinct string is cleaned once.
    """
    if text not in cache:
        changes = []
        if _ACCOUNT_HINT.search(text):
            changes = _json_account_edits(text, cache)
            if changes is None:
                changes = _line_account_edits(text)
        cache[text] = sorted(changes)
    return cache[text]


def _line_account_edits(text: str) -> list:
    changes = []
    for pattern in _ACCOUNT_SECRETS:
        replace = _ACCOUNT_REPLACE.get(pattern, _replace_credential)
        for match in pattern.finditer(text):
            replacement = replace(match)
            if replacement != match.group(0):
                changes.append((match.start(), match.end(), replacement))
    return changes


def _json_account_edits(text: str, cache: dict) -> list | None:
    """Translate the edits of each JSON string token into document offsets.

    None when ``text`` is not a JSON object or array. The line rules never run over
    the raw text of a document (task 302-r2): `enable` may follow a space inside a
    string, and its value would take the closing quote (`{"c": "  enable secret 5 x"}`).
    The rules anchored to a line start cannot match the raw text of a valid document.
    """
    if text.lstrip()[:1] not in ("{", "["):
        return None
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(decoded, (dict, list)):
        return None
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
    """Account, `enable secret|password` and AAA credential lines, also inside JSON string tokens.

    The rules are anchored to a CLI line start (`enable` also after whitespace or a
    prompt), which a JSON-escaped newline or a string's opening quote is not. In a
    JSON object or array only the matched credential text inside a string token is
    re-encoded, so the rest of the document and its original ranges are kept.
    """
    if not _ACCOUNT_HINT.search(value):
        return value
    try:
        changes = _json_account_edits(value, {})
    except RecursionError:
        raise ValueError('redaction could not be verified; output withheld') from None
    if changes is None:
        for pattern in _ACCOUNT_SECRETS:
            value = sub(pattern, _ACCOUNT_REPLACE.get(pattern, _replace_credential), value)
        return value
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
    """A character a frozen released chain hides (original), or text a replacement
    inserted over one (derived). Each floor has its own pair of kinds (_FLOOR for the
    complete 1.0.8 chain of redact_response and redact, _PROXY_FLOOR for the proxy), so
    one layer never masks the floor another layer carries."""
    __slots__ = ("original", "_derived")

    def __init__(self, original: bool, derived=None):
        self.original, self._derived = original, derived or self

    def derived(self):
        return self._derived


_FLOOR_DERIVED = _Floor(False)
_FLOOR = _Floor(True, _FLOOR_DERIVED)
_PROXY_FLOOR_DERIVED = _Floor(False)
_PROXY_FLOOR = _Floor(True, _PROXY_FLOOR_DERIVED)


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
    return _unclaimed(plain, chain(_origin(plain)))


def _origin(plain: str):
    return Marked(plain, [(0, len(plain), _Origin(0))])


def _unclaimed(plain: str, result) -> list:
    """Ranges of ``plain`` that no origin range of ``result`` claims (sorted, disjoint)."""
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


def _subtract(ranges: list, removed: list) -> list:
    """Sorted, disjoint ``ranges`` without the sorted, disjoint ``removed`` ranges."""
    result, index = [], 0
    for start, end in ranges:
        while index < len(removed) and removed[index][1] <= start:
            index += 1
        cursor, scan = start, index
        while scan < len(removed) and removed[scan][0] < end:
            if removed[scan][0] > cursor:
                result.append((cursor, removed[scan][0]))
            cursor = max(cursor, removed[scan][1])
            scan += 1
        if cursor < end:
            result.append((cursor, end))
    return result


def _union(first: list, second: list) -> list:
    joined = []
    for start, end in sorted((*first, *second)):
        if joined and start <= joined[-1][1]:
            joined[-1] = (joined[-1][0], max(end, joined[-1][1]))
        else:
            joined.append((start, end))
    return joined


def _floored(value, floor: list, kind: _Floor):
    """``value`` with ``floor`` (original offsets of its text) as ranges of ``kind``."""
    spans = value.spans if isinstance(value, Marked) else ()
    return Marked(str.__str__(value), (*spans, *((start, end, kind) for start, end in floor)))


def _mask_origin(value, ranges: list):
    """``value`` with every character whose origin offset lies in the sorted, disjoint
    ``ranges`` replaced by `<REDACTED>` (touching characters as one token, as ``mask``
    joins ranges); a masked character loses its origin, so it counts as hidden."""
    if not ranges or not isinstance(value, Marked):
        return value
    starts, pieces = [start for start, _ in ranges], []
    for start, end, kind in value.spans:
        if not isinstance(kind, _Origin):
            continue
        low = kind.offset
        high = low + (1 if kind.atom else end - start)
        index = max(bisect.bisect_right(starts, low) - 1, 0)
        while index < len(ranges) and ranges[index][0] < high:
            a, b = max(low, ranges[index][0]), min(high, ranges[index][1])
            if a < b:
                pieces.append((start, end) if kind.atom else (start + a - low, start + b - low))
            index += 1
    joined = []
    for start, end in sorted(pieces):
        if joined and start <= joined[-1][1]:
            joined[-1] = (joined[-1][0], max(end, joined[-1][1]))
        else:
            joined.append((start, end))
    return edits(value, [(start, end, "<REDACTED>") for start, end in joined]) if joined else value


def _covering_floor(plain: str, released: list, output, later):
    """The output of a layer, with origin ranges of ``plain``, such that ``later(output)``
    hides every range of ``released`` (task 302-r6): the structural guarantee of a layer
    whose output goes on to ``later`` layers before it reaches the AI client.

    ``released`` is what the frozen released chain hides of ``plain``; ``output`` is the
    current layer's output and ``later`` runs the layers after it. The union of both masks is
    hidden, found by original offsets (_unclaimed), not by a guess about later rules:
    - the current chain already hides all of ``released``: ``output`` itself (no change);
    - otherwise the missing characters are masked in the layer's output; a mask that removed
      an anchor of a later current rule is checked once more;
    - last, every character of ``released`` is masked in the layer's output: the output
      itself then hides what the frozen chain hides, whatever the later layers do.
    """
    missing = _subtract(released, _unclaimed(plain, later(output)))
    if not missing:
        return output
    masked = _mask_origin(output, missing)
    if not _subtract(released, _unclaimed(plain, later(masked))):
        return masked
    return _mask_origin(masked, released)


def _floor_1_0_8_ranges(value: str, normalized: tuple[str, ...]) -> list:
    """Original-input ranges the released 1.0.8 credential rules (61e7de3) hide."""
    return _hidden_ranges(value, lambda marked: _redact_1_0_8(marked, normalized))


_REDACTION_TOKEN = re.compile(
    r"<REDACTED>|<PRIVATE-KEY-REDACTED>|<REDACTED:credential#[1-9][0-9]*>|\[REDACTED\]")
_TOKEN_TEXTS = ("<REDACTED>", "<PRIVATE-KEY-REDACTED>", "<REDACTED:credential#", "[REDACTED]")


def _surviving_floor(result, kind: _Floor = _FLOOR) -> tuple:
    """Floor groups (of ``kind`` and its derived kind) left in ``result``, joined as mask()
    joins ranges.

    A group with an original character is masked whole (like the 1.0.8 token over
    it); a group of derived (inserted) text only is kept when it is just redaction
    tokens or a piece of one (e.g. the `>` left by trimming `<REDACTED:credential#9>X`).
    """
    groups, kinds = [], (kind, kind.derived())
    floor = sorted((span for span in result.spans if span[2] in kinds), key=lambda span: span[:2])
    for start, end, found in floor:
        if groups and start <= groups[-1][1]:
            groups[-1][1] = max(end, groups[-1][1])
            groups[-1][2] = groups[-1][2] or found.original
        else:
            groups.append([start, end, found.original])
    return tuple((start, end, "community") for start, end, original in groups
                 if original or not _inserted_only(result[start:end]))


def _inserted_only(text: str) -> bool:
    for piece in _REDACTION_TOKEN.split(text):
        piece = piece.strip(" \t\r\n\"'")
        if piece and not _token_piece(piece):
            return False
    return True


def _token_piece(piece: str) -> bool:
    """A piece of a redaction token, also of a numbered credential token (`1>`,
    `REDACTED:credential#12>`) that SNMP masking renumbered in a later pass (task 302-r3)."""
    if any(piece in token for token in _TOKEN_TEXTS):
        return True
    number = re.search(r"[0-9]+", piece)
    return number is not None and piece in "<REDACTED:credential#%s>" % number.group()


def _mask_floor(value) -> str:
    """Mask the floor ranges left after the last layer (one pass)."""
    groups = _surviving_floor(value) if isinstance(value, Marked) else ()
    return mask(Marked(str.__str__(value), groups)) if groups else str.__str__(value)


def _mask_kept(value, kind: _Floor):
    """Mask the surviving floor groups of ``kind`` as ``mask`` masks them (`<REDACTED>`),
    keeping every other range of ``value`` (origin, other floors, SNMP credentials)."""
    if not isinstance(value, Marked):
        return value
    groups = _surviving_floor(value, kind)
    kinds = (kind, kind.derived())
    rest = Marked(str.__str__(value), tuple(span for span in value.spans if span[2] not in kinds))
    if groups:
        rest = edits(rest, [(start, end, "<REDACTED>") for start, end, _ in groups])
    return rest if rest.spans else str.__str__(rest)


def _later_layers(value, normalized: tuple[str, ...], typed: bool):
    """The layers after ``redact()`` on the way to the AI client: the proxy (released 1.0.8
    rules when ``typed`` is false) and the product, with tracked ranges."""
    from .proxy_sanitize import _sanitize_object
    proxied = _atomize(_sanitize_object(_atomize(value), normalized, typed=typed))
    return _tracked_product()(proxied, normalized)[0]


def _cut(value, max_bytes: int):
    """The prefix of ``value`` (text or ``Marked``) within ``max_bytes`` UTF-8 bytes, cut as the
    diagnostics cut their output (``text.encode()[:max_bytes].decode(errors="ignore")``);
    ``value`` itself when it fits."""
    plain = str.__str__(value)
    kept = len(plain.encode("utf-8")[:max_bytes].decode("utf-8", "ignore"))
    if kept >= len(plain):
        return value
    return edits(value, [(kept, len(plain), "")]) if isinstance(value, Marked) else plain[:kept]


def _redact_credentials(value: str, normalized: tuple[str, ...], cut_bytes: int | None = None) -> str:
    """Current credential rules for ``redact``, never weaker than the 1.0.8 chain (task 302-r6).

    The output of ``redact()`` goes on through the proxy and the product (e.g. a
    diagnostic's ``untrusted_device_output``). The released 1.0.8 chain of that path
    (Helper 1.0.8 rules, proxy 1.0.8, product) runs over the input with origin ranges;
    every character it hides is hidden on this path too (_covering_floor):
    - the floor of the Helper 1.0.8 rules alone is carried as before: the current rules
      run over the original input with it as floor ranges and the surviving ones are
      masked at the end, so no rule loses an anchor to an earlier mask;
    - a character that the 1.0.8 proxy or product hid and that the current chain
      (this output, the current proxy, the product) leaves visible joins that floor, so
      ``redact()`` masks it itself; if that is not enough, the whole 1.0.8 chain floor;
    - when the current rules give the text of the 1.0.8 Helper rules, nothing is computed:
      the later layers get the input they got in 1.0.8.
    In a JSON document whose 1.0.8 result keeps its shape, the floor of the later layers
    keeps only string contents (_json_value_floor), as in redact_response.

    ``cut_bytes`` (task 302-r7): the caller sends only the first ``cut_bytes`` UTF-8 bytes of
    the output on (a diagnostic's ``max_bytes``). A cut can remove context that a later layer
    needs (the END line of a private key), so the floor must not depend on the later layers
    seeing the whole output:
    - the floor also takes what the 1.0.8 chain hid with the same cut (the 1.0.8 Helper
      output cut to ``cut_bytes``, then the 1.0.8 proxy and the product);
    - when the output is longer than ``cut_bytes``, every floor character is masked in the
      output itself, so every prefix hides the whole floor, whatever the later layers do;
    - an output within ``cut_bytes`` is not cut and keeps the guarantee above.
    The fast path gives the 1.0.8 Helper text: the same cut gives the 1.0.8 prefix.
    """
    plain = str.__str__(value)
    current = _redact_current(plain, normalized)
    if not _ACCOUNT_HINT.search(plain) or current == _redact_1_0_8(plain, normalized):
        # The same text as the 1.0.8 Helper rules give (without an account rule they are the
        # same rules): the later layers see the 1.0.8 input, and the proxy keeps its own
        # floor of the 1.0.8 proxy and the product (proxy_sanitize._sanitize_text).
        return current
    helper = _redact_1_0_8(_origin(plain), normalized)
    base = _unclaimed(plain, helper)
    released_result = _later_layers(helper, normalized, False)
    released = _json_value_floor(plain, _unclaimed(plain, released_result), released_result)
    released = _union(base, released)
    if cut_bytes is not None:
        cut = _cut(helper, cut_bytes)
        if cut is not helper:
            # What the 1.0.8 proxy and product hid of the cut 1.0.8 Helper output.
            released = _union(released, _subtract(_unclaimed(plain, _later_layers(cut, normalized, False)),
                                                   _unclaimed(plain, cut)))

    def layer(text):
        if not base:
            return _redact_current(text, normalized)
        return _mask_kept(_redact_current(_floored(text, base, _FLOOR), normalized), _FLOOR)

    if not _subtract(released, base):
        # The output itself hides the whole floor (base): every prefix does too.
        return str.__str__(layer(plain))
    covered = _covering_floor(plain, released, layer(_origin(plain)),
                              lambda text: _later_layers(text, normalized, True))
    if cut_bytes is not None and _cut(covered, cut_bytes) is not covered:
        # The output will be cut: it hides the whole floor itself, not through later layers.
        covered = _mask_origin(covered, released)
    return str.__str__(covered)


def _redact_current(value: str, normalized: tuple[str, ...]) -> str:
    for secret in normalized:
        value = replace(value, secret, "<REDACTED>")
    value = sub(PRIVATE_PEM, "<PRIVATE-KEY-REDACTED>", value)
    # Quoted values go first, so that an ENC or bearer token cannot consume their closing quote.
    value = sub(SNMP_CLI_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sub(PRESHARED_SECRET, _quoted_only(_replace_preshared), value)
    value = sub(CLI_OPTION_SECRET, _quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    # Before ENC/bearer/type-7 rules, which could split a quoted or escaped value.
    value = sub(CISCO_MANAGEMENT_SECRET, lambda match: match.group(1) + "<REDACTED>", value)
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


def redact(text: object, secrets: Iterable[str] = (), limit: int | None = None,
           cut_bytes: int | None = None) -> str:
    """Redact credentials; control-bearing diagnostics need the complete chain.

    ``cut_bytes``: the caller sends on only the first ``cut_bytes`` UTF-8 bytes of the result
    (task 302-r7); the result then keeps the 1.0.8 floor in every such prefix
    (``_redact_credentials``). The complete chain (``redact_response``) already masks its
    floor in its own output, after its last layer, so a prefix keeps it too.
    """
    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    value = str(text)
    from .proxy_sanitize import _contains_snmp
    if C0_CONTROL.search(value) or _contains_snmp(value):
        # The complete chain; see redact_response for its complete passes.
        value = redact_response(value, normalized)
    else:
        # Two passes, both used (task 302): the 1.0.8 rules with origin ranges give
        # the floor, the current rules give the text (carrying that floor if any).
        value = _redact_credentials(value, normalized, cut_bytes)
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


def _proxy_1_0_8(value, secrets):
    """The released 1.0.8 proxy rules: the current proxy without CISCO_TYPED_SECRET.

    Since 1.0.8 (61e7de3) the proxy changed only by that rule (task 302-r2) and by the
    span operations, which give the same results. The 1.0.8 floor chain uses this, so a
    new proxy rule cannot weaken its own reference (task 302-r3).
    """
    from .proxy_sanitize import _sanitize_object
    return _sanitize_object(value, secrets, typed=False)


def _settle_response(value, secrets, *, helper=False, credentials=None, proxy=None):
    """Run the pre-SNMP layers to a fixed point on the same document."""
    from netops.redaction import redact as product_redact
    from .proxy_sanitize import _sanitize_object

    credentials = credentials or _redact_current
    proxy = proxy or _sanitize_object
    normalized = tuple(sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True))
    for _ in range(8):
        original = credentials(value, normalized) if helper else value
        proxied = _atomize(proxy(_atomize(original), secrets))
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


def _snmp_response(value, secrets, *, helper=False, credentials=None, proxy=None):
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
    settled = _settle_response(original, secrets, helper=helper, credentials=credentials, proxy=proxy)
    for _ in range(8):
        cleaned = _mask_tracked(settled)
        if cleaned == settled:
            return cleaned
        # Legacy matches can remove a CR/newline and extend a community's
        # remaining line. Recheck only after a change, after preserving its floor.
        settled = _mark_tracked(_settle_response(cleaned, secrets, helper=helper, credentials=credentials,
                                                 proxy=proxy))
    raise ValueError('redaction could not be verified; output withheld')


def _response_chain(text, secrets, credentials, proxy=None):
    """The complete response chain (Helper credential rules, proxy, product, SNMP mask)."""
    text = _snmp_response(text, secrets, helper=True, credentials=credentials, proxy=proxy)
    cleaned = strip_terminal_controls(text)
    return (_snmp_response(cleaned, secrets, helper=True, credentials=credentials, proxy=proxy)
            if cleaned != text else text)


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


def _same_coverage(first, second) -> bool:
    """Two proxy results with the same structure and the same ``_coverage`` of every string."""
    if isinstance(first, str) or isinstance(second, str):
        return isinstance(first, str) and isinstance(second, str) and _coverage(first) == _coverage(second)
    if isinstance(first, dict) and isinstance(second, dict):
        return len(first) == len(second) and all(
            _same_coverage(key, other_key) and _same_coverage(child, other_child)
            for (key, child), (other_key, other_child) in zip(first.items(), second.items()))
    if isinstance(first, list) and isinstance(second, list):
        return len(first) == len(second) and all(map(_same_coverage, first, second))
    return type(first) is type(second) and first == second


def redact_response(text: str, secrets: Iterable[str] = ()) -> str:
    """Capture original SNMP ranges and preserve the complete legacy secrecy floor.

    Preserve the raw-input floor before cleaning terminal controls; repeat the
    complete chain on the cleaned text so controls cannot disguise a label.

    The chain runs with the current credential and proxy rules. Where the released
    1.0.8 rules give the same text and ranges at every Helper step and every proxy step
    (task 302-r3: the proxy has a new rule too), the complete 1.0.8 chain reaches the
    same result. Otherwise the characters the complete 1.0.8 chain
    hides are found by original offset and masked after the last layer of the
    current chain, which itself runs unchanged (task 165-r4). In a JSON document
    whose 1.0.8 result keeps its shape, the floor keeps only string contents
    (``_json_value_floor``, task 302); a floor the chain cannot carry through JSON
    decoding still withholds the output.
    """
    secrets = tuple(secrets)
    state = {}

    # Complete chains (task 302): (1) the current chain; once the rules differ,
    # (2) the complete 1.0.8 chain with origin ranges, computed at the first
    # difference; (3) the current chain carrying the floor, only for a partial
    # floor. Until task 302, (1) always ran to its end and, with a partial floor,
    # its text served only to be compared with the text of (3). (3) runs the same
    # functions on the same text: the span operations give the text of the plain
    # operations and a floor range never changes text (a floor that cannot follow
    # a JSON token raises _UnrepresentableFloor, and the output is withheld). So
    # (1) now stops at the first difference when the floor is partial; the
    # differential test in test_response_json_account_floor_302.py compares both
    # algorithms. Without a floor or with a floor over the whole input, (1) is the
    # result and runs to its end as before. No other complete chain repeats work.
    #
    # The 1.0.8 chain uses the released Helper rules and the released proxy rules
    # (_proxy_1_0_8, task 302-r3): a new proxy rule that removes an anchor of a later
    # rule cannot weaken the reference. A difference at a proxy step starts it as a
    # difference at a Helper step does; the proxy is compared only after its new rule
    # changed text (otherwise both proxies give the same result). The masked result of
    # (3) runs through the current chain to its fixed point (_settle_floor_result).
    def reference():
        released = []

        def chain(marked):
            released.append(_response_chain(marked, secrets, _redact_1_0_8, _proxy_1_0_8))
            return released[0]

        floor = state["floor"] = _hidden_ranges(text, chain)
        if floor and floor != [(0, len(text))]:
            state["released"] = released[0] if released else None
            raise _PartialFloor

    def watched(value, normalized):
        result = _redact_current(value, normalized)
        if "floor" not in state and _coverage(_redact_1_0_8(value, normalized)) != _coverage(result):
            reference()
        return result

    def watched_proxy(value, proxy_secrets):
        from .proxy_sanitize import _sanitize_object
        changes = []
        result = _sanitize_object(value, proxy_secrets, typed_changes=changes)
        if changes and "floor" not in state and not _same_coverage(_proxy_1_0_8(value, proxy_secrets), result):
            reference()
        return result

    try:
        result = _response_chain(text, secrets, watched, watched_proxy)
    except _PartialFloor:
        return _floor_response(text, secrets, state["floor"], state["released"])
    if state.get("floor") == [(0, len(text))]:
        # The released chain withheld the complete input (e.g. a JSON key with
        # `set password`). Keep that decision before JSON decoding can discard
        # floor ranges on numbers, booleans, null or document punctuation.
        return dumps('[REDACTED]')
    return result


class _PartialFloor(Exception):
    """Internal: stop the plain current chain, the floor-tracking chain follows."""


def _floor_response(text, secrets, floor, released):
    """The current chain carrying the 1.0.8 floor, masked after its last layer."""
    plain = str.__str__(text)
    floor = _json_value_floor(plain, floor, released)
    try:
        tracked = _response_chain(Marked(plain, [(start, end, _FLOOR) for start, end in floor]), secrets, _redact_current)
    except _UnrepresentableFloor:
        raise ValueError('redaction could not be verified; output withheld') from None
    return _settle_floor_result(_mask_floor(tracked), secrets)


def _settle_floor_result(text, secrets):
    """The masked floor result, run through the current chain to its fixed point (task 302-r3).

    The floor is masked after the last layer, so a layer can still change the masked
    text (`set passwd <REDACTED>` for the product, a line joined by a masked line break
    for the proxy, a renumbered SNMP token). Each pass only replaces text with redaction
    tokens; a result that does not settle is withheld.
    """
    for _ in range(8):
        again = str.__str__(_response_chain(text, secrets, _redact_current))
        if again == text:
            return text
        text = again
    raise ValueError('redaction could not be verified; output withheld')


def _same_shape(original, released) -> bool:
    if isinstance(original, dict):
        return (isinstance(released, dict) and len(original) == len(released)
                and all(_same_shape(a, b) for a, b in zip(original.values(), released.values())))
    if isinstance(original, list):
        return (isinstance(released, list) and len(original) == len(released)
                and all(_same_shape(a, b) for a, b in zip(original, released)))
    if isinstance(original, str):
        return isinstance(released, str)
    return type(original) is type(released) and original == released


def _json_value_floor(text: str, floor: list, released) -> list:
    """The floor of a JSON document reduced to string-token contents (task 302).

    When the complete 1.0.8 chain re-serializes a document (e.g. the product
    rule replaces `set password x` inside a value that holds a CLI account
    line), every character it wrote anew counts as hidden: the document
    punctuation, whitespace, numbers, booleans and null. A floor range between
    string tokens cannot follow JSON decoding, so the current chain would
    withhold the whole output. Such a range hides nothing if the 1.0.8 result is
    still a JSON document of the same shape: the same containers and lengths,
    strings in place of strings and equal numbers, booleans and null. Then the
    characters outside string-token contents (including the token quotes) leave
    the floor; every character of a key or a string value that 1.0.8 hid stays
    in it. Otherwise (a legacy rule consumed a quote, a separator or a sibling
    value, or changed a number or a literal) the floor is returned unchanged and
    the output is withheld as before.

    A string that holds a JSON document, which the proxy decodes and may
    re-serialize as well, is reduced the same way when the 1.0.8 result holds a
    document of the same shape at the same place (task 302-r2): only the contents
    of its own string tokens keep their floor, at any depth. Otherwise that string
    keeps its floor on all of its contents, as before, and a range on the nested
    document's punctuation still withholds the output.
    """
    if text.lstrip()[:1] not in ("{", "[") or released is None:
        return floor
    tokens = [(match.start(), match.end()) for match in _spans._JSON_STRING.finditer(text)]
    # Only a floor between string tokens, or on a string that holds a JSON document,
    # makes the current chain withhold the output.
    if (not any(True for start, end in floor for _ in _outside(text, start, end, tokens))
            and not any(_json_container(json.loads(text[a:b])) is not None
                        for a, b in (tokens[index] for index in _touched(tokens, floor)))):
        return floor
    from .proxy_sanitize import _unique_pairs
    try:
        original = json.loads(text, object_pairs_hook=_unique_pairs)
        result = json.loads(str.__str__(released), object_pairs_hook=_unique_pairs)
        if not isinstance(original, (dict, list)) or not _same_shape(original, result):
            return floor
        contents = _content_ranges(text, original, result)
    except (ValueError, RecursionError):
        return floor
    reduced = []
    for start, end in floor:
        # Index iteration, no copy of the remaining list per floor range (task 302-r2).
        for index in range(max(bisect.bisect_right(contents, (start, len(text) + 1)) - 1, 0), len(contents)):
            content_start, content_end = contents[index]
            if content_start >= end:
                break
            a, b = max(start, content_start), min(end, content_end)
            if a < b:
                reduced.append((a, b))
    return reduced


def _json_container(text):
    """The JSON object or array a string holds, decoded as the proxy decodes it, else None."""
    if not isinstance(text, str) or str.lstrip(text)[:1] not in ("{", "["):
        return None
    from .proxy_sanitize import _unique_pairs
    try:
        value = json.loads(str.__str__(text), object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _string_pairs(original, released):
    """The strings of a document and of its same-shape 1.0.8 result in token order (key, then value)."""
    if isinstance(original, dict):
        for (key, value), (other_key, other) in zip(original.items(), released.items()):
            yield key, other_key
            yield from _string_pairs(value, other)
    elif isinstance(original, list):
        for value, other in zip(original, released):
            yield from _string_pairs(value, other)
    elif isinstance(original, str):
        yield original, released


def _content_ranges(text: str, original, released) -> list:
    """Sorted offsets of ``text`` that may keep a floor: string-token contents, and inside
    a string holding a JSON document of the same shape in both, only its string contents."""
    ranges = []
    for match, (value, other) in zip(_spans._JSON_STRING.finditer(text), _string_pairs(original, released)):
        nested, other_nested = _json_container(value), _json_container(other)
        if nested is not None and other_nested is not None and _same_shape(nested, other_nested):
            bounds = _spans._boundaries(match.group())
            ranges.extend((match.start() + bounds[a], match.start() + bounds[b])
                          for a, b in _content_ranges(value, nested, other_nested))
        else:
            ranges.append((match.start() + 1, match.end() - 1))
    return ranges


def _touched(spans: list, ranges: list) -> list:
    """Indexes of the sorted, disjoint ``spans`` that meet any of the sorted ``ranges``."""
    found = []
    for start, end in ranges:
        for index in range(max(bisect.bisect_right(spans, (start, float("inf"))) - 1, 0), len(spans)):
            if spans[index][0] >= end:
                break
            if spans[index][1] > start and (not found or found[-1] != index):
                found.append(index)
    return found


def _outside(text: str, start: int, end: int, spans: list):
    """Characters of text[start:end] outside the sorted, disjoint ``spans``."""
    position = start
    for index in range(max(bisect.bisect_right(spans, (start, len(text) + 1)) - 1, 0), len(spans)):
        span_start, span_end = spans[index]
        if span_start >= end:
            break
        if span_end <= position:
            continue
        yield from text[position:max(position, span_start)]
        position = max(position, span_end)
    if position < end:
        yield from text[position:end]


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# EOS can show the v1/v2c community as a notification destination's "user".
# Preserve only the documented status grammar before logging, hashing or paging.
_EOS_HOST = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}"
_EOS_VRF = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}"
_EOS_READ_REFUSAL = re.compile(
    r"(?:%(?: Invalid input(?: \(privileged mode required\))?| (?:Incomplete command|"
    r"Ambiguous command|Authorization denied|Authorization failed|Permission denied))"
    r"(?: at line [0-9]+)?|" + EOS_UNAVAILABLE_LINE + r")", re.I,
)
_EOS_BACKEND_COUNTER = (
    r"(?:Connection (?:opens|closes|disconnects|failures|timeouts)|"
    r"Messages (?:sent|received)|Requests (?:accepted|rejected|timeout|retransmitted)|"
    r"Bad responses|Receive (?:errors|timeouts)|Send (?:timeouts|failures)|"
    r"(?:Access|Accounting)-(?:Requests|Accepts|Rejects|Challenges|Responses)|"
    r"Retransmissions|Timeouts|Malformed responses|Bad authenticators|"
    r"Pending requests|Unknown types|Packets dropped)[ \t]*:[ \t]+[0-9]+"
)
_EOS_MANAGEMENT_STATUS = {
    "radius": (
        rf"RADIUS server[ \t]*:[ \t]+{_EOS_HOST}(?:/[0-9]+)?|"
        rf"server[0-9]+:[ \t]+{_EOS_HOST}|"
        rf"No (?:RADIUS )?servers (?:configured|defined)\.?|{_EOS_BACKEND_COUNTER}|"
        r"Last time counters were cleared: (?:never|[0-9]+(?: days?,)? [0-9:]+ ago|[0-9:]+ ago)"
    ),
    "radius_status": (
        r"Probe method: (?:Disabled|Status-Server packet|Access-Request packet)|"
        r"RADIUS Server[ \t]+Messages Sent[ \t]+Messages Accepted[ \t]+Messages Dropped[ \t]+Status|"
        r"[- \t]+|"
        rf"{_EOS_HOST}[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+(?:alive|not alive)"
    ),
    "tacacs": (
        rf"TACACS\+? server[ \t]*:[ \t]+{_EOS_HOST}(?:/[0-9]+)?|"
        rf"No (?:TACACS\+? )?servers (?:configured|defined)\.?|{_EOS_BACKEND_COUNTER}|"
        r"Last time counters were cleared: (?:never|[0-9]+(?: days?,)? [0-9:]+ ago|[0-9:]+ ago)"
    ),
    "snmp_status": (
        rf"SNMP agent enabled in VRFs: {_EOS_VRF}(?:[ \t,]+{_EOS_VRF})*|"
        r"SNMP agent (?:enabled|disabled)(?:: Either no communities and no users are configured, or no VRFs are configured\.)?|"
        r"SNMP logging: (?:enabled|disabled)|"
        r"[0-9]+ (?:SNMP packets (?:input|output)|Bad SNMP version errors|Unknown community name|"
        r"Illegal operation for community name supplied|Encoding errors|Number of (?:requested|altered) variables|"
        r"(?:Get-request|Get-next|Set-request|Response|Trap) PDUs|"
        r"(?:Too big|No such name|Bad value|General) errors)"
    ),
    "snmp_targets": (
        rf"Notification host: {_EOS_HOST}[ \t]+udp-port: [0-9]{{1,5}}[ \t]+"
        r"type: (?:trap|inform)[ \t]+refresh: (?:True|False)|"
        r"No (?:SNMP )?(?:notification )?hosts (?:configured|defined)\.?"
    ),
    # DHCP option payloads and TFTP URLs may contain credentials.
    "dhcp_server": (
        r"IPv[46] DHCP server is (?:active|inactive)|"
        r"Client ID echo: (?:enabled|disabled)|"
        r"Lease duration: [0-9]+ days? [0-9]+ hours? [0-9]+ minutes?|Active leases: [0-9]+|"
        r"IPv[46] DHCP interface status:|Interface[ \t]+Status|[- \t]+|"
        rf"{_EOS_VRF}[ \t]+(?:Active|Inactive)(?: \((?:Could not determine VRF|"
        r"Not in default VRF|Kernel interface not created yet|Not up|No IP address|"
        r"No Link Local address|DHCP relay is configured for this interface|DHCP relay is always on)\))?|"
        r"Subnet: [0-9a-f:.]+/[0-9]{1,3}(?: \(Subnet is disabled\))?|"
        rf"Subnet name:(?:[ \t]+{_EOS_VRF})?|"
        r"(?:Range|Overlapping range): [0-9a-f:.]+ to [0-9a-f:.]+|"
        r"(?:IPv[46] address|Duplicate IPv[46] address reservation): [0-9a-f:.]+|"
        r"MAC address: [0-9a-f.:-]+|Reservations:|Disabled reason\(s\):|"
        r"Overlapping subnets: [0-9a-f:.]+/[0-9]{1,3}(?:[, \t]+[0-9a-f:.]+/[0-9]{1,3})*"
    ),
    # AAA-returned attributes can contain arbitrary provider data. Keep the local
    # authentication diagnosis and VLAN fields without passing those attributes through.
    "dot1x_clients": (
        rf"Interface(?: host details)?: {_EOS_VRF}|Operational:|"
        r"Supplicant MAC: [0-9a-f.:-]+|Supplicant IP: [0-9a-f:.]+(?: sourceLldp)?|"
        r"(?:Authentication method|Supplicant state|Fallback Applied): [A-Za-z0-9_-]+|"
        r"VLAN ID: [0-9]{1,4}(?: \((?:static|dynamic)\))?|"
        rf"VLAN Name: {_EOS_VRF}"
    ),
    "logging_status": (
        r"Syslog logging: (?:enabled|disabled)|"
        r"(?:Buffer|Console|Monitor|Persistent|Trap) logging: (?:disabled|level "
        r"(?:emergencies|alerts|critical|errors|warnings|notifications|informational|debugging))|"
        rf"Logging to (?:'{_EOS_HOST}'|{_EOS_HOST}) port [0-9]{{1,5}} in VRF {_EOS_VRF} via (?:udp|tcp|tls)"
    ),
}
_EOS_MANAGEMENT_STATUS = {query: re.compile(pattern, re.I) for query, pattern in _EOS_MANAGEMENT_STATUS.items()}


def eos_management_status(query: str, output: str) -> str:
    """Project status-only EOS reads onto fixed fields; unknown lines stay private."""
    pattern = _EOS_MANAGEMENT_STATUS.get(query)
    if pattern is None or not output.strip():
        return output
    kept = []
    for line in output.splitlines():
        line = line.strip()
        if len(line) <= 512 and (pattern.fullmatch(line) or _EOS_READ_REFUSAL.fullmatch(line)):
            kept.append(line)
    return "\n".join(kept) + ("\n" if kept else "")
