"""Small text adapters above the canonical query catalogue; no transport or CLI list."""
from __future__ import annotations

import re

# One profile per OS; the device type (switch/router/firewall) is an inventory
# attribute that only enables template groups, never an identity check.
IDENTITY_PROFILES = frozenset({
    "extreme_exos", "cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos",
    "juniper_junos", "juniper_junos_els",
})
IDENTITY_FIELDS = ("hostname", "model", "serial_number", "os_version", "uptime")


class IdentityError(ValueError):
    """Stable, non-output-bearing refusal reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _one(text: str, pattern: str) -> str | None:
    values = set(re.findall(pattern, text, re.MULTILINE | re.IGNORECASE))
    if len(values) > 1:
        raise IdentityError("identity_ambiguous")
    return next(iter(values)).strip() if values else None


def _optional(text: str, pattern: str, field: str, warnings: list[str] | None) -> str | None:
    """Descriptive field: an unreadable or conflicting value is a warning, never a refusal."""
    try:
        return _one(text, pattern)
    except IdentityError:
        if warnings is not None:
            warnings.append("identity_" + field + "_ambiguous")
        return None


def _junos_first_member(output: str) -> str:
    """Virtual chassis / dual RE print one block per member; use the first (fpc0/re0)."""
    parts = re.split(r"(?mi)^(?:fpc|re)[0-9]+:[ \t]*\r?$", output)
    return next((part for part in parts[1:] if part.strip()), output) if len(parts) > 1 else output


def _nxos_sku(chassis: str | None) -> str | None:
    """Keep the SKU only: 'Nexus9000 C9336C-FX2' -> 'C9336C-FX2'; 'Nexus5548' stays."""
    match = re.match(r"(?i)nexus[ \t]*[0-9]*[ \t]+(\S+)", chassis or "")
    return match[1] if match else chassis


def parse_identity(profile: str, output: str, warnings: list[str] | None = None) -> dict:
    """Require an OS signature and version; read model, serial and uptime as data only.

    Only the operating system is verified. The hardware model never decides
    whether a device may be read; an unreadable model is reported by the caller.
    """
    record = dict.fromkeys(IDENTITY_FIELDS)
    if profile in {"cisco_ios", "cisco_xe"}:
        xe = re.search(r"(?mi)^Cisco IOS (?:XE Software|Software, IOS[ -]XE|Software \[IOSXE\],)", output)       # IOL (17.18) prints only the last form
        ios = re.search(r"(?mi)^Cisco IOS Software,", output)
        if not (xe if profile == "cisco_xe" else ios and not xe):
            raise IdentityError("identity_os_mismatch")
        record.update(
            os_version=_one(output, r"^Cisco IOS XE Software, Version[ \t]+(\S+)" ) if xe else None,
            model=_optional(output, r"^cisco[ \t]+(\S+)[ \t]+\([^)\r\n]*\)[ \t]+(?:processor|with)\b", "model", warnings),
            serial_number=_optional(output, r"^Processor [Bb]oard ID[ \t]+(\S+)", "serial_number", warnings),
            hostname=_optional(output, r"^[ \t]*(\S+) uptime is .+$", "hostname", warnings),
            uptime=_optional(output, r"^[ \t]*\S+ uptime is (.+)$", "uptime", warnings),
        )
        if not record["os_version"]:
            record["os_version"] = _one(output, r"^Cisco IOS Software(?:,| \[[^\]\r\n]+\],).*?\bVersion[ \t]+([^, \t\r\n]+)")
    elif profile == "cisco_nxos":
        if not re.search(r"(?mi)^Cisco (?:Nexus Operating System \(NX-OS\) Software|NX-OSv)", output):
            raise IdentityError("identity_os_mismatch")
        record.update(
            os_version=_one(output, r"^[ \t]*(?:NXOS|system):[ \t]+version[ \t]+(\S+)"),
            model=_nxos_sku(_optional(output, r"^[ \t]*cisco[ \t]++(\S(?:.*?\S)?)[ \t]++[Cc]hassis\b", "model", warnings)),
            serial_number=_optional(output, r"^[ \t]*Processor Board ID[ \t]+(\S+)", "serial_number", warnings),
            hostname=_optional(output, r"^[ \t]*Device name:[ \t]*(\S+)", "hostname", warnings),
            uptime=_optional(output, r"^Kernel uptime is (.+)$", "uptime", warnings),
        )
    elif profile == "arista_eos":
        record.update(
            model=_optional(output, r"^Arista[ \t]+(\S+)(?:[ \t].*)?$", "model", warnings),
            os_version=_one(output, r"^Software image version:[ \t]*(\S+)"),
            serial_number=_optional(output, r"^Serial number:[ \t]*(\S+)", "serial_number", warnings),
            uptime=_optional(output, r"^Uptime:[ \t]*(.+)$", "uptime", warnings),
        )
        if not re.search(r"(?m)^Arista[ \t]+\S", output):
            raise IdentityError("identity_os_mismatch")
    elif profile.startswith("juniper_junos"):
        member = _junos_first_member(output)
        record.update(
            hostname=_optional(member, r"^Hostname:[ \t]*(\S+)", "hostname", warnings),
            model=_optional(member, r"^Model:[ \t]*(\S+)", "model", warnings),
            os_version=_one(member, r"^Junos:[ \t]*(\S+)"),
        )
        if not record["os_version"]:
            record["os_version"] = _one(output, r"^JUNOS (?:Software Release|Base OS boot)[ \t]+\[([^\]]+)\]")
        if not record["os_version"]:
            raise IdentityError("identity_os_mismatch")
    elif profile == "extreme_exos":
        record.update(
            os_version=_one(output, r"^[ \t]*Image[ \t]*:[ \t]*ExtremeXOS version[ \t]+(\S+)"),
            serial_number=_optional(output, r"^Switch[ \t]*:[ \t]*\S+[ \t]+(\S+)[ \t]+Rev\b", "serial_number", warnings),
            model=_optional(output, r"^[ \t]*(?:System Type|Platform|Switch Model)[ \t]*:[ \t]*(\S+)", "model", warnings),
        )
        if not record["os_version"]:
            raise IdentityError("identity_os_mismatch")
    else:
        raise IdentityError("identity_unsupported")
    if not record["os_version"] or not re.fullmatch(r"[0-9][A-Za-z0-9_.()+:-]*", record["os_version"]):
        raise IdentityError("identity_unparsed")
    return record


def identity_supplements(profile: str) -> tuple[str, ...]:
    """Catalogue query names, never a second collection of commands."""
    return {
        "extreme_exos": ("switch",),
        "arista_eos": ("hostname",),
        "juniper_junos": ("hardware", "uptime"),
        "juniper_junos_els": ("hardware", "uptime"),
    }.get(profile, ())


def supplement_identity(record: dict, query: str, output: str) -> None:
    patterns = {
        "switch": {"hostname": r"^SysName:[ \t]*(\S+)", "model": r"^System Type:[ \t]*(\S+)", "uptime": r"^System UpTime:[ \t]*(.+)$"},
        "hostname": {"hostname": r"^(?:Hostname:[ \t]*|[ \t]*Hostname:[ \t]*)(\S+)"},
        "hardware": {"serial_number": r"^Chassis[ \t]+(\S+)[ \t]+.+$"},
        "uptime": {"uptime": r"^System booted:.*?\((.+?) ago\)"},
    }
    for field, pattern in patterns.get(query, {}).items():
        value = _one(output, pattern)
        if value:
            if record[field] and record[field] != value:
                raise IdentityError("identity_ambiguous")
            record[field] = value


def normalize_mac(value: str) -> str:
    """Normalize colon, hyphen, Cisco dotted and twelve-hex MAC spellings."""
    if not isinstance(value, str) or not re.fullmatch(
        r'(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|'
        r'(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})', value
    ):
        raise ValueError('invalid MAC literal')
    digits = re.sub(r'[:.\-]', '', value).lower()
    return ':'.join(digits[index:index + 2] for index in range(0, 12, 2))


def normalize_port(value: str) -> dict:
    """Canonical comparison key plus explicit parent; logical units stay distinct.

    This is for correlating observed names, not authorizing command arguments.
    Aggregates across different vendors must not be merged by their numeric ID.
    `kind` is physical, aggregate, or other: a safe name that is not a physical
    port (Vlan10, Loopback0, mgmt0, irb.10) is returned unchanged as "other".
    """
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:/.-]{0,63}', value):
        raise ValueError('invalid port name')
    aliases = {
        'gi': 'GigabitEthernet', 'gigabitethernet': 'GigabitEthernet',
        'fa': 'FastEthernet', 'fastethernet': 'FastEthernet',
        'te': 'TenGigabitEthernet', 'tengigabitethernet': 'TenGigabitEthernet',
        'twe': 'TwentyFiveGigE', 'twentyfivegige': 'TwentyFiveGigE',
        'fo': 'FortyGigabitEthernet', 'fortygigabitethernet': 'FortyGigabitEthernet',
        'hu': 'HundredGigE', 'hundredgige': 'HundredGigE',
        'tw': 'TwoGigabitEthernet', 'twogigabitethernet': 'TwoGigabitEthernet',
        'eth': 'Ethernet', 'et': 'Ethernet', 'ethernet': 'Ethernet',
        'po': 'Port-channel', 'port-channel': 'Port-channel',
        'ma': 'Management', 'management': 'Management',
        'lag': 'lag', 'ae': 'ae',
    }
    match = re.fullmatch(r'([A-Za-z-]+)([0-9]+(?:/[0-9]+){0,3})(\.[0-9]+)?', value)
    canonical = value
    aggregate = False
    kind = 'physical'
    if match and match[1].lower() in aliases:
        prefix = aliases[match[1].lower()]
        canonical = prefix + match[2] + (match[3] or '')
        aggregate = prefix in {'Port-channel', 'lag', 'ae'}
        kind = 'aggregate' if aggregate else 'other' if prefix == 'Management' else 'physical'
    elif not re.fullmatch(r'(?:[1-9][0-9]*(?::[1-9][0-9]*){0,2}|(?:ge|xe|et|fe|mge)-[0-9]+/[0-9]+/[0-9]+(?::[0-9]+)?(?:\.[0-9]+)?)', value):
        # Vlan10, Loopback0, mgmt0, irb.10 ...: safe but not a physical port; compare as written.
        return {'name': value, 'physical': value, 'unit': None, 'aggregate': False, 'kind': 'other'}
    parent, separator, unit = canonical.partition('.')
    return {'name': canonical, 'physical': parent, 'unit': int(unit) if separator else None, 'aggregate': aggregate, 'kind': kind}


RESULT_STATES = frozenset({
    'ok', 'empty', 'not_applicable', 'unsupported', 'permission_denied',
    'unparsed', 'truncated', 'timeout', 'transport_error',
})
# Explicit authorization/permission refusals of every CLI.
_PERMISSION = re.compile(
    r'(?mi)^[^\S\n]*(?:%\s*(?:Authorization failed|Authorization denied|Permission denied|Access denied)'
    r'|This user does not have permissions for this command'
    r'|error:\s*permission denied'
    r'|Line has invalid autocommand'
    r'|Error:\s*(?:Permission denied|You do not have))'
)
# IOS/IOS XE hide commands outside the read-only view behind a plain syntax error.
_IOS_INVALID_INPUT = re.compile(r'(?mi)^[^\S\n]*%\s*Invalid input')
_UNSUPPORTED = re.compile(
    r'(?mi)^[^\S\n]*(?:Method is not implemented on this platform\.'
    r'|%{1,2}\s*(?:Unrecognized command|Incomplete command|Ambiguous command|Invalid command|Invalid input)'
    r'|error:\s*(?:unknown command|syntax error|the [a-z0-9-]+ subsystem is not running)'
    r'|Syntax error while parsing)'
)


# A protocol that is not configured answers with a plain notice (IOS "% BGP not active", EOS "% BGP inactive",
# EOS "! IPv6 routing not enabled", Junos "BGP is not running", "Spanning-tree is not enabled at global level"
# and "warning: lacp subsystem not running - not needed by configuration.").
_NOT_CONFIGURED = re.compile(r'(?mi)^[^\S\n]*(?:%\s*BGP (?:not active|inactive)\b|!\s*IPv6 routing not enabled\b|BGP is not running\b'
                             r'|Spanning-tree is not enabled at global level\b'
                             r'|warning: [a-z0-9-]+ subsystem not running - not needed by configuration\b)')


# Device refusal patterns search the complete output at line boundaries, as in 1fad86c.
# Table data with parsed records is handled separately by tables.parse.
_EXOS_ERROR_MARKS = re.compile(r'(?m)^[ \t]*(?:%% |Error:|Invalid input|Incomplete command)')
# A final standalone prompt permits trailing blank lines. An appended prompt
# must end the capture without a following newline, as in 1fad86c.
_PAGER_MARK = r'(?:--More--|---\(more(?: [0-9]+%)?\)---)'
_PAGER = re.compile(r'(?i)' + _PAGER_MARK + r'[ \t\r]*+\Z')
_PRESS_PAGER = re.compile(r'(?i)Press <SPACE> to continue')


def _terminal_pager(output: str) -> bool:
    # Bound all searches to one line, including Press prompts with arbitrary
    # trailing words; repeated prefixes before later data remain linear.
    tail = output.rstrip(' \t\r\n')
    line = tail[tail.rfind('\n') + 1:]
    standalone = line.lstrip(' \t')
    if _PAGER.fullmatch(standalone) or (_PRESS_PAGER.match(standalone) and '\r' not in standalone):
        return True
    if '\n' in output[len(tail):]:
        return False
    # A carriage return is not a multiline anchor, but it ends the Press
    # grammar. Search only its final segment to avoid repeated-prefix scans.
    return _PAGER.search(line) is not None or _PRESS_PAGER.search(line[line.rfind('\r') + 1:]) is not None


def exos_exit_250(profile: str | None, rc: int | None, output: str, command: str | None = None) -> bool:
    """ExtremeXOS ends some complete, successful show commands with exit status 250."""
    return (profile == 'extreme_exos' and rc == 250 and bool(output.strip())
            and _EXOS_ERROR_MARKS.search(output) is None)


def output_status(output: str, *, rc: int | None = 0, truncated: bool = False, profile: str | None = None, command: str | None = None) -> str:
    """`truncated` is for a capture limit; a paged but complete capture is not truncated."""
    if truncated or _terminal_pager(output):
        return 'truncated'
    if _PERMISSION.search(output) or (profile in {'cisco_ios', 'cisco_xe'} and _IOS_INVALID_INPUT.search(output)):
        return 'permission_denied'
    if _UNSUPPORTED.search(output):
        return 'unsupported'
    if _NOT_CONFIGURED.search(output):
        return 'not_applicable'
    if rc not in (0, None) and not exos_exit_250(profile, rc, output):
        return 'transport_error'
    return 'ok' if output.strip() else 'empty'


def response_envelope(profile: str, status: str, sources: list[dict], *, identity: dict | None = None,
                      warnings: list[str] | None = None, identity_coverage: bool = True) -> dict:
    """Identity coverage belongs to the `version` envelope only; other queries carry none."""
    from datetime import datetime, timezone
    if status not in RESULT_STATES:
        raise ValueError('unknown result status')
    parsed = [field for field in IDENTITY_FIELDS if identity and identity[field] is not None]
    if identity_coverage:
        coverage = {'complete': status == 'ok' and len(parsed) == len(IDENTITY_FIELDS),
                    'parsed_fields': parsed,
                    'missing_fields': [field for field in IDENTITY_FIELDS if field not in parsed]}
    else:
        coverage = {'complete': False, 'parsed_fields': [], 'missing_fields': []}
    return {
        'schema_version': 1, 'profile': profile,
        'captured_at': datetime.now(timezone.utc).isoformat(), 'status': status,
        'identity': identity, 'sources': sources,
        'coverage': coverage,
        'warnings': list(warnings or []),
    }


def source_record(query: str, output: str, status: str) -> dict:
    import hashlib
    return {'query': query, 'content_sha256': hashlib.sha256(output.encode('utf-8')).hexdigest(), 'status': status}


_EXPLICIT_RO_REFUSAL = r"(?:Authorization failed|Authorization denied|Permission denied|Access denied)"
_CISCO_RO_REFUSAL = re.compile(r"(?mi)^[ \t]*%[ \t]*" + _EXPLICIT_RO_REFUSAL + r"[^\r\n]*\r?$")
# IOS/IOS XE read-only views answer a hidden command with "% Invalid input".
_IOS_RO_REFUSAL = re.compile(r"(?mi)^[ \t]*%[ \t]*(?:Invalid input|" + _EXPLICIT_RO_REFUSAL + r")[^\r\n]*\r?$")
_JUNOS_RO_REFUSAL = re.compile(r"(?mi)^[ \t]*error: permission denied(?::[^\r\n]*)?[ \t]*\r?$")


# IOS/IOS XE answer a command outside the account's view and a command the image does not have (a router image
# without switching commands) with the same line. The status stays permission_denied; the hint names both causes.
_IOS_REFUSED_OR_ABSENT = re.compile(r'(?mi)^[ \t]*(?:Line has invalid autocommand|%[ \t]*Invalid input)')
IOS_REFUSAL_HINT = ('The command was refused by the account or does not exist on this image'
                    ' (for example a router image without switching commands)')


def refusal_hint(profile: str | None, output: str, command: str | None = None) -> str | None:
    """Explains a permission_denied that may also mean the command is absent on this image."""
    if profile in {"cisco_ios", "cisco_xe"} and _IOS_REFUSED_OR_ABSENT.search(output):
        return IOS_REFUSAL_HINT
    return None


def permission_refused(profile: str, output: str, command: str | None = None) -> bool:
    """Extra RO-account refusals, scoped to the OS that emits them."""
    if profile in {"cisco_ios", "cisco_xe"}:
        return _IOS_RO_REFUSAL.search(output) is not None
    if profile in {"cisco_nxos", "arista_eos"}:
        return _CISCO_RO_REFUSAL.search(output) is not None
    if profile.startswith("juniper_junos"):
        return _JUNOS_RO_REFUSAL.search(output) is not None
    return False


_TEMPLATE_ERROR = re.compile(r"(?mi)^[ \t]*%[ \t]*(?:Incomplete command|Ambiguous command|Invalid command\b)[^\r\n]*\r?$")


def template_refused(profile: str, output: str, command: str | None = None) -> bool:
    """Command not accepted as written (template error or unsupported); not a permission refusal."""
    return profile in {"cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"} and _TEMPLATE_ERROR.search(output) is not None
