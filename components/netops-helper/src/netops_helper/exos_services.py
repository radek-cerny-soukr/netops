"""Credential removal for EXOS operational service output, before paging/cache."""
from __future__ import annotations

import re


_SECRET_LINE = re.compile(
    r"(?im)^([^\r\n]*\b(?:password|passwd|secret|community|"
    r"(?:shared|private|authentication|privacy)[ -]?key)\b[^:\r\n]*:)[^\r\n]*"
)
_ENC = re.compile(r"\bENC\s+\S+")


def redact_credentials(text: str) -> str:
    """Hide labelled credentials and unlabelled management community tables.

    Target addresses remain available through show snmpv3 target-addr. The
    legacy management receiver table can contain credentials in table cells.
    """
    output = []
    section = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(('Total Read Only Communities', 'Total Read Write Communities')):
            section = True
            output.append(line)
            continue
        if stripped.startswith(('RMON ', 'SNMP stats:')):
            section = False
        if stripped.startswith('SNMP Notification Receivers'):
            section = True
            output.append('SNMP Notification Receivers: [REDACTED; use snmp_targets]\n')
            continue
        if section:
            if stripped:
                output.append('[REDACTED]\n')
            continue
        output.append(line)
    return _ENC.sub('[REDACTED]', _SECRET_LINE.sub(r'\1 [REDACTED]', ''.join(output)))
