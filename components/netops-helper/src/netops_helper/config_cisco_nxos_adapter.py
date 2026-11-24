"""Cisco NX-OS identity/profile adapter for the public ``config_read`` (verification).

Same shape as the Cisco IOS XE and Arista EOS adapters.  The tested combination is Nexus 9000v
``cisco Nexus9000 C9300v Chassis`` with ``NXOS: version 9.3(12)``
(``tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12/version.txt``).  Another model or release is read too
and reported as ``firmware_support`` ``untested`` with a warning (startup, decision of 2026-11-17).  The identity is read only from
three lines of ``show version``, each of which must occur exactly once: the software header ``Cisco
Nexus Operating System (NX-OS) Software``, the release line (``NXOS: version`` or legacy ``system: version``)
and the hardware line ``cisco <model> Chassis``; never from the image file name, serial numbers, package names
or host names.  The running configuration goes through the indentation-based
``config_indented.NxosStreamRedactor`` (verification: two-space indentation allowlist, every other line one
``NXOS_MARKER``, the ``!Command: show running-config`` frame required).  NX-OS prints no ``end``, so
completeness is never claimed.  A tested identity does not verify account rights, the full-config
format or complete redaction.
"""

import hashlib
import json
import re

from netops_core import tested
from netops_core.nxos_config import IDENTITY_MAX_BYTES, firmware_record, line_count, version_identity

from .config_indented import NXOS_MARKER, NxosStreamRedactor
from .configuration import ConfigurationRefusedError

PLATFORM = 'cisco_nxos'
COMMAND = 'show running-config'
STARTUP_COMMAND = 'show startup-config'
DIFF_COMMAND = 'show running-config diff'
LIVE_DIFF = ('startup', 'running')
IDENTITY_COMMANDS = ('show version',)
# The identity config_read was tested on (startup: a list of tested identities, not a gate).
TESTED = ('Nexus9000 C9300v', '9.3(12)')
TESTED_NAME = 'Cisco NX-OS'

POLICY_DESCRIPTOR = (PLATFORM, 'config_indented.NxosStreamRedactor', 'nxos-indent-allowlist-1', NXOS_MARKER,
                     COMMAND, IDENTITY_COMMANDS, TESTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufffd]')
_TIMESTAMPS = ('!Running configuration last done at:', '!Startup config saved at:', '!Time:')
_DIFF_OLD_RANGE = re.compile(r'\*\*\* ([0-9]{1,8})(?:,([0-9]{1,8}))? \*\*\*\*')
_DIFF_NEW_RANGE = re.compile(r'--- ([0-9]{1,8})(?:,([0-9]{1,8}))? ----')
_PAGER = re.compile(r'--\s*More\s*--', re.I)


class ComparisonRedactor(NxosStreamRedactor):
    """Require a matching source frame and line count, then compare the redacted body."""

    def __init__(self, forbidden, section, *, limits, command, expected_lines):
        super().__init__(forbidden, section, limits=limits)
        self._header = '!Command: ' + command
        self._expected_lines = expected_lines
        self._comparison_frame = 'header'

    def _logical(self, line, end):
        if self._comparison_frame == 'body':
            super()._logical(line, '\n')
            return
        if not line.strip(' '):
            return
        if line.startswith('%') or line == 'Cmd exec error.':
            raise ConfigurationRefusedError()
        if self._comparison_frame == 'header':
            if line.rstrip(' ') != self._header:
                raise self._failure('stream-incomplete')
            self._comparison_frame = 'metadata'
            return
        if line.startswith(_TIMESTAMPS):
            return
        self._comparison_frame = self._phase = 'body'
        super()._logical(line, '\n')

    def _complete(self):
        return self._comparison_frame == 'body' and self._line_number == self._expected_lines


def _diff_range(pattern, line):
    match = pattern.fullmatch(line)
    if not match:
        return None
    first, last = match.groups()
    start = int(first)
    if last is None:
        return int(start != 0)
    return int(last) - start + 1 if start and int(last) >= start else None


def native_diff_status(output):
    """Read the status of a measured NX-OS context diff without retaining its text."""
    if not output.strip(' \t\r\n'):
        return False
    if not output.endswith('\n') or _CONTROL.search(output) or _PAGER.search(output):
        return None
    lines = output.replace('\r\n', '\n').split('\n')[:-1]
    if lines[:2] != ['*** Startup-config', '--- Running-config']:
        return None
    index = 2
    while index < len(lines):
        if lines[index] != '***************' or index + 2 >= len(lines):
            return None
        before = _diff_range(_DIFF_OLD_RANGE, lines[index + 1])
        if before is None:
            return None
        index += 2
        removed = 0
        # The context format omits one side's rows for a pure addition or deletion.
        if not _DIFF_NEW_RANGE.fullmatch(lines[index]):
            for _ in range(before):
                if index >= len(lines) or lines[index][:2] not in ('  ', '- ', '! '):
                    return None
                removed += lines[index][:2] != '  '
                index += 1
        if index >= len(lines) or (after := _diff_range(_DIFF_NEW_RANGE, lines[index])) is None:
            return None
        index += 1
        added = 0
        if index < len(lines) and lines[index] != '***************':
            for _ in range(after):
                if index >= len(lines) or lines[index][:2] not in ('  ', '+ ', '! '):
                    return None
                added += lines[index][:2] != '  '
                index += 1
        elif after != before - removed:
            return None
        if not (removed or added) or after - before != added - removed:
            return None
    return True if len(lines) > 2 else None


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_nxos supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def verify_identity(version):
    """Firmware record (model, release) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity.  A consistent identity of another model or release
    is returned as well; firmware_support() tells whether it is the tested one.
    """
    return version_identity(version), metadata()


def firmware_support(firmware):
    """The firmware_support structure (netops_core.tested) of a firmware record against the tested identity."""
    model, release = firmware
    return tested.support(TESTED_NAME, release, [TESTED], model=model, function='config_read')


def metadata():
    return {'config_scope': 'device-account-visible', 'configuration_complete': False,
            'identity_scope_verified': False, 'visibility_limitations': list(VISIBILITY)}


def assess(metadata_fields, summary):
    """Add the consumer summary and the limitation names it implies; inputs are never mutated.

    Whatever the input says, the result never claims a complete configuration or a verified identity,
    and carries each required limitation (VISIBILITY) exactly once; other notes are kept.
    """
    fields = dict(metadata_fields)
    limits = []
    for name in fields['visibility_limitations']:
        if name not in VISIBILITY or name not in limits:
            limits.append(name)
    fields.update(summary)
    fields['configuration_complete'] = False
    fields['identity_scope_verified'] = False
    if fields['unverified_count'] > fields['unsupported_format_count'] and 'schema-fields-unverified' not in limits:
        limits.append('schema-fields-unverified')
    for name in VISIBILITY:
        if name not in limits:
            limits.append(name)
    fields['visibility_limitations'] = limits
    return fields
