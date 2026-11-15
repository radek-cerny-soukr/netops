"""Cisco NX-OS identity/profile adapter for the public ``config_read`` (task 153).

Same shape as the Cisco IOS XE and Arista EOS adapters.  Only one evidenced combination is admitted:
Nexus 9000v ``cisco Nexus9000 C9300v Chassis`` with ``NXOS: version 9.3(12)``
(``tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12/version.txt``).  The identity is read only from
three lines of ``show version``, each of which must occur exactly once: the software header ``Cisco
Nexus Operating System (NX-OS) Software``, the release line ``NXOS: version <release>`` and the
hardware line ``cisco <model> Chassis``; never from the image file name, serial numbers, package names
or host names.  The running configuration goes through the indentation-based
``config_indented.NxosStreamRedactor`` (task 147: two-space indentation allowlist, every other line one
``NXOS_MARKER``, the ``!Command: show running-config`` frame required).  NX-OS prints no ``end``, so
completeness is never claimed.  Supported identity does not verify account rights, the full-config
format or complete redaction.
"""

import hashlib
import json
import re

from .config_indented import NXOS_MARKER

PLATFORM = 'cisco_nxos'
COMMAND = 'show running-config'
IDENTITY_COMMANDS = ('show version',)
SUPPORTED = ('Nexus9000 C9300v', '9.3(12)')
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_indented.NxosStreamRedactor', 'nxos-indent-allowlist-1', NXOS_MARKER,
                     COMMAND, IDENTITY_COMMANDS, SUPPORTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_HEADER_TEXT = 'Cisco Nexus Operating System (NX-OS) Software'
_HEADER = re.compile(re.escape(_HEADER_TEXT))
# Release such as 9.3(12), 10.3(4a) or 7.0(3)I7(9); bounded character classes only.
_RELEASE = re.compile(r'NXOS: version ([0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}[a-z]?\)'
                      r'(?:[A-Z][0-9]{1,2}\([0-9]{1,3}[a-z]?\))?)')
_HARDWARE = re.compile(r'cisco (Nexus ?[0-9]{1,5} [A-Za-z0-9-]{1,32}) [Cc]hassis(?: \([^()]{1,64}\))?')


class UnsupportedNxosFirmware(ValueError):
    """The live identity is consistent but is not the single admitted model and release."""


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_nxos supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def _utf8_size(text):
    try:
        return len(text.encode('utf-8'))
    except UnicodeEncodeError:
        return None


def _lines(text):
    size = _utf8_size(text) if type(text) is str else None
    if (size is None or size > IDENTITY_MAX_BYTES or not text.strip() or
            _CONTROL.search(text.replace('\n', '').replace('\r', '').replace('\t', ''))):
        raise ValueError('configuration identity could not be verified')
    return text.replace('\r\n', '\n').replace('\r', '\n').split('\n')


def _one(lines, selector, pattern):
    """The single line selected by ``selector``; it must match ``pattern`` completely."""
    found = [line.strip(' \t') for line in lines if selector(line.strip(' \t'))]
    if len(found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0])
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match


def version_identity(version):
    """(model, release) from ``show version``; ValueError when not conclusive."""
    lines = _lines(version)
    _one(lines, lambda line: line.startswith('Cisco Nexus Operating System'), _HEADER)
    release = _one(lines, lambda line: line.startswith('NXOS: version'), _RELEASE).group(1)
    model = _one(lines, lambda line: line.startswith('cisco ') and 'hassis' in line, _HARDWARE).group(1)
    return model, release


def verify_identity(version):
    """Firmware record (model, release) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity; UnsupportedNxosFirmware: a consistent identity
    outside the single admitted model and release.
    """
    if version_identity(version) != SUPPORTED:
        raise UnsupportedNxosFirmware('configuration firmware-not-supported')
    return SUPPORTED, metadata()


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
