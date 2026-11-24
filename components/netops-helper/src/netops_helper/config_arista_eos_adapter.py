"""Arista EOS identity/profile adapter for the public ``config_read`` (tasks 143 and 153).

Same shape as the Cisco IOS XE and IOS adapters.  The tested
combination is model ``cEOSLab`` with EOS ``4.36.1F``
(``tests/fixtures/real/arista_eos/ceos_4.36.1F/version.txt``); another model or release is read too and
reported as ``firmware_support`` ``untested`` with a warning (startup, decision of 2026-11-17).  The model is read only from the
``Arista <model>`` line and the release only from the ``Software image version:`` line of ``show
version``, each of which must occur exactly once; never from image file names, serial numbers or host
names.  The build suffix of the image version (e.g. ``-48405728.4361F (engineering build)``) is not
dropped: the whole image version text is the third element of the firmware record (``build``).  The
configuration goes through the EOS indentation-based redactor. Live comparison captures omit
the verified command-specific header before comparing the redacted configuration bodies.
A tested identity does not verify account rights, the full-config format or complete redaction.
"""

import hashlib
import json
import re

from netops_core import tested

from .config_indented import EOS_MARKER

PLATFORM = 'arista_eos'
COMMAND = 'show running-config'
STARTUP_COMMAND = 'show startup-config'
DIFF_COMMAND = 'show running-config diffs'
LIVE_DIFF = ('startup', 'running')
IDENTITY_COMMANDS = ('show version',)
# The identity config_read was tested on (startup: a list of tested identities, not a gate).
TESTED = ('cEOSLab', '4.36.1F')
TESTED_NAME = 'Arista EOS'
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_indented.EosStreamRedactor', 'eos-indent-allowlist-2', EOS_MARKER,
                     COMMAND, IDENTITY_COMMANDS, TESTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_MODEL = re.compile(r'Arista ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})')
# Release (major.minor.patch[.n] + train letter), optional build suffix and optional build note.
_IMAGE = re.compile(r'Software image version: (([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?[A-Z]{1,2})'
                    r'(?:-[A-Za-z0-9.]{1,64})?(?: \([A-Za-z][A-Za-z ]{0,31}\))?)')
_DIFF_HUNK = re.compile(r'@@ -[0-9]{1,10}(?:,([0-9]{1,10}))? \+[0-9]{1,10}(?:,([0-9]{1,10}))? @@(?: .*)?')


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: arista_eos supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def native_diff_status(output):
    """Return the presence of changes from the measured EOS unified diff, without disclosing it."""
    if not output.strip():
        return False
    if _CONTROL.search(output) or re.search(r'--\s*More\s*--', output, re.I):
        return None
    lines = output.splitlines()
    if (not output.endswith('\n') or len(lines) < 4 or not lines[0].startswith('--- ') or
            not lines[1].startswith('+++ ')):
        return None
    before = after = 0
    hunk = changed = False
    for line in lines[2:]:
        if match := _DIFF_HUNK.fullmatch(line):
            if before or after:
                return None
            before, after = (int(value) if value is not None else 1 for value in match.groups())
            hunk = True
        elif hunk and line[:1] in (' ', '+', '-'):
            before -= line[0] != '+'
            after -= line[0] != '-'
            changed |= line[0] != ' '
            if before < 0 or after < 0:
                return None
        elif not hunk or line != r'\ No newline at end of file':
            return None
    return True if changed and before == after == 0 else None


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


def _one(lines, prefix, pattern):
    """The single line starting with ``prefix``; it must match ``pattern`` completely."""
    found = [line.strip(' \t') for line in lines if line.strip(' \t').startswith(prefix)]
    if len(found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0])
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match


def version_identity(version):
    """(model, release, image version text) from ``show version``; ValueError when not conclusive."""
    lines = _lines(version)
    model = _one(lines, 'Arista', _MODEL).group(1)
    image = _one(lines, 'Software image version', _IMAGE)
    return model, image.group(2), image.group(1)


def firmware_record(firmware):
    """True for a firmware record as verify_identity returns it (model, release, image version text); a
    stored snapshot is read back with it.  The release must be the one the image version text names."""
    if (type(firmware) is not tuple or len(firmware) != 3 or not all(type(item) is str and item for item in firmware)
            or _MODEL.fullmatch('Arista ' + firmware[0]) is None):
        return False
    match = _IMAGE.fullmatch('Software image version: ' + firmware[2])
    return match is not None and match.group(2) == firmware[1]


def verify_identity(version):
    """Firmware record (model, release, image version text) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity.  A consistent identity of another model or release
    is returned as well; firmware_support() tells whether it is the tested one (any build note of the
    tested release counts as tested, as before).
    """
    return version_identity(version), metadata()


def firmware_support(firmware):
    """The firmware_support structure (netops_core.tested) of a firmware record against the tested identity."""
    model, release, _ = firmware
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
