"""Cisco IOS XE identity/profile adapter for the public ``config_read`` (task 140).

Same shape as ``config_cisco_ios_adapter``.  Only one evidenced combination is admitted: IOL-XE
``Version 17.18.2``, ``RELEASE SOFTWARE (fc3)``, image family ``X86_64BI_LINUX-ADVENTERPRISEK9-M``
(``tests/fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``).  The model is read from the ``[IOSXE]``
header and the separate hardware line of ``show version`` only, never from file names, serial numbers
or host names.  The header may be repeated verbatim; two different headers are never admitted.  The
running configuration goes through the unchanged ``config_cisco_ios.StreamRedactor`` (same line syntax;
unknown or opaque blocks are refused by it).  Supported identity does not verify account rights, the
full-config format or complete redaction.
"""

import hashlib
import json
import re

from .config_cisco_ios import MARKER

PLATFORM = 'cisco_xe'
COMMAND = 'show running-config'
IDENTITY_COMMANDS = ('show version',)
SUPPORTED = ('Linux', '17.18.2', 'fc3')
IMAGE_FAMILY = 'X86_64BI_LINUX-ADVENTERPRISEK9-M'
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
                     COMMAND, IDENTITY_COMMANDS, IMAGE_FAMILY, SUPPORTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_TRAIN = 'IOSXE'
_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufffd]')
# Any well-formed IOS header (classic or with a release train); bounded character classes only.
_GENERIC = re.compile(r'Cisco IOS Software(?: \[([A-Za-z0-9]{1,32})\])?, ([A-Za-z0-9_]{1,32}) Software '
                      r'\(([A-Za-z0-9_-]{1,64})\), (?:Experimental )?Version [0-9].*')
_HEADER = re.compile(r'Cisco IOS Software \[IOSXE\], ([A-Za-z0-9_]{1,32}) Software \(([A-Za-z0-9_-]{1,64})\), '
                     r'Version ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[a-z]{0,2})'
                     r', RELEASE SOFTWARE \(([a-z0-9]{1,16})\)')
_HARDWARE = re.compile(r'([A-Za-z0-9_]{1,32}) Unix \([A-Za-z0-9_]{1,16}\) processor with '
                       r'[0-9]{1,12}K bytes of memory\.')
# Narrow candidate prefix of a hardware line; complete or truncated, every candidate is counted.
_HARDWARE_CANDIDATE = re.compile(r'[^ ]+ Unix \(')


class UnsupportedXeFirmware(ValueError):
    """The live identity is consistent but is not the single admitted model and image."""


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_xe supports only redaction full, '
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


def _one(lines, selector, pattern, *, repeated=False):
    """The single matching line; ``repeated`` admits verbatim repeats of that one line only."""
    found = [line.strip(' \t') for line in lines if selector(line.strip(' \t'))]
    if not found or len(set(found) if repeated else found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0])
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match


def _is_header(line):
    return line.startswith('Cisco IOS Software')


def version_identity(version):
    """(model, version, build, image family) from ``show version``; ValueError when not conclusive.

    A well-formed header of another train, software or image family (e.g. classic IOS) is reported as
    such, with ``None`` for model, version and build; it is never admitted.
    """
    lines = _lines(version)
    text = _one(lines, _is_header, _GENERIC, repeated=True)
    if text.group(1) != _TRAIN or text.group(2) != SUPPORTED[0]:
        return None, None, None, text.group(3)
    header = _one(lines, _is_header, _HEADER, repeated=True)
    hardware = _one(lines, lambda s: _HARDWARE_CANDIDATE.match(s) is not None or 'bytes of memory' in s,
                    _HARDWARE)
    model, family, number, build = header.groups()
    if hardware.group(1) != model:
        raise ValueError('configuration identity could not be verified')
    return model, number, build, family


def verify_identity(version):
    """Firmware record (model, version, build) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity; UnsupportedXeFirmware: a consistent identity
    outside the single admitted model, release and image family.
    """
    model, number, build, family = version_identity(version)
    firmware = (model, number, build)
    if firmware != SUPPORTED or family != IMAGE_FAMILY:
        raise UnsupportedXeFirmware('configuration firmware-not-supported')
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
