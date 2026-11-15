"""Cisco IOS identity/profile adapter used by the public IOS ``config_read`` path.

Only one evidenced combination is admitted: IOSv ``15.9(3)M12`` build ``fc1``, image family
``VIOS-ADVENTERPRISEK9-M`` (``tests/fixtures/real/cisco_ios/iosv_15.9.3M12/version.txt``).  The model is
read from the header and the separate hardware line of ``show version`` only, never from file names,
serial numbers or host names.  ``show running-config`` is privileged EXEC and, without ``all``, omits
default values (Cisco command reference); this is not a measurement of any device or its privilege.
Supported identity does not verify account rights, the full-config format or complete redaction.
"""

import hashlib
import json
import re

from .config_cisco_ios import MARKER

PLATFORM = 'cisco_ios'
COMMAND = 'show running-config'
IDENTITY_COMMANDS = ('show version',)
SUPPORTED = ('IOSv', '15.9(3)M12', 'fc1')
IMAGE_FAMILY = 'VIOS-ADVENTERPRISEK9-M'
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
                     COMMAND, IDENTITY_COMMANDS, IMAGE_FAMILY, SUPPORTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_GENERIC = re.compile(r'Cisco IOS Software, ([A-Za-z0-9_]{1,32}) Software \(([A-Za-z0-9_-]{1,64})\), '
                      r'(?:Experimental )?Version [0-9].*')
_HEADER = re.compile(r'Cisco IOS Software, ([A-Za-z0-9_]{1,32}) Software \(([A-Za-z0-9_-]{1,64})\), '
                     r'Version ([0-9]+\.[0-9]+\([0-9]+\)[A-Za-z]+[0-9]+)'
                     r', RELEASE SOFTWARE \(([a-z0-9]+)\)')
_HARDWARE = re.compile(r'Cisco ([A-Za-z0-9_]{1,32}) \(revision [0-9]+\.[0-9]+\) with +(?:with +)?'
                       r'[0-9]+K/[0-9]+K bytes of memory\.')
# Narrow candidate prefix of a hardware line; complete or truncated, every candidate is counted.
_HARDWARE_CANDIDATE = re.compile(r'Cisco [^ ]+ \(revision')


class UnsupportedIosFirmware(ValueError):
    """The live identity is consistent but is not the single admitted model and image."""


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_ios supports only redaction full, '
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
    found = [line.strip(' \t') for line in lines if selector(line.strip(' \t'))]
    if len(found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0])
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match


def version_identity(version):
    """(model, version, build, image family) from ``show version``; ValueError when not conclusive.

    A well-formed header of another software/image family (e.g. IOSvL2) is reported as such, with
    ``None`` for model, version and build; it is never admitted.
    """
    lines = _lines(version)
    text = _one(lines, lambda s: s.startswith('Cisco IOS Software'), _GENERIC)
    if text.group(1) != 'IOSv':
        return None, None, None, text.group(2)
    header = _one(lines, lambda s: s.startswith('Cisco IOS Software'), _HEADER)
    hardware = _one(lines, lambda s: _HARDWARE_CANDIDATE.match(s) is not None or 'bytes of memory' in s,
                    _HARDWARE)
    model, family, number, build = header.groups()
    if hardware.group(1) != model:
        raise ValueError('configuration identity could not be verified')
    return model, number, build, family


def verify_identity(version):
    """Firmware record (model, version, build) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity; UnsupportedIosFirmware: a consistent identity
    outside the single admitted model, release and image family.
    """
    model, number, build, family = version_identity(version)
    firmware = (model, number, build)
    if firmware != SUPPORTED or family != IMAGE_FAMILY:
        raise UnsupportedIosFirmware('configuration firmware-not-supported')
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
