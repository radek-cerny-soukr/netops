"""Cisco IOS identity/profile adapter used by the public IOS ``config_read`` path.

The tested combination is IOSv ``15.9(3)M12`` build ``fc1``, image family ``VIOS-ADVENTERPRISEK9-M``
(``tests/fixtures/real/cisco_ios/iosv_15.9.3M12/version.txt``).  Another model, release or image family
(e.g. IOSvL2 or a Catalyst) is read too and reported as ``firmware_support`` ``untested`` with a warning
(startup, decision of 2026-11-17); the line-based stream redactor hides every line it does not know on every
version.  The model is read from the separate hardware line of ``show version`` only (for the tested
IOSv also checked against the header), never from file names, serial numbers or host names; when no
single hardware line is recognized the model is unknown (``None``).  ``show running-config`` is
privileged EXEC and, without ``all``, omits default values (Cisco command reference); this is not a
measurement of any device or its privilege.  A tested identity does not verify account rights, the
full-config format or complete redaction.
"""

import hashlib
import json
import re

from netops_core import tested

from .config_cisco_ios import MARKER

PLATFORM = 'cisco_ios'
COMMAND = 'show running-config'
STARTUP_COMMAND = 'show startup-config'
DIFF_COMMAND = 'show archive config differences nvram:startup-config system:running-config'
LIVE_DIFF = ('startup', 'running')
IDENTITY_COMMANDS = ('show version',)
# The identity config_read was tested on (startup: a list of tested identities, not a gate).
TESTED = ('IOSv', '15.9(3)M12', 'fc1')
TESTED_NAME = 'Cisco IOS'
IMAGE_FAMILY = 'VIOS-ADVENTERPRISEK9-M'
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
                     COMMAND, IDENTITY_COMMANDS, IMAGE_FAMILY, TESTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_XE_HEADER = re.compile(r'[ \t]*Cisco IOS (?:XE Software\b|Software, IOS[ -]XE\b|Software \[IOSXE\],)', re.I)
_NAME = r'[A-Za-z0-9_]{1,32}(?: {1,2}[A-Za-z0-9_]{1,32}){0,4}'
_GENERIC = re.compile(r'Cisco IOS Software, (' + _NAME + r') {1,2}Software \(([A-Za-z0-9_-]{1,64})\), '
                      r'(?:Experimental )?Version [0-9].*')
_HEADER = re.compile(r'Cisco IOS Software, ([A-Za-z0-9_]{1,32}) Software \(([A-Za-z0-9_-]{1,64})\), '
                     r'Version ([0-9]+\.[0-9]+\([0-9]+\)[A-Za-z]+[0-9]+)'
                     r', RELEASE SOFTWARE \(([a-z0-9]+)\)')
_HARDWARE = re.compile(r'Cisco ([A-Za-z0-9_]{1,32}) \(revision [0-9]+\.[0-9]+\) with +(?:with +)?'
                       r'[0-9]+K/[0-9]+K bytes of memory\.')
# Narrow candidate prefix of a hardware line; complete or truncated, every candidate is counted.
_HARDWARE_CANDIDATE = re.compile(r'Cisco [^ ]+ \(revision')
# Release and optional build of any well-formed header (an untested identity); bounded classes only.
_ANY_HEADER = re.compile(r'Cisco IOS Software, (' + _NAME + r') {1,2}Software \(([A-Za-z0-9_-]{1,64})\), '
                         r'(?:Experimental )?Version ([0-9]{1,3}\.[0-9]{1,3}\([0-9A-Za-z:.]{1,32}\)[A-Za-z0-9.]{0,16})'
                         r'(?:, RELEASE SOFTWARE \(([a-z0-9]{1,16})\)|, CISCO DEVELOPMENT TEST VERSION'
                         r'| \[[^\[\]]{1,96}\])?')
# Hardware line of an untested identity: IOSvL2 ``Cisco IOSv () processor (revision 1.0) with ...``,
# Catalyst ``cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with ...``.
_ANY_HARDWARE = re.compile(r'[Cc]isco ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})(?: \([^()]{0,32}\))?(?: processor)? '
                           r'(?:\(revision [^()]{1,16}\) )?with +(?:with +)?'
                           r'[0-9]{1,12}K(?:/[0-9]{1,12}K)? bytes of memory\.')
_DIFF_CHANGE = re.compile(r'[ \t]*[+-]\s*\S.*')


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_ios supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def native_diff_status(output):
    """Return the native change indicator. The response body never leaves the engine."""
    if (not isinstance(output, str) or not output.endswith(('\n', '\r')) or _CONTROL.search(output)
            or re.search(r'--\s*More\s*--', output, re.I)):
        return None
    lines = [line.strip(' \t') for line in output.splitlines() if line.strip(' \t')]
    if not lines or lines[0] != '!Contextual Config Diffs:':
        return None
    changes = lines[1:]
    if changes == ['!No changes were found']:
        return False
    if any(line.startswith(('%', '^', '!')) for line in changes):
        return None
    # A context line can precede a signed change or follow it. Without a signed
    # change or the explicit no-change footer the result is inconclusive.
    return True if any(_DIFF_CHANGE.fullmatch(line) for line in changes) else None


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


def _is_header(line):
    return line.startswith('Cisco IOS Software')


def _hardware_model(lines):
    """The model of the single recognized hardware line, None when there is none or more than one."""
    found = [_ANY_HARDWARE.fullmatch(line.strip(' \t')) for line in lines]
    found = [match.group(1) for match in found if match is not None]
    return found[0] if len(found) == 1 else None


def version_identity(version):
    """(model, version, build, image family) from ``show version``; ValueError when not conclusive.

    The header must occur once and name a release.  The tested IOSv keeps its strict reading (the header
    with release and build, one hardware line naming the same model).  Any other well-formed header
    (e.g. IOSvL2 or a Catalyst) is read as an untested identity: model from the single hardware line or
    None, build None when the header names none.
    """
    lines = _lines(version)
    # Older XE releases identify the OS on a separate line above the IOSd release.
    if any(_XE_HEADER.match(line) for line in lines):
        raise ValueError('configuration identity could not be verified')
    text = _one(lines, _is_header, _GENERIC)
    if text.group(1) == TESTED[0] and _HEADER.fullmatch(text.group(0)):
        header = _HEADER.fullmatch(text.group(0))
        hardware = _one(lines, lambda s: _HARDWARE_CANDIDATE.match(s) is not None or 'bytes of memory' in s,
                        _HARDWARE)
        model, family, number, build = header.groups()
        if hardware.group(1) != model:
            raise ValueError('configuration identity could not be verified')
        return model, number, build, family
    header = _ANY_HEADER.fullmatch(text.group(0))
    if header is None:
        raise ValueError('configuration identity could not be verified')
    _, family, number, build = header.groups()
    return _hardware_model(lines), number, build, family


def verify_identity(version):
    """Firmware record (model, version, build, image family) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity.  A consistent identity of another model, release
    or image family is returned as well; firmware_support() tells whether it is the tested one.  The
    reply shows model, version and build (the image family is kept in the stored record only).
    """
    return version_identity(version), metadata()


def _text(item, size=96):
    return type(item) is str and 0 < len(item) <= size


def firmware_record(firmware):
    """True for a firmware record as verify_identity returns it (a stored snapshot is read back with it)."""
    return (type(firmware) is tuple and len(firmware) == 4 and _text(firmware[1]) and _text(firmware[3]) and
            all(item is None or _text(item) for item in (firmware[0], firmware[2])))


def _shown(number, build, family):
    return number + ('' if build is None else ' ' + build) + ' (' + family + ')'


def firmware_support(firmware):
    """The firmware_support structure (netops_core.tested) of a firmware record against the tested identity."""
    model, number, build, family = firmware
    return tested.support(TESTED_NAME, _shown(number, build, family),
                          [(TESTED[0], _shown(TESTED[1], TESTED[2], IMAGE_FAMILY))],
                          model=model, function='config_read')


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
