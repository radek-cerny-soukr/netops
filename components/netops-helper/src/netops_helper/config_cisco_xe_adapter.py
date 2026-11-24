"""Cisco IOS XE identity/profile adapter for the public ``config_read`` (verification).

Same shape as ``config_cisco_ios_adapter``.  The tested combination is IOL-XE ``Version 17.18.2``,
``RELEASE SOFTWARE (fc3)``, image family ``X86_64BI_LINUX-ADVENTERPRISEK9-M``
(``tests/fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``).  Another model, release, train or image
family (e.g. a Catalyst 9300) is read too and reported as ``firmware_support`` ``untested`` with a warning
(startup, decision of 2026-11-17).  The model is read from the separate hardware line of ``show version``
only (for the tested IOL also checked against the header), never from file names, serial numbers or host
names; when no single hardware line is recognized the model is unknown (``None``).  The header may be
repeated verbatim; two different headers are never admitted.  The running configuration goes through the
unchanged ``config_cisco_ios.StreamRedactor`` on every version (same line syntax; unknown or opaque blocks
are refused or hidden by it).  A tested identity does not verify account rights, the full-config format
or complete redaction.
"""

import hashlib
import json
import re

from netops_core import tested

from .config_cisco_ios import MARKER
from .normalization import is_ios_xe

PLATFORM = 'cisco_xe'
COMMAND = 'show running-config'
STARTUP_COMMAND = 'show startup-config'
DIFF_COMMAND = 'show archive config differences nvram:startup-config system:running-config'
LIVE_DIFF = ('startup', 'running')
IDENTITY_COMMANDS = ('show version',)
# The identity config_read was tested on (startup: a list of tested identities, not a gate).
TESTED = ('Linux', '17.18.2', 'fc3')
TESTED_NAME = 'Cisco IOS XE'
IMAGE_FAMILY = 'X86_64BI_LINUX-ADVENTERPRISEK9-M'
IDENTITY_MAX_BYTES = 65536

POLICY_DESCRIPTOR = (PLATFORM, 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
                     COMMAND, IDENTITY_COMMANDS, IMAGE_FAMILY, TESTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_TRAIN = 'IOSXE'
_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufffd]')
# An IOS XE detail header may include a release train. The software name may have up to five
# words, e.g. ``Catalyst L3 Switch Software``.
_NAME = r'[A-Za-z0-9_-]{1,32}(?: {1,2}[A-Za-z0-9_-]{1,32}){0,4}'
_GENERIC = re.compile(r'Cisco IOS Software(?: \[([A-Za-z0-9]{1,32})\])?, (' + _NAME + r') {1,2}Software '
                      r'\(([A-Za-z0-9_-]{1,64})\), (?:Experimental )?Version [0-9].*')
_HEADER = re.compile(r'Cisco IOS Software \[IOSXE\], ([A-Za-z0-9_]{1,32}) Software \(([A-Za-z0-9_-]{1,64})\), '
                     r'Version ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[a-z]{0,2})'
                     r', RELEASE SOFTWARE \(([a-z0-9]{1,16})\)')
_HARDWARE = re.compile(r'([A-Za-z0-9_]{1,32}) Unix \([A-Za-z0-9_]{1,16}\) processor with '
                       r'[0-9]{1,12}K bytes of memory\.')
# Narrow candidate prefix of a hardware line; complete or truncated, every candidate is counted.
_HARDWARE_CANDIDATE = re.compile(r'[^ ]+ Unix \(')
# Release and optional build of any well-formed header (an untested identity); bounded classes only.
_ANY_HEADER = re.compile(r'Cisco IOS Software(?: \[([A-Za-z0-9]{1,32})\])?, ' + _NAME + r' {1,2}Software '
                         r'\(([A-Za-z0-9_-]{1,64})\), (?:Experimental )?Version ([0-9][0-9A-Za-z.():]{0,47}?)'
                         r'(?:, RELEASE SOFTWARE(?: \(([a-z0-9]{1,16})\))?| \[[^\[\]]{1,96}\])?')
# Hardware line of an untested identity: IOL ``Linux Unix (i686) processor with ...``, Catalyst
# ``cisco C9300-48P (X86) processor with ...`` (optionally with a revision).
_ANY_HARDWARE = re.compile(r'(?:([A-Za-z0-9_]{1,32}) Unix|[Cc]isco ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})) '
                           r'\([^()]{0,32}\) processor(?: \(revision [^()]{1,16}\))? with +'
                           r'[0-9]{1,12}K(?:/[0-9]{1,12}K)? bytes of memory\.')
_DIFF_CHANGE = re.compile(r'[ \t]*[+-][ \t]*\S.*')
_DIFF_CONTEXT = re.compile(r'[ \t]*[A-Za-z][^\r\n]*')
_PAGER = re.compile(r'--\s*More\s*--', re.I)


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: cisco_xe supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def native_diff_status(output):
    """Return only the native comparison result. Context and changed statements are private."""
    if (not output.endswith('\n') or _CONTROL.search(output.replace('\n', '').replace('\t', ''))
            or _PAGER.search(output)):
        return None
    lines = [line.rstrip(' \t') for line in output.split('\n') if line.strip()]
    if not lines or lines[0] != '!Contextual Config Diffs:':
        return None
    if lines[1:] == ['!No changes were found']:
        return False
    changed = False
    pending_context = False
    for line in lines[1:]:
        if _DIFF_CHANGE.fullmatch(line):
            changed = True
            pending_context = False
        elif _DIFF_CONTEXT.fullmatch(line):
            pending_context = True
        else:
            return None
    return True if changed and not pending_context else None


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


def _hardware_model(lines):
    """The model of the single recognized hardware line, None when there is none or more than one."""
    found = [_ANY_HARDWARE.fullmatch(line.strip(' \t')) for line in lines]
    found = [match.group(1) or match.group(2) for match in found if match is not None]
    return found[0] if len(found) == 1 else None


def version_identity(version):
    """(model, version, build, image family, train) from ``show version``; ValueError when not conclusive.

    The header must occur once (verbatim repeats admitted) and name a release.  The tested IOL keeps its
    strict reading (``[IOSXE]`` header with release and build, one hardware line naming the same model).
    Any other well-formed header (another train, software or image family) is read as an untested
    identity: model from the single hardware line or None, build None when the header names none, train
    None when the header names none.
    """
    lines = _lines(version)
    if not is_ios_xe("\n".join(lines)):
        raise ValueError('configuration identity could not be verified')
    text = _one(lines, _is_header, _GENERIC, repeated=True)
    if text.group(1) == _TRAIN and text.group(2) == TESTED[0] and _HEADER.fullmatch(text.group(0)):
        header = _HEADER.fullmatch(text.group(0))
        hardware = _one(lines, lambda s: _HARDWARE_CANDIDATE.match(s) is not None or 'bytes of memory' in s,
                        _HARDWARE)
        model, family, number, build = header.groups()
        if hardware.group(1) != model:
            raise ValueError('configuration identity could not be verified')
        return model, number, build, family, _TRAIN
    header = _ANY_HEADER.fullmatch(text.group(0))
    if header is None:
        raise ValueError('configuration identity could not be verified')
    train, family, number, build = header.groups()
    return _hardware_model(lines), number, build, family, train


def verify_identity(version):
    """Firmware record (model, version, build, image family, train) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity.  A consistent identity of another model, release,
    train or image family is returned as well; firmware_support() tells whether it is the tested one.  The
    reply shows model, version and build (image family and train are kept in the stored record only).
    """
    return version_identity(version), metadata()


def _text(item, size=96):
    return type(item) is str and 0 < len(item) <= size


def firmware_record(firmware):
    """True for a firmware record as verify_identity returns it (a stored snapshot is read back with it)."""
    return (type(firmware) is tuple and len(firmware) == 5 and _text(firmware[1]) and _text(firmware[3]) and
            all(item is None or _text(item) for item in (firmware[0], firmware[2], firmware[4])))


def _shown(number, build, family, train):
    return (number + ('' if build is None else ' ' + build) + ' (' + family + ')' +
            ('' if train is None else ' [' + train + ']'))


def firmware_support(firmware):
    """The firmware_support structure (netops_core.tested) of a firmware record against the tested identity."""
    model, number, build, family, train = firmware
    return tested.support(TESTED_NAME, _shown(number, build, family, train),
                          [(TESTED[0], _shown(TESTED[1], TESTED[2], IMAGE_FAMILY, _TRAIN))],
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
