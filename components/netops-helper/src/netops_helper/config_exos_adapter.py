"""Narrow ExtremeXOS wiring for the public ``config_read`` (task 81).

Only one documented combination is admitted: platform ``extreme_exos``, redaction ``full``,
section ``all`` with ``include_all`` true, no defaults, running view, and a live identity of exactly
one evidenced model and image.  The accepted consumer :class:`config_exos.StreamRedactor` decides
which lines are kept; this module only checks request options and identity and names the profile.

Evidence for the admitted identity (separate real read-only captures, anonymized):

* ``tests/fixtures/real/exos/dom_33.7.1.6_20261114/sample_a-version.txt`` -- ``show version``:
  ``ExtremeXOS version 33.7.1.6 33.7.1.6-patch1-11`` (it does not name the model);
* ``tests/fixtures/real/exos/x440g2-12p-10g4_33.7.1.6/switch.txt`` -- ``show switch``:
  ``System Type: X440G2-12p-10G4`` with primary image 33.7.1.6 patch1-11 booted.

The model is never derived from a part number or serial number.  No other model or image is admitted
without captured evidence.
"""

import hashlib
import json
import re

from .config_exos import MARKER

PLATFORM = 'extreme_exos'
COMMAND = 'show configuration'
IDENTITY_COMMANDS = ('show version', 'show switch')
SUPPORTED = ('X440G2-12p-10G4', '33.7.1.6', 'patch1-11')
IDENTITY_MAX_BYTES = 65536

# A small explicit policy version descriptor; a change of any item (consumer policy version, marker,
# admitted identity, capture command) is a new profile, and cached snapshots of the old one are refused.
POLICY_DESCRIPTOR = (PLATFORM, 'config_exos.StreamRedactor', 'exos-vlan-port-sentences-1', MARKER,
                     COMMAND, IDENTITY_COMMANDS, SUPPORTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified',)

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_IMAGE = re.compile(r'Image[ \t]*:[ \t]*ExtremeXOS version ([0-9]+(?:\.[0-9]+){3})[ \t]+'
                    r'([0-9]+(?:\.[0-9]+){3}-patch[0-9]+-[0-9]+)[ \t]+by[ \t]+\S.*')
_IMG = re.compile(r'Switch[ \t]*:.*[ \t]IMG:[ \t]*([0-9]+(?:\.[0-9]+){3})[ \t]*')
_TYPE = re.compile(r'System Type:[ \t]*([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})[ \t]*')
_BOOTED = re.compile(r'Image Booted:[ \t]*(primary|secondary)[ \t]*')
_PATCH = re.compile(r'[ \t]+(patch[0-9]+-[0-9]+)[ \t]*')


class UnsupportedExosFirmware(ValueError):
    """The live identity is consistent but is not the single admitted model and image."""


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: extreme_exos supports only redaction full, '
                         'section all with include_all true and include_defaults false')
    return COMMAND


def _lines(text):
    if (type(text) is not str or not text or len(text.encode('utf-8')) > IDENTITY_MAX_BYTES or
            _CONTROL.search(text.replace('\n', '').replace('\r', '').replace('\t', ''))):
        raise ValueError('configuration identity could not be verified')
    return text.replace('\r\n', '\n').replace('\r', '\n').split('\n')


def _one(lines, prefix, pattern):
    """Exactly one line starts with ``prefix`` and it fully matches ``pattern``."""
    found = [line for line in lines if line.lstrip(' \t').startswith(prefix)]
    if len(found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0].strip(' \t'))
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match, lines.index(found[0])


def version_identity(version):
    """(version, build) from ``show version``; ValueError when absent, repeated or contradictory."""
    lines = _lines(version)
    image, _ = _one(lines, 'Image', _IMAGE)
    number, release = image.groups()
    if not release.startswith(number + '-'):
        raise ValueError('configuration identity could not be verified')
    build = release[len(number) + 1:]
    switch_lines = [line for line in lines if line.lstrip(' \t').startswith('Switch')]
    if len(switch_lines) > 1:
        raise ValueError('configuration identity could not be verified')
    if switch_lines:
        img = _IMG.fullmatch(switch_lines[0].strip(' \t'))
        if img is None or img.group(1) != number:
            raise ValueError('configuration identity could not be verified')
    return number, build


def switch_identity(switch):
    """(model, booted version, booted build) from ``show switch``; ValueError when not conclusive."""
    lines = _lines(switch)
    model = _one(lines, 'System Type', _TYPE)[0].group(1)
    booted = _one(lines, 'Image Booted', _BOOTED)[0].group(1)
    label = 'Primary ver' if booted == 'primary' else 'Secondary ver'
    pattern = re.compile(re.escape(label) + r':[ \t]*([0-9]+(?:\.[0-9]+){3})[ \t]*')
    found, index = _one(lines, label, pattern)
    patch = _PATCH.fullmatch(lines[index + 1]) if index + 1 < len(lines) else None
    if patch is None:
        raise ValueError('configuration identity could not be verified')
    return model, found.group(1), patch.group(1)


def verify_identity(version, switch):
    """Firmware record (model, version, build) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity; UnsupportedExosFirmware: a consistent identity
    outside the single admitted model and image.
    """
    number, build = version_identity(version)
    model, booted_number, booted_build = switch_identity(switch)
    if (booted_number, booted_build) != (number, build):
        raise ValueError('configuration identity could not be verified')
    firmware = (model, number, build)
    if firmware != SUPPORTED:
        raise UnsupportedExosFirmware('configuration firmware-not-supported')
    return firmware, metadata()


def metadata():
    return {'config_scope': 'device-account-visible', 'configuration_complete': False,
            'identity_scope_verified': False, 'visibility_limitations': list(VISIBILITY)}


def assess(metadata_fields, summary):
    """Add the consumer summary and the existing limitation names it implies."""
    fields = dict(metadata_fields)
    fields['visibility_limitations'] = list(fields['visibility_limitations'])
    fields.update(summary)
    fields['configuration_complete'] = False
    if fields['unverified_count'] > fields['unsupported_format_count']:
        fields['visibility_limitations'].append('schema-fields-unverified')
    if fields['unsupported_format_count']:
        fields['visibility_limitations'].append('formats-not-verified')
    return fields
