"""Narrow ExtremeXOS wiring for the public ``config_read`` (task 81).

Only one documented option set is admitted: platform ``extreme_exos``, redaction ``full``,
section ``all`` with ``include_all`` true, no defaults, running view.  The live identity (model, image)
must be read conclusively; it is compared with the tested identities (G00, decision of 2026-11-17): another
model or image is read too and reported as ``firmware_support`` ``untested`` with a warning, never refused
for its version.  The accepted consumer :class:`config_exos.StreamRedactor` decides which lines are kept
on every version (unknown lines stay hidden); this module only checks request options and identity and
names the profile.

Evidence for the tested identities (real captures, anonymized):

* ``tests/fixtures/real/exos/dom_33.7.1.6_20261114/sample_a-version.txt`` -- ``show version``:
  ``ExtremeXOS version 33.7.1.6 33.7.1.6-patch1-11`` (it does not name the model);
* ``tests/fixtures/real/exos/x440g2-12p-10g4_33.7.1.6/switch.txt`` -- ``show switch``:
  ``System Type: X440G2-12p-10G4`` with primary image 33.7.1.6 patch1-11 booted;
* ``tests/fixtures/real/exos/g41-20261118/`` -- real-derived reads from both models.

The model is never derived from a part number or serial number.  No other model or image is listed as
tested without captured evidence.
"""

import hashlib
import json
import re

from netops_core import tested

from .config_exos import MARKER

PLATFORM = 'extreme_exos'
COMMAND = 'show configuration'
IDENTITY_COMMANDS = ('show version', 'show switch')
# Models and images for which config_read has lab evidence.
TESTED = ('X440G2-12p-10G4', '33.7.1.6', 'patch1-11')
TESTED_VM = ('EXOS-VM', '33.6.1.14', '')
TESTED_NAME = 'ExtremeXOS'
IDENTITY_MAX_BYTES = 65536

# A small explicit policy version descriptor; a change of any item (consumer policy version, marker,
# tested identity, capture command) is a new profile, and cached snapshots of the old one are refused.
POLICY_DESCRIPTOR = (PLATFORM, 'config_exos.StreamRedactor', 'exos-vlan-port-service-sentences-2', MARKER,
                     COMMAND, IDENTITY_COMMANDS, TESTED)
PROFILE = PLATFORM + '-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified',)

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
# The release token is absent on an image without a patch (measured on EXOS-VM 33.6.1.14:
# ``Image : ExtremeXOS version 33.6.1.14 by release-manager``, task 441); such a build is ''.
_IMAGE = re.compile(r'Image[ \t]*:[ \t]*ExtremeXOS version ([0-9]+(?:\.[0-9]+){3})[ \t]+'
                    r'(?:([0-9]+(?:\.[0-9]+){3}-patch[0-9]+-[0-9]+)[ \t]+)?by[ \t]+\S.*')
# The line after the booted ``Primary ver``/``Secondary ver`` line: its patch, or (no patch) the next
# label of show switch, which starts in the first column.
_NEXT_LABEL = re.compile(r'[A-Za-z][^:\n]*:.*')
_IMG = re.compile(r'Switch[ \t]*:.*[ \t]IMG:[ \t]*([0-9]+(?:\.[0-9]+){3})[ \t]*')
_TYPE = re.compile(r'System Type:[ \t]*([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})[ \t]*')
_BOOTED = re.compile(r'Image Booted:[ \t]*(primary|secondary)[ \t]*')
_PATCH = re.compile(r'[ \t]+(patch[0-9]+-[0-9]+)[ \t]*')
_CONFIG_NAME = r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}'
_HUNK = re.compile(r'@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@')


def live_comparison(base, other):
    """Whether the snapshot selectors request a device-side comparison."""
    return isinstance(base, str) and other == 'running' and (base in ('saved', 'booted') or
                                   re.fullmatch('saved:' + _CONFIG_NAME, base) is not None)


def comparison_source(switch, base):
    lines = _lines(switch)

    def field(label, pattern):
        return _one(lines, label, re.compile(re.escape(label) + r'[ \t]*(' + pattern + ')'))[0][1]

    def configuration_file(label):
        try:
            return field(label, _CONFIG_NAME + r'\.cfg')
        except ValueError:
            return None

    hostname = field('SysName:', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}')
    selected = configuration_file('Config Selected:')
    booted = configuration_file('Config Booted:')
    if base == 'booted':
        saved = booted
    elif base == 'saved':
        saved = selected
    else:
        saved = base.removeprefix('saved:') + '.cfg'
    if saved is None:
        raise ValueError('saved configuration file could not be verified')
    return hostname, selected, booted, saved


def comparison_command(saved):
    """Build the native comparison from the verified snapshot source."""
    return COMMAND + ' difference ' + saved.removesuffix('.cfg') + ' context 0'


def diff_counts(text, saved):
    """Validate the context-free native diff. Hunk bodies may contain fragments of secrets."""
    if text == '':
        return 0, 0
    if not text.endswith('\n') or _CONTROL.search(text):
        raise ValueError('unverified ExtremeXOS difference')
    lines = iter(text.splitlines())
    if (not next(lines, '').startswith('--- ' + saved + ' ') or next(lines, None) != '' or
            not next(lines, '').startswith('+++ Running ')):
        raise ValueError('unverified ExtremeXOS difference')
    removed = added = 0
    for line in lines:
        if not line.strip():
            continue
        hunk = _HUNK.fullmatch(line)
        if hunk is None:
            raise ValueError('unverified ExtremeXOS difference')
        old, new = (1 if value is None else int(value) for value in hunk.groups())
        if old + new == 0:
            raise ValueError('unverified ExtremeXOS difference')
        removed += old
        added += new
        for _ in range(old + new):
            body = next(lines, '')
            if body.startswith('-') and old:
                old -= 1
            elif body.startswith('+') and new:
                new -= 1
            else:
                raise ValueError('unverified ExtremeXOS difference')
    if removed + added == 0:
        raise ValueError('unverified ExtremeXOS difference')
    return removed, added


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
    """(version, build) from ``show version``; build '' for an image without a patch.

    ValueError when absent, repeated or contradictory.
    """
    lines = _lines(version)
    image, _ = _one(lines, 'Image', _IMAGE)
    number, release = image.groups()
    if release is None:
        build = ''
    elif release.startswith(number + '-'):
        build = release[len(number) + 1:]
    else:
        raise ValueError('configuration identity could not be verified')
    switch_lines = [line for line in lines if line.lstrip(' \t').startswith('Switch')]
    if len(switch_lines) > 1:
        raise ValueError('configuration identity could not be verified')
    if switch_lines:
        img = _IMG.fullmatch(switch_lines[0].strip(' \t'))
        if img is None or img.group(1) != number:
            raise ValueError('configuration identity could not be verified')
    return number, build


def switch_identity(switch):
    """(model, booted version, booted build) from ``show switch``; build '' without a patch line.

    ValueError when not conclusive.
    """
    lines = _lines(switch)
    model = _one(lines, 'System Type', _TYPE)[0].group(1)
    booted = _one(lines, 'Image Booted', _BOOTED)[0].group(1)
    label = 'Primary ver' if booted == 'primary' else 'Secondary ver'
    pattern = re.compile(re.escape(label) + r':[ \t]*([0-9]+(?:\.[0-9]+){3})[ \t]*')
    found, index = _one(lines, label, pattern)
    following = lines[index + 1] if index + 1 < len(lines) else ''
    patch = _PATCH.fullmatch(following)
    if patch is not None:
        return model, found.group(1), patch.group(1)
    # no patch line: the image has no patch only when the next line is another label (or the end);
    # an indented line that is not a patch stays inconclusive
    if index + 1 >= len(lines) or (following == '' and index + 2 == len(lines)) or _NEXT_LABEL.fullmatch(following):
        return model, found.group(1), ''
    raise ValueError('configuration identity could not be verified')


def verify_identity(version, switch):
    """Firmware record (model, version, build) and honest visibility metadata.

    ValueError: inconclusive or contradictory identity.  A consistent identity of another model or image
    is returned as well; firmware_support() tells whether it is the tested one.
    """
    number, build = version_identity(version)
    model, booted_number, booted_build = switch_identity(switch)
    if (booted_number, booted_build) != (number, build):
        raise ValueError('configuration identity could not be verified')
    return (model, number, build), metadata()


def firmware_record(firmware):
    """True for a firmware record as verify_identity returns it (a stored snapshot is read back with it)."""
    if type(firmware) is not tuple or len(firmware) != 3 or not all(type(item) is str for item in firmware):
        return False
    model, number, build = firmware
    shown = _TYPE.fullmatch('System Type: ' + model)
    return (shown is not None and shown.group(1) == model and
            re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', number) is not None and
            (build == '' or re.fullmatch(r'patch[0-9]+-[0-9]+', build) is not None))


def firmware_support(firmware):
    """Describe whether the model and image have lab evidence."""
    model, number, build = firmware
    identities = [(label, (release + ' ' + patch).strip()) for label, release, patch in (TESTED, TESTED_VM)]
    return tested.support(TESTED_NAME, (number + ' ' + build).strip(), identities,
                          model=model, function='config_read')


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
