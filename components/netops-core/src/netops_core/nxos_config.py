"""Shared NX-OS identity and read-only configuration line-count framing."""

import re

IDENTITY_MAX_BYTES = 65536

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_HEADER_TEXT = 'Cisco Nexus Operating System (NX-OS) Software'
_HEADER = re.compile(re.escape(_HEADER_TEXT))
# Release such as 9.3(12), 10.3(4a) or 7.0(3)I7(9); bounded character classes only.
_RELEASE = re.compile(r'NXOS: version ([0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}[a-z]?\)'
                      r'(?:[A-Z][0-9]{1,2}\([0-9]{1,3}[a-z]?\)|\([FM]\))?)')
_LEGACY_RELEASE = re.compile(r'system: version ([0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}[a-z]?\)'
                             r'[A-Z][0-9]{1,2}\([0-9]{1,3}[a-z]?\))')
_HARDWARE = re.compile(r'cisco (Nexus ?[0-9]{1,5}(?: [A-Za-z0-9-]{1,32})?) [Cc]hassis(?: \([^()]{1,64}\))?')


def line_count(output):
    """The positive, standalone line total from an NX-OS `show … | count`."""
    count = output.strip(' \t\r\n')
    return int(count) if re.fullmatch(r'[1-9][0-9]{0,7}', count) else None


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
    if any(line.strip(' \t').startswith('NXOS: version') for line in lines):
        release = _one(lines, lambda line: line.startswith('NXOS: version'), _RELEASE).group(1)
    else:
        release = _one(lines, lambda line: line.startswith('system: version'), _LEGACY_RELEASE).group(1)
    model = _one(lines, lambda line: line.startswith('cisco ') and 'hassis' in line, _HARDWARE).group(1)
    return model, release


def firmware_record(firmware):
    """True for a firmware record as verify_identity returns it (a stored snapshot is read back with it)."""
    if type(firmware) is not tuple or len(firmware) != 2 or not all(type(item) is str for item in firmware):
        return False
    model = _HARDWARE.fullmatch('cisco ' + firmware[0] + ' Chassis')
    release = (_RELEASE.fullmatch('NXOS: version ' + firmware[1]) or
               _LEGACY_RELEASE.fullmatch('system: version ' + firmware[1]))
    return (model is not None and model.group(1) == firmware[0] and
            release is not None and release.group(1) == firmware[1])
