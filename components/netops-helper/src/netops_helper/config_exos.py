"""Conservative ExtremeXOS ``show configuration`` stream consumer (task 109-06).

This is a building block only.  It is not registered as a platform, stream or I/O path and it does
not decide whether a capture is complete or whether the account could see everything; the engine
integration that follows decides that from rc, raw identity and flags.

Policy (explicit and conservative, not a claim of full EXOS knowledge):

* Only a short list of VLAN and physical-port sentences is verified as safe.  A line is copied
  unchanged (original ASCII text, original order, including trailing blanks) only when the whole
  sentence matches one of those shapes; there is no prefix pass.
* Empty lines are kept.  Every other line -- comments, unknown commands, credential statements,
  quoted records that span lines, opaque multi-line blocks (PEM, UPM profiles), non-ASCII names --
  is replaced by the constant ``MARKER``.  The marker, the summary, ``repr`` and errors never carry
  an original word, name or value.  A masked line is an admitted unverified part, not a claim that
  it held a password.
* A verified sentence that contains a registered forbidden value is masked as well; the
  ``ContentBuilder`` additionally refuses forbidden values and serialized secret markers.
* An obvious CLI refusal, error or pager prompt withholds the whole output, as does a stream with
  no verified sentence at all.
"""

import codecs
import re
import sys

from .config_buffers import ContentBuilder, ContentLimitError, HiddenRecords
from .config_limits import ConfigurationLimits
from .configuration import (ConfigurationBudgetError, ConfigurationRedactionError,
                            ConfigurationRefusedError, _budget)

MARKER = '<UNVERIFIED:exos-opaque-line>'

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_PAGER = re.compile(r'--\s*More\s*--|Press\s*<\s*SPACE\s*>\s*to\s+continue', re.I)
_REFUSAL = re.compile(r'%%|(?:Error|ERROR)[ \t]*:|Permission denied\b')
# The read-only account refusal of 'show configuration' (rc 254; live 178) is a device refusal as well, but only
# as the exact whole answer with no other non-blank content: inside a quoted multi-line
# value, a UPM/PEM block or after any configuration line it is configuration content (hidden like the rest).
_READ_ONLY_REFUSAL = re.compile(r'This user does not have permissions for this command\.')
_QUOTED_STOP = re.compile(r'[\\"]')
_NEWLINE = re.compile('[\r\n]')
_BLANK = re.compile(r'[ \t]*')
_UPM_OPEN = re.compile(r'create[ \t]+upm[ \t]+profile(?:[ \t]|$)')

_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,63}')
_NUMBER = re.compile(r'[1-9][0-9]{0,5}')
_PORT = r'[1-9][0-9]{0,3}(?::[1-9][0-9]{0,3})?'
_PORT_ITEM = _PORT + '(?:-' + _PORT + ')?'
_PORTS = re.compile(_PORT_ITEM + '(?:,' + _PORT_ITEM + '){0,127}')
_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = re.compile(_OCTET + r'(?:\.' + _OCTET + '){3}')
_PREFIX = re.compile(r'(?:3[0-2]|[12]?[0-9])')
_SPEEDS = frozenset(('10', '100', '1000', '2500', '5000', '10000', '25000', '40000', '50000',
                     '100000', '400000'))

_COMMENT, _UNSUPPORTED, _MULTILINE, _BLOCK, _RESERVED = (
    'exos / comment', 'exos / unsupported-statement', 'exos / multiline-record',
    'exos / opaque-block', 'exos / reserved-marker-collision')
_FORMAT_LABELS = frozenset((_MULTILINE, _BLOCK))

# One feed is decoded and split in internal slices of at most _SLICE_BYTES raw bytes (smaller when
# the remaining memory budget is low).  Before a slice is touched, a conservative upper bound of its
# live working memory is reserved in the budget: the decoder's raw copy and carried bytes
# (2 bytes per raw byte), the decoded text and one line piece of it in the widest (UCS-4) form
# (4 + 4) and the UTF-8 encoding of that piece (1), plus a fixed allowance for object headers.
_SLICE_BYTES = 4096
_WORK_BASE = 512
_WORK_PER_BYTE = 12


def _name(token):
    if len(token) > 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    return _NAME.fullmatch(token) is not None


def _number(token, low, high):
    return _NUMBER.fullmatch(token) is not None and low <= int(token) <= high


def _ports(token):
    return token == 'all' or _PORTS.fullmatch(token) is not None


def _netmask(token):
    if not _IPV4.fullmatch(token):
        return False
    value = int.from_bytes(bytes(int(part) for part in token.split('.')), 'big')
    inverted = ~value & 0xffffffff
    return inverted & (inverted + 1) == 0


def _address(words):
    if len(words) == 2:
        return _IPV4.fullmatch(words[0]) is not None and _netmask(words[1])
    if len(words) == 1 and words[0].count('/') == 1:
        address, prefix = words[0].split('/')
        return _IPV4.fullmatch(address) is not None and _PREFIX.fullmatch(prefix) is not None
    return False


def _port_options(words):
    seen, index = set(), 0
    while index < len(words):
        if index + 1 >= len(words) or words[index] in seen:
            return False
        key, value = words[index], words[index + 1]
        if not ((key == 'auto' and value in ('on', 'off')) or
                (key == 'speed' and value in _SPEEDS) or
                (key == 'duplex' and value in ('full', 'half')) or
                (key == 'max-frame-size' and _number(value, 1500, 9216))):
            return False
        seen.add(key)
        index += 2
    return bool(seen)


def verified_sentence(line):
    """True only when the whole ASCII line is one of the verified VLAN/port sentences."""
    if not line.isascii() or _CONTROL.search(line) or line[:1] in (' ', '\t'):
        return False
    words = line.split()
    if not words:
        return False
    if words[:2] == ['create', 'vlan']:
        return ((len(words) == 3 and _name(words[2])) or
                (len(words) == 5 and _name(words[2]) and words[3] == 'tag' and _number(words[4], 1, 4095)))
    if words[:2] == ['configure', 'vlan'] and len(words) >= 5 and _name(words[2]):
        rest = words[3:]
        if rest[0] == 'tag':
            return len(rest) == 2 and _number(rest[1], 1, 4095)
        if rest[0] in ('add', 'delete') and len(rest) in (3, 4) and rest[1] == 'ports':
            return _ports(rest[2]) and (len(rest) == 3 or rest[3] in ('tagged', 'untagged'))
        if rest[0] == 'ipaddress':
            return _address(rest[1:])
        return False
    if words[0] in ('enable', 'disable') and len(words) >= 2:
        if words[1] == 'ipforwarding':
            return len(words) == 2 or (len(words) == 4 and words[2] == 'vlan' and _name(words[3]))
        return words[1] == 'ports' and len(words) == 3 and _ports(words[2])
    if words[:2] == ['configure', 'ports'] and len(words) >= 5:
        return _ports(words[2]) and _port_options(words[3:])
    return False


class StreamRedactor:
    """Incremental EXOS consumer: ``feed(bytes)`` ... ``finish()`` -> (Content, HiddenRecords, count)."""

    def __init__(self, forbidden, section, *, limits=None):
        if type(section) is not str or section != 'all':
            raise ValueError('invalid configuration section')
        self.limits = ConfigurationLimits() if limits is None else limits
        if type(self.limits) is not ConfigurationLimits:
            raise ValueError('invalid configuration limits')
        forbidden = tuple(forbidden)
        if any(type(value) is not str for value in forbidden):
            raise ValueError('invalid forbidden configuration values')
        self._secrets = tuple(value.encode('utf-8') for value in forbidden if value)
        self._builder = ContentBuilder(self.limits.all_bytes, forbidden, serialized_markers=True)
        self._decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self._state = 'open'
        self._raw_bytes = 0
        self._after_cr = False
        self._physical, self._physical_bytes, self._physical_memory = [], 0, 0
        self._pending, self._pending_bytes, self._pending_memory = [], 0, 0
        self._in_quote = False
        self._work = 0
        self._block = None
        self._line_number = self._error_line = 0
        self._preamble = True     # no non-blank line seen yet (no record, value or block open)
        self._read_only_refusal = False
        self._verified = self._lines = 0
        self.credential_count = self.unverified_count = self.unsupported_format_count = 0
        self._labels = []

    def __repr__(self):
        return '<exos configuration stream state=%s lines=%d masked=%d>' % (
            self._state, self._lines, self.credential_count + self.unverified_count)

    def summary(self):
        return {'credential_redactions': self.credential_count,
                'unverified_count': self.unverified_count,
                'unsupported_format_count': self.unsupported_format_count,
                'unverified_fields': list(self._labels),
                'unverified_truncated': False}

    def close(self):
        if self._state == 'open':
            self._state = 'closed'
        self._physical.clear()
        self._pending.clear()
        self._physical_bytes = self._physical_memory = 0
        self._pending_bytes = self._pending_memory = 0
        self._builder.close()
        self._decoder = None
        self._work = 0
        self._secrets = ()
        self._block = None

    def _failure(self, reason):
        line = self._line_number if reason == 'stream-incomplete' else self._error_line
        return ConfigurationRedactionError(reason, line=line or None)

    def _run(self, step, *args):
        # Only the existing safe categories leave this class; the internal exception (which may
        # reference raw input, e.g. UnicodeDecodeError.object) is dropped, never chained.
        failure = None
        try:
            return None, step(*args)
        except (ConfigurationBudgetError, ConfigurationRefusedError, ConfigurationRedactionError) as exc:
            failure = exc
        except ContentLimitError:
            failure = self._failure('capture-limit-exceeded')
        except Exception:
            failure = self._failure('redaction-unverifiable')
        failure.__traceback__ = failure.__context__ = failure.__cause__ = None
        self.close()
        return failure, None

    def feed(self, data):
        failure, unused = self._run(self._feed, data)
        data = None
        if failure is not None:
            raise failure

    def finish(self):
        failure, result = self._run(self._finish)
        self.close()
        if failure is not None:
            raise failure
        return result

    def _memory(self):
        used = (self._builder.memory_bytes + self._physical_memory + self._pending_memory +
                sys.getsizeof(self._physical) + sys.getsizeof(self._pending) + self._work)
        if used > self.limits.memory_bytes:
            raise ConfigurationBudgetError('configuration memory budget exhausted for target; output withheld')
        return used

    def _feed(self, data):
        if self._state != 'open' or type(data) is not bytes:
            raise ValueError('configuration stream is not open')
        self._raw_bytes += len(data)
        if self._raw_bytes > self.limits.all_bytes:
            raise self._failure('capture-limit-exceeded')
        # The caller-owned data is only viewed (no copy); each internal slice's working memory is
        # reserved in the budget before it is decoded and released after it was consumed.
        view = memoryview(data)
        try:
            offset = 0
            while offset < len(view):
                self._work = 0
                room = self.limits.memory_bytes - self._memory()
                size = min(_SLICE_BYTES, len(view) - offset, (room - _WORK_BASE) // _WORK_PER_BYTE)
                if size < 1:
                    raise ConfigurationBudgetError(
                        'configuration memory budget exhausted for target; output withheld')
                self._work = _WORK_BASE + _WORK_PER_BYTE * size
                self._memory()
                self._text(self._decoder.decode(view[offset:offset + size], final=False))
                offset += size
        finally:
            self._work = 0
            view.release()

    def _text(self, text):
        if not text:
            return
        if _CONTROL.search(text):
            raise ValueError('control character in configuration stream')
        start, end = 0, len(text)
        if self._after_cr and text[0] == '\n':
            start = 1
        self._after_cr = text.endswith('\r')
        # Walk the line ends in place (CR, LF and CRLF each end one line); no normalized copy and
        # no list of all parts.
        while True:
            found = _NEWLINE.search(text, start)
            stop = end if found is None else found.start()
            if stop > start:
                self._part(text[start:stop])
            if found is None:
                return
            self._line()
            start = found.end()
            if found.group() == '\r' and text.startswith('\n', start):
                start += 1

    def _part(self, part):
        self._physical_bytes += len(part.encode('utf-8'))
        if self._physical_bytes > self.limits.physical_line_bytes:
            raise self._failure('capture-limit-exceeded')
        if len(self._physical) >= 64:
            joined = ''.join(self._physical)
            self._physical[:] = [joined]
            self._physical_memory = sys.getsizeof(joined)
        self._physical.append(part)
        self._physical_memory += sys.getsizeof(part)
        self._memory()

    def _line(self):
        line = ''.join(self._physical)
        self._physical.clear()
        self._physical_bytes = self._physical_memory = 0
        self._line_number += 1
        self._error_line = self._line_number
        stripped = line.strip(' \t')
        if _PAGER.search(line):
            raise ValueError('pager prompt in configuration stream')
        if stripped:
            # Defer until EOF: a first-line refusal followed by configuration is opaque content.
            self._read_only_refusal = self._preamble and bool(_READ_ONLY_REFUSAL.fullmatch(stripped))
            self._preamble = False
        if _REFUSAL.match(stripped):
            raise ConfigurationRefusedError()
        if self._block is not None:
            self._block_line(line, stripped)
        elif not self._pending and stripped.startswith('#'):
            self._mask(1, _COMMENT)
        else:
            self._logical(line)
        self._lines += 1
        if self._lines % 1024 == 0:
            _budget(self._memory())

    def _block_line(self, line, stripped):
        if self._block == 'pem' and '-----END' in line:
            self._block = None
        elif self._block == 'upm' and stripped == '.':
            self._block = None
        if not stripped:
            self._emit(line + '\n')
        else:
            self._mask(1, _BLOCK)

    def _logical(self, line):
        size = len(line.encode('utf-8')) + 1
        self._pending_bytes += size
        if self._pending_bytes > self.limits.logical_record_bytes:
            raise self._failure('capture-limit-exceeded')
        self._pending.append(line)
        self._pending_memory += sys.getsizeof(line)
        self._memory()
        self._in_quote = self._quote_state(line, self._in_quote)
        if self._in_quote:
            return
        lines = list(self._pending)
        self._pending.clear()
        self._pending_bytes = self._pending_memory = 0
        if len(lines) > 1:
            self._mask(len(lines), _MULTILINE)
        else:
            self._record(lines[0])

    @staticmethod
    def _quote_state(line, in_quote):
        """Quote state after ``line``.  Outside a quoted value only ``"`` matters (it opens one).
        Inside, a backslash escapes the very next real character, whatever it is (``\\b``, ``\\t``,
        ``\\"``, ``\\\\``); when the backslash is the last character, the next character is the line
        end itself, so the quoted value stays open into the next line."""
        position = 0
        while True:
            if in_quote:
                found = _QUOTED_STOP.search(line, position)
                if found is None:
                    return True
                if found.group() == '"':
                    in_quote = False
                    position = found.end()
                else:
                    position = found.end() + 1  # consume the escaped character immediately
            else:
                position = line.find('"', position)
                if position < 0:
                    return False
                in_quote = True
                position += 1

    def _record(self, line):
        if _BLANK.fullmatch(line):
            self._emit(line + '\n')
        elif verified_sentence(line):
            data = line.encode('ascii')
            if any(secret in data for secret in self._secrets):
                self.credential_count += 1
                self._emit(MARKER + '\n')
            elif any(marker in data + b'\n' for marker in self._builder.forbidden):
                self._mask(1, _RESERVED)
            else:
                self._emit(line + '\n')
                self._verified += 1
        elif '-----BEGIN' in line and '-----END' not in line:
            self._block = 'pem'
            self._mask(1, _BLOCK)
        elif _UPM_OPEN.match(line):
            self._block = 'upm'
            self._mask(1, _BLOCK)
        else:
            self._mask(1, _UNSUPPORTED)

    def _mask(self, lines, label):
        self.unverified_count += lines
        if label in _FORMAT_LABELS:
            self.unsupported_format_count += lines
        if label not in self._labels:
            self._labels.append(label)
        for _ in range(lines):
            self._emit(MARKER + '\n')

    def _emit(self, text):
        self._builder.add(text)
        self._memory()

    def _finish(self):
        if self._state != 'open' or not self._raw_bytes:
            raise self._failure('stream-incomplete')
        try:
            tail = self._decoder.decode(b'', final=True)
        except UnicodeDecodeError:
            tail = None
        if tail is None:
            raise self._failure('stream-incomplete')
        self._text(tail)
        if self._physical:
            self._line()
        if self._read_only_refusal:
            raise ConfigurationRefusedError()
        if self._pending or self._in_quote or self._block is not None:
            raise self._failure('stream-incomplete')
        if not self._verified:
            raise ValueError('no verified configuration sentence')
        _budget(self._memory())
        count = self.credential_count + self.unverified_count
        content = self._builder.finish()
        self._state = 'finished'
        return content, HiddenRecords(), count
