"""Conservative Cisco IOS ``show running-config`` stream consumer (verification, bod 06).

The public IOS ``config_read`` path uses this stream consumer for redaction.  The engine and
identity/profile adapter control device I/O and admitted firmware/model checks.  The bounded
decoder/feed/error/finish scaffolding is a local copy of the accepted ``config_exos.StreamRedactor``
(same contract, same shared ``ContentBuilder``/``ConfigurationLimits``/error classes); the line
grammar below is new and small.  The allowlists are not a complete IOS schema.

Policy (a stateful line parser, not a shell parser and not an IOS interpreter):

* Contexts: global, ``interface <token>``, ``vlan <n>``, an unknown stanza and a crypto/key stanza.
  An exact global ``!`` ends a stanza.  Globally only ``version`` and ``hostname`` are kept.
* In an interface only ``description`` (plain ASCII), ``ip address`` IPv4 + netmask, ``ipv6
  address`` IPv6/prefix, ``shutdown``/``no shutdown``, ``switchport``, ``switchport mode
  access|trunk``, ``switchport access vlan N`` and ``switchport trunk allowed vlan`` with a plain
  number/range list are kept; in a VLAN only ``name`` with a plain token.  Kept lines are copied
  unchanged with their original line ending; nothing is synthesized.
* Everything else is replaced by ``MARKER`` (one marker per physical line, original line ending).
  An unknown global statement opens an opaque stanza up to the next real global ``!`` or ``end``;
  nothing inside it is interpreted (an indented or unseparated ``interface`` stays hidden).  An
  unknown sub-line in an interface/VLAN is hidden and the context continues.
* Opaque records come before command recognition: a banner (any type; a one-character, raw
  control-character or caret ``^X`` delimiter; inline or multi-line) is hidden from its header up to
  the real closing delimiter, ``macro name`` up to a global ``@``, ``crypto``/``key`` stanzas up to
  their own real ``!`` (an ``end`` or prompt-like line inside is hidden, not the global end), and an
  open quoted value or a trailing-backslash continuation up to its real end.  An indented banner or
  ``macro name`` header (in any context) and an unknown or malformed banner delimiter refuse the
  stream; an unclosed block at EOF is ``stream-incomplete``.  Hidden data is never kept for later
  classification.
* A ``menu`` header (``menu`` as a separate token, indented or not, in any context) outside an open
  banner/macro/quoted body is an unsupported multi-line format and refuses the whole stream
  (verification); there is no menu parser.  Inside such an open body the word stays masked text.
* A ``Building configuration...`` / ``Current configuration : N bytes`` preamble and a command echo
  are recognized only as exact frames before the body (the byte count is not verified and does not
  describe the redacted content); after the required global ``end`` only blank lines and an exact
  prompt may follow.
* Every kept line is checked against all forbidden values first; a collision hides the whole line.
* Counting: one hidden logical record per hidden line, except that a banner, a macro, one quoted or
  escaped continuation, and one unindented statement of a crypto/key stanza with its indented body
  are one record each.  Such a crypto/key record (header, indented body lines, empty lines and an
  indented quoted value, each with its line ending) shares one ``logical_record_bytes`` budget, as
  do the lines of a banner, a macro or a continuation.  ``HiddenRecords`` holds one generic entry
  per hidden record (an ordinal key and a label digest); nothing derived from the input is stored
  there.
"""

import codecs
import hashlib
import ipaddress
import re
import sys

from .config_buffers import ContentBuilder, ContentLimitError, HiddenRecords
from .config_limits import ConfigurationLimits
from .configuration import (ConfigurationBudgetError, ConfigurationRedactionError,
                            ConfigurationRefusedError, _budget)

MARKER = '<UNVERIFIED:cisco-ios-opaque-line>'
MAX_HIDDEN_RECORDS = 1 << 20

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_RAW_DELIMITER = re.compile('[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]')
_PAGER = re.compile(r'--\s*More\s*--', re.I)
_NEWLINE = re.compile('[\r\n]')
_BLANK = re.compile('[ \t]*')
_QUOTED_STOP = re.compile(r'[\\"]')

# Frames (only before the configuration body, or a prompt after the global end).
_HOST = r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}'
_ECHO = re.compile(_HOST + r'#[ ]?show[ ]+run(?:ning-config)?[ ]*')
_PREAMBLE = re.compile(r'Building configuration\.\.\.[ ]*|Current configuration : [0-9]{1,12} bytes[ ]*')
_STARTUP_ECHO = re.compile(_HOST + r'#[ ]?show[ ]+start(?:up-config)?[ ]*')
_STARTUP_FRAME = re.compile(r'Using [0-9]{1,12} out of [0-9]{1,12} bytes'
                            r'(?:, uncompressed size = [0-9]{1,12} bytes)?[ ]*'
                            r'|Uncompressed configuration from [0-9]{1,12} bytes to [0-9]{1,12} bytes[ ]*')
_COMPARISON_COMMENT = re.compile(r'! (?:Last configuration change|NVRAM config last updated) at .+')
_PROMPT = re.compile(_HOST + r'#[ ]*')
_RUNNING_SIZE = re.compile(r'Current configuration : ([1-9][0-9]{0,11}) bytes[ ]*')
_STARTUP_SIZE = re.compile(r'Using ([1-9][0-9]{0,11}) out of [0-9]{1,12} bytes'
                           r'(?:, uncompressed size = ([1-9][0-9]{0,11}) bytes)?[ ]*')
_STARTUP_COMPRESSED = re.compile(r'Uncompressed configuration from ([1-9][0-9]{0,11}) bytes'
                                 r' to ([1-9][0-9]{0,11}) bytes[ ]*')
_CAPTURE_ECHO = re.compile(_HOST + r'#[ ]?show (?:running|startup)-config[ ]*')
_NO_STARTUP = re.compile(r'(?:startup-config is not present|Non-volatile configuration memory is not present)[.]?',
                         re.I)

# Global statements.
_VERSION = re.compile(r'version [0-9]{1,3}(?:\.[0-9]{1,3}){1,3}[ ]*')
_HOSTNAME = re.compile(r'hostname ' + _HOST + r'[ ]*')
_INTERFACE = re.compile(r'interface [A-Za-z0-9][\x21\x23-\x5b\x5d-\x7e]{0,63}[ ]*')
_VLAN = re.compile(r'vlan ([1-9][0-9]{0,3})[ ]*')
_CRYPTO = re.compile(r'(?:crypto|key)(?:[ \t]|$)')
_BANNER_WORD = re.compile(r'banner(?:[ \t]|$)')
_BANNER = re.compile(r'banner[ ]+[a-z][a-z0-9-]{0,31}[ ]+(.+)', re.S)
_CARET = re.compile(r'\^[@A-Z\[\\\]^_]')
_PRINTABLE = re.compile(r'[\x21-\x7e]')
_MACRO = re.compile(r'macro[ ]+name(?:[ \t]|$)')
_MENU = re.compile(r'menu(?:[ \t]|$)')
# The whole answer of IOS/IOS XE when the account may not run the exec command (rc 0; live 178): a device
# refusal before any configuration line, not an unverifiable stream.
_AUTOCOMMAND = re.compile(r'Line has invalid autocommand "[^"\r\n]{0,256}"[ \t]*')

# Interface and VLAN sub-lines (exactly one leading space; trailing spaces tolerated).
_DESCRIPTION = re.compile(r' description [\x20\x21\x23-\x5b\x5d-\x7e]{1,240}')
_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = _OCTET + r'(?:\.' + _OCTET + '){3}'
_IP_ADDRESS = re.compile(r' ip address (' + _IPV4 + ') (' + _IPV4 + r')[ ]*')
_IPV6_ADDRESS = re.compile(r' ipv6 address ([0-9A-Fa-f:.]{2,45})/(12[0-8]|1[01][0-9]|[1-9]?[0-9])[ ]*')
_FIXED_SUBLINES = frozenset((' shutdown', ' no shutdown', ' switchport', ' switchport mode access',
                             ' switchport mode trunk'))
_ACCESS_VLAN = re.compile(r' switchport access vlan ([1-9][0-9]{0,3})[ ]*')
_ITEM = r'[1-9][0-9]{0,3}(?:-[1-9][0-9]{0,3})?'
_ALLOWED_VLANS = re.compile(r' switchport trunk allowed vlan (' + _ITEM + '(?:,' + _ITEM + r'){0,255})[ ]*')
_VLAN_NAME = re.compile(r' name [A-Za-z0-9][A-Za-z0-9._-]{0,31}[ ]*')

_UNSUPPORTED, _MODE, _SUBLINE, _MULTILINE, _BLOCK, _RESERVED, _CREDENTIAL = (
    'cisco-ios / unsupported-statement', 'cisco-ios / unsupported-mode-line',
    'cisco-ios / unsupported-interface-or-vlan-line', 'cisco-ios / multiline-record',
    'cisco-ios / opaque-block', 'cisco-ios / reserved-marker-collision', 'cisco-ios / forbidden-value')
_FORMAT_LABELS = frozenset((_MULTILINE, _BLOCK))

# Same bounded work reservation as config_exos: one feed is decoded in slices of at most
# _SLICE_BYTES raw bytes and a conservative upper bound of a slice's live working memory is
# reserved in the budget before it is touched.
_SLICE_BYTES = 4096
_WORK_BASE = 512
_WORK_PER_BYTE = 12
# While one joined physical line is classified: the line and up to two transient copies of it.
_LINE_COPIES = 3


def _vlan_id(text):
    return 1 <= int(text) <= 4094


def _netmask(text):
    value = int.from_bytes(bytes(int(part) for part in text.split('.')), 'big')
    inverted = ~value & 0xffffffff
    return inverted & (inverted + 1) == 0


def _ipv6(text):
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _vlan_list(text):
    for item in text.split(','):
        low, unused, high = item.partition('-')
        if not _vlan_id(low) or (high and (not _vlan_id(high) or int(high) < int(low))):
            return False
    return True


def interface_line(line):
    """True only when the whole line is one of the small set of verified interface sub-lines."""
    if line.rstrip(' ') in _FIXED_SUBLINES:
        return True
    if _DESCRIPTION.fullmatch(line):
        return True
    match = _IP_ADDRESS.fullmatch(line)
    if match:
        return _netmask(match.group(2))
    match = _IPV6_ADDRESS.fullmatch(line)
    if match:
        return _ipv6(match.group(1))
    match = _ACCESS_VLAN.fullmatch(line)
    if match:
        return _vlan_id(match.group(1))
    match = _ALLOWED_VLANS.fullmatch(line)
    if match:
        return _vlan_list(match.group(1))
    return False


def _banner_delimiter(line):
    """The delimiter of a banner header and the text after it, or ``None`` when unknown/malformed."""
    match = _BANNER.fullmatch(line)
    if match is None:
        return None
    rest = match.group(1)
    if _CARET.match(rest):
        delimiter = rest[:2]
    elif _RAW_DELIMITER.match(rest) or _PRINTABLE.match(rest):
        delimiter = rest[0]
    else:
        return None
    return delimiter, rest[len(delimiter):]


class StreamRedactor:
    """Incremental IOS consumer: ``feed(bytes)`` ... ``finish()`` -> (Content, HiddenRecords, count)."""

    def __init__(self, forbidden, section, *, limits=None, comparison=False, comparison_view=None):
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
        self._hidden = HiddenRecords()
        self._decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self._state = 'open'
        self._raw_bytes = 0
        self._cr_held = False
        self._physical, self._physical_bytes, self._physical_memory = [], 0, 0
        self._line_memory = 0
        self._work = 0
        self._phase = 'preamble'      # preamble -> body -> ended
        self._comparison = comparison
        self._comparison_fields = set()
        self._comparison_view = comparison_view
        self._declared_size = None
        self._startup_sizes = None
        self._body_size = 0
        self._context = 'global'      # global | interface | vlan | unknown | crypto
        self._block = None            # None | 'banner' | 'macro' | 'continuation'
        self._delimiter = None
        self._in_quote = False
        self._record_bytes = 0
        self._line_number = self._error_line = 0
        self._lines = 0
        self.credential_count = self.unverified_count = self.unsupported_format_count = 0
        self._labels = []

    def __repr__(self):
        return '<cisco-ios configuration stream state=%s lines=%d masked=%d>' % (
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
        self._physical_bytes = self._physical_memory = self._line_memory = 0
        self._builder.close()
        self._hidden = None
        self._decoder = None
        self._work = 0
        self._secrets = ()
        self._block = self._delimiter = None
        self._cr_held = False

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
        hidden = self._hidden.memory_bytes if self._hidden is not None else 0
        used = (self._builder.memory_bytes + self._physical_memory + self._line_memory + hidden +
                sys.getsizeof(self._physical) + self._work)
        if used > self.limits.memory_bytes:
            raise ConfigurationBudgetError('configuration memory budget exhausted for target; output withheld')
        return used

    # -- bounded decoding (copied from config_exos, plus a held CR so CRLF is kept as written) --

    def _feed(self, data):
        if self._state != 'open' or type(data) is not bytes:
            raise ValueError('configuration stream is not open')
        self._raw_bytes += len(data)
        if self._raw_bytes > self.limits.all_bytes:
            raise self._failure('capture-limit-exceeded')
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
        start, end = 0, len(text)
        if self._cr_held:
            self._cr_held = False
            if text[0] == '\n':
                start = 1
                self._line('\r\n')
            else:
                self._line('\r')
        # Walk the line ends in place (CR, LF and CRLF each end one line); no normalized copy and
        # no list of all parts.  A CR at the very end of a slice is held until the next character.
        while True:
            found = _NEWLINE.search(text, start)
            stop = end if found is None else found.start()
            if stop > start:
                self._part(text[start:stop])
            if found is None:
                return
            start = found.end()
            if found.group() == '\n':
                self._line('\n')
            elif start == end:
                self._cr_held = True
                return
            elif text[start] == '\n':
                start += 1
                self._line('\r\n')
            else:
                self._line('\r')

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

    # -- line grammar --

    def _line(self, end):
        line = ''.join(self._physical)
        size = self._physical_bytes
        self._physical.clear()
        self._physical_bytes = self._physical_memory = 0
        self._line_memory = _LINE_COPIES * sys.getsizeof(line)
        self._memory()
        self._line_number += 1
        self._error_line = self._line_number
        if _PAGER.search(line):
            raise ValueError('pager prompt in configuration stream')
        if self._comparison_view is not None:
            if self._comparison_frame(line):
                self._line_memory = 0
                return
            end = '\n' if end else ''
            if self._phase != 'ended':
                self._body_size += size + len(end)
        if self._block == 'banner':
            self._banner_line(line, end)
        elif self._block == 'macro':
            self._controls(line)
            self._grow(line, end)
            self._emit(MARKER + end)
            if line == '@':
                self._block = None
        elif self._block == 'continuation':
            self._controls(line)
            self._grow(line, end)
            self._emit(MARKER + end)
            state = self._quote_state(line, self._in_quote)
            if state is None:
                self._block = None
            self._in_quote = state == 'quote'
        else:
            self._logical(line, end)
        self._line_memory = 0
        self._lines += 1
        if self._lines % 1024 == 0:
            _budget(self._memory())

    def _comparison_frame(self, line):
        if self._phase == 'ended':
            return _BLANK.fullmatch(line) is not None or _PROMPT.fullmatch(line) is not None
        if self._phase != 'preamble':
            return False
        running = self._comparison_view == 'running'
        size = (_RUNNING_SIZE if running else _STARTUP_SIZE).fullmatch(line)
        if size and self._declared_size is None:
            stored_size = int(size[1])
            expanded_size = int(size[2]) if not running and size[2] else None
            self._declared_size = expanded_size or stored_size
            if not running:
                self._startup_sizes = (stored_size, expanded_size)
            return True
        if not running and (compression := _STARTUP_COMPRESSED.fullmatch(line)):
            stored_size, expanded_size = map(int, compression.groups())
            if self._startup_sizes not in ((stored_size, None), (stored_size, expanded_size)):
                raise self._failure('stream-incomplete')
            self._startup_sizes = None
            self._declared_size = expanded_size
            return True
        if _BLANK.fullmatch(line) or _CAPTURE_ECHO.fullmatch(line) or (
                running and line.rstrip(' ') == 'Building configuration...'):
            return True
        if not running and _NO_STARTUP.fullmatch(line):
            raise ConfigurationRefusedError()
        if self._declared_size is None and not (_AUTOCOMMAND.fullmatch(line) or line.startswith('%')):
            raise self._failure('stream-incomplete')
        return False

    @staticmethod
    def _controls(line, allowed=None):
        if _CONTROL.search(line) and (allowed is None or _CONTROL.search(line.replace(allowed, ''))):
            raise ValueError('control character in configuration stream')

    def _grow(self, line, end):
        self._record_bytes += len(line.encode('utf-8')) + len(end)
        if self._record_bytes > self.limits.logical_record_bytes:
            raise self._failure('capture-limit-exceeded')

    def _open(self, block, line, end):
        self._block = block
        self._start(line, end)

    def _start(self, line, end):
        """Begin a new logical record (opaque block or crypto/key statement) with ``line``."""
        self._record_bytes = 0
        self._grow(line, end)

    def _banner_line(self, line, end):
        raw = self._delimiter if _RAW_DELIMITER.fullmatch(self._delimiter) else None
        self._controls(line, raw)
        self._grow(line, end)
        self._emit(MARKER + end)
        if self._delimiter in line:
            self._block = self._delimiter = None

    def _logical(self, line, end):
        indented = line[:1] in (' ', '\t')
        body = line.lstrip(' \t')
        if _MENU.match(body):
            # An unsupported multi-line menu text (verification), indented or not and in any context:
            # its body could contain an exact '!' followed by allowed-looking lines, so the whole
            # stream is refused.  Only reached outside an open banner/macro/quoted body.
            raise ValueError('unsupported menu stanza')
        if indented:
            # An indented banner/macro header is not supported.  It is refused before any sub-line,
            # '!' or 'end' rule: hiding only the header would let an exact '!' inside its body
            # release the rest of the body as allowed syntax.
            if _BANNER_WORD.match(body) or _MACRO.match(body):
                raise ValueError('indented opaque block header')
        elif self._phase != 'ended':
            if _BANNER_WORD.match(line):
                self._banner(line, end)
                return
            if _MACRO.match(line):
                self._controls(line)
                self._phase = 'body'
                self._hide(_BLOCK, end)
                self._open('macro', line, end)
                return
        self._controls(line)
        if not indented and line.startswith('%'):
            raise ConfigurationRefusedError()
        if self._phase == 'preamble' and not indented and _AUTOCOMMAND.fullmatch(line):
            raise ConfigurationRefusedError()
        state = self._quote_state(line, False)
        if state is not None:
            # An open quoted value or escape continuation: one opaque record up to its real end.
            if self._phase == 'ended':
                raise ValueError('data after configuration end')
            self._phase = 'body'
            if not indented and self._context != 'crypto':
                self._context = 'unknown'
            self._hide(_MULTILINE, end)
            if indented and self._context == 'crypto':
                # Part of the body of the current crypto/key record: same record budget.
                self._block = 'continuation'
                self._grow(line, end)
            else:
                self._open('continuation', line, end)
            self._in_quote = state == 'quote'
            return
        self._record(line, end, indented)

    def _banner(self, line, end):
        parsed = _banner_delimiter(line)
        if parsed is None:
            raise ValueError('unknown banner delimiter')
        delimiter, rest = parsed
        self._controls(line, delimiter if _RAW_DELIMITER.fullmatch(delimiter) else None)
        self._phase = 'body'
        self._hide(_BLOCK, end)
        self._open('banner', line, end)
        if delimiter not in rest:
            self._delimiter = delimiter
        else:
            self._block = None

    @staticmethod
    def _quote_state(line, in_quote):
        """``'quote'`` when a quoted value stays open after ``line``, ``'escape'`` when the line
        ends in a backslash outside a quoted value, otherwise ``None``.  Inside a quoted value a
        backslash escapes the very next character; a final backslash keeps the value open."""
        position = 0
        while True:
            if in_quote:
                found = _QUOTED_STOP.search(line, position)
                if found is None:
                    return 'quote'
                if found.group() == '"':
                    in_quote = False
                    position = found.end()
                else:
                    position = found.end() + 1
            else:
                found = line.find('"', position)
                if found < 0:
                    return 'escape' if line.endswith('\\') else None
                in_quote = True
                position = found + 1

    def _record(self, line, end, indented):
        blank = _BLANK.fullmatch(line) is not None
        if self._phase == 'preamble':
            if (blank or _ECHO.fullmatch(line) or _PREAMBLE.fullmatch(line)
                    or (self._comparison and (_STARTUP_FRAME.fullmatch(line) or _STARTUP_ECHO.fullmatch(line)))):
                if not self._comparison:
                    self._keep(line, end)
                return
            self._phase = 'body'
        elif self._phase == 'ended':
            if blank or _PROMPT.fullmatch(line):
                if not self._comparison:
                    self._keep(line, end)
                return
            raise ValueError('data after configuration end')
        if self._comparison and self._context == 'global' and _COMPARISON_COMMENT.fullmatch(line):
            return
        if blank:
            if self._context == 'crypto':
                self._grow(line, end)  # an empty line inside the current crypto/key record
            self._keep(line, end)
        elif indented:
            self._subline(line, end)
        elif line == '!':
            self._context = 'global'
            self._keep(line, end)
        elif self._context == 'crypto':
            # Opaque up to its own real '!': an 'end' here is not the global end.  Every unindented
            # statement starts a new record of the stanza.
            self._start(line, end)
            self._hide(_BLOCK, end)
        elif line == 'end':
            self._context = 'global'
            self._phase = 'ended'
            self._keep(line, end)
        elif self._context == 'unknown':
            self._hide(_MODE, end)
        else:
            self._global(line, end)

    def _global(self, line, end):
        self._context = 'global'
        if _VERSION.fullmatch(line) or _HOSTNAME.fullmatch(line):
            if self._comparison:
                self._comparison_fields.add(line.split(' ', 1)[0])
            self._keep(line, end)
        elif _INTERFACE.fullmatch(line):
            self._context = 'interface' if self._keep(line, end) else 'unknown'
        elif (match := _VLAN.fullmatch(line)) and _vlan_id(match.group(1)):
            self._context = 'vlan' if self._keep(line, end) else 'unknown'
        elif _CRYPTO.match(line):
            self._context = 'crypto'
            self._start(line, end)
            self._hide(_BLOCK, end)
        else:
            self._context = 'unknown'
            self._hide(_UNSUPPORTED, end)

    def _subline(self, line, end):
        if self._context == 'interface':
            if line[1:2] not in (' ', '\t') and interface_line(line):
                self._keep(line, end)
            else:
                self._hide(_SUBLINE, end)
        elif self._context == 'vlan':
            if _VLAN_NAME.fullmatch(line):
                self._keep(line, end)
            else:
                self._hide(_SUBLINE, end)
        elif self._context == 'crypto':
            self._grow(line, end)  # body of the current crypto/key record
            self._emit(MARKER + end)
        else:
            self._hide(_MODE, end)

    def _keep(self, line, end):
        """Emit a verified line unchanged unless it holds a forbidden value or a reserved marker."""
        data = (line + end).encode('ascii')
        if any(secret in data for secret in self._secrets):
            self.credential_count += 1
            self._hidden_record(_CREDENTIAL)
            self._emit(MARKER + end)
            return False
        if any(marker in data for marker in self._builder.forbidden):
            self._hide(_RESERVED, end)
            return False
        self._emit(line + end)
        return True

    def _hide(self, label, end):
        self.unverified_count += 1
        if label in _FORMAT_LABELS:
            self.unsupported_format_count += 1
        if label not in self._labels:
            self._labels.append(label)
        self._hidden_record(label)
        self._emit(MARKER + end)

    def _hidden_record(self, label):
        if len(self._hidden) >= MAX_HIDDEN_RECORDS:
            raise self._failure('capture-limit-exceeded')
        ordinal = len(self._hidden).to_bytes(8, 'big')
        self._hidden.add(hashlib.sha256(b'cisco-ios hidden record\0' + ordinal).digest()[:16],
                         hashlib.sha256(label.encode('ascii')).digest()[:16])

    def _emit(self, text):
        if self._comparison:
            text = text.replace('\r\n', '\n').replace('\r', '\n')
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
        if self._cr_held:
            self._cr_held = False
            self._line('\r')
        elif self._physical:
            self._line('')
        if (self._block is not None or self._phase != 'ended'
                or (self._comparison and self._comparison_fields != {'hostname', 'version'})):
            raise self._failure('stream-incomplete')
        # IOS XE can include the configuration file's extra final newline in its reported byte count.
        if self._comparison_view is not None and self._declared_size not in (self._body_size, self._body_size + 1):
            raise self._failure('stream-incomplete')
        _budget(self._memory())
        count = self.credential_count + self.unverified_count
        if count != len(self._hidden):
            raise ValueError('hidden record count mismatch')
        content = self._builder.finish()
        hidden, self._hidden = self._hidden, None
        self._state = 'finished'
        return content, hidden, count
