"""Conservative indentation-based running-config stream consumers for NX-OS and EOS (bod 06).

This is an internal stream consumer.  It adds no SSH command, adapter, admitted firmware, model or gate of
its own; the public ``config_read`` of NX-OS and EOS uses it through their adapters and the engine.  The
bounded decoder/feed/error/finish scaffolding is a local copy of the accepted IOS consumer (same
constructor ``(forbidden, section, limits=...)``, same shared ``ContentBuilder``/
``ConfigurationLimits``/``HiddenRecords``/error classes, same ``MARKER`` contract); the line grammar is
new.  The allowlists are not a complete NX-OS or EOS schema.

Policy (a stateful line parser over indentation, not a CLI interpreter):

* Structure comes from indentation only.  Every non-blank, non-``!`` line pops the context stack
  down to the nearest line with a smaller indentation; that line is its parent.  A line is
  interpreted only when its parent is a verified context and it is indented by exactly one dialect
  unit more than the parent (NX-OS 2 spaces, EOS 3 spaces).  Every other line is replaced by the
  dialect ``MARKER`` and opens an opaque context: nothing below a hidden line is ever interpreted.
  A tab in the indentation or a nesting deeper than 64 levels refuses the stream.
* Kept lines (copied unchanged with their original line ending, nothing is synthesized):
  ``hostname``; ``interface <name>`` with ``description``, ``ip address`` (``A.B.C.D/len`` or
  netmask), ``ipv6 address``, ``switchport`` (mode access/trunk, access vlan, trunk allowed/native
  vlan), ``no switchport``, ``channel-group``, ``mtu``, ``speed``, ``duplex``, ``shutdown``/``no
  shutdown``, ``vrf member``/``vrf`` and ``spanning-tree`` keyword lines; ``vlan <list>`` with
  ``name``; ``vrf context`` (NX-OS) / ``vrf instance`` (EOS) with static routes; static ``ip
  route``/``ipv6 route``; ``router ospf|bgp <id>`` with ``router-id``, ``network``, ``neighbor <ip>
  remote-as <asn>`` and ``address-family`` (with ``network``); NX-OS ``neighbor <ip>`` blocks with
  ``remote-as``; NX-OS ``feature <x>``; global ``spanning-tree`` keyword lines; ``!`` and blank
  lines; the EOS ``end``.  Everything else is one MARKER per physical line.
* Every kept line is checked against all forbidden values, the serialized secret markers of the
  shared ``ContentBuilder``, a list of secret keywords (``password``, ``secret``, ``key``,
  ``community``, ``auth``, ``priv``, ``-cvauth=`` ...) and recognizable password hashes (crypt
  ``$1$``/``$2a$``/``$2b$``/``$2y$``/``$5$``/``$6$``/``$8$``/``$9$``/``$y$`` ... and the Cisco type 7
  form), independent of ``forbidden``; any hit hides the whole line and its block.
* Opaque records come before command recognition: a banner (NX-OS: delimiter as written; EOS:
  ``banner login|motd`` up to an exact ``EOF`` line), a PEM block (an exact
  ``-----BEGIN <label>-----`` line up to the exact ``-----END <same label>-----`` line; any other
  line holding ``-----BEGIN`` or ``-----END`` refuses the stream), an EOS here-document
  (``action bash`` / ``comment`` up to an ``EOF`` line) and an open quoted value or
  trailing-backslash continuation are hidden up to their real end.  An indented banner header or
  an unknown banner form refuses the stream; an unclosed block at EOF is ``stream-incomplete``.
  Hidden data is never kept for later classification.
* Completeness: EOS requires the global ``end`` (after it only blank lines).  NX-OS prints no
  ``end``: the first non-blank line must be the exact ``!Command: show running-config`` frame and the
  last physical line must be terminated by a line ending before ``finish()`` (EOF); a later public
  path still has to report the capture as not provably complete.
* Counting: one hidden logical record per hidden line, except that a banner, PEM block,
  here-document or quoted/escaped continuation is one record (one marker per physical line, one
  shared ``logical_record_bytes`` budget).  ``HiddenRecords`` holds one generic entry per hidden
  record (an ordinal key and a label digest); nothing derived from the input is stored there.
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

NXOS_MARKER = '<UNVERIFIED:cisco-nxos-opaque-line>'
EOS_MARKER = '<UNVERIFIED:arista-eos-opaque-line>'
MAX_HIDDEN_RECORDS = 1 << 20

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufffd]')
_PAGER = re.compile(r'--\s*More\s*--', re.I)
_NEWLINE = re.compile('[\r\n]')
_BLANK = re.compile('[ \t]*')
_QUOTED_STOP = re.compile(r'[\\"]')
_SEPARATOR = re.compile(r'![ ]*')
_END = re.compile(r'end[ ]*')

# Opaque multi-line records.
_BANNER_WORD = re.compile(r'banner(?:[ \t]|$)')
_NXOS_BANNER = re.compile(r'banner[ ]+[a-z][a-z0-9-]{0,31}[ ]+(.+)', re.S)
_EOS_BANNER = re.compile(r'banner (?:login|motd)[ ]*')
_CARET = re.compile(r'\^[@A-Z\[\\\]^_]')
_PRINTABLE = re.compile(r'[\x21-\x7e]')
_HEREDOC = re.compile(r'(?:action bash|comment)[ ]*')
_HEREDOC_END = 'EOF'
_PEM_BEGIN = '-----BEGIN'
_PEM_END = '-----END'
# RFC 7468 label: printable ASCII without '-', single inner spaces.  The opening line (after the
# indentation) must be exactly '-----BEGIN <label>-----'; the block ends only on the exact line
# '-----END <same label>-----' (after the indentation).  Any other line holding '-----BEGIN' or
# '-----END' is an unverifiable format and refuses the stream.
_PEM_LABEL = r'[\x21-\x2c\x2e-\x7e]{1,32}(?: [\x21-\x2c\x2e-\x7e]{1,32}){0,7}'
_PEM_BEGIN_LINE = re.compile('-----BEGIN (' + _PEM_LABEL + ')-----')

# Secret keywords: a hit hides an otherwise allowed line (defense in depth next to the allowlist).
_SECRET_TEXT = ('password', 'secret', 'passphrase', 'cvauth', 'community', 'localizedkey',
                'key-string', 'authentication-key', 'message-digest-key')
_SECRET_TOKENS = frozenset(('key', 'auth', 'priv', 'md5', 'sha'))
_TOKEN_SPLIT = re.compile(r'[ \t",=:]+')
# Recognizable password hashes: a hit hides the whole line whatever ``forbidden`` holds (the shared
# ContentBuilder markers only know '$6$' / '$9$').  crypt prefixes $1$ (MD5, Cisco type 5), $2a$/
# $2b$/$2x$/$2y$ (bcrypt), $5$ (SHA-256), $6$ (SHA-512), $7$ (scrypt), $8$/$9$ (Cisco type 8/9),
# $y$/$gy$ (yescrypt), $sha1$, $md5$, $argon2*$; and the Cisco type 7 form '7 <seed><hex pairs>':
# a decimal seed 00-15 followed by an even number (at least 2: a one-character password is one
# encrypted byte, '7 0005', review 219-rv) of hex digits.  The value is bounded by
# anything that is not a word character on the left and anything that is not a hex digit on the right,
# so trailing punctuation (',', ';', ')', '.', ...) still matches (review 147-r2rv); a plain number such
# as '7 2026' (seed 20) is not a type 7 value; '7 1500' has the type 7 shape and is hidden (security
# first).
_CRYPT_HASH = re.compile(r'\$(?:1|2[abxy]?|5|6|7|8|9|y|gy|sha1|md5|argon2(?:i|d|id))[$,]', re.I)
_TYPE7 = re.compile(r'(?<![0-9A-Za-z_])7[ \t]+(?:0[0-9]|1[0-5])(?:[0-9A-Fa-f]{2})+(?![0-9A-Fa-f])')

# Shared tokens.
_HOST = r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}'
_NAME = r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}'
_IFNAME = r'[A-Za-z][A-Za-z-]{0,31}[0-9][0-9/.:]{0,31}'
_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = _OCTET + r'(?:\.' + _OCTET + '){3}'
_LEN4 = r'(?:3[0-2]|[12]?[0-9])'
_V6 = r'[0-9A-Fa-f:.]{2,45}'
_LEN6 = r'(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])'
_ASN = r'[0-9]{1,10}(?:\.[0-9]{1,5})?'
_ITEM = r'[1-9][0-9]{0,3}(?:-[1-9][0-9]{0,3})?'
_VLANS = _ITEM + '(?:,' + _ITEM + '){0,255}'
_T = '[ ]*'  # trailing spaces are tolerated on every kept statement

# Global statements.
_HOSTNAME = re.compile(r'hostname ' + _HOST + _T)
_INTERFACE = re.compile(r'interface ' + _IFNAME + _T)
_VLAN = re.compile(r'vlan (' + _VLANS + ')' + _T)
_NXOS_VRF = re.compile(r'vrf context ' + _NAME + _T)
_EOS_VRF = re.compile(r'vrf instance ' + _NAME + _T)
_FEATURE = re.compile(r'feature [a-z0-9][a-z0-9+_-]{0,31}' + _T)
_SPANNING_TREE = re.compile(r'spanning-tree(?: [a-z0-9][a-z0-9,-]{0,63}){1,8}' + _T)
_ROUTER = re.compile(r'router (?:ospf ' + _NAME + '(?: vrf ' + _NAME + ')?|bgp ' + _ASN + ')' + _T)
_IFNAME_TOKEN = re.compile(_IFNAME)
_DISTANCE = re.compile(r'[0-9]{1,3}')
_ROUTE_OPTION = r'(?: [0-9]{1,3}| tag [0-9]{1,10}| name ' + _NAME + '| vrf ' + _NAME + r'| track [0-9]{1,4})'
_IP_ROUTE = re.compile(r'ip route(?: vrf ' + _NAME + ')? ' + _IPV4 + '/' + _LEN4 +
                       '(?: (?:' + _IPV4 + '|' + _IFNAME + ')){1,2}' + _ROUTE_OPTION + '{0,6}' + _T)
_IPV6_ROUTE = re.compile(r'ipv6 route(?: vrf ' + _NAME + ')? (' + _V6 + ')/' + _LEN6 +
                         '((?: (?:' + _V6 + '|' + _IFNAME + ')){1,2})' + _ROUTE_OPTION + '{0,6}' + _T)

# Interface sub-lines.
_DESCRIPTION = re.compile(r'description [\x20\x21\x23-\x5b\x5d-\x7e]{1,240}')
_IP_PREFIX = re.compile(r'ip address ' + _IPV4 + '/' + _LEN4 + '(?: secondary)?' + _T)
_IP_MASK = re.compile(r'ip address ' + _IPV4 + ' (' + _IPV4 + ')(?: secondary)?' + _T)
_IPV6_ADDRESS = re.compile(r'ipv6 address (' + _V6 + ')/' + _LEN6 + _T)
_FIXED_SUBLINES = frozenset(('shutdown', 'no shutdown', 'switchport', 'no switchport',
                             'switchport mode access', 'switchport mode trunk'))
_ACCESS_VLAN = re.compile(r'switchport (?:access|trunk native) vlan ([1-9][0-9]{0,3})' + _T)
_ALLOWED_VLANS = re.compile(r'switchport trunk allowed vlan (?:none|all|(?:(?:add|remove|except) )?(' +
                            _VLANS + '))' + _T)
_CHANNEL_GROUP = re.compile(r'channel-group [0-9]{1,4}(?: mode (?:active|passive|on))?' + _T)
_MTU = re.compile(r'mtu ([0-9]{2,5})' + _T)
_SPEED = re.compile(r'speed(?: [a-z0-9-]{1,16}){1,2}' + _T)
_DUPLEX = re.compile(r'duplex (?:auto|full|half)' + _T)
_VRF_MEMBER = re.compile(r'vrf (?:member )?' + _NAME + _T)

# VLAN, routing protocol sub-lines.
_VLAN_NAME = re.compile(r'name [A-Za-z0-9][A-Za-z0-9._-]{0,31}' + _T)
_ROUTER_ID = re.compile(r'router-id ' + _IPV4 + _T)
_NETWORK = re.compile(r'network ' + _IPV4 + '/' + _LEN4 + '(?: area (?:' + _IPV4 + '|[0-9]{1,10}))?' + _T)
_NETWORK6 = re.compile(r'network (' + _V6 + ')/' + _LEN6 + _T)
_NEIGHBOR = re.compile(r'neighbor (' + _IPV4 + '|' + _V6 + ')( remote-as ' + _ASN + ')?' + _T)
_REMOTE_AS = re.compile(r'remote-as ' + _ASN + _T)
_ADDRESS_FAMILY = re.compile(r'address-family [a-z0-9]{2,12}(?: [a-z0-9-]{2,20})?' + _T)

_LEAF, _OPAQUE = 'leaf', 'opaque'
# Upper bound of one context stack entry (list slot, tuple, indentation int) and of the nesting
# depth (real configurations nest a few levels; a deeper stream is refused, which also keeps the
# per-line stack walk bounded).
_STACK_ENTRY = 128
_MAX_DEPTH = 64


def _vlan_id(text):
    return 1 <= int(text) <= 4094


def _vlan_list(text):
    for item in text.split(','):
        low, unused, high = item.partition('-')
        if not _vlan_id(low) or (high and (not _vlan_id(high) or int(high) < int(low))):
            return False
    return True


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


def _address(text):
    """A valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _static_route(body):
    if _IP_ROUTE.fullmatch(body):
        return True
    match = _IPV6_ROUTE.fullmatch(body)
    if match is None or not _ipv6(match.group(1)):
        return False
    # Every next-hop token is an interface name, a valid IPv6 address or a plain distance.
    return all(_ipv6(hop) or _IFNAME_TOKEN.fullmatch(hop) or _DISTANCE.fullmatch(hop)
               for hop in match.group(2).split())


def _interface_line(body):
    if body.rstrip(' ') in _FIXED_SUBLINES:
        return True
    if (_DESCRIPTION.fullmatch(body) or _IP_PREFIX.fullmatch(body) or _CHANNEL_GROUP.fullmatch(body) or
            _SPEED.fullmatch(body) or _DUPLEX.fullmatch(body) or _VRF_MEMBER.fullmatch(body) or
            _SPANNING_TREE.fullmatch(body)):
        return True
    if match := _IP_MASK.fullmatch(body):
        return _netmask(match.group(1))
    if match := _IPV6_ADDRESS.fullmatch(body):
        return _ipv6(match.group(1))
    if match := _ACCESS_VLAN.fullmatch(body):
        return _vlan_id(match.group(1))
    if match := _ALLOWED_VLANS.fullmatch(body):
        return match.group(1) is None or _vlan_list(match.group(1))
    if match := _MTU.fullmatch(body):
        return 64 <= int(match.group(1)) <= 65535
    return False


def _password_hash(text):
    return _CRYPT_HASH.search(text) is not None or _TYPE7.search(text) is not None


def _secret_word(text):
    lowered = text.lower()
    if any(word in lowered for word in _SECRET_TEXT):
        return True
    return any(token in _SECRET_TOKENS for token in _TOKEN_SPLIT.split(lowered))


class _IndentedStreamRedactor:
    """Incremental consumer: ``feed(bytes)`` ... ``finish()`` -> (Content, HiddenRecords, count)."""

    MARKER = None
    DIALECT = None
    UNIT = 0

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
        self._hidden = HiddenRecords()
        self._decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self._state = 'open'
        self._raw_bytes = 0
        self._cr_held = False
        self._physical, self._physical_bytes, self._physical_memory = [], 0, 0
        self._line_memory = 0
        self._work = 0
        self._phase = 'preamble'      # preamble -> body -> ended (EOS only)
        self._stack = []              # [(indent, context)] of the open parents
        self._block = None            # None | 'banner' | 'eof' | 'heredoc' | 'pem' | 'continuation'
        self._delimiter = None
        self._pem_end = None          # the exact '-----END <label>-----' closing the open PEM block
        self._in_quote = False
        self._record_bytes = 0
        self._line_number = self._error_line = 0
        self._lines = 0
        self.credential_count = self.unverified_count = self.unsupported_format_count = 0
        self._labels = []
        prefix = self.DIALECT + ' / '
        (self._UNSUPPORTED, self._SUBLINE, self._MODE, self._COMMENT, self._MULTILINE, self._BLOCK,
         self._RESERVED, self._CREDENTIAL, self._KEYWORD, self._HASH) = (
            prefix + label for label in (
                'unsupported-statement', 'unsupported-sub-line', 'opaque-mode-line', 'comment-line',
                'multiline-record', 'opaque-block', 'reserved-marker-collision', 'forbidden-value',
                'secret-keyword', 'password-hash'))
        self._format_labels = frozenset((self._MULTILINE, self._BLOCK))

    def __repr__(self):
        return '<%s configuration stream state=%s lines=%d masked=%d>' % (
            self.DIALECT, self._state, self._lines, self.credential_count + self.unverified_count)

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
        self._stack = []
        self._block = self._delimiter = self._pem_end = None
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
                sys.getsizeof(self._physical) + _STACK_ENTRY * len(self._stack) + self._work)
        if used > self.limits.memory_bytes:
            raise ConfigurationBudgetError('configuration memory budget exhausted for target; output withheld')
        return used

    # -- bounded decoding (same as the IOS consumer, with a held CR so CRLF is kept as written) --

    _SLICE_BYTES = 4096
    _WORK_BASE = 512
    _WORK_PER_BYTE = 12
    _LINE_COPIES = 3

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
                size = min(self._SLICE_BYTES, len(view) - offset,
                           (room - self._WORK_BASE) // self._WORK_PER_BYTE)
                if size < 1:
                    raise ConfigurationBudgetError(
                        'configuration memory budget exhausted for target; output withheld')
                self._work = self._WORK_BASE + self._WORK_PER_BYTE * size
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
        self._physical.clear()
        self._physical_bytes = self._physical_memory = 0
        self._line_memory = self._LINE_COPIES * sys.getsizeof(line)
        self._memory()
        self._line_number += 1
        self._error_line = self._line_number
        if _PAGER.search(line):
            raise ValueError('pager prompt in configuration stream')
        self._controls(line)
        if self._block is None:
            self._logical(line, end)
        else:
            self._grow(line, end)
            self._emit(self.MARKER + end)
            self._block_line(line)
        self._line_memory = 0
        self._lines += 1
        if self._lines % 1024 == 0:
            _budget(self._memory())

    def _block_line(self, line):
        """Advance the open opaque block with one more (already hidden) physical line."""
        if self._block == 'banner':
            if self._delimiter in line:
                self._block = self._delimiter = None
        elif self._block == 'eof':
            if line == _HEREDOC_END:
                self._block = None
        elif self._block == 'heredoc':
            if line.strip(' ') == _HEREDOC_END:
                self._block = None
        elif self._block == 'pem':
            body = line.lstrip(' ')
            if body == self._pem_end:
                self._block = self._pem_end = None
            elif _PEM_END in line or _PEM_BEGIN in line:
                # A foreign or malformed boundary: the block end cannot be verified.
                raise ValueError('unverifiable PEM boundary')
        else:
            state = self._quote_state(line, self._in_quote)
            if state is None:
                self._block = None
            self._in_quote = state == 'quote'

    def _controls(self, line):
        if _CONTROL.search(line):
            raise ValueError('control character in configuration stream')

    def _grow(self, line, end):
        self._record_bytes += len(line.encode('utf-8')) + len(end)
        if self._record_bytes > self.limits.logical_record_bytes:
            raise self._failure('capture-limit-exceeded')

    def _open(self, block, line, end):
        """Hide ``line`` as the first line of one opaque multi-line record."""
        self._block = block
        self._record_bytes = 0
        self._grow(line, end)
        self._hide(self._MULTILINE if block == 'continuation' else self._BLOCK, end)

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

    def _logical(self, line, end):
        if _BLANK.fullmatch(line):
            self._keep(line, end)
            return
        body = line.lstrip(' ')
        indent = len(line) - len(body)
        if body[:1] == '\t':
            raise ValueError('tab in configuration indentation')
        if self._phase == 'ended':
            raise ValueError('data after configuration end')
        if not indent and body.startswith('%'):
            raise ConfigurationRefusedError()
        if self._phase == 'preamble':
            self._phase = 'body'
            if self._preamble(line, end):
                return
        if _BANNER_WORD.match(body):
            if indent:
                # Hiding only the header would let the body be read as configuration.
                raise ValueError('indented banner header')
            self._stack = [(0, _OPAQUE)]
            self._banner(line, end)
            return
        if body.startswith('!'):
            # A separator is kept unless it lies inside an opaque block; a comment ('!Time:',
            # '! device:', '!! text') is hidden.  Neither changes the context, and a comment is
            # always one physical line.
            if not _SEPARATOR.fullmatch(body):
                self._hide(self._COMMENT, end)
            elif indent and self._parent(indent) in (_OPAQUE, _LEAF):
                self._hide(self._MODE, end)
            else:
                self._keep(line, end)
            return
        if not indent and self._end(line, end):
            return
        while self._stack and self._stack[-1][0] >= indent:
            self._stack.pop()
        parent_indent, parent = self._stack[-1] if self._stack else (-self.UNIT, 'global')
        self._stack.append((indent, _OPAQUE))
        if len(self._stack) > _MAX_DEPTH:
            raise ValueError('configuration nesting too deep')
        if _PEM_BEGIN in body or _PEM_END in body:
            match = _PEM_BEGIN_LINE.fullmatch(body)
            if match is None:
                # Not exactly '-----BEGIN <label>-----' (e.g. an inline '-----END', a stray END or
                # trailing text): the block boundaries cannot be verified.
                raise ValueError('unverifiable PEM boundary')
            self._open('pem', line, end)
            self._pem_end = '-----END ' + match.group(1) + '-----'
            return
        if self._heredoc(body):
            self._open('heredoc', line, end)
            return
        state = self._quote_state(line, False)
        if state is not None:
            self._open('continuation', line, end)
            self._in_quote = state == 'quote'
            return
        if parent in (_OPAQUE, _LEAF) or indent != parent_indent + self.UNIT:
            self._hide(self._MODE, end)
            return
        context = self._classify(parent, body)
        if context is None:
            self._hide(self._UNSUPPORTED if parent == 'global' else self._SUBLINE, end)
        elif self._keep(line, end):
            self._stack[-1] = (indent, context)

    def _parent(self, indent):
        """The context of the innermost open line indented less than ``indent`` (stack unchanged)."""
        for opened, context in reversed(self._stack):
            if opened < indent:
                return context
        return 'global'

    def _classify(self, parent, body):
        """The context opened by an allowed ``body`` under ``parent``, or ``None`` when not allowed."""
        if parent == 'global':
            return self._global(body)
        if parent == 'interface':
            return _LEAF if _interface_line(body) else None
        if parent == 'vlan':
            return _LEAF if _VLAN_NAME.fullmatch(body) else None
        if parent == 'vrf':
            return _LEAF if _static_route(body) else None
        if parent == 'router':
            if _ROUTER_ID.fullmatch(body) or self._network(body):
                return _LEAF
            if _ADDRESS_FAMILY.fullmatch(body):
                return 'family'
            return self._neighbor(body)
        if parent == 'family':
            return _LEAF if self._network(body) else None
        if parent == 'neighbor':
            return _LEAF if _REMOTE_AS.fullmatch(body) else None
        return None

    def _global(self, body):
        if _HOSTNAME.fullmatch(body) or _SPANNING_TREE.fullmatch(body) or _static_route(body):
            return _LEAF
        if _INTERFACE.fullmatch(body):
            return 'interface'
        if (match := _VLAN.fullmatch(body)) and _vlan_list(match.group(1)):
            return 'vlan'
        if _ROUTER.fullmatch(body):
            return 'router'
        return self._dialect_global(body)

    @staticmethod
    def _network(body):
        if _NETWORK.fullmatch(body):
            return True
        match = _NETWORK6.fullmatch(body)
        return match is not None and _ipv6(match.group(1))

    def _keep(self, line, end):
        """Emit a verified line unchanged unless it holds a forbidden value, a reserved marker or a
        secret keyword."""
        data = (line + end).encode('ascii')
        if any(secret in data for secret in self._secrets):
            self.credential_count += 1
            self._hidden_record(self._CREDENTIAL)
            self._emit(self.MARKER + end)
            return False
        if _secret_word(line):
            self.credential_count += 1
            self._hidden_record(self._KEYWORD)
            self._emit(self.MARKER + end)
            return False
        if _password_hash(line):
            self.credential_count += 1
            self._hidden_record(self._HASH)
            self._emit(self.MARKER + end)
            return False
        if any(marker in data for marker in self._builder.forbidden):
            self._hide(self._RESERVED, end)
            return False
        self._emit(line + end)
        return True

    def _hide(self, label, end):
        self.unverified_count += 1
        if label in self._format_labels:
            self.unsupported_format_count += 1
        if label not in self._labels:
            self._labels.append(label)
        self._hidden_record(label)
        self._emit(self.MARKER + end)

    def _hidden_record(self, label):
        if len(self._hidden) >= MAX_HIDDEN_RECORDS:
            raise self._failure('capture-limit-exceeded')
        ordinal = len(self._hidden).to_bytes(8, 'big')
        self._hidden.add(hashlib.sha256(self.DIALECT.encode('ascii') + b' hidden record\0' + ordinal).digest()[:16],
                         hashlib.sha256(label.encode('ascii')).digest()[:16])

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
        if self._cr_held:
            self._cr_held = False
            self._line('\r')
        elif self._physical:
            self._last_line()
        if self._block is not None or not self._complete():
            raise self._failure('stream-incomplete')
        _budget(self._memory())
        count = self.credential_count + self.unverified_count
        if count != len(self._hidden):
            raise ValueError('hidden record count mismatch')
        content = self._builder.finish()
        hidden, self._hidden = self._hidden, None
        self._state = 'finished'
        return content, hidden, count

    # -- dialect hooks --

    def _preamble(self, line, end):
        raise NotImplementedError

    def _end(self, line, end):
        raise NotImplementedError

    def _banner(self, line, end):
        raise NotImplementedError

    def _heredoc(self, body):
        raise NotImplementedError

    def _dialect_global(self, body):
        raise NotImplementedError

    def _neighbor(self, body):
        raise NotImplementedError

    def _last_line(self):
        raise NotImplementedError

    def _complete(self):
        raise NotImplementedError


_NXOS_HEADER = re.compile(r'!Command: show running-config[ ]*')


class NxosStreamRedactor(_IndentedStreamRedactor):
    """Cisco NX-OS ``show running-config``: two-space indentation, no ``!`` separators, no ``end``."""

    MARKER = NXOS_MARKER
    DIALECT = 'cisco-nxos'
    UNIT = 2

    def _preamble(self, line, end):
        # The first non-blank line must be the exact command frame; anything else is not a verified
        # start of a running-config.
        if not _NXOS_HEADER.fullmatch(line):
            raise ValueError('missing running-config header')
        self._keep(line, end)
        return True

    def _end(self, line, end):
        return False  # NX-OS prints no 'end'; an unindented 'end' is an ordinary unknown statement

    def _banner(self, line, end):
        match = _NXOS_BANNER.fullmatch(line)
        if match is None:
            raise ValueError('unknown banner form')
        rest = match.group(1)
        if _CARET.match(rest):
            delimiter = rest[:2]
        elif _PRINTABLE.match(rest):
            delimiter = rest[0]
        else:
            raise ValueError('unknown banner delimiter')
        self._open('banner', line, end)
        if delimiter in rest[len(delimiter):]:
            self._block = None
        else:
            self._delimiter = delimiter

    def _heredoc(self, body):
        return False

    def _dialect_global(self, body):
        if _FEATURE.fullmatch(body):
            return _LEAF
        if _NXOS_VRF.fullmatch(body):
            return 'vrf'
        return None

    def _neighbor(self, body):
        # NX-OS prints a BGP neighbor as a block ('neighbor A' + indented 'remote-as N').
        match = _NEIGHBOR.fullmatch(body)
        if match is None or not _address(match.group(1)):
            return None
        return 'neighbor'

    def _last_line(self):
        # A last physical line without a line ending may be truncated: not a complete stream.
        raise self._failure('stream-incomplete')

    def _complete(self):
        return self._phase == 'body'


class EosStreamRedactor(_IndentedStreamRedactor):
    """Arista EOS ``show running-config``: three-space indentation, ``!`` separators, final ``end``."""

    MARKER = EOS_MARKER
    DIALECT = 'arista-eos'
    UNIT = 3

    def _preamble(self, line, end):
        return False  # the '! Command:' / '! device:' comment frame is hidden like any comment

    def _end(self, line, end):
        if not _END.fullmatch(line):
            return False
        self._stack = []
        self._phase = 'ended'
        self._keep(line, end)
        return True

    def _banner(self, line, end):
        if not _EOS_BANNER.fullmatch(line):
            raise ValueError('unknown banner form')
        # EOS ends the banner text with an exact, unindented 'EOF' line.
        self._open('eof', line, end)

    def _heredoc(self, body):
        return _HEREDOC.fullmatch(body) is not None

    def _dialect_global(self, body):
        return 'vrf' if _EOS_VRF.fullmatch(body) else None

    def _neighbor(self, body):
        match = _NEIGHBOR.fullmatch(body)
        if match is None or match.group(2) is None or not _address(match.group(1)):
            return None
        return _LEAF

    def _last_line(self):
        self._line('')

    def _complete(self):
        return self._phase == 'ended'
