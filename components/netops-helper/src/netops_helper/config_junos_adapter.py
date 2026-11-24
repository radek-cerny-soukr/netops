"""Juniper Junos identity/profile adapter for the public ``config_read`` and ``config_diff`` (junos config, JP10).

Same shape as the Cisco/Arista adapters.  The tested combination is model ``ex9214`` (vJunos-switch) with Junos
``26.2R1.7`` (``tests/fixtures/real/juniper_junos_els/vjunosswitch_26.2R1.7/version.txt``); another model or
release is read too and reported as ``firmware_support`` ``untested`` with a warning (startup).  The model is read
only from the ``Model:`` line and the release only from the ``Junos:`` line of ``show version``, each of which
must occur exactly once.

Capture (measured on vJunos-switch, verification): ``show configuration | display set | no-more`` over SSH exec.  Every
statement is one physical line ``set <path...>`` (``deactivate <path...>`` for an inactive statement); the first
line is ``set version <release>``.  The exit status is 0 also for an error (``error:...`` on stdout).  An
account without the view-configuration permission (class read-only) gets ``set <section> /* ACCESS-DENIED */;``
lines with exit status 0: such a capture is refused as a device refusal, never shown as a configuration.

Redaction (``JunosSetRedactor``, an allowlist of statement paths, not a Junos schema): a line is kept unchanged
only when its path starts with an allowed prefix (``version``; ``system`` host-name, domain-name, domain-search,
time-zone, name-server, ntp, services, syslog, arp, processes and ``login user <name> uid|class|full-name``;
interfaces, vlans, routing-options, protocols, firewall, policy-options, routing-instances, chassis,
multi-chassis, switch-options, forwarding-options, class-of-service, poe, ethernet-switching-options,
virtual-chassis) and when it holds no forbidden value, no secret keyword and no password hash (the shared checks
of ``config_indented``: ``encrypted-password``, ``authentication-key``, ``secret``, ``$1$``/``$6$``/``$9$``...).
Every other line is one ``JUNOS_MARKER``.  Root authentication, the authentication of every login user, SNMP,
security (IKE/IPsec), access/RADIUS/TACACS and groups are therefore never shown.  An unclosed quoted value refuses
the stream (redaction-unverifiable); a last line without a line ending is ``stream-incomplete``.

Live comparison with a committed rollback (``config_diff`` base ``rollback:<1-49>``, other ``running``): one
visibility probe ``show configuration | display set | match ACCESS-DENIED | count`` must answer ``Count: 0
lines`` (a read-only account sees an EMPTY compare, measured, which would look identical), then ``show
configuration | compare rollback <n> | no-more``.  ``compare_lines`` interprets the hierarchical diff (``[edit
<path>]`` headers, ``+``/``-`` statement lines, nested ``{``/``}``) with the same path allowlist and secret
checks; a kept line is copied unchanged, every other one becomes ``<sign> JUNOS_MARKER``.  An unknown line shape
makes the comparison incomplete. A shared candidate comparison uses the same visibility probe and diff redactor
with ``show | compare | no-more`` in a shared configuration session that makes no edits.
"""

import hashlib
import json
import re

from netops_core import tested

from .config_indented import _BLANK, _IndentedStreamRedactor, _password_hash, _secret_word
from .configuration import ConfigurationRefusedError

PLATFORMS = ('juniper_junos', 'juniper_junos_els')
PLATFORM = 'juniper_junos_els'
COMMAND = 'show configuration | display set | no-more'
IDENTITY_COMMANDS = ('show version | no-more',)
VISIBILITY_COMMAND = 'show configuration | display set | match ACCESS-DENIED | count'
CANDIDATE_COMPARE = 'show | compare | no-more'
TESTED = ('ex9214', '26.2R1.7')
TESTED_NAME = 'Juniper Junos'
IDENTITY_MAX_BYTES = 65536
JUNOS_MARKER = '<UNVERIFIED:juniper-junos-opaque-line>'
ROLLBACK_MAX = 49
DIFF_MAX_BYTES = 48000

POLICY_DESCRIPTOR = ('juniper_junos', 'config_junos_adapter.JunosSetRedactor', 'junos-set-allowlist-1',
                     JUNOS_MARKER, COMMAND, IDENTITY_COMMANDS, TESTED)
PROFILE = 'juniper_junos-full-1:' + hashlib.sha256(
    json.dumps(POLICY_DESCRIPTOR, separators=(',', ':')).encode('ascii')).hexdigest()

VISIBILITY = ('account-rights-not-verified', 'formats-not-verified')

_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  �]')
_MODEL = re.compile(r'Model: ([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})')
_RELEASE = re.compile(r'Junos: ([0-9]{1,2}\.[0-9]{1,2}[A-Z][0-9]{1,3}(?:-S[0-9]{1,3})?(?:\.[0-9]{1,3})?)')
_VERSION_LINE = re.compile(r'set version [A-Za-z0-9][A-Za-z0-9._:-]{0,63}[ ]*')
_PAGER = re.compile(r'---\(more')
_DENIED = '/* ACCESS-DENIED */'
_ERROR = re.compile(r'[ \t]*error: ')
_COUNT = re.compile(r'Count: ([0-9]{1,9}) lines')
_ROLLBACK = re.compile(r'rollback:([1-9]|[1-4][0-9])')
_SECRET_DATA = '## SECRET-DATA'

# Statement path allowlist (after 'set'/'deactivate').
_OPEN_SECTIONS = frozenset(('interfaces', 'vlans', 'routing-options', 'protocols', 'firewall', 'policy-options',
                            'routing-instances', 'chassis', 'multi-chassis', 'switch-options', 'forwarding-options',
                            'class-of-service', 'poe', 'ethernet-switching-options', 'virtual-chassis'))
_SYSTEM_OPEN = frozenset(('host-name', 'domain-name', 'domain-search', 'time-zone', 'name-server', 'ntp',
                          'services', 'syslog', 'arp', 'processes'))
_LOGIN_USER_FIELDS = frozenset(('uid', 'class', 'full-name'))


def read_command(section, include_all, include_defaults, redaction='full', view='running'):
    """The capture command for the only admitted option set; anything else is refused before SSH."""
    if (type(section) is not str or section != 'all' or include_all is not True or
            include_defaults is not False or redaction != 'full' or view != 'running'):
        raise ValueError('config_platform_not_supported: juniper_junos supports only redaction full, '
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


def _one(lines, prefix, pattern):
    found = [line.strip(' \t') for line in lines if line.strip(' \t').startswith(prefix)]
    if len(found) != 1:
        raise ValueError('configuration identity could not be verified')
    match = pattern.fullmatch(found[0])
    if match is None:
        raise ValueError('configuration identity could not be verified')
    return match


def version_identity(version):
    """(model, release, release) from ``show version``; ValueError when not conclusive."""
    lines = _lines(version)
    model = _one(lines, 'Model:', _MODEL).group(1)
    release = _one(lines, 'Junos:', _RELEASE).group(1)
    return model, release, release


def firmware_record(firmware):
    return (type(firmware) is tuple and len(firmware) == 3 and all(type(item) is str and item for item in firmware)
            and _MODEL.fullmatch('Model: ' + firmware[0]) is not None
            and _RELEASE.fullmatch('Junos: ' + firmware[1]) is not None and firmware[2] == firmware[1])


def verify_identity(version):
    return version_identity(version), metadata()


def firmware_support(firmware):
    model, release, _ = firmware
    return tested.support(TESTED_NAME, release, [TESTED], model=model, function='config_read')


def metadata():
    return {'config_scope': 'device-account-visible', 'configuration_complete': False,
            'identity_scope_verified': False, 'visibility_limitations': list(VISIBILITY)}


def assess(metadata_fields, summary):
    """Same contract as the other adapters: never complete, never a verified identity, VISIBILITY once each."""
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


def words(text):
    """The words of a Junos statement (a quoted value is one word, quotes kept); None for unverifiable quoting."""
    result, position, size = [], 0, len(text)
    while position < size:
        while position < size and text[position] == ' ':
            position += 1
        if position >= size:
            break
        start = position
        if text[position] == '"':
            position += 1
            while position < size and text[position] != '"':
                position += 2 if text[position] == '\\' else 1
            if position >= size:
                return None
            position += 1
            if position < size and text[position] != ' ':
                return None
        else:
            while position < size and text[position] != ' ':
                if text[position] == '"':
                    return None
                position += 1
        result.append(text[start:position])
    return result


def allowed(path):
    """Whether a statement path (words after 'set') is in the readable allowlist."""
    if not path:
        return False
    head = path[0]
    if head == 'version':
        return len(path) == 2
    if head in _OPEN_SECTIONS:
        return len(path) >= 2
    if head == 'system' and len(path) >= 3:
        if path[1] in _SYSTEM_OPEN:
            return True
        return (path[1] == 'login' and len(path) == 6 and path[2] == 'user' and path[4] in _LOGIN_USER_FIELDS)
    return False


def safe_text(line, forbidden=()):
    """No forbidden value, secret keyword, password hash or Junos secret annotation in ``line``."""
    return not (_SECRET_DATA in line or _secret_word(line) or _password_hash(line) or
                any(value and value in line for value in forbidden))


class JunosSetRedactor(_IndentedStreamRedactor):
    """Capture one Junos display-set statement per line, escaped for the ASCII snapshot store."""

    MARKER = JUNOS_MARKER
    DIALECT = 'juniper-junos'
    UNIT = 1
    KEPT_ENCODING = 'utf-8'

    def _emit(self, text):
        # Preserve existing ASCII snapshots, including literal backslashes.
        if not text.isascii():
            text = text.replace('\\', '\\\\').encode('ascii', 'backslashreplace').decode('ascii')
        super()._emit(text)

    def _logical(self, line, end):
        if _PAGER.search(line):
            raise ValueError('pager prompt in configuration stream')
        if _DENIED in line or _ERROR.match(line):
            # The account does not see (part of) the configuration or the device refused the command.
            raise ConfigurationRefusedError()
        if _BLANK.fullmatch(line):
            self._keep(line, end)
            return
        if self._phase == 'preamble':
            if not _VERSION_LINE.fullmatch(line):
                raise ValueError('missing set version')
            self._phase = 'body'
            self._keep(line, end)
            return
        statement = words(line.rstrip(' '))
        if statement is None:
            raise ValueError('unverifiable quoting')
        if len(statement) < 2 or statement[0] not in ('set', 'deactivate'):
            self._hide(self._UNSUPPORTED, end)
            return
        if not allowed(statement[1:]):
            self._hide(self._UNSUPPORTED, end)
            return
        self._keep(line, end)

    def _end(self, line, end):
        return False

    def _last_line(self):
        raise self._failure('stream-incomplete')

    def _complete(self):
        return self._phase == 'body'


# ----------------------------------------------------------------------------- live comparison

def live_comparison(base, other):
    """Whether the selectors request a device-side comparison with running."""
    if base == 'running':
        return other == 'candidate'
    return type(base) is str and other == 'running' and (base == 'candidate' or _ROLLBACK.fullmatch(base) is not None)


def comparison_command(base):
    if base == 'candidate':
        return CANDIDATE_COMPARE
    match = _ROLLBACK.fullmatch(base) if type(base) is str else None
    if match is None:
        raise ValueError('invalid rollback selector')
    return 'show configuration | compare rollback %d | no-more' % int(match.group(1))


def visible(output):
    """True only for the exact answer 'Count: 0 lines' of VISIBILITY_COMMAND (the account sees everything)."""
    lines = [line.strip() for line in output.replace('\r', '').split('\n') if line.strip()]
    return len(lines) == 1 and _COUNT.fullmatch(lines[0]) is not None and int(_COUNT.fullmatch(lines[0]).group(1)) == 0


_HEADER = re.compile(r'\[edit(?: ([^\]]*))?\]')
_DIFF = re.compile(r'([-+ ])( *)(\S.*)')
_REVERSE_SIGN = str.maketrans('+-', '-+')
_STATEMENT_END = re.compile(r'(.*?)[ ]*(\{|;|\}|)[ ]*(?:## SECRET-DATA)?[ ]*')


def _statement(body):
    """(words, opens, closes) of one diff statement body; None for an unknown shape."""
    text = body
    for prefix in ('inactive: ', 'protect: '):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if text.startswith('/*') or text.startswith('#'):
        return None
    if text.rstrip() == '}':
        return [], False, True
    match = _STATEMENT_END.fullmatch(text)
    if match is None or match.group(2) not in ('{', ';'):
        return None
    content = match.group(1)
    if content.endswith(']') and '[' in content:
        # 'name [ a b ];' list form: the list items are values of one statement
        content = content.replace('[ ', '').replace(' ]', '')
    statement = words(content)
    if not statement:
        return None
    return statement, match.group(2) == '{', False


def compare_lines(output, forbidden=(), *, reverse=False):
    """Redact a hierarchical Junos comparison.

    Returns (lines, summary) where lines are the kept or masked lines and summary the counts.  ValueError for a
    device refusal; an unknown line shape is masked and counted in ``unparsed_lines`` (comparison incomplete).
    With reverse=True, signs and counts are expressed in the opposite snapshot order from the device output.
    """
    if type(output) is not str or _utf8_size(output) is None or _CONTROL.search(
            output.replace('\n', '').replace('\r', '').replace('\t', '')):
        raise ValueError('comparison unverifiable')
    if _PAGER.search(output):
        raise ValueError('comparison unverifiable')
    lines, counts = [], {'added_lines': 0, 'removed_lines': 0, 'hidden_added_lines': 0, 'hidden_removed_lines': 0,
                         'unparsed_lines': 0}
    header, stack = None, []
    for raw in output.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        if not raw.strip():
            continue
        if _ERROR.match(raw) or _DENIED in raw:
            raise ConfigurationRefusedError()
        found = _HEADER.fullmatch(raw.strip())
        if found is not None:
            path = words(found.group(1) or '')
            stack = []
            if path is None:
                header = None
                counts['unparsed_lines'] += 1
                lines.append(JUNOS_MARKER)
                continue
            header = path
            lines.append(raw.strip() if safe_text(raw, forbidden) else JUNOS_MARKER)
            continue
        found = _DIFF.fullmatch(raw)
        sign = found.group(1) if found is not None else ' '
        if reverse:
            sign = sign.translate(_REVERSE_SIGN)
        parsed = _statement(found.group(3)) if found is not None and header is not None else None
        if parsed is None:
            counts['unparsed_lines'] += 1
            if sign == '+':
                counts['added_lines'] += 1
                counts['hidden_added_lines'] += 1
            elif sign == '-':
                counts['removed_lines'] += 1
                counts['hidden_removed_lines'] += 1
            lines.append((sign + ' ' + JUNOS_MARKER) if sign in '+-' else JUNOS_MARKER)
            continue
        statement, opens, closes = parsed
        nested = [word for block in stack for word in block]
        if closes:
            if stack:
                stack.pop()
            keep = True
        else:
            keep = allowed(header + nested + statement) and safe_text(raw, forbidden)
            if opens:
                stack.append(statement)
        if sign in '+-':
            key = 'added_lines' if sign == '+' else 'removed_lines'
            counts[key] += 1
            if not keep:
                counts['hidden_' + key] += 1
        lines.append(sign + raw[1:] if keep else (sign + ' ' + JUNOS_MARKER if sign in '+-' else JUNOS_MARKER))
    return lines, counts
