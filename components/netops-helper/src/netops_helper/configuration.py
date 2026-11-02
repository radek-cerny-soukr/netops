from dataclasses import dataclass, replace
from collections import OrderedDict, deque
import codecs
import sys
from pathlib import Path
from contextlib import contextmanager
from itertools import zip_longest
from .config_buffers import Content, ContentBuilder, HiddenRecords, ChangedRecords, ContentLimitError
import hashlib
import json
import hmac
import re
import secrets
import shlex
from netops_core import prompt, ssh as core_ssh
from .config_limits import ConfigurationLimits
import threading
import time

_KEY = secrets.token_bytes(32)
_LOCK = threading.RLock()
_SNAPSHOTS = OrderedDict()
_MAX_BYTES = 48000
_BYTE_BUDGET = 512 * 1024 * 1024
_ACTIVE_BUDGET = _BYTE_BUDGET
_ACTIVE_TARGET = None
_TARGET_BUDGET = _BYTE_BUDGET
_CAPTURE_LOCK = threading.Lock()
_DIFFS = OrderedDict()
_TTL = 86400
PROFILE = 'fortios-minimal-4'
SECTIONS = frozenset(('system interface', 'firewall policy', 'firewall address',
                      'router static', 'vpn ipsec phase1-interface'))
_FORTIADC_REFUSAL = re.compile(
    r"Parsing error at '[A-Za-z0-9_.-]{1,64}'\. err=-?[0-9]{1,6}"
    r'|Command fail\. Return code is [+-]?[0-9]{1,6} \((?:[^()\r\n]{1,128}|\(null\))\)')
_HEADER = re.compile(r'^#(?:config-version|conf_file_ver|buildno|global_vdom)(?:[= :].*)?$')


@dataclass(frozen=True)
class FullConfigPolicy:
    platform: str
    public_fields: frozenset = frozenset()
    public_edit_sections: frozenset = frozenset()
    opaque_sections: frozenset = frozenset()
    header_keys: frozenset = frozenset()
    allow_vdom: bool = False
    secret_fields: frozenset = frozenset()
    unverified_fields: frozenset = frozenset()
    inline_header_fields: frozenset = frozenset()
    sibling_header_fields: frozenset = frozenset()

    def __post_init__(self):
        if self.platform not in ('fortios', 'fortiadc') or type(self.allow_vdom) is not bool:
            raise ValueError('invalid full configuration policy')
        groups = (self.public_fields, self.public_edit_sections, self.opaque_sections, self.header_keys, self.secret_fields, self.unverified_fields,
                  self.inline_header_fields, self.sibling_header_fields)
        if any(type(group) is not frozenset or len(group) > 65536 for group in groups):
            raise ValueError('invalid full configuration policy')
        def path_ok(path):
            return (type(path) is tuple and 1 <= len(path) <= 32 and
                    all(type(part) is str and len(part) <= 256 and
                        all(re.fullmatch(self.grammar, word) for word in part.split(' ')) for part in path))
        if any(type(item) is not tuple or len(item) != 2 or not path_ok(item[0]) or
               type(item[1]) is not str or not re.fullmatch(self.grammar, item[1])
               for item in self.public_fields | self.secret_fields | self.unverified_fields | self.inline_header_fields):
            raise ValueError('invalid full configuration policy')
        if any(type(item) is not tuple or len(item) != 3 or not path_ok(item[0]) or
               any(type(field) is not str or not re.fullmatch(self.grammar, field) for field in item[1:]) or
               item[1] == item[2] for item in self.sibling_header_fields):
            raise ValueError('invalid full configuration policy')
        if len({item[0] for item in self.sibling_header_fields}) != len(self.sibling_header_fields):
            raise ValueError('invalid full configuration policy')
        if any(not path_ok(path) for group in (self.public_edit_sections, self.opaque_sections) for path in group):
            raise ValueError('invalid full configuration policy')
        if any(type(key) is not str or not re.fullmatch(self.grammar, key) for key in self.header_keys):
            raise ValueError('invalid full configuration policy')

    @property
    def grammar(self):
        return r'[A-Za-z][A-Za-z0-9_+-]*' if self.platform == 'fortiadc' else r'[A-Za-z0-9][A-Za-z0-9_+().-]*'

    @property
    def identifier(self):
        material = (self.platform, sorted(self.public_fields), sorted(self.public_edit_sections),
                    sorted(self.opaque_sections), sorted(self.header_keys), self.allow_vdom, sorted(self.secret_fields), sorted(self.unverified_fields), "embedded-cli-6",
                    sorted(self.inline_header_fields), sorted(self.sibling_header_fields))
        digest = hashlib.sha256(json.dumps(material, separators=(',', ':')).encode()).hexdigest()
        return self.platform + '-full-2:' + digest

    def opaque(self, path):
        return any(path[:len(prefix)] == prefix for prefix in self.opaque_sections)

    def header(self, line):
        found = re.fullmatch(r'#([a-z][a-z0-9_-]*)(?:[= :].*)?', line)
        return found is not None and found.group(1) in self.header_keys


_PRIVATE_PEM = re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----')
_CREDENTIAL_HASH = re.compile(r'^\$(?:[0-9]|apr1|2[aby])\$')
_HTTP_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_HTTP_HEADER = re.compile('(' + _HTTP_TOKEN + '):([ \t]*)([^\r\n]*)')
_HTTP_AUTH_SCHEME = re.compile('(' + _HTTP_TOKEN + '[ \t]+)[^ \t].*')
_HTTP_CREDENTIAL_HEADERS = ('authorization', 'proxy-authorization', 'x-api-key')
_HTTP_SCHEME_HEADERS = ('authorization', 'proxy-authorization')


_SHELL_ARGUMENT = re.compile(r'[A-Za-z0-9_./+-]+|--?[A-Za-z0-9][A-Za-z0-9_-]*=[A-Za-z0-9_./+-]+')

def _public_value(values, forbidden):
    return (bool(values) and not (len(values) > 1 and values[0] == 'ENC') and
            all(not _PRIVATE_PEM.search(value) and not _CREDENTIAL_HASH.match(value) and
                not any(secret and secret in value for secret in forbidden) for value in values))

def _quoted_value(value):
    return value if re.fullmatch(r'[A-Za-z0-9_./:@%+*-]+', value) else json.dumps(value, ensure_ascii=True)

def _snapshot_profile(profile, platform):
    if platform not in ('fortios', 'fortiadc'):
        raise ValueError('invalid configuration profile')
    if profile == PROFILE and platform == 'fortios':
        return
    if type(profile) is not str or re.fullmatch(re.escape(platform) + r'-full-[12]:[0-9a-f]{64}', profile) is None:
        raise ValueError('invalid configuration profile')


def _prune():
    now = time.monotonic()
    for key in list(_SNAPSHOTS):
        if now - _SNAPSHOTS[key].created > _TTL:
            del _SNAPSHOTS[key]
    for pair in list(_DIFFS):
        if any(key not in _SNAPSHOTS for key in pair):
            del _DIFFS[pair]

class ConfigurationBudgetError(ValueError):
    pass


def _budget(staged=0):
    with _LOCK:
        retained = sum(s.memory_bytes for s in _SNAPSHOTS.values())
        retained += sum(t.memory_bytes + c.memory_bytes for t,c,i in _DIFFS.values())
        if retained + staged > min(_BYTE_BUDGET, _ACTIVE_BUDGET):
            raise ConfigurationBudgetError('configuration memory budget exhausted; output withheld')
        if _ACTIVE_TARGET is not None:
            target_retained = sum(s.memory_bytes for s in _SNAPSHOTS.values()
                                  if s.scope[:3] == _ACTIVE_TARGET[:3])
            target_retained += sum(t.memory_bytes + c.memory_bytes for pair, (t,c,i) in _DIFFS.items()
                                   if pair[0] in _SNAPSHOTS and
                                   _SNAPSHOTS[pair[0]].scope[:3] == _ACTIVE_TARGET[:3])
            if target_retained + staged > _TARGET_BUDGET:
                raise ConfigurationBudgetError('configuration memory budget exhausted for target; output withheld')

def _available_memory():
    values = []
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                values.append(int(line.split()[1])*1024)
        base = Path('/sys/fs/cgroup')
        limit = (base/'memory.max').read_text().strip()
        if limit != 'max':
            values.append(max(0, int(limit)-int((base/'memory.current').read_text())))
    except (OSError, ValueError):
        pass
    return min(values) if values else 0

@contextmanager
def capture(limits=None, *, target=None):
    limits = ConfigurationLimits() if limits is None else limits
    if type(limits) is not ConfigurationLimits:
        raise ValueError("invalid configuration limits")
    global _ACTIVE_BUDGET, _ACTIVE_TARGET, _TARGET_BUDGET
    if not _CAPTURE_LOCK.acquire(blocking=False):
        raise ValueError('another configuration capture or comparison is active')
    try:
        with _LOCK:
            if target is not None:
                for identity in list(_SNAPSHOTS):
                    if _SNAPSHOTS[identity].scope[:3] == target[:3] and _SNAPSHOTS[identity].scope != target:
                        del _SNAPSHOTS[identity]
            _prune()
        available = _available_memory()
        if available < 64*1024*1024:
            raise ValueError('insufficient memory for configuration capture')
        with _LOCK:
            retained = sum(s.memory_bytes for s in _SNAPSHOTS.values())
            retained += sum(t.memory_bytes+c.memory_bytes for t,c,i in _DIFFS.values())
        _ACTIVE_BUDGET = min(_BYTE_BUDGET, retained + available - 64*1024*1024)
        _ACTIVE_TARGET, _TARGET_BUDGET = target, limits.memory_bytes
        _budget()
        yield
    finally:
        _ACTIVE_BUDGET = _BYTE_BUDGET
        _ACTIVE_TARGET, _TARGET_BUDGET = None, _BYTE_BUDGET
        _CAPTURE_LOCK.release()

def content_digest(text):
    return text.sha256 if isinstance(text, Content) else hashlib.sha256(text.encode()).hexdigest()

def read_command(section, include_all=False):
    if type(include_all) is not bool or not isinstance(section, str):
        raise ValueError('invalid configuration section')
    if section == 'all' and include_all:
        return 'show'
    if section in SECTIONS and not include_all:
        return 'show ' + section
    raise ValueError('invalid configuration section')

@dataclass(frozen=True)
class Snapshot:
    scope: tuple
    text: str
    hidden: tuple
    created: float
    redacted_count: int
    section: str
    firmware: tuple
    profile: str
    include_defaults: bool = False
    metadata: tuple = ()
    filtered: tuple | None = None

    @property
    def memory_bytes(self):
        return (self.text.memory_bytes + self.hidden.memory_bytes + sys.getsizeof(self) + 1024 +
                sum(sys.getsizeof(value) + (sum(sys.getsizeof(item) for item in value) if type(value) is tuple else 0)
                    for key, value in self.metadata) +
                (self.filtered[1].memory_bytes if self.filtered is not None else 0))

def require(auth, platform, permission):
    if platform not in ('fortios', 'fortinet', 'fortiadc'):
        raise ValueError('config_platform_not_supported')
    if auth.ssh_platform != ('fortiadc' if platform == 'fortiadc' else 'fortinet'):
        raise ValueError('configuration platform is outside target policy')
    rights = auth.read_inventory.get('config_access', ())
    if permission not in rights:
        raise ValueError('config access is not enabled for this target')
    auth.require_tcp_port(auth.port)

def require_single_vdom(status):
    from netops_core import platforms
    if (not isinstance(status, str) or len(status.encode()) > 65536 or
            any(ord(c) < 32 and c not in "\n\r\t" for c in status) or
            "\ufffd" in status):
        raise ValueError("configuration identity could not be verified")
    try:
        identity = platforms.version_record(status)
    except platforms.VersionRecordError:
        raise ValueError("configuration identity could not be verified") from None
    version_lines = [line for line in status.splitlines()
                     if line.lstrip().casefold().startswith("version:")]
    if (len(version_lines) != 1 or
            not re.fullmatch(r"(?:FortiGate|FortiWiFi)-[A-Za-z0-9_.+-]+", identity[0])):
        raise ValueError("configuration identity could not be verified")
    markers = [line for line in status.splitlines()
               if " ".join(line.split()).casefold().startswith("virtual domain configuration")]
    if markers != ["Virtual domain configuration: disable"]:
        raise ValueError("config_platform_not_supported: verified single-VDOM mode required")
    return identity

def scope(auth, platform='fortios'):
    if platform not in ('fortios', 'fortiadc') or auth.ssh_platform != ('fortinet' if platform == 'fortios' else 'fortiadc'):
        raise ValueError('configuration platform is outside target policy')
    material = '\0'.join((auth.alias, auth.host, str(auth.port), auth.login,
                          auth.host_key_fingerprint, auth.credential_kind, auth.secret))
    return (hmac.digest(_KEY, material.encode(), 'sha256'), platform, 'running', auth.configuration_limits.identity())


class UnsupportedConfigurationFirmware(ValueError):
    def __init__(self, message, *, detected=(), supported=()):
        def numeric(record):
            return (type(record) is tuple and len(record) == 2 and
                    all(type(value) is str and len(value) <= 32 for value in record) and
                    re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', record[0]) is not None and
                    re.fullmatch(r'[0-9]{4,6}', record[1]) is not None)
        if (type(detected) is not tuple or type(supported) is not tuple or len(supported) > 16 or
                bool(detected) != bool(supported) or
                (detected and (not numeric(detected) or not all(numeric(record) for record in supported)))):
            raise ValueError('invalid configuration firmware details')
        self.detected, self.supported = detected, supported
        super().__init__(message)


class ConfigurationRedactionError(ValueError):
    def __init__(self, reason, *, line=None, context=()):
        if reason not in ('stream-incomplete', 'redaction-unverifiable', 'capture-limit-exceeded'):
            raise ValueError('invalid configuration failure category')
        if line is not None and (type(line) is not int or not 1 <= line <= 2147483647):
            raise ValueError('invalid configuration failure location')
        if (type(context) is not tuple or len(context) > 32 or
                any(type(part) is not str or not re.fullmatch(r'[A-Za-z0-9_+(). -]{1,256}', part)
                    for part in context)):
            raise ValueError('invalid configuration failure context')
        self.reason, self.line, self.context = reason, line, context
        super().__init__('redaction could not be verified; output withheld')

    @property
    def location(self):
        return ((' at line ' + str(self.line)) if self.line is not None else '') + (
            (' in config ' + ' / '.join(self.context)) if self.context else '')


class ConfigurationRefusedError(ValueError):
    def __init__(self):
        super().__init__('configuration device-refused during capture; output withheld')


class StreamRedactor:
    def __init__(self, forbidden, section, *, policy=None, limits=None, _embedded_depth=0, _script_mode=False):
        self.limits = ConfigurationLimits() if limits is None else limits
        if type(self.limits) is not ConfigurationLimits:
            raise ValueError("invalid configuration limits")
        if policy is not None and type(policy) is not FullConfigPolicy:
            raise ValueError('invalid full configuration policy')
        if type(_script_mode) is not bool:
            raise ValueError('invalid embedded script mode')
        self._embedded_depth = _embedded_depth
        self._script_mode = _script_mode
        self._operational_seen = False
        self.budget_refusal = None
        self.line_number, self._error_line = 0, None
        self.policy, self.record_count, self.edit_index = policy, 0, 0
        self.credential_count, self.unverified_count, self.unsupported_format_count = 0, 0, 0
        self.unverified_fields = OrderedDict()
        self.unverified_truncated = False
        self.forbidden, self.section = tuple(forbidden), section
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.maximum = self.limits.all_bytes if section == 'all' else self.limits.section_bytes
        self.result = ContentBuilder(self.maximum, forbidden, serialized_markers=policy is None)
        self.hidden, self.stack, self.path = HiddenRecords(), [], []
        self.logical_bytes = self.physical_bytes = 0
        self.configured = self.refused = False
        self.started = self.header = self.closed = False
        self.count = self.raw_bytes = 0
        self.physical, self.pending = [], []
        self.quote, self.escaped, self.after_cr = None, False, False
        self.frame_first, self.frame_ended, self.frame_prompt = True, False, None
        self._sibling_fields = {path: (name, value) for path, name, value in
                                (policy.sibling_header_fields if policy else ())}
        self._sibling_output = []
        self._sibling_bytes = 0
        self._sibling_name = None
        self._sibling_name_count = self._sibling_value_count = 0

    def _unverified(self, context, field, unsupported=False):
        self.unverified_count += 1
        if unsupported:
            self.unsupported_format_count += 1
        label = ' / '.join(context + (field,))[:768]
        if label in self.unverified_fields or len(self.unverified_fields) < 32:
            self.unverified_fields[label] = None
        else:
            self.unverified_truncated = True
        return '<UNVERIFIED:unsupported-format>' if unsupported else '<UNVERIFIED:unclassified-field>'

    def _failure(self, reason):
        line = (self.line_number or None) if reason == 'stream-incomplete' else self._error_line
        context = tuple(part[7:].decode() for part in self.path if part.startswith(b'config\0'))
        if line is None or self.policy is None or not context:
            context = ()
        else:
            known = (any(path[:len(context)] == context for path in self.policy.public_edit_sections) or
                     any(path[:len(context)] == context for group in
                         (self.policy.public_fields, self.policy.secret_fields, self.policy.unverified_fields)
                         for path, field in group))
            if not known:
                context = ()
        return ConfigurationRedactionError(reason, line=line, context=context)

    def _embedded_cli(self, values):
        if values == ['']:
            return ''
        if len(values) != 1 or self._embedded_depth >= 2:
            return None
        nested = StreamRedactor(self.forbidden, 'all', policy=self.policy,
                                limits=self.limits, _embedded_depth=self._embedded_depth + 1, _script_mode=True)
        nested.credential_count = self.credential_count
        nested.frame_first = False
        try:
            nested.feed(values[0].encode('utf-8'))
            content, hidden, count = nested.finish()
            if not (nested.configured or nested._operational_seen) or nested.unverified_count:
                return None
            text = ''.join(line.decode('ascii') for line in content.lines())
            self.credential_count = nested.credential_count
            self.count += count
            return text
        except ConfigurationBudgetError:
            raise
        except ConfigurationRedactionError as exc:
            if exc.reason == 'capture-limit-exceeded':
                raise
            return None
        except ValueError:
            return None
        finally:
            nested.close()

    def _operational_cli(self, words):
        fixed = (('get', 'system', 'status'), ('get', 'system', 'performance', 'status'),
                 ('get', 'system', 'arp'), ('get', 'system', 'ha', 'status'), ('diagnose', 'sys', 'session', 'stat'),
                 ('diagnose', 'sys', 'session6', 'stat'), ('diagnose', 'sys', 'vd', 'list'),
                 ('diagnose', 'sys', 'cmdb', 'info'), ('diagnose', 'hardware', 'sysinfo', 'memory'),
                 ('diagnose', 'hardware', 'sysinfo', 'slab'), ('fnsysctl', 'date'))
        counted = {'top': 3, 'mpstat': 2, 'top-mem': 1, 'top-fd': 1}
        profile = ('cpumask', 'module', 'report', 'show', 'start', 'stop', 'sysmap')
        shell = {'ps': (0, 0), 'df': (0, 1), 'du': (1, 4)}
        canonical = ('diagnose' if words[0] == 'diag' else words[0], *words[1:])
        if words[0] == 'get':
            matches = [shape for shape in fixed if shape[0] == 'get' and len(shape) == len(words) and
                       all(word and literal.startswith(word) for word, literal in zip(words, shape))]
            if len(matches) == 1:
                canonical = matches[0]
        prefix, raw = None, False
        if canonical in fixed:
            prefix = len(words)
        elif (canonical[:2] == ('diagnose', 'sys') and len(words) >= 3 and canonical[2] in counted and
              len(words) <= 3 + counted[canonical[2]]):
            if all(re.fullmatch(r'[0-9]{1,10}', word) for word in words[3:]):
                prefix = 3
        elif canonical[:3] == ('diagnose', 'sys', 'profile') and len(words) == 4 and canonical[3] in profile:
            prefix = 4
        elif canonical[:4] == ('diagnose', 'sys', 'process', 'pidof') and len(words) == 5:
            if re.fullmatch(r'[A-Za-z0-9_./+-]{1,128}', words[4]):
                prefix = 4
        elif (canonical[:2] == ('diagnose', 'test') and len(words) == 5 and canonical[2] in ('application', 'app') and
              canonical[3] == 'hasync'):
            if re.fullmatch(r'[0-9]{1,10}', words[4]):
                prefix = 4
        elif canonical[0] == 'fnsysctl' and len(words) >= 2 and words[1] in shell:
            low, high = shell[words[1]]
            if low <= len(words) - 2 <= high and all(
                    len(word) <= 1024 and _SHELL_ARGUMENT.fullmatch(word) for word in words[2:]):
                prefix, raw = 2, True
        if prefix is None:
            return None, False
        if not _public_value(words[:prefix], self.forbidden):
            return None, False
        rendered, withheld = list(words[:prefix]), False
        for word in words[prefix:]:
            if _public_value((word,), self.forbidden):
                rendered.append(word if raw else _quoted_value(word))
            else:
                rendered.append(self._credential())
                withheld = True
        return ' '.join(rendered), withheld

    def _inline_header(self, values):
        if values == ['']:
            return '', False
        found = _HTTP_HEADER.fullmatch(values[0]) if len(values) == 1 and '\\' not in values[0] else None
        if found is None:
            return None, False
        name, space, value = found.groups()
        if name.lower() not in _HTTP_CREDENTIAL_HEADERS or not value.strip():
            return values[0], False
        scheme = _HTTP_AUTH_SCHEME.fullmatch(value) if name.lower() in _HTTP_SCHEME_HEADERS else None
        return name + ':' + space + (scheme.group(1) if scheme else '') + self._credential(), True

    @property
    def _sibling_memory(self):
        return self._sibling_bytes + sys.getsizeof(self._sibling_output) + sys.getsizeof(self._sibling_name)

    def _sibling_add(self, item):
        size = sys.getsizeof(item)
        if isinstance(item, tuple):
            size += sum(sys.getsizeof(value) for value in item)
            size += sum(sys.getsizeof(value) for value in item[0])
            size += sum(sys.getsizeof(value) for value in item[2])
        self._sibling_bytes += size
        self._sibling_output.append(item)
        if self._sibling_memory > 1024*1024:
            raise ValueError('configuration header record exceeds safety cap')
        _budget(self.result.memory_bytes + self.hidden.memory_bytes + self._sibling_memory + 2*1024*1024)

    def _sibling_flush(self):
        for item in self._sibling_output:
            if isinstance(item, str):
                self.result.add(item)
                continue
            context, field, values = item
            header, withheld = None, False
            if values == ['']:
                header = ''
            elif (self._sibling_name_count == self._sibling_value_count == 1 and
                  self._sibling_name is not None and len(values) == 1):
                prefix = self._sibling_name + ':'
                header, withheld = self._inline_header([prefix + values[0]])
                if header is not None:
                    header = header[len(prefix):]
            if header is None:
                value = self._unverified(context, field, True)
                withheld = True
            else:
                value = _quoted_value(header)
            self.result.add('    set ' + field + ' ' + value + '\n')
            if withheld:
                self.count += 1
        self._sibling_output.clear()
        self._sibling_bytes = 0
        self._sibling_name = None
        self._sibling_name_count = self._sibling_value_count = 0

    def _credential(self):
        self.credential_count += 1
        return '<REDACTED:credential#' + str(self.credential_count) + '>'

    def summary(self):
        return {'credential_redactions': self.credential_count,
                'unverified_count': self.unverified_count,
                'unsupported_format_count': self.unsupported_format_count,
                'unverified_fields': list(self.unverified_fields),
                'unverified_truncated': self.unverified_truncated}

    def close(self):
        self.closed = True
        self.physical.clear()
        self.pending.clear()
        self.result.close()
        self.hidden = None
        self.stack.clear()
        self.path.clear()
        self.forbidden = ()
        self.decoder = None
        self.frame_prompt = None
        self._sibling_output.clear()
        self._sibling_name = None
        self._sibling_bytes = 0
        self._sibling_name_count = self._sibling_value_count = 0

    def feed(self, data):
        try:
            if self.closed or not isinstance(data, bytes):
                raise ValueError()
            self.raw_bytes += len(data)
            if self.raw_bytes > self.maximum:
                raise self._failure('capture-limit-exceeded')
            text = self.decoder.decode(data, final=False)
            if not text:
                return
            if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x85\u2028\u2029\ufffd]', text):
                raise ValueError()
            if self.after_cr and text.startswith('\n'):
                text = text[1:]
            self.after_cr = text.endswith('\r')
            text = text.replace('\r\n','\n').replace('\r','\n')
            parts = text.split('\n')
            for i,part in enumerate(parts):
                self.physical_bytes += len(part.encode())
                if self.physical_bytes > self.limits.physical_line_bytes:
                    raise self._failure('capture-limit-exceeded')
                self.physical.append(part)
                if i < len(parts)-1:
                    self._line()
                    self._error_line = None
        except ConfigurationBudgetError as exc:
            self.budget_refusal = str(exc)
            self.close()
            raise
        except ContentLimitError:
            failure = self._failure('capture-limit-exceeded')
            self.close()
            raise failure from None
        except ConfigurationRedactionError:
            self.close()
            raise
        except Exception:
            failure = self._failure('redaction-unverifiable')
            self.close()
            raise failure from None

    def _line(self):
        self.line_number += 1
        self._error_line = self.line_number
        line = ''.join(self.physical)
        self.physical.clear()
        self.physical_bytes = 0
        if self.frame_first:
            self.frame_first = False
            found = prompt.prefix(self.policy.platform if self.policy else 'fortinet').match(line)
            if found:
                self.frame_prompt = found.group(1).rstrip()
                line = line[len(found.group(1)):]
        if self.refused or (self.policy is not None and self.policy.platform == 'fortiadc' and not self.started and
                            not self.configured and not self.pending and self.quote is None and
                            _FORTIADC_REFUSAL.fullmatch(line.strip())):
            if self.frame_prompt and line.rstrip() == self.frame_prompt and not self.frame_ended:
                self.frame_ended = True
            elif line.strip() and (self.frame_ended or not _FORTIADC_REFUSAL.fullmatch(line.strip())):
                raise ValueError('redaction could not be verified; output withheld')
            self.refused = True
            return
        if self.quote is None and self.frame_prompt and line.rstrip() == self.frame_prompt:
            if self.stack or self.pending or not self.configured:
                raise ValueError('redaction could not be verified; output withheld')
            self.frame_ended = True
            return
        if self.frame_ended and line.strip():
            raise ValueError('redaction could not be verified; output withheld')
        if len(line.encode()) > self.limits.physical_line_bytes:
            raise self._failure('capture-limit-exceeded')
        self.logical_bytes += len(line.encode()) + 1
        if self.logical_bytes > self.limits.logical_record_bytes:
            raise self._failure('capture-limit-exceeded')
        self.pending.append(line)
        skip = -1
        for match in re.finditer(r"[\\'\"]", line):
            index, char = match.start(), match.group()
            if index == skip:
                skip = -1
                continue
            if char == chr(92) and self.quote != "'":
                skip = index+1
            elif self.quote:
                if char == self.quote:
                    self.quote = None
            elif char in ('"', "'"):
                self.quote = char
        if skip == len(line):
            raise ValueError()
        if self.quote is None:
            logical = '\n'.join(self.pending)
            self.pending.clear()
            self.logical_bytes = 0
            if '--More--' in logical:
                raise ValueError()
            self._record(logical)

    def _record(self, line):
        result, hidden, stack, path = self.result, self.hidden, self.stack, self.path
        section = self.section
        if not line.strip():
            return
        if line.lstrip().startswith('#'):
            if self.started or '\n' in line or not (self.policy.header(line.strip()) if self.policy else _HEADER.fullmatch(line.strip())):
                raise ValueError('redaction could not be verified; output withheld')
            if self.policy:
                result.add(line.strip() + '\n' if _public_value((line,), self.forbidden)
                           else '# ' + self._credential() + '\n')
            elif not self.header:
                result.add('# configuration\n')
            self.header = True
            return
        self.started = True
        try:
            ordinary_set = re.fullmatch(r'[ \t]*set[ \t]+([a-z][a-z0-9-]*)[ \t]+(.+)', line, re.S)
            if self.policy is None and ordinary_set and ordinary_set.group(1) != 'status' and ordinary_set.group(2).strip():
                words = ['set', ordinary_set.group(1), '<private-value>']
            else:
                words = shlex.split(line, comments=False, posix=True)
        except ValueError:
            raise ValueError('redaction could not be verified; output withheld') from None
        command = words[0]
        grammar = self.policy.grammar if self.policy else '[a-z][a-z0-9-]*'
        context = tuple(part[7:].decode() for part in path if part.startswith(b'config\0'))
        clean, withheld = None, False
        if command in ('config', 'edit', 'next', 'end'):
            self._sibling_flush()
        sibling = self._sibling_fields.get(context)
        deferred_header = None
        if sibling and command in ('set', 'unset') and len(words) >= 2:
            if words[1] == sibling[0]:
                self._sibling_name_count = min(2, self._sibling_name_count + 1)
                if (self._sibling_name_count == 1 and command == 'set' and len(words) == 3 and
                        (context, words[1]) not in self.policy.secret_fields and
                        _public_value(words[2:], self.forbidden) and re.fullmatch(_HTTP_TOKEN, words[2])):
                    self._sibling_name = words[2]
                else:
                    self._sibling_name = None
            elif words[1] == sibling[1]:
                self._sibling_value_count = min(2, self._sibling_value_count + 1)
        if (command == 'config' and self.policy and self.policy.platform == 'fortios' and len(words) >= 4 and
                words[1:3] == ['rule', 'iotd']):
            if not (len(words) == 4 and context in ((), ('global',), ('vdom',)) and
                    0 < len(words[3]) <= 63 and words[3][0].isalnum() and
                    all(char.isalnum() or char in '_+().-' for char in words[3])):
                raise ValueError('redaction could not be verified; output withheld')
            if not stack and section not in ('all', 'rule iotd'):
                raise ValueError('configuration section scope mismatch; output withheld')
            self.configured = True
            stack.append('config')
            path.append(b'config\0rule iotd')
            if context + ('rule iotd',) not in self.policy.public_edit_sections:
                clean, withheld = 'config rule iotd ' + self._unverified(context, 'rule-iotd-name'), True
            elif not _public_value(words[3:], self.forbidden):
                clean, withheld = 'config rule iotd ' + self._credential(), True
            else:
                clean = 'config rule iotd ' + _quoted_value(words[3])
        elif command == 'config' and len(words) >= 2 and all(
                re.fullmatch(grammar, w) for w in words[1:]):
            if words[1:] == ['vdom'] and not (self.policy and self.policy.allow_vdom):
                raise ValueError('config_platform_not_supported: VDOM configuration refused')
            if not stack and section != 'all' and ' '.join(words[1:]) != section:
                raise ValueError('configuration section scope mismatch; output withheld')
            self.configured = True
            stack.append('config')
            path.append(b'config\0' + ' '.join(words[1:]).encode())
            clean = ' '.join(words)
        elif command == 'edit' and len(words) == 2 and stack and stack[-1] == 'config':
            stack.append('edit')
            self.edit_index += 1
            path.append(b'edit\0' + (str(self.edit_index).encode() if self.policy else hmac.digest(_KEY, words[1].encode(), 'sha256')))
            clean = 'edit <REDACTED>'
            if self.policy:
                if context not in self.policy.public_edit_sections:
                    clean, withheld = 'edit ' + self._unverified(context, 'edit-name'), True
                elif not _public_value(words[1:], self.forbidden):
                    clean, withheld = 'edit ' + self._credential(), True
                else:
                    clean = 'edit ' + _quoted_value(words[1])
        elif command == 'next' and len(words) == 1 and stack and stack[-1] == 'edit':
            stack.pop()
            path.pop()
            clean = 'next'
        elif command == 'end' and len(words) == 1 and stack and stack[-1] == 'config':
            stack.pop()
            path.pop()
            clean = 'end'
        elif command in ('set', 'unset') and len(words) >= 2 and stack and re.fullmatch(
                grammar, words[1]):
            if command == 'unset' and len(words) == 2:
                clean = 'unset ' + words[1]
            elif command == 'set' and len(words) >= 3:
                if self.policy is None and words[1] == 'status' and len(words) == 3 and words[2] in ('up', 'down'):
                    clean = 'set status ' + words[2]
                else:
                    clean = 'set ' + words[1] + ' <REDACTED>'
                    if self.policy:
                        item = (context, words[1])
                        if item in self.policy.secret_fields:
                            clean, withheld = 'set ' + words[1] + ' ' + self._credential(), True
                        elif (self.policy.platform == 'fortios' and words[1] == 'script' and
                              context in tuple(prefix + (name,) for prefix in ((), ('global',), ('vdom',))
                                               for name in ('system auto-script', 'system automation-action'))):
                            script = self._embedded_cli(words[2:])
                            if script is None:
                                clean, withheld = 'set script ' + self._unverified(context, 'script', True), True
                            else:
                                clean = 'set script ' + _quoted_value(script)
                        elif not _public_value(words[2:], self.forbidden):
                            clean, withheld = 'set ' + words[1] + ' ' + self._credential(), True
                        elif item in self.policy.unverified_fields and words[2:] == ['']:
                            clean = 'set ' + words[1] + ' ""'
                        elif sibling and words[1] == sibling[1]:
                            clean = ''
                            deferred_header = (context, words[1], words[2:])
                        elif item in self.policy.inline_header_fields:
                            header, withheld = self._inline_header(words[2:])
                            if header is None:
                                clean, withheld = 'set ' + words[1] + ' ' + self._unverified(context, words[1], True), True
                            else:
                                clean = 'set ' + words[1] + ' ' + _quoted_value(header)
                        elif item in self.policy.unverified_fields or self.policy.opaque(context):
                            clean, withheld = 'set ' + words[1] + ' ' + self._unverified(context, words[1], True), True
                        elif item not in self.policy.public_fields:
                            clean, withheld = 'set ' + words[1] + ' ' + self._unverified(context, words[1]), True
                        else:
                            clean = 'set ' + words[1] + ' ' + ' '.join(_quoted_value(word) for word in words[2:])

        if (clean is None and self._script_mode and self._embedded_depth > 0 and
                self.policy is not None and self.policy.platform == 'fortios' and not stack and not path):
            clean, withheld = self._operational_cli(words)
            if clean is not None:
                self._operational_seen = True
        if clean is None:
            raise ValueError('redaction could not be verified; output withheld')
        if withheld or (self.policy is None and '<REDACTED>' in clean):
            self.count += 1
            if self.policy is None:
                components = path + [command.encode(), words[1].encode() if command == 'set' else b'']
                material = b''.join(len(part).to_bytes(4, 'big') + part for part in components)
                location = hmac.digest(_KEY, material, 'sha256')[:16]
                hidden.add(location, hmac.digest(_KEY, line.encode(), 'sha256')[:16])
        output = ('    ' + clean if command in ('set', 'unset') else clean) + '\n'
        if deferred_header is not None:
            self._sibling_add(deferred_header)
        elif sibling and command in ('set', 'unset'):
            self._sibling_add(output)
        else:
            result.add(output)
        self.record_count += 1
        if ((self.policy is None and self.count % 1024 == 0) or
                (self.policy is not None and (self.record_count == 1 or self.record_count % 1024 == 0))):
            _budget(result.memory_bytes + hidden.memory_bytes + self._sibling_memory + 2*1024*1024)
            if _available_memory() < 32*1024*1024:
                raise ValueError('configuration memory exhausted')

    def finish(self):
        try:
            if self.closed or not self.raw_bytes:
                raise self._failure('stream-incomplete')
            try:
                self.decoder.decode(b'', final=True)
            except UnicodeDecodeError:
                raise self._failure('stream-incomplete') from None
            if any(self.physical):
                self._line()
                self._error_line = None
            if self.pending or self.quote is not None or self.stack:
                raise self._failure('stream-incomplete')
            if self.refused:
                raise ConfigurationRefusedError()
            return self._finished()
        except (ConfigurationRedactionError, ConfigurationBudgetError, ConfigurationRefusedError):
            raise
        except ContentLimitError:
            raise self._failure('capture-limit-exceeded') from None
        except Exception:
            raise self._failure('redaction-unverifiable') from None
        finally:
            self.close()

    def _finished(self):
        if self.stack or not (self.configured or (self._script_mode and self._operational_seen)):
            raise ValueError('redaction could not be verified; output withheld')
        _budget(self.result.memory_bytes + self.hidden.memory_bytes)
        return self.result.finish(), self.hidden, self.count

def bounded_consumer(consumer):
    def feed(data):
        try:
            consumer(data)
        except ConfigurationRedactionError as exc:
            if exc.reason == 'capture-limit-exceeded':
                raise core_ssh.OutputLimitError() from None
            raise
    return feed


def redact(raw, forbidden, section, *, policy=None):
    if not isinstance(raw, str):
        raise ValueError('redaction could not be verified; output withheld')
    capture = StreamRedactor(forbidden, section, policy=policy)
    try:
        capture.feed(raw.encode())
        return capture.finish()
    finally:
        capture.close()

def store(auth, text, hidden, count, section, firmware, *, platform='fortios', profile=PROFILE,
          include_defaults=False, metadata=None):
    _snapshot_profile(profile, platform)
    if type(include_defaults) is not bool or (profile == PROFILE and (include_defaults or metadata is not None)):
        raise ValueError('invalid configuration capture options')
    metadata = _capture_metadata(metadata)
    if profile != PROFILE and len(hidden):
        raise ValueError('full configuration cannot cache secret-derived records')
    now = time.monotonic()
    target = scope(auth, platform)
    with _LOCK:
        for key in list(_SNAPSHOTS):
            if now - _SNAPSHOTS[key].created > _TTL:
                del _SNAPSHOTS[key]
        same = [key for key, value in _SNAPSHOTS.items() if value.scope[:3] == target[:3]]
        while len(same) >= 4:
            del _SNAPSHOTS[same.pop(0)]
        while len(_SNAPSHOTS) >= 16:
            _SNAPSHOTS.popitem(last=False)
        identity = 'cfg_' + secrets.token_hex(16)
        while identity in _SNAPSHOTS:
            identity = 'cfg_' + secrets.token_hex(16)
        _prune()
        snapshot = Snapshot(target, text, hidden, now, count, section, tuple(firmware), profile, include_defaults, metadata)
        _budget(snapshot.memory_bytes)
        _SNAPSHOTS[identity] = snapshot
    return identity

def compare(auth, base, other, *, platform='fortios', with_metadata=False):
    if not all(isinstance(i, str) and re.fullmatch('cfg_[0-9a-f]{32}', i) for i in (base, other)):
        raise ValueError('configuration snapshot not found or expired')
    with _LOCK:
        _prune()
        pair = [_SNAPSHOTS.get(i) for i in (base, other)]
        if any(s is None for s in pair):
            raise ValueError('configuration snapshot not found or expired')
        if any(s.scope != scope(auth, platform) for s in pair):
            raise ValueError('configuration snapshot scope mismatch')
    left, right = pair
    if (left.section, left.firmware, left.profile, left.include_defaults, left.metadata) != (right.section, right.firmware, right.profile, right.include_defaults, right.metadata):
        raise ValueError('configuration snapshot section, firmware or profile mismatch')
    metadata = {}
    if with_metadata and left.profile != PROFILE:
        metadata = {name: {
            'capture_complete': True, 'section': snapshot.section,
            'firmware': dict(zip(('model', 'version', 'build'), snapshot.firmware)),
            'redaction_profile': snapshot.profile, 'include_defaults': snapshot.include_defaults,
            **snapshot_metadata(snapshot),
        } for name, snapshot in (('base_capture', left), ('other_capture', right))}
    if (base,other) in _DIFFS:
        value = _DIFFS[base,other]
        return (*value, metadata) if with_metadata else value
    changed = ChangedRecords()
    for key, value in left.hidden.records():
        if right.hidden.get(key) != value:
            changed.add(key)
    for key, value in right.hidden.records():
        if left.hidden.get(key) is None:
            changed.add(key)
    out = ContentBuilder(512*1024*1024, serialized_markers=left.profile == PROFILE)
    equal = left.text == right.text
    order_changed = left.hidden.order.digest() != right.hidden.order.digest()
    if not equal:
        wrote = False
        for before,after in zip_longest(left.text.lines(), right.text.lines()):
            if before == after:
                continue
            if not wrote:
                out.add(b'--- base\n+++ other\n')
                wrote = True
            if before is not None:
                out.add(b'-'+before)
            if after is not None:
                out.add(b'+'+after)
            _budget(out.memory_bytes + changed.memory_bytes)
    elif order_changed:
        out.add('record order changed\n')
    value = out.finish(), changed, equal and not len(changed) and not order_changed
    _budget(value[0].memory_bytes + changed.memory_bytes)
    with _LOCK:
        _DIFFS[base,other] = value
    return (*value, metadata) if with_metadata else value

def page_arguments(offset, limit):
    if type(offset) is not int or not 0 <= offset <= 1073741824 or type(limit) is not int or not 1 <= limit <= 48000:
        raise ValueError('invalid configuration page')
    return offset, limit

def _capture_metadata(metadata):
    if metadata is None:
        return ()
    allowed = {'config_scope', 'configuration_complete', 'identity_scope_verified', 'visibility_limitations',
               'credential_redactions', 'unverified_count', 'unsupported_format_count', 'unverified_fields', 'unverified_truncated'}
    limitations = frozenset(('system', 'networking', 'load-balance', 'log', 'link-load-balance',
                             'global-load-balance', 'security', 'share-resource', 'user',
                             'access-profile-unverified', 'vdom-unverified', 'vdom-override-unverified', 'vdom-coverage-not-verified',
                             'account-rights-not-verified', 'requested-section-only', 'schema-fields-unverified', 'formats-not-verified'))
    if (type(metadata) is not dict or set(metadata) - allowed or
            not {'config_scope', 'configuration_complete', 'visibility_limitations'} <= set(metadata) or
            metadata['config_scope'] not in ('all', 'single-vdom-device', 'device-account-visible') or
            type(metadata['configuration_complete']) is not bool or
            type(metadata.get('identity_scope_verified', False)) is not bool or
            type(metadata['visibility_limitations']) is not list or
            any(type(value) is not str or value not in limitations for value in metadata['visibility_limitations']) or
            len(metadata['visibility_limitations']) > len(limitations) or
            (metadata['configuration_complete'] and metadata['visibility_limitations'])):
        raise ValueError('invalid configuration visibility metadata')
    for key in ('credential_redactions', 'unverified_count', 'unsupported_format_count'):
        if key in metadata and (type(metadata[key]) is not int or not 0 <= metadata[key] <= 1073741824):
            raise ValueError('invalid configuration visibility metadata')
    if 'unverified_truncated' in metadata and type(metadata['unverified_truncated']) is not bool:
        raise ValueError('invalid configuration visibility metadata')
    if 'unverified_fields' in metadata:
        fields = metadata['unverified_fields']
        if (type(fields) is not list or len(fields) > 32 or
                any(type(value) is not str or len(value) > 768 or
                    any(ord(char) < 32 or ord(char) == 127 for char in value) for value in fields)):
            raise ValueError('invalid configuration visibility metadata')
    return tuple(sorted((key, tuple(value) if type(value) is list else value) for key, value in metadata.items()))


def snapshot_metadata(snapshot):
    return {key: list(value) if type(value) is tuple else value for key, value in snapshot.metadata}


def _scoped_snapshot(auth, identity, section, platform):
    if not isinstance(identity, str) or not re.fullmatch('cfg_[0-9a-f]{32}', identity):
        raise ValueError('configuration snapshot not found or expired')
    with _LOCK:
        value = _SNAPSHOTS.get(identity)
        if value is None or time.monotonic() - value.created > _TTL:
            raise ValueError('configuration snapshot not found or expired')
        if value.scope != scope(auth, platform) or value.section != section:
            raise ValueError('configuration snapshot scope mismatch')
        return value


def get_snapshot(auth, identity, section, *, platform='fortios', profile=PROFILE):
    _snapshot_profile(profile, platform)
    value = _scoped_snapshot(auth, identity, section, platform)
    if value.profile != profile:
        raise ValueError('configuration snapshot scope mismatch')
    return value


def get_full_snapshot(auth, identity, section, *, platform, include_defaults):
    value = _scoped_snapshot(auth, identity, section, platform)
    _snapshot_profile(value.profile, platform)
    if (value.profile == PROFILE or not value.metadata or
            type(include_defaults) is not bool or value.include_defaults != include_defaults):
        raise ValueError('configuration snapshot capture options mismatch')
    return value

def payload(text, offset=0, limit=48000):
    page_arguments(offset, limit)
    if isinstance(text, Content):
        page, end = text.page(offset, limit)
        total, sha = text.total, text.sha256
    else:
        data = text.encode()
        if offset > len(data):
            raise ValueError('configuration page offset is beyond completed content')
        end = min(len(data), offset + limit)
        page = data[offset:end].decode('utf-8')
        total, sha = len(data), hashlib.sha256(data).hexdigest()
    return {'untrusted_device_output': page, 'content_sha256': sha,
            'total_bytes': total, 'returned_bytes': end-offset,
            'offset': offset, 'next_offset': end if end < total else None}


def filter_arguments(contains=None, context=0, content_sha256=None, filter_sha256=None):
    if contains is not None and (not isinstance(contains, str) or not 1 <= len(contains) <= 64 or
            any(not 32 <= ord(char) <= 126 for char in contains)):
        raise ValueError('invalid configuration filter')
    if type(context) is not int or not 0 <= context <= 10 or (contains is None and context):
        raise ValueError('invalid configuration filter context')
    for value in (content_sha256, filter_sha256):
        if value is not None and (not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)):
            raise ValueError('invalid configuration filter fingerprint')


def filter_digest(snapshot_id, contains, context):
    value = json.dumps([snapshot_id, contains, context], separators=(',', ':')).encode()
    return hmac.digest(_KEY, value, 'sha256').hex()


def filtered_content(text, contains, context, serialized_markers=True):
    filter_arguments(contains, context)
    if contains is None:
        return text, 0, None
    needle = contains.encode('ascii')
    before = deque(maxlen=context)
    out = ContentBuilder(_BYTE_BUDGET, serialized_markers=serialized_markers)
    total = matched = 0
    last_written = -1
    through = -1
    checked = 0
    try:
        for index, line in enumerate(text.lines()):
            total += 1
            if needle in line:
                matched += 1
                for previous_index, previous in before:
                    if previous_index > last_written:
                        out.add(previous)
                        last_written = previous_index
                through = index + context
            if index <= through and index > last_written:
                out.add(line)
                last_written = index
            before.append((index, line))
            if index % 1024 == 0 or out.memory_bytes - checked >= 32768:
                _budget(out.memory_bytes + len(line) * (context + 1))
                checked = out.memory_bytes
        _budget(out.memory_bytes)
        return out.finish(), total, matched
    finally:
        out.close()


def filtered_snapshot(lookup, identity, contains, context, offset):
    with _LOCK:
        snapshot = lookup()
        if contains is None:
            return snapshot.text, 0, None
        fingerprint = filter_digest(identity, contains, context)
        if snapshot.filtered is not None and snapshot.filtered[0] == fingerprint:
            return snapshot.filtered[1:]
        if offset:
            raise ValueError('configuration filtered view expired; restart at offset 0')
        baseline = replace(snapshot, filtered=None)
        _SNAPSHOTS[identity] = baseline
    snapshot = None
    text, total, matched = filtered_content(baseline.text, contains, context, baseline.profile == PROFILE)
    with _LOCK:
        if _SNAPSHOTS.get(identity) is not baseline or time.monotonic() - baseline.created > _TTL:
            raise ValueError('configuration snapshot not found or expired')
        _budget(text.memory_bytes)
        _SNAPSHOTS[identity] = replace(baseline, filtered=(fingerprint, text, total, matched))
    return text, total, matched


def discard_snapshot(identity):
    with _LOCK:
        _SNAPSHOTS.pop(identity, None)
        _prune()
