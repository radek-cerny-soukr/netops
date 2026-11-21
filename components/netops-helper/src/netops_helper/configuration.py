from array import array
from dataclasses import dataclass, replace
from collections import OrderedDict, deque
import codecs
import fcntl
import os
import stat
import sys
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar
from itertools import zip_longest
from .config_buffers import CHUNK, Content, ContentBuilder, HiddenRecords, ChangedRecords, ContentLimitError
import hashlib
import json
import hmac
import re
import secrets
import shlex
from netops_core import prompt, ssh as core_ssh
from .config_limits import ConfigurationLimits, BASELINE_FILE_BYTES
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
_HISTORY_STAGED_BYTES = ContextVar('configuration_history_staged_bytes', default=0)
_DIFFS = OrderedDict()
_TTL = 86400
PROFILE = 'fortios-minimal-4'
RUCKUS_PROFILE = 'ruckus_unleashed-allowlisted-1'
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


_SNMP_COMMUNITY_PATHS = frozenset((('system snmp community',),
    ('switch-controller snmp-community',), ('switch-controller managed-switch', 'snmp-community'),
    ('wireless-controller snmp', 'community')))

def _snmp_credential(context, field):
    if context[:1] in (('global',), ('vdom',)):
        context = context[1:]
    return ((field == 'name' and context in _SNMP_COMMUNITY_PATHS) or
            (field == 'community' and context == ('system health-check',)))


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

def response_content(content, secrets):
    """The whole helper → proxy → worker chain, before and after terminal cleanup.

    content_sha256, total_bytes and the pages describe this text, so the same layers find nothing to
    change on a page; the worker still withholds a page that they change (page_changed_by_redaction).
    """
    if not isinstance(content, Content):
        raise ValueError('redaction could not be verified; output withheld')
    _budget(content.memory_bytes + 8*content.total)
    from .sanitize import redact_response
    secrets = tuple(secrets)
    original = content.page(0, content.total)[0]
    text = redact_response(original, secrets)
    if text == original:
        return content
    out = ContentBuilder(_BYTE_BUDGET, secrets, serialized_markers=False)
    try:
        for start in range(0, len(text), CHUNK):
            out.add(text[start:start + CHUNK])
        return out.finish()
    finally:
        out.close()


def _redaction_tag(response_secrets):
    return hmac.digest(_KEY, json.dumps(tuple(response_secrets)).encode(), 'sha256')


def snapshot_redaction_current(snapshot, response_secrets):
    # A cached capture already passed response_content with these exact inputs.
    # Recheck in full when the inputs change or the capture has no in-memory tag.
    return (snapshot.redaction_tag == _redaction_tag(response_secrets) or
            response_content(snapshot.text, response_secrets) is snapshot.text)


def _quoted_value(value):
    return value if re.fullmatch(r'[A-Za-z0-9_./:@%+*-]+', value) else json.dumps(value, ensure_ascii=True)

def _snapshot_profile(profile, platform):
    if platform == 'extreme_exos':
        # Only the EXOS read profile (config_exos_adapter.PROFILE family); config_diff compares two of them.
        if type(profile) is not str or re.fullmatch(r'extreme_exos-full-1:[0-9a-f]{64}', profile) is None:
            raise ValueError('invalid configuration profile')
        return
    if platform == 'cisco_ios':
        # Only the exact reviewed IOS read profile (config_cisco_ios_adapter.PROFILE); no family pattern.
        from . import config_cisco_ios_adapter
        if type(profile) is not str or profile != config_cisco_ios_adapter.PROFILE:
            raise ValueError('invalid configuration profile')
        return
    if platform == 'cisco_xe':
        # Only the exact IOS XE read profile (config_cisco_xe_adapter.PROFILE); no family pattern.
        from . import config_cisco_xe_adapter
        if type(profile) is not str or profile != config_cisco_xe_adapter.PROFILE:
            raise ValueError('invalid configuration profile')
        return
    if platform == 'cisco_nxos':
        # Only the exact NX-OS read profile (config_cisco_nxos_adapter.PROFILE); no family pattern.
        from . import config_cisco_nxos_adapter
        if type(profile) is not str or profile != config_cisco_nxos_adapter.PROFILE:
            raise ValueError('invalid configuration profile')
        return
    if platform == 'arista_eos':
        # Only the exact Arista EOS read profile (config_arista_eos_adapter.PROFILE); no family pattern.
        from . import config_arista_eos_adapter
        if type(profile) is not str or profile != config_arista_eos_adapter.PROFILE:
            raise ValueError('invalid configuration profile')
        return
    if platform == 'ruckus_unleashed':
        if profile != RUCKUS_PROFILE:
            raise ValueError('invalid configuration profile')
        return
    if platform in ('juniper_junos', 'juniper_junos_els'):
        # Only the exact Junos read profile (config_junos_adapter.PROFILE, G136); no family pattern.
        from . import config_junos_adapter
        if type(profile) is not str or profile != config_junos_adapter.PROFILE:
            raise ValueError('invalid configuration profile')
        return
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
    staged += _HISTORY_STAGED_BYTES.get()
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
    historical: bool = False
    redaction_tag: bytes | None = None

    @property
    def memory_bytes(self):
        return (self.text.memory_bytes + self.hidden.memory_bytes + sys.getsizeof(self) + 1024 +
                sum(sys.getsizeof(value) + (sum(sys.getsizeof(item) for item in value) if type(value) is tuple else 0)
                    for key, value in self.metadata) +
                (self.filtered[1].memory_bytes if self.filtered is not None else 0))

def require(auth, platform, permission):
    if platform == 'extreme_exos':
        # EXOS: read, and compare (config_diff of two stored snapshots, task 157) only together with read.
        if permission not in ('read', 'compare'):
            raise ValueError('config_platform_not_supported')
        if auth.ssh_platform != 'extreme_exos':
            raise ValueError('configuration platform is outside target policy')
        rights = auth.read_inventory.get('config_access', ())
        if 'read' not in rights or permission not in rights:
            raise ValueError('config access is not enabled for this target')
        auth.require_tcp_port(auth.port)
        return
    if platform in ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'ruckus_unleashed',
                    'juniper_junos', 'juniper_junos_els'):
        # Read and compare are allowed only for a target enrolled as exactly that platform.
        # Compare requires read access as well.
        if permission not in ('read', 'compare'):
            raise ValueError('config_platform_not_supported')
        if auth.ssh_platform != platform:
            raise ValueError('config_platform_not_supported: configuration platform is outside target policy')
        rights = auth.read_inventory.get('config_access', ())
        if 'read' not in rights or permission not in rights:
            raise ValueError('config access is not enabled for this target')
        auth.require_tcp_port(auth.port)
        return
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
    if platform == 'extreme_exos':
        if auth.ssh_platform != 'extreme_exos':
            raise ValueError('configuration platform is outside target policy')
    elif platform in ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'ruckus_unleashed',
                      'juniper_junos', 'juniper_junos_els'):
        if auth.ssh_platform != platform:
            raise ValueError('configuration platform is outside target policy')
    elif platform not in ('fortios', 'fortiadc') or auth.ssh_platform != ('fortinet' if platform == 'fortios' else 'fortiadc'):
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
            ordinary_set = re.fullmatch(r'[ \t]*set[ \t]+([A-Za-z0-9][A-Za-z0-9_+().-]*)[ \t]+(.+)', line, re.S)
            if self.policy is None and ordinary_set and ordinary_set.group(1) != 'status' and ordinary_set.group(2).strip():
                words = ['set', ordinary_set.group(1), '<private-value>']
            else:
                words = shlex.split(line, comments=False, posix=True)
        except ValueError:
            raise ValueError('redaction could not be verified; output withheld') from None
        command = words[0]
        grammar = self.policy.grammar if self.policy else r'[A-Za-z0-9][A-Za-z0-9_+().-]*'
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
                if _snmp_credential(context, words[1]):
                    clean, withheld = 'set ' + words[1] + ' ' + self._credential(), True
                elif self.policy is None and words[1] == 'status' and len(words) == 3 and words[2] in ('up', 'down'):
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
          include_defaults=False, metadata=None, response_secrets=None):
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
        snapshot = Snapshot(target, text, hidden, now, count, section, tuple(firmware), profile, include_defaults,
                            metadata, redaction_tag=None if response_secrets is None else _redaction_tag(response_secrets))
        _budget(snapshot.memory_bytes)
        _SNAPSHOTS[identity] = snapshot
    return identity

INCOMPARABLE = 'configuration snapshot section, firmware or profile mismatch'
FORTIADC_VISIBILITY_MISMATCH = 'configuration snapshot account visibility mismatch'

# config_diff of the ExtremeXOS, Cisco IOS, IOS XE, NX-OS and Arista EOS snapshots (task 186) and, since
# 1.0.10 (task 298), of the FortiOS snapshots (minimal and full profiles), now also used by FortiADC: a line diff along a
# shortest edit script (Myers 1986, greedy forward pass with a stored furthest-reaching trace), not a
# positional comparison, so one inserted line is one '+' line and a device-rewritten header line is one '-'/'+'
# pair without shifting the rest.  In the FortiOS minimal profile the hidden values stay outside the text
# (constant '<REDACTED>' markers; their changes are the secrets_changed records, computed apart from the text).
# In the FortiOS and FortiADC full profiles the hidden values are numbered '<REDACTED:credential#N>' markers (StreamRedactor
# ._credential), and an added or removed hidden line renumbers every later marker; there (task 298-r2) the lines
# are matched with the marker number left out ('<REDACTED:credential>', only the marker is normalized, never a
# value) while the diff writes the real lines of each snapshot, numbers included.  So the full profile shows an
# added or removed hidden line, not a changed hidden value: it keeps no secrets_changed records (only the
# minimal profile reports a changed value).  The output builder keeps its serialized-marker check, so the
# redaction is unchanged.  The inputs are the stored
# snapshots (bounded by the configuration capture limits); the line tables and the trace are charged to the
# same configuration memory budget, and the edit script has fixed bounds: more than LINE_DIFF_MAX_EDITS
# changed lines between the common head and tail, or more than LINE_DIFF_MAX_WORK steps, refuses the diff
# with DiffLimitExceeded instead of running without bound.
LINE_DIFF_PLATFORMS = frozenset(('extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos',
                                 'fortios', 'fortiadc', 'ruckus_unleashed', 'juniper_junos', 'juniper_junos_els'))
LINE_DIFF_MAX_EDITS = 3000
LINE_DIFF_MAX_WORK = 20_000_000
DIFF_LIMIT_EXCEEDED = ('configuration diff exceeds its comparison limit (at most %d changed lines); output withheld'
                       % LINE_DIFF_MAX_EDITS)
_LINE_ENTRY_BYTES = 120   # per distinct line: dict slot, key reference and list slot (conservative)
_BUDGET_EVERY = 4096
# Measure object headers once.  Capacity estimates below include allocation/growth
# slack; list reservations also cover the old pointer buffer during a resize.
_DIFF_ARRAY_HEADER = sys.getsizeof(array('i'))
_DIFF_ITEM_BYTES = array('i').itemsize
_DIFF_BYTES_HEADER = sys.getsizeof(b'')
_DIFF_LIST_HEADER = sys.getsizeof([])
_DIFF_LIST_SLOT = sys.getsizeof([None]) - _DIFF_LIST_HEADER
_DIFF_PAIR_BYTES = sys.getsizeof((None, None))
_DIFF_RANGE_BYTES = sys.getsizeof(range(0))


def _diff_list_bytes(count):
    return _DIFF_LIST_HEADER + (3 * count + 8) * _DIFF_LIST_SLOT


def _diff_array_bytes(count):
    # array.frombytes can reserve spare elements in addition to its payload.
    return _DIFF_ARRAY_HEADER + (count + count // 8 + 8) * _DIFF_ITEM_BYTES


def _diff_hunk_bytes(edits, index_bytes):
    # At most one hunk per edit, two lists and one pair per hunk, and
    # `edits` integer indexes across all the deleted/inserted lists.
    return (_diff_list_bytes(edits) + 2 * _diff_list_bytes(0)
            + edits * (_DIFF_PAIR_BYTES + 2 * _diff_list_bytes(0))
            + edits * (3 * _DIFF_LIST_SLOT + index_bytes))


DIFF_BUDGET_EXCEEDED = 'configuration diff exceeds its memory budget; output withheld'


class DiffLimitExceeded(ValueError):
    """The line diff would exceed its fixed edit or work bound or the memory budget; nothing was cached."""

    def __init__(self, message=DIFF_LIMIT_EXCEEDED):
        super().__init__(message)


# FortiOS full profile (task 298-r2): the number of a credential marker is its order in the snapshot, not
# configuration; the comparison key leaves it out.
_CREDENTIAL_NUMBER = re.compile(rb'<REDACTED:credential#[1-9][0-9]*>')
_CREDENTIAL_KEY = b'<REDACTED:credential>'


def _line_ids(content, ids, lines, charged, originals=None):
    """The lines of ``content`` as small integers; equal lines share one id (and one stored bytes object).

    With ``originals`` (a dict, FortiOS full profile) a line is identified with its credential marker numbers
    left out, and the real line of every such position of ``content`` is kept in ``originals`` for the output.
    """
    sequence = array('i')
    for line in content.lines():
        key = line
        if originals is not None and b'<REDACTED:credential#' in line:
            key = _CREDENTIAL_NUMBER.sub(_CREDENTIAL_KEY, line)
            if key != line:
                originals[len(sequence)] = line
                charged[0] += sys.getsizeof(line) + _LINE_ENTRY_BYTES
        identity = ids.get(key)
        if identity is None:
            identity = ids[key] = len(lines)
            lines.append(key)
            charged[0] += sys.getsizeof(key) + _LINE_ENTRY_BYTES
        sequence.append(identity)
        if len(sequence) % _BUDGET_EVERY == 0:
            _budget(charged[0] + sys.getsizeof(sequence))   # the allocated size, growth headroom included
    charged[0] += sys.getsizeof(sequence)
    _budget(charged[0])
    return sequence


def _edit_script(a, b, charged, head=0, tail=0):
    """Hunks [(deleted a indexes, inserted b indexes), ...] of a shortest edit script from a to b, in order.

    Only a[head:len(a) - tail] and b[head:len(b) - tail] are compared, through offsets (no copies of the line
    tables, task 186-r2); the returned indexes are relative to ``head``.  The edit bound is checked first on
    every path, including a pure insertion or deletion (one side empty after the common head and tail).

    Greedy forward pass of Myers' O((N+M)D) algorithm.  After step d the furthest-reaching x of every
    diagonal k = -d, -d+2, ..., d is kept (d + 1 values), so the trace of D steps holds (D+1)(D+2)/2 values;
    the backtrack takes, as the forward pass did, the diagonal k+1 (an insertion) when k == -d or when
    v[k-1] < v[k+1], otherwise k-1 (a deletion).  Equal lines are never listed.
    """
    n, m = len(a) - head - tail, len(b) - head - tail
    if n < 0 or m < 0:
        raise ValueError('invalid line diff range')
    if abs(n - m) > LINE_DIFF_MAX_EDITS:
        raise DiffLimitExceeded()   # at least |n - m| lines are added or removed
    if not n or not m:
        retained = _diff_list_bytes(1) + _DIFF_PAIR_BYTES + 2 * _DIFF_RANGE_BYTES if n or m else _diff_list_bytes(0)
        _budget(charged[0] + retained)
        charged[0] += retained
        return [(range(n), range(m))] if n or m else []
    limit = min(n + m, LINE_DIFF_MAX_EDITS)
    offset = limit + 1
    v_count = 2 * limit + 3
    v_bytes = _diff_array_bytes(v_count)
    _budget(charged[0] + v_bytes + _DIFF_BYTES_HEADER + _DIFF_ITEM_BYTES * v_count + _diff_list_bytes(0))
    v = array('i', bytes(_DIFF_ITEM_BYTES * v_count))
    trace = []
    trace_bytes = 0
    work = 0
    found = None
    for d in range(limit + 1):
        row_bytes = _diff_array_bytes(d + 1)
        # Check before allocating either the temporary bytes or the next row.
        _budget(charged[0] + v_bytes + trace_bytes + row_bytes + _diff_list_bytes(d + 1)
                + _DIFF_BYTES_HEADER + _DIFF_ITEM_BYTES * (d + 1))
        row = array('i', bytes(_DIFF_ITEM_BYTES * (d + 1)))
        trace_bytes += row_bytes
        for k in range(-d, d + 1, 2):
            if k == -d or (k != d and v[offset + k - 1] < v[offset + k + 1]):
                x = v[offset + k + 1]
            else:
                x = v[offset + k - 1] + 1
            y = x - k
            start = x
            while x < n and y < m and a[head + x] == b[head + y]:
                x += 1
                y += 1
            work += 1 + x - start
            v[offset + k] = x
            row[(k + d) >> 1] = x
            if x >= n and y >= m:
                found = d
                break
        trace.append(row)
        if found is not None:
            break
        if work > LINE_DIFF_MAX_WORK:
            raise DiffLimitExceeded()
    if found is None:
        raise DiffLimitExceeded()
    index_bytes = sys.getsizeof(max(n, m))
    retained = _diff_hunk_bytes(found, index_bytes)
    moves_bytes = _diff_list_bytes(2 * found) + found * (_DIFF_PAIR_BYTES + index_bytes)
    # Reserve both reconstruction phases before creating moves.  This is
    # conservative: hunks are built after releasing the trace, while moves live
    # through both phases.  The final row/previous aliases are covered as well.
    _budget(charged[0] + v_bytes + trace_bytes + _diff_list_bytes(found + 1) + moves_bytes + retained)
    moves = []     # backwards: ('-', a index) / ('+', b index); None separates hunks
    x, y = n, m
    for d in range(found, -1, -1):
        k = x - y
        if d == 0:
            prev_x = prev_y = 0
        else:
            previous = trace[d - 1]   # step d-1 values: diagonal j at index (j + d - 1) >> 1
            if k == -d or (k != d and previous[(k - 1 + d - 1) >> 1] < previous[(k + 1 + d - 1) >> 1]):
                prev_k = k + 1
            else:
                prev_k = k - 1
            prev_x = previous[(prev_k + d - 1) >> 1]
            prev_y = prev_x - prev_k
        snake = 0
        while x > prev_x and y > prev_y:
            x -= 1
            y -= 1
            snake += 1
        if d == 0:
            break
        if snake and moves and moves[-1] is not None:
            moves.append(None)
        if x == prev_x:
            moves.append(('+', prev_y))
        else:
            moves.append(('-', prev_x))
        x, y = prev_x, prev_y
    trace = v = None
    moves.reverse()
    hunks, deleted, inserted = [], [], []
    for move in moves:
        if move is None:
            hunks.append((deleted, inserted))
            deleted, inserted = [], []
        elif move[0] == '-':
            deleted.append(move[1])
        else:
            inserted.append(move[1])
    if deleted or inserted:
        hunks.append((deleted, inserted))
    charged[0] += retained   # the caller retains these lists while writing the diff
    return hunks


def _line_diff(left, right, out, changed, normalize_credentials=False):
    """Write the removed ('-') and added ('+') lines of right against left, in order, after the diff header.

    ``normalize_credentials`` (FortiOS full profile): lines are compared with their credential marker numbers
    left out; the written lines are the real lines of the side they come from.
    """
    ids, lines, charged = {}, [], [0]
    left_originals = right_originals = None
    if normalize_credentials:
        left_originals, right_originals = {}, {}
    a = _line_ids(left, ids, lines, charged, left_originals)
    b = _line_ids(right, ids, lines, charged, right_originals)
    ids = None
    n, m = len(a), len(b)
    head = 0
    while head < n and head < m and a[head] == b[head]:
        head += 1
    tail = 0
    while tail < n - head and tail < m - head and a[n - 1 - tail] == b[m - 1 - tail]:
        tail += 1
    hunks = _edit_script(a, b, charged, head, tail)
    out.add(b'--- base\n+++ other\n')
    written = 0
    for deleted, inserted in hunks:
        for sign, sequence, originals, indexes in ((b'-', a, left_originals, deleted),
                                                   (b'+', b, right_originals, inserted)):
            for index in indexes:
                line = originals.get(head + index) if originals else None
                if line is None:
                    line = lines[sequence[head + index]]
                out.add(sign + line if line.endswith(b'\n') else sign + line + b'\n')
                written += 1
                if written % 1024 == 0:
                    _budget(charged[0] + out.memory_bytes + changed.memory_bytes)
    _budget(charged[0] + out.memory_bytes + changed.memory_bytes)


# Comparability of two snapshots of the same scope (task 194).  For the EXOS/IOS family the capture
# metadata also carries content summaries (unverified_count, credential_redactions, unsupported_format_count,
# unverified_fields, unverified_truncated, configuration_complete and the visibility_limitations they imply),
# which change with every added or removed hidden line; only the identity keys below take part, so such a
# change is a diff (a redacted marker line), not a false config_snapshot_incomparable.  Section, firmware,
# redaction profile (name and rule hash) and include_defaults still have to match. FortiADC also compares
# account visibility. FortiOS compares the whole metadata except that a full-profile pair ignores
# credential_redactions, which changes with every added or removed secret line (task 298-r3).
# The stored metadata itself is unchanged and is still
# returned per capture in base_capture/other_capture.
_IDENTITY_METADATA = frozenset(('config_scope', 'identity_scope_verified'))
_IDENTITY_METADATA_PLATFORMS = frozenset(('extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos',
                                          'juniper_junos', 'juniper_junos_els'))
_FORTINET_FULL_CONTENT_METADATA = frozenset(('credential_redactions',))
_FORTIADC_NON_ACCOUNT_LIMITATIONS = frozenset(('requested-section-only', 'schema-fields-unverified',
                                             'formats-not-verified'))


def _comparable_identity(snapshot, platform):
    metadata = snapshot.metadata
    if platform == 'fortiadc' or platform in _IDENTITY_METADATA_PLATFORMS:
        metadata = tuple((key, value) for key, value in metadata if key in _IDENTITY_METADATA)
    elif platform == 'fortios' and snapshot.profile != PROFILE:
        metadata = tuple((key, value) for key, value in metadata if key not in _FORTINET_FULL_CONTENT_METADATA)
    identity = snapshot.section, snapshot.firmware, snapshot.profile, snapshot.include_defaults, metadata
    if platform == 'fortiadc':
        limitations = dict(snapshot.metadata).get('visibility_limitations', ())
        visibility = tuple(sorted(set(limitations) - _FORTIADC_NON_ACCOUNT_LIMITATIONS))
        return (*identity, visibility)
    if platform in ('arista_eos', 'cisco_nxos', 'cisco_ios', 'cisco_xe'):
        normalized_comparison = 'comparison_view' in dict(snapshot.metadata)
        return (*identity, normalized_comparison)
    return identity


def compare(auth, base, other, *, platform='fortios', with_metadata=False, admit=None):
    approved = None
    if base == 'baseline':
        base, approved = load_baseline(auth, other, platform=platform)
    if not all(isinstance(i, str) and re.fullmatch('cfg_[0-9a-f]{32}', i) for i in (base, other)):
        raise ValueError('configuration snapshot not found or expired')
    with _LOCK:
        _prune()
        left = _comparison_snapshot(auth, base, platform)
        staged = left.memory_bytes if left is not None and left.historical and base not in _SNAPSHOTS else 0
        right = _comparison_snapshot(auth, other, platform, staged=staged)
        pair = (left, right)
        if any(s is None for s in pair):
            raise ValueError('configuration snapshot not found or expired')
        if any(s.scope != scope(auth, platform) for s in pair):
            raise ValueError('configuration snapshot scope mismatch')
        if right.historical and other not in _SNAPSHOTS:
            staged += right.memory_bytes
    mark = _HISTORY_STAGED_BYTES.set(staged)
    try:
        return _compare_pair(auth, base, other, pair, platform, approved, with_metadata, admit)
    finally:
        _HISTORY_STAGED_BYTES.reset(mark)


def _compare_pair(auth, base, other, pair, platform, approved, with_metadata, admit):
    left, right = pair
    if admit is not None:
        # Apply the same session redaction guard as config_read to each snapshot.
        # it runs before the diff cache, so a cached diff never bypasses it.
        for snapshot in pair:
            admit(snapshot)
    left_identity = _comparable_identity(left, platform)
    right_identity = _comparable_identity(right, platform)
    if left_identity != right_identity:
        if platform == 'fortiadc' and left_identity[-1] != right_identity[-1]:
            raise ValueError(FORTIADC_VISIBILITY_MISMATCH)
        raise ValueError(INCOMPARABLE)
    metadata = {}
    if with_metadata and left.profile != PROFILE:
        metadata = {name: {
            'capture_complete': True, 'section': snapshot.section,
            'firmware': dict(zip(('model', 'version', 'build'), snapshot.firmware)),
            'redaction_profile': snapshot.profile, 'include_defaults': snapshot.include_defaults,
            **snapshot_metadata(snapshot),
        } for name, snapshot in (('base_capture', left), ('other_capture', right))}
    compare_hidden = approved is None and not (left.historical or right.historical)
    if compare_hidden and (base,other) in _DIFFS:
        value = _DIFFS[base,other]
        return (*value, metadata) if with_metadata else value
    if approved is not None:
        metadata.update(baseline_snapshot=base, baseline_approved_at=approved)
    if not compare_hidden:
        metadata['hidden_lines_compared'] = False
    changed = ChangedRecords()
    left_hidden = left.hidden if compare_hidden else HiddenRecords()
    right_hidden = right.hidden if compare_hidden else HiddenRecords()
    for key, value in left_hidden.records():
        if right_hidden.get(key) != value:
            changed.add(key)
    for key, value in right_hidden.records():
        if left_hidden.get(key) is None:
            changed.add(key)
    out = ContentBuilder(512*1024*1024, serialized_markers=left.profile == PROFILE)
    equal = left.text == right.text
    order_changed = left_hidden.order.digest() != right_hidden.order.digest()
    if not equal and platform in LINE_DIFF_PLATFORMS:
        try:
            _line_diff(left.text, right.text, out, changed,
                       normalize_credentials=platform in ('fortios', 'fortiadc') and left.profile != PROFILE)
        except ConfigurationBudgetError:
            # The line tables, trace or output of the new diff path exceed the memory budget (task 186-r2):
            # the same controlled refusal code as the edit bound, not an internal error.
            out.close()
            raise DiffLimitExceeded(DIFF_BUDGET_EXCEEDED) from None
        except BaseException:
            out.close()
            raise
    elif not equal:
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
    value = response_content(out.finish(), auth.secrets), changed, equal and not len(changed) and not order_changed
    _budget(value[0].memory_bytes + changed.memory_bytes)
    with _LOCK:
        if compare_hidden:
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
               'credential_redactions', 'unverified_count', 'unsupported_format_count', 'unverified_fields',
               'unverified_truncated', 'comparison_view'}
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
    if 'comparison_view' in metadata and metadata['comparison_view'] not in ('startup', 'running'):
        raise ValueError('invalid configuration capture view')
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
    """One page; a page that is not the last ends after its last line feed, if it has one.

    Response redaction judges whole lines, so a page cut inside a line could be rewritten after its
    hash was computed; whole-line pages keep content_sha256 and the sizes true for the joined pages.
    """
    page_arguments(offset, limit)
    if isinstance(text, Content):
        page, end = text.page(offset, limit)
        total, sha = text.total, text.sha256
        cut = page.rfind('\n') if end < total else -1
        if cut >= 0:
            page, end = page[:cut + 1], offset + cut + 1
    else:
        data = text.encode()
        if offset > len(data):
            raise ValueError('configuration page offset is beyond completed content')
        end = min(len(data), offset + limit)
        cut = data.rfind(b'\n', offset, end) if end < len(data) else -1
        if cut >= 0:
            end = cut + 1
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


def filtered_content(text, contains, context, serialized_markers=True, secrets=()):
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
        return response_content(out.finish(), secrets), total, matched
    finally:
        out.close()


def filtered_snapshot(lookup, identity, contains, context, offset, secrets=()):
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
    text, total, matched = filtered_content(baseline.text, contains, context, baseline.profile == PROFILE, secrets)
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


class ConfigurationBaselineError(ValueError):
    """Fixed safe refusal of durable baseline storage or approval."""


def _baseline_directory():
    # The bootstrap sets the audit path inside the persistent, private Helper state volume.
    directory = Path(os.environ.get('NETOPS_CONFIG_BASELINE_DIR',
        str(Path(os.environ.get('NETOPS_HELPER_AUDIT_PATH', '/var/lib/netops-helper/audit.jsonl')).parent /
            'config-baselines')))
    return _private_directory(directory)


def _private_directory(directory, *, create=True):
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ConfigurationBaselineError('configuration storage is not private')
    return directory


def _baseline_target(auth, platform, *capture_options):
    # Public identity only: password rotations retain the same approved baseline. Never persist credentials,
    # session keys, hidden-line HMACs or the process-local snapshot scope.
    material = (auth.alias, auth.host, auth.port, auth.login, auth.host_key_fingerprint,
                auth.credential_kind, platform, *capture_options)
    return hashlib.sha256(json.dumps(material, separators=(',', ':')).encode()).hexdigest()


def _baseline_safe(snapshot, auth):
    platform = snapshot.scope[1]
    forbidden = auth.redaction_secrets if platform in ('fortios', 'fortiadc') or platform in _IDENTITY_METADATA_PLATFORMS else auth.secrets
    if response_content(snapshot.text, forbidden) is not snapshot.text:
        raise ConfigurationBaselineError('configuration baseline redaction changed; fresh capture required')


def _encode_saved_snapshot(snapshot, target, identity, approved):
    # JSON encoding is bounded before constructing the serialized copy.
    _budget(8 * snapshot.text.total + 65536)
    record = dict(version=1, target=target, snapshot_id=identity, approved_at=approved,
                  section=snapshot.section, firmware=list(snapshot.firmware), profile=snapshot.profile,
                  include_defaults=snapshot.include_defaults, metadata=snapshot_metadata(snapshot),
                  redacted_count=snapshot.redacted_count, content_sha256=snapshot.text.sha256,
                  text=snapshot.text.page(0, snapshot.text.total)[0])
    data = json.dumps(record, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    if len(data) > BASELINE_FILE_BYTES:
        raise ConfigurationBaselineError('configuration baseline exceeds storage limit')
    return data


def approve_baseline(auth, identity, section, expected_sha256, *, platform='fortios'):
    """Explicit approval of an existing completed, unfiltered capture; no device writes.

    Latest approval replaces only this target/section/defaults baseline. The redacted text survives
    cache eviction, TTL and process restart. Hidden records deliberately never go to disk.
    """
    from netops.files import write_private
    require(auth, platform, 'read')
    require(auth, platform, 'compare')
    with _LOCK:
        snapshot = _scoped_snapshot(auth, identity, section, platform)
        if type(expected_sha256) is not str or not hmac.compare_digest(snapshot.text.sha256, expected_sha256):
            raise ConfigurationBaselineError('configuration baseline content fingerprint mismatch')
        _baseline_safe(snapshot, auth)
        target = _baseline_target(auth, platform, section, snapshot.include_defaults)
        approved = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        data = _encode_saved_snapshot(snapshot, target, identity, approved)
        try:
            path = _baseline_directory() / (target + '.json')
            write_private(path, data, owner=os.getuid(), replace=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationBaselineError('configuration baseline could not be saved') from None
        return dict(baseline_approved=True, baseline_snapshot=identity, baseline_approved_at=approved,
                    baseline_sha256=snapshot.text.sha256, hidden_lines_compared=False)


def _decode_saved_snapshot(path, target, auth, platform, *, staged=0, key=None):
    from netops.files import read_private

    # Bound allocation by this target's current limits, including JSON escaping.
    maximum = min(BASELINE_FILE_BYTES, 2 * auth.configuration_limits.all_bytes + 65536)
    maximum += _ADC_ARCHIVE_OVERHEAD if key is not None else 0
    _budget(staged + 8 * min(path.lstat().st_size, maximum))
    raw = read_private(path, maximum, owner=os.getuid())
    if key is not None:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        start = len(_ADC_ARCHIVE_MAGIC)
        if len(raw) < _ADC_ARCHIVE_OVERHEAD or not raw.startswith(_ADC_ARCHIVE_MAGIC):
            raise ValueError()
        try:
            raw = AESGCM(key).decrypt(raw[start:start + 12], raw[start + 12:], _ADC_ARCHIVE_MAGIC)
        except InvalidTag:
            raise ValueError() from None
    record = json.loads(raw)
    if (type(record) is not dict or set(record) != {
            'version', 'target', 'snapshot_id', 'approved_at', 'section', 'firmware', 'profile',
            'include_defaults', 'metadata', 'redacted_count', 'content_sha256', 'text'} or
            type(record['version']) is not int or record['version'] != 1 or
            record['target'] != target or type(record['section']) is not str or
            type(record['include_defaults']) is not bool or
            type(record['snapshot_id']) is not str or re.fullmatch('cfg_[0-9a-f]{32}', record['snapshot_id']) is None or
            type(record['approved_at']) is not str or
            re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', record['approved_at']) is None or
            type(record['firmware']) is not list or
            type(record['redacted_count']) is not int or record['redacted_count'] < 0 or
            type(record['text']) is not str):
        raise ValueError()
    _snapshot_profile(record['profile'], platform)
    if platform in ('cisco_ios', 'cisco_xe'):
        # G00 stores image family (and XE train) in addition to the public firmware fields.
        # Validate with the same authority as cached config_read; optional fields may be None.
        from . import config_cisco_ios_adapter, config_cisco_xe_adapter
        adapter = config_cisco_ios_adapter if platform == 'cisco_ios' else config_cisco_xe_adapter
        if not adapter.firmware_record(tuple(record['firmware'])):
            raise ValueError()
    elif (not 2 <= len(record['firmware']) <= 3 or
          any(type(v) is not str or len(v) > 256 for v in record['firmware'])):
        raise ValueError()
    if platform == 'fortios' and record['profile'] != PROFILE:
        from . import config_fortios
        # An older full policy may have saved credentials in otherwise valid records.
        if record['profile'] != config_fortios.policy_for(tuple(record['firmware'])).identifier:
            raise ValueError()
    if key is not None:
        from . import config_fortiadc

        if (record['section'] != 'all' or not record['include_defaults'] or
                len(record['firmware']) != 3 or
                record['profile'] != config_fortiadc.policy_for(tuple(record['firmware'])).identifier):
            raise ValueError()
    metadata = _capture_metadata(record['metadata'] if record['profile'] != PROFILE else None)
    maximum = auth.configuration_limits.all_bytes if record['section'] == 'all' else auth.configuration_limits.section_bytes
    builder = ContentBuilder(maximum, serialized_markers=False)
    try:
        builder.add(record['text'])
        content = builder.finish()
    finally:
        builder.close()
    if content.sha256 != record['content_sha256']:
        raise ValueError()
    loaded = Snapshot(scope(auth, platform), content, HiddenRecords(), time.monotonic(),
                      record['redacted_count'], record['section'], tuple(record['firmware']),
                      record['profile'], record['include_defaults'], metadata, historical=True)
    _baseline_safe(loaded, auth)
    return record, loaded


def load_baseline(auth, other, *, platform='fortios'):
    """Load the latest approval into the bounded cache, bound to today's authenticated target.

    The original capture ID is returned; no cached diff can bypass a newly loaded approval.
    """
    require(auth, platform, 'read')
    require(auth, platform, 'compare')
    with _LOCK:
        if type(other) is not str or re.fullmatch('cfg_[0-9a-f]{32}', other) is None:
            raise ValueError('configuration snapshot not found or expired')
        current = _SNAPSHOTS.get(other)
        if current is None:
            raise ValueError('configuration snapshot not found or expired')
        current = _scoped_snapshot(auth, other, current.section, platform)
        target = _baseline_target(auth, platform, current.section, current.include_defaults)
        try:
            path = _baseline_directory() / (target + '.json')
            record, loaded = _decode_saved_snapshot(path, target, auth, platform)
            if (loaded.section, loaded.include_defaults) != (current.section, current.include_defaults):
                raise ValueError()
        except FileNotFoundError:
            raise ConfigurationBaselineError('configuration baseline not found; approve a completed snapshot first') from None
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, UnicodeError):
            raise ConfigurationBaselineError('configuration baseline is invalid or unavailable; output withheld') from None
        identity = record['snapshot_id']
        existing = _SNAPSHOTS.get(identity)
        if existing is not None and (existing.scope != loaded.scope or existing.text != loaded.text):
            raise ConfigurationBaselineError('configuration baseline snapshot collision')
        if existing is None:
            _prune()
            while len(_SNAPSHOTS) >= 16:
                key = next(key for key in _SNAPSHOTS if key != other)
                del _SNAPSHOTS[key]
            _budget(loaded.memory_bytes)
            _SNAPSHOTS[identity] = loaded
        return identity, record['approved_at']


_HISTORY_STEM = r'(cfg_[0-9a-f]{32})-([0-9a-f]{64})'
_HISTORY_NAME = re.compile(_HISTORY_STEM + r'\.json')
_ADC_HISTORY_NAME = re.compile(_HISTORY_STEM + r'\.aesgcm')
_ADC_ARCHIVE_MAGIC = b'NETOPS-FORTIADC-HISTORY\x00\x01'
_ADC_ARCHIVE_OVERHEAD = len(_ADC_ARCHIVE_MAGIC) + 12 + 16
_ADC_KEY_FILE = 'NETOPS_FORTIADC_BACKUP_KEY_FILE'
_HISTORY_COUNT = 16
_HISTORY_BYTES = 128 * 1024 * 1024


def fortiadc_history_enabled(auth):
    rights = auth.read_inventory.get('config_access', ())
    return bool(os.environ.get(_ADC_KEY_FILE)) and 'read' in rights and 'compare' in rights


def _fortiadc_archive_key():
    from netops.files import read_private

    key = read_private(os.environ[_ADC_KEY_FILE], 32, owner=os.getuid())
    if len(key) != 32:
        raise ConfigurationBaselineError('invalid FortiADC archive key size')
    return key


def _history_directory(auth, platform, *, create):
    directory = os.environ.get('NETOPS_CONFIG_HISTORY_DIR')
    if directory is None:
        audit_path = os.environ.get('NETOPS_HELPER_AUDIT_PATH')
        if audit_path is None:
            return None
        directory = Path(audit_path).parent / 'config-history'
    # A persisted capture follows the same configuration-limit scope as a cached capture.
    target = _baseline_target(auth, platform, auth.configuration_limits.identity())
    directory = Path(directory)
    if platform == 'fortiadc':
        for path in (directory.absolute(), directory.resolve()):
            if any((parent / '.git').exists() for parent in (path, *path.parents)):
                raise ConfigurationBaselineError('FortiADC archive directory must be outside a Git worktree')
    try:
        root = _private_directory(directory, create=create)
        return _private_directory(root / target, create=create)
    except FileNotFoundError:
        if create:
            raise
        return None


def _history_shape(snapshot, *, legacy_fortiadc=False):
    platform = snapshot.scope[1]
    identity = _comparable_identity(snapshot, platform)
    if platform == 'fortiadc':
        # Preserve existing filename hashes. Pair archives using their authenticated capture metadata.
        identity = identity[:-1]
    if legacy_fortiadc:
        # Authenticate filenames of existing FortiADC archives written before the identity fix.
        metadata = tuple((key, value) for key, value in snapshot.metadata
                         if key not in _FORTINET_FULL_CONTENT_METADATA)
        identity = (*identity[:-1], metadata)
    material = json.dumps(identity, separators=(',', ':'))
    return hashlib.sha256(material.encode()).hexdigest()


def retain_history(auth, identity, section, *, platform='fortios'):
    """Retain completed redacted text and return IDs for comparisons of the same capture scope."""
    if 'compare' not in auth.read_inventory.get('config_access', ()):
        return {}
    if platform == 'fortiadc' and not fortiadc_history_enabled(auth):
        return {}
    snapshot = _scoped_snapshot(auth, identity, section, platform)
    try:
        key = _fortiadc_archive_key() if platform == 'fortiadc' else None
        directory = _history_directory(auth, platform, create=True)
        if directory is None:
            return {'history_retained': False} if key is not None else {}
        _baseline_safe(snapshot, auth)
        captured = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        data = _encode_saved_snapshot(snapshot, directory.name, identity, captured)
        if key is not None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = os.urandom(12)
            data = _ADC_ARCHIVE_MAGIC + nonce + AESGCM(key).encrypt(nonce, data, _ADC_ARCHIVE_MAGIC)
        if len(data) > _HISTORY_BYTES:
            raise ValueError()
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return _publish_history(auth, platform, directory, identity, snapshot, captured, data, key)
        finally:
            os.close(fd)
    except (OSError, ValueError, RuntimeError, KeyError):
        return {'history_retained': False}


def _publish_history(auth, platform, directory, identity, snapshot, captured, data, key):
    from netops.files import sync_directory, write_private
    from . import config_fortiadc

    shape = _history_shape(snapshot)
    comparable_identity = _comparable_identity(snapshot, platform) if key is not None else None
    pattern, suffix = (_ADC_HISTORY_NAME, '.aesgcm') if key is not None else (_HISTORY_NAME, '.json')
    entries, unavailable_count, unavailable_bytes = [], 0, 0
    for previous in directory.iterdir():
        match = pattern.fullmatch(previous.name)
        if match is None:
            continue
        info = previous.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        comparable = match[2] == shape
        if key is not None:
            try:
                loaded = _verify_history_file(auth, platform, directory, previous, match, key=key)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError):
                # An unreadable file could belong to an earlier key. Preserve it.
                unavailable_count += 1
                unavailable_bytes += info.st_size
                continue
            comparable = (_comparable_identity(loaded, platform) == comparable_identity and
                          config_fortiadc.full_capture_complete(loaded.text))
        entries.append((info.st_mtime_ns, previous, info.st_size, match, comparable))
    if unavailable_count >= _HISTORY_COUNT or unavailable_bytes + len(data) > _HISTORY_BYTES:
        raise ConfigurationBaselineError('FortiADC archive capacity is occupied by unreadable captures')
    retained_bytes = unavailable_bytes + len(data) + sum(entry[2] for entry in entries)
    entries.sort(reverse=True)
    expired_paths = []
    while len(entries) + unavailable_count >= _HISTORY_COUNT or retained_bytes > _HISTORY_BYTES:
        _, expired, size, _, _ = entries.pop()
        expired_paths.append(expired)
        retained_bytes -= size
    write_private(directory / f'{identity}-{shape}{suffix}', data, owner=os.getuid())
    try:
        for expired in expired_paths:
            expired.unlink()
        if expired_paths:
            sync_directory(directory)
        retention_ok = True
    except OSError:
        retention_ok = False
    recent = [{'snapshot_id': identity, 'captured_at': captured}]
    for modified, path, _, match, comparable in entries:
        if not comparable:
            continue
        if key is None:
            try:
                _verify_history_file(auth, platform, directory, path, match)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError):
                continue
        recent.append({'snapshot_id': match[1],
                       'captured_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(modified // 10**9))})
    result = {'history_retained': True, 'recent_snapshots': recent}
    if not retention_ok:
        result['history_retention_ok'] = False
    if unavailable_count:
        result['history_unavailable_count'] = unavailable_count
    return result


def _verify_history_file(auth, platform, directory, path, match, *, staged=0, key=None):
    record, loaded = _decode_saved_snapshot(path, directory.name, auth, platform, staged=staged, key=key)
    if record['snapshot_id'] != match[1]:
        raise ValueError()
    if match[2] != _history_shape(loaded) and (key is None or match[2] != _history_shape(loaded, legacy_fortiadc=True)):
        raise ValueError()
    return loaded


def _read_history_snapshot(auth, platform, directory, identity, *, staged=0, key=None):
    from . import config_fortiadc

    pattern, suffix = (_ADC_HISTORY_NAME, '.aesgcm') if key is not None else (_HISTORY_NAME, '.json')
    paths = list(directory.glob(identity + '-*' + suffix))
    if not paths:
        return None
    path, *duplicates = paths
    if duplicates or not (match := pattern.fullmatch(path.name)):
        raise ValueError()
    loaded = _verify_history_file(auth, platform, directory, path, match, staged=staged, key=key)
    if key is not None and not config_fortiadc.full_capture_complete(loaded.text):
        raise ValueError()
    return loaded


def _comparison_snapshot(auth, identity, platform, *, staged=0):
    current = _SNAPSHOTS.get(identity)
    if current is not None or platform not in ('fortios', 'fortiadc'):
        return current
    if 'read' not in auth.read_inventory.get('config_access', ()):
        return None
    if platform == 'fortiadc' and not fortiadc_history_enabled(auth):
        return None
    try:
        directory = _history_directory(auth, platform, create=False)
        if directory is not None:
            key = _fortiadc_archive_key() if platform == 'fortiadc' else None
            return _read_history_snapshot(auth, platform, directory, identity, staged=staged, key=key)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise ValueError('configuration history is invalid or unavailable; output withheld') from None
