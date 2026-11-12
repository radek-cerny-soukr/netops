from functools import lru_cache
import json
from pathlib import Path
import re
import shlex
from netops_core import platforms, prompt
from .config_buffers import Content
from .read_policy import SAFE_FORTIADC_OBJECT
from .configuration import FullConfigPolicy, UnsupportedConfigurationFirmware, ConfigurationRedactionError

SUPPORTED = ('FortiADC-KVM', '7.6.7', '0676')
RIGHTS = frozenset(('system', 'networking', 'load-balance', 'log', 'link-load-balance',
                    'global-load-balance', 'security', 'share-resource', 'user'))
LEVELS = frozenset(('none', 'read', 'read-write'))
PAGER = re.compile(rb'--More-- \r {1,256}\r')
_PARTIAL = re.compile(rb'-(?:-(?:M(?:o(?:r(?:e(?:-(?:-(?: (?:\r {0,256})?)?)?)?)?)?)?)?)?')
_TAIL = 267


class Normalizer:
    def __init__(self, consumer, maximum):
        if not callable(consumer) or type(maximum) is not int or maximum < 1:
            raise ValueError('invalid configuration normalizer')
        self.consumer, self.maximum = consumer, maximum
        self.raw_bytes, self.tail, self.closed = 0, b'', False

    def feed(self, data):
        if self.closed or type(data) is not bytes:
            raise ValueError('configuration output could not be normalized')
        self.raw_bytes += len(data)
        if self.raw_bytes > self.maximum:
            self.closed = True
            raise ConfigurationRedactionError('capture-limit-exceeded')
        buffer, start, output = self.tail + data, 0, []
        for found in PAGER.finditer(buffer):
            output.append(buffer[start:found.start()])
            start = found.end()
        keep = len(buffer)
        for index in range(max(start, len(buffer) - _TAIL), len(buffer)):
            if buffer[index] == 0x2d and _PARTIAL.fullmatch(buffer, index):
                keep = index
                break
        output.append(buffer[start:keep])
        self.tail = buffer[keep:]
        chunk = b''.join(output)
        if b'\r' in chunk:
            self.closed = True
            raise ValueError('configuration output carries a carriage return outside the pager')
        if chunk:
            self.consumer(chunk)

    def finish(self):
        if self.closed or self.tail:
            self.closed = True
            raise ValueError('configuration output ends inside a pager prompt')
        self.closed = True


TLS_GET_FAMILY = 'load-balance client-ssl-profile'


class TLSGetFields:
    def __init__(self, capture, section, command):
        family, name = object_section(section)
        if family != TLS_GET_FAMILY or command != 'get ' + section:
            raise ValueError('invalid TLS configuration selector')
        self.capture, self.command, self.name = capture, command, name
        self.buffer, self.seen, self.marker = b'', set(), None
        self.echo, self.ended = False, False

    def feed(self, data):
        parts = (self.buffer + data).split(b'\n')
        self.buffer = parts.pop()
        for line in parts:
            self._line(line)
        if len(self.buffer) > self.capture.limits.physical_line_bytes:
            raise ConfigurationRedactionError('capture-limit-exceeded')

    def _line(self, raw):
        if len(raw) > self.capture.limits.physical_line_bytes:
            raise ConfigurationRedactionError('capture-limit-exceeded')
        line = raw.decode('utf-8', errors='strict')
        if any(ord(char) < 32 and char != '\t' for char in line) or '\ufffd' in line:
            raise ValueError('TLS configuration format could not be verified')
        if not line.strip():
            return
        if self.ended:
            raise ValueError('TLS configuration continued after its prompt')
        if self.marker is not None and self.seen and line.rstrip() == self.marker.rstrip():
            self.ended = True
            return
        found = prompt.prefix(prompt.PLATFORM_FORTIADC).match(line)
        if found and ':' not in line:
            body = prompt.cleaned(line, prompt.PLATFORM_FORTIADC)
            marker = found.group(1)
            if not self.seen and not self.echo and body == self.command:
                self.marker, self.echo = marker, True
                return
            if not body and self.seen and (self.marker is None or line == self.marker):
                self.ended = True
                return
            raise ValueError('TLS configuration command framing mismatch')
        if found and not self.seen and not self.echo and ':' not in found.group(1):
            self.marker = found.group(1)
            line = line[len(self.marker):]
        if line == self.command and not self.seen and not self.echo:
            self.echo = True
            return
        key, separator, value = line.partition(':')
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', key) or key in self.seen:
            raise ValueError('TLS configuration fields could not be verified')
        if not self.seen:
            self.capture.feed(('config ' + TLS_GET_FAMILY + '\nedit ' + self.name + '\n').encode())
        self.seen.add(key)
        values = value.split(None, 1) if value.startswith('ENC ') else [value]
        self.capture.feed(('set ' + key + ' ' + ' '.join(
            shlex.quote(part) for part in values) + '\n').encode())

    def finish(self):
        if self.buffer:
            self._line(self.buffer)
            self.buffer = b''
        if not self.seen:
            raise ValueError('TLS configuration fields were not returned')
        self.capture.feed(b'next\nend\n')


def verify_identity(status):
    if (not isinstance(status, str) or len(status.encode()) > 65536 or
            any(ord(c) < 32 and c not in "\n\r\t" for c in status) or "�" in status):
        raise ValueError('configuration identity could not be verified')
    lines = prompt.cleaned(status.replace('\r\n', '\n'), prompt.PLATFORM_FORTIADC).split('\n')
    for line in lines:
        found = prompt.prefix(prompt.PLATFORM_FORTIADC).match(line)
        if found and line[len(found.group(1)):].lstrip().casefold().startswith('version:'):
            raise ValueError('configuration identity could not be verified')
    records = [line for line in lines if line.lstrip().casefold().startswith('version:')]
    products = [line for line in records if not re.fullmatch(r'Version:\s+n/a\s*', line)]
    if len(products) != 1:
        raise ValueError('configuration identity could not be verified')
    try:
        identity = platforms.version_record(products[0])
    except platforms.VersionRecordError:
        raise ValueError('configuration identity could not be verified') from None
    if identity != SUPPORTED:
        raise UnsupportedConfigurationFirmware('config_platform_not_supported',
                                               detected=identity[1:], supported=(SUPPORTED[1:],))
    return identity, {'product': identity[0], 'version': identity[1], 'build': identity[2]}


OBJECT_SECTIONS = frozenset(('load-balance virtual-server', 'load-balance pool',
                             'load-balance real-server',
                             'system health-check', 'security waf profile',
                             'system certificate local_cert_group',
                             'load-balance client-ssl-profile'))


def object_section(section):
    if isinstance(section, str):
        family, separator, name = section.rpartition(' ')
        if separator and family in OBJECT_SECTIONS and SAFE_FORTIADC_OBJECT.fullmatch(name):
            return family, name
    raise ValueError('invalid configuration section')


def read_command(section, include_all=False, include_defaults=False):
    if section == 'all':
        if include_all is not True or type(include_defaults) is not bool:
            raise ValueError('invalid configuration section')
        return 'show full-configuration' if include_defaults else 'show'
    family, _ = object_section(section)
    if include_all is not False or type(include_defaults) is not bool:
        raise ValueError('invalid configuration section')
    if family == TLS_GET_FAMILY:
        if include_defaults:
            raise ValueError('invalid configuration section')
        return 'get ' + section
    return ('show full-configuration ' if include_defaults else 'show ') + section


def _object_scope(content, section):
    family, name = object_section(section)
    stack, roots, objects = [], 0, 0
    for raw in content.lines():
        words = shlex.split(raw.decode().rstrip('\n'), comments=False, posix=True)
        if not words or words[0].startswith('#'):
            continue
        command = words[0]
        if command == 'config':
            if not stack:
                roots += 1
                if ' '.join(words[1:]) != family:
                    raise ValueError('configuration object scope mismatch; output withheld')
            elif len(stack) < 2:
                raise ValueError('configuration object scope mismatch; output withheld')
            stack.append('config')
        elif command == 'edit':
            if len(stack) == 1:
                objects += 1
                if words[1:] != [name]:
                    raise ValueError('configuration object scope mismatch; output withheld')
            stack.append('edit')
        elif command in ('next', 'end'):
            stack.pop()
        elif len(stack) < 2:
            raise ValueError('configuration object scope mismatch; output withheld')
    if stack or roots != 1 or objects != 1:
        raise ValueError('configuration object scope mismatch; output withheld')
    return {'config_scope': 'device-account-visible', 'configuration_complete': False,
            'visibility_limitations': ['access-profile-unverified', 'vdom-unverified']}


@lru_cache(maxsize=1)
def _policy():
    data = json.loads(Path(__file__).with_name('config-fortiadc-' + SUPPORTED[1] + '.json').read_text())
    if data['version'] != SUPPORTED[1] or data['opaque']:
        raise ValueError('configuration policy identity mismatch')
    admin, profile = ('system admin',), ('system accprofile',)
    fields = {(tuple(path), field) for path, field in data['fields']}
    fields |= {(admin, 'access-profile'), (admin, 'accprofile-override')} | {(profile, right) for right in RIGHTS}
    edits = {tuple(path) for path in data['edits']} | {admin, profile, ('system vdom',)}
    return FullConfigPolicy('fortiadc', frozenset(fields), frozenset(edits),
                            secret_fields=frozenset((tuple(path), field) for path, field in data['secret_fields']),
                            unverified_fields=frozenset((tuple(path), field) for path, field in data['unverified_fields']),
                            inline_header_fields=frozenset((tuple(path), field) for path, field in data['inline_header_fields']),
                            sibling_header_fields=frozenset(((('security waf api-gateway-rule', 'attach-http-header'),
                                                             'http-header-name', 'http-header-value'),)))


def policy_for(firmware):
    if type(firmware) is not tuple or firmware != SUPPORTED:
        raise ValueError('config_platform_not_supported')
    return _policy()


def assess(content, account, section='all'):
    if (type(content) is not Content or type(account) is not str or not 1 <= len(account) <= 256 or
            any(ord(c) < 32 for c in account)):
        raise ValueError('configuration scope could not be assessed')
    if section != 'all':
        return _object_scope(content, section)
    path, accounts, profiles, vdoms = [], 0, {}, 0
    assigned, override, vdom_override, system_admin = [], [], [], []
    for raw in content.lines():
        try:
            words = shlex.split(raw.decode().rstrip('\n'), comments=False, posix=True)
        except (UnicodeDecodeError, ValueError):
            raise ValueError('configuration scope could not be assessed') from None
        if not words:
            continue
        command = words[0]
        top = path[0][1] if path and path[0][0] == 'config' else None
        if command == 'config':
            path.append(('config', ' '.join(words[1:])))
        elif command == 'edit':
            if len(path) == 1 and top == 'system admin' and words[1] == account:
                accounts += 1
            elif len(path) == 1 and top == 'system accprofile':
                entry = profiles.setdefault(words[1], {'edits': 0, 'fields': {}, 'unknown': False})
                entry['edits'] += 1
            elif len(path) == 1 and top == 'system vdom':
                vdoms += 1
            path.append(('edit', words[1]))
        elif command in ('next', 'end'):
            if path:
                path.pop()
        elif command in ('set', 'unset') and len(path) == 2 and path[1][0] == 'edit':
            values = tuple(words[2:]) if command == 'set' else None
            if top == 'system admin' and path[1][1] == account:
                if words[1] == 'access-profile':
                    assigned.append(values)
                elif words[1] == 'accprofile-override':
                    override.append(values)
                elif words[1] == 'vdom-override' and len(vdom_override) < 2:
                    vdom_override.append(values)
                elif words[1] == 'is-system-admin' and len(system_admin) < 2:
                    system_admin.append(values)
            elif top == 'system accprofile':
                entry = profiles[path[1][1]]
                if words[1] in RIGHTS:
                    seen = entry['fields'].setdefault(words[1], [])
                    if len(seen) < 2:
                        seen.append(values)
                else:
                    entry['unknown'] = True
    if vdoms > 1:
        raise ValueError('config_platform_not_supported: verified single-VDOM mode required')
    limitations, rights = set(), None
    if vdom_override not in ([], [('disable',)]):
        limitations.add('vdom-override-unverified')
    if accounts == 1 and system_admin == [('yes',)] and not assigned and override in ([], [('disable',)]):
        # A system administrator has no access profile of its own; FortiADC gives it every area.
        rights = dict.fromkeys(RIGHTS, 'read-write')
    elif accounts == 1 and len(assigned) == 1 and system_admin in ([], [('no',)]) and override in ([], [('disable',)]):
        values = assigned[0]
        entry = profiles.get(values[0]) if values and len(values) == 1 and not values[0].startswith(('<REDACTED', '<UNVERIFIED')) else None
        if (entry and entry['edits'] == 1 and not entry['unknown'] and set(entry['fields']) == RIGHTS and
                all(len(seen) == 1 and seen[0] and len(seen[0]) == 1 and seen[0][0] in LEVELS
                    for seen in entry['fields'].values())):
            rights = {name: seen[0][0] for name, seen in entry['fields'].items()}
    if rights is None:
        limitations.add('access-profile-unverified')
    else:
        limitations.update(name for name, level in rights.items() if level == 'none')
    if vdoms != 1:
        limitations.add('vdom-unverified')
    return {'config_scope': 'all',
            'configuration_complete': not limitations,
            'visibility_limitations': sorted(limitations)}
