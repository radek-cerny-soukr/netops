from functools import lru_cache
import json
from pathlib import Path
import re
import shlex
from netops_core import platforms, prompt
from .config_buffers import Content
from .read_policy import SAFE_FORTIADC_OBJECT
from .configuration import FullConfigPolicy, UnsupportedConfigurationFirmware, ConfigurationRedactionError

# Tested identity (G00, decision of 2026-11-17): not a gate. Every FortiADC configuration read, triage_slb and the
# FortiADC diagnostics run on another model or build with firmware_support "untested" and a warning; the field
# policy of the tested version (config-fortiadc-7.6.7.json, the only one) is the nearest policy for every build
# and stays fail-closed: a field outside it is hidden.
SUPPORTED = ('FortiADC-KVM', '7.6.7', '0676')
TESTED = (SUPPORTED,)
# Top-level evidence from the VM220 show full-configuration capture. The final two blocks
# must immediately precede the closing prompt. Partial output can still have balanced CLI syntax.
_FULL_CAPTURE_SYSTEM = frozenset((b'config system global\n', b'config system interface\n',
                                  b'config system admin\n', b'config system vdom\n'))
_FULL_CAPTURE_TAIL = (b'config security web-vulnerability-scanner task\n',
                      b'config security web-vulnerability-scanner integration\n')
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
    if (len(identity[0]) > 64 or not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}', identity[1]) or
            not re.fullmatch(r'[0-9]{4,6}', identity[2])):
        # Every model and build may be read since G00, so a malformed or oversized record is unreadable.
        raise ValueError('configuration identity could not be verified')
    if not identity[0].startswith(platforms.PRODUCT_HARDWARE['fortiadc']):
        # The product kind is a real boundary (G00 §2.4); the model and build are not.
        raise UnsupportedConfigurationFirmware('config_platform_not_supported: the device is not a FortiADC product')
    return identity, {'product': identity[0], 'version': identity[1], 'build': identity[2]}


def firmware_support(identity, function='config_read for FortiADC'):
    """firmware_support (netops_core.tested) of a verified FortiADC identity (model, version, build)."""
    from netops_core import tested

    def shown(item):
        return item[1] + ' build' + item[2]

    return tested.support('FortiADC', shown(identity), [(item[0], shown(item)) for item in TESTED],
                          model=identity[0], function=function)


DEFAULT_OBJECT_SECTIONS = frozenset(('load-balance persistence', 'load-balance profile',
                                     'load-balance real-server-ssl-profile'))
OBJECT_SECTIONS = DEFAULT_OBJECT_SECTIONS | frozenset(('load-balance virtual-server', 'load-balance pool',
                             'load-balance real-server',
                             'system health-check', 'security waf profile',
                             'system certificate local_cert_group',
                             'load-balance client-ssl-profile',
                             'load-balance schedule-pool', 'system schedule-group',
                             'load-balance content-routing', 'system interface', 'system certificate local'))

# Measured on FortiADC-KVM 7.6.7 build 0676 (VM220, 2026-11-14, task 173; show full-configuration system
# schedule-group, CLI help of schedule-member): the schedule fields live in the member table, which the schema lists one level higher.
SCHEDULE_MEMBER = ('system schedule-group', 'schedule-member')
SCHEDULE_MEMBER_FIELDS = ('type', 'startdate', 'enddate', 'starttime-of-startdate', 'endtime-of-enddate',
                          'day-of-week', 'day-of-month')


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


def _object_scope(content, section, include_defaults):
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
    if not stack and roots == 1 and objects == 0 and not include_defaults and family in DEFAULT_OBJECT_SECTIONS:
        raise ValueError('configuration object not visible in show; retry with include_defaults=true')
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
    fields |= {(SCHEDULE_MEMBER, field) for field in SCHEDULE_MEMBER_FIELDS}
    edits = {tuple(path) for path in data['edits']} | {admin, profile, ('system vdom',), SCHEDULE_MEMBER}
    return FullConfigPolicy('fortiadc', frozenset(fields), frozenset(edits),
                            secret_fields=frozenset((tuple(path), field) for path, field in data['secret_fields']),
                            unverified_fields=frozenset((tuple(path), field) for path, field in data['unverified_fields']),
                            inline_header_fields=frozenset((tuple(path), field) for path, field in data['inline_header_fields']),
                            sibling_header_fields=frozenset(((('security waf api-gateway-rule', 'attach-http-header'),
                                                             'http-header-name', 'http-header-value'),)))


def policy_firmware(firmware):
    """The version whose field policy redacts this firmware: the only measured FortiADC policy (7.6.7)."""
    if (type(firmware) is not tuple or len(firmware) != 3 or not all(type(value) is str for value in firmware) or
            not firmware[0].startswith(platforms.PRODUCT_HARDWARE['fortiadc'])):
        raise ValueError('configuration identity could not be verified')
    return SUPPORTED[1]


def policy_for(firmware):
    policy_firmware(firmware)
    return _policy()


def full_capture_complete(content):
    """Check the top-level extent of a redacted full configuration."""
    depth, system = 0, set()
    first = previous = last = None
    for line in content.lines():
        if line.startswith(b'config '):
            if depth == 0:
                if first is None:
                    first = line
                if line in _FULL_CAPTURE_SYSTEM:
                    system.add(line)
                previous, last = last, line
            depth += 1
        elif line.startswith(b'edit '):
            depth += 1
        elif line in (b'next\n', b'end\n'):
            depth -= 1
    return (depth == 0 and first == b'config system global\n' and system == _FULL_CAPTURE_SYSTEM and
            (previous, last) == _FULL_CAPTURE_TAIL)


def assess(content, account, section='all', *, include_defaults=False):
    if (type(content) is not Content or type(account) is not str or not 1 <= len(account) <= 256 or
            any(ord(c) < 32 for c in account)):
        raise ValueError('configuration scope could not be assessed')
    if section != 'all':
        return _object_scope(content, section, include_defaults)
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


CERTIFICATE_QUERY = 'certificate_inventory'
CERTIFICATE_COMMAND = 'get system certificate local'
_CERT_ENDPOINTS = {
    'local': 'system_certificate_local',
    'intermediate_ca': 'system_certificate_intermediate_ca',
    'ca': 'system_certificate_ca',
}
_CERT_GROUPS = {
    'local_cert_group': 'system_certificate_local_cert_group',
    'intermediate_ca_group': 'system_certificate_intermediate_ca_group',
    'certificate_verify': 'system_certificate_certificate_verify',
}
_CERT_PROFILES = {
    'client_ssl_profile': 'load_balance_client_ssl_profile',
    'real_server_ssl_profile': 'load_balance_real_server_ssl_profile',
}
_CERT_DATE = re.compile(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+)')
_CERT_ZONES = {'UTC': 0, 'GMT': 0, 'PST': -8, 'PDT': -7, 'MST': -7, 'MDT': -6,
               'CST': -6, 'CDT': -5, 'EST': -5, 'EDT': -4, 'CET': 1, 'CEST': 2}
_CERT_GET_NAME = re.compile(r'== \[ ([^\[\]\r\n]+) \]')
_CERT_GET_FIELD = re.compile(r'[ \t]*([\w-]+):[ \t]*(.*)')


def certificate_acme(text):
    """Parse the CLI listing without retaining any field other than the ACME status."""
    result, current = {}, None
    for row in prompt.cleaned(text.replace('\r\n', '\n'), prompt.PLATFORM_FORTIADC).splitlines():
        row = row.rstrip()
        if not row or row == CERTIFICATE_COMMAND:
            continue
        entry = _CERT_GET_NAME.fullmatch(row)
        if entry and entry[1].strip() not in result:
            current = entry[1].strip()
            result[current] = None
            continue
        field = _CERT_GET_FIELD.fullmatch(row)
        if current is None or field is None:
            raise ValueError('unverified certificate listing')
        if field[1] == 'acme-status':
            if result[current] is not None or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', field[2]):
                raise ValueError('unverified ACME status')
            result[current] = field[2]
    if any(value is None for value in result.values()):
        raise ValueError('missing ACME status')
    return result


def _certificate_date(value):
    from datetime import datetime, timedelta, timezone

    match = _CERT_DATE.fullmatch(value)
    if not match:
        raise ValueError('unverified certificate date')
    timestamp, zone = match.groups()
    if zone in _CERT_ZONES:
        local_zone = timezone(timedelta(hours=_CERT_ZONES[zone]))
        return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').replace(
            tzinfo=local_zone).astimezone(timezone.utc)
    return datetime.strptime(value, '%Y-%m-%d %H:%M:%S %z').astimezone(timezone.utc)


def _certificate_text(value, limit=2048):
    if not isinstance(value, str) or len(value.encode()) > limit or (value and not value.isprintable()):
        raise ValueError('unverified certificate field')
    return value


def _certificate_row(kind, row, now):
    from datetime import timedelta

    entry = {'name': _certificate_text(row['mkey'], 128), 'kind': kind, 'references': [],
             'status': _certificate_text(row['status'], 64)}
    if not entry['name']:
        raise ValueError('missing certificate name')
    entry.update(subject=_certificate_text(row['subject']), issuer=_certificate_text(row['issuer']))
    start, expires = (_certificate_date(row[field]) for field in ('validfrom', 'validto'))
    if start > expires:
        raise ValueError('invalid certificate validity')
    extensions = row['extension']
    if not isinstance(extensions, list) or any(
            not isinstance(extension, dict) or not isinstance(extension.get('name'), str)
            for extension in extensions):
        raise ValueError('invalid certificate extensions')
    san = [_certificate_text(extension['content']) for extension in extensions
           if extension['name'] == 'X509v3 Subject Alternative Name']
    if len(san) > 1:
        raise ValueError('duplicate SAN extension')
    entry.update(not_before=start.isoformat(), not_after=expires.isoformat(),
                 days_to_expiry=(expires - now).days, expired=expires <= now,
                 expires_within_30_days=now < expires <= now + timedelta(days=30),
                 san=san[0] if san else None)
    return entry


def certificate_inventory(rest, acme, now):
    """Join account-visible global certificate tables and usage without returning raw replies."""
    from time import monotonic
    from netops_core.fortiadc_https import RequestError

    deadline = monotonic() + 35
    missing = []
    rows = {}

    def fetch(endpoint, label, **parameters):
        try:
            if monotonic() >= deadline:
                raise RequestError('timeout')
            payload = rest.read(endpoint, vdom='global', **parameters)
            if isinstance(payload, list) and all(isinstance(row, dict) for row in payload):
                return payload
            raise RequestError('incomplete_output')
        except RequestError as exc:
            missing.append({'source': label, 'reason': exc.code})
            return None

    for kind, endpoint in _CERT_ENDPOINTS.items():
        data = fetch(endpoint, kind)
        if data is None:
            continue
        for row in data:
            try:
                entry = _certificate_row(kind, row, now)
                key = (kind, entry['name'])
                if key in rows:
                    raise ValueError('duplicate certificate name')
                if kind == 'local':
                    entry['acme_status'] = (acme or {}).get(entry['name'])
                rows[key] = entry
            except (KeyError, TypeError, ValueError, OverflowError):
                missing.append({'source': kind, 'reason': 'unparsed'})

    if acme is None or set(acme) != {name for kind, name in rows if kind == 'local'}:
        missing.append({'source': 'acme_status', 'reason': 'incomplete_output'})

    groups = {}
    for kind, endpoint in _CERT_GROUPS.items():
        known = groups[kind] = {}
        for group in fetch(endpoint, kind) or ():
            name = group.get('mkey')
            count = group.get('member_count')
            if (not isinstance(name, str) or not SAFE_FORTIADC_OBJECT.fullmatch(name)
                    or type(count) is not int or count < 0 or name in known):
                missing.append({'source': kind, 'reason': 'unparsed'})
                continue
            members = fetch(endpoint + '_child_group_member', kind, pkey=name) if count else []
            if members is None or count != len(members):
                missing.append({'source': kind, 'reason': 'incomplete_output'})
                continue
            known[name] = members

    def reference(kind, name, ref):
        if not isinstance(name, str):
            missing.append({'source': ref['kind'], 'reason': 'unparsed'})
        elif name:
            target = rows.get((kind, name))
            if target is None:
                missing.append({'source': ref['kind'], 'reason': 'unresolved_reference'})
            else:
                target['references'].append(ref)

    def group_references(kind, name, ref):
        if name == '':
            return
        if not isinstance(name, str) or name not in groups[kind]:
            missing.append({'source': ref['kind'], 'reason': 'unresolved_reference'})
            return
        for member in groups[kind][name]:
            if kind == 'local_cert_group':
                for field in ('local_cert', 'extra_local_cert'):
                    reference('local', member.get(field), ref)
                for field in ('intermediate_cag', 'extra_intermediate_cag'):
                    group_references('intermediate_ca_group', member.get(field), ref)
            else:
                certificate_kind, field = (('intermediate_ca', 'intermediate_ca') if kind == 'intermediate_ca_group'
                                           else ('ca', 'ca'))
                reference(certificate_kind, member.get(field), ref)

    for kind, group_rows in groups.items():
        for name in group_rows:
            group_references(kind, name, {'kind': kind, 'name': name})

    for kind, endpoint in _CERT_PROFILES.items():
        for profile in fetch(endpoint, kind) or ():
            name = profile.get('mkey')
            if not isinstance(name, str) or not SAFE_FORTIADC_OBJECT.fullmatch(name):
                missing.append({'source': kind, 'reason': 'unparsed'})
                continue
            ref = {'kind': kind, 'name': name}
            if kind == 'client_ssl_profile':
                group_references('local_cert_group', profile.get('local_certificate_group'), ref)
                group_references('intermediate_ca_group', profile.get('forward_proxy_intermediate_ca_group'), ref)
                reference('local', profile.get('forward_proxy_local_signing_ca'), ref)
                for field in ('backend_certificate_verify', 'client_certificate_verify'):
                    group_references('certificate_verify', profile.get(field), ref)
            else:
                reference('local', profile.get('local_cert'), ref)
                group_references('certificate_verify', profile.get('cert_verify'), ref)
    for entry in rows.values():
        refs = {(ref['kind'], ref['name']) for ref in entry['references']}
        entry['references'] = [{'kind': kind, 'name': name} for kind, name in sorted(refs)]
    failures = {(entry['source'], entry['reason']) for entry in missing}
    return list(rows.values()), [{'source': source, 'reason': reason} for source, reason in sorted(failures)]
