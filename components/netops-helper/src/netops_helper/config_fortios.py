from functools import lru_cache
import json
from pathlib import Path
import re
import shlex

from . import configuration

_BUILDS = {'7.6.8': '3744', '8.0.2': '0251'}
_HEADERS = frozenset(('config-version', 'conf_file_ver', 'buildno', 'global_vdom'))


def _firmware(firmware):
    if (type(firmware) is not tuple or len(firmware) != 3 or
            not all(type(value) is str for value in firmware) or
            not re.fullmatch(r'(?:FortiGate|FortiWiFi)-[A-Za-z0-9_.+-]+', firmware[0])):
        raise configuration.UnsupportedConfigurationFirmware('config_platform_not_supported: unverified FortiOS firmware')
    if _BUILDS.get(firmware[1]) != firmware[2]:
        raise configuration.UnsupportedConfigurationFirmware('config_platform_not_supported: unverified FortiOS firmware',
                    detected=firmware[1:], supported=tuple(_BUILDS.items()))
    return firmware


@lru_cache(maxsize=2)
def _policy(version):
    data = json.loads(Path(__file__).with_name('config-fortios-' + version + '.json').read_text())
    if data['version'] != version:
        raise ValueError('configuration policy identity mismatch')
    prefixes = ((), ('global',), ('vdom',))
    fields = frozenset((prefix + tuple(path), field)
                       for prefix in prefixes for path, field in data['fields'])
    edits = frozenset(prefix + tuple(path) for prefix in prefixes for path in data['edits'])
    edits = edits | frozenset((('vdom',),))
    opaque = frozenset(prefix + tuple(path) for prefix in prefixes for path in data['opaque'])
    secret_fields = frozenset((prefix + tuple(path), field)
                              for prefix in prefixes for path, field in data['secret_fields'])
    return configuration.FullConfigPolicy('fortios', fields, edits, opaque, _HEADERS, True,
                                         secret_fields=secret_fields,
                                         unverified_fields=frozenset((prefix + tuple(path), field)
                                             for prefix in prefixes for path, field in data['unverified_fields']),
                                         sibling_header_fields=frozenset((prefix + ('system automation-action', 'http-headers'), 'key', 'value')
                                             for prefix in prefixes))


def policy_for(firmware):
    return _policy(_firmware(firmware)[1])


def verify_identity(status):
    from netops_core import platforms
    if (type(status) is not str or len(status.encode()) > 65536 or
            any(ord(char) < 32 and char not in '\r\n\t' for char in status) or '\ufffd' in status):
        raise ValueError('configuration identity could not be verified')
    versions = [line for line in status.splitlines() if line.lstrip().casefold().startswith('version:')]
    if len(versions) != 1:
        raise ValueError('configuration identity could not be verified')
    try:
        firmware = platforms.version_record(status)
    except platforms.VersionRecordError:
        raise ValueError('configuration identity could not be verified') from None
    firmware = _firmware(firmware)
    markers = [line for line in status.splitlines()
               if ' '.join(line.split()).casefold().startswith('virtual domain configuration')]
    single = markers == ['Virtual domain configuration: disable']
    return firmware, {
        'config_scope': 'single-vdom-device' if single else 'device-account-visible',
        'configuration_complete': False,
        'identity_scope_verified': single,
        'visibility_limitations': [] if single else ['vdom-coverage-not-verified'],
    }


def read_command(section, include_all, include_defaults):
    if type(include_defaults) is not bool:
        raise ValueError('invalid configuration defaults option')
    if section in ('switch-controller managed-switch', 'wireless-controller vap') and include_all is False:
        command = 'show ' + section
    else:
        command = configuration.read_command(section, include_all)
    return command.replace('show', 'show full-configuration', 1) if include_defaults else command

_READ_GROUPS = frozenset(('authgrp', 'ftviewgrp', 'fwgrp', 'loggrp', 'netgrp',
                          'secfabgrp', 'sysgrp', 'utmgrp', 'vpngrp', 'wanoptgrp', 'wifi'))
_ACCOUNT_OVERRIDES = frozenset(('accprofile-override', 'vdom-override', 'wildcard', 'remote-auth'))


def _visibility_entries(content, section):
    stack, name, fields, depth = [], None, None, None
    for raw in content.lines():
        line = raw.decode('ascii').strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('set ') and fields is None:
            continue
        words = shlex.split(line, comments=False, posix=True)
        if not words:
            continue
        command = words[0]
        if command == 'config':
            stack.append(('config', ' '.join(words[1:])))
        elif command == 'edit':
            configs = tuple(value for kind, value in stack if kind == 'config')
            if configs in ((section,), ('global', section)):
                name, fields, depth = words[1], {}, len(stack) + 1
            stack.append(('edit', words[1]))
        elif command in ('next', 'end'):
            if stack:
                kind, value = stack.pop()
                if kind == 'edit' and len(stack) + 1 == depth and fields is not None:
                    yield name, fields
                    name, fields, depth = None, None, None
        elif command in ('set', 'unset') and fields is not None and len(stack) == depth:
            configs = tuple(value for kind, value in stack if kind == 'config')
            if configs in ((section,), ('global', section)):
                if words[1] in _READ_GROUPS | _ACCOUNT_OVERRIDES | {'scope', 'cli-show', 'accprofile'}:
                    values = fields.setdefault(words[1], [])
                    if len(values) < 2:
                        values.append(tuple(words[2:]))


def assess(content, account, identity):
    if (type(content) is not configuration.Content or type(account) is not str or
            not 1 <= len(account) <= 256 or any(ord(char) < 32 for char in account)):
        raise ValueError('configuration scope could not be assessed')
    assigned, accounts = None, 0
    for name, fields in _visibility_entries(content, 'system admin'):
        if name == account:
            accounts += 1
            if (all(fields.get(key, [('disable',)]) == [('disable',)] for key in _ACCOUNT_OVERRIDES) and
                    len(fields.get('accprofile', [])) == 1 and len(fields['accprofile'][0]) == 1):
                assigned = fields['accprofile'][0][0]
    profiles, readable = 0, False
    if accounts == 1 and assigned is not None:
        for name, fields in _visibility_entries(content, 'system accprofile'):
            if name == assigned:
                profiles += 1
                readable = (fields.get('scope') == [('global',)] and
                            fields.get('cli-show') == [('enable',)] and
                            all(fields.get(group) in ([('read',)], [('read-write',)]) for group in _READ_GROUPS))
    metadata = dict(identity)
    metadata['visibility_limitations'] = list(identity['visibility_limitations'])
    if not (accounts == profiles == 1 and readable):
        metadata['visibility_limitations'].append('account-rights-not-verified')
    for index, unused in enumerate(_visibility_entries(content, 'vdom')):
        if index:
            if 'vdom-coverage-not-verified' not in metadata['visibility_limitations']:
                metadata['visibility_limitations'].append('vdom-coverage-not-verified')
            metadata['identity_scope_verified'] = False
            metadata['config_scope'] = 'device-account-visible'
            break
    metadata['configuration_complete'] = not metadata['visibility_limitations'] and metadata['identity_scope_verified']
    return metadata
