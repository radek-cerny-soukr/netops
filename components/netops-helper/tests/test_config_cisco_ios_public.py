"""Task 128: the public config_read path for the single admitted Cisco IOS profile.

Only ``cisco_ios`` / IOSv ``15.9(3)M12`` ``fc1`` / ``VIOS-ADVENTERPRISEK9-M`` is admitted
(``config_cisco_ios_adapter``).  The positive reads run through the real root
``netops.worker.HelperBridge.call`` -> ``Proxy.request`` -> FastMCP ``server.config_read``
(``_paged_auth``) -> ``TargetAuth.decode`` -> ``engine.config_read`` -> ``read_from_device`` ->
``_exec_read`` -> the real ``config_cisco_ios.StreamRedactor`` / ``configuration.store`` / page ->
``Proxy.response`` -> the worker's final redaction and page-change guard, in process.  Refusals use the
same real ``Proxy.request`` and, for engine checks, the auth context it produced.  Only the physical SSH
exec backend (``core_ssh.run_command``), the physical host-key scan and the audit file location are
replaced; the fake feeds real byte chunks into the consumer callback it receives.

Identity: ``show version`` is the immutable REAL anonymized capture
``fixtures/real/cisco_ios/iosv_15.9.3M12/version.txt``; the unsupported case also uses the REAL
``fixtures/real/cisco_ios/iosvl2_15.2.20200924/version.txt``.  Other identity texts are DERIVED by
editing those captures.  Every ``show running-config`` text below is SYNTHETIC, not a live capture.
Nothing here measures account rights, the full-config format or any hardware/firmware.
"""

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from netops import worker
from netops.files import write_private
from netops_core import ssh as core_ssh
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, config_cisco_ios, configuration, engine, server
from netops_helper import config_cisco_ios_adapter as adapter, config_exos_adapter
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from test_proxy import DEVICE_PIN, _section

REAL = Path(__file__).parent / 'fixtures' / 'real' / 'cisco_ios'
VERSION = (REAL / 'iosv_15.9.3M12' / 'version.txt').read_text()
VERSION_L2 = (REAL / 'iosvl2_15.2.20200924' / 'version.txt').read_text()
HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask128Only'
ADDRESS = {'router-a': '192.0.2.10', 'router-b': '192.0.2.20', 'fw-c': '192.0.2.30'}
A_SECRET = 'Uplink'              # valid password of A; also a safe description word on B
A_NEW_SECRET = 'Campus'          # A's next password, registered only after B's snapshot exists
B_SECRET = 'b-router-password-only'
M = config_cisco_ios.MARKER
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
SENTINELS = ('SECRET-ENABLE-SENTINEL', 'SECRET-PASSWORD-SENTINEL', 'SECRET-COMMUNITY-SENTINEL',
             'SECRET-BANNER-SENTINEL', 'SECRET-LINE-SENTINEL', B_SECRET)
IDENTITY_TEXT = ('Technical Support', 'Processor board ID', 'host06', 'flash0:')

# SYNTHETIC running-config: 'k' kept unless it holds a forbidden value, 'h' one hidden record per line,
# 'b' the three physical lines of one banner record.
ROWS = (
    ('k', 'Building configuration...'),
    ('k', ''),
    ('k', 'Current configuration : 1873 bytes'),
    ('k', '!'),
    ('k', 'version 15.9'),
    ('h', 'service timestamps debug datetime msec'),
    ('k', '!'),
    ('k', 'hostname lab-r1'),
    ('k', '!'),
    ('h', 'enable secret 9 $9$SECRET-ENABLE-SENTINEL'),
    ('h', 'username reader privilege 15 password 0 SECRET-PASSWORD-SENTINEL'),
    ('k', '!'),
    ('k', 'interface GigabitEthernet0/0'),
    ('k', ' description Uplink to core'),
    ('k', ' ip address 192.0.2.1 255.255.255.0'),
    ('h', ' duplex auto'),
    ('k', ' no shutdown'),
    ('k', '!'),
    ('k', 'interface GigabitEthernet0/1'),
    ('k', ' description Campus access port'),
    ('k', ' description owner ' + B_SECRET),
    ('k', ' shutdown'),
    ('k', '!'),
    ('h', 'snmp-server community SECRET-COMMUNITY-SENTINEL RO'),
    ('k', '!'),
    ('b', 'banner motd ^C'),
    ('b', 'SECRET-BANNER-SENTINEL'),
    ('b', '^C'),
    ('k', '!'),
    ('h', 'line vty 0 4'),
    ('h', ' password 7 SECRET-LINE-SENTINEL'),
    ('h', ' login'),
    ('k', '!'),
    ('k', 'end'),
)
CONFIG = ''.join(text + '\n' for _, text in ROWS)
LABELS = ['cisco-ios / unsupported-statement', 'cisco-ios / unsupported-mode-line',
          'cisco-ios / unsupported-interface-or-vlan-line', 'cisco-ios / opaque-block']


def expected(*secrets):
    """The consumer-safe text: kept lines unless they hold a forbidden value, everything else masked."""
    return ''.join((text if kind == 'k' and not any(secret in text for secret in secrets) else M) + '\n'
                   for kind, text in ROWS)


def summary(*secrets):
    credentials = sum(kind == 'k' and any(secret in text for secret in secrets) for kind, text in ROWS)
    return {'credential_redactions': credentials,
            'unverified_count': sum(kind == 'h' for kind, _ in ROWS) + 1,
            'unsupported_format_count': 1, 'unverified_fields': list(LABELS), 'unverified_truncated': False}


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Wire:
    """Stands in for core_ssh.run_command, the physical SSH exec backend; records every call."""

    def __init__(self, version=VERSION, config=CONFIG.encode(), *, chunk=7, identity_rc=0, rc=0, stdout=b''):
        self.version, self.config, self.chunk = version, config, chunk
        self.identity_rc, self.rc, self.stdout = identity_rc, rc, stdout
        self.calls = []

    def __call__(self, host, port, login, credential, host_key_line, command, *, legacy_ssh=None,
                 timeout_seconds=None, capture_max_bytes=None, stdout_consumer=None,
                 idle_timeout_seconds=None, run=None, now=None):
        self.calls.append({'host': host, 'command': command, 'login': login, 'secret': credential.use(),
                           'host_key_line': host_key_line, 'timeout': timeout_seconds, 'cap': capture_max_bytes,
                           'idle': idle_timeout_seconds, 'consumer': stdout_consumer})
        if stdout_consumer is None:
            data = self.version if type(self.version) is bytes else self.version.encode()
            return core_ssh.Result(rc=self.identity_rc, stdout=data, said='', started_at='t0', finished_at='t1')
        assert command == 'show running-config'
        for start in range(0, len(self.config), self.chunk):
            try:
                stdout_consumer(self.config[start:start + self.chunk])
            except core_ssh.OutputLimitError:
                raise
            except Exception:
                raise core_ssh.OutputConsumerError() from None
        return core_ssh.Result(rc=self.rc, stdout=self.stdout, said='', started_at='t0', finished_at='t1')

    def commands(self, alias='router-b'):
        return [call['command'] for call in self.calls if call['host'] == ADDRESS[alias]]


def _ios_section(alias, access=('read',)):
    section = _section()
    section.pop('snmp_credential')
    section['egress']['addresses'] = [ADDRESS[alias]]
    section.update(ssh_platform='cisco_ios', enabled_queries=['version'],
                   fortios_output_standard_verified=False, configuration_limits=dict(LIMITS),
                   rate_limit={'requests': 30, 'window_seconds': 60})
    section['read_inventory'] = {'interfaces': [], 'services': [], 'addresses': [], 'config_access': list(access)}
    return section


def _device(alias, platform, section):
    return {'name': alias, 'platform': platform, 'address': ADDRESS[alias], 'port': 22, 'role': 'internal',
            'credential': alias + '-account', 'host_key_fingerprint': DEVICE_PIN, 'legacy_ssh': None,
            'auditor': None, 'helper': section}


def _vault(helper, a_secret, replace=False):
    write_private(helper / 'vault.json', json.dumps({'version': 2, 'credentials': {
        'router-a-account': {'kind': 'password', 'login': 'a-user', 'value': a_secret},
        'router-b-account': {'kind': 'password', 'login': 'b-user', 'value': B_SECRET},
        'fw-c-account': {'kind': 'password', 'login': 'c-user', 'value': 'fw-c-password-only'},
    }}).encode(), replace=replace)


def _inventory(helper, b_access=('read',)):
    forti = _section()
    forti.pop('snmp_credential')
    forti['egress']['addresses'] = [ADDRESS['fw-c']]
    forti['read_inventory'] = {'interfaces': ['port1'], 'services': [], 'addresses': [], 'config_access': ['read']}
    forti['rate_limit'] = {'requests': 30, 'window_seconds': 60}
    write_private(helper / 'inventory.json', json.dumps({'version': 2, 'devices': [
        _device('router-a', 'cisco_ios', _ios_section('router-a')),
        _device('router-b', 'cisco_ios', _ios_section('router-b', b_access)),
        _device('fw-c', 'fortios', forti),
    ]}).encode(), replace=True)


@pytest.fixture
def env(tmp_path, monkeypatch):
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    state = tmp_path / 'state'
    helper = state / 'helper'
    helper.mkdir(parents=True, mode=0o700)
    _inventory(helper)
    _vault(helper, A_SECRET)
    monkeypatch.setattr(worker, 'STATE', state)
    monkeypatch.setattr(proxy_module, 'INVENTORY', helper / 'inventory.json')
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(helper / 'operations.jsonl', 'helper'))
    scans = []

    def scan(address, port, pin, timeout, legacy=None):
        scans.append((address, port, pin))
        return address + ' ' + HOST_KEY
    monkeypatch.setattr(engine.core_hostkey, 'scan', scan)
    wire = Wire()
    monkeypatch.setattr(engine.core_ssh, 'run_command', wire)
    paged = []
    original = server._paged_auth

    def observed(target, auth_context, redaction_context):
        auth = original(target, auth_context, redaction_context)
        paged.append((target, auth.redaction_secrets))
        return auth
    monkeypatch.setattr(server, '_paged_auth', observed)
    bridge = worker.HelperBridge()
    yield {'bridge': bridge, 'wire': wire, 'helper': helper, 'paged': paged, 'scans': scans,
           'monkeypatch': monkeypatch}
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _call(env, name, arguments):
    return asyncio.run(env['bridge'].call(server.mcp, name, dict(arguments)))


def _b(**options):
    return {'target': 'router-b', 'platform': 'cisco_ios', 'section': 'all', 'include_all': True,
            'redaction': 'full', **options}


def _rewire(env, wire):
    env['monkeypatch'].setattr(engine.core_ssh, 'run_command', wire)
    env['wire'] = wire
    return wire


def _assert_clean(value, *secrets):
    shown = value if type(value) is str else json.dumps(value, default=repr) + str(value) + repr(value)
    for item in (*secrets, *SENTINELS):
        assert item not in shown
    assert 'page_changed_by_redaction' not in shown


def _page(result):
    assert result['isError'] is False, result
    data = result['structuredContent']
    assert data.get('error_code') != 'page_changed_by_redaction', data
    assert data['ok'] is True, data
    assert json.loads(result['content'][0]['text']) == data
    assert data['returned_bytes'] == len(data['untrusted_device_output'].encode())
    return data


def _pages(env, first, arguments, limit):
    pages, data = [first], first
    while data['next_offset'] is not None:
        data = _page(_call(env, 'config_read', {**arguments, 'snapshot_id': first['snapshot_id'],
                                                'offset': data['next_offset'], 'limit': limit,
                                                'content_sha256': first['content_sha256']}))
        pages.append(data)
    return pages, ''.join(page['untrusted_device_output'] for page in pages)


def _register_a(env):
    """An allowed ordinary read on A: the Proxy registers A's credential as a session secret."""
    _call(env, 'ssh_read', {'target': 'router-a', 'platform': 'cisco_ios', 'query': 'version'})
    assert A_SECRET in env['bridge'].proxy.session_secrets or A_NEW_SECRET in env['bridge'].proxy.session_secrets


def _engine_auth(env, **overrides):
    """The auth context the real Proxy.request forwards for an IOS config_read, decoded by TargetAuth."""
    message = {'jsonrpc': '2.0', 'id': 'engine-auth', 'method': 'tools/call',
               'params': {'name': 'config_read', 'arguments': _b(**overrides)}}
    raw = env['bridge'].proxy.request(json.dumps(message).encode())
    assert raw is not None, env['bridge'].proxy.emitted
    arguments = json.loads(raw)['params']['arguments']
    return TargetAuth.decode('router-b', arguments['auth_context'])


def _read(auth, **options):
    arguments = {'redaction': 'full', 'include_defaults': False, **options}
    return engine.config_read(auth, arguments.pop('platform', 'cisco_ios'), arguments.pop('section', 'all'),
                              arguments.pop('include_all', True), **arguments)


# ------------------------------------------------------------------- positive public read and paging

def test_fresh_public_read_pages_and_continues_without_more_ssh(env):
    first = _page(_call(env, 'config_read', _b(limit=200)))
    wire = env['wire']
    text_expected = expected(B_SECRET)

    # One bounded identity read, then exactly the fixed capture command, streamed into the bounded consumer.
    assert wire.commands() == ['show version', 'show running-config']
    assert [call['consumer'] is None for call in wire.calls] == [True, False]
    capture = wire.calls[1]
    assert 'bounded_consumer' in capture['consumer'].__qualname__
    assert (capture['timeout'], capture['idle'], capture['cap']) == (123, 17, 4194304)
    for call in wire.calls:
        assert (call['host'], call['login'], call['secret']) == (ADDRESS['router-b'], 'b-user', B_SECRET)
        assert call['host_key_line'] == ADDRESS['router-b'] + ' ' + HOST_KEY
    assert env['scans'] and all(pin == DEVICE_PIN for _, _, pin in env['scans'])
    # The real server wrapper took the private handoff (_paged_auth) for the IOS read.
    assert [target for target, _ in env['paged']] == ['router-b']
    assert B_SECRET in env['paged'][0][1]

    # Exact profile and honest metadata.
    assert first['platform'] == 'cisco_ios' and first['redaction'] == 'full' and first['view'] == 'running'
    assert first['section'] == 'all' and first['command'] == 'show running-config'
    assert first['include_defaults'] is False
    assert first['redaction_profile'] == adapter.PROFILE
    assert first['firmware'] == {'model': 'IOSv', 'version': '15.9(3)M12', 'build': 'fc1'}
    assert first['capture_complete'] is True and first['configuration_complete'] is False
    assert first['identity_scope_verified'] is False and first['config_scope'] == 'device-account-visible'
    assert first['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified',
                                               'schema-fields-unverified']
    assert {key: first[key] for key in summary(B_SECRET)} == summary(B_SECRET)
    assert first['credential_redactions'] == 1
    assert first['redacted_count'] == 1 + summary()['unverified_count']

    # Continuations page the stored Content; no further SSH.
    pages, text = _pages(env, first, _b(), 200)
    assert len(pages) > 2 and text == text_expected
    assert wire.commands() == ['show version', 'show running-config'] and len(wire.calls) == 2
    for page in pages:
        assert page['content_sha256'] == page['snapshot_sha256'] == sha(text)
        assert page['total_bytes'] == len(text.encode())
        assert page['redaction_profile'] == adapter.PROFILE and page['configuration_complete'] is False
        assert page['identity_scope_verified'] is False and page['firmware'] == first['firmware']
    for page in pages[:-1]:
        assert page['untrusted_device_output'].endswith('\n')
        assert page['next_offset'] == page['offset'] + page['returned_bytes']

    stored = configuration._SNAPSHOTS[first['snapshot_id']]
    assert stored.text.sha256 == sha(text) and stored.text.page(0, stored.text.total)[0] == text
    assert stored.profile == adapter.PROFILE and stored.firmware == adapter.SUPPORTED
    assert stored.scope[1:3] == ('cisco_ios', 'running') and len(stored.hidden) == 0
    # The caller credential became a marker, not a raw value or <REDACTED>.
    assert ' description owner' not in text and '<REDACTED' not in text
    for page in pages:
        _assert_clean(page)
    _assert_clean(repr(stored) + str(dict(stored.metadata)))


def test_proxy_reserves_two_reads_for_a_capture_and_none_for_a_cached_page(env):
    proxy = env['bridge'].proxy
    _, section, _ = proxy._target('router-b')
    assert proxy._rate_cost('config_read', None, section, {'platform': 'cisco_ios'}) == 2
    assert proxy._rate_cost('config_read', None, section,
                            {'platform': 'cisco_ios', 'snapshot_id': 'cfg_' + '0' * 32}) == 0


# ------------------------------------------------- session secret collision before store and hash

def test_session_secret_collision_is_redacted_before_store_hash_and_final_response(env):
    _register_a(env)
    proxy = env['bridge'].proxy
    assert A_SECRET in proxy.session_secrets
    first = _call(env, 'config_read', _b(limit=60))
    data = _page(first)
    _assert_clean(first, A_SECRET)
    safe = expected(B_SECRET, A_SECRET)
    assert ' description Campus access port\n' in safe and ' description Uplink' not in safe
    assert data['credential_redactions'] == 2
    assert env['wire'].commands('router-b') == ['show version', 'show running-config']
    assert any(target == 'router-b' and A_SECRET in secrets for target, secrets in env['paged'])

    pages, text = _pages(env, data, _b(), 60)
    assert len(pages) > 2 and text == safe
    for page in pages:
        assert page['content_sha256'] == page['snapshot_sha256'] == sha(text)
        assert page['total_bytes'] == len(text.encode())
        assert A_SECRET not in json.dumps(page)
    stored = configuration._SNAPSHOTS[data['snapshot_id']].text
    assert stored.page(0, stored.total)[0] == text and stored.sha256 == sha(text)
    assert env['wire'].commands('router-b') == ['show version', 'show running-config']

    # A later session secret that collides with the stored text: concrete refusal, never a re-read.
    _vault(env['helper'], A_NEW_SECRET, replace=True)
    _register_a(env)
    assert A_NEW_SECRET in proxy.session_secrets
    before = list(env['wire'].calls)
    for arguments in (_b(snapshot_id=data['snapshot_id'], offset=data['next_offset'], limit=60,
                         content_sha256=data['content_sha256']),
                      _b(snapshot_id=data['snapshot_id'], offset=0, limit=60)):
        result = _call(env, 'config_read', arguments)
        _assert_clean(result, A_NEW_SECRET)
        refused = result['structuredContent']
        assert result['isError'] is True and refused['ok'] is False, result
        assert refused['error_code'] == 'config_snapshot_redaction_changed' and refused['restart_offset'] == 0
        assert 'untrusted_device_output' not in refused and 'content_sha256' not in refused
    assert env['wire'].calls == before

    fresh = _page(_call(env, 'config_read', _b(limit=48000)))
    _assert_clean(fresh, A_SECRET, A_NEW_SECRET)
    text = expected(B_SECRET, A_SECRET, A_NEW_SECRET)
    assert fresh['untrusted_device_output'] == text and fresh['next_offset'] is None
    assert fresh['content_sha256'] == fresh['snapshot_sha256'] == sha(text)
    assert env['wire'].commands('router-b') == ['show version', 'show running-config'] * 2


# ------------------------------------------------------------------- refusals before any transport

def _refused(result):
    assert result['isError'] is True, result
    return json.loads(result['content'][0]['text'])


def test_proxy_refuses_without_config_access_before_ssh(env):
    _inventory(env['helper'], b_access=())
    error = _refused(_call(env, 'config_read', _b()))
    assert error['data']['field'] == 'config_access'
    assert env['wire'].calls == [] and env['paged'] == []


@pytest.mark.parametrize('target, platform', [
    ('router-b', 'fortios'), ('router-b', 'fortiadc'), ('router-b', 'extreme_exos'), ('fw-c', 'cisco_ios'),
])
def test_proxy_refuses_platform_mismatch_before_ssh(env, target, platform):
    error = _refused(_call(env, 'config_read', {**_b(), 'target': target, 'platform': platform}))
    assert error['data']['field'] == 'platform'
    assert env['wire'].calls == [] and env['paged'] == []


@pytest.mark.parametrize('options, field', [
    ({'include_defaults': True}, 'include_defaults'),
    ({'redaction': 'minimal'}, 'redaction'),
    ({'include_all': False}, 'include_all'),
    ({'section': 'interface'}, 'section'),
])
def test_proxy_refuses_unsupported_options_before_ssh(env, options, field):
    error = _refused(_call(env, 'config_read', _b(**options)))
    assert error['data']['field'] == field
    assert env['wire'].calls == [] and env['paged'] == []


def test_engine_refuses_options_access_and_platform_before_ssh(env):
    auth = _engine_auth(env)
    for options in ({'include_defaults': True}, {'redaction': 'minimal'}, {'include_all': False},
                    {'section': 'interface', 'include_all': False}):
        with pytest.raises(ValueError, match='config_platform_not_supported'):
            _read(auth, **options)
    with pytest.raises(ValueError, match='outside target policy'):
        _read(replace(auth, ssh_platform='fortinet'))
    with pytest.raises(ValueError, match='not enabled'):
        _read(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ()}))
    # Task 157: config_diff is open for cisco_ios, but only with compare (next to read) in config_access.
    with pytest.raises(ValueError, match='not enabled'):
        engine.config_diff(auth, 'cisco_ios', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    compare = replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(compare, 'cisco_ios', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    with pytest.raises(ValueError, match='outside target policy'):
        engine.config_diff(replace(compare, ssh_platform='fortinet'), 'cisco_ios', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    assert env['wire'].calls == [] and not configuration._SNAPSHOTS


# ------------------------------------------------------------ identity gates the configuration command

@pytest.mark.parametrize('version, message', [
    (VERSION_L2, 'firmware-not-supported for cisco_ios'),
    (VERSION.replace('15.9(3)M12', '15.9(3)M11'), 'firmware-not-supported for cisco_ios'),
    (VERSION + VERSION, 'identity-unverifiable'),
    (VERSION.replace('Cisco IOSv (revision', 'Cisco IOSvX (revision'), 'identity-unverifiable'),
    ('', 'identity-unverifiable'),
], ids=['real-iosvl2', 'derived-other-release', 'repeated-header', 'model-mismatch', 'empty'])
def test_unsupported_or_unverifiable_identity_never_runs_the_config_command(env, version, message):
    auth = _engine_auth(env)
    wire = _rewire(env, Wire(version=version))
    with pytest.raises(ValueError, match=message) as raised:
        _read(auth)
    assert wire.commands() == ['show version'] and not configuration._SNAPSHOTS
    shown = str(raised.value) + repr(raised.value)
    assert 'output withheld' in shown
    for text in IDENTITY_TEXT:
        assert text not in shown


def test_refused_identity_read_never_runs_the_config_command(env):
    auth = _engine_auth(env)
    wire = _rewire(env, Wire(identity_rc=1))
    with pytest.raises(ValueError, match='device-refused during identity read'):
        _read(auth)
    assert wire.commands() == ['show version'] and not configuration._SNAPSHOTS


# ------------------------------------------------------- damaged or incomplete capture stores nothing

def _replace_row(old, new):
    return CONFIG.replace(old, new).encode()


@pytest.mark.parametrize('wire, message', [
    (lambda: Wire(config=CONFIG[:-len('end\n')].encode()), 'stream-incomplete'),
    (lambda: Wire(config=CONFIG.split('SECRET-BANNER-SENTINEL')[0].encode() + b'SECRET-BANNER-SENTINEL\n'),
     'stream-incomplete'),
    (lambda: Wire(config=_replace_row('hostname lab-r1\n', 'hostname lab-r1\n --More-- SECRET-PASSWORD-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('hostname lab-r1\n', 'menu ops title ^C SECRET-BANNER-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=CONFIG.encode()[:40] + b'\xff\xfe' + CONFIG.encode()[40:]), 'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('end\n', '% Invalid input SECRET-PASSWORD-SENTINEL\nend\n')),
     'device-refused during capture'),
    (lambda: Wire(rc=1), 'device-refused during capture'),
    (lambda: Wire(stdout=b'accumulated SECRET-PASSWORD-SENTINEL'), 'transport-contract-failed'),
    (lambda: Wire(config=_replace_row('hostname lab-r1\n', 'hostname ' + 'a' * 5000 + '\n')),
     'capture-limit-exceeded'),
], ids=['no-end', 'open-banner', 'pager', 'menu', 'bad-utf8', 'device-refusal', 'rc', 'accumulated-raw',
        'line-limit'])
def test_damaged_or_incomplete_capture_is_refused_without_store_or_leak(env, wire, message):
    auth = _engine_auth(env)
    wire = _rewire(env, wire())
    with pytest.raises(ValueError, match=message) as raised:
        _read(auth)
    assert 'output withheld' in str(raised.value)
    assert wire.commands() == ['show version', 'show running-config']
    assert not configuration._SNAPSHOTS
    _assert_clean(str(raised.value) + repr(raised.value))
    for text in IDENTITY_TEXT:
        assert text not in str(raised.value)


# ------------------------------------------------- cached snapshot: foreign profile/platform refused

def test_cached_snapshot_keeps_profile_and_platform_binding(env):
    auth = _engine_auth(env)
    first = _read(auth, limit=200)
    identity = first['snapshot_id']
    assert env['wire'].commands() == ['show version', 'show running-config']
    page = _read(auth, snapshot_id=identity, offset=first['next_offset'], limit=200)
    assert page['snapshot_sha256'] == first['snapshot_sha256'] and len(env['wire'].calls) == 2

    stored = configuration._SNAPSHOTS[identity]
    for profile in (config_exos_adapter.PROFILE, 'cisco_ios-full-1:' + '0' * 64, configuration.PROFILE):
        configuration._SNAPSHOTS[identity] = replace(stored, profile=profile)
        with pytest.raises(ValueError, match='invalid configuration profile|capture options mismatch'):
            _read(auth, snapshot_id=identity)
    configuration._SNAPSHOTS[identity] = replace(stored, firmware=('IOSv', '15.9(3)M11', 'fc1'))
    with pytest.raises(ValueError, match='policy mismatch'):
        _read(auth, snapshot_id=identity)
    configuration._SNAPSHOTS[identity] = stored
    # Another platform or another credential cannot page this snapshot.
    exos = replace(auth, ssh_platform='extreme_exos')
    with pytest.raises(ValueError, match='scope mismatch|not_supported'):
        engine.config_read(exos, 'extreme_exos', 'all', True, identity, 0, 200, 'full')
    with pytest.raises(ValueError, match='scope mismatch'):
        _read(replace(auth, secret='another-secret'), snapshot_id=identity, offset=1)
    assert _read(auth, snapshot_id=identity)['snapshot_sha256'] == first['snapshot_sha256']
    assert len(env['wire'].calls) == 2

    configuration._snapshot_profile(adapter.PROFILE, 'cisco_ios')
    for profile, platform in ((adapter.PROFILE, 'fortios'), (adapter.PROFILE, 'extreme_exos'),
                              (config_exos_adapter.PROFILE, 'cisco_ios'), ('cisco_ios-full-1:' + '0' * 64, 'cisco_ios'),
                              (adapter.PROFILE.upper(), 'cisco_ios'), (None, 'cisco_ios')):
        with pytest.raises(ValueError, match='invalid configuration profile'):
            configuration._snapshot_profile(profile, platform)
