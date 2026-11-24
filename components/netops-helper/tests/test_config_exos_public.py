"""verification: the public config_read path for one evidenced ExtremeXOS identity.

A fresh read is driven through the real Proxy.request -> auth_context -> TargetAuth.decode ->
engine.config_read -> read_from_device -> _exec_read -> _exec_command.  Only the physical core SSH
exec backend (``core_ssh.run_command``) and the physical host-key scan are replaced; the fake feeds
real byte chunks into the callback it receives and answers rc 0 with empty accumulated stdout, the
same contract the core runner keeps (a consumer exception becomes OutputConsumerError).

Identity texts: ``show version`` is the real anonymized capture
``fixtures/real/exos/dom_33.7.1.6_20261114/sample_a-version.txt`` (image 33.7.1.6-patch1-11, no model
name); ``show switch`` is the real anonymized capture
``fixtures/real/exos/x440g2-12p-10g4_33.7.1.6/switch.txt`` (System Type X440G2-12p-10G4).  They come
from separate captures; served together they are a derived coherent scenario for this shared fake
transport, not a new live measurement.  The configuration below is synthetic.
"""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re

import pytest

from netops_core import ssh as core_ssh
from netops_helper import configuration, config_exos, config_exos_adapter as adapter, engine
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from test_proxy import DEVICE_PIN, _paths, _rewrite, _tool_call

FIXTURES = Path(__file__).parent / 'fixtures' / 'real' / 'exos'
VERSION = (FIXTURES / 'dom_33.7.1.6_20261114' / 'sample_a-version.txt').read_text()
SWITCH = (FIXTURES / 'x440g2-12p-10g4_33.7.1.6' / 'switch.txt').read_text()
KNOWN_HOSTS = '192.0.2.10 ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask81Only'
CALLER_SECRET = 'selected-secret'      # the vault password of device-a-account in test_proxy
M = config_exos.MARKER
SENTINELS = ('SECRET-COMMUNITY-SENTINEL', 'SECRET-PASSWORD-SENTINEL', 'SECRET-BANNER-SENTINEL',
             'SECRET-PEM-SENTINEL', CALLER_SECRET)
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}

CONFIG = (
    '#\n'
    '# Module vlan configuration.\n'
    '#\n'
    'create vlan Users\n'
    'create vlan Servers tag 20\n'
    'configure vlan Users tag 10\n'
    'configure vlan Users add ports 1-4 untagged\n'
    'configure vlan Servers add ports 5,6 tagged\n'
    'configure vlan Users ipaddress 192.0.2.1 255.255.255.0\n'
    'enable ipforwarding vlan Users\n'
    'configure ports 1 auto off speed 1000 duplex full\n'
    'disable ports 12\n'
    '\n'
    'create vlan ' + CALLER_SECRET + '\n'
    'configure snmpv3 add community "SECRET-COMMUNITY-SENTINEL" name "SECRET-COMMUNITY-SENTINEL" user v1v2c_ro\n'
    'create account admin reader "SECRET-PASSWORD-SENTINEL"\n'
    'configure banner after-login "Welcome\n'
    'SECRET-BANNER-SENTINEL line\n'
    'end"\n'
    '-----BEGIN RSA PRIVATE KEY-----\n'
    'SECRET-PEM-SENTINEL\n'
    '-----END RSA PRIVATE KEY-----\n'
    'configure vlan Users add ports 7 untagged\n'
)
EXPECTED = (
    M + '\n' + M + '\n' + M + '\n'
    'create vlan Users\n'
    'create vlan Servers tag 20\n'
    'configure vlan Users tag 10\n'
    'configure vlan Users add ports 1-4 untagged\n'
    'configure vlan Servers add ports 5,6 tagged\n'
    'configure vlan Users ipaddress 192.0.2.1 255.255.255.0\n'
    'enable ipforwarding vlan Users\n'
    'configure ports 1 auto off speed 1000 duplex full\n'
    'disable ports 12\n'
    '\n' + (M + '\n') * 9 +
    'configure vlan Users add ports 7 untagged\n'
)
SUMMARY = {'credential_redactions': 1, 'unverified_count': 11, 'unsupported_format_count': 6,
           'unverified_fields': ['exos / comment', 'exos / unsupported-statement', 'exos / multiline-record',
                                 'exos / opaque-block'],
           'unverified_truncated': False}


class Wire:
    """Stands in for core_ssh.run_command, the physical SSH exec backend, and records every call."""

    def __init__(self, version=VERSION, switch=SWITCH, config=CONFIG.encode(), *, chunk=7,
                 identity_rc=None, rc=0, stdout=b'', fail=None):
        self.identity = {'show version': version, 'show switch': switch}
        self.config, self.chunk = config, chunk
        self.identity_rc = identity_rc or {}
        self.rc, self.stdout, self.fail = rc, stdout, fail
        self.calls = []

    def __call__(self, host, port, login, credential, host_key_line, command, *, legacy_ssh=None,
                 timeout_seconds=None, capture_max_bytes=None, stdout_consumer=None,
                 idle_timeout_seconds=None, run=None, now=None):
        self.calls.append({'command': command, 'host': host, 'port': port, 'login': login,
                           'secret': credential.use(), 'host_key_line': host_key_line,
                           'timeout': timeout_seconds, 'cap': capture_max_bytes,
                           'idle': idle_timeout_seconds, 'consumer': stdout_consumer})
        if stdout_consumer is None:
            text = self.identity[command]
            data = text if type(text) is bytes else text.encode()
            return core_ssh.Result(rc=self.identity_rc.get(command, 0), stdout=data, said='',
                                   started_at='t0', finished_at='t1')
        assert command == 'show configuration'
        fed = 0
        for start in range(0, len(self.config), self.chunk):
            if self.fail is not None and fed >= len(self.config) // 2:
                raise self.fail
            try:
                stdout_consumer(self.config[start:start + self.chunk])
            except core_ssh.OutputLimitError:
                raise
            except Exception:
                raise core_ssh.OutputConsumerError() from None
            fed += self.chunk
        return core_ssh.Result(rc=self.rc, stdout=self.stdout, said='', started_at='t0', finished_at='t1')

    @property
    def commands(self):
        return [call['command'] for call in self.calls]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    scans = []

    def scan(address, port, pin, timeout, legacy=None):
        scans.append((address, port, pin))
        return KNOWN_HOSTS
    monkeypatch.setattr(engine.core_hostkey, 'scan', scan)
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    document = json.loads(inventory.read_text())
    device = document['devices'][0]
    device['platform'] = 'exos'
    helper = device['helper']
    helper.update(ssh_platform='exos', enabled_queries=['version', 'switch'],
                  fortios_output_standard_verified=False, configuration_limits=dict(LIMITS),
                  rate_limit={'requests': 3, 'window_seconds': 60})
    helper['read_inventory'] = {'interfaces': [], 'services': [], 'addresses': [], 'config_access': ['read']}
    _rewrite(inventory, document)
    state = {'inventory': inventory, 'document': document, 'scans': scans, 'monkeypatch': monkeypatch}
    yield state
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _proxy(env, arguments, request_id=1, proxy=None):
    proxy = proxy or proxy_module.Proxy()
    emitted = []
    env['monkeypatch'].setattr(proxy, '_emit', emitted.append)
    forwarded = proxy.request(_tool_call(request_id, 'config_read', arguments))
    return proxy, forwarded, emitted


def _auth(env, **overrides):
    arguments = {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all', 'include_all': True,
                 'redaction': 'full', **overrides}
    _, forwarded, emitted = _proxy(env, arguments)
    assert forwarded is not None, emitted
    context = json.loads(forwarded)['params']['arguments']['auth_context']
    return TargetAuth.decode('device-a', context)


def _wire(env, wire):
    env['monkeypatch'].setattr(engine.core_ssh, 'run_command', wire)
    return wire


def _read(auth, **options):
    arguments = {'redaction': 'full', 'include_defaults': False, **options}
    return engine.config_read(auth, arguments.pop('platform', 'extreme_exos'), arguments.pop('section', 'all'),
                              arguments.pop('include_all', True), **arguments)


def _assert_no_sentinel(*values):
    for value in values:
        shown = value if type(value) is str else repr(value) + json.dumps(value, default=repr)
        for sentinel in SENTINELS:
            assert sentinel not in shown


# ---------------------------------------------------------------------------- positive public read

def test_fresh_public_read_redacts_stores_and_pages_without_more_ssh(env):
    auth = _auth(env)
    assert auth.ssh_platform == 'extreme_exos'
    assert CALLER_SECRET in auth.secrets
    wire = _wire(env, Wire())
    first = _read(auth, limit=200)

    # Exactly three exec operations: two protected identity reads, then the streamed capture.
    assert wire.commands == ['show version', 'show switch', 'show configuration']
    assert [call['consumer'] is None for call in wire.calls] == [True, True, False]
    capture = wire.calls[2]
    assert callable(capture['consumer']) and 'bounded_consumer' in capture['consumer'].__qualname__
    limits = auth.configuration_limits
    assert (capture['timeout'], capture['idle'], capture['cap']) == (123, 17, 4194304)
    assert (limits.total_seconds, limits.idle_seconds, limits.all_bytes) == (123, 17, 4194304)
    for call in wire.calls:
        assert (call['host'], call['port'], call['login'], call['secret']) == (
            '192.0.2.10', 22, 'selected-user', CALLER_SECRET)
        assert call['host_key_line'] == KNOWN_HOSTS
    assert env['scans'] and all(pin == DEVICE_PIN for _, _, pin in env['scans'])

    # Response fields: capture complete, configuration honestly not complete.
    assert first['ok'] is True and first['platform'] == 'extreme_exos' and first['redaction'] == 'full'
    assert first['view'] == 'running' and first['section'] == 'all' and first['command'] == 'show configuration'
    assert first['capture_complete'] is True and first['configuration_complete'] is False
    assert first['config_scope'] == 'device-account-visible' and first['identity_scope_verified'] is False
    assert first['visibility_limitations'] == ['account-rights-not-verified', 'schema-fields-unverified',
                                               'formats-not-verified']
    assert {key: first[key] for key in SUMMARY} == SUMMARY
    assert first['redacted_count'] == 12
    assert first['firmware'] == {'model': 'X440G2-12p-10G4', 'version': '33.7.1.6', 'build': 'patch1-11'}
    assert first['redaction_profile'] == adapter.PROFILE
    assert re.fullmatch(r'extreme_exos-full-1:[0-9a-f]{64}', adapter.PROFILE)
    assert first['include_defaults'] is False
    # The tested identity (STARTUP): the reply is as before, without firmware_support or warnings.
    assert 'firmware_support' not in first and 'warnings' not in first

    # Paging by whole lines over the stored Content; continuations never touch SSH.
    pages, page = [first], first
    while page['next_offset'] is not None:
        page = _read(auth, snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=200)
        pages.append(page)
    assert len(pages) > 2 and len(wire.calls) == 3
    text = ''.join(item['untrusted_device_output'] for item in pages)
    assert text == EXPECTED
    digest = hashlib.sha256(EXPECTED.encode()).hexdigest()
    for item in pages:
        assert item['content_sha256'] == item['snapshot_sha256'] == digest
        assert item['returned_bytes'] == len(item['untrusted_device_output'].encode())
        assert item['capture_complete'] is True and item['configuration_complete'] is False
        assert item['firmware'] == first['firmware'] and item['redaction_profile'] == adapter.PROFILE
        assert 'firmware_support' not in item and 'warnings' not in item
    for item in pages[:-1]:
        assert item['untrusted_device_output'].endswith('\n')
        assert item['next_offset'] == item['offset'] + item['returned_bytes']
    assert pages[-1]['total_bytes'] == len(EXPECTED.encode())

    stored = configuration._SNAPSHOTS[first['snapshot_id']]
    assert isinstance(stored.text, configuration.Content)
    assert stored.text.sha256 == digest and stored.profile == adapter.PROFILE
    assert stored.scope[1:3] == ('extreme_exos', 'running') and stored.firmware == adapter.TESTED
    assert len(stored.hidden) == 0
    _assert_no_sentinel(text, first, pages, repr(stored), str(dict(stored.metadata)))

    # The caller credential reached the consumer: its verified sentence became a marker, not <REDACTED>.
    lines = EXPECTED.split('\n')
    assert lines[13] == M and '<REDACTED' not in text


def test_filter_and_cached_filtered_continuation_without_ssh(env):
    auth = _auth(env)
    wire = _wire(env, Wire())
    first = _read(auth, limit=48000)
    assert len(wire.calls) == 3
    view = _read(auth, snapshot_id=first['snapshot_id'], contains='vlan Users', limit=60)
    expected = ''.join(line + '\n' for line in EXPECTED.split('\n') if 'vlan Users' in line)
    assert view['matched_lines'] == expected.count('\n') == 6
    assert view['total_lines'] == EXPECTED.count('\n')
    assert re.fullmatch('[0-9a-f]{64}', view['filter_sha256'])
    parts, page = [view['untrusted_device_output']], view
    while page['next_offset'] is not None:
        page = _read(auth, snapshot_id=first['snapshot_id'], contains='vlan Users', limit=60,
                     offset=page['next_offset'], content_sha256=view['content_sha256'],
                     filter_sha256=view['filter_sha256'])
        parts.append(page['untrusted_device_output'])
    assert ''.join(parts) == expected and len(parts) > 1
    assert view['content_sha256'] == hashlib.sha256(expected.encode()).hexdigest()
    with pytest.raises(ValueError, match='filter changed'):
        _read(auth, snapshot_id=first['snapshot_id'], contains='vlan Servers', offset=view['next_offset'],
              limit=60, content_sha256=view['content_sha256'], filter_sha256=view['filter_sha256'])
    assert len(wire.calls) == 3


def test_proxy_reserves_three_reads_for_a_capture_and_none_for_a_cached_page(env):
    proxy, forwarded, emitted = _proxy(env, {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all',
                                             'include_all': True, 'redaction': 'full'})
    assert forwarded is not None and not emitted
    _, section, _ = proxy._target('device-a')
    assert proxy._rate_cost('config_read', None, section, {'platform': 'extreme_exos'}) == 3
    assert proxy._rate_cost('config_read', None, section,
                            {'platform': 'extreme_exos', 'snapshot_id': 'cfg_' + '0' * 32}) == 0
    assert proxy._rate_cost('config_read', None, section, {'platform': 'fortios'}) == 1
    _, cached, emitted = _proxy(env, {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all',
                                      'include_all': True, 'redaction': 'full', 'snapshot_id': 'cfg_' + '0' * 32,
                                      'offset': 10}, 2, proxy)
    assert cached is not None and not emitted
    _, again, emitted = _proxy(env, {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all',
                                     'include_all': True, 'redaction': 'full'}, 3, proxy)
    assert again is None and emitted[-1]['error']['data']['category'] == 'rate_limit'


# ---------------------------------------------------------------------- refusals before any transport

@pytest.mark.parametrize('arguments, field', [
    ({'redaction': 'minimal'}, 'redaction'),
    ({'redaction': None}, 'redaction'),
    ({'include_defaults': True}, 'include_defaults'),
    ({'section': 'vlan'}, 'section'),
    ({'section': 'vlan', 'include_all': True}, 'section'),
    ({'include_all': False}, 'include_all'),
    ({'section': 'all', 'include_all': 'true'}, 'include_all'),
])
def test_proxy_refuses_other_exos_options_before_transport(env, arguments, field):
    wire = _wire(env, Wire())
    base = {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all', 'include_all': True,
            'redaction': 'full'}
    if arguments.get('redaction', 'x') is None:
        del base['redaction']
        arguments = {}
    _, forwarded, emitted = _proxy(env, {**base, **arguments})
    assert forwarded is None and emitted[-1]['error']['data']['field'] == field
    assert wire.calls == []


@pytest.mark.parametrize('options', [
    {'redaction': 'minimal'}, {'include_defaults': True}, {'section': 'vlan', 'include_all': False},
    {'include_all': False}, {'section': 'firewall policy'},
])
def test_engine_refuses_other_exos_options_before_transport(env, options):
    auth = _auth(env)
    wire = _wire(env, Wire())
    with pytest.raises(ValueError, match='config_platform_not_supported'):
        _read(auth, **options)
    assert wire.calls == [] and not configuration._SNAPSHOTS


def _policy_refusal(env, change, arguments=None):
    document = json.loads(env['inventory'].read_text())
    change(document['devices'][0])
    _rewrite(env['inventory'], document)
    wire = _wire(env, Wire())
    request = {'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all', 'include_all': True,
               'redaction': 'full', **(arguments or {})}
    _, forwarded, emitted = _proxy(env, request)
    assert forwarded is None and wire.calls == []
    return emitted[-1]['error']['data']


def test_proxy_refuses_without_config_access(env):
    def change(device):
        device['helper']['read_inventory']['config_access'] = []
    assert _policy_refusal(env, change)['field'] == 'config_access'


def test_compare_only_access_is_refused_before_transport(env):
    # The inventory itself refuses compare without read; no request reaches the engine or SSH.
    def change(device):
        device['helper']['read_inventory']['config_access'] = ['compare']
    data = _policy_refusal(env, change)
    assert data.get('category') and data.get('field') != 'platform'


def test_proxy_refuses_port_outside_egress(env):
    def change(device):
        device['port'] = 2222
    assert _policy_refusal(env, change)['field'] == 'egress'


def test_proxy_refuses_platform_mismatch(env):
    assert _policy_refusal(env, lambda device: None, {'platform': 'fortios'})['field'] == 'platform'

    def forti(device):
        device['platform'] = 'fortios'
        device['helper'].update(ssh_platform='fortios', enabled_queries=['system_status'])
    assert _policy_refusal(env, forti)['field'] == 'platform'


@pytest.mark.parametrize('platform', ['exos', 'EXTREME_EXOS', 'extreme', 'cisco_ios'])
def test_proxy_admits_only_the_exact_exos_platform_name(env, platform):
    data = _policy_refusal(env, lambda device: None, {'platform': platform})
    assert data['field'] == 'platform'


def test_engine_refuses_wrong_target_platform_access_and_port(env):
    auth = _auth(env)
    wire = _wire(env, Wire())
    for changed, message in (
            (replace(auth, ssh_platform='fortinet'), 'outside target policy'),
            (replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('compare',)}), 'not enabled'),
    ):
        with pytest.raises(ValueError, match=message):
            _read(changed)
    # verification: config_diff is open for EXOS, but only with compare (next to read) in config_access.
    with pytest.raises(ValueError, match='not enabled'):
        engine.config_diff(auth, 'extreme_exos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    compare = replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(compare, 'extreme_exos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    with pytest.raises(ValueError, match='outside target policy'):
        engine.config_diff(replace(compare, ssh_platform='fortinet'), 'extreme_exos', 'cfg_' + '0' * 32,
                           'cfg_' + '1' * 32)
    with pytest.raises(Exception):
        _read(replace(auth, port=2222))
    assert wire.calls == []


def test_config_diff_requires_compare_for_exos_and_reads_no_device(env):
    # verification (was: config_diff stays refused): refused without compare, forwarded with read+compare.
    wire = _wire(env, Wire())
    diff = {'target': 'device-a', 'platform': 'extreme_exos', 'base_snapshot': 'cfg_' + '0' * 32,
            'other_snapshot': 'cfg_' + '1' * 32}
    proxy = proxy_module.Proxy()
    emitted = []
    env['monkeypatch'].setattr(proxy, '_emit', emitted.append)
    forwarded = proxy.request(_tool_call(5, 'config_diff', diff))
    assert forwarded is None and emitted[-1]['error']['data']['field'] == 'config_access'
    document = json.loads(env['inventory'].read_text())
    document['devices'][0]['helper']['read_inventory']['config_access'] = ['read', 'compare']
    _rewrite(env['inventory'], document)
    forwarded = proxy.request(_tool_call(6, 'config_diff', diff))
    assert forwarded is not None, emitted
    arguments = json.loads(forwarded)['params']['arguments']
    assert CALLER_SECRET in arguments['redaction_context']
    auth = TargetAuth.decode('device-a', arguments['auth_context'])
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(auth, 'extreme_exos', diff['base_snapshot'], diff['other_snapshot'])
    assert wire.calls == []


# ----------------------------------------------------------------- identity gates the configuration

def _identity_refusal(env, wire, message):
    auth = _auth(env)
    _wire(env, wire)
    with pytest.raises(ValueError, match=message) as raised:
        _read(auth)
    assert 'show configuration' not in wire.commands and not configuration._SNAPSHOTS
    assert len(wire.calls) <= 2
    _assert_no_sentinel(str(raised.value))
    return raised.value


SWITCH_OTHER_MODEL = SWITCH.replace('X440G2-12p-10G4', 'X440G2-24p-10G4')
# Keep the untested firmware version distinct from the tested version.
VERSION_OTHER = VERSION.replace('33.7.1.6', '33.7.' + '2.1')
SWITCH_OTHER = SWITCH.replace('33.7.1.6', '33.7.' + '2.1')
# Real read-only captures of the lab X435-8P-4S (one device, booted secondary 33.7.1.6 patch1-11).
X435 = FIXTURES / 'x435-8p-4s_33.7.1.6'


@pytest.mark.parametrize('wire, firmware', [
    (lambda: Wire(switch=SWITCH_OTHER_MODEL), ('X440G2-24p-10G4', '33.7.1.6', 'patch1-11')),
    (lambda: Wire(version=VERSION_OTHER, switch=SWITCH_OTHER), ('X440G2-12p-10G4', '33.7.' + '2.1', 'patch1-11')),
    (lambda: Wire(version=VERSION.replace('patch1-11', 'patch1-12'), switch=SWITCH.replace('patch1-11', 'patch1-12')),
     ('X440G2-12p-10G4', '33.7.1.6', 'patch1-12')),
    (lambda: Wire(version=(X435 / 'version.txt').read_text(), switch=(X435 / 'switch.txt').read_text()),
     ('X435-8P-4S', '33.7.1.6', 'patch1-11')),
], ids=['other-model', 'other-version', 'other-patch', 'real-x435'])
def test_untested_consistent_firmware_reads_with_a_warning(env, wire, firmware):
    """STARTUP: another model, image or patch is read with the same redaction and an untested warning."""
    auth = _auth(env)
    wire = _wire(env, wire())
    first = _read(auth, limit=200)
    assert wire.commands == ['show version', 'show switch', 'show configuration']
    assert first['ok'] is True and first['capture_complete'] is True and first['configuration_complete'] is False
    assert first['firmware'] == dict(zip(('model', 'version', 'build'), firmware))
    support = first['firmware_support']
    assert support == {
        'status': 'untested', 'platform': 'ExtremeXOS', 'device_version': firmware[1] + ' ' + firmware[2],
        'model': firmware[0], 'tested_versions': ['X440G2-12p-10G4 33.7.1.6 patch1-11', 'EXOS-VM 33.6.1.14'],
        'message': ('ExtremeXOS %s %s on %s is not among the versions config_read was tested on '
                    '(X440G2-12p-10G4 33.7.1.6 patch1-11, EXOS-VM 33.6.1.14). It may or may not work as designed and tested; '
                    'check the result.' % (firmware[1], firmware[2], firmware[0]))}
    assert first['warnings'] == [{'code': 'firmware_untested', 'message': support['message']}]
    # The redaction is the same consumer and profile as on the tested identity: unknown lines stay hidden.
    assert first['redaction_profile'] == adapter.PROFILE and first['redacted_count'] == 12
    assert {key: first[key] for key in SUMMARY} == SUMMARY
    pages, page = [first], first
    while page['next_offset'] is not None:
        page = _read(auth, snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=200)
        assert page['firmware_support'] == support and page['warnings'] == first['warnings']
        pages.append(page)
    assert ''.join(item['untrusted_device_output'] for item in pages) == EXPECTED
    assert len(wire.calls) == 3
    stored = configuration._SNAPSHOTS[first['snapshot_id']]
    assert stored.firmware == firmware
    _assert_no_sentinel(first, pages, repr(stored))


def test_untested_and_tested_snapshots_are_not_compared(env):
    """A firmware change between two captures stays a config_diff incomparable pair, as before STARTUP."""
    auth = _auth(env)
    _wire(env, Wire())
    tested = _read(auth)
    _wire(env, Wire(switch=SWITCH_OTHER_MODEL))
    untested = _read(auth)
    assert 'warnings' not in tested and untested['warnings'][0]['code'] == 'firmware_untested'
    with pytest.raises(ValueError, match='firmware or profile mismatch'):
        configuration.compare(auth, tested['snapshot_id'], untested['snapshot_id'], platform='extreme_exos')


@pytest.mark.parametrize('wire', [
    lambda: Wire(switch=SWITCH_OTHER),                                    # booted image contradicts show version
    lambda: Wire(switch=SWITCH.replace('patch1-11', 'patch1-12')),        # patch contradicts
    lambda: Wire(switch=SWITCH.replace('Image Booted:     primary', 'Image Booted:     secondary')),
    lambda: Wire(switch=SWITCH.replace('System Type:      X440G2-12p-10G4\n', '')),    # model unknown
    lambda: Wire(switch=SWITCH + 'System Type:      X440G2-12p-10G4\n'),   # repeated
    lambda: Wire(version=VERSION + VERSION),                              # repeated image
    lambda: Wire(version=VERSION.replace('IMG: 33.7.1.6', 'IMG: 33.6.1.14')),
    lambda: Wire(version=VERSION.replace('Image   : ExtremeXOS', 'Image   : SomethingOS')),
    lambda: Wire(version=VERSION.encode() + b'\xff\xfe'),                 # not UTF-8
    lambda: Wire(switch=SWITCH.replace('Boot Count', '\x1b[0mBoot Count')),
    lambda: Wire(version=VERSION + 'x' * 70000 + '\n'),                    # oversized identity
    lambda: Wire(version=''),
], ids=['booted-version', 'booted-patch', 'secondary-booted', 'no-model', 'two-models', 'two-images',
        'img-mismatch', 'not-exos', 'bad-utf8', 'control', 'oversized', 'empty'])
def test_inconclusive_or_contradictory_identity_never_reads_configuration(env, wire):
    _identity_refusal(env, wire(), 'identity-unverifiable')


@pytest.mark.parametrize('wire', [
    lambda: Wire(identity_rc={'show version': 1}),
    lambda: Wire(identity_rc={'show switch': 255}),
    lambda: Wire(version='This user does not have permissions for this command.\n'),
    lambda: Wire(switch=SWITCH + '%% Invalid input detected at "^" marker.\n'),
], ids=['version-rc', 'switch-rc', 'permission', 'invalid-input'])
def test_refused_identity_never_reads_configuration(env, wire):
    _identity_refusal(env, wire(), 'device-refused during identity read')


# --------------------------------------------------------------- capture failures store nothing

def _capture_failure(env, wire):
    auth = _auth(env)
    _wire(env, wire)
    try:
        result = _read(auth)
    except ValueError as exc:
        result = exc
    assert wire.commands == ['show version', 'show switch', 'show configuration']
    assert not configuration._SNAPSHOTS
    if isinstance(result, dict):
        assert result['ok'] is False and result['platform'] == 'extreme_exos'
        assert 'untrusted_device_output' not in result and 'snapshot_id' not in result
    _assert_no_sentinel(str(result), repr(result))
    return result


@pytest.mark.parametrize('wire, message', [
    (lambda: Wire(rc=1), 'device-refused during capture'),
    (lambda: Wire(stdout=b'unexpected accumulated SECRET-PEM-SENTINEL'), 'transport-contract-failed'),
    (lambda: Wire(config=CONFIG.encode() + b'Error: SECRET-PASSWORD-SENTINEL refused\n'), 'device-refused during capture'),
    (lambda: Wire(config=CONFIG.encode() + b'--More-- SECRET-BANNER-SENTINEL\n'), 'redaction-unverifiable'),
    (lambda: Wire(config=CONFIG.encode()[:100] + b'\xff\xfe' + CONFIG.encode()[100:]), 'redaction-unverifiable'),
    (lambda: Wire(config=CONFIG.encode() + b'\xe2\x82'), 'stream-incomplete'),
    (lambda: Wire(config=CONFIG.encode() + b'configure banner before-login "SECRET-BANNER-SENTINEL\n'),
     'stream-incomplete'),
    (lambda: Wire(config=CONFIG.encode() + b'create vlan ' + b'A' * 5000 + b'\n'), 'capture-limit-exceeded'),
    (lambda: Wire(config=b'# only a comment SECRET-PASSWORD-SENTINEL\n'), 'redaction-unverifiable'),
], ids=['rc', 'accumulated-raw', 'refusal', 'pager', 'bad-utf8', 'partial-utf8', 'partial-quote',
        'line-limit', 'nothing-verified'])
def test_capture_failure_withholds_and_stores_nothing(env, wire, message):
    result = _capture_failure(env, wire())
    assert isinstance(result, ValueError) and message in str(result)
    assert 'output withheld' in str(result)


@pytest.mark.parametrize('failure, code', [
    (core_ssh.SshError('ssh to 192.0.2.10 did not finish within 123.0 seconds'), 'timeout'),
    (core_ssh.SshError('ssh produced no bytes within its idle timeout'), 'timeout'),
])
def test_capture_timeout_is_a_transport_failure_for_exos(env, failure, code):
    result = _capture_failure(env, Wire(fail=failure))
    assert isinstance(result, dict) and result['error_code'] == code


def test_identity_transport_failure_reports_exos_not_fortios(env):
    auth = _auth(env)
    wire = Wire()

    def broken(*args, **kwargs):
        wire.calls.append({'command': args[5]})
        raise core_ssh.SshError('ssh to 192.0.2.10 failed: connection refused')
    _wire(env, broken)
    result = _read(auth)
    assert result['ok'] is False and result['platform'] == 'extreme_exos'
    assert result['error_code'] == 'connection_refused'
    assert wire.commands == ['show version'] and not configuration._SNAPSHOTS


# -------------------------------------------------------- snapshot scope, credential and profile

def test_cached_snapshot_refuses_other_target_credential_profile_and_platform(env):
    auth = _auth(env)
    wire = _wire(env, Wire())
    first = _read(auth)
    identity = first['snapshot_id']
    assert len(wire.calls) == 3
    for other in (replace(auth, secret='another-secret'), replace(auth, alias='device-b'),
                  replace(auth, host_key_fingerprint='SHA256:' + 'C' * 43),
                  replace(auth, login='someone-else')):
        with pytest.raises(ValueError, match='scope mismatch'):
            _read(other, snapshot_id=identity, offset=1)
    forti = replace(auth, ssh_platform='fortinet', fortios_output_standard_verified=True)
    with pytest.raises(ValueError):
        engine.config_read(forti, 'fortios', 'all', True, identity, 0, 48000, 'full')
    stored = configuration._SNAPSHOTS[identity]
    configuration._SNAPSHOTS[identity] = replace(stored, profile='extreme_exos-full-1:' + '0' * 64)
    with pytest.raises(ValueError, match='policy mismatch'):
        _read(auth, snapshot_id=identity)
    # STARTUP: a stored untested identity pages with its warning; a record of another shape is refused.
    configuration._SNAPSHOTS[identity] = replace(stored, firmware=('X440G2-24p-10G4', '33.7.1.6', 'patch1-11'))
    page = _read(auth, snapshot_id=identity)
    assert page['firmware_support']['status'] == 'untested' and page['firmware_support']['model'] == 'X440G2-24p-10G4'
    assert page['warnings'][0]['code'] == 'firmware_untested'
    for record in (('X440G2-12p-10G4', '33.7.1.6'), ('X440G2-12p-10G4', '33.7.1.6', None),
                   ['X440G2-12p-10G4', '33.7.1.6', 'patch1-11'], ('', '33.7.1.6', 'patch1-11')):
        configuration._SNAPSHOTS[identity] = replace(stored, firmware=record)
        with pytest.raises(ValueError, match='policy mismatch'):
            _read(auth, snapshot_id=identity)
    configuration._SNAPSHOTS[identity] = stored
    with pytest.raises(ValueError, match='capture options mismatch|not_supported'):
        _read(auth, snapshot_id=identity, include_defaults=True)
    assert _read(auth, snapshot_id=identity)['snapshot_sha256'] == first['snapshot_sha256']
    # Other limits isolate too: the capture scope of the same target drops the old snapshot.
    other_limits = replace(auth, configuration_limits=replace(auth.configuration_limits, idle_seconds=16))
    with pytest.raises(ValueError, match='scope mismatch|not found or expired'):
        _read(other_limits, snapshot_id=identity, offset=1)
    with pytest.raises(ValueError, match='not found or expired'):
        _read(auth, snapshot_id=identity)
    assert len(wire.calls) == 3


# ------------------------------------------------- directly touched Forti/ADC guards stay unchanged

def test_touched_forti_and_adc_guards_are_unchanged(env):
    auth = _auth(env)
    forti = replace(auth, ssh_platform='fortinet',
                    read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})
    adc = replace(auth, ssh_platform='fortiadc')
    configuration.require(forti, 'fortios', 'read')
    configuration.require(forti, 'fortinet', 'compare')
    configuration.require(adc, 'fortiadc', 'read')
    with pytest.raises(ValueError, match='outside target policy'):
        configuration.require(auth, 'fortios', 'read')
    with pytest.raises(ValueError, match='outside target policy'):
        configuration.require(forti, 'extreme_exos', 'read')
    with pytest.raises(ValueError, match='not enabled'):
        configuration.require(auth, 'extreme_exos', 'compare')   # verification: open, but only with compare
    configuration.require(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')}),
                          'extreme_exos', 'compare')
    with pytest.raises(ValueError, match='config_platform_not_supported'):
        configuration.require(auth, 'extreme_exos', 'write')
    with pytest.raises(ValueError, match='config_platform_not_supported'):
        configuration.require(auth, 'cisco_ios', 'read')
    assert configuration.scope(forti, 'fortios')[1] == 'fortios'
    assert configuration.scope(adc, 'fortiadc')[1] == 'fortiadc'
    assert configuration.scope(auth, 'extreme_exos')[1] == 'extreme_exos'
    for who, platform in ((forti, 'extreme_exos'), (auth, 'fortios'), (auth, 'cisco_ios')):
        with pytest.raises(ValueError, match='outside target policy'):
            configuration.scope(who, platform)
    digest = '0' * 64
    configuration._snapshot_profile(configuration.PROFILE, 'fortios')
    configuration._snapshot_profile('fortios-full-2:' + digest, 'fortios')
    configuration._snapshot_profile('fortiadc-full-2:' + digest, 'fortiadc')
    configuration._snapshot_profile(adapter.PROFILE, 'extreme_exos')
    for profile, platform in ((adapter.PROFILE, 'fortios'), (adapter.PROFILE, 'fortiadc'),
                              (configuration.PROFILE, 'extreme_exos'), ('fortios-full-2:' + digest, 'extreme_exos'),
                              ('extreme_exos-full-2:' + digest, 'extreme_exos'), (adapter.PROFILE, 'cisco_ios')):
        with pytest.raises(ValueError, match='invalid configuration profile'):
            configuration._snapshot_profile(profile, platform)
    with pytest.raises(ValueError, match='streaming is supported only'):
        engine.read_from_device(replace(auth, ssh_platform='cisco_ios'), 'cisco_ios', 'show running-config',
                                stdout_consumer=lambda data: None)


def test_forti_minimal_request_shape_is_still_validated_by_proxy(env):
    def forti(device):
        device['platform'] = 'fortios'
        device['helper'].update(ssh_platform='fortios', enabled_queries=['system_status'],
                                fortios_output_standard_verified=True)
    document = json.loads(env['inventory'].read_text())
    forti(document['devices'][0])
    _rewrite(env['inventory'], document)
    _, forwarded, emitted = _proxy(env, {'target': 'device-a', 'platform': 'fortios', 'section': 'all',
                                         'include_all': True})
    assert forwarded is not None and not emitted
    _, forwarded, emitted = _proxy(env, {'target': 'device-a', 'platform': 'fortiadc', 'section': 'all',
                                         'include_all': True, 'redaction': 'minimal'})
    assert forwarded is None and emitted[-1]['error']['data']['field'] == 'redaction'


# ------------------------------------------------- image without a patch (verification, EXOS-VM 33.6.1.14)
# Real anonymised captures of the GNS3 EXOS-VM; re-read live on 2026-11-17 with the same Image line and the
# same show switch layout (no patch line after "Primary ver").
EXOSVM_VERSION = (FIXTURES / 'exosvm_33.6.1.14' / 'version.txt').read_text()
EXOSVM_SWITCH = (FIXTURES / 'exosvm_33.6.1.14' / 'switch.txt').read_text()


def test_real_image_without_patch_is_read_conclusively():
    from netops_helper import config_exos_adapter as adapter
    assert adapter.version_identity(EXOSVM_VERSION) == ('33.6.1.14', '')
    assert adapter.switch_identity(EXOSVM_SWITCH) == ('EXOS-VM', '33.6.1.14', '')
    # the patched image of the lab X440 keeps its build
    assert adapter.version_identity(VERSION) == ('33.7.1.6', 'patch1-11')
    assert adapter.switch_identity(SWITCH) == ('X440G2-12p-10G4', '33.7.1.6', 'patch1-11')


def test_real_image_without_patch_is_a_consistent_identity_not_unverifiable(env):
    auth = _auth(env)
    wire = _wire(env, Wire(version=EXOSVM_VERSION, switch=EXOSVM_SWITCH))
    first = _read(auth, limit=200)
    assert first['ok'] is True and first['capture_complete'] is True
    assert first['firmware'] == {'model': 'EXOS-VM', 'version': '33.6.1.14', 'build': ''}
    assert 'firmware_support' not in first and 'warnings' not in first
    pages, page = [first], first
    while page['next_offset'] is not None:
        page = _read(auth, snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=200)
        assert 'firmware_support' not in page and 'warnings' not in page
        pages.append(page)
    assert ''.join(item['untrusted_device_output'] for item in pages) == EXPECTED
    assert wire.commands == ['show version', 'show switch', 'show configuration']
    assert configuration._SNAPSHOTS[first['snapshot_id']].firmware == ('EXOS-VM', '33.6.1.14', '')
    _assert_no_sentinel(first, pages)



@pytest.mark.parametrize('wire', [
    lambda: Wire(version=EXOSVM_VERSION, switch=SWITCH),                       # no patch vs patched booted image
    lambda: Wire(version=VERSION, switch=SWITCH.replace('                  patch1-11\n', '')),  # patch vs none
    lambda: Wire(version=EXOSVM_VERSION, switch=EXOSVM_SWITCH.replace(
        'Primary ver:      33.6.1.14               \n',
        'Primary ver:      33.6.1.14               \n                  something-else\n')),
    lambda: Wire(version=EXOSVM_VERSION.replace('33.6.1.14 by', '33.6.1.14 33.6.1.14 by'), switch=EXOSVM_SWITCH),
    lambda: Wire(version=EXOSVM_VERSION.replace(' by release-manager', ''), switch=EXOSVM_SWITCH),
], ids=['nopatch-vs-patch', 'patch-vs-nopatch', 'indented-non-patch', 'bare-release', 'no-by'])
def test_image_without_patch_stays_strict(env, wire):
    _identity_refusal(env, wire(), 'identity-unverifiable')
