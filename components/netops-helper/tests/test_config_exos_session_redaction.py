"""Task 87 (review 84-N1): EXOS config_read honours the whole Proxy session before store and hash.

One Proxy session first serves an allowed read on target A whose valid vault password is ``Users``;
the Proxy keeps it as a session secret.  Target B is an ExtremeXOS switch with another password whose
safe configuration holds ``create vlan Users``.  The engine has to redact with the same session
secrets the Proxy and the worker apply to the final reply; otherwise the stored text, its hash and
the sizes describe text that the final redaction then changes, and the worker withholds the page as
``page_changed_by_redaction``.

The calls run through the real root ``netops.worker.HelperBridge.call`` -> ``Proxy.request`` ->
FastMCP ``server.mcp.call_tool`` -> ``server.config_read`` (``_paged_auth``) -> ``engine.config_read``
-> ``read_from_device`` -> ``_exec_read`` -> ``Proxy.response`` -> the worker's final redaction and
page-change guard, in process.  Only the physical SSH exec backend (``core_ssh.run_command``) and the
physical host-key scan are replaced; ``_paged_auth`` is only observed (it calls the real function).

Identity texts are the real anonymized captures also used by ``test_config_exos_public.py``
(``dom_33.7.1.6_20261114/sample_a-version.txt`` and ``x440g2-12p-10g4_33.7.1.6/switch.txt``); served
together they are a derived coherent scenario of two separate captures, not a live measurement.
The configuration is synthetic.
"""

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from netops import worker
from netops.files import write_private
from netops_core import ssh as core_ssh
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, config_exos, configuration, engine, server
from netops_helper import proxy as proxy_module
from test_proxy import DEVICE_PIN, _section

FIXTURES = Path(__file__).parent / 'fixtures' / 'real' / 'exos'
VERSION = (FIXTURES / 'dom_33.7.1.6_20261114' / 'sample_a-version.txt').read_text()
SWITCH = (FIXTURES / 'x440g2-12p-10g4_33.7.1.6' / 'switch.txt').read_text()
HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask87Only'
ADDRESS = {'switch-a': '192.0.2.10', 'switch-b': '192.0.2.20', 'fw-c': '192.0.2.30'}
A_SECRET = 'Users'               # valid alphanumeric password of A, also a safe VLAN name on B
A_NEW_SECRET = 'Servers'         # A's next password, registered only after B's snapshot exists
B_SECRET = 'b-switch-password-only'
M = config_exos.MARKER
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
SENTINELS = ('SECRET-COMMUNITY-SENTINEL', 'SECRET-PASSWORD-SENTINEL', B_SECRET)

CONFIG_LINES = (
    '#',
    'create vlan Users',
    'create vlan Servers tag 20',
    'configure vlan Users tag 10',
    'configure vlan Servers add ports 5,6 tagged',
    'enable ports 1',
    'configure ports 1 auto off speed 1000 duplex full',
    'configure snmpv3 add community "SECRET-COMMUNITY-SENTINEL" name "SECRET-COMMUNITY-SENTINEL" user v1v2c_ro',
    'create account admin reader "SECRET-PASSWORD-SENTINEL"',
    'disable ports 12',
)
CONFIG = ''.join(line + '\n' for line in CONFIG_LINES)
VERIFIED = ('create vlan Users', 'create vlan Servers tag 20', 'configure vlan Users tag 10',
            'configure vlan Servers add ports 5,6 tagged', 'enable ports 1',
            'configure ports 1 auto off speed 1000 duplex full', 'disable ports 12')


def expected(*secrets):
    """The consumer-safe text: verified sentences kept unless they hold a session secret, all else masked."""
    return ''.join((line if line in VERIFIED and not any(secret in line for secret in secrets) else M) + '\n'
                   for line in CONFIG_LINES)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Wire:
    """Stands in for core_ssh.run_command, the physical SSH exec backend; records every call per host."""

    def __init__(self):
        self.calls = []

    def __call__(self, host, port, login, credential, host_key_line, command, *, legacy_ssh=None,
                 timeout_seconds=None, capture_max_bytes=None, stdout_consumer=None,
                 idle_timeout_seconds=None, run=None, now=None):
        self.calls.append((host, command, stdout_consumer is not None))
        if stdout_consumer is None:
            text = {'show version': VERSION, 'show switch': SWITCH}[command]
            return core_ssh.Result(rc=0, stdout=text.encode(), said='', started_at='t0', finished_at='t1')
        assert command == 'show configuration' and host == ADDRESS['switch-b']
        data = CONFIG.encode()
        for start in range(0, len(data), 7):
            try:
                stdout_consumer(data[start:start + 7])
            except core_ssh.OutputLimitError:
                raise
            except Exception:
                raise core_ssh.OutputConsumerError() from None
        return core_ssh.Result(rc=0, stdout=b'', said='', started_at='t0', finished_at='t1')

    def commands(self, alias):
        return [command for host, command, _ in self.calls if host == ADDRESS[alias]]


def _exos_section(alias):
    section = _section()
    section.pop('snmp_credential')
    section['egress']['addresses'] = [ADDRESS[alias]]
    section.update(ssh_platform='exos', enabled_queries=['version', 'switch'],
                   fortios_output_standard_verified=False, configuration_limits=dict(LIMITS),
                   rate_limit={'requests': 30, 'window_seconds': 60})
    section['read_inventory'] = {'interfaces': [], 'services': [], 'addresses': [], 'config_access': ['read']}
    return section


def _device(alias, platform, section):
    return {'name': alias, 'platform': platform, 'address': ADDRESS[alias], 'port': 22, 'role': 'internal',
            'credential': alias + '-account', 'host_key_fingerprint': DEVICE_PIN, 'legacy_ssh': None,
            'auditor': None, 'helper': section}


def _vault(helper, a_secret, replace=False):
    write_private(helper / 'vault.json', json.dumps({'version': 2, 'credentials': {
        'switch-a-account': {'kind': 'password', 'login': 'a-user', 'value': a_secret},
        'switch-b-account': {'kind': 'password', 'login': 'b-user', 'value': B_SECRET},
        'fw-c-account': {'kind': 'password', 'login': 'c-user', 'value': 'fw-c-password-only'},
    }}).encode(), replace=replace)


@pytest.fixture
def env(tmp_path, monkeypatch):
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    state = tmp_path / 'state'
    helper = state / 'helper'
    helper.mkdir(parents=True, mode=0o700)
    forti = _section()
    forti.pop('snmp_credential')
    forti['egress']['addresses'] = [ADDRESS['fw-c']]
    forti['read_inventory'] = {'interfaces': ['port1'], 'services': [], 'addresses': [], 'config_access': ['read']}
    forti['rate_limit'] = {'requests': 30, 'window_seconds': 60}
    inventory = helper / 'inventory.json'
    write_private(inventory, json.dumps({'version': 2, 'devices': [
        _device('switch-a', 'exos', _exos_section('switch-a')),
        _device('switch-b', 'exos', _exos_section('switch-b')),
        _device('fw-c', 'fortios', forti),
    ]}).encode())
    _vault(helper, A_SECRET)
    monkeypatch.setattr(worker, 'STATE', state)
    monkeypatch.setattr(proxy_module, 'INVENTORY', inventory)
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(helper / 'operations.jsonl', 'helper'))
    monkeypatch.setattr(engine.core_hostkey, 'scan',
                        lambda address, port, pin, timeout, legacy=None: address + ' ' + HOST_KEY)
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
    yield {'bridge': bridge, 'wire': wire, 'helper': helper, 'paged': paged}
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _call(env, name, arguments):
    return asyncio.run(env['bridge'].call(server.mcp, name, dict(arguments)))


def _b(**options):
    return {'target': 'switch-b', 'platform': 'extreme_exos', 'section': 'all', 'include_all': True,
            'redaction': 'full', **options}


def _register_a(env):
    """An allowed ordinary read on A: the Proxy registers A's credential as a session secret."""
    result = _call(env, 'ssh_read', {'target': 'switch-a', 'platform': 'extreme_exos', 'query': 'version'})
    assert result['isError'] is False and result['structuredContent']['ok'] is True, result
    assert 'show version' in env['wire'].commands('switch-a')
    return result


def _assert_clean(result, *secrets):
    shown = json.dumps(result) + str(result) + repr(result)
    for value in (*secrets, *SENTINELS):
        assert value not in shown
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
    """Every continuation page of `first` through the bridge; the joined client view."""
    pages, data = [first], first
    while data['next_offset'] is not None:
        data = _page(_call(env, 'config_read', {**arguments, 'snapshot_id': first['snapshot_id'],
                                                'offset': data['next_offset'], 'limit': limit,
                                                'content_sha256': first['content_sha256'],
                                                **({'filter_sha256': first['filter_sha256']}
                                                   if 'filter_sha256' in first else {})}))
        pages.append(data)
    return pages, ''.join(page['untrusted_device_output'] for page in pages)


# --------------------------------------------------------------------------------------- control

def test_b_alone_passes_the_whole_bridge(env):
    """Control: without A's session secret the same B read already succeeds through the bridge."""
    result = _call(env, 'config_read', _b(limit=48000))
    data = _page(result)
    _assert_clean(result)
    assert data['untrusted_device_output'] == expected()
    assert data['content_sha256'] == data['snapshot_sha256'] == sha(expected())
    assert env['wire'].commands('switch-b') == ['show version', 'show switch', 'show configuration']


# --------------------------------------------------------------------------------- 84-N1 repro

def test_session_secret_of_a_is_redacted_before_b_is_stored_and_hashed(env):
    _register_a(env)
    proxy = env['bridge'].proxy
    assert A_SECRET in proxy.session_secrets
    first = _call(env, 'config_read', _b(limit=60))
    data = _page(first)                      # 84-N1: page_changed_by_redaction before the fix
    _assert_clean(first, A_SECRET)
    safe = expected(A_SECRET)
    assert any(line in safe for line in ('enable ports 1\n', 'disable ports 12\n'))
    assert data['capture_complete'] is True and data['configuration_complete'] is False
    assert data['firmware'] == {'model': 'X440G2-12p-10G4', 'version': '33.7.1.6', 'build': 'patch1-11'}
    # Fresh B capture: exactly three SSH exec requests (two identity reads and the streamed capture).
    assert env['wire'].commands('switch-b') == ['show version', 'show switch', 'show configuration']
    # The real server wrapper derived the private handoff: B's auth holds A's session secret.
    assert [target for target, _ in env['paged']].count('switch-b') == 1
    assert any(target == 'switch-b' and A_SECRET in secrets for target, secrets in env['paged'])

    pages, text = _pages(env, data, _b(), 60)
    assert len(pages) > 2 and text == safe
    assert env['wire'].commands('switch-b') == ['show version', 'show switch', 'show configuration']
    for page in pages:
        # content_sha256 / total_bytes describe the whole client view, snapshot_sha256 the whole capture.
        assert page['content_sha256'] == page['snapshot_sha256'] == sha(text)
        assert page['total_bytes'] == len(text.encode())
    stored = configuration._SNAPSHOTS[data['snapshot_id']].text
    assert stored.page(0, stored.total)[0] == text and stored.sha256 == sha(text)

    # Filter over the cached snapshot in the same session: no SSH, hashes describe the filtered view.
    view = _page(_call(env, 'config_read', _b(snapshot_id=data['snapshot_id'], contains='ports', limit=1000)))
    filtered = ''.join(line + '\n' for line in safe.splitlines() if 'ports' in line)
    assert view['untrusted_device_output'] == filtered
    assert view['content_sha256'] == sha(filtered) and view['snapshot_sha256'] == sha(text)
    assert view['matched_lines'] == filtered.count('\n')
    small = _page(_call(env, 'config_read', _b(snapshot_id=data['snapshot_id'], contains='ports', limit=60)))
    filtered_pages, joined = _pages(env, small, _b(contains='ports'), 60)
    assert len(filtered_pages) > 1 and joined == filtered
    assert all(page['content_sha256'] == sha(filtered) and page['filter_sha256'] == small['filter_sha256']
               for page in filtered_pages)
    assert env['wire'].commands('switch-b') == ['show version', 'show switch', 'show configuration']
    for page in (*pages, view, *filtered_pages):
        assert A_SECRET not in json.dumps(page)


# ------------------------------------------------- a new session secret before a cached continuation

def test_a_new_session_secret_refuses_old_cached_pages_and_a_fresh_read_is_consistent(env):
    _register_a(env)
    first = _page(_call(env, 'config_read', _b(limit=60)))
    view = _page(_call(env, 'config_read', _b(snapshot_id=first['snapshot_id'], contains='vlan', limit=50)))
    stored = configuration._SNAPSHOTS[first['snapshot_id']].text
    assert 'Servers' in stored.page(0, stored.total)[0] and 'Servers' in view['untrusted_device_output']
    assert first['next_offset'] is not None and view['next_offset'] is not None

    # A's password changes; the next allowed read on A registers it in the same session.
    _vault(env['helper'], A_NEW_SECRET, replace=True)
    _register_a(env)
    assert A_NEW_SECRET in env['bridge'].proxy.session_secrets
    ssh_before = list(env['wire'].calls)
    continuations = (
        _b(snapshot_id=first['snapshot_id'], offset=first['next_offset'], limit=60,
           content_sha256=first['content_sha256']),
        _b(snapshot_id=first['snapshot_id'], offset=0, limit=60),
        _b(snapshot_id=first['snapshot_id'], contains='vlan', offset=view['next_offset'], limit=50,
           content_sha256=view['content_sha256'], filter_sha256=view['filter_sha256']),
        _b(snapshot_id=first['snapshot_id'], contains='vlan', offset=0, limit=50),
    )
    for arguments in continuations:
        result = _call(env, 'config_read', arguments)
        _assert_clean(result, A_NEW_SECRET)
        refused = result['structuredContent']
        assert result['isError'] is True and refused['ok'] is False, result
        assert refused['error_code'] == 'config_snapshot_redaction_changed' and refused['restart_offset'] == 0
        assert 'untrusted_device_output' not in refused and 'content_sha256' not in refused
    assert env['wire'].calls == ssh_before          # never silently re-read over SSH

    fresh = _page(_call(env, 'config_read', _b(limit=48000)))
    _assert_clean(fresh, A_SECRET, A_NEW_SECRET)
    text = expected(A_SECRET, A_NEW_SECRET)
    assert fresh['untrusted_device_output'] == text and 'enable ports 1\n' in text
    assert fresh['content_sha256'] == fresh['snapshot_sha256'] == sha(text)
    assert fresh['total_bytes'] == len(text.encode()) and fresh['next_offset'] is None
    assert env['wire'].commands('switch-b') == ['show version', 'show switch', 'show configuration'] * 2


# ------------------------------------------------------------ private handoff and untouched paths

def test_the_private_handoff_is_neither_published_nor_accepted_from_a_client(env):
    descriptors = asyncio.run(env['bridge'].tools(server.mcp))
    schemas = {item['name']: item['inputSchema'] for item in descriptors}
    for name in ('config_read', 'ssh_read', 'config_diff'):
        assert 'redaction_context' not in schemas[name].get('properties', {})
        assert 'auth_context' not in schemas[name].get('properties', {})
        assert 'redaction_context' not in schemas[name].get('required', [])
    injected = _call(env, 'config_read', _b(redaction_context=['spoofed-value']))
    assert injected['isError'] is True and 'spoofed-value' not in json.dumps(injected)
    assert env['wire'].calls == [] and env['paged'] == []


def test_config_reads_and_diffs_receive_the_private_session_handoff(env):
    proxy = env['bridge'].proxy

    def forwarded(request_id, name, arguments):
        message = {'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
                   'params': {'name': name, 'arguments': arguments}}
        raw = proxy.request(json.dumps(message).encode())
        assert raw is not None, proxy.emitted
        return json.loads(raw)['params']['arguments']

    exos = forwarded(1, 'config_read', _b())
    assert B_SECRET in exos['redaction_context'] and exos['auth_context'] in exos['redaction_context']
    forti = forwarded(2, 'config_read', {'target': 'fw-c', 'platform': 'fortios', 'section': 'all',
                                              'include_all': True})
    assert {'fw-c-password-only', B_SECRET, forti['auth_context']} <= set(forti['redaction_context'])
    assert 'redaction_context' in forwarded(3, 'ssh_read', {'target': 'switch-a', 'platform': 'extreme_exos',
                                                             'query': 'version'})
    # Comparisons must check the same secrets before returning stored configuration.
    inventory = env['helper'] / 'inventory.json'
    document = json.loads(inventory.read_text())
    for device in document['devices']:
        if device['name'] in ('switch-b', 'fw-c'):
            device['helper']['read_inventory']['config_access'] = ['read', 'compare']
    write_private(inventory, json.dumps(document).encode(), replace=True)
    diff = forwarded(4, 'config_diff', {'target': 'switch-b', 'platform': 'extreme_exos',
                                        'base_snapshot': 'cfg_' + '0' * 32, 'other_snapshot': 'cfg_' + '1' * 32})
    assert B_SECRET in diff['redaction_context'] and diff['auth_context'] in diff['redaction_context']
    forti_diff = forwarded(5, 'config_diff', {
        'target': 'fw-c', 'platform': 'fortios', 'base_snapshot': 'cfg_' + '0' * 32,
        'other_snapshot': 'cfg_' + '1' * 32})
    assert {'fw-c-password-only', B_SECRET, forti_diff['auth_context']} <= set(forti_diff['redaction_context'])
    assert env['wire'].calls == []
