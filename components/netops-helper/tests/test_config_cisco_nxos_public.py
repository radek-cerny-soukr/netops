"""verification: the public config_read path for the Cisco NX-OS profile (STARTUP: other identities read with a warning).

``cisco_nxos`` / ``cisco Nexus9000 C9300v Chassis`` with ``NXOS: version 9.3(12)`` is the tested identity
(``config_cisco_nxos_adapter``), the same pattern as the cisco_xe path (verification), the arista_eos path
(tasks 143/153) and the accepted ``cisco_ios`` path (verification).  The capture goes through the
indentation-based ``config_indented.NxosStreamRedactor`` (verification).
The positive reads run through the real root ``netops.worker.HelperBridge.call`` -> ``Proxy.request`` ->
FastMCP ``server.config_read`` (``_paged_auth``) -> ``TargetAuth.decode`` -> ``engine.config_read`` ->
``read_from_device`` -> ``_exec_read`` -> the real unchanged ``config_indented.NxosStreamRedactor`` /
``configuration.store`` / page -> ``Proxy.response`` -> the worker's final redaction and page-change guard,
in process.  Refusals use the same real ``Proxy.request`` and, for engine checks, the auth context it
produced.  Only the physical SSH exec backend (``core_ssh.run_command``), the physical host-key scan and
the audit file location are replaced; the fake feeds real byte chunks into the consumer callback.

Identity: ``show version`` is the immutable REAL capture
``fixtures/real/cisco_nxos/nexus9300v_9.3.12/version.txt``; the foreign-vendor cases use the REAL
``fixtures/real/cisco_xe/iolxe_17.18.2/version.txt`` and ``fixtures/real/arista_eos/ceos_4.36.1F/version.txt``.
Other identity texts are DERIVED by editing those captures.  Every ``show running-config`` text below is
SYNTHETIC: the NX-OS configuration of ``tests/test_config_indented.py`` (verification gate + verification rows,
Cisco Nexus 9000 NX-OS 9.3(x) configuration guides) with its secrets replaced by sentinels and a few added
rows (banner, caller credential), not a live capture.  Nothing here measures account rights, the
full-config format or any hardware/firmware.
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
from netops_helper import config_cisco_nxos_adapter as adapter, config_cisco_ios_adapter, config_exos_adapter
from netops_helper import config_arista_eos_adapter, config_cisco_xe_adapter
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from netops_helper.config_indented import NXOS_MARKER, NxosStreamRedactor
from test_proxy import DEVICE_PIN, _section

REAL = Path(__file__).parent / 'fixtures' / 'real'
VERSION = (REAL / 'cisco_nxos' / 'nexus9300v_9.3.12' / 'version.txt').read_text()
VERSION_XE = (REAL / 'cisco_xe' / 'iolxe_17.18.2' / 'version.txt').read_text()
VERSION_EOS = (REAL / 'arista_eos' / 'ceos_4.36.1F' / 'version.txt').read_text()
HEADER = 'Cisco Nexus Operating System (NX-OS) Software'
RELEASE = ' NXOS: version 9.3(12)'
CHASSIS = '  cisco Nexus9000 C9300v Chassis '
FIRMWARE = ('Nexus9000 C9300v', '9.3(12)')
HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask153Only'
ADDRESS = {'router-a': '192.0.2.10', 'router-b': '192.0.2.20', 'fw-c': '192.0.2.30', 'xe-d': '192.0.2.40'}
A_SECRET = 'Ethernet1/2'         # valid password of A; also a safe interface name on B
A_NEW_SECRET = 'Ethernet1/3'     # A's next password, registered only after B's snapshot exists
B_SECRET = 'b-nexus-sesame-only'
M = NXOS_MARKER
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
SENTINELS = ('SECRET-PASSWORD-SENTINEL', 'SECRET-SNMP-SENTINEL', 'SECRET-TACACS-SENTINEL', 'SECRET-COMMUNITY-SENTINEL',
             'SECRET-OSPF-SENTINEL', 'SECRET-MD5-SENTINEL', 'SECRET-CHAIN-SENTINEL', 'SECRET-BGP-SENTINEL',
             'SECRET-BANNER-SENTINEL', B_SECRET)
IDENTITY_TEXT = ('0SSSSS0001S', 'Processor Board ID', 'host01', 'nxos.9.3.12.bin', 'Kernel uptime', 'bootflash')

# SYNTHETIC NX-OS running-config (not a live capture).  'k' kept unless it (or its block header) holds a
# forbidden value, 'h' one hidden record, 'c' a further hidden physical line of the same record.
ROWS = (
    ('k', ''),
    ('k', '!Command: show running-config'),
    ('h', '!Running configuration last done at: Sat Nov 14 09:12:44 2026'),
    ('h', '!Time: Sat Nov 14 10:05:31 2026'),
    ('k', ''),
    ('h', 'version 9.3(12) Bios:version'),
    ('k', 'hostname lab-n9k1'),
    ('h', 'vdc lab-n9k1 id 1'),
    ('h', '  limit-resource vlan minimum 16 maximum 4094'),
    ('h', '  limit-resource vrf minimum 2 maximum 4096'),
    ('k', ''),
    ('k', 'feature tacacs+'),
    ('k', 'feature ospf'),
    ('k', 'feature bgp'),
    ('k', 'feature interface-vlan'),
    ('k', ''),
    ('h', 'username admin password 5 $5$salt$SECRET-PASSWORD-SENTINEL  role network-admin'),
    ('h', 'ip domain-lookup'),
    ('h', 'tacacs-server key 7 "SECRET-TACACS-SENTINEL"'),
    ('h', 'tacacs-server host 192.0.2.10'),
    ('h', 'aaa group server tacacs+ TACACS'),
    ('h', '    server 192.0.2.10'),
    ('h', 'snmp-server user admin network-admin auth md5 0xSECRET-SNMP-SENTINEL priv 0xSECRET-SNMP-SENTINEL'
          ' localizedkey'),
    ('h', 'snmp-server community SECRET-COMMUNITY-SENTINEL group network-operator'),
    ('h', 'banner motd #'),
    ('c', 'SECRET-BANNER-SENTINEL'),
    ('c', '#'),
    ('k', ''),
    ('k', 'vlan 1,10,20'),
    ('k', 'vlan 10'),
    ('k', '  name USERS'),
    ('k', 'vlan 20'),
    ('k', '  name SERVERS'),
    ('k', ''),
    ('h', 'key chain OSPF-KEYS'),
    ('h', '  key 1'),
    ('h', '    key-string 7 SECRET-CHAIN-SENTINEL'),
    ('k', 'vrf context management'),
    ('k', '  ip route 0.0.0.0/0 192.0.2.1'),
    ('k', ''),
    ('k', 'interface Vlan10'),
    ('k', '  no shutdown'),
    ('k', '  ip address 203.0.113.1/24'),
    ('h', '  ip router ospf 1 area 0.0.0.0'),
    ('k', ''),
    ('k', 'interface Ethernet1/1'),
    ('k', '  description uplink-core'),
    ('k', '  description circuit ' + B_SECRET),
    ('k', '  no switchport'),
    ('k', '  ip address 198.51.100.1/30'),
    ('h', '  ip ospf authentication-key 3 SECRET-OSPF-SENTINEL'),
    ('h', '  ip ospf message-digest-key 1 md5 3 SECRET-MD5-SENTINEL'),
    ('h', '  ip router ospf 1 area 0.0.0.0'),
    ('k', '  no shutdown'),
    ('k', ''),
    ('k', 'interface Ethernet1/2'),
    ('k', '  switchport access vlan 10'),
    ('k', ''),
    ('k', 'interface Ethernet1/3'),
    ('k', '  switchport mode trunk'),
    ('k', '  switchport trunk allowed vlan 10,20'),
    ('k', ''),
    ('k', 'interface mgmt0'),
    ('k', '  vrf member management'),
    ('k', '  ip address 192.0.2.5/24'),
    ('h', 'line console'),
    ('h', 'line vty'),
    ('h', 'boot nxos bootflash:/nxos.9.3.12.bin'),
    ('k', 'router ospf 1'),
    ('k', '  router-id 192.0.2.254'),
    ('k', ''),
    ('k', 'spanning-tree mode mst'),
    ('k', 'ip route 198.51.100.0/24 192.0.2.1'),
    ('k', 'router bgp 65000'),
    ('k', '  router-id 192.0.2.254'),
    ('k', '  address-family ipv4 unicast'),
    ('k', '    network 203.0.113.0/24'),
    ('h', '    maximum-paths 4'),
    ('k', '  neighbor 198.51.100.2'),
    ('k', '    remote-as 65001'),
    ('h', '    password 3 SECRET-BGP-SENTINEL'),
    ('h', '    address-family ipv4 unicast'),
    ('h', '      send-community'),
)
CONFIG = ''.join(text + '\n' for _, text in ROWS)
# Readable statements of the SYNTHETIC configuration (verification goal): verbatim in every fresh read.
READABLE = ('!Command: show running-config', 'hostname lab-n9k1', 'feature ospf', 'vlan 10', '  name USERS',
            '  name SERVERS', 'interface Ethernet1/1', '  description uplink-core', '  ip address 198.51.100.1/30',
            '  ip address 203.0.113.1/24', '  ip route 0.0.0.0/0 192.0.2.1', 'ip route 198.51.100.0/24 192.0.2.1',
            'router ospf 1', '  router-id 192.0.2.254', 'router bgp 65000', '    network 203.0.113.0/24',
            '  neighbor 198.51.100.2', '    remote-as 65001', 'spanning-tree mode mst',
            '  switchport trunk allowed vlan 10,20')
LABELS = ['cisco-nxos / comment-line', 'cisco-nxos / unsupported-statement', 'cisco-nxos / opaque-mode-line',
          'cisco-nxos / opaque-block', 'cisco-nxos / unsupported-sub-line']


def _indent(text):
    return len(text) - len(text.lstrip(' '))


def _model(*secrets):
    """[(line, outcome)] with outcome 'kept', 'credential', 'hidden' (new record) or 'continued'.

    A kept candidate holding a forbidden value is masked and its block becomes opaque: every later
    non-blank line indented deeper than it is hidden, until a less or equally indented statement."""
    rows, opaque = [], None
    for kind, text in ROWS:
        body = text.strip(' ')
        if opaque is not None and body and _indent(text) <= opaque:
            opaque = None
        if kind == 'c':
            rows.append((text, 'continued'))
        elif kind == 'h' or (opaque is not None and body and _indent(text) > opaque):
            rows.append((text, 'hidden'))
        elif any(secret in text for secret in secrets):
            rows.append((text, 'credential'))
            opaque = _indent(text)
        else:
            rows.append((text, 'kept'))
    return rows


def expected(*secrets):
    """The consumer-safe text: kept lines unchanged, every other physical line one NX-OS marker."""
    return ''.join((text if outcome == 'kept' else M) + '\n' for text, outcome in _model(*secrets))


def summary(*secrets):
    outcomes = [outcome for _, outcome in _model(*secrets)]
    return {'credential_redactions': outcomes.count('credential'),
            'unverified_count': outcomes.count('hidden'),
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


def _nxos_section(alias, access=('read',), platform='cisco_nxos'):
    section = _section()
    section.pop('snmp_credential')
    section['egress']['addresses'] = [ADDRESS[alias]]
    section.update(ssh_platform=platform, enabled_queries=['version'],
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
        'xe-d-account': {'kind': 'password', 'login': 'd-user', 'value': 'xe-d-password-only'},
    }}).encode(), replace=replace)


def _inventory(helper, b_access=('read',)):
    forti = _section()
    forti.pop('snmp_credential')
    forti['egress']['addresses'] = [ADDRESS['fw-c']]
    forti['read_inventory'] = {'interfaces': ['port1'], 'services': [], 'addresses': [], 'config_access': ['read']}
    forti['rate_limit'] = {'requests': 30, 'window_seconds': 60}
    write_private(helper / 'inventory.json', json.dumps({'version': 2, 'devices': [
        _device('router-a', 'cisco_nxos', _nxos_section('router-a')),
        _device('router-b', 'cisco_nxos', _nxos_section('router-b', b_access)),
        _device('fw-c', 'fortios', forti),
        _device('xe-d', 'cisco_xe', _nxos_section('xe-d', platform='cisco_xe')),
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
    return {'target': 'router-b', 'platform': 'cisco_nxos', 'section': 'all', 'include_all': True,
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
    _call(env, 'ssh_read', {'target': 'router-a', 'platform': 'cisco_nxos', 'query': 'version'})
    assert A_SECRET in env['bridge'].proxy.session_secrets or A_NEW_SECRET in env['bridge'].proxy.session_secrets


def _engine_auth(env, **overrides):
    """The auth context the real Proxy.request forwards for an NX-OS config_read, decoded by TargetAuth."""
    message = {'jsonrpc': '2.0', 'id': 'engine-auth', 'method': 'tools/call',
               'params': {'name': 'config_read', 'arguments': _b(**overrides)}}
    raw = env['bridge'].proxy.request(json.dumps(message).encode())
    assert raw is not None, env['bridge'].proxy.emitted
    arguments = json.loads(raw)['params']['arguments']
    return TargetAuth.decode('router-b', arguments['auth_context'])


def _read(auth, **options):
    arguments = {'redaction': 'full', 'include_defaults': False, **options}
    return engine.config_read(auth, arguments.pop('platform', 'cisco_nxos'), arguments.pop('section', 'all'),
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
    # The real server wrapper took the private handoff (_paged_auth) for the NX-OS read.
    assert [target for target, _ in env['paged']] == ['router-b']
    assert B_SECRET in env['paged'][0][1]

    # Exact profile and honest metadata.
    assert first['platform'] == 'cisco_nxos' and first['redaction'] == 'full' and first['view'] == 'running'
    assert first['section'] == 'all' and first['command'] == 'show running-config'
    assert first['include_defaults'] is False
    assert first['redaction_profile'] == adapter.PROFILE
    assert first['firmware'] == {'model': 'Nexus9000 C9300v', 'version': '9.3(12)'}
    # The tested identity (STARTUP): the reply is as before, without firmware_support or warnings.
    assert 'firmware_support' not in first and 'warnings' not in first
    assert first['capture_complete'] is True and first['configuration_complete'] is False
    assert first['identity_scope_verified'] is False and first['config_scope'] == 'device-account-visible'
    assert first['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified',
                                               'schema-fields-unverified']
    assert {key: first[key] for key in summary(B_SECRET)} == summary(B_SECRET)
    assert first['credential_redactions'] == 1
    assert first['redacted_count'] == 1 + summary()['unverified_count']
    assert first['unsupported_format_count'] == 1
    # hostname, features, descriptions, addresses, VLAN names and static/BGP/OSPF statements stay readable;
    # version/AAA/SNMP/TACACS/key chain/line/banner lines and every secret are masked (one marker per line).
    lines = text_expected.splitlines()
    assert lines[:4] == ['', '!Command: show running-config', M, M]
    for line in READABLE + ('interface Ethernet1/2', '  switchport access vlan 10', 'interface Ethernet1/3'):
        assert line in lines
    assert text_expected.count(M) == sum(kind != 'k' for kind, _ in ROWS) + 1
    # The real profile consumer, run directly, gives the same text and summary as the public path.
    direct = NxosStreamRedactor((B_SECRET,), 'all')
    try:
        direct.feed(CONFIG.encode())
        content = direct.finish()[0]
        assert content.page(0, content.total)[0] == text_expected
        assert direct.summary() == summary(B_SECRET)
    finally:
        direct.close()

    # Continuations page the stored Content; no further SSH.
    pages, text = _pages(env, first, _b(), 200)
    assert len(pages) > 2 and text == text_expected
    assert wire.commands() == ['show version', 'show running-config'] and len(wire.calls) == 2
    for page in pages:
        assert page['content_sha256'] == page['snapshot_sha256'] == sha(text)
        assert page['total_bytes'] == len(text.encode())
        assert page['redaction_profile'] == adapter.PROFILE and page['configuration_complete'] is False
        assert page['identity_scope_verified'] is False and page['firmware'] == first['firmware']
        assert page['visibility_limitations'] == first['visibility_limitations']
    for page in pages[:-1]:
        assert page['untrusted_device_output'].endswith('\n')
        assert page['next_offset'] == page['offset'] + page['returned_bytes']

    stored = configuration._SNAPSHOTS[first['snapshot_id']]
    assert stored.text.sha256 == sha(text) and stored.text.page(0, stored.text.total)[0] == text
    assert stored.profile == adapter.PROFILE and stored.firmware == FIRMWARE
    assert stored.scope[1:3] == ('cisco_nxos', 'running') and len(stored.hidden) == 0
    # The caller credential became a marker, not a raw value or <REDACTED>.
    assert 'circuit' not in text and '<REDACTED' not in text and config_cisco_ios.MARKER not in text
    for page in pages:
        _assert_clean(page)
    _assert_clean(repr(stored) + str(dict(stored.metadata)))


def test_crlf_capture_is_paged_with_line_feeds(env):
    _rewire(env, Wire(config=CONFIG.replace('\n', '\r\n').encode(), chunk=5))
    first = _page(_call(env, 'config_read', _b(limit=48000)))
    assert first['untrusted_device_output'] == expected(B_SECRET) and first['next_offset'] is None
    assert first['configuration_complete'] is False and first['credential_redactions'] == 1
    _assert_clean(first)


def test_proxy_reserves_two_reads_for_a_capture_and_none_for_a_cached_page(env):
    proxy = env['bridge'].proxy
    _, section, _ = proxy._target('router-b')
    assert proxy._rate_cost('config_read', None, section, {'platform': 'cisco_nxos'}) == 2
    assert proxy._rate_cost('config_read', None, section,
                            {'platform': 'cisco_nxos', 'snapshot_id': 'cfg_' + '0' * 32}) == 0


# ------------------------------------------------- session secret collision before store and hash

def test_session_secret_collision_is_redacted_before_store_hash_and_final_response(env):
    _register_a(env)
    proxy = env['bridge'].proxy
    assert A_SECRET in proxy.session_secrets
    first = _call(env, 'config_read', _b(limit=60))
    data = _page(first)
    _assert_clean(first, A_SECRET)
    safe = expected(B_SECRET, A_SECRET)
    assert 'interface Ethernet1/1\n' in safe and 'interface Ethernet1/2' not in safe
    # A's credential hides B's 'interface Ethernet1/2' header and, as an opaque block, its sub-line.
    assert '  switchport access vlan 10' not in safe.splitlines()
    assert data['credential_redactions'] == 2
    assert data['unverified_count'] == summary()['unverified_count'] + 1
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
    ('router-b', 'fortios'), ('router-b', 'fortiadc'), ('router-b', 'extreme_exos'), ('router-b', 'cisco_ios'),
    ('router-b', 'cisco_xe'), ('router-b', 'arista_eos'), ('fw-c', 'cisco_nxos'), ('xe-d', 'cisco_nxos'),
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


def test_proxy_refuses_config_diff_without_compare_and_forwards_it_with_compare(env):
    # verification (was: config_diff refused for NX-OS): read alone refuses it before the engine, read+compare
    # forwards it through _paged_auth; an unknown snapshot pair then fails in the engine, never over SSH.
    diff = {'target': 'router-b', 'platform': 'cisco_nxos',
            'base_snapshot': 'cfg_' + '0' * 32, 'other_snapshot': 'cfg_' + '1' * 32}
    error = _refused(_call(env, 'config_diff', diff))
    assert error['data']['field'] == 'config_access'
    assert env['wire'].calls == [] and env['paged'] == [] and not configuration._SNAPSHOTS
    _inventory(env['helper'], b_access=('read', 'compare'))
    result = _call(env, 'config_diff', diff)
    assert result['isError'] is True, result
    assert [target for target, _ in env['paged']] == ['router-b']
    assert env['wire'].calls == [] and not configuration._SNAPSHOTS


def test_engine_refuses_options_access_and_platform_before_ssh(env):
    auth = _engine_auth(env)
    for options in ({'include_defaults': True}, {'redaction': 'minimal'}, {'include_all': False},
                    {'section': 'interface', 'include_all': False}):
        with pytest.raises(ValueError, match='config_platform_not_supported'):
            _read(auth, **options)
    for platform in ('fortinet', 'cisco_ios', 'cisco_xe', 'arista_eos', 'extreme_exos'):
        with pytest.raises(ValueError, match='outside target policy'):
            _read(replace(auth, ssh_platform=platform))
    with pytest.raises(ValueError, match='not enabled'):
        _read(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ()}))
    # verification: config_diff is open for cisco_nxos, but only with compare (next to read) in config_access.
    with pytest.raises(ValueError, match='not enabled'):
        engine.config_diff(auth, 'cisco_nxos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    compare = replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(compare, 'cisco_nxos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    with pytest.raises(ValueError, match='outside target policy'):
        engine.config_diff(replace(compare, ssh_platform='fortinet'), 'cisco_nxos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    assert env['wire'].calls == [] and not configuration._SNAPSHOTS


# ------------------------------------------------------------ identity gates the configuration command

@pytest.mark.parametrize('version, firmware', [
    (VERSION.replace(CHASSIS, '  cisco Nexus9000 C9500v Chassis'), {'model': 'Nexus9000 C9500v', 'version': '9.3(12)'}),
    (VERSION.replace(RELEASE, ' NXOS: version 10.3(4a)'), {'model': 'Nexus9000 C9300v', 'version': '10.3(4a)'}),
], ids=['derived-other-model', 'derived-other-release'])
def test_untested_identity_is_read_with_a_warning_through_the_public_chain(env, version, firmware):
    """STARTUP: an untested identity is read through worker, proxy and engine; same redaction, plus a warning."""
    wire = _rewire(env, Wire(version=version))
    first = _page(_call(env, 'config_read', _b(limit=200)))
    assert wire.commands() == ['show version', 'show running-config']
    assert first['firmware'] == firmware
    message = ('Cisco NX-OS %s on %s is not among the versions config_read was tested on (Nexus9000 C9300v 9.3(12)). '
               'It may or may not work as designed and tested; check the result.' % (firmware['version'],
                                                                                      firmware['model']))
    assert first['firmware_support'] == {
        'status': 'untested', 'platform': 'Cisco NX-OS', 'device_version': firmware['version'],
        'model': firmware['model'], 'tested_versions': ['Nexus9000 C9300v 9.3(12)'], 'message': message}
    assert first['warnings'] == [{'code': 'firmware_untested', 'message': message}]
    assert first['redaction_profile'] == adapter.PROFILE
    pages, text = _pages(env, first, _b(), 200)
    assert text == expected(B_SECRET) and len(wire.calls) == 2
    for page in pages:
        assert page['firmware_support'] == first['firmware_support'] and page['warnings'] == first['warnings']
        _assert_clean(page)


@pytest.mark.parametrize('version, message', [
    (VERSION_XE, 'identity-unverifiable'),
    (VERSION_EOS, 'identity-unverifiable'),
    (VERSION + ' NXOS: version 9.3(11)\n', 'identity-unverifiable'),
    (VERSION + VERSION, 'identity-unverifiable'),
    (VERSION.replace(CHASSIS + '\n', ''), 'identity-unverifiable'),
    (VERSION.replace(HEADER + '\n', ''), 'identity-unverifiable'),
    (VERSION.replace(RELEASE, ' NXOS: version 9.3'), 'identity-unverifiable'),
    ('', 'identity-unverifiable'),
], ids=['real-cisco-xe', 'real-arista-eos', 'two-different-releases',
        'repeated-identity', 'no-hardware-line', 'no-header', 'malformed-release-line', 'empty'])
def test_unverifiable_identity_never_runs_the_config_command(env, version, message):
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
    assert CONFIG.count(old) == 1
    return CONFIG.replace(old, new).encode()


@pytest.mark.parametrize('wire, message', [
    (lambda: Wire(config=CONFIG.encode()[:-len('nity\n')]), 'stream-incomplete'),
    (lambda: Wire(config=b''), 'stream-incomplete'),
    (lambda: Wire(config=_replace_row('!Command: show running-config\n', '')), 'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('!Command: show running-config\n', '!Command: show startup-config\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('SECRET-BANNER-SENTINEL\n#\n', 'SECRET-BANNER-SENTINEL\n')), 'stream-incomplete'),
    (lambda: Wire(config=_replace_row('hostname lab-n9k1\n', 'hostname lab-n9k1\n  banner motd #SECRET-BANNER-SENTINEL#\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('  description uplink-core\n', '\tdescription SECRET-PASSWORD-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('hostname lab-n9k1\n', 'hostname lab-n9k1\n --More-- SECRET-PASSWORD-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=CONFIG.encode()[:60] + b'\xff\xfe' + CONFIG.encode()[60:]), 'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('hostname lab-n9k1\n', "% Permission denied SECRET-PASSWORD-SENTINEL\n")),
     'device-refused during capture'),
    (lambda: Wire(rc=1), 'device-refused during capture'),
    (lambda: Wire(stdout=b'accumulated SECRET-PASSWORD-SENTINEL'), 'transport-contract-failed'),
    (lambda: Wire(config=_replace_row('hostname lab-n9k1\n', 'hostname ' + 'a' * 5000 + '\n')),
     'capture-limit-exceeded'),
], ids=['unterminated-last-line', 'empty', 'no-header', 'other-header', 'unclosed-banner', 'indented-banner',
        'tab-indent', 'pager', 'bad-utf8', 'device-refusal', 'rc', 'accumulated-raw', 'line-limit'])
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
    assert page['configuration_complete'] is False and page['identity_scope_verified'] is False
    assert {'account-rights-not-verified', 'formats-not-verified'} <= set(page['visibility_limitations'])

    stored = configuration._SNAPSHOTS[identity]
    for profile in (config_exos_adapter.PROFILE, config_cisco_ios_adapter.PROFILE, config_cisco_xe_adapter.PROFILE,
                    config_arista_eos_adapter.PROFILE, 'cisco_nxos-full-1:' + '0' * 64, configuration.PROFILE):
        configuration._SNAPSHOTS[identity] = replace(stored, profile=profile)
        with pytest.raises(ValueError, match='invalid configuration profile|capture options mismatch'):
            _read(auth, snapshot_id=identity)
    # STARTUP: a stored untested record pages with its warning; a record of another shape is refused.
    for firmware in (('Nexus9000 C9300v', '9.3(11)'), ('Nexus9000 C9500v', '9.3(12)')):
        configuration._SNAPSHOTS[identity] = replace(stored, firmware=firmware)
        page = _read(auth, snapshot_id=identity)
        assert page['firmware_support']['status'] == 'untested' and page['warnings'][0]['code'] == 'firmware_untested'
    for firmware in (('Nexus9000 C9300v', '9.3(12)', 'x'), ['Nexus9000 C9300v', '9.3(12)'], ('Nexus9000 C9300v', '9.3'),
                     config_arista_eos_adapter.TESTED, config_cisco_xe_adapter.TESTED, config_cisco_ios_adapter.TESTED):
        configuration._SNAPSHOTS[identity] = replace(stored, firmware=firmware)
        with pytest.raises(ValueError, match='policy mismatch'):
            _read(auth, snapshot_id=identity)
    # An IOS XE, IOS or EOS snapshot (its platform scope and profile) is never paged as NX-OS.
    for platform, other in (('cisco_xe', config_cisco_xe_adapter), ('cisco_ios', config_cisco_ios_adapter),
                            ('arista_eos', config_arista_eos_adapter)):
        configuration._SNAPSHOTS[identity] = replace(stored, scope=(stored.scope[0], platform, *stored.scope[2:]),
                                                     profile=other.PROFILE, firmware=other.TESTED)
        with pytest.raises(ValueError, match='scope mismatch'):
            _read(auth, snapshot_id=identity)
    configuration._SNAPSHOTS[identity] = stored
    # Another platform or another credential cannot page this snapshot.
    for platform in ('cisco_ios', 'cisco_xe', 'arista_eos', 'extreme_exos'):
        other = replace(auth, ssh_platform=platform)
        with pytest.raises(ValueError, match='scope mismatch|not_supported'):
            engine.config_read(other, platform, 'all', True, identity, 0, 200, 'full')
    with pytest.raises(ValueError, match='scope mismatch'):
        _read(replace(auth, secret='another-secret'), snapshot_id=identity, offset=1)
    assert _read(auth, snapshot_id=identity)['snapshot_sha256'] == first['snapshot_sha256']
    assert len(env['wire'].calls) == 2

    configuration._snapshot_profile(adapter.PROFILE, 'cisco_nxos')
    for profile, platform in ((adapter.PROFILE, 'fortios'), (adapter.PROFILE, 'extreme_exos'),
                              (adapter.PROFILE, 'cisco_ios'), (adapter.PROFILE, 'cisco_xe'),
                              (adapter.PROFILE, 'arista_eos'),
                              (config_cisco_ios_adapter.PROFILE, 'cisco_nxos'),
                              (config_cisco_xe_adapter.PROFILE, 'cisco_nxos'),
                              (config_arista_eos_adapter.PROFILE, 'cisco_nxos'),
                              (config_exos_adapter.PROFILE, 'cisco_nxos'), ('cisco_nxos-full-1:' + '0' * 64, 'cisco_nxos'),
                              (adapter.PROFILE.upper(), 'cisco_nxos'), (None, 'cisco_nxos')):
        with pytest.raises(ValueError, match='invalid configuration profile'):
            configuration._snapshot_profile(profile, platform)


def test_live_startup_count_failure_does_not_capture_or_keep_config(env, monkeypatch):
    wire = env["wire"]
    attempted = []

    def read(*args, **kwargs):
        command = args[5]
        attempted.append(command)
        if command == "show startup-config | count":
            raise ValueError("fixture invalid transport count reply")
        return wire(*args, **kwargs)

    monkeypatch.setattr(engine.core_ssh, "run_command", read)
    auth = replace(_engine_auth(env), read_inventory={"config_access": ("read", "compare")})
    answer = engine.config_diff(auth, "cisco_nxos", "startup", "running")
    assert not answer["ok"] and answer["error_code"] == "stream-incomplete"
    assert "untrusted_device_output" not in answer and not configuration._SNAPSHOTS
    assert "fixture invalid transport count reply" not in str(answer)
    assert attempted == ["show version", "show startup-config | count"]
