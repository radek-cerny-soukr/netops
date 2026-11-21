"""Tasks 143/153: the public config_read path for the Arista EOS profile (G00: other identities read with a warning).

``arista_eos`` / ``Arista cEOSLab`` with ``Software image version: 4.36.1F`` (any build suffix, which
is kept in the firmware record) is the tested identity (``config_arista_eos_adapter``), the same pattern as the
cisco_xe path (task 140) and the accepted ``cisco_ios`` path (task 128).  Task 153: the capture goes
through the indentation-based ``config_indented.EosStreamRedactor`` (task 147), so hostname,
descriptions, addresses, VLAN names and static/BGP/OSPF statements stay readable and every secret is
masked.
The positive reads run through the real root ``netops.worker.HelperBridge.call`` -> ``Proxy.request`` ->
FastMCP ``server.config_read`` (``_paged_auth``) -> ``TargetAuth.decode`` -> ``engine.config_read`` ->
``read_from_device`` -> ``_exec_read`` -> the real unchanged ``config_indented.EosStreamRedactor`` /
``configuration.store`` / page -> ``Proxy.response`` -> the worker's final redaction and page-change guard,
in process.  Refusals use the same real ``Proxy.request`` and, for engine checks, the auth context it
produced.  Only the physical SSH exec backend (``core_ssh.run_command``), the physical host-key scan and
the audit file location are replaced; the fake feeds real byte chunks into the consumer callback.

Identity: ``show version`` is the immutable REAL capture
``fixtures/real/arista_eos/ceos_4.36.1F/version.txt``; the foreign-vendor case uses the REAL
``fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``.  Other identity texts are DERIVED by editing
those captures.  Every ``show running-config`` text below is SYNTHETIC: the EOS configuration of
``tests/test_config_indented.py`` (task 143 gate, Arista EOS User Manual statement syntax) with its
secrets replaced by sentinels and a few added rows (banner, caller credential, Ethernet3), not a live
capture.  Nothing here measures account rights, the full-config format or any hardware/firmware.
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
from netops_helper import config_arista_eos_adapter as adapter, config_cisco_ios_adapter, config_exos_adapter
from netops_helper import config_cisco_xe_adapter
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from netops_helper.config_indented import EOS_MARKER, EosStreamRedactor
from test_proxy import DEVICE_PIN, _section

REAL = Path(__file__).parent / 'fixtures' / 'real'
VERSION = (REAL / 'arista_eos' / 'ceos_4.36.1F' / 'version.txt').read_text()
VERSION_XE = (REAL / 'cisco_xe' / 'iolxe_17.18.2' / 'version.txt').read_text()
MODEL = 'Arista cEOSLab'
IMAGE = 'Software image version: 4.36.1F-48405728.4361F (engineering build)'
FIRMWARE = ('cEOSLab', '4.36.1F', '4.36.1F-48405728.4361F (engineering build)')
HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask143Only'
ADDRESS = {'router-a': '192.0.2.10', 'router-b': '192.0.2.20', 'fw-c': '192.0.2.30', 'xe-d': '192.0.2.40'}
A_SECRET = 'Ethernet2'           # valid password of A; also a safe interface name on B
A_NEW_SECRET = 'Ethernet3'       # A's next password, registered only after B's snapshot exists
B_SECRET = 'b-router-sesame-only'
M = EOS_MARKER
# The task 143 profile (unchanged IOS line consumer); a snapshot under it is never paged as this profile.
OLD_PROFILE = 'arista_eos-full-1:' + hashlib.sha256(json.dumps(
    ('arista_eos', 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', config_cisco_ios.MARKER,
     'show running-config', ('show version',), ('cEOSLab', '4.36.1F')), separators=(',', ':')).encode()).hexdigest()
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
SENTINELS = ('SECRET-ENABLE-SENTINEL', 'SECRET-PASSWORD-SENTINEL', 'SECRET-SNMP-SENTINEL',
             'SECRET-TACACS-SENTINEL', 'SECRET-BGP-SENTINEL', 'SECRET-BANNER-SENTINEL', 'SECRET-OSPF-SENTINEL',
             'SECRET-EAPI-SENTINEL', B_SECRET)
IDENTITY_TEXT = ('Serial number', 'S000S0000', 'Internal build ID', 'da7ae8ea', '20481232', 'Kernel version')

# SYNTHETIC Arista EOS running-config (not a live capture).  'k' kept unless it (or its block header)
# holds a forbidden value, 'h' one hidden record, 'c' a further hidden physical line of the same record.
ROWS = (
    ('h', '! Command: show running-config'),
    ('h', '! device: lab-eos1 (cEOSLab, EOS-4.36.1F)'),
    ('k', '!'),
    ('h', '! boot system flash:/cEOS-lab.swi'),
    ('k', '!'),
    ('k', 'no aaa root'),
    ('k', '!'),
    ('h', 'username admin privilege 15 role network-admin secret sha512 $6$salt$SECRET-PASSWORD-SENTINEL'),
    ('k', '!'),
    ('h', 'enable password sha512 $6$salt$SECRET-ENABLE-SENTINEL'),
    ('k', '!'),
    ('k', 'management api http-commands'),
    ('k', '   no shutdown'),
    ('k', '   !'),
    ('k', '   vrf MGMT'),
    ('k', '      no shutdown'),
    ('k', '!'),
    ('h', 'daemon TerminAttr'),
    ('h', '   exec /usr/bin/TerminAttr -cvauth=token,SECRET-EAPI-SENTINEL -taillogs'),
    ('h', '   no shutdown'),
    ('k', '!'),
    ('k', 'service routing protocols model multi-agent'),
    ('k', '!'),
    ('k', 'hostname lab-eos1'),
    ('k', 'ip name-server vrf default 192.0.2.53'),
    ('k', '!'),
    ('h', 'banner login'),
    ('c', 'SECRET-BANNER-SENTINEL'),
    ('c', 'EOF'),
    ('k', '!'),
    ('h', 'snmp-server user u1 g1 v3 auth sha 0xSECRET-SNMP-SENTINEL priv aes 0xSECRET-SNMP-SENTINEL'),
    ('k', '!'),
    ('h', 'tacacs-server host 198.51.100.1 key 7 SECRET-TACACS-SENTINEL'),
    ('k', '!'),
    ('k', 'spanning-tree mode mstp'),
    ('k', '!'),
    ('k', 'vlan 10'),
    ('k', '   name users'),
    ('k', '!'),
    ('k', 'vlan 20'),
    ('k', '   name servers'),
    ('k', '!'),
    ('k', 'interface Ethernet1'),
    ('k', '   description uplink to spine1'),
    ('k', '   description circuit ' + B_SECRET),
    ('k', '   no switchport'),
    ('k', '   ip address 198.51.100.1/31'),
    ('h', '   ip ospf authentication-key 7 SECRET-OSPF-SENTINEL'),
    ('k', '!'),
    ('k', 'interface Ethernet2'),
    ('k', '   switchport access vlan 10'),
    ('k', '!'),
    ('k', 'interface Ethernet3'),
    ('k', '   shutdown'),
    ('k', '!'),
    ('k', 'interface Loopback0'),
    ('k', '   ip address 192.0.2.1/32'),
    ('k', '!'),
    ('k', 'interface Management0'),
    ('k', '   ip address 203.0.113.10/24'),
    ('k', '!'),
    ('k', 'ip routing'),
    ('k', '!'),
    ('k', 'ip route 0.0.0.0/0 203.0.113.1'),
    ('k', '!'),
    ('k', 'router bgp 65000'),
    ('k', '   router-id 192.0.2.1'),
    ('k', '   neighbor 198.51.100.2 remote-as 65001'),
    ('h', '   neighbor 198.51.100.2 password 7 SECRET-BGP-SENTINEL'),
    ('k', '   !'),
    ('k', '   address-family ipv4'),
    ('k', '      neighbor 198.51.100.2 activate'),
    ('k', '      network 192.0.2.1/32'),
    ('k', '!'),
    ('k', 'router ospf 1'),
    ('k', '   network 198.51.100.0/31 area 0.0.0.0'),
    ('k', '!'),
    ('k', 'end'),
)
CONFIG = ''.join(text + '\n' for _, text in ROWS)
# Readable statements of the SYNTHETIC configuration (task 153 goal): verbatim in every fresh read.
READABLE = ('hostname lab-eos1', 'vlan 10', '   name users', '   name servers', 'interface Ethernet1',
            '   description uplink to spine1', '   ip address 198.51.100.1/31', '   ip address 192.0.2.1/32',
            'ip route 0.0.0.0/0 203.0.113.1', 'router bgp 65000', '   neighbor 198.51.100.2 remote-as 65001',
            '      network 192.0.2.1/32', 'router ospf 1', '   network 198.51.100.0/31 area 0.0.0.0',
            'spanning-tree mode mstp', 'end')
LABELS = ['arista-eos / comment-line', 'arista-eos / unsupported-statement', 'arista-eos / opaque-mode-line',
          'arista-eos / opaque-block', 'arista-eos / unsupported-sub-line']


def _indent(text):
    return len(text) - len(text.lstrip(' '))


def _model(*secrets):
    """[(line, outcome)] with outcome 'kept', 'credential', 'hidden' (new record) or 'continued'.

    A kept candidate holding a forbidden value is masked and its block becomes opaque: every later line
    indented deeper than it is hidden, until a less or equally indented statement ('!' separators never
    end a block)."""
    rows, opaque = [], None
    for kind, text in ROWS:
        body = text.strip(' ')
        if opaque is not None and body and body != '!' and _indent(text) <= opaque:
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
    """The consumer-safe text: kept lines unchanged, every other physical line one EOS marker."""
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


def _eos_section(alias, access=('read',), platform='arista_eos'):
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
        _device('router-a', 'arista_eos', _eos_section('router-a')),
        _device('router-b', 'arista_eos', _eos_section('router-b', b_access)),
        _device('fw-c', 'fortios', forti),
        _device('xe-d', 'cisco_xe', _eos_section('xe-d', platform='cisco_xe')),
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
    return {'target': 'router-b', 'platform': 'arista_eos', 'section': 'all', 'include_all': True,
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
    _call(env, 'ssh_read', {'target': 'router-a', 'platform': 'arista_eos', 'query': 'version'})
    assert A_SECRET in env['bridge'].proxy.session_secrets or A_NEW_SECRET in env['bridge'].proxy.session_secrets


def _engine_auth(env, **overrides):
    """The auth context the real Proxy.request forwards for an EOS config_read, decoded by TargetAuth."""
    message = {'jsonrpc': '2.0', 'id': 'engine-auth', 'method': 'tools/call',
               'params': {'name': 'config_read', 'arguments': _b(**overrides)}}
    raw = env['bridge'].proxy.request(json.dumps(message).encode())
    assert raw is not None, env['bridge'].proxy.emitted
    arguments = json.loads(raw)['params']['arguments']
    return TargetAuth.decode('router-b', arguments['auth_context'])


def _read(auth, **options):
    arguments = {'redaction': 'full', 'include_defaults': False, **options}
    return engine.config_read(auth, arguments.pop('platform', 'arista_eos'), arguments.pop('section', 'all'),
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
    # The real server wrapper took the private handoff (_paged_auth) for the EOS read.
    assert [target for target, _ in env['paged']] == ['router-b']
    assert B_SECRET in env['paged'][0][1]

    # Exact profile and honest metadata.
    assert first['platform'] == 'arista_eos' and first['redaction'] == 'full' and first['view'] == 'running'
    assert first['section'] == 'all' and first['command'] == 'show running-config'
    assert first['include_defaults'] is False
    assert first['redaction_profile'] == adapter.PROFILE
    assert first['firmware'] == {'model': 'cEOSLab', 'version': '4.36.1F',
                                 'build': '4.36.1F-48405728.4361F (engineering build)'}
    # The tested identity (G00): the reply is as before, without firmware_support or warnings.
    assert 'firmware_support' not in first and 'warnings' not in first
    assert first['capture_complete'] is True and first['configuration_complete'] is False
    assert first['identity_scope_verified'] is False and first['config_scope'] == 'device-account-visible'
    assert first['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified',
                                               'schema-fields-unverified']
    assert {key: first[key] for key in summary(B_SECRET)} == summary(B_SECRET)
    assert first['credential_redactions'] == 1
    assert first['redacted_count'] == 1 + summary()['unverified_count']
    assert first['unsupported_format_count'] == 1
    # hostname, descriptions, addresses, VLAN names and static/BGP/OSPF statements stay readable;
    # AAA/SNMP/TACACS/management/banner lines and every secret are masked (one EOS marker per line).
    assert text_expected.splitlines()[:3] == [M, M, '!']
    for line in READABLE + ('interface Ethernet2', '   switchport access vlan 10', 'interface Ethernet3'):
        assert line in text_expected.splitlines()
    assert text_expected.count(M) == sum(kind != 'k' for kind, _ in ROWS) + 1
    # The real profile consumer, run directly, gives the same text and summary as the public path.
    direct = EosStreamRedactor((B_SECRET,), 'all')
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
    for page in pages[:-1]:
        assert page['untrusted_device_output'].endswith('\n')
        assert page['next_offset'] == page['offset'] + page['returned_bytes']

    stored = configuration._SNAPSHOTS[first['snapshot_id']]
    assert stored.text.sha256 == sha(text) and stored.text.page(0, stored.text.total)[0] == text
    assert stored.profile == adapter.PROFILE and stored.firmware == FIRMWARE
    assert stored.scope[1:3] == ('arista_eos', 'running') and len(stored.hidden) == 0
    # The caller credential became a marker, not a raw value or <REDACTED>.
    assert 'circuit' not in text and '<REDACTED' not in text and config_cisco_ios.MARKER not in text
    for page in pages:
        _assert_clean(page)
    _assert_clean(repr(stored) + str(dict(stored.metadata)))


def test_proxy_reserves_two_reads_for_a_capture_and_none_for_a_cached_page(env):
    proxy = env['bridge'].proxy
    _, section, _ = proxy._target('router-b')
    assert proxy._rate_cost('config_read', None, section, {'platform': 'arista_eos'}) == 2
    assert proxy._rate_cost('config_read', None, section,
                            {'platform': 'arista_eos', 'snapshot_id': 'cfg_' + '0' * 32}) == 0


# ------------------------------------------------- session secret collision before store and hash

def test_session_secret_collision_is_redacted_before_store_hash_and_final_response(env):
    _register_a(env)
    proxy = env['bridge'].proxy
    assert A_SECRET in proxy.session_secrets
    first = _call(env, 'config_read', _b(limit=60))
    data = _page(first)
    _assert_clean(first, A_SECRET)
    safe = expected(B_SECRET, A_SECRET)
    assert 'interface Ethernet1\n' in safe and 'interface Ethernet2' not in safe
    # A's credential hides B's 'interface Ethernet2' header and, as an opaque block, its sub-line.
    assert '   switchport access vlan 10' not in safe.splitlines()
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
    ('router-b', 'cisco_xe'), ('router-b', 'cisco_nxos'), ('fw-c', 'arista_eos'), ('xe-d', 'arista_eos'),
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
    for platform in ('fortinet', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'extreme_exos'):
        with pytest.raises(ValueError, match='outside target policy'):
            _read(replace(auth, ssh_platform=platform))
    with pytest.raises(ValueError, match='not enabled'):
        _read(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ()}))
    # Task 157: config_diff is open for arista_eos, but only with compare (next to read) in config_access.
    with pytest.raises(ValueError, match='not enabled'):
        engine.config_diff(auth, 'arista_eos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    compare = replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(compare, 'arista_eos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    with pytest.raises(ValueError, match='outside target policy'):
        engine.config_diff(replace(compare, ssh_platform='fortinet'), 'arista_eos', 'cfg_' + '0' * 32, 'cfg_' + '1' * 32)
    assert env['wire'].calls == [] and not configuration._SNAPSHOTS


# ------------------------------------------------------------ identity gates the configuration command

@pytest.mark.parametrize('version, firmware', [
    (VERSION.replace(MODEL, 'Arista vEOS-lab'),
     {'model': 'vEOS-lab', 'version': '4.36.1F', 'build': '4.36.1F-48405728.4361F (engineering build)'}),
    (VERSION.replace(IMAGE, IMAGE.replace('4.36.1F-', '4.35.1F-')),
     {'model': 'cEOSLab', 'version': '4.35.1F', 'build': '4.35.1F-48405728.4361F (engineering build)'}),
], ids=['derived-other-model', 'derived-other-release'])
def test_untested_identity_is_read_with_a_warning_through_the_public_chain(env, version, firmware):
    """G00: an untested identity is read through worker, proxy and engine; same redaction, plus a warning."""
    wire = _rewire(env, Wire(version=version))
    first = _page(_call(env, 'config_read', _b(limit=200)))
    assert wire.commands() == ['show version', 'show running-config']
    assert first['firmware'] == firmware
    message = ('Arista EOS %s on %s is not among the versions config_read was tested on (cEOSLab 4.36.1F). '
               'It may or may not work as designed and tested; check the result.' % (firmware['version'],
                                                                                      firmware['model']))
    assert first['firmware_support'] == {
        'status': 'untested', 'platform': 'Arista EOS', 'device_version': firmware['version'],
        'model': firmware['model'], 'tested_versions': ['cEOSLab 4.36.1F'], 'message': message}
    assert first['warnings'] == [{'code': 'firmware_untested', 'message': message}]
    assert first['redaction_profile'] == adapter.PROFILE
    pages, text = _pages(env, first, _b(), 200)
    assert text == expected(B_SECRET) and len(wire.calls) == 2
    for page in pages:
        assert page['firmware_support'] == first['firmware_support'] and page['warnings'] == first['warnings']
        _assert_clean(page)


@pytest.mark.parametrize('version, message', [
    (VERSION_XE, 'identity-unverifiable'),
    (VERSION + IMAGE.replace('4.36.1F-', '4.35.1F-') + '\n', 'identity-unverifiable'),
    (VERSION + VERSION, 'identity-unverifiable'),
    (VERSION.replace(MODEL + '\n', ''), 'identity-unverifiable'),
    (VERSION.replace(IMAGE, 'Software image version: 4.36'), 'identity-unverifiable'),
    ('', 'identity-unverifiable'),
], ids=['real-cisco-xe', 'two-different-releases',
        'repeated-identity', 'no-model-line', 'malformed-image-line', 'empty'])
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
    return CONFIG.replace(old, new).encode()


@pytest.mark.parametrize('wire, message', [
    (lambda: Wire(config=CONFIG[:-len('end\n')].encode()), 'stream-incomplete'),
    (lambda: Wire(config=_replace_row('SECRET-BANNER-SENTINEL\nEOF\n', 'SECRET-BANNER-SENTINEL\n')),
     'stream-incomplete'),
    (lambda: Wire(config=_replace_row('hostname lab-eos1\n', 'hostname lab-eos1\n   banner motd\nSECRET-BANNER-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('hostname lab-eos1\n', 'hostname lab-eos1\nbanner exec ^C SECRET-BANNER-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('   description uplink to spine1\n',
                                      '\tdescription SECRET-PASSWORD-SENTINEL\n')), 'redaction-unverifiable'),
    (lambda: Wire(config=(CONFIG + 'hostname SECRET-PASSWORD-SENTINEL\n').encode()), 'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('hostname lab-eos1\n', 'hostname lab-eos1\n --More-- SECRET-PASSWORD-SENTINEL\n')),
     'redaction-unverifiable'),
    (lambda: Wire(config=CONFIG.encode()[:40] + b'\xff\xfe' + CONFIG.encode()[40:]), 'redaction-unverifiable'),
    (lambda: Wire(config=_replace_row('end\n', '% Invalid input SECRET-PASSWORD-SENTINEL\nend\n')),
     'device-refused during capture'),
    (lambda: Wire(rc=1), 'device-refused during capture'),
    (lambda: Wire(stdout=b'accumulated SECRET-PASSWORD-SENTINEL'), 'transport-contract-failed'),
    (lambda: Wire(config=_replace_row('hostname lab-eos1\n', 'hostname ' + 'a' * 5000 + '\n')),
     'capture-limit-exceeded'),
], ids=['no-end', 'unclosed-banner', 'indented-banner', 'unknown-banner', 'tab-indent', 'data-after-end',
        'pager', 'bad-utf8', 'device-refusal', 'rc', 'accumulated-raw', 'line-limit'])
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
    for profile in (config_exos_adapter.PROFILE, config_cisco_ios_adapter.PROFILE, config_cisco_xe_adapter.PROFILE,
                    'arista_eos-full-1:' + '0' * 64, OLD_PROFILE, configuration.PROFILE):
        configuration._SNAPSHOTS[identity] = replace(stored, profile=profile)
        with pytest.raises(ValueError, match='invalid configuration profile|capture options mismatch'):
            _read(auth, snapshot_id=identity)
    # G00: a stored untested record pages with its warning; a record of another shape is refused.
    for firmware in (('cEOSLab', '4.35.1F', '4.35.1F'), ('vEOS-lab', '4.36.1F', '4.36.1F')):
        configuration._SNAPSHOTS[identity] = replace(stored, firmware=firmware)
        page = _read(auth, snapshot_id=identity)
        assert page['firmware_support']['status'] == 'untested' and page['warnings'][0]['code'] == 'firmware_untested'
    for firmware in (adapter.TESTED, ('cEOSLab', '4.36.1F', '4.35.1F-1.4351F'), config_cisco_xe_adapter.TESTED,
                     config_cisco_ios_adapter.TESTED):
        configuration._SNAPSHOTS[identity] = replace(stored, firmware=firmware)
        with pytest.raises(ValueError, match='policy mismatch'):
            _read(auth, snapshot_id=identity)
    # An IOS XE or IOS snapshot (its platform scope and profile) is never paged as EOS.
    for platform, other in (('cisco_xe', config_cisco_xe_adapter), ('cisco_ios', config_cisco_ios_adapter)):
        configuration._SNAPSHOTS[identity] = replace(stored, scope=(stored.scope[0], platform, *stored.scope[2:]),
                                                     profile=other.PROFILE, firmware=other.TESTED)
        with pytest.raises(ValueError, match='scope mismatch'):
            _read(auth, snapshot_id=identity)
    configuration._SNAPSHOTS[identity] = stored
    # Another platform or another credential cannot page this snapshot.
    for platform in ('cisco_ios', 'cisco_xe', 'extreme_exos'):
        other = replace(auth, ssh_platform=platform)
        with pytest.raises(ValueError, match='scope mismatch|not_supported'):
            engine.config_read(other, platform, 'all', True, identity, 0, 200, 'full')
    with pytest.raises(ValueError, match='scope mismatch'):
        _read(replace(auth, secret='another-secret'), snapshot_id=identity, offset=1)
    assert _read(auth, snapshot_id=identity)['snapshot_sha256'] == first['snapshot_sha256']
    assert len(env['wire'].calls) == 2

    configuration._snapshot_profile(adapter.PROFILE, 'arista_eos')
    for profile, platform in ((adapter.PROFILE, 'fortios'), (adapter.PROFILE, 'extreme_exos'),
                              (adapter.PROFILE, 'cisco_ios'), (adapter.PROFILE, 'cisco_xe'),
                              (config_cisco_ios_adapter.PROFILE, 'arista_eos'),
                              (config_cisco_xe_adapter.PROFILE, 'arista_eos'),
                              (config_exos_adapter.PROFILE, 'arista_eos'), ('arista_eos-full-1:' + '0' * 64, 'arista_eos'),
                              (OLD_PROFILE, 'arista_eos'),
                              (adapter.PROFILE.upper(), 'arista_eos'), (None, 'arista_eos')):
        with pytest.raises(ValueError, match='invalid configuration profile'):
            configuration._snapshot_profile(profile, platform)


G121 = REAL / 'arista_eos' / 'g121_ceos_4.36.1F'


class G121Wire(Wire):
    def __init__(self, running='running.out', startup='startup.out', native='diff-empty.out'):
        super().__init__()
        self.answers = {
            'show running-config': (G121 / running).read_bytes(),
            'show startup-config': (G121 / startup).read_bytes(),
            'show running-config diffs': (G121 / native).read_bytes(),
        }
        self.status = {'show startup-config': int(startup == 'startup-denied.out')}

    def __call__(self, host, port, login, credential, key, command, *, stdout_consumer=None, **options):
        if command == 'show version':
            return super().__call__(host, port, login, credential, key, command, stdout_consumer=stdout_consumer, **options)
        self.calls.append({'host': host, 'command': command})
        output = self.answers[command]
        if stdout_consumer is not None:
            for offset in range(0, len(output), 11):
                try:
                    stdout_consumer(output[offset:offset + 11])
                except Exception:
                    raise core_ssh.OutputConsumerError() from None
            output = b''
        return core_ssh.Result(rc=self.status.get(command, 0), stdout=output, said='', started_at='t0', finished_at='t1')


def _live_diff(env, **options):
    return _call(env, 'config_diff', {'target': 'router-b', 'platform': 'arista_eos',
                                     'base_snapshot': 'startup', 'other_snapshot': 'running', **options})


@pytest.mark.parametrize('changed', (False, True))
def test_g121_live_diff_real_captures_and_continuation(env, changed):
    _inventory(env['helper'], b_access=('read', 'compare'))
    wire = _rewire(env, G121Wire('running-changed.out' if changed else 'running.out',
                                native='diff-changed.out' if changed else 'diff-empty.out'))
    data = _page(_live_diff(env, limit=80))
    assert data['unsaved_changes'] is changed and data['identical'] is not changed
    assert data['comparison_status'] == 'verified'
    assert not data['hidden_lines_compared']
    assert data['base_capture']['comparison_view'] == 'startup'
    assert data['other_capture']['comparison_view'] == 'running'
    assert wire.commands() == ['show version', 'show startup-config', 'show version',
                               'show running-config', 'show running-config diffs']
    text = data['untrusted_device_output']
    while data['next_offset'] is not None:
        data = _page(_live_diff(env, base_snapshot=data['base_snapshot'], other_snapshot=data['other_snapshot'],
                                offset=data['next_offset'], limit=80))
        text += data['untrusted_device_output']
    assert len(wire.calls) == 5
    assert ('+ip access-list G121-VERIFY' in text) is changed
    assert ('+   10 permit tcp 192.0.2.0/24 any eq https' in text) is changed
    assert ('+ipv6 access-list G121-VERIFY' in text) is changed
    assert ('+ip prefix-list G121-VERIFY seq 10 permit 198.51.100.0/24 le 32' in text) is changed
    assert 'Startup-config last modified' not in text


@pytest.mark.parametrize('scenario', ('denied', 'truncated', 'no-compare'))
def test_g121_live_diff_refuses_invalid_access_or_side(env, scenario):
    if scenario != 'no-compare':
        _inventory(env['helper'], b_access=('read', 'compare'))
    wire = _rewire(env, G121Wire(startup='startup-denied.out' if scenario == 'denied' else 'startup.out'))
    if scenario == 'truncated':
        wire.answers['show running-config'] = wire.answers['show running-config'].removesuffix(b'end\n')
    result = _live_diff(env)
    shown = str(result)
    expected_message = {'denied': 'device-refused', 'truncated': 'stream-incomplete', 'no-compare': 'config_access'}[scenario]
    assert expected_message in shown
    assert not configuration._SNAPSHOTS
    assert 'untrusted_device_output' not in shown
    assert 'show running-config diffs' not in wire.commands()


def test_g121_incomplete_native_diff_keeps_the_redacted_difference(env):
    _inventory(env['helper'], b_access=('read', 'compare'))
    wire = _rewire(env, G121Wire('running-changed.out', native='diff-changed.out'))
    # Derived truncation: the last context row is missing even though the line ending is intact.
    wire.answers['show running-config diffs'] = b''.join(wire.answers['show running-config diffs'].splitlines(keepends=True)[:-1])
    data = _page(_live_diff(env))
    assert not data['identical'] and data['unsaved_changes'] is None
    assert data['comparison_status'] == 'incomplete'
    assert '+ip access-list G121-VERIFY' in data['untrusted_device_output']


def test_g121_public_config_read_preserves_acl_and_routing_with_credentials_masked(env):
    wire = _rewire(env, G121Wire('running-changed.out'))
    # Derived negative security cases: inject fictitious credentials into the measured structure,
    # including a short known credential embedded in the name of an otherwise admissible ACL.
    _vault(env['helper'], 'xy', replace=True)
    _call(env, 'ssh_read', {'target': 'router-a', 'platform': 'arista_eos', 'query': 'version'})
    assert 'xy' in env['bridge'].proxy.session_secrets
    wire.answers['show running-config'] = wire.answers['show running-config'].replace(
        b'   20 deny ip any any log\n',
        b'   20 deny ip any any log\n   30 remark FAKE-ACL-VALUE\n').replace(
        b'ip routing\n',
        b'ip access-list g121-xy-hidden\n   10 permit ip any any\n!\n'
        b'management ssh\n   idle-timeout 10\n   hostkey FAKE-MANAGEMENT-VALUE\n!\nip routing\n')
    result = _page(_call(env, 'config_read', _b()))
    text = result['untrusted_device_output']
    for line in ('ip access-list G121-VERIFY', '   20 deny ip any any log', 'management ssh',
                 '   idle-timeout 10', 'ip routing', 'router ospf 29', 'aaa authorization exec default local'):
        assert line in text.splitlines()
    _assert_clean(result, 'FAKE-ACL-VALUE', 'FAKE-MANAGEMENT-VALUE', 'g121-xy-hidden', '10 permit ip any any')
    assert result['credential_redactions'] >= 1 and result['unverified_count'] >= 1
