"""verification: config_diff for the ExtremeXOS, Cisco IOS, IOS XE, NX-OS and Arista EOS full captures.

Every platform runs the same scenarios through the real root ``netops.worker.HelperBridge.call`` ->
``Proxy.request`` -> FastMCP ``server.config_read`` / ``server.config_diff`` (``_paged_auth``) ->
``engine.config_read`` / ``engine.config_diff`` -> ``configuration.compare`` -> ``Proxy.response`` -> the
worker's final redaction and page guard, in process.  Engine checks use the auth context the real
``Proxy.request`` produced.  Only the physical SSH exec backend (``core_ssh.run_command``), the physical
host-key scan and the audit file location are replaced.

Identity texts are the REAL anonymized captures, and the configurations the SYNTHETIC texts, of the existing
public tests (``test_config_exos_session_redaction``, ``test_config_cisco_ios_public``,
``test_config_cisco_xe_public``, ``test_config_cisco_nxos_public``, ``test_config_arista_eos_public``); the
changed variants below edit one line of those synthetic texts.  Nothing here is a live measurement.
"""

import asyncio
from contextlib import nullcontext
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest import mock

import pytest

from netops import worker
from netops.files import write_private
from netops_core import ssh as core_ssh
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, config_cisco_ios, config_exos, configuration, engine, server
from netops_helper import proxy as proxy_module
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_helper.config_indented import EOS_MARKER, NXOS_MARKER
from conftest import HOST_KEY_BLOB, HOST_KEY_PIN
from test_proxy import DEVICE_PIN, _section
import test_config_arista_eos_public as eos_fixture
import test_config_cisco_ios_public as ios_fixture
import test_config_cisco_nxos_public as nxos_fixture
import test_config_cisco_xe_public as xe_fixture
import test_config_exos_session_redaction as exos_fixture

HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask157Only'
ADDRESS = {'router-a': '192.0.2.10', 'router-b': '192.0.2.20'}
A_SECRET = 'a-initial-password-only'      # never in any configuration text
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
SENTINELS = ('SECRET-COMMUNITY-SENTINEL', 'SECRET-PASSWORD-SENTINEL', 'SECRET-TACACS-SENTINEL',
             'SECRET-ENABLE-SENTINEL', 'SECRET-BANNER-SENTINEL', 'SECRET-LINE-SENTINEL', 'SECRET-SNMP-SENTINEL',
             'SECRET-BGP-SENTINEL', 'SECRET-OSPF-SENTINEL', A_SECRET)
FAMILY = ('extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos')

# visible: one allowlisted line and its changed form; hidden: one masked line and its changed form;
# late: a later password of A that is a word of a visible line of B (registered only after B's captures).
SPECS = {
    'extreme_exos': dict(
        enrolled='exos', queries=['version', 'switch'], command='show configuration',
        identity={'show version': exos_fixture.VERSION, 'show switch': exos_fixture.SWITCH},
        config=exos_fixture.CONFIG, b_secret=exos_fixture.B_SECRET, marker=config_exos.MARKER,
        visible=('disable ports 12', 'disable ports 11'),
        hidden=('create account admin reader "SECRET-PASSWORD-SENTINEL"',
                'create account admin reader "SECRET-PASSWORD-SENTINEL-CHANGED"'),
        late='Servers'),
    'cisco_ios': dict(
        enrolled='cisco_ios', queries=['version'], command='show running-config',
        identity={'show version': ios_fixture.VERSION},
        config=ios_fixture.CONFIG, b_secret=ios_fixture.B_SECRET, marker=config_cisco_ios.MARKER,
        visible=('hostname lab-r1', 'hostname lab-r2'),
        hidden=('snmp-server community SECRET-COMMUNITY-SENTINEL RO',
                'snmp-server community SECRET-COMMUNITY-SENTINEL-CHANGED RO'),
        late='Campus'),
    'cisco_xe': dict(
        enrolled='cisco_xe', queries=['version'], command='show running-config',
        identity={'show version': xe_fixture.VERSION},
        config=xe_fixture.CONFIG, b_secret=xe_fixture.B_SECRET, marker=config_cisco_ios.MARKER,
        visible=('hostname lab-r1', 'hostname lab-r2'),
        hidden=('snmp-server community SECRET-COMMUNITY-SENTINEL RO',
                'snmp-server community SECRET-COMMUNITY-SENTINEL-CHANGED RO'),
        late='Campus'),
    'cisco_nxos': dict(
        enrolled='cisco_nxos', queries=['version'], command='show running-config',
        identity={'show version': nxos_fixture.VERSION},
        config=nxos_fixture.CONFIG, b_secret=nxos_fixture.B_SECRET, marker=NXOS_MARKER,
        visible=('  description uplink-core', '  description uplink-edge'),
        hidden=('tacacs-server key 7 "SECRET-TACACS-SENTINEL"', 'tacacs-server key 7 "SECRET-TACACS-SENTINEL-CHANGED"'),
        late='Ethernet1/3'),
    'arista_eos': dict(
        enrolled='arista_eos', queries=['version'], command='show running-config',
        identity={'show version': eos_fixture.VERSION},
        config=eos_fixture.CONFIG, b_secret=eos_fixture.B_SECRET, marker=EOS_MARKER,
        visible=('   description uplink to spine1', '   description uplink to spine2'),
        hidden=('tacacs-server host 198.51.100.1 key 7 SECRET-TACACS-SENTINEL',
                'tacacs-server host 198.51.100.1 key 7 SECRET-TACACS-SENTINEL-CHANGED'),
        late='Ethernet3'),
}


def _edit(config, old, new):
    """The configuration with exactly one whole line replaced (new may hold several lines)."""
    assert ('\n' + config).count('\n' + old + '\n') == 1, old
    return ('\n' + config).replace('\n' + old + '\n', '\n' + new + '\n', 1)[1:]


class Wire:
    """Stands in for core_ssh.run_command, the physical SSH exec backend; records every call."""

    def __init__(self, spec):
        self.spec, self.config, self.calls = spec, spec['config'], []
        # Exit status of the configuration capture and of the identity reads (command -> rc); 0 by default.
        self.config_rc, self.identity_rc = 0, {}

    def __call__(self, host, port, login, credential, host_key_line, command, *, legacy_ssh=None,
                 timeout_seconds=None, capture_max_bytes=None, stdout_consumer=None,
                 idle_timeout_seconds=None, run=None, now=None):
        self.calls.append((host, command, stdout_consumer is not None))
        identity = self.spec['identity']
        if stdout_consumer is None:
            text = identity.get(command, identity['show version'])
            return core_ssh.Result(rc=self.identity_rc.get(command, 0), stdout=text.encode(), said='',
                                   started_at='t0', finished_at='t1')
        assert command == self.spec['command'] and host == ADDRESS['router-b']
        data = self.config.encode()
        for start in range(0, len(data), 7):
            try:
                stdout_consumer(data[start:start + 7])
            except core_ssh.OutputLimitError:
                raise
            except Exception:
                raise core_ssh.OutputConsumerError() from None
        return core_ssh.Result(rc=self.config_rc, stdout=b'', said='', started_at='t0', finished_at='t1')


    def fortinet_session(self, device, credential, **options):
        from netops_core import prompt, session
        cli = SimpleNamespace(_last_prompt=b"fixture-adc # ")
        is_adc = device.platform == "fortiadc"

        def run(command, *, stdout_consumer=None, **limits):
            def feed(chunk):
                chunks.append(chunk)

            chunks = []
            result = self(device.address, device.port, credential.login, credential, None, command,
                          stdout_consumer=feed if stdout_consumer is not None else None, **limits)
            if stdout_consumer is None:
                text = prompt.cleaned(result.stdout.decode(), "fortiadc").encode() if is_adc else result.stdout
            else:
                text = b"".join(chunks)
                incomplete = False
                if is_adc and (frame := prompt.prefix("fortiadc").match(text.decode())) is not None:
                    marker = frame.group(1).rstrip().encode()
                    text = text[len(frame.group(1).encode()):]
                    body, separator, final = text.rstrip().rpartition(b"\n")
                    if separator and final == marker:
                        text = body + b"\n"
                    else:
                        incomplete = True
                if result.rc == 0:
                    for start in range(0, len(text), 7):
                        try:
                            stdout_consumer(text[start:start + 7])
                        except core_ssh.OutputLimitError:
                            raise
                        except Exception:
                            raise core_ssh.OutputConsumerError() from None
                if incomplete:
                    raise session.SessionError("unclosed fixture command", code="disconnected")
                text = b""
            return session.FortinetResult(result.rc, text, "", "t0", "t1")

        cli.run = run
        return nullcontext(cli)


def _family_section(spec, alias, access):
    section = _section()
    section.pop('snmp_credential')
    section['egress']['addresses'] = [ADDRESS[alias]]
    section.update(ssh_platform=spec['enrolled'], enabled_queries=list(spec['queries']),
                   fortios_output_standard_verified=False, configuration_limits=dict(LIMITS),
                   rate_limit={'requests': 30, 'window_seconds': 60})
    section['read_inventory'] = {'interfaces': [], 'services': [], 'addresses': [], 'config_access': list(access)}
    return section


def _inventory(helper, spec, b_access=('read', 'compare')):
    devices = []
    for alias, access in (('router-a', ('read',)), ('router-b', b_access)):
        key = ({'host_key': 'ssh-ed25519 ' + HOST_KEY_BLOB, 'host_key_fingerprint': HOST_KEY_PIN}
               if spec['enrolled'] in {'fortiadc', 'fortios'} else {'host_key_fingerprint': DEVICE_PIN})
        devices.append({'name': alias, 'platform': spec['enrolled'], 'address': ADDRESS[alias], 'port': 22,
                        'role': 'internal', 'credential': alias + '-account', **key,
                        'legacy_ssh': None, 'auditor': None, 'helper': _family_section(spec, alias, access)})
    write_private(helper / 'inventory.json', json.dumps({'version': 2, 'devices': devices}).encode(), replace=True)


def _vault(helper, spec, a_secret, replace=False):
    write_private(helper / 'vault.json', json.dumps({'version': 2, 'credentials': {
        'router-a-account': {'kind': 'password', 'login': 'a-user', 'value': a_secret},
        'router-b-account': {'kind': 'password', 'login': spec.get('b_login', 'b-user'), 'value': spec['b_secret']},
    }}).encode(), replace=replace)


@pytest.fixture(params=FAMILY)
def env(request, tmp_path, monkeypatch):
    platform = request.param
    spec = SPECS[platform]
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    state = tmp_path / 'state'
    helper = state / 'helper'
    helper.mkdir(parents=True, mode=0o700)
    _inventory(helper, spec)
    _vault(helper, spec, A_SECRET)
    monkeypatch.setattr(worker, 'STATE', state)
    monkeypatch.setattr(proxy_module, 'INVENTORY', helper / 'inventory.json')
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(helper / 'operations.jsonl', 'helper'))
    scans = []

    def scan(address, port, pin, timeout, legacy=None):
        scans.append(address)
        return address + ' ' + HOST_KEY
    monkeypatch.setattr(engine.core_hostkey, 'scan', scan)
    wire = Wire(spec)
    monkeypatch.setattr(engine.core_ssh, 'run_command', wire)
    if platform in {'fortiadc', 'fortios'}:
        monkeypatch.setattr(engine.core_session, 'fortinet_session', wire.fortinet_session)
    paged = []
    original = server._paged_auth

    def observed(target, auth_context, redaction_context):
        auth = original(target, auth_context, redaction_context)
        paged.append((target, auth.redaction_secrets))
        return auth
    monkeypatch.setattr(server, '_paged_auth', observed)
    bridge = worker.HelperBridge()
    yield {'platform': platform, 'spec': spec, 'bridge': bridge, 'wire': wire, 'helper': helper,
           'paged': paged, 'scans': scans}
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _call(env, name, arguments):
    return asyncio.run(env['bridge'].call(server.mcp, name, dict(arguments)))


def _read_arguments(env, **options):
    return {'target': 'router-b', 'platform': env['platform'], 'section': 'all', 'include_all': True,
            'redaction': 'full', 'limit': 48000, **options}


def _diff_arguments(env, base, other, **options):
    return {'target': 'router-b', 'platform': env['platform'], 'base_snapshot': base, 'other_snapshot': other,
            **options}


def _ok(result):
    assert result['isError'] is False, result
    data = result['structuredContent']
    assert data.get('error_code') != 'page_changed_by_redaction', data
    assert data['ok'] is True, data
    assert json.loads(result['content'][0]['text']) == data
    assert data['returned_bytes'] == len(data['untrusted_device_output'].encode())
    return data


def _capture(env, config=None):
    env['wire'].config = env['spec']['config'] if config is None else config
    data = _ok(_call(env, 'config_read', _read_arguments(env)))
    assert data['next_offset'] is None and data['platform'] == env['platform']
    return data


def _diff(env, base, other, **options):
    return _call(env, 'config_diff', _diff_arguments(env, base['snapshot_id'], other['snapshot_id'], **options))


def _stored_text(capture):
    text = configuration._SNAPSHOTS[capture['snapshot_id']].text
    return text.page(0, text.total)[0]


def _assert_clean(value, *secrets):
    shown = json.dumps(value, default=repr) + str(value) + repr(value)
    for item in (*secrets, *SENTINELS):
        assert item not in shown


def _refused(result):
    assert result['isError'] is True, result
    return json.loads(result['content'][0]['text'])


def _engine_auth(env):
    """The auth context the real Proxy.request forwards for this platform's config_read, decoded by TargetAuth."""
    message = {'jsonrpc': '2.0', 'id': 'engine-auth', 'method': 'tools/call',
               'params': {'name': 'config_read', 'arguments': _read_arguments(env)}}
    raw = env['bridge'].proxy.request(json.dumps(message).encode())
    assert raw is not None, env['bridge'].proxy.emitted
    return TargetAuth.decode('router-b', json.loads(raw)['params']['arguments']['auth_context'])


def _register_late_secret(env):
    """A's password changes to a word of B's visible text; an allowed read on A registers it in the session."""
    _vault(env['helper'], env['spec'], env['spec']['late'], replace=True)
    _call(env, 'ssh_read', {'target': 'router-a', 'platform': env['platform'], 'query': 'version'})
    assert env['spec']['late'] in env['bridge'].proxy.session_secrets


# ------------------------------------------------------------------------------- positive diffs

def test_identical_captures_and_one_visible_change(env):
    spec, platform = env['spec'], env['platform']
    base = _capture(env)
    same = _capture(env)
    changed = _capture(env, _edit(spec['config'], *spec['visible']))
    ssh = list(env['wire'].calls)
    scans = list(env['scans'])
    assert base['snapshot_id'] != same['snapshot_id'] and base['snapshot_sha256'] == same['snapshot_sha256']
    assert changed['snapshot_sha256'] != base['snapshot_sha256']

    identical = _ok(_diff(env, base, same))
    assert identical['identical'] is True and identical['hidden_lines_compared'] is False
    assert identical['platform'] == platform and identical['target'] == 'router-b'
    assert (identical['base_snapshot'], identical['other_snapshot']) == (base['snapshot_id'], same['snapshot_id'])
    assert identical['untrusted_device_output'] == '' and identical['total_bytes'] == 0
    assert identical['next_offset'] is None
    assert identical['secrets_changed'] == [] and identical['secrets_changed_count'] == 0
    assert identical['next_secret_offset'] is None
    for name, capture in (('base_capture', base), ('other_capture', same)):
        assert identical[name]['redaction_profile'] == capture['redaction_profile']
        assert identical[name]['firmware'] == capture['firmware']
        assert identical[name]['capture_complete'] is True and identical[name]['configuration_complete'] is False
        assert identical[name]['unverified_count'] == capture['unverified_count']

    diff = _ok(_diff(env, base, changed))
    old, new = spec['visible']
    assert diff['identical'] is False and diff['hidden_lines_compared'] is False
    assert diff['untrusted_device_output'] == '--- base\n+++ other\n-' + old + '\n+' + new + '\n'
    assert diff['secrets_changed'] == [] and diff['next_offset'] is None
    # Paged with a small limit: whole lines, joined pages equal the one-page text, no SSH.
    first = _ok(_diff(env, base, changed, limit=40))
    pages, page = [first], first
    while page['next_offset'] is not None:
        page = _ok(_diff(env, base, changed, offset=page['next_offset'], limit=40))
        pages.append(page)
    assert len(pages) > 1 and ''.join(p['untrusted_device_output'] for p in pages) == diff['untrusted_device_output']
    assert all(p['content_sha256'] == diff['content_sha256'] for p in pages)

    # No device contact while comparing; the diff took the private session handoff (_paged_auth).
    assert env['wire'].calls == ssh and env['scans'] == scans
    assert [target for target, _ in env['paged']].count('router-b') == 3 + 2 + len(pages)
    assert all(spec['b_secret'] in secrets for _, secrets in env['paged'])
    _assert_clean([identical, diff, pages], spec['b_secret'])


def test_change_only_in_a_hidden_line_is_not_visible(env):
    spec = env['spec']
    base = _capture(env)
    hidden = _capture(env, _edit(spec['config'], *spec['hidden']))
    ssh = list(env['wire'].calls)
    # The masked line is the same constant marker in both stored texts.
    assert hidden['snapshot_sha256'] == base['snapshot_sha256']
    assert spec['marker'] in _stored_text(base)
    diff = _ok(_diff(env, base, hidden))
    assert diff['identical'] is True and diff['hidden_lines_compared'] is False
    assert diff['untrusted_device_output'] == '' and diff['secrets_changed'] == []
    assert diff['secrets_changed_count'] == 0
    assert env['wire'].calls == ssh
    _assert_clean(diff, spec['b_secret'], 'CHANGED')


# ------------------------------------------------------------------------- incomparable snapshots

# verification (live finding of scenario 191 on X440 EXOS 33.7.1.6): a hidden line added on the same target
# changes the content counts of the capture (unverified_count/credential_redactions); the pair stays
# comparable and the diff shows only the redacted marker line, never its content.  EXOS uses the exact
# change of ref/scenare-191.md, IOS/XE a username secret; NX-OS/EOS a second copy of their hidden line.
ADDED_HIDDEN = {
    'extreme_exos': ('disable ports 12', 'configure ports 10 display-string netops-191'),
    'cisco_ios': ('hostname lab-r1', 'username netops-194 privilege 15 secret 9 $9$SECRET-PASSWORD-SENTINEL'),
    'cisco_xe': ('hostname lab-r1', 'username netops-194 privilege 15 secret 9 $9$SECRET-PASSWORD-SENTINEL'),
}


def _masked(capture):
    return capture['unverified_count'] + capture.get('credential_redactions', 0)


def _hidden_pair(env):
    """(base capture, capture with one more hidden line, the added line)."""
    spec = env['spec']
    anchor, line = ADDED_HIDDEN.get(env['platform'], spec['hidden'])
    base = _capture(env)
    more = _capture(env, _edit(spec['config'], anchor, anchor + '\n' + line))
    return base, more, line


def test_added_hidden_line_is_a_marker_diff_not_incomparable(env):
    spec = env['spec']
    base, more, line = _hidden_pair(env)
    assert _masked(more) == _masked(base) + 1                 # content counts differ, identity does not
    assert more['redaction_profile'] == base['redaction_profile'] and more['firmware'] == base['firmware']
    ssh = list(env['wire'].calls)
    marker = spec['marker']
    for left, right, sign in ((base, more, '+'), (more, base, '-')):
        diff = _ok(_diff(env, left, right))
        assert diff['identical'] is False and diff['hidden_lines_compared'] is False
        assert diff['untrusted_device_output'] == '--- base\n+++ other\n' + sign + marker + '\n', diff
        assert diff['secrets_changed'] == [] and diff['secrets_changed_count'] == 0
        # Each capture keeps its own content counts in the reply.
        assert diff['base_capture']['unverified_count'] == left['unverified_count']
        assert diff['other_capture']['unverified_count'] == right['unverified_count']
        _assert_clean(diff, spec['b_secret'], 'CHANGED', line, 'netops-19', 'display-string')
    assert env['wire'].calls == ssh


def test_hidden_count_change_with_firmware_or_profile_change_stays_incomparable(env):
    base, more, _ = _hidden_pair(env)
    auth = _engine_auth(env)
    stored = configuration._SNAPSHOTS[more['snapshot_id']]
    result = engine.config_diff(auth, env['platform'], base['snapshot_id'], more['snapshot_id'])
    assert result['identical'] is False
    ssh = list(env['wire'].calls)
    for changed in (replace(stored, firmware=stored.firmware[:-1] + ('other-build',)),
                    replace(stored, profile=stored.profile[:-1] + ('0' if stored.profile[-1] != '0' else '1')),
                    replace(stored, include_defaults=not stored.include_defaults),
                    replace(stored, section='other-section')):
        configuration._SNAPSHOTS[more['snapshot_id']] = changed
        configuration._DIFFS.clear()
        with pytest.raises((engine.SnapshotIncomparable, ValueError)) as raised:
            engine.config_diff(auth, env['platform'], base['snapshot_id'], more['snapshot_id'])
        assert str(raised.value) == configuration.INCOMPARABLE
    assert env['wire'].calls == ssh


def test_engine_refuses_firmware_profile_and_scope_mismatch_without_ssh(env):
    base = _capture(env)
    other = _capture(env)
    auth = _engine_auth(env)
    ssh = list(env['wire'].calls)
    platform = env['platform']
    stored = configuration._SNAPSHOTS[other['snapshot_id']]
    result = engine.config_diff(auth, platform, base['snapshot_id'], other['snapshot_id'])
    assert result['identical'] is True and result['hidden_lines_compared'] is False
    for changed in (replace(stored, firmware=stored.firmware[:-1] + ('other-build',)),
                    replace(stored, profile=stored.profile[:-1] + ('0' if stored.profile[-1] != '0' else '1')),
                    replace(stored, metadata=tuple((key, 'other-scope' if key == 'config_scope' else value)
                                                   for key, value in stored.metadata))):
        configuration._SNAPSHOTS[other['snapshot_id']] = changed
        configuration._DIFFS.clear()
        with pytest.raises(engine.SnapshotIncomparable) as raised:
            engine.config_diff(auth, platform, base['snapshot_id'], other['snapshot_id'])
        assert raised.value.code == 'config_snapshot_incomparable' and raised.value.restartable is False
        assert str(raised.value) == configuration.INCOMPARABLE
    configuration._SNAPSHOTS[other['snapshot_id']] = replace(stored, scope=(b'\0' * 32,) + stored.scope[1:])
    configuration._DIFFS.clear()
    with pytest.raises(engine.SnapshotIncomparable) as raised:
        engine.config_diff(auth, platform, base['snapshot_id'], other['snapshot_id'])
    assert raised.value.code == 'config_snapshot_incomparable' and raised.value.restartable is False
    assert str(raised.value) == 'configuration snapshot scope mismatch'
    with pytest.raises(ValueError, match='not found or expired'):
        engine.config_diff(auth, platform, base['snapshot_id'], 'cfg_' + '0' * 32)
    assert env['wire'].calls == ssh


def test_snapshot_of_another_target_is_incomparable_with_a_machine_code(env):
    # Review: a snapshot of another scope (another target) reaches the client with the machine
    # code config_snapshot_incomparable and the unchanged scope mismatch text, not a generic failure.
    spec = env['spec']
    base = _capture(env)
    other = _capture(env)
    stored = configuration._SNAPSHOTS[base['snapshot_id']]
    configuration._SNAPSHOTS[base['snapshot_id']] = replace(stored, scope=(b'\1' * 32,) + stored.scope[1:])
    ssh = list(env['wire'].calls)
    for left, right in ((base, other), (other, base)):
        refused = _diff(env, left, right)
        _assert_clean(refused, spec['b_secret'], 'CHANGED')
        data = refused['structuredContent']
        assert refused['isError'] is True and data['ok'] is False, refused
        assert data['error_code'] == 'config_snapshot_incomparable'
        assert data['error'] == 'configuration snapshot scope mismatch'
        assert 'restart_offset' not in data and 'untrusted_device_output' not in data
    assert env['wire'].calls == ssh


# ---------------------------------------------------------------- session secret after the captures

def test_session_secret_added_after_the_captures_refuses_the_diff(env):
    spec = env['spec']
    base = _capture(env)
    other = _capture(env)
    assert spec['late'] in _stored_text(base)
    first = _ok(_diff(env, base, other))                 # also fills the diff cache of this pair
    assert first['identical'] is True and (base['snapshot_id'], other['snapshot_id']) in configuration._DIFFS
    _register_late_secret(env)
    ssh = [call for call in env['wire'].calls if call[0] == ADDRESS['router-b']]
    for left, right in ((base, other), (other, base)):  # cached pair and a pair not computed yet
        result = _diff(env, left, right)
        _assert_clean(result, spec['b_secret'], spec['late'])
        refused = result['structuredContent']
        assert result['isError'] is True and refused['ok'] is False, result
        assert refused['error_code'] == 'config_snapshot_redaction_changed' and refused['restart_offset'] == 0
        assert 'untrusted_device_output' not in refused and 'content_sha256' not in refused
    assert [call for call in env['wire'].calls if call[0] == ADDRESS['router-b']] == ssh
    assert any(target == 'router-b' and spec['late'] in secrets for target, secrets in env['paged'])

    # A fresh pair redacts the new session secret and compares again.
    fresh = _capture(env)
    again = _capture(env)
    assert spec['late'] not in fresh['untrusted_device_output']
    diff = _ok(_diff(env, fresh, again))
    assert diff['identical'] is True and diff['hidden_lines_compared'] is False
    _assert_clean(diff, spec['b_secret'], spec['late'])


# ------------------------------------------------------------------------- refusals before compare

def test_compare_is_required_in_proxy_and_engine(env):
    base = _capture(env)
    other = _capture(env)
    auth = _engine_auth(env)
    _inventory(env['helper'], env['spec'], b_access=('read',))
    ssh = list(env['wire'].calls)
    error = _refused(_diff(env, base, other))
    assert error['data']['field'] == 'config_access'
    with pytest.raises(ValueError, match='^config access is not enabled for this target$'):
        engine.config_diff(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read',)}),
                           env['platform'], base['snapshot_id'], other['snapshot_id'])
    with pytest.raises(ValueError, match='^config access is not enabled for this target$'):
        engine.config_diff(replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('compare',)}),
                           env['platform'], base['snapshot_id'], other['snapshot_id'])
    assert env['wire'].calls == ssh and not configuration._DIFFS


def test_platform_must_match_the_enrolled_platform_and_the_handoff_stays_private(env):
    base = _capture(env)
    other = _capture(env)
    auth = _engine_auth(env)
    ssh = list(env['wire'].calls)
    for platform in (*(name for name in FAMILY if name != env['platform']), 'fortios', 'fortiadc'):
        error = _refused(_call(env, 'config_diff', {**_diff_arguments(env, base['snapshot_id'], other['snapshot_id']),
                                                    'platform': platform}))
        assert error['data']['field'] == 'platform', platform
        with pytest.raises(ValueError, match='outside target policy'):
            engine.config_diff(auth, platform, base['snapshot_id'], other['snapshot_id'])
    with pytest.raises(ValueError, match='config_platform_not_supported'):
        engine.config_diff(auth, 'exos', base['snapshot_id'], other['snapshot_id'])
    injected = _call(env, 'config_diff', _diff_arguments(env, base['snapshot_id'], other['snapshot_id'],
                                                         redaction_context=['spoofed-value']))
    assert injected['isError'] is True and 'spoofed-value' not in json.dumps(injected)
    descriptors = asyncio.run(env['bridge'].tools(server.mcp))
    schema = {item['name']: item['inputSchema'] for item in descriptors}['config_diff']
    assert 'redaction_context' not in schema.get('properties', {}) and 'auth_context' not in schema.get('properties', {})
    assert env['wire'].calls == ssh and not configuration._DIFFS


def test_proxy_forwards_the_session_handoff_for_this_platform_only(env):
    proxy = env['bridge'].proxy
    message = {'jsonrpc': '2.0', 'id': 'handoff', 'method': 'tools/call',
               'params': {'name': 'config_diff', 'arguments': _diff_arguments(env, 'cfg_' + '0' * 32,
                                                                              'cfg_' + '1' * 32)}}
    raw = proxy.request(json.dumps(message).encode())
    assert raw is not None, proxy.emitted
    arguments = json.loads(raw)['params']['arguments']
    assert env['spec']['b_secret'] in arguments['redaction_context']
    assert arguments['auth_context'] in arguments['redaction_context']
    assert proxy._rate_cost('config_diff', None, proxy._target('router-b')[1],
                            {'platform': env['platform']}) == 1
    assert env['wire'].calls == []


# ------------------------------------------------------------- FortiOS diff output stays unchanged

def _forti_auth():
    return TargetAuth(alias='fixture', host='192.0.2.20', port=22, login='reader', secret='auth-canary-91',
                      host_key_fingerprint='SHA256:fixture', ssh_platform='fortinet',
                      enabled_queries=('system_status',), fortios_output_standard_verified=True,
                      read_inventory={'config_access': ('read', 'compare')},
                      egress=EgressPolicy(addresses=('192.0.2.20',), tcp_ports=(22,)))


def _forti_config(status):
    return 'config system interface\n edit "port1"\n set status ' + status + '\n next\nend\n'


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_fortios_diff_keeps_its_keys_and_plain_refusal(env):
    status = ('Version: FortiGate-VM64-KVM v7.6.7,build3658,260101 (GA)\n'
              'Virtual domain configuration: disable\nCurrent virtual domain: root\n')
    outputs = iter((_forti_config('up'), _forti_config('down')))

    def wire(auth, platform, command, **kwargs):
        if command == 'get system status':
            return 0, status
        kwargs['stdout_consumer'](next(outputs).encode())
        return 0, ''
    auth = _forti_auth()
    with mock.patch.object(engine, 'read_from_device', side_effect=wire):
        first = engine.config_read(auth, 'fortios', 'system interface')
        second = engine.config_read(auth, 'fortios', 'system interface')
    for name in ('fortios', 'fortinet'):
        configuration._DIFFS.clear()
        diff = engine.config_diff(auth, name, first['snapshot_id'], second['snapshot_id'])
        assert list(diff) == ['ok', 'target', 'platform', 'base_snapshot', 'other_snapshot', 'identical',
                              'secrets_changed', 'secret_offset', 'next_secret_offset', 'secrets_changed_count',
                              'untrusted_device_output', 'content_sha256', 'total_bytes', 'returned_bytes',
                              'offset', 'next_offset']
        assert diff['platform'] == 'fortios' and diff['identical'] is False
        assert '-    set status up\n' in diff['untrusted_device_output']
        assert '+    set status down\n' in diff['untrusted_device_output']
    stored = configuration._SNAPSHOTS[second['snapshot_id']]
    configuration._SNAPSHOTS[second['snapshot_id']] = replace(stored, section='firewall policy')
    configuration._DIFFS.clear()
    with pytest.raises(ValueError, match='^configuration snapshot section, firmware or profile mismatch$') as raised:
        engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert not isinstance(raised.value, engine.PaginationRefused)
