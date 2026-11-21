"""Z1's uncovered engine handlers, through real contexts, captures and storage.

Only device/session backends and failures of the snapshot store are substituted;
engine navigation, identity checks, stream processing and refusal handling run.
"""
from dataclasses import replace

import pytest

from netops_core import ssh as core_ssh
from netops_helper import configuration, engine
import test_config_exos_public as exos
import test_config_cisco_ios_public as ios
from test_config_exos_public import env as exos_env
from test_config_cisco_ios_public import env as ios_env
from test_fortios_multivdom import device, fortigate, ROOT_STATUS


def _failure(message, call, kind=ValueError):
    with pytest.raises(kind) as caught:
        call()
    assert message in str(caught.value)
    assert configuration._SNAPSHOTS == {}
    return caught.value


def test_unclassified_capture_backend_failure_is_withheld(ios_env):
    auth = ios._engine_auth(ios_env)
    original = ios.Wire()

    def failed(*args, **options):
        if options.get('stdout_consumer') is not None:
            raise RuntimeError('backend lost its local stream')
        return original(*args, **options)

    ios_env['monkeypatch'].setattr(engine.core_ssh, 'run_command', failed)
    _failure('transport-failed during capture', lambda: ios._read(auth))


@pytest.mark.parametrize('family', ['exos', 'ios'])
def test_capture_preserves_a_transport_budget_refusal(request, family):
    module = exos if family == 'exos' else ios
    env = request.getfixturevalue(family + '_env')
    auth = exos._auth(env) if family == 'exos' else ios._engine_auth(env)
    original = module.Wire()
    refusal = configuration.ConfigurationBudgetError('fixture transport budget exhausted')

    def exhausted(*args, **options):
        if options.get('stdout_consumer') is not None:
            raise refusal
        return original(*args, **options)

    env['monkeypatch'].setattr(engine.core_ssh, 'run_command', exhausted)
    caught = _failure('fixture transport budget exhausted', lambda: module._read(auth),
                      configuration.ConfigurationBudgetError)
    assert caught is refusal


@pytest.mark.parametrize('family', ['exos', 'ios'])
def test_out_of_memory_while_storing_capture_withholds_it(request, family):
    module = exos if family == 'exos' else ios
    env = request.getfixturevalue(family + '_env')
    auth = exos._auth(env) if family == 'exos' else ios._engine_auth(env)
    env['monkeypatch'].setattr(engine.core_ssh, 'run_command', module.Wire())
    attempts = []

    def out_of_memory(*args, **options):
        attempts.append(options['platform'])
        raise MemoryError('snapshot store allocation failed')

    env['monkeypatch'].setattr(configuration, 'store', out_of_memory)
    _failure('capture-failed', lambda: module._read(auth))
    assert attempts == ['extreme_exos' if family == 'exos' else 'cisco_ios']


def test_ios_fresh_snapshot_is_discarded_if_its_requested_view_is_stale(ios_env):
    auth = ios._engine_auth(ios_env)
    _failure('filter changed; restart at offset 0',
             lambda: engine._ios_capture(auth, 'all', True, '', 0, 48000, 'full', False,
                                         ('interface', 0, None, '0' * 64)))
    assert ios_env['wire'].commands() == ['show version', 'show running-config']


@pytest.mark.parametrize('global_read', [False, True])
def test_context_login_failure_uses_enrolled_key_without_scan_or_retry(monkeypatch, global_read):
    attempts = []

    def fail_login(device, credential, **options):
        attempts.append((device.host_key, device.host_key_fingerprint))
        raise engine.core_session.SessionError('connection closed before prompt', code='disconnected')

    def unexpected_scan(*args, **options):
        pytest.fail('FortiOS context read attempted a host-key scan')

    monkeypatch.setattr(engine.core_session, 'fortinet_session', fail_login)
    monkeypatch.setattr(engine.core_hostkey, 'scan', unexpected_scan)
    auth = fortigate('arp_table')
    address = engine._resolve_target_ipv4(auth)[0]
    key = (address, auth.port, auth.host_key_fingerprint)
    engine._HOST_KEY_LINE_CACHE[key] = (engine._now() + 60, 'stale')
    call = (lambda: engine._global_context_read(auth, 'fortinet', 'get system performance status')) if global_read else (
        lambda: engine._vdom_context_read(auth, 'fortinet', 'root', ('get system arp',)))
    with engine._fortinet_operation(auth):
        for _ in range(2):
            with pytest.raises(engine.core_session.SessionError, match='connection closed') as error:
                call()
            assert error.value.code == 'disconnected'
    assert auth.host_key is not None
    assert attempts == [(auth.host_key, auth.host_key_fingerprint)]


@pytest.mark.parametrize('global_read', [False, True])
def test_a_failed_context_exit_still_closes_the_session(device, monkeypatch, global_read):
    replay = device('197-34-gdiag-global' if global_read else '512-A-root-arp', override={
        ('FortiGate-60F (global) # ', 'get system performance status'): ('CPU states: 1% user\n',
                                                                       'FortiGate-60F (global) # ')})
    factory = replay.session
    events = []

    def session(*args, **options):
        original = factory(*args, **options)

        class ExitFails(type(original)):
            def send(self, command):
                if command == 'end':
                    events.append('end')
                    raise engine.core_session.SessionError('connection lost on context exit')
                return super().send(command)

            def close(self):
                events.append('close')
                return super().close()

            def __exit__(self, *exc):
                events.append('exit')
                return super().__exit__(*exc)

        original.__class__ = ExitFails
        return original

    monkeypatch.setattr(engine.core_session, 'fortinet_session', session)
    auth = fortigate('arp_table')
    if global_read:
        rc, text = engine._global_context_read(auth, 'fortinet', 'get system performance status')
        assert rc is None and text == 'CPU states: 1% user'
    else:
        rc, text, index, extras = engine._vdom_context_read(auth, 'fortinet', 'root', ('get system arp',))
        assert rc is None and index == 0 and not extras
        assert text
    assert events == ['end', 'close', 'exit']


def test_refused_vdom_edit_is_a_context_refusal_before_the_read(device):
    replay = device('512-A-root-arp', override={
        ('FortiGate-60F (vdom) # ', 'edit root'): (
            'Command fail. Return code -61\n', 'FortiGate-60F (vdom) # ')})
    with pytest.raises(engine.fortios_vdom.VdomRefused) as caught:
        engine._vdom_context_read(fortigate('arp_table'), 'fortinet', 'root', ('get system arp',))
    assert caught.value.code == 'vdom_context_unverified'
    assert 'get system arp' not in replay.sent


def test_triage_does_not_assign_interfaces_from_a_malformed_membership(device):
    from test_fortios_multivdom import _health_device, _health_target
    replay = _health_device(device, '517-A-root-physical', '514-A-root-intfshow')
    replay.answers[('FortiGate-60F (root) # ', 'show system interface')] = (
        'config system interface\n edit port1\n next\nend\n', 'FortiGate-60F (root) # ')
    result = engine.triage_health(_health_target('interface_vlan_ids'))
    assert {'step': 'physical_interfaces', 'reason': 'vdom_membership_unverified'} in result['missing']
    assert result['chain']['links']['physical'] is None


def test_locate_with_an_unenrolled_session_vdom_returns_a_scope_refusal(device):
    device('512-A-root-arp', status=ROOT_STATUS)
    auth = fortigate('system_status', 'arp_table', 'mac_table', 'lldp_neighbors', 'interfaces', vdoms=('other',))
    result = engine._locate_endpoint_run([auth], '192.0.2.10')
    assert result['verdict'] == 'incomplete'
    assert any(item.get('error_code') == 'vdom_scope_required' for item in result['missing'])
    assert not result['findings']


def test_ios_identity_backend_exception_withholds_the_capture(ios_env):
    auth = ios._engine_auth(ios_env)
    calls = []

    def failed(*args, **options):
        calls.append(args[5])
        raise RuntimeError('identity channel unavailable')

    ios_env['monkeypatch'].setattr(engine.core_ssh, 'run_command', failed)
    _failure('transport-failed during identity read', lambda: ios._read(auth))
    assert calls == ['show version']


def test_ios_classified_capture_failure_returns_only_the_transport_cause(ios_env):
    auth = ios._engine_auth(ios_env)
    original = ios.Wire()

    def disconnected(*args, **options):
        if options.get('stdout_consumer') is not None:
            raise core_ssh.SshError('Connection closed by remote host.')
        return original(*args, **options)

    ios_env['monkeypatch'].setattr(engine.core_ssh, 'run_command', disconnected)
    result = ios._read(auth)
    assert result['ok'] is False and result['error_code'] == 'disconnected'
    assert result['error'] == engine._TRANSPORT_ADVICE['disconnected']
    assert 'untrusted_device_output' not in result and 'snapshot_id' not in result
    assert not configuration._SNAPSHOTS
