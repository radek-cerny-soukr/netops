"""NX-OS NXOS-PROBES uses real lab captures through a fake physical transport."""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine
from netops_helper.auth import TargetAuth, EgressPolicy
from netops_helper.read_policy import render_read_query, _validate_query_command

REAL = Path(__file__).parent / 'fixtures/real/cisco_nxos/nxos_probes_9.3.12'
INVENTORY = {'vrfs': ('management', 'default', 'NXOS_PROBES_NOT_PRESENT'),
             'addresses': ('192.0.2.1', '192.0.2.55', '::1')}
NAMES = ('ping', 'ping_source', 'traceroute', 'traceroute_source',
         'ping6', 'ping6_source', 'traceroute6', 'traceroute6_source')


def auth():
    return TargetAuth(alias='nx', host='192.0.2.10', port=2255, login='netops-ro', secret='fixture-password',
                      host_key_fingerprint='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                      ssh_platform='cisco_nxos', enabled_queries=NAMES, read_inventory=INVENTORY,
                      egress=EgressPolicy(addresses=('192.0.2.10',)))


def parameters(name):
    ipv6 = '6' in name
    value = {'vrf': 'default' if ipv6 else 'management', 'address': '::1' if ipv6 else '192.0.2.1'}
    if name.endswith('_source'):
        value['source'] = '::1' if ipv6 else '192.0.2.55'
    return value


def physical(monkeypatch, name, text, rc=0):
    calls = []
    command = render_read_query('cisco_nxos', name, parameters(name), INVENTORY)[1]
    def execute(target, profile, cmd, **kwargs):
        calls.append(cmd)
        if cmd == 'show version':
            return 0, (REAL / 'version_ro.out').read_text()
        assert cmd == command
        return rc, text
    monkeypatch.setattr(engine, '_exec_read', execute)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    return calls, command


@pytest.mark.parametrize('name', NAMES)
def test_actual_ro_output(monkeypatch, name):
    body = (REAL / (name + '_ro.out')).read_text()
    calls, command = physical(monkeypatch, name, body)
    result = engine.ssh_read(auth(), 'cisco_nxos', name, parameters(name), 0, 48000)
    assert command in calls
    assert result['ok'] == (name in ('ping', 'ping_source', 'traceroute', 'traceroute_source', 'ping6'))
    if body.strip():
        assert result['untrusted_device_output'].strip() == body.strip()
    if name == 'traceroute6_source':
        assert result['error_code'] == 'device_cli_error'
    if name == 'traceroute6':
        assert result['error_code'] == 'incomplete_output'


@pytest.mark.parametrize('name', NAMES[:4])
def test_actual_admin_output(monkeypatch, name):
    body = (REAL / (name + '_admin.out')).read_text()
    physical(monkeypatch, name, body)
    result = engine.ssh_read(auth(), 'cisco_nxos', name, parameters(name), 0, 48000)
    assert result['ok']


@pytest.mark.parametrize('name', ('ping_source', 'traceroute_source'))
def test_incomplete_real_capture_is_not_success(monkeypatch, name):
    body = (REAL / (name + '_ro.out')).read_text()
    body = body.split('---')[0] if name.startswith('ping') else body.rsplit(' ms', 2)[0]
    physical(monkeypatch, name, body)
    result = engine.ssh_read(auth(), 'cisco_nxos', name, parameters(name), 0, 48000)
    assert not result['ok'] and result['error_code'] == 'incomplete_output'


def test_actual_refusal_even_with_zero_exit(monkeypatch):
    body = (REAL / 'ping_refused_ro.out').read_text()
    physical(monkeypatch, 'ping', body)
    result = engine.ssh_read(auth(), 'cisco_nxos', 'ping', parameters('ping'), 0, 48000)
    assert not result['ok']


@pytest.mark.parametrize('name', NAMES)
@pytest.mark.parametrize('field,value', [('vrf', 'not-enrolled'), ('address', '192.0.2.99'),
                                         ('vrf', 'management;reload'), ('count', '999')])
def test_typed_enrolled_parameters(name, field, value):
    with pytest.raises(ValueError):
        render_read_query('cisco_nxos', name, {**parameters(name), field: value}, INVENTORY)


@pytest.mark.parametrize('name', NAMES)
def test_source_and_family_scope(name):
    bad = {**parameters(name), 'address': '192.0.2.1' if '6' in name else '::1'}
    with pytest.raises(ValueError):
        render_read_query('cisco_nxos', name, bad, INVENTORY)
    if name.endswith('_source'):
        with pytest.raises(ValueError):
            render_read_query('cisco_nxos', name, {**parameters(name), 'source': '192.0.2.99'}, INVENTORY)


@pytest.mark.parametrize('command', ['ping {address}', 'ping {address} vrf {vrf} count 500',
                                    'traceroute {address}', 'traceroute {address} source {source} vrf {vrf}; reload'])
def test_only_reviewed_templates(command):
    with pytest.raises(RuntimeError):
        _validate_query_command('cisco_nxos', command)


def test_probe_must_be_enabled(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, '_exec_read', lambda *a, **kw: pytest.fail('must refuse before device access'))
    with pytest.raises(ValueError):
        engine.ssh_read(replace(auth(), enabled_queries=()), 'cisco_nxos', 'ping', parameters('ping'), 0, 48000)


def test_exec_transport_has_finite_deadline(monkeypatch):
    from netops_core import ssh as core_ssh
    seen = []
    def run(*args, **kwargs):
        seen.append(kwargs['timeout_seconds'])
        raise TimeoutError('timed out')
    monkeypatch.setattr(core_ssh, 'run_command', run)
    with pytest.raises(TimeoutError):
        engine._exec_command(auth(), '192.0.2.10', 'public-host-key', None,
                             'traceroute 192.0.2.1 vrf management', 'cisco_nxos')
    assert seen == [60.0]


def test_nxos_trace_timeout_keeps_complete_hops_from_transport(monkeypatch):
    from netops_core import ssh as core_ssh

    identity = (REAL / 'version_ro.out').read_bytes()
    hops = (REAL / 'traceroute6_ro.out').read_bytes()
    monkeypatch.setattr(engine, 'host_key_line', lambda *args: 'pinned-test-key')
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)

    def run(address, port, login, credential, known_hosts_line, command, **options):
        if command == 'show version':
            return core_ssh.Result(rc=0, stdout=identity, stderr=b'', said='', started_at='', finished_at='')
        assert command == 'traceroute6 ::1 vrf default'
        if receive := options.get('stdout_consumer'):
            receive(hops + b' 5  *')
        raise core_ssh.SshError('ssh to 192.0.2.10 did not finish within 60.0 seconds')

    monkeypatch.setattr(core_ssh, 'run_command', run)
    result = engine.ssh_read(auth(), 'cisco_nxos', 'traceroute6', parameters('traceroute6'), 0, 48000)
    assert not result['ok'] and result['status'] == 'timeout'
    assert not result['complete'] and not result['normalized']['coverage']['complete']
    assert result['untrusted_device_output'] == hops.decode()
