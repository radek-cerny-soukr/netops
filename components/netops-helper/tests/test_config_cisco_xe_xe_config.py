"""Public IOS XE configuration replay with captured and redacted XE-CONFIG fixtures."""

import json
from pathlib import Path
import re

import pytest

from netops_core import ssh
from netops.files import write_private
from test_config_cisco_xe_public import _b, _call, _inventory, _page, env

FIXTURES = Path(__file__).parent / 'fixtures/real/cisco_xe/xe-config'
RUNNING = 'show running-config'
STARTUP = 'show startup-config'
NATIVE = 'show archive config differences nvram:startup-config system:running-config'
LIVE = dict(target='router-b', platform='cisco_xe', base_snapshot='startup', other_snapshot='running')


def fixture(name):
    return (FIXTURES / f'{name}.out').read_bytes()


def device(name):
    return {'show version': fixture(f'{name}-version'), RUNNING: fixture(f'{name}-running'),
            STARTUP: fixture(f'{name}-startup'), NATIVE: fixture(f'{name}-native')}


def wire(env, answers, *, native_rc=0):
    calls = []

    def run(_host, _port, _login, _credential, _pin, command, *, stdout_consumer=None, **_options):
        calls.append(command)
        data = answers[command]
        if stdout_consumer is not None:
            for at in range(0, len(data), 73):
                try:
                    stdout_consumer(data[at:at + 73])
                except Exception:
                    raise ssh.OutputConsumerError() from None
            data = b''
        return ssh.Result(rc=native_rc if command == NATIVE else 0, stdout=data, said='',
                          started_at='t0', finished_at='t1')

    env['monkeypatch'].setattr(ssh, 'run_command', run)
    return calls


@pytest.mark.parametrize('node,changed', [('iol-xe-router', True), ('iol-xe-switch', False)])
def test_live_pair_uses_redacted_captures_and_native_status(env, node, changed):
    _inventory(env['helper'], b_access=('read', 'compare'))
    calls = wire(env, device(node))
    live = _page(_call(env, 'config_diff', {**LIVE, 'limit': 160}))
    assert live['unsaved_changes'] is changed
    assert live['comparison_status'] == 'verified'
    assert live['identical'] is not changed
    assert live['hidden_lines_compared'] is False
    assert live['base_capture']['comparison_view'] == 'startup'
    assert live['other_capture']['comparison_view'] == 'running'
    assert calls == ['show version', STARTUP, 'show version', RUNNING, NATIVE]

    startup = _page(_call(env, 'config_read', _b(snapshot_id=live['base_snapshot'])))
    assert startup['command'] == STARTUP and startup['view'] == 'startup'
    if changed:
        assert live['next_offset'] is not None
        continued = _page(_call(env, 'config_diff', {**LIVE, 'base_snapshot': live['base_snapshot'],
                                                   'other_snapshot': live['other_snapshot'],
                                                   'offset': live['next_offset']}))
        assert continued['offset'] == live['next_offset']
    assert len(calls) == 5


@pytest.mark.parametrize('shape', ['separate', 'both', 'mismatched-size', 'contradictory-headers'])
def test_live_pair_with_separate_startup_compression_header(env, shape):
    _inventory(env['helper'], b_access=('read', 'compare'))
    answers = device('iol-xe-switch')

    def compressed_frame(header):
        actual_size = int(header[1])
        first = b'Using 600 out of ' + header[2] + b' bytes'
        if shape in ('both', 'contradictory-headers'):
            inline_size = actual_size + (500 if shape == 'contradictory-headers' else 0)
            first += f', uncompressed size = {inline_size} bytes'.encode()
        size = actual_size + (500 if shape == 'mismatched-size' else 0)
        return first + f'\n\nUncompressed configuration from 600 bytes to {size} bytes'.encode()

    # DERIVED: keep the measured body and declared uncompressed length from the redacted XE-CONFIG capture.
    # https://www.cisco.com/c/dam/en/us/td/docs/switches/lan/catalyst4500/XE3-11-0E/configuration/guide/xe-311-cg.pdf
    answers[STARTUP], changed_headers = re.subn(rb'Using (\d+) out of (\d+) bytes', compressed_frame, answers[STARTUP])
    assert changed_headers == 1
    calls = wire(env, answers)
    result = _call(env, 'config_diff', LIVE)
    if shape in ('separate', 'both'):
        page = _page(result)
        assert page['comparison_status'] == 'verified' and page['unsaved_changes'] is False
        assert NATIVE in calls
    else:
        assert 'base_snapshot' not in (result.get('structuredContent') or {}) and NATIVE not in calls


@pytest.mark.parametrize('model,expected', [('c9300', 'C9300-48P'), ('c9800', None), ('iol-xe-switch', 'Linux')])
def test_other_xe_identities_read_with_firmware_warning(env, model, expected):
    answers = device('iol-xe-switch')
    # For the vendor examples, replay the vendor identity with measured IOS XE configuration framing.
    answers['show version'] = fixture(f'{model}-version')
    wire(env, answers)
    running = _page(_call(env, 'config_read', _b()))
    assert running['capture_complete']
    assert running['firmware']['model'] == expected
    assert running['firmware_support']['status'] == 'untested'


def test_live_pair_requires_compare_permission_before_transport(env):
    calls = wire(env, device('iol-xe-router'))
    result = _call(env, 'config_diff', LIVE)
    assert result['isError'] or not result['structuredContent']['ok']
    assert not calls


def test_config_only_admin_bounded_account(env):
    _inventory(env['helper'], b_access=('read', 'compare'))
    path = env['helper'] / 'inventory.json'
    inventory = json.loads(path.read_bytes())
    section = next(entry['helper'] for entry in inventory['devices'] if entry['name'] == 'router-b')
    section.update(account_role='admin-bounded', role_boundary='catalogue', enabled_queries=[])
    write_private(path, json.dumps(inventory).encode(), replace=True)
    calls = wire(env, device('iol-xe-switch'))
    assert _page(_call(env, 'config_diff', LIVE))['unsaved_changes'] is False
    blocked = _call(env, 'ssh_read', dict(target='router-b', platform='cisco_xe', query='version'))
    assert blocked['isError'] or not blocked['structuredContent']['ok']
    assert len(calls) == 5


@pytest.mark.parametrize('broken', ['incomplete', 'size', 'pager', 'refused'])
def test_running_failure_withholds_both_snapshots(env, broken):
    _inventory(env['helper'], b_access=('read', 'compare'))
    answers = device('iol-xe-switch')
    data = answers[RUNNING]
    answers[RUNNING] = {
        'incomplete': data.rsplit(b'end', 1)[0],
        'size': re.sub(rb'(?m)(?<=Current configuration : )\d+', b'9216', data),
        'pager': data.replace(b'\nend\n', b'\n--More--\nend\n'),
        'refused': fixture('iol-xe-switch-refused'),
    }[broken]
    calls = wire(env, answers)
    result = _call(env, 'config_diff', LIVE)
    payload = result.get('structuredContent') or {}
    assert not payload.get('ok', False)
    assert 'base_snapshot' not in payload and 'other_snapshot' not in payload
    assert NATIVE not in calls


@pytest.mark.parametrize('bad_native', ['truncated', 'refused', 'contradicts'])
def test_bad_native_read_preserves_redacted_comparison(env, bad_native):
    _inventory(env['helper'], b_access=('read', 'compare'))
    answers = device('iol-xe-router')
    answers[NATIVE] = {
        'truncated': answers[NATIVE].rstrip() + b'\nunfinished-context\n',
        'refused': fixture('iol-xe-router-refused'),
        'contradicts': fixture('iol-xe-switch-native'),
    }[bad_native]
    wire(env, answers)
    result = _page(_call(env, 'config_diff', LIVE))
    assert result['comparison_status'] == 'incomplete'
    assert result['unsaved_changes'] is None
    assert result['identical'] is False
    assert 'TP-self-signed' not in str(result)


@pytest.mark.parametrize('operation,arguments', [('config_read', _b()), ('config_diff', LIVE)])
def test_classic_ios_is_refused_before_an_xe_configuration_capture(env, operation, arguments):
    _inventory(env['helper'], b_access=('read', 'compare'))
    answers = device('iol-xe-switch')
    answers['show version'] = (FIXTURES.parents[1] / 'cisco_ios/router-diagnostics/iosv/version.out').read_bytes()
    calls = wire(env, answers)
    result = _call(env, operation, arguments)
    assert result['isError'] or not result['structuredContent']['ok']
    assert calls == ['show version']
