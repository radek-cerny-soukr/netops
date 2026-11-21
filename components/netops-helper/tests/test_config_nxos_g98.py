"""Public Helper reads over the pinned SSH fake using G98 lab captures."""
import json

import pytest

from netops.files import write_private
from netops_core import ssh
from netops_helper import configuration
from netops_helper.config_cisco_nxos_adapter import DIFF_COMMAND, STARTUP_COMMAND
from test_config_cisco_nxos_public import (
    B_SECRET, REAL, VERSION, _assert_clean, _b, _call, _inventory, _page, _refused, env,
)

FIXTURES = REAL / 'cisco_nxos/g98_9.3.12'
IDENTITIES = REAL.parent / 'identity'
CHANGED = (REAL.parents[3] / 'netops-admin/tests/fixtures/nxos_9_3_12/'
           'show-running-config-diff__unsaved.txt').read_bytes()
RUNNING = 'show running-config'
STARTUP = STARTUP_COMMAND
DIFF = {'target': 'router-b', 'platform': 'cisco_nxos', 'base_snapshot': 'startup', 'other_snapshot': 'running'}
COMMANDS = ['show version', STARTUP + ' | count', STARTUP, 'show version', RUNNING + ' | count', RUNNING, DIFF_COMMAND]


@pytest.fixture
def lab(env, monkeypatch):
    def configure(node='b04-nx-a', *, same_running_generation=False):
        _inventory(env['helper'], b_access=('read', 'compare'))
        path = env['helper'] / 'inventory.json'
        inventory = json.loads(path.read_bytes())
        helper = inventory['devices'][1]['helper']
        helper.update(account_role='admin-bounded', role_boundary='catalogue', enabled_queries=[])
        helper.pop('sftp_roots', None)
        write_private(path, json.dumps(inventory).encode(), replace=True)
        replies = {'show version': (0, VERSION.encode())}
        for label, command in (('startup', STARTUP), ('running', RUNNING), ('count-startup', STARTUP + ' | count'),
                               ('count-running', RUNNING + ' | count'), ('native-diff', DIFF_COMMAND)):
            path = FIXTURES / f'{node}-{label}.out'
            replies[command] = (0, path.read_bytes() if path.exists() else CHANGED)
        if same_running_generation:
            # The d-nxos configuration changed before its separate count read. Derive the count
            # for the earlier capture to test the difference while holding that generation fixed.
            running_lines = replies[RUNNING][1].count(b'\n')
            replies[RUNNING + ' | count'] = (0, f'{running_lines}\n'.encode())
        commands = []

        def exec_command(host, port, login, credential, host_key_line, command, *, stdout_consumer=None, **options):
            commands.append(command)
            rc, data = replies[command]
            if stdout_consumer is not None:
                for offset in range(0, len(data), 47):
                    try:
                        stdout_consumer(data[offset:offset + 47])
                    except Exception:
                        raise ssh.OutputConsumerError() from None
                data = b''
            return ssh.Result(rc=rc, stdout=data, said='', started_at='t0', finished_at='t1')

        monkeypatch.setattr(ssh, 'run_command', exec_command)
        return replies, commands

    return configure


@pytest.mark.parametrize(('source', 'model', 'version'), [
    ('cisco_nxos.txt', 'Nexus9000 C9336C-FX2', '10.5(4)(M)'),
    ('full_cisco_nxos_n5548.txt', 'Nexus5548', '5.1(3)N2(1)'),
])
def test_physical_identity_warns_on_public_running_snapshots(env, lab, source, model, version):
    replies, commands = lab()
    replies['show version'] = (0, (IDENTITIES / source).read_bytes())
    first = _page(_call(env, 'config_read', _b()))
    second = _page(_call(env, 'config_read', _b()))
    result = _page(_call(env, 'config_diff', {**DIFF, 'base_snapshot': first['snapshot_id'],
                                             'other_snapshot': second['snapshot_id']}))
    assert first['firmware'] == {'model': model, 'version': version}
    assert first['firmware_support']['status'] == 'untested'
    assert first['warnings'][0]['code'] == 'firmware_untested'
    assert 'interface Ethernet1/48' in first['untrusted_device_output']
    assert result['identical'] is True
    assert result['firmware_support'] == first['firmware_support']
    assert result['warnings'] == first['warnings']
    assert commands == ['show version', RUNNING] * 2


@pytest.mark.parametrize('node', ['b04-nx-a', 'b04-nx-b'])
def test_saved_lab_configs_have_verified_no_changes(env, lab, node):
    _, commands = lab(node)
    result = _page(_call(env, 'config_diff', DIFF))
    assert commands == COMMANDS
    assert result['unsaved_changes'] is False
    assert result['identical'] is True
    assert result['comparison_status'] == 'verified'
    assert result['hidden_lines_compared'] is False
    assert result['base_capture']['comparison_view'] == 'startup'
    assert result['other_capture']['comparison_view'] == 'running'
    continued = _page(_call(env, 'config_diff', {**DIFF, 'base_snapshot': result['base_snapshot'],
                                                'other_snapshot': result['other_snapshot']}))
    assert continued['identical'] is True and commands == COMMANDS


def test_visible_difference_and_native_context_do_not_expose_secrets(env, lab):
    replies, commands = lab('d-nxos', same_running_generation=True)
    # The real context diff uses a different live change; inject a harmless canary in its masked username field.
    secret = b'fixture-key-never-in-diff'
    replies[DIFF_COMMAND] = (0, CHANGED.replace(b'<REDIGOVANO>', secret))
    rc, running = replies[RUNNING]
    # Preserve framing/count while using a credential-bearing line in place of an opaque lab row.
    replies[RUNNING] = (rc, running.replace(b'<UNVERIFIED:cisco-nxos-opaque-line>\n',
                                          b'username fixture password 5 ' + secret + b' role network-admin\n', 1))
    response = _call(env, 'config_diff', {**DIFF, 'limit': 120})
    result = _page(response)
    assert result['unsaved_changes'] is True
    assert result['comparison_status'] == 'verified'
    assert result['identical'] is False
    assert commands == COMMANDS
    pages = []
    for _ in range(20):
        pages.append(result['untrusted_device_output'])
        _assert_clean(result, secret.decode(), B_SECRET, 'password 5', '*** Startup-config')
        if result['next_offset'] is None:
            break
        result = _page(_call(env, 'config_diff', {**DIFF, 'base_snapshot': result['base_snapshot'],
                                                 'other_snapshot': result['other_snapshot'],
                                                 'limit': 120, 'offset': result['next_offset']}))
    assert result['next_offset'] is None
    assert '+  channel-group 140 mode active' in ''.join(pages)
    assert commands == COMMANDS


@pytest.mark.parametrize('scenario', ['aux-refused', 'aux-truncated', 'aux-contradicts-visible-diff'])
def test_auxiliary_native_failure_keeps_redacted_comparison(env, lab, scenario):
    replies, _ = lab('d-nxos', same_running_generation=True)
    replies[DIFF_COMMAND] = {'aux-refused': (30, b'Cmd exec error.\n'),
                             'aux-truncated': (0, CHANGED.rsplit(b'\n', 2)[0] + b'\n'),
                             'aux-contradicts-visible-diff': (0, b'')}[scenario]
    result = _page(_call(env, 'config_diff', DIFF))
    assert result['comparison_status'] == 'incomplete'
    assert result['unsaved_changes'] is None
    assert 'channel-group 140 mode active' in result['untrusted_device_output']


def test_native_difference_can_be_entirely_masked(env, lab):
    replies, _ = lab()
    replies[DIFF_COMMAND] = (0, CHANGED)
    result = _page(_call(env, 'config_diff', DIFF))
    assert result['unsaved_changes'] is True and result['identical'] is True
    assert result['hidden_lines_compared'] is False
    assert result['untrusted_device_output'] == ''


def test_real_count_mismatch_discards_both_captures(env, lab):
    _, commands = lab('d-nxos')
    result = _call(env, 'config_diff', DIFF)['structuredContent']
    assert result['ok'] is False and result['error_code'] == 'stream-incomplete'
    assert commands == COMMANDS[:-1]
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize('scenario', ['refused', 'newline-truncated', 'pager', 'invalid-count'])
def test_refused_or_partial_startup_has_no_pages_or_snapshot(env, lab, scenario):
    replies, _ = lab()
    rc, startup = replies[STARTUP]
    expected = 'stream-incomplete'
    if scenario == 'refused':
        replies[STARTUP] = (30, (FIXTURES / 'd-nxos-startup-refused.out').read_bytes())
        expected = 'device-refused'
    elif scenario == 'newline-truncated':
        replies[STARTUP] = (rc, b'\n'.join(startup.split(b'\n')[:80]) + b'\n')
    elif scenario == 'pager':
        replies[STARTUP] = (rc, startup.replace(b'hostname ', b'--More-- ', 1))
        expected = 'redaction-unverifiable'
    else:
        replies[STARTUP + ' | count'] = (0, b'')
    response = _call(env, 'config_diff', DIFF)
    result = response['structuredContent']
    assert result['ok'] is False and result['error_code'] == expected
    assert not configuration._SNAPSHOTS
    assert 'untrusted_device_output' not in result


def test_public_admission_and_rate_cost(env, lab):
    assert _refused(_call(env, 'config_diff', DIFF))['data']['field'] == 'config_access'
    _, commands = lab()
    proxy = env['bridge'].proxy
    assert proxy._rate_cost('config_diff', None, None, DIFF) == 7
    assert _refused(_call(env, 'config_diff', {**DIFF, 'offset': 1}))['data']['field'] == 'offset'
    probe = _call(env, 'ssh_read', {'target': 'router-b', 'platform': 'cisco_nxos', 'query': 'version'})
    assert _refused(probe)['data']['field'] == 'account_role'
    assert commands == []


@pytest.mark.parametrize(('field', 'value'), [('enabled_queries', ['version']), ('sftp_roots', ['/safe'])])
def test_privileged_enrollment_rejects_other_access(env, lab, field, value):
    _, commands = lab()
    path = env['helper'] / 'inventory.json'
    inventory = json.loads(path.read_bytes())
    inventory['devices'][1]['helper'][field] = value
    write_private(path, json.dumps(inventory).encode(), replace=True)
    assert _refused(_call(env, 'config_read', _b()))['data']['category'] == 'role_rejected'
    assert commands == []
