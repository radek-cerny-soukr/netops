"""FortiOS retained comparisons via the MCP bridge with a redacted real 60F capture."""
import asyncio
import json
from pathlib import Path
import stat

import pytest

from netops.audit import Audit
from netops_helper import configuration
import test_config_diff_ios_family as family
from test_config_diff_ios_family import SPECS, _call, env  # noqa: F401 (pytest fixture)

ROOT = Path(__file__).resolve().parents[3]
PROJECTED = (ROOT / 'components/netops-admin/tests/fixtures/interface-addressing/fg60f-global.conf').read_text()
CONFIG = PROJECTED.split('\n', 1)[1]
STATUS = json.loads((Path(__file__).parent / 'fixtures/firewall_health_fortios_60f_768.json').read_text())
STATUS = STATUS['members']['probe']['responses']['get system status']
STATUS = '\n'.join(line for line in STATUS.splitlines()
                   if line.startswith(('Version:', 'Virtual domain configuration:')))


@pytest.fixture
def fortios_spec(monkeypatch):
    monkeypatch.setitem(SPECS, 'fortios', dict(
        enrolled='fortios', queries=['system_status'], command='show system interface',
        identity={'show version': STATUS, 'get system status': STATUS}, config=CONFIG,
        b_secret='fixture-only-password'))
    original = family._family_section

    def section(*args):
        return {**original(*args), 'fortios_output_standard_verified': True}

    monkeypatch.setattr(family, '_family_section', section)


def _read(env, **args):
    return _call(env, 'config_read', dict(target='router-b', platform='fortios',
                                        section='system interface', **args))


def _diff(env, first, second, **args):
    return _call(env, 'config_diff', dict(target='router-b', platform='fortios',
                                        base_snapshot=first, other_snapshot=second, **args))


@pytest.mark.parametrize('env', ['fortios'], indirect=True)
def test_history_reloads_and_compares_after_restart(fortios_spec, env, tmp_path, monkeypatch):
    history = tmp_path / 'history'
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(history))
    first = _read(env)['structuredContent']
    assert first['ok'] and first['history_retained']
    saved, = history.glob('*/*.json')
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert 'wan1' not in saved.read_text() and 'fixture-only-password' not in saved.read_text()

    # Recreate the state a restarted process has, including the process-local redaction key.
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    monkeypatch.setattr(configuration, '_KEY', b'\x11' * 32)
    env['wire'].config = CONFIG.replace('        set mode dhcp\n', '        set status down\n        set mode dhcp\n', 1)
    second = _read(env)['structuredContent']
    assert [item['snapshot_id'] for item in second['recent_snapshots']] == [second['snapshot_id'], first['snapshot_id']]
    response = _diff(env, first['snapshot_id'], second['snapshot_id'])['structuredContent']
    assert response['ok'] and not response['identical']
    assert response['hidden_lines_compared'] is False
    assert '+    set status down' in response['untrusted_device_output']

    # Corrupt the older record. The successful result must never come from a stale cached diff.
    saved.write_text(saved.read_text().replace('system interface', 'system changed'))
    assert _diff(env, first['snapshot_id'], second['snapshot_id'])['isError']


@pytest.mark.parametrize('env', ['fortios'], indirect=True)
def test_truncated_capture_is_not_retained(fortios_spec, env, tmp_path, monkeypatch):
    history = tmp_path / 'history'
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(history))
    env['wire'].config = CONFIG.removesuffix('end\n')
    assert _read(env)['isError']
    assert not list(history.glob('*/*.json'))


@pytest.mark.parametrize('env', ['fortios'], indirect=True)
def test_session_secret_is_removed_before_disk_write(fortios_spec, env, tmp_path, monkeypatch):
    history = tmp_path / 'history'
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(history))
    env['bridge'].proxy._remember_session_secrets(('wan1',))
    reply = _read(env, redaction='full')['structuredContent']
    assert reply['ok'] and reply['history_retained']
    saved, = history.glob('*/*.json')
    assert 'wan1' not in reply['untrusted_device_output'] and 'wan1' not in saved.read_text()


@pytest.mark.parametrize('env', ['fortios'], indirect=True)
def test_icap_api_key_is_redacted_in_full_mcp_capture(fortios_spec, env, tmp_path, monkeypatch):
    history = tmp_path / 'history'
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(history))
    env['spec']['command'] = 'show'
    placeholder = 'fixture-icap-api-key-value'
    env['wire'].config = CONFIG + f'''config icap profile
    edit "fixture-profile"
        config icap-headers
            edit 1
                set content "{placeholder}"
                set name "X-API-Key"
            next
            edit 2
                set name "X-Fixture"
                set content "visible-fixture"
            next
        end
    next
end
'''
    reply = _call(env, 'config_read', dict(target='router-b', platform='fortios', section='all',
                                          include_all=True, redaction='full'))
    data = reply['structuredContent']
    assert data['ok'] and data['capture_complete'] and data['history_retained']
    output = data['untrusted_device_output']
    saved, = history.glob('*/*.json')
    audit = Audit(tmp_path / 'gateway-audit', {'mode': 'local'})
    wire_response = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': reply}).encode()
    asyncio.run(audit.record('response', wire_response, 'fixture-icap', decode='response', status=200))
    observations = (wire_response.decode(), saved.read_text(), audit.current.read_text())
    assert all('X-API-Key' in view and 'visible-fixture' in view for view in observations)
    assert not any(placeholder in view for view in observations)
    assert 'set content "<REDACTED:credential#' in output


@pytest.mark.parametrize('damage', ['truncated-json', 'wrong-digest', 'unreadable'])
@pytest.mark.parametrize('env', ['fortios'], indirect=True)
def test_history_excludes_invalid_recent_entries_after_restart(fortios_spec, env, tmp_path, monkeypatch, damage):
    history = tmp_path / 'history'
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(history))
    first = _read(env)['structuredContent']
    assert first['ok'] and first['history_retained']
    saved, = history.glob('*/*.json')
    if damage == 'truncated-json':
        saved.write_text('{')
    elif damage == 'wrong-digest':
        record = json.loads(saved.read_text())
        record['content_sha256'] = '0' * 64
        saved.write_text(json.dumps(record))
    else:
        saved.chmod(0o200)

    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    monkeypatch.setattr(configuration, '_KEY', b'\x11' * 32)
    second = _read(env)['structuredContent']
    assert second['ok'] and second['history_retained']
    assert _diff(env, first['snapshot_id'], second['snapshot_id'])['isError']
    assert [item['snapshot_id'] for item in second['recent_snapshots']] == [second['snapshot_id']]
