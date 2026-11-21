"""Public Helper configuration operations over the fake SSH wire and VM220 captures."""
from pathlib import Path
import stat

import pytest

from netops_helper import configuration
from test_config_diff_ios_family import SPECS, _call, _ok, env  # noqa: F401


FIXTURES = Path(__file__).parent / 'fixtures' / 'fortiadc_g31'
FULL_EXPORT = Path(__file__).resolve().parents[3] / 'tests/v1/fixtures/fortiadc_7_6_7_full_export.conf'
OBJECTS = (
    ('certificate', 'system certificate local host02', 'set acme-status not_set'),
    ('persistence', 'load-balance persistence LB_PERSIS_SRC_ADDR', 'set type source-address'),
    ('profile', 'load-balance profile LB_PROF_TCP', 'set type tcp'),
    ('ssl-profile', 'load-balance real-server-ssl-profile LB_RS_SSL_PROF_DEFAULT', 'set ssl enable'),
    ('interface', 'system interface port1', 'set allowaccess'),
)


def fixture(name):
    return (FIXTURES / (name + '.out')).read_text()


@pytest.fixture
def adc_spec(monkeypatch):
    status = fixture('status')
    monkeypatch.setitem(SPECS, 'fortiadc', dict(
        enrolled='fortiadc', queries=['system_status'], command='show full-configuration',
        identity={'show version': status, 'get system status': status},
        config=fixture('full-projection'), b_login='user01', b_secret='fixture-only-ssh-password'))


def read(env, section='all', defaults=True):
    return _call(env, 'config_read', dict(target='router-b', platform='fortiadc', section=section,
                                         include_all=section == 'all', include_defaults=defaults,
                                         redaction='full'))


def diff(env, first, second):
    return _call(env, 'config_diff', dict(target='router-b', platform='fortiadc',
                                         base_snapshot=first, other_snapshot=second))


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
@pytest.mark.parametrize('name,section,expected', OBJECTS)
def test_named_object(adc_spec, env, name, section, expected):
    command = 'show full-configuration ' + section
    env['spec']['command'] = command
    env['wire'].config = fixture(name)
    result = _ok(read(env, section))
    assert expected in result['untrusted_device_output']
    if name == 'certificate':
        assert 'G31-FIXTURE-ONLY-PASSWORD' not in result['untrusted_device_output']
        assert 'set private-key-file fixture-key.pem' in result['untrusted_device_output']
    assert result['capture_complete'] and not result['configuration_complete']
    assert result['firmware_support']['status'] == 'tested'
    assert [call[1] for call in env['wire'].calls] == ['get system status', command]


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
@pytest.mark.parametrize('name,section,defaults', [
    ('absent', 'load-balance profile netops-g31-does-not-exist', True),
    ('defaults-omitted', 'load-balance profile LB_PROF_TCP', False),
    ('truncated', 'load-balance profile LB_PROF_TCP', True),
    ('no-final-prompt', 'load-balance profile LB_PROF_TCP', True),
])
def test_object_without_confirmed_scope_is_withheld(adc_spec, env, name, section, defaults):
    command = ('show full-configuration ' if defaults else 'show ') + section
    env['spec']['command'] = command
    if name == 'truncated':
        env['wire'].config = fixture('profile').split('  next\n')[0]
    elif name == 'no-final-prompt':
        env['wire'].config = fixture('profile').rsplit('\n', 2)[0] + '\n'
    else:
        env['wire'].config = fixture(name)
    result = read(env, section, defaults)
    assert result['isError']
    assert 'untrusted_device_output' not in result.get('structuredContent', {})
    if name == 'defaults-omitted':
        assert 'include_defaults=true' in result['content'][0]['text']


@pytest.fixture
def backup(tmp_path, monkeypatch):
    root = tmp_path / 'history'
    key = tmp_path / 'fortiadc.key'
    key.write_bytes(b'\x18' * 32)
    key.chmod(0o600)
    monkeypatch.setenv('NETOPS_CONFIG_HISTORY_DIR', str(root))
    monkeypatch.setenv('NETOPS_FORTIADC_BACKUP_KEY_FILE', str(key))
    return root, key


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_encrypted_archive_survives_process_restart(adc_spec, env, backup, monkeypatch):
    root, key = backup
    first = _ok(read(env))
    assert first['history_retained']
    archive, = root.glob('*/*.aesgcm')
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert b'load-balance persistence' not in archive.read_bytes()

    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    monkeypatch.setattr(configuration, '_KEY', b'\x11' * 32)
    # Derived: a single visible setting changes in the real CLI projection.
    original = fixture('full-projection')
    env['wire'].config = original.replace('    set timeout 300\n', '    set timeout 310\n', 1)
    assert env['wire'].config != original
    second = _ok(read(env))
    assert [item['snapshot_id'] for item in second['recent_snapshots']] == [second['snapshot_id'], first['snapshot_id']]
    result = _ok(diff(env, first['snapshot_id'], second['snapshot_id']))
    assert result['hidden_lines_compared'] is False
    assert result['untrusted_device_output'] == '--- base\n+++ other\n-    set timeout 300\n+    set timeout 310\n'

    key.write_bytes(b'\x19' * 32)
    assert diff(env, first['snapshot_id'], second['snapshot_id'])['isError']
    assert archive.is_file()


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_archive_refuses_balanced_capture_without_terminal_prompt(adc_spec, env, backup):
    root, _ = backup
    env['wire'].config = fixture('full-projection').rsplit('\n', 2)[0] + '\n'
    assert read(env)['isError']
    assert not list(root.glob('*/*.aesgcm'))


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
@pytest.mark.parametrize('omission', ['after-global', 'interface', 'tail'])
def test_archive_refuses_partial_capture_with_terminal_prompt(adc_spec, env, backup, omission):
    root, _ = backup
    original = fixture('full-projection')
    lines = original.splitlines(keepends=True)
    # Derived from VM220: remove complete blocks while preserving the actual prompts.
    if omission == 'after-global':
        env['wire'].config = ''.join([*lines[:2], lines[-1]])
    elif omission == 'interface':
        env['wire'].config = original.replace('config system interface\nend\n', '', 1)
    else:
        env['wire'].config = ''.join([*lines[:-3], lines[-1]])
    result = read(env)
    assert result['isError']
    data = result.get('structuredContent') or {}
    assert not data.get('capture_complete') and not data.get('history_retained')
    assert not list(root.glob('*/*.aesgcm'))


@pytest.fixture
def visibility_pair(adc_spec, env, backup):
    prompt = fixture('full-projection').splitlines()[-1]
    original = FULL_EXPORT.read_text()
    env['wire'].config = f'{prompt} {original}{prompt}\n'
    first = _ok(read(env))
    assert first['capture_complete'] and first['history_retained']
    assert 'access-profile-unverified' not in first['visibility_limitations']
    assert 'load-balance' not in first['visibility_limitations']
    configuration._SNAPSHOTS.clear()

    # Model the same account after its VM220 profile loses visibility of the load-balance area.
    right = '    set load-balance read\n'
    assert original.count(right) == 1
    limited = original.replace(right, '    set load-balance none\n')
    visible, depth, hidden = [], 0, False
    for line in limited.splitlines(keepends=True):
        command = line.strip()
        if command.startswith('config '):
            if depth == 0:
                hidden = command.startswith('config load-balance ')
            depth += 1
        if not hidden:
            visible.append(line)
        if command == 'end':
            depth -= 1
            if depth == 0:
                hidden = False
    assert depth == 0
    assert len(visible) < len(limited.splitlines())
    env['wire'].config = f'{prompt} {"".join(visible)}{prompt}\n'
    second = _ok(read(env))
    assert second['capture_complete'] and second['history_retained']
    assert 'load-balance' in second['visibility_limitations']
    return first, second


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_diff_rejects_changed_account_visibility(visibility_pair, env):
    first, second = visibility_pair
    refused = diff(env, first['snapshot_id'], second['snapshot_id'])
    assert refused['isError']
    data = refused['structuredContent']
    assert data['error_code'] == 'config_snapshot_incomparable'
    assert data['error'] == 'configuration snapshot account visibility mismatch'
    assert 'untrusted_device_output' not in data


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_recent_history_excludes_changed_account_visibility(visibility_pair):
    _, latest = visibility_pair
    assert [item['snapshot_id'] for item in latest['recent_snapshots']] == [latest['snapshot_id']]


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_archive_diff_and_recent_history_ignore_content_summary(adc_spec, env, backup):
    # The complete VM220 export is an anonymized/redacted Helper capture. Restore its SSH framing.
    prompt = fixture('full-projection').splitlines()[-1]
    original = FULL_EXPORT.read_text()
    removed = '    set ssl-ciphers <UNVERIFIED:unclassified-field>\n'
    assert original.count(removed) == 1
    env['wire'].config = f'{prompt} {original}{prompt}\n'
    first = _ok(read(env))
    assert first['capture_complete'] and first['history_retained']
    configuration._SNAPSHOTS.clear()

    # The second full capture differs by one unclassified field in LB_HLTHCK_HTTPS.
    env['wire'].config = f'{prompt} {original.replace(removed, "", 1)}{prompt}\n'
    second = _ok(read(env))
    assert second['capture_complete'] and second['history_retained']
    assert first['unverified_count'] == second['unverified_count'] + 1
    result = _ok(diff(env, first['snapshot_id'], second['snapshot_id']))
    assert result['untrusted_device_output'] == f'--- base\n+++ other\n-{removed}'
    assert result['base_capture']['unverified_count'] == first['unverified_count']
    assert result['other_capture']['unverified_count'] == second['unverified_count']
    assert [item['snapshot_id'] for item in second['recent_snapshots']] == [second['snapshot_id'], first['snapshot_id']]


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_archive_reads_legacy_filename_for_a_complete_capture(adc_spec, env, backup, monkeypatch):
    root, _ = backup
    first = _ok(read(env))
    archive, = root.glob('*/*.aesgcm')
    identity = first['snapshot_id']
    shape = configuration._history_shape(configuration._SNAPSHOTS[identity], legacy_fortiadc=True)
    previous = archive.with_name(f'{identity}-{shape}.aesgcm')
    assert archive != previous
    archive.rename(previous)
    configuration._SNAPSHOTS.clear()
    monkeypatch.setattr(configuration, '_KEY', b'\x11' * 32)

    second = _ok(read(env))
    assert [item['snapshot_id'] for item in second['recent_snapshots']] == [second['snapshot_id'], identity]
    assert _ok(diff(env, identity, second['snapshot_id']))['identical']
    assert previous.is_file()


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_archive_retains_only_newest_authenticated_captures(adc_spec, env, backup, monkeypatch):
    root, _ = backup
    monkeypatch.setattr(configuration, '_HISTORY_COUNT', 2)
    first, second, third = (_ok(read(env)) for _ in range(3))
    assert len(list(root.glob('*/*.aesgcm'))) == 2
    assert [item['snapshot_id'] for item in third['recent_snapshots']] == [third['snapshot_id'], second['snapshot_id']]
    configuration._SNAPSHOTS.clear()
    assert diff(env, first['snapshot_id'], third['snapshot_id'])['isError']
    assert _ok(diff(env, second['snapshot_id'], third['snapshot_id']))['identical']


@pytest.mark.parametrize('env', ['fortiadc'], indirect=True)
def test_archive_does_not_keep_the_proxy_session_secret(adc_spec, env, backup):
    env['bridge'].proxy._remember_session_secrets(('source-address',))
    first = _ok(read(env))
    assert first['history_retained']
    assert 'set type source-address\n' not in first['untrusted_device_output']

    configuration._SNAPSHOTS.clear()
    env['bridge'].proxy.session_secrets.clear()
    second = _ok(read(env))
    result = _ok(diff(env, first['snapshot_id'], second['snapshot_id']))
    assert '-    set type source-address\n' not in result['untrusted_device_output']
    assert '+    set type source-address\n' in result['untrusted_device_output']
