"""PLATFORM-BASELINE durable approvals through the public Helper bridge.

Success scenarios reuse the explicitly SYNTHETIC configurations of the pre-existing
public config_diff tests; they do not constitute U-H evidence of successful live capture.
Real RO identity/refusal fixtures are replayed at the SSH transport boundary below.
"""
from dataclasses import replace
import json
from pathlib import Path
import secrets

import pytest

from netops_helper import configuration, engine
from netops_helper.auth import TargetAuth
from test_config_diff_ios_family import env, _call, _read_arguments, _family_section, SPECS, _inventory, _register_late_secret
from test_config_cisco_ios_public import _page

REAL = Path(__file__).parent / 'fixtures' / 'real' / 'platform_baseline_20261117'


@pytest.fixture(autouse=True)
def durable_directory(tmp_path, monkeypatch):
    directory = tmp_path / 'baselines'
    monkeypatch.setenv('NETOPS_CONFIG_BASELINE_DIR', str(directory))
    return directory


def read(env, **options):
    return _page(_call(env, 'config_read', _read_arguments(env, **options)))


def approve(env, capture):
    return read(env, snapshot_id=capture['snapshot_id'], content_sha256=capture['content_sha256'], approve_baseline=True)


def diff(env, capture, **options):
    return _page(_call(env, 'config_diff', dict(target='router-b', platform=env['platform'],
                    base_snapshot='baseline', other_snapshot=capture['snapshot_id'], **options)))


def test_approval_survives_restart_ttl_and_changes(env, durable_directory, monkeypatch):
    first = read(env)
    saved = approve(env, first)
    assert saved['baseline_approved'] is True
    assert saved['baseline_sha256'] == first['content_sha256']
    assert saved['hidden_lines_compared'] is False
    assert diff(env, first)['identical'] is True
    files = list(durable_directory.glob('*.json'))
    assert len(files) == 1
    assert files[0].stat().st_mode & 0o777 == 0o600
    assert durable_directory.stat().st_mode & 0o777 == 0o700
    disk = files[0].read_text()
    assert env['spec']['b_secret'] not in disk and 'SECRET-' not in disk
    assert 'hidden' not in json.loads(disk) and 'scope' not in json.loads(disk)
    # Simulate a new Helper's empty caches, new scope/redaction key and a later day.
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    monkeypatch.setattr(configuration, '_KEY', secrets.token_bytes(32))
    clock = configuration.time.monotonic
    monkeypatch.setattr(configuration.time, 'monotonic', lambda: clock() + 3 * 86400)
    current = read(env)
    same = diff(env, current)
    assert same['identical'] is True and same['hidden_lines_compared'] is False
    assert same['baseline_snapshot'] == first['snapshot_id']
    assert same['baseline_approved_at'] == saved['baseline_approved_at']
    before, after = env['spec']['visible']
    env['wire'].config = env['wire'].config.replace(before, after)
    current = read(env)
    changed = diff(env, current)
    assert changed['identical'] is False
    assert '-' + before in changed['untrusted_device_output']
    assert '+' + after in changed['untrusted_device_output']
    assert changed['secrets_changed_count'] == 0
    assert not changed['hidden_lines_compared']
    assert files[0].read_text() == disk  # reading/diffing does not silently approve
    approve(env, current)
    assert diff(env, current)['identical'] is True


def test_approval_requires_reviewed_hash_and_compare_right(env, durable_directory):
    first = read(env)
    attempts = [dict(approve_baseline=True), dict(snapshot_id=first['snapshot_id'], approve_baseline=True),
                dict(snapshot_id=first['snapshot_id'], content_sha256='0' * 64, approve_baseline=True),
                dict(snapshot_id=first['snapshot_id'], content_sha256=first['content_sha256'],
                     contains='interface', approve_baseline=True), dict(approve_baseline='true')]
    for options in attempts:
        result = _call(env, 'config_read', _read_arguments(env, **options))
        assert result['isError'] or not result.get('structuredContent', {}).get('ok', False), result
    assert not durable_directory.exists()
    _inventory(env['helper'], env['spec'], b_access=('read',))
    result = _call(env, 'config_read', _read_arguments(env, snapshot_id=first['snapshot_id'],
                   content_sha256=first['content_sha256'], approve_baseline=True))
    assert result['isError']
    assert not durable_directory.exists()


def test_corrupt_missing_and_other_target_baseline_refused(env, durable_directory):
    first = read(env)
    missing = _call(env, 'config_diff', dict(target='router-b', platform=env['platform'],
                   base_snapshot='baseline', other_snapshot=first['snapshot_id']))
    assert missing['isError']
    approve(env, first)
    path = next(durable_directory.glob('*.json'))
    original = path.read_text()
    for field, value in [('text', 'untrusted corruption\n'), ('target', '0' * 64), ('profile', 'invalid'),
                         ('firmware', []), ('firmware', [None]), ('firmware', ['x'] * 6),
                         ('firmware', ['x' * 257, 'version', 'build'])]:
        record = json.loads(original)
        record[field] = value
        path.write_text(json.dumps(record))
        rejected = _call(env, 'config_diff', dict(target='router-b', platform=env['platform'],
                        base_snapshot='baseline', other_snapshot=first['snapshot_id']))
        assert rejected['isError']
    path.write_text(original)
    path.chmod(0o644)
    rejected = _call(env, 'config_diff', dict(target='router-b', platform=env['platform'],
                    base_snapshot='baseline', other_snapshot=first['snapshot_id']))
    assert rejected['isError']


def test_changed_session_redaction_refuses_baseline(env):
    first = read(env)
    approve(env, first)
    _register_late_secret(env)
    # Existing tests' late value occurs in B's safe visible content.
    result = _call(env, 'config_diff', dict(target='router-b', platform=env['platform'],
                   base_snapshot='baseline', other_snapshot=first['snapshot_id']))
    assert result['isError']


@pytest.mark.parametrize('env', ['extreme_exos', 'cisco_ios'], indirect=True)
def test_real_ro_refusal_creates_no_approvable_snapshot(env, durable_directory):
    name = 'x440' if env['platform'] == 'extreme_exos' else 'iosv'
    wire = env['wire']
    wire.spec = dict(env['spec'], identity={'show version': (REAL / (name + '-show_version.out')).read_text()})
    if name == 'x440':
        wire.spec['identity']['show switch'] = (REAL / 'x440-show_switch.out').read_text()
    command = 'show_configuration' if name == 'x440' else 'show_running-config'
    wire.config = (REAL / (name + '-' + command + '.out')).read_text()
    wire.config_rc = 254 if name == 'x440' else 0
    result = _call(env, 'config_read', _read_arguments(env))
    assert result['isError'] or not result.get('structuredContent', {}).get('ok', False), result
    assert not configuration._SNAPSHOTS
    assert not durable_directory.exists()
