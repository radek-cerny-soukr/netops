"""Durable baseline with real redacted FortiOS and G02-r2 IOS captures.

Physical SSH alone is replayed. IOSv exercises the public Helper bridge across
an actual Python process restart; IOSvL2 reads with the G00 untested firmware warning.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from netops_helper import configuration, engine
from test_config_diff_fortios_line import _auth, _read, CONFIG, SECTION, STATUS, VOICE, _after


@pytest.fixture(autouse=True)
def baseline_state(tmp_path, monkeypatch):
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    monkeypatch.setenv('NETOPS_CONFIG_BASELINE_DIR', str(tmp_path / 'baselines'))
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', str(tmp_path / 'child-audit.jsonl'))
    yield tmp_path / 'baselines'
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def test_real_fortios_capture_baseline_diff_after_process_restart(wire, baseline_state):
    auth = _auth()
    first = _read(wire, auth, CONFIG)
    approved = engine.config_read(auth, 'fortios', SECTION, snapshot_id=first['snapshot_id'],
                                 content_sha256=first['content_sha256'], approve_baseline=True)
    assert approved['baseline_approved'] is True
    # A new Python process has a fresh configuration._KEY and no snapshots. Re-redact the same real
    # input, store today's snapshot and run the public diff; persistence itself is never replaced.
    script = r'''
import json, sys
sys.path.insert(0, str(__import__('pathlib').Path.cwd() / 'tests'))
from netops_helper import configuration, engine
from test_config_diff_fortios_line import _auth, CONFIG, SECTION, STATUS
auth = _auth()
assert not configuration._SNAPSHOTS
firmware = configuration.require_single_vdom(STATUS)
with configuration.capture(auth.configuration_limits, target=configuration.scope(auth)):
    text, hidden, count = configuration.redact(CONFIG, auth.secrets, SECTION)
    identity = configuration.store(auth, text, hidden, count, SECTION, firmware)
result = engine.config_diff(auth, 'fortios', 'baseline', identity)
print(json.dumps(result))
'''
    completed = subprocess.run([sys.executable, '-B', '-c', script], env=os.environ.copy(),
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result['ok'] is True and result['identical'] is True
    assert result['baseline_snapshot'] == first['snapshot_id']
    assert result['hidden_lines_compared'] is False and result['secrets_changed_count'] == 0
    newer = _read(wire, auth, _after(CONFIG, VOICE, '                set status down\n'))
    result = engine.config_diff(auth, 'fortios', 'baseline', newer['snapshot_id'])
    assert result['identical'] is False
    assert result['untrusted_device_output'] == '--- base\n+++ other\n+    set status down\n'
    assert result['hidden_lines_compared'] is False
    # Secret-only changes must never be reported as changed or retain old keyed hidden records.
    hidden_change = _read(wire, auth, CONFIG.replace('"4091"', '"4092"'))
    result = engine.config_diff(auth, 'fortios', 'baseline', hidden_change['snapshot_id'])
    assert result['identical'] is True and result['secrets_changed_count'] == 0
    assert result['hidden_lines_compared'] is False
    disk = next(baseline_state.glob('*.json')).read_text()
    record = json.loads(disk)
    assert set(record) == {'version', 'target', 'snapshot_id', 'approved_at', 'section', 'firmware',
                           'profile', 'include_defaults', 'metadata', 'redacted_count', 'content_sha256', 'text'}
    assert '"4091"' not in disk and auth.secret not in disk


def test_failed_approval_keeps_previous_baseline(wire, baseline_state, monkeypatch):
    auth = _auth()
    first = _read(wire, auth, CONFIG)
    engine.config_read(auth, 'fortios', SECTION, snapshot_id=first['snapshot_id'],
                       content_sha256=first['content_sha256'], approve_baseline=True)
    path = next(baseline_state.glob('*.json'))
    previous = path.read_bytes()
    second = _read(wire, auth, _after(CONFIG, VOICE, '                set status down\n'))
    import netops.files
    def refuse(*args, **kwargs):
        raise OSError('simulated full disk')
    monkeypatch.setattr(netops.files, 'write_private', refuse)
    with pytest.raises(engine.ConfigurationRefusal) as refused:
        engine.config_read(auth, 'fortios', SECTION, snapshot_id=second['snapshot_id'],
                           content_sha256=second['content_sha256'], approve_baseline=True)
    assert refused.value.code == 'config_baseline_unavailable'
    assert path.read_bytes() == previous
    assert engine.config_diff(auth, 'fortios', 'baseline', second['snapshot_id'])['identical'] is False


# Captured using the configuration account on PC-Radek, with no device writes.
# The configuration fixture is actual config_read output after product redaction
# and site anonymization. Hidden original statements are deliberately absent.
from test_config_diff_ios_family import env
from test_config_baselines import read as bridge_read, approve as bridge_approve, diff as bridge_diff

REAL_IOS = Path(__file__).parent / 'fixtures' / 'real' / 'g02_r2_20261117'


def _real_ios(env, name='iosv'):
    env['wire'].spec = dict(env['spec'], identity={
        'show version': (REAL_IOS / (name + '-version.out')).read_text()})
    suffix = '-config_read.out' if name == 'iosv' else '-cli-redacted.out'
    env['wire'].config = (REAL_IOS / (name + suffix)).read_text()


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_real_iosv_baseline_public_bridge_after_process_restart(env, baseline_state, tmp_path):
    _real_ios(env)
    first = bridge_read(env)
    assert first['ok'] and first['capture_complete']
    assert first['firmware'] == {'model': 'IOSv', 'version': '15.9(3)M12', 'build': 'fc1'}
    approved = bridge_approve(env, first)
    assert approved['baseline_approved']
    assert bridge_diff(env, bridge_read(env))['identical']
    script = r'''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0, str(Path.cwd() / 'tests'))
from netops_helper import configuration
from test_config_diff_ios_family import env as make_env
from test_config_baselines_real import _real_ios
from test_config_baselines import read, diff
assert not configuration._SNAPSHOTS
with pytest.MonkeyPatch.context() as patch:
    fixture = make_env.__wrapped__(SimpleNamespace(param='cisco_ios'), Path(sys.argv[1]), patch)
    env = next(fixture)
    try:
        _real_ios(env)
        capture = read(env)
        result = diff(env, capture)
        print(json.dumps({'pid': os.getpid(), 'capture': capture, 'diff': result}))
    finally:
        next(fixture, None)
'''
    completed = subprocess.run([sys.executable, '-B', '-c', script, str(tmp_path / 'new-helper')],
                               env=os.environ.copy(), capture_output=True, text=True, timeout=45)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result['pid'] != os.getpid()
    assert result['capture']['snapshot_id'] != first['snapshot_id']
    assert result['capture']['content_sha256'] == first['content_sha256']
    compared = result['diff']
    assert compared['ok'] and compared['identical']
    assert compared['baseline_snapshot'] == first['snapshot_id']
    assert compared['baseline_approved_at'] == approved['baseline_approved_at']
    assert compared['hidden_lines_compared'] is False
    assert compared['secrets_changed_count'] == 0
    assert compared['untrusted_device_output'] == ''


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_real_iosvl2_config_account_reads_with_warning_and_baseline(env, baseline_state):
    # G00-3 accepts IOSvL2 (untested firmware, warning); supersedes the G02 refusal test and the 448 positive test.
    _real_ios(env, 'iosvl2')
    first = bridge_read(env)
    assert first['ok'] and first['capture_complete']
    support = first['firmware_support']
    assert support['status'] == 'untested'
    assert first['warnings'] == [{'code': 'firmware_untested', 'message': support['message']}]
    assert bridge_approve(env, first)['baseline_approved']
    assert bridge_diff(env, bridge_read(env))['identical']
    assert baseline_state.exists()
    assert any(command == 'show running-config' for _, command, _ in env['wire'].calls)
