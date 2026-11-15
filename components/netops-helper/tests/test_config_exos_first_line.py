"""Task 211: derived first-line refusal scenarios, real EXOS identity fixtures, fake SSH."""

import pytest

from netops_helper import config_exos, configuration
import test_config_diff_ios_family as family
from test_config_diff_ios_family import env  # noqa: F401
from test_live_scenarios_178 import DEVICE_REFUSED, EXOS_REFUSAL, _error, _read


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
@pytest.mark.parametrize('prefix', [EXOS_REFUSAL, '\r\n  ' + EXOS_REFUSAL.rstrip() + ' \t\r\n\r\n'])
def test_first_line_refusal_followed_by_configuration_is_redacted(env, prefix):
    ordinary = family._capture(env)
    capture = family._capture(env, prefix + env['spec']['config'])
    text = capture['untrusted_device_output']
    assert text.endswith(ordinary['untrusted_device_output'])
    assert config_exos.MARKER in text[:len(text) - len(ordinary['untrusted_device_output'])]
    assert 'does not have permissions' not in text
    family._assert_clean(capture, env['spec']['b_secret'])
    assert capture['capture_complete'] is True
    assert len(configuration._SNAPSHOTS) == 2


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
@pytest.mark.parametrize('rc', [0, 254])
@pytest.mark.parametrize('answer', [EXOS_REFUSAL.rstrip(), EXOS_REFUSAL,
                                 '\r\n  ' + EXOS_REFUSAL.rstrip() + ' \t\r\n\r\n'])
def test_standalone_refusal_stays_fail_closed(env, rc, answer):
    env['wire'].config_rc = rc
    env['wire'].config = answer
    assert _error(_read(env)) == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
def test_configuration_after_first_line_refusal_with_nonzero_rc_stays_refused(env):
    env['wire'].config_rc = 254
    env['wire'].config = EXOS_REFUSAL + env['spec']['config']
    assert _error(_read(env)) == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS
