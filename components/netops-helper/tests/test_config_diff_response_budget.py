"""verification: final diff redaction budget, using real 178 captures and fake SSH."""

import pytest

from netops_helper import configuration
import test_config_diff_ios_family as family
from test_config_diff_ios_family import env  # noqa: F401
from test_live_scenarios_178 import _live


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_final_diff_response_budget_has_the_controlled_machine_code(env, monkeypatch):
    base = family._capture(env, _live('cisco_ios', 'base'))
    other = family._capture(env, _live('cisco_ios', 'changed'))
    original = configuration.compare

    def tight(*args, **kwargs):
        result = original(*args, **kwargs)
        # Exhaust the budget only after compare and snapshot admission have succeeded.
        retained = sum(s.memory_bytes for s in configuration._SNAPSHOTS.values())
        retained += sum(t.memory_bytes + c.memory_bytes for t, c, _ in configuration._DIFFS.values())
        monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', retained)
        return result

    monkeypatch.setattr(configuration, 'compare', tight)
    result = family._diff(env, base, other)
    data = result['structuredContent']
    assert result['isError'] is True and data['ok'] is False, result
    assert data['error_code'] == 'config_diff_limit_exceeded'
    assert data['error'] == configuration.DIFF_BUDGET_EXCEEDED
    assert 'untrusted_device_output' not in data and 'restart_offset' not in data
    assert 'Role operation failed' not in str(result)
    assert configuration._ACTIVE_BUDGET == configuration._BYTE_BUDGET
