"""Read-only forced standby, with measured reply excerpts (not a simulated HA pair)."""
from pathlib import Path

import pytest

from conftest import FORTIADC_STATUS, _calls, _fortinet_wire, _target
from netops_helper import engine, read_policy

FIXTURES = Path(__file__).parent / "fixtures/fortiadc_adc_ha_doc"
QUERY = "ha_standby_status"
COMMAND = "execute ha force failover-standby status"


def read_reply(wire, monkeypatch, body):
    if body and not body.endswith("\n"):
        body += "\n"
    _fortinet_wire(wire, {"get system status": FORTIADC_STATUS, COMMAND: body})
    return engine.ssh_read(_target("fortiadc", QUERY), "fortiadc", QUERY, {}, 0, 48000)


@pytest.mark.parametrize("state,expected", [("set", True), ("unset", False)])
def test_measured_status_through_fake_transport(wire, monkeypatch, state, expected):
    answer = read_reply(wire, monkeypatch, (FIXTURES / (state + '.out')).read_text())
    assert answer["ok"], answer
    assert answer["ha_standby"] == {"status": "complete", "forced_standby": expected}
    assert wire["transcript"].read_text().splitlines() == ["get system status", COMMAND]
    assert len(_calls(wire)) == 1


def test_measured_refusal_has_no_standby_result(wire, monkeypatch):
    answer = read_reply(wire, monkeypatch, (FIXTURES / 'refused.out').read_text())
    assert answer['ok'] is False and answer['error_code'] == 'device_cli_error', answer
    assert 'ha_standby' not in answer


@pytest.mark.parametrize('body', [
    (FIXTURES / 'set.out').read_text().removesuffix('set.\n'),
    (FIXTURES / 'unset.out').read_text() + '--More--\n',
    'unexpected output\n',
])
def test_incomplete_is_never_inferred_as_unset(wire, monkeypatch, body):
    answer = read_reply(wire, monkeypatch, body)
    assert answer['ha_standby'] == {'status': 'incomplete'}, answer


def test_empty_is_failure(wire, monkeypatch):
    answer = read_reply(wire, monkeypatch, '')
    assert answer['ok'] is False and answer['error_code'] == 'empty', answer


@pytest.mark.parametrize('action', ['set', 'unset', 'status; execute reboot', 'status\nset'])
def test_only_fixed_status_command_is_allowed(action):
    with pytest.raises(RuntimeError):
        read_policy._validate_query_command('fortiadc', 'execute ha force failover-standby ' + action)
