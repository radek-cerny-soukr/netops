"""Exercise real engine/configuration paths; only the SSH transport is replaced.

The RS object is the reported live edit/set-ip excerpt wrapped in its SHOW
section, with the address anonymized. The other SLB configurations below are explicitly synthetic.
"""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import configuration, engine, progress
from netops_helper.auth import EgressPolicy
from netops_helper.query_catalog import READ_QUERIES
import test_triage_slb as slb

FIXTURES = Path(__file__).parent / 'fixtures/triage_t12'


def adc_auth():
    return replace(_target('fortiadc', 'system_status'), enabled_queries=tuple(READ_QUERIES['fortiadc']),
                   egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,), allow_icmp=True),
                   read_inventory=slb.Auth().read_inventory)


@pytest.fixture
def wire(monkeypatch):
    configuration._SNAPSHOTS.clear()
    calls = []
    def transport(auth, platform, command, stdout_consumer=None):
        calls.append(command)
        values = {
            'get system status': slb.STATUS,
            'show full-configuration load-balance virtual-server ' + slb.VS: slb.vs_config(),
            'show full-configuration load-balance pool ' + slb.POOL: slb.pool_config().replace('RS_1', 'RS_A'),
            'show full-configuration system health-check HC_HTTP_APP': slb.HC,
            'show full-configuration load-balance real-server RS_A': (FIXTURES / 'real-server.txt').read_text(),
            'diagnose server-load-balance vs_stat vdom root vs ' + slb.VS: slb.vs_stat(('DOWN', 'UP'), 'UNHEALTHY'),
            'diagnose server-load-balance slb_load': slb.SLB_LOAD,
            'get system performance': slb.PERF,
        }
        body = values[command]
        if stdout_consumer:
            encoded = body.encode()
            for index in range(0, len(encoded), 7):
                stdout_consumer(encoded[index:index + 7])
            return 0, ''
        return 0, body
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, '_prompt_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    yield calls
    configuration._SNAPSHOTS.clear()


def test_down_member_through_real_config_read_and_triage(wire):
    auth = adc_auth()
    direct = engine.config_read(auth, 'fortiadc', 'load-balance real-server RS_A',
                                redaction='full', include_defaults=True)
    assert direct['ok'] and 'set ip 192.0.2.11' in direct['untrusted_device_output']
    result = engine.triage_slb(auth, slb.VS)
    assert result['verdict'] == 'fault_found' and result['missing'] == [], result['missing']
    assert result['chain']['real_servers'] == {'RS_A': '192.0.2.11'}
    assert 'show full-configuration load-balance real-server RS_A' in wire
    health = next(s['arguments'] for s in result['next_steps'] if s['arguments']['recipe'] == 'health_check_verify')
    assert health == {'target': auth.alias, 'recipe': 'health_check_verify', 'interface': '',
                      'address': '192.0.2.11', 'health_check': 'HC_HTTP_APP', 'count': 3, 'timeout': 20}
    assert all(s['arguments']['address'] == '192.0.2.11' for s in result['next_steps'])


def test_local_config_refusal_neither_blames_device_nor_advances_progress(wire, monkeypatch):
    from netops_helper import config_fortiadc
    # Remove precisely the grant whose absence caused the live regression.
    monkeypatch.setattr(config_fortiadc, 'OBJECT_SECTIONS',
                        config_fortiadc.OBJECT_SECTIONS - {'load-balance real-server'})
    reports = []
    token = progress.bind(lambda *report: reports.append(report))
    try:
        result = engine.triage_slb(adc_auth(), slb.VS)
    finally:
        progress.unbind(token)
    assert result['missing'] == [{'step': 'real_server_config:RS_A', 'reason': 'local_refusal',
                                  'detail': 'invalid configuration section'}]
    assert not any('real-server' in command for command in wire)
    assert not any('real_server_config' in report[2] for report in reports)
    assert reports[-1][0] == 7
    assert engine._TRIAGE_READ_ATTEMPT.get() is None


def test_device_config_refusal_still_counts_read_and_names_device(wire, monkeypatch):
    transport = engine._exec_read
    def refused(auth, platform, command, **kwargs):
        if 'real-server RS_A' in command:
            wire.append(command)
            return 1, ''
        return transport(auth, platform, command, **kwargs)
    monkeypatch.setattr(engine, '_exec_read', refused)
    reports = []
    token = progress.bind(lambda *report: reports.append(report))
    try:
        result = engine.triage_slb(adc_auth(), slb.VS)
    finally:
        progress.unbind(token)
    assert result['missing'][0]['reason'] == 'device_cli_error'
    assert reports[-1][0] == 8 and 'real_server_config:RS_A' in reports[-1][2]


