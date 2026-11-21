"""G28 transport tests with anonymized ADC VM220 7.6.7 build0676 captures."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_core import prompt
from netops_helper import engine, read_policy, triage_slb
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / 'fixtures/real/fortiadc/fortiadc-kvm_7.6.7_g28_20261117'


def capture(name):
    text = (FIXTURES / name).read_text()
    # The fake terminal returns the body, as the real PTY transport does.
    return '\n'.join(line for line in prompt.cleaned(text, 'fortiadc').splitlines()
                     if line.strip() != 'FortiADC-KVM #')


@pytest.fixture
def wire(monkeypatch):
    calls = []
    output = {'text': capture('vs-all.out')}

    def execute(auth, platform, command, **kwargs):
        calls.append(command)
        assert command == 'get system status'
        return 0, capture('status.out')

    def terminal(auth, platform, command):
        calls.append(command)
        return None, output['text']

    monkeypatch.setattr(engine, '_exec_read', execute)
    monkeypatch.setattr(engine, '_prompt_read', terminal)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    yield calls, output
    engine._SSH_PAGE_CACHE.clear()


def auth():
    return replace(_target('fortiadc', 'system_status'),
                   enabled_queries=tuple(READ_QUERIES['fortiadc']),
                   read_inventory={'adc_vdoms': ('root',), 'adc_virtual_servers': ('VS_APP_HTTP',)})


def test_all_vs_one_runtime_read(wire):
    calls, output = wire
    result = engine.ssh_read(auth(), 'fortiadc', 'slb_vs_overview', {'vdom': 'root'}, 0, 48000)
    assert result['ok'], result
    assert result['statistics_status'] == 'data'
    assert len(result['virtual_servers']) == 5
    assert all(row['availability'] == 'DEAD' for row in result['virtual_servers'])
    assert all(row['counters']['Concurrent Connections'] == 0 for row in result['virtual_servers'])
    assert calls == ['get system status', 'diagnose server-load-balance vs_stat vdom root']


def test_rs_id_selects_only_one_member(wire):
    calls, output = wire
    output['text'] = capture('vs-stat-rs-1.out')
    result = engine.ssh_read(auth(), 'fortiadc', 'slb_rs_stat',
                             {'vdom': 'root', 'virtual_server': 'VS_APP_HTTP', 'real_server': '1'}, 0, 48000)
    assert result['ok'], result
    assert result['statistics_status'] == 'data'
    assert result['real_server_statistics']['id'] == 1
    assert result['real_server_statistics']['hc_state'] == 'DOWN'
    assert result['real_server_statistics']['counters']['Concurrent Connections'] == 0
    assert calls[-1].endswith('rs 1')


@pytest.mark.parametrize('query,filename', [('slb_vs_overview', 'vs-all.out'), ('slb_rs_stat', 'vs-stat-rs-1.out')])
def test_incomplete_counter_is_not_a_complete_statistics_result(wire, query, filename):
    calls, output = wire
    output['text'] = capture(filename).replace('\t\tServer RTT: 1\n', '')
    params = {'vdom': 'root'}
    if query == 'slb_rs_stat':
        params.update(virtual_server='VS_APP_HTTP', real_server='1')
    result = engine.ssh_read(auth(), 'fortiadc', query, params, 0, 48000)
    assert result['statistics_status'] == 'incomplete'
    assert 'virtual_servers' not in result
    assert 'real_server_statistics' not in result


@pytest.mark.parametrize('value', ['0', '-1', 'RS_A', '1; reboot', '01', '1 2', '99999999999'])
def test_member_argument_is_a_numeric_id_and_cannot_inject_commands(value):
    with pytest.raises(ValueError):
        read_policy.render_read_query('fortiadc', 'slb_rs_stat',
                                      {'vdom': 'root', 'virtual_server': 'VS_APP_HTTP', 'real_server': value},
                                      auth().read_inventory)


def test_unenrolled_vdom_is_refused_before_transport(wire):
    with pytest.raises(ValueError):
        engine.ssh_read(auth(), 'fortiadc', 'slb_vs_overview', {'vdom': 'other'}, 0, 48000)
    assert not wire[0]


def test_duplicate_vs_is_rejected():
    text = capture('vs-all.out')
    with pytest.raises(triage_slb.TriageParseError):
        triage_slb.parse_vs_overview(text + '\n\tvirtual-server: VS_APP_HTTP, availability:DEAD', 'root')


@pytest.mark.parametrize('query', ['slb_vs_overview', 'slb_rs_stat'])
def test_device_refusal_does_not_become_statistics(wire, query):
    wire[1]['text'] = capture('refusal.out')
    parameters = {'vdom': 'root'}
    if query == 'slb_rs_stat':
        parameters.update(virtual_server='VS_APP_HTTP', real_server='1')
    result = engine.ssh_read(auth(), 'fortiadc', query, parameters, 0, 48000)
    assert not result['ok']
    assert 'virtual_servers' not in result
    assert 'real_server_statistics' not in result


def test_missing_member_is_incomplete_not_zero(wire):
    wire[1]['text'] = capture('rs-missing.out')
    result = engine.ssh_read(auth(), 'fortiadc', 'slb_rs_stat',
                             {'vdom': 'root', 'virtual_server': 'VS_APP_HTTP', 'real_server': '999'}, 0, 48000)
    assert result['statistics_status'] == 'incomplete'
    assert 'real_server_statistics' not in result


def test_only_a_full_page_can_become_a_complete_overview(wire):
    result = engine.ssh_read(auth(), 'fortiadc', 'slb_vs_overview', {'vdom': 'root'}, 0, 1000)
    assert result['statistics_status'] == 'incomplete'
    assert result['next_offset'] is not None
    assert 'virtual_servers' not in result
