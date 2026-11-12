"""Complete real EXOS sharing captures through switch_read, plus explicit synthetic mutations."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_core import prompt
from netops_helper import engine
from netops_helper.auth import EgressPolicy

FIXTURES = Path(__file__).parent / 'fixtures/triage_t12'


@pytest.mark.parametrize('fixture', ['show-sharing.txt', 'show-sharing-x435.txt'])
@pytest.mark.parametrize('rc', [0, 250])
def test_exos_lag_real_empty_capture_through_switch_read(monkeypatch, rc, fixture):
    calls = []
    def transport(auth, platform, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (Path(__file__).parent / 'fixtures/identity/extreme_exos.txt').read_text()
        assert command == 'show sharing'
        return rc, prompt.cleaned((FIXTURES / fixture).read_text(), platform)
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(_target('extreme_exos', 'lag_summary'), device_types=('switch',), egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,)))
    result = engine.switch_read(auth, 'lag')
    assert result['ok'] and result['status'] == 'empty' and result['coverage']['complete'], result
    assert result['records'] == [] and result['unparsed'] == []
    assert calls[-1] == 'show sharing'
    if rc == 250:
        assert 'exit_status_250' in result['warnings']


@pytest.mark.parametrize('extra,rc', [('%% Unrecognized command\n', 250), ('', 1)])
def test_exos_sharing_refusal_never_becomes_empty_success(monkeypatch, extra, rc):
    def transport(auth, platform, command, **kwargs):
        if command == 'show version':
            return 0, (Path(__file__).parent / 'fixtures/identity/extreme_exos.txt').read_text()
        return rc, prompt.cleaned((FIXTURES / 'show-sharing.txt').read_text(), platform) + extra
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    result = engine.switch_read(replace(_target('extreme_exos', 'lag_summary'), device_types=('switch',), egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,))), 'lag')
    assert not result['ok']


def test_synthetic_populated_sharing_rows_and_unknowns():
    from netops_helper import tables
    empty = prompt.cleaned((FIXTURES / 'show-sharing.txt').read_text(), 'extreme_exos')
    rows = ('1 1 LACP 1 L3_L4 A 1 Y A 4\n'
            '                  L3_L4 A 2 Y A 3\n'
            '3 - STATIC <2 L2 A 3 N R 0\n'
            '                  L2 A 4 N D 0\n')
    text = empty.replace('Number of load sharing trunks: 0', rows + 'Number of load sharing trunks: 2')
    result = tables.parse('extreme_exos', 'lag', 'lag_summary', text)
    assert result['ok'] and result['coverage']['complete'], result
    assert result['records'] == [
        {'name': '1', 'protocol': 'LACP', 'status': 'up', 'members': [
            {'port': '1', 'state': 'bundled'}, {'port': '2', 'state': 'bundled'}]},
        {'name': '3', 'protocol': 'Static', 'status': 'down', 'members': [
            {'port': '3', 'state': 'down'}, {'port': '4', 'state': 'down'}]}]
    for changed in (text + 'unknown data\n', text.replace('trunks: 2', 'trunks: 3')):
        result = tables.parse('extreme_exos', 'lag', 'lag_summary', changed)
        assert result['status'] == 'unparsed' and not result['coverage']['complete']


@pytest.mark.parametrize('enabled', [True, False])
def test_proxy_enrollment_and_forwarding_to_real_engine(tmp_path, monkeypatch, enabled):
    import json
    import test_proxy_contracts as contracts
    from netops_helper.auth import TargetAuth
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform='exos', device_types=['switch'],
                   enabled_queries=['lag_summary'] if enabled else ['lacp'], read_inventory={})
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'exos')))
    gateway = module.Proxy()
    emitted = []
    monkeypatch.setattr(gateway, '_emit', emitted.append)
    calls = []
    def transport(auth, platform, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (Path(__file__).parent / 'fixtures/identity/extreme_exos.txt').read_text()
        assert command == 'show sharing'
        return 250, (FIXTURES / 'show-sharing.txt').read_text()
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    forwarded = gateway.request(contracts._request(1, 'switch_read', {'target': 'device-a', 'table': 'lag'}))
    if not enabled:
        assert forwarded is None and emitted[-1]['error']['data']['category'] == 'policy_scope'
        assert calls == []
        return
    assert forwarded is not None, emitted
    arguments = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(arguments['target'], arguments['auth_context'])
    result = engine.switch_read(auth, arguments['table'])
    assert result['ok'] and result['status'] == 'empty' and result['coverage']['complete']
    assert calls[-1] == 'show sharing' and 'exit_status_250' in result['warnings']


@pytest.mark.parametrize('legend', [
    '(L2) Layer 2 address based',
    '(L2) Layer 2 address based, (L3) Layer 3 address based',
    '(L2) Layer 2 address based, (L3) Layer 3 address based, (L3_L4) Layer 3 address and Layer 4 port based',
    '(L3_L4) Layer 3 address and Layer 4 port based, (L2) Layer 2 address based',
])
def test_sharing_algorithm_legend_lists(legend):
    from netops_helper import tables
    text = (FIXTURES / 'show-sharing-x435.txt').read_text()
    original = next(line for line in text.splitlines() if line.startswith('Load Sharing Algorithm:'))
    result = tables.parse('extreme_exos', 'lag', 'lag_summary',
                          text.replace(original, 'Load Sharing Algorithm: ' + legend))
    assert result['ok'] and result['status'] == 'empty', result


@pytest.mark.parametrize('legend', [
    '', '(L2) ', '(L2) Layer 2 address based,',
    '(L2) Layer 2 address based, unknown data',
    '(L2) Layer 2 address based, (L3) ',
    '(L2) Layer 2 address based, ' + '(L' + '3' * 20000,
    '(L2) ' + ' ' * 20000 + ',',
])
def test_malformed_sharing_legend_remains_unparsed(legend):
    from netops_helper import tables
    text = (FIXTURES / 'show-sharing-x435.txt').read_text()
    original = next(line for line in text.splitlines() if line.startswith('Load Sharing Algorithm:'))
    result = tables.parse('extreme_exos', 'lag', 'lag_summary',
                          text.replace(original, 'Load Sharing Algorithm: ' + legend))
    assert not result['ok'] and result['status'] == 'unparsed', result


@pytest.mark.parametrize('directory,populated', [
    ('x440g2-12p-10g4_33.7.1.6_2', True),
    ('x440g2-12p-10g4_33.7.1.6_3', True),
    ('x435-8p-4s_33.7.1.6', False),
    ('x440g2-12p-10g4_33.7.1.6', False),
    ('exosvm_33.6.1.14', False),
])
def test_acceptance_sharing_whole_output_through_switch_read(monkeypatch, directory, populated):
    real = Path(__file__).parent / 'fixtures/real/exos'
    # EXOS-VM identity with the physical lab's empty monitor: explicit cross-device replay.
    capture = directory if directory != 'exosvm_33.6.1.14' else 'x435-8p-4s_33.7.1.6'
    calls = []
    def transport(auth, profile, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (real / directory / 'version.txt').read_text()
        assert command == 'show sharing'
        return 250, (real / capture / 'captures_20261110_final/lag_summary.txt').read_text()
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(_target('extreme_exos', 'lag_summary'), device_types=('switch',),
                   egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,)))
    result = engine.switch_read(auth, 'lag')
    assert calls == ['show version', 'show sharing']
    assert result['ok'] and result['status'] == ('ok' if populated else 'empty'), result
    assert result['coverage']['complete'] and not result['unparsed']
    assert result['records'] == ([{'name': '13', 'protocol': 'LACP', 'status': 'up', 'members': [
        {'port': '13', 'state': 'bundled'}, {'port': '14', 'state': 'down'},
        {'port': '15', 'state': 'bundled'}, {'port': '16', 'state': 'down'}]}] if populated else [])
