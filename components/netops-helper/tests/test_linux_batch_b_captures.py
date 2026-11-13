"""2026-11-13 read-only captures through proxy authorization and real engine."""
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy as proxy_module, tables
from netops_helper.auth import TargetAuth
from support.replay_capture import load
import test_proxy_contracts as contract

SCENARIOS = [load(path) for path in sorted(
    (Path(__file__).parent / 'fixtures/real/scenarios').glob('linux_*_batch_b.json'))]
CASES = [(scenario, capture) for scenario in SCENARIOS for capture in scenario['captures']]


def configure(tmp_path, monkeypatch, scenario, queries):
    for attribute in ('INVENTORY', 'VAULT', 'EGRESS_POLICY', 'RUNNER'):
        monkeypatch.setattr(proxy_module, attribute, getattr(proxy_module, attribute))
    inventory, _, _, _ = contract._configure(proxy_module, tmp_path)
    section = contract._section()
    section.update(ssh_platform='linux', enabled_queries=list(queries))
    section['read_inventory']['interfaces'] = [
        row['name'] for capture in scenario['captures'] if capture['query'] == 'links'
        for row in capture['expected']['records']]
    contract._write(inventory, contract._inventory(contract._device(section, 'linux')))
    proxy = proxy_module.Proxy()
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    commands = {capture['command']: capture for capture in scenario['captures']}
    calls = []

    def read(auth, profile, command):
        assert profile == 'linux'
        calls.append(command)
        capture = scenario['environment']['version'] if command == 'uname -a' else commands[command]
        return capture['rc'], capture['stdout']

    monkeypatch.setattr(engine, 'read_from_device', read)
    return proxy, calls


def through_proxy(proxy, table, **kwargs):
    forwarded = proxy.request(contract._request(1, 'switch_read', {
        'target': 'device-a', 'table': table, **kwargs}))
    assert forwarded is not None
    arguments = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(arguments.pop('target'), arguments.pop('auth_context'))
    result = engine.switch_read(auth, **arguments)
    # The real response path applies public response shaping and secret redaction.
    public = proxy.response(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {
        'content': [{'type': 'text', 'text': json.dumps(result)}],
        'structuredContent': result,
    }}).encode())
    return json.loads(public)['result']['structuredContent']


@pytest.mark.parametrize('scenario,capture', CASES,
    ids=[scenario['scenario'].split()[0] + ':' + capture['command'] for scenario, capture in CASES])
def test_captures_through_proxy_and_engine(tmp_path, monkeypatch, scenario, capture):
    proxy, calls = configure(tmp_path, monkeypatch, scenario, [capture['query']])
    kwargs = {'interface': capture['command'].split()[-1]} if capture['query'] == 'interface_link' else {}
    result = through_proxy(proxy, capture['table'], **kwargs)
    expected = capture['expected']
    assert result['status'] == expected['status'], result
    assert len(result['records']) == expected['record_count']
    assert len(result['unparsed']) == expected['unparsed_count']
    for actual, manual in zip(result['records'], expected['records'], strict=True):
        assert {key: actual[key] for key in manual} == manual
        assert set(actual) == set(tables.FIELDS[capture['table']])
    assert calls == ['uname -a', capture['command']]


@pytest.mark.parametrize('scenario', SCENARIOS, ids=lambda s: s['scenario'].split()[0])
def test_joined_addresses_have_cli_mac_prefix_and_gateway(tmp_path, monkeypatch, scenario):
    proxy, calls = configure(tmp_path, monkeypatch, scenario, ['addresses', 'links', 'routes'])
    result = through_proxy(proxy, 'ip_interface')
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    if scenario['scenario'].startswith('Ubuntu'):
        interface, address, mac, prefix = 'eno1', '192.0.2.66', '00:00:5e:00:53:01', 24
    elif scenario['scenario'].startswith('Proxmox'):
        interface, address, mac, prefix = 'vmbr0', '192.0.2.2', '00:00:5e:00:53:01', 24
    else:
        interface, address, mac, prefix = 'ens18', '192.0.2.36', '00:00:5e:00:53:01', 24
    row = next(row for row in result['records'] if row['interface'] == interface and row['ip'] == address)
    assert {key: row[key] for key in ('mac', 'prefix_length', 'gateway')} == {
        'mac': mac, 'prefix_length': prefix, 'gateway': '192.0.2.1'}
    # Compare every address against manually transcribed CLI values, including
    # the second address, loopback and bridge-only IPv6 interfaces.
    manual_addresses = next(c['expected']['records'] for c in scenario['captures'] if c['query'] == 'addresses')
    manual_links = {row['name']: row for c in scenario['captures'] if c['query'] == 'links'
                    for row in c['expected']['records']}
    assert len(result['records']) == len(manual_addresses)
    for actual, manual in zip(result['records'], manual_addresses, strict=True):
        assert {key: actual[key] for key in manual} == manual
        assert actual['mac'] == manual_links[manual['interface']]['mac']
        assert actual['gateway'] == ('192.0.2.1' if manual['interface'] == interface and ':' not in manual['ip'] else None)
    assert [source['query'] for source in result['sources']] == ['addresses', 'links', 'routes']
    assert calls.count('ip -brief address') == calls.count('ip -brief link') == calls.count('ip route show') == 1
