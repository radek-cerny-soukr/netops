"""G117 public reads replay real anonymized cEOS captures over a fake physical SSH transport."""
import json
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.auth import TargetAuth, EgressPolicy
from netops_helper.query_catalog.arista import QUERIES
from netops_helper.read_policy import render_read_query, _validate_query_command

REAL = Path(__file__).parent / 'fixtures/real/arista_eos/g117_ceos_4.36.1F'
INDEX = json.loads((REAL / 'index.json').read_text())
INVENTORY = {'vrfs': ('default',), 'addresses': ('127.0.0.1', '192.0.2.1', '::1'), 'interfaces': ('Vlan10',)}


def auth():
    return TargetAuth(alias='ceos', host='192.0.2.10', port=2253, login='netops-ro', secret='fixture-password',
                      host_key_fingerprint='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                      ssh_platform='arista_eos', enabled_queries=tuple(QUERIES), read_inventory=INVENTORY,
                      egress=EgressPolicy(addresses=('192.0.2.10',)))


@pytest.mark.parametrize('key', [key for key in INDEX if not key.startswith('version')])
def test_real_query_via_fake_physical_transport(key, monkeypatch):
    row = INDEX[key]
    body = (REAL / row['file']).read_text()
    calls = []
    def physical(target, profile, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (REAL / 'version_ro.out').read_text()
        assert command == row['command']
        return row['rc'], body
    monkeypatch.setattr(engine, '_exec_read', physical)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    result = engine.ssh_read(auth(), 'arista_eos', row['query'], row['parameters'], 0, 48000)
    assert row['command'] in calls
    assert result['rc'] == row['rc']
    assert result.get('untrusted_device_output', '').strip() == body.strip()
    absent = '% BGP inactive' in body or '% OSPF3 process does not exist in vrf ' in body
    assert result['ok'] == (row['rc'] == 0 or absent)
    if absent:
        assert result['normalized']['status'] == 'not_applicable'
    if row['rc'] != 0:
        assert result['normalized']['status'] != 'ok'


@pytest.mark.parametrize('name,parameters', [
    ('ping', {'vrf': 'default', 'address': '127.0.0.1', 'source': '192.0.2.99'}),
    ('ping', {'vrf': 'default;reload', 'address': '127.0.0.1', 'source': '127.0.0.1'}),
    ('ping', {'vrf': 'default', 'address': '::1', 'source': '127.0.0.1'}),
    ('traceroute', {'vrf': 'default', 'address': '127.0.0.1', 'count': '20'}),
    ('route_table_vrf', {'vrf': 'unlisted'}),
    ('bgp_peer', {'address': '192.0.2.99'}),
    ('ospf_interface_detail', {'interface': 'Vlan11'}),
])
def test_parameters_must_be_typed_and_enrolled(name, parameters):
    with pytest.raises(ValueError):
        render_read_query('arista_eos', name, parameters, INVENTORY)


@pytest.mark.parametrize('command', ['ping {address}', 'ping vrf {vrf} {address} repeat 500',
                                    'traceroute {address}', 'ping vrf {vrf} {address} source {source} repeat 5; reload'])
def test_probe_exception_is_exact_and_eos_only(command):
    with pytest.raises(RuntimeError):
        _validate_query_command('arista_eos', command)
    with pytest.raises(RuntimeError):
        _validate_query_command('cisco_ios', 'ping vrf {vrf} {address} source {source} repeat 5')


def test_real_vrf_table_retains_route_scope():
    text = (REAL / 'route_table_vrf_ro.out').read_text()
    result = tables.parse('arista_eos', 'route', 'route_table_vrf', text)
    assert result['ok'] and result['records']
    assert all(row['vrf'] == 'default' for row in result['records'])
    assert any(row['protocol'] == 'ospf' for row in result['records'])


def test_disabled_ipv6_is_not_an_empty_success():
    text = (REAL / 'ipv6_route_table_ro.out').read_text()
    result = tables.parse('arista_eos', 'route', 'ipv6_route_table', text)
    assert not result['ok'] and result['status'] == 'not_applicable'
    assert not result['coverage']['complete']


def test_incomplete_real_ipv6_header_is_not_an_empty_table():
    text = (REAL / 'ipv6_route_table_ro.out').read_text().split('Displaying')[0]
    result = tables.parse('arista_eos', 'route', 'ipv6_route_table', text)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_incomplete_capture_is_reported(monkeypatch):
    row = INDEX['ospf_neighbors_detail_ro']
    # DERIVED: truncate a real output at an existing boundary and append the CLI pager marker.
    body = (REAL / row['file']).read_text().split('Neighbor priority')[0] + '--More--'
    monkeypatch.setattr(engine, '_exec_read', lambda *a, **kw: (0, body))
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    result = engine.ssh_read(auth(), 'arista_eos', row['query'], {}, 0, 48000)
    assert result['normalized']['status'] == 'truncated'


VENDOR = json.loads((REAL / 'vendor_examples.json').read_text())


@pytest.mark.parametrize('name', list(VENDOR))
def test_vendor_real_output_excerpt_survives_public_read(name, monkeypatch):
    # Real vendor examples are excerpts, never claimed to be a complete measured lab table.
    text = VENDOR[name]['text']
    parameters = INDEX[name + '_ro']['parameters'] if name + '_ro' in INDEX else {}
    command = QUERIES[name].command.format_map(parameters)
    def physical(target, profile, selected, **kwargs):
        if selected == 'show version':
            return 0, (REAL / 'version_ro.out').read_text()
        assert selected == command
        return 0, text
    monkeypatch.setattr(engine, '_exec_read', physical)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    result = engine.ssh_read(auth(), 'arista_eos', name, parameters, 0, 48000)
    assert result['ok'] and result['untrusted_device_output'].strip() == text.strip()
    assert result['normalized']['status'] == 'unparsed'


def test_vendor_real_ipv6_ecmp_is_parsed_without_losing_hops():
    result = tables.parse('arista_eos', 'route', 'ipv6_route_table', VENDOR['ipv6_route_table']['text'])
    assert result['ok'] and result['coverage']['complete']
    assert len(result['records']) == 5
    assert {r['interface'] for r in result['records']} == {'Vlan3601', 'Vlan3602', 'Vlan3608', 'Vlan3610', 'Vlan3611'}
    assert all(r['protocol'] == 'ospf' and ':' in r['prefix'] for r in result['records'])


def test_cut_ipv6_route_after_valid_hops_is_incomplete():
    # DERIVED: remove all next-hop lines from a second copy of the documented route.
    text = VENDOR['ipv6_route_table']['text']
    prefix = next(line for line in text.splitlines() if line.startswith('O '))
    result = tables.parse('arista_eos', 'route', 'ipv6_route_table', text + prefix + '\n')
    assert result['records'] and result['status'] == 'unparsed'
    assert not result['coverage']['complete']
