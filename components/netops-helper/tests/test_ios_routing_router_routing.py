"""ROUTER-ROUTING public ssh_read, fake SSH transport only, measured IOSv/Cisco examples."""
import json
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.auth import TargetAuth
from netops_helper.read_policy import render_read_query

HERE = Path(__file__).parent
LIVE = HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12_router_routing'
DOCS = HERE / 'fixtures/docs/cisco_ios/router-routing'
# Independent command expectations; the same cases drive live verification.
CASES = [
    ('vrfs', {}, 'show ip vrf', 'docs:vrfs'),
    ('vrf_route_lookup', {'vrf': 'blue', 'address': '192.0.2.1'}, 'show ip route vrf blue 192.0.2.1', 'route'),
    ('vrf_arp_table', {'vrf': 'blue'}, 'show arp vrf blue', 'arp'),
    ('vrf_ip_interfaces', {'vrf': 'vpn152-1'}, 'show ip vrf interfaces vpn152-1', 'docs:vrf_ip_interfaces'),
    ('bgp_neighbor', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1', 'docs:bgp_neighbor'),
    ('bgp_prefix', {'address': '192.0.2.1'}, 'show ip bgp 192.0.2.1', 'docs:bgp_prefix'),
    ('bgp_advertised_routes', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1 advertised-routes', 'docs:bgp_advertised_routes'),
    ('bgp_routes', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1 routes', 'live:bgp_routes'),
    ('ospf_neighbor_detail', {}, 'show ip ospf neighbor detail', 'live:ospf_neighbor_detail'),
    ('ospf_interface', {'interface': 'GigabitEthernet0/1.10'}, 'show ip ospf interface GigabitEthernet0/1.10', 'live:ospf_interface'),
    ('ospf_database', {}, 'show ip ospf database', 'live:ospf_database'),
    ('ip_protocols', {}, 'show ip protocols', 'live:ip_protocols'),
    ('ipv6_route_table', {}, 'show ipv6 route', 'docs:ipv6_route_table'),
    ('ospfv3_neighbors', {}, 'show ipv6 ospf neighbor', 'docs:ospfv3_neighbors'),
    ('bgp_ipv6_summary', {}, 'show bgp ipv6 unicast summary', 'docs:bgp_ipv6_summary'),
    ('ip_interface_details', {'interface': 'GigabitEthernet0/1.10'}, 'show ip interface GigabitEthernet0/1.10', 'live:ip_interface'),
    ('ipv6_interface_details', {'interface': 'GigabitEthernet0/1'}, 'show ipv6 interface GigabitEthernet0/1', 'docs:ipv6_interface_details'),
    ('cef_lookup', {'address': '192.0.2.1'}, 'show ip cef 192.0.2.1 detail', 'live:cef'),
    ('adjacency_details', {'interface': 'GigabitEthernet0/1'}, 'show adjacency GigabitEthernet0/1 detail', 'live:adjacency'),
    ('bfd_neighbors', {}, 'show bfd neighbors details', 'docs:bfd_neighbors'),
    ('route_maps', {}, 'show route-map', 'docs:route_maps'),
    ('ip_policy', {}, 'show ip policy', 'live:ip_policy'),
]
INVENTORY = {'interfaces': ['GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/1.10', 'Loopback0'],
             'addresses': ['192.0.2.1'], 'vrfs': ['blue', 'vpn152-1'], 'lookup_prefixes': ['198.51.100.0/24']}


def fixture(source):
    if source == 'route':
        return (HERE / 'fixtures/docs/cisco_ios/route_lookup_ecmp.txt').read_text()
    if source == 'arp':
        return (HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12/arp_table.txt').read_text()
    kind, name = source.split(':')
    return ((LIVE if kind == 'live' else DOCS) / (name + '.out')).read_text()


def gateway(tmp_path, monkeypatch, outputs, rc=0):
    import test_proxy_contracts as contracts
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform='cisco_ios', device_types=['router', 'switch'],
                   enabled_queries=[case[0] for case in CASES] + list(EMPTY_TABLES),
                   read_inventory=INVENTORY)
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'cisco_ios')))
    proxy = module.Proxy()
    calls = []
    def transport(auth, platform, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (LIVE / 'version.out').read_text()
        return rc, outputs[command]
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, proxy, calls


def read(contracts, proxy, query, parameters, *, index=1, **page):
    forwarded = proxy.request(contracts._request(index, 'ssh_read', {
        'target': 'device-a', 'platform': 'cisco_ios', 'query': query, 'parameters': parameters, **page}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(args['target'], args['auth_context'])
    return engine.ssh_read(auth, 'cisco_ios', query, parameters, page.get('offset', 0), page.get('max_bytes', 48000),
                           page.get('content_sha256'))


@pytest.mark.parametrize('query,parameters,command,source', CASES, ids=[c[0] for c in CASES])
def test_public_real_output(tmp_path, monkeypatch, query, parameters, command, source):
    body = fixture(source)
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, query, parameters)
    assert calls[-1] == command
    assert result['rc'] == 0
    # Raw details are intentionally retained (protocol/reset reason/LSDB/ND/CEF/PBR).
    assert result['untrusted_device_output'].strip() == body.strip()
    assert result['ok']
    if query == 'ip_interface_details':
        assert 'firmware_support' not in result
        assert 'warnings' not in result
        assert result['normalized']['records'][0]['prefix_length'] == 24
    if query == 'ipv6_interface_details':
        assert len(result['normalized']['records']) == 2
        assert 'ND reachable time is 30000' in result['untrusted_device_output']
    if query == 'ipv6_route_table':
        assert len(result['normalized']['records']) == 9
        assert result['normalized']['coverage']['complete']
    if query == 'vrfs':
        rows = result['normalized']['records']
        assert len(rows) == 2 and len(rows[0]['interfaces']) == 4
    if query.startswith('vrf_'):
        assert all(row['vrf'] == parameters['vrf'] for row in result['normalized']['records'])


@pytest.mark.parametrize('query,parameters,command,source', CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize('failure', ['refused', 'truncated'])
def test_public_refusal_and_incomplete_capture(tmp_path, monkeypatch, query, parameters, command, source, failure):
    # Derived negatives from real output; never represented as new measurements.
    body = ('% Authorization failed.\n' if failure == 'refused' else fixture(source) + '\n--More--')
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, query, parameters)
    assert result['status'] == ('permission_denied' if failure == 'refused' else 'truncated')
    normalized = result['normalized']
    assert not normalized.get('coverage', {}).get('complete', False)
    assert not normalized.get('records')


@pytest.mark.parametrize('query,command', [(q, cmd) for q, _, cmd, _ in CASES
                                          if q in {'vrfs', 'route_maps', 'ospfv3_neighbors', 'bfd_neighbors',
                                                   'ipv6_route_table'}])
@pytest.mark.parametrize('capture', ['empty', 'failed', 'refused'])
def test_empty_ios_routing_preserves_transport_and_cli_errors(tmp_path, monkeypatch, query, command, capture):
    body = fixture('live:' + query)
    assert not body.strip()
    if capture == 'refused':
        body = (HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12_router_probes/ro/ping_source.out').read_text()
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body}, rc=255 if capture == 'failed' else 0)
    result = read(contracts, proxy, query, {})
    assert calls[-1] == command
    if capture == 'empty':
        assert result['ok'] and result['status'] == 'empty', result
        assert result['normalized']['records'] == []
    else:
        assert not result['ok'] and result['error_code'] == 'device_cli_error', result


@pytest.mark.parametrize('code,protocol', [('D', 'eigrp'), ('EX', 'eigrp'), ('I1', 'isis'), ('I2', 'isis'),
                                           ('IA', 'isis'), ('ND', 'nd'), ('NDp', 'nd')])
def test_ios_ipv6_route_recognizes_documented_protocol_codes(tmp_path, monkeypatch, code, protocol):
    command = 'show ipv6 route'
    # Derived from the Cisco RIB fixture with codes from the same IOS command reference.
    body = fixture('docs:ipv6_route_table').replace('\nB   2001:db8:3::2', f'\n{code}   2001:db8:3::2')
    contracts, proxy, _ = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, 'ipv6_route_table', {})
    assert result['normalized']['coverage']['complete']
    assert result['normalized']['records'][0]['protocol'] == protocol


def test_ios_ipv6_interface_keeps_addresses_with_multiple_flags(tmp_path, monkeypatch):
    interface = 'GigabitEthernet0/1'
    command = 'show ipv6 interface ' + interface
    body = fixture('docs:ipv6_interface_details').replace('2001:db8:2::0/64', '2001:db8:2::0/64 [EUI/CAL/PRE]')
    contracts, proxy, _ = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, 'ipv6_interface_details', {'interface': interface})
    assert result['normalized']['coverage']['complete']
    assert any(row['ip'] == '2001:db8:2::130' for row in result['normalized']['records'])


@pytest.mark.parametrize('rd', ['192.0.2.100:9', '65000.1:9'])
def test_ios_vrf_keeps_dotted_route_distinguishers(tmp_path, monkeypatch, rd):
    command = 'show ip vrf'
    body = fixture('docs:vrfs').replace('20:20', rd, 1)
    assert rd in body
    contracts, proxy, _ = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, 'vrfs', {})
    assert result['normalized']['coverage']['complete']
    assert rd in [row['rd'] for row in result['normalized']['records']]


def test_blank_ios_vrf_arp_remains_an_error(tmp_path, monkeypatch):
    # IOSv returns the same two blank lines when the requested VRF no longer exists.
    command = 'show arp vrf blue'
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: fixture('live:vrfs')})
    result = read(contracts, proxy, 'vrf_arp_table', {'vrf': 'blue'})
    assert calls[-1] == command
    assert not result['ok'] and result['error_code'] == 'empty', result


EMPTY_TABLES = {'arp_table': 'show ip arp', 'ipv6_neighbors': 'show ipv6 neighbors',
                'mac_table': 'show mac address-table', 'lldp_neighbors': 'show lldp neighbors detail',
                'cdp_neighbors': 'show cdp neighbors detail'}


@pytest.mark.parametrize('query,command', EMPTY_TABLES.items())
@pytest.mark.parametrize('scenario', ['empty', 'failed', 'refused'])
def test_empty_ios_catalog_tables(tmp_path, monkeypatch, query, command, scenario):
    # DERIVED: exercise these queries with the measured IOS blank reply or RO refusal.
    body = fixture('live:vrfs') if scenario != 'refused' else (
        HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12_router_probes/ro/ping_source.out').read_text()
    ctx, proxy, calls = gateway(tmp_path, monkeypatch, {command: body}, rc=255 if scenario == 'failed' else 0)
    result = read(ctx, proxy, query, {})
    assert calls[-1] == command
    if scenario == 'empty':
        assert result['ok'] and result['status'] == 'empty' and result['normalized']['records'] == [], result
    else:
        assert not result['ok'] and result['error_code'] == 'device_cli_error', result


@pytest.mark.parametrize('value', ['red', 'blue;reload', 'blue\nshow version'])
def test_vrf_not_enrolled_or_injected(value):
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', 'vrf_arp_table', {'vrf': value}, INVENTORY)


def test_prefix_lookup_is_network_address_and_inventory_bound():
    assert render_read_query('cisco_ios', 'cef_lookup', {'address': '198.51.100.0/24'}, INVENTORY)[1] == 'show ip cef 198.51.100.0 detail'
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', 'cef_lookup', {'address': '203.0.113.1'}, INVENTORY)


def test_secondary_addresses_from_cisco_documentation():
    result = tables.parse('cisco_ios', 'ip_interface', 'ip_interface_details', fixture('docs:ip_interface_secondary'))
    assert result['ok'] and len(result['records']) == 2
    assert [row['prefix_length'] for row in result['records']] == [28, 24]


def test_header_only_rib_is_not_empty_success():
    result = tables.parse('cisco_ios', 'route', 'ipv6_route_table', fixture('docs:ipv6_route_table').split('Codes:')[0])
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_interface_header_only_is_incomplete():
    result = tables.parse('cisco_ios', 'ip_interface', 'ip_interface_details', fixture('live:ip_interface').split('Internet address')[0])
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_unknown_interface_line_does_not_claim_complete_coverage():
    result = tables.parse('cisco_ios', 'ip_interface', 'ip_interface_details', fixture('live:ip_interface') + '\nUnrecognized state: unavailable\n')
    assert result['status'] == 'unparsed' and result['unparsed']
    assert not result['coverage']['complete']


def test_vrf_route_without_paths_is_incomplete():
    body = fixture('route').split('Routing Descriptor Blocks:')[0]
    result = tables.parse('cisco_ios', 'route', 'vrf_route_lookup', body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_ipv6_entry_without_next_hop_is_incomplete():
    body = fixture('docs:ipv6_route_table').split('     via ')[0]
    result = tables.parse('cisco_ios', 'route', 'ipv6_route_table', body)
    assert result['status'] == 'unparsed' and not result['records']


def test_ipv6_legend_without_header_is_incomplete():
    body = fixture('docs:ipv6_route_table').splitlines()[1] + '\n'
    result = tables.parse('cisco_ios', 'route', 'ipv6_route_table', body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
