"""G69 public ssh_read through proxy; transport uses measured IOL XE 17.18.2 captures."""
import json
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_helper.read_policy import render_read_query

HERE = Path(__file__).parent
LIVE = HERE / 'fixtures/real/cisco_xe/iolxe_17.18.2_g69'
# Independent command expectations; the same cases drive live verification.
CASES = [
    ('vrfs', {}, 'show ip vrf'),
    ('vrf_route_lookup', {'vrf': 'blue', 'address': '192.0.2.1'}, 'show ip route vrf blue 192.0.2.1'),
    ('vrf_arp_table', {'vrf': 'blue'}, 'show arp vrf blue'),
    ('vrf_ip_interfaces', {'vrf': 'blue'}, 'show ip vrf interfaces blue'),
    ('bgp_neighbor', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1'),
    ('bgp_prefix', {'address': '192.0.2.1'}, 'show ip bgp 192.0.2.1'),
    ('bgp_advertised_routes', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1 advertised-routes'),
    ('bgp_routes', {'address': '192.0.2.1'}, 'show ip bgp neighbors 192.0.2.1 routes'),
    ('ospf_neighbor_detail', {}, 'show ip ospf neighbor detail'),
    ('ospf_interface', {'interface': 'Ethernet0/1.10'}, 'show ip ospf interface Ethernet0/1.10'),
    ('ospf_database', {}, 'show ip ospf database'),
    ('ip_protocols', {}, 'show ip protocols'),
    ('ipv6_route_table', {}, 'show ipv6 route'),
    ('ospfv3_neighbors', {}, 'show ipv6 ospf neighbor'),
    ('bgp_ipv6_summary', {}, 'show bgp ipv6 unicast summary'),
    ('ip_interface_details', {'interface': 'Ethernet0/1.10'}, 'show ip interface Ethernet0/1.10'),
    ('ipv6_interface_details', {'interface': 'Ethernet0/1.10'}, 'show ipv6 interface Ethernet0/1.10'),
    ('cef_lookup', {'address': '192.0.2.1'}, 'show ip cef 192.0.2.1 detail'),
    ('adjacency_details', {'interface': 'Ethernet0/1.10'}, 'show adjacency Ethernet0/1.10 detail'),
    ('bfd_neighbors', {}, 'show bfd neighbors details'),
    ('route_maps', {}, 'show route-map'),
    ('ip_policy', {}, 'show ip policy'),
]
INVENTORY = {'interfaces': ['Ethernet0/1.10'], 'addresses': ['192.0.2.1'],
             'vrfs': ['blue'], 'lookup_prefixes': ['198.51.100.0/24']}


def fixture(query):
    return (LIVE / (query + '.out')).read_text()


def gateway(tmp_path, monkeypatch, outputs):
    import test_proxy_contracts as contracts
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform='cisco_xe', device_types=['router'], enabled_queries=[case[0] for case in CASES],
                   read_inventory=INVENTORY)
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'cisco_xe')))
    proxy = module.Proxy()
    calls = []
    def transport(auth, platform, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (LIVE / 'version.out').read_text()
        return 0, outputs[command]
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, proxy, calls


def read(contracts, proxy, query, parameters, *, index=1, **page):
    forwarded = proxy.request(contracts._request(index, 'ssh_read', {
        'target': 'device-a', 'platform': 'cisco_xe', 'query': query, 'parameters': parameters, **page}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(args['target'], args['auth_context'])
    return engine.ssh_read(auth, 'cisco_xe', query, parameters, page.get('offset', 0), page.get('max_bytes', 48000),
                           page.get('content_sha256'))


@pytest.mark.parametrize('query,parameters,command', CASES, ids=[c[0] for c in CASES])
def test_public_real_output(tmp_path, monkeypatch, query, parameters, command):
    body = fixture(query)
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, query, parameters)
    assert calls[-1] == command
    assert result['rc'] == 0
    assert result['untrusted_device_output'].strip() == body.strip()
    if query.startswith('bgp_') or query in {'vrf_route_lookup', 'vrf_ip_interfaces'}:
        assert result['status'] == 'not_applicable'
    elif not body.strip():
        assert result['status'] == 'empty'
    else:
        # Raw protocol/CEF/PBR details have no structured table adapter.
        expected = 'ok' if query in {'ip_interface_details', 'ipv6_route_table'} else 'unparsed'
        assert result['status'] == expected
        assert result['ok']
    if query == 'ip_interface_details':
        assert result['normalized']['records'][0]['prefix_length'] == 24
        assert result['normalized']['records'][0]['interface'] == 'Ethernet0/1.10'
    if query == 'ipv6_route_table':
        assert len(result['normalized']['records']) == 1
        assert result['normalized']['coverage']['complete']


# Task 473: the same public queries against the permanently configured lab
# scenarios (VRF blue, eBGP v4/v6 with BFD, OSPFv3, secondary/IPv6 addresses, PBR).
POPULATED = HERE / 'fixtures/real/cisco_xe/iolxe_17.18.2_g69_populated'
POPULATED_CASES = [case for case in CASES if (POPULATED / (case[0] + '.out')).is_file()]
POPULATED_RECORDS = {
    'vrfs': [{'name': 'blue', 'rd': '65007:69', 'interfaces': ['Ethernet0/2']}],
    'vrf_route_lookup': [{'prefix': '192.0.2.0/24', 'next_hop': '203.0.113.250', 'protocol': 'static', 'vrf': 'blue'}],
    'vrf_arp_table': [{'ip': '203.0.113.250', 'mac': '00:00:5e:00:53:01', 'interface': 'Ethernet0/2', 'vrf': 'blue'},
                      {'ip': '203.0.113.249', 'mac': '00:00:5e:00:53:02', 'interface': 'Ethernet0/2', 'vrf': 'blue'}],
    'vrf_ip_interfaces': [{'interface': 'Ethernet0/2', 'ip': '203.0.113.249', 'vrf': 'blue', 'oper_status': 'up'}],
    'ipv6_route_table': [
        {'prefix': '2001:db8:1::/64', 'protocol': 'connected', 'interface': 'Ethernet0/1.10'},
        {'prefix': '2001:db8:1::7/128', 'protocol': 'local'},
        {'prefix': '2001:db8:3::1/128', 'protocol': 'ospf', 'next_hop': 'fe80::13', 'interface': 'Ethernet0/1.10'},
        {'prefix': '2001:db8:3::7/128', 'protocol': 'local', 'interface': 'Loopback0'},
        {'prefix': '2001:db8:4::/64', 'protocol': 'static', 'interface': 'Null0'},
        {'prefix': '2001:db8:5::/64', 'protocol': 'bgp', 'next_hop': 'fe80::13', 'interface': 'Ethernet0/1.10'},
        {'prefix': 'ff00::/8', 'protocol': 'local'}],
    'ip_interface_details': [{'interface': 'Ethernet0/1.10', 'ip': '192.0.2.7', 'prefix_length': 24},
                             {'interface': 'Ethernet0/1.10', 'ip': '203.0.113.251', 'prefix_length': 24}],
    'ipv6_interface_details': [{'interface': 'Ethernet0/1.10', 'ip': 'fe80::10'},
                               {'interface': 'Ethernet0/1.10', 'ip': '2001:db8:1::7', 'prefix_length': 64}],
}
# Raw protocol details keep the full CLI text; these facts must reach the caller unchanged.
POPULATED_FACTS = {
    'bgp_neighbor': ('BGP state = Established', 'BFD peer is Up', 'remote AS 65001'),
    'bgp_prefix': ('BGP routing table entry for 192.0.2.0/24', 'valid, external, best'),
    'bgp_advertised_routes': ('Total number of prefixes 2',),
    'bgp_routes': ('Total number of prefixes 3', '192.0.2.1'),
    'ospfv3_neighbors': ('FULL/BDR', 'Process ID 69'),
    'bgp_ipv6_summary': ('2001:db8:1::1', '65001'),
    'bfd_neighbors': ('Session state is UP', 'Registered protocols: BGP'),
    'route_maps': ('route-map G69-PBR, permit, sequence 10', 'Policy routing matches: 2 packets'),
    'ip_policy': ('Ethernet0/1.10 G69-PBR',),
}


def test_populated_scenarios_cover_the_six_open_ids():
    covered = {case[0] for case in POPULATED_CASES}
    assert covered == set(POPULATED_RECORDS) | set(POPULATED_FACTS)


@pytest.mark.parametrize('query,parameters,command', POPULATED_CASES, ids=[c[0] for c in POPULATED_CASES])
def test_public_populated_output(tmp_path, monkeypatch, query, parameters, command):
    body = (POPULATED / (query + '.out')).read_text()
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, query, parameters)
    assert calls[-1] == command
    assert result['rc'] == 0 and result['ok']
    assert result['untrusted_device_output'].strip() == body.strip()
    if query in POPULATED_RECORDS:
        assert result['status'] == 'ok'
        records = result['normalized']['records']
        assert len(records) == len(POPULATED_RECORDS[query])
        for record, expected in zip(records, POPULATED_RECORDS[query]):
            assert {key: record[key] for key in expected} == expected
        assert not result['normalized']['unparsed']
    else:
        assert result['status'] == 'unparsed'
        for fact in POPULATED_FACTS[query]:
            assert fact in result['untrusted_device_output']


def test_ipv6_bgp_route_tag_is_parsed_and_incomplete_entry_is_not():
    body = (POPULATED / 'ipv6_route_table.out').read_text()
    result = tables.parse('cisco_xe', 'route', 'ipv6_route_table', body)
    assert result['coverage']['complete']
    assert any(r['protocol'] == 'bgp' and r['prefix'] == '2001:db8:5::/64' for r in result['records'])
    cut = body.split('[20/0], tag 65001')[0] + '[20/0], tag 65001\n'
    partial = tables.parse('cisco_xe', 'route', 'ipv6_route_table', cut)
    assert not partial['coverage']['complete']
    assert not any(r['protocol'] == 'bgp' for r in partial['records'])


@pytest.mark.parametrize('complete', [False, True], ids=['missing-last-route', 'full-table'])
@pytest.mark.parametrize('multipath', [False, True], ids=['single-path', 'multipath'])
def test_public_ipv6_rib_matches_header_count(tmp_path, monkeypatch, complete, multipath):
    lines = (POPULATED / 'ipv6_route_table.out').read_text().splitlines(keepends=True)
    if not complete:
        lines = lines[:27]
    if multipath:
        lines.insert(27, '     via fe80::14, Ethernet0/1.10\n')
    command = 'show ipv6 route'
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: ''.join(lines)})
    result = read(contracts, proxy, 'ipv6_route_table', {})

    assert calls[-1] == command
    assert result['rc'] == 0
    normalized = result['normalized']
    assert len(normalized['records']) == (7 if complete else 6) + multipath
    assert normalized['coverage']['complete'] is complete
    assert result['status'] == ('ok' if complete else 'unparsed')


@pytest.mark.parametrize('query,parameters,command', CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize('failure', ['refused', 'truncated'])
def test_public_refusal_and_incomplete_capture(tmp_path, monkeypatch, query, parameters, command, failure):
    body = '% Authorization failed.\n' if failure == 'refused' else fixture(query) + '\n--More--'
    contracts, proxy, calls = gateway(tmp_path, monkeypatch, {command: body})
    result = read(contracts, proxy, query, parameters)
    assert result['status'] == ('permission_denied' if failure == 'refused' else 'truncated')
    normalized = result.get('normalized', {})
    assert not normalized.get('coverage', {}).get('complete', False)
    assert not normalized.get('records')


@pytest.mark.parametrize('value', ['red', 'blue;reload', 'blue\nshow version'])
def test_vrf_not_enrolled_or_injected(value):
    with pytest.raises(ValueError):
        render_read_query('cisco_xe', 'vrf_arp_table', {'vrf': value}, INVENTORY)


def test_prefix_lookup_is_network_address_and_inventory_bound():
    assert render_read_query('cisco_xe', 'cef_lookup', {'address': '198.51.100.0/24'}, INVENTORY)[1] == 'show ip cef 198.51.100.0 detail'
    with pytest.raises(ValueError):
        render_read_query('cisco_xe', 'cef_lookup', {'address': '203.0.113.1'}, INVENTORY)


def test_incomplete_rib_does_not_claim_success():
    body = fixture('ipv6_route_table').split('     via ')[0]
    result = tables.parse('cisco_xe', 'route', 'ipv6_route_table', body)
    assert not result['records'] and not result['coverage']['complete']


def test_incomplete_interface_does_not_claim_success():
    body = fixture('ip_interface_details').split('Internet address')[0]
    result = tables.parse('cisco_xe', 'ip_interface', 'ip_interface_details', body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_routing_runbook_with_inconclusive_version_withholds_findings(monkeypatch):
    from dataclasses import replace
    from conftest import _target

    calls = []

    def read(auth, platform, command, **kwargs):
        assert platform == "cisco_xe" and command == "show version"
        calls.append(command)
        return 0, fixture("version")

    monkeypatch.setattr(engine, "_exec_read", read)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    # Identity is checked on the wire before the shared redaction removes the colliding release.
    target = _target("cisco_xe", "version", secret="17.18.2")
    auth = replace(target, enabled_queries=("version", "route_lookup"),
                   read_inventory={"addresses": ("192.0.2.1",)},
                   egress=EgressPolicy(addresses=(target.host,), tcp_ports=(target.port,)))
    result = engine.triage_routing(auth, "192.0.2.1")
    assert not result["ok"] and result["verdict"] == "incomplete"
    assert result["findings"]["identity"]["status"] == "unknown"
    assert calls == ["show version"]
