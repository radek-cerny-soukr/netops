"""G90: real NX-OS captures through the Helper transport boundary."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, tables
from netops_helper.auth import PolicyScopeError
from netops_helper.read_policy import render_read_query

FIX = Path(__file__).parent / 'fixtures/real/cisco_nxos/g90_9.3.12'
PROFILE = 'cisco_nxos'
INVENTORY = {'addresses': ('192.0.2.1', '198.51.100.1', '2001:db8::1'),
             'lookup_prefixes': ('192.0.2.0/24', '198.51.100.11/32'), 'interfaces': ('Vlan10',),
             'route_maps': ('pbr-sample',), 'vrfs': ('management', 'default')}


def fixture(name):
    return (FIX / name).read_text()


@pytest.fixture
def wire(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    calls = []

    def install(query, command, output, rc=0, inventory=INVENTORY):
        auth = replace(_target(PROFILE, query), read_inventory=inventory)

        def read(target, profile, actual):
            calls.append(actual)
            if actual == 'show version':
                return 0, fixture('raw/version.out')
            assert actual == command
            return rc, output
        monkeypatch.setattr(engine, 'read_from_device', read)
        return auth, calls
    return install


# These commands and visible facts come from the measured CLI or vendor examples,
# independently of the catalogue implementation. Details stay readable sourced text.
DETAILS = [
    ('ospf_neighbors_detail', {}, 'show ip ospf neighbors detail', 'raw/ospf_neighbors_detail.out', 'Dead timer due'),
    ('ospf_process', {}, 'show ip ospf', 'raw/ospf_process.out', 'SPF throttling'),
    ('ospf_interface_detail', {'interface': 'Vlan10'}, 'show ip ospf interface Vlan10', 'admin/ospf_interface_detail.out', 'Timer intervals: Hello 10, Dead 40'),
    ('ospf_database', {}, 'show ip ospf database', 'raw/ospf_database.out', 'Network Link States'),
    ('bgp_neighbor_detail', {'address': '198.51.100.1'}, 'show bgp ipv4 unicast neighbors 198.51.100.1', 'vendor/bgp_neighbor_detail.out', 'Last reset by peer'),
    ('bgp_prefix_detail', {'prefix': '198.51.100.11/32'}, 'show bgp ipv4 unicast 198.51.100.11/32', 'vendor/bgp_prefix_detail.out', 'localpref 100, weight 0'),
    ('bgp_advertised_routes', {'address': '192.0.2.1'}, 'show bgp ipv4 unicast neighbors 192.0.2.1 advertised-routes', 'vendor/bgp_advertised_routes.out', '32768'),
    ('bfd_neighbors_detail', {}, 'show bfd neighbors details', 'vendor/bfd_neighbors_detail.out', 'MinTxInt: 50000 us'),
    ('ipv6_route_table', {}, 'show ipv6 route', 'vendor/ipv6_route_table.out', 'ospf-100'),
    ('bgp_ipv6_summary', {}, 'show bgp ipv6 unicast summary', 'vendor/bgp_ipv6_summary.out', 'IPv6 Unicast'),
    ('ospfv3_neighbors', {}, 'show ipv6 ospfv3 neighbors', 'vendor/ospfv3_neighbors.out', 'FULL/DR'),
    ('forwarding_ipv4_route', {}, 'show forwarding ipv4 route', 'vendor/forwarding_ipv4_route.out', 'PUSH 24030'),
    ('ip_adjacency', {}, 'show ip adjacency', 'raw/ip_adjacency.out', 'Total number of entries: 5'),
    ('route_maps', {}, 'show route-map', 'vendor/route_maps.out', 'Set clauses:'),
    ('route_map_counters', {'route_map': 'pbr-sample'}, 'show route-map pbr-sample pbr-statistics', 'vendor/route_map_counters.out', '84 packets'),
    ('ip_policy', {}, 'show ip policy', 'vendor/ip_policy.out', 'Inactive'),
]


@pytest.mark.parametrize('query,parameters,command,path,visible', DETAILS, ids=[row[0] for row in DETAILS])
def test_detail_preserves_real_output_and_diagnostic_facts(wire, query, parameters, command, path, visible):
    body = fixture(path)
    auth, calls = wire(query, command, body)
    result = engine.ssh_read(auth, PROFILE, query, parameters, 0, 16000)
    assert result['ok'], result
    assert visible in result['untrusted_device_output']
    assert result['content_sha256']
    assert calls == ['show version', command]


@pytest.mark.parametrize('query,parameters,command,path,visible', DETAILS, ids=[row[0] for row in DETAILS])
def test_details_do_not_hide_an_incomplete_capture(wire, query, parameters, command, path, visible):
    body = fixture(path) + '\n--More--'
    auth, _ = wire(query, command, body)
    result = engine.ssh_read(auth, PROFILE, query, parameters, 0, 16000)
    assert result['status'] == 'truncated'
    assert result['normalized']['coverage']['complete'] is False


@pytest.mark.parametrize('query,parameters,command,path,visible', DETAILS, ids=[row[0] for row in DETAILS])
def test_details_report_the_real_disabled_feature_refusal(wire, query, parameters, command, path, visible):
    auth, _ = wire(query, command, fixture('raw/bfd_neighbors_detail.out'), rc=16)
    result = engine.ssh_read(auth, PROFILE, query, parameters, 0, 16000)
    assert not result['ok'] and result['status'] == 'unsupported'


@pytest.mark.parametrize('table,kwargs,query,command,path,count', [
    ('route', {}, 'route_table_vrf', 'show ip route vrf management', 'raw/route_table_vrf.out', 3),
    ('route', {'ip': '192.0.2.1'}, 'route_lookup_vrf', 'show ip route 192.0.2.1 vrf management', 'raw/route_lookup_vrf.out', 1),
    ('neighbor_l3', {}, 'arp_table_vrf', 'show ip arp vrf management', 'raw/arp_table_vrf.out', 1),
    ('ip_interface', {}, 'ip_interfaces_vrf', 'show ip interface brief vrf management', 'raw/ip_interfaces_vrf.out', 1),
    ('ospf_neighbor', {}, 'ospf_neighbors_vrf', 'show ip ospf neighbors vrf management', 'raw/ospf_neighbors_vrf.out', 4),
])
def test_switch_read_selects_an_enrolled_vrf(wire, table, kwargs, query, command, path, count):
    # OSPF is configured only in default; use its measured VRF, not a fabricated management process.
    vrf = 'default' if table == 'ospf_neighbor' else 'management'
    command = command.replace('vrf management', 'vrf ' + vrf)
    auth, calls = wire(query, command, fixture(path))
    result = engine.switch_read(auth, table, vrf=vrf, **kwargs)
    assert result['ok'] and len(result['records']) == count, result
    assert {row['vrf'] for row in result['records']} == {vrf}
    assert calls == ['show version', command]


def test_full_ipv6_rib_and_ospfv3_use_distinct_family_queries(wire):
    auth, calls = wire('ipv6_route_table', 'show ipv6 route', fixture('vendor/ipv6_route_table.out'))
    result = engine.switch_read(auth, 'route', address_family='ipv6')
    assert result['ok'] and len(result['records']) == 4, result
    assert [r['protocol'] for r in result['records']] == ['connected', 'ospf', 'local', 'connected']
    auth, calls = wire('ospfv3_neighbors', 'show ipv6 ospfv3 neighbors', fixture('vendor/ospfv3_neighbors.out'))
    result = engine.switch_read(auth, 'ospf_neighbor', address_family='ipv6')
    assert result['ok'] and len(result['records']) == 1, result
    assert result['records'][0]['state'] == 'full'
    assert result['records'][0]['address'].startswith('fe80:')


@pytest.mark.parametrize('path,table,query', [
    ('vendor/ipv6_route_table.out', 'route', 'ipv6_route_table'),
    ('vendor/ospfv3_neighbors.out', 'ospf_neighbor', 'ospfv3_neighbors'),
])
def test_missing_next_hop_or_neighbor_address_is_incomplete(path, table, query):
    body = fixture(path).rstrip().rsplit('\n', 1)[0]
    # Keep just the first RIB prefix with no next-hop, or the neighbor without its continuation.
    if table == 'route':
        body = '\n'.join(body.splitlines()[:6])
    result = tables.parse(PROFILE, table, query, body)
    assert result['status'] == 'unparsed' and result['unparsed']
    assert not result['coverage']['complete']


def test_empty_ipv6_rib_is_measured_but_blank_capture_is_not_a_table():
    result = tables.parse(PROFILE, 'route', 'ipv6_route_table', fixture('raw/ipv6_route_table.out'))
    assert result['status'] == 'empty' and result['coverage']['complete']
    result = tables.parse(PROFILE, 'route', 'ipv6_route_table', '')
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_fib_output_with_real_exec_error_cannot_be_a_success(wire):
    auth, _ = wire('forwarding_ipv4_route', 'show forwarding ipv4 route', fixture('raw/forwarding_ipv4_route.out'), rc=236)
    result = engine.ssh_read(auth, PROFILE, 'forwarding_ipv4_route', None, 0, 16000)
    assert not result['ok'], result
    assert 'Cmd exec error.' in result['untrusted_device_output']
    assert result['complete'] is False
    assert 'partial forwarding table' in result['error']


def test_received_routes_disabled_feature_is_reported(wire):
    command = 'show bgp ipv4 unicast neighbors 192.0.2.1 routes'
    auth, _ = wire('bgp_received_routes', command, fixture('raw/bgp_received_routes.out'), rc=16)
    result = engine.ssh_read(auth, PROFILE, 'bgp_received_routes', {'address': '192.0.2.1'}, 0, 16000)
    assert not result['ok'] and result['status'] == 'unsupported'


@pytest.mark.parametrize('vrf', ['other', 'management;reload', 'all', 'management\nshow version'])
def test_vrf_must_be_safe_and_enrolled(vrf):
    with pytest.raises(ValueError):
        render_read_query(PROFILE, 'route_table_vrf', {'vrf': vrf}, INVENTORY)


@pytest.mark.parametrize('prefix', ['2001:db8::/64', '192.0.2.1/24', '198.51.100.0/24', '192.0.2.0/24;reload'])
def test_bgp_prefix_must_be_ipv4_canonical_and_enrolled(prefix):
    with pytest.raises(ValueError):
        render_read_query(PROFILE, 'bgp_prefix_detail', {'prefix': prefix}, INVENTORY)


def test_old_query_grant_cannot_authorize_a_vrf_query(wire):
    auth, calls = wire('route_table', 'show ip route', fixture('raw/route_table_vrf.out'))
    with pytest.raises(PolicyScopeError):
        engine.switch_read(auth, 'route', vrf='management')
    assert calls == []


@pytest.mark.parametrize('kwargs', [{'address_family': 'vpnv4'}, {'address_family': 'ipv6', 'ip': '192.0.2.1'}])
def test_invalid_family_refuses_before_transport(wire, kwargs):
    auth, calls = wire('route_table', 'show ip route', '')
    with pytest.raises(ValueError):
        engine.switch_read(auth, 'route', **kwargs)
    assert calls == []


def test_proxy_selects_vrf_query_and_requires_its_inventory():
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy, PolicyScopeError as ProxyScopeError, ToolArgumentsError
    args = {'target': 'nx', 'table': 'route', 'vrf': 'management', 'address_family': 'ipv6'}
    assert Proxy._validate_tool_arguments('switch_read', args) == args
    section = SimpleNamespace(egress={}, catalog_platform=lambda: PROFILE, device_types=('router',), account_role='read-only',
                              ssh_platform=PROFILE, enabled_queries=('ipv6_route_table',), read_inventory=INVENTORY)
    with pytest.raises(ProxyScopeError):
        Proxy._authorize_tool('switch_read', args, None, section)
    section.enabled_queries = ('ipv6_route_table_vrf',)
    Proxy._authorize_tool('switch_read', args, None, section)
    with pytest.raises(ProxyScopeError):
        Proxy._authorize_tool('switch_read', {**args, 'vrf': 'other'}, None, section)
    for bad in ({**args, 'vrf': 'management;reload'}, {**args, 'address_family': 'evpn'}):
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('switch_read', bad)


@pytest.mark.parametrize('profile, options, field', [
    ('cisco_nxos', {'ip': '192.0.2.1', 'address_family': 'ipv6'}, 'address_family'),
    ('cisco_nxos', {'vrf': 'management', 'table': 'interface'}, 'vrf'),
    ('exos', {'vrf': 'management'}, 'vrf'),
    ('exos', {'address_family': 'ipv6'}, 'address_family'),
])
def test_proxy_names_the_routing_selector_that_was_refused(tmp_path, profile, options, field):
    from netops_helper import proxy
    from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write

    inventory, _, _, _ = _configure(proxy, tmp_path)
    section = dict(_section(), ssh_platform=profile, enabled_queries=['access_lists'],
                   snmp_credential=None, read_inventory={})
    _write(inventory, _inventory(_device(section, profile)))
    gateway = proxy.Proxy()
    replies = []
    gateway._emit = replies.append
    args = {'target': 'device-a', 'table': 'route', **options}
    assert gateway.request(_request(90, 'switch_read', args)) is None
    assert not gateway.rate_history
    error = replies[-1]['error']
    assert error['code'] == -32602 and error['data']['field'] == field, error


def test_vrf_interface_mask_join_reads_only_the_same_vrf(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    auth = replace(_target(PROFILE, 'ip_interfaces_vrf'), read_inventory=INVENTORY,
                   enabled_queries=('ip_interfaces_vrf', 'route_table', 'route_table_vrf'))
    calls = []
    outputs = {'show version': fixture('raw/version.out'),
               'show ip interface brief vrf management': fixture('raw/ip_interfaces_vrf.out'),
               'show ip route vrf management': fixture('raw/route_table_vrf.out')}
    def read(auth, profile, command):
        calls.append(command)
        return 0, outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.switch_read(auth, 'ip_interface', vrf='management')
    assert result['ok'] and result['records'][0]['prefix_length'] == 24, result
    assert 'show ip route' not in calls
    assert calls[-1] == 'show ip route vrf management'


@pytest.mark.parametrize('name', ['pbr-sample;reload', 'other', 'pbr-sample\nshow version'])
def test_pbr_counters_require_an_enrolled_route_map(name):
    with pytest.raises(ValueError):
        render_read_query(PROFILE, 'route_map_counters', {'route_map': name}, INVENTORY)
