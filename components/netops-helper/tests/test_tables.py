import json
from pathlib import Path

import pytest

from netops_helper import tables as t

FIXTURES = Path(__file__).parent / 'fixtures/tables'


@pytest.mark.parametrize('profile,label', [('cisco_ios', 'IOS / IOS XE'), ('cisco_xe', 'IOS / IOS XE'),
                                           ('arista_eos', 'EOS')])
def test_documented_ios_eos_capabilities_match_route_requests_and_lldp_binding(profile, label):
    docs = (Path(__file__).parents[1] / 'docs/tools.md').read_text()
    row = next(line.split('|')[1:-1] for line in docs.splitlines() if line.startswith(f'| {label} |'))
    route_cell = row[-1]
    for filters in ({}, {'ip': '192.0.2.1'}):
        query, _, _ = t.request(profile, 'route', **filters)
        assert f'`{query}`' in route_cell
    assert 'whole table without `ip`' in route_cell
    if profile == 'arista_eos':
        assert f"`{t.BINDINGS[profile]['lldp_neighbor']}`" in row[-2]
        assert 'capabilities and management address' in row[-2]


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
def test_ios_subnet_group_mask_applies_to_connected_routes_and_ecmp(profile):
    text = '''Codes: C - connected, O - OSPF
Gateway of last resort is not set
      198.51.100.0/24 is subnetted, 2 subnets
C        198.51.100.0 is directly connected, Vlan10
O        203.0.113.0 [110/20] via 198.51.100.3, 00:10:11, Vlan10
                   [110/20] via 198.51.100.4, 00:10:11, Vlan10
      192.0.2.0/25 is subnetted, 1 subnets
C        192.0.2.128 is directly connected, Vlan20
'''
    result = t.parse(profile, 'route', 'route_table', text)
    assert result['status'] == 'ok' and not result['unparsed']
    assert [(r['prefix'], r['next_hop']) for r in result['records']] == [
        ('198.51.100.0/24', None), ('203.0.113.0/24', '198.51.100.3'), ('203.0.113.0/24', '198.51.100.4'),
        ('192.0.2.128/25', None)]


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
@pytest.mark.parametrize('group', ['', '198.51.100.0/24 is variably subnetted, 2 subnets, 2 masks',
                                  '203.0.113.0 is subnetted, 2 subnets'])
def test_ios_route_without_a_known_mask_is_unparsed_and_cannot_reuse_an_ecmp_prefix(profile, group):
    text = f'''Codes: C - connected, O - OSPF
      198.51.100.0/24 is subnetted, 1 subnets
C        198.51.100.0 is directly connected, Vlan10
{group or 'Gateway of last resort is not set'}
O        203.0.113.0 [110/20] via 198.51.100.3, 00:10:11, Vlan10
                   [110/20] via 198.51.100.4, 00:10:11, Vlan10
C        192.0.2.1/32 is directly connected, Vlan20
'''
    result = t.parse(profile, 'route', 'route_table', text)
    assert result['status'] == 'unparsed'
    assert len(result['unparsed']) == 2
    assert [r['prefix'] for r in result['records']] == ['198.51.100.0/24', '192.0.2.1/32']


@pytest.mark.parametrize('fixture', sorted(FIXTURES.glob('*.json')), ids=lambda p: p.stem)
def test_documented_tables_and_unknown_line(fixture):
    for table, output in json.loads(fixture.read_text()).items():
        result = t.parse(fixture.stem, table, 'fixture', output)
        assert result['status'] == 'ok', result
        assert result['records'], result
        assert set(result['records'][0]) == set(t.FIELDS[table])
        assert len(result['sources'][0]['content_sha256']) == 64
        unknown = t.parse(fixture.stem, table, 'fixture', output.rstrip('\n') + '\nNEW UNRECOGNIZED OUTPUT\n')   # live captures end without a newline
        assert unknown['status'] == 'unparsed'
        assert unknown['unparsed'][-1]['text'] == 'NEW UNRECOGNIZED OUTPUT'
        assert not unknown['coverage']['complete']


@pytest.mark.parametrize('value', ['192.0.2.1;reload', 'host.example', '192.0.2.0/24', 'fe80::1%eth0', '', None])
def test_endpoint_literal_rejects_injection_and_non_literal(value):
    with pytest.raises(ValueError):
        t.literal(value)


def test_canonical_endpoint_and_filters():
    assert t.literal('0000.5e00.5381') == ('mac', '00:00:5e:00:53:81')
    assert t.literal('2001:db8::1') == ('ip', '2001:db8::1')
    with pytest.raises(ValueError):
        t.request('extreme_exos', 'vlan', vlan_id='101;show')
    # EXOS has no lookup template: the whole table is read and narrowed locally
    assert t.request('extreme_exos', 'route', ip='192.0.2.1') == ('route_table', {}, {})
    assert t.request('extreme_exos', 'route', ip='2001:db8::1')[0] is None


def test_each_binding_is_catalogue_backed():
    from netops_helper.query_catalog import READ_QUERIES
    for profile, binding in t.BINDINGS.items():
        for query in binding.values():
            if query in ('vlans', 'mac_table') and profile == 'juniper_junos':
                continue
            assert query in READ_QUERIES[profile]


@pytest.mark.parametrize('state', ['permission_denied', 'unsupported', 'truncated', 'timeout', 'transport_error'])
def test_failure_has_no_positive_records(state):
    r = t.parse('cisco_ios', 'mac_entry', 'mac_table', '101 0000.5e00.5381 DYNAMIC Gi1/0/1', status=state)
    assert not r['records'] and r['status'] == state
    assert not r['coverage']['complete']


def test_switch_read_checks_identity_permission_and_redacts(monkeypatch):
    from netops_helper import engine
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    auth = _target('cisco_ios', 'mac_table')
    fixture = json.loads((FIXTURES / 'cisco_ios.json').read_text())
    version = (FIXTURES.parent / 'identity/cisco_ios.txt').read_text()
    calls = []
    def read(auth, profile, command):
        calls.append(command)
        return 0, version if command == 'show version' else fixture['mac_entry']
    monkeypatch.setattr(engine, 'read_from_device', read)
    r = engine.switch_read(auth, 'mac_entry', mac='0000.5e00.5304')
    assert r['ok'] and [(row['mac'], row['port']) for row in r['records']] == [('00:00:5e:00:53:04', 'GigabitEthernet0/2')]
    assert calls == ['show version', 'show mac address-table']
    from netops_helper.auth import PolicyScopeError
    with pytest.raises(PolicyScopeError):
        engine.switch_read(auth, 'vlan')
    monkeypatch.setattr(engine, 'read_from_device', lambda *a: (0, 'not an IOS switch'))
    r = engine.switch_read(auth, 'mac_entry')
    assert r['status'] == 'unparsed' and not r['records']


def test_switch_read_redacts_every_known_secret_before_parsing(monkeypatch):
    from dataclasses import replace
    from netops_helper import engine
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    auth = replace(_target('cisco_ios', 'mac_table'), output_secrets=('synthetic-session-canary-7Q',))
    fixture = json.loads((FIXTURES / 'cisco_ios.json').read_text())
    version = (FIXTURES.parent / 'identity/cisco_ios.txt').read_text()
    leaked = fixture['mac_entry'] + 'synthetic-session-canary-7Q ' + auth.secret + '\n'
    monkeypatch.setattr(engine, 'read_from_device',
                        lambda auth, profile, command: (0, version if command == 'show version' else leaked))
    r = engine.switch_read(auth, 'mac_entry')
    assert r['status'] == 'unparsed' and r['unparsed']
    assert 'synthetic-session-canary-7Q' not in json.dumps(r) and auth.secret not in json.dumps(r)


def test_filters_preserve_unparsed_evidence():
    r = t.parse('cisco_ios', 'mac_entry', 'mac_table', '101 0000.5e00.5381 DYNAMIC Gi1/0/1\nBAD',
                filters={'mac': '00:00:5e:00:53:e9'})
    assert not r['records'] and r['status'] == 'unparsed'
    assert r['unparsed']


@pytest.mark.parametrize('profile,text,interface', [
    ('cisco_ios', '2001:db8::10 0 0000.5e00.5381 REACH Gi1/0/5', 'GigabitEthernet1/0/5'),
    ('cisco_xe', '2001:db8::10 0 0000.5e00.5381 REACH Gi1/0/5', 'GigabitEthernet1/0/5'),
    ('cisco_nxos', '2001:db8::10 0000.5e00.5381 REACH Eth1/5', 'Ethernet1/5'),
    ('arista_eos', '2001:db8::10 0 0000.5e00.5381 REACH Et5', 'Ethernet5'),
    ('juniper_junos', '2001:db8::10 00:00:5e:00:53:81 stale 10 no ge-0/0/5.0', 'ge-0/0/5.0'),
    ('extreme_exos', 'VR Destination\nMac Age Static VLAN VID Port\nVR-Default 2001:db8::10\n00:00:5e:00:53:81 0 NO lab-data 101 1:5', '1:5'),
])
def test_ipv6_neighbor_variants(profile, text, interface):
    r = t.parse(profile, 'neighbor_l3', 'ipv6_neighbors', text)
    assert r['status'] == 'ok', r
    assert r['records'][0]['ip'] == '2001:db8::10'
    assert r['records'][0]['mac'] == '00:00:5e:00:53:81'
    assert r['records'][0]['interface'] == interface


def test_missing_neighbor_continuation_is_unparsed():
    r = t.parse('extreme_exos', 'neighbor_l3', 'ipv6_neighbors', 'VR-Default 2001:db8::10')
    assert r['status'] == 'unparsed' and not r['records']


def test_route_filter_is_a_catalogue_selector_and_multi_next_hops_are_preserved():
    query, parameters, filters = t.request('cisco_ios', 'route', ip='192.0.2.10')
    assert query == 'route_lookup' and parameters == {'address': '192.0.2.10'}
    assert not filters
    output = 'Routing entry for 192.0.2.0/24\nKnown via "static", distance 1, metric 0\n* 192.0.2.1, via Gi1/0/1\n* 192.0.2.2, via Gi1/0/2\n'
    r = t.parse('cisco_ios', 'route', query, output)
    assert r['status'] == 'ok' and len(r['records']) == 2
    assert {row['next_hop'] for row in r['records']} == {'192.0.2.1', '192.0.2.2'}


def test_lldp_multiple_management_ips_are_not_silently_overwritten():
    output = 'Local Intf: Gi1/0/1\nSystem Name: lab-peer\nIP: 192.0.2.1\nIP: 192.0.2.2\n'
    r = t.parse('cisco_ios', 'lldp_neighbor', 'lldp_neighbors', output)
    assert r['status'] == 'unparsed'
    assert r['records'][0]['management_ip'] == '192.0.2.1'
    assert r['unparsed'][0]['text'] == 'IP: 192.0.2.2'


def test_junos_mac_vlan_join_uses_authorized_template(monkeypatch):
    from dataclasses import replace
    from netops_helper import engine
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    data = json.loads((FIXTURES / 'juniper_junos_els.json').read_text())
    auth = replace(_target('juniper_junos_els', 'mac_table'), enabled_queries=('mac_table', 'vlans'))
    version = (FIXTURES.parent / 'identity/juniper_junos_els.txt').read_text()
    outputs = {'show version | no-more': version, 'show ethernet-switching table | no-more': data['mac_entry'],
               'show vlans brief | no-more': data['vlan']}
    monkeypatch.setattr(engine, 'read_from_device', lambda a, p, c: (0, outputs[c]))
    r = engine.switch_read(auth, 'mac_entry', vlan_id='10')
    assert r['status'] == 'ok' and r['records'][0]['vlan_id'] == 10 and r['records'][0]['vlan_name'] == 'Users'
    assert len(r['sources']) == 2
    assert r['coverage']['missing_fields'] == [] and r['coverage']['complete']
    assert 'fields_absent_in_catalogue_output' not in r['warnings']
    r = engine.switch_read(replace(auth, enabled_queries=('mac_table',)), 'mac_entry')
    assert r['records'][0]['vlan_id'] is None
    assert 'vlan_tag_join_not_enabled' in r['warnings']
    assert 'fields_absent_in_catalogue_output' in r['warnings']


def test_lldp_nxos_chassis_before_local_port_preserves_neighbor_blocks():
    text = ('Chassis id: 0000.5e00.5381\nPort id: eth0\nLocal Port id: Eth1/5\nSystem Name: host-a\n'
            'Chassis id: 0000.5e00.5382\nPort id: eth1\nLocal Port id: Eth1/6\nSystem Name: host-b\n')
    r = t.parse('cisco_nxos', 'lldp_neighbor', 'lldp_neighbors', text)
    assert r['status'] == 'ok' and len(r['records']) == 2
    assert [(n['local_port'], n['neighbor_port'], n['neighbor']) for n in r['records']] == [
        ('Ethernet1/5', 'eth0', 'host-a'), ('Ethernet1/6', 'eth1', 'host-b')]


def test_exos_missing_continuation_cannot_mix_two_neighbors():
    text = 'VR-Default 2001:db8::10\nVR-Default 2001:db8::20\n00:00:5e:00:53:81 0 NO lab-data 101 1:5'
    r = t.parse('extreme_exos', 'neighbor_l3', 'ipv6_neighbors', text)
    assert r['status'] == 'unparsed'
    assert len(r['records']) == 1 and r['records'][0]['ip'] == '2001:db8::20'
    assert r['unparsed'][0] == {'line': 1, 'text': 'VR-Default 2001:db8::10'}


def test_no_router_profiles_or_bases_exist():
    from netops_helper import normalization
    from netops_helper.query_catalog import READ_QUERIES
    assert not hasattr(normalization, 'ROUTER_BASES')
    assert not any(name.endswith('_router') for name in set(t.BINDINGS) | set(t.PARSERS) | set(READ_QUERIES))


def test_unbound_or_uncatalogued_table_is_unsupported_not_refused():
    # Common Junos has no VLAN/MAC template; the answer is a state, not an error.
    for table in ('vlan', 'mac_entry'):
        assert t.request('juniper_junos', table) == (None, {}, {})
    assert t.request('cisco_ios', 'mac_entry')[0] == 'mac_table'
    assert t.parse('juniper_junos', 'vlan', None, '', status='unsupported')['status'] == 'unsupported'


def test_template_group_needs_the_declared_device_type(monkeypatch):
    from dataclasses import replace
    from netops_helper.query_catalog import READ_QUERIES
    monkeypatch.setitem(READ_QUERIES['cisco_ios'], 'mac_table', replace(READ_QUERIES['cisco_ios']['mac_table'], group='switch'))
    assert t.request('cisco_ios', 'mac_entry', device_types=('switch',))[0] == 'mac_table'
    assert t.request('cisco_ios', 'mac_entry', device_types=('router',))[0] is None
    assert t.request('cisco_ios', 'mac_entry', device_types=())[0] is None
    # A template without a group serves any type (an IOS router reads `interface` from ip_interfaces instead,
    # see test_ip_interfaces.py).
    assert t.request('cisco_ios', 'vlan', device_types=('router',))[0] == 'vlans'
    assert t.request('cisco_ios', 'interface', device_types=('switch',))[0] == 'interfaces'


def test_route_without_ip_reads_the_whole_table_where_the_catalogue_has_one():
    assert t.request('cisco_ios', 'route') == ('route_table', {}, {})
    assert t.request('cisco_xe', 'route') == ('route_table', {}, {})
    assert t.request('arista_eos', 'route') == ('route_table', {}, {})
    assert t.request('extreme_exos', 'route') == ('route_table', {}, {})
    assert t.request('cisco_nxos', 'route') == ('route_table', {}, {})
    assert t.request('juniper_junos', 'route') == ('route_table', {}, {})
    assert t.request('juniper_junos_els', 'route') == ('route_table', {}, {})
    assert t.request('fortinet', 'route') == ('routing_table', {}, {})
    assert t.request('cisco_ios', 'route', ip='192.0.2.10')[0] == 'route_lookup'      # an enrolled address keeps the lookup template


@pytest.mark.parametrize('table', ['ospf_neighbor', 'bgp_peer', 'lag', 'stp_port'])
def test_routing_peer_and_layer_two_tables_are_bound_where_the_catalogue_prints_them(table):
    for profile in ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'juniper_junos_els'):
        assert t.request(profile, table)[0] is not None
    # Common Junos has no spanning-tree template (ELS only); EXOS also has the sharing LAG source.
    assert (t.request('juniper_junos', table)[0] is not None) == (table != 'stp_port')
    assert t.request('extreme_exos', table)[0] == ('lag_summary' if table == 'lag' else None)
    for profile in (('fortinet',) if table == 'lag' else ('extreme_exos', 'fortinet')):
        assert t.request(profile, table)[0] is None
        assert t.parse(profile, table, None, '', status='unsupported')['status'] == 'unsupported'


@pytest.mark.parametrize('text', ['% BGP not active\r\n', '\n> show ip bgp summary\n% BGP inactive at line 1\n', '! IPv6 routing not enabled\n',
                                  '\nWarning: License key missing; requires \'BGP\' license\n\nBGP is not running\n',
                                  '\nSpanning-tree is not enabled at global level.\n',
                                  'warning: lacp subsystem not running - not needed by configuration.\n'])
def test_a_routing_protocol_that_is_not_configured_is_not_applicable(text):
    from netops_helper import normalization
    assert normalization.output_status(text, rc=1) == 'not_applicable'


def test_eos_ipv6_neighbor_takes_the_first_interface_of_the_cell():
    text = (FIXTURES.parent / 'docs/arista_eos/ipv6_neighbors.txt').read_text()
    r = t.parse('arista_eos', 'neighbor_l3', 'ipv6_neighbors', text)
    assert r['status'] == 'ok' and r['records'][0]['interface'] == 'Vlan10' and r['records'][0]['vlan_id'] == 10


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_junos_route_entries_of_one_prefix_return_only_the_active_protocol(profile):
    text = (FIXTURES.parent / 'docs/juniper_junos/route_lookup.txt').read_text()
    text = text.replace('(1 entry, 1 announced)', '(2 entries, 1 announced)')
    text += '        OSPF Preference: 150\n                Next hop: 198.51.100.2 via irb.10\n'
    r = t.parse(profile, 'route', 'route_lookup', text)
    assert r['status'] == 'ok' and not r['unparsed']
    assert {(row['next_hop'], row['protocol']) for row in r['records']} == {('198.51.100.1', 'static')}


def test_a_transport_failure_of_a_switch_read_is_its_status_not_an_exception(monkeypatch):
    from netops_helper import engine
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    def refuse(*args, **kwargs):
        raise TimeoutError('deadline')
    monkeypatch.setattr(engine, 'read_from_device', refuse)
    r = engine.switch_read(_target('cisco_ios', 'mac_table'), 'mac_entry')
    assert r['status'] == 'timeout' and not r['records']


def test_the_proxy_refuses_malformed_switch_read_arguments_before_any_target_is_used():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    good = {'target': 'sw1', 'table': 'mac_entry'}
    assert Proxy._validate_tool_arguments('switch_read', good) == good
    for bad in ({**good, 'table': 'running_config'}, {**good, 'mac': 'not-a-mac'}, {**good, 'vlan_id': '99999'}):
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('switch_read', bad)


@pytest.mark.parametrize('profile,text', [
    ('cisco_ios', 'Line has invalid autocommand "show interfaces status"\r\n'),
    ('cisco_xe', 'Line has invalid autocommand "show etherchannel summary"\r\n'),
    ('cisco_ios', "show vlan brief\r\n        ^\r\n% Invalid input detected at '^' marker.\r\n"),
])
def test_an_ios_refusal_stays_permission_denied_and_says_the_command_may_not_exist_on_the_image(monkeypatch, profile, text):
    # Live 1.0.7 check: IOSv and IOL XE router images answer switching commands with "Line has invalid autocommand".
    from netops_helper import engine, normalization
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    version = (FIXTURES.parent / ('identity/%s.txt' % profile)).read_text()
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, profile, command: (0, version if command == 'show version' else text))
    r = engine.switch_read(_target(profile, 'mac_table'), 'mac_entry')
    assert r['status'] == 'permission_denied' and not r['ok'] and not r['records']
    assert r['hint'] == normalization.IOS_REFUSAL_HINT
    assert 'refused by the account or does not exist on this image' in r['hint']


@pytest.mark.parametrize('profile,text', [
    ('cisco_ios', '% Authorization failed.\r\n'),
    ('cisco_nxos', '% Permission denied for the role\r\n'),
    ('juniper_junos_els', 'error: permission denied: lacp\n'),
])
def test_other_refusals_carry_no_absent_command_hint(profile, text):
    r = t.parse(profile, 'lag', 'lacp', text, status='permission_denied')
    assert r['status'] == 'permission_denied' and 'hint' not in r


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_junos_lag_without_a_running_lacp_subsystem_is_not_applicable(profile):
    # Live 1.0.7 check: vJunos-switch without an aggregate answers `show lacp interfaces` with this one line.
    text = 'warning: lacp subsystem not running - not needed by configuration.\n'
    from netops_helper import normalization
    state = normalization.output_status(text, rc=0, profile=profile)
    r = t.parse(profile, 'lag', 'lacp_interfaces', text, status=state)
    assert (r['status'], r['records'], r['unparsed']) == ('not_applicable', [], [])


def test_proxy_fortios_whole_route_table_requires_its_enabled_query():
    from netops_helper.proxy import Proxy, PolicyScopeError
    from types import SimpleNamespace
    section = SimpleNamespace(egress={}, catalog_platform=lambda: 'fortinet', device_types=('firewall',),
                              ssh_platform='fortios', enabled_queries=('route_lookup',))
    with pytest.raises(PolicyScopeError) as error:
        Proxy._authorize_tool('switch_read', {'table': 'route'}, None, section)
    assert error.value.data['field'] == 'enabled_queries'
