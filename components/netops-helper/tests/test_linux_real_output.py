"""Linux captures through the real engine with only the SSH transport replaced."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, normalization, tables
from netops_helper.auth import PolicyScopeError
from netops_helper.query_catalog import READ_QUERIES
from support.replay_capture import load

SCENARIO = load(Path(__file__).parent / 'fixtures/real/scenarios/linux_ubuntu_24.04.5.json')
CAPTURES = SCENARIO['captures']
IDENTITY = SCENARIO['environment']['version']['stdout']


def target(query, interfaces=('lo', 'eno1', 'docker0')):
    return replace(_target('linux', query), read_inventory={'interfaces': interfaces})


def fake_transport(monkeypatch, capture, identity=IDENTITY, rc=None, suffix=''):
    calls = []

    def read(auth, profile, command):
        assert profile == 'linux'
        calls.append(command)
        if command == 'uname -a':
            return 0, identity
        assert command == capture['command']
        return capture['rc'] if rc is None else rc, capture['stdout'] + suffix

    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    return calls


def read_capture(capture, auth=None, **filters):
    if capture['query'] == 'interface_link':
        filters['interface'] = capture['command'].split()[-1]
    return engine.switch_read(auth or target(capture['query']), capture['table'], **filters)


@pytest.mark.parametrize('capture', CAPTURES, ids=lambda c: c['command'])
def test_live_linux_capture_through_real_engine(monkeypatch, capture):
    calls = fake_transport(monkeypatch, capture)
    result = read_capture(capture)
    expected = capture['expected']
    assert result['status'] == expected['status'], result
    assert len(result['records']) == expected['record_count']
    assert len(result['unparsed']) == expected['unparsed_count']
    for row, manual in zip(result['records'], expected['records'], strict=True):
        assert {key: row[key] for key in manual} == manual
        assert set(row) == set(tables.FIELDS[capture['table']])
    assert calls == ['uname -a', capture['command']]
    assert result['sources'][0]['query'] == capture['query']
    assert result['coverage']['complete'] == (not result['coverage']['missing_fields'])


@pytest.mark.parametrize('capture', CAPTURES, ids=lambda c: c['command'])
def test_new_linux_lines_are_visible_before_filtering_and_paging(monkeypatch, capture):
    calls = fake_transport(monkeypatch, capture, suffix='NEW UNRECOGNIZED OUTPUT\n')
    result = read_capture(capture, limit=1)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['coverage']['unparsed_lines'] == 1
    assert calls == ['uname -a', capture['command']]
    parsed = tables.parse('linux', capture['table'], capture['query'],
                          capture['stdout'] + 'NEW UNRECOGNIZED OUTPUT\n')
    assert parsed['unparsed'][-1]['text'] == 'NEW UNRECOGNIZED OUTPUT'


@pytest.mark.parametrize('capture', CAPTURES, ids=lambda c: c['command'])
@pytest.mark.parametrize('rc', [1, 2])
def test_linux_nonzero_exit_never_returns_positive_records(monkeypatch, capture, rc):
    fake_transport(monkeypatch, capture, rc=rc)
    result = read_capture(capture)
    assert result['status'] == 'transport_error' and not result['ok']
    assert result['records'] == [] and not result['coverage']['complete']


@pytest.mark.parametrize('identity', ['FreeBSD lab 14.0 GENERIC amd64\n', 'Linux lab\n',
                                      IDENTITY + '% Permission denied\n'])
def test_linux_identity_mismatch_or_refusal_stops_the_data_read(monkeypatch, identity):
    calls = fake_transport(monkeypatch, CAPTURES[0], identity=identity)
    result = read_capture(CAPTURES[0])
    assert calls == ['uname -a']
    assert result['records'] == [] and not result['ok']
    assert any(warning.startswith('identity_') for warning in result['warnings'])


def test_linux_identity_reports_only_kernel_fields_and_keeps_kernel_query(monkeypatch):
    calls = fake_transport(monkeypatch, CAPTURES[0])
    result = engine.ssh_read(target('kernel'), 'linux', 'kernel', {}, 0, 16000)
    assert result['ok']
    assert calls == ['uname -a']
    identity = normalization.parse_identity('linux', IDENTITY)
    assert identity == {'hostname': 'host01', 'os_version': '6.8.0-147-generic',
                         'model': None, 'serial_number': None, 'uptime': None}
    assert READ_QUERIES['linux']['version'].command == READ_QUERIES['linux']['kernel'].command
    assert 'version' not in READ_QUERIES['linux']
    assert READ_QUERIES['linux'].get('version') is None
    from netops_helper.read_policy import render_read_query
    with pytest.raises(ValueError):
        render_read_query('linux', 'version', {}, {})


@pytest.mark.parametrize('query', ['links', 'addresses', 'routes', 'neighbors', 'bridge_fdb', 'interface_link'])
def test_linux_does_not_grant_unenrolled_queries(monkeypatch, query):
    calls = []
    monkeypatch.setattr(engine, 'read_from_device', lambda *a, **k: calls.append(a))
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    capture = next(c for c in CAPTURES if c['query'] == query)
    with pytest.raises(PolicyScopeError):
        read_capture(capture, target('hostname'))
    assert calls == []


def test_linux_detail_requires_an_enrolled_interface_before_connecting(monkeypatch):
    calls = []
    monkeypatch.setattr(engine, 'read_from_device', lambda *a, **k: calls.append(a))
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    with pytest.raises(ValueError, match='not enrolled'):
        read_capture(CAPTURES[-1], target('interface_link', interfaces=('eno1',)))
    assert calls == []
    for interface in ('eno1;reboot', 'eno1\nreboot'):
        with pytest.raises(ValueError):
            tables.request('linux', 'interface', interface=interface)
    with pytest.raises(ValueError):
        tables.request('linux', 'interface', interface='eno1', managed_switch='x')


@pytest.mark.parametrize('capture', CAPTURES, ids=lambda c: c['command'])
def test_linux_reads_survive_proxy_validation_and_inventory_authorization(tmp_path, monkeypatch, capture):
    from netops_helper import proxy as p
    import test_proxy_contracts as c

    for attribute in ('INVENTORY', 'VAULT', 'EGRESS_POLICY', 'RUNNER'):
        monkeypatch.setattr(p, attribute, getattr(p, attribute))
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section.update(ssh_platform='linux', enabled_queries=[capture['query']])
    section['read_inventory']['interfaces'] = ['eno1', 'lo', 'docker0']
    c._write(inventory, c._inventory(c._device(section, 'linux')))
    proxy = p.Proxy()
    args = {'target': 'device-a', 'table': capture['table']}
    if capture['query'] == 'interface_link':
        args['interface'] = capture['command'].split()[-1]
    args = proxy._validate_tool_arguments('switch_read', args)
    entry, section, _ = proxy._target('device-a')
    proxy._authorize_tool('switch_read', args, entry, section)
    if capture['query'] == 'interface_link':
        with pytest.raises(p.PolicyScopeError):
            proxy._authorize_tool('switch_read', {**args, 'interface': 'eth9'}, entry, section)
    with pytest.raises(p.PolicyScopeError):
        proxy._authorize_tool('switch_read', args, entry, replace(section, enabled_queries=('hostname',)))


def test_generic_interface_selector_only_filters_existing_summary_records(monkeypatch):
    # The unchanged proxy validates table selectors using a generic IOS profile.
    # Other profiles retain their existing read and narrow its records locally.
    query, params, filters = tables.request('cisco_ios', 'interface', interface='Gi1/0/1')
    assert query == 'interfaces' and params == {} and filters == {'name': 'GigabitEthernet1/0/1'}
    result = tables.parse('cisco_ios', 'interface', query,
        'Port      Name               Status       Vlan       Duplex  Speed Type\n'
        'Gi1/0/1   one                connected    10         a-full  a-1000 10/100/1000BaseTX\n'
        'Gi1/0/2   two                connected    20         a-full  a-1000 10/100/1000BaseTX\n',
        filters=filters)
    assert result['status'] == 'ok' and [row['name'] for row in result['records']] == ['GigabitEthernet1/0/1']


def test_linux_route_lookup_and_ipv6_neighbor_filter_use_existing_table_commands(monkeypatch):
    routes = next(c for c in CAPTURES if c['query'] == 'routes')
    fake_transport(monkeypatch, routes)
    result = read_capture(routes, ip='192.0.2.66')
    assert [row['prefix'] for row in result['records']] == ['192.0.2.0/24']
    assert tables.request('linux', 'route', ip='2001:db8::1')[0] is None
    neighbors = next(c for c in CAPTURES if c['query'] == 'neighbors')
    fake_transport(monkeypatch, neighbors)
    address = neighbors['expected']['records'][-1]['ip']
    result = read_capture(neighbors, ip=address)
    assert len(result['records']) == 1 and result['records'][0]['ip'] == address


def test_linux_address_filter_retains_missing_field_coverage(monkeypatch):
    capture = next(c for c in CAPTURES if c['query'] == 'addresses')
    fake_transport(monkeypatch, capture)
    result = read_capture(capture, interface='lo')
    assert [row['ip'] for row in result['records']] == ['203.0.113.1', '2001:db8:ffff::1']
    assert result['coverage']['missing_fields'] == []
    assert result['coverage']['complete']


@pytest.mark.parametrize('table,query,body', [
    ('interface', 'links', 'veth0@if2 UP 00:00:5e:00:53:01 <BROADCAST,UP,LOWER_UP>\n'),
    ('ip_interface', 'addresses', 'veth0@if2 DOWN\n'),
    ('neighbor_l3', 'neighbors', '192.0.2.7 dev eth0 FAILED\n2001:db8::1 dev eth0 INCOMPLETE\n'),
])
def test_linux_veth_and_addressless_or_unresolved_rows(table, query, body):
    result = tables.parse('linux', table, query, body)
    assert result['status'] in ('ok', 'empty') and result['unparsed'] == []
    if table == 'neighbor_l3':
        assert [r['type'] for r in result['records']] == ['failed', 'incomplete']
        assert all(row['mac'] is None for row in result['records'])
        assert 'mac' in result['coverage']['missing_fields']
    elif result['records']:
        assert result['records'][0]['name'] == 'veth0'


@pytest.mark.parametrize('table,query,body', [
    ('route', 'routes', 'default via 192.0.2.1 dev eth0 nexthop via 192.0.2.2 dev eth1\n'),
    ('route', 'routes', 'blackhole 192.0.2.0/24\n'),
    ('neighbor_l3', 'neighbors', '192.0.2.1 dev eth0 future-flag\n'),
    ('mac_entry', 'bridge_fdb', '00:00:5e:00:53:01 dev eth0 future-flag\n'),
    ('ip_interface', 'addresses', 'eth0 UP 192.0.2.1/24 future-flag\n'),
])
def test_linux_unsupported_shapes_are_not_successful_empty_tables(table, query, body):
    result = tables.parse('linux', table, query, body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['unparsed'] == [{'line': 1, 'text': body.rstrip('\n')}]


def test_linux_detailed_metadata_extension_is_visible():
    capture = CAPTURES[-1]
    body = capture['stdout'].replace('bridge forward_delay', 'bridge future-attribute 1 forward_delay')
    result = tables.parse('linux', 'interface', 'interface_link', body)
    assert result['status'] == 'unparsed' and len(result['unparsed']) == 1
    assert result['records'][0]['mtu'] == 1500


@pytest.mark.parametrize('table,query', [('interface', 'links'), ('ip_interface', 'addresses'),
                                         ('neighbor_l3', 'neighbors')])
def test_linux_catalogue_coverage_excludes_unavailable_switch_fields(table, query):
    capture = next(c for c in CAPTURES if c['query'] == query)
    result = tables.parse('linux', table, query, capture['stdout'])
    assert result['coverage']['missing_fields'] == []
    assert result['coverage']['complete']
    assert tables.optional_fields('cisco_ios', table) == tables.OPTIONAL_FIELDS[table]


@pytest.mark.parametrize('body', ['wg0 UNKNOWN <POINTOPOINT,NOARP,UP,LOWER_UP>',
                                  'tun0 UNKNOWN link/none <POINTOPOINT,UP,LOWER_UP>'])
def test_linux_links_without_hardware_address(body):
    result = tables.parse('linux', 'interface', 'links', body)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert result['records'][0]['mac'] is None


@pytest.mark.parametrize('interface', ['eth0', 'br0', 'eth0.10@eth0', 'bond0', 'veth0@if3'])
def test_linux_ethernet_link_mac_is_preserved(interface):
    result = tables.parse('linux', 'interface', 'links',
                          interface + ' UP 00:00:5e:00:53:8a <BROADCAST,UP,LOWER_UP>')
    assert result['status'] == 'ok'
    assert result['records'][0]['mac'] == '00:00:5e:00:53:8a'


def test_linux_fdb_stale_and_veth_namespace_metadata():
    result = tables.parse('linux', 'mac_entry', 'bridge_fdb',
                          '00:00:5e:00:53:8a dev veth0 master br0 stale')
    assert result['status'] == 'ok' and not result['unparsed']
    result = tables.parse('linux', 'interface', 'interface_link',
        '2: veth0@if3: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\n'
        '    link/ether 00:00:5e:00:53:8a brd 00:00:5e:00:53:89 link-netnsid 0\n')
    assert result['status'] == 'ok' and not result['unparsed']
    assert result['records'][0]['mac'] == '00:00:5e:00:53:8a'


def test_linux_gateway_join_uses_only_enrolled_catalogue_routes(monkeypatch):
    addresses = next(c for c in CAPTURES if c['query'] == 'addresses')
    routes = next(c for c in CAPTURES if c['query'] == 'routes')
    links = next(c for c in CAPTURES if c['query'] == 'links')
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        return 0, {'uname -a': IDENTITY, addresses['command']: addresses['stdout'],
                   routes['command']: routes['stdout'], links['command']: links['stdout']}[command]

    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(target('addresses'), enabled_queries=('addresses', 'links', 'routes'))
    result = read_capture(addresses, auth)
    assert result['status'] == 'ok' and result['coverage']['complete']
    for row in result['records']:
        assert row['mac'] is not None
        assert row['gateway'] == ('192.0.2.1' if row['ip'] == '192.0.2.66' else None)
    assert [source['query'] for source in result['sources']] == ['addresses', 'links', 'routes']
    assert calls.count('ip route show') == 1
    assert set(calls) == {'uname -a', 'ip -brief address', 'ip -brief link', 'ip route show'}
    calls.clear()
    result = read_capture(addresses)
    assert all(row['gateway'] is None for row in result['records'])
    assert result['coverage']['complete']
    assert 'routes_join_not_enabled' in result['warnings']
    assert 'ip route show' not in calls


@pytest.mark.parametrize('suffix,rc,status', [('NEW OUTPUT\n', 0, 'ok'), ('', 1, 'transport_error')])
def test_linux_gateway_join_reports_route_failure(monkeypatch, suffix, rc, status):
    addresses = next(c for c in CAPTURES if c['query'] == 'addresses')
    routes = next(c for c in CAPTURES if c['query'] == 'routes')
    def read(auth, profile, command):
        if command == 'uname -a':
            return 0, IDENTITY
        if command == addresses['command']:
            return 0, addresses['stdout']
        return rc, routes['stdout'] + suffix
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    result = read_capture(addresses, replace(target('addresses'), enabled_queries=('addresses', 'routes')))
    assert result['status'] == status
    assert result['coverage']['complete'] == (status == 'ok')
    if status == 'ok':
        assert 'routes_partial' not in result['warnings']
    addressed = next(row for row in result['records'] if row['ip'] == '192.0.2.66')
    assert addressed['gateway'] == ('192.0.2.1' if status == 'ok' else None)


@pytest.mark.parametrize('enabled,cost', [
    (('addresses',), 1), (('addresses', 'links'), 2),
    (('addresses', 'routes'), 2), (('addresses', 'links', 'routes'), 3),
])
def test_linux_address_join_proxy_charges_every_enrolled_read(enabled, cost):
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy
    section = SimpleNamespace(catalog_platform=lambda: 'linux', enabled_queries=enabled)
    assert Proxy._rate_cost('switch_read', None, section, {'table': 'ip_interface'}) == cost


def test_linux_address_join_exposes_link_transport_failure(monkeypatch):
    addresses = next(c for c in CAPTURES if c['query'] == 'addresses')
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        if command == 'uname -a':
            return 0, IDENTITY
        if command == 'ip -brief address':
            return 0, addresses['stdout']
        assert command == 'ip -brief link'
        return 1, ''

    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    result = read_capture(addresses, replace(target('addresses'), enabled_queries=('addresses', 'links')))
    assert result['status'] == 'transport_error' and not result['coverage']['complete']
    assert all(row['mac'] is None for row in result['records'])
    assert [source['query'] for source in result['sources']] == ['addresses', 'links']
    assert 'ip route show' not in calls


@pytest.mark.parametrize('interface', ['eth0', 'eno1', 'bond0', 'br0', 'eth0.10'])
def test_linux_address_interface_filter_keeps_linux_spelling(monkeypatch, interface):
    capture = next(c for c in CAPTURES if c['query'] == 'addresses')
    capture = {**capture, 'stdout': capture['stdout'].replace('eno1', interface)}
    calls = fake_transport(monkeypatch, capture)
    result = read_capture(capture, interface=interface)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert [row['ip'] for row in result['records']] == ['192.0.2.66', '2001:db8:fffe::10']
    assert all(row['interface'] == interface for row in result['records'])
    assert calls == ['uname -a', 'ip -brief address']


@pytest.mark.parametrize('metadata', [
    'gso_ipv4_max_size 65536 gro_ipv4_max_size 65536',
    'permaddr 00:00:5e:00:53:02',
])
def test_linux_detail_recent_iproute_link_metadata(metadata):
    body = ('2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\n'
            '    link/ether 00:00:5e:00:53:01 brd 00:00:5e:00:53:ff ' + metadata + '\n')
    result = tables.parse('linux', 'interface', 'interface_link', body)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert result['records'][0]['mac'] == '00:00:5e:00:53:01'


@pytest.mark.parametrize('metadata', [
    'bridge_slave state forwarding priority 32 cost 100 hairpin off guard off root_block off learning on flood on',
    'vlan protocol 802.1Q id 10 <REORDER_HDR>',
    'vlan protocol 802.1Q id 10',
])
def test_linux_detail_bridge_port_and_vlan_metadata(metadata):
    body = ('2: eth0.10@eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\n'
            '    link/ether 00:00:5e:00:53:01 brd 00:00:5e:00:53:ff\n    ' + metadata + '\n')
    result = tables.parse('linux', 'interface', 'interface_link', body)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert result['records'][0]['mac'] == '00:00:5e:00:53:01'
    assert result['records'][0]['name'] == 'eth0.10'


def test_linux_brief_secondary_ipv4_and_metric_are_retained():
    # ip -brief address omits secondary address labels, retaining both CIDRs.
    result = tables.parse('linux', 'ip_interface', 'addresses',
                         'eth0 UP 192.0.2.10/24 metric 100 192.0.2.11/24 2001:db8::10/64\n')
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert [(r['ip'], r['prefix_length']) for r in result['records']] == [
        ('192.0.2.10', 24), ('192.0.2.11', 24), ('2001:db8::10', 64)]


@pytest.mark.parametrize('metadata', ['bridge_slave future_flag on', 'vlan protocol 802.1Q id 4095',
                                      'vlan protocol future id 10', 'future_max_size 65536'])
def test_linux_detail_unknown_metadata_is_still_unparsed(metadata):
    body = ('2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\n'
            '    link/ether 00:00:5e:00:53:01 brd 00:00:5e:00:53:ff\n    ' + metadata + '\n')
    result = tables.parse('linux', 'interface', 'interface_link', body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['records'][0]['mac'] == '00:00:5e:00:53:01'


@pytest.mark.parametrize('unsupported', [
    'blackhole 198.51.100.0/24\n',
    '203.0.113.0/24 proto static\n    nexthop via 192.0.2.2 dev eno1 weight 1\n',
])
def test_linux_partial_routes_keep_gateway_and_unknowns_in_route_table(monkeypatch, unsupported):
    addresses = next(c for c in CAPTURES if c['query'] == 'addresses')
    links = next(c for c in CAPTURES if c['query'] == 'links')
    routes = next(c for c in CAPTURES if c['query'] == 'routes')
    commands = {'uname -a': IDENTITY, addresses['command']: addresses['stdout'],
                links['command']: links['stdout'], routes['command']: routes['stdout'] + unsupported}
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, profile, cmd: (0, commands[cmd]))
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(target('addresses'), enabled_queries=('addresses', 'links', 'routes'))
    result = read_capture(addresses, auth)
    assert result['ok'] and result['status'] == 'ok'
    assert result['coverage']['complete']
    assert 'routes_partial' not in result['warnings']
    assert result['unparsed'] == []
    assert next(r for r in result['records'] if r['ip'] == '192.0.2.66')['gateway'] == '192.0.2.1'
    routes_result = engine.switch_read(auth, 'route')
    assert routes_result['status'] == 'unparsed' and not routes_result['coverage']['complete']
    assert routes_result['unparsed']
    assert any(row['text'].strip() in unsupported for row in routes_result['unparsed'])
