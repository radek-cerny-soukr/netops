"""The ip_interface table and the router interface table on real device output (fixtures/real)."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netops_helper import ip_interfaces, tables as t

ROOT = Path(__file__).parent / 'fixtures'
REAL = ROOT / 'real'
DIRECTORIES = {'cisco_ios': ['cisco_ios/iosv_15.9.3M12', 'cisco_ios/iosvl2_15.2.20200924'],
               'cisco_xe': ['cisco_xe/iolxe_17.18.2'], 'cisco_nxos': ['cisco_nxos/nexus9300v_9.3.12'],
               'arista_eos': ['arista_eos/ceos_4.36.1F'], 'juniper_junos_els': ['juniper_junos_els/vjunosswitch_26.2R1.7'],
               'extreme_exos': ['exos/' + path.name for path in sorted((REAL / 'exos').iterdir()) if path.is_dir()],
               'fortinet': ['fortinet/fortigate80f_8.0.2']}
CASES = [(profile, directory) for profile, directories in DIRECTORIES.items() for directory in directories]


def output(directory, query):
    return (REAL / directory / (query + '.txt')).read_text()


def read(profile, directory, joined=True):
    query = t.BINDINGS[profile]['ip_interface']
    result = t.parse(profile, 'ip_interface', query, output(directory, query))
    if joined:
        result = ip_interfaces.join(profile, result, {'route_table', 'vlan_summary'},
                                    lambda name, table: t.parse(profile, table, name, output(directory, name)))
    return result


def summary(result):
    return [(row['interface'], row['ip'], row['prefix_length'], row['vlan_id'], row['admin_status'], row['oper_status'], row['vrf'])
            for row in result['records']]


@pytest.mark.parametrize('profile,directory', CASES, ids=[directory for _, directory in CASES])
def test_every_real_output_is_fully_recognized(profile, directory):
    result = read(profile, directory)
    assert result['status'] == 'ok' and result['unparsed'] == [] and result['records']
    assert all(set(row) == set(t.FIELDS['ip_interface']) for row in result['records'])
    query = t.BINDINGS[profile]['ip_interface']
    unknown = t.parse(profile, 'ip_interface', query, output(directory, query).rstrip('\n') + '\nNEW UNRECOGNIZED OUTPUT\n')
    assert unknown['status'] == 'unparsed' and unknown['unparsed'][-1]['text'] == 'NEW UNRECOGNIZED OUTPUT'


def test_ios_router_takes_the_mask_from_connected_routes_and_no_vlan_from_a_subinterface():
    result = read('cisco_ios', 'cisco_ios/iosv_15.9.3M12')
    assert summary(result) == [
        ('GigabitEthernet0/0', '203.0.113.51', 24, None, 'up', 'up', None),
        ('GigabitEthernet0/1.10', '192.0.2.1', 24, None, 'up', 'up', None),
        ('GigabitEthernet0/1.20', '198.51.100.1', 24, None, 'up', 'up', None),
        ('Loopback0', '203.0.113.129', 32, None, 'up', 'up', None)]
    assert result['coverage']['complete'] and [s['query'] for s in result['sources']] == ['ip_interfaces', 'route_table']
    assert 'fields_absent_in_catalogue_output' not in result['warnings']


def test_without_the_route_table_the_prefix_length_stays_null():
    result = read('cisco_xe', 'cisco_xe/iolxe_17.18.2', joined=False)
    assert {row['prefix_length'] for row in result['records']} == {None}
    result = ip_interfaces.join('cisco_xe', result, {'ip_interfaces'}, lambda *a: pytest.fail('no second read'))
    assert result['coverage']['missing_fields'] == ['prefix_length'] and not result['coverage']['complete']
    assert 'route_table_join_not_enabled' in result['warnings']


def test_svi_nxos_vrf_eos_mask_junos_inet_and_exos_tag():
    assert summary(read('cisco_ios', 'cisco_ios/iosvl2_15.2.20200924'))[0] == ('Vlan10', '192.0.2.2', 24, 10, 'up', 'up', None)
    assert summary(read('cisco_nxos', 'cisco_nxos/nexus9300v_9.3.12')) == [
        ('Vlan10', '192.0.2.5', 24, 10, 'up', 'up', 'default'), ('Vlan20', '198.51.100.5', 24, 20, 'up', 'up', 'default'),
        ('Lo0', '203.0.113.5', 32, None, 'up', 'up', 'default')]
    assert ('Management0', '203.0.113.53', 24, None, 'up', 'up', None) in summary(read('arista_eos', 'arista_eos/ceos_4.36.1F'))
    junos = summary(read('juniper_junos_els', 'juniper_junos_els/vjunosswitch_26.2R1.7'))
    assert ('irb.10', '192.0.2.6', 24, 10, 'up', 'up', None) in junos
    assert ('em1.0', '198.51.100.241', 2, None, 'up', 'up', None) in junos          # continuation line of the inet family
    assert ('lo0.0', '203.0.113.6', None, None, 'up', 'up', None) in junos           # no mask printed: not guessed
    assert not any(row[1].startswith('fe80') for row in junos)                        # inet6 is not this table
    assert summary(read('extreme_exos', 'exos/x440g2-12p-10g4_33.7.1.6_2')) == [
        ('V10', '192.0.2.2', 24, 10, 'up', 'up', None), ('VLAN100', '198.51.100.2', 24, 100, 'up', 'up', None)]


def test_fortios_lists_addressed_interfaces_with_the_configured_status():
    result = read('fortinet', 'fortinet/fortigate80f_8.0.2')
    rows = {row['interface']: row for row in result['records']}
    assert rows['wan1'] == {'interface': 'wan1', 'ip': '192.0.2.206', 'prefix_length': 24, 'vlan_id': None,
                            'admin_status': 'up', 'oper_status': None, 'vrf': None, 'mac': None, 'gateway': None}
    assert rows['fortilink']['prefix_length'] == 24 and 'internal1' not in rows and 'modem' not in rows     # 0.0.0.0: no address
    assert len(rows) == 15 and result['coverage']['missing_fields'] == ['oper_status']


def test_ios_router_interface_table_comes_from_ip_interface_brief():
    assert t.request('cisco_ios', 'interface')[0] == 'interfaces'
    assert t.request('cisco_xe', 'interface', device_types=('router',))[0] == 'ip_interfaces'
    assert t.request('cisco_xe', 'interface', device_types=('router', 'switch'))[0] == 'interfaces'
    assert t.request('cisco_nxos', 'interface', device_types=('router',))[0] == 'interfaces'
    result = t.parse('cisco_xe', 'interface', 'ip_interfaces', output('cisco_xe/iolxe_17.18.2', 'ip_interfaces'))
    assert result['status'] == 'ok' and not result['unparsed'] and len(result['records']) == 19
    rows = {row['name']: row for row in result['records']}
    assert (rows['Ethernet0/1.10']['admin_status'], rows['Ethernet0/1.10']['oper_status']) == ('up', 'up')
    assert (rows['Serial2/0']['admin_status'], rows['Serial2/0']['oper_status']) == ('down', 'down')


def test_interface_filter_is_validated_canonical_for_interface_tables():
    assert t.request('cisco_ios', 'ip_interface', interface='Gi0/1.10') == (
        'ip_interfaces', {}, {'interface': 'GigabitEthernet0/1.10'})
    assert t.request('extreme_exos', 'ip_interface', interface='V10')[2] == {'interface': 'V10'}
    for value in ('Gi0/1;reload', '', 'a b'):
        with pytest.raises(ValueError):
            t.request('cisco_ios', 'ip_interface', interface=value)
    assert t.request('cisco_ios', 'interface', interface='Gi0/1')[2] == {'name': 'GigabitEthernet0/1'}
    with pytest.raises(ValueError):
        t.request('cisco_ios', 'vlan', interface='Gi0/1')


def test_a_failed_second_read_is_reported_in_the_same_envelope():
    result = read('cisco_ios', 'cisco_ios/iosv_15.9.3M12', joined=False)
    failed = t.parse('cisco_ios', 'route', 'route_table', '', status='timeout')
    result = ip_interfaces.join('cisco_ios', result, {'route_table'}, lambda *a: failed)
    assert result['status'] == 'timeout' and not result['coverage']['complete']
    assert [source['query'] for source in result['sources']] == ['ip_interfaces', 'route_table']


def _engine(monkeypatch, profile, directory, queries, device_types=()):
    from netops_helper import engine
    from conftest import _target
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    auth = replace(_target(profile, queries[0]), enabled_queries=tuple(queries), device_types=device_types)
    version = (ROOT / 'identity' / (profile + '.txt')).read_text()
    from netops_helper.query_catalog import READ_QUERIES
    commands = {READ_QUERIES[profile][query].command: output(directory, query) for query in queries}
    calls = []

    def device(auth, profile, command):
        calls.append(command)
        return 0, version if command == READ_QUERIES[profile]['version'].command else commands[command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    return engine, auth, calls


def test_switch_read_joins_the_route_table_and_filters_by_interface(monkeypatch):
    engine, auth, calls = _engine(monkeypatch, 'cisco_ios', 'cisco_ios/iosv_15.9.3M12', ['ip_interfaces', 'route_table'])
    result = engine.switch_read(auth, 'ip_interface', interface='Gi0/1.10')
    assert result['ok'] and result['status'] == 'ok'
    assert result['records'] == [{'interface': 'GigabitEthernet0/1.10', 'ip': '192.0.2.1', 'prefix_length': 24, 'vlan_id': None,
                                  'admin_status': 'up', 'oper_status': 'up', 'vrf': None, 'mac': None, 'gateway': None}]
    assert [command for command in calls if command != 'show version'] == ['show ip interface brief', 'show ip route']


def test_switch_read_router_interface_and_exos_vlan_tag(monkeypatch):
    engine, auth, calls = _engine(monkeypatch, 'cisco_ios', 'cisco_ios/iosv_15.9.3M12', ['ip_interfaces'], ('router',))
    result = engine.switch_read(auth, 'interface')
    assert result['ok'] and len(result['records']) == 7 and calls[-1] == 'show ip interface brief'
    engine, auth, calls = _engine(monkeypatch, 'extreme_exos', 'exos/x440g2-12p-10g4_33.7.1.6_3', ['ipconfig', 'vlan_summary'])
    result = engine.switch_read(auth, 'ip_interface')
    assert [(row['interface'], row['vlan_id']) for row in result['records']] == [('V10', 10), ('VLAN100', 100)]
    assert result['coverage']['complete']


def test_fortios_fixture_index_names_the_catalogue_command():
    index = json.loads((REAL / 'fortinet/fortigate80f_8.0.2/index.json').read_text())
    from netops_helper.query_catalog import READ_QUERIES
    assert {name: item['command'] for name, item in index.items()} == {
        'system_interfaces': READ_QUERIES['fortinet']['system_interfaces'].command}
