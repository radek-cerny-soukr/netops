"""Port VLAN membership on real lab output and authorized composite reads."""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine, locate, port_vlan, tables
from conftest import _target

REAL = Path(__file__).parent / 'fixtures/real'


def parsed(profile, directory, query=None, table='port_vlan'):
    query = query or port_vlan.BINDINGS[profile]
    return tables.parse(profile, table, query, (REAL / profile / directory / (query + '.txt')).read_text())


@pytest.mark.parametrize('profile,directory,name', [
    ('cisco_ios', 'iosvl2_15.2.20200924', 'GigabitEthernet0/1'),
    ('cisco_ios', 'iosvl2_15.2.20200924_pty', 'GigabitEthernet0/1'),
    ('cisco_nxos', 'nexus9300v_9.3.12', 'Ethernet1/1'),
    ('cisco_nxos', 'nexus9300v_9.3.12_vtp_disabled', 'Ethernet1/1'),
    ('arista_eos', 'ceos_4.36.1F', 'Ethernet1'),
    ('arista_eos', 'ceos_4.36.1F_pty', 'Ethernet1'),
    ('juniper_junos_els', 'vjunosswitch_26.2R1.7', 'ge-0/0/0.0'),
    ('extreme_exos', 'exosvm_33.6.1.14_pty', '1'),
])
def test_real_trunks(profile, directory, name):
    result = parsed(profile, directory)
    assert result['status'] == 'ok' and not result['unparsed']
    item = next(r for r in result['records'] if r['port'] == name)
    assert item['mode'] == 'trunk' and item['tagged_vlans'] == [10, 20]
    assert port_vlan.membership(item, 10) == {'carries_vlan': True, 'tagging': 'tagged'}
    assert port_vlan.membership(item, 99) == {'carries_vlan': False, 'tagging': None}
    # A configured native default excluded from allowed VLANs carries no traffic.
    assert item['native_vlan'] is None


@pytest.mark.parametrize('directory', sorted(p.name for p in (REAL / 'extreme_exos').iterdir()))
def test_all_real_exos_vlan_detail(directory):
    result = parsed('extreme_exos', directory)
    assert result['status'] == 'ok' and not result['unparsed']
    assert result['records']
    assert not any(r['port'] == 'Mgmt-port' for r in result['records'])
    if 'x435' in directory:
        assert len(result['records']) == 12
        assert all(r['mode'] == 'access' and r['access_vlan'] == 1 for r in result['records'])
        # No active VLAN flag does not establish physical link down.
        assert result['records'][1]['oper_status'] is None
    if 'x440' in directory:
        assert any(r['native_vlan'] is not None and r['tagged_vlans'] for r in result['records'])


def test_junos_access_and_down_flag():
    result = parsed('juniper_junos_els', 'vjunosswitch_26.2R1.7')
    assert result['records'][1] == port_vlan.row('ge-0/0/1.0', 'access', access=10, tagged=[], status='down')


def test_junos_native_only_trunk_keeps_interface_mode():
    text = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/ethernet_switching_interfaces.txt').read_text()
    lines = text.split('default-switch  ge-0/0/1.0', 1)[0].splitlines()
    lines = [line for line in lines if 'D20' not in line]
    # The interface declares tagged mode; its only current member is native.
    lines = [line.rstrip().removesuffix('tagged') + 'untagged' if 'D10' in line else line for line in lines]
    result = tables.parse('juniper_junos_els', 'port_vlan', 'ethernet_switching_interfaces', '\n'.join(lines))
    assert result['status'] == 'ok'
    assert result['records'][0] == port_vlan.row('ge-0/0/0.0', 'trunk', native=10, tagged=[], status='up')


def test_access_routed_unknown_and_trunk_status():
    header = 'Port      Name               Status       Vlan       Duplex  Speed Type\n'
    text = header + ''.join(f'{name:<10}{"":19}{state:<13}{vlan:<11}full    1000\n'
                            for name, state, vlan in [('Gi0/1', 'connected', '10'), ('Gi0/2', 'notconnect', 'routed'),
                                                       ('Gi0/3', 'connected', '--'), ('Gi0/4', 'notconnect', 'trunk')])
    result = tables.parse('cisco_xe', 'port_vlan', 'interfaces', text)
    assert result['status'] == 'ok'
    assert [r['mode'] for r in result['records']] == ['access', 'routed', 'unknown', 'trunk']
    assert result['records'][0]['access_vlan'] == 10
    assert result['records'][1]['oper_status'] == 'down'
    assert result['records'][3]['tagged_vlans'] is None


def test_native_and_wrapped_allowed_list():
    text = ('Port Mode Encapsulation Status Native vlan\nGi0/1 on 802.1q trunking 10\n'
            'Port Vlans allowed on trunk\nGi0/1 10,20-22,\n  30\n'
            'Port Vlans allowed and active in management domain\nGi0/1 10,20\n')
    result = tables.parse('cisco_ios', 'port_vlan', 'interfaces_trunk', text)
    assert result['status'] == 'ok' and not result['unparsed']
    assert result['records'][0]['tagged_vlans'] == [20, 21, 22, 30]
    assert port_vlan.membership(result['records'][0], 10)['tagging'] == 'untagged'


@pytest.mark.parametrize('status', ['truncated', 'timeout', 'transport_error'])
def test_failed_capture_does_not_create_membership(status):
    text = (REAL / 'cisco_nxos/nexus9300v_9.3.12/interfaces_trunk.txt').read_text()
    result = tables.parse('cisco_nxos', 'port_vlan', 'interfaces_trunk', text, status=status)
    assert result['status'] == status and not result['records']


def test_real_refusals_and_unknown_lines():
    result = parsed('cisco_xe', 'iolxe_17.18.2')
    assert result['status'] == 'permission_denied' and not result['records']
    for profile, directory, query in [('cisco_nxos', 'nexus9300v_9.3.12_pty', 'interfaces_trunk_refused'),
                                       ('juniper_junos_els', 'vjunosswitch_26.2R1.7_pty', 'ethernet_switching_interfaces_refused')]:
        result = parsed(profile, directory, query)
        assert result['status'] in ('unsupported', 'unparsed') and not result['records']
    text = (REAL / 'cisco_ios/iosvl2_15.2.20200924/interfaces_trunk.txt').read_text() + '\nunrecognized data\n'
    result = tables.parse('cisco_ios', 'port_vlan', 'interfaces_trunk', text)
    assert result['status'] == 'unparsed' and result['unparsed'][-1]['text'] == 'unrecognized data'


def test_interface_filter_is_local_and_strict():
    assert tables.request('cisco_ios', 'port_vlan', interface='Gi0/1') == (
        'interfaces_trunk', {}, {'port': 'GigabitEthernet0/1'})
    for table, value in [('vlan', 'Gi0/1'), ('port_vlan', 'Gi0/1;show'), ('port_vlan', 12)]:
        with pytest.raises(ValueError):
            tables.request('cisco_ios', table, interface=value)


def test_composite_read_filters_after_capture_and_checks_enabled_queries(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, '_check_identity', lambda *a, **kw: ('show version', 0, ''))
    profile, directory = 'cisco_ios', 'iosvl2_15.2.20200924_pty'
    auth = replace(_target(profile, 'interfaces_trunk'), enabled_queries=('interfaces_trunk', 'interfaces'))
    calls = []
    def device(auth, profile, command):
        calls.append(command)
        query = 'interfaces_trunk' if command.endswith('trunk') else 'interfaces'
        return 0, (REAL / profile / directory / (query + '.txt')).read_text()
    monkeypatch.setattr(engine, 'read_from_device', device)
    result = engine.switch_read(auth, 'port_vlan', interface='Gi0/0')
    assert result['records'] == [port_vlan.row('GigabitEthernet0/0', 'access', access=99, tagged=[], status='up')]
    assert result['coverage']['complete']
    assert calls == ['show interfaces trunk', 'show interfaces status']
    calls.clear()
    result = engine.switch_read(replace(auth, enabled_queries=('interfaces_trunk',)), 'port_vlan')
    assert calls == ['show interfaces trunk']
    assert not result['coverage']['complete'] and 'port_vlan_status_join_not_enabled' in result['warnings']


def test_nxos_vtp_disabled_real_switch_read(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, '_check_identity', lambda *a, **kw: ('show version', 0, ''))
    directory = REAL / 'cisco_nxos/nexus9300v_9.3.12_vtp_disabled'
    auth = replace(_target('cisco_nxos', 'interfaces_trunk'),
                   enabled_queries=('interfaces_trunk', 'interfaces'))
    answers = {'show interface trunk': (directory / 'interfaces_trunk.txt').read_text(),
               'show interface status': (directory / 'interfaces.txt').read_text()}
    calls = []

    def device(auth, profile, command):
        calls.append(command)
        return 0, answers[command]

    monkeypatch.setattr(engine, 'read_from_device', device)
    result = engine.switch_read(auth, 'port_vlan', interface='Eth1/1')
    assert result['ok'] and result['status'] == 'ok' and not result['unparsed']
    assert result['coverage']['complete'] and not result['warnings']
    # Native default 1 is excluded from allowed 10,20: neither is untagged.
    # The status read, captured separately, reports the physical link down.
    assert result['records'] == [port_vlan.row('Ethernet1/1', 'trunk', tagged=[10, 20], status='down')]
    for vlan in (10, 20):
        assert port_vlan.membership(result['records'][0], vlan) == {'carries_vlan': True, 'tagging': 'tagged'}
    assert port_vlan.membership(result['records'][0], 1) == {'carries_vlan': False, 'tagging': None}
    assert calls == list(answers)


def test_ios_vlan_join_does_not_report_trunk_only_vlan_empty():
    profile, directory = 'cisco_ios', 'iosvl2_15.2.20200924_pty'
    auth = replace(_target(profile, 'vlans'), enabled_queries=('vlans', 'interfaces_trunk'))
    def read(query, table):
        return parsed(profile, directory, query, table)
    result = port_vlan.join_vlans(auth, read('vlans', 'vlan'), read)
    vlan = next(r for r in result['records'] if r['vlan_id'] == 10)
    assert vlan['ports'] == ['GigabitEthernet0/1', 'GigabitEthernet0/2']
    result = port_vlan.join_vlans(replace(auth, enabled_queries=('vlans',)), read('vlans', 'vlan'), read)
    assert next(r for r in result['records'] if r['vlan_id'] == 10)['ports'] is None
    assert 'trunk_vlan_join_not_enabled' in result['warnings']


def test_locate_membership_and_missing_without_extra_permissions():
    from test_locate_endpoint import auth, reader, MAC
    target = replace(auth(), enabled_queries=auth().enabled_queries + ('interfaces_trunk',))
    budget = locate.Budget()
    base = reader(budget)
    def read(auth, table, *args):
        if table == 'port_vlan':
            budget.take()
            result = tables.parse('cisco_ios', table, None, '', status='empty')
            result['records'] = [port_vlan.row('GigabitEthernet1/0/5', 'access', access=101, tagged=[], status='up')]
            return result
        return base(auth, table, *args)
    result = locate.run([target], MAC, read, budget)
    assert result['findings'][0]['vlan_membership'] == {'carries_vlan': True, 'tagging': 'untagged'}
    assert result['verdict'] == 'located'
    budget = locate.Budget()
    result = locate.run([auth()], MAC, reader(budget), budget)
    assert result['findings'][0]['vlan_membership']['tagging'] == 'missing'
    assert result['verdict'] == 'located'  # Optional, disabled VLAN evidence does not change MAC/LLDP location.


@pytest.mark.parametrize('profile,directory,port,neighbor_query,carries', [
    ('cisco_nxos', 'nexus9300v_9.3.12', 'Ethernet1/2', 'lldp_neighbors', False),
    ('juniper_junos_els', 'vjunosswitch_26.2R1.7', 'ge-0/0/1.0', 'lldp_neighbors_detail', True),
])
def test_locate_enabled_membership_on_real_endpoint(monkeypatch, profile, directory, port, neighbor_query, carries):
    from netops_helper.query_catalog import READ_QUERIES
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    query = port_vlan.BINDINGS[profile]
    target = replace(_target(profile, 'mac_table'), device_types=('switch',),
                     enabled_queries=('mac_table', neighbor_query, 'interfaces', 'vlans', query))
    macs = parsed(profile, directory, 'mac_table', 'mac_entry')['records']
    mac = next(r['mac'] for r in macs if r['port'] == port and r['type'] == 'static')
    answers = {template.command: (REAL / profile / directory / (q + '.txt')).read_text()
               for q, template in READ_QUERIES[profile].items()
               if not template.slots and (REAL / profile / directory / (q + '.txt')).exists()}
    calls = []
    def device(auth, profile, command):
        calls.append(command)
        return 0, answers[command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    result = engine._locate_endpoint_run([target], mac)
    finding = next(r for r in result['findings'] if r['port'] == port)
    # The Nexus capture has a static VLAN 10 MAC on an access VLAN 1 port:
    # the inconsistency must be visible rather than inferred away from the FDB.
    assert finding['vlan_membership'] == {'carries_vlan': carries, 'tagging': 'untagged' if carries else None}
    assert READ_QUERIES[profile][query].command in calls
    assert calls.count(READ_QUERIES[profile]['version'].command) == 1


def test_proxy_interface_schema_permission_and_read_cost():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    from types import SimpleNamespace
    args = Proxy._validate_tool_arguments('switch_read', {'target': 'sw1', 'table': 'port_vlan', 'interface': 'Gi0/1'})
    assert args['interface'] == 'Gi0/1'
    for interface in ('Gi0/1;show', 1, []):
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('switch_read', {'target': 'sw1', 'table': 'port_vlan', 'interface': interface})
    section = SimpleNamespace(catalog_platform=lambda: 'cisco_ios', enabled_queries=('interfaces_trunk', 'interfaces'))
    assert Proxy._rate_cost('switch_read', None, section, args) == 2
    section.enabled_queries = ('interfaces_trunk',)
    assert Proxy._rate_cost('switch_read', None, section, args) == 1


@pytest.mark.parametrize('profile,directory,short,long', [
    ('arista_eos', 'ceos_4.36.1F', 'Ma0', 'Management0'),
    ('arista_eos', 'ceos_4.36.1F_pty', 'Ma0', 'Management0'),
    ('arista_eos', 'ceos_4.36.1F', 'Et1', 'Ethernet1'),
    ('cisco_nxos', 'nexus9300v_9.3.12', 'Eth1/1', 'Ethernet1/1'),
    ('cisco_ios', 'iosvl2_15.2.20200924', 'Gi0/1', 'GigabitEthernet0/1'),
])
def test_real_interface_alias_filters_do_not_hide_rows(monkeypatch, profile, directory, short, long):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    target = replace(_target(profile, 'interfaces_trunk'),
                     device_types=('switch', 'router'), enabled_queries=('interfaces_trunk', 'interfaces'))
    calls = []
    def read(auth, selected, query, table, parameters=None):
        calls.append(query)
        return parsed(profile, directory, query, table)
    monkeypatch.setattr(engine, 'normalized_query', read)
    results = [engine.switch_read(target, 'port_vlan', interface=name) for name in (short, long)]
    assert all(r['status'] == 'ok' and len(r['records']) == 1 for r in results)
    assert results[0]['records'] == results[1]['records']
    assert results[0]['records'][0]['port'] == long
    assert calls == ['interfaces_trunk', 'interfaces'] * 2


def test_ceos_management_name_is_shared_by_real_tables():
    directory = 'ceos_4.36.1F'
    for table, query, field in [('interface', 'interfaces', 'name'),
                                ('port_vlan', 'interfaces', 'port'),
                                ('ip_interface', 'ip_interfaces', 'interface'),
                                ('lldp_neighbor', 'lldp_neighbors_detail', 'local_port')]:
        result = parsed('arista_eos', directory, query, table)
        assert result['status'] == 'ok'
        assert 'Management0' in {row[field] for row in result['records']}
        assert 'Ma0' not in {row[field] for row in result['records']}
    # A name copied from ip_interface also works as either filter spelling.
    filters = [tables.request('arista_eos', 'ip_interface', interface=name)[2]
               for name in ('Ma0', 'Management0')]
    assert filters == [{'interface': 'Management0'}] * 2


@pytest.mark.parametrize('profile', ['arista_eos', 'cisco_ios', 'cisco_xe', 'cisco_nxos'])
@pytest.mark.parametrize('table', ['port_vlan', 'ip_interface'])
@pytest.mark.parametrize('short,long', [('Et1', 'Ethernet1'), ('Po1', 'Port-channel1'),
                                       ('Port-Channel1', 'Port-channel1')])
def test_interface_filters_share_ethernet_and_aggregate_names(profile, table, short, long):
    left = tables.request(profile, table, interface=short)
    right = tables.request(profile, table, interface=long)
    assert left == right
    assert next(iter(left[2].values())) == long


@pytest.mark.parametrize('profile,short,long', [
    ('arista_eos', 'Ma0', 'Management0'), ('arista_eos', 'Et1', 'Ethernet1'),
    ('arista_eos', 'Po1', 'Port-channel1'), ('cisco_nxos', 'Eth1/1', 'Ethernet1/1'),
    ('cisco_ios', 'Gi0/1', 'GigabitEthernet0/1'), ('cisco_xe', 'Gi1/0/1', 'GigabitEthernet1/0/1'),
])
def test_error_filters_keep_existing_platform_scope_and_normalize_aliases(profile, short, long):
    assert tables.request(profile, 'interface_errors', interface=short) == tables.request(
        profile, 'interface_errors', interface=long)
