"""Normalized tables on complete device output.

fixtures/real/exos: anonymised output of physical EXOS switches (see its README).
fixtures/docs: complete outputs reproduced from the vendor documentation of the very
command in the catalogue (sources in its README); live checks of those OS come from the lab.
Every line of every output must be either parsed or explicitly recognized - never `unparsed`.
"""
import json
import re
from pathlib import Path

import pytest

from netops_helper import normalization, tables as t
from netops_helper.query_catalog import READ_QUERIES

ROOT = Path(__file__).parent / 'fixtures'
EXOS_DIRS = sorted(p for p in (ROOT / 'real/exos').iterdir() if p.is_dir() and not p.name.startswith('exosvm'))      # the lab VM: test_locate_lab.py
TABLES = {'interface': 'interface', 'vlan': 'vlan', 'mac_entry': 'mac_entry', 'neighbor_l3': 'neighbor_l3',
          'lldp_neighbor': 'lldp_neighbor', 'route': 'route'}


def parse(profile, table, text):
    query = t.BINDINGS[profile][table]
    return t.parse(profile, table, query, text)


def doc(profile, name):
    return (ROOT / 'docs' / profile / (name + '.txt')).read_text()


def records(profile, table, name):
    result = parse(profile, table, doc(profile, name))
    assert result['status'] == 'ok' and not result['unparsed'], result['unparsed']
    return result['records']


# ---- EXOS: real switches -------------------------------------------------------------------

@pytest.mark.parametrize('directory', EXOS_DIRS, ids=lambda p: p.name)
@pytest.mark.parametrize('table', sorted(TABLES))
def test_every_exos_output_is_fully_recognized(directory, table):
    query = t.BINDINGS['extreme_exos'][table]
    result = t.parse('extreme_exos', table, query, (directory / (query + '.txt')).read_text())
    assert result['status'] == 'ok', result['unparsed']
    assert result['unparsed'] == [] and result['records']
    assert set(result['records'][0]) == set(t.FIELDS[table])


def exos_records(directory, table):
    query = t.BINDINGS['extreme_exos'][table]
    return t.parse('extreme_exos', table, query, (ROOT / 'real/exos' / directory / (query + '.txt')).read_text())['records']


def test_exos_record_counts_and_values_match_the_printed_tables():
    for directory in EXOS_DIRS:
        for table, query, header_rows in (('mac_entry', 'mac_table', 0), ('neighbor_l3', 'arp_table', 0)):
            text = (directory / (query + '.txt')).read_text()
            expected = sum(1 for line in text.splitlines() if line.startswith(('00:00:5e', 'VR-')))
            assert len(exos_records(directory.name, table)) == expected, (directory.name, query)
    ports = exos_records('x440g2-12p-10g4_33.7.1.6_2', 'interface')
    assert len(ports) == 16
    by_name = {row['name']: row for row in ports}
    assert by_name['1']['oper_status'] == 'up' and by_name['1']['speed'] == '100' and by_name['1']['trunk'] is False
    assert by_name['12']['admin_status'] == 'down' and by_name['12']['oper_status'] == 'down' and by_name['12']['speed'] is None
    assert by_name['13']['trunk'] is True            # (0006): six VLANs on the LAG ports
    assert by_name['4']['description'] is None and by_name['1']['description'].startswith('port-desc')


def test_exos_vlans_include_the_management_vlan_with_tag_4095():
    rows = {row['name']: row['vlan_id'] for row in exos_records('x440g2-12p-10g4_33.7.1.6', 'vlan')}
    assert rows == {'Default': 1, 'VL-30': 30, 'V20': 20, 'VLAN40': 40, 'V50': 50, 'Mgmt': 4095, 'VLAN100': 100}
    assert t.parse('extreme_exos', 'vlan', 'vlan_summary', (EXOS_DIRS[0] / 'vlan_summary.txt').read_text())['coverage']['missing_fields'] == ['ports']


def test_exos_fdb_rows_carry_vlan_name_tag_and_the_lag_master_port():
    rows = exos_records('x440g2-12p-10g4_33.7.1.6_2', 'mac_entry')
    sample = next(row for row in rows if row['mac'] == '00:00:5e:00:53:11')
    assert (sample['vlan_id'], sample['vlan_name'], sample['port'], sample['type']) == (10, 'V10', '6', 'dynamic')
    assert {row['port'] for row in rows} >= {'13', '2', '3', '11'}


def test_exos_arp_rows_keep_vr_vlan_tag_and_port():
    rows = exos_records('x440g2-12p-10g4_33.7.1.6_2', 'neighbor_l3')
    sample = next(row for row in rows if row['ip'] == '192.0.2.35')
    assert sample == {'ip': '192.0.2.35', 'mac': '00:00:5e:00:53:11', 'interface': '6', 'vlan_id': 10, 'vrf': 'VR-Default', 'type': None}


def test_exos_lldp_detail_gives_capabilities_and_management_address():
    rows = {row['local_port']: row for row in exos_records('x440g2-12p-10g4_33.7.1.6_2', 'lldp_neighbor')}
    assert rows['3']['capabilities'] == 'B,W' and rows['3']['management_ip'] == '192.0.2.5'      # Ruckus AP
    assert rows['11']['capabilities'] == 'B,T' and rows['11']['neighbor_port'].endswith(':P1')     # IP phone
    assert rows['2']['capabilities'] == 'B'
    # EXOS-to-EXOS neighbours send no System Capabilities TLV: unknown, not guessed
    assert rows['13']['capabilities'] is None and rows['13']['management_ip'] is None


def test_exos_routes_become_records_with_gateway_and_vlan():
    rows = exos_records('x440g2-12p-10g4_33.7.1.6_2', 'route')
    assert [(row['prefix'], row['protocol']) for row in rows] == [
        ('0.0.0.0/0', 'static'), ('198.51.100.0/24', 'connected'), ('192.0.2.0/24', 'connected')]
    assert rows[0]['next_hop'] == '192.0.2.1' and rows[0]['interface'] == 'V10'
    assert all(row['next_hop'] is None for row in rows if row['protocol'] == 'connected')
    best = t.longest_prefix(rows, '192.0.2.77')
    assert [row['prefix'] for row in best] == ['192.0.2.0/24']
    assert [row['prefix'] for row in t.longest_prefix(rows, '203.0.113.88')] == ['0.0.0.0/0']
    assert t.longest_prefix(rows, '2001:db8::1') == []


@pytest.mark.parametrize('directory', EXOS_DIRS + [ROOT / 'real/exos/exosvm_33.6.1.14'], ids=lambda p: p.name)
def test_exos_direct_gateway_is_local_vlan_address_not_next_hop(directory):
    rows = exos_records(directory.name, 'route')
    direct = [row for row in rows if row['protocol'] == 'connected']
    assert direct and all(row['next_hop'] is None and row['interface'] for row in direct)
    if directory.name == 'exosvm_33.6.1.14':
        assert {row['interface'] for row in direct} == {'D10', 'D20'}
        assert t.longest_prefix(rows, '192.0.2.1')[0]['next_hop'] is None


def test_exos_unsupported_command_is_not_parsed_as_data():
    text = (ROOT / 'real/exos/x435-8p-4s_33.7.1.6/stacking.txt').read_text()
    assert t.parse('extreme_exos', 'interface', 'ports', text)['status'] == 'unsupported'


def test_exos_index_lists_the_command_and_exit_status_of_each_output():
    for directory in EXOS_DIRS:
        index = json.loads((directory / 'index.json').read_text())
        files = {p.stem for p in directory.glob('*.txt')}
        assert set(index) == files and files <= set(READ_QUERIES['extreme_exos'])
        for name, item in index.items():
            if '{' not in READ_QUERIES['extreme_exos'][name].command:
                assert item['command'] == READ_QUERIES['extreme_exos'][name].command
    codes = json.loads((EXOS_DIRS[1] / 'index.json').read_text())
    assert codes['vlan_details']['rc'] == 250 and codes['mac_table']['rc'] == 0


@pytest.mark.parametrize('directory', EXOS_DIRS, ids=lambda p: p.name)
def test_every_exos_lacp_output_is_recognized_and_names_the_lag_master_port(directory):
    result = t.parse('extreme_exos', 'aggregate', 'lacp', (directory / 'lacp.txt').read_text())
    assert result['unparsed'] == [] and result['status'] in ('ok', 'empty')
    expected = {'13': 2} if directory.name.endswith(('_2', '_3')) else {}
    assert {row['name']: row['member_count'] for row in result['records']} == expected
    unknown = t.parse('extreme_exos', 'aggregate', 'lacp', (directory / 'lacp.txt').read_text() + 'NEW UNRECOGNIZED OUTPUT\n')
    assert unknown['status'] == 'unparsed'


# ---- the other operating systems: vendor documentation outputs -----------------------------

DOC_CASES = [(p.name, f.stem) for p in sorted((ROOT / 'docs').iterdir()) if p.is_dir() for f in sorted(p.glob('*.txt'))]
DOC_TABLE = {'interfaces': 'interface', 'vlans': 'vlan', 'mac_table': 'mac_entry', 'arp_table': 'neighbor_l3',
             'ipv6_neighbors': 'neighbor_l3', 'ipv6_route_lookup': 'route', 'lldp_neighbors': 'lldp_neighbor', 'lldp_neighbors_detail': 'lldp_neighbor', 'route_table': 'route', 'ospf_neighbors': 'ospf_neighbor',
             'lag_summary': 'lag', 'lacp_interfaces': 'lag', 'stp_tree': 'stp_port', 'bgp_summary': 'bgp_peer'}


@pytest.mark.parametrize('profile,name', DOC_CASES, ids=lambda v: str(v))
def test_every_documented_output_is_fully_recognized(profile, name):
    table = DOC_TABLE.get(name, 'route' if name.startswith('route_lookup') else None)
    result = parse(profile, table, doc(profile, name))
    assert not result['unparsed'], result['unparsed']
    assert result['status'] == ('empty' if name.endswith('_none') else 'ok')
    unknown = parse(profile, table, doc(profile, name).rstrip('\n') + '\nNEW UNRECOGNIZED OUTPUT\n')
    assert unknown['status'] == 'unparsed' and unknown['unparsed'][-1]['text'] == 'NEW UNRECOGNIZED OUTPUT'


@pytest.mark.parametrize('profile', ['cisco_xe'])
def test_ios_mac_table_skips_system_rows_and_keeps_every_host(profile):
    rows = records(profile, 'mac_entry', 'mac_table')
    assert all(row['mac'].replace(':', '') != '01000ccccccc' and row['port'] not in ('CPU', 'Vl10') for row in rows)
    assert {(row['mac'], row['port']) for row in rows} >= {('00:00:5e:00:53:a0', 'GigabitEthernet1/0/2')}
    if profile == 'cisco_xe':
        assert {row['port'] for row in rows if row['mac'] == '00:00:5e:00:53:83'} == {'GigabitEthernet1/0/7', 'GigabitEthernet1/0/8'}


def test_ios_interface_status_handles_port_channel_without_type_and_blank_names():
    rows = {row['name']: row for row in records('cisco_xe', 'interface', 'interfaces')}
    assert rows['Port-channel1']['trunk'] is True and rows['Port-channel1']['oper_status'] == 'up'
    assert rows['GigabitEthernet1/0/3']['description'] == 'printer 2nd floor'
    assert rows['GigabitEthernet1/0/2']['description'] is None and rows['GigabitEthernet1/0/2']['vlan_id'] == 10
    assert rows['GigabitEthernet1/0/4']['admin_status'] == 'down'
    assert rows['GigabitEthernet1/0/6']['vlan_id'] is None and rows['GigabitEthernet1/0/6']['trunk'] is False     # routed
    assert rows['GigabitEthernet1/0/2']['speed'] == 'a-100'


@pytest.mark.parametrize('name', ['route_lookup_supernet', 'route_lookup_classful'])
def test_ios_default_route_is_a_default_route_not_a_host_route(name):
    (row,) = records('cisco_xe', 'route', name)
    assert row['prefix'] == '0.0.0.0/0' and row['next_hop'] == '198.51.100.254' and row['protocol'] == 'static'


def test_ios_route_variants():
    (bgp,) = records('cisco_ios', 'route', 'route_lookup_bgp')
    assert (bgp['prefix'], bgp['next_hop'], bgp['protocol']) == ('198.51.100.128/25', '192.0.2.1', 'bgp')
    # IOS XE connected and no-route lookups come from the IOL router in the lab (tests/fixtures/real/cisco_xe)
    iol = ROOT / 'real/cisco_xe/iolxe_17.18.2'
    (connected,) = t.parse('cisco_xe', 'route', 'route_lookup', (iol / 'route_lookup_connected.txt').read_text())['records']
    assert (connected['prefix'], connected['interface'], connected['protocol']) == ('192.0.2.0/24', 'Ethernet0/1.10', 'connected')
    assert connected['next_hop'] is None        # "via Ethernet0/1.10" is the interface, never a next hop called "via"
    ecmp = records('cisco_ios', 'route', 'route_lookup_ecmp')
    assert [(row['next_hop'], row['interface'], row['protocol']) for row in ecmp] == [
        ('198.51.100.2', 'Vlan10', 'ospf'), ('198.51.100.3', 'Vlan10', 'ospf')]
    none = t.parse('cisco_xe', 'route', 'route_lookup', (iol / 'route_lookup_none.txt').read_text(), status=normalization.output_status((iol / 'route_lookup_none.txt').read_text()))
    assert none['status'] == 'empty'


def test_ios_lldp_detail_reads_capabilities_across_multiline_system_description():
    rows = {row['local_port']: row for row in records('cisco_xe', 'lldp_neighbor', 'lldp_neighbors')}
    assert rows['GigabitEthernet1/0/1'] == {'local_port': 'GigabitEthernet1/0/1', 'neighbor': 'core-sw', 'neighbor_port': 'Gi0/1',
                                            'management_ip': '198.51.100.2', 'capabilities': 'B,R'}
    assert rows['GigabitEthernet1/0/3']['capabilities'] == 'B,T' and rows['GigabitEthernet1/0/3']['management_ip'] == '192.0.2.30'


def test_ios_arp_incomplete_entry_has_no_mac_and_no_made_up_interface():
    rows = {row['ip']: row for row in records('cisco_xe', 'neighbor_l3', 'arp_table')}
    assert rows['198.51.100.20']['interface'] == 'Vlan10' and rows['198.51.100.20']['vlan_id'] == 10
    assert t.parse('cisco_ios', 'neighbor_l3', 'arp_table', 'Internet  198.51.100.99 0  Incomplete  ARPA\n')['records'] == [
        {'ip': '198.51.100.99', 'mac': None, 'interface': None, 'vlan_id': None, 'vrf': None, 'type': None}]


def test_ios_vlan_brief_continuation_lines_extend_the_ports():
    rows = {row['vlan_id']: row for row in records('cisco_xe', 'vlan', 'vlans')}
    assert rows[10]['ports'] == ['GigabitEthernet1/0/2', 'GigabitEthernet1/0/5', 'GigabitEthernet1/0/9',
                                 'GigabitEthernet1/0/10', 'GigabitEthernet1/0/11']
    # show vlan brief alone cannot establish absence of trunk members.
    assert rows[30]['name'] == 'Quarantine VLAN' and rows[30]['ports'] is None


def test_documented_routing_peers_port_channels_and_spanning_tree():
    # layouts the lab images cannot print: populated BGP, LACP bundles with wrapped member lists, root/alternate ports
    for profile in ('cisco_ios', 'cisco_xe'):
        peers = {row['neighbor']: row for row in records(profile, 'bgp_peer', 'bgp_summary')}
        assert (peers['192.0.2.1']['state'], peers['192.0.2.1']['prefixes'], peers['192.0.2.1']['remote_as']) == ('Established', 3, '65002')
        assert peers['192.0.2.9']['state'] == 'Idle' and peers['192.0.2.9']['prefixes'] is None
    peers = records('arista_eos', 'bgp_peer', 'bgp_summary')
    assert [(p['neighbor'], p['state'], p['vrf']) for p in peers] == [
        ('192.0.2.1', 'Established', 'default'), ('192.0.2.9', 'Active', 'default'),
        ('2001:db8::2', 'Established', 'default'), ('198.51.100.2', 'Established', 'tenant1')]
    routes = records('cisco_xe', 'route', 'route_table')
    assert [(r['prefix'], r['next_hop'], r['interface'], r['protocol']) for r in routes if r['prefix'] == '203.0.113.128/26'] == [
        ('203.0.113.128/26', '198.51.100.3', 'Vlan10', 'ospf'), ('203.0.113.128/26', '198.51.100.4', 'Vlan10', 'ospf')]
    assert ('203.0.113.64/26', None, 'Null0', 'static') in {(r['prefix'], r['next_hop'], r['interface'], r['protocol']) for r in routes}
    assert ('192.0.2.128/25', '192.0.2.1', None, 'bgp') in {(r['prefix'], r['next_hop'], r['interface'], r['protocol']) for r in routes}
    ospf = records('cisco_xe', 'ospf_neighbor', 'ospf_neighbors')
    assert [(n['state'], n['role']) for n in ospf] == [('full', 'DR'), ('full', 'BDR'), ('full', None), ('init', 'DROTHER')]      # "FULL/  -" on a point-to-point link
    lags = {row['name']: row for row in records('cisco_xe', 'lag', 'lag_summary')}
    assert len(lags['Port-channel1']['members']) == 6 and lags['Port-channel1']['members'][5] == {'port': 'GigabitEthernet1/0/6', 'state': 'down'}
    assert lags['Port-channel2']['status'] == 'down' and lags['Port-channel3']['protocol'] is None
    eos = {row['name']: row for row in records('arista_eos', 'lag', 'lag_summary')}
    assert eos['Port-channel1']['protocol'] == 'LACP' and eos['Port-channel10']['members'][1] == {'port': 'PEt3', 'state': 'down'}
    stp = records('cisco_xe', 'stp_port', 'stp_tree')
    assert {(r['instance'], r['port']): (r['role'], r['state']) for r in stp}[('VLAN0010', 'GigabitEthernet1/0/2')] == ('alternate', 'blocking')
    assert ('VLAN0020', 'GigabitEthernet1/0/2') in {(r['instance'], r['port']) for r in stp if r['state'] == 'learning'}
    eos_stp = {r['port']: (r['role'], r['state']) for r in records('arista_eos', 'stp_port', 'stp_tree')}
    assert eos_stp == {'Ethernet1': ('root', 'forwarding'), 'Ethernet2': ('alternate', 'discarding'),
                       'Ethernet3': ('designated', 'forwarding'), 'Port-channel10': ('backup', 'discarding')}


def test_nxos_outputs():
    rows = {row['name']: row for row in records('cisco_nxos', 'interface', 'interfaces')}
    assert rows['Ethernet1/2']['oper_status'] == 'down' and rows['Ethernet1/2']['description'] is None       # "--" is no description
    assert rows['Ethernet1/1']['description'] == 'leaf-uplink' and rows['Ethernet1/1']['trunk'] is True
    assert all(rows[f'Ethernet1/{n}']['oper_status'] == 'down' for n in range(4, 9))     # sfpAbsent, xcvrAbsen, noOperMem, down, disabled
    macs = records('cisco_nxos', 'mac_entry', 'mac_table')
    assert {row['port'] for row in macs} == {'Ethernet1/3', 'Port-channel1', 'vPC Peer-Link'}
    assert [row['type'] for row in macs if row['port'] == 'vPC Peer-Link'] == ['trunk']
    vlans = {row['vlan_id']: row for row in records('cisco_nxos', 'vlan', 'vlans')}
    assert vlans[10]['ports'] == ['Ethernet1/3', 'Ethernet1/5', 'Ethernet1/6', 'Ethernet1/7', 'Ethernet1/8']
    arp = {row['ip']: row for row in records('cisco_nxos', 'neighbor_l3', 'arp_table')}
    assert arp['198.51.100.99']['mac'] is None and arp['198.51.100.20']['interface'] == 'Ethernet1/3'
    (default,) = records('cisco_nxos', 'route', 'route_lookup')
    assert (default['prefix'], default['next_hop'], default['interface'], default['protocol'], default['vrf']) == (
        '0.0.0.0/0', '203.0.113.193', None, 'static', 'default')
    routes = records('cisco_nxos', 'route', 'route_lookup_connected_ecmp')
    assert [(r['prefix'], r['next_hop'], r['interface'], r['protocol']) for r in routes] == [
        ('198.51.100.0/24', None, 'Vlan10', 'connected'), ('192.0.2.128/25', '203.0.113.193', 'Ethernet1/1', 'ospf'),
        ('192.0.2.128/25', '203.0.113.197', 'Ethernet1/2', 'ospf')]
    (neighbor,) = records('cisco_nxos', 'lldp_neighbor', 'lldp_neighbors')
    assert (neighbor['local_port'], neighbor['neighbor'], neighbor['capabilities'], neighbor['management_ip']) == (
        'Ethernet1/49', 'leaf2', 'B,R', '203.0.113.194')


def test_eos_outputs():
    # documented layouts the lab cEOS does not print: IPv6 neighbours and an ECMP route lookup
    assert parse('arista_eos', 'neighbor_l3', doc('arista_eos', 'ipv6_neighbors'))['status'] == 'ok'
    routes = records('arista_eos', 'route', 'route_lookup_ecmp')
    assert [(r['prefix'], r['next_hop'], r['protocol']) for r in routes] == [
        ('0.0.0.0/0', '198.51.100.254', 'static'), ('192.0.2.128/25', '198.51.100.2', 'ospf'),
        ('192.0.2.128/25', '198.51.100.3', 'ospf'), ('198.51.100.0/24', None, 'connected')]


def test_junos_outputs():
    interfaces = {row['name']: row for row in records('juniper_junos', 'interface', 'interfaces')}
    for pseudo in ('bme0', 'dsc', 'em0', 'gre', 'vme', 'lo0.0', 'irb.10', 'bme0.32768'):
        assert pseudo in interfaces
    assert interfaces['vme']['oper_status'] == 'down' and interfaces['ge-0/0/1']['oper_status'] == 'down'
    lldp = {row['local_port']: row for row in records('juniper_junos', 'lldp_neighbor', 'lldp_neighbors')}
    assert lldp['ge-0/0/1']['neighbor'] == 'core switch' and lldp['ge-0/0/1']['neighbor_port'] == 'ge-0/0/10'   # a space in System Name
    assert lldp['ge-0/0/2']['neighbor'] == 'phone-1'
    arp = {row['ip']: row for row in records('juniper_junos', 'neighbor_l3', 'arp_table')}
    assert arp['198.51.100.254']['interface'] == 'ge-0/0/1.0'                    # not the Flags column
    assert arp['198.51.100.20']['interface'] == 'irb.10' and arp['198.51.100.20']['vlan_id'] == 10
    assert arp['198.51.100.21']['interface'] == 'ae0.0'
    routes = records('juniper_junos', 'route', 'route_lookup')
    assert [(r['prefix'], r['next_hop'], r['interface'], r['protocol'], r['vrf']) for r in routes] == [
        ('0.0.0.0/0', '198.51.100.1', 'ge-0/0/1.0', 'static', 'default')]
    ecmp = records('juniper_junos', 'route', 'route_lookup_ecmp')
    assert [(r['prefix'], r['next_hop'], r['protocol']) for r in ecmp] == [
        ('192.0.2.128/25', '198.51.100.2', 'ospf'), ('192.0.2.128/25', '198.51.100.3', 'ospf'), ('198.51.100.0/24', None, 'connected')]


def test_junos_els_tables():
    macs = records('juniper_junos_els', 'mac_entry', 'mac_table')
    assert {(r['vlan_name'], r['port'], r['type']) for r in macs} >= {('Users', 'ge-0/0/1.0', 'dynamic'), ('default', 'ge-0/0/5.0', 'static')}
    assert all(r['vlan_id'] is None for r in macs)                       # the tag comes from the vlans join, never from a guess
    assert all(r['mac'] != '*' for r in macs) and len(macs) == 4         # the flood entry "*" is no host
    vlans = {row['name']: row for row in records('juniper_junos_els', 'vlan', 'vlans')}
    assert vlans['Users']['vlan_id'] == 10 and vlans['Users']['ports'] == ['ae0.0', 'ge-0/0/1.0']


def test_wrong_column_layout_is_unparsed_not_silently_misread():
    # `show arp` with a Name column is not `show arp no-resolve`: the interface would be a wrong value
    text = '00:00:5e:00:53:a0 198.51.100.20 host.example irb.10 none\n'
    assert t.parse('juniper_junos', 'neighbor_l3', 'arp_table', text)['status'] == 'unparsed'
    assert t.parse('arista_eos', 'lldp_neighbor', 'lldp_neighbors', 'Et1 core-sw Ethernet49\n')['status'] == 'unparsed'


# ---- the GNS3 lab: IOSv, IOSvL2, cEOS (anonymised output of the read-only account) ----------------

LAB = {'cisco_ios': [ROOT / 'real/cisco_ios/iosv_15.9.3M12', ROOT / 'real/cisco_ios/iosvl2_15.2.20200924'],
       'cisco_xe': [ROOT / 'real/cisco_xe/iolxe_17.18.2'],
       'cisco_nxos': [ROOT / 'real/cisco_nxos/nexus9300v_9.3.12'],
       'arista_eos': [ROOT / 'real/arista_eos/ceos_4.36.1F'],
       'juniper_junos_els': [ROOT / 'real/juniper_junos_els/vjunosswitch_26.2R1.7']}
LAB_CASES = [(profile, directory, key, query) for profile, directories in LAB.items() for directory in directories
             for key, query in t.BINDINGS[profile].items() if (directory / (query + '.txt')).exists()]
LAB_CASES += [('juniper_junos_els', LAB['juniper_junos_els'][0], 'route', query)
              for query in ('route_lookup_connected', 'route_lookup_default', 'route_lookup_ospf')]


def lab(directory, query):
    return (directory / (query + '.txt')).read_text()


def lab_records(profile, directory, table, query):
    result = t.parse(profile, table, query, lab(directory, query))
    assert result['status'] == 'ok' and not result['unparsed'], result['unparsed']
    return result['records']


@pytest.mark.parametrize('profile,directory,key,query', LAB_CASES, ids=lambda v: v.name if isinstance(v, Path) else str(v))
def test_every_lab_output_is_fully_recognized(profile, directory, key, query):
    table = 'route' if key.startswith('route') else key.removesuffix('_v6')
    text = lab(directory, query)
    rc = json.loads((directory / 'index.json').read_text())[query]['rc']
    status = normalization.output_status(text, rc=rc, profile=profile)
    result = t.parse(profile, table, query, text, status=status)
    assert not result['unparsed'], result['unparsed']
    assert result['status'] in ('ok', 'empty', 'not_applicable', 'permission_denied'), result['status']
    unknown = t.parse(profile, table, query, text.rstrip('\n') + '\nNEW UNRECOGNIZED OUTPUT\n', status='ok')
    if result['status'] == 'ok':
        assert unknown['status'] == 'unparsed' and unknown['unparsed'][-1]['text'] == 'NEW UNRECOGNIZED OUTPUT'


def test_a_router_image_refuses_the_switch_reads_with_the_exec_channel_message():
    iosv = LAB['cisco_ios'][0]
    for key in ('interface', 'vlan', 'mac_entry', 'lag'):
        query = t.BINDINGS['cisco_ios'][key]
        result = t.parse('cisco_ios', key, query, lab(iosv, query), status=normalization.output_status(lab(iosv, query), profile='cisco_ios'))
        assert result['status'] == 'permission_denied' and not result['records'], key


def test_iosvl2_tables():
    directory = LAB['cisco_ios'][1]
    ports = {row['name']: row for row in lab_records('cisco_ios', directory, 'interface', 'interfaces')}
    assert ports['GigabitEthernet0/1']['trunk'] is True and ports['GigabitEthernet0/3']['oper_status'] == 'down'
    assert ports['GigabitEthernet0/0']['vlan_id'] == 99 and ports['GigabitEthernet0/0']['speed'] == 'auto'
    vlans = {row['vlan_id']: row for row in lab_records('cisco_ios', directory, 'vlan', 'vlans')}
    assert vlans[99]['ports'] == ['GigabitEthernet0/0'] and vlans[10]['ports'] is None and 1002 in vlans
    macs = lab_records('cisco_ios', directory, 'mac_entry', 'mac_table')
    assert len(macs) == 17 and all(row['type'] in ('dynamic', 'static') for row in macs)
    assert {(row['mac'], row['port'], row['type']) for row in macs if row['type'] == 'static'} == {('00:00:5e:00:53:19', 'GigabitEthernet0/2', 'static')}
    arp = {row['ip']: row for row in lab_records('cisco_ios', directory, 'neighbor_l3', 'arp_table')}
    assert arp['192.0.2.2']['interface'] == 'Vlan10' and arp['192.0.2.2']['vlan_id'] == 10
    lldp = lab_records('cisco_ios', directory, 'lldp_neighbor', 'lldp_neighbors')
    peer = next(row for row in lldp if row['local_port'] == 'GigabitEthernet0/2')
    assert (peer['neighbor_port'], peer['capabilities'], peer['management_ip']) == ('Ethernet1', 'B,R', '203.0.113.131')


def test_iosv_router_tables():
    directory = LAB['cisco_ios'][0]
    arp = {row['ip']: row for row in lab_records('cisco_ios', directory, 'neighbor_l3', 'arp_table')}
    assert arp['192.0.2.77'] == {'ip': '192.0.2.77', 'mac': '00:00:5e:00:53:19', 'interface': None, 'vlan_id': None, 'vrf': None, 'type': None}   # static ARP prints no interface
    assert arp['192.0.2.3']['interface'] == 'GigabitEthernet0/1.10' and arp['192.0.2.3']['vlan_id'] is None
    (route,) = lab_records('cisco_ios', directory, 'route', 'route_lookup')
    assert (route['prefix'], route['next_hop'], route['interface'], route['protocol']) == ('203.0.113.131/32', '192.0.2.3', 'GigabitEthernet0/1.10', 'ospf')
    table = lab_records('cisco_ios', directory, 'route', 'route_table')
    assert ('0.0.0.0/0', '203.0.113.1', None, 'static') in {(r['prefix'], r['next_hop'], r['interface'], r['protocol']) for r in table}
    assert {r['protocol'] for r in table} == {'static', 'connected', 'local', 'ospf'}
    neighbors = lab_records('cisco_ios', directory, 'ospf_neighbor', 'ospf_neighbors')
    assert [(n['neighbor_id'], n['state'], n['role']) for n in neighbors] == [
        ('203.0.113.131', 'full', 'BDR'), ('203.0.113.133', '2way', 'DROTHER'), ('203.0.113.135', 'full', 'DR')]
    assert t.parse('cisco_ios', 'bgp_peer', 'bgp_summary', lab(directory, 'bgp_summary'),
                   status=normalization.output_status(lab(directory, 'bgp_summary')))['status'] == 'not_applicable'


def test_iosvl2_port_channel_and_spanning_tree():
    directory = LAB['cisco_ios'][1]
    (lag,) = lab_records('cisco_ios', directory, 'lag', 'lag_summary')
    assert lag == {'name': 'Port-channel1', 'protocol': None, 'status': 'down', 'members': []}       # Po1(SD): no member listed while Gi0/3 has no link
    stp = lab_records('cisco_ios', directory, 'stp_port', 'stp_tree')
    assert {r['instance'] for r in stp} == {'VLAN0001', 'VLAN0010', 'VLAN0020', 'VLAN0099'}
    assert {(r['role'], r['state']) for r in stp} == {('designated', 'forwarding'), ('root', 'forwarding')}      # the root port of VLAN 99 is Gi0/0
    assert {r['port'] for r in stp if r['instance'] == 'VLAN0010'} == {'GigabitEthernet0/1', 'GigabitEthernet0/2', 'GigabitEthernet0/3'}


def test_ceos_tables():
    directory = LAB['arista_eos'][0]
    ports = {row['name']: row for row in lab_records('arista_eos', directory, 'interface', 'interfaces')}
    assert ports['Ethernet1']['trunk'] is True and ports['Ethernet1']['oper_status'] == 'up' and ports['Management0']['oper_status'] == 'up'
    assert ports['Port-channel1']['vlan_id'] == 1
    vlans = {row['vlan_id']: row for row in lab_records('arista_eos', directory, 'vlan', 'vlans')}
    assert set(vlans) == {1, 10, 20} and 'Ethernet1' in vlans[10]['ports']
    macs = lab_records('arista_eos', directory, 'mac_entry', 'mac_table')
    assert {(r['mac'], r['port'], r['type']) for r in macs if r['type'] == 'static'} == {('00:00:5e:00:53:19', 'Ethernet2', 'static')}
    arp = {row['ip']: row for row in lab_records('arista_eos', directory, 'neighbor_l3', 'arp_table')}
    assert arp['192.0.2.1']['interface'] == 'Vlan10' and arp['198.51.100.5']['interface'] == 'Vlan20'      # "Vlan20, not learned"
    lldp = lab_records('arista_eos', directory, 'lldp_neighbor', 'lldp_neighbors_detail')
    by_port = {(r['local_port'], r['neighbor_port']): r for r in lldp}
    assert by_port[('Ethernet1', 'Gi0/2')]['capabilities'] == 'R' and by_port[('Ethernet1', 'Gi0/2')]['management_ip'] == '192.0.2.2'
    assert by_port[('Ethernet2', '1')]['capabilities'] is None and by_port[('Ethernet2', '1')]['management_ip'] is None     # EXOS sends neither
    assert by_port[('Ethernet4', '521')]['neighbor'] is None and by_port[('Ethernet4', '521')]['capabilities'] == 'B,R'     # no System Name TLV
    routes = lab_records('arista_eos', directory, 'route', 'route_table')
    assert {(r['prefix'], r['protocol']) for r in routes} >= {('0.0.0.0/0', 'static'), ('192.0.2.0/24', 'connected'), ('203.0.113.129/32', 'ospf')}
    assert all(r['vrf'] == 'default' for r in routes)
    (lookup,) = lab_records('arista_eos', directory, 'route', 'route_lookup_ospf')
    assert (lookup['prefix'], lookup['next_hop'], lookup['interface']) == ('203.0.113.129/32', '192.0.2.1', 'Vlan10')
    neighbors = lab_records('arista_eos', directory, 'ospf_neighbor', 'ospf_neighbors')
    assert {(n['neighbor_id'], n['state'], n['role'], n['interface'], n['vrf']) for n in neighbors} >= {('203.0.113.135', 'full', 'DR', 'Vlan10', 'default')}
    (lag,) = lab_records('arista_eos', directory, 'lag', 'lag_summary')
    assert lag == {'name': 'Port-channel1', 'protocol': 'Static', 'status': 'up', 'members': [{'port': 'Ethernet6', 'state': 'bundled'}]}
    stp = lab_records('arista_eos', directory, 'stp_port', 'stp_tree')
    assert {r['instance'] for r in stp} == {'MST0'} and ('Port-channel1', 'forwarding') in {(r['port'], r['state']) for r in stp}
    bgp = t.parse('arista_eos', 'bgp_peer', 'bgp_summary', lab(directory, 'bgp_summary'),
                  status=normalization.output_status(lab(directory, 'bgp_summary'), rc=1))
    assert bgp['status'] == 'not_applicable'


# ---- the GNS3 lab, second part: Nexus 9300v (NX-OS), IOL (IOS XE), vJunos-switch (Junos ELS) -----------------
# The lab had temporary BGP/NTP/static-route configuration while these were captured (see fixtures/real/README.md).

NXOS = LAB['cisco_nxos'][0]
IOLXE = LAB['cisco_xe'][0]
VJUNOS = ROOT / 'real/juniper_junos_els/vjunosswitch_26.2R1.7'


def lab_status(profile, directory, query):
    rc = json.loads((directory / 'index.json').read_text())[query]['rc']
    return normalization.output_status(lab(directory, query), rc=rc, profile=profile)


def test_nxos_routes_ospf_bgp_lag_and_spanning_tree():
    routes = lab_records('cisco_nxos', NXOS, 'route', 'route_table')
    assert {r['protocol'] for r in routes} == {'connected', 'local', 'ospf', 'static'} and {r['vrf'] for r in routes} == {'default'}
    ospf = [r for r in routes if r['protocol'] == 'ospf']
    assert len(ospf) == 4 and all(r['interface'] == 'Vlan10' and r['next_hop'] for r in ospf)
    assert any(r['protocol'] == 'static' and r['interface'] is None and r['next_hop'] for r in routes)       # "via 10.x, [1/0], static": no interface printed
    peers = lab_records('cisco_nxos', NXOS, 'ospf_neighbor', 'ospf_neighbors')
    assert {(n['state'], n['role']) for n in peers} == {('2way', 'DROTHER'), ('full', 'BDR'), ('full', 'DR')} and {n['vrf'] for n in peers} == {'default'}
    (bgp,) = lab_records('cisco_nxos', NXOS, 'bgp_peer', 'bgp_summary')
    assert (bgp['state'], bgp['prefixes'], bgp['remote_as'], bgp['vrf']) == ('Idle', None, '65099', 'default')
    (lag,) = lab_records('cisco_nxos', NXOS, 'lag', 'lag_summary')
    assert lag == {'name': 'Port-channel1', 'protocol': 'LACP', 'status': 'down', 'members': [{'port': 'Ethernet1/3', 'state': 'suspended'}]}
    stp = lab_records('cisco_nxos', NXOS, 'stp_port', 'stp_tree')
    assert {r['instance'] for r in stp} == {'VLAN0001', 'VLAN0010', 'VLAN0020'}
    assert {(r['port'], r['role']) for r in stp if r['instance'] == 'VLAN0010'} == {('Ethernet1/1', 'root')}


def test_nxos_without_a_feature_the_command_is_unsupported_and_a_denied_role_is_permission_denied():
    for query in ('hsrp_summary', 'vrrp_summary', 'dhcp_snooping_binding'):
        assert lab_status('cisco_nxos', NXOS, query) == 'unsupported', query
    assert normalization.output_status('% Permission denied for the role\n\nCmd exec error.\n', rc=30, profile='cisco_nxos') == 'permission_denied'
    assert lab(NXOS, 'bfd_neighbors') == '' and lab_status('cisco_nxos', NXOS, 'bfd_neighbors') == 'empty'


def test_nxos_lldp_detail_has_the_management_port_neighbour_only():
    (row,) = lab_records('cisco_nxos', NXOS, 'lldp_neighbor', 'lldp_neighbors')
    assert row['local_port'] == 'mgmt0' and row['capabilities'] == 'R' and row['management_ip'] and row['neighbor_port'] == 'Et0/0'     # the data link prints no LLDP neighbour on 9300v


def test_nxos_static_mac_and_incomplete_arp_are_read_as_they_are_printed():
    macs = lab_records('cisco_nxos', NXOS, 'mac_entry', 'mac_table')
    assert [(r['port'], r['type']) for r in macs if r['type'] == 'static'] == [('Ethernet1/2', 'static')]         # the gateway (G) rows are the switch itself
    arp = {r['ip']: r for r in lab_records('cisco_nxos', NXOS, 'neighbor_l3', 'arp_table')}
    assert any(r['mac'] is None and r['interface'] == 'Vlan10' for r in arp.values())


def test_nxos_documented_established_bgp_and_bundled_port_channels():
    peers = {row['neighbor']: row for row in records('cisco_nxos', 'bgp_peer', 'bgp_summary')}
    assert (peers['192.0.2.1']['state'], peers['192.0.2.1']['prefixes']) == ('Established', 3)
    assert peers['192.0.2.9']['state'] == 'Idle' and peers['192.0.2.13']['state'] == 'Active'
    lags = {row['name']: row for row in records('cisco_nxos', 'lag', 'lag_summary')}
    assert lags['Port-channel1']['status'] == 'up' and [m['state'] for m in lags['Port-channel1']['members']] == ['bundled', 'bundled']
    assert lags['Port-channel2']['status'] == 'down' and lags['Port-channel10']['protocol'] is None
    assert [m['state'] for m in lags['Port-channel10']['members']] == ['bundled', 'bundled', 'suspended']


def test_iolxe_router_tables():
    routes = lab_records('cisco_xe', IOLXE, 'route', 'route_table')
    assert {r['protocol'] for r in routes} >= {'static', 'connected', 'local', 'ospf'}
    assert any(r['prefix'] == '0.0.0.0/0' and r['protocol'] == 'static' and r['next_hop'] for r in routes)
    assert all(r['interface'] is None or r['interface'].startswith(('Ethernet0/', 'Loopback0')) for r in routes)
    ospf = lab_records('cisco_xe', IOLXE, 'ospf_neighbor', 'ospf_neighbors')
    assert len(ospf) == 4 and {n['state'] for n in ospf} == {'full'} and {n['role'] for n in ospf} == {'DROTHER', 'BDR'}
    (bgp,) = lab_records('cisco_xe', IOLXE, 'bgp_peer', 'bgp_summary')
    assert bgp['state'] in ('Idle', 'Active') and bgp['prefixes'] is None
    lldp = lab_records('cisco_xe', IOLXE, 'lldp_neighbor', 'lldp_neighbors')
    assert {r['local_port'] for r in lldp} == {'Ethernet0/0', 'Ethernet0/1'} and any(r['capabilities'] == 'B,R' for r in lldp)
    arp = lab_records('cisco_xe', IOLXE, 'neighbor_l3', 'arp_table')
    assert any(r['mac'] is None for r in arp) and all(r['interface'] is None or r['interface'].startswith('Ethernet0/') for r in arp)


def test_iolxe_router_image_refuses_the_switch_reads_and_has_no_spanning_tree():
    for key in ('interface', 'vlan', 'mac_entry', 'lag'):
        query = t.BINDINGS['cisco_xe'][key]
        assert lab_status('cisco_xe', IOLXE, query) == 'permission_denied', key
    assert t.parse('cisco_xe', 'stp_port', 'stp_tree', lab(IOLXE, 'stp_tree'))['status'] == 'empty'     # "No spanning tree instance exists."
    for query in ('log_messages', 'stp_inconsistent'):          # privilege 1 is refused, the admin account is answered
        assert 'invalid autocommand' in lab(IOLXE, query) and (IOLXE / (query + '.admin.txt')).exists()


def test_vjunos_routes_ospf_spanning_tree_and_lldp_detail():
    routes = lab_records('juniper_junos_els', VJUNOS, 'route', 'route_table')
    assert {r['protocol'] for r in routes} >= {'static', 'connected', 'local', 'ospf'}
    assert next(r for r in routes if r['prefix'] == '0.0.0.0/0')['interface'] == 'fxp0.0'
    assert {(r['interface'], r['protocol']) for r in routes if r['prefix'].endswith('/32') and r['protocol'] == 'connected'} == {('lo0.0', 'connected')}
    ospf = lab_records('juniper_junos_els', VJUNOS, 'ospf_neighbor', 'ospf_neighbors')
    assert {n['state'] for n in ospf} == {'2way', 'full'} and {n['interface'] for n in ospf} == {'irb.10'}
    (stp,) = lab_records('juniper_junos_els', VJUNOS, 'stp_port', 'stp_interfaces')
    assert (stp['port'], stp['role'], stp['state'], stp['cost']) == ('ge-0/0/0', 'root', 'forwarding', 20000)
    (lldp,) = lab_records('juniper_junos_els', VJUNOS, 'lldp_neighbor', 'lldp_neighbors_detail')
    assert (lldp['local_port'], lldp['capabilities']) == ('ge-0/0/0', 'B,R') and lldp['management_ip'] and lldp['neighbor_port'] == 'Ethernet4'


def test_vjunos_mac_table_has_age_and_gbp_columns_and_the_static_entry_is_on_the_access_port():
    macs = lab_records('juniper_junos_els', VJUNOS, 'mac_entry', 'mac_table')
    assert {r['port'] for r in macs if r['type'] == 'static'} == {'ge-0/0/1.0'} and {r['vlan_name'] for r in macs} == {'D10', 'D20'}
    assert all(r['port'] in ('ge-0/0/0.0', 'ge-0/0/1.0') for r in macs)
    arp = lab_records('juniper_junos_els', VJUNOS, 'neighbor_l3', 'arp_table')
    assert any(r['interface'] == 'irb.10' for r in arp) and not any(r['interface'] in ('permanent', 'published') for r in arp)      # "permanent published" are flags


def test_vjunos_without_the_feature_or_the_licence_a_table_is_not_applicable_or_empty():
    assert lab_status('juniper_junos_els', VJUNOS, 'bgp_summary') == 'not_applicable'                  # "BGP is not running" (no licence key)
    assert lab_status('juniper_junos_els', VJUNOS, 'lacp_interfaces') == 'empty'                       # an aggregate whose member is down prints nothing
    assert normalization.output_status('\nSpanning-tree is not enabled at global level.\n', profile='juniper_junos_els') == 'not_applicable'
    for query in ('log_messages', 'log_interactive_commands'):       # the built-in read-only class cannot read the log files
        assert lab_status('juniper_junos_els', VJUNOS, query) == 'permission_denied'
        assert 'permission denied' not in lab(VJUNOS, query + '.admin') and (VJUNOS / (query + '.admin.txt')).stat().st_size > 1000


def test_vjunos_documented_established_bgp_and_lacp_bundles():
    for profile in ('juniper_junos', 'juniper_junos_els'):
        peers = {row['neighbor']: row for row in records(profile, 'bgp_peer', 'bgp_summary')}
        assert (peers['192.0.2.65']['state'], peers['192.0.2.65']['prefixes']) == ('Established', 4)
        assert (peers['192.0.2.69']['state'], peers['192.0.2.73']['state']) == ('Active', 'Idle')
        lags = {row['name']: row for row in records(profile, 'lag', 'lacp_interfaces')}
        assert lags['ae0']['status'] == 'up' and [m['state'] for m in lags['ae0']['members']] == ['bundled', 'bundled']
        assert lags['ae1']['status'] == 'down' and lags['ae1']['members'] == [{'port': 'ge-0/0/3', 'state': 'down'}]


def test_junos_route_table_with_several_protocols_and_next_hops():
    text = ("\ninet.0: 3 destinations, 4 routes (3 active, 0 holddown, 0 hidden)\n+ = Active Route, - = Last Active, * = Both\n\n"
            "198.51.100.0/24    *[OSPF/10] 00:10:00, metric 5\n                    >  to 192.0.2.2 via ge-0/0/1.0\n                       to 192.0.2.6 via ge-0/0/2.0\n"
            "                   [BGP/170] 00:09:00, localpref 100\n                      AS path: 65001 I\n                    >  to 192.0.2.10 via ge-0/0/3.0\n"
            "203.0.113.0/25     *[Static/5] 00:01:00\n                       Discard\n"
            "red.inet.0: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)\n\n"
            "203.0.113.128/25   *[Direct/0] 00:01:00\n                    >  via ge-0/0/4.0\n")
    result = t.parse('juniper_junos_els', 'route', 'route_table', text)
    assert result['status'] == 'ok', result['unparsed']
    assert [(r['prefix'], r['next_hop'], r['interface'], r['protocol'], r['vrf']) for r in result['records']] == [
        ('198.51.100.0/24', '192.0.2.2', 'ge-0/0/1.0', 'ospf', 'default'), ('198.51.100.0/24', '192.0.2.6', 'ge-0/0/2.0', 'ospf', 'default'),
        ('203.0.113.0/25', None, None, 'static', 'default'), ('203.0.113.128/25', None, 'ge-0/0/4.0', 'connected', 'red')]


@pytest.mark.parametrize('query,hop,interface,protocol', [
    ('route_lookup_ospf', '192.0.2.1', 'irb.10', 'ospf'),
    ('route_lookup_default', '203.0.113.129', 'fxp0.0', 'static'),
])
def test_junos_live_lookup_preserves_next_hop(query, hop, interface, protocol):
    (route,) = lab_records('juniper_junos_els', VJUNOS, 'route', query)
    assert (route['next_hop'], route['interface'], route['protocol']) == (hop, interface, protocol)


def test_junos_unknown_next_hop_is_not_skipped_as_an_attribute():
    text = lab(VJUNOS, 'route_lookup_ospf').replace('Next hop: 192.0.2.1  via irb.10, selected',
                                                               'Next hop: UNKNOWN FORMAT')
    result = t.parse('juniper_junos_els', 'route', 'route_lookup', text)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert len(result['unparsed']) == 1 and 'Next hop: UNKNOWN FORMAT' in result['unparsed'][0]['text']


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
@pytest.mark.parametrize('marker', ['+', '*', None])
@pytest.mark.parametrize('active_first', [False, True])
def test_junos_route_table_only_selects_active_routes(profile, marker, active_first):
    inactive = '-[BGP/170] 00:10:00, localpref 100\n                    > to 198.51.100.1 via ge-0/0/1.0\n'
    candidate = (marker or '') + '[OSPF/10] 00:01:00, metric 2\n                    > to 198.51.100.2 via ge-0/0/2.0\n'
    entries = [candidate, inactive] if active_first else [inactive, candidate]
    text = ('inet.0: 1 destinations, 2 routes (1 active, 0 holddown, 0 hidden)\n'
            '+ = Active Route, - = Last Active, * = Both\n'
            '192.0.2.0/24      ' + entries[0] + '                 ' + entries[1])
    result = t.parse(profile, 'route', 'route_table', text)
    assert not result['unparsed']
    if marker is None:
        assert result['status'] == 'empty' and result['records'] == []
    else:
        assert result['status'] == 'ok'
        (route,) = result['records']
        assert (route['protocol'], route['next_hop'], route['interface']) == ('ospf', '198.51.100.2', 'ge-0/0/2.0')


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_junos_documented_neighbour_detail_values(profile):
    result = t.parse(profile, 'lldp_neighbor', 'lldp_neighbors_detail', doc('juniper_junos', 'lldp_neighbors_detail'))
    assert result['status'] == 'ok' and not result['unparsed']
    (neighbor,) = result['records']
    assert (neighbor['local_port'], neighbor['neighbor'], neighbor['neighbor_port']) == ('ge-0/0/2', 'host01', 'ge-0/0/2')


@pytest.mark.parametrize('heading', ['Neighbor Information:', 'Neighbour Information:'])
def test_junos_live_lldp_accepts_both_heading_spellings(heading):
    text = lab(VJUNOS, 'lldp_neighbors_detail').replace('Neighbor Information:', heading)
    result = t.parse('juniper_junos_els', 'lldp_neighbor', 'lldp_neighbors_detail', text)
    assert result['status'] == 'ok' and not result['unparsed']
    (neighbor,) = result['records']
    assert (neighbor['neighbor'], neighbor['neighbor_port'], neighbor['capabilities'], neighbor['management_ip']) == (
        'host06', 'Ethernet4', 'B,R', '203.0.113.3')


@pytest.mark.parametrize('profile,directory', [
    (profile, directory) for profile, directories in LAB.items() for directory in directories
] + [('extreme_exos', directory) for directory in EXOS_DIRS])
def test_live_connected_routes_share_one_protocol_name(profile, directory):
    query = t.BINDINGS[profile]['route_all' if 'route_all' in t.BINDINGS[profile] else 'route']
    rows = lab_records(profile, directory, 'route', query)
    assert 'connected' in {row['protocol'] for row in rows}
    assert 'direct' not in {row['protocol'] for row in rows}


@pytest.mark.parametrize('profile,directory,key,query', [
    case for case in LAB_CASES if case[2] in ('interface', 'ospf_neighbor', 'bgp_peer', 'lag', 'stp_port')
])
def test_known_live_state_values_use_shared_names(profile, directory, key, query):
    enums = {
        'interface': {'oper_status': {'up', 'down'}},
        'ospf_neighbor': {'state': {'down', 'attempt', 'init', '2way', 'exstart', 'exchange', 'loading', 'full'},
                          'role': {'DR', 'BDR', 'DROTHER', None}},
        'bgp_peer': {'state': {'Idle', 'Connect', 'Active', 'OpenSent', 'OpenConfirm', 'Established',
                                'Idle(admin)', 'Idle(prefixlimit)'}},
        'lag': {'protocol': {'LACP', 'PAgP', 'Static', None}, 'status': {'up', 'down', 'not in use', None}},
        'stp_port': {'role': {'designated', 'root', 'alternate', 'backup', 'master', 'disabled', 'boundary'},
                     'state': {'forwarding', 'blocking', 'learning', 'listening', 'discarding', 'disabled', 'broken'}},
    }
    for row in t.parse(profile, key, query, lab(directory, query))['records']:
        for field, allowed in enums[key].items():
            assert row[field] in allowed, (profile, key, field, row)
        if key == 'lag':
            assert all(member['state'] in {'bundled', 'down', 'suspended'} for member in row['members'])


@pytest.mark.parametrize('protocol,expected', [('direct', 'connected'), ('ospf-1', 'ospf'), ('is-is', 'isis'), ('is-is-1', 'isis')])
@pytest.mark.parametrize('interface_only', [False, True])
def test_nxos_route_protocol_spellings_on_live_layout(protocol, expected, interface_only):
    # Variants of the real connected lookup exercise both NX-OS next-hop forms.
    text = lab(NXOS, 'route_lookup_connected').replace(', direct', ', ' + protocol)
    if interface_only:
        text = text.replace('192.0.2.5, Vlan10', 'Vlan10')
    (route,) = parse('cisco_nxos', 'route', text)['records']
    assert route['protocol'] == expected and route['interface'] == 'Vlan10'


@pytest.mark.parametrize('profile,directory', [('cisco_xe', IOLXE), ('cisco_nxos', NXOS)])
def test_bgp_state_case_variants_on_live_layout(profile, directory):
    text = lab(directory, 'bgp_summary')
    original = lab_records(profile, directory, 'bgp_peer', 'bgp_summary')[0]['state']
    for word, expected in [('idle', 'Idle'), ('ACTIVE', 'Active'), ('OpenSent', 'OpenSent'), ('openconfirm', 'OpenConfirm')]:
        (peer,) = parse(profile, 'bgp_peer', text.replace(original, word))['records']
        assert peer['state'] == expected and peer['prefixes'] is None


def test_lacp_protocol_case_variants_on_live_layout():
    text = lab(NXOS, 'lag_summary')
    for word in ('lacp', 'Lacp', 'LACP'):
        (lag,) = parse('cisco_nxos', 'lag', text.replace('LACP', word))['records']
        assert lag['protocol'] == 'LACP' and lag['members'][0]['state'] == 'suspended'


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_junos_bgp_state_case_variants_on_documented_layout(profile):
    # The live vJunos BGP fixture has no peers, so state variants use a documented layout.
    text = doc(profile, 'bgp_summary').replace('Idle', 'IDLE').replace('Active', 'active')
    rows = parse(profile, 'bgp_peer', text)['records']
    assert {row['state'] for row in rows} == {'Idle', 'Active', 'Established'}


@pytest.mark.parametrize('word,expected', [('Direct', 'connected'), ('OSPF3', 'ospf'), ('IS-IS', 'isis')])
def test_junos_detail_protocol_spellings_on_live_layout(word, expected):
    text = lab(VJUNOS, 'route_lookup_connected').replace('Direct', word)
    rows = parse('juniper_junos_els', 'route', text)['records']
    assert rows and {row['protocol'] for row in rows} == {expected}


@pytest.mark.parametrize('profile,directory', [('cisco_ios', IOLXE), ('cisco_xe', IOLXE), ('cisco_nxos', NXOS)])
@pytest.mark.parametrize('word,expected', [
    ('Idle(admin)', 'Idle(admin)'), ('idle (admin)', 'Idle(admin)'), ('Idle (Admin)', 'Idle(admin)'),
    ('Shut (Admin)', 'Idle(admin)'), ('Idle (PfxCt)', 'Idle(prefixlimit)'),
    ('idle(prefixlimit)', 'Idle(prefixlimit)'), ('Idle (prefixlimit)', 'Idle(prefixlimit)'),
    ('Idle   (Admin)', 'Idle(admin)'), ('12', 'Established'),
])
def test_bgp_reason_and_prefix_count_on_cisco_live_layout(profile, directory, word, expected):
    # IOS/XE share the IOL XE column layout; vary only the final State/PfxRcd cell.
    text = lab(directory, 'bgp_summary')
    original = lab_records('cisco_xe' if directory == IOLXE else profile, directory, 'bgp_peer', 'bgp_summary')[0]['state']
    result = parse(profile, 'bgp_peer', text.replace(original, word))
    assert result['status'] == 'ok' and not result['unparsed']
    (peer,) = result['records']
    assert (peer['state'], peer['prefixes'], peer['remote_as']) == (expected, 12 if word == '12' else None, '65099')
    assert peer['neighbor'] == '192.0.2.99'


@pytest.mark.parametrize('profile,directory', [('cisco_xe', IOLXE), ('cisco_nxos', NXOS)])
def test_unknown_bgp_reason_is_explicitly_unparsed(profile, directory):
    original = lab_records(profile, directory, 'bgp_peer', 'bgp_summary')[0]['state']
    result = parse(profile, 'bgp_peer', lab(directory, 'bgp_summary').replace(original, 'Idle (NewReason)'))
    assert result['status'] == 'unparsed' and not result['records'] and len(result['unparsed']) == 1


@pytest.mark.parametrize('profile,directory', [('cisco_ios', LAB['cisco_ios'][1]), ('cisco_nxos', NXOS)])
@pytest.mark.parametrize('word,expected', [('pagp', 'PAgP'), ('none', None), ('static', 'Static'), ('VendorProto', 'VendorProto')])
def test_lag_protocol_names_and_unknown_passthrough_on_live_layout(profile, directory, word, expected):
    text = lab(directory, 'lag_summary')
    if profile == 'cisco_ios':
        changed = text.replace('          -        ', f'          {word}        ')
    else:
        changed = text.replace('LACP', word)
    assert changed != text
    result = parse(profile, 'lag', changed)
    assert result['status'] == 'ok' and not result['unparsed']
    (lag,) = result['records']
    assert lag['protocol'] == expected


@pytest.mark.parametrize('word,expected', [('ospfv3', 'ospf'), ('ospfv3-1', 'ospf'), ('OSPFv3-20', 'ospf'), ('hsrp', 'hsrp'), ('Vendor-10', 'vendor')])
@pytest.mark.parametrize('interface_only', [False, True])
def test_nxos_ipv6_route_protocol_names(word, expected, interface_only):
    # IPv6 Routing Table and via layout from the review reproduction; not a live IPv6 capture.
    hop = 'Eth1/1' if interface_only else 'fe80::1, Eth1/1'
    text = f'''IPv6 Routing Table for VRF "default"
2001:db8::/64, ubest/mbest: 1/0
    *via {hop}, [110/41], 00:01:00, {word}, intra
'''
    result = t.parse('cisco_nxos', 'route', 'route_v6', text)
    assert result['status'] == 'ok' and not result['unparsed']
    (route,) = result['records']
    assert (route['prefix'], route['protocol'], route['interface'], route['vrf']) == ('2001:db8::/64', expected, 'Ethernet1/1', 'default')
    assert route['next_hop'] == (None if interface_only else 'fe80::1')


@pytest.mark.parametrize('profile,directory', [('cisco_ios', LAB['cisco_ios'][0]), ('arista_eos', LAB['arista_eos'][0]), ('cisco_nxos', NXOS)])
def test_unknown_ospf_state_preserves_text_with_lowercase(profile, directory):
    text = lab(directory, 'ospf_neighbors')
    changed = text.replace('FULL', 'VendorState').replace('Full', 'VendorState').replace('TWOWAY', 'VendorState').replace('2WAY', 'VendorState')
    assert changed != text
    result = parse(profile, 'ospf_neighbor', changed)
    assert result['status'] == 'ok' and not result['unparsed']
    assert result['records'] and {row['state'] for row in result['records']} == {'vendorstate'}


def test_populated_ipv6_neighbour_layouts_are_docs_only():
    # Keep the public scope statement tied to all dated captures, including lookup variants.
    seen = 0
    for profile, directories in {**LAB, 'extreme_exos': EXOS_DIRS + [ROOT / 'real/exos/exosvm_33.6.1.14']}.items():
        query = t.BINDINGS[profile]['neighbor_l3_v6']
        for directory in directories:
            for path in directory.glob(query + '*.txt'):
                result = t.parse(profile, 'neighbor_l3', query, path.read_text())
                assert result['status'] == 'empty' and not result['records'] and not result['unparsed'], path
                seen += 1
    assert seen >= len(LAB)


EOS_LEGEND_PROTOCOLS = {
    'C': 'connected', 'S': 'static', 'K': 'kernel',
    'O': 'ospf', 'O IA': 'ospf', 'O E1': 'ospf', 'O E2': 'ospf', 'O N1': 'ospf', 'O N2': 'ospf',
    'O3': 'ospf', 'O3 IA': 'ospf', 'O3 E1': 'ospf', 'O3 E2': 'ospf', 'O3 N1': 'ospf', 'O3 N2': 'ospf',
    'B': 'bgp', 'B I': 'bgp', 'B E': 'bgp', 'R': 'rip', 'I L1': 'isis', 'I L2': 'isis',
    'A B': 'aggregate', 'A O': 'aggregate', 'NG': 'ng', 'V': 'v', 'M': 'm', 'DH': 'dhcp',
    'DP': 'dp', 'L': 'l', 'G': 'g', 'RC': 'rc', 'CL': 'cl',
}


def test_eos_route_cases_cover_every_code_in_the_live_legend():
    text = lab(LAB['arista_eos'][0], 'route_table')
    legend = text.split('Source Codes:', 1)[1].split('Gateway of last resort:', 1)[0]
    codes = re.findall(r'(?:^|,)\s*([A-Z0-9]+(?: [A-Z0-9]+)?)\s+- ', legend, re.MULTILINE)
    assert set(codes) == set(EOS_LEGEND_PROTOCOLS)


@pytest.mark.parametrize('code,expected', list(EOS_LEGEND_PROTOCOLS.items()) + [
    ('I', 'isis'), ('A', 'aggregate'), ('D', 'd'), ('O X', 'o x'), ('O3 X', 'o3 x'), ('ZZ', 'zz')])
@pytest.mark.parametrize('layout', ['multiline', 'inline', 'direct'])
@pytest.mark.parametrize('ipv6', [False, True])
def test_eos_complete_route_codes_on_live_capture_layout(code, expected, layout, ipv6):
    # Keep the real legend and surrounding routes; substitute one OSPF row.
    text = lab(LAB['arista_eos'][0], 'route_table')
    prefix = '2001:db8:5::/64' if ipv6 else '203.0.113.129/32'
    hop = 'fe80::1' if ipv6 else '192.0.2.1'
    route = f' {code:<8} {prefix}'
    if layout == 'direct':
        route += ' is directly connected, Vlan10'
    elif layout == 'inline':
        route += f' [110/11] via {hop}, Vlan10'
    else:
        route += f' [110/11]\n           via {hop}, Vlan10'
    text = text.replace(' O        203.0.113.129/32 [110/11]\n           via 192.0.2.1, Vlan10', route)
    for query in ('route_table', 'ipv6_route_lookup' if ipv6 else 'route_lookup'):
        result = t.parse('arista_eos', 'route', query, text)
        assert result['status'] == 'ok' and not result['unparsed'], result
        (row,) = [row for row in result['records'] if row['prefix'] == prefix]
        assert row == {'prefix': prefix, 'next_hop': None if layout == 'direct' else hop,
                       'interface': 'Vlan10', 'protocol': expected, 'vrf': 'default'}


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
def test_ios_ipv6_detail_lookup_from_documentation(profile):
    result = t.parse(profile, 'route', 'ipv6_route_lookup', doc(profile, 'ipv6_route_lookup'))
    assert result['status'] == 'ok' and not result['unparsed'], result
    assert result['records'] == [{'prefix': '2001:db8::/64', 'next_hop': 'fe80::1',
                                 'interface': 'GigabitEthernet0/1', 'protocol': 'ospf', 'vrf': None}]


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
def test_ios_ipv6_detail_ecmp_and_scoped_link_local(profile):
    text = doc(profile, 'ipv6_route_lookup').replace('1/1', '2/2').replace(
        'FE80::1, GigabitEthernet0/1', 'FE80::1%GigabitEthernet0/1, GigabitEthernet0/1')
    text += '    2001:DB8:1::2, GigabitEthernet0/2\n      From 2001:DB8:1::2\n      Last updated 1d01h ago\n'
    result = t.parse(profile, 'route', 'ipv6_route_lookup', text)
    assert result['status'] == 'ok' and not result['unparsed'], result
    assert [(row['next_hop'], row['interface'], row['protocol']) for row in result['records']] == [
        ('fe80::1', 'GigabitEthernet0/1', 'ospf'), ('2001:db8:1::2', 'GigabitEthernet0/2', 'ospf')]
    assert {row['prefix'] for row in result['records']} == {'2001:db8::/64'}


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
@pytest.mark.parametrize('protocol,interface', [('connected', 'GigabitEthernet0/1'), ('static', 'Null0'), ('local', 'Loopback0')])
def test_ios_ipv6_direct_path_preserves_known_via_protocol(profile, protocol, interface):
    text = doc(profile, 'ipv6_route_lookup').replace('ospf 1', protocol).replace(
        'FE80::1, GigabitEthernet0/1', 'directly connected via ' + interface)
    result = t.parse(profile, 'route', 'ipv6_route_lookup', text)
    assert result['status'] == 'ok' and not result['unparsed'], result
    (row,) = result['records']
    assert (row['prefix'], row['next_hop'], row['interface'], row['protocol']) == (
        '2001:db8::/64', None, interface, protocol)


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
@pytest.mark.parametrize('old,new', [
    ('2001:DB8::/64', '2001:DB8::/129'),
    ('FE80::1, GigabitEthernet0/1', 'FE80::1::2, GigabitEthernet0/1'),
    ('FE80::1, GigabitEthernet0/1', 'FE80::1, GigabitEthernet0/1 unexpected'),
    ('Routing paths:', 'Unexpected paths:'),
])
def test_ios_ipv6_invalid_detail_rows_stay_unparsed(profile, old, new):
    text = doc(profile, 'ipv6_route_lookup').replace(old, new)
    result = t.parse(profile, 'route', 'ipv6_route_lookup', text)
    assert result['status'] == 'unparsed' and result['unparsed'], result
