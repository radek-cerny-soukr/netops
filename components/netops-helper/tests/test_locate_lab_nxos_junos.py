"""locate_endpoint end to end on the GNS3 lab with the Nexus 9300v (NX-OS) and the vJunos-switch (Junos ELS).

Chain: IOSv (router, static ARP) - IOSvL2 Gi0/2 - cEOS Ethernet3 or Ethernet4 - NX-OS Ethernet1/2 or vJunos ge-0/0/1.0.
Two static hosts were created for the capture: host A behind the Nexus port Ethernet1/2, host B behind the vJunos port ge-0/0/1.
Every answer is the anonymised output the device printed to the read-only account, `show version` included
(tests/fixtures/real/lab_endpoints holds IOSv, IOSvL2 and cEOS of that moment; Nexus and vJunos are the full template sets).
The endpoint values are read from the stored tables, so the test follows the anonymiser mapping.
"""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

REAL = Path(__file__).parent / 'fixtures/real'
LAB = {
    'iosv': ('cisco_ios', REAL / 'lab_endpoints/iosv', ('router',)),
    'iosvl2': ('cisco_ios', REAL / 'lab_endpoints/iosvl2', ('switch',)),
    'ceos': ('arista_eos', REAL / 'lab_endpoints/ceos', ('switch', 'router')),
    'nxos': ('cisco_nxos', REAL / 'cisco_nxos/nexus9300v_9.3.12', ('switch', 'router')),
    'vjunos': ('juniper_junos_els', REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7', ('switch', 'router')),
}
QUERIES = {
    'cisco_ios': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans'),
    'arista_eos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans', 'hostname'),
    'cisco_nxos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans'),
    'juniper_junos_els': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans', 'hardware', 'uptime'),
}


def lab_target(name):
    profile, directory, types = LAB[name]
    return replace(_target(profile, 'mac_table'), alias=name, device_types=types, enabled_queries=QUERIES[profile]), directory


def answers(profile, directory):
    result = {}
    for query_name, query in READ_QUERIES[profile].items():
        file = directory / (query_name + '.txt')
        if file.exists() and not query.slots:
            result[query.command] = file.read_text()
    return result


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)

    def install(*names):
        targets = [lab_target(n) for n in names]
        by_alias = {auth.alias: answers(auth.ssh_platform, directory) for auth, directory in targets}
        calls = []

        def read(auth, profile, command):
            calls.append((auth.alias, command))
            return 0, by_alias[auth.alias][command]
        monkeypatch.setattr(engine, 'read_from_device', read)
        return [auth for auth, _ in targets], calls
    return install


def static_mac(alias):
    profile, directory, _ = LAB[alias]
    rows = tables.parse(profile, 'mac_entry', 'mac_table', (directory / 'mac_table.txt').read_text())['records']
    (row,) = [r for r in rows if r['type'] == 'static']
    return row['mac'], row['port']


def host_ip(mac):
    rows = tables.parse('cisco_ios', 'neighbor_l3', 'arp_table', (LAB['iosv'][1] / 'arp_table.txt').read_text())['records']
    (row,) = [r for r in rows if r['mac'] == mac]
    return row['ip']


def roles(result):
    return {f['vantage']: (f['port'], f['role']) for f in result['findings']}


def test_host_behind_the_nexus_port_is_followed_by_ip_across_ios_eos_to_the_nx_os_edge(lab):
    mac, port = static_mac('nxos')
    assert port == 'Ethernet1/2'
    auths, calls = lab('iosv', 'iosvl2', 'ceos', 'nxos')
    result = engine._locate_endpoint_run(auths, host_ip(mac))
    assert result['verdict'] == 'located', result['missing']
    assert roles(result) == {'iosvl2': ('GigabitEthernet0/2', 'transit'), 'ceos': ('Ethernet3', 'transit'), 'nxos': ('Ethernet1/2', 'edge')}
    edge = next(f for f in result['findings'] if f['edge'])
    assert (edge['mac'], edge['vlan_id']) == (mac, 10) and edge['lldp_neighbors'] == []
    assert [o['vantage'] for o in result['neighbors_l3']] == ['iosv'] and result['neighbors_l3'][0]['mac'] == mac
    assert sum(command == 'show version' for _, command in calls) == 4          # one identity check per alias


def test_host_behind_the_vjunos_port_is_followed_by_mac_across_ios_eos_to_the_junos_edge(lab):
    mac, port = static_mac('vjunos')
    assert port == 'ge-0/0/1.0'
    auths, calls = lab('iosvl2', 'ceos', 'vjunos')
    result = engine._locate_endpoint_run(auths, mac)
    assert result['verdict'] == 'located', result['missing']
    assert roles(result) == {'iosvl2': ('GigabitEthernet0/2', 'transit'), 'ceos': ('Ethernet4', 'transit'), 'vjunos': ('ge-0/0/1.0', 'edge')}
    edge = next(f for f in result['findings'] if f['edge'])
    assert (edge['mac'], edge['vlan_id'], edge['vlan_name']) == (mac, 10, 'D10')          # the tag comes from the vlans join
    assert any(command == 'show vlans brief | no-more' for _, command in calls)
    assert sum(command == 'show version | no-more' for _, command in calls) == 1


def test_all_five_devices_find_each_host_where_it_is(lab):
    auths, _ = lab('iosv', 'iosvl2', 'ceos', 'nxos', 'vjunos')
    for alias, edge_port in (('nxos', 'Ethernet1/2'), ('vjunos', 'ge-0/0/1.0')):
        result = engine._locate_endpoint_run(auths, host_ip(static_mac(alias)[0]))
        assert result['verdict'] == 'located' and roles(result)[alias] == (edge_port, 'edge')
        assert sum(1 for f in result['findings'] if f['edge']) == 1


def test_without_the_leaf_switch_the_host_is_beyond_the_last_enrolled_one(lab):
    auths, _ = lab('iosv', 'iosvl2', 'ceos')
    result = engine._locate_endpoint_run(auths, host_ip(static_mac('nxos')[0]))
    assert result['verdict'] == 'incomplete'
    assert {'vantage': 'ceos', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': 'Ethernet3'} in result['missing']


def test_every_stored_table_output_of_the_chain_is_recognized_by_the_parsers():
    for name, (profile, directory, _) in LAB.items():
        for key, query in tables.BINDINGS[profile].items():
            file = directory / (query + '.txt')
            if query in QUERIES[profile] and file.exists() and not key.startswith('route'):
                result = tables.parse(profile, key.removesuffix('_v6'), query, file.read_text())
                assert not result['unparsed'] and result['status'] in ('ok', 'empty', 'permission_denied'), (name, key, result['status'])


def test_identity_is_read_from_the_real_show_version_output():
    from netops_helper.normalization import IdentityError, parse_identity
    nxos = parse_identity('cisco_nxos', (LAB['nxos'][1] / 'version.txt').read_text())
    assert (nxos['os_version'], nxos['model']) == ('9.3(12)', 'C9300v') and nxos['hostname']
    junos = parse_identity('juniper_junos_els', (LAB['vjunos'][1] / 'version.txt').read_text())
    assert junos['os_version'] == '26.2R1.7' and junos['model'] == 'ex9214' and junos['hostname']
    # IOL prints "Cisco IOS Software [IOSXE], ..." and no "Cisco IOS XE Software" line: still IOS XE, never plain IOS
    text = (REAL / 'cisco_xe/iolxe_17.18.2/version.txt').read_text()
    iol = parse_identity('cisco_xe', text)
    assert (iol['os_version'], iol['hostname']) == ('17.18.2', 'host07') and iol['serial_number']
    with pytest.raises(IdentityError):
        parse_identity('cisco_ios', text)
