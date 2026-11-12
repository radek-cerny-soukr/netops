"""locate_endpoint across all seven GNS3 lab nodes stays inside the 40-read budget.

Live finding 3 (2026-11-10): the IOSv SVI address located across IOSv, IOSvL2, cEOS, EXOS-VM, NX-OS,
vJunos and IOL XE ran out of reads (`budget/read_limit`). Here every node answers with its anonymised
read-only output from tests/fixtures/real, `show version` included: IOSv, IOSvL2 and cEOS from
lab_endpoints (the capture of 2026-11-09, one anonymiser mapping with NX-OS, vJunos and IOL XE), their
port VLAN reads from the full capture of the same node. EXOS-VM is the capture of 2026-11-08 with its
own mapping; its FDB holds the same anonymised MAC string on uplink port 1 (VLAN 10), where the live
EXOS-VM saw the router MAC too. Every enrolled switch is also declared a router and every locate query
is enabled, so each node is read as much as the inventory allows. The read order before this change
reproduces the live finding on these files: 40 reads, findings of IOSvL2, cEOS, EXOS-VM and NX-OS only.
"""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine, locate, tables
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

REAL = Path(__file__).parent / 'fixtures/real'
LAB = {
    'iosv': ('cisco_ios', (REAL / 'lab_endpoints/iosv',), ('router',)),
    'iosvl2': ('cisco_ios', (REAL / 'lab_endpoints/iosvl2', REAL / 'cisco_ios/iosvl2_15.2.20200924'), ('switch', 'router')),
    'ceos': ('arista_eos', (REAL / 'lab_endpoints/ceos', REAL / 'arista_eos/ceos_4.36.1F'), ('switch', 'router')),
    'exos': ('extreme_exos', (REAL / 'exos/exosvm_33.6.1.14', REAL / 'extreme_exos/exosvm_33.6.1.14_pty'), ('switch', 'router')),
    'nxos': ('cisco_nxos', (REAL / 'cisco_nxos/nexus9300v_9.3.12',), ('switch', 'router')),
    'vjunos': ('juniper_junos_els', (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7',), ('switch', 'router')),
    'iolxe': ('cisco_xe', (REAL / 'cisco_xe/iolxe_17.18.2',), ('router',)),
}
QUERIES = {
    'cisco_ios': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk'),
    'cisco_xe': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk'),
    'arista_eos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans', 'interfaces_trunk'),
    'extreme_exos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'ports', 'vlan_summary', 'lacp', 'vlan_detail'),
    'cisco_nxos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk'),
    'juniper_junos_els': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans',
                          'ethernet_switching_interfaces'),
}
SEVEN = tuple(LAB)


def lab_target(name):
    profile, _, types = LAB[name]
    return replace(_target(profile, 'mac_table'), alias=name, device_types=types, enabled_queries=QUERIES[profile])


def answers(profile, directories):
    """command -> stored output; the first directory that holds the query wins."""
    result = {}
    for directory in reversed(directories):
        for name, query in READ_QUERIES[profile].items():
            file = directory / (name + '.txt')
            if file.exists() and not query.slots:
                result[query.command] = file.read_text()
    return result


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)

    def install(*names):
        by_alias = {name: answers(LAB[name][0], LAB[name][1]) for name in names}
        calls = []

        def read(auth, profile, command):
            calls.append((auth.alias, command))
            return 0, by_alias[auth.alias][command]
        monkeypatch.setattr(engine, 'read_from_device', read)
        return [lab_target(name) for name in names], calls
    return install


def stored(name, table, query):
    profile, directories, _ = LAB[name]
    return tables.parse(profile, table, query, (directories[0] / (query + '.txt')).read_text())['records']


def router_svi():
    """The IOSv VLAN 10 sub-interface: the MAC IOSvL2 learns on Gi0/1 towards the router, and its address."""
    (mac,) = {r['mac'] for r in stored('iosvl2', 'mac_entry', 'mac_table') if r['port'] == 'GigabitEthernet0/1' and r['vlan_id'] == 10}
    (ip,) = {r['ip'] for r in stored('iosv', 'neighbor_l3', 'arp_table')
             if r['mac'] == mac and r['interface'] == 'GigabitEthernet0/1.10'}
    return ip, mac


def static_host(alias):
    (row,) = [r for r in stored(alias, 'mac_entry', 'mac_table') if r['type'] == 'static']
    (ip,) = [r['ip'] for r in stored('iosv', 'neighbor_l3', 'arp_table') if r['mac'] == row['mac']]
    return ip, row['mac'], row['port']


def roles(result):
    return {f['vantage']: (f['port'], f['role']) for f in result['findings']}


def by_alias(calls):
    result = {}
    for alias, command in calls:
        result.setdefault(alias, []).append(command)
    return result


def test_the_router_address_across_all_seven_nodes_ends_on_the_facts_not_on_the_budget(lab):
    ip, mac = router_svi()
    auths, calls = lab(*SEVEN)
    r = engine._locate_endpoint_run(auths, ip)
    assert not any(m['table'] == 'budget' for m in r['missing']), r['missing']
    assert r['verdict'] == 'own_interface_of_target'
    assert r['own_interfaces'] == [{'target': 'iosv', 'interface': 'GigabitEthernet0/1.10',
                                     'ip': ip, 'mac': mac, 'source': 'neighbor_l3'}]
    assert roles(r) == {'iosvl2': ('GigabitEthernet0/1', 'transit'), 'ceos': ('Ethernet1', 'transit'),
                        'exos': ('1', 'transit'), 'nxos': ('Ethernet1/1', 'transit'), 'vjunos': ('ge-0/0/0.0', 'transit')}
    assert r['missing'] == []
    assert {o['vantage'] for o in r['neighbors_l3']} == set(SEVEN) - {'exos'}       # EXOS-VM has an empty ARP cache
    assert all(o['mac'] == mac for o in r['neighbors_l3'])
    # 7 identities + 7 ARP + 5 MAC tables + 5 LLDP; only the NX-OS uplink has no LLDP neighbour
    # (interfaces + trunk membership tell it), and Junos names VLAN D10 (VLAN table).
    assert r['reads'] == len(calls) == 28
    seen = by_alias(calls)
    assert seen['nxos'].count('show ip arp') == 1
    assert [c for c in seen['nxos'] if c != 'show ip arp'] == [
        'show version', 'show mac address-table', 'show lldp neighbors detail',
        'show interface status', 'show interface trunk', 'show interface status']
    assert len(seen['iosv']) == len(seen['iolxe']) == 2                                # identity and ARP only


def test_the_router_mac_is_owned_by_the_enrolled_router_within_the_same_budget(lab):
    _, mac = router_svi()
    auths, calls = lab(*SEVEN)
    r = engine._locate_endpoint_run(auths, mac)
    assert r['verdict'] == 'own_interface_of_target' and len(r['findings']) == 5
    assert r['missing'] == []
    assert {(o['target'], o['interface']) for o in r['own_interfaces']} == {
        ('iosv', 'GigabitEthernet0/1.10'), ('iosv', 'GigabitEthernet0/1.20')}
    assert all(o['mac'] == mac for o in r['own_interfaces'])
    assert {o['vantage'] for o in r['neighbors_l3']} == set(SEVEN) - {'exos'}
    # The fallback reuses already verified switch identities and reads no other tables.
    assert r['reads'] == len(calls) == 28 < locate.MAX_READS
    assert by_alias(calls)['iosv'] == ['show version', 'show ip arp']


@pytest.mark.parametrize('alias,reads', [('nxos', 28), ('vjunos', 25)])
def test_a_host_is_located_across_all_seven_nodes(lab, alias, reads):
    ip, mac, port = static_host(alias)
    auths, calls = lab(*SEVEN)
    r = engine._locate_endpoint_run(auths, ip)
    assert r['verdict'] == 'located', r['missing']
    assert r['missing'] == []
    edge = next(f for f in r['findings'] if f['edge'])
    assert (edge['vantage'], edge['port'], edge['mac'], edge['vlan_id']) == (alias, port, mac, 10)
    assert r['reads'] == len(calls) == reads < locate.MAX_READS
    # A switch without the MAC is a branch away from the host: identity, ARP and its MAC table only.
    exos_reads = by_alias(calls)['exos']
    assert exos_reads[0] == 'show version'
    # Another cache may resolve the IP before this switch's own ARP reader starts.
    assert sorted(exos_reads[1:]) == ['show fdb', 'show iparp']

