"""locate_endpoint replayed over the read-only outputs of the 1.0.7 acceptance (2026-11-10).

GNS3 (finding N2): the VLAN 10 interface addresses of cEOS, EXOS-VM, NX-OS and vJunos (and the vJunos MAC)
ended as `edge_beyond_enrolled_targets` or `mac_not_observed`, because only IOS lists its own addresses in ARP.
The seven nodes answer with their anonymised CLI output of that day (`lab_endpoints_20261110`, one mapping:
the VLAN 10 subnet became 192.0.2.0/24 with the host octets kept); identity comes from the earlier captures of
the same images. Every switch is also a router and every locate query plus the interface address query is enabled.

IT case (finding N3): FortiGate 80F with two FortiSwitches ran into the 60 s worker deadline (AP address:
12 reads, FortiSwitch MAC: 11 reads) and called the FortiAP port (LLDP `B,W,R,S`) transit. The FortiSwitch
MAC/LLDP/port/VLAN captures of the same FortiGate are byte-for-byte the structure of the acceptance day; the ARP
cache is the acceptance capture (AP 203.0.113.250 with MAC ...:02; the second switch ...:08).

Time model, from `captured_at` of the acceptance evidence: every FortiOS read costs 5 s (connection spacing
and SSH exec) after 4.5 s worker start; a GNS3 node costs its median identity and read time.
"""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netops_helper import engine, locate, tables
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target, FORTIOS_STATUS

REAL = Path(__file__).parent / 'fixtures/real'
DAY = REAL / 'lab_endpoints_20261110'
# alias: profile, device types, identity capture, (identity, read) seconds
LAB = {
    'iosv': ('cisco_ios', ('router',), 'lab_endpoints/iosv', (0.9, 0.9)),
    'iosvl2': ('cisco_ios', ('switch', 'router'), 'lab_endpoints/iosvl2', (0.6, 0.5)),
    'ceos': ('arista_eos', ('switch', 'router'), 'lab_endpoints/ceos', (2.1, 2.0)),
    'exos': ('extreme_exos', ('switch', 'router'), 'exos/exosvm_33.6.1.14', (0.4, 0.4)),
    'nxos': ('cisco_nxos', ('switch', 'router'), 'cisco_nxos/nexus9300v_9.3.12', (3.0, 0.9)),
    'vjunos': ('juniper_junos_els', ('switch', 'router'), 'juniper_junos_els/vjunosswitch_26.2R1.7', (12.0, 2.1)),
    'iolxe': ('cisco_xe', ('router',), 'cisco_xe/iolxe_17.18.2', (0.6, 0.6)),
}
QUERIES = {
    'cisco_ios': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk',
                  'ip_interfaces'),
    'cisco_xe': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk',
                 'ip_interfaces'),
    'arista_eos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans', 'interfaces_trunk',
                   'ip_interfaces'),
    'extreme_exos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'ports', 'vlan_summary', 'lacp',
                     'vlan_detail', 'ipconfig'),
    'cisco_nxos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans', 'interfaces_trunk',
                   'ip_interfaces'),
    'juniper_junos_els': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans',
                          'ethernet_switching_interfaces'),
}
SEVEN = tuple(LAB)
FORTI = REAL / 'fortinet/fortigate80f_8.0.2_build0251'
SERIALS = ('S000SSSS00000001', 'S000SSSS00000002')
AP_IP, AP_MAC, SWITCH2_MAC = '203.0.113.250', '00:00:5e:00:53:02', '00:00:5e:00:53:08'


from support.virtual_clock import Clock, install


def lab_outputs(name):
    """command -> (rc, output) of one node on 2026-11-10, plus its identity."""
    profile, _, identity, _ = LAB[name]
    index = json.loads((DAY / name / 'index.json').read_text())
    result = {READ_QUERIES[profile]['version'].command: (0, (REAL / identity / 'version.txt').read_text())}
    for query, meta in index.items():
        assert READ_QUERIES[profile][query].command == meta['command']
        result[meta['command']] = (meta['rc'], (DAY / name / (query + '.txt')).read_text())
    return result


@pytest.fixture(params=[0.0, 10_000_000.0])
def lab(monkeypatch, request):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    clock = Clock(request.param)
    install(monkeypatch, clock)
    outputs = {name: lab_outputs(name) for name in SEVEN}
    calls, unknown = [], []

    def read(auth, profile, command):
        identity, seconds = LAB[auth.alias][3]
        first = not any(alias == auth.alias for alias, _ in calls)
        calls.append((auth.alias, command))
        clock.value += identity if first else seconds
        if command not in outputs[auth.alias]:
            unknown.append((auth.alias, command))
        return outputs[auth.alias][command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    targets = [replace(_target(LAB[name][0], 'mac_table'), alias=name, device_types=LAB[name][1],
                       enabled_queries=QUERIES[LAB[name][0]]) for name in SEVEN]
    yield targets, calls, clock
    assert not unknown


def by_alias(calls):
    result = {}
    for alias, command in calls:
        result.setdefault(alias, []).append(command)
    return result


def address_reads(calls):
    commands = {'show ip interface brief', 'show ipconfig', 'show interfaces terse | no-more'}
    return [alias for alias, command in calls if command in commands]


@pytest.mark.parametrize('alias,ip,interface,others', [
    ('ceos', '192.0.2.3', 'Vlan10', ['ceos', 'exos']),
    ('exos', '192.0.2.4', 'D10', ['ceos', 'exos', 'nxos', 'vjunos']),
    ('nxos', '192.0.2.5', 'Vlan10', ['exos', 'nxos']),
    ('vjunos', '192.0.2.6', 'irb.10', ['exos', 'vjunos']),
])
def test_an_svi_address_of_any_enrolled_profile_is_its_own_interface(lab, alias, ip, interface, others):
    targets, calls, clock = lab
    r = engine._locate_endpoint_run(targets, ip)
    assert r['verdict'] == 'own_interface_of_target', r['missing']
    assert [(o['target'], o['interface'], o['ip'], o['source']) for o in r['own_interfaces']] == [
        (alias, interface, ip, 'ip_interface')]
    assert not any(m['reason'] in ('edge_beyond_enrolled_targets', 'read_limit', 'timeout') for m in r['missing'])
    # Interface addresses are read last and only where no complete ARP cache rules the owner out:
    # IOS lists its own addresses, any other cache that holds the IP learned it from the wire.
    assert sorted(address_reads(calls)) == sorted(others)
    assert r['reads'] == len(calls) < locate.MAX_READS
    assert clock.value - clock.start < locate.MAX_SECONDS


def test_the_vjunos_mac_is_its_own_interface_through_the_arp_caches(lab):
    targets, calls, clock = lab
    (mac,) = {row['mac'] for row in tables.parse('cisco_ios', 'neighbor_l3', 'arp_table',
                                                  (DAY / 'iosv/arp_table.txt').read_text())['records'] if row['ip'] == '192.0.2.6'}
    r = engine._locate_endpoint_run(targets, mac)
    assert r['verdict'] == 'own_interface_of_target', r['missing']
    assert {(o['target'], o['interface'], o['ip'], o['mac'], o['source']) for o in r['own_interfaces']} == {
        ('vjunos', 'irb.10', '192.0.2.6', mac, 'ip_interface'), ('vjunos', 'irb.20', '198.51.100.6', mac, 'ip_interface')}
    assert all(f['role'] == 'transit' for f in r['findings'])
    assert not any(m['reason'] == 'edge_beyond_enrolled_targets' for m in r['missing'])
    assert address_reads(calls) == ['vjunos']             # EXOS-VM holds the MAC in ARP for VLAN 20
    assert r['reads'] == len(calls) < locate.MAX_READS and clock.value - clock.start < locate.MAX_SECONDS


@pytest.mark.parametrize('alias,ip,interface', [('iosv', '192.0.2.1', 'GigabitEthernet0/1.10'),
                                                ('iosvl2', '192.0.2.2', 'Vlan10'),
                                                ('iolxe', '192.0.2.7', 'Ethernet0/1.10')])
def test_ios_ownership_still_comes_from_arp_without_address_reads(lab, alias, ip, interface):
    targets, calls, clock = lab
    r = engine._locate_endpoint_run(targets, ip)
    assert r['verdict'] == 'own_interface_of_target'
    assert [(o['target'], o['interface'], o['source']) for o in r['own_interfaces']] == [(alias, interface, 'neighbor_l3')]
    assert address_reads(calls) == []
    assert clock.value - clock.start < locate.MAX_SECONDS


def test_an_unknown_address_stays_incomplete_after_the_owner_check(lab):
    targets, calls, _ = lab
    r = engine._locate_endpoint_run(targets, '192.0.2.250')
    assert r['verdict'] == 'incomplete' and r['own_interfaces'] == []
    assert {'vantage': None, 'table': 'neighbor_l3', 'reason': 'mac_not_observed'} in r['missing']
    assert sorted(address_reads(calls)) == ['ceos', 'exos', 'nxos', 'vjunos']


def test_an_unknown_mac_reads_no_interface_addresses(lab):
    targets, calls, _ = lab
    r = engine._locate_endpoint_run(targets, '00:00:5e:00:53:ff')
    assert r['verdict'] == 'not_found_in_checked_data'
    # Identity and MAC table of the five switches; without a finding no ARP cache and no address table is read.
    assert address_reads(calls) == [] and r['reads'] == len(calls) == 10


# --- IT case: FortiGate with two FortiSwitches ------------------------------------------------------------

def forti_outputs():
    blocks = (FORTI / 'managed_switch_mac_all.txt').read_text().split('Managed Switch :')
    captures = FORTI / 'captures_20261110'
    commands = READ_QUERIES['fortinet']
    result = {'get system status': FORTIOS_STATUS,
              commands['arp_table'].command: (captures / 'arp_table.txt').read_text(),
              commands['managed_switch_port_vlans'].command.format(managed_switch=SERIALS[0]):
                  (captures / 'managed_ports_config.txt').read_text(),
              commands['interface_vlan_ids'].command: (captures / 'vlan_config.txt').read_text(),
              commands['managed_switch_port_stats'].command.format(managed_switch=SERIALS[0], port='').rstrip():
                  (captures / 'port_stats_1.txt').read_text()}
    for number, serial in enumerate(SERIALS, 1):
        result[commands['managed_switch_mac'].command.format(managed_switch=serial)] = 'Managed Switch :' + blocks[number]
        result[commands['managed_switch_lldp'].command.format(managed_switch=serial)] = (
            FORTI / f'managed_switch_lldp_{number}.txt').read_text()
    return result


@pytest.fixture(params=[0.0, 10_000_000.0])
def kufr(monkeypatch, request):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    clock = Clock(request.param)
    install(monkeypatch, clock)
    outputs = forti_outputs()
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        clock.value += 5.0
        return 0, outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    gate = replace(_target('fortinet', 'arp_table'), alias='gateway', device_types=('firewall',),
                   enabled_queries=('arp_table', 'ipv6_neighbors', 'system_interfaces', 'managed_switch_mac', 'managed_switch_lldp',
                                    'managed_switch_port_stats', 'managed_switch_port_vlans', 'interface_vlan_ids'),
                   read_inventory={'managed_switches': SERIALS})
    return gate, calls, clock


def seconds(clock):
    """What a client measures: worker start plus the reads."""
    return 4.5 + clock.value - clock.start


def test_the_fortiap_is_located_behind_its_port_in_eight_reads(kufr):
    gate, calls, clock = kufr
    r = engine._locate_endpoint_run([gate], AP_IP)
    assert r['verdict'] == 'located', r['missing']
    assert r['missing'] == [] and r['own_interfaces'] == []
    (edge,) = [f for f in r['findings'] if f['edge']]
    assert (edge['vantage'], edge['port'], edge['vlan_id'], edge['role'], edge['behind']) == (
        'gateway/' + SERIALS[0], 'port3', 100, 'edge_behind_ap', 'ap')
    assert edge['lldp_neighbors'][0]['capabilities'] == 'B,W,R,S'
    assert edge['vlan_membership'] == {'carries_vlan': True, 'tagging': 'untagged', 'source': 'configuration'}
    assert (edge['interface']['oper_status'], edge['interface']['speed']) == ('up', '1000M')
    # The second switch sees the AP over the inter-switch trunk only: transit, no further read there.
    assert [(f['vantage'], f['role']) for f in r['findings'] if not f['edge']] == [('gateway/' + SERIALS[1], 'transit')]
    assert sorted(calls) == sorted(['get system status', 'get system arp',
                     'diagnose switch-controller switch-info mac-table ' + SERIALS[0],
                     'diagnose switch-controller switch-info mac-table ' + SERIALS[1],
                     'diagnose switch-controller switch-info lldp neighbors-summary ' + SERIALS[0],
                     'diagnose switch-controller switch-info port-stats ' + SERIALS[0],
                     'show switch-controller managed-switch ' + SERIALS[0], 'show system interface'])
    # 5 s per FortiOS read leaves little room: one more read would pass the 45 s target.
    assert r['reads'] == 8 and seconds(clock) == 44.5 < 45


def test_the_managed_switch_mac_is_its_own_interface_in_three_reads(kufr):
    gate, calls, clock = kufr
    r = engine._locate_endpoint_run([gate], SWITCH2_MAC)
    assert r['verdict'] == 'own_interface_of_target', r['missing']
    assert r['own_interfaces'] == [{'target': 'gateway/' + SERIALS[1], 'interface': 'internal', 'ip': None,
                                    'mac': SWITCH2_MAC, 'source': 'mac_entry'}]
    assert [(f['vantage'], f['port'], f['role']) for f in r['findings']] == [
        ('gateway/' + SERIALS[0], 'host01', 'transit'), ('gateway/' + SERIALS[0], 'host01', 'transit')]
    assert r['missing'] == []
    assert r['reads'] == len(calls) == 3 and seconds(clock) == 19.5 < 45


def test_the_fortiap_mac_without_arp_is_located_too(kufr):
    gate, calls, clock = kufr
    r = engine._locate_endpoint_run([gate], AP_MAC)
    assert r['verdict'] == 'located' and r['missing'] == []
    assert r['reads'] == 7 and seconds(clock) == 39.5


@pytest.mark.parametrize('name,capabilities,kind', [
    ('host04', 'BRWS', 'ap'),                 # the real FortiAP row
    ('FortiAP-231K', 'BR', 'ap'),             # the real row with its name and without W
    ('FAP-221E', None, 'ap'),
    ('host04', 'BRW', 'switch'),              # a WLAN router or bridge that is no station stays a switch
    ('fapello', 'BR', 'switch'),
])
def test_fortiap_lldp_neighbour_is_an_ap_not_a_switch(name, capabilities, kind):
    text = (FORTI / 'managed_switch_lldp_1.txt').read_text()
    text = text.replace('host04                      120   BRWS',
                        f'{name:<27} 120   {capabilities or "-":<4}')
    rows = tables.parse('fortinet', 'lldp_neighbor', 'managed_switch_lldp', text)['records']
    (row,) = [row for row in rows if row['local_port'] == 'port3']
    assert row['neighbor'] == name
    assert locate.peer_kind(row, {'gateway'}) == kind
