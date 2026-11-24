"""EOS-PORTS EOS port, STP, QoS, IGMP and normalization reads replay real anonymized cEOS 4.36.1F captures.

Only the SSH transport is replaced. Derived (cut) captures are marked DERIVED and come from
real output at an existing boundary; nothing here is written from guessed EOS syntax.
"""
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
import test_proxy_contracts as contracts
from netops_helper import engine, tables
from netops_helper.auth import TargetAuth
from netops_helper.query_catalog.arista import QUERIES
from netops_helper.read_policy import render_read_query

REAL = Path(__file__).parent / 'fixtures/real/arista_eos/eos_ports_ceos_4.36.1F'
INDEX = json.loads((REAL / 'index.json').read_text())
INVENTORY = {'interfaces': ('Ethernet2', 'Ethernet14', 'Port-Channel104', 'Port-Channel128')}
EOS_PORTS = ('interfaces_counters_rates', 'interface_counters_rates', 'mac_table_interface', 'mac_table_vlan',
        'mac_table_address', 'poe', 'stp_detail', 'stp_interface_detail', 'stp_counters', 'interface_qos',
        'interface_queue_counters', 'igmp_snooping', 'igmp_snooping_groups', 'igmp_snooping_mrouter',
        'igmp_snooping_counters')


def text(key):
    return (REAL / INDEX[key]['file']).read_text()


def transport(monkeypatch, keys, role='ro', enabled=None, overrides=None):
    """Answer each catalogue command with the real capture of the given fixture keys."""
    outputs = {}
    for key in keys:
        entry = INDEX[key + '_' + role]
        outputs[entry['command']] = (entry['rc'], text(key + '_' + role))
    outputs.update(overrides or {})
    pair = any(key.startswith('pair_') for key in keys)
    version = text(('pair_version_' if pair else 'version_') + role)
    auth = replace(_target('arista_eos', 'version'), enabled_queries=tuple(enabled or QUERIES),
                   read_inventory=INVENTORY)
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        if command == 'show version':
            return 0, version
        return outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    return auth, calls


def public_read(tmp_path, auth, tool, **arguments):
    proxy = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(proxy, tmp_path)
    section = dict(contracts._section(), ssh_platform='arista_eos', device_types=['switch'],
                   enabled_queries=list(auth.enabled_queries), read_inventory=INVENTORY)
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'arista_eos')))
    gateway = proxy.Proxy()
    errors = []
    gateway._emit = errors.append
    forwarded = gateway.request(contracts._request(1, tool, {'target': 'device-a', **arguments}))
    assert forwarded is not None, errors
    forwarded_args = json.loads(forwarded)['params']['arguments']
    worker_auth = TargetAuth.decode(forwarded_args.pop('target'), forwarded_args.pop('auth_context'))
    return getattr(engine, tool)(worker_auth, **forwarded_args)


def test_every_eos_ports_query_has_ro_and_admin_capture():
    queries = {entry['query'] for entry in INDEX.values()}
    assert set(EOS_PORTS) <= queries
    for name in EOS_PORTS:
        assert name + '_ro' in INDEX and name + '_admin' in INDEX


@pytest.mark.parametrize('key', [key for key in INDEX if INDEX[key]['query'] in EOS_PORTS])
def test_real_capture_via_public_ssh_read(key, monkeypatch):
    entry = INDEX[key]
    auth, calls = transport(monkeypatch, [key.rsplit('_', 1)[0]], role=key.rsplit('_', 1)[1])
    result = engine.ssh_read(auth, 'arista_eos', entry['query'], entry['parameters'], 0, 48000)
    assert entry['command'] in calls
    assert result['rc'] == entry['rc']
    assert result.get('untrusted_device_output', '').strip() == text(key).strip()
    if entry['rc'] != 0:
        assert result['normalized']['status'] not in ('ok', 'empty')


def test_rates_are_device_load_interval_averages(monkeypatch):
    auth, calls = transport(monkeypatch, ['interfaces_counters_rates'])
    result = engine.switch_read(auth, 'port_rates', limit=500)
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    rows = {row['port']: row for row in result['records']}
    assert {'Ethernet2', 'Ethernet14', 'Port-channel104', 'Management0'} <= set(rows)
    assert all(row['interval'] == 300 and isinstance(row['tx_pps'], int) for row in rows.values())
    assert calls[-1] == 'show interfaces counters rates'


def test_documented_mbps_and_kpps_rates_keep_the_same_result_units(monkeypatch):
    fixture = REAL.parents[2] / 'docs/arista_eos/port_rates_mbps.out'
    auth, _ = transport(monkeypatch, [], overrides={'show interfaces counters rates': (0, fixture.read_text())})
    result = engine.switch_read(auth, 'port_rates', limit=500)
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    row, = result['records']
    assert (row['port'], row['interval']) == ('Ethernet1', 5)
    assert (row['rx_kbps'], row['rx_pps'], row['tx_kbps'], row['tx_pps']) == (53300, 5000, 31200, 2000)


def test_rates_wrapped_by_terminal_width_are_joined(monkeypatch):
    auth, _ = transport(monkeypatch, ['pair_interfaces_counters_rates'])
    result = engine.switch_read(auth, 'port_rates', limit=500)
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert all(isinstance(row['tx_pps'], int) for row in result['records'])
    assert {row['port'] for row in result['records']} >= {'Port-channel128', 'Port-channel200'}


def test_rates_cut_before_wrapped_column_is_not_complete():
    # DERIVED: the real wrapped capture cut before its "Port  Out Pps" continuation table.
    cut = text('pair_interfaces_counters_rates_ro').split('Port       Out Pps')[0]
    result = tables.parse('arista_eos', 'port_rates', 'interfaces_counters_rates', cut)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_one_interface_rates_use_the_switch_selector(monkeypatch):
    auth, calls = transport(monkeypatch, ['interface_counters_rates'])
    result = engine.switch_read(auth, 'port_rates', interface='Ethernet2')
    assert calls[-1] == 'show interfaces Ethernet2 counters rates'
    assert [row['port'] for row in result['records']] == ['Ethernet2'] and result['coverage']['complete']


@pytest.mark.parametrize('arguments,key,command,count', [
    ({'interface': 'Ethernet2'}, 'mac_table_interface', 'show mac address-table interface Ethernet2', 2),
    ({'interface': 'Ethernet14'}, 'mac_table_interface_et14', 'show mac address-table interface Ethernet14', 0),
    ({'interface': 'Port-Channel104'}, 'mac_table_interface_po104', 'show mac address-table interface Port-Channel104', 1),
    ({'vlan_id': '10'}, 'mac_table_vlan', 'show mac address-table vlan 10', 5),
    ({'vlan_id': '4000'}, 'mac_table_vlan_v4000', 'show mac address-table vlan 4000', 0),
])
def test_mac_filters_run_on_the_switch(monkeypatch, arguments, key, command, count):
    auth, calls = transport(monkeypatch, [key])
    result = engine.switch_read(auth, 'mac_entry', **arguments)
    assert calls[-1] == command and 'show mac address-table' not in calls
    assert len(result['records']) == count and result['status'] == ('ok' if count else 'empty'), result
    assert result['coverage']['complete']


def test_mac_address_lookup_on_the_switch(monkeypatch):
    entry = INDEX['mac_table_address_ro']
    auth, calls = transport(monkeypatch, ['mac_table_address'])
    result = engine.switch_read(auth, 'mac_entry', mac=entry['parameters']['mac'])
    assert calls[-1] == entry['command']
    assert result['status'] == 'ok' and len(result['records']) == 2
    assert {row['vlan_id'] for row in result['records']} == {10, 20}
    assert all(row['mac'] == entry['parameters']['mac'] and row['port'] == 'Ethernet2' for row in result['records'])
    # An interface and a VLAN together keep the interface on the switch and the VLAN as a local filter.
    auth, calls = transport(monkeypatch, ['mac_table_interface'])
    both = engine.switch_read(auth, 'mac_entry', interface='Ethernet2', vlan_id='20')
    assert calls[-1] == 'show mac address-table interface Ethernet2'
    assert [row['vlan_id'] for row in both['records']] == [20]


@pytest.mark.parametrize('arguments', [{'interface': 'Ethernet3'}, {'interface': 'Ethernet2; reload'},
                                       {'mac': 'not-a-mac'}, {'vlan_id': '5000'}])
def test_mac_selectors_are_typed_and_enrolled_before_transport(monkeypatch, arguments):
    auth, calls = transport(monkeypatch, ['mac_table_interface'])
    with pytest.raises(ValueError):
        engine.switch_read(auth, 'mac_entry', **arguments)
    assert calls == []


def test_stp_topology_changes_and_root(monkeypatch):
    auth, _ = transport(monkeypatch, ['stp_detail'])
    result = engine.switch_read(auth, 'stp_topology')
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    row = result['records'][0]
    assert row['instance'] == 'MST0' and row['root_bridge'] is True and row['root_port'] is None
    assert row['topology_changes'] >= 1 and row['last_change_from'] == 'Ethernet4'
    auth, _ = transport(monkeypatch, ['pair_stp_detail'])
    pair = engine.switch_read(auth, 'stp_topology')['records'][0]
    assert pair['root_bridge'] is False and pair['root_port'] == 'Port-channel128'
    assert pair['last_change_from'] == 'Port-channel128'


def test_stp_port_counters_and_boundary(monkeypatch):
    auth, _ = transport(monkeypatch, ['pair_stp_detail'])
    result = engine.switch_read(auth, 'stp_port_counters')
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    rows = {row['port']: row for row in result['records']}
    assert rows['Port-channel128']['role'] == 'root' and rows['Port-channel128']['boundary'] is True
    assert rows['Port-channel128']['bpdu_received'] > 0
    assert 'PeerEthernet5' in rows and all(row['state'] == 'forwarding' for row in rows.values())


def test_stp_one_port_detail_and_cut_block(monkeypatch):
    auth, calls = transport(monkeypatch, ['stp_interface_detail'])
    result = engine.switch_read(auth, 'stp_port_counters', interface='Ethernet2')
    assert calls[-1] == 'show spanning-tree interface Ethernet2 detail'
    row = result['records'][0]
    assert row['port'] == 'Ethernet2' and row['bpdu_tagged_errors'] == 0 and row['forward_transitions'] == 1
    # DERIVED: the real block cut before its BPDU counters must not look complete.
    cut = text('stp_interface_detail_ro').split('   BPDU:')[0]
    partial = tables.parse('arista_eos', 'stp_port_counters', 'stp_interface_detail', cut)
    assert not partial['coverage']['complete'] and 'bpdu_sent' in partial['coverage']['missing_fields']


def test_stp_detail_pager_is_truncated(monkeypatch):
    # DERIVED: real output cut at a port block with the CLI pager marker appended.
    body = text('stp_detail_ro').split(' Port 3 ')[0] + '--More--'
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    auth, _ = transport(monkeypatch, ['stp_detail'])
    monkeypatch.setattr(engine, 'read_from_device',
                        lambda a, p, c: (0, text('version_ro')) if c == 'show version' else (0, body))
    result = engine.switch_read(auth, 'stp_topology')
    assert result['status'] == 'truncated' and not result['ok']


def test_igmp_groups_and_router_ports(monkeypatch):
    auth, _ = transport(monkeypatch, ['igmp_snooping_groups'])
    groups = engine.switch_read(auth, 'igmp_group')
    assert groups['status'] == 'ok' and groups['coverage']['complete'], groups
    assert {(row['vlan_id'], row['group']) for row in groups['records']} == {(10, '*'), (20, '*')}
    assert all(row['members'] == ['Et2'] for row in groups['records'])
    only = engine.switch_read(auth, 'igmp_group', vlan_id='20')
    assert [row['vlan_id'] for row in only['records']] == [20]
    auth, _ = transport(monkeypatch, ['igmp_snooping_mrouter'])
    mrouter = engine.switch_read(auth, 'igmp_mrouter')
    assert mrouter['coverage']['complete'] and {(r['vlan_id'], r['port'], r['learned']) for r in mrouter['records']} == {
        (10, 'Ethernet2', 'dynamic'), (20, 'Ethernet2', 'dynamic')}


def test_igmp_without_groups_is_empty_not_unparsed(monkeypatch):
    auth, _ = transport(monkeypatch, ['pair_igmp_snooping_groups'])
    result = engine.switch_read(auth, 'igmp_group')
    assert result['status'] == 'empty' and result['coverage']['complete'] and result['records'] == []


def test_poe_absence_is_a_refusal_not_an_empty_table(monkeypatch):
    for role in ('ro', 'admin'):
        auth, _ = transport(monkeypatch, ['poe'], role=role)
        result = engine.ssh_read(auth, 'arista_eos', 'poe', {}, 0, 16000)
        # The transport succeeded; the normalized state never claims an (empty) PoE table.
        assert result['rc'] == 1 and result['normalized']['status'] not in ('ok', 'empty')


def test_queue_counters_empty_answer_is_a_declared_empty_output(monkeypatch):
    auth, _ = transport(monkeypatch, ['interface_queue_counters'])
    result = engine.ssh_read(auth, 'arista_eos', 'interface_queue_counters', {'interface': 'Ethernet2'}, 0, 16000)
    assert result['rc'] == 0 and result['ok'] and result['untrusted_device_output'].strip() == ''
    assert QUERIES['interface_queue_counters'].empty_allowed


def test_qos_shows_transmit_queues(monkeypatch):
    auth, _ = transport(monkeypatch, ['interface_qos'])
    result = engine.ssh_read(auth, 'arista_eos', 'interface_qos', {'interface': 'Ethernet2'}, 0, 16000)
    assert result['ok'] and 'UC7' in result['untrusted_device_output'] and 'Trust Mode' in result['untrusted_device_output']


@pytest.mark.parametrize('table,arguments', [('port_rates', {'vlan_id': '10'}), ('stp_topology', {'interface': 'Ethernet2'}),
                                             ('igmp_group', {'interface': 'Ethernet2'}), ('port_rates', {'interface': 'Ethernet3'})])
def test_table_selectors_are_checked_before_transport(monkeypatch, table, arguments):
    auth, calls = transport(monkeypatch, ['interfaces_counters_rates'])
    with pytest.raises(ValueError):
        engine.switch_read(auth, table, **arguments)
    assert calls == []


def test_error_and_discard_deltas_from_two_real_timed_reads(monkeypatch):
    auth, _ = transport(monkeypatch, ['interfaces_counters_errors', 'interfaces_counters_discards'])
    first = engine.switch_read(auth, 'interface_errors', limit=500)
    assert first['status'] == 'ok' and first['counter_baseline'], first
    auth, _ = transport(monkeypatch, ['interfaces_counters_errors_t2', 'interfaces_counters_discards_t2'])
    second = engine.switch_read(auth, 'interface_errors', limit=500, baseline=first['counter_baseline'], summary='changes')
    report = second['summary']['baseline']
    assert report['ports_compared'] >= 16 and report['missing_ports'] == []
    assert report['compared_ports_by_counter']['discards_in'] >= 16
    assert all(row['delta'] is not None for row in second['records'])


@pytest.mark.parametrize('table,query,key,status', [
    ('neighbor_l3', 'show ipv6 neighbors', 'ipv6_neighbors', 'empty'),
    ('bgp_peer', 'show ipv6 bgp summary', 'ipv6_bgp_summary', 'not_applicable'),
    ('ospf_neighbor', 'show ipv6 ospf neighbor', 'ospfv3_neighbors', 'empty'),
])
def test_ipv6_tables_select_eos_address_family(monkeypatch, table, query, key, status):
    auth, calls = transport(monkeypatch, [key])
    result = engine.switch_read(auth, table, address_family='ipv6')
    assert calls[-1] == query and result['status'] == status, result


TRIAGE_COMMON = ['interfaces', 'interfaces_trunk', 'interfaces_counters_errors', 'interfaces_counters_discards',
                 'mlag_interfaces', 'interfaces_errdisabled']
ETHERNET_TRIAGE = ['stp_interface_detail', 'mac_table_interface', 'lldp_neighbors_interface',
                   'lacp_peer_interface', 'interface_poe', 'interface_optics']
MEMBER_TRIAGE = [f'{key}_et14' for key in ETHERNET_TRIAGE]
CHANNEL_TRIAGE = ['stp_interface_detail_po104', 'mac_table_interface_po104']


def triage(monkeypatch, interface, keys, enabled=None):
    auth, calls = transport(monkeypatch, TRIAGE_COMMON + keys, enabled=enabled)
    return engine.triage_port(auth, interface), calls


def test_eos_port_triage_ethernet_without_optional_hardware(monkeypatch):
    result, calls = triage(monkeypatch, 'Ethernet2', ['stp_interface_detail', 'mac_table_interface',
                                                      'lldp_neighbors_interface', 'lacp_peer_interface',
                                                      'interface_poe', 'interface_optics'])
    assert result['verdict'] == 'no_fault_observed' and result['missing'] == [], result['missing']
    assert result['unavailable'] == ['interface_poe']
    assert result['evidence']['lacp_peer_interface']['status'] == 'not_applicable'
    assert result['evidence']['mlag_interfaces']['status'] == 'not_applicable'
    assert result['evidence']['interface_optics']['status'] == 'not_present'
    assert len(result['evidence']['mac_entry']['records']) == 2
    assert len(calls) <= 16 + 16  # every read is a catalogue command plus its identity check


def test_eos_port_triage_lacp_member(monkeypatch):
    result, _ = triage(monkeypatch, 'Ethernet14', ['stp_interface_detail_et14', 'mac_table_interface_et14',
                                                   'lldp_neighbors_interface_et14', 'lacp_peer_interface_et14',
                                                   'interface_poe_et14', 'interface_optics_et14'])
    assert result['verdict'] == 'no_fault_observed', result
    assert 'Bundled' in result['evidence']['lacp_peer_interface']['untrusted_device_output']
    assert result['evidence']['port_vlan']['status'] == 'not_applicable'
    assert result['evidence']['port_vlan']['member_of'] == 'Port-Channel104'


def test_eos_port_triage_port_channel_skips_member_reads(monkeypatch):
    # Found live: physical-port templates refuse a Port-Channel, so the triage must not call them.
    result, calls = triage(monkeypatch, 'Port-Channel104', ['stp_interface_detail_po104', 'mac_table_interface_po104'])
    assert result['verdict'] == 'no_fault_observed', result['missing']
    for query in ('lacp_peer_interface', 'lldp_neighbors_interface', 'interface_poe', 'interface_optics'):
        assert query not in result['evidence']
    assert not any(word in command for command in calls for word in ('lacp', 'lldp', 'poe', 'transceiver'))


def test_eos_port_triage_disabled_read_is_missing_evidence(monkeypatch):
    result, _ = triage(monkeypatch, 'Ethernet2', ['stp_interface_detail', 'mac_table_interface', 'lacp_peer_interface',
                                                  'interface_poe', 'interface_optics'],
                       enabled=[q for q in QUERIES if q != 'lldp_neighbors_interface'])
    # A disabled read is reported as missing evidence, never as a healthy port.
    assert result['verdict'] == 'incomplete' and result['missing'] == ['lldp_neighbors_interface']


def test_eos_port_triage_checks_selector_before_transport(monkeypatch):
    auth, calls = transport(monkeypatch, ['interfaces'])
    with pytest.raises(ValueError):
        engine.triage_port(auth, 'Ethernet3')
    with pytest.raises(ValueError):
        engine.triage_port(auth, 'Ethernet2', 'lab-stp')
    assert calls == []


@pytest.mark.parametrize('interface,keys', [('Ethernet2', ETHERNET_TRIAGE), ('Port-Channel104', CHANNEL_TRIAGE)])
def test_public_eos_port_triage(tmp_path, monkeypatch, interface, keys):
    auth, calls = transport(monkeypatch, TRIAGE_COMMON + keys)
    result = public_read(tmp_path, auth, 'triage_port', interface=interface)
    assert result['interface'] == interface and result['verdict'] == 'no_fault_observed'
    assert f'show spanning-tree interface {interface} detail' in calls


@pytest.mark.parametrize('filters', ['vlan', 'mac', 'both'])
def test_public_legacy_eos_mac_filters_use_full_table(tmp_path, monkeypatch, filters):
    mac = INDEX['mac_table_address_ro']['parameters']['mac']
    arguments = {'vlan_id': '10'} if filters != 'mac' else {}
    if filters != 'vlan':
        arguments['mac'] = mac
    auth, calls = transport(monkeypatch, ['mac_table'], enabled=['version', 'mac_table'])
    result = public_read(tmp_path, auth, 'switch_read', table='mac_entry', **arguments)
    assert result['coverage']['complete'] and len(result['records']) == {'vlan': 5, 'mac': 2, 'both': 1}[filters]
    assert calls[-1] == 'show mac address-table'
    for row in result['records']:
        assert ('vlan_id' not in arguments or row['vlan_id'] == 10) and ('mac' not in arguments or row['mac'] == mac)


def test_eos_lag_member_preserves_denied_vlan_evidence(monkeypatch):
    result, calls = triage(monkeypatch, 'Ethernet14', MEMBER_TRIAGE,
                           enabled=[query for query in QUERIES if query != 'interfaces_trunk'])
    assert result['evidence']['port_vlan']['status'] == 'permission_denied'
    assert result['missing'] == ['port_vlan'] and result['verdict'] == 'incomplete'
    assert 'show interfaces trunk' not in calls


def test_eos_triage_reports_only_selected_degraded_mlag(monkeypatch):
    from test_switch_mlag_eos_interfaces import _row, _table

    # DERIVED from the documented EOS MLAG capture using the same column layout.
    output = _table(_row('104', 'Selected', 'active-partial', 'Po104', 'Po104', 'up/down'),
                    _row('128', 'Other', 'inactive', 'Po128', 'Po128', 'down/down'))
    auth, _ = transport(monkeypatch, TRIAGE_COMMON + CHANNEL_TRIAGE,
                        overrides={'show mlag interfaces': (0, output)})
    result = engine.triage_port(auth, 'Port-Channel104')
    members = result['evidence']['mlag_interfaces']['mlag_members']['members']
    assert {member['local_port'] for member in members} == {'Po104', 'Po128'}
    assert result['verdict'] == 'findings'
    assert [(item['mlag_id'], item['state'], item['local_status'], item['remote_status'])
            for item in result['findings'] if item['source'] == 'mlag_interfaces'] == [(104, 'active-partial', 'up', 'down')]


def test_eos_stp_partial_last_port_reduces_coverage(monkeypatch):
    # DERIVED: omit just the last port's BPDU counters from the real multi-port capture.
    cut = '\n'.join(text('stp_detail_ro').splitlines()[:158])
    auth, _ = transport(monkeypatch, ['stp_detail'], overrides={'show spanning-tree detail': (0, cut)})
    result = engine.switch_read(auth, 'stp_port_counters')
    rows = {row['port']: row for row in result['records']}
    assert rows['Ethernet2']['bpdu_sent'] is not None
    assert rows['Port-channel104']['bpdu_sent'] is None
    assert not result['coverage']['complete'] and 'bpdu_sent' in result['coverage']['missing_fields']


@pytest.mark.parametrize('script', [
    'import netops_helper.ip_interfaces',
    '''
import sys
from pathlib import Path
from netops_helper import engine
from netops_helper.auth import TargetAuth

fixtures = Path(sys.argv[1])
captures = {'show version': 'version_ro.out', 'show mac address-table': 'mac_table_ro.out'}
calls = []

def read(auth, profile, command):
    calls.append(command)
    return 0, (fixtures / captures[command]).read_text()

engine.read_from_device = read
engine.record = lambda *args, **kwargs: None
auth = TargetAuth(alias='device-a', host='192.0.2.10', port=22, login='fixture', secret='fixture',
                  host_key_fingerprint='SHA256:' + 'A' * 43,
                  ssh_platform='arista_eos', enabled_queries=('version', 'mac_table'))
result = engine.switch_read(auth, 'mac_entry')
assert result['status'] == 'ok' and result['records'], result['status']
assert calls[-1] == 'show mac address-table'
''',
], ids=['ip_interfaces', 'engine_switch_read'])
def test_cold_import_eos_ports(script):
    subprocess.run([sys.executable, '-B', '-c', script, str(REAL)], check=True, timeout=15)


def test_new_templates_render_typed_parameters():
    assert render_read_query('arista_eos', 'mac_table_address', {'mac': '0000.5E00.53AB'}, INVENTORY)[1] == \
        'show mac address-table address 00:00:5e:00:53:ab'
    assert render_read_query('arista_eos', 'stp_interface_detail', {'interface': 'Port-Channel104'}, INVENTORY)[1] == \
        'show spanning-tree interface Port-Channel104 detail'
    with pytest.raises(ValueError):
        render_read_query('arista_eos', 'interface_qos', {'interface': 'Ethernet9'}, INVENTORY)
