"""G133 reads through the public engine over anonymized Junos CLI responses."""
from pathlib import Path

import pytest

from netops_helper import engine
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_helper.query_catalog.junos import ELS_QUERIES
from netops_helper.read_policy import render_read_query

FIXTURES = Path(__file__).parent / 'fixtures'
REAL = FIXTURES / 'real/juniper_junos_els/g133_vjunosswitch_26.2R1.7'
VENDOR = FIXTURES / 'docs/juniper_junos_els/g133'
IDENTITY = FIXTURES / 'real/juniper_junos_els/g132_vjunosswitch_26.2R1.7/version_ro.out'
PLATFORM = 'juniper_junos_els'
INTERFACE = {'interface': 'ge-0/0/0'}


def output(name, directory=REAL):
    return (directory / (name + '.out')).read_text()


def read(auth, query, parameters=None):
    return engine.ssh_read(auth, PLATFORM, query, parameters, 0, 16000)


def replay(monkeypatch, replies):
    auth = TargetAuth(alias='vjunos', host='192.0.2.10', port=2256, login='lab',
                      secret='fixture-password', ssh_platform=PLATFORM,
                      host_key_fingerprint='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                      enabled_queries=tuple(ELS_QUERIES),
                      read_inventory={'interfaces': ('ge-0/0/0', 'ge-0/1/0', 'ge-0/0/47', 'ge-1/0/0', 'ge-0/0/5'),
                                      'vlans': ('D20', 'default', 'g133-missing')},
                      egress=EgressPolicy(addresses=('192.0.2.10',)))
    calls = []

    def physical(target, profile, command, **kwargs):
        if command == 'show version | no-more':
            return 0, IDENTITY.read_text()
        calls.append(command)
        return 0, replies[command.removesuffix(' | no-more')]

    monkeypatch.setattr(engine, '_exec_read', physical)
    monkeypatch.setattr(engine, 'record', lambda *a, **kwargs: None)
    return auth, calls


@pytest.mark.parametrize('name,query,parameters,command,state', [
    ('mac_vlan', 'mac_table_vlan', {'vlan': 'D20'}, 'show ethernet-switching table vlan-name D20', 'unparsed'),
    ('mac_vlan_empty', 'mac_table_vlan', {'vlan': 'default'}, 'show ethernet-switching table vlan-name default', 'empty'),
    ('vlan_detail', 'vlan_details', {'vlan': 'default'}, 'show vlans default extensive', 'unparsed'),
    ('stp_detail', 'stp_interface_detail', INTERFACE, 'show spanning-tree interface ge-0/0/0 detail', 'not_applicable'),
    ('stp_stats', 'stp_interface_statistics', INTERFACE, 'show spanning-tree statistics interface ge-0/0/0', 'not_applicable'),
    ('cos', 'interface_class_of_service', INTERFACE, 'show class-of-service interface ge-0/0/0', 'unparsed'),
    ('igmp_membership', 'igmp_snooping_membership', {}, 'show igmp snooping membership', 'not_applicable'),
    ('igmp_interface', 'igmp_snooping_interfaces', {}, 'show igmp snooping interface', 'not_applicable'),
])
def test_catalogue_reads(name, query, parameters, command, state, monkeypatch):
    text = output(name)
    auth, calls = replay(monkeypatch, {command: text})
    result = read(auth, query, parameters)
    assert result['ok'] and result['status'] == state
    assert result['untrusted_device_output'].strip() == text.strip()
    assert calls == [command + ' | no-more']


def test_vlan_scope_refuses_keywords_and_unenrolled_names():
    for name in ('all', 'ext', 'operational', 'interface', 'D10', 'D20 | count'):
        for query in ('vlan_details', 'mac_table_vlan'):
            with pytest.raises(ValueError):
                render_read_query(PLATFORM, query, {'vlan': name}, {'vlans': ('D20', 'all', 'ext', 'operational', 'interface')})


def test_refused_and_empty_device_reads(monkeypatch):
    replies = {'show interfaces ge-0/0/47 extensive': output('detail_missing'),
               'show vlans g133-missing extensive': output('vlan_missing')}
    auth, _ = replay(monkeypatch, replies)
    result = read(auth, 'interface_details', {'interface': 'ge-0/0/47'})
    assert not result['ok'] and result['error_code'] == 'device_cli_error'
    result = read(auth, 'vlan_details', {'vlan': 'g133-missing'})
    assert not result['ok'] and result['error_code'] == 'empty'


def test_junos_port_overview_two_timed_reads(monkeypatch):
    from netops_helper import tables

    command = 'show interfaces ge-0/0/0 extensive'
    text = output('details')
    replies = {command: text}
    auth, calls = replay(monkeypatch, replies)
    original = tables.response_envelope
    times = iter(['2026-11-17T21:00:00+00:00', '2026-11-17T21:00:30+00:00',
                  '2026-11-17T21:01:00+00:00'])

    def capture_time(*args, **kwargs):
        return {**original(*args, **kwargs), 'captured_at': next(times)}

    monkeypatch.setattr(tables, 'response_envelope', capture_time)
    first = engine.switch_read(auth, 'interface_errors', **INTERFACE)
    assert first['status'] == 'ok', first['unparsed']
    row = first['records'][0]
    assert (row['port'], row['oper_status'], row['speed'], row['mtu']) == ('ge-0/0/0', 'up', '1000mbps', 1514)
    assert first['counter_baseline']
    # Replay the captured grammar after changing the cumulative values for the timed exercise.
    replies[command] = text.replace('Input errors:\n    Errors: 0,', 'Input errors:\n    Errors: 3,').replace(
        'Carrier transitions: 1,', 'Carrier transitions: 2,')
    second = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'], **INTERFACE)
    row = second['records'][0]
    assert row['delta']['rx_errors'] == 3 and row['errors_per_minute']['rx_errors'] == 6.0
    assert row['delta']['carrier_transitions'] == 1
    assert second['summary']['baseline']['interval_seconds'] == 30.0
    replies[command] = text[:text.index('  Input errors:')]
    cut = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'], **INTERFACE)
    assert cut['counter_baseline'] is None
    assert not cut['coverage']['complete']
    assert calls == [command + ' | no-more'] * 3


def test_junos_triage_preserves_evidence_and_read_gaps(monkeypatch):
    replies = {
        'show interfaces ge-0/0/0 extensive': output('details'),
        'show ethernet-switching interface ge-0/0/0 detail': output('switching'),
        'show spanning-tree interface ge-0/0/0 detail': output('stp_detail'),
        'show lacp interfaces ge-0/0/0': output('lacp'),
        'show poe interface': output('poe'),
        'show interfaces diagnostics optics ge-0/0/0': output('optics'),
        'show lldp neighbors interface ge-0/0/0': output('lldp'),
    }
    auth, calls = replay(monkeypatch, replies)
    result = engine.triage_port(auth, 'ge-0/0/0')
    assert not result['missing'] and result['verdict'] == 'incomplete'
    assert {'stp_interface_detail', 'lacp_interface', 'poe_interfaces'} <= set(result['unavailable'])
    assert result['evidence']['interface_optics']['status'] == 'empty'
    assert 'LLDP Neighbor Information:' in result['evidence']['lldp_neighbors_interface']['untrusted_device_output']
    assert calls == [command + ' | no-more' for command in replies]
    replies['show interfaces ge-0/0/0 extensive'] = output('details').splitlines()[1]
    result = engine.triage_port(auth, 'ge-0/0/0')
    assert not result['ok'] and 'interface_details' in result['missing']


def test_junos_ipv6_interfaces_and_ospfv3_neighbor(monkeypatch):
    replies = {'show interfaces terse': output('terse'), 'show ospf3 neighbor': output('ospf3', VENDOR)}
    auth, calls = replay(monkeypatch, replies)
    result = engine.switch_read(auth, 'ip_interface_v6', interface='em1.0')
    assert result['ok'], result['unparsed']
    assert {(r['ip'], r['prefix_length'], r['address_family']) for r in result['records']} == {
        ('fe80::10', 64, 'ipv6'), ('2001:db8:1::10', 64, 'ipv6')}
    result = engine.switch_read(auth, 'ospf_neighbor', address_family='ipv6')
    assert result['ok'] and len(result['records']) == 1
    assert result['records'][0]['neighbor_id'] == '192.0.2.1'
    assert result['records'][0]['address'] == 'fe80::10'
    assert result['records'][0]['address_family'] == 'ipv6'
    replies['show ospf3 neighbor'] = '\n'.join(output('ospf3', VENDOR).splitlines()[:-1])
    cut = engine.switch_read(auth, 'ospf_neighbor', address_family='ipv6')
    assert cut['status'] == 'unparsed' and not cut['records']
    assert calls == ['show interfaces terse | no-more'] + ['show ospf3 neighbor | no-more'] * 2


def test_junos_poe_and_optics_vendor_outputs(monkeypatch):
    optics_command = 'show interfaces diagnostics optics ge-0/1/0'
    replies = {optics_command: output('optics', VENDOR), 'show poe interface': output('poe_interfaces', VENDOR),
               'show poe controller': output('poe_controller', VENDOR)}
    auth, _ = replay(monkeypatch, replies)
    ports = read(auth, 'poe_interfaces')['poe']
    assert ports['state'] == 'measured' and ports['records'][0]['power_w'] == 7.9
    controller = read(auth, 'poe_controller')['poe']['records'][0]
    assert (controller['max_power_w'], controller['reserved_power_w'], controller['power_w']) == (1650, 43, 8)
    optics = read(auth, 'interface_optics', {'interface': 'ge-0/1/0'})['optics']
    assert optics['state'] == 'measured' and optics['readings']['rx_power'] == {'value': -4.16, 'unit': 'dBm'}
    replies[optics_command] = '\n'.join(replies[optics_command].splitlines()[:-1])
    optics = read(auth, 'interface_optics', {'interface': 'ge-0/1/0'})['optics']
    assert optics['state'] == 'partial' and optics['missing_fields'] == ['rx_power']
    replies['show poe interface'] = output('poe')
    assert read(auth, 'poe_interfaces')['poe']['state'] == 'not_applicable'


def test_queue_drop_output_from_vendor(monkeypatch):
    command = 'show interfaces queue ge-0/0/0'
    text = output('queue', VENDOR)
    auth, calls = replay(monkeypatch, {command: text})
    result = read(auth, 'interface_queue', INTERFACE)
    assert result['ok'] and 'Total-dropped packets: 526512' in result['untrusted_device_output']
    assert calls == [command + ' | no-more']


def test_junos_bgp_family_reports_peer_transport_family(monkeypatch):
    auth, calls = replay(monkeypatch, {'show bgp summary': output('bgp6', VENDOR)})
    rows = engine.switch_read(auth, 'bgp_peer', address_family='ipv6')
    assert rows['ok'] and len(rows['records']) == 1
    assert rows['records'][0]['neighbor'] == '2001:db8:1::10'
    assert rows['records'][0]['address_family'] == 'ipv6'
    assert not engine.switch_read(auth, 'bgp_peer', address_family='ipv4')['records']
    assert calls == ['show bgp summary | no-more'] * 2


@pytest.mark.parametrize('query,parameters,command,marker', [
    ('stp_interface_detail', {'interface': 'ge-1/0/0'}, 'show spanning-tree interface ge-1/0/0 detail', 'Blocking'),
    ('igmp_snooping_interfaces', {}, 'show igmp snooping interface', 'Up Groups:'),
])
def test_populated_stp_and_igmp_are_available(query, parameters, command, marker, monkeypatch):
    name = 'stp_detail' if 'stp' in query else 'igmp_interface'
    auth, calls = replay(monkeypatch, {command: output(name, VENDOR)})
    result = read(auth, query, parameters)
    assert result['ok'] and marker in result['untrusted_device_output']
    assert calls == [command + ' | no-more']


# 482-r2: an administratively disabled port (`set interfaces ge-0/0/5 disable`, captured live on the lab
# vJunos-switch during a commit confirmed window) keeps its state in JP01 and is a link_down finding in JP02.
STATUS_FIELDS = ('admin_status', 'oper_status', 'description', 'speed', 'mtu')
DISABLED = 'ge-0/0/5'


def triage_replies(port, details):
    return {
        f'show interfaces {port} extensive': details,
        # The unused lab port has no ethernet-switching family; the device answered rc 0 with no text.
        f'show ethernet-switching interface {port} detail': '',
        f'show spanning-tree interface {port} detail': output('stp_detail'),
        f'show lacp interfaces {port}': output('lacp'),
        'show poe interface': output('poe'),
        f'show interfaces diagnostics optics {port}': '',
        f'show lldp neighbors interface {port}': '',
    }


@pytest.mark.parametrize('name,admin', [('details_admin_down', 'down'), ('details_reenabled', 'up')])
def test_junos_disabled_port_overview_keeps_state(name, admin, monkeypatch):
    command = f'show interfaces {DISABLED} extensive'
    auth, calls = replay(monkeypatch, {command: output(name)})
    result = engine.switch_read(auth, 'interface_errors', interface=DISABLED)
    assert result['ok'] and result['status'] == 'ok', result['unparsed']
    row = result['records'][0]
    assert set(STATUS_FIELDS) <= set(row)
    assert (row['port'], row['admin_status'], row['oper_status'], row['speed'], row['mtu'], row['description']) == (
        DISABLED, admin, 'down', '1000mbps', 1514, None)
    assert (row['rx_errors'], row['tx_errors']) == (0, 0)
    assert calls == [command + ' | no-more']


def test_junos_disabled_port_triage_reports_link_down(monkeypatch):
    replies = triage_replies(DISABLED, output('details_admin_down'))
    auth, calls = replay(monkeypatch, replies)
    result = engine.triage_port(auth, DISABLED)
    assert 'interface_details' not in result['missing']
    assert result['ok'] and result['missing'] == []
    assert result['last_flap'] == '2026-11-12 05:05:01 UTC (5d 17:24 ago)'
    assert 'ethernet_switching_interface' in result['unavailable']
    switching = result['evidence']['ethernet_switching_interface']
    assert switching['ok'] and switching['status'] == switching['normalized']['status'] == 'not_applicable'
    assert [f for f in result['findings'] if f['code'] == 'link_down'] == [
        {'code': 'link_down', 'source': 'interface_details', 'port': DISABLED, 'admin_status': 'down'}]
    assert calls == [command + ' | no-more' for command in replies]
    replies[f'show interfaces {DISABLED} extensive'] = output('details_reenabled')
    result = engine.triage_port(auth, DISABLED)
    assert [f for f in result['findings'] if f['code'] == 'link_down'] == [
        {'code': 'link_down', 'source': 'interface_details', 'port': DISABLED, 'admin_status': 'up'}]


@pytest.mark.parametrize('state,admin,oper', [
    # Header values listed for the "Enabled" field in Junos Common Output Fields.
    ('Administratively down, Physical link is Down', 'down', 'down'),
    ('Administratively down, Physical link is Up', 'down', 'up'),
    ('Enabled, Physical link is Down', 'up', 'down'),
    ('Enabled, Physical link is Up', 'up', 'up'),
    ('Disabled, Physical link is Down', 'down', 'down'),
])
def test_junos_header_states_through_engine(state, admin, oper, monkeypatch):
    text = output('details')
    lines = text.splitlines(keepends=True)
    lines[0] = f'Physical interface: ge-0/0/0, {state}\n'
    replies = triage_replies('ge-0/0/0', ''.join(lines))
    auth, _ = replay(monkeypatch, replies)
    row = engine.switch_read(auth, 'interface_errors', **INTERFACE)['records'][0]
    assert (row['admin_status'], row['oper_status'], row['mtu']) == (admin, oper, 1514)
    result = engine.triage_port(auth, 'ge-0/0/0')
    assert 'interface_details' not in result['missing']
    down = [f for f in result['findings'] if f['code'] == 'link_down']
    assert down == ([{'code': 'link_down', 'source': 'interface_details', 'port': 'ge-0/0/0', 'admin_status': admin}]
                    if oper == 'down' else [])


def test_junos_unknown_header_state_keeps_fields_and_stays_missing(monkeypatch):
    lines = output('details').splitlines(keepends=True)
    lines[0] = 'Physical interface: ge-0/0/0, Testing, Physical link is Down\n'
    replies = triage_replies('ge-0/0/0', ''.join(lines))
    auth, _ = replay(monkeypatch, replies)
    row = engine.switch_read(auth, 'interface_errors', **INTERFACE)['records'][0]
    assert set(STATUS_FIELDS) <= set(row) and row['oper_status'] is None and row['mtu'] == 1514
    assert 'interface_details' in engine.triage_port(auth, 'ge-0/0/0')['missing']


def test_junos_detail_output_of_disabled_port():
    from netops_helper import port_errors

    rows, _ = port_errors.parse(PLATFORM, output('detail_admin_down'), f'show interfaces {DISABLED} detail')
    assert [(r['port'], r['admin_status'], r['oper_status'], r['speed'], r['mtu']) for r in rows] == [
        (DISABLED, 'down', 'down', '1000mbps', 1514)]


def test_empty_switching_read_stays_missing_for_a_switched_port(monkeypatch):
    replies = triage_replies('ge-0/0/0', output('details'))
    auth, _ = replay(monkeypatch, replies)
    result = engine.triage_port(auth, 'ge-0/0/0')
    assert not result['ok'] and 'ethernet_switching_interface' in result['missing']


@pytest.mark.parametrize('size, truncated', [(24000, False), (50000, True)])
def test_junos_triage_large_interface_details(size, truncated, monkeypatch):
    capture = output('details')
    logical = capture[capture.index('  Logical interface '):]
    while len(capture.encode()) < size:
        capture += logical.replace('ge-0/0/0.0', f'ge-0/0/0.{len(capture)}')
    replies = triage_replies('ge-0/0/0', capture)
    replies['show ethernet-switching interface ge-0/0/0 detail'] = output('switching')
    auth, _ = replay(monkeypatch, replies)
    result = engine.triage_port(auth, 'ge-0/0/0')
    details = result['evidence']['interface_details']
    assert details['complete'] is not truncated
    assert details.get('truncated', False) is truncated
    assert ('interface_details' in result['missing']) is truncated


@pytest.mark.parametrize('name, reason', [('switching_bpdu', 'Disabled by bpdu-control'),
                                         ('switching_stp', 'blocked by STP')])
def test_junos_triage_reports_switching_protection(name, reason, monkeypatch):
    replies = triage_replies('ge-0/0/0', output('details'))
    replies['show ethernet-switching interface ge-0/0/0 detail'] = output(name, VENDOR)
    auth, _ = replay(monkeypatch, replies)
    result = engine.triage_port(auth, 'ge-0/0/0')
    assert [item for item in result['findings'] if item['code'] == 'spanning_tree_protection'] == [
        {'code': 'spanning_tree_protection', 'source': 'ethernet_switching_interface',
         'port': 'ge-0/0/0', 'device_reason': reason}]
