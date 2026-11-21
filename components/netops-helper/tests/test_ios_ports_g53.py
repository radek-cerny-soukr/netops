"""G53 IOS port, STP, EtherChannel, PoE, DOM and per-port neighbor reads.

Real anonymized IOSvL2 15.2(20200924) captures (`fixtures/real/cisco_ios/iosvl2_15.2.20200924_g53`, admin
and the netops-ro refusals) and verbatim Cisco command-reference outputs for what the lab image cannot print
(`fixtures/docs/cisco_ios/g53`: populated LACP, PoE detail, DOM). Only the SSH transport is replaced.
Variants marked DERIVED change one documented token of such an output (a member state, a counter, a reading)
or cut it at an existing line boundary; nothing here is written from guessed syntax.
"""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
import test_proxy_contracts as contracts
from netops_helper import engine, ios_ports, normalization, optics, tables
from netops_helper.auth import TargetAuth
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.read_policy import _validate_query_command, render_read_query

HERE = Path(__file__).parent
REAL = HERE / 'fixtures/real/cisco_ios/iosvl2_15.2.20200924_g53'
DOCS = HERE / 'fixtures/docs/cisco_ios/g53'
G53 = ('stp_detail', 'stp_interface_detail', 'stp_mst', 'etherchannel_detail', 'lacp_internal',
       'etherchannel_load_balance', 'power_inline_detail', 'lldp_neighbor_interface', 'cdp_neighbor_interface')
PORTS = ('GigabitEthernet0/1', 'GigabitEthernet0/2', 'GigabitEthernet0/3', 'GigabitEthernet1/0/1',
         'GigabitEthernet2/0/2', 'GigabitEthernet0/0/0', 'GigabitEthernet1/1/1')
INVENTORY = {'interfaces': PORTS}
QUERIES = tuple(READ_QUERIES['cisco_ios'])


def real(name, role='admin'):
    return ((REAL / 'ro' if role == 'ro' else REAL) / (name + '.out')).read_text()


def doc(name):
    return (DOCS / (name + '.out')).read_text()


def transport(monkeypatch, outputs, role='admin', enabled=QUERIES, inventory=INVENTORY):
    """Answer each rendered command with its capture; any other command fails the test."""
    version = real('version', role)
    auth = replace(_target('cisco_ios', 'version'), enabled_queries=tuple(enabled), read_inventory=inventory)
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        if command == 'show version':
            return 0, version
        return 0, outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    engine._SSH_PAGE_CACHE.clear()
    return auth, calls


def ssh_read(monkeypatch, query, parameters, body, role='admin'):
    command = render_read_query('cisco_ios', query, parameters, INVENTORY)[1]
    auth, calls = transport(monkeypatch, {command: body}, role)
    result = engine.ssh_read(auth, 'cisco_ios', query, parameters, 0, 48000)
    assert calls[-1] == command
    return result


# --- catalogue -------------------------------------------------------------------------------------------

@pytest.mark.parametrize('query,parameters,command', [
    ('stp_detail', {}, 'show spanning-tree detail'),
    ('stp_interface_detail', {'interface': 'GigabitEthernet0/1'}, 'show spanning-tree interface GigabitEthernet0/1 detail'),
    ('stp_mst', {}, 'show spanning-tree mst'),
    ('etherchannel_detail', {}, 'show etherchannel detail'),
    ('lacp_internal', {}, 'show lacp internal'),
    ('etherchannel_load_balance', {}, 'show etherchannel load-balance'),
    ('power_inline_detail', {'interface': 'GigabitEthernet0/1'}, 'show power inline GigabitEthernet0/1 detail'),
    ('lldp_neighbor_interface', {'interface': 'GigabitEthernet0/1'}, 'show lldp neighbors GigabitEthernet0/1 detail'),
    ('cdp_neighbor_interface', {'interface': 'GigabitEthernet0/1'}, 'show cdp neighbors GigabitEthernet0/1 detail'),
])
def test_catalogue_renders_the_lab_verified_commands(query, parameters, command):
    assert render_read_query('cisco_ios', query, parameters, INVENTORY)[1] == command
    _validate_query_command('cisco_ios', READ_QUERIES['cisco_ios'][query].command)


@pytest.mark.parametrize('query', ['stp_interface_detail', 'power_inline_detail', 'lldp_neighbor_interface', 'cdp_neighbor_interface'])
def test_per_port_queries_refuse_unenrolled_and_logical_ports(query):
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', query, {'interface': 'GigabitEthernet0/9'}, INVENTORY)
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', query, {'interface': 'Vlan10'}, {'interfaces': ('Vlan10',)})


# --- real IOSvL2 captures through ssh_read ----------------------------------------------------------------

def test_stp_detail_has_topology_change_history(monkeypatch):
    result = ssh_read(monkeypatch, 'stp_detail', {}, real('stp_detail'))
    assert result['untrusted_device_output'].strip() == real('stp_detail').strip()
    normalized = result['normalized']
    assert normalized['status'] == 'ok' and normalized['coverage']['complete'], normalized
    rows = {row['instance']: row for row in normalized['records']}
    assert set(rows) == {'VLAN0001', 'VLAN0010', 'VLAN0020', 'VLAN0099'}
    vlan1 = rows['VLAN0001']
    assert vlan1['protocol'] == 'ieee' and vlan1['root_bridge'] is True
    assert vlan1['topology_changes'] == 3 and vlan1['last_change_from'] == 'GigabitEthernet1/0'
    # hh:mm:ss and 1d19h ages are both seconds.
    assert all(isinstance(row['last_change_seconds'], int) for row in rows.values())
    assert rows['VLAN0010']['last_change_seconds'] >= 86400


def test_stp_ports_of_the_whole_detail(monkeypatch):
    auth, calls = transport(monkeypatch, {'show spanning-tree detail': real('stp_detail')})
    result = engine.switch_read(auth, 'stp_port_counters', limit=500)
    assert calls[-1] == 'show spanning-tree detail'
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    ports = {(row['instance'], row['port']): row for row in result['records']}
    row = ports['VLAN0010', 'GigabitEthernet0/1']
    assert row['role'] == 'designated' and row['state'] == 'forwarding' and row['cost'] == 4
    assert row['link_type'] == 'point-to-point' and row['forward_transitions'] == 1
    assert row['bpdu_sent'] > 0 and row['bpdu_received'] == 0
    topology = engine.switch_read(auth, 'stp_topology')
    assert topology['status'] == 'ok' and len(topology['records']) == 4


@pytest.mark.parametrize('port,fixture,instances', [
    ('GigabitEthernet0/1', 'stp_interface_detail_gi01', ['VLAN0010', 'VLAN0020']),
    ('GigabitEthernet0/2', 'stp_interface_detail_gi02', ['VLAN0010', 'VLAN0020']),
    ('GigabitEthernet0/3', 'stp_interface_detail_gi03', ['VLAN0010']),
])
def test_one_port_stp_detail_runs_on_the_switch(monkeypatch, port, fixture, instances):
    command = f'show spanning-tree interface {port} detail'
    auth, calls = transport(monkeypatch, {command: real(fixture)})
    result = engine.switch_read(auth, 'stp_port_counters', interface=port)
    assert calls[-1] == command and 'show spanning-tree detail' not in calls
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert [row['instance'] for row in result['records']] == instances
    assert {row['port'] for row in result['records']} == {port}


# r4: a portfast edge (access) port prints `The port is in the portfast edge mode` in its one-port detail
# (real IOSvL2 capture of Gi0/0, r3 live round); the whole `show spanning-tree detail` does not print it.
def _assert_gi00_edge(normalized):
    assert normalized['status'] == 'ok' and normalized['coverage']['complete'] and not normalized['unparsed'], normalized
    [row] = normalized['records']
    assert (row['instance'], row['port'], row['role'], row['state']) == ('VLAN0099', 'GigabitEthernet0/0', 'root', 'forwarding')
    assert row['cost'] == 4 and row['forward_transitions'] == 1 and row['link_type'] == 'point-to-point'
    assert (row['bpdu_sent'], row['bpdu_received']) == (0, 85219)
    assert row['portfast'] == 'edge'


@pytest.mark.parametrize('port', ['GigabitEthernet0/0', 'Gi0/0'])
def test_portfast_edge_port_detail_through_ssh_read(monkeypatch, port):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    auth, calls = transport(monkeypatch, {command: real('stp_interface_detail_gi00')},
                            inventory={'interfaces': ('GigabitEthernet0/0',)})
    result = engine.ssh_read(auth, 'cisco_ios', 'stp_interface_detail', {'interface': port}, 0, 48000)
    assert calls[-1] == command
    assert result['untrusted_device_output'].strip() == real('stp_interface_detail_gi00').strip()
    _assert_gi00_edge(result['normalized'])


@pytest.mark.parametrize('port', ['GigabitEthernet0/0', 'Gi0/0'])
def test_portfast_edge_port_detail_through_switch_read(monkeypatch, port):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    auth, calls = transport(monkeypatch, {command: real('stp_interface_detail_gi00')},
                            inventory={'interfaces': ('GigabitEthernet0/0',)})
    result = engine.switch_read(auth, 'stp_port_counters', interface=port)
    assert calls[-1] == command and 'show spanning-tree detail' not in calls
    assert result['ok'] is True
    _assert_gi00_edge(result)


def test_portfast_is_unknown_where_the_device_does_not_print_it(monkeypatch):
    auth, calls = transport(monkeypatch, {'show spanning-tree detail': real('stp_detail')})
    result = engine.switch_read(auth, 'stp_port_counters', limit=500)
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert 'portfast' not in result['coverage']['missing_fields']
    assert all(row['portfast'] is None for row in result['records'])


@pytest.mark.parametrize('line', ['   The port is in the portfast network mode', '   The port is in the portfast edge mode 2',
                                  '   Bpdu filter is disabled', '   Bpdu guard is disabled'])
def test_other_portfast_lines_stay_unparsed(line):
    # DERIVED: the edge line of the real Gi0/0 capture replaced by a form not documented for IOS 15.x.
    text = real('stp_interface_detail_gi00').replace('   The port is in the portfast edge mode', line, 1)
    assert line in text
    result = tables.parse('cisco_ios', 'stp_port_counters', 'stp_interface_detail', text)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert [item['text'] for item in result['unparsed']] == [line]


@pytest.mark.parametrize('line', ['Loop guard is enabled on the port', 'Root guard is enabled on the port',
                                  'Bpdu guard is enabled', 'Loop guard:enabled', 'Root guard:enabled',
                                  'Bpdu guard:enabled', 'BPDU guard: enabled on the port'])
def test_stp_port_guard_lines_are_known_through_ssh_read(monkeypatch, line):
    # DERIVED: one explicit guard line is added to the measured IOSvL2 port detail.
    marker = '   Link type is point-to-point by default\n'
    body = real('stp_interface_detail_gi00')
    assert marker in body
    body = body.replace(marker, f'{marker}   {line}\n', 1)
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    auth, calls = transport(monkeypatch, {command: body}, inventory={'interfaces': ('GigabitEthernet0/0',)})
    result = engine.ssh_read(auth, 'cisco_ios', 'stp_interface_detail', {'interface': 'Gi0/0'}, 0, 48000)
    assert calls[-1] == command
    assert line in result['untrusted_device_output']
    _assert_gi00_variant(result['normalized'], 'edge', False)


# r5 (review 483-r4-rv finding 1): the PortFast and BPDU filter lines of the Cisco IOS 15.4SY one-port detail examples
# (fixtures/docs/cisco_ios/g53/stp_interface_detail_*.out, verbatim). Each documented line is taken from its file.
def _doc_line(fixture, start):
    [line] = [line.strip() for line in doc(fixture).splitlines() if line.strip().startswith(start)]
    return line


DOCUMENTED_PORTFAST = [('stp_interface_detail_edge_trunk', 'edge trunk'), ('stp_interface_detail_bpdufilter', 'trunk'),
                       ('stp_interface_detail_edge_default', 'edge')]


def _gi00_with(portfast=None, bpdu_filter=False):
    """DERIVED: the real Gi0/0 capture with its PortFast line replaced by a documented one and/or the documented
    `Bpdu filter is enabled` line added after `Link type`, where the Cisco example prints it."""
    text = real('stp_interface_detail_gi00')
    if portfast is not None:
        line = '   ' + _doc_line(portfast, 'The port is in the portfast')
        text = text.replace('   The port is in the portfast edge mode\n', line + '\n', 1)
        assert line + '\n' in text
    if bpdu_filter:
        line = '   ' + _doc_line('stp_interface_detail_bpdufilter', 'Bpdu filter')
        text = text.replace('   Link type is point-to-point by default\n',
                            '   Link type is point-to-point by default\n' + line + '\n', 1)
        assert line + '\n' in text
    return text


VARIANTS = [(fixture, value, False) for fixture, value in DOCUMENTED_PORTFAST] + [
    (None, 'edge', True), ('stp_interface_detail_bpdufilter', 'trunk', True)]
VARIANT_IDS = ['edge-trunk', 'trunk-configuration', 'edge-default', 'edge+bpdufilter', 'trunk+bpdufilter']


def _assert_gi00_variant(normalized, portfast, bpdu_filter):
    assert normalized['status'] == 'ok' and normalized['coverage']['complete'] and not normalized['unparsed'], normalized
    [row] = normalized['records']
    assert (row['instance'], row['port'], row['role'], row['state']) == ('VLAN0099', 'GigabitEthernet0/0', 'root', 'forwarding')
    assert (row['bpdu_sent'], row['bpdu_received']) == (0, 85219)
    assert row['portfast'] == portfast
    assert row['bpdu_filter'] is (True if bpdu_filter else None)


@pytest.mark.parametrize('fixture,portfast,bpdu_filter', VARIANTS, ids=VARIANT_IDS)
def test_documented_portfast_and_bpdu_filter_through_ssh_read(monkeypatch, fixture, portfast, bpdu_filter):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    body = _gi00_with(fixture, bpdu_filter)
    auth, calls = transport(monkeypatch, {command: body}, inventory={'interfaces': ('GigabitEthernet0/0',)})
    result = engine.ssh_read(auth, 'cisco_ios', 'stp_interface_detail', {'interface': 'Gi0/0'}, 0, 48000)
    assert calls[-1] == command
    _assert_gi00_variant(result['normalized'], portfast, bpdu_filter)


@pytest.mark.parametrize('fixture,portfast,bpdu_filter', VARIANTS, ids=VARIANT_IDS)
def test_documented_portfast_and_bpdu_filter_through_switch_read(monkeypatch, fixture, portfast, bpdu_filter):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    auth, calls = transport(monkeypatch, {command: _gi00_with(fixture, bpdu_filter)},
                            inventory={'interfaces': ('GigabitEthernet0/0',)})
    result = engine.switch_read(auth, 'stp_port_counters', interface='GigabitEthernet0/0')
    assert calls[-1] == command and 'show spanning-tree detail' not in calls
    assert result['ok'] is True
    _assert_gi00_variant(result, portfast, bpdu_filter)


@pytest.mark.parametrize('fixture,interface,portfast,bpdu_filter,bpdu_sent', [
    ('stp_interface_detail_edge_trunk', 'Gi3/13', 'edge trunk', None, 2183),
    ('stp_interface_detail_edge_default', 'Gi3/13', 'edge', None, 2183),
    ('stp_interface_detail_bpdufilter', 'Gi4/4', 'trunk', True, 0),
])
@pytest.mark.parametrize('tool', ['switch_read', 'ssh_read'])
def test_documented_one_port_examples_verbatim(tmp_path, monkeypatch, fixture, interface, portfast, bpdu_filter,
                                               bpdu_sent, tool):
    port = interface.replace('Gi', 'GigabitEthernet')
    command = f'show spanning-tree interface {port} detail'
    auth, calls = transport(monkeypatch, {command: doc(fixture)}, enabled=('stp_interface_detail',),
                            inventory={'interfaces': (interface,)})
    args = (dict(table='stp_port_counters', interface=interface) if tool == 'switch_read' else
            dict(platform='cisco_ios', query='stp_interface_detail', parameters={'interface': interface},
                 offset=0, max_bytes=48000))
    result, errors = public(tmp_path, auth, tool, inventory_interfaces=(interface,), **args)
    assert result is not None, errors
    assert [call for call in calls if call != 'show version'] == [command]
    if tool == 'ssh_read':
        result = result['normalized']
    assert result['ok'] and result['status'] == 'ok' and result['unparsed'] == [], result
    [row] = result['records']
    assert row['port'] == port
    assert (row['forward_transitions'], row['bpdu_sent'], row['bpdu_received']) == (1, bpdu_sent, 0)
    assert row['portfast'] == portfast and row['bpdu_filter'] is bpdu_filter


def test_bpdu_filter_is_unknown_where_the_device_does_not_print_it(monkeypatch):
    for command, body, kwargs in (('show spanning-tree detail', real('stp_detail'), {'limit': 500}),
                                  ('show spanning-tree interface GigabitEthernet0/0 detail', real('stp_interface_detail_gi00'),
                                   {'interface': 'GigabitEthernet0/0'})):
        auth, calls = transport(monkeypatch, {command: body}, inventory={'interfaces': ('GigabitEthernet0/0',)})
        result = engine.switch_read(auth, 'stp_port_counters', **kwargs)
        assert result['status'] == 'ok' and result['coverage']['complete'], result
        assert 'bpdu_filter' not in result['coverage']['missing_fields']
        assert all(row['bpdu_filter'] is None for row in result['records'])


def test_ro_account_is_refused_the_per_port_stp_and_mst(monkeypatch):
    # netops-ro (privilege 1) gets "Line has invalid autocommand" over the exec channel.
    for query, parameters, fixture in (('stp_interface_detail', {'interface': 'GigabitEthernet0/1'}, 'stp_interface_detail_gi01'),
                                       ('stp_mst', {}, 'stp_mst')):
        result = ssh_read(monkeypatch, query, parameters, real(fixture, 'ro'), 'ro')
        assert result['untrusted_device_output'].strip().startswith('Line has invalid autocommand')
        assert normalization.output_status(real(fixture, 'ro'), profile='cisco_ios') == 'permission_denied'
    result = ssh_read(monkeypatch, 'stp_interface_detail', {'interface': 'GigabitEthernet0/1'},
                      real('stp_interface_detail_gi01', 'ro'), 'ro')
    assert result['status'] == 'permission_denied' and not result['normalized']['coverage']['complete']


def test_ro_whole_stp_detail_is_readable(monkeypatch):
    result = ssh_read(monkeypatch, 'stp_detail', {}, real('stp_detail', 'ro'), 'ro')
    assert result['normalized']['status'] == 'ok' and len(result['normalized']['records']) == 4


def test_pvst_switch_answers_mst_as_not_applicable(monkeypatch):
    result = ssh_read(monkeypatch, 'stp_mst', {}, real('stp_mst'))
    assert result['untrusted_device_output'].strip() == '% Switch is not in mst mode'
    assert normalization.output_status(real('stp_mst'), profile='cisco_ios') == 'not_applicable'
    assert result['status'] == 'not_applicable'


def test_port_without_stp_is_empty_not_unparsed():
    # Real IOSvL2 answer for a port without spanning tree (raw session, Gi1/1 is notconnect).
    text = 'no spanning tree info available for GigabitEthernet1/1 \n\n'
    result = tables.parse('cisco_ios', 'stp_port_counters', 'stp_interface_detail', text)
    assert result['status'] == 'empty' and not result['unparsed']


def test_cut_or_unknown_stp_detail_is_not_complete():
    text = real('stp_detail')
    # DERIVED: an unknown line inside a port block.
    broken = text.replace('   Link type is point-to-point by default', '   Link type is point-to-point by default\n   Unknown guard line 7', 1)
    result = tables.parse('cisco_ios', 'stp_port_counters', 'stp_detail', broken)
    assert result['status'] == 'unparsed' and not result['coverage']['complete'] and len(result['unparsed']) == 1
    # DERIVED: cut after a port header, before its counters.
    head = text.split('   Port path cost 4', 1)[0]
    result = tables.parse('cisco_ios', 'stp_port_counters', 'stp_detail', head)
    assert not result['coverage']['complete']
    assert {'cost', 'bpdu_sent', 'forward_transitions', 'link_type'} <= set(result['coverage']['missing_fields'])


def test_etherchannel_detail_without_groups_is_a_complete_raw_read(monkeypatch):
    result = ssh_read(monkeypatch, 'etherchannel_detail', {}, real('etherchannel_detail'))
    assert 'Channel-group listing:' in result['untrusted_device_output']
    assert normalization.output_status(real('etherchannel_detail'), profile='cisco_ios') == 'ok'
    # Raw catalogue output without a table adapter keeps the engine's convention: status unparsed, no records.
    assert result['ok'] and result['status'] == 'unparsed' and 'records' not in result['normalized']


def test_lacp_internal_without_groups_is_empty(monkeypatch):
    result = ssh_read(monkeypatch, 'lacp_internal', {}, real('lacp_internal'))
    assert result['normalized']['status'] == 'empty' and result['normalized']['records'] == []
    # r3 finding 3: no channel group is not complete member data (as etherchannel_detail).
    assert result['ok'] and result['normalized']['ok'] and not result['normalized']['coverage']['complete']
    assert 'no_channel_groups' in result['normalized']['warnings']


def test_lag_member_without_groups_is_empty_but_not_complete(monkeypatch):
    auth, calls = transport(monkeypatch, {'show lacp internal': real('lacp_internal')})
    for interface in (None, 'GigabitEthernet0/1'):
        result = engine.switch_read(auth, 'lag_member', interface=interface)
        assert calls[-1] == 'show lacp internal'
        assert result['ok'] and result['status'] == 'empty' and result['records'] == [], result
        assert not result['coverage']['complete'] and 'no_channel_groups' in result['warnings']


def test_load_balance_method_and_fields(monkeypatch):
    result = ssh_read(monkeypatch, 'etherchannel_load_balance', {}, real('etherchannel_load_balance'))
    balance = result['load_balance']
    assert balance['status'] == 'ok' and balance['method'] == 'src-dst-ip'
    assert result['status'] == 'ok' and result['normalized']['coverage']['complete']
    assert balance['non_ip'] == 'Source XOR Destination MAC address'
    assert balance['ipv4'] == balance['ipv6'].replace('IP', 'IP') and 'IP address' in balance['ipv4']
    # DERIVED: the method line missing (cut) is never ok.
    cut = real('etherchannel_load_balance').replace('        src-dst-ip\n', '')
    assert ios_ports.load_balance(cut, 'ok')['status'] == 'unparsed'


@pytest.mark.parametrize('cut_at', ['EtherChannel Load-Balancing Addresses Used Per-Protocol:',
                                    '  IPv6:'])
def test_load_balance_without_all_protocols_has_incomplete_coverage(monkeypatch, cut_at):
    # DERIVED: truncate the real output at a line boundary, leaving the method intact.
    prefix, marker, _ = real('etherchannel_load_balance').partition(cut_at)
    assert marker
    result = ssh_read(monkeypatch, 'etherchannel_load_balance', {}, prefix)
    assert result['load_balance']['method'] == 'src-dst-ip'
    assert result['load_balance']['ipv6'] is None
    assert result['status'] == 'unparsed'
    assert result['normalized']['coverage']['complete'] is False


def test_load_balance_cut_inside_the_final_protocol_line(monkeypatch):
    body = real('etherchannel_load_balance').rstrip().removesuffix(' address')
    result = ssh_read(monkeypatch, 'etherchannel_load_balance', {}, body)
    assert result['status'] == 'unparsed' and not result['normalized']['coverage']['complete']


@pytest.mark.parametrize('terminated', [True, False], ids=['complete', 'mid-line'])
def test_legacy_load_balance_without_ipv6(monkeypatch, terminated):
    # DERIVED: Cisco added the IPv6 row in 12.2(17a)SX1. Use the real IOSvL2 layout
    # without that row and a version banner for the preceding Catalyst 6500 IOS release.
    command = 'show etherchannel load-balance'
    body = real('etherchannel_load_balance').partition('  IPv6:')[0]
    if not terminated:
        body = body.rstrip().removesuffix(' address')
    auth, calls = transport(monkeypatch, {command: body})
    read = engine.read_from_device

    def legacy_read(auth, profile, command):
        rc, output = read(auth, profile, command)
        if command == 'show version':
            output = output.replace('15.2(20200924:215240)', '12.2(14)SX')
        return rc, output

    monkeypatch.setattr(engine, 'read_from_device', legacy_read)
    result = engine.ssh_read(auth, 'cisco_ios', 'etherchannel_load_balance', {}, 0, 48000)
    assert calls[-1] == command and result['load_balance']['ipv6'] is None
    assert result['status'] == ('ok' if terminated else 'unparsed')
    assert result['normalized']['coverage']['complete'] is terminated


@pytest.mark.parametrize('port,fixture,count', [('GigabitEthernet0/1', 'gi01', 3), ('GigabitEthernet0/2', 'gi02', 1),
                                                ('GigabitEthernet0/3', 'gi03', 0)])
def test_lldp_neighbors_of_one_port(monkeypatch, port, fixture, count):
    command = f'show lldp neighbors {port} detail'
    auth, calls = transport(monkeypatch, {command: real('lldp_neighbor_interface_' + fixture)})
    result = engine.switch_read(auth, 'lldp_neighbor', interface=port)
    assert calls[-1] == command and 'show lldp neighbors detail' not in calls
    assert len(result['records']) == count and result['status'] == ('ok' if count else 'empty'), result
    assert result['coverage']['complete'] or not count
    assert all(row['local_port'] == port for row in result['records'])


@pytest.mark.parametrize('port,fixture,count', [('GigabitEthernet0/1', 'gi01', 1), ('GigabitEthernet0/2', 'gi02', 0),
                                                ('GigabitEthernet0/3', 'gi03', 0)])
def test_cdp_neighbors_of_one_port(monkeypatch, port, fixture, count):
    command = f'show cdp neighbors {port} detail'
    auth, calls = transport(monkeypatch, {command: real('cdp_neighbor_interface_' + fixture)})
    result = engine.switch_read(auth, 'cdp_neighbor', interface=port)
    assert calls[-1] == command
    assert len(result['records']) == count and result['status'] == ('ok' if count else 'empty'), result
    if count:
        row, = result['records']
        assert row['local_port'] == port and row['neighbor_port'] == 'GigabitEthernet0/1'
        assert row['management_ip'] and result['coverage']['complete']


def test_neighbor_ssh_read_is_normalized(monkeypatch):
    result = ssh_read(monkeypatch, 'cdp_neighbor_interface', {'interface': 'GigabitEthernet0/1'},
                      real('cdp_neighbor_interface_gi01'))
    assert result['normalized']['status'] == 'ok' and len(result['normalized']['records']) == 1


@pytest.mark.parametrize('query,name,command', [
    # r3 finding 4: module/slot/port names with zeros from the real capture and the documentation.
    ('stp_interface_detail', 'Gi0/0', 'show spanning-tree interface GigabitEthernet0/0 detail'),
    ('stp_interface_detail', 'GigabitEthernet0/0', 'show spanning-tree interface GigabitEthernet0/0 detail'),
    ('stp_interface_detail', 'Gi1/1', 'show spanning-tree interface GigabitEthernet1/1 detail'),
    ('power_inline_detail', 'Gi0/0/0', 'show power inline GigabitEthernet0/0/0 detail'),
    ('interface_transceiver', 'Gi1/1/1', 'show interfaces GigabitEthernet1/1/1 transceiver detail'),
    ('interface_errors', 'GigabitEthernet0/0', 'show interfaces GigabitEthernet0/0 counters errors'),
])
def test_ios_module_slot_port_names_with_zeros_are_valid(query, name, command):
    assert render_read_query('cisco_ios', query, {'interface': name}, {'interfaces': (name,)})[1] == command


@pytest.mark.parametrize('name', ['Gi0/0 ', ' Gi0/0', 'Gi 0/0', 'Gi0/0/0/0', 'Gi00/0', 'Gi0/00', 'Gi9/0',
                                  'Gi0/9/1', 'Gi1/1/100', 'Gi0/0-1', 'Gi0/0,Gi0/1', 'Gi0/0.1', 'gi0/0',
                                  'Gi0/0;show', 'Port-channel1', 'Vlan1'])
def test_ios_physical_port_validator_is_not_loosened(name):
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', 'stp_interface_detail', {'interface': name}, {'interfaces': (name,)})


def test_lab_image_without_poe_or_dom_is_not_a_reading(monkeypatch):
    poe = ssh_read(monkeypatch, 'power_inline_detail', {'interface': 'GigabitEthernet0/1'}, real('power_inline_detail_gi01'))
    assert poe['status'] == 'permission_denied' and 'poe' not in poe
    dom = ssh_read(monkeypatch, 'interface_transceiver', {'interface': 'GigabitEthernet0/1'}, real('interface_transceiver_gi01'))
    assert dom['status'] == 'permission_denied' and 'optics' not in dom


# --- port rates and bounded counter reads (IOS-C003) ------------------------------------------------------

def test_port_rates_are_device_averages_with_link_utilisation(monkeypatch):
    auth, calls = transport(monkeypatch, {'show interfaces': real('interfaces_details')})
    result = engine.switch_read(auth, 'port_rates', limit=500)
    assert calls[-1] == 'show interfaces'
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    rows = {row['port']: row for row in result['records']}
    assert {'GigabitEthernet0/1', 'GigabitEthernet0/3', 'GigabitEthernet1/0'} <= set(rows)
    row = rows['GigabitEthernet0/1']
    assert row['interval'] == 300 and isinstance(row['rx_pps'], int) and isinstance(row['tx_kbps'], float)
    # BW 1000000 Kbit/sec: percent = bits / (BW * 1000) * 100.
    assert row['rx_percent'] == round(row['rx_kbps'] * 1000 / (1000000 * 10), 3)


def test_one_port_rates_use_the_bounded_read(monkeypatch):
    auth, calls = transport(monkeypatch, {'show interfaces GigabitEthernet0/1': real('interface_details_gi01')})
    result = engine.switch_read(auth, 'port_rates', interface='Gi0/1')
    assert calls[-1] == 'show interfaces GigabitEthernet0/1' and 'show interfaces' not in calls
    assert [row['port'] for row in result['records']] == ['GigabitEthernet0/1'] and result['coverage']['complete']


def test_unknown_line_in_interface_details_keeps_rates_incomplete():
    text = real('interface_details_gi01') + '  Unknown rate line 5\n'  # DERIVED
    result = tables.parse('cisco_ios', 'port_rates', 'interface_details', text)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']


def test_enrolled_port_counters_are_two_bounded_reads_with_delta(monkeypatch):
    errors = 'show interfaces GigabitEthernet0/1 counters errors'
    details = 'show interfaces GigabitEthernet0/1'
    enabled = ('interface_errors', 'interface_details', 'interfaces_counters_errors', 'interfaces_details')
    # IOSvL2 prints nothing for the per-port counters table: the bounded details are the source.
    auth, calls = transport(monkeypatch, {errors: real('interface_errors_gi01'), details: real('interface_details_gi01')},
                            enabled=enabled)
    first = engine.switch_read(auth, 'interface_errors', interface='GigabitEthernet0/1')
    assert [c for c in calls if c != 'show version'] == [errors, details]
    assert first['status'] == 'ok' and first['counter_baseline'], first
    row, = first['records']
    assert row['port'] == 'GigabitEthernet0/1' and row['crc'] == 0 and row['rx_errors'] == 0
    assert [source['status'] for source in first['sources']] == ['empty', 'ok']
    # DERIVED: the same capture with growing CRC/input errors, as a later read would print them.
    grown = real('interface_details_gi01').replace('0 input errors, 0 CRC', '6 input errors, 4 CRC', 1)
    transport(monkeypatch, {errors: real('interface_errors_gi01'), details: grown}, enabled=enabled)
    second = engine.switch_read(auth, 'interface_errors', interface='GigabitEthernet0/1', baseline=first['counter_baseline'])
    assert second['status'] == 'ok', second
    row, = second['records']
    assert (row['delta']['rx_errors'], row['delta']['crc']) == (6, 4)
    assert second['summary']['baseline']['ports_increased'] == 1


def test_unenrolled_port_keeps_the_whole_table_reads(monkeypatch):
    auth, calls = transport(monkeypatch, {'show interfaces counters errors': real('interfaces_counters_errors'),
                                          'show interfaces': real('interfaces_details')},
                            enabled=('interface_errors', 'interface_details', 'interfaces_counters_errors', 'interfaces_details'),
                            inventory={'interfaces': ()})
    result = engine.switch_read(auth, 'interface_errors', interface='GigabitEthernet0/1')
    assert [c for c in calls if c != 'show version'] == ['show interfaces counters errors', 'show interfaces']
    assert [row['port'] for row in result['records']] == ['GigabitEthernet0/1']


# --- documented LACP members (IOS-C010) -------------------------------------------------------------------

@pytest.mark.parametrize('fixture,group,ports', [
    ('lacp_internal', 1, ['GigabitEthernet2/0/1', 'GigabitEthernet2/0/2']),
    ('lacp_internal_group5', 5, ['GigabitEthernet5/0/0']),
    ('lacp_internal_interval', 1, ['FastEthernet4/1', 'FastEthernet4/2', 'FastEthernet4/3', 'FastEthernet4/4']),
])
def test_documented_bundled_members(fixture, group, ports):
    result = tables.parse('cisco_ios', 'lag_member', 'lacp_internal', doc(fixture))
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert [row['port'] for row in result['records']] == ports
    assert all(row['group'] == group and row['bundled'] and row['reason'] is None and row['mode'] == 'active'
               for row in result['records'])


def test_documented_member_keys_and_port_state():
    row = tables.parse('cisco_ios', 'lag_member', 'lacp_internal', doc('lacp_internal'))['records'][0]
    assert (row['priority'], row['admin_key'], row['oper_key'], row['port_number'], row['port_state']) == (32768, 3, 3, 4, 0x3D)
    assert row['port_state_flags'] == ['lacp_active', 'aggregatable', 'in_sync', 'collecting', 'distributing']


@pytest.mark.parametrize('state,port_state,expected', [
    ('susp', '0x7D', ['suspended', 'defaulted']),
    ('indep', '0x45', ['individual', 'defaulted', 'not in sync']),
    ('hot-sby', '0x05', ['hot-standby', 'not in sync']),
    ('down', '0x45', ['link down']),
])
def test_not_bundled_member_explains_why(monkeypatch, state, port_state, expected):
    # DERIVED: the documented row with the member state word and port state of a non-bundled member.
    text = doc('lacp_internal').replace('Gi2/0/2    SA      bndl     32768         0x3     0x3       0x5    0x3D',
                                        f'Gi2/0/2    SA      {state:<8} 32768         0x3     0x3       0x5    {port_state}')
    assert state in text
    auth, calls = transport(monkeypatch, {'show lacp internal': text})
    result = engine.switch_read(auth, 'lag_member', interface='GigabitEthernet2/0/2')
    assert calls[-1] == 'show lacp internal'
    row, = result['records']
    assert row['state'] == state and row['bundled'] is False
    assert all(word in row['reason'] for word in expected), row['reason']


def test_unknown_lacp_row_is_not_complete():
    text = doc('lacp_internal') + 'Gi2/0/3    SA      bndl     32768\n'  # DERIVED: cut row
    result = tables.parse('cisco_ios', 'lag_member', 'lacp_internal', text)
    assert result['status'] == 'unparsed' and len(result['unparsed']) == 1


# --- documented PoE detail (IOS-C011) ---------------------------------------------------------------------

def test_documented_poe_detail(monkeypatch):
    result = ssh_read(monkeypatch, 'power_inline_detail', {'interface': 'GigabitEthernet0/0/0'},
                      doc('power_inline_detail'))
    poe = result['poe']
    assert poe['complete'] and poe['oper_status'] == 'on' and poe['ieee_class'] == 4
    assert (poe['admin_value_w'], poe['allocated_w'], poe['available_to_device_w']) == (30.0, 15.4, 15.4)
    assert poe['counters'] == {'absent': 0, 'over_current': 0, 'short_current': 0, 'invalid_signature': 0, 'power_denied': 0}
    assert poe['faults'] == []
    normalized = result['normalized']
    assert normalized['status'] == 'ok' and normalized['coverage']['complete'], normalized
    row, = normalized['records']
    assert row['state'] == 'on' and row['class'] == 4 and row['power_w'] is None and row['fault'] is None


def test_poe_fault_counters_and_table(monkeypatch):
    # DERIVED: the documented output with a power-denied status and nonzero fault counters.
    text = doc('power_inline_detail').replace('Operational status: on', 'Operational status: power-deny')
    text = text.replace('Over Current Counter: 0', 'Over Current Counter: 2').replace('Power Denied Counter: 0', 'Power Denied Counter: 5')
    auth, calls = transport(monkeypatch, {'show power inline GigabitEthernet0/0/0 detail': text})
    result = engine.switch_read(auth, 'poe_port', interface='Gi0/0/0')
    assert calls[-1] == 'show power inline GigabitEthernet0/0/0 detail'
    row, = result['records']
    assert row['fault'] == 'over_current, power_denied, oper_status_power-deny'


def test_poe_unknown_line_is_not_complete():
    detail, unknown = ios_ports.poe_detail(doc('power_inline_detail') + ' 12.5 W\n')  # DERIVED
    assert unknown and detail['interface'] == 'Gi0/0/0'


def test_poe_answer_for_another_port_is_not_this_ports_reading(monkeypatch):
    result = ssh_read(monkeypatch, 'power_inline_detail', {'interface': 'GigabitEthernet0/1'}, doc('power_inline_detail'))
    assert not result['poe']['complete'] and result['poe']['warning'] == 'answer_for_another_interface'
    auth, _ = transport(monkeypatch, {'show power inline GigabitEthernet0/1 detail': doc('power_inline_detail')})
    assert engine.switch_read(auth, 'poe_port', interface='GigabitEthernet0/1')['records'] == []


def test_poe_table_needs_an_interface(monkeypatch):
    auth, _ = transport(monkeypatch, {})
    with pytest.raises(ValueError, match='interface is required'):
        engine.switch_read(auth, 'poe_port')


# --- documented DOM (IOS-C012) ----------------------------------------------------------------------------

def test_documented_dom_values_thresholds_and_alarms(monkeypatch):
    result = ssh_read(monkeypatch, 'interface_transceiver', {'interface': 'GigabitEthernet1/1/1'},
                      doc('interface_transceiver'))
    summary = result['optics']
    readings = summary['readings']
    assert summary['interface'] == 'GigabitEthernet1/1/1'
    assert readings['temperature']['value'] == 29.9 and readings['temperature']['unit'] == 'C'
    assert readings['temperature']['thresholds'] == {'high_alarm': 74.0, 'high_warn': 70.0, 'low_warn': 0.0, 'low_alarm': -4.0}
    assert readings['voltage']['value'] == 3.28 and readings['tx_power']['value'] == 1.8
    assert readings['rx_power']['value'] == -23.5 and readings['rx_power']['status'] == 'normal'
    assert summary['alarms'] == []
    # The documented module prints no bias current table: reported as missing, never invented.
    assert summary['state'] == 'partial' and summary['missing_fields'] == ['tx_bias_current']
    assert readings['tx_bias_current']['value'] is None


@pytest.mark.parametrize('rx,status', [('-29.0', 'low_warning'), ('-33.0', 'low_alarm'), ('-5.0', 'high_alarm')])
def test_dom_threshold_evaluation(rx, status):
    # DERIVED: the documented receive-power row with another reading.
    text = doc('interface_transceiver').replace('Gi1/1/1  -23.5   ', f'Gi1/1/1  {rx:<8}')
    summary = optics.ios_transceiver(text, 'GigabitEthernet1/1/1')
    assert summary['readings']['rx_power']['status'] == status
    assert summary['alarms'] == [f'rx_power: {status}']


def test_dom_device_flag_is_kept():
    text = doc('interface_transceiver').replace('Gi1/1/1  -23.5              -5.0', 'Gi1/1/1  -29.0 -            -5.0')  # DERIVED
    summary = optics.ios_transceiver(text, 'GigabitEthernet1/1/1')
    assert summary['readings']['rx_power']['device_flag'] == 'low_warning'


def test_dom_other_port_or_unknown_line_is_not_measured():
    assert optics.ios_transceiver(doc('interface_transceiver'), 'GigabitEthernet1/1/2')['state'] == 'unparsed'
    summary = optics.ios_transceiver(doc('interface_transceiver') + 'Gi1/1/1 garbage\n', 'GigabitEthernet1/1/1')  # DERIVED
    assert summary['state'] == 'partial' and 'unparsed_lines' in summary['missing_fields']


def test_dom_table_row(monkeypatch):
    auth, _ = transport(monkeypatch, {'show interfaces GigabitEthernet1/1/1 transceiver detail':
                                      doc('interface_transceiver')})
    result = engine.switch_read(auth, 'optics_port', interface='Gi1/1/1')
    row, = result['records']
    assert (row['temperature_c'], row['voltage'], row['tx_dbm'], row['rx_dbm'], row['alerts']) == (29.9, 3.28, 1.8, -23.5, [])
    assert result['coverage']['complete'], result


# --- proxy contracts --------------------------------------------------------------------------------------

def public(tmp_path, auth, tool, inventory_interfaces=PORTS, **arguments):
    proxy = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(proxy, tmp_path)
    section = dict(contracts._section(), ssh_platform='cisco_ios', device_types=['switch'],
                   enabled_queries=list(auth.enabled_queries), read_inventory={'interfaces': list(inventory_interfaces)})
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'cisco_ios')))
    gateway = proxy.Proxy()
    errors = []
    gateway._emit = errors.append
    forwarded = gateway.request(contracts._request(1, tool, {'target': 'device-a', **arguments}))
    if forwarded is None:
        return None, errors
    forwarded_args = json.loads(forwarded)['params']['arguments']
    worker_auth = TargetAuth.decode(forwarded_args.pop('target'), forwarded_args.pop('auth_context'))
    # server.py turns redaction_context into the paged auth; the engine function itself does not take it.
    forwarded_args.pop('redaction_context', None)
    return getattr(engine, tool)(worker_auth, **forwarded_args), errors


@pytest.mark.parametrize('table,interface,command,fixture', [
    ('stp_port_counters', 'GigabitEthernet0/1', 'show spanning-tree interface GigabitEthernet0/1 detail', 'stp_interface_detail_gi01'),
    ('port_rates', 'GigabitEthernet0/1', 'show interfaces GigabitEthernet0/1', 'interface_details_gi01'),
    ('cdp_neighbor', 'GigabitEthernet0/1', 'show cdp neighbors GigabitEthernet0/1 detail', 'cdp_neighbor_interface_gi01'),
    ('lldp_neighbor', 'GigabitEthernet0/1', 'show lldp neighbors GigabitEthernet0/1 detail', 'lldp_neighbor_interface_gi01'),
])
def test_public_switch_read_of_ios_port_tables(tmp_path, monkeypatch, table, interface, command, fixture):
    auth, calls = transport(monkeypatch, {command: real(fixture)})
    result, errors = public(tmp_path, auth, 'switch_read', table=table, interface=interface)
    assert result is not None, errors
    assert calls[-1] == command and result['status'] == 'ok', result


def test_public_poe_and_dom_tables_accept_ios_ports(tmp_path, monkeypatch):
    auth, calls = transport(monkeypatch, {'show power inline GigabitEthernet0/0/0 detail': doc('power_inline_detail')})
    result, errors = public(tmp_path, auth, 'switch_read', table='poe_port', interface='GigabitEthernet0/0/0')
    assert result is not None, errors
    assert result['records'][0]['power_w'] is None


# r4: the portfast edge port Gi0/0 through the public proxy, both tools, real capture.
@pytest.mark.parametrize('enrolled', ['GigabitEthernet0/0', 'Gi0/0'])
def test_public_portfast_edge_port_detail(tmp_path, monkeypatch, enrolled):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    inventory = {'interfaces': (enrolled,)}
    auth, calls = transport(monkeypatch, {command: real('stp_interface_detail_gi00')}, enabled=('stp_interface_detail',),
                            inventory=inventory)
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=(enrolled,), table='stp_port_counters',
                            interface=enrolled)
    assert result is not None, errors
    assert calls[-1] == command and result['ok'] is True
    _assert_gi00_edge(result)
    result, errors = public(tmp_path, auth, 'ssh_read', inventory_interfaces=(enrolled,), platform='cisco_ios',
                            query='stp_interface_detail', parameters={'interface': enrolled}, offset=0, max_bytes=48000)
    assert result is not None, errors
    assert calls[-1] == command
    _assert_gi00_edge(result['normalized'])


# r5 finding 1: the documented PortFast trunk / BPDU filter variants through the public proxy, both tools.
@pytest.mark.parametrize('fixture,portfast,bpdu_filter', VARIANTS, ids=VARIANT_IDS)
def test_public_documented_portfast_and_bpdu_filter(tmp_path, monkeypatch, fixture, portfast, bpdu_filter):
    command = 'show spanning-tree interface GigabitEthernet0/0 detail'
    auth, calls = transport(monkeypatch, {command: _gi00_with(fixture, bpdu_filter)}, enabled=('stp_interface_detail',),
                            inventory={'interfaces': ('Gi0/0',)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=('Gi0/0',), table='stp_port_counters',
                            interface='Gi0/0')
    assert result is not None, errors
    assert calls[-1] == command and result['ok'] is True
    _assert_gi00_variant(result, portfast, bpdu_filter)
    result, errors = public(tmp_path, auth, 'ssh_read', inventory_interfaces=('Gi0/0',), platform='cisco_ios',
                            query='stp_interface_detail', parameters={'interface': 'Gi0/0'}, offset=0, max_bytes=48000)
    assert result is not None, errors
    assert calls[-1] == command
    _assert_gi00_variant(result['normalized'], portfast, bpdu_filter)


# r3 finding 1: the bounded per-port counter reads need only the queries the worker uses for that port.
@pytest.mark.parametrize('interface,enrolled', [('GigabitEthernet0/1', 'GigabitEthernet0/1'), ('Gi0/1', 'Gi0/1'),
                                                ('GigabitEthernet0/1', 'Gi0/1')])
def test_public_bounded_interface_errors_without_whole_table_queries(tmp_path, monkeypatch, interface, enrolled):
    errors_command = 'show interfaces GigabitEthernet0/1 counters errors'
    details = 'show interfaces GigabitEthernet0/1'
    auth, calls = transport(monkeypatch, {errors_command: real('interface_errors_gi01'), details: real('interface_details_gi01')},
                            enabled=('interface_errors', 'interface_details'), inventory={'interfaces': (enrolled,)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=(enrolled,), table='interface_errors',
                            interface=interface)
    assert result is not None, errors
    assert [c for c in calls if c != 'show version'] == [errors_command, details]
    assert result['status'] == 'ok' and [row['port'] for row in result['records']] == ['GigabitEthernet0/1'], result


def test_public_bounded_interface_errors_with_only_the_details_query(tmp_path, monkeypatch):
    details = 'show interfaces GigabitEthernet0/1'
    auth, calls = transport(monkeypatch, {details: real('interface_details_gi01')},
                            enabled=('interface_details',), inventory={'interfaces': ('GigabitEthernet0/1',)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=('GigabitEthernet0/1',),
                            table='interface_errors', interface='GigabitEthernet0/1')
    assert result is not None, errors
    assert [c for c in calls if c != 'show version'] == [details]
    assert result['status'] == 'ok' and result['records'][0]['port'] == 'GigabitEthernet0/1', result


@pytest.mark.parametrize('allow_details', [True, False], ids=['fallback-allowed', 'fallback-denied'])
def test_public_enrolled_interface_errors_authorizes_whole_switch_fallback(tmp_path, monkeypatch, allow_details):
    queries = ('interfaces_counters_errors', 'interfaces_details') if allow_details else ('interfaces_counters_errors',)
    counters, details = 'show interfaces counters errors', 'show interfaces'
    auth, calls = transport(monkeypatch, {counters: real('interfaces_counters_errors'),
                                          details: real('interfaces_details')},
                            enabled=queries, inventory={'interfaces': ('Gi0/1',)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=('Gi0/1',), table='interface_errors',
                            interface='Gi0/1')
    if not allow_details:
        assert result is None and not calls, result
        [error] = errors
        assert error['error']['data']['category'] == 'policy_scope'
        assert error['error']['data']['field'] == 'enabled_queries'
        return

    assert result is not None and not errors, errors
    assert [call for call in calls if call != 'show version'] == [counters, details]
    assert [source['query'] for source in result['sources']] == list(queries)
    assert result['ok'] and result['status'] == 'ok', result
    [row] = result['records']
    assert row['port'] == 'GigabitEthernet0/1'
    assert (row['rx_errors'], row['crc'], row['tx_errors']) == (0, 0, 0)


# r5 (review 483-r4-rv finding 2): with a mixed set of enabled queries the worker uses for an enrolled port exactly
# the per-port queries the proxy authorized; it never adds a whole-switch read the proxy did not check.
@pytest.mark.parametrize('interface', ['Gi0/1', 'GigabitEthernet0/1'])
def test_public_one_port_errors_without_details_query_never_reads_the_whole_switch(tmp_path, monkeypatch, interface):
    errors_command = 'show interfaces GigabitEthernet0/1 counters errors'
    auth, calls = transport(monkeypatch, {errors_command: real('interface_errors_gi01'),
                                          'show interfaces': real('interfaces_details')},
                            enabled=('interface_errors', 'interfaces_details'), inventory={'interfaces': ('Gi0/1',)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=('Gi0/1',), table='interface_errors',
                            interface=interface)
    assert result is not None, errors
    assert [c for c in calls if c != 'show version'] == [errors_command]
    # IOSvL2 prints nothing for the per-port counters: no evidence, and the reason is stated.
    assert result['ok'] is False and not result['coverage']['complete'] and result['records'] == [], result
    assert 'one_port_details_query_not_enabled' in result['warnings'], result
    assert 'interface_details' in result['hint'] and 'show interfaces' in result['hint'], result
    assert [source['query'] for source in result['sources']] == ['interface_errors']


def test_public_one_port_errors_without_errors_query_never_reads_the_whole_counters(tmp_path, monkeypatch):
    details = 'show interfaces GigabitEthernet0/1'
    auth, calls = transport(monkeypatch, {details: real('interface_details_gi01'),
                                          'show interfaces counters errors': real('interfaces_counters_errors')},
                            enabled=('interface_details', 'interfaces_counters_errors'),
                            inventory={'interfaces': ('GigabitEthernet0/1',)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=('GigabitEthernet0/1',),
                            table='interface_errors', interface='Gi0/1')
    assert result is not None, errors
    assert [c for c in calls if c != 'show version'] == [details]
    assert result['status'] == 'ok' and [row['port'] for row in result['records']] == ['GigabitEthernet0/1'], result


def test_one_port_errors_use_only_the_per_port_queries_in_the_engine(monkeypatch):
    # The worker path alone (no proxy): an enrolled port with both whole-switch queries also enabled.
    errors_command = 'show interfaces GigabitEthernet0/1 counters errors'
    auth, calls = transport(monkeypatch, {errors_command: real('interface_errors_gi01'),
                                          'show interfaces': real('interfaces_details'),
                                          'show interfaces counters errors': real('interfaces_counters_errors')},
                            enabled=('interface_errors', 'interfaces_counters_errors', 'interfaces_details'),
                            inventory={'interfaces': ('GigabitEthernet0/1',)})
    result = engine.switch_read(auth, 'interface_errors', interface='GigabitEthernet0/1')
    assert [c for c in calls if c != 'show version'] == [errors_command]
    assert result['ok'] is False and 'one_port_details_query_not_enabled' in result['warnings'], result


def test_public_interface_errors_still_needs_a_query_the_worker_can_use(tmp_path, monkeypatch):
    # Not enrolled: the worker would read the whole tables, so their query stays required.
    auth, calls = transport(monkeypatch, {}, enabled=('interface_errors', 'interface_details'), inventory={'interfaces': ()})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=(), table='interface_errors',
                            interface='GigabitEthernet0/1')
    assert result is None and errors and not calls


# r3 findings 2 and 4: the short and the full name of one enrolled port are the same port.
_STP_GI00 = real('stp_detail').split('\n Port 1 (GigabitEthernet0/0) of VLAN0099', 1)[1]
SHORT_ENROLLED = [
    ('cdp_neighbor', 'Gi0/1', 'show cdp neighbors GigabitEthernet0/1 detail', real('cdp_neighbor_interface_gi01')),
    ('lldp_neighbor', 'Gi0/1', 'show lldp neighbors GigabitEthernet0/1 detail', real('lldp_neighbor_interface_gi01')),
    ('stp_port_counters', 'Gi0/1', 'show spanning-tree interface GigabitEthernet0/1 detail', real('stp_interface_detail_gi01')),
    ('port_rates', 'Gi0/1', 'show interfaces GigabitEthernet0/1', real('interface_details_gi01')),
    # DERIVED: the Gi0/0 root-port block of the real whole detail, as the per-port command prints it.
    ('stp_port_counters', 'Gi0/0', 'show spanning-tree interface GigabitEthernet0/0 detail',
     '\n Port 1 (GigabitEthernet0/0) of VLAN0099' + _STP_GI00),
    # r4: the real one-port capture of the portfast edge port Gi0/0.
    ('stp_port_counters', 'Gi0/0', 'show spanning-tree interface GigabitEthernet0/0 detail', real('stp_interface_detail_gi00')),
    ('poe_port', 'Gi0/0/0', 'show power inline GigabitEthernet0/0/0 detail', doc('power_inline_detail')),
    ('optics_port', 'Gi1/1/1', 'show interfaces GigabitEthernet1/1/1 transceiver detail', doc('interface_transceiver')),
]


@pytest.mark.parametrize('full', [False, True], ids=['short', 'full'])
@pytest.mark.parametrize('table,enrolled,command,body', SHORT_ENROLLED, ids=[f'{c[0]}-{c[1]}-{i}' for i, c in enumerate(SHORT_ENROLLED)])
def test_public_switch_read_matches_short_enrolled_port(tmp_path, monkeypatch, table, enrolled, command, body, full):
    interface = enrolled.replace('Gi', 'GigabitEthernet') if full else enrolled
    auth, calls = transport(monkeypatch, {command: body}, inventory={'interfaces': (enrolled,)})
    result, errors = public(tmp_path, auth, 'switch_read', inventory_interfaces=(enrolled,), table=table, interface=interface)
    assert result is not None, errors
    assert calls[-1] == command and result['status'] == 'ok' and result['records'], result
    port = enrolled.replace('Gi', 'GigabitEthernet')
    assert all(row.get('port', row.get('local_port')) == port for row in result['records']), result


@pytest.mark.parametrize('query,enrolled,other,canonical', [
    ('cdp_neighbor_interface', 'Gi0/1', 'GigabitEthernet0/1', 'GigabitEthernet0/1'),
    ('lldp_neighbor_interface', 'Gi0/1', 'GigabitEthernet0/1', 'GigabitEthernet0/1'),
    ('stp_interface_detail', 'GigabitEthernet0/0', 'Gi0/0', 'GigabitEthernet0/0'),
    ('power_inline_detail', 'Gi0/0/0', 'GigabitEthernet0/0/0', 'GigabitEthernet0/0/0'),
    ('interface_transceiver', 'GigabitEthernet1/1/1', 'Gi1/1/1', 'GigabitEthernet1/1/1'),
])
def test_render_accepts_either_name_of_an_enrolled_port(query, enrolled, other, canonical):
    for name in (enrolled, other):
        command = render_read_query('cisco_ios', query, {'interface': name}, {'interfaces': (enrolled,)})[1]
        assert f' {canonical} ' in command + ' '
    with pytest.raises(ValueError):
        render_read_query('cisco_ios', query, {'interface': 'Gi0/2'}, {'interfaces': (enrolled,)})
