"""Public Helper IOS XE port diagnostics against lab and Cisco CLI captures."""

import json
import re
from pathlib import Path

import pytest

from netops.files import write_private
from netops_core.ssh import Result
from netops_helper import engine
from netops_helper.query_catalog.cisco import IOS_XE_PORT_QUERIES
from test_config_cisco_xe_public import ADDRESS, _call, _device, _xe_section, env  # noqa: F401


FIXTURES = Path(__file__).parent / 'fixtures'
LAB = FIXTURES / 'real/cisco_xe/xe-ports'
DOCS = FIXTURES / 'docs/cisco_xe/xe-ports'
TARGET = 'router-b'
PORTS = ['Ethernet0/0', 'Ethernet0/1', 'Ethernet0/2', 'Ethernet2/0',
         'GigabitEthernet1/1/1', 'TenGigabitEthernet3/0/1', 'TenGigabitEthernet1/0/1']


def raw(name, node='iol-xe-switch', role='admin'):
    return (LAB / node / role / (name + '.out')).read_text()


def documented(name):
    return (DOCS / (name + '.out')).read_text()


@pytest.fixture
def public(env, monkeypatch):
    section = _xe_section(TARGET)
    section.update(enabled_queries=['version', 'interface_details', 'interface_errors',
                                   'interface_transceiver', *IOS_XE_PORT_QUERIES],
                   device_types=['router', 'switch'], rate_limit={'requests': 60, 'window_seconds': 60})
    section['read_inventory']['interfaces'] = PORTS
    write_private(env['helper'] / 'inventory.json',
                  json.dumps({'version': 2, 'devices': [_device(TARGET, 'cisco_xe', section)]}).encode(), replace=True)
    calls, outputs = [], {'show version': raw('version')}

    def read(host, port, login, credential, host_key_line, command, **options):
        calls.append(command)
        item = outputs[command]
        return item if isinstance(item, Result) else Result(0, item.encode(), '', 'start', 'end')

    monkeypatch.setattr(engine.core_ssh, 'run_command', read)

    def call(tool, **args):
        response = _call(env, tool, {'target': TARGET, **args})
        assert isinstance(response, dict), response
        return response.get('structuredContent') or response

    return call, calls, outputs


def ssh(call, query, **parameters):
    return call('ssh_read', platform='cisco_xe', query=query, parameters=parameters)


def test_counter_delta_on_enrolled_xe_router_port(public):
    call, commands, output = public
    command = 'show interfaces Ethernet0/1'
    body = raw('interface_details', node='iol-xe-router')
    output[command] = body
    first = call('switch_read', table='interface_errors', interface='Ethernet0/1')
    assert first.get('coverage', {}).get('complete'), first
    assert first['counter_baseline']
    assert first['records'][0]['rx_octets'] == int(re.search(r'packets input, (\d+)', body)[1])

    # DERIVED: more receive octets and CRC errors in the same lab response.
    output[command] = re.sub(r'(packets input, )(\d+)', lambda m: m[1] + str(int(m[2]) + 1200), body)
    output[command] = output[command].replace('0 input errors, 0 CRC', '2 input errors, 2 CRC')
    current = call('switch_read', table='interface_errors', interface='Ethernet0/1',
                   baseline=first['counter_baseline'])
    assert current['coverage']['complete'], current
    [row] = current['records']
    assert row['interval_traffic']['rx']['octets_delta'] == 1200
    assert row['interval_traffic']['rx']['bits_per_second'] > 0
    assert row['interval_traffic']['rx']['utilization_percent'] is None
    assert row['delta']['crc'] == 2 and row['errors_per_minute']['crc'] > 0
    assert row['delta']['link_flaps'] is None
    assert set(commands) == {'show version', command}
    output[command] = body.split('packets output,')[0]
    result = call('switch_read', table='interface_errors', interface='Ethernet0/1')
    assert not result['coverage']['complete'] and result['counter_baseline'] is None


def test_interval_utilization_uses_the_documented_negotiated_speed(public):
    call, _, output = public
    port = 'TenGigabitEthernet1/0/1'
    command = f'show interfaces {port}'
    # DERIVED: only the ESS port name changes to the enrolled Catalyst port grammar.
    body = documented('negotiated_speed').replace('TenGigabitEthernet1/1', port)
    output[command] = body
    first = call('switch_read', table='interface_errors', interface=port)
    assert first['records'][0]['link_speed_bps'] == 1_000_000_000
    # DERIVED: another sample on the same link has received more octets.
    output[command] = body.replace('4750634 bytes', '5750634 bytes')
    result = call('switch_read', table='interface_errors', interface=port, baseline=first['counter_baseline'])
    assert result['coverage']['complete'], result
    [row] = result['records']
    rx = row['interval_traffic']['rx']
    assert rx['octets_delta'] == 1_000_000
    assert rx['utilization_percent'] == pytest.approx(rx['bits_per_second'] / 10_000_000, abs=1e-6)


def test_stp_topology_and_port_through_public_mcp(public):
    call, _, output = public
    output['show spanning-tree detail'] = raw('stp_detail')
    result = call('switch_read', table='stp_topology')
    assert result.get('coverage', {}).get('complete'), result
    assert {row['instance'] for row in result['records']} == {'VLAN0001', 'VLAN0099'}
    assert all(row['topology_changes'] > 0 for row in result['records'])

    command = 'show spanning-tree interface Ethernet2/0 detail'
    output[command] = raw('stp_interface_detail_active')
    result = call('switch_read', table='stp_port_counters', interface='Ethernet2/0')
    [row] = result['records']
    assert result.get('coverage', {}).get('complete'), result
    assert (row['port'], row['cost'], row['state']) == ('Ethernet2/0', 100, 'forwarding')
    output[command] = raw('stp_interface_detail_active', role='ro')
    assert call('switch_read', table='stp_port_counters', interface='Ethernet2/0')['status'] == 'permission_denied'

    output['show spanning-tree mst'] = raw('stp_mst')
    assert 'not in mst mode' in ssh(call, 'stp_mst')['untrusted_device_output']


def test_lacp_detail_hash_and_scope(public):
    call, commands, output = public
    output['show lacp internal'] = documented('lacp')
    result = call('switch_read', table='lag_member')
    assert result.get('coverage', {}).get('complete'), result
    assert len(result['records']) == 2 and all(row['bundled'] for row in result['records'])
    # DERIVED: documented suspended member state and actor defaulted bit.
    output['show lacp internal'] = documented('lacp').replace('bndl', 'susp', 1).replace('0x3D', '0x45', 1)
    failed = call('switch_read', table='lag_member')
    assert 'partner information defaulted' in failed['records'][0]['reason']

    output['show etherchannel load-balance'] = raw('etherchannel_load_balance')
    result = ssh(call, 'etherchannel_load_balance')['load_balance']
    assert result['status'] == 'ok' and result['method'] == 'src-dst-ip'
    output['show etherchannel 1 detail'] = raw('etherchannel_group_1')
    assert ssh(call, 'etherchannel_detail', group_id='1')['etherchannel'] == {
        'group': 1, 'status': 'empty', 'complete': True,
    }
    output['show etherchannel 1 detail'] = documented('etherchannel_group')
    details = ssh(call, 'etherchannel_detail', group_id='1')['etherchannel']
    assert details['port_count'] == 2 and details['protocol'] == 'LACP' and details['port_channels'] == ['Po1']
    assert details['status'] == 'unparsed' and not details['complete']
    count = len(commands)
    for group in ('0', '129', '01', '1 detail'):
        response = ssh(call, 'etherchannel_detail', group_id=group)
        assert response.get('isError') is True
    assert len(commands) == count


@pytest.mark.parametrize('rc,stdout,known_notice,empty', [
    (0, b'\r\n\r\n', True, True),
    (0, b'', True, False),
    (0, b'\r\n\r\n', False, False),
    (1, b'\r\n\r\n', True, False),
])
def test_empty_channel_exec_requires_success_and_exact_peer_notice(public, rc, stdout, known_notice, empty):
    call, _, output = public
    # Live IOL-L2 returned two CRLFs and the OpenSSH close notice after a successful exec.
    # Other combinations are DERIVED transport error cases.
    sender = ADDRESS[TARGET] if known_notice else '192.0.2.99'
    notice = f'Connection to {sender} closed by remote host.\n'.encode()
    output['show etherchannel 1 detail'] = Result(rc, stdout, '', 'start', 'end', stderr=notice)
    result = ssh(call, 'etherchannel_detail', group_id='1')
    if empty:
        assert result['etherchannel']['status'] == 'empty' and result['ok'], result
    else:
        assert result['error_code'] == 'device_cli_error' and not result['ok'], result


@pytest.mark.parametrize('table,command,fixture,port', [
    ('cdp_neighbor', 'show cdp neighbors Ethernet0/2 detail', 'cdp_neighbor_interface_2', 'Ethernet0/2'),
    ('lldp_neighbor', 'show lldp neighbors Ethernet0/1 detail', 'lldp_neighbor_interface', 'Ethernet0/1'),
])
def test_scoped_neighbors_require_complete_advertised_total(public, table, command, fixture, port):
    call, commands, output = public
    body = raw(fixture, node='iol-xe-router')
    output[command] = body
    result = call('switch_read', table=table, interface=port)
    [row] = result['records']
    assert result.get('coverage', {}).get('complete'), result
    assert row['local_port'] == port and row['neighbor'] and commands[-1] == command
    # DERIVED: cut the final footer at a line boundary.
    output[command] = '\n'.join(body.strip().splitlines()[:-1]) + '\n'
    result = call('switch_read', table=table, interface=port)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    count = len(commands)
    response = call('switch_read', table=table, interface='Ethernet0/3')
    assert response.get('isError') is True
    assert len(commands) == count


def test_poe_four_pair_allocation_and_faults(public):
    call, _, output = public
    port = 'TenGigabitEthernet3/0/1'
    command = f'show power inline {port} detail'
    body = documented('poe')
    output[command] = body
    response = ssh(call, 'power_inline_detail', interface=port)
    assert response['firmware_support']['status'] == 'untested'
    assert response['poe']['complete'], response
    assert response['poe']['allocated_w'] == 60
    assert response['poe']['measured_w'] == 6.7
    assert response['poe']['faults'] == []
    assert call('switch_read', table='poe_port', interface=port)['records'][0]['power_w'] == 6.7

    # DERIVED: change one documented fault counter and omit the allocation line.
    output[command] = body.replace('Power Denied Counter: 0', 'Power Denied Counter: 2')
    assert ssh(call, 'power_inline_detail', interface=port)['poe']['faults'] == ['power_denied']
    output[command] = body.replace('Power drawn from the source: 60.0\n', '')
    assert not ssh(call, 'power_inline_detail', interface=port)['poe']['complete']


def test_dom_thresholds_and_truncation(public):
    call, _, output = public
    port = 'GigabitEthernet1/1/1'
    command = f'show interfaces {port} transceiver detail'
    body = documented('transceiver')
    output[command] = body
    optics = ssh(call, 'interface_transceiver', interface=port)['optics']
    assert optics['state'] == 'measured', optics
    assert optics['readings']['rx_power']['value'] == -23.5
    assert optics['readings']['rx_power']['thresholds']['low_alarm'] == -32.2
    # DERIVED: cross a real low alarm threshold, then cut the last metric.
    output[command] = body.replace('-23.5', '-33.0')
    row = call('switch_read', table='optics_port', interface=port)['records'][0]
    assert row['alerts'] == ['rx_power: low_alarm']
    output[command] = '\n'.join(body.splitlines()[:-1]) + '\n'
    assert not call('switch_read', table='optics_port', interface=port)['coverage']['complete']
