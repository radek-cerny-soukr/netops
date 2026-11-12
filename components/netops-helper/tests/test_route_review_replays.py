"""A20 B2/B3: connected gateways and active route entries."""
import json
import pytest

from netops_helper import engine, port_vlan
from test_locate_acceptance_107 import forti_outputs, SERIALS, AP_IP, REAL
from review_replay_support import device, configure, locate, switch


@pytest.mark.parametrize('whole', [False, True])
def test_nxos_connected_and_local_routes_have_no_ip_gateway(tmp_path, monkeypatch, whole):
    from netops_helper.query_catalog import READ_QUERIES
    root = REAL / 'cisco_nxos/nexus9300v_9.3.12'
    query = 'route_table' if whole else 'route_lookup'
    command = READ_QUERIES['cisco_nxos'][query].command.format(address='192.0.2.1')
    gate = device('gate', 'cisco_nxos', [query], addresses=['192.0.2.1'])
    outputs = {'show version': (root / 'version.txt').read_text(),
               command: (root / ('route_table.txt' if whole else 'route_lookup_connected.txt')).read_text()}
    proxy, code, _ = configure(tmp_path, monkeypatch, [gate], {'gate': outputs})
    with monkeypatch.context() as scoped:
        scoped.setattr(engine, 'host_key_line', engine.host_key_line)
        scoped.setattr(engine, '_lane_directory', engine._lane_directory)
        scoped.setattr(engine.core_ssh, 'run_command', engine.core_ssh.run_command)
        result = switch(proxy, code, scoped, {'table': 'route', **({} if whole else {'ip': '192.0.2.1'})})
    assert result['status'] == 'ok', result
    connected = [r for r in result['records'] if r['protocol'] in ('connected', 'local')]
    assert connected and all(r['next_hop'] is None and r['interface'] for r in connected)
    assert any(r['prefix'] == '192.0.2.0/24' and r['interface'] == 'Vlan10' for r in connected)
    if whole:
        assert any(r['next_hop'] for r in result['records'] if r['protocol'] not in ('connected', 'local'))


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
@pytest.mark.parametrize('backup_first', [False, True])
@pytest.mark.parametrize('ipv6', [False, True])
def test_junos_lookup_returns_only_active_entry_and_all_its_hops(tmp_path, monkeypatch, profile, backup_first, ipv6):
    from netops_helper.query_catalog import READ_QUERIES
    root = REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7'
    captured = (root / 'route_lookup_ospf.txt').read_text()
    header, active = captured.split('        *OSPF', 1)
    # Synthetic backup entry and second next hop of the captured active OSPF entry.
    active = '        *OSPF' + active
    active = active.replace('                Session Id:', '                Next hop: 192.0.2.3 via irb.20, selected\n                Session Id:', 1)
    backup = '         Static Preference: 200\n                Next hop: 192.0.2.2 via irb.10, selected\n                State: <Int Ext>\n'
    text = header.replace('(1 entry, 1 announced)', '(2 entries, 1 announced)') + (backup + active if backup_first else active + backup)
    ip = '203.0.113.1'
    if ipv6:
        text = text.replace('inet.0:', 'inet6.0:').replace('203.0.113.1/32', '2001:db8:1::1/128')
        for old,new in [('192.0.2.1', '2001:db8::1'), ('192.0.2.2', '2001:db8::2'), ('192.0.2.3', '2001:db8::3')]:
            text = text.replace(old, new)
        ip = '2001:db8:1::1'
    query = 'ipv6_route_lookup' if ipv6 else 'route_lookup'
    # Junos uses a family-specific validated IP slot.
    command = READ_QUERIES[profile][query].command.format(address=ip)
    gate = device('gate', profile, [query], addresses=[ip])
    outputs = {'show version | no-more': (root / 'version.txt').read_text(), command: text}
    version_query = READ_QUERIES[profile]['version'].command
    outputs[version_query] = (root / 'version.txt').read_text()
    proxy, code, _ = configure(tmp_path, monkeypatch, [gate], {'gate': outputs})
    with monkeypatch.context() as scoped:
        scoped.setattr(engine, 'host_key_line', engine.host_key_line)
        scoped.setattr(engine, '_lane_directory', engine._lane_directory)
        scoped.setattr(engine.core_ssh, 'run_command', engine.core_ssh.run_command)
        result = switch(proxy, code, scoped, {'table': 'route', 'ip': ip})
    assert result['status'] == 'ok', result
    assert {(r['next_hop'], r['protocol']) for r in result['records']} == {
        ('2001:db8::1' if ipv6 else '192.0.2.1', 'ospf'), ('2001:db8::3' if ipv6 else '192.0.2.3', 'ospf')}
