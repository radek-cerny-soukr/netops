"""G06 through the public MCP bridge and private worker decoder, over captured CLI."""
import asyncio
import json
import re
from pathlib import Path

import pytest

from netops import worker
from netops_helper import endpoint_worker, engine, proxy, server
from test_proxy_contracts import _device, _inventory, _section, _vault_document, _write


FIXTURES = Path(__file__).with_name('fixtures') / 'real' / 'g06_20261120'
KUFR = json.loads((FIXTURES / 'kufr.json').read_text())
ENDPOINT = KUFR['endpoint']
LEASE = 'execute dhcp lease-list ap-mgmt'
ARP = 'get system arp'
SERIALS = ('S000SSSS00000001', 'S000SSSS00000002')
FORTI_QUERIES = ('system_status', 'dhcp_leases', 'user_devices', 'arp_table', 'managed_switch_mac',
                 'managed_switch_lldp', 'managed_switch_port_stats', 'managed_switch_port_vlans', 'interface_vlan_ids')
EXOS_QUERIES = ('version', 'mac_table', 'lldp_neighbors_detail', 'ports', 'lag_summary', 'dns_lookup')


@pytest.fixture
def public(tmp_path, monkeypatch):
    helper = tmp_path / 'helper'
    helper.mkdir(mode=0o700)
    monkeypatch.setattr(worker, 'STATE', tmp_path)
    monkeypatch.setattr(proxy, 'INVENTORY', helper / 'inventory.json')
    _write(helper / 'vault.json', _vault_document(), 0o600)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    monkeypatch.setattr(endpoint_worker, 'call', lambda targets, endpoint, context:
                        engine._locate_endpoint_run(endpoint_worker.decode(targets, context), endpoint))
    gate = _section()
    gate.update(enabled_queries=FORTI_QUERIES, device_types=['firewall'],
                read_inventory={'interfaces': ['ap-mgmt'], 'managed_switches': list(SERIALS)})
    switch = _section()
    switch.update(ssh_platform='exos', enabled_queries=EXOS_QUERIES, device_types=['switch'],
                  read_inventory={'diagnostic_names': ['example.com', 'g06-absent.invalid']})
    switch['egress'].update(addresses=['192.0.2.11'], tls_server_names=[])
    _write(helper / 'inventory.json', _inventory(
        dict(_device(gate), name='gate'),
        dict(_device(switch, 'exos'), name='x440', address='192.0.2.11')))
    switch_commands = json.loads((FIXTURES / 'x440.json').read_text())
    commands = {'gate': dict(KUFR['commands']), 'x440': switch_commands}
    reads = []

    def device(auth, profile, command):
        reads.append((auth.alias, command))
        return 0, commands[auth.alias][command]

    monkeypatch.setattr(engine, 'read_from_device', device)

    def call(endpoint, targets=('gate',)):
        bridge = worker.HelperBridge()
        reply = asyncio.run(bridge.call(server.mcp, 'locate_endpoint', {'targets': list(targets), 'endpoint': endpoint}))
        assert reply['isError'] is False, reply
        result = reply['structuredContent']
        for alias, count in result['limits']['target_reads'].items():
            assert len(bridge.proxy.rate_history[alias]) == count
        return result

    return call, commands, reads


def test_hostname_lease_arp_and_fortilink_fdb_at_public_entry_point(public):
    call, _, reads = public
    result = call(ENDPOINT['hostname'].upper() + '.')
    assert result['endpoint'] == {'hostname': ENDPOINT['hostname']}
    assert (result['resolution']['ip'], result['resolution']['mac']) == (ENDPOINT['ip'], ENDPOINT['mac'])
    assert {r['table'] for r in result['resolution']['evidence']} >= {'dhcp_lease', 'neighbor_l3'}
    assert all(r['sources'] and r['captured_at'] for r in result['vantage'])
    assert result['verdict'] == 'located', result
    assert [(f['port'], f['vlan_id']) for f in result['findings'] if f['edge']] == [('port3', 100)]
    assert sum(command == ARP for _, command in reads) == 1


def test_untested_firmware_warns_and_keeps_the_location(public):
    call, commands, _ = public
    status = 'get system status'
    commands['gate'][status] = commands['gate'][status].replace('build0251', 'build9251')
    result = call(ENDPOINT['hostname'])
    assert result['verdict'] == 'located'
    sources = [v for v in result['vantage'] if v.get('firmware_support')]
    assert sources and all(v['firmware_support']['status'] == 'untested' for v in sources)
    assert all(any(isinstance(warning, dict) and warning['code'] == 'firmware_untested'
                   for warning in v['warnings']) for v in sources)


def test_fortios_redrawn_command_echo_is_removed_before_parsing(public):
    call, commands, _ = public
    for query in ('mac-table', 'port-stats'):
        command = f'diagnose switch-controller switch-info {query} {SERIALS[0]}'
        split = command.index(SERIALS[0]) + (3 if query == 'mac-table' else 2)
        echo = command[:split] + ' \b' + command[split:]
        commands['gate'][command] = echo + '\n' + commands['gate'][command]
    assert call(ENDPOINT['hostname'])['verdict'] == 'located'


def test_fortios_mac_table_count_mismatch_prevents_edge_confirmation(public):
    call, commands, _ = public
    command = f'diagnose switch-controller switch-info mac-table {SERIALS[0]}'
    commands['gate'][command] = re.sub(r'Total Displayed:\s*\d+', 'Total Displayed: 15', commands['gate'][command])
    result = call(ENDPOINT['hostname'])
    assert result['verdict'] == 'incomplete'
    assert not any(f['edge'] for f in result['findings'])


@pytest.mark.parametrize('variant', ['absent', 'partial', 'refused', 'conflict', 'arp_conflict'])
def test_incomplete_or_ambiguous_name_never_reaches_switch_port_lookup(public, variant):
    call, commands, reads = public
    end = ENDPOINT['hostname']
    if variant == 'absent':
        end = 'unseen-host'
    elif variant == 'partial':
        commands['gate'][LEASE] += '192.0.2.99\t00:00:5e:00:53:ff\t'
    elif variant == 'refused':
        commands['gate'][LEASE] = KUFR['commands']['execute dhcp lease-list g06-absent']
    elif variant == 'conflict':
        lease = commands['gate'][LEASE]
        line = next(line for line in lease.splitlines() if ENDPOINT['mac'] in line)
        commands['gate'][LEASE] += line.replace(ENDPOINT['ip'], '192.0.2.99') + '\n'
    else:
        commands['gate'][ARP] = commands['gate'][ARP].replace(ENDPOINT['mac'], '00:00:5e:00:53:ff')
    result = call(end)
    assert result['verdict'] == ('ambiguous' if 'conflict' in variant else 'incomplete')
    assert result['findings'] == [] and result['missing']
    assert not any('mac-table' in command for _, command in reads)


def test_enrolled_dns_retains_two_addresses_and_never_invents_a_lease(public):
    call, _, reads = public
    result = call('EXAMPLE.COM', ('x440',))
    assert result['verdict'] == 'ambiguous', result
    assert {r['table'] for r in result['resolution']['evidence']} == {'dns'}
    addresses = {r['ip'] for r in result['resolution']['evidence']}
    assert len(addresses) == 2 and any(':' in address for address in addresses)
    assert reads == [('x440', 'show version'), ('x440', 'nslookup example.com')]
    reads.clear()
    result = call('not-enrolled.example', ('x440',))
    assert reads == [] and result['verdict'] == 'incomplete'


def test_client_fdb_on_ap_port_is_an_observation_when_no_station_source(public):
    call, commands, _ = public
    # Derived replay: use the observed AP port/VLAN layout and an anonymised client
    # MAC in the FDB row, while keeping the independently observed LLDP AP identity.
    mac = '00:00:5e:00:53:fe'
    command = 'diagnose switch-controller switch-info mac-table ' + SERIALS[0]
    commands['gate'][command], count = re.subn(
        rf'(MAC: ){ENDPOINT["mac"]}(\s+VLAN: 100 Port: port3)', rf'\g<1>{mac}\2', commands['gate'][command])
    assert count == 1
    result = call(mac)
    assert result['verdict'] == 'incomplete'
    assert [(f['role'], f['edge'], f['port']) for f in result['findings']] == [('behind_ap', False, 'port3')]
    assert any(gap['reason'] == 'client_ap_association_unverified' for gap in result['missing'])


@pytest.mark.parametrize('device', ['d-exos', 'd-exos-b'])
def test_exos_lag_without_algorithm_stays_transit(public, device):
    call, commands, _ = public
    captures = json.loads((FIXTURES / (device + '.json')).read_text())
    commands['x440'].update(captures)
    mac = next(line.split()[0] for line in captures['show fdb'].splitlines()
               if re.match(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}\s', line) and line.split()[-1] == '5')
    result = call(mac, ('x440',))
    assert result['verdict'] == 'incomplete' and any(f['role'] == 'transit' and f['port'] == '5'
                                                     for f in result['findings'])
    assert not any(f['edge'] for f in result['findings'])
