"""G2-29-1: PC-Radek captures via proxy, isolated worker and real engine.

The replay fixture imports neighbors/bridge_fdb/links together from
ref/captures/g2-live-2-linux.json using tests/support/add_capture.py. Dynamic FDB cases below are explicit
synthetic extensions: the live host only supplied static FDB entries.
"""
import json
from pathlib import Path

import pytest

from review_replay_support import configure, device, locate
from support.replay_capture import load
import test_proxy_contracts as c

REAL = Path(__file__).parent / 'fixtures/real'
CAPTURES = {c['query']: c['stdout'] for c in load(REAL / 'scenarios/linux_g2_locate.json')['captures']}
IP, MAC = '192.0.2.36', '00:00:5e:00:53:03'
QUERIES = ['neighbors', 'bridge_fdb', 'links']


def setup(tmp_path, monkeypatch, queries=QUERIES, types=('router', 'switch'), fdb=None, neighbors=None):
    target = device('linux', 'linux', list(queries))
    target['helper']['device_types'] = list(types)
    outputs = {'uname -a': (REAL.parent / 'identity/linux.txt').read_text(),
               'ip neigh show': CAPTURES['neighbors'] if neighbors is None else neighbors,
               'bridge fdb show': CAPTURES['bridge_fdb'] if fdb is None else fdb,
               'ip -brief link': CAPTURES['links']}
    return configure(tmp_path, monkeypatch, [target], {'linux': outputs})


@pytest.mark.parametrize('endpoint', [IP, MAC, 'fe80::10'])
def test_live_linux_neighbor_is_returned_without_claiming_an_edge(tmp_path, monkeypatch, endpoint):
    proxy, _, wire = setup(tmp_path, monkeypatch)
    result = locate(proxy, endpoint, ['linux'])
    assert result['ok'] and result['verdict'] == 'incomplete', result
    expected_ip = 'fe80::10' if endpoint == 'fe80::10' else IP
    expected_mac = '00:00:5e:00:53:0b' if endpoint == 'fe80::10' else MAC
    assert any((r['ip'], r['mac'], r['interface']) == (expected_ip, expected_mac, 'eno1')
               for r in result['neighbors_l3']), result
    assert not result['findings'] and not result['coverage']['complete']
    calls = [json.loads(line)['command'] for line in wire.read_text().splitlines()]
    assert set(calls) == {'uname -a', 'ip neigh show', 'bridge fdb show'}
    assert result['reads'] == len(calls) == 3
    assert result['limits']['target_reads'] == {'linux': 7}


@pytest.mark.parametrize('endpoint', [IP, MAC])
def test_linux_host_without_bridge_reader_retains_neighbor_interface(tmp_path, monkeypatch, endpoint):
    proxy, _, wire = setup(tmp_path, monkeypatch, queries=['neighbors'], types=['router'])
    result = locate(proxy, endpoint, ['linux'])
    assert result['verdict'] == 'incomplete', result
    assert any(r['mac'] == MAC and r['interface'] == 'eno1' for r in result['neighbors_l3'])
    assert {'vantage': None, 'table': 'mac_entry', 'reason': 'no_enrolled_switch_reader'} in result['missing']
    assert 'bridge fdb show' not in wire.read_text()


@pytest.mark.parametrize('endpoint', [IP, MAC])
@pytest.mark.parametrize('suffix', ['', 'NEW UNKNOWN LINE\n'])
def test_linux_bridge_port_is_evidence_with_uncertain_edge(tmp_path, monkeypatch, endpoint, suffix):
    fdb = CAPTURES['bridge_fdb'] + f'{MAC} dev veth1 vlan 10 master br0 dynamic\n' + suffix
    proxy, _, wire = setup(tmp_path, monkeypatch, fdb=fdb)
    result = locate(proxy, endpoint, ['linux'])
    assert result['verdict'] == 'incomplete', result
    finding, = result['findings']
    assert (finding['mac'], finding['port'], finding['vlan_id']) == (MAC, 'veth1', 10)
    assert not finding['edge'] and finding['role'] == 'unverified'
    assert not result['coverage']['complete']
    assert any(m['table'] == 'lldp_neighbor' and m['reason'] == 'unsupported' for m in result['missing'])
    if suffix:
        assert any(m['table'] == 'mac_entry' and m['reason'] == 'unparsed' for m in result['missing'])
    assert 'show mac address-table' not in wire.read_text()


@pytest.mark.parametrize('queries,types', [(['neighbors'], []), (['neighbors'], ['switch']),
                                         (['bridge_fdb'], ['router']), (['links'], ['router', 'switch'])])
def test_linux_locate_keeps_inventory_reader_scope(tmp_path, monkeypatch, queries, types):
    proxy, _, wire = setup(tmp_path, monkeypatch, queries=queries, types=types)
    emitted = []
    monkeypatch.setattr(proxy, '_emit', emitted.append)
    assert proxy.request(c._request(1, 'locate_endpoint', {'targets': ['linux'], 'endpoint': IP})) is None
    assert emitted[-1]['error']['code'] == -32009
    assert not wire.exists()


def test_linux_switch_reader_does_not_enable_neighbor_query(tmp_path, monkeypatch):
    proxy, _, wire = setup(tmp_path, monkeypatch, queries=['bridge_fdb'], types=['switch'])
    result = locate(proxy, IP, ['linux'])
    assert result['verdict'] == 'incomplete'
    assert {'vantage': None, 'table': 'neighbor_l3', 'reason': 'no_enrolled_l3_reader'} in result['missing']
    assert not wire.exists()


@pytest.mark.parametrize('body', ['NEW UNKNOWN LINE\n', 'RTNETLINK answers: Operation not permitted\n'])
def test_linux_neighbor_failure_never_proves_absence(tmp_path, monkeypatch, body):
    proxy, _, _ = setup(tmp_path, monkeypatch, neighbors=body)
    result = locate(proxy, IP, ['linux'])
    assert result['verdict'] == 'incomplete' and not result['coverage']['complete'], result
    assert any(m['table'] == 'neighbor_l3' for m in result['missing'])
    assert not result['findings']


def mixed_outputs(*, switch=True, edge=False, absent=False):
    """Real Linux/IOSvL2 captures with an explicit synthetic access port."""
    root = REAL / 'lab_endpoints_20261110/iosvl2'
    identity = (REAL / 'lab_endpoints/iosvl2/version.txt').read_text()
    linux = device('linux', 'linux', QUERIES if switch else ['neighbors'])
    linux['helper']['device_types'] = ['router', 'switch'] if switch else ['router']
    router = device('router', 'cisco_ios', ['arp_table'])
    router['helper']['device_types'] = ['router']
    devices = [linux, router]
    outputs = {
        'linux': {'uname -a': (REAL.parent / 'identity/linux.txt').read_text(),
                  'ip neigh show': CAPTURES['neighbors'], 'bridge fdb show': CAPTURES['bridge_fdb']},
        'router': {'show version': identity, 'show ip arp': (root / 'arp_table.txt').read_text()},
    }
    if switch:
        sw = device('sw', 'cisco_ios', ['mac_table', 'lldp_neighbors', 'interfaces'])
        sw['helper']['device_types'] = ['switch']
        devices.append(sw)
        interfaces = (root / 'interfaces.txt').read_text()
        if edge:
            # Model an access port instead of the captured lab trunk; no LLDP peer.
            interfaces = '\n'.join(line.replace('trunk', '10') if line.startswith('Gi0/2') else line
                                   for line in interfaces.splitlines()) + '\n'
        outputs['sw'] = {'show version': identity,
                         'show mac address-table': '' if absent else (root / 'mac_table.txt').read_text(),
                         'show lldp neighbors detail': '', 'show interfaces status': interfaces}
    return devices, outputs


@pytest.mark.parametrize('unknown', [False, True])
def test_linux_neighbor_without_bridge_port_keeps_other_switch_located(tmp_path, monkeypatch, unknown):
    devices, outputs = mixed_outputs(edge=True)
    if unknown:
        outputs['linux']['bridge fdb show'] += 'NEW UNKNOWN LINE\n'
    # Only Linux resolves this IP; IOSvL2 independently supplies the matching MAC port.
    proxy, _, wire = configure(tmp_path, monkeypatch, devices, outputs)
    result = locate(proxy, IP, [d['name'] for d in devices])
    assert result['verdict'] == ('incomplete' if unknown else 'located'), result
    assert result['coverage']['complete'] is (not unknown), result
    assert result['missing'] == ([{'vantage': 'linux', 'table': 'mac_entry', 'reason': 'unparsed'}]
                                 if unknown else []), result
    assert any(o['vantage'] == 'linux' and o['ip'] == IP and o['mac'] == MAC
               for o in result['neighbors_l3'])
    finding, = result['findings']
    assert (finding['vantage'], finding['port'], finding['edge']) == ('sw', 'GigabitEthernet0/2', True)
    assert 'bridge fdb show' in wire.read_text()


@pytest.mark.parametrize('mode,arp_expected', [('absent', False), ('transit', True), ('no_switch', True)])
def test_linux_mac_fallback_keeps_existing_arp_reader_conditions(tmp_path, monkeypatch, mode, arp_expected):
    devices, outputs = mixed_outputs(switch=mode != 'no_switch', absent=mode == 'absent')
    proxy, _, wire = configure(tmp_path, monkeypatch, devices, outputs)
    result = locate(proxy, MAC, [d['name'] for d in devices])
    calls = [json.loads(line) for line in wire.read_text().splitlines()]
    assert any(c['command'] == 'ip neigh show' for c in calls)
    assert any(c['command'] == 'show ip arp' for c in calls) is arp_expected
    assert any(o['vantage'] == 'linux' and o['mac'] == MAC for o in result['neighbors_l3'])
    assert result['verdict'] == 'incomplete', result
