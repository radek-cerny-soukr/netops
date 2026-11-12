"""End to end: engine._locate_endpoint_run with read_from_device answering complete device output.

EXOS answers are the anonymised outputs of physical switches (tests/fixtures/real/exos);
IOS XE answers are the complete outputs reproduced from the vendor documentation
(tests/fixtures/docs); IOS and EOS on the GNS3 lab are in test_locate_lab.py. Nothing here replaces a parser result by a hand-made record.
"""
from dataclasses import replace
import json
from pathlib import Path
import shutil

import pytest

from netops_helper import engine
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

ROOT = Path(__file__).parent / 'fixtures'
HOME_1 = ROOT / 'real/exos/x440g2-12p-10g4_33.7.1.6_2'       # first floor: AP, phone, switch, LAG uplink
HOME_2 = ROOT / 'real/exos/x440g2-12p-10g4_33.7.1.6_3'       # attic
EXOS_QUERIES = ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'ports', 'vlan_summary', 'lacp', 'lag_summary')
IOS_QUERIES = ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans')


def exos(alias, directory, types=('switch', 'router')):
    return replace(_target('extreme_exos', 'mac_table'), alias=alias, device_types=types, enabled_queries=EXOS_QUERIES), directory


def answers(directory, profile='extreme_exos'):
    """command -> complete output; the rendered command comes from the catalogue, the text from the files."""
    result = {}
    for name, query in READ_QUERIES[profile].items():
        file = directory / (name + '.txt')
        if not file.exists():
            file = directory / 'captures_20261110_final' / (name + '.txt')
        if file.exists() and not query.slots:
            result[query.command] = file.read_text()
    return result


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)

    def install(*targets):
        by_alias = {auth.alias: answers(directory) for auth, directory in targets}
        calls = []

        def read(auth, profile, command):
            calls.append((auth.alias, command))
            return 0, by_alias[auth.alias][command]
        monkeypatch.setattr(engine, 'read_from_device', read)
        return [auth for auth, _ in targets], calls
    return install


def only(result, key):
    assert len(result[key]) == 1, result[key]
    return result[key][0]


def test_exos_ip_on_an_access_port_is_located(device):
    auths, calls = device(exos('floor1', HOME_1))
    r = engine._locate_endpoint_run(auths, '192.0.2.35')
    finding = only(r, 'findings')
    assert r['verdict'] == 'located', r['missing']
    assert (finding['port'], finding['vlan_id'], finding['role'], finding['edge']) == ('6', 10, 'edge', True)
    assert finding['vlan_name'] == 'V10' and finding['mac'] == '00:00:5e:00:53:11'
    assert calls[0] == ('floor1', 'show version') and sum(c == 'show version' for _, c in calls) == 1
    assert r['reads'] == len(calls)


def test_exos_endpoint_behind_a_phone_is_the_edge_at_the_phone_port(device):
    auths, _ = device(exos('floor1', HOME_1))
    r = engine._locate_endpoint_run(auths, '192.0.2.25')            # LLDP on port 11: "Bridge, Telephone"
    finding = only(r, 'findings')
    assert r['verdict'] == 'located', r['missing']
    assert (finding['port'], finding['role'], finding['behind'], finding['edge']) == ('11', 'edge_behind_phone', 'phone', True)
    assert finding['lldp_neighbors'][0]['capabilities'] == 'B,T'


def test_exos_endpoint_behind_an_access_point_is_the_edge_at_the_ap_port(device):
    auths, _ = device(exos('floor1', HOME_1))
    r = engine._locate_endpoint_run(auths, '192.0.2.14')            # LLDP on port 3: "Bridge, WLAN AP"
    finding = only(r, 'findings')
    assert r['verdict'] == 'located', r['missing']
    assert (finding['port'], finding['role'], finding['behind']) == ('3', 'edge_behind_ap', 'ap')
    assert finding['lldp_neighbors'][0]['capabilities'] == 'B,W'


def test_exos_mac_only_seen_on_an_uplink_to_a_switch_that_is_not_enrolled_is_not_not_found(device):
    auths, _ = device(exos('floor1', HOME_1))
    r = engine._locate_endpoint_run(auths, '192.0.2.88')            # port 2: LLDP neighbour is a "Bridge" switch
    finding = only(r, 'findings')
    assert finding['role'] == 'transit' and not finding['edge']
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'floor1', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': '2'} in r['missing']


def test_exos_two_enrolled_switches_follow_the_lag_to_the_edge(device):
    auths, calls = device(exos('floor1', HOME_1), exos('attic', HOME_2))
    r = engine._locate_endpoint_run(auths, '192.0.2.36')
    roles = {f['vantage']: (f['port'], f['role']) for f in r['findings']}
    assert roles == {'floor1': ('13', 'transit'), 'attic': ('9', 'edge')}      # port 13 is a multi-VLAN LAG
    assert r['verdict'] == 'located', r['missing']
    assert sum(c == 'show version' for _, c in calls) == 2


def test_exos_access_and_distribution_locate_the_captured_ip(device):
    auths, _ = device(exos('floor1', HOME_1), exos('attic', HOME_2))
    result = engine._locate_endpoint_run(auths, '192.0.2.35')
    assert result['verdict'] == 'located', result['missing']
    assert {f['vantage']: (f['port'], f['role']) for f in result['findings']} == {
        'floor1': ('6', 'edge'), 'attic': ('13', 'transit')}


def lag_without_lldp(tmp_path):
    """The LAG uplink as a single-VLAN port with LLDP switched off: only `show lacp` still shows the aggregation."""
    shutil.copytree(HOME_1, tmp_path / 'sw')
    ports = tmp_path / 'sw/ports.txt'
    ports.write_text(ports.read_text().replace('(0006)', 'V10   '))
    (tmp_path / 'sw/lldp_neighbors_detail.txt').write_text('')
    return tmp_path / 'sw'


def test_exos_single_vlan_lag_without_lldp_is_transit_by_lacp(device, tmp_path):
    auth, directory = exos('floor1', lag_without_lldp(tmp_path))
    auth = replace(auth, enabled_queries=tuple(q for q in EXOS_QUERIES if q != 'lag_summary'))
    auths, calls = device((auth, directory))
    r = engine._locate_endpoint_run(auths, '192.0.2.36')
    finding = only(r, 'findings')
    assert (finding['port'], finding['role'], finding['edge']) == ('13', 'transit', False)
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'floor1', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': '13'} in r['missing']
    assert ('floor1', 'show lacp') in calls


def test_exos_edge_is_not_promised_when_lacp_cannot_be_read(device, tmp_path):
    auth, directory = exos('floor1', lag_without_lldp(tmp_path))
    auth = replace(auth, enabled_queries=tuple(q for q in EXOS_QUERIES if q not in ('lacp', 'lag_summary')))
    auths, calls = device((auth, directory))
    r = engine._locate_endpoint_run(auths, '192.0.2.36')
    finding = only(r, 'findings')
    assert not finding['edge'] and r['verdict'] != 'located'
    assert {'vantage': 'floor1', 'table': 'aggregate', 'reason': 'permission_denied'} in r['missing']
    assert {'vantage': 'floor1', 'table': 'edge', 'reason': 'aggregation_not_verified'} in r['missing']
    assert ('floor1', 'show lacp') not in calls


def test_exos_unknown_mac_is_not_found_with_every_table_read(device):
    auths, _ = device(exos('floor1', HOME_1))
    r = engine._locate_endpoint_run(auths, '00:00:5e:00:53:ff')
    assert r['verdict'] == 'not_found_in_checked_data' and not r['missing'] and not r['findings']


def test_ios_xe_documentation_output_locates_host_phone_and_uplink(device, monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    directory = ROOT / 'docs/cisco_xe'
    outputs = {READ_QUERIES['cisco_xe'][q].command: (directory / (q + '.txt')).read_text() for q in IOS_QUERIES
               if (directory / (q + '.txt')).exists()}
    outputs['show version'] = (ROOT / 'identity/cisco_xe.txt').read_text()
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, profile, command: (0, outputs[command]))
    sw = replace(_target('cisco_xe', 'mac_table'), alias='dist', device_types=('switch', 'router'), enabled_queries=IOS_QUERIES)
    plain = engine._locate_endpoint_run([sw], '198.51.100.20')
    assert plain['verdict'] == 'located' and only(plain, 'findings')['port'] == 'GigabitEthernet1/0/2'
    phone = engine._locate_endpoint_run([sw], '198.51.100.40')                 # PC behind the IP phone on Gi1/0/3 (B,T)
    assert phone['verdict'] == 'located' and only(phone, 'findings')['role'] == 'edge_behind_phone'
    uplink = engine._locate_endpoint_run([sw], '198.51.100.50')                # on Gi1/0/1 towards core-sw (B,R)
    assert uplink['verdict'] == 'incomplete'
    assert any(m['reason'] == 'edge_beyond_enrolled_targets' for m in uplink['missing'])


@pytest.mark.parametrize('protocol', ['LACP', 'STATIC'])
@pytest.mark.parametrize('sharing_enabled', [False, True])
def test_exos_single_vlan_aggregation_requires_sharing_for_complete_edge_coverage(
        device, tmp_path, protocol, sharing_enabled):
    # Real X440G2 show sharing capture; the STATIC variant is explicitly synthetic.
    directory = lag_without_lldp(tmp_path)
    sharing = directory / 'captures_20261110_final/lag_summary.txt'
    sharing.write_text(sharing.read_text().replace('LACP', protocol))
    if protocol == 'STATIC':
        # Real empty show lacp capture: a static LAG is absent from that table.
        empty = ROOT / 'real/exos/exosvm_33.6.1.14/lacp.txt'
        (directory / 'lacp.txt').write_text(empty.read_text())
    auth, _ = exos('floor1', directory)
    if not sharing_enabled:
        auth = replace(auth, enabled_queries=tuple(q for q in EXOS_QUERIES if q != 'lag_summary'))
    auths, calls = device((auth, directory))
    result = engine._locate_endpoint_run(auths, '192.0.2.36')
    finding = only(result, 'findings')
    assert finding['port'] == '13' and not finding['edge']
    assert result['verdict'] == 'incomplete' and result['coverage']['complete'] is False
    assert (('floor1', 'show sharing') in calls) is sharing_enabled
    assert (('floor1', 'show lacp') in calls) is not sharing_enabled
    assert result['reads'] == len(calls)
    if sharing_enabled or protocol == 'LACP':
        assert finding['role'] == 'transit'
    else:
        assert finding['role'] == 'unverified'
        assert {'vantage': 'floor1', 'table': 'edge', 'reason': 'aggregation_not_verified'} in result['missing']


@pytest.mark.parametrize('sharing_text', ['Load Sharing Monitor\n', 'Error: permission denied'])
def test_exos_failed_or_unrecognized_sharing_cannot_establish_an_edge(device, tmp_path, sharing_text):
    directory = lag_without_lldp(tmp_path)
    (directory / 'captures_20261110_final/lag_summary.txt').write_text(sharing_text)
    auths, calls = device(exos('floor1', directory))
    result = engine._locate_endpoint_run(auths, '192.0.2.36')
    assert not only(result, 'findings')['edge']
    assert result['coverage']['complete'] is False
    assert any(item['reason'] == 'aggregation_not_verified' for item in result['missing'])
    assert ('floor1', 'show sharing') in calls


@pytest.mark.parametrize('sharing_enabled', [False, True])
def test_static_exos_lag_through_proxy_engine_and_isolated_worker(tmp_path, monkeypatch, sharing_enabled):
    import test_proxy_contracts as c
    from netops_helper import proxy, endpoint_worker
    directory = lag_without_lldp(tmp_path)
    outputs = answers(directory)
    outputs['show sharing'] = outputs['show sharing'].replace('LACP', 'STATIC')
    outputs['show lacp'] = (ROOT / 'real/exos/exosvm_33.6.1.14/lacp.txt').read_text()
    inventory, _, _, _ = c._configure(proxy, tmp_path)
    section = c._section()
    queries = [q for q in EXOS_QUERIES if sharing_enabled or q != 'lag_summary']
    section.update(ssh_platform='exos', enabled_queries=queries, device_types=['switch', 'router'], read_inventory={})
    c._write(inventory, c._inventory(c._device(section, 'exos')))
    forwarded = proxy.Proxy().request(c._request(1, 'locate_endpoint', {
        'targets': ['device-a'], 'endpoint': '192.0.2.36'}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    audit = tmp_path / 'worker-audit.jsonl'
    wire = tmp_path / 'worker-wire.jsonl'
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', str(audit))
    bootstrap = endpoint_worker.command()
    roots = bootstrap[-1].split('; from netops_helper.endpoint_worker import main; main()')[0]
    # Only the device transport is replaced. Authorization, identity, parsing,
    # operation audit, read limits and the real subprocess protocol all run.
    code = '''
import json
from netops_helper import engine
outputs = %r
def read(auth, profile, command):
    with open(%r, 'a') as handle:
        handle.write(json.dumps(command) + '\\n')
    return 0, outputs[command]
engine.read_from_device = read
from netops_helper.endpoint_worker import main
main()
''' % (outputs, str(wire))
    monkeypatch.setattr(endpoint_worker, 'command', lambda: bootstrap[:-1] + [roots + '\n' + code])
    result = engine.locate_endpoint(**args)
    assert result['ok'] and result['verdict'] == 'incomplete'
    assert not result['coverage']['complete']
    finding = only(result, 'findings')
    assert finding['port'] == '13' and not finding['edge']
    assert finding['role'] == ('transit' if sharing_enabled else 'unverified')
    if not sharing_enabled:
        assert any(m['reason'] == 'aggregation_not_verified' for m in result['missing'])
    calls = [json.loads(line) for line in wire.read_text().splitlines()]
    assert ('show sharing' in calls) is sharing_enabled
    assert ('show lacp' in calls) is not sharing_enabled
    assert result['reads'] == len(calls)
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    starts = [row for row in records if row['status'] == 'started']
    ends = [row for row in records if row['status'] != 'started']
    assert starts and {row['operation_id'] for row in starts} == {row['operation_id'] for row in ends}
