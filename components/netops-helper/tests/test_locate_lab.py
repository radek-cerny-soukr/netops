"""locate_endpoint end to end on the GNS3 lab: IOSv (router) - IOSvL2 - cEOS - EXOS-VM.

Every answer is the anonymised output the lab device printed to the read-only account
(tests/fixtures/real/<profile>/<model>_<version>); `show version` included, so the identity
check runs on real output as well. The endpoint is a static host entry created for the capture
(ARP on the router, MAC entries on the three switches, port 2 of the EXOS-VM): IP 192.0.2.77,
MAC 00:00:5e:00:53:19 in the anonymised files, sitting behind EXOS port 2.
The VM capture has no show sharing: that final port remains unverified for static aggregation.
"""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netops_helper import engine, normalization
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

REAL = Path(__file__).parent / 'fixtures/real'
LAB = {
    'iosv': ('cisco_ios', REAL / 'cisco_ios/iosv_15.9.3M12', ('router',)),
    'iosvl2': ('cisco_ios', REAL / 'cisco_ios/iosvl2_15.2.20200924', ('switch',)),
    'ceos': ('arista_eos', REAL / 'arista_eos/ceos_4.36.1F', ('switch', 'router')),
    'exos': ('extreme_exos', REAL / 'exos/exosvm_33.6.1.14', ('switch',)),
}
QUERIES = {
    'cisco_ios': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans'),
    'arista_eos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'interfaces', 'vlans'),
    'extreme_exos': ('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors_detail', 'ports', 'vlan_summary', 'lacp'),
}
ENDPOINT_IP, ENDPOINT_MAC = '192.0.2.77', '00:00:5e:00:53:19'


def lab_target(name):
    profile, directory, types = LAB[name]
    return replace(_target(profile, 'mac_table'), alias=name, device_types=types, enabled_queries=QUERIES[profile]), directory


def answers(profile, directory):
    result = {}
    for query_name, query in READ_QUERIES[profile].items():
        file = directory / (query_name + '.txt')
        if file.exists() and not query.slots:
            result[query.command] = file.read_text()
    return result


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)

    def install(*names):
        targets = [lab_target(n) for n in names]
        by_alias = {auth.alias: answers(auth.ssh_platform, directory) for auth, directory in targets}
        calls = []

        def read(auth, profile, command):
            calls.append((auth.alias, command))
            return 0, by_alias[auth.alias][command]
        monkeypatch.setattr(engine, 'read_from_device', read)
        return [auth for auth, _ in targets], calls
    return install


def roles(result):
    return {f['vantage']: (f['port'], f['role']) for f in result['findings']}


def test_ip_is_followed_to_the_exos_port_but_static_aggregation_is_unverified(lab):
    auths, calls = lab('iosv', 'iosvl2', 'ceos', 'exos')
    r = engine._locate_endpoint_run(auths, ENDPOINT_IP)
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'exos', 'table': 'edge', 'reason': 'aggregation_not_verified'} in r['missing']
    assert {m['reason'] for m in r['missing']} == {'aggregation_not_verified', 'edge_beyond_enrolled_targets'}
    assert not r['coverage']['complete']
    assert roles(r) == {'iosvl2': ('GigabitEthernet0/2', 'transit'), 'ceos': ('Ethernet2', 'transit'), 'exos': ('2', 'unverified')}
    edge = next(f for f in r['findings'] if f['vantage'] == 'exos')
    assert not edge['edge']
    assert (edge['mac'], edge['vlan_id'], edge['vlan_name']) == (ENDPOINT_MAC, 10, 'D10')
    assert [o['vantage'] for o in r['neighbors_l3']] == ['iosv']
    assert r['neighbors_l3'][0]['mac'] == ENDPOINT_MAC and r['neighbors_l3'][0]['interface'] is None   # static ARP: no interface printed
    assert sum(c == 'show version' for _, c in calls) == 4          # one identity check per alias
    # IOSvL2 and cEOS see the MAC on ports with an LLDP switch neighbour: no interface/VLAN reads there.
    assert r['reads'] == len(calls) == 15
    assert ('exos', 'show lacp') in calls and ('iosvl2', 'show interfaces status') not in calls


def test_mac_without_the_router_also_requires_complete_aggregation_evidence(lab):
    auths, calls = lab('iosvl2', 'ceos', 'exos')
    r = engine._locate_endpoint_run(auths, ENDPOINT_MAC)
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'exos', 'table': 'edge', 'reason': 'aggregation_not_verified'} in r['missing']
    assert {m['reason'] for m in r['missing']} == {'aggregation_not_verified', 'edge_beyond_enrolled_targets'}
    assert not r['coverage']['complete']
    assert roles(r)['exos'] == ('2', 'unverified')
    assert ('exos', 'show lacp') in calls


def test_without_the_exos_the_endpoint_is_beyond_the_last_enrolled_switch(lab):
    auths, _ = lab('iosv', 'iosvl2', 'ceos')
    r = engine._locate_endpoint_run(auths, ENDPOINT_IP)
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'ceos', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': 'Ethernet2'} in r['missing']


def test_every_lab_table_output_is_recognized_by_the_parsers():
    from netops_helper import tables
    for name, (profile, directory, _) in LAB.items():
        for key, query in tables.BINDINGS[profile].items():
            table = 'route' if key.startswith('route') else key.removesuffix('_v6')
            file = directory / (query + '.txt')
            if query not in READ_QUERIES[profile] or not file.exists() or key == 'route':      # route: a lookup, see the route tests
                continue
            text = file.read_text()
            rc = json.loads((directory / 'index.json').read_text())[query]['rc']        # the SSH exit status the device gave
            result = tables.parse(profile, table, query, text, status=normalization.output_status(text, rc=rc))
            assert not result['unparsed'], (name, key, result['unparsed'][:3])
            assert result['status'] in ('ok', 'empty', 'not_applicable', 'permission_denied'), (name, key, result['status'])


def test_identity_is_read_from_the_real_show_version_output():
    from netops_helper.normalization import parse_identity
    ios = parse_identity('cisco_ios', (LAB['iosv'][1] / 'version.txt').read_text())
    assert (ios['hostname'], ios['model'], ios['os_version'], ios['uptime']) == ('host06', 'IOSv', '15.9(3)M12', '51 minutes')
    l2 = parse_identity('cisco_ios', (LAB['iosvl2'][1] / 'version.txt').read_text())
    assert (l2['hostname'], l2['os_version']) == ('host08', '15.2(20200924:215240)')       # an experimental image: the version carries a build stamp
    eos = parse_identity('arista_eos', (LAB['ceos'][1] / 'version.txt').read_text())
    assert (eos['model'], eos['os_version'], eos['hostname']) == ('cEOSLab', '4.36.1F-48405728.4361F', None)          # the hostname comes from the `hostname` supplement
    exos = parse_identity('extreme_exos', (LAB['exos'][1] / 'version.txt').read_text())
    assert (exos['os_version'], exos['model']) == ('33.6.1.14', None)                                              # the model comes from the `switch` supplement
