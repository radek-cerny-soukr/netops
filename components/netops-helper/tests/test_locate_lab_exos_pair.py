"""locate_endpoint between two enrolled lab EXOS switches, replayed over their read-only outputs of 2026-11-10.

Acceptance 08-exos (findings 1 and 2): X435 (`x435`) port 1 is cabled to X440G2 (`x440`) port 7. The NAS on X440
port 11 ended `incomplete`, because X435 holds the NAS MAC on port 1 and EXOS advertises neither LLDP
capabilities nor a management address: the neighbour (anonymised `host01`) was not recognised as
the enrolled X440. The own addresses of both switches (.110, .111) ended `incomplete` on the measured candidate.

`exos/<switch>/captures_20261110/` holds the independent CLI reads of that acceptance (11:02 UTC, `netops-ro`), one
anonymiser mapping for both switches: X440 is SysName `host01` with System MAC ...:0c, X435 `host02` with ...:0d,
the NAS 192.0.2.20 / 00:00:5e:00:53:0e. `show version` was not part of the capture; identity comes from the
earlier captures of the same switches. The inventory is the acceptance one: device types switch and router,
the 13 original EXOS queries plus the later captured `lag_summary` (show sharing).
"""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netops_helper import engine, locate
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

REAL = Path(__file__).parent / 'fixtures/real'
# alias -> stored switch; its captures_20261110/ holds the acceptance reads, version.txt the identity
IDENTITY = {'x435': REAL / 'exos/x435-8p-4s_33.7.1.6', 'x440': REAL / 'exos/x440g2-12p-10g4_33.7.1.6'}
ENABLED = ('version', 'switch', 'ports', 'vlan_detail', 'vlan_summary', 'ipconfig', 'route_table', 'arp_table', 'mac_table',
           'lldp_neighbors_detail', 'ports_rx_errors', 'ports_tx_errors', 'lacp', 'lag_summary')
NAS_IP, NAS_MAC = '192.0.2.20', '00:00:5e:00:53:0e'
PROFILE = 'extreme_exos'


def outputs(node):
    commands = READ_QUERIES[PROFILE]
    day = IDENTITY[node] / 'captures_20261110'
    result = {commands['version'].command: (0, (IDENTITY[node] / 'version.txt').read_text())}
    for query, meta in json.loads((day / 'index.json').read_text()).items():
        assert commands[query].command == meta['command']
        result[meta['command']] = (meta['rc'], (day / (query + '.txt')).read_text())
    # The later independent show sharing capture is needed to rule out static LAGs.
    result[commands['lag_summary'].command] = (0, (IDENTITY[node] / 'captures_20261110_final/lag_summary.txt').read_text())
    return result


@pytest.fixture
def pair(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    answers = {node: outputs(node) for node in IDENTITY}
    calls = []

    def read(auth, profile, command):
        calls.append((auth.alias, command))
        return answers[auth.alias][command]
    monkeypatch.setattr(engine, '_exec_read', read)
    targets = [replace(_target(PROFILE, 'mac_table'), alias=node, device_types=('switch', 'router'), enabled_queries=ENABLED)
               for node in IDENTITY]
    return targets, calls, answers


def lldp_name(answers, node, name):
    """Explicitly synthetic: the stored LLDP neighbour of `node` advertises another system name."""
    command = READ_QUERIES[PROFILE]['lldp_neighbors_detail'].command
    rc, text = answers[node][command]
    assert text.count('System Name: "host0') == 1
    answers[node][command] = (rc, text.replace('System Name: "host01"', f'System Name: "{name}"'))


@pytest.mark.parametrize('endpoint', [NAS_IP, NAS_MAC])
def test_the_nas_is_located_on_x440_although_x435_sees_it_on_the_link(pair, endpoint):
    targets, calls, _ = pair
    r = engine._locate_endpoint_run(targets, endpoint)
    assert r['verdict'] == 'located', r['missing']
    assert r['missing'] == [] and r['own_interfaces'] == []
    roles = {(f['vantage'], f['port']): f['role'] for f in r['findings']}
    assert roles == {('x435', '1'): 'transit', ('x440', '11'): 'edge'}
    (edge,) = [f for f in r['findings'] if f['edge']]
    assert (edge['vlan_id'], edge['vlan_membership']['tagging'], edge['interface']['oper_status']) == (1, 'untagged', 'up')
    (link,) = [f for f in r['findings'] if f['vantage'] == 'x435']
    # EXOS advertises no capabilities: the neighbour is the enrolled X440 by its system name only.
    assert [(n['neighbor'], n['capabilities'], n['management_ip']) for n in link['lldp_neighbors']] == [('host01', None, None)]
    # The X440 system name comes from its identity supplement `show switch`, read once.
    assert calls.count(('x440', 'show switch')) == 1 and ('x435', 'show switch') not in calls
    assert r['reads'] == len(calls) < locate.MAX_READS


@pytest.mark.parametrize('alias,ip', [('x435', '192.0.2.110'), ('x440', '192.0.2.111')])
def test_the_own_address_of_either_switch_is_its_own_interface(pair, alias, ip):
    targets, calls, _ = pair
    r = engine._locate_endpoint_run(targets, ip)
    assert r['verdict'] == 'own_interface_of_target', r['missing']
    assert [(o['target'], o['interface'], o['ip'], o['source']) for o in r['own_interfaces']] == [
        (alias, 'Default', ip, 'ip_interface')]
    # The other switch sees the owner's MAC on the link between them: transit, identified by the LLDP system name.
    assert [(f['vantage'], f['role']) for f in r['findings']] == [({'x435': 'x440', 'x440': 'x435'}[alias], 'transit')]
    assert not any(m['reason'] in ('lldp_or_mac_incomplete', 'edge_beyond_enrolled_targets') for m in r['missing'])
    assert [a for a, command in calls if command == 'show ipconfig'] == [alias]
    assert r['reads'] == len(calls) < locate.MAX_READS


def test_without_the_identity_supplement_the_link_stays_unverified(pair):
    targets, calls, _ = pair
    targets = [replace(t, enabled_queries=tuple(q for q in ENABLED if q != 'switch')) for t in targets]
    r = engine._locate_endpoint_run(targets, NAS_MAC)
    assert r['verdict'] == 'incomplete'
    assert {(f['vantage'], f['role']) for f in r['findings']} == {('x435', 'unverified'), ('x440', 'edge')}
    assert {'vantage': 'x435', 'table': 'edge', 'reason': 'lldp_or_mac_incomplete'} in r['missing']
    assert not any(command == 'show switch' for _, command in calls)


def test_a_host_behind_x440_only_reads_no_identity(pair):
    targets, calls, _ = pair
    r = engine._locate_endpoint_run(targets, '192.0.2.37')
    assert r['verdict'] == 'located' and r['missing'] == []
    assert [(f['vantage'], f['port'], f['role']) for f in r['findings']] == [('x440', '3', 'edge')]
    assert not any(command == 'show switch' for _, command in calls)


def test_an_uplink_beyond_the_enrolled_switches_stays_incomplete(pair):
    targets, _, _ = pair
    r = engine._locate_endpoint_run(targets, '192.0.2.36')
    assert r['verdict'] == 'incomplete'
    # X440 port 1 is the tagged uplink to a switch that is not enrolled; X435 sees the host on its link to X440.
    assert {(f['vantage'], f['port'], f['role']) for f in r['findings']} == {('x435', '1', 'transit'), ('x440', '1', 'transit')}
    assert {'vantage': 'x440', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': '1'} in r['missing']


def test_the_system_name_is_compared_without_case_and_domain(pair):
    targets, _, answers = pair
    lldp_name(answers, 'x435', 'HOST01.lab.example.net')
    r = engine._locate_endpoint_run(targets, NAS_MAC)
    assert r['verdict'] == 'located', r['missing']
    assert {(f['vantage'], f['role']) for f in r['findings']} == {('x435', 'transit'), ('x440', 'edge')}


@pytest.mark.parametrize('name', ['host02', 'host011', 'Extreme', ''])
def test_a_name_that_is_no_other_enrolled_target_stays_unverified(pair, name):
    # host02 is the reading X435 itself, the others are no enrolled host name.
    targets, calls, answers = pair
    lldp_name(answers, 'x435', name)
    r = engine._locate_endpoint_run(targets, NAS_MAC)
    assert r['verdict'] == 'incomplete'
    assert {(f['vantage'], f['role']) for f in r['findings']} == {('x435', 'unverified'), ('x440', 'edge')}
    assert {'vantage': 'x435', 'table': 'edge', 'reason': 'lldp_or_mac_incomplete'} in r['missing']
    assert ('x435', 'show switch') not in calls


@pytest.mark.parametrize('change', ['two names', 'refused'])
def test_an_unusable_identity_supplement_identifies_no_neighbour(pair, change):
    # Explicitly synthetic: the stored `show switch` of the X440 names two hosts, or the device refuses it.
    targets, calls, answers = pair
    command = READ_QUERIES[PROFILE]['switch'].command
    rc, text = answers['x440'][command]
    answers['x440'][command] = (rc, text.replace('SysName:          host01\n', 'SysName:          host01\nSysName:          host09\n', 1)
                                if change == 'two names' else "%% Invalid input detected at '^' marker.\n")
    assert answers['x440'][command][1] != text
    r = engine._locate_endpoint_run(targets, NAS_MAC)
    assert r['verdict'] == 'incomplete'
    assert {(f['vantage'], f['role']) for f in r['findings']} == {('x435', 'unverified'), ('x440', 'edge')}
    assert calls.count(('x440', 'show switch')) == 1


@pytest.mark.parametrize('name_source', ['sysname', 'alias', 'management_ip', 'enrolled_address'])
def test_endpoint_seen_only_on_link_to_enrolled_lab_neighbor(pair, name_source):
    targets, calls, answers = pair
    # Real endpoint beyond X440: X435:1 -> enrolled X440, X440:1 -> external switch.
    # Other matching modes vary only the enrollment/LLDP identity field explicitly.
    if name_source == 'alias':
        lldp_name(answers, 'x435', 'x440')
    elif name_source in ('management_ip', 'enrolled_address'):
        targets = [replace(t, host='192.0.2.111') if t.alias == 'x440' else t for t in targets]
        q = READ_QUERIES[PROFILE]['lldp_neighbors_detail'].command
        rc, text = answers['x435'][q]
        if name_source == 'management_ip':
            text = text.replace('System Name: "host01"', 'System Name: "unlisted"\n    - Management Address Subtype: IPv4 (1)\n      Management Address        : 192.0.2.111')
        else:
            text = text.replace('System Name: "host01"', 'System Name: "192.0.2.111"')
        answers['x435'][q] = rc, text
    r = engine._locate_endpoint_run(targets, '192.0.2.36')
    assert r['verdict'] == 'incomplete'
    assert {'vantage': 'x435', 'table': 'edge', 'reason': 'endpoint_not_seen_on_neighbor_target', 'port': '1'} in r['missing']
    assert {'vantage': 'x440', 'table': 'edge', 'reason': 'edge_beyond_enrolled_targets', 'port': '1'} in r['missing']
    assert r['reads'] == len(calls) < locate.MAX_READS
