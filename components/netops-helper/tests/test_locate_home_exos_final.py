"""Final acceptance home EXOS link replay with complete independently captured tables."""
from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from conftest import _target
from netops_helper import engine
from netops_helper.query_catalog import READ_QUERIES

REAL = Path(__file__).parent / 'fixtures/real/exos'
DIRECTORIES = {'floor': 'x440g2-12p-10g4_33.7.1.6_2', 'attic': 'x440g2-12p-10g4_33.7.1.6_3'}


@pytest.mark.parametrize('endpoint,known,external,external_port', [
    ('192.0.2.1', 'floor', 'attic', '1'), ('192.0.2.206', 'attic', 'floor', '2'),
])
@pytest.mark.parametrize('enrolled_by', ['address', 'hostname'])
def test_home_reciprocal_port13_is_an_enrolled_neighbor(monkeypatch, enrolled_by, endpoint, known, external, external_port):
    commands = READ_QUERIES['extreme_exos']
    answers, calls = {}, []
    for node, directory in DIRECTORIES.items():
        parent = REAL / directory
        day = parent / 'captures_20261110_final'
        index = json.loads((day / 'index.json').read_text())
        answers[node] = {commands[q].command: (meta['rc'], (day / (q + '.txt')).read_text()) for q, meta in index.items()}
        answers[node]['show version'] = 0, (parent / 'version.txt').read_text()
        # Earlier real identity supplement, rebase only its anonymized SysName to
        # this capture's shared mapping (floor host05, attic host04).
        name = 'host05' if node == 'floor' else 'host04'
        text = re.sub(r'(?m)^(SysName:\s*)\S+', lambda m: m[1] + name, (parent / 'switch.txt').read_text())
        answers[node]['show switch'] = 0, text
    def transport(auth, profile, command, **kwargs):
        calls.append((auth.alias, command))
        return answers[auth.alias][command]
    monkeypatch.setattr(engine, '_exec_read', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    targets = [replace(_target('extreme_exos', 'mac_table'), alias=node,
                       host=('192.0.2.2' if node == 'floor' else '192.0.2.3') if enrolled_by == 'address'
                       else ('host05' if node == 'floor' else 'host04') + '.example.invalid',
                       device_types=('switch', 'router'), enabled_queries=tuple([
                           'version', 'switch', 'mac_table', 'lldp_neighbors_detail', 'arp_table', 'ipconfig']))
               for node in DIRECTORIES]
    r = engine._locate_endpoint_run(targets, endpoint)
    assert r['verdict'] == 'incomplete', r['missing']
    assert {(f['vantage'], f['port'], f['role']) for f in r['findings']} == {
        (known, '13', 'transit'), (external, external_port, 'transit')}
    assert {(m['vantage'], m.get('port'), m['reason']) for m in r['missing']} == {
        (known, '13', 'endpoint_not_seen_on_neighbor_target'),
        (external, external_port, 'edge_beyond_enrolled_targets')}
    assert r['reads'] == len(calls) < 40
