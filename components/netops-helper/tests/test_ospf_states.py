"""Live 2026-11-10 CLI captures and state-cell variants through switch_read."""
import json
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import audit, engine, tables
from netops_core.audit import Recorder
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / 'fixtures'
LIVE = json.loads((FIXTURES / 'ospf_live20.json').read_text())
PROFILES = [('cisco_ios', 'iosv'), ('cisco_xe', 'iolxe'), ('cisco_nxos', 'nxos'),
            ('arista_eos', 'ceos'), ('juniper_junos', 'vjunos'), ('juniper_junos_els', 'vjunos')]


@pytest.fixture(autouse=True)
def private_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))


def read(monkeypatch, profile, text):
    calls = []
    def transport(auth, requested_profile, command):
        calls.append(command)
        assert requested_profile == profile
        if command == READ_QUERIES[profile]['version'].command:
            return 0, (FIXTURES / 'identity' / (profile + '.txt')).read_text()
        assert command == READ_QUERIES[profile]['ospf_neighbors'].command
        return 0, text
    monkeypatch.setattr(engine, 'read_from_device', transport)
    result = engine.switch_read(_target(profile, 'ospf_neighbors'), 'ospf_neighbor')
    assert calls == [READ_QUERIES[profile]['version'].command, READ_QUERIES[profile]['ospf_neighbors'].command]
    return result


@pytest.mark.parametrize('profile,capture', PROFILES)
def test_all_live_neighbors_survive_engine_path(monkeypatch, profile, capture):
    result = read(monkeypatch, profile, LIVE[capture]['stdout'])
    assert result['ok'] is True and result['status'] == 'ok'
    assert result['coverage']['complete'] and not result['unparsed']
    rows = result['records']
    assert len(rows) == 4
    expected_ids = {'203.0.113.' + n for n in ('1', '3', '5', '6', '7')}
    expected_ids.remove('203.0.113.' + {'iosv': '1', 'iolxe': '7', 'nxos': '5', 'ceos': '3', 'vjunos': '6'}[capture])
    assert {r['neighbor_id'] for r in rows} == expected_ids
    assert {r['state'] for r in rows} <= {'full', '2way'}
    if capture == 'ceos':
        assert [(r['neighbor_id'], r['state'], r['role']) for r in rows] == [
            ('203.0.113.7', '2way', 'DROTHER'), ('203.0.113.6', 'full', 'DR'),
            ('203.0.113.5', 'full', 'BDR'), ('203.0.113.1', '2way', 'DROTHER')]


@pytest.mark.parametrize('profile,capture', PROFILES)
@pytest.mark.parametrize('state,canonical', [
    ('DOWN', 'down'), ('ATTEMPT', 'attempt'), ('INIT', 'init'), ('EXSTART', 'exstart'),
    ('EXCHANGE', 'exchange'), ('LOADING', 'loading'), ('FULL', 'full'), ('2WAY', '2way')])
def test_documented_state_spellings_through_engine(monkeypatch, profile, capture, state, canonical):
    # Vary only the state cell of each real row. Junos spells mixed-case states;
    # NX-OS spells TWOWAY and EOS spells 2 WAYS.
    import re
    raw_state = ('2 WAYS' if profile == 'arista_eos' else 'TWOWAY' if profile == 'cisco_nxos' else '2WAY') if state == '2WAY' else state
    if profile.startswith('juniper'):
        raw_state = {'2WAY': '2Way', 'EXSTART': 'ExStart'}.get(state, state.title())
        text = re.sub(r'\bFull\b', raw_state, LIVE[capture]['stdout'])
    else:
        text = re.sub(r'(?:2 WAYS|2WAY|FULL)/(?:DROTHER|BDR|DR)', raw_state, LIVE[capture]['stdout'])
    result = read(monkeypatch, profile, text)
    assert result['ok'] and result['coverage']['complete'] and not result['unparsed']
    assert len(result['records']) == 4
    assert {row['state'] for row in result['records']} == {canonical}


@pytest.mark.parametrize('profile,capture', PROFILES[:4])
@pytest.mark.parametrize('role', ['DR', 'BDR', 'DROTHER', '-'])
def test_slash_role_and_spacing_through_engine(monkeypatch, profile, capture, role):
    import re
    text = re.sub(r'(?:2 WAYS|2WAY|FULL)/(?:DROTHER|BDR|DR)',
                  'FULL /  ' + role, LIVE[capture]['stdout'])
    result = read(monkeypatch, profile, text)
    assert result['ok'] and not result['unparsed'] and len(result['records']) == 4
    assert {(r['state'], r['role']) for r in result['records']} == {('full', None if role == '-' else role)}


@pytest.mark.parametrize('profile', [p for p, bindings in tables.BINDINGS.items() if 'ospf_neighbor' not in bindings])
def test_profiles_without_ospf_binding_stay_explicitly_unsupported(monkeypatch, profile):
    def unexpected_transport(*args):
        pytest.fail('An unsupported OSPF table must not contact a device')
    monkeypatch.setattr(engine, 'read_from_device', unexpected_transport)
    result = engine.switch_read(_target(profile, 'version'), 'ospf_neighbor')
    assert not result['ok'] and result['status'] == 'unsupported'
    assert not result['records'] and not result['coverage']['complete']
