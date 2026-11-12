"""Replay the 2026-11-10 RO FortiGate/FortiSwitch captures, including policy boundaries."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, fortiswitch_ports as ports, port_vlan, tables
from netops_helper.auth import PolicyScopeError

REAL = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2_build0251/captures_20261110'
SERIAL = 'S000SSSS00000001'


def fixture(name):
    return (REAL / (name + '.txt')).read_text()


def test_captured_port_states_speed_and_cumulative_errors():
    state = tables.parse('fortinet', 'interface', ports.STATS, fixture('port_stats_1'))
    assert state['status'] == 'ok' and len(state['records']) == 29
    rows = {r['name']: r for r in state['records']}
    assert (rows['port1']['oper_status'], rows['port3']['oper_status'], rows['port3']['speed']) == ('down', 'up', '1000M')
    errors = tables.parse('fortinet', 'interface_errors', ports.STATS, fixture('port_stats_2_port3'))
    assert errors['status'] == 'ok' and len(errors['records']) == 1
    row = errors['records'][0]
    assert row['rx_errors'] == row['tx_errors'] == 0
    assert row['discards_in'] == 0
    nonzero = tables.parse('fortinet', 'interface_errors', ports.STATS, fixture('port_stats_1'))
    assert nonzero['records'][2]['discards_in'] == 30
    assert nonzero['records'][2]['discards_out'] == 1
    assert all(row[k] is None for k in ('crc', 'last_flap', 'link_flaps', 'carrier_transitions'))
    assert tables.parse('fortinet', 'interface_errors', ports.STATS, 'Port(port3) is HW Admin up, SW Admin up, line protocol is up\n')['status'] == 'unparsed'


def test_real_config_membership_resolves_names_and_marks_source():
    auth = replace(_target('fortinet', ports.CONFIG), enabled_queries=(ports.CONFIG, ports.VLAN_IDS),
                   read_inventory={'managed_switches': (SERIAL,)})
    calls = []
    def read(query, table, parameters):
        calls.append((query, parameters))
        return tables.parse('fortinet', table, query, fixture('managed_ports_config' if query == ports.CONFIG else 'vlan_config'))
    result = ports.read_vlan(auth, {'managed_switch': SERIAL}, read)
    assert result['status'] == 'ok' and result['source'] == 'configuration'
    assert len(result['sources']) == 2 and not result['coverage']['complete']
    row = next(r for r in result['records'] if r['port'] == 'port3')
    assert row['oper_status'] is None
    assert port_vlan.membership(row, 100) == {'carries_vlan': True, 'tagging': 'untagged'}
    assert port_vlan.membership(row, 4093) == {'carries_vlan': True, 'tagging': 'untagged'}
    assert port_vlan.membership(row, 200) == {'carries_vlan': False, 'tagging': None}
    assert calls == [(ports.CONFIG, {'managed_switch': SERIAL}), (ports.VLAN_IDS, None)]
    # Add a real named VLAN to allowed, preserving the two independently untagged VLANs.
    text = fixture('managed_ports_config').replace('set allowed-vlans "quarantine"', 'set allowed-vlans "quarantine" "voice"')
    with_tagged = ports.read_vlan(auth, {'managed_switch': SERIAL}, lambda q,t,p: tables.parse(
        'fortinet',t,q,text if q == ports.CONFIG else fixture('vlan_config')))
    assert port_vlan.membership(with_tagged['records'][2],4091)['tagging'] == 'tagged'


def test_unresolved_or_refused_configuration_never_promises_membership():
    auth = replace(_target('fortinet', ports.CONFIG), enabled_queries=(ports.CONFIG, ports.VLAN_IDS),
                   read_inventory={'managed_switches': (SERIAL,)})
    for value in ('Permission denied\n', fixture('vlan_config').replace('edit "ap-mgmt"', 'edit "other"')):
        result = ports.read_vlan(auth, {'managed_switch': SERIAL}, lambda q,t,p: tables.parse(
            'fortinet',t,q,fixture('managed_ports_config') if q == ports.CONFIG else value,
            status='permission_denied' if q == ports.VLAN_IDS and value == 'Permission denied\n' else None))
        assert result['status'] in ('unsupported','ok')
        row = next(r for r in result['records'] if r['port'] == 'port3')
        assert port_vlan.membership(row,100)['carries_vlan'] is None or result['status'] == 'unsupported'
    calls = []
    result = ports.read_vlan(replace(auth, enabled_queries=()), {'managed_switch':SERIAL}, lambda *a: calls.append(a))
    assert result['status'] == 'unsupported' and result['reason'] and not calls


@pytest.mark.parametrize('table', ['interface', 'interface_errors', 'port_vlan'])
def test_serial_port_enrolment_is_checked_before_any_device_read(monkeypatch, table):
    auth = replace(_target('fortinet', ports.STATS if table != 'port_vlan' else ports.CONFIG),
                   read_inventory={'managed_switches': (SERIAL,), 'managed_switch_ports': ('port3',)})
    monkeypatch.setattr(engine, 'record', lambda *a,**kw: None)
    calls = []
    monkeypatch.setattr(engine, 'read_from_device', lambda *a: calls.append(a))
    for serial in ('S000SSSS00000002', SERIAL + ';show'):
        with pytest.raises((ValueError,PolicyScopeError)):
            engine.switch_read(auth, table, managed_switch=serial)
    if table != 'port_vlan':
        with pytest.raises((ValueError,PolicyScopeError)):
            engine.switch_read(auth, table, managed_switch=SERIAL, interface='port4')
    assert not calls
