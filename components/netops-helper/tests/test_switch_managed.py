"""FortiLink tables over the dated read-only capture and enrolled catalogue slots."""
from dataclasses import replace
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.auth import PolicyScopeError
from conftest import _target, FORTIOS_STATUS

REAL = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2_build0251'
SERIAL = 'S000SSSS00000001'


def test_captured_mac_rows_flags_and_trunks():
    result = tables.parse('fortinet', 'mac_entry', 'managed_switch_mac',
                          (REAL / 'managed_switch_mac_all.txt').read_text())
    assert result['status'] == 'ok' and not result['unparsed']
    assert result['coverage']['complete'] and len(result['records']) == 24
    assert result['records'][1] == {'mac': '00:00:5e:00:53:02', 'vlan_id': 100, 'port': 'port3',
                                     'type': 'dynamic', 'vlan_name': None}
    assert result['records'][4]['type'] == 'static'
    assert result['records'][0]['type'] == 'trunk'


@pytest.mark.parametrize('number,ports', [(1, ['port2', 'port3', 'port13', 'port14', 'port23']),
                                        (2, ['port1', 'port3', 'port13', 'port14', 'port24'])])
def test_captured_lldp_skips_empty_slots_and_reports_missing_management_address(number, ports):
    result = tables.parse('fortinet', 'lldp_neighbor', 'managed_switch_lldp',
                          (REAL / f'managed_switch_lldp_{number}.txt').read_text())
    assert result['status'] == 'ok' and not result['unparsed']
    assert [row['local_port'] for row in result['records']] == ports
    assert result['records'][1]['capabilities'] == 'B,W,R,S'
    assert result['records'][1]['neighbor_port'].startswith('00:00:5e:00:53:')
    assert result['coverage']['missing_fields'] == ['management_ip']
    assert not result['coverage']['complete']


@pytest.mark.parametrize('table,file', [('mac_entry', 'managed_switch_mac_all.txt'),
                                       ('lldp_neighbor', 'managed_switch_lldp_1.txt')])
def test_unknown_lines_survive_with_original_line_number_even_outside_filter(table, file):
    text = (REAL / file).read_text().rstrip('\n') + '\nNEW OUTPUT\n'
    result = tables.parse('fortinet', table, tables.BINDINGS['fortinet'][table], text,
                          filters={'mac': '00:00:5e:00:53:ff'} if table == 'mac_entry' else None)
    assert result['status'] == 'unparsed'
    assert result['unparsed'] == [{'line': len(text.splitlines()), 'text': 'NEW OUTPUT'}]
    assert not result['coverage']['complete']


@pytest.mark.parametrize('table', ['mac_entry', 'lldp_neighbor'])
def test_serial_selects_managed_tables_and_only_applies_to_them(table):
    query, parameters, _ = tables.request('fortinet', table, managed_switch=SERIAL)
    assert query == 'managed_switch_' + ('mac' if table == 'mac_entry' else 'lldp')
    assert parameters == {'managed_switch': SERIAL}
    query, parameters, _ = tables.request('fortinet', table)
    assert query == ('lldp_summary' if table == 'lldp_neighbor' else None)
    assert parameters == {}
    with pytest.raises(ValueError, match='managed_switch'):
        tables.request('cisco_ios', table, managed_switch=SERIAL)
    with pytest.raises(ValueError, match='managed_switch'):
        tables.request('fortinet', 'neighbor_l3', managed_switch=SERIAL)


@pytest.mark.parametrize('table', ['mac_entry', 'lldp_neighbor'])
def test_worker_checks_query_and_inventory_before_identity_or_device_read(monkeypatch, table):
    query = tables.BINDINGS['fortinet'][table]
    auth = replace(_target('fortinet', query), read_inventory={'managed_switches': (SERIAL,)})
    calls = []
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', lambda *a: calls.append(a))
    for denied in (replace(auth, enabled_queries=()), replace(auth, read_inventory={})):
        with pytest.raises((PolicyScopeError, ValueError)):
            engine.switch_read(denied, table, managed_switch=SERIAL)
    for serial in ('S000SSSS00000002', SERIAL + ';show', '', 'all'):
        with pytest.raises((PolicyScopeError, ValueError)):
            engine.switch_read(auth, table, managed_switch=serial)
    assert not calls


def test_worker_uses_one_serial_and_applies_filters_before_paging(monkeypatch):
    text = (REAL / 'managed_switch_mac_all.txt').read_text()
    # The capture read all switches. Replay the exact first switch block for a slotted request.
    block = 'Managed Switch :' + text.split('Managed Switch :')[1]
    auth = replace(_target('fortinet', 'managed_switch_mac'), read_inventory={'managed_switches': (SERIAL,)})
    calls = []
    def read(auth, profile, command):
        calls.append(command)
        return 0, FORTIOS_STATUS if command == 'get system status' else block
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.switch_read(auth, 'mac_entry', managed_switch=SERIAL, vlan_id='100', limit=1)
    assert result['status'] == 'ok' and result['managed_switch'] == SERIAL
    assert result['records'] == [{'mac': '00:00:5e:00:53:02', 'vlan_id': 100, 'port': 'port3',
                                   'type': 'dynamic', 'vlan_name': None}]
    assert result['has_more'] and result['next']['offset'] == 1
    assert calls == ['get system status', 'diagnose switch-controller switch-info mac-table ' + SERIAL]
