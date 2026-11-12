"""FortiGate-local 2026-11-10 captures through the authorized engine path."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target, FORTIOS_STATUS
from netops_helper import engine, tables, fortigate_tables as fg
from netops_helper.auth import PolicyScopeError

REAL = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2_build0251/local_20261110'


def fixture(name):
    return (REAL / (name + '.txt')).read_text()


def setup_engine(monkeypatch, query, text, inventory=None):
    auth = replace(_target('fortinet', query), read_inventory=inventory or {})
    calls = []
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    def read(auth, profile, command):
        calls.append(command)
        return 0, FORTIOS_STATUS if command == 'get system status' else text
    monkeypatch.setattr(engine, 'read_from_device', read)
    return auth, calls


@pytest.mark.parametrize('table,query,name,count', [
    ('interface', 'physical_interfaces', 'physical', 11),
    ('vlan', 'interface_vlan_ids', 'vlans', 8),
    ('lldp_neighbor', 'lldp_summary', 'lldp', 2),
])
def test_captures_via_engine(monkeypatch, table, query, name, count):
    auth, calls = setup_engine(monkeypatch, query, fixture(name))
    result = engine.switch_read(auth, table)
    assert result['status'] == 'ok' and len(result['records']) == count
    assert calls == ['get system status', tables.READ_QUERIES['fortinet'][query].command]
    assert result['sources'][0]['query'] == query
    assert not result['unparsed']
    if table == 'interface':
        rows = {r['name']: r for r in result['records']}
        assert (rows['a']['oper_status'], rows['a']['speed'], rows['a']['duplex']) == ('up','1000M','full')
        assert rows['internal1']['oper_status'] == 'down' and rows['internal1']['speed'] is None
        assert rows['a']['admin_status'] is None  # link status does not establish admin state
    elif table == 'vlan':
        row = next(r for r in result['records'] if r['vlan_id'] == 100)
        assert (row['name'],row['interface'],row['ip'],row['prefix_length']) == ('ap-mgmt','fortilink','192.0.2.4',24)
        assert row['ports'] is None and row['source'] == 'configuration'
        result = engine.switch_read(auth, table, vlan_id='100')
        assert len(result['records']) == 1
    else:
        assert result['records'][0]['local_port'] == 'a'
        assert result['records'][0]['neighbor_port'] == 'port2'
        assert result['records'][0]['neighbor'] == 'S000SSSS00000001'
        assert result['records'][0]['management_ip'] is None


def test_projection_removes_unrelated_configuration(monkeypatch):
    text = fixture('vlans').replace('set vlanid 100', 'set vlanid 100\n        set password "private-fixture-marker"')
    auth, _ = setup_engine(monkeypatch, 'interface_vlan_ids', text)
    result = engine.switch_read(auth, 'vlan')
    assert result['status'] == 'ok'  # the keyword remains parseable; projection removes its hidden value
    assert len(result['records']) == 8
    assert 'private-fixture-marker' not in str(result)
    view = engine._fortiswitch_configuration_output('fortinet','interface_vlan_ids',{},text)
    assert 'private-fixture-marker' not in view
    assert 'set interface' in view and 'set ip' in view


@pytest.mark.parametrize('table,query', [('interface','physical_interfaces'),('vlan','interface_vlan_ids'),('lldp_neighbor','lldp_summary')])
def test_refused_disabled_and_unknown_output(monkeypatch, table, query):
    auth, calls = setup_engine(monkeypatch, query, 'Command fail. Return code -61\n')
    assert engine.switch_read(auth,table)['status'] == 'permission_denied'
    calls.clear()
    with pytest.raises(PolicyScopeError):
        engine.switch_read(replace(auth,enabled_queries=()),table)
    assert calls == []
    parsed = tables.parse('fortinet',table,query,'NEW OUTPUT\n')
    assert parsed['status'] == 'unparsed' and parsed['unparsed']


def test_empty_local_bridge_and_unqualified_populated_layout(monkeypatch):
    auth, calls = setup_engine(monkeypatch,'bridge_mac_table',fixture('bridge_empty'),{'switches':('internal',)})
    result = engine.switch_read(auth,'mac_entry')
    assert result['status'] == 'empty' and result['bridges'] == ['internal']
    assert calls == ['get system status','diagnose netlink brctl name host internal']
    result = tables.parse('fortinet','mac_entry','bridge_mac_table',fixture('bridge_empty')+'NEW ROW\n')
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    calls.clear()
    result = engine.switch_read(replace(auth,read_inventory={}), 'mac_entry')
    assert result['status'] == 'not_applicable' and result['reason'] == 'FortiGate je L3; MAC klientů viz arp a FortiSwitch'
    assert calls == []


def test_multiple_bridges_preserve_refusal(monkeypatch):
    auth, _ = setup_engine(monkeypatch,'bridge_mac_table',fixture('bridge_empty'),{'switches':('internal','other')})
    def read(query,table,parameters):
        return tables.parse('fortinet',table,query,fixture('bridge_empty') if parameters['switch']=='internal' else 'Command fail. Return code -61\n',
                            status=None if parameters['switch']=='internal' else 'permission_denied')
    result = fg.read_mac(auth,read)
    assert result['status'] == 'permission_denied' and not result['coverage']['complete']
    assert len(result['sources']) == 2


def test_incomplete_blocks_and_bad_vlan_stay_unknown():
    assert tables.parse('fortinet','interface','physical_interfaces','== [onboard]\n ==[a]\n status: up\n')['status'] == 'unparsed'
    for text in (fixture('vlans').replace('set vlanid 100','set vlanid 5000'),
                 fixture('vlans').replace('255.255.255.0','invalid-mask'),
                 fixture('vlans').replace('set interface "fortilink"','set interface "a" "b"')):
        assert tables.parse('fortinet','vlan','interface_vlan_ids',text)['status'] == 'unparsed'


@pytest.mark.parametrize('table', ['interface','vlan','lldp_neighbor','mac_entry'])
def test_local_tables_do_not_accept_unrelated_filters(table):
    with pytest.raises(ValueError):
        tables.request('fortinet',table,ip='192.0.2.1')
    with pytest.raises(ValueError):
        tables.request('fortinet',table,interface='wan1')
