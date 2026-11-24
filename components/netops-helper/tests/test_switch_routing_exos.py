"""SWITCH-ROUTING: real redacted EXOS captures through fake transport, never fake parsers."""
from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from conftest import _target
from netops_helper import engine, tables
from netops_helper.auth import EgressPolicy
from netops_helper.query_catalog.extreme import QUERIES
from netops_helper.read_policy import render_read_query, _validate_query_command

EVIDENCE = Path(__file__).resolve().parent / 'fixtures/real/switch_routing_exos_20261117'
FIXTURES = EVIDENCE
INVENTORY = {'virtual_routers': ('VR-Default', 'VR-Mgmt'), 'addresses': ('192.0.2.4', '192.0.2.1')}
CASES = {
    'ping_source': 'ping', 'traceroute_source': 'trace_source',
    'ospf_neighbors': 'ospf', 'ospf_interfaces': 'ospf_interfaces', 'ospf_lsdb': 'ospf_lsdb',
    'ospfv3_neighbors': 'ospfv3', 'ospfv3_interfaces': 'ospfv3_interfaces',
    'bgp_summary': 'bgp', 'bgp_neighbor': 'bgp_detail', 'bgp_routes': 'bgp_routes',
    'vrrp': 'vrrp', 'bfd_sessions': 'bfd_sessions',
    'route_table_vr': 'routes', 'ipv6_route_table_vr': 'routes6',
    'arp_table_vr': 'arp', 'ipv6_neighbors_vr': 'nd',
}
EMPTY_ROUTING = ('ospf_neighbors', 'ospf_lsdb', 'bfd_sessions')


def auth(query):
    return replace(_target('extreme_exos', query), read_inventory=INVENTORY, device_types=('switch',),
                   egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,)))


def params(query):
    values = {'vr': 'VR-Default', 'address': '192.0.2.4', 'source': '192.0.2.1'}
    return {name: values[name] for name in QUERIES[query].slots}


def transport(monkeypatch, device, query, text, rc):
    expected = render_read_query('extreme_exos', query, params(query), INVENTORY)[1]
    calls = []
    def execute(auth, platform, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (FIXTURES / device / 'version.out').read_text()
        assert command == expected
        return rc, text
    monkeypatch.setattr(engine, '_exec_read', execute)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    return calls


@pytest.mark.parametrize('device', ['vm', 'x440', 'x435'])
@pytest.mark.parametrize('query,fixture', CASES.items())
def test_real_capture_through_ssh_read(monkeypatch, device, query, fixture):
    path = FIXTURES / device / (fixture + '.out')
    text = path.read_text()
    rc = json.loads((EVIDENCE / 'capture-manifest.json').read_text())[device][fixture]['rc']
    calls = transport(monkeypatch, device, query, text, rc)
    result = engine.ssh_read(auth(query), 'extreme_exos', query, params(query), 0, 48000)
    empty = query in EMPTY_ROUTING and (rc, text) == (250, '\n')
    good = empty or rc == 0 and bool(text.strip())
    assert result['ok'] == good, result
    if good:
        assert result['untrusted_device_output'] == text
    else:
        assert result['error_code'] in ('empty', 'device_cli_error', 'exit_status'), result
    if empty:
        assert result['status'] == 'empty' and result['normalized']['records'] == [], result
        assert 'exit_status_250' in result['normalized']['warnings']
    assert calls[-1] == render_read_query('extreme_exos', query, params(query), INVENTORY)[1]


@pytest.mark.parametrize('query', EMPTY_ROUTING)
@pytest.mark.parametrize('failure', ['cli error', 'missing stdout'])
def test_exos_routing_status_250_errors_do_not_mean_empty(monkeypatch, query, failure):
    # DERIVED: pair the real X435 refusal with rc 250 to test a same-status CLI failure.
    body = (FIXTURES / 'x435' / (CASES[query] + '.out')).read_text() if failure == 'cli error' else ''
    transport(monkeypatch, 'vm', query, body, 250)
    result = engine.ssh_read(auth(query), 'extreme_exos', query, {}, 0, 48000)
    assert not result['ok'] and result['error_code'] == 'device_cli_error', result
    assert 'exit_status_250' not in result['normalized']['warnings']


@pytest.mark.parametrize('query', ['arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors',
                                  'lldp_neighbors_detail'])
@pytest.mark.parametrize('scenario', ['empty', 'failed', 'refused'])
def test_empty_exos_catalog_tables(monkeypatch, query, scenario):
    # DERIVED: apply the measured routing blank or refusal to the table command.
    body = (FIXTURES / ('x435' if scenario == 'refused' else 'vm') / 'ospf.out').read_text()
    calls = transport(monkeypatch, 'vm', query, body, 250 if scenario == 'failed' else 0)
    result = engine.ssh_read(auth(query), 'extreme_exos', query, {}, 0, 48000)
    assert calls[-1] == QUERIES[query].command
    if scenario == 'empty':
        assert result['ok'] and result['status'] == 'empty' and result['normalized']['records'] == [], result
    else:
        assert not result['ok'] and result['error_code'] == 'device_cli_error', result


@pytest.mark.parametrize('query', ['ping', 'ping_source', 'traceroute', 'traceroute_source',
                                  'route_table_vr', 'ipv6_route_table_vr', 'arp_table_vr', 'ipv6_neighbors_vr'])
@pytest.mark.parametrize('bad', ['VR-Other', 'VR-Default; reboot', 'VR-Default\nshow version'])
def test_vr_not_enrolled_or_invalid_refuses_before_transport(monkeypatch, query, bad):
    calls = []
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    monkeypatch.setattr(engine, '_exec_read', lambda *a, **k: calls.append(a))
    values = {**params(query), 'vr': bad}
    with pytest.raises(ValueError):
        engine.ssh_read(auth(query), 'extreme_exos', query, values, 0, 48000)
    assert calls == []


@pytest.mark.parametrize('query', ['ping_source', 'traceroute_source'])
def test_probe_source_must_be_enrolled(monkeypatch, query):
    calls = []
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    monkeypatch.setattr(engine, '_exec_read', lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError):
        engine.ssh_read(auth(query), 'extreme_exos', query, {**params(query), 'source': '203.0.113.99'}, 0, 48000)
    assert calls == []


@pytest.mark.parametrize('command', ['ping continuous {address}', 'ping count 100 vr {vr} {address}',
                                    'traceroute {address}', 'ping {address}; reboot'])
def test_only_reviewed_fixed_probe_templates_allowed(command):
    with pytest.raises(RuntimeError):
        _validate_query_command('extreme_exos', command)


@pytest.mark.parametrize('device', ['vm', 'x440', 'x435'])
@pytest.mark.parametrize('ip,query,fixture', [(None, 'route_table_vr', 'routes'),
                                          ('2001:db8::4', 'ipv6_route_table_vr', 'routes6')])
def test_vr_normalized_route_through_engine(monkeypatch, device, ip, query, fixture):
    text = (FIXTURES / device / (fixture + '.out')).read_text()
    calls = transport(monkeypatch, device, query, text, 0)
    result = engine.switch_read(auth(query), 'route', ip=ip, vr='VR-Default')
    assert result['ok'] and result['coverage']['complete'], result
    assert all(row['vrf'] == 'VR-Default' for row in result['records'])
    assert calls[-1] == QUERIES[query].command.format(vr='VR-Default')
    if ip:
        assert result['records'] == [] and result['status'] == 'empty'
    else:
        assert result['records']


def test_ipv6_vendor_populated_and_vr_selection():
    text = (EVIDENCE / 'vendor-ipv6.out').read_text()
    result = tables.parse('extreme_exos', 'route', 'ipv6_route_table_vr', text,
                          command='show iproute ipv6 vr VR-Mgmt')
    assert result['ok'] and result['coverage']['complete'], result
    assert result['records'] == [
        {'prefix': '2001:db8::/64', 'next_hop': None, 'interface': 'ixia', 'protocol': 'connected', 'vrf': 'VR-Mgmt'},
        {'prefix': '2001:db8:2:78::/64', 'next_hop': 'fe80::10', 'interface': 'ixia', 'protocol': 'ospfv3', 'vrf': 'VR-Mgmt'},
    ]


@pytest.mark.parametrize('mutation', ['missing_hop', 'missing_footer', 'wrong_count', 'pager', 'bad_address'])
def test_ipv6_partial_capture_never_complete(mutation):
    text = (EVIDENCE / 'vendor-ipv6.out').read_text()
    if mutation == 'missing_hop': text = text.replace('fe80::10                                      ixia\n', '')
    if mutation == 'missing_footer': text = text.split('Total number of routes')[0]
    if mutation == 'wrong_count': text = text.replace('routes = 2', 'routes = 3')
    if mutation == 'pager': text += '\n--More--'
    if mutation == 'bad_address': text = text.replace('2001:db8::/64', 'not-ipv6/64')
    result = tables.parse('extreme_exos', 'route', 'ipv6_route_table', text)
    assert not result['ok'] and not result['coverage']['complete'], result


def test_ipv6_default_binding_and_vr_scope():
    assert tables.request('extreme_exos', 'route', ip='2001:db8::4')[:2] == ('ipv6_route_table', {})
    assert tables.request('extreme_exos', 'neighbor_l3', ip='2001:db8::4', vr='VR-Mgmt')[:2] == ('ipv6_neighbors_vr', {'vr':'VR-Mgmt'})
    with pytest.raises(ValueError): tables.request('cisco_ios', 'route', ip='192.0.2.1', vr='VR-Default')
    with pytest.raises(ValueError): tables.request('extreme_exos', 'vlan', vr='VR-Default')


@pytest.mark.parametrize('query,fixture', [('ping_source','ping'), ('ospf_interfaces','ospf_interfaces'),
                                         ('bgp_summary','bgp'), ('vrrp','vrrp'), ('ipv6_route_table_vr','routes6')])
def test_pager_reports_incomplete_for_every_group(monkeypatch, query, fixture):
    text=(FIXTURES / 'vm' / (fixture+'.out')).read_text()+'\n--More--'
    transport(monkeypatch,'vm',query,text,0)
    answer=engine.ssh_read(auth(query),'extreme_exos',query,params(query),0,48000)
    assert answer['status']=='truncated',answer


@pytest.mark.parametrize('enabled,vr', [(True,'VR-Mgmt'), (False,'VR-Mgmt'), (True,'Other')])
def test_proxy_vr_authorization_and_engine_forwarding(tmp_path,monkeypatch,enabled,vr):
    import test_proxy_contracts as contracts
    from netops_helper.auth import TargetAuth
    module=contracts._load_proxy()
    inventory,_,_,_=contracts._configure(module,tmp_path)
    section=contracts._section()
    section.update(ssh_platform='exos',device_types=['switch'],
                   enabled_queries=['ipv6_route_table_vr'] if enabled else ['ipv6_route_table'],
                   read_inventory={'virtual_routers':['VR-Default','VR-Mgmt']})
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory,contracts._inventory(contracts._device(section,'exos')))
    gateway=module.Proxy(); emitted=[]
    monkeypatch.setattr(gateway,'_emit',emitted.append)
    forwarded=gateway.request(contracts._request(1,'switch_read',{'target':'device-a','table':'route','ip':'2001:db8::4','vr':vr}))
    if not enabled or vr=='Other':
        assert forwarded is None and emitted[-1]['error']['data']['category']=='policy_scope',emitted
        return
    assert forwarded is not None,emitted
    arguments=json.loads(forwarded)['params']['arguments']
    target=TargetAuth.decode(arguments['target'],arguments['auth_context'])
    calls=[]
    def execute(auth,platform,command,**kwargs):
        calls.append(command)
        if command=='show version': return 0,(FIXTURES/'vm/version.out').read_text()
        assert command=='show iproute ipv6 vr VR-Mgmt'
        return 0,(FIXTURES/'vm/routes6.out').read_text()
    monkeypatch.setattr(engine,'_exec_read',execute)
    monkeypatch.setattr(engine,'record',lambda *a,**k:None)
    answer=engine.switch_read(target,arguments['table'],ip=arguments['ip'],vr=arguments['vr'])
    assert answer['ok'] and answer['status']=='empty' and answer['coverage']['complete'],answer
    assert calls[-1]=='show iproute ipv6 vr VR-Mgmt'


@pytest.mark.parametrize('query,filename', [('ospf_neighbors','vendor-ospf.out'),
                                          ('bgp_neighbor','vendor-bgp-detail.out'),
                                          ('bfd_sessions','vendor-bfd.out')])
def test_published_vendor_protocol_output_through_transport(monkeypatch,query,filename):
    text=(EVIDENCE/filename).read_text()
    transport(monkeypatch,'vm',query,text,0)
    result=engine.ssh_read(auth(query),'extreme_exos',query,params(query),0,48000)
    assert result['ok'] and result['untrusted_device_output']==text,result


def test_vr_whole_table_still_filters_longest_prefix(monkeypatch):
    query='route_table_vr'
    transport(monkeypatch,'vm',query,(FIXTURES/'vm/routes.out').read_text(),0)
    result=engine.switch_read(auth(query),'route',ip='192.0.2.200',vr='VR-Default')
    assert result['ok'] and result['coverage']['complete'],result
    assert [r['prefix'] for r in result['records']]==['192.0.2.0/24']
