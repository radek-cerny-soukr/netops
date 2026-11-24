"""Real EXOS service captures through the Helper, with scoped L2 requests."""
from dataclasses import replace
from pathlib import Path
import json

import pytest
from conftest import _target
from netops_helper import engine, tables
from netops_helper.read_policy import render_read_query

# Real SWITCH-SERVICES captures (verification); '.out' keeps them out of the historical classifier captures (*.txt).
FIXTURES = Path(__file__).parent / 'fixtures' / 'real' / 'switch_services_exos_20261117'
# query -> capture and explicit parameters; only the transport is faked.
CASES = {
    'access_lists': ('access_list', {}), 'policies': ('policy_detail', {}),
    'policy_details': ('policy', {'policy': 'netops-switch-services'}),
    'dhcp_server': ('dhcp_server', {'vlan': 'Default'}),
    'bootprelay': ('bootprelay', {}), 'bootprelay_configuration': ('bootprelay_configuration', {}),
    'radius': ('radius', {}), 'tacacs': ('tacacs', {}), 'accounts': ('accounts', {}),
    'netlogin': ('netlogin', {}), 'netlogin_port': ('netlogin_port', {'interface': '1'}),
    'dns_client': ('dns_client', {}), 'dns_lookup': ('nslookup', {'name': 'example.com'}),
    'management': ('management', {}), 'snmp_engine': ('snmpv3_engine', {}),
    'snmp_targets': ('snmpv3_target', {}),
    'dhcp_snooping': ('dhcp_snooping', {'vlan': 'Default'}),
    'dhcp_snooping_violations': ('dhcp_snooping_violations', {'vlan': 'Default'}),
    'mac_address': ('mac_address', {'mac': '00:00:5e:00:53:01'}),
    'mac_vlan': ('mac_vlan_id', {'vlan_id': '1'}),
    'arp_vlan': ('arp_vlan_id', {'vlan_id': '1'}),
}


def fake(monkeypatch, device, body, rc):
    sent = []
    def read(auth, platform, command):
        sent.append(command)
        if command == 'show version':
            return 0, (FIXTURES/device/'version.out').read_text()
        return rc, body
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    return sent


def target(query):
    return replace(_target('extreme_exos', query), read_inventory={'vlans': ('Default',), 'interfaces': ('1',)})


@pytest.mark.parametrize('device', ['x435', 'x440'])
@pytest.mark.parametrize('query', CASES)
def test_real_service_output(monkeypatch, device, query):
    capture, parameters = CASES[query]
    # Only X440 has an additional numeric VLAN capture; X435 named VLAN
    # output has the same framing, not an invented successful response.
    if device == 'x435' and capture.endswith('_vlan_id'):
        capture = capture.removesuffix('_id')
    body = (FIXTURES/device/(capture+'.out')).read_text()
    meta = json.loads((FIXTURES/device/'commands.json').read_text())[capture]
    sent = fake(monkeypatch, device, body, meta['rc'])
    answer = engine.ssh_read(target(query), 'extreme_exos', query, parameters, 0, 48000)
    assert sent[-1] == render_read_query('extreme_exos', query, parameters, target(query).read_inventory)[1]
    if query in ('accounts', 'policies', 'policy_details', 'dhcp_server'):
        assert answer['ok'] is False
        assert answer['error_code'] == ('empty' if query == 'dhcp_server' else 'device_cli_error')
    else:
        assert answer['ok'] is True, answer
        assert answer['untrusted_device_output'].strip()


@pytest.mark.parametrize('query', CASES)
def test_real_denial_cannot_be_success(monkeypatch, query):
    fake(monkeypatch, 'x440', (FIXTURES/'x440/accounts.out').read_text(), 254)
    answer = engine.ssh_read(target(query), 'extreme_exos', query, CASES[query][1], 0, 48000)
    assert answer['ok'] is False


@pytest.mark.parametrize('query', CASES)
def test_pager_is_incomplete(monkeypatch, query):
    capture, parameters = CASES[query]
    body = (FIXTURES/'x440'/(capture+'.out')).read_text()
    fake(monkeypatch, 'x440', body + '\n--More--', 0)
    answer = engine.ssh_read(target(query), 'extreme_exos', query, parameters, 0, 48000)
    assert answer.get('status') == 'truncated' or answer['ok'] is False


@pytest.mark.parametrize('table,filters,query,params', [
    ('mac_entry', {'mac':'00:00:5e:00:53:01'}, 'mac_address', {'mac':'00:00:5e:00:53:01'}),
    ('mac_entry', {'vlan_id':'1'}, 'mac_vlan', {'vlan_id':'1'}),
    ('neighbor_l3', {'vlan_id':'1'}, 'arp_vlan', {'vlan_id':'1'}),
    ('mac_entry', {'vlan_id':'1', 'mac':'00:00:5e:00:53:01'}, 'mac_address', {'mac':'00:00:5e:00:53:01'}),
])
def test_device_side_l2_filter(table, filters, query, params):
    name, parameters, local = tables.request('extreme_exos', table, **filters)
    assert (name, parameters) == (query, params)
    for key in filters:
        assert key in local


@pytest.mark.parametrize('table,query,capture', [
    ('mac_entry','mac_vlan','mac_vlan_id'), ('neighbor_l3','arp_vlan','arp_vlan_id'),
])
def test_real_scoped_l2_parser(table, query, capture):
    body = (FIXTURES/'x440'/(capture+'.out')).read_text()
    result = tables.parse('extreme_exos', table, query, body, command='show fdb vlan 1' if table == 'mac_entry' else 'show iparp vlan 1')
    assert result['status'] == 'ok', result
    assert result['records'] and all(r['vlan_id'] == 1 for r in result['records'])


@pytest.mark.parametrize('query,params', [
    ('dns_lookup', {'name':'example.com;show accounts'}), ('dns_lookup', {'name':'-server'}),
    ('policy_details', {'policy':'detail'}), ('policy_details', {'policy':'x\nshow accounts'}),
    ('mac_address', {'mac':'all'}), ('mac_vlan', {'vlan_id':'4095'}),
    ('netlogin_port', {'interface':'all'}), ('dhcp_server', {'vlan':'other'}),
])
def test_invalid_or_unenrolled_scope_rejected(query, params):
    with pytest.raises(ValueError):
        render_read_query('extreme_exos', query, params, target(query).read_inventory)


def test_service_credentials_removed_before_paging(monkeypatch):
    body = (FIXTURES/'x440/management.out').read_text()
    body = body.replace('Total Read Only Communities', 'Read Community: switch-services-credential-a\nShared Secret : switch-services-credential-b\nTotal Read Only Communities')
    body = body.replace('RMON ', 'switch-services-unlabelled-community\nRMON ')
    body += '\nPrivate Key: switch-services-credential-c\nOther: ENC switch-services-credential-d\n'
    fake(monkeypatch, 'x440', body, 0)
    answer = engine.ssh_read(target('management'), 'extreme_exos', 'management', {}, 0, 48000)
    assert answer['ok'] is True
    encoded = json.dumps(answer)
    assert 'switch-services-credential' not in encoded and 'switch-services-unlabelled-community' not in encoded
    assert 'SNMP access' in encoded and 'snmp_targets' in encoded


@pytest.mark.parametrize('table,query,capture', [
    ('mac_entry', 'mac_vlan', 'mac_vlan_id'), ('neighbor_l3', 'arp_vlan', 'arp_vlan_id'),
])
def test_switch_read_sends_scope_and_returns_real_rows(monkeypatch, table, query, capture):
    sent = fake(monkeypatch, 'x440', (FIXTURES/'x440'/(capture+'.out')).read_text(), 0)
    answer = engine.switch_read(target(query), table, vlan_id='1', limit=100, max_bytes=48000)
    assert answer['status'] == 'ok', answer
    assert answer['records'] and all(row['vlan_id'] == 1 for row in answer['records'])
    assert sent[-1] == ('show fdb vlan 1' if table == 'mac_entry' else 'show iparp vlan 1')


# Positive captures from the lab X440 with the R/W ai-login account and temporary
# test objects (verification): policy x04test on port 12, VLAN x07test with a DHCP pool.
ADMIN_CASES = {
    'access_lists': ('access_list', {}, ('x04test', 'ingress', '12')),
    'policies': ('policy_detail', {}, ('Policy: x04test', 'entry x04-deny-doc', 'deny', 'count x04-doc-hits')),
    'policy_details': ('policy', {'policy': 'x04test'}, ('Policy: x04test', 'source-address')),
    'dhcp_server': ('dhcp_server', {'vlan': 'x07test'}, ('VLAN "x07test"', 'DHCP Address Range', 'DHCP Lease Timer     : 600 seconds', 'Ports DHCP Enabled   : 14')),
    'accounts': ('accounts', {}, ('User Name', 'R/W', 'RO', 'Enabled')),
}


def admin_target(query):
    return replace(_target('extreme_exos', query), read_inventory={'vlans': ('Default', 'x07test'), 'interfaces': ('12', '14')})


@pytest.mark.parametrize('query', ADMIN_CASES)
def test_real_positive_admin_output(monkeypatch, query):
    capture, parameters, expected = ADMIN_CASES[query]
    body = (FIXTURES/'x440-admin'/(capture+'.out')).read_text()
    meta = json.loads((FIXTURES/'x440-admin'/'commands.json').read_text())[capture]
    assert meta['rc'] == 0 and body.strip()
    sent = fake(monkeypatch, 'x440', body, meta['rc'])
    target = admin_target(query)
    answer = engine.ssh_read(target, 'extreme_exos', query, parameters, 0, 48000)
    assert sent[-1] == render_read_query('extreme_exos', query, parameters, target.read_inventory)[1] == meta['command']
    assert answer['ok'] is True, answer
    assert answer['untrusted_device_output'].strip() == body.strip()
    for text in expected:
        assert text in answer['untrusted_device_output']


@pytest.mark.parametrize('query', ADMIN_CASES)
def test_real_positive_admin_output_paged_is_not_complete(monkeypatch, query):
    capture, parameters, _ = ADMIN_CASES[query]
    body = (FIXTURES/'x440-admin'/(capture+'.out')).read_text()
    fake(monkeypatch, 'x440', body + '\n--More--', 0)
    answer = engine.ssh_read(admin_target(query), 'extreme_exos', query, parameters, 0, 48000)
    assert answer.get('status') == 'truncated' or answer['ok'] is False
