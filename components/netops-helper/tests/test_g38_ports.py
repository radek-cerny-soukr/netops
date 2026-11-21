"""G38 uses real anonymized captures; only SSH transport is replaced."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, tables
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.read_policy import render_read_query

ROOT = Path(__file__).parent / 'fixtures/g38'


def fixture(device, name):
    return (ROOT / device / (name + '.out')).read_text()


CASES = [
    ('x440', 'budget', 'poe_budget', 'inline_power', None),
    ('extreme-sw1', 'budget', 'poe_budget', 'inline_power', None),
    ('x440', 'poe', 'poe_port', 'inline_power_port', '1'),
    ('extreme-sw1', 'poe', 'poe_port', 'inline_power_port', '1'),
    ('sw2', 'optics', 'optics_port', 'interface_transceiver', '13'),
    ('sw3', 'optics', 'optics_port', 'interface_transceiver', '13'),
    ('x440', 'utilization', 'port_utilization', 'port_utilization', '1'),
    ('x440', 'pps', 'port_packets', 'port_packets', '1'),
    ('exos-b', 'lacp5', 'lacp_member', 'lacp_member', '5'),
    ('x440', 'stp', 'stp_port', 'stp_ports', None),
    ('extreme-sw1', 'stp', 'stp_port', 'stp_ports', None),
    ('exos-a', 'stp', 'stp_port', 'stp_ports', None),
]


def transport(monkeypatch, outputs, interface='1', domain='s0', device='x440'):
    auth = replace(_target('extreme_exos', next(iter(outputs))), enabled_queries=tuple(outputs),
                   read_inventory={'interfaces': (interface,), 'services': (domain,)})
    commands = {READ_QUERIES['extreme_exos'][q].command.format(interface=interface, domain=domain): body
                for q, body in outputs.items()}
    calls = []
    def read(auth, profile, command):
        calls.append(command)
        return (0, fixture(device, 'version')) if command == 'show version' else (0, commands[command])
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    return auth, calls


@pytest.mark.parametrize('device,name,table,query,interface', CASES)
def test_public_table_real_transport(monkeypatch, device, name, table, query, interface):
    auth, calls = transport(monkeypatch, {query: fixture(device, name)}, interface or '1', device=device)
    result = engine.switch_read(auth, table, interface=interface)
    assert result['status'] == 'ok', result
    assert result['records'] and result['coverage']['complete'], result
    assert calls[-1] == READ_QUERIES['extreme_exos'][query].command.format(interface=interface)
    row = result['records'][0]
    if table == 'poe_port':
        assert row['state'] == 'searching' and row['power_w'] == 0 and row['class'] is None
    if table == 'optics_port':
        assert row['state'] == 'measured' and row['tx_dbm'] < 0 and row['temperature_c'] > 0
    if table == 'lacp_member':
        assert row['mux_state'] == 'Collect-Dist' and row['actor_flags'] == 'A-GSCD--'
        assert row['partner_key'] == '0x0068' and row['partner_port'] == 15
    if table == 'stp_port':
        assert row['state'] in ('disabled', 'forwarding')


@pytest.mark.parametrize('device,name,table,query,interface', CASES)
def test_refusal_and_incomplete(monkeypatch, device, name, table, query, interface):
    auth, _ = transport(monkeypatch, {query: 'This user does not have permissions for this command.\n'}, interface or '1', device=device)
    result = engine.switch_read(auth, table, interface=interface)
    assert result['status'] == 'permission_denied' and not result['records']
    auth, _ = transport(monkeypatch, {query: fixture(device, name) + '\nPress <SPACE> to continue or <Q> to quit:\n'}, interface or '1', device=device)
    result = engine.switch_read(auth, table, interface=interface)
    assert result['status'] == 'truncated' and not result['coverage']['complete']


@pytest.mark.parametrize('query,name', [('port_qos','qos'), ('port_qos_drops','qos-drops'),
                                       ('igmp_snooping','igmp-snooping'), ('igmp_groups','igmp-group'),
                                       ('stp_port_detail','stp-detail'), ('ipconfig_ipv6','ip6')])
def test_raw_queries_real_output(monkeypatch, query, name):
    device = 'extreme-lab' if name == 'qos-drops' else 'x440'
    output = fixture(device, name)
    auth, calls = transport(monkeypatch, {query: output})
    params = {'interface': '1', 'domain': 's0'} if query == 'stp_port_detail' else {'interface': '1'} if query.startswith('port_') else None
    result = engine.ssh_read(auth, 'extreme_exos', query, params, 0, 16000)
    assert result['ok'], result
    assert result['untrusted_device_output'].strip() == output.strip()
    assert calls[-1] == READ_QUERIES['extreme_exos'][query].command.format(**(params or {}))


def test_domain_and_interface_enrollment_before_transport(monkeypatch):
    auth, calls = transport(monkeypatch, {'stp_port_detail': fixture('x440', 'stp-detail')})
    with pytest.raises(ValueError):
        engine.triage_port(auth, '2', 's0')
    assert calls == []
    with pytest.raises(ValueError):
        engine.triage_port(auth, '1', 'other')
    assert calls == []
    for domain in ('s0; reboot', 's0\nshow accounts', '../s0'):
        with pytest.raises(ValueError):
            render_read_query('extreme_exos', 'stp_domain_ports', {'domain': domain}, {'services': (domain,)})
    # Another domain is rendered exactly and never silently rewritten to s0.
    assert render_read_query('extreme_exos', 'stp_domain_ports', {'domain': 'lab-stp'}, {'services': ('lab-stp',)})[1] == 'show stpd lab-stp ports'


def test_lacp_cut_does_not_claim_complete():
    text = fixture('exos-b', 'lacp5').split('LAG Id:')[0]
    result = tables.parse('extreme_exos', 'lacp_member', 'lacp_member', text)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['records'][0]['partner_key'] is None


def test_tagged_single_vlan_is_trunk_and_untagged_is_access(monkeypatch):
    auth, _ = transport(monkeypatch, {'ports': fixture('x440', 'ports'), 'vlan_detail': fixture('x440', 'vlan')})
    result = engine.switch_read(auth, 'interface')
    assert result['status'] == 'ok', result
    assert result['coverage']['complete'], result
    memberships = engine.switch_read(auth, 'port_vlan')
    for row in result['records']:
        match = next((m for m in memberships['records'] if m['port'] == row['name']), None)
        if match:
            assert row['trunk'] == bool(match['tagged_vlans'])
            assert row['vlan_id'] == (match['native_vlan'] if match['mode'] == 'trunk' else match['access_vlan'])


def test_triage_records_missing_sources_without_inventing_cause(monkeypatch):
    auth, calls = transport(monkeypatch, {'stp_port_detail': fixture('x440', 'stp-detail')})
    result = engine.triage_port(auth, '1')
    assert result['verdict'] == 'incomplete' and result['missing'] and not result['findings']
    assert 'poe_port' in result['missing'] and 'mlag_ports' in result['missing']
    assert all(c in ('show version', 'show stpd s0 ports 1 detail') for c in calls)


@pytest.mark.parametrize('query,name', [('port_qos','qos'), ('port_qos_drops','qos-drops'),
                                       ('igmp_snooping','igmp-snooping'), ('igmp_groups','igmp-group'),
                                       ('stp_port_detail','stp-detail'), ('ipconfig_ipv6','ip6')])
def test_raw_query_refusal_and_pager(monkeypatch, query, name):
    params = {'interface': '1', 'domain': 's0'} if query == 'stp_port_detail' else {'interface': '1'} if query.startswith('port_') else None
    for output in ('This user does not have permissions for this command.\n',
                   fixture('extreme-lab' if name == 'qos-drops' else 'x440', name) + '\nPress <SPACE> to continue or <Q> to quit:\n'):
        auth, _ = transport(monkeypatch, {query: output})
        result = engine.ssh_read(auth, 'extreme_exos', query, params, 0, 16000)
        assert result['status'] in ('permission_denied', 'truncated'), result


def test_full_description_join_and_budget(monkeypatch):
    auth, _ = transport(monkeypatch, {q: fixture('x440', f) for q, f in (
        ('ports','ports'), ('vlan_detail','vlan'), ('ports_description','description'), ('inline_power','budget'))})
    result = engine.switch_read(auth, 'interface', interface='1')
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert result['records'][0]['description'] == 'port-desc-01'
    budget = engine.switch_read(auth, 'poe_budget')['records'][0]
    assert budget == {'state': 'Operational', 'budget_w': 200.0, 'power_w': 0.0}


def test_error_time_series_uses_existing_real_counter_baseline(monkeypatch):
    auth, _ = transport(monkeypatch, {'ports_rx_errors': fixture('extreme-lab', 'rx'),
                                    'ports_tx_errors': fixture('extreme-lab', 'tx')})
    first = engine.switch_read(auth, 'interface_errors', interface='1')
    second = engine.switch_read(auth, 'interface_errors', interface='1', baseline=first['counter_baseline'])
    assert first['status'] == second['status'] == 'ok'
    assert second['records'][0]['delta']['crc'] == 0
    assert second['summary']['baseline']['interval_seconds'] >= 0


def test_new_tables_and_triage_through_proxy(tmp_path, monkeypatch):
    import json
    import test_proxy_contracts as contracts
    from netops_helper.auth import TargetAuth
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform='exos', device_types=['switch'], enabled_queries=['inline_power_port', 'stp_port_detail'],
                   read_inventory={'interfaces': ['1'], 'services': ['s0'], 'addresses': [], 'switches': []})
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'exos')))
    gateway = module.Proxy()
    calls = []
    def read(auth, profile, command):
        calls.append(command)
        return 0, fixture('x440', {'show version': 'version', 'show inline-power info ports 1': 'poe',
                                 'show stpd s0 ports 1 detail': 'stp-detail'}[command])
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    for i, tool, args in [(1, 'switch_read', {'table': 'poe_port', 'interface': '1'}),
                          (2, 'triage_port', {'interface': '1'})]:
        forwarded = gateway.request(contracts._request(i, tool, {'target': 'device-a', **args}))
        assert forwarded is not None
        args = json.loads(forwarded)['params']['arguments']
        auth = TargetAuth.decode(args.pop('target'), args.pop('auth_context'))
        result = getattr(engine, tool)(auth, **args)
        assert result['status'] == 'ok' if tool == 'switch_read' else result['verdict'] == 'incomplete'
    before = len(calls)
    denied = gateway.request(contracts._request(3, 'triage_port', {'target': 'device-a', 'interface': '1', 'domain': 'other'}))
    assert denied is None and len(calls) == before


@pytest.mark.parametrize('device,name,table,query,interface', CASES)
def test_unrecognized_line_preserves_incomplete_coverage(device,name,table,query,interface):
    result = tables.parse('extreme_exos', table, query, fixture(device,name) + '\nUnexpected new firmware field\n')
    # The existing DOM adapter reports its recognized metrics; the other new tables
    # must preserve unknown lines rather than silently accepting a firmware variant.
    if table != 'optics_port':
        assert result['status'] == 'unparsed' and not result['coverage']['complete']



def test_real_vm_power_budget_not_operational_is_not_measured_zero(monkeypatch):
    output = (ROOT.parent / 'real/exos/exosvm_33.6.1.14/inline_power.txt').read_text()
    auth, _ = transport(monkeypatch, {'inline_power': output}, device='exos-a')
    result = engine.switch_read(auth, 'poe_budget')
    assert result['status'] == 'ok' and result['coverage']['complete'], result
    assert result['records'] == [{'state': 'Not Operational', 'budget_w': 0.0, 'power_w': None}]


def ordinary_port_outputs(device='extreme-lab'):
    outputs = {q: fixture(device, f) for q, f in (
        ('ports', 'ports'), ('ports_description', 'description'), ('vlan_detail', 'vlan'),
        ('ports_rx_errors', 'rx'), ('ports_tx_errors', 'tx'),
        ('lldp_interface_details', 'lldp'), ('inline_power_port', 'poe'),
        ('interface_transceiver', 'optics'), ('lacp_member', 'lacp'),
        ('stp_port_detail', 'stp-detail'), ('mlag_peer', 'mlag-peer'), ('mlag_ports', 'mlag-ports'))}
    # Older captures contain a vault redaction inside the word 'awaiting'; use
    # the later clean capture. DOM must be for the queried port 1, not port 13.
    outputs['ports'] = fixture('x440', 'ports')
    outputs['interface_transceiver'] = (ROOT.parent / 'real/exos/dom_33.7.1.6_20261114/existing_port1_ddmi_unsupported.txt').read_text()
    return outputs


@pytest.mark.parametrize('device', ['extreme-lab', 'extreme-sw1'])
def test_ordinary_nonmember_port_has_conclusion(monkeypatch, device):
    auth, calls = transport(monkeypatch, ordinary_port_outputs(device), device=device)
    result = engine.triage_port(auth, '1')
    assert result['ok'] and result['verdict'] in ('findings', 'no_fault_observed'), {k: (v.get('status'), v.get('coverage'), v.get('unparsed')) for k, v in result['evidence'].items() if k in result['missing']}
    assert result['missing'] == []
    assert result['evidence']['lacp_member']['status'] == 'not_applicable'
    lldp = result['evidence']['lldp_neighbor']
    assert lldp['coverage']['complete'] and lldp['records'][0]['neighbor'] == 'host01'
    assert lldp['records'][0]['management_ip'] is None
    if device == 'extreme-sw1':
        assert result['evidence']['mlag_peer']['status'] == 'not_applicable'
        assert result['evidence']['mlag_ports']['status'] == 'not_applicable'
    assert all(command.startswith('show ') for command in calls)


@pytest.mark.parametrize('query,source', [('lacp_member','lacp_member'), ('inline_power_port','poe_port'),
                                        ('mlag_peer','mlag_peer'), ('mlag_ports','mlag_ports'),
                                        ('lldp_interface_details','lldp_neighbor')])
@pytest.mark.parametrize('failure', ['permission', 'pager', 'transport', 'unknown'])
def test_ordinary_port_preserves_read_failures(monkeypatch, query, source, failure):
    outputs = ordinary_port_outputs()
    original = outputs[query]
    outputs[query] = {'permission': 'This user does not have permissions for this command.\n',
                      'pager': original + '\nPress <SPACE> to continue or <Q> to quit:\n',
                      'transport': original, 'unknown': 'Error: unexpected firmware failure\n'}[failure]
    auth, _ = transport(monkeypatch, outputs)
    if failure == 'transport':
        read = engine.read_from_device
        command = READ_QUERIES['extreme_exos'][query].command.format(interface='1')
        monkeypatch.setattr(engine, 'read_from_device',
                            lambda a, p, c: (255, original) if c == command else read(a, p, c))
    result = engine.triage_port(auth, '1')
    assert not result['ok'] and result['verdict'] == 'incomplete'
    assert source in result['missing'], result


@pytest.mark.parametrize('rc', [0, 250])
def test_non_poe_port_is_not_applicable(monkeypatch, rc):
    outputs = ordinary_port_outputs()
    outputs['inline_power_port'] = 'Port 1 is not inline-power capable\n'
    auth, _ = transport(monkeypatch, outputs)
    read = engine.read_from_device
    monkeypatch.setattr(engine, 'read_from_device', lambda a, p, c:
                        (rc, outputs['inline_power_port']) if c == 'show inline-power info ports 1' else read(a, p, c))
    result = engine.triage_port(auth, '1')
    assert result['verdict'] in ('findings', 'no_fault_observed') and result['ok'], result
    assert result['evidence']['poe_port']['status'] == 'not_applicable'
    assert result['evidence']['poe_port']['records'] == []


@pytest.mark.parametrize('rc', [0, 254, 255])
def test_unsupported_mlag_exit_status(monkeypatch, rc):
    # Real X435 capture-commands.json records exit 254 for both unsupported
    # MLAG commands. SSH exit 255 must remain a failed read even with that text.
    outputs = ordinary_port_outputs()
    outputs.update(mlag_peer=fixture('extreme-sw1', 'mlag-peer'),
                   mlag_ports=fixture('extreme-sw1', 'mlag-ports'))
    auth, _ = transport(monkeypatch, outputs)
    read = engine.read_from_device
    monkeypatch.setattr(engine, 'read_from_device', lambda a, p, c:
                        (rc, outputs['mlag_peer' if c.endswith('peer') else 'mlag_ports'])
                        if c in ('show mlag peer', 'show mlag ports') else read(a, p, c))
    result = engine.triage_port(auth, '1')
    if rc == 255:
        assert result['verdict'] == 'incomplete' and {'mlag_peer', 'mlag_ports'} <= set(result['missing'])
    else:
        assert result['ok'] and result['verdict'] in ('findings', 'no_fault_observed'), result['missing']
        assert result['evidence']['mlag_peer']['status'] == 'not_applicable'


@pytest.mark.parametrize('rc', [250, 255])
def test_nonmember_lacp_exit_status(monkeypatch, rc):
    outputs = ordinary_port_outputs()
    auth, _ = transport(monkeypatch, outputs)
    read = engine.read_from_device
    monkeypatch.setattr(engine, 'read_from_device', lambda a, p, c:
                        (rc, outputs['lacp_member']) if c == 'show lacp member-port 1 detail' else read(a, p, c))
    result = engine.triage_port(auth, '1')
    if rc == 255:
        assert result['verdict'] == 'incomplete'
    else:
        assert result['ok'] and result['verdict'] in ('findings', 'no_fault_observed')
    assert ('lacp_member' in result['missing']) == (rc == 255)
