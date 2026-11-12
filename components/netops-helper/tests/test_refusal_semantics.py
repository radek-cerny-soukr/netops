"""Historical refusal semantics with the narrow parsed-table exception."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from conftest import _target, FORTIOS_STATUS, FORTIADC_STATUS
from netops_helper import engine, normalization as n, tables
from netops_helper.query_catalog import READ_QUERIES

ROOT = Path(__file__).parent / 'fixtures'
REFUSALS = [
    ('fortinet', 'Command fail. Return code -61', 'permission_denied'),
    ('fortinet', "command parse error before 'x'", 'permission_denied'),
    ('fortinet', 'Unknown action 7', 'permission_denied'),
    ('fortiadc', 'Command fail. Return code is -284 (CLI parsing error.)', 'permission_denied'),
    ('fortiadc', 'get vty failed\nCommand fail. Return code is -1 ((null))', 'permission_denied'),
    ('cisco_ios', '% Invalid input detected', 'permission_denied'),
    ('cisco_ios', '% Permission denied', 'permission_denied'),
    ('cisco_xe', 'Line has invalid autocommand "x"', 'permission_denied'),
    ('cisco_xe', '% Authorization failed.', 'permission_denied'),
    ('cisco_nxos', '% Permission denied for the role', 'permission_denied'),
    ('cisco_nxos', "Syntax error while parsing 'x'", 'unsupported'),
    ('arista_eos', '% Invalid input at line 1', 'unsupported'),
    ('arista_eos', '% BGP inactive', 'not_applicable'),
    ('juniper_junos', 'error: permission denied: system', 'permission_denied'),
    ('juniper_junos_els', 'error: unknown command: x', 'unsupported'),
    ('juniper_junos_els', 'BGP is not running', 'not_applicable'),
    ('extreme_exos', 'This user does not have permissions for this command.', 'permission_denied'),
    ('extreme_exos', '%% Unrecognized command', 'unsupported'),
    ('linux', '% Permission denied', 'permission_denied'),
    ('ruckus_unleashed', '% Permission denied', 'permission_denied'),
]


@pytest.fixture(autouse=True)
def quiet_audit(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)


def classified(profile, output, rc=0, command=None):
    state = n.output_status(output, rc=rc, profile=profile, command=command)
    return 'permission_denied' if state == 'ok' and engine._cli_refused(profile, output, command=command) else state


@pytest.mark.parametrize('profile,notice,state', REFUSALS)
@pytest.mark.parametrize('prefix,suffix', [('', ''), ('heading\n', '\nmore output'),
                                          ('\r\nshow something\r\n^\r\n', '\r\n')])
@pytest.mark.parametrize('command', [None, 'show something', 'another command'])
def test_whole_output_refusals_do_not_depend_on_command(profile, notice, state, prefix, suffix, command):
    output = prefix + notice + suffix
    assert classified(profile, output, command=command) == state
    assert engine._control_refused(profile, output) == engine._cli_refused(profile, output)




def lldp_injection(notice='% Permission denied'):
    original = (ROOT / 'real/cisco_ios/iosv_15.9.3M12/lldp_neighbors.txt').read_text()
    output = original.replace('Copyright (c) 1986-2020 by Cisco Systems, Inc.',
                              'Copyright (c) 1986-2020 by Cisco Systems, Inc.\n' + notice, 1)
    assert output != original
    return original, output


@pytest.mark.parametrize('notice', ['% Permission denied', '% Invalid command', 'BGP is not running'])
@pytest.mark.parametrize('rc', [0, 1, 250])
def test_lldp_data_rows_survive_refusal_lines_in_all_table_entrypoints(monkeypatch, notice, rc):
    original, output = lldp_injection(notice)
    target = _target('cisco_ios', 'lldp_neighbors')
    version = (ROOT / 'identity/cisco_ios.txt').read_text()
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, profile, command:
                        (0, version) if command == 'show version' else (rc, output))
    expected = tables.parse('cisco_ios', 'lldp_neighbor', 'lldp_neighbors', original)['records']
    for result in (engine.normalized_query(target, 'cisco_ios', 'lldp_neighbors', 'lldp_neighbor'),
                   engine.switch_read(target, 'lldp_neighbor')):
        if rc:
            assert result['status'] == classified('cisco_ios', output, rc)
            assert not result['records']
            if result['status'] != 'not_applicable':
                assert not result['ok']
            assert 'refusal_like_line_in_data' not in result['warnings']
            continue
        assert result['status'] == 'ok' and result['ok']
        assert result['records'] == expected
        assert result['coverage']['warnings'] == ['refusal_like_line_in_data']
        assert not result['coverage']['complete']
        assert notice not in json.dumps(result['coverage'])
    target = replace(target, device_types=('switch',), enabled_queries=('mac_table', 'lldp_neighbors', 'interfaces', 'vlans'))
    mac = '00:00:5e:00:53:19'
    def read(auth, profile, command):
        if command == 'show version':
            return 0, version
        if command == READ_QUERIES[profile]['mac_table'].command:
            return 0, '10 0000.5e00.5319 DYNAMIC Gi0/1\n'
        return (rc, output) if command == READ_QUERIES[profile]['lldp_neighbors'].command else (0, '')
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine._locate_endpoint_run([target], mac)
    source = next(v for v in result['vantage'] if v['table'] == 'lldp_neighbor')
    assert source['status'] == ('ok' if not rc else classified('cisco_ios', output, rc))
    if not rc:
        assert source['coverage']['warnings'] == ['refusal_like_line_in_data']


@pytest.mark.parametrize('profile,notice,state', REFUSALS)
@pytest.mark.parametrize('rc', [0, 1, 250])
def test_real_refusal_shapes_return_no_rows(monkeypatch, profile, notice, state, rc):
    if profile in {'linux', 'ruckus_unleashed'}:
        # These profiles have no table parser; the raw output classifier remains covered.
        assert not tables.parse(profile, 'lldp_neighbor', 'fixture', notice)['records']
        return
    query = tables.BINDINGS.get(profile, {}).get('lldp_neighbor', 'system_performance')
    target = _target(profile, query)
    if profile in {'fortinet', 'fortiadc'}:
        identity = FORTIOS_STATUS if profile == 'fortinet' else FORTIADC_STATUS
        identity_command = 'get system status'
    else:
        identity = (ROOT / ('identity/' + profile + '.txt')).read_text()
        identity_command = READ_QUERIES[profile]['version'].command
    # No slots for this test: only fixed catalogue authorization/rendering is stubbed.
    monkeypatch.setattr(engine, '_ssh_read_state', lambda *a: (profile, 'read table', {}))
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command:
                        (0, identity) if command == identity_command else (rc, 'heading\n' + notice + '\nremaining output'))
    result = engine.normalized_query(target, profile, query, 'lldp_neighbor')
    expected = state
    if state == 'permission_denied' and profile in {'fortinet', 'fortiadc'} and rc != 0:
        expected = 'transport_error'  # retain the historical rc priority
    assert result['status'] == expected and not result['records']
    assert 'refusal_like_line_in_data' not in result['warnings']


@pytest.mark.parametrize('state', ['truncated', 'timeout', 'transport_error', 'permission_denied'])
def test_no_guard_without_a_refusal_line_or_with_incomplete_transport(state):
    text = '10 0000.5e00.5319 DYNAMIC Gi0/1\n'
    assert tables.parse('cisco_ios', 'mac_entry', 'mac_table', text, status=state)['status'] == state
    if state in {'truncated', 'timeout', 'transport_error'}:
        result = tables.parse('cisco_ios', 'mac_entry', 'mac_table', text + '% Permission denied\n', status=state)
        assert result['status'] == state and not result['records']


@pytest.mark.parametrize('profile,notice', [('cisco_ios', '% Permission denied'),
                                          ('arista_eos', '% Invalid input at line 1'),
                                          ('juniper_junos', 'error: unknown command: x'),
                                          ('extreme_exos', '%% Invalid input detected')])
def test_identity_read_rejects_refusal_after_valid_identity(profile, notice):
    identity = (ROOT / ('identity/' + profile + '.txt')).read_text()
    with pytest.raises(engine._ProductIdentityError):
        engine._check_identity(_target(profile, 'version'), profile, lambda *a: (0, identity + '\n' + notice + '\n'))


@pytest.mark.parametrize('profile', sorted(tables.PARSERS))
@pytest.mark.parametrize('notice', ['% Permission denied', '% Invalid command', 'BGP is not running'])
def test_all_table_parsers_guard_only_after_producing_rows(profile, notice):
    path = ROOT / ('tables/' + profile + '.json')
    for table, text in json.loads(path.read_text()).items():
        query = tables.BINDINGS[profile].get(table)
        before = tables.parse(profile, table, query, text)
        assert before['records'], (profile, table)
        result = tables.parse(profile, table, query, text + '\n' + notice + '\n')
        assert result['status'] == ('unparsed' if result['unparsed'] else 'ok') and result['records'] == before['records'], (profile, table)
        assert result['coverage']['warnings'] == ['refusal_like_line_in_data']
        # A local filter that removes every row does not erase the capture warning.
        filtered = tables.parse(profile, table, query, text + '\n' + notice + '\n', filters={'absent': True})
        assert filtered['status'] == result['status'] and not filtered['records']
        assert filtered['coverage']['parsed_records'] == len(before['records'])
        assert filtered['coverage']['warnings'] == ['refusal_like_line_in_data']


@pytest.mark.parametrize('injected_table', ['mac_entry', 'vlan'])
@pytest.mark.parametrize('notice', ['% Permission denied', 'error: permission denied: system'])
def test_junos_vlan_join_keeps_refusal_coverage_incomplete(monkeypatch, injected_table, notice):
    profile = 'juniper_junos_els'
    fixture = json.loads((ROOT / 'tables/juniper_junos_els.json').read_text())
    target = replace(_target(profile, 'mac_table'), enabled_queries=('mac_table', 'vlans'))
    identity = (ROOT / 'identity/juniper_junos_els.txt').read_text()
    def read(auth, platform, command):
        if command == READ_QUERIES[profile]['version'].command:
            return 0, identity
        table = 'mac_entry' if command == READ_QUERIES[profile]['mac_table'].command else 'vlan'
        return 0, fixture[table] + ('\n' + notice + '\n' if table == injected_table else '')
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.switch_read(target, 'mac_entry')
    assert result['status'] == ('unparsed' if result['unparsed'] else 'ok') and result['records']
    assert result['coverage']['warnings'] == ['refusal_like_line_in_data']
    assert not result['coverage']['complete']
    if injected_table == 'vlan':
        assert any(line.get('query') == 'vlans' for line in result['unparsed'])
    assert 'refusal_like_line_in_data' in result['warnings']


@pytest.mark.parametrize('profile,notice,rc', [
    ('cisco_ios', '% Invalid input detected', 1),
    ('extreme_exos', '%% Invalid input', 1),
    ('extreme_exos', 'Error: Permission denied', 250),
])
def test_refusal_row_does_not_hide_failed_command(monkeypatch, profile, notice, rc):
    fixture = json.loads((ROOT / ('tables/' + profile + '.json')).read_text())['mac_entry']
    target = _target(profile, 'mac_table')
    monkeypatch.setattr(engine, '_verified_read', lambda *a: (rc, fixture + '\n' + notice + '\n'))
    result = engine.normalized_query(target, profile, 'mac_table', 'mac_entry')
    assert result['status'] == classified(profile, fixture + '\n' + notice + '\n', rc)
    assert not result['ok'] and not result['records']
    assert 'refusal_like_line_in_data' not in result['warnings']
    assert not result['coverage']['complete']


def test_junos_vlan_join_propagates_ok_but_incomplete_vlan_capture(monkeypatch):
    profile = 'juniper_junos_els'
    fixture = json.loads((ROOT / 'tables/juniper_junos_els.json').read_text())
    target = replace(_target(profile, 'mac_table'), enabled_queries=('mac_table', 'vlans'))
    def normalized(auth, profile, query, table, *args):
        result = tables.parse(profile, table, query, fixture[table])
        if table == 'vlan':
            result['status'] = 'ok'
            result['coverage']['complete'] = False
            result['coverage']['warnings'] = ['refusal_like_line_in_data']
            result['warnings'].append('refusal_like_line_in_data')
            result['unparsed'].append({'line': 99, 'text': 'unknown'})
        return result
    monkeypatch.setattr(engine, 'normalized_query', normalized)
    result = engine.switch_read(target, 'mac_entry')
    assert result['status'] == 'ok' and result['records']
    assert not result['coverage']['complete']
    assert result['coverage']['warnings'] == ['refusal_like_line_in_data']
    assert 'refusal_like_line_in_data' in result['warnings']
    assert result['coverage']['missing_fields'] == []
    assert 'fields_absent_in_catalogue_output' not in result['warnings']
    assert any(line.get('query') == 'vlans' for line in result['unparsed'])


@pytest.mark.parametrize('extra', ['', '\nunknown data row'])
def test_protection_keeps_normal_parser_status_for_unknown_rows(extra):
    body = '10 0000.5e00.5319 DYNAMIC Gi0/1\n' + extra
    ordinary = tables.parse('cisco_ios', 'mac_entry', 'mac_table', body + '\nordinary unknown line\n')
    protected = tables.parse('cisco_ios', 'mac_entry', 'mac_table', body + '\n% Permission denied\n')
    assert protected['status'] == ordinary['status'] == 'unparsed'
    assert protected['records'] == ordinary['records']
    assert len(protected['unparsed']) == len(ordinary['unparsed'])
    assert protected['coverage']['warnings'] == ['refusal_like_line_in_data']
    assert not protected['ok'] and not protected['coverage']['complete']


def test_table_protection_only_applies_to_refusal_statuses():
    text = '10 0000.5e00.5319 DYNAMIC Gi0/1\n% Permission denied\n'
    result = tables.parse('cisco_ios', 'mac_entry', 'mac_table', text, status='ok', refused=True)
    assert result['status'] == 'unparsed' and result['records']
    assert 'refusal_like_line_in_data' not in result['warnings']
