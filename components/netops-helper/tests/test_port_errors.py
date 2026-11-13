"""Real captures plus nonzero counters and authorized multi-source reads."""
from dataclasses import replace
from pathlib import Path
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[3] / "tests/v1"))
from parser_watchdog import measured_growth

import pytest

from netops_helper import engine, port_errors, tables
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

ROOT = Path(__file__).parent / 'fixtures'
REAL = ROOT / 'real'
CAPTURES = sorted(REAL.rglob('port_errors_capture_*.txt'))


def captured(path):
    profile = 'extreme_exos' if path.relative_to(REAL).parts[0] == 'exos' else path.relative_to(REAL).parts[0]
    query = ('interface_details' if 'junos' in profile else 'ports_rx_errors' if 'rxerrors' in path.name
             else 'ports_tx_errors' if 'txerrors' in path.name else 'interfaces_counters_errors')
    return profile, query, tables.parse(profile, 'interface_errors', query, path.read_text(),
                                      command='show interfaces ge-0/0/0 extensive | no-more' if 'junos' in profile else None)


@pytest.mark.parametrize('path', CAPTURES, ids=lambda p: '/'.join(p.parts[-3:]))
def test_real_captures(path):
    profile, query, result = captured(path)
    expected = ('unsupported' if profile in ('cisco_ios', 'cisco_xe', 'cisco_nxos') else 'ok')
    if path.parts[-2].startswith('iosvl2'):
        expected = 'empty'  # source contains only echo/prompt: no counter evidence
    assert result['status'] == expected, result
    assert result['unparsed'] == []
    if expected == 'ok':
        assert result['records'] and result['coverage']['complete']
        assert set(result['records'][0]) == set(port_errors.FIELDS)
    if profile == 'extreme_exos' and query == 'ports_rx_errors':
        assert all(row['rx_errors'] is None and row['discards_in'] is None for row in result['records'])
        if path.relative_to(REAL).parts[1].endswith('_2'):
            assert {r['port']: r['crc'] for r in result['records']}['15'] == 17
    if profile.startswith('juniper_'):
        assert result['records'][0]['carrier_transitions'] == 1
        assert result['records'][0]['last_flap'].startswith('2026-11-08 22:53:56 UTC')


def test_complete_junos_extensive_and_distinct_input_output_totals():
    text = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/interface_details.txt').read_text()
    text = text.replace('Errors: 0, Drops: 0, Framing', 'Errors: 7, Drops: 3, Framing')
    text = text.replace('Carrier transitions: 1, Errors: 0, Drops: 0', 'Carrier transitions: 4, Errors: 9, Drops: 5')
    for profile in ('juniper_junos', 'juniper_junos_els'):
        result = tables.parse(profile, 'interface_errors', 'interface_details', text)
        assert result['status'] == 'ok', result['unparsed']
        row = result['records'][0]
        assert (row['rx_errors'], row['tx_errors'], row['discards_in'], row['discards_out'], row['carrier_transitions']) == (7, 9, 3, 5, 4)
        assert row['link_flaps'] is None and row['crc'] == 0


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe', 'cisco_nxos'])
def test_split_counter_blocks_and_unknown_data(profile):
    text = ('Port Align-Err FCS-Err Xmit-Err Rcv-Err UnderSize OutDiscards\n'
            'Gi1/0/1 2 11 13 17 3 19\n'
            'Port Single-Col Multi-Col Late-Col Excess-Col Carri-Sen Runts Giants\n'
            'Gi1/0/1 0 0 0 0 0 0 0\n')
    result = tables.parse(profile, 'interface_errors', 'interfaces_counters_errors', text)
    assert result['status'] == 'ok' and len(result['records']) == 1
    row = result['records'][0]
    assert (row['rx_errors'], row['crc'], row['tx_errors'], row['discards_out']) == (17, 11, 13, 19)
    assert row['discards_in'] is None
    bad = tables.parse(profile, 'interface_errors', 'interfaces_counters_errors', text + 'unknown counter block\n')
    assert bad['status'] == 'unparsed' and not bad['coverage']['complete']


def setup_reads(monkeypatch, profile, outputs, interfaces=()):
    auth = replace(_target(profile, next(iter(outputs))), enabled_queries=tuple(outputs),
                   read_inventory={'interfaces': interfaces})
    version = (ROOT / 'identity' / (profile + '.txt')).read_text()
    commands = {READ_QUERIES[profile][q].command: body for q, body in outputs.items()}
    for interface in interfaces:
        commands.update({READ_QUERIES[profile][q].command.format(interface=interface): body
                         for q, body in outputs.items() if '{interface}' in READ_QUERIES[profile][q].command})
    calls = []
    def read(auth, selected, command):
        calls.append(command)
        return 0, version if command == READ_QUERIES[profile]['version'].command else commands[command]
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', read)
    return auth, calls


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
@pytest.mark.parametrize('unit', ['a: 1, ', 'a'])
def test_junos_long_description_through_switch_read(monkeypatch, profile, unit):
    body = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/interface_details.txt').read_text()
    body = body.replace('Errors: 0, Drops: 0, Framing', 'Errors: 7, Drops: 3, Framing')
    body = body.replace('Carrier transitions: 1, Errors: 0, Drops: 0',
                        'Carrier transitions: 4, Errors: 9, Drops: 5')
    auth, _ = setup_reads(monkeypatch, profile, {'interface_details': body}, ('ge-0/0/0',))
    baseline = engine.switch_read(auth, 'interface_errors', interface='ge-0/0/0')
    # Logical descriptions follow Output errors in the real extensive layout.
    def run(size):
        payload = (unit * (size // len(unit) + 1))[:size]
        changed = body.replace('    Flags: Up SNMP-Traps',
                               '    Description: ' + payload + '\n    Flags: Up SNMP-Traps')
        _, calls = setup_reads(monkeypatch, profile, {'interface_details': changed}, ('ge-0/0/0',))
        result = engine.switch_read(auth, 'interface_errors', interface='ge-0/0/0')
        assert calls[-1] == 'show interfaces ge-0/0/0 extensive | no-more'
        assert result['status'] == baseline['status'] == 'ok'
        assert result['coverage']['complete'] and not result['unparsed']
        assert result['records'] == baseline['records']
        return result
    result = measured_growth(lambda size: size, run)
    assert result['status'] == baseline['status'] == 'ok'
    assert result['coverage']['complete'] and not result['unparsed']
    assert result['records'] == baseline['records']
    assert (result['records'][0]['rx_errors'], result['records'][0]['tx_errors']) == (7, 9)


@pytest.mark.parametrize('unit,suffix', [('a', ''), ('Errors: 1, ', 'invalid'), ('Errors: 1, , Drops: 2', '')])
def test_junos_malformed_counter_line_is_fast_and_preserves_coverage(monkeypatch, unit, suffix):
    profile = 'juniper_junos_els'
    body = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/interface_details.txt').read_text()
    auth, _ = setup_reads(monkeypatch, profile, {'interface_details': body}, ('ge-0/0/0',))
    baseline = engine.switch_read(auth, 'interface_errors', interface='ge-0/0/0')
    def run(size):
        payload = (unit * (size // len(unit) + 1))[:size] + suffix
        changed = body.replace('  Active alarms', '    ' + payload + '\n  Active alarms', 1)
        setup_reads(monkeypatch, profile, {'interface_details': changed}, ('ge-0/0/0',))
        result = engine.switch_read(auth, 'interface_errors', interface='ge-0/0/0')
        assert [line['text'].strip() for line in result['unparsed']] == [payload]
        assert result['status'] == 'unparsed' and not result['coverage']['complete']
        assert result['records'] == baseline['records']
        return result
    result = measured_growth(lambda size: size, run)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['records'] == baseline['records']


def test_junos_original_short_malformed_counter_reproduction():
    profile = 'juniper_junos_els'
    body = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/interface_details.txt').read_text()
    payload = 'Errors: 1, , Drops: 2'
    changed = body.replace('  Active alarms', '    ' + payload + '\n  Active alarms', 1)
    result = measured_growth(lambda size: changed + '\n' * size,
                             lambda text: tables.parse(profile, 'interface_errors', 'interface_details', text))
    assert result['status'] == 'unparsed'
    assert [line['text'].strip() for line in result['unparsed']] == [payload]


def test_eos_merges_discards_before_filter_and_paging(monkeypatch):
    body = next((REAL / 'arista_eos').rglob('port_errors_capture*')).read_text()
    auth, calls = setup_reads(monkeypatch, 'arista_eos', {
        'interfaces_counters_errors': body,
        'interfaces_counters_discards': 'Port InDiscards OutDiscards\nEt1 31 41\nEt2 0 0\n'})
    result = engine.switch_read(auth, 'interface_errors', interface='Et1', limit=1)
    assert result['status'] == 'ok' and len(result['records']) == 1
    assert (result['records'][0]['discards_in'], result['records'][0]['discards_out']) == (31, 41)
    assert len(result['sources']) == 2 and calls.count('show version') == 2
    # No extra permission is implied by the table.
    auth = replace(auth, enabled_queries=('interfaces_counters_errors',))
    result = engine.switch_read(auth, 'interface_errors')
    assert 'discards_query_not_enabled' in result['warnings']


def test_exos_join_preserves_missing_authorization(monkeypatch):
    directory = REAL / 'exos/x435-8p-4s_33.7.1.6'
    bodies = {q: (directory / (q + '.txt')).read_text() for q in ('ports_rx_errors', 'ports_tx_errors')}
    auth, calls = setup_reads(monkeypatch, 'extreme_exos', bodies)
    result = engine.switch_read(auth, 'interface_errors', interface='1')
    assert result['status'] == 'ok' and len(result['sources']) == 2
    assert result['records'][0]['crc'] == 0 and result['records'][0]['tx_errors'] == 0
    auth = replace(auth, enabled_queries=('ports_rx_errors',))
    calls.clear()
    result = engine.switch_read(auth, 'interface_errors')
    assert result['status'] == 'permission_denied' and not result['coverage']['complete']
    assert not any('txerrors' in cmd for cmd in calls)


IOS_DETAILS = [
    ('cisco_ios', 'iosv_15.9.3M12', 7, 'GigabitEthernet0/1'),
    ('cisco_ios', 'iosvl2_15.2.20200924', 7, 'GigabitEthernet0/1'),
    ('cisco_xe', 'iolxe_17.18.2', 19, 'Ethernet0/1'),
]


@pytest.mark.parametrize('profile,version,count,port', IOS_DETAILS)
def test_real_ios_whole_interfaces_counters(profile, version, count, port):
    body = (REAL / profile / version / 'interfaces_details.txt').read_text()
    result = tables.parse(profile, 'interface_errors', 'interfaces_details', body)
    assert result['status'] == 'ok' and result['coverage']['complete'], result['unparsed']
    assert len(result['records']) == count and not result['unparsed']
    row = next(r for r in result['records'] if r['port'] == port)
    assert (row['rx_errors'], row['crc'], row['tx_errors'], row['discards_in'], row['discards_out']) == (0, 0, 0, 0, 0)
    assert row['last_flap'] is None and row['link_flaps'] is None
    # Subinterfaces do not repeat their parent's counters.
    for row in result['records']:
        if row['port'].endswith(('.10', '.20')):
            assert all(row[field] is None for field in port_errors.FIELDS[1:])


@pytest.mark.parametrize('profile,version,count,port', IOS_DETAILS)
@pytest.mark.parametrize('primary,state', [
    ("% Invalid input detected at '^' marker.\n", 'unsupported'),
    ('Line has invalid autocommand\n', 'permission_denied'),
    ('% Authorization failed\n', 'permission_denied'),
    ('', 'empty'),
    ('Port FCS-Err Rcv-Err Xmit-Err OutDiscards\n', 'empty'),
])
@pytest.mark.parametrize('filtered', [False, True])
def test_ios_falls_back_to_authorized_whole_interfaces(monkeypatch, profile, version, count, port, primary, state, filtered):
    body = (REAL / profile / version / 'interfaces_details.txt').read_text()
    auth, calls = setup_reads(monkeypatch, profile, {
        'interfaces_counters_errors': primary, 'interfaces_details': body})
    result = engine.switch_read(auth, 'interface_errors', interface=port if filtered else None)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert len(result['records']) == (1 if filtered else count)
    assert [s['status'] for s in result['sources']] == [state, 'ok']
    assert calls[-1] == 'show interfaces' and calls.count('show interfaces') == 1
    assert 'counters_unavailable_used_interfaces_details' in result['warnings']
    # An enrolled whole-port read has no per-port slots or extra inventory requirement.
    assert not auth.read_inventory['interfaces']


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
def test_ios_fallback_needs_its_own_query_permission(monkeypatch, profile):
    auth, calls = setup_reads(monkeypatch, profile, {
        'interfaces_counters_errors': "Line has invalid autocommand\n"})
    result = engine.switch_read(auth, 'interface_errors')
    assert not result['ok'] and not result['coverage']['complete']
    assert result['status'] == 'permission_denied'
    assert len(calls) == 2 and 'show interfaces' not in calls


@pytest.mark.parametrize('status', ['timeout', 'transport_error', 'truncated', 'unparsed'])
def test_ios_does_not_retry_failed_or_partial_counter_capture(status):
    auth = replace(_target('cisco_ios', 'interfaces_counters_errors'),
                   enabled_queries=('interfaces_counters_errors', 'interfaces_details'))
    calls = []
    def fetch(auth, profile, query, table, params):
        calls.append(query)
        return tables.parse(profile, table, query, '', status=status)
    result = port_errors.read(auth, None, fetch)
    assert result['status'] == status and calls == ['interfaces_counters_errors']
    assert not result['ok'] and not result['coverage']['complete']


def test_ios_nonzero_details_and_unknown_lines_are_not_hidden():
    body = (REAL / 'cisco_ios/iosv_15.9.3M12/interface_details.txt').read_text()
    body = body.replace('0 input errors, 0 CRC', '19 input errors, 7 CRC')
    body = body.replace('0 output errors', '13 output errors')
    body = body.replace('0/75/0/0 (size/max/drops/flushes); Total output drops: 0',
                        '1/75/5/2 (size/max/drops/flushes); Total output drops: 11')
    result = tables.parse('cisco_ios', 'interface_errors', 'interfaces_details', body)
    row, = result['records']
    assert result['coverage']['complete']
    assert (row['rx_errors'], row['crc'], row['tx_errors'], row['discards_in'], row['discards_out']) == (19, 7, 13, 5, 11)
    assert row['last_flap'] is None and row['link_flaps'] is None
    result = tables.parse('cisco_ios', 'interface_errors', 'interfaces_details', body + '  Unknown counter: 123\n')
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert len(result['unparsed']) == 1


@pytest.mark.parametrize('body', ['', 'Port FCS-Err Rcv-Err Xmit-Err OutDiscards\n'])
def test_empty_counter_tables_have_no_successful_coverage(body):
    result = tables.parse('cisco_ios', 'interface_errors', 'interfaces_counters_errors', body)
    assert result['status'] == 'empty' and not result['records']
    assert not result['ok'] and not result['coverage']['complete']


def test_empty_or_partial_ios_fallback_is_not_success(monkeypatch):
    for body, status in [('', 'empty'), ('unrecognized details\n', 'unparsed')]:
        auth, _ = setup_reads(monkeypatch, 'cisco_ios', {
            'interfaces_counters_errors': '', 'interfaces_details': body})
        result = engine.switch_read(auth, 'interface_errors')
        assert result['status'] == status and not result['ok'] and not result['coverage']['complete']


def test_absent_ios_port_filter_is_not_success(monkeypatch):
    body = (REAL / 'cisco_ios/iosv_15.9.3M12/interfaces_details.txt').read_text()
    auth, _ = setup_reads(monkeypatch, 'cisco_ios', {
        'interfaces_counters_errors': '', 'interfaces_details': body})
    result = engine.switch_read(auth, 'interface_errors', interface='Gi0/99')
    assert not result['records'] and not result['ok'] and not result['coverage']['complete']


def test_junos_requires_interface_and_existing_inventory(monkeypatch):
    body = (REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/interface_details.txt').read_text()
    auth, calls = setup_reads(monkeypatch, 'juniper_junos_els', {'interface_details': body}, ('ge-0/0/0',))
    with pytest.raises(ValueError, match='interface is required'):
        engine.switch_read(auth, 'interface_errors')
    assert not calls
    assert engine.switch_read(auth, 'interface_errors', interface='ge-0/0/0')['status'] == 'ok'
    with pytest.raises(ValueError, match='not enrolled'):
        engine.switch_read(auth, 'interface_errors', interface='ge-0/0/1')


def test_proxy_accepts_interface_forms_but_rejects_injection_and_other_filters():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    for interface in ('Et1', 'ge-0/0/0', '1:2'):
        args = {'target': 'switch', 'table': 'interface_errors', 'interface': interface}
        assert Proxy._validate_tool_arguments('switch_read', args) == args
    for extra in ({'interface': 'Et1;reload'}, {'vlan_id': '10'}, {'mac': '0000.5e00.5301'}):
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('switch_read', {'target': 'switch', 'table': 'interface_errors', **extra})
    with pytest.raises(ToolArgumentsError):
        Proxy._validate_tool_arguments('switch_read', {'target': 'switch', 'table': 'vlan', 'interface': 'Et1'})
    assert port_errors.read_cost('extreme_exos', None, ()) == 2
    assert port_errors.read_cost('cisco_ios', 'Gi1/0/1', ()) == 2
    assert port_errors.read_cost('arista_eos', None, ()) == 1



def test_prior_real_nxos_canonical_capture_preserves_large_counters():
    text = (REAL / 'cisco_nxos/nexus9300v_9.3.12/interfaces_counters_errors.txt').read_text()
    result = tables.parse('cisco_nxos', 'interface_errors', 'interfaces_counters_errors', text)
    assert result['status'] == 'ok' and result['coverage']['complete'], result['unparsed']
    assert len(result['records']) == 65
    row = next(r for r in result['records'] if r['port'] == 'Ethernet1/9')
    assert row['rx_errors'] == 6755511143759872
    assert row['tx_errors'] == 10133210864287744
    assert row['discards_in'] == 0 and row['discards_out'] == 0


def test_prior_real_eos_discard_capture_omits_totals_row():
    text = (REAL / 'arista_eos/ceos_4.36.1F/interfaces_counters_discards.txt').read_text()
    result = tables.parse('arista_eos', 'interface_errors', 'interfaces_counters_discards', text)
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert len(result['records']) == 17
    assert all(row['port'] != 'Totals' for row in result['records'])
    assert next(row for row in result['records'] if row['port'] == 'Management0')['discards_in'] == 3



@pytest.mark.parametrize('interface,canonical', [('Ma0', 'Management0'), ('Management0', 'Management0'), ('Port-channel1', 'Port-channel1'), ('Po1', 'Port-channel1')])
def test_eos_can_filter_the_names_returned_by_real_discard_output(monkeypatch, interface, canonical):
    directory = REAL / 'arista_eos/ceos_4.36.1F'
    auth, _ = setup_reads(monkeypatch, 'arista_eos', {
        query: (directory / (query + '.txt')).read_text()
        for query in ('interfaces_counters_errors', 'interfaces_counters_discards')})
    result = engine.switch_read(auth, 'interface_errors', interface=interface)
    assert result['status'] == 'ok' and len(result['records']) == 1
    assert result['records'][0]['port'] == canonical
    assert result['records'][0]['discards_in'] == (3 if canonical == 'Management0' else 0)


def test_proxy_invalid_platform_interface_reports_interface():
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy, ToolArgumentsError

    section = SimpleNamespace(catalog_platform=lambda: 'extreme_exos', device_types=('switch',), egress={})
    args = {'target': 'switch', 'table': 'interface_errors', 'interface': 'Et1'}
    Proxy._validate_tool_arguments('switch_read', args)
    with pytest.raises(ToolArgumentsError) as caught:
        Proxy._authorize_tool('switch_read', args, None, section)
    assert caught.value.code == -32602
    assert caught.value.data['field'] == 'interface'
    assert 'interface' in caught.value.data['hint']
    assert 'route' not in caught.value.data['hint']


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_proxy_missing_junos_interface_reports_required_enrolled_interface(profile):
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy, ToolArgumentsError

    section = SimpleNamespace(catalog_platform=lambda: profile, device_types=('switch',), egress={})
    args = {'target': 'switch', 'table': 'interface_errors'}
    Proxy._validate_tool_arguments('switch_read', args)
    with pytest.raises(ToolArgumentsError) as caught:
        Proxy._authorize_tool('switch_read', args, None, section)
    assert caught.value.code == -32602
    assert caught.value.data['field'] == 'interface'
    assert 'required' in caught.value.data['hint'] and 'enrolled' in caught.value.data['hint']
    assert 'route' not in caught.value.data['hint']
