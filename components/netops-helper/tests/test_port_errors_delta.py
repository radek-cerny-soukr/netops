"""1.0.12 X-08: counter deltas between two reads and short output modes of interface_errors.

Every device text is a real, anonymised capture read through the fake transport
(engine.read_from_device); a second time is the same capture with counter values
changed in place, so the layout stays the device's own.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

import pytest

from netops_helper import engine, port_errors, tables
from netops_helper.normalization import counter_delta
from netops_helper.page_metadata import BASELINE_PATTERN, page_metadata, strip_page_metadata
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

ROOT = Path(__file__).parent / 'fixtures'
REAL = ROOT / 'real'
EXOS = REAL / 'exos/x435-8p-4s_33.7.1.6'
IOSV = REAL / 'cisco_ios/iosv_15.9.3M12/interfaces_details.txt'


def setup_reads(monkeypatch, profile, outputs, interfaces=()):
    auth = replace(_target(profile, next(iter(outputs))), enabled_queries=tuple(outputs),
                   read_inventory={'interfaces': interfaces})
    version = (ROOT / 'identity' / (profile + '.txt')).read_text()
    commands = {READ_QUERIES[profile][query].command: body for query, body in outputs.items()}
    if len(interfaces) == 1:
        commands = {command.replace('{interface}', interfaces[0]): body for command, body in commands.items()}
    calls = []

    def read(auth, selected, command):
        calls.append(command)
        return 0, version if command == READ_QUERIES[profile]['version'].command else commands[command]
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', read)
    return auth, calls


def exos_bodies(rx=None, tx=None):
    return {'ports_rx_errors': rx or (EXOS / 'ports_rx_errors.txt').read_text(),
            'ports_tx_errors': tx or (EXOS / 'ports_tx_errors.txt').read_text()}


def set_exos_crc(text, port, value):
    """Replace the Rx Crc column of one port row, keeping the device's column layout."""
    pattern = re.compile(r'(?m)^(%s\s+[A-Z]+\s+)(\d+)' % re.escape(port))
    match = pattern.search(text)
    assert match, port
    old = match[2]
    new = str(value)
    # Keep the total row width: shrink or grow the following spaces.
    end = match.end()
    spaces = re.match(r' *', text[end:])[0]
    padding = ' ' * max(1, len(spaces) + len(old) - len(new))
    return text[:match.start(2)] + new + padding + text[end + len(spaces):]


def test_counter_delta_states():
    assert counter_delta(5, 12) == (7, 'ok')
    assert counter_delta(12, 12) == (0, 'ok')
    assert counter_delta(12, 3) == (None, 'reset_or_wrap')
    assert counter_delta(None, 3) == (None, 'absent')
    assert counter_delta(3, None) == (None, 'absent')
    assert counter_delta(True, 3) == (None, 'absent')
    # A 32-bit wrap and a clear look the same in two samples; 64-bit totals stay exact.
    assert counter_delta(2**32 - 5, 10) == (None, 'reset_or_wrap')
    assert counter_delta(2**63, 2**63 + 9) == (9, 'ok')


def test_exos_two_times_delta_and_short_modes(monkeypatch):
    auth, calls = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    first = engine.switch_read(auth, 'interface_errors')
    assert first['status'] == 'ok' and first['ok']
    token = first['counter_baseline']
    assert re.fullmatch(BASELINE_PATTERN, token)
    assert first['summary']['mode'] == 'full' and first['summary']['ports'] == len(first['records']) == 12
    assert 'baseline' not in first['summary'] and 'delta' not in first['records'][0]
    # Second time: port 3 got 5 new CRC errors.
    rx = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '3', 5)
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=rx))
    second = engine.switch_read(auth, 'interface_errors', baseline=token)
    assert second['status'] == 'ok' and second['coverage']['complete']
    row = next(r for r in second['records'] if r['port'] == '3')
    assert row['crc'] == 5 and row['delta']['crc'] == 5 and row['delta']['tx_errors'] == 0
    assert row['delta']['rx_errors'] is None  # EXOS prints no aggregate RX total
    assert row['counter_reset_or_wrap'] == []
    base = second['summary']['baseline']
    assert base['ports_compared'] == 12 and base['ports_increased'] == 1
    assert base['increased_ports_by_counter']['crc'] == 1 and base['ports_reset_or_wrap'] == 0
    assert base['new_ports'] == [] and base['missing_ports'] == []
    assert base['interval_seconds'] >= 0
    # Only the deviation is listed; statuses and coverage are unchanged.
    changes = engine.switch_read(auth, 'interface_errors', baseline=token, summary='changes')
    assert [r['port'] for r in changes['records']] == ['3']
    assert changes['summary']['ports'] == 12 and changes['summary']['ports_listed'] == 1
    assert changes['status'] == 'ok' and changes['coverage']['complete'] and changes['coverage']['parsed_records'] == 12
    counts = engine.switch_read(auth, 'interface_errors', baseline=token, summary='counts')
    assert counts['records'] == [] and counts['unparsed'] == []
    assert counts['summary']['baseline']['ports_increased'] == 1
    assert counts['summary']['ports_listed'] == 0 and counts['ok']
    # Each read carries its own capture time; the counters of both new tokens are those of the second time.
    key = port_errors._key(auth.alias, 'extreme_exos', None)
    assert port_errors.decode_baseline(counts['counter_baseline'], key)[1] == \
        port_errors.decode_baseline(changes['counter_baseline'], key)[1] != port_errors.decode_baseline(token, key)[1]
    assert port_errors.decode_baseline(counts['counter_baseline'], key)[1]['3']['crc'] == 5


def test_exos_reset_or_wrap_has_no_invented_increase(monkeypatch):
    high = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '1', 2**32 - 3)
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=high))
    token = engine.switch_read(auth, 'interface_errors')['counter_baseline']
    low = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '1', 4)
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=low))
    result = engine.switch_read(auth, 'interface_errors', baseline=token, summary='changes')
    row, = result['records']
    assert row['port'] == '1' and row['crc'] == 4
    assert row['delta']['crc'] is None and row['counter_reset_or_wrap'] == ['crc']
    assert result['summary']['baseline']['ports_reset_or_wrap'] == 1
    assert result['summary']['baseline']['ports_increased'] == 0


def test_without_baseline_changes_lists_nonzero_ports(monkeypatch):
    rx = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '7', 17)
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=rx))
    result = engine.switch_read(auth, 'interface_errors', summary='changes')
    assert [r['port'] for r in result['records']] == ['7']
    assert result['summary']['ports_with_nonzero_counters'] == 1
    assert result['summary']['nonzero_ports_by_counter']['crc'] == 1
    assert 'delta' not in result['records'][0]


def test_summary_counts_cover_all_ports_before_paging(monkeypatch):
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    result = engine.switch_read(auth, 'interface_errors', limit=1)
    assert len(result['records']) == 1 and result['has_more']
    assert result['summary']['ports'] == 12 and result['summary']['ports_listed'] == 12


def test_ios_whole_interfaces_two_times(monkeypatch):
    body = IOSV.read_text()
    auth, calls = setup_reads(monkeypatch, 'cisco_ios', {
        'interfaces_counters_errors': "% Invalid input detected at '^' marker.\n", 'interfaces_details': body})
    first = engine.switch_read(auth, 'interface_errors', interface='Gi0/1')
    assert first['status'] == 'ok' and first['counter_baseline']
    head, mark, tail = body.partition('GigabitEthernet0/1 is up')
    changed = head + mark + tail.replace('0 input errors, 0 CRC', '9 input errors, 4 CRC', 1)
    setup_reads(monkeypatch, 'cisco_ios', {
        'interfaces_counters_errors': "% Invalid input detected at '^' marker.\n", 'interfaces_details': changed})
    second = engine.switch_read(auth, 'interface_errors', interface='Gi0/1', baseline=first['counter_baseline'])
    row, = second['records']
    assert row['port'] == 'GigabitEthernet0/1' and row['crc'] == 4
    assert (row['delta']['rx_errors'], row['delta']['crc'], row['delta']['tx_errors']) == (9, 4, 0)
    assert second['summary']['baseline']['ports_increased'] == 1
    assert row['delta']['link_flaps'] is None  # never printed by IOS: absent, not zero
    # The token is bound to the port selection: another port is refused before any read.
    calls.clear()
    with pytest.raises(ValueError, match='another target'):
        engine.switch_read(auth, 'interface_errors', interface='Gi0/2', baseline=first['counter_baseline'])
    assert calls == []


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe'])
@pytest.mark.parametrize('before,after,reset', [
    ('never', '00:00:30', True),
    ('00:02:00', '00:00:30', True),
    ('00:02:00', '00:03:00', False),
    ('1d02h', '1d02h', False),
])
def test_ios_last_clearing_tracks_counter_epoch(monkeypatch, profile, before, after, reset):
    captured = datetime(2026, 11, 19, tzinfo=timezone.utc)
    envelope = tables.response_envelope

    def timestamped(*args, **kwargs):
        return {**envelope(*args, **kwargs), 'captured_at': captured.isoformat()}

    monkeypatch.setattr(tables, 'response_envelope', timestamped)
    port = 'TenGigabitEthernet1/0/1'
    fixture = ROOT / 'docs/cisco_xe/g71/negotiated_speed.out'
    original = fixture.read_text().replace('TenGigabitEthernet1/1', port)

    def sample(age, received, errors):
        body = original.replace('counters never', 'counters ' + age)
        body = body.replace('4750634 bytes', f'{received} bytes')
        body = re.sub(r'\d+ input errors, \d+ CRC', f'{errors} input errors, {errors} CRC', body)
        if profile == 'cisco_xe':
            return {'interface_details': body}
        return {'interfaces_counters_errors': "% Invalid input detected at '^' marker.\n",
                'interfaces_details': body}

    auth, _ = setup_reads(monkeypatch, profile, sample(before, 100_000_000, 10), [port])
    first = engine.switch_read(auth, 'interface_errors', interface=port)
    assert first['counter_baseline'], first
    captured += timedelta(seconds=60)
    auth, _ = setup_reads(monkeypatch, profile, sample(after, 150_000_000, 13), [port])
    second = engine.switch_read(auth, 'interface_errors', interface=port,
                                baseline=first['counter_baseline'], summary='changes')
    [row] = second['records']
    assert row['delta']['crc'] == (None if reset else 3)
    assert second['summary']['baseline']['ports_reset_or_wrap'] == int(reset)
    if reset:
        assert row['counter_status'] == 'counters_reset'
    if profile == 'cisco_xe':
        traffic = row['interval_traffic']
        assert traffic['interval_seconds'] == 60
        assert traffic['rx']['octets_delta'] == (None if reset else 50_000_000)
        assert traffic['rx']['bits_per_second'] == (None if reset else pytest.approx(50_000_000 * 8 / 60))
        if reset:
            assert traffic['status'] == 'counters_reset'
            assert traffic['rx']['utilization_percent'] is None


def test_refused_or_incomplete_second_read_is_not_a_delta(monkeypatch):
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    token = engine.switch_read(auth, 'interface_errors')['counter_baseline']
    # Missing TX authorization: status stays permission_denied, no new baseline, no lost ports claimed.
    denied = replace(auth, enabled_queries=('ports_rx_errors',))
    result = engine.switch_read(denied, 'interface_errors', baseline=token)
    assert result['status'] == 'permission_denied' and not result['ok']
    assert result['counter_baseline'] is None
    assert result['summary']['baseline']['missing_ports'] is None
    assert all(row['delta']['tx_errors'] is None for row in result['records'])
    # A pager-terminated capture is truncated: no records, no baseline.
    paged = (EXOS / 'ports_rx_errors.txt').read_text() + 'Press <SPACE> to continue or <Q> to quit:'
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=paged))
    result = engine.switch_read(auth, 'interface_errors', baseline=token)
    assert result['status'] == 'truncated' and not result['ok']
    assert result['counter_baseline'] is None and result['records'] == []
    assert result['summary']['baseline']['ports_compared'] == 0


def test_shape_interval_new_and_missing_ports():
    key = port_errors._key('sw', 'extreme_exos', None)
    old = [port_errors.record('1') | {'crc': 1}, port_errors.record('2') | {'crc': 0}]
    token = port_errors.encode_baseline(key, '2026-11-17T09:00:00+00:00', old)
    result = {'status': 'ok', 'captured_at': '2026-11-17T09:05:30.500000+00:00', 'warnings': [], 'unparsed': [],
              'coverage': {'complete': True, 'parsed_records': 2, 'unparsed_lines': 0, 'missing_fields': []},
              'records': [port_errors.record('1') | {'crc': 3}, port_errors.record('3') | {'crc': 0}]}
    shaped = port_errors.shape(result, key, port_errors.decode_baseline(token, key))
    base = shaped['summary']['baseline']
    assert base['captured_at'] == '2026-11-17T09:00:00+00:00' and base['interval_seconds'] == 330.5
    assert base['new_ports'] == ['3'] and base['missing_ports'] == ['2']
    assert shaped['records'][1]['delta'] is None
    assert shaped['records'][0]['delta']['crc'] == 2


@pytest.mark.parametrize('token', ['nb1.' + 'A' * 40, 'nb1.short', 'x' * 20, 'nb1.' + 'A' * 32001])
def test_malformed_baseline_is_refused_before_any_read(monkeypatch, token):
    auth, calls = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    with pytest.raises(ValueError, match='counter_baseline'):
        engine.switch_read(auth, 'interface_errors', baseline=token)
    assert calls == []


def test_baseline_of_another_target_and_other_tables_are_refused(monkeypatch):
    auth, calls = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    token = engine.switch_read(auth, 'interface_errors')['counter_baseline']
    calls.clear()
    with pytest.raises(ValueError, match='another target'):
        engine.switch_read(replace(auth, alias='other'), 'interface_errors', baseline=token)
    with pytest.raises(ValueError, match='only to table interface_errors'):
        engine.switch_read(auth, 'vlan', baseline=token)
    with pytest.raises(ValueError, match='only to table interface_errors'):
        engine.switch_read(auth, 'vlan', summary='counts')
    with pytest.raises(ValueError, match='counts or changes'):
        engine.switch_read(auth, 'interface_errors', summary='all')
    assert calls == []


def test_baseline_survives_response_redaction_as_metadata():
    from netops_helper.proxy_sanitize import sanitize_object
    key = port_errors._key('sw', 'extreme_exos', None)
    token = port_errors.encode_baseline(key, '2026-11-17T09:00:00+00:00', [port_errors.record('1') | {'crc': 1}])
    secret = token[10:18]
    structured = {'ok': True, 'status': 'ok', 'counter_baseline': token, 'records': []}
    result = {'structuredContent': structured, 'content': [{'type': 'text', 'text': __import__('json').dumps(structured)}]}
    assert sanitize_object(result, (secret,)) != result  # the plain redaction would break the token
    metadata = page_metadata(structured, 'switch_read')
    assert metadata == {'counter_baseline': token}
    stripped, restore = strip_page_metadata(result, metadata)
    cleaned = restore(sanitize_object(stripped, (secret,)))
    assert cleaned['structuredContent']['counter_baseline'] == token
    assert token in cleaned['content'][0]['text']
    # Failed reads and other shapes carry no protected metadata.
    assert page_metadata({**structured, 'ok': False}, 'switch_read') is None
    assert page_metadata({**structured, 'counter_baseline': 'nb1.bad!'}, 'switch_read') is None
    assert page_metadata({**structured, 'counter_baseline': None}, 'switch_read') is None


def test_proxy_accepts_baseline_and_summary_only_for_interface_errors():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    token = 'nb1.' + 'A' * 40
    for extra in ({'baseline': token}, {'summary': 'counts'}, {'summary': 'changes'}, {'baseline': token, 'summary': 'changes'}):
        args = {'target': 'switch', 'table': 'interface_errors', **extra}
        assert Proxy._validate_tool_arguments('switch_read', args) == args
    for args, field in (({'table': 'vlan', 'baseline': token}, 'baseline'),
                        ({'table': 'interface_errors', 'baseline': 'nb1.$$$$$$$$$$'}, 'baseline'),
                        ({'table': 'interface_errors', 'baseline': 7}, 'baseline'),
                        ({'table': 'interface_errors', 'summary': 'full'}, 'summary'),
                        ({'table': 'mac_entry', 'summary': 'counts'}, 'summary')):
        with pytest.raises(ToolArgumentsError) as caught:
            Proxy._validate_tool_arguments('switch_read', {'target': 'switch', **args})
        assert caught.value.data['field'] == field


def test_managed_fortiswitch_rows_share_the_delta_interface():
    from netops_helper import fortiswitch_ports as ports
    text = (REAL / 'fortinet/fortigate80f_8.0.2_build0251/captures_20261110/port_stats_1.txt').read_text()
    key = port_errors._key('fgt', 'fortinet', None, 'S000SSSS00000001')
    first = port_errors.shape(tables.parse('fortinet', 'interface_errors', ports.STATS, text), key)
    assert first['status'] == 'ok' and first['counter_baseline']
    port = first['records'][2]['port']
    assert first['records'][2]['discards_in'] == 30
    later = text.replace('30 drops', '42 drops', 1)
    assert later != text
    second = tables.parse('fortinet', 'interface_errors', ports.STATS, later)
    second = port_errors.shape(second, key, port_errors.decode_baseline(first['counter_baseline'], key), 'changes')
    row, = second['records']
    assert row['port'] == port and row['delta']['discards_in'] == 12 and row['delta']['crc'] is None
    with pytest.raises(ValueError, match='another target'):
        port_errors.decode_baseline(first['counter_baseline'], port_errors._key('fgt', 'fortinet', None, 'S000SSSS00000002'))


@pytest.mark.parametrize('target,interface,token_kind', [
    ('other-switch', None, 'valid'), ('switch', '1', 'valid'), ('switch', None, 'damaged')])
def test_proxy_refuses_foreign_or_damaged_baseline_as_argument_error(target, interface, token_kind):
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy, ToolArgumentsError
    key = port_errors._key('switch', 'extreme_exos', None)
    token = port_errors.encode_baseline(key, '2026-11-17T09:00:00+00:00', [port_errors.record('1') | {'crc': 1}])
    if token_kind == 'damaged':
        token = token[:-6] + 'AAAAAA'
    section = SimpleNamespace(catalog_platform=lambda: 'extreme_exos', device_types=('switch',), egress={})
    args = {'target': target, 'table': 'interface_errors', 'baseline': token}
    if interface:
        args['interface'] = interface
    Proxy._validate_tool_arguments('switch_read', args)
    with pytest.raises(ToolArgumentsError) as caught:
        Proxy._authorize_tool('switch_read', args, None, section)
    assert caught.value.code == -32602 and caught.value.data['field'] == 'baseline'
    assert 'counter_baseline' in caught.value.data['hint'] or 'another target' in caught.value.data['hint']
    assert token not in json_dumps(caught.value.data)


def json_dumps(value):
    import json
    return json.dumps(value)


# Two reads of the same device about 90 s apart, captured 2026-11-17 with the RO account netops-ro
# (fixtures/real/<os>/<device>/captures_20261117_g03, index.json holds command, exit status and time).
G03 = 'captures_20261117_g03'
TWO_TIMES = [
    ('extreme_exos', REAL / 'exos/x435-8p-4s_33.7.1.6' / G03, ('ports_rx_errors', 'ports_tx_errors'), '1', 12, None),
    ('extreme_exos', REAL / 'exos/x440g2-12p-10g4_33.7.1.6' / G03, ('ports_rx_errors', 'ports_tx_errors'), '1', 16, None),
    ('cisco_ios', REAL / 'cisco_ios/iosv_15.9.3M12' / G03, ('interfaces_counters_errors', 'interfaces_details'),
     'Gi0/1', 7, 'permission_denied'),
    ('cisco_ios', REAL / 'cisco_ios/iosvl2_15.2.20200924' / G03, ('interfaces_counters_errors', 'interfaces_details'),
     'Gi0/1', 11, 'empty'),
]


def two_time_bodies(directory, queries, label):
    return {query: (directory / ('%s_%s.txt' % (query, label))).read_text() for query in queries}


@pytest.mark.parametrize('profile,directory,queries,port,count,primary', TWO_TIMES,
                         ids=lambda value: value.parent.name if isinstance(value, Path) else None)
def test_real_two_time_captures(monkeypatch, profile, directory, queries, port, count, primary):
    auth, calls = setup_reads(monkeypatch, profile, two_time_bodies(directory, queries, 't1'))
    first = engine.switch_read(auth, 'interface_errors')
    assert first['status'] == 'ok' and first['coverage']['complete'] and not first['unparsed']
    assert len(first['records']) == count and first['summary']['ports'] == count
    if primary:  # IOS: the counter table is refused (IOSv) or empty (IOSvL2); show interfaces answers
        assert [s['status'] for s in first['sources']] == [primary, 'ok']
    single = engine.switch_read(auth, 'interface_errors', interface=port)
    setup_reads(monkeypatch, profile, two_time_bodies(directory, queries, 't2'))
    second = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'])
    assert second['status'] == 'ok' and second['coverage']['complete']
    before = {row['port']: row for row in first['records']}
    for row in second['records']:
        for field in port_errors.COUNTERS:
            old, new = before[row['port']][field], row[field]
            assert row['delta'][field] == (None if old is None or new is None else new - old), (row['port'], field)
    base = second['summary']['baseline']
    assert base['ports_compared'] == count and base['new_ports'] == [] and base['missing_ports'] == []
    changes = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'], summary='changes')
    assert [r['port'] for r in changes['records']] == [r['port'] for r in second['records']
                                                       if any(r['delta'][f] for f in port_errors.COUNTERS)]
    counts = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'], summary='counts')
    assert counts['records'] == [] and counts['summary']['ports'] == count and counts['ok']
    one = engine.switch_read(auth, 'interface_errors', interface=port, baseline=single['counter_baseline'])
    row, = one['records']
    assert row['delta'] is not None and one['summary']['baseline']['ports_compared'] == 1


def test_real_iosv_refused_fallback_without_authorization_has_no_baseline(monkeypatch):
    directory = REAL / 'cisco_ios/iosv_15.9.3M12' / G03
    body = (directory / 'interfaces_counters_errors_t1.txt').read_text()
    assert 'Line has invalid autocommand' in body
    auth, calls = setup_reads(monkeypatch, 'cisco_ios', {'interfaces_counters_errors': body})
    result = engine.switch_read(auth, 'interface_errors', summary='counts')
    assert result['status'] == 'permission_denied' and not result['ok']
    assert result['counter_baseline'] is None and result['summary']['ports'] == 0
    assert 'show interfaces' not in calls


def test_real_cut_capture_is_unparsed_and_gives_no_new_baseline(monkeypatch):
    directory = REAL / 'cisco_ios/iosvl2_15.2.20200924' / G03
    queries = ('interfaces_counters_errors', 'interfaces_details')
    auth, _ = setup_reads(monkeypatch, 'cisco_ios', two_time_bodies(directory, queries, 't1'))
    token = engine.switch_read(auth, 'interface_errors')['counter_baseline']
    bodies = two_time_bodies(directory, queries, 't2')
    text = bodies['interfaces_details']
    cut = text.index(' input errors, ', len(text) // 2) + len(' input err')
    bodies['interfaces_details'] = text[:cut]
    setup_reads(monkeypatch, 'cisco_ios', bodies)
    result = engine.switch_read(auth, 'interface_errors', baseline=token)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['counter_baseline'] is None
    assert result['summary']['baseline']['missing_ports'] is None  # an incomplete read cannot prove a port vanished


# 434-rv finding 1: an incomplete read (RX rows, empty TX answer with rc 0) must not issue a new baseline;
# otherwise the next complete read would lose the earlier TX values and miss their increase.
def set_exos_tx(text, port, value):
    """Replace the Tx Errors column (4th counter) of one port row, keeping the device's column layout."""
    pattern = re.compile(r'(?m)^(%s\s+[A-Z]+(?:\s+\d+){3}\s+)(\d+)' % re.escape(port))
    match = pattern.search(text)
    assert match, port
    old, new = match[2], str(value)
    end = match.end()
    spaces = re.match(r' *', text[end:])[0]
    padding = ' ' * max(1, len(spaces) + len(old) - len(new))
    return text[:match.start(2)] + new + padding + text[end + len(spaces):]


def test_incomplete_exos_read_without_tx_gives_no_new_baseline(monkeypatch):
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    first = engine.switch_read(auth, 'interface_errors')
    assert first['status'] == 'ok' and first['coverage']['complete'] and first['counter_baseline']
    # Second read: RX as before, TX answers with an empty output and rc 0.
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(tx='\n'))
    second = engine.switch_read(auth, 'interface_errors', baseline=first['counter_baseline'])
    assert [s['status'] for s in second['sources']] == ['ok', 'empty']
    assert not second['coverage']['complete']
    assert second['counter_baseline'] is None
    assert second['summary']['baseline']['missing_ports'] is None
    # Third, complete read: TX errors on port 1 rose to 5. The caller keeps the last issued token (the first).
    token = second['counter_baseline'] or first['counter_baseline']
    tx = set_exos_tx((EXOS / 'ports_tx_errors.txt').read_text(), '1', 5)
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(tx=tx))
    third = engine.switch_read(auth, 'interface_errors', baseline=token, summary='changes')
    assert third['status'] == 'ok' and third['coverage']['complete'] and third['counter_baseline']
    row, = third['records']
    assert row['port'] == '1' and row['tx_errors'] == 5 and row['delta']['tx_errors'] == 5
    assert third['summary']['baseline']['ports_increased'] == 1
    assert third['summary']['baseline']['increased_ports_by_counter']['tx_errors'] == 1
    assert third['summary']['baseline']['missing_ports'] == []


def test_shape_never_issues_baseline_or_missing_ports_for_incomplete_coverage():
    key = port_errors._key('sw', 'extreme_exos', None)
    old = [port_errors.record('1') | {'crc': 1}, port_errors.record('2') | {'crc': 0}]
    token = port_errors.encode_baseline(key, '2026-11-17T09:00:00+00:00', old)
    result = {'status': 'ok', 'captured_at': '2026-11-17T09:05:30+00:00', 'warnings': [], 'unparsed': [],
              'coverage': {'complete': False, 'parsed_records': 1, 'unparsed_lines': 0, 'missing_fields': []},
              'records': [port_errors.record('1') | {'crc': 3}]}
    shaped = port_errors.shape(result, key, port_errors.decode_baseline(token, key))
    assert shaped['counter_baseline'] is None
    assert shaped['summary']['baseline']['missing_ports'] is None
    assert 'counter_baseline_too_large' not in shaped['warnings']


# 434-rv finding 2: the short summaries tell a measured zero from an unavailable or incomparable counter.
def test_counts_summary_tells_measured_zero_from_unavailable_counter(monkeypatch):
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies())
    counts = engine.switch_read(auth, 'interface_errors', summary='counts')
    assert counts['status'] == 'ok' and counts['coverage']['complete'] and counts['records'] == []
    summary = counts['summary']
    # Existing keys stay: zero nonzero ports for both the measured crc and the never printed rx_errors.
    assert summary['nonzero_ports_by_counter']['crc'] == summary['nonzero_ports_by_counter']['rx_errors'] == 0
    # The new per-counter count of ports with a value tells them apart.
    assert summary['measured_ports_by_counter'] == {
        'rx_errors': 0, 'crc': 12, 'tx_errors': 12, 'discards_in': 0, 'discards_out': 0,
        'link_flaps': 0, 'carrier_transitions': 0}
    # The same with the baseline: zero increase of crc is a compared zero, rx_errors is not comparable.
    again = engine.switch_read(auth, 'interface_errors', baseline=counts['counter_baseline'], summary='counts')
    base = again['summary']['baseline']
    assert base['ports_compared'] == 12
    assert base['increased_ports_by_counter']['crc'] == base['increased_ports_by_counter']['rx_errors'] == 0
    assert base['compared_ports_by_counter'] == {
        'rx_errors': 0, 'crc': 12, 'tx_errors': 12, 'discards_in': 0, 'discards_out': 0,
        'link_flaps': 0, 'carrier_transitions': 0}
    assert again['summary']['measured_ports_by_counter']['crc'] == 12


def test_reset_or_wrap_is_not_a_comparable_delta(monkeypatch):
    high = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '1', 2**32 - 3)
    auth, _ = setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=high))
    token = engine.switch_read(auth, 'interface_errors')['counter_baseline']
    low = set_exos_crc((EXOS / 'ports_rx_errors.txt').read_text(), '1', 4)
    setup_reads(monkeypatch, 'extreme_exos', exos_bodies(rx=low))
    base = engine.switch_read(auth, 'interface_errors', baseline=token, summary='counts')['summary']['baseline']
    assert base['ports_reset_or_wrap'] == 1
    assert base['compared_ports_by_counter']['crc'] == 11 and base['compared_ports_by_counter']['tx_errors'] == 12
