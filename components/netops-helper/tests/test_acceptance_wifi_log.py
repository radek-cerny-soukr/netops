"""FortiGate 80F 8.0.2 log display, captured through MCP wifi_events on 2026-11-10.

Fixture anonymized with support/anonymize_fixture.py; the full 50-event batch is retained.
"""
from pathlib import Path

import pytest

from netops_helper import wifi_parse

EVENTS = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2/wifi_events_acceptance.txt'


def test_full_fortios_acceptance_wifi_log_and_mac_filter():
    text = EVENTS.read_text()
    result = wifi_parse.parse_events(text)
    assert result['unparsed'] == [] and result['unparsed_count'] == 0
    assert (result['found'], result['returned'], len(result['records'])) == (388, 50, 50)
    mac = next(row['client_mac'] for row in result['records'] if row['client_mac'])
    filtered, metadata = wifi_parse.filter_events_by_mac(text, mac)
    selected = wifi_parse.parse_events(filtered)
    assert selected['unparsed'] == []
    assert selected['records'] and all(row['client_mac'] == mac or row['bssid'] == mac for row in selected['records'])
    assert metadata['scanned_lines'] == 50
    assert (selected['found'], selected['returned']) == (388, 50)


@pytest.mark.parametrize('progress', ['0', '2.8', '99.99', '100', '100.0'])
@pytest.mark.parametrize('verb', ['has', 'have'])
def test_log_search_progress_without_events(progress, verb):
    result = wifi_parse.parse_events(f'0 logs found.\n0 logs returned.\n{progress}% of logs {verb} been searched.\n')
    assert result['unparsed'] == [] and result['records'] == []
    assert result['found'] == result['returned'] == 0


@pytest.mark.parametrize('line', ['101% of logs has been searched.', 'search failed',
                                  '2.8% of logs has been searched. unexpected'])
def test_unknown_log_status_is_visible(line):
    result = wifi_parse.parse_events(line)
    assert result['unparsed_count'] == 1
