"""Adversarial device text exercises parser entry points, not copied regexes."""
from time import perf_counter

import pytest

from netops_helper import normalization, switch_managed, tables, wifi_parse


def timed(call):
    started = perf_counter()
    result = call()
    elapsed = perf_counter() - started
    assert elapsed < 0.5, elapsed
    return result


@pytest.mark.parametrize('padding', [' ' * 10000, 'a ' * 5000])
def test_nxos_model_near_miss(padding):
    text = 'Cisco Nexus Operating System (NX-OS) Software\nNXOS: version 9.3(12)\ncisco ' + padding + '!\n'
    row = timed(lambda: normalization.parse_identity('cisco_nxos', text))
    assert row['os_version'] == '9.3(12)' and row['model'] is None


@pytest.mark.parametrize('padding', [' ' * 10000, 'a ' * 5000])
@pytest.mark.parametrize('case', ['managed_lldp', 'exos_mac', 'vlan', 'fortios_mac', 'fortios_flags'])
def test_table_near_misses_keep_unknown_rows(case, padding):
    mac = '00:00:5e:00:53:01'
    if case == 'managed_lldp':
        line = 'port1 Up ' + padding + '!'
        text = 'Portname Status Device-name TTL Capability MED-type Port-ID\n' + line
        parse = lambda: switch_managed.parse('lldp_neighbor', text)
    elif case == 'exos_mac':
        line = mac + ' vlan(0001) 0 ' + padding + '!'
        parse = lambda: tables.exos('mac_entry', line)
    elif case == 'vlan':
        line = '10 ' + padding + '!'
        parse = lambda: tables.vlan_sections('VLAN Name Status Ports\n' + line, 'cisco_ios')
    elif case == 'fortios_mac':
        line = 'MAC:' + mac + ' VLAN:10 Port:' + padding.replace(' ', '\u00a0') + '!'
        parse = lambda: tables.fortinet('mac_entry', line)
    else:
        line = 'Flags:0x0[' + padding + '!'
        parse = lambda: tables.fortinet('mac_entry', line)
    rows, unknown = timed(parse)
    assert not rows and any(item['text'] == line for item in unknown)


@pytest.mark.parametrize('padding', [' ' * 10000, 'a ' * 5000])
def test_wifi_scan_near_miss(padding):
    result = timed(lambda: wifi_parse.parse_scan(
        'CMWF VF SSID BSSID CHAN RATE SIGNAL NOISE INT CAPS ACT LIVE AGE WIRED\n'
        'C--F 0 ' + padding + '!'))
    assert not result['records'] and result['unparsed'] == [2]


def test_wifi_event_long_malformed_identifier():
    started = perf_counter()
    with pytest.raises(ValueError):
        wifi_parse._event_fields('a' * 10000)
    assert perf_counter() - started < 0.5
    assert wifi_parse._event_fields('key="two words" other=value') == {'key': 'two words', 'other': 'value'}


def test_wifi_event_long_valid_value():
    value = 'a' * 10000
    assert timed(lambda: wifi_parse._event_fields('key=' + value)) == {'key': value}
