"""Adversarial device text exercises parser entry points, not copied regexes."""
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[3] / "tests/v1"))
from parser_watchdog import measured_growth

import pytest

from netops_helper import normalization, switch_managed, tables, wifi_parse


@pytest.mark.parametrize('unit', [' ', 'a '])
def test_nxos_model_near_miss(unit):
    build = lambda size: 'Cisco Nexus Operating System (NX-OS) Software\nNXOS: version 9.3(12)\ncisco ' + unit * size + '!\n'
    row = measured_growth(build, lambda text: normalization.parse_identity('cisco_nxos', text))
    assert row['os_version'] == '9.3(12)' and row['model'] is None


@pytest.mark.parametrize('unit', [' ', 'a '])
@pytest.mark.parametrize('case', ['managed_lldp', 'exos_mac', 'vlan', 'fortios_mac', 'fortios_flags'])
def test_table_near_misses_keep_unknown_rows(case, unit):
    def parse_size(size):
        padding = unit * size
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
        rows, unknown = parse()
        assert not rows and any(item['text'] == line for item in unknown)
    measured_growth(lambda size: size, parse_size)


@pytest.mark.parametrize('unit', [' ', 'a '])
def test_wifi_scan_near_miss(unit):
    result = measured_growth(lambda size: unit * size, lambda padding: wifi_parse.parse_scan(
        'CMWF VF SSID BSSID CHAN RATE SIGNAL NOISE INT CAPS ACT LIVE AGE WIRED\n'
        'C--F 0 ' + padding + '!'))
    assert not result['records'] and result['unparsed'] == [2]


def test_wifi_event_long_malformed_identifier():
    def reject(value):
        with pytest.raises(ValueError):
            wifi_parse._event_fields(value)
    measured_growth(lambda size: 'a' * size, reject)
    assert wifi_parse._event_fields('key="two words" other=value') == {'key': 'two words', 'other': 'value'}


def test_wifi_event_long_valid_value():
    result = measured_growth(lambda size: 'a' * size, lambda value: wifi_parse._event_fields('key=' + value))
    assert result == {'key': 'a' * 2500}
