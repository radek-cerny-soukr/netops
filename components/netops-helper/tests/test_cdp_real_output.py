"""CDP normalization from the existing, anonymized RO IOS/IOS XE/NX-OS captures."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, tables
from netops_helper.auth import PolicyScopeError

REAL = Path(__file__).parent / 'fixtures/real'
# Expected values transcribed from CLI, independent of the parser.
CASES = [
    ('cisco_ios', 'iosv_15.9.3M12', 4,
     ('GigabitEthernet0/0', 'host01(93M7JA0RG21)', 'mgmt0', '203.0.113.55',
      'N9K-C9300v', 'Router Switch CVTA phone port')),
    ('cisco_ios', 'iosvl2_15.2.20200924', 4,
     ('GigabitEthernet0/1', 'host07', 'GigabitEthernet0/1', '203.0.113.51',
      'Cisco', 'Router Source-Route-Bridge')),
    ('cisco_xe', 'iolxe_17.18.2', 3,
     ('Ethernet0/0', 'host04', 'GigabitEthernet0/0', '203.0.113.179',
      'Cisco', 'Router Source-Route-Bridge')),
    ('cisco_nxos', 'nexus9300v_9.3.12', 3,
     ('mgmt0', 'host03', 'GigabitEthernet0/0', '203.0.113.180',
      'Cisco', 'Router Switch IGMP Filtering')),
]
CDP_FIELDS = ('local_port', 'neighbor', 'neighbor_port', 'management_ip', 'platform', 'capabilities')


@pytest.mark.parametrize('profile,firmware,count,first', CASES)
def test_cdp_capture_through_real_engine(monkeypatch, profile, firmware, count, first):
    directory = REAL / profile / firmware
    calls = []

    def transport(auth, selected, command):
        calls.append(command)
        assert selected == profile
        assert command in ('show version', 'show cdp neighbors detail')
        return 0, (directory / ('version.txt' if command == 'show version' else 'cdp_neighbors.txt')).read_text()

    monkeypatch.setattr(engine, 'read_from_device', transport)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(_target(profile, 'cdp_neighbors'), device_types=('switch',))
    result = engine.switch_read(auth, 'cdp_neighbor')
    assert result['status'] == 'ok', result
    assert result['coverage']['complete'] and result['unparsed'] == []
    assert len(result['records']) == count
    assert tuple(result['records'][0][field] for field in CDP_FIELDS) == first
    assert calls == ['show version', 'show cdp neighbors detail']
    assert result['sources'][0]['query'] == 'cdp_neighbors'
    # Every advertised adjacency is retained, even the same neighbor on two local ports.
    assert len({tuple(row[field] for field in CDP_FIELDS) for row in result['records']}) == count


@pytest.mark.parametrize('profile,firmware,count,first', CASES)
def test_unknown_cdp_data_is_visible(profile, firmware, count, first):
    body = (REAL / profile / firmware / 'cdp_neighbors.txt').read_text()
    result = tables.parse(profile, 'cdp_neighbor', 'cdp_neighbors', body + '\nUnknown CDP field: value\n')
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert len(result['records']) == count
    assert [line['text'] for line in result['unparsed']] == ['Unknown CDP field: value']


def test_cdp_missing_required_port_is_incomplete():
    body = (REAL / 'cisco_xe/iolxe_17.18.2/cdp_neighbors.txt').read_text()
    body = body.replace('Interface: Ethernet0/0,  Port ID (outgoing port): GigabitEthernet0/0', '', 1)
    result = tables.parse('cisco_xe', 'cdp_neighbor', 'cdp_neighbors', body)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert len(result['records']) == 3 and result['records'][0]['local_port'] is None


def test_cdp_uses_management_section_not_entry_address():
    body = (REAL / 'cisco_xe/iolxe_17.18.2/cdp_neighbors.txt').read_text()
    body = body.replace('  IP address: 203.0.113.179', '  IP address: 192.0.2.99', 1)
    result = tables.parse('cisco_xe', 'cdp_neighbor', 'cdp_neighbors', body)
    assert result['status'] == 'ok' and result['records'][0]['management_ip'] == '203.0.113.179'


def test_cdp_does_not_grant_an_unenrolled_query(monkeypatch):
    calls = []
    monkeypatch.setattr(engine, 'read_from_device', lambda *a, **k: calls.append(a))
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    auth = replace(_target('cisco_xe', 'lldp_neighbors'), device_types=('switch',))
    with pytest.raises(PolicyScopeError):
        engine.switch_read(auth, 'cdp_neighbor')
    assert not calls
