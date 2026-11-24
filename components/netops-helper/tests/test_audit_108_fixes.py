"""Regression cases for the external audit of 1.0.8, items A, B and D.

Every input is the synthetic/adversarial input of the audit reproducer
(ref/verification-42-reproduce.py), not a device capture; it goes through the
real tables.parse with the real CDP and Linux parsers (nothing is mocked).
The FDB MAC is moved into the documentation range (the release gate refuses
other MAC literals); the state words, ports and bridges are the reproducer's.
"""
from pathlib import Path

import pytest

from netops_helper import tables

REAL = Path(__file__).parent / 'fixtures/real'
CDP_FIXTURES = sorted(REAL.glob('*/*/cdp_neighbors*.txt'))


def cdp(text, profile='cisco_ios'):
    return tables.parse(profile, 'cdp_neighbor', 'cdp_neighbors', text)


def cdp_block(device, local, port_id, extra=(), platform='Linux', caps='Host'):
    return '\n'.join([
        '-------------------------',
        f'Device ID: {device}',
        'Entry address(es): ',
        '  IP address: 192.0.2.66',
        f'Platform: {platform},  Capabilities: {caps} ',
        f'Interface: {local},  Port ID (outgoing port): {port_id}',
        'Holdtime : 150 sec',
        *extra,
        '',
        'Version :',
        'Synthetic OS 1.0',
        '',
        'advertisement version: 2',
        '',
    ])


# A. Version TLV injection (reproducer A_TEXT).
INJECTED = '\n'.join([
    '-------------------------',
    'Device ID: evil',
    'Entry address(es): ',
    '  IP address: 192.0.2.66',
    'Platform: Linux,  Capabilities: Host ',
    'Interface: GigabitEthernet1/0/9,  Port ID (outgoing port): eth0',
    'Holdtime : 150 sec',
    '',
    'Version :',
    'Synthetic OS 1.0',
    'Device ID: CORE-SW1',
    'Platform: Cisco, Capabilities: Router Switch',
    'Interface: GigabitEthernet1/0/1, Port ID (outgoing port): TenGigabitEthernet1/1/1',
    '',
    'advertisement version: 2',
    '',
    'Total cdp entries displayed : 1',
    '',
])
INJECTED_LINES = ('Device ID: CORE-SW1\n', 'Platform: Cisco, Capabilities: Router Switch\n',
                  'Interface: GigabitEthernet1/0/1, Port ID (outgoing port): TenGigabitEthernet1/1/1\n')
CONTROL = INJECTED
for _line in INJECTED_LINES:
    CONTROL = CONTROL.replace(_line, '')
EVIL = {'neighbor': 'evil', 'local_port': 'GigabitEthernet1/0/9', 'neighbor_port': 'eth0',
        'management_ip': None, 'platform': 'Linux', 'capabilities': 'Host'}


@pytest.mark.parametrize('text', [INJECTED, CONTROL], ids=['injected', 'control'])
def test_a_device_id_inside_version_text_is_not_a_neighbor(text):
    result = cdp(text)
    assert [row['neighbor'] for row in result['records']] == ['evil']
    assert result['records'][0] == EVIL
    assert result['status'] == 'ok' and result['unparsed'] == [] and result['coverage']['complete']


def test_a_real_captures_separate_records_with_a_dashed_line():
    # The record separator the rule relies on: every real CDP block starts after a dashed line.
    assert CDP_FIXTURES
    for path in CDP_FIXTURES:
        lines = [line.strip() for line in path.read_text().splitlines()]
        starts = [index for index, line in enumerate(lines) if line.lower().startswith('device id:')]
        assert starts, path
        for index in starts:
            assert set(lines[index - 1]) == {'-'} and len(lines[index - 1]) >= 5, (path, index)


def test_a_entry_count_mismatch_is_never_complete():
    # A separator injected inside the Version text still creates a second block, but the device's own
    # count (1) disagrees with the two parsed blocks: the read is visible as incomplete.
    text = INJECTED.replace('Device ID: CORE-SW1\n', '-------------------------\nDevice ID: CORE-SW1\n')
    result = cdp(text)
    assert len(result['records']) == 2
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert result['unparsed'] == [{'line': 18, 'text': 'Total cdp entries displayed : 1 (parsed 2 CDP neighbor blocks)'}]
    assert 'unrecognized_output_lines' in result['warnings']
    # The control with a wrong count is incomplete too.
    result = cdp(CONTROL.replace('displayed : 1', 'displayed : 2'))
    assert len(result['records']) == 1 and not result['coverage']['complete']
    assert result['unparsed'][-1]['text'].startswith('Total cdp entries displayed : 2')


# Review: an "advertisement version" line injected in the Version text ends the section,
# and a following "Device ID:" without a dashed separator must still not open a record.
FORGED_END = '\n'.join([
    '-------------------------',
    'Device ID: evil',
    'Platform: Linux, Capabilities: Host',
    'Interface: Ethernet1/9, Port ID (outgoing port): eth0',
    'Version:',
    'Synthetic OS',
    'advertisement version: 2',
    'Device ID: CORE-SW1',
    'Platform: Cisco, Capabilities: Router Switch',
    'Interface: Ethernet1/1, Port ID (outgoing port): Ethernet1/2',
    'Version:',
    'Synthetic tail',
    'Advertisement Version: 2',
])


@pytest.mark.parametrize('profile', ['cisco_nxos', 'cisco_ios'])
def test_a_device_id_after_forged_version_end_is_not_a_neighbor(profile):
    result = cdp(FORGED_END, profile)
    assert 'CORE-SW1' not in [row['neighbor'] for row in result['records']]
    assert [row['neighbor'] for row in result['records']] == ['evil']
    assert result['coverage']['complete'] is not True
    assert result['status'] == 'unparsed' and 'unrecognized_output_lines' in result['warnings']
    assert result['unparsed'][0] == {'line': 8, 'text': 'Device ID: CORE-SW1'}


@pytest.mark.parametrize('path', CDP_FIXTURES, ids=lambda path: path.parent.name)
def test_a_real_captures_with_matching_count_stay_complete(path):
    profile = path.parent.parent.name
    result = cdp(path.read_text(), profile)
    assert result['status'] == 'ok' and result['coverage']['complete'] and result['unparsed'] == []


# B. Foreign Port IDs: one independent block per input (reproducer B).
@pytest.mark.parametrize('index,port_id', list(enumerate(('eth0', 'Port 1', 'ether1', 'vmnic0', 'ens18', 'swp1'), 2)))
def test_b_foreign_port_id_is_kept_as_advertised(index, port_id):
    result = cdp(cdp_block(f'peer-{index}', f'GigabitEthernet1/0/{index}', port_id)
                 + 'Total cdp entries displayed : 1\n')
    assert result['status'] == 'ok' and result['unparsed'] == [] and result['coverage']['complete'], result
    (row,) = result['records']
    assert row['neighbor_port'] == port_id
    assert row['local_port'] == f'GigabitEthernet1/0/{index}'


PHONE_EXTRA = ('Power drawn: 6.300 Watts', 'Power request id: 0, Power management id: 1',
               'Power request levels are: 0 0 0 0 0', 'Second Port Status: Down')


def test_b_ip_phone_port_and_power_lines():
    text = cdp_block('SEP00005E005399', 'GigabitEthernet1/0/5', 'Port 1', PHONE_EXTRA,
                     platform='Cisco IP Phone 8851', caps='Host Phone Two-port Mac Relay') \
        + 'Total cdp entries displayed : 1\n'
    result = cdp(text)
    assert result['status'] == 'ok' and result['unparsed'] == [] and result['coverage']['complete'], result
    (row,) = result['records']
    assert row['neighbor_port'] == 'Port 1' and row['local_port'] == 'GigabitEthernet1/0/5'
    assert row['platform'] == 'Cisco IP Phone 8851'


def test_b_power_available_tlv_is_a_known_line():
    extra = ('Power Available TLV:', '', '    Power request id: 0, Power management id: 0, Power available: 0, '
             'Power management level: 0')
    result = cdp(cdp_block('SEP00005E005398', 'GigabitEthernet1/0/6', 'Port 1', extra,
                           platform='Cisco IP Phone 8851', caps='Host Phone'))
    assert result['status'] == 'ok' and result['unparsed'] == []


@pytest.mark.parametrize('platform', ['cisco WS-C2960X-48FPD-L', 'Cisco', 'CISCO C9300-48P'])
def test_b_cisco_neighbor_port_is_still_normalized(platform):
    result = cdp(cdp_block('sw-a', 'Gi1/0/7', 'Gi0/1', platform=platform, caps='Switch IGMP'))
    (row,) = result['records']
    assert row['neighbor_port'] == 'GigabitEthernet0/1' and row['local_port'] == 'GigabitEthernet1/0/7'
    assert result['status'] == 'ok'


def test_b_foreign_platform_keeps_cisco_like_port_text():
    result = cdp(cdp_block('linux-a', 'GigabitEthernet1/0/8', 'eth1'))
    assert result['records'][0]['neighbor_port'] == 'eth1'


# D. Linux bridge FDB state (reproducer D).
FDB = {
    'no_state': ('00:00:5e:00:53:01 dev nic0 master vmbr0\n', 'dynamic'),
    'no_state_trailing_space_as_in_repo_capture': ('00:00:5e:00:53:01 dev nic0 master vmbr0 \n', 'dynamic'),
    'dynamic': ('00:00:5e:00:53:01 dev nic0 master vmbr0 dynamic\n', 'dynamic'),
    'static': ('00:00:5e:00:53:01 dev nic0 master vmbr0 static\n', 'static'),
    'permanent': ('00:00:5e:00:53:01 dev nic0 master vmbr0 permanent\n', 'static'),
    'stale': ('00:00:5e:00:53:01 dev nic0 master vmbr0 stale\n', 'dynamic'),
}


@pytest.mark.parametrize('name', FDB)
def test_d_bridge_fdb_state(name):
    text, kind = FDB[name]
    result = tables.parse('linux', 'mac_entry', 'bridge_fdb', text)
    assert result['status'] == 'ok' and result['unparsed'] == []
    assert [row['type'] for row in result['records']] == [kind]
    assert result['records'][0]['port'] == 'nic0'


def test_d_conflicting_states_stay_visible():
    result = tables.parse('linux', 'mac_entry', 'bridge_fdb', '00:00:5e:00:53:01 dev nic0 master vmbr0 permanent stale\n')
    assert result['status'] == 'unparsed' and result['records'] == []
