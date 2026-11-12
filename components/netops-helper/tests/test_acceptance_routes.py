"""Replay anonymized candidate-acceptance output, retaining every device line."""
from pathlib import Path

import pytest

from netops_helper import tables

REAL = Path(__file__).parent / 'fixtures/real'
ROUTES = REAL / 'juniper_junos_els/vjunosswitch_26.2R1.7/route_table_acceptance.txt'


@pytest.mark.parametrize('profile', ['juniper_junos', 'juniper_junos_els'])
def test_full_junos_acceptance_routes(profile):
    result = tables.parse(profile, 'route', 'route_table', ROUTES.read_text())
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert result['unparsed'] == [] and len(result['records']) == 15
    rows = {r['prefix']: r for r in result['records']}
    assert rows['0.0.0.0/0']['next_hop'] == '192.0.2.1'
    assert rows['fe80::10/128']['interface'] == 'fxp0.0'
    assert rows['ff02::2/128']['protocol'] == 'local'
    assert rows['203.0.113.254/32']['protocol'] == 'ospf'


@pytest.mark.parametrize('age', ['09:25:51', '1d 09:25:51', '2w3d 09:25:51',
                                 '2w 09:25:51', '3d', '2w3d', '1h2m3s'])
def test_junos_age_formats_with_separate_ipv6_prefix_and_multiple_entries(age):
    text = ('2001:db8::/64\n'
            f'  *[OSPF3/10] {age}, metric 2\n'
            '    > to fe80::1 via ge-0/0/0.0\n'
            f'   [Static/5] {age}\n'
            '    > to fe80::2 via ge-0/0/1.0\n')
    result = tables.parse('juniper_junos_els', 'route', 'route_table', text)
    assert result['status'] == 'ok' and result['unparsed'] == []
    row, = result['records']
    assert (row['prefix'], row['protocol'], row['next_hop']) == ('2001:db8::/64', 'ospf', 'fe80::1')


def test_junos_unknown_age_remains_unparsed():
    result = tables.parse('juniper_junos_els', 'route', 'route_table',
                          '192.0.2.0/24 *[Direct/0] yesterday\n  > via irb.10\n')
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
