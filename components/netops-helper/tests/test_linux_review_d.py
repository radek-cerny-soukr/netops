"""Review D regressions through the real engine, with documentary IP addresses."""
from dataclasses import replace

import pytest

from conftest import _target
from netops_helper import engine


def read_interfaces(monkeypatch, addresses, routes=''):
    commands = {
        'uname -a': 'Linux host01 6.8.0-147-generic #1 SMP x86_64 GNU/Linux\n',
        'ip -brief address': addresses,
        'ip -brief link': 'eth0 UP 00:00:5e:00:53:01 <UP,LOWER_UP>\n'
                         'eth1 UP 00:00:5e:00:53:02 <UP,LOWER_UP>\n'
                         'tun0 UNKNOWN link/none <POINTOPOINT,UP,LOWER_UP>\n',
        'ip route show': routes,
    }
    calls = []

    def read(auth, profile, command):
        assert profile == 'linux'
        calls.append(command)
        return 0, commands[command]

    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    auth = replace(_target('linux', 'addresses'), enabled_queries=('addresses', 'links', 'routes'))
    result = engine.switch_read(auth, 'ip_interface')
    expected = ['ip -brief address', 'ip -brief link', 'ip route show'] if result['records'] else ['ip -brief address']
    assert [command for command in calls if command != 'uname -a'] == expected
    return result


@pytest.mark.parametrize('routes', [
    'default nhid 7 via 192.0.2.1 dev eth0 proto static\n',
    'default nhid 7\n',
    'default nhid 7 proto static\n    nexthop via 192.0.2.1 dev eth0 weight 1\n',
])
def test_missing_gateway_with_unknown_routes_is_incomplete(monkeypatch, routes):
    result = read_interfaces(monkeypatch, 'eth0 UP 192.0.2.10/24\n', routes)
    assert result['status'] == 'ok'
    assert result['records'][0]['ip'] == '192.0.2.10'
    assert result['records'][0]['mac'] == '00:00:5e:00:53:01'
    assert not result['coverage']['complete']
    assert 'routes_partial' in result['warnings']
    assert 'routes_partial' in result['coverage']['warnings']


def test_found_gateway_with_unknown_routes_keeps_complete_coverage(monkeypatch):
    result = read_interfaces(monkeypatch, 'eth0 UP 192.0.2.10/24\n',
                             'default via 192.0.2.1 dev eth0\nFUTURE ROUTE OUTPUT\n')
    assert result['records'][0]['gateway'] == '192.0.2.1'
    assert result['coverage']['complete']
    assert 'routes_partial' not in result['warnings']


def test_one_found_gateway_does_not_hide_another_missing_gateway(monkeypatch):
    result = read_interfaces(monkeypatch, 'eth0 UP 192.0.2.10/24\neth1 UP 198.51.100.10/24\n',
                             'default via 192.0.2.1 dev eth0\ndefault nhid 7 via 198.51.100.1 dev eth1\n')
    assert [row['gateway'] for row in result['records']] == ['192.0.2.1', None]
    assert not result['coverage']['complete']
    assert 'routes_partial' in result['warnings']


@pytest.mark.parametrize('routes', [
    'FUTURE ROUTE OUTPUT\n',
    '192.0.2.0/24 nhid 7 dev eth0\n',
    'blackhole 198.51.100.0/24\n',
])
def test_unknown_nondefault_does_not_affect_gateway_coverage(monkeypatch, routes):
    result = read_interfaces(monkeypatch, 'eth0 UP 192.0.2.10/24\n', routes)
    assert result['coverage']['complete']
    assert result['records'][0]['gateway'] is None
    assert 'routes_partial' not in result['warnings']


@pytest.mark.parametrize('unknown', [
    'default nhid 7 via 192.0.2.254 dev eth0\n',
    'default nhid 7 proto static\n    nexthop via 192.0.2.254 dev eth0 weight 1\n',
])
def test_unknown_default_warns_without_penalizing_unrelated_interfaces(monkeypatch, unknown):
    addresses = ('eth0 UP 192.0.2.10/24\nlo UNKNOWN 127.0.0.1/8\n'
                 'docker0 DOWN 198.51.100.1/24\nbr0 UP 203.0.113.1/24\n')
    result = read_interfaces(monkeypatch, addresses, 'default via 192.0.2.1 dev eth0\n' + unknown)
    assert result['records'][0]['gateway'] == '192.0.2.1'
    assert result['coverage']['complete']
    assert 'routes_partial' in result['warnings']
    assert 'routes_partial' not in result['coverage'].get('warnings', [])


@pytest.mark.parametrize('routes', ['', '192.0.2.0/24 dev eth0 proto kernel scope link\n'])
def test_fully_parsed_routes_without_default_remain_complete(monkeypatch, routes):
    result = read_interfaces(monkeypatch, 'eth0 UP 192.0.2.10/24\n', routes)
    assert result['records'][0]['gateway'] is None
    assert result['coverage']['complete']

@pytest.mark.parametrize('local,peer,prefix', [
    ('192.0.2.1', '192.0.2.2/32', 32),
    ('192.0.2.1', '192.0.2.2/30', 30),
    ('2001:db8::1', '2001:db8::2/128', 128),
])
def test_brief_peer_uses_local_address_and_peer_prefix(monkeypatch, local, peer, prefix):
    result = read_interfaces(monkeypatch, f'tun0 UNKNOWN {local} peer {peer}\n')
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert len(result['records']) == 1
    row = result['records'][0]
    assert (row['interface'], row['ip'], row['prefix_length']) == ('tun0', local, prefix)
    assert row['admin_status'] == 'up'


@pytest.mark.parametrize('body', [
    '192.0.2.1 peer', '192.0.2.1 peer invalid/32',
    '192.0.2.1 peer 2001:db8::2/128', '192.0.2.1 peer 192.0.2.2',
])
def test_malformed_peer_is_still_unparsed(monkeypatch, body):
    result = read_interfaces(monkeypatch, f'tun0 UNKNOWN {body}\n')
    assert result['status'] == 'unparsed'
    assert result['records'] == [] and not result['coverage']['complete']
