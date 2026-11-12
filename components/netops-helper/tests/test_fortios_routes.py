"""FortiOS IPv4 route bindings over the dated RO captures."""
from pathlib import Path

from netops_helper import tables

REAL = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2_build0251/captures_20261110'


def fixture(name):
    return (REAL / (name + '.txt')).read_text()


def test_route_lookup_reuses_triage_and_preserves_three_ecmp_hops():
    result = tables.parse('fortinet', 'route', 'route_lookup', fixture('route_lookup'))
    assert result['status'] == 'ok' and result['coverage']['complete']
    assert [(r['prefix'], r['protocol'], r['interface'], r['next_hop'], r['vrf']) for r in result['records']] == [
        ('0.0.0.0/0', 'static', 'wan1', '192.0.2.1', 'default'),
        ('0.0.0.0/0', 'static', 'LTE-OP1', '198.51.100.121', 'default'),
        ('0.0.0.0/0', 'static', 'LTE-OP2', '203.0.113.129', 'default')]
    assert tables.request('fortinet', 'route')[0] == 'routing_table'
    assert tables.request('fortinet', 'route', ip='192.0.2.8')[:2] == ('route_lookup', {'address': '192.0.2.8'})
    assert tables.parse('fortinet', 'route', 'route_lookup', '% Network not in table\n')['status'] == 'empty'


def test_whole_route_table_keeps_ecmp_connected_and_tunnel_routes():
    result = tables.parse('fortinet', 'route', 'routing_table', fixture('routing_table'))
    assert result['status'] == 'ok' and len(result['records']) == 26
    assert len([r for r in result['records'] if r['prefix'] == '0.0.0.0/0']) == 3
    assert all(r['next_hop'] is None for r in result['records'] if r['protocol'] == 'connected')
    assert any(r['interface'] == 'HUB-O1' and r['protocol'] == 'static' for r in result['records'])
    result = tables.parse('fortinet', 'route', 'routing_table', fixture('routing_table') + 'NEW OUTPUT\n')
    assert result['status'] == 'unparsed' and result['unparsed'][-1]['text'] == 'NEW OUTPUT'


