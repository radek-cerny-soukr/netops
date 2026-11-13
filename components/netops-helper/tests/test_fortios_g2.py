"""The three G2 FortiOS findings, with independent full-record expectations."""
import ipaddress
from pathlib import Path

import pytest

from support.replay_capture import load, replay
from netops_helper import fortiswitch_ports, switch_managed

CAPTURES = load(Path(__file__).parent / 'fixtures/real/scenarios/fortios-g2-route-vlan.json')['captures']


@pytest.mark.parametrize('capture', CAPTURES, ids=['fg80-32-routes', 'fg60-13-routes', 'fg60-9-vlans', 'fg80-7-vlans-reconstructed'])
def test_g2_cli_replay(capture):
    actual = replay(capture)
    if capture['table'] == 'route':
        assert [r['prefix'] for r in actual['records']] == [
            str(ipaddress.IPv4Network(p, strict=False)) for p in capture['expected_prefix_inputs']]


def test_config_node_fields_do_not_overwrite_parent_or_child_edit_fields():
    text = '''config system interface
    edit "vlan10"
        set vlanid 10
        config ipv6
            set vlanid 999
            set ip6-mode dhcp
            unset ip6-allowaccess
            config ip6-prefix-list
                edit "2001:db8::/64"
                    set autonomous-flag enable
                next
            end
        end
        set interface "port1"
    next
end
'''
    entries, unknown = fortiswitch_ports._entries(text, ('system interface',))
    assert unknown == []
    assert entries == [('vlan10', {'vlanid': ['10'], 'interface': ['port1']})]


def test_invalid_config_syntax_still_reported():
    for text in ['set ip6-mode dhcp', 'config ipv6\nset ip6-mode',
                 'config ipv6\nset ip6-mode dhcp\nset ip6-mode static\nend',
                 'config ipv6\nset ip6-mode dhcp\nnext\nend']:
        assert fortiswitch_ports._entries(text, ('system interface',))[1]


def test_route_legend_codes_are_structural_and_bad_routes_stay_unknown():
    text = '''Codes: C - connected, B - BGP
       V - BGP VPNv4
       X1 - Future protocol, X2 - Another protocol
B       192.0.2.0/24 [200/0] via 999.1.1.1 (recursive is directly connected, port1), 00:01:00
S       198.51.100.0/24 [254/0] is a summary
unexpected output
'''
    rows, unknown = switch_managed.routes('route', text)
    assert rows == []
    assert [item['line'] for item in unknown] == [4, 5, 6]
