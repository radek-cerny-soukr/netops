from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog.cisco import (  # noqa: E402
    IOS_QUERIES,
    IOS_XE_QUERIES,
    NXOS_QUERIES,
)
from netops_helper.read_policy import render_read_query  # noqa: E402


EXPECTED: dict[str, dict[str, tuple[str, dict[str, tuple[str, str]]]]] = {
    "ios": {
        "aaa_servers": ("show aaa servers", {}),
        "radius_statistics": ("show radius statistics", {}),
        "tacacs_statistics": ("show tacacs", {}),
        "snmp_statistics": ("show snmp", {}),
        "snmp_engine_id": ("show snmp engineID", {}),
        "dns_hosts": ("show hosts", {}),
        "users": ("show users", {}),
        "ssh_sessions": ("show ssh", {}),
        "lines": ("show line", {}),
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "interfaces": ("show interfaces status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "route_summary": ("show ip route summary", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interface_details": ("show interfaces {interface}", {"interface": ("interfaces", "cisco_ios_interface")}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "inventory": ("show inventory", {}),
        "environment": ("show env all", {}),
        "interface_errors": ("show interfaces {interface} counters errors", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbors", {}),
        "mac_table": ("show mac address-table", {}),
        "vlans": ("show vlan brief", {}),
        "lag_summary": ("show etherchannel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "bgp_summary": ("show ip bgp summary", {}),
        "ospf_neighbors": ("show ip ospf neighbor", {}),
        "hsrp_summary": ("show standby brief", {}),
        "vrrp_summary": ("show vrrp brief", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interfaces status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interfaces description", {}),
        "interfaces_trunk": ("show interfaces trunk", {}),
        "interfaces_counters_errors": ("show interfaces counters errors", {}),
        "interfaces_details": ("show interfaces", {}),
        "interface_switchport": ("show interfaces {interface} switchport", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "interface_transceiver": ("show interfaces {interface} transceiver detail", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "power_inline": ("show power inline", {}),
        "vtp_status": ("show vtp status", {}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp associations", {}),
        "stack_members": ("show switch", {}),
        "stack_ports": ("show switch stack-ports summary", {}),
        "log_messages": ("show logging", {}),
    },
    "ios_xe": {
        "aaa_servers": ("show aaa servers", {}),
        "radius_statistics": ("show radius statistics", {}),
        "tacacs_statistics": ("show tacacs", {}),
        "snmp_statistics": ("show snmp", {}),
        "snmp_engine_id": ("show snmp engineID", {}),
        "dns_hosts": ("show hosts", {}),
        "users": ("show users", {}),
        "ssh_sessions": ("show ssh", {}),
        "lines": ("show line", {}),
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "interfaces": ("show interfaces status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "route_summary": ("show ip route summary", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interface_details": ("show interfaces {interface}", {"interface": ("interfaces", "cisco_xe_interface")}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "inventory": ("show inventory", {}),
        "environment": ("show environment all", {}),
        "interface_errors": ("show interfaces {interface} counters errors", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbors", {}),
        "mac_table": ("show mac address-table", {}),
        "vlans": ("show vlan brief", {}),
        "lag_summary": ("show etherchannel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "bgp_summary": ("show ip bgp summary", {}),
        "ospf_neighbors": ("show ip ospf neighbor", {}),
        "hsrp_summary": ("show standby brief", {}),
        "vrrp_summary": ("show vrrp brief", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interfaces status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interfaces description", {}),
        "interfaces_trunk": ("show interfaces trunk", {}),
        "interfaces_counters_errors": ("show interfaces counters errors", {}),
        "interfaces_details": ("show interfaces", {}),
        "interface_switchport": ("show interfaces {interface} switchport", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "interface_transceiver": ("show interfaces {interface} transceiver detail", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "power_inline": ("show power inline", {}),
        "vtp_status": ("show vtp status", {}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp associations", {}),
        "stack_members": ("show switch", {}),
        "stack_ports": ("show switch stack-ports summary", {}),
        "log_messages": ("show logging", {}),
        "platform_resources": ("show platform resources", {}),
    },
    "nxos": {
        "dns_hosts": ("show hosts", {}),
        "snmp_statistics": ("show snmp", {}),
        "snmp_engine_id": ("show snmp engineID", {}),
        "aaa_authentication": ("show aaa authentication", {}),
        "radius_statistics": ("show radius-server statistics {address}", {'address': ('addresses', 'ipv4_address')}),
        "tacacs_statistics": ("show tacacs-server statistics {address}", {'address': ('addresses', 'ipv4_address')}),
        "users": ("show users", {}),
        "ssh_server": ("show ssh server", {}),
        "configuration_sessions": ("show configuration session summary", {}),
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "inventory": ("show inventory", {}),
        "environment": ("show environment", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interfaces": ("show interface status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "interface_details": ("show interface {interface}", {"interface": ("interfaces", "cisco_nxos_interface")}),
        "interface_errors": ("show interface {interface} counters errors", {"interface": ("interfaces", "cisco_nxos_errors_interface")}),
        "vlans": ("show vlan", {}),
        "mac_table": ("show mac address-table", {}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbor", {}),
        "lag_summary": ("show port-channel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "route_summary": ("show ip route summary", {}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "bgp_sessions": ("show bgp sessions", {}),
        "ospf_neighbors": ("show ip ospf neighbors", {}),
        "hsrp_summary": ("show hsrp summary", {}),
        "vrrp_summary": ("show vrrp summary", {}),
        "vpc_status": ("show vpc brief", {}),
        "vpc_peer_keepalive": ("show vpc peer-keepalive", {}),
        "vpc_role": ("show vpc role", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "bgp_summary": ("show bgp ipv4 unicast summary", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_blocked": ("show spanning-tree blockedports", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interface status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interface description", {}),
        "interfaces_trunk": ("show interface trunk", {}),
        "interfaces_counters_errors": ("show interface counters errors", {}),
        "interface_switchport": ("show interface {interface} switchport", {"interface": ("interfaces", "cisco_nxos_interface")}),
        "interface_transceiver": ("show interface {interface} transceiver details", {"interface": ("interfaces", "cisco_nxos_non_subinterface")}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp peer-status", {}),
        "system_resources": ("show system resources", {}),
        "reset_reason": ("show system reset-reason", {}),
        "modules": ("show module", {}),
        "license_usage": ("show license usage", {}),
        "redundancy_status": ("show redundancy status", {}),
        "features": ("show feature", {}),
        "vrfs": ("show vrf", {}),
        "bfd_neighbors": ("show bfd neighbors", {}),
        "vpc_consistency": ("show vpc consistency-parameters global", {}),
        "vpc_orphan_ports": ("show vpc orphan-ports", {}),
        "dhcp_snooping_binding": ("show ip dhcp snooping binding", {}),
        "access_lists": ("show ip access-lists", {}),
        "log_messages": ("show logging last 200", {}),
    },
}

EXPECTED["ios"].update({
    'vrfs': ('show ip vrf', {}),
    'vrf_route_lookup': ('show ip route vrf {vrf} {address}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_lookup')}),
    'vrf_arp_table': ('show arp vrf {vrf}', {'vrf': ('vrfs', 'vrf')}),
    'vrf_ip_interfaces': ('show ip vrf interfaces {vrf}', {'vrf': ('vrfs', 'vrf')}),
    'bgp_neighbor': ('show ip bgp neighbors {address}', {'address': ('addresses', 'ipv4_address')}),
    'bgp_prefix': ('show ip bgp {address}', {'address': ('addresses', 'ipv4_lookup')}),
    'bgp_advertised_routes': ('show ip bgp neighbors {address} advertised-routes', {'address': ('addresses', 'ipv4_address')}),
    'bgp_routes': ('show ip bgp neighbors {address} routes', {'address': ('addresses', 'ipv4_address')}),
    'ospf_neighbor_detail': ('show ip ospf neighbor detail', {}),
    'ospf_interface': ('show ip ospf interface {interface}', {'interface': ('interfaces', 'interface')}),
    'ospf_database': ('show ip ospf database', {}),
    'ip_protocols': ('show ip protocols', {}),
    'ipv6_route_table': ('show ipv6 route', {}),
    'ospfv3_neighbors': ('show ipv6 ospf neighbor', {}),
    'bgp_ipv6_summary': ('show bgp ipv6 unicast summary', {}),
    'ip_interface_details': ('show ip interface {interface}', {'interface': ('interfaces', 'interface')}),
    'ipv6_interface_details': ('show ipv6 interface {interface}', {'interface': ('interfaces', 'interface')}),
    'cef_lookup': ('show ip cef {address} detail', {'address': ('addresses', 'ipv4_lookup')}),
    'vrf_cef_lookup': ('show ip cef vrf {vrf} {address} detail', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_lookup')}),
    'adjacency_details': ('show adjacency {interface} detail', {'interface': ('interfaces', 'interface')}),
    'bfd_neighbors': ('show bfd neighbors details', {}),
    'route_maps': ('show route-map', {}),
    'ip_policy': ('show ip policy', {}),
})

# G69 independently declared IOS XE command and slot expectations.
EXPECTED["ios_xe"].update({
    'vrfs': ('show ip vrf', {}),
    'vrf_route_lookup': ('show ip route vrf {vrf} {address}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_lookup')}),
    'vrf_arp_table': ('show arp vrf {vrf}', {'vrf': ('vrfs', 'vrf')}),
    'vrf_ip_interfaces': ('show ip vrf interfaces {vrf}', {'vrf': ('vrfs', 'vrf')}),
    'bgp_neighbor': ('show ip bgp neighbors {address}', {'address': ('addresses', 'ipv4_address')}),
    'bgp_prefix': ('show ip bgp {address}', {'address': ('addresses', 'ipv4_lookup')}),
    'bgp_advertised_routes': ('show ip bgp neighbors {address} advertised-routes', {'address': ('addresses', 'ipv4_address')}),
    'bgp_routes': ('show ip bgp neighbors {address} routes', {'address': ('addresses', 'ipv4_address')}),
    'ospf_neighbor_detail': ('show ip ospf neighbor detail', {}),
    'ospf_interface': ('show ip ospf interface {interface}', {'interface': ('interfaces', 'interface')}),
    'ospf_database': ('show ip ospf database', {}),
    'ip_protocols': ('show ip protocols', {}),
    'ipv6_route_table': ('show ipv6 route', {}),
    'ospfv3_neighbors': ('show ipv6 ospf neighbor', {}),
    'bgp_ipv6_summary': ('show bgp ipv6 unicast summary', {}),
    'ip_interface_details': ('show ip interface {interface}', {'interface': ('interfaces', 'interface')}),
    'ipv6_interface_details': ('show ipv6 interface {interface}', {'interface': ('interfaces', 'interface')}),
    'cef_lookup': ('show ip cef {address} detail', {'address': ('addresses', 'ipv4_lookup')}),
    'vrf_cef_lookup': ('show ip cef vrf {vrf} {address} detail', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_lookup')}),
    'adjacency_details': ('show adjacency {interface} detail', {'interface': ('interfaces', 'interface')}),
    'bfd_neighbors': ('show bfd neighbors details', {}),
    'route_maps': ('show route-map', {}),
    'ip_policy': ('show ip policy', {}),
})

# Exact volume rationale: process tables, global interface, neighbor, forwarding,
# and discovery tables, plus variable LAG, STP, routing-peer, and FHRP lists can
# need continuation. False remains an advisory, not a bounded-output guarantee.
HIGH_VOLUME = {
    "ios": {
        "dns_hosts", "users", "ssh_sessions", "lines",
        "interfaces", "ip_interfaces", "ipv6_interfaces", "cpu", "memory",
        "arp_table", "ipv6_neighbors", "mac_table", "vlans", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_summary", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "route_table", "ospf_interfaces", "stp_tree",
        "stp_root", "stp_inconsistent", "err_disabled",
        "interfaces_description", "interfaces_trunk", "interfaces_counters_errors", "interfaces_details", "power_inline",
        "log_messages",
    },
    "ios_xe": {
        "dns_hosts", "users", "ssh_sessions", "lines",
        "interfaces", "ip_interfaces", "ipv6_interfaces", "cpu", "memory",
        "arp_table", "ipv6_neighbors", "mac_table", "vlans", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_summary", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "route_table", "ospf_interfaces", "stp_tree",
        "stp_root", "stp_inconsistent", "err_disabled",
        "interfaces_description", "interfaces_trunk", "interfaces_counters_errors", "interfaces_details", "power_inline",
        "log_messages",
    },
    "nxos": {
        "dns_hosts", "users", "ssh_server", "configuration_sessions",
        "cpu", "memory", "interfaces", "ip_interfaces", "ipv6_interfaces",
        "vlans", "mac_table", "arp_table", "ipv6_neighbors", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_sessions", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "vpc_status", "route_table", "ospf_interfaces", "bgp_summary",
        "stp_tree", "stp_root", "err_disabled", "interfaces_description",
        "interfaces_trunk", "interfaces_counters_errors",
        "dhcp_snooping_binding", "access_lists", "log_messages",
    },
}

HIGH_VOLUME["ios"].update({'ospf_neighbor_detail', 'bgp_neighbor', 'vrfs', 'ipv6_route_table', 'adjacency_details', 'vrf_arp_table', 'vrf_ip_interfaces', 'bgp_routes', 'ip_policy', 'route_maps', 'ospfv3_neighbors', 'bgp_ipv6_summary', 'bfd_neighbors', 'ip_protocols', 'bgp_advertised_routes', 'ospf_database'})
HIGH_VOLUME["ios_xe"].update({'ospf_neighbor_detail', 'bgp_neighbor', 'vrfs', 'ipv6_route_table', 'adjacency_details', 'vrf_arp_table', 'vrf_ip_interfaces', 'bgp_routes', 'ip_policy', 'route_maps', 'ospfv3_neighbors', 'bgp_ipv6_summary', 'bfd_neighbors', 'ip_protocols', 'bgp_advertised_routes', 'ospf_database'})

CATALOGUES = {
    "ios": IOS_QUERIES,
    "ios_xe": IOS_XE_QUERIES,
    "nxos": NXOS_QUERIES,
}


SHELL_METACHARACTERS = {
    ";",
    "&",
    "|",
    "`",
    "$",
    ">",
    "<",
    chr(92),
    chr(34),
    chr(39),
    "*",
    "?",
    "[",
    "]",
    "(",
    ")",
    "!",
    "#",
    "~",
}



# G90 catalogue additions.
EXPECTED["nxos"]['route_prefix_lookup'] = ('show ip route {prefix}', {'prefix': ('lookup_prefixes', 'ipv4_prefix')})
EXPECTED["nxos"]['route_map_counters'] = ('show route-map {route_map} pbr-statistics', {'route_map': ('route_maps', 'route_map')})
HIGH_VOLUME["nxos"].add('route_map_counters')
EXPECTED["nxos"]['bgp_neighbor_detail'] = ('show bgp ipv4 unicast neighbors {address}', {'address': ('addresses', 'ipv4_address')})
HIGH_VOLUME["nxos"].add('bgp_neighbor_detail')
EXPECTED["nxos"]['bgp_prefix_detail'] = ('show bgp ipv4 unicast {prefix}', {'prefix': ('lookup_prefixes', 'ipv4_prefix')})
HIGH_VOLUME["nxos"].add('bgp_prefix_detail')
EXPECTED["nxos"]['bgp_advertised_routes'] = ('show bgp ipv4 unicast neighbors {address} advertised-routes', {'address': ('addresses', 'ipv4_address')})
HIGH_VOLUME["nxos"].add('bgp_advertised_routes')
EXPECTED["nxos"]['bgp_received_routes'] = ('show bgp ipv4 unicast neighbors {address} routes', {'address': ('addresses', 'ipv4_address')})
HIGH_VOLUME["nxos"].add('bgp_received_routes')
EXPECTED["nxos"]['ospf_process'] = ('show ip ospf', {})
HIGH_VOLUME["nxos"].add('ospf_process')
EXPECTED["nxos"]['ospf_neighbors_detail'] = ('show ip ospf neighbors detail', {})
HIGH_VOLUME["nxos"].add('ospf_neighbors_detail')
EXPECTED["nxos"]['ospf_interface_detail'] = ('show ip ospf interface {interface}', {'interface': ('interfaces', 'cisco_nxos_interface')})
HIGH_VOLUME["nxos"].add('ospf_interface_detail')
EXPECTED["nxos"]['ospf_database'] = ('show ip ospf database', {})
HIGH_VOLUME["nxos"].add('ospf_database')
EXPECTED["nxos"]['ipv6_route_table'] = ('show ipv6 route', {})
HIGH_VOLUME["nxos"].add('ipv6_route_table')
EXPECTED["nxos"]['bgp_ipv6_summary'] = ('show bgp ipv6 unicast summary', {})
HIGH_VOLUME["nxos"].add('bgp_ipv6_summary')
EXPECTED["nxos"]['ospfv3_neighbors'] = ('show ipv6 ospfv3 neighbors', {})
HIGH_VOLUME["nxos"].add('ospfv3_neighbors')
EXPECTED["nxos"]['bfd_neighbors_detail'] = ('show bfd neighbors details', {})
HIGH_VOLUME["nxos"].add('bfd_neighbors_detail')
EXPECTED["nxos"]['forwarding_ipv4_route'] = ('show forwarding ipv4 route', {})
HIGH_VOLUME["nxos"].add('forwarding_ipv4_route')
EXPECTED["nxos"]['ip_adjacency'] = ('show ip adjacency', {})
HIGH_VOLUME["nxos"].add('ip_adjacency')
EXPECTED["nxos"]['route_maps'] = ('show route-map', {})
HIGH_VOLUME["nxos"].add('route_maps')
EXPECTED["nxos"]['ip_policy'] = ('show ip policy', {})
HIGH_VOLUME["nxos"].add('ip_policy')
for _name in ('route_lookup', 'route_prefix_lookup', 'route_table', 'arp_table', 'ipv6_neighbors', 'ip_interfaces', 'bgp_summary', 'ospf_neighbors', 'ospf_interfaces', 'ipv6_route_lookup', 'ipv6_route_table', 'bgp_ipv6_summary', 'ospfv3_neighbors'):
    _command, _slots_g90 = EXPECTED['nxos'][_name]
    EXPECTED['nxos'][_name + '_vrf'] = (_command + ' vrf {vrf}', {**_slots_g90, 'vrf': ('vrfs', 'vrf')})
    if _name in HIGH_VOLUME['nxos']:
        HIGH_VOLUME['nxos'].add(_name + '_vrf')


# G52 independently specified probe contract.
EXPECTED["ios"]['ping'] = ('ping {address} repeat 5 timeout 1', {'address': ('addresses', 'ipv4_address')})
EXPECTED["ios"]['ping_source'] = ('ping {address} source {source} repeat 5 timeout 1', {'address': ('addresses', 'ipv4_address'), 'source': ('interfaces', 'interface')})
EXPECTED["ios"]['ping_vrf'] = ('ping vrf {vrf} {address} repeat 5 timeout 1', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address')})
EXPECTED["ios"]['ping_vrf_source'] = ('ping vrf {vrf} {address} source {source} repeat 5 timeout 1', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address'), 'source': ('interfaces', 'interface')})
EXPECTED["ios"]['ping_ipv6'] = ('ping ipv6 {address} repeat 5 timeout 1', {'address': ('addresses', 'ipv6_address')})
EXPECTED["ios"]['ping_ipv6_source'] = ('ping ipv6 {address} source {source} repeat 5 timeout 1', {'address': ('addresses', 'ipv6_address'), 'source': ('interfaces', 'interface')})
EXPECTED["ios"]['traceroute'] = ('traceroute {address} numeric timeout 1 probe 1 ttl 1 5', {'address': ('addresses', 'ipv4_address')})
EXPECTED["ios"]['traceroute_source'] = ('traceroute {address} source {source} numeric timeout 1 probe 1 ttl 1 5', {'address': ('addresses', 'ipv4_address'), 'source': ('interfaces', 'interface')})
EXPECTED["ios"]['traceroute_vrf'] = ('traceroute vrf {vrf} {address} numeric timeout 1 probe 1 ttl 1 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address')})
EXPECTED["ios"]['traceroute_vrf_source'] = ('traceroute vrf {vrf} {address} source {source} numeric timeout 1 probe 1 ttl 1 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address'), 'source': ('interfaces', 'interface')})

# G70 adds the same bounded command forms on IOS XE and the measured IPv6/VRF forms.
_XE_IPV6_PROBES = {
    "ping_ipv6_vrf": ("ping vrf {vrf} ipv6 {address} repeat 5 timeout 1", ("vrf", "address")),
    "ping_ipv6_vrf_source": ("ping vrf {vrf} ipv6 {address} source {source} repeat 5 timeout 1", ("vrf", "address", "source")),
    "traceroute_ipv6": ("traceroute ipv6 {address} numeric timeout 1 probe 1 ttl 1 5", ("address",)),
    "traceroute_ipv6_source": ("traceroute ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5", ("address", "source")),
    "traceroute_ipv6_vrf": ("traceroute vrf {vrf} ipv6 {address} numeric timeout 1 probe 1 ttl 1 5", ("vrf", "address")),
    "traceroute_ipv6_vrf_source": ("traceroute vrf {vrf} ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5", ("vrf", "address", "source")),
}
_XE_PROBE_SLOTS = {"vrf": ("vrfs", "vrf"), "address": ("addresses", "ipv6_address"),
                   "source": ("interfaces", "interface")}
EXPECTED["ios_xe"].update({name: spec for name, spec in EXPECTED["ios"].items()
                       if name.startswith(("ping", "traceroute"))})
EXPECTED["ios_xe"].update({name: (command, {slot: _XE_PROBE_SLOTS[slot] for slot in names})
                       for name, (command, names) in _XE_IPV6_PROBES.items()})

# G53 independently specified port/STP/EtherChannel/PoE/neighbor contract (IOSvL2-verified syntax).
_G53_PORT = {'interface': ('interfaces', 'cisco_ios_physical_interface')}
EXPECTED["ios"].update({
    'stp_detail': ('show spanning-tree detail', {}),
    'stp_interface_detail': ('show spanning-tree interface {interface} detail', _G53_PORT),
    'stp_mst': ('show spanning-tree mst', {}),
    'etherchannel_detail': ('show etherchannel detail', {}),
    'lacp_internal': ('show lacp internal', {}),
    'etherchannel_load_balance': ('show etherchannel load-balance', {}),
    'power_inline_detail': ('show power inline {interface} detail', _G53_PORT),
    'lldp_neighbor_interface': ('show lldp neighbors {interface} detail', _G53_PORT),
    'cdp_neighbor_interface': ('show cdp neighbors {interface} detail', _G53_PORT),
})
HIGH_VOLUME["ios"].update({'stp_detail', 'stp_mst', 'etherchannel_detail', 'lacp_internal'})

def _slots(query) -> dict[str, tuple[str, str]]:
    return {
        name: (slot.inventory, slot.kind)
        for name, slot in query.slots.items()
    }


EXPECTED["nxos"].update({'ping': ('ping {address} vrf {vrf} count 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address')}), 'ping_source': ('ping {address} vrf {vrf} source {source} count 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address'), 'source': ('addresses', 'ipv4_address')}), 'traceroute': ('traceroute {address} vrf {vrf}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address')}), 'traceroute_source': ('traceroute {address} source {source} vrf {vrf}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv4_address'), 'source': ('addresses', 'ipv4_address')}), 'ping6': ('ping6 {address} vrf {vrf} count 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv6_address')}), 'ping6_source': ('ping6 {address} vrf {vrf} source {source} count 5', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv6_address'), 'source': ('addresses', 'ipv6_address')}), 'traceroute6': ('traceroute6 {address} vrf {vrf}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv6_address')}), 'traceroute6_source': ('traceroute6 {address} source {source} vrf {vrf}', {'vrf': ('vrfs', 'vrf'), 'address': ('addresses', 'ipv6_address'), 'source': ('addresses', 'ipv6_address')})})


EXPECTED["nxos"].update({
    "stp_detail": ("show spanning-tree detail", {}),
    "stp_interface_detail": ("show spanning-tree interface {interface} detail",
                             {"interface": ("interfaces", "cisco_nxos_interface")}),
    "stp_mst": ("show spanning-tree mst", {}),
    "port_channel_database": ("show port-channel database", {}),
    "lacp_interface": ("show lacp interface {interface}",
                       {"interface": ("interfaces", "cisco_nxos_non_subinterface")}),
    "port_channel_load_balance": ("show port-channel load-balance", {}),
    "vpc_member_consistency": ("show vpc consistency-parameters vpc {vpc_id}", {"vpc_id": (None, "vpc_id")}),
    "vpc_interface_consistency": ("show vpc consistency-parameters interface {interface}",
                                  {"interface": ("interfaces", "cisco_nxos_port_channel")}),
    "lldp_neighbor_interface": ("show lldp neighbors interface {interface} detail",
                                {"interface": ("interfaces", "cisco_nxos_interface")}),
    "cdp_neighbor_interface": ("show cdp neighbors interface {interface} detail",
                               {"interface": ("interfaces", "cisco_nxos_interface")}),
})
HIGH_VOLUME["nxos"].update(("stp_detail", "stp_mst", "port_channel_database"))


EXPECTED["nxos"].update({
    "mac_table_address": ("show mac address-table address {mac}", {"mac": (None, "mac_literal")}),
    "mac_table_vlan": ("show mac address-table vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
    "arp_lookup": ("show ip arp {address}", {"address": (None, "ipv4_neighbor")}),
    "arp_lookup_vrf": ("show ip arp {address} vrf {vrf}", {"address": (None, "ipv4_neighbor"), "vrf": ("vrfs", "vrf")}),
    "ipv6_neighbor_lookup": ("show ipv6 neighbor {address}", {"address": (None, "ipv6_neighbor")}),
    "ipv6_neighbor_lookup_vrf": ("show ipv6 neighbor {address} vrf {vrf}", {"address": (None, "ipv6_neighbor"), "vrf": ("vrfs", "vrf")}),
    "ipv4_access_lists": ("show ip access-lists {name}", {"name": (None, "nxos_acl_name")}),
    "ipv6_access_lists": ("show ipv6 access-lists {name}", {"name": (None, "nxos_acl_name")}),
    "mac_access_lists": ("show mac access-lists {name}", {"name": (None, "nxos_acl_name")}),
    "ipv4_access_lists_summary": ("show ip access-lists summary", {}),
    "ipv6_access_lists_summary": ("show ipv6 access-lists summary", {}),
    "mac_access_lists_summary": ("show mac access-lists summary", {}),
    "ip_interface_details": ("show ip interface {interface}", {"interface": ("interfaces", "cisco_nxos_interface")}),
    "dhcp_snooping_status": ("show ip dhcp snooping", {}),
    "dhcp_snooping_statistics": ("show ip dhcp snooping statistics", {}),
    "dhcp_relay_status": ("show ip dhcp relay", {}),
    "dhcp_relay_statistics": ("show ip dhcp relay statistics", {}),
    "arp_inspection_statistics": ("show ip arp inspection statistics", {}),
    "arp_inspection_statistics_vlan": ("show ip arp inspection statistics vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
})
HIGH_VOLUME["nxos"].update({
    "mac_table_vlan", "ipv6_access_lists", "mac_access_lists", "ipv4_access_lists_summary",
    "ipv6_access_lists_summary", "mac_access_lists_summary", "arp_inspection_statistics",
})



_G55_PHYSICAL_PORT = {"interface": ("interfaces", "cisco_ios_physical_interface")}
_G55_INTERFACE = {"interface": ("interfaces", "interface")}
_G55_VRF = {"vrf": ("vrfs", "vrf")}
_G55_IPV4 = {"address": (None, "ipv4_neighbor")}

_IOS_SECURITY_EXPECTED = {
    "mac_table_address": ("show mac address-table address {mac}", {"mac": (None, "mac_literal")}),
    "mac_table_interface": ("show mac address-table interface {interface}", {"interface": ("interfaces", "cisco_ios_switchport")}),
    "mac_table_vlan": ("show mac address-table vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
    "arp_lookup": ("show ip arp {address}", _G55_IPV4),
    "arp_lookup_vrf": ("show ip arp vrf {vrf} {address}", {**_G55_VRF, **_G55_IPV4}),
    "arp_table_vrf": ("show ip arp vrf {vrf}", _G55_VRF),
    "ipv6_neighbors_interface": ("show ipv6 neighbors {interface}", _G55_INTERFACE),
    "ipv6_neighbors_vrf": ("show ipv6 neighbors vrf {vrf}", _G55_VRF),
    "ipv6_neighbors_interface_vrf": ("show ipv6 neighbors vrf {vrf} {interface}", {**_G55_VRF, **_G55_INTERFACE}),
    "ipv4_access_lists": ("show ip access-lists", {}),
    "ipv6_access_lists": ("show ipv6 access-list", {}),
    "dhcp_server_bindings": ("show ip dhcp binding", {}),
    "dhcp_server_binding_address": ("show ip dhcp binding {address}", _G55_IPV4),
    "dhcp_server_pools": ("show ip dhcp pool", {}),
    "dhcp_server_conflicts": ("show ip dhcp conflict", {}),
    "dhcp_server_statistics": ("show ip dhcp server statistics", {}),
    "dhcp_snooping_status": ("show ip dhcp snooping", {}),
    "dhcp_snooping_binding": ("show ip dhcp snooping binding", {}),
    "dhcp_snooping_statistics": ("show ip dhcp snooping statistics", {}),
    "port_security_interface": ("show port-security interface {interface}", _G55_PHYSICAL_PORT),
    "port_security_addresses": ("show port-security address", {}),
    "authentication_sessions_interface": ("show authentication sessions interface {interface} details", _G55_PHYSICAL_PORT),
    "dot1x_interface": ("show dot1x interface {interface} details", _G55_PHYSICAL_PORT),
    "arp_inspection_statistics": ("show ip arp inspection statistics", {}),
    "ip_source_guard": ("show ip verify source", {}),
}
_IOS_SECURITY_HIGH_VOLUME = {
    "arp_table_vrf", "ipv6_neighbors_vrf", "ipv4_access_lists", "ipv6_access_lists",
    "dhcp_server_bindings", "dhcp_server_pools", "dhcp_server_conflicts",
    "dhcp_snooping_status", "dhcp_snooping_binding", "port_security_addresses",
    "authentication_sessions_interface", "dot1x_interface", "arp_inspection_statistics", "ip_source_guard",
}

EXPECTED["ios"].update(_IOS_SECURITY_EXPECTED)
HIGH_VOLUME["ios"].update(_IOS_SECURITY_HIGH_VOLUME)
_G73_PHYSICAL_PORT = {"interface": ("interfaces", "cisco_xe_physical_interface")}
EXPECTED["ios_xe"].update({
    **_IOS_SECURITY_EXPECTED,
    "mac_table_interface": ("show mac address-table interface {interface}", {"interface": ("interfaces", "cisco_xe_switchport")}),
    "port_security_interface": ("show port-security interface {interface}", _G73_PHYSICAL_PORT),
    "authentication_sessions_interface": ("show access-session interface {interface} details", _G73_PHYSICAL_PORT),
    "dot1x_interface": ("show dot1x interface {interface} details", _G73_PHYSICAL_PORT),
})
HIGH_VOLUME["ios_xe"].update(_IOS_SECURITY_HIGH_VOLUME)


# G57 operational reads share syntax across the two router profiles. MLS is Catalyst IOS only.
for _profile in ("ios", "ios_xe"):
    _g57 = {
        "qos_policy": ("show policy-map interface {interface}", {"interface": ("interfaces", "interface")}),
        "nat_translations": ("show ip nat translations", {}),
        "nat_statistics": ("show ip nat statistics", {}),
        "ikev1_sa": ("show crypto isakmp sa", {}),
        "ikev2_sa": ("show crypto ikev2 sa", {}),
        "ipsec_sa": ("show crypto ipsec sa", {}),
    }
    EXPECTED[_profile].update(_g57)
    HIGH_VOLUME[_profile].update(_g57)
EXPECTED["ios"]["qos_queues"] = ("show mls qos interface {interface} statistics",
                                {"interface": ("interfaces", "cisco_ios_physical_interface")})
HIGH_VOLUME["ios"].add("qos_queues")
EXPECTED["ios_xe"]["qos_queues"] = (
    "show platform hardware fed switch active qos queue stats interface {interface}",
    {"interface": ("interfaces", "cisco_xe_physical_interface")},
)
HIGH_VOLUME["ios_xe"].add("qos_queues")


# G71: IOS XE uses the Catalyst interface grammar and an explicit channel-group selector.
_XE_PHYSICAL_PORT = {"interface": ("interfaces", "cisco_xe_physical_interface")}
EXPECTED["ios_xe"].update({
    "stp_detail": ("show spanning-tree detail", {}),
    "stp_interface_detail": ("show spanning-tree interface {interface} detail", _XE_PHYSICAL_PORT),
    "stp_mst": ("show spanning-tree mst", {}),
    "etherchannel_detail": ("show etherchannel {group_id} detail", {"group_id": (None, "etherchannel_group_id")}),
    "lacp_internal": ("show lacp internal", {}),
    "etherchannel_load_balance": ("show etherchannel load-balance", {}),
    "power_inline_detail": ("show power inline {interface} detail", _XE_PHYSICAL_PORT),
    "lldp_neighbor_interface": ("show lldp neighbors {interface} detail", _XE_PHYSICAL_PORT),
    "cdp_neighbor_interface": ("show cdp neighbors {interface} detail", _XE_PHYSICAL_PORT),
})
HIGH_VOLUME["ios_xe"].update({"stp_detail", "stp_mst", "lacp_internal"})


EXPECTED["ios_xe"].update({
    "hsrp_detail": ("show standby", {}),
    "vrrp_detail": ("show vrrp", {}),
    "object_tracking": ("show track", {}),
    "ip_sla_statistics": ("show ip sla statistics", {}),
    "log_history": ("show logging", {
        "begin_date": (None, "log_date"), "begin_time": (None, "log_time"),
        "end_date": (None, "log_date"), "end_time": (None, "log_time"),
        "severity": (None, "log_severity"), "interface": ("interfaces", "cisco_xe_interface"),
    }),
})
HIGH_VOLUME["ios_xe"].update({"hsrp_detail", "vrrp_detail", "object_tracking", "ip_sla_statistics", "log_history"})

EXPECTED["ios"].update({
    "hsrp_detail": ("show standby", {}),
    "vrrp_detail": ("show vrrp", {}),
    "object_tracking": ("show track", {}),
    "ip_sla_statistics": ("show ip sla statistics", {}),
    "log_history": ("show logging", {
        "begin_date": (None, "log_date"), "begin_time": (None, "log_time"),
        "end_date": (None, "log_date"), "end_time": (None, "log_time"),
        "severity": (None, "log_severity"), "interface": ("interfaces", "cisco_ios_interface"),
    }),
})
HIGH_VOLUME["ios"].update({"hsrp_detail", "vrrp_detail", "object_tracking", "ip_sla_statistics", "log_history"})


_NXOS_ETHERNET = {"interface": ("interfaces", "cisco_nxos_ethernet")}
EXPECTED["nxos"].update({
    "qos_queues": ("show queuing interface {interface}", _NXOS_ETHERNET),
    "qos_policy": ("show policy-map interface {interface}", _NXOS_ETHERNET),
    "priority_flow_control": ("show interface priority-flow-control", {}),
    "tcam_utilization": ("show hardware access-list resource utilization", {}),
    "hardware_capacity": ("show hardware capacity", {}),
})
HIGH_VOLUME["nxos"].update({"priority_flow_control", "tcam_utilization", "hardware_capacity"})

EXPECTED["nxos"].update({
    "nve_peers": ("show nve peers", {}),
    "nve_vni": ("show nve vni", {}),
    "nve_interface_detail": ("show nve interface nve1 detail", {}),
    "evpn_bgp_summary": ("show bgp l2vpn evpn summary", {}),
    "evpn_bgp_prefix": ("show bgp l2vpn evpn {prefix}", {"prefix": (None, "ip_literal")}),
    "evpn_mac_ip": ("show l2route evpn mac-ip all", {}),
})
HIGH_VOLUME["nxos"].update({"nve_peers", "nve_vni", "evpn_bgp_summary", "evpn_bgp_prefix", "evpn_mac_ip"})


EXPECTED["nxos"].update({
    "processes_cpu": ("show processes cpu", {}),
    "logging_info": ("show logging info", {}),
    "log_history": ("show logging last {count}", {
        "count": (None, "nxos_log_count"), "begin_date": (None, "log_date"), "begin_time": (None, "log_time"),
        "end_date": (None, "log_date"), "end_time": (None, "log_time"), "severity": (None, "log_severity"),
        "interface": ("interfaces", "cisco_nxos_interface"),
    }),
    "hsrp_detail": ("show hsrp detail", {}),
    "vrrp_detail": ("show vrrp detail", {}),
    "vrrpv3_detail": ("show vrrpv3 detail", {}),
    "object_tracking": ("show track", {}),
})
HIGH_VOLUME["nxos"].update({"processes_cpu", "logging_info", "log_history", "hsrp_detail", "vrrp_detail",
                           "vrrpv3_detail", "object_tracking"})

# G87 Catalyst 9800 operational reads and G89 hardware QFP diagnostics.
EXPECTED["ios_xe"].update({
    "c9800_aps": ("show ap summary", {}),
    "c9800_ap_joins": ("show wireless stats ap join summary", {}),
    "c9800_clients": ("show wireless client summary", {}),
    "c9800_client_detail": ("show wireless client mac-address {mac} detail", {"mac": (None, "mac_literal")}),
    "c9800_client_stats": ("show wireless stats client detail", {}),
    "c9800_radio_24": ("show ap dot11 24ghz summary", {}),
    "c9800_radio_5": ("show ap dot11 5ghz summary", {}),
    "c9800_ap_load": ("show ap summary load-info", {}),
    "c9800_wlans": ("show wlan summary", {}),
    "c9800_ap_tags": ("show ap tag summary", {}),
    "c9800_ap_tag_detail": ("show ap name {ap_name} tag detail", {"ap_name": (None, "c9800_ap_name")}),
    "c9800_policy_profiles": ("show wireless profile policy summary", {}),
    "c9800_client_deletes": ("show wireless stats client delete reasons", {}),
    "c9800_exclusions": ("show wireless exclusionlist", {}),
    "c9800_rogue_aps": ("show wireless wps rogue ap summary", {}),
    "c9800_redundancy": ("show redundancy", {}),
    "c9800_chassis_rmi": ("show chassis rmi", {}),
    "qfp_drops": ("show platform hardware qfp active statistics drop", {}),
    "qfp_utilization": ("show platform hardware qfp active datapath utilization", {}),
})
HIGH_VOLUME["ios_xe"].update({
    "c9800_aps", "c9800_ap_joins", "c9800_clients", "c9800_client_stats", "c9800_radio_24",
    "c9800_radio_5", "c9800_ap_load", "c9800_wlans", "c9800_ap_tags", "c9800_policy_profiles",
    "c9800_client_deletes", "c9800_exclusions", "c9800_rogue_aps", "qfp_drops",
})


def test_exact_commands_slots_and_volume() -> None:
    assert set(CATALOGUES) == set(EXPECTED) == set(HIGH_VOLUME)
    for platform, catalogue in CATALOGUES.items():
        oracle = EXPECTED[platform]
        assert set(catalogue) == set(oracle)
        for name, (command, slots) in oracle.items():
            query = catalogue[name]
            assert query.command == command, (platform, name)
            assert _slots(query) == slots, (platform, name)
            assert query.high_volume is (name in HIGH_VOLUME[platform]), (platform, name)
            assert query.description and query.description.endswith("."), (platform, name)


def test_catalogues_are_explicit_and_do_not_share_queries() -> None:
    assert IOS_QUERIES is not IOS_XE_QUERIES
    assert IOS_QUERIES is not NXOS_QUERIES
    assert IOS_XE_QUERIES is not NXOS_QUERIES
    for name in set(IOS_QUERIES) & set(IOS_XE_QUERIES):
        assert IOS_QUERIES[name] is not IOS_XE_QUERIES[name], name


def _validate_safe_command(command: str) -> None:
    if not isinstance(command, str) or not command.startswith("show "):
        raise ValueError("command must use the exact show prefix")
    if command != command.strip() or "  " in command:
        raise ValueError("command whitespace must be canonical")
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        raise ValueError("command contains a control character")
    if SHELL_METACHARACTERS.intersection(command):
        raise ValueError("command contains a shell metacharacter")
    forbidden_show_family = re.compile(
        r"^show (?:run(?:ning-config)?|start(?:up-config)?|full-configuration|"
        r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|"
        r"log(?:ging|s)?|debug(?:ging)?|support|capture|bash|shell)(?: |$)",
        re.IGNORECASE,
    )
    forbidden_key_chain = re.compile(
        r"^show key chain(?: |$)",
        re.IGNORECASE,
    )
    if forbidden_show_family.match(command) or forbidden_key_chain.match(command):
        raise ValueError("command belongs to a forbidden show family")


def test_commands_are_bounded_show_only_and_shell_safe() -> None:
    for platform, catalogue in CATALOGUES.items():
        for name, query in catalogue.items():
            command = query.command
            if name == "log_messages":  # the one fixed, slotless buffer template; read_policy allows exactly this form
                assert command == {"nxos": "show logging last 200"}.get(platform, "show logging") and not query.slots
                continue
            if platform in {"ios", "ios_xe"} and name == "log_history":
                assert command == "show logging" and query.filter_slots == set(query.slots)
                continue
            if platform == "nxos" and name in {"log_history", "logging_info"}:
                assert command == EXPECTED["nxos"][name][0]
                assert set(query.slots) - query.filter_slots == ({"count"} if name == "log_history" else set())
                continue
            if platform == "nxos" and name == "configuration_sessions":
                assert command == "show configuration session summary" and not query.slots
                continue
            if platform == "nxos" and name in ('ping', 'ping_source', 'traceroute', 'traceroute_source', 'ping6', 'ping6_source', 'traceroute6', 'traceroute6_source'):
                assert command == EXPECTED["nxos"][name][0]
            elif platform in {"ios", "ios_xe"} and name.startswith(("ping", "traceroute")):
                assert query.pty
                assert command.endswith("repeat 5 timeout 1") or command.endswith("numeric timeout 1 probe 1 ttl 1 5")
            else:
                _validate_safe_command(command)
            assert set(re.findall(r"{([a-z_]+)}", command)) == set(query.slots), (
                platform,
                name,
                command,
            )


def test_vendor_interface_rendering_is_canonical_and_exact() -> None:
    accepted = (
        (
            "cisco_ios", "interface_details",
            "Gi1/0/1", "show interfaces GigabitEthernet1/0/1",
        ),
        (
            "cisco_ios", "interface_details",
            "Vl10", "show interfaces vlan 10",
        ),
        (
            "cisco_xe", "interface_details",
            "Twe8/1/2", "show interfaces TwentyFiveGigE8/1/2",
        ),
        (
            "cisco_xe", "interface_errors",
            "Te1/0/24",
            "show interfaces TenGigabitEthernet1/0/24 counters errors",
        ),
        (
            "cisco_nxos", "interface_details",
            "Ethernet101/1/1.100",
            "show interface Ethernet101/1/1.100",
        ),
        (
            "cisco_nxos", "interface_errors",
            "Loopback1023",
            "show interface Loopback1023 counters errors",
        ),
        (
            "cisco_nxos", "interface_errors",
            "Ethernet1/1.100",
            "show interface Ethernet1/1.100 counters errors",
        ),
    )
    for platform, query, value, expected in accepted:
        _, rendered = render_read_query(
            platform,
            query,
            {"interface": value},
            {"interfaces": (value,)},
        )
        assert rendered == expected

    rejected = (
        ("cisco_ios", "interface_details", "status"),
        ("cisco_ios", "interface_details", "description"),
        ("cisco_ios", "interface_details", "counters"),
        ("cisco_ios", "interface_details", "Gi1/0/1-4"),
        ("cisco_ios", "interface_details", "Gi1/0/1,Gi1/0/2"),
        ("cisco_xe", "interface_details", "Gi1/0/1 counters"),
        ("cisco_xe", "interface_errors", "Loopback0"),
        ("cisco_nxos", "interface_details", "quick"),
        ("cisco_nxos", "interface_details", "Ethernet1/1-4"),
        ("cisco_nxos", "interface_transceiver", "Ethernet1/1.100"),
        ("cisco_nxos", "interface_errors", "Ethernet1/1.0"),
    )
    for platform, query, value in rejected:
        try:
            render_read_query(
                platform,
                query,
                {"interface": value},
                {"interfaces": (value,)},
            )
        except ValueError:
            continue
        raise AssertionError(
            f"unsafe Cisco interface was accepted: {platform} {value!r}"
        )

    # G53 r3: on IOS the short and the full name of one enrolled port are the same port (both
    # sides canonicalized by the slot validator); another port and other platforms stay exact.
    assert render_read_query(
        "cisco_ios",
        "interface_details",
        {"interface": "Gi1/0/1"},
        {"interfaces": ("GigabitEthernet1/0/1",)},
    )[1] == "show interfaces GigabitEthernet1/0/1"
    for platform, value, enrolled in (
        ("cisco_ios", "Gi1/0/2", "GigabitEthernet1/0/1"),
        ("cisco_ios", "Gi1/0/1", "Gi1/0/1 "),
        ("cisco_xe", "Gi1/0/1", "GigabitEthernet1/0/1"),
    ):
        try:
            render_read_query(
                platform,
                "interface_details",
                {"interface": value},
                {"interfaces": (enrolled,)},
            )
        except ValueError:
            continue
        raise AssertionError(
            f"canonical equivalence bypassed exact inventory: {platform} {value!r}"
        )


def test_forbidden_command_corpus_is_rejected() -> None:
    forbidden_commands = (
        "show run",
        "show running-config",
        "show start",
        "show startup-config",
        "show conf",
        "show config terminal",
        "show configuration",
        "show full-configuration",
        "show tech",
        "show tech-support",
        "show file bootflash:secret.txt",
        "show key chain",
        "show log",
        "show logging",
        "show debug",
        "show debugging",
        "show support details",
        "show capture session",
        "show bash",
        "show shell",
        "show version | include uptime",
        "show version\nreload",
        "show version\x7f",
    )
    for command in forbidden_commands:
        try:
            _validate_safe_command(command)
        except ValueError:
            continue
        raise AssertionError(f"forbidden command was accepted: {command!r}")


def main() -> int:
    test_exact_commands_slots_and_volume()
    test_catalogues_are_explicit_and_do_not_share_queries()
    test_commands_are_bounded_show_only_and_shell_safe()
    test_vendor_interface_rendering_is_canonical_and_exact()
    test_forbidden_command_corpus_is_rejected()
    print("query_catalog_cisco_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
