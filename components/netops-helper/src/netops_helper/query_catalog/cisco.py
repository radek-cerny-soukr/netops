"""Curated Cisco IOS, IOS-XE, and NX-OS phase-1 diagnostic queries."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from .model import (
    CISCO_IOS_INTERFACE,
    CISCO_IOS_PHYSICAL_INTERFACE,
    CISCO_IOS_SWITCHPORT,
    CISCO_NXOS_ERRORS_INTERFACE,
    CISCO_NXOS_INTERFACE,
    CISCO_NXOS_NON_SUBINTERFACE,
    CISCO_XE_INTERFACE,
    CISCO_XE_PHYSICAL_INTERFACE,
    CISCO_XE_SWITCHPORT,
    IPV4_ADDRESS,
    IPV6_ADDRESS,
    NO_SLOTS,
    Query,
    Slot,
)

VLAN_ID = {"vlan_id": Slot(None, "vlan_id")}


def _campus_queries(physical_interface) -> dict[str, Query]:
    """1.0.7 additions shared by IOS and IOS XE; the slotted ones take the profile's physical-port kind."""
    return {
        "interfaces_counters_errors": Query("show interfaces counters errors", NO_SLOTS, "Show cumulative error and discard counters of every interface (switch images only).", high_volume=True),
        "interfaces_details": Query("show interfaces", NO_SLOTS, "Show operational details and cumulative error counters of every interface.", high_volume=True),
        "route_table": Query("show ip route", NO_SLOTS, "Show the IPv4 routing table.", high_volume=True),
        "ospf_interfaces": Query("show ip ospf interface brief", NO_SLOTS, "Summarize OSPF interfaces, areas, cost and neighbor counts.", high_volume=True),
        "stp_tree": Query("show spanning-tree", NO_SLOTS, "Show spanning-tree state per VLAN with root and port roles.", high_volume=True),
        "stp_root": Query("show spanning-tree root", NO_SLOTS, "Show the spanning-tree root bridge and root port per VLAN.", high_volume=True),
        "stp_inconsistent": Query("show spanning-tree inconsistentports", NO_SLOTS, "Show ports blocked by spanning-tree guards (root, loop, BPDU or type inconsistency).", high_volume=True),
        "stp_vlan": Query("show spanning-tree vlan {vlan_id}", VLAN_ID, "Show spanning-tree state for one VLAN."),
        "err_disabled": Query("show interfaces status err-disabled", NO_SLOTS, "List err-disabled interfaces with the disabling reason.", high_volume=True),
        "errdisable_recovery": Query("show errdisable recovery", NO_SLOTS, "Show which err-disable causes recover automatically and the interfaces waiting for it."),
        "interfaces_description": Query("show interfaces description", NO_SLOTS, "Show interface state with configured descriptions.", high_volume=True),
        "interfaces_trunk": Query("show interfaces trunk", NO_SLOTS, "Show trunk ports with allowed, active and forwarding VLANs.", high_volume=True),
        "interface_switchport": Query("show interfaces {interface} switchport", physical_interface, "Show administrative and operational switchport mode, VLANs and voice VLAN for one enrolled interface."),
        "interface_transceiver": Query("show interfaces {interface} transceiver detail", physical_interface, "Show transceiver diagnostics for one enrolled physical interface."),
        "power_inline": Query("show power inline", NO_SLOTS, "Show PoE budget and per-port power state.", high_volume=True),
        "vtp_status": Query("show vtp status", NO_SLOTS, "Show VTP mode, domain and revision."),
        "vlan_details": Query("show vlan id {vlan_id}", VLAN_ID, "Show one VLAN with its member ports."),
        "ntp_status": Query("show ntp status", NO_SLOTS, "Show NTP synchronization state."),
        "ntp_associations": Query("show ntp associations", NO_SLOTS, "Show NTP peers with stratum, reachability, delay and offset."),
        "stack_members": Query("show switch", NO_SLOTS, "Show stack members with role, priority and state."),
        "stack_ports": Query("show switch stack-ports summary", NO_SLOTS, "Show stack port link state and neighbors."),
        "log_messages": Query("show logging", NO_SLOTS, "Show the logging configuration summary and the in-memory log buffer (bounded by the configured buffer size).", high_volume=True),
    }


# router management / xe management: IOS and IOS XE use the same independent management reads.
IOS_MANAGEMENT_QUERIES = {
    "aaa_servers": Query("show aaa servers", NO_SLOTS, "Show AAA server availability and request counters.", empty_allowed=True),
    "radius_statistics": Query("show radius statistics", NO_SLOTS, "Show RADIUS authentication, accounting, timeout and error counters."),
    "tacacs_statistics": Query("show tacacs", NO_SLOTS, "Show TACACS server state and request counters.", empty_allowed=True),
    "snmp_statistics": Query("show snmp", NO_SLOTS, "Show SNMP agent state and request and notification counters."),
    "snmp_engine_id": Query("show snmp engineID", NO_SLOTS, "Show the local and remote SNMP engine identifiers."),
    "dns_hosts": Query("show hosts", NO_SLOTS, "Show the device DNS resolver settings and host cache.", high_volume=True),
    "users": Query("show users", NO_SLOTS, "Show logged-in administrators and occupied terminal lines.", high_volume=True),
    "ssh_sessions": Query("show ssh", NO_SLOTS, "Show active SSH sessions and their negotiated security.", high_volume=True),
    "lines": Query("show line", NO_SLOTS, "Show terminal and VTY line usage and error counters.", high_volume=True),
}


IOS_QUERIES: dict[str, Query] = {
    **IOS_MANAGEMENT_QUERIES,
    "version": Query("show version", NO_SLOTS, "Show software and platform version details."),
    "clock": Query("show clock", NO_SLOTS, "Show the device clock."),
    "interfaces": Query("show interfaces status", NO_SLOTS, "Summarize interface state and VLAN assignment.", high_volume=True),
    "ip_interfaces": Query("show ip interface brief", NO_SLOTS, "Summarize IPv4 interface state and addresses.", high_volume=True),
    "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS, "Summarize IPv6 interface state and addresses.", high_volume=True),
    "route_summary": Query("show ip route summary", NO_SLOTS, "Summarize the IPv4 routing table."),
    "cpu": Query("show processes cpu", NO_SLOTS, "Show CPU utilization by process.", high_volume=True),
    "memory": Query("show processes memory", NO_SLOTS, "Show memory utilization by process.", high_volume=True),
    "interface_details": Query("show interfaces {interface}", CISCO_IOS_INTERFACE, "Show operational details for one enrolled interface."),
    "route_lookup": Query("show ip route {address}", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show ipv6 route {address}", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "inventory": Query("show inventory", NO_SLOTS, "Show installed hardware inventory."),
    "environment": Query("show env all", NO_SLOTS, "Show environmental sensor status."),
    "interface_errors": Query("show interfaces {interface} counters errors", CISCO_IOS_PHYSICAL_INTERFACE, "Show error counters for one enrolled interface."),
    "arp_table": Query("show ip arp", NO_SLOTS, "Show the IPv4 ARP table. An empty output means no ARP entries.", high_volume=True, empty_allowed=True),
    "ipv6_neighbors": Query("show ipv6 neighbors", NO_SLOTS, "Show the IPv6 neighbor table. An empty output means no IPv6 neighbors.", high_volume=True, empty_allowed=True),
    "mac_table": Query("show mac address-table", NO_SLOTS, "Show the MAC address table. An empty output means no MAC entries.", high_volume=True, empty_allowed=True),
    "vlans": Query("show vlan brief", NO_SLOTS, "Summarize configured VLAN state.", high_volume=True),
    "lag_summary": Query("show etherchannel summary", NO_SLOTS, "Summarize EtherChannel state and membership.", high_volume=True),
    "lacp_neighbors": Query("show lacp neighbor", NO_SLOTS, "Show LACP neighbor state.", high_volume=True),
    "stp_summary": Query("show spanning-tree summary", NO_SLOTS, "Summarize spanning-tree state.", high_volume=True),
    "lldp_neighbors": Query("show lldp neighbors detail", NO_SLOTS, "Show detailed LLDP neighbor information. An empty output means no LLDP neighbors.", high_volume=True, empty_allowed=True),
    "cdp_neighbors": Query("show cdp neighbors detail", NO_SLOTS, "Show detailed CDP neighbor information. An empty output means no CDP neighbors.", high_volume=True, empty_allowed=True),
    "bgp_summary": Query("show ip bgp summary", NO_SLOTS, "Summarize IPv4 BGP peer state.", high_volume=True),
    "ospf_neighbors": Query("show ip ospf neighbor", NO_SLOTS, "Show OSPF neighbor state.", high_volume=True),
    "hsrp_summary": Query("show standby brief", NO_SLOTS, "Summarize HSRP state.", high_volume=True),
    "vrrp_summary": Query("show vrrp brief", NO_SLOTS, "Summarize VRRP state.", high_volume=True),
    **_campus_queries(CISCO_IOS_PHYSICAL_INTERFACE),
    "ntp_associations": Query("show ntp associations", NO_SLOTS,
                              "Show NTP peers with stratum, reachability, delay and offset. An empty output means no NTP peers.",
                              empty_allowed=True),
}


# router routing: IOS router diagnostics. Logical/subinterfaces use the existing enrolled
# interface slot; the campus physical-port validator excludes Lo0 and subinterfaces.
_ROUTING_INTERFACE = {"interface": Slot("interfaces", "interface")}
_VRF = {"vrf": Slot("vrfs", "vrf")}
_DESTINATION = {"address": Slot("addresses", "ipv4_lookup")}
IOS_QUERIES.update({
    "vrfs": Query("show ip vrf", NO_SLOTS, "List IPv4 VRFs and their interfaces. An empty output means the device reports no IPv4 VRFs.", high_volume=True, empty_allowed=True),
    "vrf_route_lookup": Query("show ip route vrf {vrf} {address}", {**_VRF, **_DESTINATION}, "Look up an enrolled IPv4 destination in one enrolled VRF."),
    "vrf_arp_table": Query("show arp vrf {vrf}", _VRF, "Show ARP entries in one enrolled VRF.", high_volume=True),
    "vrf_ip_interfaces": Query("show ip vrf interfaces {vrf}", _VRF, "Show IPv4 interfaces and protocol state in one enrolled VRF.", high_volume=True),
    "bgp_neighbor": Query("show ip bgp neighbors {address}", IPV4_ADDRESS, "Show an enrolled BGP neighbor, session timers and last reset reason.", high_volume=True),
    "bgp_prefix": Query("show ip bgp {address}", _DESTINATION, "Show BGP paths matching an enrolled IPv4 destination."),
    "bgp_advertised_routes": Query("show ip bgp neighbors {address} advertised-routes", IPV4_ADDRESS, "Show routes advertised to an enrolled BGP neighbor.", high_volume=True),
    "bgp_routes": Query("show ip bgp neighbors {address} routes", IPV4_ADDRESS, "Show accepted routes received from an enrolled BGP neighbor.", high_volume=True),
    "ospf_neighbor_detail": Query("show ip ospf neighbor detail", NO_SLOTS, "Show detailed OSPF adjacencies, state changes and retransmissions.", high_volume=True),
    "ospf_interface": Query("show ip ospf interface {interface}", _ROUTING_INTERFACE, "Show OSPF area, timers and neighbor counts on an enrolled interface."),
    "ospf_database": Query("show ip ospf database", NO_SLOTS, "Show the OSPF link-state database.", high_volume=True),
    "ip_protocols": Query("show ip protocols", NO_SLOTS, "Show active routing processes, networks and information sources.", high_volume=True),
    "ipv6_route_table": Query("show ipv6 route", NO_SLOTS, "Show the complete IPv6 routing table. An empty output means the device reports no IPv6 routes.", high_volume=True, empty_allowed=True),
    "ospfv3_neighbors": Query("show ipv6 ospf neighbor", NO_SLOTS, "Show OSPFv3 neighbor state. An empty output means the device reports no OSPFv3 neighbors.", high_volume=True, empty_allowed=True),
    "bgp_ipv6_summary": Query("show bgp ipv6 unicast summary", NO_SLOTS, "Show IPv6 unicast BGP peer state.", high_volume=True),
    "ip_interface_details": Query("show ip interface {interface}", _ROUTING_INTERFACE, "Show all IPv4 addresses, prefixes and operational state of an enrolled interface."),
    "ipv6_interface_details": Query("show ipv6 interface {interface}", _ROUTING_INTERFACE, "Show IPv6 addresses, prefixes, link-local address and ND settings of an enrolled interface."),
    "cef_lookup": Query("show ip cef {address} detail", _DESTINATION, "Show CEF forwarding details for an enrolled IPv4 destination."),
    "vrf_cef_lookup": Query("show ip cef vrf {vrf} {address} detail", {**_VRF, **_DESTINATION}, "Show CEF forwarding details for an enrolled IPv4 destination in one enrolled VRF."),
    "adjacency_details": Query("show adjacency {interface} detail", _ROUTING_INTERFACE, "Show CEF adjacency details for an enrolled interface.", high_volume=True),
    "bfd_neighbors": Query("show bfd neighbors details", NO_SLOTS, "Show BFD sessions, diagnostics and packet timers. An empty output means the device reports no BFD sessions.", high_volume=True, empty_allowed=True),
    "route_maps": Query("show route-map", NO_SLOTS, "Show route-map match and set clauses with policy routing hit counters. An empty output means the device reports no route maps.", high_volume=True, empty_allowed=True),
    "ip_policy": Query("show ip policy", NO_SLOTS, "Show interfaces with policy routing and their route maps.", high_volume=True),
})


# router probes: bounded device-originated probes, only enrolled destinations/source interfaces/VRFs.
_IOS_PROBE_QUERIES = {
    "ping": Query('ping {address} repeat 5 timeout 1', {'address': Slot('addresses', 'ipv4_address')}, 'Send five ICMP echo requests with a one-second timeout per request.', pty=True),
    "ping_source": Query('ping {address} source {source} repeat 5 timeout 1', {'address': Slot('addresses', 'ipv4_address'), 'source': Slot('interfaces', 'interface')}, 'Send five ICMP echo requests with a one-second timeout per request from an enrolled source interface.', pty=True),
    "ping_vrf": Query('ping vrf {vrf} {address} repeat 5 timeout 1', {'vrf': Slot('vrfs', 'vrf'), 'address': Slot('addresses', 'ipv4_address')}, 'Send five ICMP echo requests with a one-second timeout per request in an enrolled VRF.', pty=True),
    "ping_vrf_source": Query('ping vrf {vrf} {address} source {source} repeat 5 timeout 1', {'vrf': Slot('vrfs', 'vrf'), 'address': Slot('addresses', 'ipv4_address'), 'source': Slot('interfaces', 'interface')}, 'Send five ICMP echo requests with a one-second timeout per request in an enrolled VRF from an enrolled source interface.', pty=True),
    "ping_ipv6": Query('ping ipv6 {address} repeat 5 timeout 1', {'address': Slot('addresses', 'ipv6_address')}, 'Send five ICMP echo requests with a one-second timeout per request over IPv6.', pty=True),
    "ping_ipv6_source": Query('ping ipv6 {address} source {source} repeat 5 timeout 1', {'address': Slot('addresses', 'ipv6_address'), 'source': Slot('interfaces', 'interface')}, 'Send five ICMP echo requests with a one-second timeout per request over IPv6 from an enrolled source interface.', pty=True),
    "traceroute": Query('traceroute {address} numeric timeout 1 probe 1 ttl 1 5', {'address': Slot('addresses', 'ipv4_address')}, 'Trace at most five hops numerically with one probe and a one-second timeout per hop.', pty=True),
    "traceroute_source": Query('traceroute {address} source {source} numeric timeout 1 probe 1 ttl 1 5', {'address': Slot('addresses', 'ipv4_address'), 'source': Slot('interfaces', 'interface')}, 'Trace at most five hops numerically with one probe and a one-second timeout per hop from an enrolled source interface.', pty=True),
    "traceroute_vrf": Query('traceroute vrf {vrf} {address} numeric timeout 1 probe 1 ttl 1 5', {'vrf': Slot('vrfs', 'vrf'), 'address': Slot('addresses', 'ipv4_address')}, 'Trace at most five hops numerically with one probe and a one-second timeout per hop in an enrolled VRF.', pty=True),
    "traceroute_vrf_source": Query('traceroute vrf {vrf} {address} source {source} numeric timeout 1 probe 1 ttl 1 5', {'vrf': Slot('vrfs', 'vrf'), 'address': Slot('addresses', 'ipv4_address'), 'source': Slot('interfaces', 'interface')}, 'Trace at most five hops numerically with one probe and a one-second timeout per hop in an enrolled VRF from an enrolled source interface.', pty=True),
}
IOS_QUERIES.update(_IOS_PROBE_QUERIES)


# router ports: port, STP, EtherChannel, PoE and neighbor detail; syntax verified on IOSvL2 15.2 (PoE detail from
# the Cisco IOS command reference: the lab image has no PoE). Interface slots use the physical-port kind.
_IOS_PORT_QUERIES = {
    "stp_detail": Query("show spanning-tree detail", NO_SLOTS, "Show spanning-tree instances with topology change history and per-port BPDU counters.", high_volume=True),
    "stp_interface_detail": Query("show spanning-tree interface {interface} detail", CISCO_IOS_PHYSICAL_INTERFACE, "Show spanning-tree role, state, transitions and BPDU counters of one enrolled port in every instance."),
    "stp_mst": Query("show spanning-tree mst", NO_SLOTS, "Show MST instances with their root, VLAN mapping and port roles.", high_volume=True),
    "etherchannel_detail": Query("show etherchannel detail", NO_SLOTS, "Show EtherChannel groups with member port state, LACP flags and port-channel age.", high_volume=True, empty_allowed=True),
    "lacp_internal": Query("show lacp internal", NO_SLOTS, "Show local LACP member flags, state, keys and port state of every channel group.", high_volume=True, empty_allowed=True),
    "etherchannel_load_balance": Query("show etherchannel load-balance", NO_SLOTS, "Show the EtherChannel load-balancing method and the address fields used per protocol."),
    "power_inline_detail": Query("show power inline {interface} detail", CISCO_IOS_PHYSICAL_INTERFACE, "Show PoE allocation, measured power and power fault counters of one enrolled port."),
    "lldp_neighbor_interface": Query("show lldp neighbors {interface} detail", CISCO_IOS_PHYSICAL_INTERFACE, "Show detailed LLDP neighbors learned on one enrolled port."),
    "cdp_neighbor_interface": Query("show cdp neighbors {interface} detail", CISCO_IOS_PHYSICAL_INTERFACE, "Show detailed CDP neighbors learned on one enrolled port."),
}
IOS_QUERIES.update(_IOS_PORT_QUERIES)


# router security: scoped forwarding lookups and operational security reads on classic IOS.
_G55_MAC = {"mac": Slot(None, "mac_literal")}
_G55_HOST = {"address": Slot(None, "ipv4_neighbor")}
IOS_G55_QUERIES = {
    "mac_table_address": Query("show mac address-table address {mac}", _G55_MAC, "Show forwarding entries for one MAC address."),
    "mac_table_interface": Query("show mac address-table interface {interface}", CISCO_IOS_SWITCHPORT, "Show forwarding entries on one enrolled port."),
    "mac_table_vlan": Query("show mac address-table vlan {vlan_id}", VLAN_ID, "Show forwarding entries in one VLAN."),
    "arp_lookup": Query("show ip arp {address}", _G55_HOST, "Show the default IPv4 ARP entry for one address. An empty output means no entry was reported.", empty_allowed=True),
    "arp_lookup_vrf": Query("show ip arp vrf {vrf} {address}", {**_VRF, **_G55_HOST}, "Show one IPv4 ARP entry in an enrolled VRF. An empty output means no entry was reported.", empty_allowed=True),
    "arp_table_vrf": Query("show ip arp vrf {vrf}", _VRF, "Show the IPv4 ARP cache in an enrolled VRF. An empty output means no entries were reported.", high_volume=True, empty_allowed=True),
    "ipv6_neighbors_interface": Query("show ipv6 neighbors {interface}", _ROUTING_INTERFACE, "Show IPv6 neighbors on one enrolled interface. An empty output means no neighbors were reported.", empty_allowed=True),
    "ipv6_neighbors_vrf": Query("show ipv6 neighbors vrf {vrf}", _VRF, "Show IPv6 neighbors in one enrolled VRF. An empty output means no neighbors were reported.", high_volume=True, empty_allowed=True),
    "ipv6_neighbors_interface_vrf": Query("show ipv6 neighbors vrf {vrf} {interface}", {**_VRF, **_ROUTING_INTERFACE}, "Show IPv6 neighbors on one enrolled interface in an enrolled VRF. An empty output means no neighbors were reported.", empty_allowed=True),
    "ipv4_access_lists": Query("show ip access-lists", NO_SLOTS, "Show IPv4 ACL rules and reported hit counters. An empty output means no lists were reported.", high_volume=True, empty_allowed=True),
    "ipv6_access_lists": Query("show ipv6 access-list", NO_SLOTS, "Show IPv6 ACL rules and reported hit counters. An empty output means no lists were reported.", high_volume=True, empty_allowed=True),
    "dhcp_server_bindings": Query("show ip dhcp binding", NO_SLOTS, "Show local DHCP server leases and expiration times.", high_volume=True),
    "dhcp_server_binding_address": Query("show ip dhcp binding {address}", _G55_HOST, "Look up a local DHCP server lease by IPv4 address."),
    "dhcp_server_pools": Query("show ip dhcp pool", NO_SLOTS, "Show DHCP pool capacity, leased addresses and excluded addresses. An empty output means no pools were reported.", high_volume=True, empty_allowed=True),
    "dhcp_server_conflicts": Query("show ip dhcp conflict", NO_SLOTS, "Show IPv4 address conflicts detected by the local DHCP server.", high_volume=True),
    "dhcp_server_statistics": Query("show ip dhcp server statistics", NO_SLOTS, "Show DHCP server counters for bindings and received and sent messages."),
    "dhcp_snooping_status": Query("show ip dhcp snooping", NO_SLOTS, "Show DHCP snooping operational state, VLANs and trusted ports.", high_volume=True),
    "dhcp_snooping_binding": Query("show ip dhcp snooping binding", NO_SLOTS, "Show the DHCP snooping bindings learned on this switch.", high_volume=True),
    "dhcp_snooping_statistics": Query("show ip dhcp snooping statistics", NO_SLOTS, "Show forwarded and dropped DHCP snooping packets."),
    "port_security_interface": Query("show port-security interface {interface}", CISCO_IOS_PHYSICAL_INTERFACE, "Show port-security status and violations on one enrolled port."),
    "port_security_addresses": Query("show port-security address", NO_SLOTS, "Show the secure MAC address table.", high_volume=True),
    "authentication_sessions_interface": Query("show authentication sessions interface {interface} details", CISCO_IOS_PHYSICAL_INTERFACE, "Show detailed active 802.1X and MAB sessions on one enrolled port.", high_volume=True),
    "dot1x_interface": Query("show dot1x interface {interface} details", CISCO_IOS_PHYSICAL_INTERFACE, "Show 802.1X state on one enrolled port. An empty output means no 802.1X state was reported.", high_volume=True, empty_allowed=True),
    "arp_inspection_statistics": Query("show ip arp inspection statistics", NO_SLOTS, "Show per-VLAN Dynamic ARP Inspection forwarding, drops and validation counters.", high_volume=True),
    "ip_source_guard": Query("show ip verify source", NO_SLOTS, "Show IP Source Guard filter modes and bindings.", high_volume=True),
}
IOS_QUERIES.update(IOS_G55_QUERIES)


IOS_XE_QUERIES: dict[str, Query] = {
    **{name: replace(query) for name, query in IOS_MANAGEMENT_QUERIES.items()},
    "version": Query("show version", NO_SLOTS, "Show software and platform version details."),
    "clock": Query("show clock", NO_SLOTS, "Show the device clock."),
    "interfaces": Query("show interfaces status", NO_SLOTS, "Summarize interface state and VLAN assignment.", high_volume=True),
    "ip_interfaces": Query("show ip interface brief", NO_SLOTS, "Summarize IPv4 interface state and addresses.", high_volume=True),
    "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS, "Summarize IPv6 interface state and addresses.", high_volume=True),
    "route_summary": Query("show ip route summary", NO_SLOTS, "Summarize the IPv4 routing table."),
    "cpu": Query("show processes cpu", NO_SLOTS, "Show CPU utilization by process.", high_volume=True),
    "memory": Query("show processes memory", NO_SLOTS, "Show memory utilization by process.", high_volume=True),
    "interface_details": Query("show interfaces {interface}", CISCO_XE_INTERFACE, "Show operational details for one enrolled interface."),
    "route_lookup": Query("show ip route {address}", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show ipv6 route {address}", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "inventory": Query("show inventory", NO_SLOTS, "Show installed hardware inventory."),
    "environment": Query("show environment all", NO_SLOTS, "Show environmental sensor status."),
    "interface_errors": Query("show interfaces {interface} counters errors", CISCO_XE_PHYSICAL_INTERFACE, "Show error counters for one enrolled interface."),
    "arp_table": Query("show ip arp", NO_SLOTS, "Show the IPv4 ARP table. An empty output means no ARP entries.", high_volume=True, empty_allowed=True),
    "ipv6_neighbors": Query("show ipv6 neighbors", NO_SLOTS, "Show the IPv6 neighbor table. An empty output means no IPv6 neighbors.", high_volume=True, empty_allowed=True),
    "mac_table": Query("show mac address-table", NO_SLOTS, "Show the MAC address table. An empty output means no MAC entries.", high_volume=True, empty_allowed=True),
    "vlans": Query("show vlan brief", NO_SLOTS, "Summarize configured VLAN state.", high_volume=True),
    "lag_summary": Query("show etherchannel summary", NO_SLOTS, "Summarize EtherChannel state and membership.", high_volume=True),
    "lacp_neighbors": Query("show lacp neighbor", NO_SLOTS, "Show LACP neighbor state; empty output means no neighbors were reported.", high_volume=True, empty_allowed=True),
    "stp_summary": Query("show spanning-tree summary", NO_SLOTS, "Summarize spanning-tree state.", high_volume=True),
    "lldp_neighbors": Query("show lldp neighbors detail", NO_SLOTS, "Show detailed LLDP neighbor information. An empty output means no LLDP neighbors.", high_volume=True, empty_allowed=True),
    "cdp_neighbors": Query("show cdp neighbors detail", NO_SLOTS, "Show detailed CDP neighbor information. An empty output means no CDP neighbors.", high_volume=True, empty_allowed=True),
    "bgp_summary": Query("show ip bgp summary", NO_SLOTS, "Summarize IPv4 BGP peer state.", high_volume=True),
    "ospf_neighbors": Query("show ip ospf neighbor", NO_SLOTS, "Show OSPF neighbor state.", high_volume=True),
    "hsrp_summary": Query("show standby brief", NO_SLOTS, "Summarize HSRP state; empty output means no HSRP groups were reported.", high_volume=True, empty_allowed=True),
    "vrrp_summary": Query("show vrrp brief", NO_SLOTS, "Summarize VRRP state.", high_volume=True),
    **_campus_queries(CISCO_XE_PHYSICAL_INTERFACE),
    "stp_root": Query("show spanning-tree root", NO_SLOTS, "Show the root bridge per VLAN; empty output means no spanning-tree roots were reported.", high_volume=True, empty_allowed=True),
    "ntp_associations": Query("show ntp associations", NO_SLOTS, "Show NTP peers and their reachability; empty output means no associations were reported.", empty_allowed=True),
    "platform_resources": Query("show platform resources", NO_SLOTS, "Show control-plane CPU, memory and resource state."),
}

XE_LOG_HISTORY = "log_history"
XE_LOG_COMMAND = "show logging"
XE_LOG_SLOTS = {
    "begin_date": Slot(None, "log_date"), "begin_time": Slot(None, "log_time"),
    "end_date": Slot(None, "log_date"), "end_time": Slot(None, "log_time"),
    "severity": Slot(None, "log_severity"), **CISCO_XE_INTERFACE,
}


def xe_log_window(parameters):
    start, end = (datetime.fromisoformat(f"{parameters[prefix + '_date']}T{parameters[prefix + '_time']}")
                  for prefix in ("begin", "end"))
    if not timedelta(0) < end - start <= timedelta(days=7):
        raise ValueError("Cisco IOS log window must be positive and at most seven days")
    return start, end


IOS_XE_HEALTH_READS = {
    XE_LOG_HISTORY: Query(
        XE_LOG_COMMAND, XE_LOG_SLOTS,
        "Filter the IOS XE log buffer by its printed timestamps (start-inclusive, end-exclusive), "
        "optional severity threshold and enrolled interface. Requires the clock query for the date.",
        high_volume=True, empty_allowed=True, optional_slots=frozenset({"severity", "interface"}),
        filter_slots=frozenset(XE_LOG_SLOTS),
    ),
    "hsrp_detail": Query("show standby", NO_SLOTS, "Show HSRP groups, timers, state changes and tracked objects.",
                         high_volume=True, empty_allowed=True),
    "vrrp_detail": Query("show vrrp", NO_SLOTS, "Show VRRP groups, timers, transitions and tracked objects.",
                         high_volume=True, empty_allowed=True),
    "object_tracking": Query("show track", NO_SLOTS, "Show tracked objects, state changes and their consumers.",
                             high_volume=True, empty_allowed=True),
    "ip_sla_statistics": Query("show ip sla statistics", NO_SLOTS, "Show IP SLA operation results and counters.",
                               high_volume=True),
}
IOS_XE_QUERIES.update(IOS_XE_HEALTH_READS)

IOS_G54_QUERIES = {
    **{name: replace(query) for name, query in IOS_XE_HEALTH_READS.items() if name != XE_LOG_HISTORY},
    XE_LOG_HISTORY: replace(
        IOS_XE_HEALTH_READS[XE_LOG_HISTORY],
        description=IOS_XE_HEALTH_READS[XE_LOG_HISTORY].description.replace("IOS XE", "IOS"),
        slots={**XE_LOG_SLOTS, **CISCO_IOS_INTERFACE},
    ),
}
IOS_QUERIES.update(IOS_G54_QUERIES)


# xe routing: verified read-only IOS XE routing diagnostics.
IOS_XE_QUERIES.update({
    "vrfs": Query("show ip vrf", NO_SLOTS, "List IPv4 VRFs and their interfaces.", high_volume=True, empty_allowed=True),
    "vrf_route_lookup": Query("show ip route vrf {vrf} {address}", {**_VRF, **_DESTINATION}, "Look up an enrolled IPv4 destination in one enrolled VRF."),
    "vrf_arp_table": Query("show arp vrf {vrf}", _VRF, "Show ARP entries in one enrolled VRF.", high_volume=True, empty_allowed=True),
    "vrf_ip_interfaces": Query("show ip vrf interfaces {vrf}", _VRF, "Show IPv4 interfaces and protocol state in one enrolled VRF.", high_volume=True),
    "bgp_neighbor": Query("show ip bgp neighbors {address}", IPV4_ADDRESS, "Show an enrolled BGP neighbor, session timers and last reset reason.", high_volume=True),
    "bgp_prefix": Query("show ip bgp {address}", _DESTINATION, "Show BGP paths matching an enrolled IPv4 destination."),
    "bgp_advertised_routes": Query("show ip bgp neighbors {address} advertised-routes", IPV4_ADDRESS, "Show routes advertised to an enrolled BGP neighbor.", high_volume=True),
    "bgp_routes": Query("show ip bgp neighbors {address} routes", IPV4_ADDRESS, "Show accepted routes received from an enrolled BGP neighbor.", high_volume=True),
    "ospf_neighbor_detail": Query("show ip ospf neighbor detail", NO_SLOTS, "Show detailed OSPF adjacencies, state changes and retransmissions.", high_volume=True),
    "ospf_interface": Query("show ip ospf interface {interface}", _ROUTING_INTERFACE, "Show OSPF area, timers and neighbor counts on an enrolled interface."),
    "ospf_database": Query("show ip ospf database", NO_SLOTS, "Show the OSPF link-state database.", high_volume=True),
    "ip_protocols": Query("show ip protocols", NO_SLOTS, "Show active routing processes, networks and information sources.", high_volume=True),
    "ipv6_route_table": Query("show ipv6 route", NO_SLOTS, "Show the complete IPv6 routing table.", high_volume=True),
    "ospfv3_neighbors": Query("show ipv6 ospf neighbor", NO_SLOTS, "Show OSPFv3 neighbor state.", high_volume=True, empty_allowed=True),
    "bgp_ipv6_summary": Query("show bgp ipv6 unicast summary", NO_SLOTS, "Show IPv6 unicast BGP peer state.", high_volume=True),
    "ip_interface_details": Query("show ip interface {interface}", _ROUTING_INTERFACE, "Show all IPv4 addresses, prefixes and operational state of an enrolled interface."),
    "ipv6_interface_details": Query("show ipv6 interface {interface}", _ROUTING_INTERFACE, "Show IPv6 addresses, prefixes, link-local address and ND settings of an enrolled interface.", empty_allowed=True),
    "cef_lookup": Query("show ip cef {address} detail", _DESTINATION, "Show CEF forwarding details for an enrolled IPv4 destination."),
    "vrf_cef_lookup": Query("show ip cef vrf {vrf} {address} detail", {**_VRF, **_DESTINATION}, "Show CEF forwarding details for an enrolled IPv4 destination in one enrolled VRF."),
    "adjacency_details": Query("show adjacency {interface} detail", _ROUTING_INTERFACE, "Show CEF adjacency details for an enrolled interface.", high_volume=True),
    "bfd_neighbors": Query("show bfd neighbors details", NO_SLOTS, "Show BFD sessions, diagnostics and packet timers.", high_volume=True, empty_allowed=True),
    "route_maps": Query("show route-map", NO_SLOTS, "Show route-map match and set clauses with policy routing hit counters.", high_volume=True, empty_allowed=True),
    "ip_policy": Query("show ip policy", NO_SLOTS, "Show interfaces with policy routing and their route maps.", high_volume=True),
})

# xe probes: IOS XE also accepts bounded IPv6 probes inside a VRF and bounded IPv6 traceroute.
_PROBE_SOURCE = {"source": Slot("interfaces", "interface")}
IOS_XE_PROBE_QUERIES = {
    **{name: replace(query) for name, query in _IOS_PROBE_QUERIES.items()},
    "ping_ipv6_vrf": Query("ping vrf {vrf} ipv6 {address} repeat 5 timeout 1", {**_VRF, **IPV6_ADDRESS}, "Send five IPv6 ICMP echo requests in an enrolled VRF with a one-second timeout per request.", pty=True),
    "ping_ipv6_vrf_source": Query("ping vrf {vrf} ipv6 {address} source {source} repeat 5 timeout 1", {**_VRF, **IPV6_ADDRESS, **_PROBE_SOURCE}, "Send five IPv6 ICMP echo requests in an enrolled VRF from an enrolled source interface with a one-second timeout per request.", pty=True),
    "traceroute_ipv6": Query("traceroute ipv6 {address} numeric timeout 1 probe 1 ttl 1 5", IPV6_ADDRESS, "Trace at most five IPv6 hops numerically with one probe and a one-second timeout per hop.", pty=True),
    "traceroute_ipv6_source": Query("traceroute ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5", {**IPV6_ADDRESS, **_PROBE_SOURCE}, "Trace at most five IPv6 hops numerically from an enrolled source interface with one probe and a one-second timeout per hop.", pty=True),
    "traceroute_ipv6_vrf": Query("traceroute vrf {vrf} ipv6 {address} numeric timeout 1 probe 1 ttl 1 5", {**_VRF, **IPV6_ADDRESS}, "Trace at most five IPv6 hops numerically in an enrolled VRF with one probe and a one-second timeout per hop.", pty=True),
    "traceroute_ipv6_vrf_source": Query("traceroute vrf {vrf} ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5", {**_VRF, **IPV6_ADDRESS, **_PROBE_SOURCE}, "Trace at most five IPv6 hops numerically in an enrolled VRF from an enrolled source interface with one probe and a one-second timeout per hop.", pty=True),
}
IOS_XE_QUERIES.update(IOS_XE_PROBE_QUERIES)

# router diagnostics: operational QoS, NAT, and VPN. Catalyst MLS counters are a separate IOS read.
IOS_G57_SHARED = {
    "qos_policy": Query("show policy-map interface {interface}", _ROUTING_INTERFACE,
                        "Show per-class QoS traffic, queue depth and drops on one enrolled interface. An empty output means no attached policy.",
                        high_volume=True, empty_allowed=True),
    "nat_translations": Query("show ip nat translations", NO_SLOTS,
                               "List active NAT translations and their inside and outside endpoints. An empty output means no active translations.",
                               high_volume=True, empty_allowed=True),
    "nat_statistics": Query("show ip nat statistics", NO_SLOTS,
                             "Show NAT activity, translation counts and address-pool usage and misses. An empty output means the device reports no NAT statistics.",
                             high_volume=True, empty_allowed=True),
    "ikev1_sa": Query("show crypto isakmp sa", NO_SLOTS, "Show IKEv1 security associations and states.",
                      high_volume=True),
    "ikev2_sa": Query("show crypto ikev2 sa", NO_SLOTS, "Show IKEv2 security associations and states. An empty output means no IKEv2 associations.",
                      high_volume=True, empty_allowed=True),
    "ipsec_sa": Query("show crypto ipsec sa", NO_SLOTS, "Show IPsec selectors, packet counters and installed SAs.",
                      high_volume=True),
}
IOS_G57_QUERIES = {
    **IOS_G57_SHARED,
    "qos_queues": Query("show mls qos interface {interface} statistics", CISCO_IOS_PHYSICAL_INTERFACE,
                        "Show egress queue and policer counters on one enrolled port on supported Catalyst switches.",
                        high_volume=True),
}
IOS_QUERIES.update(IOS_G57_QUERIES)
IOS_XE_QUERIES.update({name: replace(query) for name, query in IOS_G57_SHARED.items()})
# xe diagnostics: Catalyst IOS XE reports hardware queue statistics through FED.
IOS_XE_QUERIES["qos_queues"] = Query(
    "show platform hardware fed switch active qos queue stats interface {interface}",
    CISCO_XE_PHYSICAL_INTERFACE,
    "Show hardware egress queue buffer counts and byte counters on one enrolled port on supported Catalyst IOS XE switches.",
    high_volume=True,
)

# xe ports: IOS XE shares the IOS show commands with XE-specific physical ports and a scoped channel group.
IOS_XE_PORT_QUERIES = {
    name: replace(query, slots=CISCO_XE_PHYSICAL_INTERFACE if query.slots else NO_SLOTS)
    for name, query in _IOS_PORT_QUERIES.items()
}
IOS_XE_PORT_QUERIES["etherchannel_detail"] = Query(
    "show etherchannel {group_id} detail", {"group_id": Slot(None, "etherchannel_group_id")},
    "Show detail for one EtherChannel group (numeric group ID 1–128). An empty output means no such group was reported.",
    empty_allowed=True,
)
IOS_XE_QUERIES.update(IOS_XE_PORT_QUERIES)

# xe security shares the IOS forwarding and security commands except for IOS XE access sessions.
IOS_XE_G73_QUERIES = {
    **{name: replace(query) for name, query in IOS_G55_QUERIES.items()},
    "mac_table_interface": replace(IOS_G55_QUERIES["mac_table_interface"], slots=CISCO_XE_SWITCHPORT),
    "port_security_interface": replace(IOS_G55_QUERIES["port_security_interface"], slots=CISCO_XE_PHYSICAL_INTERFACE),
    "authentication_sessions_interface": replace(
        IOS_G55_QUERIES["authentication_sessions_interface"],
        command="show access-session interface {interface} details",
        slots=CISCO_XE_PHYSICAL_INTERFACE,
    ),
    "dot1x_interface": replace(IOS_G55_QUERIES["dot1x_interface"], slots=CISCO_XE_PHYSICAL_INTERFACE),
    "ip_source_guard": replace(IOS_G55_QUERIES["ip_source_guard"], empty_allowed=True),
}
IOS_XE_QUERIES.update(IOS_XE_G73_QUERIES)

NXOS_G95_QUERIES = frozenset({
    "dns_hosts", "snmp_statistics", "snmp_engine_id", "aaa_authentication",
    "radius_statistics", "tacacs_statistics", "users", "ssh_server", "configuration_sessions",
})


NXOS_QUERIES: dict[str, Query] = {
    # nxos management: independently enrolled management diagnostics.
    "dns_hosts": Query("show hosts", NO_SLOTS, "Show the switch DNS resolver settings and host cache.", high_volume=True),
    "snmp_statistics": Query("show snmp", NO_SLOTS, "Show SNMP agent request and notification counters with credential sections redacted."),
    "snmp_engine_id": Query("show snmp engineID", NO_SLOTS, "Show the local SNMP engine identifier."),
    "aaa_authentication": Query("show aaa authentication", NO_SLOTS, "Show AAA authentication method lists."),
    "radius_statistics": Query("show radius-server statistics {address}", IPV4_ADDRESS, "Show RADIUS authentication, accounting, timeout and error counters."),
    "tacacs_statistics": Query("show tacacs-server statistics {address}", IPV4_ADDRESS, "Show TACACS authentication, authorization and accounting counters."),
    "users": Query("show users", NO_SLOTS, "Show logged-in administrators.", high_volume=True),
    "ssh_server": Query("show ssh server", NO_SLOTS, "Show whether the SSH server is enabled.", high_volume=True),
    "configuration_sessions": Query("show configuration session summary", NO_SLOTS, "Show open configuration sessions without configuration contents.", high_volume=True),
    "version": Query("show version", NO_SLOTS, "Show software and platform version details."),
    "clock": Query("show clock", NO_SLOTS, "Show the device clock."),
    "inventory": Query("show inventory", NO_SLOTS, "Show installed hardware inventory."),
    "environment": Query("show environment", NO_SLOTS, "Show environmental sensor status."),
    "cpu": Query("show processes cpu", NO_SLOTS, "Show CPU utilization by process.", high_volume=True),
    "memory": Query("show processes memory", NO_SLOTS, "Show memory utilization by process.", high_volume=True),
    "interfaces": Query("show interface status", NO_SLOTS, "Summarize interface state and VLAN assignment.", high_volume=True),
    "ip_interfaces": Query("show ip interface brief", NO_SLOTS, "Summarize IPv4 interface state and addresses.", high_volume=True),
    "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS, "Summarize IPv6 interface state and addresses.", high_volume=True),
    "interface_details": Query("show interface {interface}", CISCO_NXOS_INTERFACE, "Show operational details for one enrolled interface."),
    "interface_errors": Query("show interface {interface} counters errors", CISCO_NXOS_ERRORS_INTERFACE, "Show error counters for one enrolled interface."),
    "vlans": Query("show vlan", NO_SLOTS, "Show VLAN state.", high_volume=True),
    "mac_table": Query("show mac address-table", NO_SLOTS, "Show the MAC address table.", high_volume=True),
    "arp_table": Query("show ip arp", NO_SLOTS, "Show the IPv4 ARP table.", high_volume=True),
    "ipv6_neighbors": Query("show ipv6 neighbor", NO_SLOTS, "Show the IPv6 neighbor table.", high_volume=True),
    "lag_summary": Query("show port-channel summary", NO_SLOTS, "Summarize port-channel state and membership.", high_volume=True),
    "lacp_neighbors": Query("show lacp neighbor", NO_SLOTS, "Show LACP neighbor state.", high_volume=True),
    "stp_summary": Query("show spanning-tree summary", NO_SLOTS, "Summarize spanning-tree state.", high_volume=True),
    "lldp_neighbors": Query("show lldp neighbors detail", NO_SLOTS, "Show detailed LLDP neighbor information.", high_volume=True),
    "cdp_neighbors": Query("show cdp neighbors detail", NO_SLOTS, "Show detailed CDP neighbor information.", high_volume=True),
    "route_summary": Query("show ip route summary", NO_SLOTS, "Summarize the IPv4 routing table."),
    "route_lookup": Query("show ip route {address}", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show ipv6 route {address}", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "bgp_sessions": Query("show bgp sessions", NO_SLOTS, "Show BGP session state.", high_volume=True),
    "ospf_neighbors": Query("show ip ospf neighbors", NO_SLOTS, "Show OSPF neighbor state.", high_volume=True),
    "hsrp_summary": Query("show hsrp summary", NO_SLOTS, "Summarize HSRP state.", high_volume=True),
    "vrrp_summary": Query("show vrrp summary", NO_SLOTS, "Summarize VRRP state.", high_volume=True),
    "vpc_status": Query("show vpc brief", NO_SLOTS, "Summarize virtual port-channel state.", high_volume=True),
    "vpc_peer_keepalive": Query("show vpc peer-keepalive", NO_SLOTS, "Show virtual port-channel peer-keepalive status."),
    "vpc_role": Query("show vpc role", NO_SLOTS, "Show the virtual port-channel role."),
    # 1.0.7: routes, OSPF/BGP tables, spanning tree, err-disable, trunks, switchports, NTP, resources, bounded log
    "route_table": Query("show ip route", NO_SLOTS, "Show the IPv4 routing table of the default VRF.", high_volume=True),
    "ospf_interfaces": Query("show ip ospf interface brief", NO_SLOTS, "Summarize OSPF interfaces, areas, cost, state and neighbor counts.", high_volume=True),
    "bgp_summary": Query("show bgp ipv4 unicast summary", NO_SLOTS, "Summarize IPv4 unicast BGP peer state of the default VRF.", high_volume=True),
    "stp_tree": Query("show spanning-tree", NO_SLOTS, "Show spanning-tree state per VLAN with root and port roles.", high_volume=True),
    "stp_root": Query("show spanning-tree root", NO_SLOTS, "Show the spanning-tree root bridge and root port per VLAN.", high_volume=True),
    "stp_blocked": Query("show spanning-tree blockedports", NO_SLOTS, "List the ports spanning-tree blocks per VLAN."),
    "stp_inconsistent": Query("show spanning-tree inconsistentports", NO_SLOTS, "Show ports blocked by spanning-tree guards (root, loop, BPDU or type inconsistency)."),
    "stp_vlan": Query("show spanning-tree vlan {vlan_id}", VLAN_ID, "Show spanning-tree state for one VLAN."),
    "err_disabled": Query("show interface status err-disabled", NO_SLOTS, "List err-disabled interfaces with the disabling reason.", high_volume=True),
    "errdisable_recovery": Query("show errdisable recovery", NO_SLOTS, "Show which err-disable causes recover automatically and the interfaces waiting for it."),
    "interfaces_description": Query("show interface description", NO_SLOTS, "Show interface state with configured descriptions.", high_volume=True),
    "interfaces_trunk": Query("show interface trunk", NO_SLOTS, "Show trunk ports with allowed, err-disabled and forwarding VLANs.", high_volume=True),
    "interfaces_counters_errors": Query("show interface counters errors", NO_SLOTS, "Show error counters of every interface.", high_volume=True),
    "interface_switchport": Query("show interface {interface} switchport", CISCO_NXOS_INTERFACE, "Show administrative and operational switchport mode and VLANs for one enrolled interface."),
    "interface_transceiver": Query("show interface {interface} transceiver details", CISCO_NXOS_NON_SUBINTERFACE, "Show transceiver diagnostics for one enrolled physical interface."),
    "vlan_details": Query("show vlan id {vlan_id}", VLAN_ID, "Show one VLAN with its member ports."),
    "ntp_status": Query("show ntp status", NO_SLOTS, "Show NTP distribution state."),
    "ntp_associations": Query("show ntp peer-status", NO_SLOTS, "Show NTP peers with stratum, reachability, delay and offset."),
    "system_resources": Query("show system resources", NO_SLOTS, "Show load, CPU and memory use of the supervisor."),
    "reset_reason": Query("show system reset-reason", NO_SLOTS, "Show why each module last reset."),
    "modules": Query("show module", NO_SLOTS, "Show modules with type, model, status and serial numbers."),
    "license_usage": Query("show license usage", NO_SLOTS, "Show license usage per feature."),
    "redundancy_status": Query("show redundancy status", NO_SLOTS, "Show supervisor redundancy state."),
    "features": Query("show feature", NO_SLOTS, "Show which features are enabled."),
    "vrfs": Query("show vrf", NO_SLOTS, "List the VRFs with their state."),
    "bfd_neighbors": Query("show bfd neighbors", NO_SLOTS, "Show BFD sessions."),
    "vpc_consistency": Query("show vpc consistency-parameters global", NO_SLOTS, "Show the global virtual port-channel consistency parameters."),
    "vpc_orphan_ports": Query("show vpc orphan-ports", NO_SLOTS, "Show the ports that are not part of a virtual port-channel."),
    "dhcp_snooping_binding": Query("show ip dhcp snooping binding", NO_SLOTS, "Show the DHCP snooping bindings.", high_volume=True),
    "access_lists": Query("show ip access-lists", NO_SLOTS, "Show IPv4 access lists with match counters.", high_volume=True),
    "log_messages": Query("show logging last 200", NO_SLOTS, "Show the newest 200 lines of the logfile; empty output means the logfile contains no lines.", high_volume=True, empty_allowed=True),
}

NXOS_LOG_HISTORY = "log_history"
_NXOS_LOG_FILTERS = {
    "begin_date": Slot(None, "log_date"), "begin_time": Slot(None, "log_time"),
    "end_date": Slot(None, "log_date"), "end_time": Slot(None, "log_time"),
    "severity": Slot(None, "log_severity"), **CISCO_NXOS_INTERFACE,
}
NXOS_G93_QUERIES = {
    "processes_cpu": Query("show processes cpu", NO_SLOTS, "Show process CPU and five-second, one-minute and five-minute CPU utilization.", high_volume=True),
    NXOS_LOG_HISTORY: Query(
        "show logging last {count}", {"count": Slot(None, "nxos_log_count"), **_NXOS_LOG_FILTERS},
        "Read 1 to 1000 lines of the local logfile with an optional start-inclusive, end-exclusive device-local interval, severity threshold or enrolled interface; empty output means no records matched within the returned capture.",
        high_volume=True, empty_allowed=True, optional_slots=frozenset(_NXOS_LOG_FILTERS),
        filter_slots=frozenset(_NXOS_LOG_FILTERS),
    ),
    "logging_info": Query("show logging info", NO_SLOTS, "Show local logging settings and configured syslog destinations.", high_volume=True),
    "hsrp_detail": Query("show hsrp detail", NO_SLOTS, "Show HSRP state, timers, transitions and tracked objects; empty output means no HSRP groups were reported.", high_volume=True, empty_allowed=True),
    "vrrp_detail": Query("show vrrp detail", NO_SLOTS, "Show VRRPv2 state, advertisement timers and tracked objects; empty output means no VRRPv2 groups were reported.", high_volume=True, empty_allowed=True),
    "vrrpv3_detail": Query("show vrrpv3 detail", NO_SLOTS, "Show VRRPv3 state, timers, transitions and tracked objects; empty output means no VRRPv3 groups were reported.", high_volume=True, empty_allowed=True),
    "object_tracking": Query("show track", NO_SLOTS, "Show tracked objects, their reported state and consumers; empty output means no tracked objects were reported.", high_volume=True, empty_allowed=True),
}
NXOS_QUERIES.update(NXOS_G93_QUERIES)
NXOS_QUERIES["ntp_associations"] = Query(
    "show ntp peer-status", NO_SLOTS, "Show NTP peer selection, stratum, reachability and delay; empty output means no peer state was reported.", empty_allowed=True,
)


def nxos_log_window(parameters):
    names = ("begin_date", "begin_time", "end_date", "end_time")
    if not any(name in parameters for name in names):
        return None
    if not all(name in parameters for name in names):
        raise ValueError("Supply both NX-OS log dates and times for an interval")
    start, end = (datetime.fromisoformat(f"{parameters[prefix + '_date']}T{parameters[prefix + '_time']}")
                  for prefix in ("begin", "end"))
    if start >= end:
        raise ValueError("NX-OS log interval must end after it begins")
    return start, end


# nxos ports: NX-OS port and peer diagnostics, verified on NX-OS 9.3(12).
NXOS_QUERIES.update({
    "stp_detail": Query("show spanning-tree detail", NO_SLOTS, "Show STP topology changes and per-port counters.", high_volume=True),
    "stp_interface_detail": Query("show spanning-tree interface {interface} detail", CISCO_NXOS_INTERFACE, "Show STP BPDU and transition counters for one enrolled port."),
    "stp_mst": Query("show spanning-tree mst", NO_SLOTS, "Show the MST instance and port states when the switch uses MST.", high_volume=True),
    "port_channel_database": Query("show port-channel database", NO_SLOTS, "Show member selection, state and last bundle events per port channel. An empty output means no port-channel records.", high_volume=True, empty_allowed=True),
    "lacp_interface": Query("show lacp interface {interface}", CISCO_NXOS_NON_SUBINTERFACE, "Show the actor and partner state of one enrolled Ethernet port."),
    "port_channel_load_balance": Query("show port-channel load-balance", NO_SLOTS, "Show the system and per-module port-channel hash inputs."),
    "vpc_member_consistency": Query("show vpc consistency-parameters vpc {vpc_id}", {"vpc_id": Slot(None, "vpc_id")}, "Compare local and peer parameters for one vPC ID. An empty output means no consistency rows for that ID.", empty_allowed=True),
    "vpc_interface_consistency": Query("show vpc consistency-parameters interface {interface}", {"interface": Slot("interfaces", "cisco_nxos_port_channel")}, "Compare local and peer parameters for one enrolled port channel."),
    "lldp_neighbor_interface": Query("show lldp neighbors interface {interface} detail", CISCO_NXOS_INTERFACE, "Show detailed LLDP neighbors of one enrolled interface."),
    "cdp_neighbor_interface": Query("show cdp neighbors interface {interface} detail", CISCO_NXOS_INTERFACE, "Show detailed CDP neighbors of one enrolled interface."),
})

# nxos routing: protocol details remain sourced CLI text (including timers, reset reasons,
# path attributes and policy counters); they do not infer a forwarding decision.
NXOS_QUERIES.update({
    "route_prefix_lookup": Query("show ip route {prefix}", {"prefix": Slot("lookup_prefixes", "ipv4_prefix")}, "Look up one enrolled IPv4 prefix in the RIB."),
    "route_map_counters": Query("show route-map {route_map} pbr-statistics", {"route_map": Slot("route_maps", "route_map")}, "Show available PBR match and default-routing counters; statistics must already be enabled.", high_volume=True),
    "bgp_neighbor_detail": Query("show bgp ipv4 unicast neighbors {address}", IPV4_ADDRESS, "Show one enrolled BGP peer, timers and last reset reason.", high_volume=True),
    "bgp_prefix_detail": Query("show bgp ipv4 unicast {prefix}", {"prefix": Slot("lookup_prefixes", "ipv4_prefix")}, "Show BGP paths and attributes for one enrolled prefix.", high_volume=True),
    "bgp_advertised_routes": Query("show bgp ipv4 unicast neighbors {address} advertised-routes", IPV4_ADDRESS, "Show routes advertised to one enrolled IPv4 BGP peer.", high_volume=True),
    "bgp_received_routes": Query("show bgp ipv4 unicast neighbors {address} routes", IPV4_ADDRESS, "Show accepted routes received from one enrolled IPv4 BGP peer.", high_volume=True),
    "ospf_process": Query("show ip ospf", NO_SLOTS, "Show OSPF processes, areas and timers.", high_volume=True),
    "ospf_neighbors_detail": Query("show ip ospf neighbors detail", NO_SLOTS, "Show OSPF neighbor transitions and dead timers.", high_volume=True),
    "ospf_interface_detail": Query("show ip ospf interface {interface}", CISCO_NXOS_INTERFACE, "Show OSPF state, cost and timers for one enrolled interface.", high_volume=True),
    "ospf_database": Query("show ip ospf database", NO_SLOTS, "Show the OSPF link-state database.", high_volume=True),
    "ipv6_route_table": Query("show ipv6 route", NO_SLOTS, "Show the complete IPv6 RIB of the default VRF.", high_volume=True),
    "bgp_ipv6_summary": Query("show bgp ipv6 unicast summary", NO_SLOTS, "Summarize IPv6 unicast BGP peers.", high_volume=True),
    "ospfv3_neighbors": Query("show ipv6 ospfv3 neighbors", NO_SLOTS, "Show OSPFv3 neighbors.", high_volume=True),
    "bfd_neighbors_detail": Query("show bfd neighbors details", NO_SLOTS, "Show BFD session state, diagnostic codes and negotiated timers.", high_volume=True),
    "forwarding_ipv4_route": Query("show forwarding ipv4 route", NO_SLOTS, "Show the platform IPv4 forwarding table; preserve command failures.", high_volume=True),
    "ip_adjacency": Query("show ip adjacency", NO_SLOTS, "Show IPv4 forwarding adjacencies.", high_volume=True),
    "route_maps": Query("show route-map", NO_SLOTS, "Show route-map clauses and available policy match counters.", high_volume=True),
    "ip_policy": Query("show ip policy", NO_SLOTS, "Show interface PBR policies and their operational status.", high_volume=True),
})

# Separate enrolled-VRF variants preserve existing default-VRF query contracts.
for _name in (
    "route_lookup", "route_prefix_lookup", "route_table", "arp_table", "ipv6_neighbors", "ip_interfaces",
    "bgp_summary", "ospf_neighbors", "ospf_interfaces", "ipv6_route_lookup",
    "ipv6_route_table", "bgp_ipv6_summary", "ospfv3_neighbors",
):
    _query = NXOS_QUERIES[_name]
    NXOS_QUERIES[_name + "_vrf"] = Query(
        _query.command + " vrf {vrf}", {**_query.slots, "vrf": Slot("vrfs", "vrf")},
        "Read " + _name.replace("_", " ") + " in one enrolled VRF.", high_volume=_query.high_volume,
    )


# nxos probes: fixed packet count; all destinations, sources and VRFs must be enrolled.
_NX_PROBE_VRF = {"vrf": Slot("vrfs", "vrf")}
NXOS_QUERIES.update({
    "ping": Query("ping {address} vrf {vrf} count 5", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv4_address")}, "Run a bounded IPv4 ping from an enrolled VRF."),
    "ping_source": Query("ping {address} vrf {vrf} source {source} count 5", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv4_address"), "source": Slot("addresses", "ipv4_address")}, "Run a bounded IPv4 ping from an enrolled VRF and source."),
    "traceroute": Query("traceroute {address} vrf {vrf}", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv4_address")}, "Run a bounded IPv4 traceroute from an enrolled VRF."),
    "traceroute_source": Query("traceroute {address} source {source} vrf {vrf}", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv4_address"), "source": Slot("addresses", "ipv4_address")}, "Run a bounded IPv4 traceroute from an enrolled VRF and source."),
    "ping6": Query("ping6 {address} vrf {vrf} count 5", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv6_address")}, "Run a bounded IPv6 ping from an enrolled VRF."),
    "ping6_source": Query("ping6 {address} vrf {vrf} source {source} count 5", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv6_address"), "source": Slot("addresses", "ipv6_address")}, "Run a bounded IPv6 ping from an enrolled VRF and source."),
    "traceroute6": Query("traceroute6 {address} vrf {vrf}", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv6_address")}, "Run a bounded IPv6 traceroute from an enrolled VRF."),
    "traceroute6_source": Query("traceroute6 {address} source {source} vrf {vrf}", {"vrf": Slot("vrfs", "vrf"), "address": Slot("addresses", "ipv6_address"), "source": Slot("addresses", "ipv6_address")}, "Run a bounded IPv6 traceroute from an enrolled VRF and source."),
})


# nxos security: focused L2/L3 lookups, ACLs and first-hop security diagnostics.
_NX_IPV4_NEIGHBOR = {"address": Slot(None, "ipv4_neighbor")}
_NX_IPV6_NEIGHBOR = {"address": Slot(None, "ipv6_neighbor")}
_NX_ACL_NAME = {"name": Slot(None, "nxos_acl_name")}
NXOS_G94_QUERIES = {
    "mac_table_address": Query("show mac address-table address {mac}", {"mac": Slot(None, "mac_literal")}, "Show forwarding entries for one MAC address."),
    "mac_table_vlan": Query("show mac address-table vlan {vlan_id}", VLAN_ID, "Show forwarding entries in one VLAN.", high_volume=True),
    "arp_lookup": Query("show ip arp {address}", _NX_IPV4_NEIGHBOR, "Show one IPv4 ARP entry in the default VRF."),
    "arp_lookup_vrf": Query("show ip arp {address} vrf {vrf}", {**_NX_IPV4_NEIGHBOR, **_VRF}, "Show one IPv4 ARP entry in an enrolled VRF."),
    "ipv6_neighbor_lookup": Query("show ipv6 neighbor {address}", _NX_IPV6_NEIGHBOR, "Show one IPv6 neighbor in the default VRF."),
    "ipv6_neighbor_lookup_vrf": Query("show ipv6 neighbor {address} vrf {vrf}", {**_NX_IPV6_NEIGHBOR, **_VRF}, "Show one IPv6 neighbor in an enrolled VRF."),
    "ipv4_access_lists": Query("show ip access-lists {name}", _NX_ACL_NAME, "Show one IPv4 ACL and its available hit counts. An empty output means no matching ACL.", empty_allowed=True),
    "ipv6_access_lists": Query("show ipv6 access-lists {name}", _NX_ACL_NAME, "Show IPv6 ACLs or one named ACL with available hit counts. An empty output means no matching ACL.", optional_slots=frozenset({"name"}), high_volume=True, empty_allowed=True),
    "mac_access_lists": Query("show mac access-lists {name}", _NX_ACL_NAME, "Show MAC ACLs or one named ACL with available hit counts. An empty output means no matching ACL.", optional_slots=frozenset({"name"}), high_volume=True, empty_allowed=True),
    "ipv4_access_lists_summary": Query("show ip access-lists summary", NO_SLOTS, "Show IPv4 ACL summaries with configured and active interface bindings. An empty output means no ACLs.", high_volume=True, empty_allowed=True),
    "ipv6_access_lists_summary": Query("show ipv6 access-lists summary", NO_SLOTS, "Show IPv6 ACL summaries with configured and active interface bindings. An empty output means no ACLs.", high_volume=True, empty_allowed=True),
    "mac_access_lists_summary": Query("show mac access-lists summary", NO_SLOTS, "Show MAC ACL summaries with configured and active interface bindings. An empty output means no ACLs.", high_volume=True, empty_allowed=True),
    "ip_interface_details": Query("show ip interface {interface}", CISCO_NXOS_INTERFACE, "Show IPv4 details for one enrolled interface."),
    "dhcp_snooping_status": Query("show ip dhcp snooping", NO_SLOTS, "Show DHCP snooping state and configured and operational VLANs."),
    "dhcp_snooping_statistics": Query("show ip dhcp snooping statistics", NO_SLOTS, "Show DHCP snooping packet and drop counters."),
    "dhcp_relay_status": Query("show ip dhcp relay", NO_SLOTS, "Show DHCP relay service, options and helper addresses."),
    "dhcp_relay_statistics": Query("show ip dhcp relay statistics", NO_SLOTS, "Show DHCP relay packet and drop counters."),
    "arp_inspection_statistics": Query("show ip arp inspection statistics", NO_SLOTS, "Show DAI counters across VLANs. An empty output means no reported statistics.", high_volume=True, empty_allowed=True),
    "arp_inspection_statistics_vlan": Query("show ip arp inspection statistics vlan {vlan_id}", VLAN_ID, "Show DAI counters for one VLAN. An empty output means no reported statistics.", empty_allowed=True),
}
NXOS_QUERIES.update(NXOS_G94_QUERIES)

_NXOS_QOS_PORT = {"interface": Slot("interfaces", "cisco_nxos_ethernet")}
NXOS_G96_QUERIES = {
    "qos_queues": Query("show queuing interface {interface}", _NXOS_QOS_PORT, "Show queue traffic and drop counters for one enrolled Ethernet port."),
    "qos_policy": Query("show policy-map interface {interface}", _NXOS_QOS_PORT, "Show the effective QoS policies and their classes on one enrolled Ethernet port."),
    "priority_flow_control": Query("show interface priority-flow-control", NO_SLOTS, "Show PFC administrative and operational state and pause frame counts by port.", high_volume=True),
    "tcam_utilization": Query("show hardware access-list resource utilization", NO_SLOTS, "Show TCAM and ACL hardware resource utilization by module and instance.", high_volume=True),
    "hardware_capacity": Query("show hardware capacity", NO_SLOTS, "Show platform capacity, including structured ACL hardware utilization where reported.", high_volume=True),
}
NXOS_QUERIES.update(NXOS_G96_QUERIES)

NXOS_G97_QUERIES = {
    "nve_peers": Query("show nve peers", NO_SLOTS, "Show remote VXLAN VTEPs and their NVE peer state.", high_volume=True),
    "nve_vni": Query("show nve vni", NO_SLOTS, "Show VXLAN VNI state and the reported bridge-domain or VRF mapping.", high_volume=True),
    "nve_interface_detail": Query("show nve interface nve1 detail", NO_SLOTS, "Show nve1 encapsulation, learning mode, and source interface details."),
    "evpn_bgp_summary": Query("show bgp l2vpn evpn summary", NO_SLOTS, "Show BGP EVPN neighbors, session state, and received prefix counts.", high_volume=True),
    "evpn_bgp_prefix": Query("show bgp l2vpn evpn {prefix}", {"prefix": Slot(None, "ip_literal")}, "Look up BGP EVPN paths and route distinguishers by IPv4 or IPv6 address.", high_volume=True),
    "evpn_mac_ip": Query("show l2route evpn mac-ip all", NO_SLOTS, "Show EVPN MAC/IP bindings with their topology, producer, and next hops.", high_volume=True),
}
NXOS_QUERIES.update(NXOS_G97_QUERIES)


# Privilege 15 is needed for the IOS XE logging buffer on the lab image. The
# clock is a separately enrolled input to the date filter.
IOS_ADMIN_READS = frozenset({XE_LOG_HISTORY, "clock", "snmp_engine_id"})
IOS_XE_ADMIN_READS = frozenset(IOS_XE_PROBE_QUERIES) | IOS_XE_G73_QUERIES.keys() | {XE_LOG_HISTORY, "clock", "ip_interface_details", "snmp_engine_id"}


# wireless controller: Catalyst 9800 operational reads. Other IOS XE products may reject them.
C9800_QUERIES = {
    "c9800_aps": Query("show ap summary", NO_SLOTS, "List the APs reported by the wireless controller and their state.", high_volume=True),
    "c9800_ap_joins": Query("show wireless stats ap join summary", NO_SLOTS, "Show controller-observed APs that joined or failed to join and the last disconnect reason.", high_volume=True),
    "c9800_clients": Query("show wireless client summary", NO_SLOTS, "List wireless clients and their current AP and state.", high_volume=True),
    "c9800_client_detail": Query("show wireless client mac-address {mac} detail", {"mac": Slot(None, "mac_literal")}, "Show authentication, association, VLAN and signal for one wireless client."),
    "c9800_client_stats": Query("show wireless stats client detail", NO_SLOTS, "Show controller-wide wireless client statistics.", high_volume=True),
    "c9800_radio_24": Query("show ap dot11 24ghz summary", NO_SLOTS, "Show the state, channels and power of 2.4 GHz radios.", high_volume=True),
    "c9800_radio_5": Query("show ap dot11 5ghz summary", NO_SLOTS, "Show the state, channels and power of 5 GHz radios.", high_volume=True),
    "c9800_ap_load": Query("show ap summary load-info", NO_SLOTS, "Show per-AP client counts and per-slot channel utilization.", high_volume=True),
    "c9800_wlans": Query("show wlan summary", NO_SLOTS, "Show WLANs, their SSIDs and any reported VLAN.", high_volume=True),
    "c9800_ap_tags": Query("show ap tag summary", NO_SLOTS, "Show AP site, RF and policy tags.", high_volume=True),
    "c9800_ap_tag_detail": Query("show ap name {ap_name} tag detail", {"ap_name": Slot(None, "c9800_ap_name")}, "Show an AP's policy, site and RF tags and its WLAN-to-policy and VLAN bindings."),
    "c9800_policy_profiles": Query("show wireless profile policy summary", NO_SLOTS, "Show wireless policy profile names and state.", high_volume=True),
    "c9800_client_deletes": Query("show wireless stats client delete reasons", NO_SLOTS, "Show controller and AP counters by client deletion reason.", high_volume=True),
    "c9800_exclusions": Query("show wireless exclusionlist", NO_SLOTS, "Show excluded clients and their exclusion reasons.", high_volume=True),
    "c9800_rogue_aps": Query("show wireless wps rogue ap summary", NO_SLOTS, "Show detected rogue APs.", high_volume=True),
    "c9800_redundancy": Query("show redundancy", NO_SLOTS, "Show the local and peer redundancy mode, processor state and image."),
    "c9800_chassis_rmi": Query("show chassis rmi", NO_SLOTS, "Show chassis roles, readiness and redundancy management addresses."),
}
IOS_XE_QUERIES.update(C9800_QUERIES)


# forwarding processor: fixed read-only commands for hardware QFP dataplanes.
QFP_QUERIES = {
    "qfp_drops": Query("show platform hardware qfp active statistics drop", NO_SLOTS,
                       "Show hardware QFP drop reasons and packet and octet counts.", high_volume=True),
    "qfp_utilization": Query("show platform hardware qfp active datapath utilization", NO_SLOTS,
                             "Show QFP rate and utilization over the 5-second, 1-, 5- and 60-minute windows."),
}
IOS_XE_QUERIES.update(QFP_QUERIES)
