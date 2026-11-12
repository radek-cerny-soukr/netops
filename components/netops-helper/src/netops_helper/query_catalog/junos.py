"""Curated Junos OS 23.4R2 phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot

MAC_LITERAL = {"mac": Slot(None, "mac_literal")}


def _interface_slot(kind: str) -> dict[str, Slot]:
    return {"interface": Slot("interfaces", kind)}


COMMON_QUERIES: dict[str, Query] = {
    "version": Query("show version | no-more", NO_SLOTS, "Show software and platform version details."),
    "uptime": Query("show system uptime | no-more", NO_SLOTS, "Show system uptime."),
    "system_alarms": Query("show system alarms | no-more", NO_SLOTS, "Show active system alarms."),
    "chassis_alarms": Query("show chassis alarms | no-more", NO_SLOTS, "Show active chassis alarms."),
    "hardware": Query("show chassis hardware | no-more", NO_SLOTS, "Show installed chassis hardware."),
    "environment": Query("show chassis environment | no-more", NO_SLOTS, "Show chassis environmental status."),
    "interfaces": Query("show interfaces terse | no-more", NO_SLOTS, "Summarize physical and logical interface state.", high_volume=True),
    "interface_details": Query("show interfaces {interface} extensive | no-more", _interface_slot("junos_interface"), "Show extensive operational details for one enrolled interface."),
    "interface_optics": Query("show interfaces diagnostics optics {interface} | no-more", _interface_slot("junos_physical_interface"), "Show optical diagnostics for one enrolled physical interface."),
    "route_summary": Query("show route summary | no-more", NO_SLOTS, "Summarize the routing tables."),
    "route_lookup": Query("show route {address} detail | no-more", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show route {address} detail | no-more", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "arp_table": Query("show arp no-resolve | no-more", NO_SLOTS, "Show the IPv4 ARP table without name resolution.", high_volume=True),
    "arp_interface": Query("show arp no-resolve interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show ARP entries for one enrolled logical interface.", high_volume=True),
    "ipv6_neighbors": Query("show ipv6 neighbors | no-more", NO_SLOTS, "Show the IPv6 neighbor table.", high_volume=True),
    "ipv6_neighbors_interface": Query("show ipv6 neighbors interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show IPv6 neighbors for one enrolled logical interface.", high_volume=True),
    "lldp_neighbors": Query("show lldp neighbors | no-more", NO_SLOTS, "Summarize LLDP neighbors.", high_volume=True),
    "lldp_neighbors_interface": Query("show lldp neighbors interface {interface} | no-more", _interface_slot("junos_physical_interface"), "Show LLDP neighbors for one enrolled physical interface."),
    "lacp_interfaces": Query("show lacp interfaces | no-more", NO_SLOTS, "Show LACP state for supported interfaces.", high_volume=True),
    "lacp_interface": Query("show lacp interfaces {interface} | no-more", _interface_slot("junos_lacp_interface"), "Show LACP state for one enrolled interface."),
    "bgp_summary": Query("show bgp summary | no-more", NO_SLOTS, "Summarize BGP peer state.", high_volume=True),
    "ospf_neighbors": Query("show ospf neighbor | no-more", NO_SLOTS, "Show OSPFv2 neighbor state.", high_volume=True),
    "ospf_neighbors_interface": Query("show ospf neighbor interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv2 neighbors for one enrolled logical interface."),
    "ospfv3_neighbors": Query("show ospf3 neighbor | no-more", NO_SLOTS, "Show OSPFv3 neighbor state.", high_volume=True),
    "ospfv3_neighbors_interface": Query("show ospf3 neighbor interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv3 neighbors for one enrolled logical interface."),
    # 1.0.7: route table, OSPF interfaces, LLDP detail, resources, NTP, VRRP, BFD, commit history, bounded logs
    "route_table": Query("show route | no-more", NO_SLOTS, "Show the routing tables of every routing instance.", high_volume=True),
    "route_instances": Query("show route instance | no-more", NO_SLOTS, "List the routing instances with their tables and state."),
    "ospf_interfaces": Query("show ospf interface brief | no-more", NO_SLOTS, "Summarize OSPFv2 interfaces, state, area, DR and neighbor counts.", high_volume=True),
    "lldp_neighbors_detail": Query("show lldp neighbors detail | no-more", NO_SLOTS, "Show detailed LLDP neighbors with capabilities and management addresses.", high_volume=True),
    "interfaces_descriptions": Query("show interfaces descriptions | no-more", NO_SLOTS, "Show interface state with configured descriptions.", high_volume=True),
    "routing_engine": Query("show chassis routing-engine | no-more", NO_SLOTS, "Show routing-engine CPU, memory, uptime and the last reboot reason."),
    "fpc": Query("show chassis fpc | no-more", NO_SLOTS, "Show line-card state, temperature, CPU and memory."),
    "storage": Query("show system storage | no-more", NO_SLOTS, "Show file system capacity and use."),
    "licenses": Query("show system license | no-more", NO_SLOTS, "Show installed licenses and license usage."),
    "commit_history": Query("show system commit | no-more", NO_SLOTS, "Show the commit history: who committed, when and from where."),
    "ntp_status": Query("show ntp status | no-more", NO_SLOTS, "Show NTP synchronization state."),
    "ntp_associations": Query("show ntp associations no-resolve | no-more", NO_SLOTS, "Show NTP peers with stratum, reachability, delay and offset."),
    "vrrp_summary": Query("show vrrp summary | no-more", NO_SLOTS, "Summarize VRRP groups and state."),
    "bfd_sessions": Query("show bfd session | no-more", NO_SLOTS, "Show BFD sessions."),
    "log_messages": Query("show log messages | last 200 | no-more", NO_SLOTS, "Show the newest 200 lines of the messages log (requires trace permission and read access to the specific log file; the built-in read-only class returns permission_denied). NetOps does not recommend broader permissions; use syslog as described in the [read-only account guidance](read-only-accounts.md#junos-os).", high_volume=True),
    "log_interactive_commands": Query("show log interactive-commands | last 200 | no-more", NO_SLOTS, "Show the newest 200 interactive CLI commands with the user who ran them (requires trace permission and read access to the specific log file; the built-in read-only class returns permission_denied). NetOps does not recommend broader permissions; use syslog as described in the [read-only account guidance](read-only-accounts.md#junos-os).", high_volume=True),
}


ELS_QUERIES: dict[str, Query] = {
    **COMMON_QUERIES,
    "vlans": Query("show vlans brief | no-more", NO_SLOTS, "Show ELS VLAN state.", high_volume=True),
    "mac_table": Query("show ethernet-switching table | no-more", NO_SLOTS, "Show the ELS Ethernet switching table.", high_volume=True),
    "stp_bridge": Query("show spanning-tree bridge | no-more", NO_SLOTS, "Show ELS spanning-tree bridge state.", high_volume=True),
    "virtual_chassis": Query("show virtual-chassis status | no-more", NO_SLOTS, "Show virtual chassis status."),
    "virtual_chassis_ports": Query("show virtual-chassis vc-port | no-more", NO_SLOTS, "Show virtual chassis port state."),
    "ethernet_switching_interfaces": Query("show ethernet-switching interface | no-more", NO_SLOTS, "Show every switched logical interface with its VLAN members, tagging and spanning-tree state.", high_volume=True),
    "ethernet_switching_interface": Query("show ethernet-switching interface {interface} detail | no-more", _interface_slot("junos_physical_interface"), "Show switching details of one enrolled physical interface."),
    "mac_table_interface": Query("show ethernet-switching table interface {interface} | no-more", _interface_slot("junos_physical_interface"), "Show the Ethernet switching table entries of one enrolled physical interface.", high_volume=True),
    "mac_table_address": Query("show ethernet-switching table {mac} | no-more", MAC_LITERAL, "Show the Ethernet switching table entry of one MAC address."),
    "stp_interfaces": Query("show spanning-tree interface | no-more", NO_SLOTS, "Show spanning-tree role and state of every port.", high_volume=True),
    "poe_interfaces": Query("show poe interface | no-more", NO_SLOTS, "Show PoE state and power per port.", high_volume=True),
    "poe_controller": Query("show poe controller | no-more", NO_SLOTS, "Show the PoE controller power budget."),
    "dot1x_interfaces": Query("show dot1x interface | no-more", NO_SLOTS, "Show 802.1X state per port.", high_volume=True),
    "dhcp_security_bindings": Query("show dhcp-security binding | no-more", NO_SLOTS, "Show the DHCP security bindings.", high_volume=True),
}
