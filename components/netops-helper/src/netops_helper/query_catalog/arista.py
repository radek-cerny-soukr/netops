"""Curated Arista EOS 4.36.x phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot


def _interface_slot(kind: str) -> dict[str, Slot]:
    return {"interface": Slot("interfaces", kind)}


QUERIES: dict[str, Query] = {
    "version": Query("show version", NO_SLOTS, "Show software and platform version details."),
    "clock": Query("show clock", NO_SLOTS, "Show the device clock."),
    "hostname": Query("show hostname", NO_SLOTS, "Show the configured hostname."),
    "inventory": Query("show inventory", NO_SLOTS, "Show installed hardware inventory."),
    "environment": Query("show system environment all", NO_SLOTS, "Show environmental sensor status."),
    "interfaces": Query("show interfaces status", NO_SLOTS, "Summarize interface state and VLAN assignment.", high_volume=True),
    "ip_interfaces": Query("show ip interface brief", NO_SLOTS, "Summarize IPv4 interface state and addresses.", high_volume=True),
    "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS, "Summarize IPv6 interface state and addresses.", high_volume=True),
    "interface_details": Query("show interfaces {interface}", _interface_slot("eos_interface"), "Show operational details for one enrolled interface."),
    "interface_errors": Query("show interfaces {interface} counters errors", _interface_slot("eos_interface"), "Show error counters for one enrolled interface."),
    "interface_optics": Query("show interfaces {interface} transceiver", _interface_slot("eos_physical_interface"), "Show transceiver diagnostics for one enrolled physical interface."),
    "vlans": Query("show vlan", NO_SLOTS, "Show VLAN state and membership.", high_volume=True),
    "mac_table": Query("show mac address-table", NO_SLOTS, "Show the MAC address table.", high_volume=True),
    "arp_table": Query("show ip arp", NO_SLOTS, "Show the IPv4 ARP table.", high_volume=True),
    "arp_entry": Query("show ip arp {address}", IPV4_ADDRESS, "Show the ARP entry for one enrolled IPv4 address."),
    "ipv6_neighbors": Query("show ipv6 neighbors", NO_SLOTS, "Show the IPv6 neighbor table.", high_volume=True),
    "ipv6_neighbor": Query("show ipv6 neighbors {address}", IPV6_ADDRESS, "Show the neighbor entry for one enrolled IPv6 address."),
    "lldp_neighbors": Query("show lldp neighbors", NO_SLOTS, "Summarize LLDP neighbors.", high_volume=True),
    "lldp_neighbors_interface": Query("show lldp neighbors {interface}", _interface_slot("eos_lldp_interface"), "Show LLDP neighbors for one enrolled interface."),
    "lag_summary": Query("show port-channel dense", NO_SLOTS, "Summarize port-channel state and membership.", high_volume=True),
    "lacp_peers": Query("show lacp peer", NO_SLOTS, "Show LACP peer state.", high_volume=True),
    "lacp_peer_interface": Query("show lacp interface {interface} peer", _interface_slot("eos_lacp_interface"), "Show LACP peer state for one enrolled member Ethernet interface."),
    "stp_root": Query("show spanning-tree root", NO_SLOTS, "Show spanning-tree root state.", high_volume=True),
    "stp_interface": Query("show spanning-tree interface {interface}", _interface_slot("eos_stp_interface"), "Show spanning-tree state for one enrolled interface."),
    "route_summary": Query("show ip route summary", NO_SLOTS, "Summarize the IPv4 routing table."),
    "ipv6_route_summary": Query("show ipv6 route summary", NO_SLOTS, "Summarize the IPv6 routing table."),
    "route_lookup": Query("show ip route {address}", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show ipv6 route {address}", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "bgp_summary": Query("show ip bgp summary", NO_SLOTS, "Summarize IPv4 BGP peer state.", high_volume=True),
    "ipv6_bgp_summary": Query("show ipv6 bgp summary", NO_SLOTS, "Summarize IPv6 BGP peer state.", high_volume=True),
    "ospf_neighbors": Query("show ip ospf neighbor", NO_SLOTS, "Show OSPFv2 neighbor state.", high_volume=True),
    "ospf_neighbors_interface": Query("show ip ospf neighbor {interface}", _interface_slot("eos_ospf_interface"), "Show OSPFv2 neighbors for one enrolled interface."),
    "ospfv3_neighbors": Query("show ipv6 ospf neighbor", NO_SLOTS, "Show OSPFv3 neighbor state.", high_volume=True),
}
