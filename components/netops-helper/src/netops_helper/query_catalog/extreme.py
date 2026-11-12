"""Curated Extreme Networks Switch Engine phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot


PHYSICAL_PORT = {
    "interface": Slot("interfaces", "extreme_physical_port"),
}


QUERIES: dict[str, Query] = {
    "vlan_detail": Query("show vlan detail", NO_SLOTS, "Show all VLANs with their tagged and untagged member ports.", high_volume=True),
    "vlan_details": Query("show vlan {vlan}", {"vlan": Slot("vlans", "vlan_name")}, "Show one enrolled VLAN.", high_volume=True),
    "dhcp_snooping_entries": Query("show ip-security dhcp-snooping entries vlan {vlan}", {"vlan": Slot("vlans", "vlan_name")}, "Show DHCP snooping bindings for one enrolled VLAN.", high_volume=True),

    "switch": Query("show switch", NO_SLOTS, "Show switch identity, role, and operating status."),
    "version": Query(
        "show version", NO_SLOTS, "Show hardware and software version information.",
    ),
    "memory": Query("show memory", NO_SLOTS, "Show system memory utilization."),
    "cpu_monitoring": Query(
        "show cpu-monitoring",
        NO_SLOTS,
        "Show CPU utilization history.",
        high_volume=True,
    ),
    "processes": Query(
        "show process",
        NO_SLOTS,
        "Show operating status for system processes.",
        high_volume=True,
    ),
    "diagnostics": Query(
        "show diagnostics",
        NO_SLOTS,
        "Show results from the most recent diagnostic test.",
    ),
    "temperature": Query(
        "show temperature", NO_SLOTS, "Show system temperature and component status.",
    ),
    "fans": Query("show fans", NO_SLOTS, "Show fan health."),
    "power": Query("show power", NO_SLOTS, "Show power-supply health."),
    "ports": Query(
        "show ports no-refresh",
        NO_SLOTS,
        "Show a one-shot summary of all ports.",
        high_volume=True,
    ),
    "ports_configuration": Query(
        "show ports configuration no-refresh",
        NO_SLOTS,
        "Show a one-shot Layer 1 port snapshot with administrative, link, "
        "autonegotiation, speed, duplex, and media state.",
        high_volume=True,
    ),
    "interface_details": Query(
        "show port {interface} information detail",
        PHYSICAL_PORT,
        "Show detailed state for one enrolled port.",
    ),
    "interface_statistics": Query(
        "show ports {interface} statistics no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot statistics snapshot for one enrolled port.",
    ),
    "interface_rx_errors": Query(
        "show ports {interface} rxerrors no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot receive-error snapshot for one enrolled port.",
    ),
    "interface_tx_errors": Query(
        "show ports {interface} txerrors no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot transmit-error snapshot for one enrolled port.",
    ),
    "interface_transceiver": Query(
        "show ports {interface} transceiver information detail",
        PHYSICAL_PORT,
        "Show optical transceiver diagnostics for one enrolled port.",
    ),
    "route_summary": Query(
        "show iproute summary", NO_SLOTS, "Summarize the IPv4 routing table.",
    ),
    "ipv6_route_summary": Query(
        "show iproute ipv6 summary", NO_SLOTS, "Summarize the IPv6 routing table.",
    ),
    "arp_table": Query(
        "show iparp", NO_SLOTS, "Show the IPv4 ARP table.", high_volume=True,
    ),
    "arp_address": Query(
        "show iparp {address}",
        IPV4_ADDRESS,
        "Show the ARP entry for one enrolled IPv4 address.",
    ),
    "arp_interface": Query(
        "show iparp port {interface}",
        PHYSICAL_PORT,
        "Show ARP entries learned on one enrolled port.",
        high_volume=True,
    ),
    "ipv6_neighbors": Query(
        "show neighbor-discovery cache ipv6",
        NO_SLOTS,
        "Show the IPv6 neighbor cache.",
        high_volume=True,
    ),
    "ipv6_neighbor_address": Query(
        "show neighbor-discovery cache ipv6 {address}",
        IPV6_ADDRESS,
        "Show the neighbor entry for one enrolled IPv6 address.",
    ),
    "mac_table": Query(
        "show fdb", NO_SLOTS, "Show the forwarding database.", high_volume=True,
    ),
    "mac_interface": Query(
        "show fdb ports {interface}",
        PHYSICAL_PORT,
        "Show forwarding entries learned on one enrolled port.",
        high_volume=True,
    ),
    "lldp_neighbors": Query(
        "show lldp neighbors",
        NO_SLOTS,
        "Summarize LLDP neighbors on all ports.",
        high_volume=True,
    ),
    "lldp_interface": Query(
        "show lldp port {interface} neighbors",
        PHYSICAL_PORT,
        "Summarize LLDP neighbors on one enrolled port.",
    ),
    "lldp_interface_details": Query(
        "show lldp port {interface} neighbors detailed",
        PHYSICAL_PORT,
        "Show detailed LLDP neighbors on one enrolled port.",
    ),
    "vlan_summary": Query(
        "show vlan", NO_SLOTS, "Summarize all VLANs.", high_volume=True,
    ),
    "lag_summary": Query("show sharing", NO_SLOTS, "Show load-sharing groups and member link state.", high_volume=True),
    "lacp": Query("show lacp", NO_SLOTS, "Show LACP operating state.", high_volume=True),
    "stp_summary": Query(
        "show stpd", NO_SLOTS, "Summarize spanning-tree domains.",
        high_volume=True,
    ),
    "stp_detail": Query(
        "show stpd detail",
        NO_SLOTS,
        "Show spanning-tree settings for each domain.",
        high_volume=True,
    ),
    "stacking": Query(
        "show stacking",
        NO_SLOTS,
        "Summarize the nodes in the stack topology.",
    ),
    "stacking_support": Query(
        "show stacking-support",
        NO_SLOTS,
        "Show the configured and current stacking-support state of the node.",
    ),
    "inline_power": Query(
        "show inline-power",
        NO_SLOTS,
        "Show the inline-power status of the switch.",
    ),
    "inline_power_port": Query(
        "show inline-power info ports {interface}",
        PHYSICAL_PORT,
        "Show inline-power information for one enrolled port.",
    ),
    "access_list_counters": Query(
        "show access-list counter",
        NO_SLOTS,
        "Show access-list counters.",
        high_volume=True,
    ),
    "qos_profiles": Query(
        "show qosprofile",
        NO_SLOTS,
        "Show QoS profile information.",
    ),
    "licenses": Query(
        "show licenses",
        NO_SLOTS,
        "Show the software license level, port speed licensing, and feature packs.",
    ),
    "ntp": Query(
        "show ntp",
        NO_SLOTS,
        "Show the global NTP status of the switch.",
    ),
    "sntp_client": Query(
        "show sntp-client",
        NO_SLOTS,
        "Show the SNTP client state.",
    ),
    "sessions": Query(
        "show session",
        NO_SLOTS,
        "Show the currently active console and remote sessions.",
    ),
    "elrp": Query(
        "show elrp",
        NO_SLOTS,
        "Show Extreme Loop Recovery Protocol information.",
    ),
    "mcast_cache_summary": Query(
        "show mcast cache summary",
        NO_SLOTS,
        "Summarize the multicast forwarding cache.",
    ),
    "mirror": Query(
        "show mirror",
        NO_SLOTS,
        "Show the configured mirror instances and their state.",
    ),
    "ports_description": Query(
        "show ports description",
        NO_SLOTS,
        "Show the display string and description of every port.",
        high_volume=True,
    ),
    "ports_rx_errors": Query(
        "show ports rxerrors no-refresh",
        NO_SLOTS,
        "Show a one-shot receive-error snapshot of all ports.",
        high_volume=True,
    ),
    "ports_tx_errors": Query(
        "show ports txerrors no-refresh",
        NO_SLOTS,
        "Show a one-shot transmit-error snapshot of all ports.",
        high_volume=True,
    ),
    "ipconfig": Query(
        "show ipconfig",
        NO_SLOTS,
        "Show the IPv4 settings and the address of every routed VLAN.",
        high_volume=True,
    ),
    "route_table": Query(
        "show iproute",
        NO_SLOTS,
        "Show the IPv4 routing table of the default virtual router.",
        high_volume=True,
    ),
    "ipv6_route_table": Query(
        "show iproute ipv6",
        NO_SLOTS,
        "Show the IPv6 routing table of the default virtual router.",
        high_volume=True,
    ),
    "lldp_neighbors_detail": Query(
        "show lldp neighbors detailed",
        NO_SLOTS,
        "Show detailed LLDP neighbors on all ports, including system capabilities and management address.",
        high_volume=True,
    ),
    "stp_ports": Query(
        "show stpd s0 ports",
        NO_SLOTS,
        "Show port roles and states of the default spanning-tree domain s0.",
        high_volume=True,
    ),
    "mlag_peer": Query(
        "show mlag peer",
        NO_SLOTS,
        "Show the configured MLAG peers and their state.",
    ),
    "mlag_ports": Query(
        "show mlag ports",
        NO_SLOTS,
        "Show MLAG ports with local and remote link state.",
        high_volume=True,
    ),
    "inline_power_stats": Query(
        "show inline-power stats",
        NO_SLOTS,
        "Show the PoE firmware state and the count of powered, waiting and faulted ports.",
    ),
    "ntp_association": Query(
        "show ntp association",
        NO_SLOTS,
        "Show the NTP associations with stratum, delay, offset and reachability.",
    ),
    "log_messages": Query(
        "show log messages memory-buffer",
        NO_SLOTS,
        "Show the local log buffer, newest message first.",
        high_volume=True,
    ),
    "log_warnings": Query(
        "show log messages memory-buffer severity warning",
        NO_SLOTS,
        "Show the local log buffer limited to warning and more severe messages, newest first.",
        high_volume=True,
    ),
    "log_configuration": Query(
        "show log configuration",
        NO_SLOTS,
        "Show the log targets, filters and syslog destinations.",
        high_volume=True,
    ),
    "edp_neighbors": Query(
        "show edp",
        NO_SLOTS,
        "Summarize Extreme Discovery Protocol neighbors.",
        high_volume=True,
    ),
}
