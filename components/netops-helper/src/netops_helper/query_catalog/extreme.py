"""Curated Extreme Networks Switch Engine phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot


PHYSICAL_PORT = {
    "interface": Slot("interfaces", "extreme_physical_port"),
}

LOG_HISTORY = "log_history"
LOG_SOURCES = ("memory-buffer", "nvram")
LOG_SEVERITIES = ("critical", "error", "warning", "notice", "info", "debug-summary", "debug-verbose", "debug-data")
LOG_HISTORY_COMMAND = (
    "show log messages {source} severity {severity} starting date {begin_date} time {begin_time} "
    "ending date {end_date} time {end_time}"
)

# STP domain names use the existing enrolled services namespace on EXOS.
STP_DOMAIN = {"domain": Slot("services", "service")}

QUERIES: dict[str, Query] = {
    "access_lists": Query("show access-list", NO_SLOTS, "Show ACL assignments and rules.", high_volume=True),
    "policies": Query("show policy detail", NO_SLOTS, "Show loaded policy contents (requires device account permission).", high_volume=True),
    "policy_details": Query("show policy {policy}", {"policy": Slot(None, "acl_policy")}, "Show one loaded policy (requires device account permission).", high_volume=True),
    "dhcp_server": Query("show dhcp-server vlan {vlan}", {"vlan": Slot("vlans", "vlan_name")}, "Show DHCP pool, lease timer and allocations for one enrolled VLAN; blank output does not confirm server state.", high_volume=True),
    "bootprelay": Query("show bootprelay", NO_SLOTS, "Show DHCP relay state and error counters."),
    "bootprelay_configuration": Query("show bootprelay configuration", NO_SLOTS, "Show DHCP relay configuration.", high_volume=True),
    "radius": Query("show radius", NO_SLOTS, "Show RADIUS status with credential fields redacted.", high_volume=True),
    "tacacs": Query("show tacacs", NO_SLOTS, "Show TACACS status with credential fields redacted.", high_volume=True),
    "accounts": Query("show accounts", NO_SLOTS, "Show local account status (requires device account permission).", high_volume=True),
    "netlogin": Query("show netlogin", NO_SLOTS, "Show network login configuration and authentication state.", high_volume=True),
    "netlogin_port": Query("show netlogin port {interface}", PHYSICAL_PORT, "Show network login state for one enrolled port.", high_volume=True),
    "dns_client": Query("show dns-client", NO_SLOTS, "Show DNS resolver configuration."),
    "dns_lookup": Query("nslookup {name}", {"name": Slot(None, "diagnostic_dns_name")}, "Resolve one fully qualified DNS name from the switch."),
    "management": Query("show management", NO_SLOTS, "Show management and SNMP agent status with credentials redacted.", high_volume=True),
    "snmp_engine": Query("show snmpv3 engine-info", NO_SLOTS, "Show SNMP engine state."),
    "snmp_targets": Query("show snmpv3 target-addr", NO_SLOTS, "Show SNMP notification target addresses with credentials redacted.", high_volume=True),
    "dhcp_snooping": Query("show ip-security dhcp-snooping {vlan}", {"vlan": Slot("vlans", "vlan_name")}, "Show DHCP snooping trusted ports, servers and violation actions for one enrolled VLAN.", high_volume=True),
    "dhcp_snooping_violations": Query("show ip-security dhcp-snooping violations vlan {vlan}", {"vlan": Slot("vlans", "vlan_name")}, "Show DHCP snooping violations for one enrolled VLAN.", high_volume=True),
    "mac_address": Query("show fdb {mac}", {"mac": Slot(None, "mac_literal")}, "Show forwarding entries for one MAC address.", high_volume=True),
    "mac_vlan": Query("show fdb vlan {vlan_id}", {"vlan_id": Slot(None, "vlan_id")}, "Show forwarding entries filtered on the switch by VLAN ID.", high_volume=True),
    "arp_vlan": Query("show iparp vlan {vlan_id}", {"vlan_id": Slot(None, "vlan_id")}, "Show ARP entries filtered on the switch by VLAN ID.", high_volume=True),
    "port_utilization": Query("show ports {interface} utilization bandwidth", PHYSICAL_PORT, "Show one snapshot of bandwidth utilization as percentages."),
    "port_packets": Query("show ports {interface} utilization packets", PHYSICAL_PORT, "Show one snapshot of packets per second."),
    "lacp_member": Query("show lacp member-port {interface} detail", PHYSICAL_PORT, "Show actor flags, partner key and collecting/distributing state."),
    "stp_domain_ports": Query("show stpd {domain} ports", STP_DOMAIN, "Show ports in one enrolled STP domain (services inventory).", high_volume=True),
    "stp_port_detail": Query("show stpd {domain} ports {interface} detail", {**STP_DOMAIN, **PHYSICAL_PORT}, "Show STP role, TCN and guard settings for one enrolled port/domain."),
    "port_qos": Query("show ports {interface} qosmonitor no-refresh", PHYSICAL_PORT, "Show transmitted packets per QoS profile."),
    "port_qos_drops": Query("show ports {interface} qosmonitor congestion no-refresh", PHYSICAL_PORT, "Show ingress congestion drops per QoS profile."),
    "igmp_snooping": Query("show igmp snooping", NO_SLOTS, "Show IGMP snooping settings and receivers.", high_volume=True),
    "igmp_groups": Query("show igmp group", NO_SLOTS, "Show IGMP multicast group membership.", high_volume=True),
    "ipconfig_ipv6": Query("show ipconfig ipv6", NO_SLOTS, "Show IPv6 interface configuration in the current VR.", high_volume=True),
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
        "show iparp", NO_SLOTS, "Show the IPv4 ARP table. An empty output means no ARP entries.",
        high_volume=True, empty_allowed=True,
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
        "Show the IPv6 neighbor cache. An empty output means no IPv6 neighbors.",
        high_volume=True, empty_allowed=True,
    ),
    "ipv6_neighbor_address": Query(
        "show neighbor-discovery cache ipv6 {address}",
        IPV6_ADDRESS,
        "Show the neighbor entry for one enrolled IPv6 address.",
    ),
    "mac_table": Query(
        "show fdb", NO_SLOTS, "Show the forwarding database. An empty output means no MAC entries.",
        high_volume=True, empty_allowed=True,
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
        "Summarize LLDP neighbors on all ports. An empty output means no LLDP neighbors.",
        high_volume=True, empty_allowed=True,
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
        "Show access-list counters. An empty output means no access list reports counters.",
        high_volume=True, empty_allowed=True,
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
        "Show detailed LLDP neighbors on all ports, including system capabilities and management address. An empty output means no LLDP neighbors.",
        high_volume=True, empty_allowed=True,
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
    LOG_HISTORY: Query(
        LOG_HISTORY_COMMAND,
        {"source": Slot(None, "exos_log_source"), "severity": Slot(None, "exos_log_severity"),
         "begin_date": Slot(None, "log_date"), "begin_time": Slot(None, "log_time"),
         "end_date": Slot(None, "log_date"), "end_time": Slot(None, "log_time"), **PHYSICAL_PORT},
        "Read retained memory-buffer or NVRAM records at the requested severity or higher. "
        "Date and time bounds are inclusive in the device's time. The optional enrolled port "
        "selects messages explicitly naming that local port. An empty output means no matching records were "
        "returned. Coverage indicates whether the full window was available.",
        high_volume=True, empty_allowed=True, optional_slots=frozenset(PHYSICAL_PORT),
        filter_slots=frozenset(PHYSICAL_PORT),
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


# G37: VR and address parameters are enrolled inventory, never free CLI text.
_VR = {"vr": Slot("virtual_routers", "vr")}
_PROBE = {**_VR, "address": Slot("addresses", "ipv4_address")}
_SOURCE_PROBE = {**_PROBE, "source": Slot("addresses", "ipv4_address")}
QUERIES.update({
    "ping": Query("ping count 5 vr {vr} {address}", _PROBE, "Send five ICMP echo requests in an enrolled VR."),
    "ping_source": Query("ping count 5 vr {vr} {address} from {source}", _SOURCE_PROBE, "Send five ICMP echo requests with an enrolled source address and VR."),
    "traceroute": Query("traceroute vr {vr} {address}", _PROBE, "Trace the routed path (30 hops maximum) in an enrolled VR."),
    "traceroute_source": Query("traceroute vr {vr} {address} from {source}", _SOURCE_PROBE, "Trace the routed path (30 hops maximum) with an enrolled source address and VR."),
    "ospf_neighbors": Query("show ospf neighbor", NO_SLOTS, "Show OSPF neighbors and their BFD protection state. An empty output means the device reports no OSPF neighbors.", high_volume=True, empty_allowed=True),
    "ospf_interfaces": Query("show ospf interfaces", NO_SLOTS, "Show OSPF interface state.", high_volume=True),
    "ospf_lsdb": Query("show ospf lsdb", NO_SLOTS, "Show the OSPF link-state database. An empty output means the device reports no OSPF link-state records.", high_volume=True, empty_allowed=True),
    "ospfv3_neighbors": Query("show ospfv3 neighbor", NO_SLOTS, "Show OSPFv3 neighbors.", high_volume=True),
    "ospfv3_interfaces": Query("show ospfv3 interfaces", NO_SLOTS, "Show OSPFv3 interface state.", high_volume=True),
    "bgp_summary": Query("show bgp neighbor", NO_SLOTS, "Show BGP peer state and message counters.", high_volume=True),
    "bgp_neighbor": Query("show bgp neighbor {address}", IPV4_ADDRESS, "Show one enrolled BGP peer's state and route statistics.", high_volume=True),
    "bgp_routes": Query("show bgp routes all", NO_SLOTS, "Show all BGP prefixes and their peers.", high_volume=True),
    "vrrp": Query("show vrrp", NO_SLOTS, "Show VRRP gateway state.", high_volume=True),
    "bfd_sessions": Query("show bfd session vr all", NO_SLOTS, "Show BFD sessions in all virtual routers. An empty output means the device reports no BFD sessions.", high_volume=True, empty_allowed=True),
    "route_table_vr": Query("show iproute vr {vr}", _VR, "Show IPv4 routes in an enrolled VR.", high_volume=True),
    "ipv6_route_table_vr": Query("show iproute ipv6 vr {vr}", _VR, "Show IPv6 routes in an enrolled VR.", high_volume=True),
    "arp_table_vr": Query("show iparp vr {vr}", _VR, "Show IPv4 ARP entries in an enrolled VR.", high_volume=True),
    "ipv6_neighbors_vr": Query("show neighbor-discovery cache ipv6 vr {vr}", _VR, "Show IPv6 neighbors in an enrolled VR.", high_volume=True),
})
