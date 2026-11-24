"""Curated Junos OS diagnostic queries."""

from __future__ import annotations

from datetime import datetime, timedelta
import re

from .model import IPV4_ADDRESS, IPV6_ADDRESS, LITERAL, NO_SLOTS, Query, Slot

_VLAN = {"vlan": Slot("vlans", "junos_vlan_name")}

MAC_LITERAL = {"mac": Slot(None, "mac_literal")}


def _interface_slot(kind: str) -> dict[str, Slot]:
    return {"interface": Slot("interfaces", kind)}


# junos routing: enrolled routing instance, peer and probe addresses (verified on vJunos-switch 26.2R1.7).
_INSTANCE = {"instance": Slot("routing_instances", "routing_instance")}
_PEER = {"address": Slot("addresses", "address")}
_PROBE = {"address": Slot("addresses", "ipv4_address"), "source": Slot("addresses", "ipv4_address")}
_NETWORK_PERMISSION = (" Requires the Junos network permission; the built-in read-only class answers"
                       " unknown command (unsupported).")
TRACEROUTE_MAX_HOPS = 30
_TRACEROUTE_OPTIONS = f"ttl {TRACEROUTE_MAX_HOPS} wait 1 | no-more"
_ABSENT = "; empty output means no matching protocol objects were reported."
FILTER_BINDING_QUERY = "interface_firewall_filter"
FILTER_BINDING_COMMAND = "show configuration interfaces {interface} family inet filter | no-more"
CONFIG_PATHS = {
    "dns_resolvers": "name-server",
    "syslog_status": "syslog",
    "authentication_order": "authentication-order",
    "radius_servers": "radius-server",
    "tacacs_servers": "tacplus-server",
}
CONFIG_COMMANDS = {
    "dns_resolvers": "show configuration system name-server | display xml | no-more",
    "syslog_status": "show configuration system syslog | display xml | no-more",
    "authentication_order": "show configuration system authentication-order | display xml | no-more",
    "radius_servers": "show configuration system radius-server | display xml | no-more",
    "tacacs_servers": "show configuration system tacplus-server | display xml | no-more",
}
CONFIG_READ_QUERIES = frozenset({FILTER_BINDING_QUERY, *CONFIG_COMMANDS})
PROFILES = frozenset({"juniper_junos", "juniper_junos_els"})
TESTED_G134 = (("ex9214", "26.2R1.7"),)
LOG_HISTORY_QUERY = "log_history"
LOG_HISTORY_LINES = 2000
LOG_HISTORY_COMMAND = f"show log messages | last {LOG_HISTORY_LINES} | no-more"
LOG_HISTORY_SLOTS = {
    "start": Slot(LITERAL, "junos_log_time"),
    "end": Slot(LITERAL, "junos_log_time"),
    "severity": Slot(LITERAL, "junos_log_severity"),
    **_interface_slot("junos_interface"),
}


def log_time(value: str) -> datetime:
    """Parse an unambiguous, seconds-resolution Junos wall-clock value."""
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", value):
        raise ValueError("log time must use device local YYYY-MM-DDTHH:MM:SS")
    return datetime.fromisoformat(value)


def log_window(parameters) -> tuple[datetime, datetime]:
    start, end = log_time(parameters["start"]), log_time(parameters["end"])
    if not timedelta(0) < end - start <= timedelta(days=7):
        raise ValueError("log window must be positive and at most seven days")
    return start, end


G134_QUERIES = frozenset({
    *CONFIG_COMMANDS, LOG_HISTORY_QUERY, "dhcp_server_bindings", "dhcp_server_statistics",
    "dhcp_relay_bindings", "dhcp_relay_statistics", "system_users", "dns_lookup", "snmp_statistics",
})
_ZONE = Slot("security_zones", "junos_security_zone")
_FLOW_ADDRESS = Slot("addresses", "address")
_FLOW_PORT = Slot("flow_ports", "flow_port")


COMMON_QUERIES: dict[str, Query] = {
    "version": Query("show version | no-more", NO_SLOTS, "Show software and platform version details."),
    "uptime": Query("show system uptime | no-more", NO_SLOTS, "Show system uptime."),
    "system_alarms": Query("show system alarms | no-more", NO_SLOTS, "Show active system alarms."),
    "chassis_alarms": Query("show chassis alarms | no-more", NO_SLOTS, "Show active chassis alarms."),
    "hardware": Query("show chassis hardware | no-more", NO_SLOTS, "Show installed chassis hardware."),
    "environment": Query("show chassis environment | no-more", NO_SLOTS, "Show chassis environmental status."),
    "interfaces": Query("show interfaces terse | no-more", NO_SLOTS, "Summarize physical and logical interface state.", high_volume=True),
    "interface_details": Query("show interfaces {interface} extensive | no-more", _interface_slot("junos_interface"), "Show extensive operational details for one enrolled interface."),
    "interface_queue": Query("show interfaces queue {interface} | no-more", _interface_slot("junos_physical_interface"), "Show queue counters, including drops, on one enrolled physical interface."),
    "interface_class_of_service": Query("show class-of-service interface {interface} | no-more", _interface_slot("junos_interface"), "Show class-of-service associations on one enrolled interface."),
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
    "dhcp_server_bindings": Query("show dhcp server binding detail | no-more", NO_SLOTS, "Show extended DHCP server leases and their assigned pools in the default routing instance; empty output means no leases were listed.", high_volume=True, empty_allowed=True),
    "dhcp_server_statistics": Query("show dhcp server statistics | no-more", NO_SLOTS, "Show extended DHCP server packet and drop counters in the default routing instance."),
    "dhcp_relay_bindings": Query("show dhcp relay binding | no-more", NO_SLOTS, "Show extended DHCP relay client bindings in the default routing instance; empty output means no bindings were listed.", high_volume=True, empty_allowed=True),
    "dhcp_relay_statistics": Query("show dhcp relay statistics | no-more", NO_SLOTS, "Show extended DHCP relay packet and drop counters in the default routing instance."),
    "system_users": Query("show system users | no-more", NO_SLOTS, "Show logged-in administrative CLI sessions."),
    "dns_lookup": Query("show host {name} | no-more", {"name": Slot("diagnostic_names", "junos_dns_name")}, "Resolve an enrolled FQDN from the device."),
    "dns_resolvers": Query(CONFIG_COMMANDS["dns_resolvers"], NO_SLOTS, "Show explicitly configured DNS resolvers and their routing instances; empty output means no explicit resolvers were listed. Requires config_access read.", empty_allowed=True),
    "snmp_statistics": Query("show snmp statistics | no-more", NO_SLOTS, "Show operational SNMP packet and error counters."),
    "syslog_status": Query(CONFIG_COMMANDS["syslog_status"], NO_SLOTS, "Show explicitly configured syslog destinations and event selectors; empty output means no explicit destinations were listed. Requires config_access read.", empty_allowed=True),
    "authentication_order": Query(CONFIG_COMMANDS["authentication_order"], NO_SLOTS, "Show explicitly configured AAA method order; empty output means no explicit order was listed. Requires config_access read.", empty_allowed=True),
    "radius_servers": Query(CONFIG_COMMANDS["radius_servers"], NO_SLOTS, "List configured administrative RADIUS server addresses and non-secret connection settings; empty output means no explicit servers were listed. Requires config_access read.", empty_allowed=True),
    "tacacs_servers": Query(CONFIG_COMMANDS["tacacs_servers"], NO_SLOTS, "List configured administrative TACACS+ server addresses and non-secret connection settings; empty output means no explicit servers were listed. Requires config_access read.", empty_allowed=True),
    LOG_HISTORY_QUERY: Query(
        LOG_HISTORY_COMMAND, LOG_HISTORY_SLOTS,
        "Scan up to 2000 lines of the current messages file for event metadata in a start-inclusive, end-exclusive "
        "device-local YYYY-MM-DDTHH:MM:SS interval of at most seven days. Optionally select an exact severity (0–7) "
        "and enrolled interface; empty output means no matching events were read. Check interval coverage. "
        "Requires the uptime query and CLI access to messages.",
        high_volume=True, empty_allowed=True, optional_slots=frozenset({"severity", "interface"}),
        filter_slots=frozenset(LOG_HISTORY_SLOTS),
    ),
    # junos routing (1.0.12): probes from the device, routing-instance context and BGP/OSPF detail.
    "ping": Query("ping {address} count 5 source {source} | no-more", _PROBE, "Send five IPv4 echo requests to an enrolled address from an enrolled source." + _NETWORK_PERMISSION),
    "ping_instance": Query("ping {address} count 5 source {source} routing-instance {instance} | no-more", {**_PROBE, **_INSTANCE}, "Send five IPv4 echo requests from an enrolled source in an enrolled routing instance." + _NETWORK_PERMISSION),
    "traceroute": Query("traceroute {address} no-resolve " + _TRACEROUTE_OPTIONS, {"address": _PROBE["address"]}, "Trace the path to an enrolled IPv4 address (at most 30 hops, 1 s per probe)." + _NETWORK_PERMISSION),
    "traceroute_instance": Query("traceroute {address} no-resolve routing-instance {instance} " + _TRACEROUTE_OPTIONS, {"address": _PROBE["address"], **_INSTANCE}, "Trace the path to an enrolled IPv4 address in an enrolled routing instance (at most 30 hops, 1 s per probe)." + _NETWORK_PERMISSION),
    "bgp_peer": Query("show bgp neighbor {address} | no-more", _PEER, "Show one enrolled BGP peer: state, last error and reset reason, import/export policy and per-table prefix counts.", high_volume=True),
    "bgp_peer_received_routes": Query("show route receive-protocol bgp {address} | no-more", _PEER, "Show routes received from one enrolled BGP peer; empty output means no matching routes were reported.", high_volume=True, empty_allowed=True),
    "bgp_peer_advertised_routes": Query("show route advertising-protocol bgp {address} | no-more", _PEER, "Show routes advertised to one enrolled BGP peer; empty output means no matching routes were reported.", high_volume=True, empty_allowed=True),
    "ospf_neighbors_detail": Query("show ospf neighbor detail | no-more", NO_SLOTS, "Show OSPFv2 adjacencies with area, DR/BDR and uptime" + _ABSENT, high_volume=True, empty_allowed=True),
    "ospf_interface_detail": Query("show ospf interface {interface} detail | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv2 details for one enrolled logical interface" + _ABSENT, empty_allowed=True),
    "ospf_database": Query("show ospf database | no-more", NO_SLOTS, "Show the OSPFv2 link-state database" + _ABSENT, high_volume=True, empty_allowed=True),
    "ospfv3_neighbors_detail": Query("show ospf3 neighbor detail | no-more", NO_SLOTS, "Show OSPFv3 adjacencies with area, DR/BDR and uptime" + _ABSENT, high_volume=True, empty_allowed=True),
    "ospfv3_interface_detail": Query("show ospf3 interface {interface} detail | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv3 details for one enrolled logical interface" + _ABSENT, empty_allowed=True),
    "ospfv3_database": Query("show ospf3 database | no-more", NO_SLOTS, "Show the OSPFv3 link-state database" + _ABSENT, high_volume=True, empty_allowed=True),
    "route_lookup_instance": Query("show route table {instance}.inet.0 {address} detail | no-more", {**_INSTANCE, **IPV4_ADDRESS}, "Look up one enrolled IPv4 route in the IPv4 table of one enrolled routing instance."),
    "arp_table_instance": Query("show arp no-resolve vpn {instance} | no-more", _INSTANCE, "Show the IPv4 ARP table of one enrolled routing instance without name resolution; empty output means no entries were reported.", high_volume=True, empty_allowed=True),
    "ipv6_neighbors_instance": Query("show ipv6 neighbors vpn {instance} | no-more", _INSTANCE, "Show the IPv6 neighbor table of one enrolled routing instance; empty output means no entries were reported.", high_volume=True, empty_allowed=True),
    "bgp_summary_instance": Query("show bgp summary exact-instance {instance} | no-more", _INSTANCE, "Summarize BGP peers of exactly one enrolled routing instance.", high_volume=True),
    "firewall_filters": Query("show firewall | no-more", NO_SLOTS, "List firewall filters, packet and byte counters, and policers. Requires the Junos firewall permission.", high_volume=True),
    "firewall_filter": Query("show firewall filter {filter} | no-more", {"filter": Slot("firewall_filters", "junos_firewall_filter")}, "Read counters and policers for one enrolled firewall filter. Requires the Junos firewall permission."),
    FILTER_BINDING_QUERY: Query(FILTER_BINDING_COMMAND, _interface_slot("junos_filter_interface"), "Read explicitly configured IPv4 filter bindings for one enrolled logical interface. Requires config_access read and Junos configuration view permission. A successful empty output means there are no explicit bindings at the selected path.", empty_allowed=True),
}

SRX_QUERIES: dict[str, Query] = {
    "security_policies": Query("show security policies detail | no-more", NO_SLOTS, "Show SRX security policy details and actions.", high_volume=True, group="firewall"),
    "security_policy_hits": Query("show security policies hit-count | no-more", NO_SLOTS, "Show SRX security policy hit counts.", high_volume=True, group="firewall"),
    "security_match_policies": Query(
        "show security match-policies from-zone {from_zone} to-zone {to_zone} source-ip {src} destination-ip {dst} "
        "source-port {src_port} destination-port {dst_port} protocol {protocol} | no-more",
        {"from_zone": _ZONE, "to_zone": _ZONE, "src": _FLOW_ADDRESS, "dst": _FLOW_ADDRESS,
         "src_port": _FLOW_PORT, "dst_port": _FLOW_PORT, "protocol": Slot("ip_protocols", "ip_protocol")},
        "Find SRX policies matching an enrolled flow and zone pair. Use a numeric IP protocol.", group="firewall"),
    "security_flow_sessions": Query("show security flow session source-prefix {prefix} | no-more", {"prefix": Slot("lookup_prefixes", "lookup_prefix")}, "Show SRX sessions and their forward and reverse tuples for one enrolled source prefix.", high_volume=True, group="firewall"),
    "security_source_nat_rules": Query("show security nat source rule all | no-more", NO_SLOTS, "Show SRX source NAT rules, actions and translation hits.", high_volume=True, group="firewall"),
    "security_destination_nat_rules": Query("show security nat destination rule all | no-more", NO_SLOTS, "Show SRX destination NAT rules, actions and translation hits.", high_volume=True, group="firewall"),
    "chassis_cluster_status": Query("show chassis cluster status | no-more", NO_SLOTS, "Show SRX cluster node roles, redundancy groups and monitor failures.", group="firewall"),
    "chassis_cluster_interfaces": Query("show chassis cluster interfaces | no-more", NO_SLOTS, "Show SRX control, fabric and redundant interface status.", group="firewall"),
    "chassis_cluster_statistics": Query("show chassis cluster statistics | no-more", NO_SLOTS, "Show SRX control and fabric counters and service synchronization statistics.", group="firewall"),
    "ike_security_associations": Query("show security ike security-associations | no-more", NO_SLOTS, "Show SRX IKE peer and security association state.", high_volume=True, group="firewall"),
    "ipsec_security_associations": Query("show security ipsec security-associations detail | no-more", NO_SLOTS, "Show SRX IPsec tunnel names, peers and inbound/outbound security associations.", high_volume=True, group="firewall"),
    "ipsec_statistics": Query("show security ipsec statistics | no-more", NO_SLOTS, "Show aggregate SRX IPsec traffic and failure counters.", group="firewall"),
}

JUNOS_QUERIES = {**COMMON_QUERIES, **SRX_QUERIES}
G135_QUERIES = frozenset({"firewall_filters", "firewall_filter", FILTER_BINDING_QUERY, *SRX_QUERIES})

ELS_QUERIES: dict[str, Query] = {
    **COMMON_QUERIES,
    "mac_table_vlan": Query("show ethernet-switching table vlan-name {vlan} | no-more", _VLAN, "Show MAC entries for one enrolled VLAN name; empty output means no matching MAC entries were reported.", high_volume=True, empty_allowed=True),
    "vlan_details": Query("show vlans {vlan} extensive | no-more", _VLAN, "Show extensive information for one enrolled VLAN name."),
    "stp_interface_detail": Query("show spanning-tree interface {interface} detail | no-more", _interface_slot("junos_interface"), "Show spanning-tree detail for one enrolled interface."),
    "stp_interface_statistics": Query("show spanning-tree statistics interface {interface} | no-more", _interface_slot("junos_interface"), "Show spanning-tree counters for one enrolled interface."),
    "igmp_snooping_membership": Query("show igmp snooping membership | no-more", NO_SLOTS, "Show IGMP snooping multicast groups and associated interfaces.", high_volume=True),
    "igmp_snooping_interfaces": Query("show igmp snooping interface | no-more", NO_SLOTS, "Show IGMP snooping state and group counts by interface.", high_volume=True),
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
