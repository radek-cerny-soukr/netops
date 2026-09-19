"""Curated Fortinet FortiOS phase-1 diagnostic queries."""

from __future__ import annotations

from .model import (
    FORTIOS_INTERFACE,
    FORTIOS_PHYSICAL_INTERFACE,
    IPV4_ADDRESS,
    NO_SLOTS,
    SWITCH,
    Query,
)


QUERIES: dict[str, Query] = {
    "system_status": Query(
        "get system status",
        NO_SLOTS,
        "Show FortiOS version, system identity, and operating status.",
    ),
    "performance": Query(
        "get system performance status",
        NO_SLOTS,
        "Show system performance and resource utilization.",
    ),
    "ha_status": Query(
        "get system ha status",
        NO_SLOTS,
        "Show high-availability cluster status.",
    ),
    "session_stats": Query(
        "diagnose sys session stat",
        NO_SLOTS,
        "Show aggregate session table statistics.",
    ),
    "hardware_memory": Query(
        "diagnose hardware sysinfo memory",
        NO_SLOTS,
        "Show hardware memory utilization.",
    ),
    "disk_status": Query(
        "diagnose hardware deviceinfo disk",
        NO_SLOTS,
        "Show disk inventory and health information.",
    ),
    "physical_interfaces": Query(
        "get system interface physical",
        NO_SLOTS,
        "Show physical interface status.",
        high_volume=True,
    ),
    "interface_details": Query(
        "diagnose netlink interface list {interface}",
        FORTIOS_INTERFACE,
        "Show detailed state for one enrolled interface.",
    ),
    "interface_hardware": Query(
        "diagnose hardware deviceinfo nic {interface}",
        FORTIOS_PHYSICAL_INTERFACE,
        "Show hardware information for one enrolled interface.",
    ),
    "routing_table": Query(
        "get router info routing-table all",
        NO_SLOTS,
        "Show the IPv4 routing table.",
        high_volume=True,
    ),
    "route_lookup": Query(
        "get router info routing-table details {address}",
        IPV4_ADDRESS,
        "Show the IPv4 route for one enrolled address.",
    ),
    "route_protocols": Query(
        "get router info protocols",
        NO_SLOTS,
        "Show IPv4 routing protocol status.",
    ),
    "ipv6_route_protocols": Query(
        "get router info6 protocols",
        NO_SLOTS,
        "Show IPv6 routing protocol status.",
    ),
    "arp_table": Query(
        "get system arp",
        NO_SLOTS,
        "Show the IPv4 ARP table.",
        high_volume=True,
    ),
    "ipv6_neighbors": Query(
        "diagnose ipv6 neighbor-cache list",
        NO_SLOTS,
        "Show the IPv6 neighbor cache.",
        high_volume=True,
    ),
    "lldp_summary": Query(
        "diagnose lldp rx neighbor summary",
        NO_SLOTS,
        "Summarize received LLDP neighbors.",
        high_volume=True,
    ),
    "bridge_mac_table": Query(
        "diagnose netlink brctl name host {switch}",
        SWITCH,
        "Show the forwarding database for one enrolled software switch.",
        high_volume=True,
    ),
    "sdwan_health": Query(
        "diagnose sys sdwan health-check",
        NO_SLOTS,
        "Show SD-WAN health-check status.",
        high_volume=True,
    ),
    "ha_checksum": Query(
        "diagnose sys ha checksum cluster",
        NO_SLOTS,
        "Show HA synchronization checksums across the cluster.",
    ),
    "ha_history": Query(
        "diagnose sys ha history read",
        NO_SLOTS,
        "Show the high-availability event history.",
        high_volume=True,
    ),
    "ipsec_summary": Query(
        "get vpn ipsec tunnel summary",
        NO_SLOTS,
        "Summarize IPsec tunnel state.",
        high_volume=True,
    ),
    "ipsec_status": Query(
        "diagnose vpn ipsec status",
        NO_SLOTS,
        "Show aggregate IPsec subsystem status.",
    ),
    "bgp_summary": Query(
        "get router info bgp summary",
        NO_SLOTS,
        "Summarize IPv4 BGP peers and routes.",
        high_volume=True,
    ),
    "ipv6_bgp_summary": Query(
        "get router info6 bgp summary",
        NO_SLOTS,
        "Summarize IPv6 BGP peers and routes.",
        high_volume=True,
    ),
    "ospf_status": Query(
        "get router info ospf status",
        NO_SLOTS,
        "Show IPv4 OSPF process status.",
    ),
    "ipv6_ospf_status": Query(
        "get router info6 ospf status",
        NO_SLOTS,
        "Show IPv6 OSPF process status.",
    ),
    "ospf_neighbors": Query(
        "get router info ospf neighbor all",
        NO_SLOTS,
        "Show IPv4 OSPF neighbors.",
        high_volume=True,
    ),
    "ipv6_ospf_neighbors": Query(
        "get router info6 ospf neighbor all",
        NO_SLOTS,
        "Show IPv6 OSPF neighbors.",
        high_volume=True,
    ),
    "bfd_neighbors": Query(
        "get router info bfd neighbor",
        NO_SLOTS,
        "Show IPv4 BFD neighbors.",
        high_volume=True,
    ),
    "ipv6_bfd_neighbors": Query(
        "get router info6 bfd neighbor",
        NO_SLOTS,
        "Show IPv6 BFD neighbors.",
        high_volume=True,
    ),
    "ntp_status": Query(
        "diagnose sys ntp status",
        NO_SLOTS,
        "Show NTP synchronization status and configured servers.",
    ),
    "system_top": Query(
        "diagnose sys top 1 5 1",
        NO_SLOTS,
        "Show one fixed five-line snapshot of the busiest processes.",
    ),
    "autoupdate_status": Query(
        "diagnose autoupdate status",
        NO_SLOTS,
        "Show FortiGuard automatic-update status.",
    ),
    "autoupdate_versions": Query(
        "diagnose autoupdate versions",
        NO_SLOTS,
        "Show the installed FortiGuard package versions.",
        high_volume=True,
    ),
    "sslvpn_sessions": Query(
        "diagnose vpn ssl list",
        NO_SLOTS,
        "List active SSL VPN sessions.",
        high_volume=True,
    ),
    "sslvpn_statistics": Query(
        "diagnose vpn ssl statistics",
        NO_SLOTS,
        "Show aggregate SSL VPN statistics.",
    ),
    "firewall_auth_users": Query(
        "diagnose firewall auth list",
        NO_SLOTS,
        "List authenticated firewall users.",
        high_volume=True,
    ),
    "ips_filter_status": Query(
        "diagnose ips filter status",
        NO_SLOTS,
        "Show the IPS engine filter status.",
    ),
    "ips_anomaly_status": Query(
        "diagnose ips anomaly status",
        NO_SLOTS,
        "Show the IPS anomaly and DoS sensor status.",
    ),
    "av_outbreak_stats": Query(
        "diagnose antivirus outbreak-prevention statistics list",
        NO_SLOTS,
        "Show antivirus outbreak-prevention statistics.",
    ),
}
