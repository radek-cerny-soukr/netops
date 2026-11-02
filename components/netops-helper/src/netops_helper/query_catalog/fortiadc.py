"""FortiADC 7.6.7 read queries: fixed status, resource, hardware, interface, routing, load-balancer, WAF, log and update-contract views."""

from __future__ import annotations

from .model import FORTIADC_INTERFACE, NO_SLOTS, Query, Slot


QUERIES: dict[str, Query] = {
    "system_status": Query(
        "get system status",
        NO_SLOTS,
        "Show FortiADC version, system identity, and operating status.",
    ),
    "system_performance": Query(
        "get system performance",
        NO_SLOTS,
        "Show CPU usage, memory usage, system load, and uptime.",
    ),
    "vm_license": Query(
        "diagnose system vm",
        NO_SLOTS,
        "Show VM license validity, registration status, and licensed CPU and memory resources.",
    ),
    "interface_state": Query(
        "diagnose netlink interface list {interface}",
        FORTIADC_INTERFACE,
        "Show state, MTU, and packet, error, and drop counters of one enrolled interface; empty output means no interface state returned.",
        empty_allowed=True,
    ),
    "interface_counters": Query(
        "diagnose netlink device",
        NO_SLOTS,
        "Show receive and transmit byte, packet, error, and drop counters of all interfaces.",
    ),
    "routing_table": Query(
        "get router info routing-table all",
        NO_SLOTS,
        "Show all routing table entries.",
        high_volume=True,
        pty=True,
    ),
    "arp_table": Query(
        "diagnose netlink neighbor list",
        NO_SLOTS,
        "Show the IPv4 neighbor (ARP) table with hardware addresses and interfaces.",
        high_volume=True,
    ),
    "firewall_timeouts": Query(
        "get firewall global",
        NO_SLOTS,
        "Show global firewall session timeouts.",
    ),
    "tls_handshake_stats": Query(
        "execute ssl-handshake-n-record-statistics show virtual-server {virtual_server}",
        {"virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server")},
        "Show successful and failed TLS handshake and record counters of one enrolled virtual server.",
        pty=True,
    ),
    "tls_session_reuse": Query(
        "execute ssl-client-side-session-statistics show virtual-server {virtual_server}",
        {"virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server")},
        "Show TLS session ID and session ticket reuse counters of one enrolled virtual server.",
        pty=True,
    ),
    "dos_access_limit": Query(
        "execute dos get dos-access-limit {virtual_server}",
        {"virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server")},
        "Show the HTTP access-limit block-period count of one enrolled virtual server; empty output means no counter returned, not zero.",
        pty=True,
        empty_allowed=True,
    ),
    "dos_conn_limit": Query(
        "execute dos get dos-conn-limit {virtual_server}",
        {"virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server")},
        "Show the HTTP connection-flood block-period count of one enrolled virtual server; empty output means no counter returned, not zero.",
        pty=True,
        empty_allowed=True,
    ),
    "dos_req_limit": Query(
        "execute dos get dos-req-limit {virtual_server}",
        {"virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server")},
        "Show the HTTP request-flood block-period count of one enrolled virtual server; empty output means no counter returned, not zero.",
        pty=True,
        empty_allowed=True,
    ),
    "slb_load": Query(
        "diagnose server-load-balance slb_load",
        NO_SLOTS,
        "Show virtual servers with the status and weight of their real-server pool members.",
        high_volume=True,
        pty=True,
    ),
    "waf_signature_status": Query(
        "get security waf-signature-status",
        NO_SLOTS,
        "Show the installed WAF signature version and its update status.",
    ),
    "slb_vs_stat": Query(
        "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server}",
        {
            "vdom": Slot("adc_vdoms", "fortiadc_vdom"),
            "virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server"),
        },
        "Show availability, connections, requests, RTT and throughput of one enrolled virtual server and the health state of all members of its real-server pool.",
        high_volume=True,
        pty=True,
    ),
    "cpu_info": Query(
        "diagnose hardware get sysinfo cpu",
        NO_SLOTS,
        "Show the per-processor CPU model, flags, and cache details as listed in the Linux cpuinfo format.",
        high_volume=True,
    ),
    "slb_sessions": Query(
        "diagnose server-load-balance session list",
        NO_SLOTS,
        "Show active load-balancer sessions with client, virtual-server, local, and real-server address and port, protocol, service, state, byte counters, expiry, and virtual-server and real-server names.",
        high_volume=True,
    ),
    "persistence_sessions": Query(
        "diagnose server-load-balance persistence list",
        NO_SLOTS,
        "Show persistence entries with client, virtual-server, local, and real-server address and port, protocol, service, expiry, and virtual-server and real-server names.",
        high_volume=True,
    ),
    "nic_detail": Query(
        "diagnose hardware get deviceinfo nic-detail {interface}",
        FORTIADC_INTERFACE,
        "Show the driver, firmware, bus, link settings and speed, and receive and transmit counters of one enrolled network interface.",
    ),
    "waf_block_ip": Query(
        "execute waf block-ip list",
        NO_SLOTS,
        "Show IP addresses blocked by the WAF with the virtual server name and expiry.",
        high_volume=True,
    ),
    "log_list_traffic": Query(
        "execute log list-type tlog",
        NO_SLOTS,
        "Show the traffic log files by name with their size or count and last-modified time.",
        high_volume=True,
    ),
    "log_list_attack": Query(
        "execute log list-type alog",
        NO_SLOTS,
        "Show the attack log files by name with their size or count and last-modified time.",
        high_volume=True,
    ),
    "autoupdate_contract": Query(
        "execute autoupdate contract",
        NO_SLOTS,
        "Show the licensed update service contracts with serial number, contract expiry per service, support level, and support type descriptions.",
    ),
    "system_date": Query(
        "execute date",
        NO_SLOTS,
        "Read the current system date and time to check the appliance clock against log and certificate timestamps.",
    ),
    "log_files": Query(
        "execute log list-type all",
        NO_SLOTS,
        "List event, traffic, and security log files by type for presence, size, and timestamp review; this does not report remaining disk capacity.",
        high_volume=True,
    ),
    "lldp_neighbors": Query(
        "diagnose lldprx neighbor summary",
        NO_SLOTS,
        "Summarize directly connected LLDP neighbors by port, MAC/chassis, and system identity to diagnose cabling and topology issues.",
        high_volume=True,
        pty=True,
    ),
    "bgp_summary": Query(
        "get router info bgp summary",
        NO_SLOTS,
        "Show BGP neighbor state, uptime, and received-prefix counts for routing-session diagnosis.",
        pty=True,
    ),
    "bgp_neighbors": Query(
        "get router info bgp neighbors",
        NO_SLOTS,
        "Show detailed BGP neighbor state, timers, capabilities, and message counters for session troubleshooting.",
        high_volume=True,
        pty=True,
    ),
    "ospf_neighbors": Query(
        "get router info ospf neighbor",
        NO_SLOTS,
        "Show OSPF neighbor relationships to diagnose adjacency state on deployments using OSPF.",
        high_volume=True,
        pty=True,
    ),
    "ha_status": Query(
        "get system ha-status",
        NO_SLOTS,
        "Show HA mode, state, configuration sync, node and peer details, and monitor status.",
    ),
    "traffic_group_status": Query(
        "get system traffic-group-status brief",
        NO_SLOTS,
        "Show each traffic group's current and next device node; the brief view omits floating IP addresses. "
        "The FortiADC 7.6.7 Administration Guide (p. 246) describes traffic groups for the HA mode "
        "active-active-VRRP and names a predefined traffic group default; empty output means the device "
        "reports no traffic group. This was measured in active-passive mode (both roles) and in standalone "
        "mode, each time with an empty config system traffic-group section in the configuration. In "
        "active-active-VRRP empty output was not measured: check it against ha_status and the traffic group "
        "configuration.",
        pty=True,
        empty_allowed=True,
    ),
    "llb_policy": Query(
        "diagnose llb policy list",
        NO_SLOTS,
        "Show link-load-balancing policy diagnostics including policy index, route-table ID, ingress interface, destination, and service.",
        high_volume=True,
        pty=True,
    ),
}
