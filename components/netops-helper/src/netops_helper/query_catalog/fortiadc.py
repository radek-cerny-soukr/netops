"""FortiADC 7.6.7 read queries: fixed status, resource, hardware, interface (one or all), routing, load-balancer, WAF, log and update-contract views."""

from __future__ import annotations

from .model import FORTIADC_INTERFACE, NO_SLOTS, Query, SequenceQuery, Slot


QUERIES: dict[str, Query] = {
    "certificate_inventory": Query(
        "get system certificate local",
        NO_SLOTS,
        "Inventory local, intermediate CA and CA certificates, expiry and SSL references from pinned "
        "FortiADC HTTPS, with ACME status from SSH.",
    ),
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
    # G32 ADC-C12: every interface in one read, measured on FortiADC-KVM 7.6.7 build0676 (VM220, 2026-11-17).
    "interface_list": Query(
        "get system interface",
        NO_SLOTS,
        "Show every configured interface with type, VDOM, IPv4 and IPv6 address, administrative status and "
        "allowed management access; it shows neither link state nor speed (nic_detail_all).",
        high_volume=True,
    ),
    "interface_state_all": Query(
        "diagnose netlink interface list",
        NO_SLOTS,
        "Show the kernel state of every interface, including VLAN, aggregate and virtual-server ports: MTU and "
        "the up and run flags; it shows neither addresses nor speed.",
        high_volume=True,
    ),
    "nic_detail_all": Query(
        "diagnose hardware get deviceinfo nic-detail",
        NO_SLOTS,
        "Show the driver, link speed, duplex, detected link, and receive and transmit counters of every physical "
        "network interface; over this read the per-port values are in the 'Settings for <port>' blocks, and the "
        "'Interface: <port>' lines with the counters follow after all of them.",
        high_volume=True,
    ),
    "interface_summary": SequenceQuery(
        "get system interface; diagnose hardware get deviceinfo nic-detail",
        NO_SLOTS,
        "Join configured IPv4, IPv6 and administrative status with detected link and speed in Mb/s by interface "
        "name. Missing source data is reported explicitly.",
        high_volume=True,
        commands=("get system interface", "diagnose hardware get deviceinfo nic-detail"),
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
    "slb_vs_overview": Query(
        "diagnose server-load-balance vs_stat vdom {vdom}",
        {"vdom": Slot("adc_vdoms", "fortiadc_vdom")},
        "Show availability, connections, RTT and throughput for every virtual server in one enrolled VDOM.",
        high_volume=True,
        pty=True,
    ),
    "slb_rs_stat": Query(
        "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server} rs {real_server}",
        {
            "vdom": Slot("adc_vdoms", "fortiadc_vdom"),
            "virtual_server": Slot("adc_virtual_servers", "fortiadc_virtual_server"),
            "real_server": Slot(None, "fortiadc_member_id"),
        },
        "Show connections, throughput and RTT of one numeric pool member ID of an enrolled virtual server.",
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
    "ha_standby_status": Query(
        "execute ha force failover-standby status",
        NO_SLOTS,
        "Show whether forced HA failover standby is set on this node; this read does not change the HA role.",
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
