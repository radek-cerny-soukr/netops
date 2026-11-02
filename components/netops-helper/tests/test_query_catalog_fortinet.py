#!/usr/bin/env python3
"""Dependency-free contract tests for the Fortinet query catalogue."""

from __future__ import annotations

import re

from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.query_catalog.model import Query
from netops_helper.read_policy import _validate_query_command, render_read_query


# Exact volume rationale: device-wide interface, route, neighbor, and FDB tables,
# retained history, variable protocol peer/session/tunnel lists, and per-pool
# allocation lists can need continuation. Aggregate and inventory-bound detail stay False.
EXPECTED = {
    'route_cache': ('diagnose ip rtcache list', (), True),
    'ospf_database_brief_ipv4': ('get router info ospf database brief', (), True),
    'ospf_database_ipv6': ('get router info6 ospf database', (), True),
    "wifi_clients": ("diagnose wireless-controller wlac -c sta", (), True),
    "wifi_client_detail": ("diagnose wireless-controller wlac -d sta {mac}", (("mac", "wireless_clients", "fortios_station_mac"),), False),
    "wifi_access_points": ("diagnose wireless-controller wlac -c wtp", (), True),
    "wifi_ap_detail": ("diagnose wireless-controller wlac -d wtp", (), True),
    "wifi_ssid_mapping": ("diagnose wireless-controller wlac -c vap", (), True),
    "sdwan_interface_quality": ("diagnose sys sdwan intf-sla-log {interface}", (("interface", "interfaces", "fortios_interface"),), True),
    "dns_cache": ("diagnose test application dnsproxy 7", (), True),
    "ha_nonsync_checksum": ("diagnose sys ha checksum show-nonsync", (), True),
    "ha_sync_statistics": ("diagnose sys ha sync-stats", (), True),
    "dhcp_leases": ("execute dhcp lease-list {interface}", (("interface", "interfaces", "fortios_interface"),), True),
    "ipsec_tunnel_statistics": ("diagnose vpn tunnel stat", (), False),
    "ike_statistics": ("diagnose vpn ike stats", (), False),
    "nat_pool_usage": ("diagnose firewall ippool stats", (), False),
    "nat_pool_assignments": ("diagnose firewall ippool list nat-ip {pool}", (("pool", "nat_pools", "fortios_nat_pool"),), True),
    "fqdn_resolved_addresses": ("diagnose firewall fqdn list-ip", (), True),
    "fqdn_cache": ("diagnose test application dnsproxy 6", (), True),
    "sdwan_zone": ("diagnose sys sdwan zone", (), True),
    "policy_routes_ipv4": ("diagnose firewall proute list", (), True),
    "policy_routes_ipv6": ("diagnose firewall proute6 list", (), True),
    "policy_lookup_ipv4": (
        "diagnose firewall iprope lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}",
        (("device", "interfaces", "fortios_interface"),
         ("dst_ip", "addresses", "ipv4_address"),
         ("dst_port", "flow_ports", "flow_port"),
         ("pol_type", "policy_types", "fortios_policy_type"),
         ("protocol", "ip_protocols", "ip_protocol"),
         ("src_ip", "addresses", "ipv4_address"),
         ("src_port", "flow_ports", "flow_port")),
        False,
    ),
    "policy_lookup_ipv6": (
        "diagnose firewall iprope6 lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}",
        (("device", "interfaces", "fortios_interface"),
         ("dst_ip", "addresses", "ipv6_address"),
         ("dst_port", "flow_ports", "flow_port"),
         ("pol_type", "policy_types", "fortios_policy_type"),
         ("protocol", "ip_protocols", "ip_protocol"),
         ("src_ip", "addresses", "ipv6_address"),
         ("src_port", "flow_ports", "flow_port")),
        False,
    ),
    "fqdn_object_detail": ("diagnose firewall fqdn get-ip {name}", (("name", "firewall_addresses", "fortios_address_object"),), False),
    "lacp_detail": ("diagnose netlink aggregate name {aggregate} show", (("aggregate", "interfaces", "fortios_interface"),), False),
    "ike_object_counts": ("diagnose vpn ike counts", (), False),
    "ike_errors": ("diagnose vpn ike errors", (), False),

    "ping_options": ("execute ping-options view-settings", (), False),
    "traceroute_options": ("execute traceroute-options view-settings", (), False),
    "debug_state": ("diagnose debug info", (), True),
    "session_filter_state": ("diagnose sys session filter", (), False),
    "certificate_details": ("get vpn certificate local details {certificate}", (("certificate", "certificates", "certificate_name"),), False),
    'managed_switch_status': ('diagnose switch-controller switch-info status {managed_switch}', (('managed_switch', 'managed_switches', 'managed_switch_serial'),), False),
    'managed_switch_poe': ('diagnose switch-controller switch-info poe summary {managed_switch}', (('managed_switch', 'managed_switches', 'managed_switch_serial'),), False),
    'managed_switch_mac': ('diagnose switch-controller switch-info mac-table {managed_switch}', (('managed_switch', 'managed_switches', 'managed_switch_serial'),), True),
    'managed_switch_stacking': ('diagnose switch-controller switch-info stacking status {managed_switch}', (('managed_switch', 'managed_switches', 'managed_switch_serial'),), False),
    'managed_switch_lldp': ('diagnose switch-controller switch-info lldp neighbors-summary {managed_switch}', (('managed_switch', 'managed_switches', 'managed_switch_serial'),), True),
    "switch_loop_guard": ("diagnose switch-controller switch-info loop-guard {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_bpdu_guard": ("diagnose switch-controller switch-info bpdu-guard-status {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_flap_guard": ("diagnose switch-controller switch-info flapguard status {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_dhcp_snooping": ("diagnose switch-controller switch-info dhcp-snooping database {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_dhcp_bindings": ("diagnose switch-controller switch-info dhcp-snooping status {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), True),
    "switch_fan_health": ("diagnose switch-controller switch-info fan {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_source_guard": ("diagnose switch-controller switch-info ip-source-guard violations {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), True),
    "switch_lldp_port": ("diagnose switch-controller switch-info lldp neighbors-detail {managed_switch} {port}", (("managed_switch", "managed_switches", "managed_switch_serial"), ("port", "managed_switch_ports", "managed_switch_port")), False),
    "switch_mac_limit": ("diagnose switch-controller switch-info mac-limit-violations interface {managed_switch} {port}", (("managed_switch", "managed_switches", "managed_switch_serial"), ("port", "managed_switch_ports", "managed_switch_port")), False),
    "switch_mclag_icl": ("diagnose switch-controller switch-info mclag icl {managed_switch}", (("managed_switch", "managed_switches", "managed_switch_serial"),), False),
    "switch_trunk_status": ("diagnose switch-controller switch-info trunk status {managed_switch} {mclag_trunk}", (("managed_switch", "managed_switches", "managed_switch_serial"), ("mclag_trunk", "managed_switch_trunks", "managed_switch_trunk")), False),
    "switch_mclag_consistency": ("diagnose switch-controller switch-info mclag peer-consistency-check {managed_switch} {mclag_trunk}", (("managed_switch", "managed_switches", "managed_switch_serial"), ("mclag_trunk", "managed_switch_trunks", "managed_switch_trunk")), False),

    "system_status": ("get system status", (), False),
    "performance": ("get system performance status", (), False),
    "ha_status": ("get system ha status", (), False),
    "session_stats": ("diagnose sys session stat", (), False),
    "hardware_memory": ("diagnose hardware sysinfo memory", (), False),
    "conserve_state": ("diagnose hardware sysinfo conserve", (), False),
    "cpu_cores": ("diagnose hardware sysinfo cpu", (), False),
    "fortiguard_communication": ("diagnose sys service-communication", (), True),
    "disk_status": ("diagnose hardware deviceinfo disk", (), False),
    "physical_interfaces": ("get system interface physical", (), True),
    "interface_details": (
        "diagnose netlink interface list {interface}",
        (("interface", "interfaces", "fortios_interface"),),
        False,
    ),
    "interface_hardware": (
        "diagnose hardware deviceinfo nic {interface}",
        (("interface", "interfaces", "fortios_physical_interface"),),
        False,
    ),
    "routing_table": ("get router info routing-table all", (), True),
    "route_lookup": (
        "get router info routing-table details {address}",
        (("address", "addresses", "ipv4_address"),),
        False,
    ),
    "route_protocols": ("get router info protocols", (), False),
    "ipv6_route_protocols": ("get router info6 protocols", (), False),
    "arp_table": ("get system arp", (), True),
    "ipv6_neighbors": ("diagnose ipv6 neighbor-cache list", (), True),
    "lldp_summary": ("diagnose lldp rx neighbor summary", (), True),
    "bridge_mac_table": (
        "diagnose netlink brctl name host {switch}",
        (("switch", "switches", "switch"),),
        True,
    ),
    "sdwan_health": ("diagnose sys sdwan health-check", (), True),
    "sdwan_sla_history": ("diagnose sys sdwan sla-log {health_check} {member}", (("health_check", "sdwan_health_checks", "fortios_sdwan_health_check"), ("member", "sdwan_members", "fortios_sdwan_member")), True),
    "link_monitor_status": ("diagnose sys link-monitor status {monitor}", (("monitor", "link_monitors", "fortios_link_monitor"),), False),
    "sdwan_member_detail": ("diagnose sys sdwan member {member}", (("member", "sdwan_members", "fortios_sdwan_member"),), False),
    "sdwan_service_ipv4": ("diagnose sys sdwan service4 {rule}", (("rule", "sdwan_rules", "fortios_sdwan_rule"),), False),
    "sdwan_service_ipv6": ("diagnose sys sdwan service6 {rule}", (("rule", "sdwan_rules", "fortios_sdwan_rule"),), False),
    "sdwan_routes_ipv4": ("diagnose sys sdwan route {member}", (("member", "sdwan_members", "fortios_sdwan_member"),), True),
    "sdwan_routes_ipv6": ("diagnose sys sdwan route6 {member}", (("member", "sdwan_members", "fortios_sdwan_member"),), True),
    "ha_checksum": ("diagnose sys ha checksum cluster", (), False),
    "ha_history": ("diagnose sys ha history read", (), True),
    "ipsec_summary": ("get vpn ipsec tunnel summary", (), True),
    "ipsec_status": ("diagnose vpn ipsec status", (), False),
    "bgp_summary": ("get router info bgp summary", (), True),
    "bgp_advertised_ipv4": ("get router info bgp neighbors {peer} advertised-routes", (("peer", "addresses", "ipv4_address"),), True),
    "bgp_received_ipv4": ("get router info bgp neighbors {peer} received-routes", (("peer", "addresses", "ipv4_address"),), True),
    "bgp_accepted_ipv4": ("get router info bgp neighbors {peer} routes", (("peer", "addresses", "ipv4_address"),), True),
    "bgp_advertised_ipv6": ("get router info6 bgp neighbors {peer6} advertised-routes", (("peer6", "addresses", "ipv6_address"),), True),
    "bgp_received_ipv6": ("get router info6 bgp neighbors {peer6} received-routes", (("peer6", "addresses", "ipv6_address"),), True),
    "bgp_accepted_ipv6": ("get router info6 bgp neighbors {peer6} routes", (("peer6", "addresses", "ipv6_address"),), True),
    "ospf_interfaces_ipv4": ("get router info ospf interface", (), True),
    "ospf_interfaces_ipv6": ("get router info6 ospf interface", (), True),
    "ipv6_bgp_summary": ("get router info6 bgp summary", (), True),
    "ospf_status": ("get router info ospf status", (), False),
    "ipv6_ospf_status": ("get router info6 ospf status", (), False),
    "ospf_neighbors": ("get router info ospf neighbor all", (), True),
    "ipv6_ospf_neighbors": ("get router info6 ospf neighbor all", (), True),
    "bfd_neighbors": ("get router info bfd neighbor", (), True),
    "ipv6_bfd_neighbors": ("get router info6 bfd neighbor", (), True),
    "ntp_status": ("diagnose sys ntp status", (), False),
    "system_top": ("diagnose sys top 1 5 1", (), False),
    "autoupdate_status": ("diagnose autoupdate status", (), False),
    "autoupdate_versions": ("diagnose autoupdate versions", (), True),
    "sslvpn_sessions": ("diagnose vpn ssl list", (), True),
    "sslvpn_statistics": ("diagnose vpn ssl statistics", (), False),
    "firewall_auth_users": ("diagnose firewall auth list", (), True),
    "ips_filter_status": ("diagnose ips filter status", (), False),
    "ips_anomaly_status": ("diagnose ips anomaly status", (), False),
    "av_outbreak_stats": (
        "diagnose antivirus outbreak-prevention statistics list",
        (),
        False,
    ),
}

CONTROL_OR_SHELL = re.compile(r"[\x00-\x1f\x7f;&|$<>\x60]")
FORBIDDEN_TERMS = (
    "config",
    "export",
    "backup",
    "debug",
    "sniffer",
    "support",
    "execute",
)


def _slots(query: Query) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        sorted(
            (name, slot.inventory, slot.kind)
            for name, slot in query.slots.items()
        )
    )


def test_exact_catalogue_contract() -> None:
    actual = {
        name: (query.command, _slots(query), query.high_volume)
        for name, query in QUERIES.items()
    }
    assert actual == EXPECTED
    assert all(isinstance(query, Query) for query in QUERIES.values())


def test_switch_dhcp_bindings_is_per_switch_status_read() -> None:
    query = QUERIES["switch_dhcp_bindings"]
    assert query.command == "diagnose switch-controller switch-info dhcp-snooping status {managed_switch}"
    assert _slots(query) == (("managed_switch", "managed_switches", "managed_switch_serial"),)
    assert query.high_volume is True

    serial = "S124FPTF23000001"
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(
            platform,
            "switch_dhcp_bindings",
            {"managed_switch": serial},
            {"managed_switches": (serial,)},
        )
        assert normalized == "fortinet"
        assert rendered == f"diagnose switch-controller switch-info dhcp-snooping status {serial}"

    for value, enrolled in (
        ("S124FPTF23000001", ("S00000000000000",)),
        ("all", ("all",)),
        ("S124FPTF23000001;clear", ("S124FPTF23000001;clear",)),
    ):
        try:
            render_read_query(
                "fortinet",
                "switch_dhcp_bindings",
                {"managed_switch": value},
                {"managed_switches": enrolled},
            )
        except ValueError:
            continue
        raise AssertionError("DHCP binding read escaped per-switch enrollment or validation")


def test_switch_fan_health_is_per_switch_fan_status() -> None:
    query = QUERIES["switch_fan_health"]
    assert query.command == "diagnose switch-controller switch-info fan {managed_switch}"
    assert _slots(query) == (("managed_switch", "managed_switches", "managed_switch_serial"),)
    assert query.high_volume is False

    serial = "S124FPTF23000001"
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(
            platform,
            "switch_fan_health",
            {"managed_switch": serial},
            {"managed_switches": (serial,)},
        )
        assert normalized == "fortinet"
        assert rendered == f"diagnose switch-controller switch-info fan {serial}"

    for value, enrolled in (("all", ("all",)), ("S124FPTF23000001", ("S00000000000000",))):
        try:
            render_read_query(
                "fortinet",
                "switch_fan_health",
                {"managed_switch": value},
                {"managed_switches": enrolled},
            )
        except ValueError:
            continue
        raise AssertionError("fan status read escaped per-switch enrollment or validation")


def test_nat_pool_assignments_are_scoped_to_an_enrolled_pool() -> None:
    query = QUERIES["nat_pool_assignments"]
    assert query.command == "diagnose firewall ippool list nat-ip {pool}"
    assert _slots(query) == (("pool", "nat_pools", "fortios_nat_pool"),)
    assert query.high_volume is True

    normalized, rendered = render_read_query(
        "fortinet", "nat_pool_assignments", {"pool": "pool-east"},
        {"nat_pools": ("pool-east",)},
    )
    assert normalized == "fortinet"
    assert rendered == "diagnose firewall ippool list nat-ip pool-east"

    try:
        render_read_query(
            "fortinet", "nat_pool_assignments", {"pool": "pool-east"},
            {"nat_pools": ("pool-west",)},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("NAT pool read escaped exact inventory enrollment")


def test_commands_are_narrow_read_only_cli() -> None:
    commands = {query.command for query in QUERIES.values()}
    for command in commands:
        if command in {
            "execute ping-options view-settings",
            "execute dhcp lease-list {interface}",
            "execute traceroute-options view-settings",
            "diagnose debug info",
        }:
            continue
        assert command.startswith(("get ", "diagnose "))
        assert CONTROL_OR_SHELL.search(command) is None
        assert "\\" not in command
        lowered = command.lower()
        assert not any(term in lowered for term in FORBIDDEN_TERMS)

    assert "diagnose vpn ike gateway list" not in commands
    assert "diagnose vpn tunnel list" not in commands
    assert {command for command in commands if " ike " in command} == {
        "diagnose vpn ike counts", "diagnose vpn ike errors", "diagnose vpn ike stats",
    }
    assert all("tunnel list" not in command.lower() for command in commands)



def test_state_views_do_not_authorize_nearby_mutations() -> None:
    for command in (
        "execute ping-options reset", "execute ping-options repeat-count 0",
        "execute ping-options interface port1", "execute ping 192.0.2.1",
        "execute traceroute-options reset", "execute traceroute-options queries 1",
        "diagnose vpn tunnel stat flush",
        "execute dhcp lease-clear all",
        "execute traceroute 192.0.2.1", "diagnose debug enable",
        "diagnose debug disable", "diagnose debug reset",
        "diagnose debug application authd -1", "diagnose debug flow trace start 10",
        "diagnose sys session filter clear", "diagnose sys session filter src 192.0.2.1",
        "diagnose switch-controller switch-info dhcp-snooping database S124FPTF23000001 clear",
        "execute ping-options view-settings extra", "diagnose debug info;diagnose debug enable",
    ):
        try:
            _validate_query_command("fortinet", command)
        except RuntimeError:
            continue
        raise AssertionError("a state-view grant authorized a nearby mutation")



def test_interface_kinds_are_bounded_and_inventory_exact() -> None:
    accepted = (
        ("interface_details", "port1"),
        ("interface_details", "wan1"),
        ("interface_hardware", "mgmt"),
        ("interface_hardware", "internal7"),
    )
    for query, value in accepted:
        _, rendered = render_read_query(
            "fortinet",
            query,
            {"interface": value},
            {"interfaces": (value,)},
        )
        assert rendered.endswith(value)

    rejected = (
        "all",
        "ALL",
        "any",
        "none",
        "clear",
        "list",
        "packet-rate",
        "speed-test",
        "speed-test-result",
        "speed-test-result-clear",
        "speed-test-shaping-reset",
        "speed-test-tunnel",
        "port 1",
        "port/1",
        "abcdefghijklmnop",
    )
    for value in rejected:
        try:
            render_read_query(
                "fortinet",
                "interface_details",
                {"interface": value},
                {"interfaces": (value,)},
            )
        except ValueError:
            continue
        raise AssertionError(f"unsafe FortiOS interface was accepted: {value!r}")

    try:
        render_read_query(
            "fortinet",
            "interface_details",
            {"interface": "wan1"},
            {"interfaces": ("port1",)},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("non-enrolled FortiOS interface was accepted")


def test_policy_lookup_flows_are_family_bound_and_exactly_enrolled() -> None:
    cases = (
        (
            "policy_lookup_ipv4", "192.0.2.10", "198.51.100.10",
            "diagnose firewall iprope lookup",
        ),
        (
            "policy_lookup_ipv6", "2001:db8::10", "2001:db8::20",
            "diagnose firewall iprope6 lookup",
        ),
    )
    for query, source, destination, command in cases:
        parameters = {
            "src_ip": source, "src_port": "40000", "dst_ip": destination,
            "dst_port": "443", "protocol": "6", "device": "port2",
            "pol_type": "policy",
        }
        inventory = {
            "addresses": (source, destination), "flow_ports": ("40000", "443"),
            "ip_protocols": ("6",), "interfaces": ("port2",),
            "policy_types": ("policy",),
        }
        assert QUERIES[query].high_volume is False
        for platform in ("fortinet", "fortios"):
            normalized, rendered = render_read_query(
                platform, query, parameters, inventory,
            )
            assert normalized == "fortinet"
            assert rendered == (
                command + " " + source + " 40000 " + destination
                + " 443 6 port2 policy"
            )

    def reject(query, parameters, inventory):
        try:
            render_read_query("fortinet", query, parameters, inventory)
        except ValueError:
            return
        raise AssertionError("invalid policy lookup tuple was accepted")

    for query, source, destination, command in cases:
        base = {
            "src_ip": source, "src_port": "40000", "dst_ip": destination,
            "dst_port": "443", "protocol": "6", "device": "port2",
            "pol_type": "policy",
        }
        inventory = {
            "addresses": (source, destination), "flow_ports": ("40000", "443"),
            "ip_protocols": ("6",), "interfaces": ("port2",),
            "policy_types": ("policy",),
        }
        missing = dict(base)
        missing.pop("protocol")
        reject(query, missing, inventory)
        unenrolled = dict(base)
        unenrolled["dst_port"] = "444"
        reject(query, unenrolled, inventory)
        for field, value, category in (
            ("src_port", "65536", "flow_ports"),
            ("src_port", "-1", "flow_ports"),
            ("src_port", "040000", "flow_ports"),
            ("src_port", "40000;show", "flow_ports"),
            ("protocol", "256", "ip_protocols"),
            ("protocol", "06", "ip_protocols"),
            ("protocol", "6;show", "ip_protocols"),
            ("pol_type", "all", "policy_types"),
        ):
            bad = dict(base)
            bad[field] = value
            bad_inventory = dict(inventory)
            bad_inventory[category] = bad_inventory[category] + (value,)
            reject(query, bad, bad_inventory)
        wrong_ip = dict(base)
        wrong_ip["src_ip"] = "2001:db8::1" if query.endswith("ipv4") else "192.0.2.1"
        wrong_inventory = dict(inventory)
        wrong_inventory["addresses"] = wrong_inventory["addresses"] + (wrong_ip["src_ip"],)
        reject(query, wrong_ip, wrong_inventory)

    boundary_parameters = {
        "src_ip": "192.0.2.10", "src_port": "0", "dst_ip": "198.51.100.10",
        "dst_port": "65535", "protocol": "255", "device": "port2",
        "pol_type": "proxy",
    }
    boundary_inventory = {
        "addresses": ("192.0.2.10", "198.51.100.10"),
        "flow_ports": ("0", "65535"), "ip_protocols": ("255",),
        "interfaces": ("port2",), "policy_types": ("proxy",),
    }
    assert render_read_query(
        "fortinet", "policy_lookup_ipv4", boundary_parameters, boundary_inventory,
    )[1] == (
        "diagnose firewall iprope lookup 192.0.2.10 0 198.51.100.10 65535 255 port2 proxy"
    )


def test_fqdn_object_detail_is_inventory_bound() -> None:
    query = QUERIES["fqdn_object_detail"]
    assert query.command == "diagnose firewall fqdn get-ip {name}"
    assert _slots(query) == (("name", "firewall_addresses", "fortios_address_object"),)
    assert query.high_volume is False
    value = "api.example"
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(
            platform, "fqdn_object_detail", {"name": value},
            {"firewall_addresses": (value,)},
        )
        assert normalized == "fortinet"
        assert rendered == "diagnose firewall fqdn get-ip api.example"
    for parameters, inventory in (
        ({"name": value}, {"firewall_addresses": ("other.example",)}),
        ({"name": "api.example;clear"}, {"firewall_addresses": ("api.example;clear",)}),
        ({}, {"firewall_addresses": (value,)}),
    ):
        try:
            render_read_query("fortinet", "fqdn_object_detail", parameters, inventory)
        except ValueError:
            pass
        else:
            raise AssertionError("FQDN object read escaped exact enrollment or parameter validation")


def test_lacp_detail_is_fixed_read_only_and_inventory_bound() -> None:
    query = QUERIES["lacp_detail"]
    assert query.command == "diagnose netlink aggregate name {aggregate} show"
    assert _slots(query) == (("aggregate", "interfaces", "fortios_interface"),)
    assert query.high_volume is False
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(
            platform, "lacp_detail", {"aggregate": "port1"},
            {"interfaces": ("port1",)},
        )
        assert normalized == "fortinet"
        assert rendered == "diagnose netlink aggregate name port1 show"
    for value in ("all", "clear", "port1 show", "port1;clear", "a" * 16):
        try:
            render_read_query(
                "fortinet", "lacp_detail", {"aggregate": value},
                {"interfaces": (value,)},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("invalid aggregate interface was accepted")
    try:
        render_read_query(
            "fortinet", "lacp_detail", {"aggregate": "port1"},
            {"interfaces": ("port2",)},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("unenrolled aggregate interface was accepted")
    try:
        _validate_query_command(
            "fortinet", "diagnose netlink aggregate name port1 clear",
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("nearby LACP clear command was accepted")


def test_process_snapshot_is_pinned_to_one_iteration() -> None:
    assert QUERIES["system_top"].command == "diagnose sys top 1 5 1"
    _validate_query_command("fortinet", "diagnose sys top 1 5 1")
    rejected = (
        "diagnose sys top",
        "diagnose sys top 1",
        "diagnose sys top 1 5",
        "diagnose sys top 1 5 2",
        "diagnose sys top 1 5 0",
        "diagnose sys top 5 20 1",
        "diagnose sys top-mem",
    )
    for command in rejected:
        try:
            _validate_query_command("fortinet", command)
        except RuntimeError:
            continue
        raise AssertionError(f"unpinned FortiOS process snapshot was accepted: {command!r}")


def test_descriptions_are_present_and_ascii() -> None:
    for query in QUERIES.values():
        assert query.description
        assert query.description.endswith(".")
        query.description.encode("ascii")


def test_sdwan_selected_ids_are_bounded_and_enrolled() -> None:
    cases = (
        ("sdwan_member_detail", "member", "sdwan_members", 512),
        ("sdwan_routes_ipv4", "member", "sdwan_members", 512),
        ("sdwan_routes_ipv6", "member", "sdwan_members", 512),
        ("sdwan_service_ipv4", "rule", "sdwan_rules", 4000),
        ("sdwan_service_ipv6", "rule", "sdwan_rules", 4000),
    )
    for query, slot, category, maximum in cases:
        for value in ("1", str(maximum)):
            for platform in ("fortinet", "fortios"):
                normalized, command = render_read_query(
                    platform, query, {slot: value}, {category: (value,)},
                )
                assert normalized == "fortinet"
                assert command == QUERIES[query].command.format_map({slot: value})
        for value in ("0", str(maximum + 1), "01", "-1", "all", "1 2", "1;clear"):
            try:
                render_read_query("fortinet", query, {slot: value}, {category: (value,)})
            except ValueError:
                pass
            else:
                raise AssertionError("invalid selected SD-WAN identifier was accepted")
        try:
            render_read_query("fortinet", query, {slot: "2"}, {category: ("1",)})
        except ValueError:
            pass
        else:
            raise AssertionError("unenrolled SD-WAN identifier was accepted")


def test_named_monitor_reads_are_bounded_and_enrolled() -> None:
    for query, slot, category, base_parameters, base_inventory in (
        ("sdwan_sla_history", "health_check", "sdwan_health_checks",
         {"member": "1"},
         {"sdwan_members": ("1",)}),
        ("link_monitor_status", "monitor", "link_monitors", {}, {}),
    ):
        for value in ("PingSLA", "a" * 35):
            parameters = {**base_parameters, slot: value}
            inventory = {**base_inventory, category: (value,)}
            for platform in ("fortinet", "fortios"):
                normalized, command = render_read_query(platform, query, parameters, inventory)
                assert normalized == "fortinet"
                assert command == QUERIES[query].command.format_map(parameters)
        invalid = ("Ping SLA", "a" * 36, "a;clear", '"PingSLA"')
        if query == "link_monitor_status":
            invalid += ("all", "ALL")
        for value in invalid:
            try:
                render_read_query(
                    "fortinet", query, {**base_parameters, slot: value},
                    {**base_inventory, category: (value,)},
                )
            except ValueError:
                pass
            else:
                raise AssertionError("invalid monitor name was accepted")
        try:
            render_read_query(
                "fortinet", query, {**base_parameters, slot: "PingSLA"},
                {**base_inventory, category: ("OtherMonitor",)},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unenrolled monitor name was accepted")
    try:
        render_read_query(
            "fortinet", "sdwan_sla_history",
            {"health_check": "PingSLA", "member": "1"},
            {"sdwan_health_checks": ("PingSLA",), "sdwan_members": ()},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("SLA history escaped enrolled member scope")


def test_sla_history_uses_two_argument_form_without_child_interface() -> None:
    inventory = {"sdwan_health_checks": ("PingSLA",), "sdwan_members": ("1",), "interfaces": ("wan1",)}
    _, command = render_read_query("fortinet", "sdwan_sla_history", {"health_check": "PingSLA", "member": "1"}, inventory)
    assert command == "diagnose sys sdwan sla-log PingSLA 1"
    try:
        render_read_query(
            "fortinet", "sdwan_sla_history",
            {"health_check": "PingSLA", "member": "1", "interface": "wan1"}, inventory,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("SLA history accepted a child interface argument")


def test_bgp_peer_reads_are_family_bound_and_enrolled() -> None:
    for family, slot, peer, other_peer, wrong_family in (
        ("ipv4", "peer", "192.0.2.20", "192.0.2.21", "2001:db8::20"),
        ("ipv6", "peer6", "2001:db8::20", "2001:db8::21", "192.0.2.20"),
    ):
        for action in ("advertised", "received", "accepted"):
            query = f"bgp_{action}_{family}"
            for platform in ("fortinet", "fortios"):
                normalized, command = render_read_query(
                    platform, query, {slot: peer}, {"addresses": (peer,)},
                )
                assert normalized == "fortinet"
                assert command == QUERIES[query].command.format_map({slot: peer})
            for candidate, enrolled in (
                (wrong_family, wrong_family), (peer, other_peer), ("all", "all"),
            ):
                try:
                    render_read_query(
                        "fortinet", query, {slot: candidate}, {"addresses": (enrolled,)},
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("BGP read escaped peer family/enrollment scope")


def test_fixed_nat_fqdn_ike_reads_require_exact_commands() -> None:
    for name in ("nat_pool_usage", "fqdn_resolved_addresses", "policy_routes_ipv4", "policy_routes_ipv6", "ike_object_counts", "ike_errors", "ike_statistics", "route_cache", "ospf_database_brief_ipv4", "ospf_database_ipv6"):
        command, _, _ = EXPECTED[name]
        for platform in ("fortinet", "fortios"):
            normalized, rendered = render_read_query(platform, name, {}, {})
            assert normalized == "fortinet"
            assert rendered == command
        try:
            render_read_query("fortinet", name, {"name": "other"}, {})
        except ValueError:
            pass
        else:
            raise AssertionError("fixed diagnostic accepted a selector")
        for changed in (command + " clear", command + " reset", command + " extra"):
            try:
                _validate_query_command("fortinet", changed)
            except RuntimeError:
                pass
            else:
                raise AssertionError("fixed diagnostic accepted trailing arguments")
    for command in (
        "diagnose firewall ippool reset-log-stats",
        "diagnose firewall fqdn clear",
        "diagnose firewall proute clear",
        "diagnose firewall proute list 1",
        "diagnose firewall proute6 clear",
        "diagnose firewall proute6 list 1",
        "diagnose vpn ike restart",
        "diagnose vpn ike gateway clear",
        "diagnose vpn ike secrets",
    ):
        try:
            _validate_query_command("fortinet", command)
        except RuntimeError:
            pass
        else:
            raise AssertionError("fixed diagnostic authorized a neighboring operation")


def test_dhcp_leases_are_limited_to_an_enrolled_interface() -> None:
    inventory = {"interfaces": ("port2",)}
    normalized, command = render_read_query(
        "fortios", "dhcp_leases", {"interface": "port2"}, inventory,
    )
    assert normalized == "fortinet"
    assert command == "execute dhcp lease-list port2"
    for parameters in ({}, {"interface": "port3"}, {"interface": "port2;reboot"}, {"interface": "port2", "action": "clear"}):
        try:
            render_read_query("fortinet", "dhcp_leases", parameters, inventory)
        except ValueError:
            pass
        else:
            raise AssertionError("DHCP lease query escaped enrolled interface scope")

def test_wireless_clients_is_an_unfiltered_high_volume_list() -> None:
    query = QUERIES["wifi_clients"]
    assert query.command == "diagnose wireless-controller wlac -c sta"
    assert query.high_volume is True
    assert _slots(query) == ()
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(platform, "wifi_clients", {}, {})
        assert normalized == "fortinet"
        assert rendered == "diagnose wireless-controller wlac -c sta"
    try:
        render_read_query("fortinet", "wifi_clients", {"mac": "00:00:5e:00:53:01"}, {})
    except ValueError:
        pass
    else:
        raise AssertionError("unfiltered station list accepted an extra MAC argument")

def test_wireless_station_detail_is_an_exactly_enrolled_mac_read() -> None:
    mac = "00:00:5e:00:53:01"
    name = "wifi_client_detail"
    command = "diagnose wireless-controller wlac -d sta " + mac
    query = QUERIES[name]
    assert query.high_volume is False
    assert _slots(query) == (("mac", "wireless_clients", "fortios_station_mac"),)
    for platform in ("fortinet", "fortios"):
        normalized, rendered = render_read_query(platform, name, {"mac": mac}, {"wireless_clients": (mac,)})
        assert normalized == "fortinet"
        assert rendered == command
    for value, enrolled in (
        ("02-00-00-00-00-01", (mac,)),
        ("00:00:5e:00:53:01;reset", ("00:00:5e:00:53:01;reset",)),
        ("00:00:5e:00:53:01\nclear", ("00:00:5e:00:53:01\nclear",)),
        ("00:00:5e:00:53:02", (mac,)),
    ):
        try:
            render_read_query("fortinet", name, {"mac": value}, {"wireless_clients": enrolled})
        except ValueError:
            pass
        else:
            raise AssertionError("station detail escaped strict syntax or exact enrollment")
    try:
        render_read_query("fortinet", name, {}, {"wireless_clients": (mac,)})
    except ValueError:
        pass
    else:
        raise AssertionError("station detail accepted a missing selector")

def test_sdwan_interface_quality_is_bound_to_enrolled_interface() -> None:
    query = QUERIES["sdwan_interface_quality"]
    assert query.command == "diagnose sys sdwan intf-sla-log {interface}"
    assert _slots(query) == (("interface", "interfaces", "fortios_interface"),)
    assert query.high_volume is True

    normalized, rendered = render_read_query(
        "fortinet", "sdwan_interface_quality", {"interface": "wan1"},
        {"interfaces": ("wan1",)},
    )
    assert normalized == "fortinet"
    assert rendered == "diagnose sys sdwan intf-sla-log wan1"

    try:
        render_read_query(
            "fortinet", "sdwan_interface_quality", {"interface": "wan1"},
            {"interfaces": ("wan2",)},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("interface quality read escaped exact interface enrollment")
def main() -> None:
    test_dhcp_leases_are_limited_to_an_enrolled_interface()
    test_fixed_nat_fqdn_ike_reads_require_exact_commands()
    test_exact_catalogue_contract()
    test_commands_are_narrow_read_only_cli()
    test_state_views_do_not_authorize_nearby_mutations()
    test_interface_kinds_are_bounded_and_inventory_exact()
    test_policy_lookup_flows_are_family_bound_and_exactly_enrolled()
    test_fqdn_object_detail_is_inventory_bound()
    test_lacp_detail_is_fixed_read_only_and_inventory_bound()
    test_process_snapshot_is_pinned_to_one_iteration()
    test_descriptions_are_present_and_ascii()
    test_sdwan_selected_ids_are_bounded_and_enrolled()
    test_named_monitor_reads_are_bounded_and_enrolled()
    test_bgp_peer_reads_are_family_bound_and_enrolled()
    test_sdwan_interface_quality_is_bound_to_enrolled_interface()
    test_wireless_clients_is_an_unfiltered_high_volume_list()
    test_wireless_station_detail_is_an_exactly_enrolled_mac_read()
    print("fortinet query catalogue tests: ok")


if __name__ == "__main__":
    main()


def test_fqdn_cache_is_exact_fixed_read_only_command() -> None:
    normalized, command = render_read_query("fortinet", "fqdn_cache", {}, {})
    assert normalized == "fortinet"
    assert command == "diagnose test application dnsproxy 6"
    try:
        render_read_query("fortinet", "fqdn_cache", {"level": "7"}, {})
    except ValueError:
        pass
    else:
        raise AssertionError("fixed FQDN cache dump accepted a selector")


def test_sdwan_zone_is_exact_fixed_read_only_command() -> None:
    normalized, command = render_read_query("fortinet", "sdwan_zone", {}, {})
    assert normalized == "fortinet"
    assert command == "diagnose sys sdwan zone"
    try:
        render_read_query("fortinet", "sdwan_zone", {"zone": "1"}, {})
    except ValueError:
        pass
    else:
        raise AssertionError("fixed SD-WAN zone dump accepted a selector")


def test_managed_switch_port_queries_require_two_enrolled_slots() -> None:
    serial = "S124FPTF23000001"
    for query in ("switch_lldp_port", "switch_mac_limit"):
        parameters = {"managed_switch": serial, "port": "port1"}
        inventory = {
            "managed_switches": (serial,),
            "managed_switch_ports": ("port1",),
        }
        normalized, rendered = render_read_query("fortinet", query, parameters, inventory)
        assert normalized == "fortinet"
        assert rendered == QUERIES[query].command.format_map(parameters)
        try:
            render_read_query(
                "fortinet", query, parameters,
                {**inventory, "managed_switch_ports": ("port2",)},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unenrolled managed switch port was accepted")


def test_switch_guard_descriptions_match_measured_802_output() -> None:
    settings = QUERIES["switch_dhcp_snooping"].description
    assert "snooping-enabled VLANs" in settings
    assert "trusted and untrusted ports" in settings
    assert "switch_dhcp_bindings" in settings
    bindings = QUERIES["switch_dhcp_bindings"].description
    assert "MAC address, VLAN, client IP" in bindings and "port" in bindings
    assert "dhcp_bindings" in bindings
    source_guard = QUERIES["switch_source_guard"].description
    assert "violation logging is disabled or its timer is zero" in source_guard
    assert "does not show that no traffic was dropped" in source_guard
    assert "learning-limit above 0" in QUERIES["switch_mac_limit"].description
