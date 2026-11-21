#!/usr/bin/env python3
"""Dependency-free contract tests for the Extreme query catalogue."""

from __future__ import annotations

import re

from netops_helper.query_catalog.extreme import QUERIES
from netops_helper.query_catalog.model import Query


# Exact volume rationale: history and process output, device-wide port, neighbor,
# forwarding, and VLAN tables, scoped ARP and FDB tables, and global LAG, LACP,
# and STP instance lists can need continuation. Single-port details stay False.
EXPECTED = {
    'access_lists': ('show access-list', (), True),
    'policies': ('show policy detail', (), True),
    'policy_details': ('show policy {policy}', (('policy', None, 'acl_policy'),), True),
    'dhcp_server': ('show dhcp-server vlan {vlan}', (('vlan', 'vlans', 'vlan_name'),), True),
    'bootprelay': ('show bootprelay', (), False),
    'bootprelay_configuration': ('show bootprelay configuration', (), True),
    'radius': ('show radius', (), True),
    'tacacs': ('show tacacs', (), True),
    'accounts': ('show accounts', (), True),
    'netlogin': ('show netlogin', (), True),
    'netlogin_port': ('show netlogin port {interface}', (('interface', 'interfaces', 'extreme_physical_port'),), True),
    'dns_client': ('show dns-client', (), False),
    'dns_lookup': ('nslookup {name}', (('name', None, 'diagnostic_dns_name'),), False),
    'management': ('show management', (), True),
    'snmp_engine': ('show snmpv3 engine-info', (), False),
    'snmp_targets': ('show snmpv3 target-addr', (), True),
    'dhcp_snooping': ('show ip-security dhcp-snooping {vlan}', (('vlan', 'vlans', 'vlan_name'),), True),
    'dhcp_snooping_violations': ('show ip-security dhcp-snooping violations vlan {vlan}', (('vlan', 'vlans', 'vlan_name'),), True),
    'mac_address': ('show fdb {mac}', (('mac', None, 'mac_literal'),), True),
    'mac_vlan': ('show fdb vlan {vlan_id}', (('vlan_id', None, 'vlan_id'),), True),
    'arp_vlan': ('show iparp vlan {vlan_id}', (('vlan_id', None, 'vlan_id'),), True),
    "port_utilization": ("show ports {interface} utilization bandwidth", (("interface", "interfaces", "extreme_physical_port"),), False),
    "port_packets": ("show ports {interface} utilization packets", (("interface", "interfaces", "extreme_physical_port"),), False),
    "lacp_member": ("show lacp member-port {interface} detail", (("interface", "interfaces", "extreme_physical_port"),), False),
    "stp_domain_ports": ("show stpd {domain} ports", (("domain", "services", "service"),), True),
    "stp_port_detail": ("show stpd {domain} ports {interface} detail", (("domain", "services", "service"), ("interface", "interfaces", "extreme_physical_port")), False),
    "port_qos": ("show ports {interface} qosmonitor no-refresh", (("interface", "interfaces", "extreme_physical_port"),), False),
    "port_qos_drops": ("show ports {interface} qosmonitor congestion no-refresh", (("interface", "interfaces", "extreme_physical_port"),), False),
    "igmp_snooping": ("show igmp snooping", (), True),
    "igmp_groups": ("show igmp group", (), True),
    "ipconfig_ipv6": ("show ipconfig ipv6", (), True),

    "lag_summary": ("show sharing", (), True),
    'vlan_detail': ('show vlan detail', (), True),
    'vlan_details': ('show vlan {vlan}', (('vlan', 'vlans', 'vlan_name'),), True),
    'dhcp_snooping_entries': ('show ip-security dhcp-snooping entries vlan {vlan}', (('vlan', 'vlans', 'vlan_name'),), True),

    "switch": ("show switch", (), False),
    "version": ("show version", (), False),
    "memory": ("show memory", (), False),
    "cpu_monitoring": ("show cpu-monitoring", (), True),
    "processes": ("show process", (), True),
    "diagnostics": ("show diagnostics", (), False),
    "temperature": ("show temperature", (), False),
    "fans": ("show fans", (), False),
    "power": ("show power", (), False),
    "ports": ("show ports no-refresh", (), True),
    "ports_configuration": (
        "show ports configuration no-refresh",
        (),
        True,
    ),
    "interface_details": (
        "show port {interface} information detail",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "interface_statistics": (
        "show ports {interface} statistics no-refresh",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "interface_rx_errors": (
        "show ports {interface} rxerrors no-refresh",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "interface_tx_errors": (
        "show ports {interface} txerrors no-refresh",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "interface_transceiver": (
        "show ports {interface} transceiver information detail",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "route_summary": ("show iproute summary", (), False),
    "ipv6_route_summary": ("show iproute ipv6 summary", (), False),
    "arp_table": ("show iparp", (), True),
    "arp_address": (
        "show iparp {address}",
        (("address", "addresses", "ipv4_address"),),
        False,
    ),
    "arp_interface": (
        "show iparp port {interface}",
        (("interface", "interfaces", "extreme_physical_port"),),
        True,
    ),
    "ipv6_neighbors": ("show neighbor-discovery cache ipv6", (), True),
    "ipv6_neighbor_address": (
        "show neighbor-discovery cache ipv6 {address}",
        (("address", "addresses", "ipv6_address"),),
        False,
    ),
    "mac_table": ("show fdb", (), True),
    "mac_interface": (
        "show fdb ports {interface}",
        (("interface", "interfaces", "extreme_physical_port"),),
        True,
    ),
    "lldp_neighbors": ("show lldp neighbors", (), True),
    "lldp_interface": (
        "show lldp port {interface} neighbors",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "lldp_interface_details": (
        "show lldp port {interface} neighbors detailed",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "vlan_summary": ("show vlan", (), True),
    "lacp": ("show lacp", (), True),
    "stp_summary": ("show stpd", (), True),
    "stp_detail": ("show stpd detail", (), True),
    "stacking": ("show stacking", (), False),
    "stacking_support": ("show stacking-support", (), False),
    "inline_power": ("show inline-power", (), False),
    "inline_power_port": (
        "show inline-power info ports {interface}",
        (("interface", "interfaces", "extreme_physical_port"),),
        False,
    ),
    "access_list_counters": ("show access-list counter", (), True),
    "qos_profiles": ("show qosprofile", (), False),
    "licenses": ("show licenses", (), False),
    "ntp": ("show ntp", (), False),
    "sntp_client": ("show sntp-client", (), False),
    "sessions": ("show session", (), False),
    "elrp": ("show elrp", (), False),
    "mcast_cache_summary": ("show mcast cache summary", (), False),
    "mirror": ("show mirror", (), False),
    "edp_neighbors": ("show edp", (), True),
    "ports_description": ("show ports description", (), True),
    "ports_rx_errors": ("show ports rxerrors no-refresh", (), True),
    "ports_tx_errors": ("show ports txerrors no-refresh", (), True),
    "ipconfig": ("show ipconfig", (), True),
    "route_table": ("show iproute", (), True),
    "ipv6_route_table": ("show iproute ipv6", (), True),
    "lldp_neighbors_detail": ("show lldp neighbors detailed", (), True),
    "stp_ports": ("show stpd s0 ports", (), True),
    "mlag_peer": ("show mlag peer", (), False),
    "mlag_ports": ("show mlag ports", (), True),
    "inline_power_stats": ("show inline-power stats", (), False),
    "ntp_association": ("show ntp association", (), False),
    "log_messages": ("show log messages memory-buffer", (), True),
    "log_warnings": ("show log messages memory-buffer severity warning", (), True),
    "log_configuration": ("show log configuration", (), True),
}

VR = (("vr", "virtual_routers", "vr"),)
PROBE = (("address", "addresses", "ipv4_address"),) + VR
SOURCE_PROBE = (("address", "addresses", "ipv4_address"), ("source", "addresses", "ipv4_address")) + VR
PROBES = {
    "ping": ("ping count 5 vr {vr} {address}", PROBE, False),
    "ping_source": ("ping count 5 vr {vr} {address} from {source}", SOURCE_PROBE, False),
    "traceroute": ("traceroute vr {vr} {address}", PROBE, False),
    "traceroute_source": ("traceroute vr {vr} {address} from {source}", SOURCE_PROBE, False),
}
EXPECTED.update(PROBES)
EXPECTED.update({
    "ospf_neighbors": ("show ospf neighbor", (), True),
    "ospf_interfaces": ("show ospf interfaces", (), True),
    "ospf_lsdb": ("show ospf lsdb", (), True),
    "ospfv3_neighbors": ("show ospfv3 neighbor", (), True),
    "ospfv3_interfaces": ("show ospfv3 interfaces", (), True),
    "bgp_summary": ("show bgp neighbor", (), True),
    "bgp_neighbor": ("show bgp neighbor {address}", (("address", "addresses", "ipv4_address"),), True),
    "bgp_routes": ("show bgp routes all", (), True),
    "vrrp": ("show vrrp", (), True),
    "bfd_sessions": ("show bfd session vr all", (), True),
    "route_table_vr": ("show iproute vr {vr}", VR, True),
    "ipv6_route_table_vr": ("show iproute ipv6 vr {vr}", VR, True),
    "arp_table_vr": ("show iparp vr {vr}", VR, True),
    "ipv6_neighbors_vr": ("show neighbor-discovery cache ipv6 vr {vr}", VR, True),
})

LOG_HISTORY_COMMAND = (
    "show log messages {source} severity {severity} starting date {begin_date} time {begin_time} "
    "ending date {end_date} time {end_time}"
)
EXPECTED["log_history"] = (LOG_HISTORY_COMMAND, (
    ("begin_date", None, "log_date"), ("begin_time", None, "log_time"),
    ("end_date", None, "log_date"), ("end_time", None, "log_time"),
    ("interface", "interfaces", "extreme_physical_port"),
    ("severity", None, "exos_log_severity"), ("source", None, "exos_log_source"),
), True)

LOG_TEMPLATES = (
    LOG_HISTORY_COMMAND,
    "show log messages memory-buffer",
    "show log messages memory-buffer severity warning",
    "show log configuration",
)
CONTROL_OR_SHELL = re.compile(r"[\x00-\x1f\x7f;&|$<>\x60]")
FORBIDDEN_TERMS = (
    "show configuration",
    "show config",
    "tech-support",
    "debug",
    "clear",
    "reset",
    "restart",
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


def test_commands_are_narrow_read_only_cli() -> None:
    for query in QUERIES.values():
        command = query.command
        assert command.startswith("show ") or command == "nslookup {name}" or command in {value[0] for value in PROBES.values()}
        assert CONTROL_OR_SHELL.search(command) is None
        assert "\\" not in command
        lowered = command.lower()
        assert not any(term in lowered for term in FORBIDDEN_TERMS)
        if " log" in lowered:
            assert command in LOG_TEMPLATES


def test_only_the_fixed_log_templates_pass_the_show_family_policy() -> None:
    from netops_helper import read_policy

    for command in LOG_TEMPLATES:
        read_policy._validate_query_command("extreme_exos", command)
    for command in ("show log", "show log messages nvram", "show log messages memory-buffer match root",
                    "show log messages memory-buffer severity warning starting date 11/01/2026",
                    "show logging", "show log configuration target syslog", "show log events all"):
        try:
            read_policy._validate_query_command("extreme_exos", command)
        except RuntimeError:
            continue
        raise AssertionError(command)
    for platform in ("cisco_ios", "arista_eos", "juniper_junos_els"):
        try:
            read_policy._validate_query_command(platform, "show log messages memory-buffer")
        except RuntimeError:
            continue
        raise AssertionError(platform)


def test_vlan_summary_has_no_inventory_slot() -> None:
    query = QUERIES["vlan_summary"]
    assert query.command == "show vlan"
    assert _slots(query) == ()


def test_descriptions_are_present_and_ascii() -> None:
    for query in QUERIES.values():
        assert query.description
        assert query.description.endswith(".")
        query.description.encode("ascii")


def test_scoped_diagnostic_inventory_boundaries() -> None:
    from netops_helper import auth, inventory, proxy
    from netops_helper.read_policy import render_read_query, validate_inventory_item

    serial = "S124FPTF23000001"
    accepted = {"vlans": ["Users_10"], "managed_switches": [serial], "certificates": ["Example_Cert"]}
    assert inventory._checked_read_inventory("test", accepted) == {
        key: tuple(values) for key, values in accepted.items()
    }
    assert auth._normalize_inventory(accepted) == {
        key: tuple(values) for key, values in accepted.items()
    }
    cases = (
        ("fortinet", "certificate_details", "certificate", "certificates", "Example_Cert"),
        ("extreme_exos", "vlan_details", "vlan", "vlans", "Users_10"),
        ("extreme_exos", "dhcp_snooping_entries", "vlan", "vlans", "Users_10"),
        ("fortinet", "managed_switch_status", "managed_switch", "managed_switches", serial),
        ("fortinet", "managed_switch_poe", "managed_switch", "managed_switches", serial),
        ("fortinet", "managed_switch_mac", "managed_switch", "managed_switches", serial),
        ("fortinet", "managed_switch_stacking", "managed_switch", "managed_switches", serial),
        ("fortinet", "managed_switch_lldp", "managed_switch", "managed_switches", serial),
    )
    for platform, query, parameter, category, value in cases:
        _, command = render_read_query(platform, query, {parameter: value}, {category: (value,)})
        assert command.endswith(" " + value)
        kind = {"vlans": "vlan_name", "managed_switches": "managed_switch_serial", "certificates": "certificate_name"}[category]
        assert proxy._valid_typed_inventory_value(value, kind)
        for bad_inventory in ({}, {"switches": (value,)}, {category: ("Other",)}):
            try:
                render_read_query(platform, query, {parameter: value}, bad_inventory)
            except ValueError:
                pass
            else:
                raise AssertionError("a different inventory authorized the query")
        for bad in ("all", "ALL", "1-4094", "Users Other", "Users;show accounts", "Users\nshow accounts", "*", "detail", "a" * 129):
            assert not proxy._valid_typed_inventory_value(bad, kind)
            try:
                render_read_query(platform, query, {parameter: bad}, {category: (bad,)})
            except ValueError:
                pass
            else:
                raise AssertionError("unsafe slot accepted")
    for category, bad in (("vlans", "ipv4"), ("vlans", "ports"), ("managed_switches", serial.lower()), ("managed_switches", "all")):
        try:
            validate_inventory_item(category, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("noncanonical or reserved inventory accepted")


def test_sharing_is_not_renderable_for_either_exos_profile() -> None:
    from netops_helper.read_policy import render_read_query

    for platform in ("extreme_exos", "extreme_switch_engine"):
        try:
            render_read_query(platform, "sharing", None, {})
        except ValueError as exc:
            assert "unknown read query" in str(exc)
        else:
            raise AssertionError("unsupported sharing query was rendered")


def main() -> None:
    test_sharing_is_not_renderable_for_either_exos_profile()
    test_scoped_diagnostic_inventory_boundaries()
    test_exact_catalogue_contract()
    test_commands_are_narrow_read_only_cli()
    test_vlan_summary_has_no_inventory_slot()
    test_descriptions_are_present_and_ascii()
    print("extreme query catalogue tests: ok")


if __name__ == "__main__":
    main()
