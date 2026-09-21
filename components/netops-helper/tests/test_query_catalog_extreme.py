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
    "sharing": ("show sharing", (), True),
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
}

CONTROL_OR_SHELL = re.compile(r"[\x00-\x1f\x7f;&|$<>\x60]")
FORBIDDEN_TERMS = (
    "show configuration",
    "show config",
    " log",
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
        assert command.startswith("show ")
        assert CONTROL_OR_SHELL.search(command) is None
        assert "\\" not in command
        lowered = command.lower()
        assert not any(term in lowered for term in FORBIDDEN_TERMS)


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


def main() -> None:
    test_scoped_diagnostic_inventory_boundaries()
    test_exact_catalogue_contract()
    test_commands_are_narrow_read_only_cli()
    test_vlan_summary_has_no_inventory_slot()
    test_descriptions_are_present_and_ascii()
    print("extreme query catalogue tests: ok")


if __name__ == "__main__":
    main()
