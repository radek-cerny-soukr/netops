#!/usr/bin/env python3
"""Dependency-free contract tests for the Fortinet query catalogue."""

from __future__ import annotations

import re

from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.query_catalog.model import Query
from netops_helper.read_policy import _validate_query_command, render_read_query


# Exact volume rationale: device-wide interface, route, neighbor, and FDB tables,
# retained history, and variable protocol peer, session, and tunnel lists can
# need continuation. Aggregate status and inventory-bound detail stay False.
EXPECTED = {
    "system_status": ("get system status", (), False),
    "performance": ("get system performance status", (), False),
    "ha_status": ("get system ha status", (), False),
    "session_stats": ("diagnose sys session stat", (), False),
    "hardware_memory": ("diagnose hardware sysinfo memory", (), False),
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
    "ha_checksum": ("diagnose sys ha checksum cluster", (), False),
    "ha_history": ("diagnose sys ha history read", (), True),
    "ipsec_summary": ("get vpn ipsec tunnel summary", (), True),
    "ipsec_status": ("diagnose vpn ipsec status", (), False),
    "bgp_summary": ("get router info bgp summary", (), True),
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


def test_commands_are_narrow_read_only_cli() -> None:
    commands = {query.command for query in QUERIES.values()}
    for command in commands:
        assert command.startswith(("get ", "diagnose "))
        assert CONTROL_OR_SHELL.search(command) is None
        assert "\\" not in command
        lowered = command.lower()
        assert not any(term in lowered for term in FORBIDDEN_TERMS)

    assert "diagnose vpn ike gateway list" not in commands
    assert "diagnose vpn tunnel list" not in commands
    assert all(" ike " not in f" {command.lower()} " for command in commands)
    assert all("tunnel list" not in command.lower() for command in commands)


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


def main() -> None:
    test_exact_catalogue_contract()
    test_commands_are_narrow_read_only_cli()
    test_interface_kinds_are_bounded_and_inventory_exact()
    test_process_snapshot_is_pinned_to_one_iteration()
    test_descriptions_are_present_and_ascii()
    print("fortinet query catalogue tests: ok")


if __name__ == "__main__":
    main()
