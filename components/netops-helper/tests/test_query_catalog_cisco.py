from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog.cisco import (  # noqa: E402
    IOS_QUERIES,
    IOS_XE_QUERIES,
    NXOS_QUERIES,
)
from netops_helper.read_policy import render_read_query  # noqa: E402


EXPECTED: dict[str, dict[str, tuple[str, dict[str, tuple[str, str]]]]] = {
    "ios": {
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "interfaces": ("show interfaces status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "route_summary": ("show ip route summary", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interface_details": ("show interfaces {interface}", {"interface": ("interfaces", "cisco_ios_interface")}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "inventory": ("show inventory", {}),
        "environment": ("show env all", {}),
        "interface_errors": ("show interfaces {interface} counters errors", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbors", {}),
        "mac_table": ("show mac address-table", {}),
        "vlans": ("show vlan brief", {}),
        "lag_summary": ("show etherchannel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "bgp_summary": ("show ip bgp summary", {}),
        "ospf_neighbors": ("show ip ospf neighbor", {}),
        "hsrp_summary": ("show standby brief", {}),
        "vrrp_summary": ("show vrrp brief", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interfaces status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interfaces description", {}),
        "interfaces_trunk": ("show interfaces trunk", {}),
        "interfaces_counters_errors": ("show interfaces counters errors", {}),
        "interfaces_details": ("show interfaces", {}),
        "interface_switchport": ("show interfaces {interface} switchport", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "interface_transceiver": ("show interfaces {interface} transceiver detail", {"interface": ("interfaces", "cisco_ios_physical_interface")}),
        "power_inline": ("show power inline", {}),
        "vtp_status": ("show vtp status", {}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp associations", {}),
        "stack_members": ("show switch", {}),
        "stack_ports": ("show switch stack-ports summary", {}),
        "log_messages": ("show logging", {}),
    },
    "ios_xe": {
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "interfaces": ("show interfaces status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "route_summary": ("show ip route summary", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interface_details": ("show interfaces {interface}", {"interface": ("interfaces", "cisco_xe_interface")}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "inventory": ("show inventory", {}),
        "environment": ("show environment all", {}),
        "interface_errors": ("show interfaces {interface} counters errors", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbors", {}),
        "mac_table": ("show mac address-table", {}),
        "vlans": ("show vlan brief", {}),
        "lag_summary": ("show etherchannel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "bgp_summary": ("show ip bgp summary", {}),
        "ospf_neighbors": ("show ip ospf neighbor", {}),
        "hsrp_summary": ("show standby brief", {}),
        "vrrp_summary": ("show vrrp brief", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interfaces status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interfaces description", {}),
        "interfaces_trunk": ("show interfaces trunk", {}),
        "interfaces_counters_errors": ("show interfaces counters errors", {}),
        "interfaces_details": ("show interfaces", {}),
        "interface_switchport": ("show interfaces {interface} switchport", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "interface_transceiver": ("show interfaces {interface} transceiver detail", {"interface": ("interfaces", "cisco_xe_physical_interface")}),
        "power_inline": ("show power inline", {}),
        "vtp_status": ("show vtp status", {}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp associations", {}),
        "stack_members": ("show switch", {}),
        "stack_ports": ("show switch stack-ports summary", {}),
        "log_messages": ("show logging", {}),
        "platform_resources": ("show platform resources", {}),
    },
    "nxos": {
        "version": ("show version", {}),
        "clock": ("show clock", {}),
        "inventory": ("show inventory", {}),
        "environment": ("show environment", {}),
        "cpu": ("show processes cpu", {}),
        "memory": ("show processes memory", {}),
        "interfaces": ("show interface status", {}),
        "ip_interfaces": ("show ip interface brief", {}),
        "ipv6_interfaces": ("show ipv6 interface brief", {}),
        "interface_details": ("show interface {interface}", {"interface": ("interfaces", "cisco_nxos_interface")}),
        "interface_errors": ("show interface {interface} counters errors", {"interface": ("interfaces", "cisco_nxos_errors_interface")}),
        "vlans": ("show vlan", {}),
        "mac_table": ("show mac address-table", {}),
        "arp_table": ("show ip arp", {}),
        "ipv6_neighbors": ("show ipv6 neighbor", {}),
        "lag_summary": ("show port-channel summary", {}),
        "lacp_neighbors": ("show lacp neighbor", {}),
        "stp_summary": ("show spanning-tree summary", {}),
        "lldp_neighbors": ("show lldp neighbors detail", {}),
        "cdp_neighbors": ("show cdp neighbors detail", {}),
        "route_summary": ("show ip route summary", {}),
        "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}),
        "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}),
        "bgp_sessions": ("show bgp sessions", {}),
        "ospf_neighbors": ("show ip ospf neighbors", {}),
        "hsrp_summary": ("show hsrp summary", {}),
        "vrrp_summary": ("show vrrp summary", {}),
        "vpc_status": ("show vpc brief", {}),
        "vpc_peer_keepalive": ("show vpc peer-keepalive", {}),
        "vpc_role": ("show vpc role", {}),
        "route_table": ("show ip route", {}),
        "ospf_interfaces": ("show ip ospf interface brief", {}),
        "bgp_summary": ("show bgp ipv4 unicast summary", {}),
        "stp_tree": ("show spanning-tree", {}),
        "stp_root": ("show spanning-tree root", {}),
        "stp_blocked": ("show spanning-tree blockedports", {}),
        "stp_inconsistent": ("show spanning-tree inconsistentports", {}),
        "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "err_disabled": ("show interface status err-disabled", {}),
        "errdisable_recovery": ("show errdisable recovery", {}),
        "interfaces_description": ("show interface description", {}),
        "interfaces_trunk": ("show interface trunk", {}),
        "interfaces_counters_errors": ("show interface counters errors", {}),
        "interface_switchport": ("show interface {interface} switchport", {"interface": ("interfaces", "cisco_nxos_interface")}),
        "interface_transceiver": ("show interface {interface} transceiver details", {"interface": ("interfaces", "cisco_nxos_errors_interface")}),
        "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}),
        "ntp_status": ("show ntp status", {}),
        "ntp_associations": ("show ntp peer-status", {}),
        "system_resources": ("show system resources", {}),
        "reset_reason": ("show system reset-reason", {}),
        "modules": ("show module", {}),
        "license_usage": ("show license usage", {}),
        "redundancy_status": ("show redundancy status", {}),
        "features": ("show feature", {}),
        "vrfs": ("show vrf", {}),
        "bfd_neighbors": ("show bfd neighbors", {}),
        "vpc_consistency": ("show vpc consistency-parameters global", {}),
        "vpc_orphan_ports": ("show vpc orphan-ports", {}),
        "dhcp_snooping_binding": ("show ip dhcp snooping binding", {}),
        "access_lists": ("show ip access-lists", {}),
        "log_messages": ("show logging last 200", {}),
    },
}

# Exact volume rationale: process tables, global interface, neighbor, forwarding,
# and discovery tables, plus variable LAG, STP, routing-peer, and FHRP lists can
# need continuation. False remains an advisory, not a bounded-output guarantee.
HIGH_VOLUME = {
    "ios": {
        "interfaces", "ip_interfaces", "ipv6_interfaces", "cpu", "memory",
        "arp_table", "ipv6_neighbors", "mac_table", "vlans", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_summary", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "route_table", "ospf_interfaces", "stp_tree",
        "stp_root", "stp_inconsistent", "err_disabled",
        "interfaces_description", "interfaces_trunk", "interfaces_counters_errors", "interfaces_details", "power_inline",
        "log_messages",
    },
    "ios_xe": {
        "interfaces", "ip_interfaces", "ipv6_interfaces", "cpu", "memory",
        "arp_table", "ipv6_neighbors", "mac_table", "vlans", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_summary", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "route_table", "ospf_interfaces", "stp_tree",
        "stp_root", "stp_inconsistent", "err_disabled",
        "interfaces_description", "interfaces_trunk", "interfaces_counters_errors", "interfaces_details", "power_inline",
        "log_messages",
    },
    "nxos": {
        "cpu", "memory", "interfaces", "ip_interfaces", "ipv6_interfaces",
        "vlans", "mac_table", "arp_table", "ipv6_neighbors", "lag_summary",
        "lacp_neighbors", "stp_summary", "lldp_neighbors", "cdp_neighbors",
        "bgp_sessions", "ospf_neighbors", "hsrp_summary", "vrrp_summary",
        "vpc_status", "route_table", "ospf_interfaces", "bgp_summary",
        "stp_tree", "stp_root", "err_disabled", "interfaces_description",
        "interfaces_trunk", "interfaces_counters_errors",
        "dhcp_snooping_binding", "access_lists", "log_messages",
    },
}

CATALOGUES = {
    "ios": IOS_QUERIES,
    "ios_xe": IOS_XE_QUERIES,
    "nxos": NXOS_QUERIES,
}


SHELL_METACHARACTERS = {
    ";",
    "&",
    "|",
    "`",
    "$",
    ">",
    "<",
    chr(92),
    chr(34),
    chr(39),
    "*",
    "?",
    "[",
    "]",
    "(",
    ")",
    "!",
    "#",
    "~",
}


def _slots(query) -> dict[str, tuple[str, str]]:
    return {
        name: (slot.inventory, slot.kind)
        for name, slot in query.slots.items()
    }


def test_exact_commands_slots_and_volume() -> None:
    assert set(CATALOGUES) == set(EXPECTED) == set(HIGH_VOLUME)
    for platform, catalogue in CATALOGUES.items():
        oracle = EXPECTED[platform]
        assert set(catalogue) == set(oracle)
        for name, (command, slots) in oracle.items():
            query = catalogue[name]
            assert query.command == command, (platform, name)
            assert _slots(query) == slots, (platform, name)
            assert query.high_volume is (name in HIGH_VOLUME[platform]), (platform, name)
            assert query.description and query.description.endswith("."), (platform, name)


def test_catalogues_are_explicit_and_do_not_share_queries() -> None:
    assert IOS_QUERIES is not IOS_XE_QUERIES
    assert IOS_QUERIES is not NXOS_QUERIES
    assert IOS_XE_QUERIES is not NXOS_QUERIES
    for name in set(IOS_QUERIES) & set(IOS_XE_QUERIES):
        assert IOS_QUERIES[name] is not IOS_XE_QUERIES[name], name


def _validate_safe_command(command: str) -> None:
    if not isinstance(command, str) or not command.startswith("show "):
        raise ValueError("command must use the exact show prefix")
    if command != command.strip() or "  " in command:
        raise ValueError("command whitespace must be canonical")
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        raise ValueError("command contains a control character")
    if SHELL_METACHARACTERS.intersection(command):
        raise ValueError("command contains a shell metacharacter")
    forbidden_show_family = re.compile(
        r"^show (?:run(?:ning-config)?|start(?:up-config)?|full-configuration|"
        r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|"
        r"log(?:ging|s)?|debug(?:ging)?|support|capture|bash|shell)(?: |$)",
        re.IGNORECASE,
    )
    forbidden_key_chain = re.compile(
        r"^show key chain(?: |$)",
        re.IGNORECASE,
    )
    if forbidden_show_family.match(command) or forbidden_key_chain.match(command):
        raise ValueError("command belongs to a forbidden show family")


def test_commands_are_bounded_show_only_and_shell_safe() -> None:
    for platform, catalogue in CATALOGUES.items():
        for name, query in catalogue.items():
            command = query.command
            if name == "log_messages":  # the one fixed, slotless buffer template; read_policy allows exactly this form
                assert command == {"nxos": "show logging last 200"}.get(platform, "show logging") and not query.slots
                continue
            _validate_safe_command(command)
            assert set(re.findall(r"{([a-z_]+)}", command)) == set(query.slots), (
                platform,
                name,
                command,
            )


def test_vendor_interface_rendering_is_canonical_and_exact() -> None:
    accepted = (
        (
            "cisco_ios", "interface_details",
            "Gi1/0/1", "show interfaces GigabitEthernet1/0/1",
        ),
        (
            "cisco_ios", "interface_details",
            "Vl10", "show interfaces vlan 10",
        ),
        (
            "cisco_xe", "interface_details",
            "Twe8/1/2", "show interfaces TwentyFiveGigE8/1/2",
        ),
        (
            "cisco_xe", "interface_errors",
            "Te1/0/24",
            "show interfaces TenGigabitEthernet1/0/24 counters errors",
        ),
        (
            "cisco_nxos", "interface_details",
            "Ethernet101/1/1.100",
            "show interface Ethernet101/1/1.100",
        ),
        (
            "cisco_nxos", "interface_errors",
            "Loopback1023",
            "show interface Loopback1023 counters errors",
        ),
    )
    for platform, query, value, expected in accepted:
        _, rendered = render_read_query(
            platform,
            query,
            {"interface": value},
            {"interfaces": (value,)},
        )
        assert rendered == expected

    rejected = (
        ("cisco_ios", "interface_details", "status"),
        ("cisco_ios", "interface_details", "description"),
        ("cisco_ios", "interface_details", "counters"),
        ("cisco_ios", "interface_details", "Gi1/0/1-4"),
        ("cisco_ios", "interface_details", "Gi1/0/1,Gi1/0/2"),
        ("cisco_xe", "interface_details", "Gi1/0/1 counters"),
        ("cisco_xe", "interface_errors", "Loopback0"),
        ("cisco_nxos", "interface_details", "quick"),
        ("cisco_nxos", "interface_details", "Ethernet1/1-4"),
        ("cisco_nxos", "interface_errors", "Ethernet1/1.100"),
    )
    for platform, query, value in rejected:
        try:
            render_read_query(
                platform,
                query,
                {"interface": value},
                {"interfaces": (value,)},
            )
        except ValueError:
            continue
        raise AssertionError(
            f"unsafe Cisco interface was accepted: {platform} {value!r}"
        )

    try:
        render_read_query(
            "cisco_ios",
            "interface_details",
            {"interface": "Gi1/0/1"},
            {"interfaces": ("GigabitEthernet1/0/1",)},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("canonical equivalence bypassed exact inventory")


def test_forbidden_command_corpus_is_rejected() -> None:
    forbidden_commands = (
        "show run",
        "show running-config",
        "show start",
        "show startup-config",
        "show conf",
        "show config terminal",
        "show configuration",
        "show full-configuration",
        "show tech",
        "show tech-support",
        "show file bootflash:secret.txt",
        "show key chain",
        "show log",
        "show logging",
        "show debug",
        "show debugging",
        "show support details",
        "show capture session",
        "show bash",
        "show shell",
        "show version | include uptime",
        "show version\nreload",
        "show version\x7f",
    )
    for command in forbidden_commands:
        try:
            _validate_safe_command(command)
        except ValueError:
            continue
        raise AssertionError(f"forbidden command was accepted: {command!r}")


def main() -> int:
    test_exact_commands_slots_and_volume()
    test_catalogues_are_explicit_and_do_not_share_queries()
    test_commands_are_bounded_show_only_and_shell_safe()
    test_vendor_interface_rendering_is_canonical_and_exact()
    test_forbidden_command_corpus_is_rejected()
    print("query_catalog_cisco_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
