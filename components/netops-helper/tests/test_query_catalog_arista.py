from __future__ import annotations

from pathlib import Path
import re
from string import Formatter
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog.arista import QUERIES  # noqa: E402


# Exact volume rationale: global interface, neighbor, forwarding, and VLAN tables
# plus variable LAG, LACP, STP, BGP, and OSPF lists can need continuation.
# Enrolled single-object lookups remain False without promising bounded output.
EXPECTED = {
    "version": ("show version", {}, False), "clock": ("show clock", {}, False),
    "hostname": ("show hostname", {}, False), "inventory": ("show inventory", {}, False),
    "environment": ("show system environment all", {}, False),
    "interfaces": ("show interfaces status", {}, True),
    "ip_interfaces": ("show ip interface brief", {}, True),
    "ipv6_interfaces": ("show ipv6 interface brief", {}, True),
    "interface_details": ("show interfaces {interface}", {"interface": ("interfaces", "eos_interface")}, False),
    "interface_errors": ("show interfaces {interface} counters errors", {"interface": ("interfaces", "eos_interface")}, False),
    "interface_optics": ("show interfaces {interface} transceiver", {"interface": ("interfaces", "eos_physical_interface")}, False),
    "vlans": ("show vlan", {}, True), "mac_table": ("show mac address-table", {}, True),
    "arp_table": ("show ip arp", {}, True),
    "arp_entry": ("show ip arp {address}", {"address": ("addresses", "ipv4_address")}, False),
    "ipv6_neighbors": ("show ipv6 neighbors", {}, True),
    "ipv6_neighbor": ("show ipv6 neighbors {address}", {"address": ("addresses", "ipv6_address")}, False),
    "lldp_neighbors": ("show lldp neighbors", {}, True),
    "lldp_neighbors_interface": ("show lldp neighbors {interface}", {"interface": ("interfaces", "eos_lldp_interface")}, False),
    "lag_summary": ("show port-channel dense", {}, True), "lacp_peers": ("show lacp peer", {}, True),
    "lacp_peer_interface": ("show lacp interface {interface} peer", {"interface": ("interfaces", "eos_lacp_interface")}, False),
    "stp_root": ("show spanning-tree root", {}, True),
    "stp_interface": ("show spanning-tree interface {interface}", {"interface": ("interfaces", "eos_stp_interface")}, False),
    "route_summary": ("show ip route summary", {}, False), "ipv6_route_summary": ("show ipv6 route summary", {}, False),
    "route_lookup": ("show ip route {address}", {"address": ("addresses", "ipv4_address")}, False),
    "ipv6_route_lookup": ("show ipv6 route {address}", {"address": ("addresses", "ipv6_address")}, False),
    "bgp_summary": ("show ip bgp summary", {}, True), "ipv6_bgp_summary": ("show ipv6 bgp summary", {}, True),
    "ospf_neighbors": ("show ip ospf neighbor", {}, True),
    "ospf_neighbors_interface": ("show ip ospf neighbor {interface}", {"interface": ("interfaces", "eos_ospf_interface")}, False),
    "ospfv3_neighbors": ("show ipv6 ospf neighbor", {}, True),
    "route_table": ("show ip route", {}, True),
    "ospf_interfaces": ("show ip ospf interface brief", {}, True),
    "stp_tree": ("show spanning-tree", {}, True),
    "stp_blocked": ("show spanning-tree blockedports", {}, False),
    "stp_vlan": ("show spanning-tree vlan {vlan_id}", {"vlan_id": (None, "vlan_id")}, False),
    "interfaces_errdisabled": ("show interfaces status errdisabled", {}, True),
    "interfaces_description": ("show interfaces description", {}, True),
    "interfaces_trunk": ("show interfaces trunk", {}, True),
    "interfaces_counters_errors": ("show interfaces counters errors", {}, True),
    "interfaces_counters_discards": ("show interfaces counters discards", {}, True),
    "interface_switchport": ("show interfaces {interface} switchport", {"interface": ("interfaces", "eos_switchport_interface")}, False),
    "interface_poe": ("show poe interface {interface}", {"interface": ("interfaces", "eos_physical_interface")}, False),
    "lldp_neighbors_detail": ("show lldp neighbors detail", {}, True),
    "vlan_details": ("show vlan id {vlan_id}", {"vlan_id": (None, "vlan_id")}, False),
    "mlag_detail": ("show mlag detail", {}, False),
    "mlag_config_sanity": ("show mlag config-sanity", {}, False),
    "ntp_status": ("show ntp status", {}, False),
    "ntp_associations": ("show ntp associations", {}, False),
    "cpu": ("show processes top once", {}, True),
    "reload_cause": ("show reload cause", {}, False),
    "log_messages": ("show logging 200", {}, True),
}

METACHARS = set(";&|`$><\\\"'*?[]()!#~")
UNSAFE_SHOW_FAMILY = re.compile(
    r"^show\s+(?:run(?:ning-config)?|start(?:up-config)?|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key|log(?:ging)?|support)"
    r"(?:\s|$)", re.I,
)
UNSAFE_WORD = re.compile(
    r"\b(?:full-configuration|debug(?:ging)?|capture|shell|bash|request|clear|"
    r"restart|secret(?:s)?|password(?:s)?|community|credentials?|private-key|"
    r"key-chain|snmp)\b", re.I,
)
UNSAFE_COMMANDS = (
    "show run", "show running-config", "show start", "show startup-config",
    "show conf", "show configuration", "show tech", "show tech-support",
    "show file flash:secret", "show key", "show logging",
    "show version; show clock", "show version | bash", "show version && shell",
    "show version\nshow clock", "show version\x7f",
)


def _slots(query):
    return {name: (slot.inventory, slot.kind) for name, slot in query.slots.items()}


def _is_safe_arista_command(command: str) -> bool:
    if not isinstance(command, str) or not command.startswith("show "):
        return False
    if command != command.strip() or len(command) > 512:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in command):
        return False
    if METACHARS.intersection(command):
        return False
    return not (
        UNSAFE_SHOW_FAMILY.search(command) or UNSAFE_WORD.search(command)
    )


def test_exact_commands_slots_and_volume() -> None:
    assert set(QUERIES) == set(EXPECTED)
    for name, (command, slots, high_volume) in EXPECTED.items():
        query = QUERIES[name]
        assert (query.command, _slots(query), query.high_volume) == (command, slots, high_volume), name
        assert query.description and query.description.endswith("."), name


def test_commands_are_show_only_and_shell_safe() -> None:
    for name, query in QUERIES.items():
        command = query.command
        if name == "log_messages":  # the one fixed, slotless buffer template; read_policy allows exactly this form
            assert command == "show logging 200" and not query.slots
            continue
        assert _is_safe_arista_command(command), (name, command)
        fields = {field for _, field, _, _ in Formatter().parse(command) if field}
        assert fields == set(query.slots), (name, command)


def test_safety_helper_rejects_abbreviations_secrets_and_shell_forms() -> None:
    for command in UNSAFE_COMMANDS:
        assert not _is_safe_arista_command(command), command


def test_unproven_commands_stay_absent() -> None:
    # Measured on cEOS 4.36.1F (2026-11): the summary LLDP query stays, the detail form is a separate template.
    assert QUERIES["lldp_neighbors"].command == "show lldp neighbors"
    assert QUERIES["lldp_neighbors_detail"].command == "show lldp neighbors detail"
    assert not any(query.command.startswith(("show logging ", "show running", "show startup")) for name, query in QUERIES.items() if name != "log_messages")
    assert QUERIES["log_messages"].command == "show logging 200" and not QUERIES["log_messages"].slots


def main() -> int:
    test_exact_commands_slots_and_volume()
    test_commands_are_show_only_and_shell_safe()
    test_safety_helper_rejects_abbreviations_secrets_and_shell_forms()
    test_unproven_commands_stay_absent()
    print("query_catalog_arista_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
