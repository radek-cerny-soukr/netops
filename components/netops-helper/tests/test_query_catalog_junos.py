from __future__ import annotations

from pathlib import Path
import re
from string import Formatter
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog.junos import COMMON_QUERIES, ELS_QUERIES  # noqa: E402


# Exact volume rationale: device-wide interface and neighbor tables, per-L3-
# interface ARP and ND collections, and global LLDP, LACP, BGP, and OSPF lists
# can need continuation. ELS additionally covers VLAN, MAC, and STP collections.
# False remains an advisory, not a bounded-output guarantee.
COMMON = {
    "version": ("show version | no-more", {}, False),
    "uptime": ("show system uptime | no-more", {}, False),
    "system_alarms": ("show system alarms | no-more", {}, False),
    "chassis_alarms": ("show chassis alarms | no-more", {}, False),
    "hardware": ("show chassis hardware | no-more", {}, False),
    "environment": ("show chassis environment | no-more", {}, False),
    "interfaces": ("show interfaces terse | no-more", {}, True),
    "interface_details": ("show interfaces {interface} extensive | no-more", {"interface": ("interfaces", "junos_interface")}, False),
    "interface_optics": ("show interfaces diagnostics optics {interface} | no-more", {"interface": ("interfaces", "junos_physical_interface")}, False),
    "route_summary": ("show route summary | no-more", {}, False),
    "route_lookup": ("show route {address} detail | no-more", {"address": ("addresses", "ipv4_address")}, False),
    "ipv6_route_lookup": ("show route {address} detail | no-more", {"address": ("addresses", "ipv6_address")}, False),
    "arp_table": ("show arp no-resolve | no-more", {}, True),
    "arp_interface": ("show arp no-resolve interface {interface} | no-more", {"interface": ("interfaces", "junos_logical_interface")}, True),
    "ipv6_neighbors": ("show ipv6 neighbors | no-more", {}, True),
    "ipv6_neighbors_interface": ("show ipv6 neighbors interface {interface} | no-more", {"interface": ("interfaces", "junos_logical_interface")}, True),
    "lldp_neighbors": ("show lldp neighbors | no-more", {}, True),
    "lldp_neighbors_interface": ("show lldp neighbors interface {interface} | no-more", {"interface": ("interfaces", "junos_physical_interface")}, False),
    "lacp_interfaces": ("show lacp interfaces | no-more", {}, True),
    "lacp_interface": ("show lacp interfaces {interface} | no-more", {"interface": ("interfaces", "junos_lacp_interface")}, False),
    "bgp_summary": ("show bgp summary | no-more", {}, True),
    "ospf_neighbors": ("show ospf neighbor | no-more", {}, True),
    "ospf_neighbors_interface": ("show ospf neighbor interface {interface} | no-more", {"interface": ("interfaces", "junos_logical_interface")}, False),
    "ospfv3_neighbors": ("show ospf3 neighbor | no-more", {}, True),
    "ospfv3_neighbors_interface": ("show ospf3 neighbor interface {interface} | no-more", {"interface": ("interfaces", "junos_logical_interface")}, False),
    "route_table": ("show route | no-more", {}, True),
    "route_instances": ("show route instance | no-more", {}, False),
    "ospf_interfaces": ("show ospf interface brief | no-more", {}, True),
    "lldp_neighbors_detail": ("show lldp neighbors detail | no-more", {}, True),
    "interfaces_descriptions": ("show interfaces descriptions | no-more", {}, True),
    "routing_engine": ("show chassis routing-engine | no-more", {}, False),
    "fpc": ("show chassis fpc | no-more", {}, False),
    "storage": ("show system storage | no-more", {}, False),
    "licenses": ("show system license | no-more", {}, False),
    "commit_history": ("show system commit | no-more", {}, False),
    "ntp_status": ("show ntp status | no-more", {}, False),
    "ntp_associations": ("show ntp associations no-resolve | no-more", {}, False),
    "vrrp_summary": ("show vrrp summary | no-more", {}, False),
    "bfd_sessions": ("show bfd session | no-more", {}, False),
    "log_messages": ("show log messages | last 200 | no-more", {}, True),
    "log_interactive_commands": ("show log interactive-commands | last 200 | no-more", {}, True),
}
ELS_ONLY = {
    "vlans": ("show vlans brief | no-more", {}, True),
    "mac_table": ("show ethernet-switching table | no-more", {}, True),
    "stp_bridge": ("show spanning-tree bridge | no-more", {}, True),
    "virtual_chassis": ("show virtual-chassis status | no-more", {}, False),
    "virtual_chassis_ports": ("show virtual-chassis vc-port | no-more", {}, False),
    "ethernet_switching_interfaces": ("show ethernet-switching interface | no-more", {}, True),
    "ethernet_switching_interface": ("show ethernet-switching interface {interface} detail | no-more", {"interface": ("interfaces", "junos_physical_interface")}, False),
    "mac_table_interface": ("show ethernet-switching table interface {interface} | no-more", {"interface": ("interfaces", "junos_physical_interface")}, True),
    "mac_table_address": ("show ethernet-switching table {mac} | no-more", {"mac": (None, "mac_literal")}, False),
    "stp_interfaces": ("show spanning-tree interface | no-more", {}, True),
    "poe_interfaces": ("show poe interface | no-more", {}, True),
    "poe_controller": ("show poe controller | no-more", {}, False),
    "dot1x_interfaces": ("show dot1x interface | no-more", {}, True),
    "dhcp_security_bindings": ("show dhcp-security binding | no-more", {}, True),
}
SUFFIX = " | no-more"
LOG_COMMANDS = {"show log messages | last 200", "show log interactive-commands | last 200"}
METACHARS = set(";&`$><\\\"'*?[]()!#~")
UNSAFE_SHOW_FAMILY = re.compile(
    r"^show\s+(?:run(?:ning-config)?|start(?:up-config)?|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key|log(?:ging)?|support|"
    r"system\s+core-dumps)(?:\s|$)", re.I,
)
UNSAFE_WORD = re.compile(
    r"\b(?:full-configuration|debug(?:ging)?|capture|shell|bash|request|clear|"
    r"restart|secret(?:s)?|password(?:s)?|community|credentials?|private-key|"
    r"key-chain|snmp)\b", re.I,
)
UNSAFE_COMMANDS = (
    "show run | no-more", "show running-config | no-more",
    "show start | no-more", "show startup-config | no-more",
    "show conf | no-more", "show configuration | no-more",
    "show tech | no-more", "show tech-support | no-more",
    "show file flash:secret | no-more", "show key | no-more",
    "show logging | no-more", "show log messages | no-more",
    "show system core-dumps | no-more",
    "show system storage | save secret",
    "show system storage | save secret | no-more",
    "request support information | no-more",
    "show version; shell | no-more",
    "show version\nshow clock | no-more",
    "show version\x7f | no-more",
)


def _slots(query):
    return {name: (slot.inventory, slot.kind) for name, slot in query.slots.items()}


def _is_safe_junos_command(command: str) -> bool:
    if not isinstance(command, str) or command != command.strip():
        return False
    if len(command) > 512 or command.count(SUFFIX) != 1:
        return False
    if not command.endswith(SUFFIX):
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in command):
        return False
    base = command[:-len(SUFFIX)]
    if base in LOG_COMMANDS:         # the fixed bounded log templates (they need command permission and file-read access on the device)
        return True
    if not base.startswith("show ") or "|" in base:
        return False
    if METACHARS.intersection(base):
        return False
    return not (UNSAFE_SHOW_FAMILY.search(base) or UNSAFE_WORD.search(base))


def _assert_oracle(catalogue, oracle) -> None:
    assert set(catalogue) == set(oracle)
    for name, (command, slots, high_volume) in oracle.items():
        query = catalogue[name]
        assert (query.command, _slots(query), query.high_volume) == (command, slots, high_volume), name
        assert query.description and query.description.endswith("."), name


def test_exact_commands_slots_and_volume() -> None:
    _assert_oracle(COMMON_QUERIES, COMMON)
    _assert_oracle(ELS_QUERIES, {**COMMON, **ELS_ONLY})


def test_els_is_an_explicit_common_superset() -> None:
    assert set(ELS_ONLY).isdisjoint(COMMON_QUERIES)
    assert set(ELS_QUERIES) == set(COMMON_QUERIES) | set(ELS_ONLY)
    assert all(ELS_QUERIES[name] is query for name, query in COMMON_QUERIES.items())


def test_commands_have_one_fixed_suffix_and_are_shell_safe() -> None:
    for profile, catalogue in (("common", COMMON_QUERIES), ("els", ELS_QUERIES)):
        for name, query in catalogue.items():
            command = query.command
            assert _is_safe_junos_command(command), (profile, name, command)
            base = command[:-len(SUFFIX)]
            fields = {field for _, field, _, _ in Formatter().parse(base) if field}
            assert fields == set(query.slots), (profile, name, command)


def test_safety_helper_rejects_abbreviations_secrets_and_extra_pipes() -> None:
    for command in UNSAFE_COMMANDS:
        assert not _is_safe_junos_command(command), command


def test_common_excludes_switch_only_queries() -> None:
    assert set(ELS_ONLY).isdisjoint(COMMON_QUERIES)



def test_log_descriptions_document_file_access_and_the_read_only_limit() -> None:
    for catalogue in (COMMON_QUERIES, ELS_QUERIES):
        for name in ('log_messages', 'log_interactive_commands'):
            description = catalogue[name].description
            assert 'trace permission and read access to the specific log file' in description
            assert 'built-in read-only class returns permission_denied' in description
            assert 'NetOps does not recommend broader permissions' in description
            assert 'syslog' in description and '(read-only-accounts.md#junos-os)' in description
            assert 'maintenance' not in description

def main() -> int:
    test_exact_commands_slots_and_volume()
    test_els_is_an_explicit_common_superset()
    test_commands_have_one_fixed_suffix_and_are_shell_safe()
    test_safety_helper_rejects_abbreviations_secrets_and_extra_pipes()
    test_common_excludes_switch_only_queries()
    test_log_descriptions_document_file_access_and_the_read_only_limit()
    print("query_catalog_junos_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
