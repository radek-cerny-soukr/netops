from __future__ import annotations

from pathlib import Path
import re
from string import Formatter
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog.ruckus import QUERIES  # noqa: E402


# Exact volume rationale: the access-point and WLAN lists grow with the network
# and can need continuation; the two fixed device summaries do not.
EXPECTED = {
    "system_info": ("show sysinfo", {}, False),
    "ethernet_info": ("show ethinfo", {}, False),
    "access_points": ("show ap all", {}, True),
    "wlans": ("show wlan all", {}, True),
    # G107 (Unleashed 200.15): client, radio, rogue/event and single-object reads.
    "clients": ("show current-active-clients all", {}, True),
    "client_detail": ("show current-active-clients mac {mac}", {"mac": ("literal", "wifi_mac_literal")}, False),
    "client_performance": ("show performance station mac {mac}", {"mac": ("literal", "wifi_mac_literal")}, False),
    "radio_performance_24": ("show performance ap-radio2-4 mac {ap_mac}", {"ap_mac": ("literal", "wifi_mac_literal")}, False),
    "radio_performance_5": ("show performance ap-radio5 mac {ap_mac}", {"ap_mac": ("literal", "wifi_mac_literal")}, False),
    "rogue_devices": ("show rogue-devices", {}, True),
    "events": ("show events", {}, True),
    "events_activities": ("show events-activities", {}, True),
    "mesh_topology": ("show mesh topology", {}, True),
    "access_point": ("show ap mac {ap_mac}", {"ap_mac": ("literal", "wifi_mac_literal")}, False),
    "access_point_by_name": ("show ap devname {wtp_id}", {"wtp_id": ("wtp_ids", "fortios_wtp_id")}, False),
    "wlan": ("show wlan name {wlan}", {"wlan": ("wlan_names", "ruckus_wlan_name")}, False),
    # G108 (R02): the CLI ping itself is bounded (three echo requests, ~12 s without answer, measured on 200.15).
    "ping": ("ping {address}", {"address": ("addresses", "ipv4_address")}, False),
    # G110 (R10-R13): lists of configured objects; (RP08) the one configuration display, passed through the section
    # allowlist and the secret redaction of the engine (tests/test_g110_ruckus.py).
    "l2_acls": ("show l2acl all", {}, True),
    "mgmt_acls": ("show mgmt-acl all", {}, False),
    "l3_acls": ("show l3acl all", {}, True),
    "aaa_servers": ("show aaa all", {}, False),
    "dhcp_relays": ("show dhcp all", {}, False),
    "static_routes": ("show static-route all", {}, False),
    "config_settings": ("show config", {}, True),
}
# G110: the only configuration display; every other `show config` form stays unsafe.
ALLOWLISTED_CONFIG_FORMS = {"show config"}
# G108: the only non-`show` form, a bounded probe to one enrolled IPv4 literal.
PROBE_FORMS = {"ping {address}"}
PERFORMANCE_FORMS = {"show performance station mac {mac}", "show performance ap-radio2-4 mac {ap_mac}",
                     "show performance ap-radio5 mac {ap_mac}"}

METACHARS = set(";&|`$><\\\"'*?[]()!#~")
UNSAFE_SHOW_FAMILY = re.compile(
    r"^show\s+(?:run(?:ning-config)?|start(?:up-config)?|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key|log(?:ging)?|support)"
    r"(?:\s|$)", re.I,
)
UNSAFE_WORD = re.compile(
    r"\b(?:full-configuration|debug(?:ging)?|capture|shell|bash|request|clear|"
    r"restart|reboot|remote_ap_cli|secret(?:s)?|password(?:s)?|community|"
    r"credentials?|private-key|snmp)\b", re.I,
)
UNSAFE_COMMANDS = (
    "show config", "show configuration", "show running-config", "show tech-support",
    "remote_ap_cli -A show version",
    "debug", "reboot", "show sysinfo; show ethinfo", "show sysinfo | bash",
    "show sysinfo\nshow ethinfo", "show sysinfo\x7f", "exit",
)


def _slots(query):
    return {name: (slot.inventory, slot.kind) for name, slot in query.slots.items()}


def _is_safe_ruckus_command(command: str) -> bool:
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


def test_commands_are_show_only_shell_safe_and_take_only_their_typed_parameter() -> None:
    for name, query in QUERIES.items():
        command = query.command
        assert command in PROBE_FORMS | ALLOWLISTED_CONFIG_FORMS or _is_safe_ruckus_command(command), (name, command)
        fields = {field for _, field, _, _ in Formatter().parse(command) if field}
        assert fields == set(query.slots), (name, command)
        assert len(fields) <= 1 and (not fields or command.endswith("{" + next(iter(fields)) + "}")), name


def test_safety_helper_rejects_configuration_debug_and_shell_forms() -> None:
    for command in UNSAFE_COMMANDS:
        assert not _is_safe_ruckus_command(command), command


def test_the_excluded_families_stay_absent() -> None:
    for name in ("configuration", "config", "performance", "remote_ap_cli", "support"):
        assert name not in QUERIES
    commands = [query.command for query in QUERIES.values()]
    assert all("config" not in command.casefold() for command in commands if command not in ALLOWLISTED_CONFIG_FORMS)
    assert {command for command in commands if "performance" in command} == PERFORMANCE_FORMS
    assert all(command.count(" ") <= 2 or "{" in command for command in commands)


def main() -> int:
    test_exact_commands_slots_and_volume()
    test_commands_are_show_only_shell_safe_and_take_only_their_typed_parameter()
    test_safety_helper_rejects_configuration_debug_and_shell_forms()
    test_the_excluded_families_stay_absent()
    print("query_catalog_ruckus_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
