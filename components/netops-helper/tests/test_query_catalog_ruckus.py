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
}

METACHARS = set(";&|`$><\\\"'*?[]()!#~")
UNSAFE_SHOW_FAMILY = re.compile(
    r"^show\s+(?:run(?:ning-config)?|start(?:up-config)?|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key|log(?:ging)?|support)"
    r"(?:\s|$)", re.I,
)
UNSAFE_WORD = re.compile(
    r"\b(?:full-configuration|debug(?:ging)?|capture|shell|bash|request|clear|"
    r"restart|reboot|remote_ap_cli|secret(?:s)?|password(?:s)?|community|"
    r"credentials?|private-key|snmp|performance)\b", re.I,
)
UNSAFE_COMMANDS = (
    "show config", "show configuration", "show running-config", "show tech-support",
    "show performance ap-throughput", "remote_ap_cli -A show version",
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


def test_commands_are_show_only_shell_safe_and_take_no_parameter() -> None:
    for name, query in QUERIES.items():
        command = query.command
        assert _is_safe_ruckus_command(command), (name, command)
        assert not query.slots, name
        fields = {field for _, field, _, _ in Formatter().parse(command) if field}
        assert fields == set(), (name, command)


def test_safety_helper_rejects_configuration_debug_and_shell_forms() -> None:
    for command in UNSAFE_COMMANDS:
        assert not _is_safe_ruckus_command(command), command


def test_the_excluded_families_stay_absent() -> None:
    for name in ("configuration", "config", "performance", "remote_ap_cli", "support"):
        assert name not in QUERIES
    commands = [query.command for query in QUERIES.values()]
    assert all("config" not in command.casefold() for command in commands)
    assert all("performance" not in command.casefold() for command in commands)
    assert all(command.count(" ") <= 2 for command in commands)


def main() -> int:
    test_exact_commands_slots_and_volume()
    test_commands_are_show_only_shell_safe_and_take_no_parameter()
    test_safety_helper_rejects_configuration_debug_and_shell_forms()
    test_the_excluded_families_stay_absent()
    print("query_catalog_ruckus_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
