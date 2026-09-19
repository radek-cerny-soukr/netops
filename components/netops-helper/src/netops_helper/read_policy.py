"""Typed, inventory-bound templates for read-only troubleshooting queries."""

from __future__ import annotations

import ipaddress
import re
from string import Formatter
from typing import Mapping

from .query_catalog import READ_QUERIES
from .query_catalog.model import Query, Slot


PLATFORM_MAP = {
    "linux": "linux",
    "fortinet": "fortinet",
    "fortios": "fortinet",
    "extreme_exos": "extreme_exos",
    "extreme_switch_engine": "extreme_exos",
    "cisco_ios": "cisco_ios",
    "cisco_xe": "cisco_xe",
    "cisco_nxos": "cisco_nxos",
    "arista_eos": "arista_eos",
    "juniper_junos": "juniper_junos",
    "juniper_junos_els": "juniper_junos_els",
    "ruckus_unleashed": "ruckus_unleashed",
}


SAFE_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}")
SAFE_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
SAFE_SWITCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")

_EOS_PHYSICAL = (
    r"(?:Ethernet[0-9]{1,5}(?:/[0-9]{1,5}){0,2}|"
    r"Management[0-9]{1,5}(?:/[0-9]{1,5})?)"
)
_EOS_PC = r"Port-Channel[0-9]{1,5}"
_EOS_LOOP = r"Loopback[0-9]{1,5}"
_EOS_VLAN = r"Vlan[0-9]{1,5}"
_EOS_INTERFACE = rf"(?:{_EOS_PHYSICAL}|{_EOS_PC}|{_EOS_LOOP}|{_EOS_VLAN})"
_EOS_PHYSICAL_OR_PC = rf"(?:{_EOS_PHYSICAL}|{_EOS_PC})"

_JUNOS_LINE = r"(?:(?:et|fe|ge|xe)-[0-9]{1,2}/[0-9]{1,2}/[0-9]{1,2})"
_JUNOS_BASE = (
    rf"(?:{_JUNOS_LINE}|ae[0-9]{{1,4}}|reth[0-9]{{1,4}}|lo0|irb|"
    r"em[0-9]{1,2}|fxp[0-9]{1,2}|me[0-9]{1,2}|vme)"
)
_JUNOS_INTERFACE = rf"{_JUNOS_BASE}(?:\.[0-9]{{1,5}})?"
_JUNOS_LOGICAL = rf"{_JUNOS_BASE}\.[0-9]{{1,5}}"
_JUNOS_LACP = (
    rf"(?:ae[0-9]{{1,4}}|(?:et|fe|ge|xe)-[0-9]{{1,2}}/"
    r"[0-9]{1,2}/[0-9]{1,2})"
)

_FORTIOS_INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
_FORTIOS_INTERFACE_RESERVED = frozenset({
    "all", "any", "none", "clear", "list", "packet-rate", "speed-test",
    "speed-test-result", "speed-test-result-clear", "speed-test-shaping-reset",
    "speed-test-tunnel",
})
_CISCO_IOS_RESERVED = frozenset({
    "all", "brief", "module", "vlan", "accounting", "capabilities",
    "counters", "debounce", "description", "etherchannel", "flowcontrol",
    "link", "private-vlan", "pruning", "stats", "status", "switchport",
    "transceiver", "trunk",
})
_CISCO_NXOS_RESERVED = frozenset({
    "all", "module", "non-zero", "aggregate-counters", "bbcredit", "brief",
    "cable-diagnostics-tdr", "capabilities", "chassis-info", "controller",
    "counters", "dampening", "debounce", "description", "detail-counters",
    "fcoe", "fec", "flowcontrol", "hardware-mappings", "mac-address",
    "priority-flow-control", "private-vlan", "pruning", "queuing-drop",
    "quick", "snmp-ifindex", "status", "storm-control", "switchport",
    "transceiver", "trunk", "untagged-cos", "vlan",
})


def _canonical_decimal(value: str, minimum: int, maximum: int) -> int | None:
    if not value.isascii() or not value.isdecimal():
        return None
    number = int(value)
    if not minimum <= number <= maximum or str(number) != value:
        return None
    return number


def _canonical_fortios_interface(value: str) -> str | None:
    if (
        _FORTIOS_INTERFACE_PATTERN.fullmatch(value)
        and value.casefold() not in _FORTIOS_INTERFACE_RESERVED
    ):
        return value
    return None


def _canonical_cisco_ios_interface(value: str, physical_only: bool) -> str | None:
    if value.casefold() in _CISCO_IOS_RESERVED:
        return None
    match = re.fullmatch(
        r"(GigabitEthernet|Gi)([0-9]+)/([0-9]+)(?:/([0-9]+))?",
        value,
    )
    if match:
        first = _canonical_decimal(match[2], 0, 8)
        second = _canonical_decimal(match[3], 0, 99)
        third = (
            None
            if match[4] is None
            else _canonical_decimal(match[4], 1, 99)
        )
        if third is None and match[4] is None:
            if first == 0 and second is not None and second >= 1:
                return f"GigabitEthernet0/{second}"
        elif (
            first is not None
            and 1 <= first <= 8
            and second == 0
            and third is not None
        ):
            return f"GigabitEthernet{first}/0/{third}"
        return None
    if physical_only:
        return None
    match = re.fullmatch(r"(Port-channel|Po)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, 48)
        return None if number is None else f"Port-channel{number}"
    match = re.fullmatch(r"(Vlan|Vl)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, 4094)
        return None if number is None else f"vlan {number}"
    return None


def _canonical_cisco_xe_physical(value: str) -> str | None:
    match = re.fullmatch(
        r"(GigabitEthernet|Gi|TwoGigabitEthernet|Tw|"
        r"FiveGigabitEthernet|Fi|TenGigabitEthernet|Te|"
        r"TwentyFiveGigE|Twe|FortyGigabitEthernet|Fo|"
        r"HundredGigE|Hu)([0-9]+)/([0-9]+)(?:/([0-9]+))?",
        value,
    )
    if not match:
        return None
    prefix, member_text, slot_text, port_text = match.groups()
    canonical_prefix = {
        "Gi": "GigabitEthernet",
        "Tw": "TwoGigabitEthernet",
        "Fi": "FiveGigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Twe": "TwentyFiveGigE",
        "Fo": "FortyGigabitEthernet",
        "Hu": "HundredGigE",
    }.get(prefix, prefix)
    member = _canonical_decimal(member_text, 0, 8)
    slot = _canonical_decimal(slot_text, 0, 1)
    if port_text is None:
        if (
            canonical_prefix == "GigabitEthernet"
            and member == 0
            and slot == 0
        ):
            return "GigabitEthernet0/0"
        return None
    port = _canonical_decimal(port_text, 1, 48)
    if (
        member is None
        or not 1 <= member <= 8
        or slot is None
        or port is None
    ):
        return None
    allowed = False
    if canonical_prefix == "GigabitEthernet":
        allowed = slot in {0, 1}
    elif canonical_prefix == "TwoGigabitEthernet":
        allowed = slot == 0 and port <= 36
    elif canonical_prefix == "FiveGigabitEthernet":
        allowed = slot == 0
    elif canonical_prefix == "TenGigabitEthernet":
        allowed = slot in {0, 1} and (port <= 24 or port >= 37)
    elif canonical_prefix in {"TwentyFiveGigE", "FortyGigabitEthernet"}:
        allowed = slot == 1 and port <= 2
    elif canonical_prefix == "HundredGigE":
        allowed = slot in {0, 1}
    if not allowed:
        return None
    return f"{canonical_prefix}{member}/{slot}/{port}"


def _canonical_cisco_xe_interface(
    value: str,
    physical_only: bool,
) -> str | None:
    if value.casefold() in _CISCO_IOS_RESERVED:
        return None
    physical = _canonical_cisco_xe_physical(value)
    if physical is not None or physical_only:
        return physical
    match = re.fullmatch(r"(Port-channel|Po)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, 128)
        return None if number is None else f"Port-channel{number}"
    match = re.fullmatch(r"(Vlan|Vl)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, 4094)
        return None if number is None else f"vlan {number}"
    match = re.fullmatch(r"(Loopback|Tunnel)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 0, 2_147_483_647)
        return None if number is None else f"{match[1]}{number}"
    return None


def _canonical_cisco_nxos_interface(
    value: str,
    errors_only: bool,
) -> str | None:
    if value.casefold() in _CISCO_NXOS_RESERVED:
        return None
    match = re.fullmatch(
        r"Ethernet([0-9]{1,3})/([0-9]{1,3})"
        r"(?:/([0-9]{1,3}))?(?:\.([0-9]{1,4}))?",
        value,
    )
    if match:
        components = [
            _canonical_decimal(match[1], 1, 999),
            _canonical_decimal(match[2], 1, 999),
        ]
        if match[3] is not None:
            components.append(_canonical_decimal(match[3], 1, 999))
        subinterface = (
            None
            if match[4] is None
            else _canonical_decimal(match[4], 1, 4094)
        )
        if any(component is None for component in components):
            return None
        if match[4] is not None and subinterface is None:
            return None
        if errors_only and subinterface is not None:
            return None
        rendered = "Ethernet" + "/".join(
            str(component) for component in components
        )
        return (
            rendered
            if subinterface is None
            else f"{rendered}.{subinterface}"
        )
    match = re.fullmatch(r"Loopback([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[1], 0, 1023)
        return None if number is None else f"Loopback{number}"
    if errors_only:
        return None
    if value == "mgmt0":
        return value
    match = re.fullmatch(
        r"Port-channel([0-9]+)(?:\.([0-9]+))?",
        value,
    )
    if match:
        number = _canonical_decimal(match[1], 1, 4096)
        subinterface = (
            None
            if match[2] is None
            else _canonical_decimal(match[2], 1, 4094)
        )
        if number is None or (
            match[2] is not None and subinterface is None
        ):
            return None
        rendered = f"Port-channel{number}"
        return (
            rendered
            if subinterface is None
            else f"{rendered}.{subinterface}"
        )
    match = re.fullmatch(r"Vlan([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[1], 1, 4094)
        return None if number is None else f"Vlan{number}"
    match = re.fullmatch(r"Tunnel([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[1], 0, 9999)
        return None if number is None else f"Tunnel{number}"
    return None


_VENDOR_INTERFACE_CANONICALIZERS = {
    "fortios_interface": _canonical_fortios_interface,
    "fortios_physical_interface": _canonical_fortios_interface,
    "cisco_ios_interface": lambda value: _canonical_cisco_ios_interface(
        value, False,
    ),
    "cisco_ios_physical_interface": lambda value: _canonical_cisco_ios_interface(
        value, True,
    ),
    "cisco_xe_interface": lambda value: _canonical_cisco_xe_interface(
        value, False,
    ),
    "cisco_xe_physical_interface": lambda value: _canonical_cisco_xe_interface(
        value, True,
    ),
    "cisco_nxos_interface": lambda value: _canonical_cisco_nxos_interface(
        value, False,
    ),
    "cisco_nxos_errors_interface": lambda value: _canonical_cisco_nxos_interface(
        value, True,
    ),
}

_TOKEN_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "interface": SAFE_INTERFACE,
    "service": SAFE_SERVICE,
    "switch": SAFE_SWITCH,
    "extreme_physical_port": re.compile(
        r"[1-9][0-9]{0,2}(?:(?::[1-9][0-9]{0,2}){1,2}|"
        r"/[1-9][0-9]{0,2})?"
    ),
    "eos_interface": re.compile(_EOS_INTERFACE),
    "eos_physical_interface": re.compile(_EOS_PHYSICAL),
    "eos_lldp_interface": re.compile(_EOS_PHYSICAL),
    "eos_lacp_interface": re.compile(_EOS_PHYSICAL_OR_PC),
    "eos_stp_interface": re.compile(_EOS_PHYSICAL_OR_PC),
    "eos_ospf_interface": re.compile(_EOS_INTERFACE),
    "junos_interface": re.compile(_JUNOS_INTERFACE),
    "junos_physical_interface": re.compile(_JUNOS_LINE),
    "junos_logical_interface": re.compile(_JUNOS_LOGICAL),
    "junos_lacp_interface": re.compile(_JUNOS_LACP),
}

_KIND_INVENTORY = {
    "interface": "interfaces",
    "service": "services",
    "switch": "switches",
    "address": "addresses",
    "ipv4_address": "addresses",
    "ipv6_address": "addresses",
    **{
        kind: "interfaces"
        for kind in _TOKEN_PATTERNS
        if kind.startswith(("extreme_", "eos_", "junos_"))
    },
    **{kind: "interfaces" for kind in _VENDOR_INTERFACE_CANONICALIZERS},
}
_INVENTORY_KINDS = {
    "interfaces": "interface",
    "services": "service",
    "addresses": "address",
    "switches": "switch",
}

_EXPECTED_PLATFORMS = frozenset({
    "linux",
    "fortinet",
    "extreme_exos",
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
    "juniper_junos",
    "juniper_junos_els",
    "ruckus_unleashed",
})
_LINUX_COMMANDS = frozenset({
    "hostname",
    "uname -a",
    "uptime",
    "df -h",
    "free -m",
    "ip -brief link",
    "ip -brief address",
    "ip route show",
    "ss -lntup",
    "systemctl --no-pager --state=running --type=service",
    "ip -brief address show dev {interface}",
    "ip -details link show dev {interface}",
    "systemctl --no-pager --full status {service}",
    "journalctl --no-pager -u {service} --since -1h",
    "ip neigh show",
    "bridge fdb show",
})
_FORTINET_COMMANDS = frozenset({
    "get system status",
    "get system performance status",
    "get system ha status",
    "diagnose sys session stat",
    "diagnose hardware sysinfo memory",
    "diagnose hardware deviceinfo disk",
    "get system interface physical",
    "diagnose netlink interface list {interface}",
    "diagnose hardware deviceinfo nic {interface}",
    "get router info routing-table all",
    "get router info routing-table details {address}",
    "get router info protocols",
    "get router info6 protocols",
    "get system arp",
    "diagnose ipv6 neighbor-cache list",
    "diagnose lldp rx neighbor summary",
    "diagnose netlink brctl name host {switch}",
    "diagnose sys sdwan health-check",
    "diagnose sys ha checksum cluster",
    "diagnose sys ha history read",
    "get vpn ipsec tunnel summary",
    "diagnose vpn ipsec status",
    "get router info bgp summary",
    "get router info6 bgp summary",
    "get router info ospf status",
    "get router info6 ospf status",
    "get router info ospf neighbor all",
    "get router info6 ospf neighbor all",
    "get router info bfd neighbor",
    "get router info6 bfd neighbor",
    "diagnose sys ntp status",
    "diagnose sys top 1 5 1",
    "diagnose autoupdate status",
    "diagnose autoupdate versions",
    "diagnose vpn ssl list",
    "diagnose vpn ssl statistics",
    "diagnose firewall auth list",
    "diagnose ips filter status",
    "diagnose ips anomaly status",
    "diagnose antivirus outbreak-prevention statistics list",
})
_FORTINET_TOP_PREFIX = "diagnose sys top"
_FORTINET_TOP_SNAPSHOT = "diagnose sys top 1 5 1"
_FORBIDDEN_SHOW_SECOND = re.compile(
    r"(?:run(?:ning-config)?|start(?:up-config)?|full-configuration|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key-chain|"
    r"log(?:ging|s)?|debug(?:ging)?|support|capture|bash|shell)",
    re.IGNORECASE,
)
_JUNOS_PLATFORMS = frozenset({"juniper_junos", "juniper_junos_els"})
_JUNOS_SUFFIX = " | no-more"
_QUERY_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SLOT_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SHELL_METACHARACTERS = frozenset({
    ";",
    "&",
    "|",
    chr(96),
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
})


def normalize_platform(platform: str) -> str:
    if not isinstance(platform, str):
        raise ValueError("platform must be a string")
    normalized = PLATFORM_MAP.get(platform.strip().lower())
    if not normalized:
        raise ValueError(f"unsupported platform: {platform}")
    return normalized


def _canonical_address(value: str, kind: str) -> str:
    if "%" in value:
        raise ValueError(f"invalid typed {kind} value")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid typed {kind} value") from exc
    if kind == "ipv4_address" and not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("invalid typed ipv4_address value")
    canonical = str(address)
    if value != canonical:
        raise ValueError(f"invalid typed {kind} value")
    if kind == "ipv6_address" and not isinstance(address, ipaddress.IPv6Address):
        raise ValueError("invalid typed ipv6_address value")
    return canonical


def _validate_slot(value: str, kind: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid typed {kind} value")
    if kind in {"address", "ipv4_address", "ipv6_address"}:
        return _canonical_address(value, kind)
    canonicalizer = _VENDOR_INTERFACE_CANONICALIZERS.get(kind)
    if canonicalizer is not None:
        canonical = canonicalizer(value)
        if canonical is not None:
            return canonical
        raise ValueError(f"invalid typed {kind} value")
    pattern = _TOKEN_PATTERNS.get(kind)
    if pattern is not None and pattern.fullmatch(value):
        return value
    raise ValueError(f"invalid typed {kind} value")


def validate_inventory_item(category: str, value: str) -> str:
    if not isinstance(category, str) or category not in _INVENTORY_KINDS:
        raise ValueError("unknown inventory category")
    if not isinstance(value, str):
        raise ValueError("inventory value must be a string")
    return _validate_slot(value, _INVENTORY_KINDS[category])


def validate_query_inventory(
    platform: str | None,
    query_names: tuple[str, ...],
    inventory: Mapping[str, tuple[str, ...]],
) -> None:
    """Reject enrolled interfaces unusable by every enabled interface query."""
    if platform is None:
        return
    normalized = normalize_platform(platform)
    interface_kinds = {
        slot.kind
        for query_name in query_names
        for slot in READ_QUERIES[normalized][query_name].slots.values()
        if slot.inventory == "interfaces"
    }
    if not interface_kinds:
        return
    for value in inventory.get("interfaces", ()):
        for kind in interface_kinds:
            try:
                _validate_slot(value, kind)
            except ValueError:
                continue
            break
        else:
            raise ValueError(
                "enrolled interface is invalid for every enabled interface query"
            )


def _validate_query_command(platform: str, command: object) -> None:
    if not isinstance(command, str) or not command:
        raise RuntimeError("query command must be a non-empty string")
    if command != command.strip() or "  " in command:
        raise RuntimeError("query command whitespace is not canonical")
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        raise RuntimeError("query command contains a control character")

    inspected = command
    if platform in _JUNOS_PLATFORMS:
        if command.count(_JUNOS_SUFFIX) != 1 or not command.endswith(_JUNOS_SUFFIX):
            raise RuntimeError("Junos query must have one fixed paging suffix")
        inspected = command.removesuffix(_JUNOS_SUFFIX)
        if "|" in inspected:
            raise RuntimeError("Junos query contains an extra pipe")
    if _SHELL_METACHARACTERS.intersection(inspected):
        raise RuntimeError("query command contains a shell metacharacter")

    if platform == "linux":
        if inspected not in _LINUX_COMMANDS:
            raise RuntimeError("Linux query is outside the reviewed templates")
        return
    if platform == "fortinet":
        if (
            inspected.startswith(_FORTINET_TOP_PREFIX)
            and inspected != _FORTINET_TOP_SNAPSHOT
        ):
            raise RuntimeError("FortiOS process snapshot must be the fixed single-iteration form")
        if inspected not in _FORTINET_COMMANDS:
            raise RuntimeError("Fortinet query is outside the reviewed templates")
        return

    words = inspected.split(" ")
    if len(words) < 2 or words[0] != "show":
        raise RuntimeError("network query must use the exact show prefix")
    if _FORBIDDEN_SHOW_SECOND.fullmatch(words[1]) or (
        len(words) >= 3
        and [word.casefold() for word in words[1:3]] == ["key", "chain"]
    ):
        raise RuntimeError("network query uses a forbidden show family")


def _validate_query_catalogs(
    catalogs: Mapping[str, Mapping[str, Query]],
) -> None:
    for platform, queries in catalogs.items():
        if platform not in _EXPECTED_PLATFORMS:
            raise RuntimeError("query catalogue contains an unknown platform")
        if not isinstance(queries, Mapping) or not queries:
            raise RuntimeError("query catalogue must be a non-empty mapping")
        for name, query in queries.items():
            if not isinstance(name, str) or not _QUERY_NAME.fullmatch(name):
                raise RuntimeError("query name is not canonical")
            if not isinstance(query, Query):
                raise RuntimeError("query catalogue contains an invalid query")
            if (
                not isinstance(query.description, str)
                or not query.description
                or query.description != query.description.strip()
            ):
                raise RuntimeError("query description must be non-empty and canonical")
            if type(query.high_volume) is not bool:
                raise RuntimeError("query high_volume must be a boolean")
            if len(query.slots) > 16:
                raise RuntimeError("query declares too many parameters")
            for slot_name, slot in query.slots.items():
                if (
                    not isinstance(slot_name, str)
                    or not _SLOT_NAME.fullmatch(slot_name)
                    or not isinstance(slot, Slot)
                    or _KIND_INVENTORY.get(slot.kind) != slot.inventory
                ):
                    raise RuntimeError("query declares an invalid typed parameter")

            _validate_query_command(platform, query.command)
            fields: list[str] = []
            try:
                for _, field, format_spec, conversion in Formatter().parse(
                    query.command
                ):
                    if field is None:
                        continue
                    if (
                        not _SLOT_NAME.fullmatch(field)
                        or format_spec
                        or conversion
                    ):
                        raise RuntimeError("query template field is not canonical")
                    fields.append(field)
            except ValueError as exc:
                raise RuntimeError("query template is invalid") from exc
            if len(fields) != len(set(fields)) or set(fields) != set(query.slots):
                raise RuntimeError("query template and slot declaration differ")


if set(READ_QUERIES) != _EXPECTED_PLATFORMS:
    raise RuntimeError("canonical query platforms do not match the reviewed set")
_validate_query_catalogs(READ_QUERIES)


def render_read_query(
    platform: str,
    query_name: str,
    parameters: Mapping[str, str] | None,
    inventory: Mapping[str, tuple[str, ...]],
) -> tuple[str, str]:
    normalized = normalize_platform(platform)
    if not isinstance(query_name, str):
        raise ValueError("query name must be a string")
    if parameters is not None and (
        not isinstance(parameters, dict)
        or len(parameters) > 16
        or any(
            not isinstance(name, str) or not isinstance(value, str)
            for name, value in parameters.items()
        )
    ):
        raise ValueError("query parameters must be a bounded string mapping")
    try:
        query = READ_QUERIES[normalized][query_name]
    except KeyError as exc:
        raise ValueError(f"unknown read query for platform: {normalized}") from exc
    supplied = dict(parameters or {})
    if set(supplied) != set(query.slots):
        raise ValueError(f"query parameters must be exactly: {sorted(query.slots)}")
    rendered: dict[str, str] = {}
    for name, slot in query.slots.items():
        supplied_value = supplied[name]
        value = _validate_slot(supplied_value, slot.kind)
        allowed = inventory.get(slot.inventory, ())
        if supplied_value not in allowed:
            raise ValueError(f"{name} is not enrolled in target inventory")
        rendered[name] = value
    return normalized, query.command.format_map(rendered)


def public_query_catalog() -> dict[str, dict[str, list[str]]]:
    return {
        platform: {
            name: sorted(slot.inventory for slot in query.slots.values())
            for name, query in sorted(queries.items())
        }
        for platform, queries in sorted(READ_QUERIES.items())
    }


def public_query_metadata() -> dict[str, dict[str, dict[str, object]]]:
    return {
        platform: {
            name: {
                "command_template": query.command,
                "description": query.description,
                "high_volume": query.high_volume,
                "parameters": {
                    slot_name: {
                        "inventory": slot.inventory,
                        "kind": slot.kind,
                    }
                    for slot_name, slot in sorted(query.slots.items())
                },
            }
            for name, query in sorted(queries.items())
        }
        for platform, queries in sorted(READ_QUERIES.items())
    }
