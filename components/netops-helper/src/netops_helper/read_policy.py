"""Typed, inventory-bound templates for read-only troubleshooting queries."""

from __future__ import annotations

import ipaddress
import re
from string import Formatter
from typing import Mapping

from .fortiadc_diagnostics import RECIPES as FORTIADC_LOG_RECIPES
from .query_catalog import READ_QUERIES
from .query_catalog.arista import LOG_WINDOW_QUERIES as EOS_LOG_WINDOW_QUERIES
from .query_catalog.arista import LOGGING_STATUS_COMMAND as EOS_LOGGING_STATUS_COMMAND
from .query_catalog.cisco import (IOS_XE_PROBE_QUERIES, NXOS_G93_QUERIES, NXOS_LOG_HISTORY, XE_LOG_COMMAND,
                                 XE_LOG_HISTORY, nxos_log_window, xe_log_window)
from .query_catalog.extreme import (
    LOG_HISTORY as EXOS_LOG_HISTORY, LOG_HISTORY_COMMAND as EXOS_LOG_HISTORY_COMMAND,
    LOG_SEVERITIES as EXOS_LOG_SEVERITIES, LOG_SOURCES as EXOS_LOG_SOURCES,
)
from .query_catalog.junos import CONFIG_COMMANDS, FILTER_BINDING_COMMAND, LOG_HISTORY_COMMAND, LOG_HISTORY_QUERY, log_time, log_window
from .query_catalog.model import DEVICE_TYPES, LITERAL, Query, SequenceQuery, Slot
from .normalization import normalize_mac


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
    "fortiadc": "fortiadc",
}


SAFE_INTERFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}")
SAFE_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
SAFE_SWITCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")

_EOS_ETHERNET = r"Ethernet[0-9]{1,5}(?:/[0-9]{1,5}){0,2}"
_EOS_PHYSICAL = (
    rf"(?:{_EOS_ETHERNET}|"
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

_FORTIOS_INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
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


def _canonical_cisco_ethernet(value: str) -> str | None:
    match = re.fullmatch(r"(Ethernet|Et)([0-9]+)/([0-9]+)", value)
    if not match:
        return None
    slot = _canonical_decimal(match[2], 0, 15)
    port = _canonical_decimal(match[3], 0, 15)
    if slot is None or port is None:
        return None
    return f"Ethernet{slot}/{port}"


def _canonical_cisco_ios_interface(value: str, physical_only: bool, *, allow_vlan: bool = True,
                                   port_channel_max: int = 48) -> str | None:
    if value.casefold() in _CISCO_IOS_RESERVED:
        return None
    ethernet = _canonical_cisco_ethernet(value)
    if ethernet is not None:
        return ethernet
    match = re.fullmatch(
        r"(FastEthernet|Fa|GigabitEthernet|Gi|TenGigabitEthernet|Te)([0-9]+)/([0-9]+)(?:/([0-9]+))?",
        value,
    )
    if match:
        prefix = {"Fa": "FastEthernet", "Gi": "GigabitEthernet", "Te": "TenGigabitEthernet"}.get(match[1], match[1])
        # IOS names use slot/port or stack-or-slot/module/port.
        first = _canonical_decimal(match[2], 0, 8)
        if match[4] is None:
            port = _canonical_decimal(match[3], 0, 99)
            if first is not None and port is not None:
                return f"{prefix}{first}/{port}"
            return None
        module = _canonical_decimal(match[3], 0, 8)
        port = _canonical_decimal(match[4], 0, 99)
        if first is not None and module is not None and port is not None:
            return f"{prefix}{first}/{module}/{port}"
        return None
    if physical_only:
        return None
    match = re.fullmatch(r"(Port-channel|Po)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, port_channel_max)
        return None if number is None else f"Port-channel{number}"
    if not allow_vlan:
        return None
    match = re.fullmatch(r"(Vlan|Vl)([0-9]+)", value)
    if match:
        number = _canonical_decimal(match[2], 1, 4094)
        return None if number is None else f"vlan {number}"
    return None


def _canonical_cisco_xe_physical(value: str) -> str | None:
    ethernet = _canonical_cisco_ethernet(value)
    if ethernet is not None:
        return ethernet
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
    *,
    switchport_only: bool = False,
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
    if switchport_only:
        return None
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
    *,
    allow_ethernet_subinterface: bool = False,
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
        if errors_only and subinterface is not None and not allow_ethernet_subinterface:
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
    "fortiadc_interface": lambda value: (
        _canonical_fortios_interface(value) if value[:1].isalnum() else None
    ),
    "cisco_ios_interface": lambda value: _canonical_cisco_ios_interface(
        value, False,
    ),
    "cisco_ios_physical_interface": lambda value: _canonical_cisco_ios_interface(
        value, True,
    ),
    "cisco_ios_switchport": lambda value: _canonical_cisco_ios_interface(
        value, False, allow_vlan=False, port_channel_max=64,
    ),
    "cisco_xe_interface": lambda value: _canonical_cisco_xe_interface(
        value, False,
    ),
    "cisco_xe_switchport": lambda value: _canonical_cisco_xe_interface(value, False, switchport_only=True),
    "cisco_xe_physical_interface": lambda value: _canonical_cisco_xe_interface(
        value, True,
    ),
    "cisco_nxos_interface": lambda value: _canonical_cisco_nxos_interface(
        value, False,
    ),
    "cisco_nxos_errors_interface": lambda value: _canonical_cisco_nxos_interface(
        value, True, allow_ethernet_subinterface=True,
    ),
    "cisco_nxos_non_subinterface": lambda value: _canonical_cisco_nxos_interface(
        value, True,
    ),
    "cisco_nxos_ethernet": lambda value: _canonical_cisco_nxos_interface(value, True)
    if value.startswith("Ethernet") else None,
    "cisco_nxos_port_channel": lambda value: _canonical_cisco_nxos_interface(value, False)
    if re.fullmatch(r"Port-channel[0-9]{1,4}", value) else None,
}


# The short and the full IOS name of one port are the same enrolled port (G53 r3): both sides are
# canonicalized by the slot's own validator; other kinds keep the exact comparison.
_CANONICAL_MEMBERSHIP_KINDS = frozenset({"cisco_ios_interface", "cisco_ios_physical_interface", "cisco_ios_switchport", "cisco_xe_switchport"})


def enrolled_interface(value: object, kind: str, listed: object) -> bool:
    if value in listed:
        return True
    if kind not in _CANONICAL_MEMBERSHIP_KINDS or not isinstance(value, str):
        return False
    canonicalize = _VENDOR_INTERFACE_CANONICALIZERS[kind]
    canonical = canonicalize(value)
    return canonical is not None and any(
        isinstance(item, str) and canonicalize(item) == canonical for item in listed
    )


SAFE_FORTIADC_OBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}")
_TOKEN_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "acl_policy": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}"),
    "nxos_acl_name": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}"),
    "interface": SAFE_INTERFACE,
    "service": SAFE_SERVICE,
    "switch": SAFE_SWITCH,
    "vlan_name": re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}"),
    "junos_vlan_name": re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}"),
    "c9800_ap_name": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"),
    "certificate_name": re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,78}"),
    "fortios_address_object": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}"),
    "fortios_station_mac": re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"),
    "fortios_wtp_id": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,34}"),
    "ruckus_wlan_name": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"),
    "wifi_mac_literal": re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"),
    "flow_port": re.compile(r"(?:0|[1-9][0-9]{0,4})"),
    "ip_protocol": re.compile(r"(?:0|[1-9][0-9]{0,2})"),
    "fortios_policy_type": re.compile(r"(?:policy|proxy)"),
    "fortios_nat_pool": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}"),
    "fortios_extender_serial": re.compile(r"FX[A-Z0-9]{12,14}"),
    # Same form as the triage_vpn tunnel argument (FortiOS phase-1 names have at most 35 characters).
    "fortios_ipsec_tunnel": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}"),
    "managed_switch_serial": re.compile(r"S[A-Z0-9]{11,15}"),
    "managed_switch_port": re.compile(r"port[1-9][0-9]{0,2}"),
    "fortiadc_member_id": re.compile(r"[1-9][0-9]{0,9}"),
    "fortiadc_vdom": SAFE_FORTIADC_OBJECT,
    "fortiadc_virtual_server": SAFE_FORTIADC_OBJECT,
    "managed_switch_trunk": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,34}"),
    "extreme_physical_port": re.compile(
        r"[1-9][0-9]{0,2}(?:(?::[1-9][0-9]{0,2}){1,2}|"
        r"/[1-9][0-9]{0,2})?"
    ),
    "eos_interface": re.compile(_EOS_INTERFACE),
    "eos_physical_interface": re.compile(_EOS_PHYSICAL),
    "eos_lldp_interface": re.compile(_EOS_PHYSICAL),
    "eos_lacp_interface": re.compile(_EOS_ETHERNET),
    "eos_stp_interface": re.compile(_EOS_PHYSICAL_OR_PC),
    "eos_switchport_interface": re.compile(_EOS_PHYSICAL_OR_PC),
    "eos_ospf_interface": re.compile(_EOS_INTERFACE),
    "junos_interface": re.compile(_JUNOS_INTERFACE),
    "junos_physical_interface": re.compile(_JUNOS_LINE),
    "junos_logical_interface": re.compile(_JUNOS_LOGICAL),
    "junos_filter_interface": re.compile(_JUNOS_LOGICAL),
    "junos_firewall_filter": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}"),
    "junos_security_zone": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}"),
    "junos_lacp_interface": re.compile(_JUNOS_LACP),
}

_KIND_INVENTORY = {
    "acl_policy": None, "nxos_acl_name": None, "diagnostic_dns_name": None,
    "eos_dns_name": "diagnostic_names", "junos_dns_name": "diagnostic_names",
    "junos_log_time": LITERAL, "junos_log_severity": LITERAL,
    "vlan_id": None, "vpc_id": None, "etherchannel_group_id": None, "mac_literal": None, "ip_literal": None,
    "ipv4_neighbor": None, "ipv6_neighbor": None,
    "route_map": "route_maps", "vrf": "vrfs", "vr": "virtual_routers", "routing_instance": "routing_instances",
    "interface": "interfaces",
    "service": "services",
    "switch": "switches",
    "vlan_name": "vlans",
    "junos_vlan_name": "vlans",
    "managed_switch_serial": "managed_switches",
    "managed_switch_port": "managed_switch_ports",
    "managed_switch_trunk": "managed_switch_trunks",
    "c9800_ap_name": None,
    "certificate_name": "certificates",
    "fortios_address_object": "firewall_addresses",
    "fortios_station_mac": "wireless_clients",
    "fortios_wtp_id": "wtp_ids",
    "ruckus_wlan_name": "wlan_names",
    "wifi_log_lines": LITERAL,
    "eos_log_minutes": None, "nxos_log_count": None, "log_severity": None, "log_date": None, "log_time": None,
    "exos_log_source": None, "exos_log_severity": None,
    "wifi_mac_literal": LITERAL,
    "flow_port": "flow_ports",
    "ip_protocol": "ip_protocols",
    "fortios_policy_type": "policy_types",
    "fortios_nat_pool": "nat_pools",
    "fortios_extender_serial": LITERAL,
    "fortios_sdwan_health_check": "sdwan_health_checks",
    "fortios_link_monitor": "link_monitors",
    "fortios_ipsec_tunnel": "ipsec_tunnels",
    "fortios_sdwan_member": "sdwan_members",
    "fortios_sdwan_rule": "sdwan_rules",
    "fortiadc_member_id": None,
    "fortiadc_vdom": "adc_vdoms",
    "fortiadc_virtual_server": "adc_virtual_servers",
    "address": "addresses",
    "ipv4_address": "addresses",
    "ipv6_address": "addresses",
    "ipv4_lookup": "addresses",
    "ipv6_lookup": "addresses",
    "lookup_prefix": "lookup_prefixes", "ipv4_prefix": "lookup_prefixes",
    **{
        kind: "interfaces"
        for kind in _TOKEN_PATTERNS
        if kind.startswith(("extreme_", "eos_")) or kind in {
            "junos_interface", "junos_physical_interface", "junos_logical_interface",
            "junos_filter_interface", "junos_lacp_interface",
        }
    },
    "junos_firewall_filter": "firewall_filters",
    "junos_security_zone": "security_zones",
    **{kind: "interfaces" for kind in _VENDOR_INTERFACE_CANONICALIZERS},
}
_INVENTORY_KINDS = {
    "route_maps": "route_map", "vrfs": "vrf", "virtual_routers": "vr", "routing_instances": "routing_instance",
    "interfaces": "interface",
    "services": "service",
    "addresses": "address",
    "lookup_prefixes": "lookup_prefix",
    "switches": "switch",
    "vlans": "vlan_name",
    "managed_switches": "managed_switch_serial",
    "managed_switch_ports": "managed_switch_port",
    "managed_switch_trunks": "managed_switch_trunk",
    "certificates": "certificate_name",
    "firewall_addresses": "fortios_address_object",
    "wireless_clients": "fortios_station_mac",
    "wtp_ids": "fortios_wtp_id",
    "wlan_names": "ruckus_wlan_name",
    "flow_ports": "flow_port",
    "firewall_filters": "junos_firewall_filter",
    "security_zones": "junos_security_zone",
    "ip_protocols": "ip_protocol",
    "policy_types": "fortios_policy_type",
    "nat_pools": "fortios_nat_pool",
    "sdwan_health_checks": "fortios_sdwan_health_check",
    "link_monitors": "fortios_link_monitor",
    "ipsec_tunnels": "fortios_ipsec_tunnel",
    "sdwan_members": "fortios_sdwan_member",
    "sdwan_rules": "fortios_sdwan_rule",
    "schema_paths": "fortios_config_path",
    "diagnostic_recipes": "fortios_diagnostic_recipe",
    "diagnostic_vdoms": "fortios_diagnostic_vdom",
    "diagnostic_names": "diagnostic_dns_name",
    "diagnostic_http_endpoints": "diagnostic_http_url",
    "adc_health_checks": "fortiadc_health_check",
    "diagnostic_virtual_servers": "fortiadc_virtual_server",
    "config_access": "config_permission",
    "adc_vdoms": "fortiadc_vdom",
    "adc_virtual_servers": "fortiadc_virtual_server",
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
    "fortiadc",
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
    "get extender modem-status {serial}",
    'diagnose switch-controller switch-info port-stats {managed_switch} {port}',
    'diagnose switch-controller switch-info port-stats {managed_switch}',
    'show switch-controller managed-switch {managed_switch}',
    'show system interface',
    "get wireless-controller wtp-status",
    "get wireless-controller wtp-status {wtp_id}",
    "get wireless-controller vap-status",
    "get wireless-controller scan",
    "get wireless-controller status",
    "get wireless-controller statistics",
    "get wireless-controller rf-analysis",
    "get wireless-controller rf-analysis {wtp_id}",
    "execute ping-options view-settings",
    "execute traceroute-options view-settings",
    "diagnose debug info",
    "diagnose user device list",
    "diagnose sys session filter",
    "get vpn certificate local details {certificate}",
    "diagnose firewall fqdn get-ip {name}",
    "diagnose firewall iprope lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}",
    "diagnose firewall iprope6 lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}",
    'diagnose switch-controller switch-info status {managed_switch}',
    'diagnose switch-controller switch-info poe summary {managed_switch}',
    'diagnose switch-controller switch-info mac-table {managed_switch}',
    'diagnose switch-controller switch-info stacking status {managed_switch}',
    'diagnose switch-controller switch-info lldp neighbors-summary {managed_switch}',
    'diagnose switch-controller switch-info loop-guard {managed_switch}',
    'diagnose switch-controller switch-info bpdu-guard-status {managed_switch}',
    'diagnose switch-controller switch-info flapguard status {managed_switch}',
    'diagnose switch-controller switch-info dhcp-snooping status {managed_switch}',
    'diagnose switch-controller switch-info dhcp-snooping database {managed_switch}',
    'diagnose switch-controller switch-info fan {managed_switch}',
    'diagnose switch-controller switch-info ip-source-guard violations {managed_switch}',
    "diagnose switch-controller switch-info lldp neighbors-detail {managed_switch} {port}",
    "diagnose switch-controller switch-info mac-limit-violations interface {managed_switch} {port}",
    "diagnose switch-controller switch-info mclag icl {managed_switch}",
    "diagnose switch-controller switch-info trunk status {managed_switch} {mclag_trunk}",
    "diagnose switch-controller switch-info mclag peer-consistency-check {managed_switch} {mclag_trunk}",

    "get system status",
    "get system performance status",
    "get system ha status",
    "diagnose sys session stat",
    "diagnose hardware sysinfo conserve",
    "diagnose hardware sysinfo cpu",
    "diagnose sys service-communication",
    "diagnose hardware sysinfo memory",
    "diagnose hardware deviceinfo disk",
    "execute sensor detail",
    "diagnose debug crashlog read",
    "diagnose debug config-error-log read",
    "get system interface physical",
    "get system interface",
    "diagnose netlink aggregate name {aggregate} show",
    "diagnose netlink interface list {interface}",
    "diagnose hardware deviceinfo nic {interface}",
    "get router info routing-table all",
    "get router info routing-table details {address}",
    "get router info6 routing-table {address}",
    "get router info protocols",
    "get router info6 protocols",
    "get system arp",
    "diagnose ipv6 neighbor-cache list",
    "diagnose lldp rx neighbor summary",
    "diagnose netlink brctl name host {switch}",
    "diagnose sys sdwan health-check",
    "diagnose sys sdwan intf-sla-log {interface}",
    "diagnose sys sdwan sla-log {health_check} {member}",
    "diagnose sys link-monitor status {monitor}",
    # G14: name-scoped IPsec detail; key material is withheld after the read (sanitize.redact_fortios_ipsec_keys).
    "diagnose vpn ike gateway list name {tunnel}",
    "diagnose vpn tunnel list name {tunnel}",
    "diagnose sys sdwan member {member}",
    "diagnose sys sdwan service4 {rule}",
    "diagnose sys sdwan service6 {rule}",
    "diagnose sys sdwan route {member}",
    "diagnose sys sdwan route6 {member}",
    "diagnose sys ha checksum cluster",
    "diagnose sys ha history read",
    "get vpn ipsec tunnel summary",
    "diagnose vpn ipsec status",
    "diagnose vpn tunnel stat",
    "execute dhcp lease-list {interface}",
    "execute dhcp lease-list",
    "diagnose wireless-controller wlac -c sta",
    "diagnose wireless-controller wlac -d sta {mac}",
    "diagnose wireless-controller wlac -c wtp",
    "diagnose wireless-controller wlac -d wtp",
    "diagnose wireless-controller wlac -c vap",
    "get router info bgp neighbors {peer} advertised-routes",
    "get router info bgp neighbors {peer} received-routes",
    "get router info bgp neighbors {peer} routes",
    "get router info6 bgp neighbors {peer6} advertised-routes",
    "get router info6 bgp neighbors {peer6} received-routes",
    "get router info6 bgp neighbors {peer6} routes",
    "get router info ospf interface",
    "get router info6 ospf interface",

    "diagnose sys ha checksum show-nonsync",
    "diagnose sys ha sync-stats",
    "diagnose test application dnsproxy 7",
    "diagnose firewall ippool stats",
    "diagnose firewall ippool list nat-ip {pool}",
    "diagnose firewall fqdn list-ip",
    "diagnose test application dnsproxy 6",
    "diagnose sys sdwan zone",
    "diagnose ip rtcache list",
    "get router info ospf database brief",
    "get router info6 ospf database",
    "diagnose firewall proute list",
    "diagnose firewall proute6 list",
    "diagnose vpn ike counts",
    "diagnose vpn ike errors",
    "diagnose vpn ike stats",

    "get router info bgp summary",
    "get router info6 bgp summary",
    # G11 (1.0.12): measured on FortiGate-60F 7.6.8 and FortiGate-80F 8.0.2 (read-only accounts).
    "get router info6 routing-table",
    "get router info routing-table database",
    "get router info6 routing-table database",
    "get router info bgp neighbors {peer}",
    "get router info bgp neighbors",
    "get router info6 bgp neighbors {peer6}",
    "get router info6 bgp neighbors",
    "diagnose netlink interface list",
    "diagnose netlink device list",
    "diagnose netlink interface packet-rate",
    "get system stp list",
    "show system virtual-switch",
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
_FORTIADC_INTERFACE_SUMMARY = ("get system interface", "diagnose hardware get deviceinfo nic-detail")
_FORTIADC_COMMANDS = frozenset({
    "get system certificate local",
    "execute ha force failover-standby status",
    "get system status",
    "get system performance",
    "diagnose system vm",
    "diagnose netlink interface list {interface}",
    "diagnose netlink interface list",
    "get system interface",
    "diagnose hardware get deviceinfo nic-detail",
    "diagnose netlink device",
    "get router info routing-table all",
    "diagnose netlink neighbor list",
    "get firewall global",
    "diagnose server-load-balance slb_load",
    "get security waf-signature-status",
    "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server}",
    "diagnose server-load-balance vs_stat vdom {vdom}",
    "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server} rs {real_server}",
    "diagnose hardware get sysinfo cpu",
    "diagnose server-load-balance session list",
    "diagnose server-load-balance persistence list",
    "diagnose hardware get deviceinfo nic-detail {interface}",
    "execute ssl-handshake-n-record-statistics show virtual-server {virtual_server}",
    "execute ssl-client-side-session-statistics show virtual-server {virtual_server}",
    "execute dos get dos-access-limit {virtual_server}",
    "execute dos get dos-conn-limit {virtual_server}",
    "execute dos get dos-req-limit {virtual_server}",
    "execute waf block-ip list",
    "execute log list-type tlog",
    "execute log list-type alog",
    "execute autoupdate contract",
    "execute date",
    "execute log list-type all",
    "diagnose lldprx neighbor summary",
    "get router info bgp summary",
    "get router info bgp neighbors",
    "get router info ospf neighbor",
    "get system ha-status",
    "get system traffic-group-status brief",
    "diagnose llb policy list",
})
# The only `execute` sequences a catalogue query may run, in one SSH session and in this order.
# A sequence query is a separate template type (SequenceQuery); nothing else may contain `execute log`.
_FORTINET_SEQUENCES = frozenset({
    (
        "execute log filter category event",
        "execute log filter field subtype wireless",
        "execute log filter view-lines {lines}",
        "execute log display",
    ),
})
_FORTINET_SEQUENCE_RENDERED = (
    re.compile(r"execute log filter category event"),
    re.compile(r"execute log filter field subtype wireless"),
    re.compile(r"execute log filter view-lines (?:[1-9][0-9]?|1[0-9]{2}|200)"),
    re.compile(r"execute log display"),
)


def require_fortinet_sequence(commands: object) -> tuple[str, ...]:
    """Last check before a FortiOS sequence is sent: exactly the four reviewed `execute log` shapes, in order."""
    if (
        not isinstance(commands, tuple)
        or len(commands) != len(_FORTINET_SEQUENCE_RENDERED)
        or not all(isinstance(command, str) for command in commands)
        or not all(pattern.fullmatch(command) for pattern, command in zip(_FORTINET_SEQUENCE_RENDERED, commands))
    ):
        raise ValueError("FortiOS command sequence is outside the reviewed shapes")
    return commands


_FORTINET_TOP_PREFIX = "diagnose sys top"
_FORTINET_TOP_SNAPSHOT = "diagnose sys top 1 5 1"
_FORBIDDEN_SHOW_SECOND = re.compile(
    r"(?:run(?:ning-config)?|start(?:up-config)?|full-configuration|"
    r"conf(?:ig(?:uration)?)?|tech(?:-support)?|file|key-chain|"
    r"log(?:ging|s)?|debug(?:ging)?|support|capture|bash|shell)",
    re.IGNORECASE,
)
# EXOS permits only these reviewed show log templates, with typed source and time/severity slots.
_EXOS_LOG_COMMANDS = frozenset({
    "show log messages memory-buffer",
    "show log messages memory-buffer severity warning",
    "show log configuration",
    EXOS_LOG_HISTORY_COMMAND,
})
# IOS and IOS XE display the device buffer. NX-OS accepts a bounded count.
# Client-side NX-OS filters do not change the CLI template.
_NETWORK_LOG_COMMANDS = {
    "cisco_ios": frozenset({"show logging"}),
    "cisco_xe": frozenset({"show logging"}),
    "cisco_nxos": frozenset({"show logging last 200", "show logging last {count}", "show logging info"}),
    "arista_eos": frozenset({
        "show logging 200",
        # G120: only typed slots (bounded minutes, calendar date/time, severity keyword) reach the device.
        "show logging last {minutes} minutes threshold {severity}",
        "show logging time-range {begin_date} {begin_time} {end_date} {end_time} threshold {severity}",
    }),
}
# Junos has no line-count argument: the fixed `last 200` pipe is part of the template, in front of the paging suffix.
_JUNOS_LOG_COMMANDS = frozenset({
    "show log messages | last 200",
    "show log interactive-commands | last 200",
})
_JUNOS_VLAN_KEYWORDS = frozenset({
    "all", "brief", "detail", "extensive", "instance", "interface", "logical-system",
    "object-summary", "operational", "satellite", "vlan-groups",
})
_JUNOS_FILTER_KEYWORDS = ("regex", "version")
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


MAX_SHOWN_PLATFORM = 64


def normalize_platform(platform: str) -> str:
    if not isinstance(platform, str):
        raise ValueError("platform must be a string")
    normalized = PLATFORM_MAP.get(platform.strip().lower())
    if not normalized:
        shown = platform if len(platform) <= MAX_SHOWN_PLATFORM else platform[:MAX_SHOWN_PLATFORM] + "..."
        raise ValueError(f"unsupported platform: {shown}")
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


LOOKUP_KINDS = {"ipv4_lookup": 4, "ipv6_lookup": 6}


def canonical_prefix(value: object, version: int | None = None):
    """Return a canonical CIDR network; refuse /0, multicast, unspecified and limited broadcast."""
    if not isinstance(value, str) or value.count("/") != 1 or "%" in value:
        raise ValueError("invalid typed lookup prefix")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("invalid typed lookup prefix") from exc
    if str(network) != value or network.prefixlen == 0 or (version is not None and network.version != version):
        raise ValueError("invalid typed lookup prefix")
    address = network.network_address
    if address.is_multicast or address.is_unspecified or (network.version == 4 and int(address) == 4294967295):
        raise ValueError("invalid typed lookup prefix")
    return network


def enrolled_lookup(value: object, version: int, inventory: Mapping[str, tuple[str, ...]]):
    """Return the network of an enrolled address (as /32 or /128) or of a prefix inside an enrolled lookup prefix."""
    if not isinstance(value, str):
        raise ValueError("invalid typed lookup value")
    if "/" not in value:
        kind = "ipv4_address" if version == 4 else "ipv6_address"
        address = _canonical_address(value, kind)
        if value not in inventory.get("addresses", ()):
            raise ValueError("lookup value is not enrolled in target inventory")
        return ipaddress.ip_network(address)
    network = canonical_prefix(value, version)
    for enrolled in inventory.get("lookup_prefixes", ()):
        try:
            outer = canonical_prefix(enrolled, version)
        except ValueError:
            continue
        if network.subnet_of(outer):
            return network
    raise ValueError("lookup value is not enrolled in target inventory")


def _validate_slot(value: str, kind: str, *, lookup_only: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid typed {kind} value")
    if kind in {"lookup_prefix", "ipv4_prefix"}:
        canonical_prefix(value, 4 if kind == "ipv4_prefix" else None)
        return value
    if kind in LOOKUP_KINDS:
        if "/" in value:
            canonical_prefix(value, LOOKUP_KINDS[kind])
            return value
        return _canonical_address(value, "ipv4_address" if kind == "ipv4_lookup" else "ipv6_address")
    if kind == "etherchannel_group_id":
        if len(value) <= 3 and _canonical_decimal(value, 1, 128) is not None:
            return value
        raise ValueError("invalid typed etherchannel_group_id value")
    if kind in {"vlan_id", "vpc_id", "mac_literal", "ip_literal", "vrf", "vr", "routing_instance", "route_map"}:
        if not value or len(value) > 128 or not value.isascii() or re.search(r"[\s|;\"'`$&<>\\]", value):
            raise ValueError(f"invalid typed {kind} value")
        if kind in ("vlan_id", "vpc_id"):
            if _canonical_decimal(value, 1, 4094 if kind == "vlan_id" else 4096) is not None:
                return value
        elif kind == "mac_literal":
            return normalize_mac(value)
        elif kind == "ip_literal":
            if "%" not in value and ("/" not in value or lookup_only and re.search(r"/[0-9]{1,3}$", value)):
                try:
                    return str(ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value))
                except ValueError:
                    pass
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", value):
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind in {"fortios_sdwan_health_check", "fortios_link_monitor"}:
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}", value)
            and not (kind == "fortios_link_monitor" and value.casefold() == "all")
        ):
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind in {"fortios_sdwan_member", "fortios_sdwan_rule"}:
        maximum = 512 if kind == "fortios_sdwan_member" else 4000
        if len(value) <= len(str(maximum)) and _canonical_decimal(value, 1, maximum) is not None:
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind in LOG_WINDOW_KINDS:
        if _valid_log_window_value(value, kind):
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind == "wifi_log_lines":
        if len(value) <= 3 and _canonical_decimal(value, 1, 200) is not None:
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind in {"flow_port", "ip_protocol"}:
        maximum = 65535 if kind == "flow_port" else 255
        if _canonical_decimal(value, 0, maximum) is not None:
            return value
        raise ValueError(f"invalid typed {kind} value")
    if kind == "config_permission":
        if value in {"read", "compare"}:
            return value
        raise ValueError("invalid configuration permission")
    if kind == "fortios_diagnostic_vdom":
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}",value):
            return value
        raise ValueError("invalid diagnostic VDOM")
    if kind == "fortiadc_virtual_server":
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}",value):
            return value
        raise ValueError("invalid FortiADC virtual server name")
    if kind == "fortios_diagnostic_recipe":
        if value in FORTIADC_LOG_RECIPES or value in {
            "ping", "traceroute", "sniffer", "sessions", "flow", "nslookup", "http_probe", "health_check_verify",
            "logs", "session_list", "persistence_list", "disk_usage", "ntp_status", "packet_capture",
        }:
            return value
        raise ValueError("invalid diagnostic recipe")
    if kind == "diagnostic_http_url":
        match = re.fullmatch(r"http://([0-9.]{7,15})(?::([1-9][0-9]{0,4}))?((?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,63})+|/)", value)
        if match is not None and len(value) <= 128:
            host, port = match.group(1), match.group(2)
            try:
                ip = ipaddress.IPv4Address(host)
            except ValueError:
                ip = None
            if (ip is not None and str(ip) == host and not ip.is_multicast and not ip.is_unspecified
                    and int(ip) != 4294967295 and (port is None or (port != "80" and int(port) <= 65535))):
                return value
        raise ValueError("invalid diagnostic HTTP endpoint")
    if kind == "fortiadc_health_check":
        if SAFE_FORTIADC_OBJECT.fullmatch(value):
            return value
        raise ValueError("invalid FortiADC health check name")
    if kind in {"diagnostic_dns_name", "eos_dns_name", "junos_dns_name"}:
        if len(value) <= 253 and re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            return value
        raise ValueError("invalid diagnostic DNS name")
    if kind == "junos_log_time":
        log_time(value)
        return value
    if kind == "junos_log_severity":
        if re.fullmatch(r"[0-7]", value):
            return value
        raise ValueError("log severity must be one digit from 0 to 7")
    if kind == "fortios_config_path":
        if len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*(?: [A-Za-z0-9][A-Za-z0-9_.+-]*){0,31}",value):
            return value
        raise ValueError("invalid measured configuration path")
    if kind in {"ipv4_neighbor", "ipv6_neighbor"}:
        return _canonical_address(value, kind.replace("neighbor", "address"))
    if kind in {"address", "ipv4_address", "ipv6_address"}:
        return _canonical_address(value, kind)
    canonicalizer = _VENDOR_INTERFACE_CANONICALIZERS.get(kind)
    if canonicalizer is not None:
        canonical = canonicalizer(value)
        if canonical is not None:
            return canonical
        raise ValueError(f"invalid typed {kind} value")
    if kind == "certificate_name" and value.casefold() in {"all", "any", "none", "detail", "details"}:
        raise ValueError("reserved certificate selector")
    if kind == "acl_policy" and value.casefold() in {"all", "any", "none", "detail", "dynamic", "profile", "rule"}:
        raise ValueError("reserved policy selector")
    if kind == "nxos_acl_name" and value and any(
        keyword.startswith(value.casefold()) for keyword in
        ("all", "brief", "capture", "expanded", "private", "stats-detail", "summary")
    ):
        raise ValueError("reserved NX-OS ACL selector")
    if kind == "ruckus_wlan_name" and value.casefold() == "all":
        raise ValueError("reserved WLAN selector")
    if kind == "junos_vlan_name" and any(word.startswith(value.casefold()) for word in _JUNOS_VLAN_KEYWORDS):
        raise ValueError("reserved Junos VLAN selector")
    if kind == "junos_firewall_filter" and any(word.startswith(value.casefold()) for word in _JUNOS_FILTER_KEYWORDS):
        raise ValueError("reserved Junos firewall filter selector")
    if kind == "vlan_name" and value.casefold() in {
        "all", "any", "none", "detail", "ipv4", "ipv6", "tag", "ports",
        "virtual-router", "statistics",
    }:
        raise ValueError("reserved VLAN selector")
    if kind == "eos_lacp_interface" and re.fullmatch(_EOS_PC, value):
        raise ValueError(
            "lacp_peer_interface needs a member Ethernet interface; "
            "a Port-Channel is not a member of a port channel"
        )
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
    """Reject enrolled interfaces unusable by every enabled interface query and recipes the platform lacks."""
    if platform is None:
        return
    normalized = normalize_platform(platform)
    recipe_allowlists = {
        "fortinet": {"ping", "traceroute", "sniffer", "sessions", "flow", "logs"},
        "fortiadc": FORTIADC_LOG_RECIPES.keys() | {"ping", "traceroute", "nslookup", "http_probe",
                     "health_check_verify", "session_list", "persistence_list", "disk_usage", "ntp_status",
                     "packet_capture"},
    }
    allowed_recipes = recipe_allowlists.get(normalized, set())
    if not set(inventory.get("diagnostic_recipes", ())) <= allowed_recipes:
        raise ValueError("enrolled diagnostic recipe does not exist on this platform")
    dns_platforms = _JUNOS_PLATFORMS | {"fortiadc", "fortinet", "arista_eos", "extreme_exos"}
    if inventory.get("diagnostic_names") and normalized not in dns_platforms:
        raise ValueError("enrolled diagnostic DNS names exist only on FortiADC, FortiOS, EOS, EXOS and Junos")
    if (inventory.get("diagnostic_http_endpoints") or inventory.get("adc_health_checks")) and normalized != "fortiadc":
        raise ValueError("enrolled diagnostic HTTP endpoints and health checks exist only on FortiADC")
    if inventory.get("diagnostic_virtual_servers") and normalized != "fortiadc":
        raise ValueError("enrolled virtual servers exist only on FortiADC")
    interface_kinds = {
        slot.kind
        for query_name in query_names
        for slot in READ_QUERIES[normalized][query_name].slots.values()
        if slot.inventory == "interfaces"
    }
    if not interface_kinds:
        return
    for value in inventory.get("interfaces", ()):
        if normalized == "fortinet" and value == "any" and "sniffer" in inventory.get("diagnostic_recipes", ()):
            continue  # the FortiOS sniffer interface any, enrolled like an interface (G10 FP-06, task 471-r3)
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

    if platform == "arista_eos" and command == EOS_LOGGING_STATUS_COMMAND:
        # Fixed, slotless EOS CLI filter over operational logging headers.
        return
    inspected = command
    if platform in _JUNOS_PLATFORMS:
        if command in (FILTER_BINDING_COMMAND, LOG_HISTORY_COMMAND, *CONFIG_COMMANDS.values()):
            return
        if command.count(_JUNOS_SUFFIX) != 1 or not command.endswith(_JUNOS_SUFFIX):
            raise RuntimeError("Junos query must have one fixed paging suffix")
        inspected = command.removesuffix(_JUNOS_SUFFIX)
        if inspected in _JUNOS_LOG_COMMANDS:
            return
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
    if platform == "fortiadc":
        if inspected not in _FORTIADC_COMMANDS:
            raise RuntimeError("FortiADC query is outside the reviewed templates")
        return

    if platform == "extreme_exos" and inspected == "nslookup {name}":
        return
    if platform == "extreme_exos" and inspected in {
        "ping count 5 vr {vr} {address}",
        "ping count 5 vr {vr} {address} from {source}",
        "traceroute vr {vr} {address}",
        "traceroute vr {vr} {address} from {source}",
    }:
        return
    # Fixed EOS probes use typed, enrolled parameters and a bounded ping count.
    if platform == "arista_eos" and inspected in {
        "ping vrf {vrf} {address} source {source} repeat 5",
        "ping {name} repeat 1",
        "traceroute vrf {vrf} {address}",
        "traceroute vrf {vrf} {address} source {source}",
    }:
        return
    if platform in {"cisco_ios", "cisco_xe"} and inspected in {
        'ping {address} repeat 5 timeout 1',
        'ping {address} source {source} repeat 5 timeout 1',
        'ping vrf {vrf} {address} repeat 5 timeout 1',
        'ping vrf {vrf} {address} source {source} repeat 5 timeout 1',
        'ping ipv6 {address} repeat 5 timeout 1',
        'ping ipv6 {address} source {source} repeat 5 timeout 1',
        'traceroute {address} numeric timeout 1 probe 1 ttl 1 5',
        'traceroute {address} source {source} numeric timeout 1 probe 1 ttl 1 5',
        'traceroute vrf {vrf} {address} numeric timeout 1 probe 1 ttl 1 5',
        'traceroute vrf {vrf} {address} source {source} numeric timeout 1 probe 1 ttl 1 5',
    }:
        return
    if platform == "cisco_xe" and inspected in {
        "ping vrf {vrf} ipv6 {address} repeat 5 timeout 1",
        "ping vrf {vrf} ipv6 {address} source {source} repeat 5 timeout 1",
        "traceroute ipv6 {address} numeric timeout 1 probe 1 ttl 1 5",
        "traceroute ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5",
        "traceroute vrf {vrf} ipv6 {address} numeric timeout 1 probe 1 ttl 1 5",
        "traceroute vrf {vrf} ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5",
    }:
        return
    # G91: exact NX-OS probes; no arbitrary CLI suffix or packet count.
    if platform == "cisco_nxos" and inspected in {
        "ping {address} vrf {vrf} count 5",
        "ping {address} vrf {vrf} source {source} count 5",
        "traceroute {address} vrf {vrf}",
        "traceroute {address} source {source} vrf {vrf}",
        "ping6 {address} vrf {vrf} count 5",
        "ping6 {address} vrf {vrf} source {source} count 5",
        "traceroute6 {address} vrf {vrf}",
        "traceroute6 {address} source {source} vrf {vrf}",
    }:
        return
    # Fixed Junos probes (G132): typed enrolled IPv4/instance slots, bounded count, hops and wait.
    if platform in _JUNOS_PLATFORMS and inspected in {
        "ping {address} count 5 source {source}",
        "ping {address} count 5 source {source} routing-instance {instance}",
        "traceroute {address} no-resolve ttl 30 wait 1",
        "traceroute {address} no-resolve routing-instance {instance} ttl 30 wait 1",
    }:
        return
    # G108 (R02): the Unleashed CLI ping is bounded by the device (three echo requests); one enrolled IPv4 slot.
    if platform == "ruckus_unleashed" and inspected == "ping {address}":
        return
    # G110 (RP08): the one configuration display admitted anywhere. Its text never leaves the engine unfiltered:
    # `ruckus_config_allowlist` passes a fixed list of sections and redacts secret labels (tests/test_g110_ruckus.py).
    if platform == "ruckus_unleashed" and inspected == "show config":
        return
    words = inspected.split(" ")
    if len(words) < 2 or words[0] != "show":
        raise RuntimeError("network query must use the exact show prefix")
    if platform == "extreme_exos" and inspected in _EXOS_LOG_COMMANDS:
        return
    if inspected in _NETWORK_LOG_COMMANDS.get(platform, ()):
        return
    # Only session metadata: no configuration text, selectors, suffixes or abbreviations.
    if platform == "cisco_nxos" and inspected == "show configuration session summary":
        return
    if _FORBIDDEN_SHOW_SECOND.fullmatch(words[1]) or (
        len(words) >= 3
        and [word.casefold() for word in words[1:3]] == ["key", "chain"]
    ):
        raise RuntimeError("network query uses a forbidden show family")


def _validate_query_sequence(platform: str, query: SequenceQuery) -> None:
    if platform == "fortiadc":
        if query.commands != _FORTIADC_INTERFACE_SUMMARY or query.slots:
            raise RuntimeError("FortiADC command sequence is outside the reviewed shape")
    elif query.commands not in _FORTINET_SEQUENCES:
        raise RuntimeError("Fortinet command sequence is outside the reviewed shapes")
    if query.command != "; ".join(query.commands):
        raise RuntimeError("sequence display form must be the joined commands")


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
            prompt_allowed = (platform in {"fortiadc", "fortinet", "cisco_ios"}
                              or platform == "cisco_xe" and query == IOS_XE_PROBE_QUERIES.get(name))
            if type(query.pty) is not bool or (query.pty and not prompt_allowed):
                raise RuntimeError("query pty is reserved for reviewed prompt-read platforms")
            if type(query.empty_allowed) is not bool:
                raise RuntimeError("query empty_allowed must be a boolean")
            if query.group is not None and query.group not in DEVICE_TYPES:
                raise RuntimeError("query group must be a device type or absent")
            if len(query.slots) > 16:
                raise RuntimeError("query declares too many parameters")
            if not isinstance(query.optional_slots, frozenset) or not query.optional_slots <= set(query.slots):
                raise RuntimeError("query optional parameters must be declared parameters")
            sequence = isinstance(query, SequenceQuery)
            if sequence and (platform not in {"fortinet", "fortiadc"} or query.pty):
                raise RuntimeError("command sequences are reserved for reviewed Fortinet queries")
            filter_only = query.filter_slots
            # The Junos messages history is filtered locally by its required interval slots as well.
            junos_history = not sequence and platform in _JUNOS_PLATFORMS and query.command == LOG_HISTORY_COMMAND
            xe_history = (not sequence and platform in {"cisco_ios", "cisco_xe"} and name == XE_LOG_HISTORY
                          and query.command == XE_LOG_COMMAND)
            nxos_history = (not sequence and platform == "cisco_nxos" and name == NXOS_LOG_HISTORY
                            and query == NXOS_G93_QUERIES[NXOS_LOG_HISTORY])
            if not (junos_history or xe_history) and not filter_only <= query.optional_slots:
                raise RuntimeError("output filter parameters must be optional")
            if not sequence and filter_only and not (
                platform == "arista_eos" and name in EOS_LOG_WINDOW_QUERIES and filter_only == {"interface"}
                and query.slots["interface"] == Slot("interfaces", "eos_interface")
            ) and not (
                platform == "extreme_exos" and name == EXOS_LOG_HISTORY and filter_only == {"interface"}
                and query.slots["interface"] == Slot("interfaces", "extreme_physical_port")
            ) and not (junos_history or xe_history or nxos_history):
                raise RuntimeError("single-command output filters are reserved for reviewed log queries")
            for slot_name, slot in query.slots.items():
                if (
                    not isinstance(slot_name, str)
                    or not _SLOT_NAME.fullmatch(slot_name)
                    or not isinstance(slot, Slot)
                    or slot.kind not in _KIND_INVENTORY
                    or _KIND_INVENTORY[slot.kind] != slot.inventory
                    or type(slot.lookup_only) is not bool
                    or (slot.lookup_only and (slot.kind != "ip_literal" or not query.command.startswith("show ")))
                ):
                    raise RuntimeError("query declares an invalid typed parameter")

            if sequence:
                _validate_query_sequence(platform, query)
            else:
                _validate_query_command(platform, query.command)
                for slot_name in query.optional_slots - filter_only:
                    tail = " {" + slot_name + "}"
                    if not query.command.endswith(tail) or query.command.count("{" + slot_name + "}") != 1:
                        raise RuntimeError("optional parameter must be the trailing template field")
                    _validate_query_command(platform, query.command.removesuffix(tail))
            fields: list[str] = []
            templates = query.commands if sequence else (query.command,)
            try:
                for _, field, format_spec, conversion in (
                    part for template in templates for part in Formatter().parse(template)
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
            if (
                len(fields) != len(set(fields))
                or set(fields) | filter_only != set(query.slots)
                or set(fields) & filter_only
            ):
                raise RuntimeError("query template and slot declaration differ")


if set(READ_QUERIES) != _EXPECTED_PLATFORMS:
    raise RuntimeError("canonical query platforms do not match the reviewed set")
_validate_query_catalogs(READ_QUERIES)


LOG_SEVERITIES = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational",
                  "debugging")
LOG_WINDOW_KINDS = frozenset({
    "eos_log_minutes", "nxos_log_count", "log_severity", "log_date", "log_time", "exos_log_source", "exos_log_severity",
})


def _valid_log_window_value(value: str, kind: str) -> bool:
    """Validate typed log source, severity, minutes, date or time selectors."""
    if kind in {"eos_log_minutes", "nxos_log_count"}:
        limit = 1000 if kind == "nxos_log_count" else 9999
        return len(value) <= 4 and _canonical_decimal(value, 1, limit) is not None
    if kind == "log_severity":
        return value in LOG_SEVERITIES
    if kind == "exos_log_severity":
        return value in EXOS_LOG_SEVERITIES
    if kind == "exos_log_source":
        return value in EXOS_LOG_SOURCES
    pattern = r"20[0-9]{2}-[01][0-9]-[0-3][0-9]" if kind == "log_date" else r"[0-2][0-9]:[0-5][0-9]:[0-5][0-9]"
    if not re.fullmatch(pattern, value):
        return False
    from datetime import datetime
    try:
        datetime.strptime(value, "%Y-%m-%d" if kind == "log_date" else "%H:%M:%S")
    except ValueError:
        return False
    return True


def check_log_range(parameters: Mapping[str, str]) -> None:
    if (parameters["begin_date"], parameters["begin_time"]) > (parameters["end_date"], parameters["end_time"]):
        raise ValueError("log time range must not end before it begins")


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
    queries = READ_QUERIES[normalized]
    # Internal identity aliases are not enrolled/renderable public queries.
    if query_name not in queries:
        raise ValueError(f"unknown read query for platform: {normalized}")
    query = queries[query_name]
    if isinstance(query, SequenceQuery):
        raise ValueError("query is a command sequence; use render_read_sequence")
    rendered = _render_slots(query, parameters, inventory)
    if normalized in {"cisco_ios", "cisco_xe"} and query_name in {"mac_table_address", "c9800_client_detail"}:
        # Catalyst IOS and IOS XE use the H.H.H form for MAC lookups.
        compact = rendered["mac"].replace(":", "")
        rendered["mac"] = ".".join(compact[start:start + 4] for start in (0, 4, 8))
    if (normalized, query_name) in {("arista_eos", "log_messages_range"), ("extreme_exos", EXOS_LOG_HISTORY)}:
        check_log_range(rendered)
    if normalized == "cisco_nxos" and query_name == NXOS_LOG_HISTORY:
        nxos_log_window(rendered)
    if normalized == "extreme_exos" and query_name == EXOS_LOG_HISTORY:
        for name in ("begin_date", "end_date"):
            year, month, day = rendered[name].split("-")
            rendered[name] = f"{month}/{day}/{year}"
    if normalized in _JUNOS_PLATFORMS and query_name == LOG_HISTORY_QUERY:
        log_window(rendered)
    if normalized in {"cisco_ios", "cisco_xe"} and query_name == XE_LOG_HISTORY:
        xe_log_window(rendered)
    command = query.command
    for name in query.optional_slots - query.filter_slots:
        if name not in rendered:
            command = command.removesuffix(" {" + name + "}")
    return normalized, command.format_map(rendered)


def _render_slots(
    query: Query,
    parameters: Mapping[str, str] | None,
    inventory: Mapping[str, tuple[str, ...]],
) -> dict[str, str]:
    supplied = dict(parameters or {})
    required = set(query.slots) - query.optional_slots
    if not required <= set(supplied) <= set(query.slots):
        raise ValueError(f"query parameters must be exactly: {sorted(required)}"
                         + (f" plus optionally {sorted(query.optional_slots)}" if query.optional_slots else ""))
    rendered: dict[str, str] = {}
    for name, supplied_value in supplied.items():
        slot = query.slots[name]
        value = _validate_slot(supplied_value, slot.kind, lookup_only=slot.lookup_only)
        if slot.kind in LOOKUP_KINDS:
            try:
                network = enrolled_lookup(value, LOOKUP_KINDS[slot.kind], inventory)
            except ValueError:
                raise ValueError(f"{name} is not enrolled in target inventory") from None
            rendered[name] = str(network.network_address)
            continue
        if slot.inventory not in (None, LITERAL) and not enrolled_interface(
                supplied_value, slot.kind, inventory.get(slot.inventory, ())):
            raise ValueError(f"{name} is not enrolled in target inventory")
        rendered[name] = value.replace(".", " unit ", 1) if slot.kind == "junos_filter_interface" else value
    return rendered


def render_read_sequence(
    platform: str,
    query_name: str,
    parameters: Mapping[str, str] | None,
    inventory: Mapping[str, tuple[str, ...]],
) -> tuple[str, tuple[str, ...], dict[str, str]]:
    """Render a SequenceQuery into its exact commands and the filters the Helper applies to the output."""
    normalized = normalize_platform(platform)
    if not isinstance(query_name, str):
        raise ValueError("query name must be a string")
    if parameters is not None and (
        not isinstance(parameters, dict)
        or len(parameters) > 16
        or any(not isinstance(name, str) or not isinstance(value, str) for name, value in parameters.items())
    ):
        raise ValueError("query parameters must be a bounded string mapping")
    query = READ_QUERIES[normalized].get(query_name)
    if not isinstance(query, SequenceQuery):
        raise ValueError(f"unknown read sequence for platform: {normalized}")
    rendered = _render_slots(query, parameters, inventory)
    commands = tuple(command.format_map(rendered) for command in query.commands)
    if normalized == "fortiadc":
        if commands != _FORTIADC_INTERFACE_SUMMARY:
            raise ValueError("FortiADC command sequence is outside the reviewed shape")
    else:
        require_fortinet_sequence(commands)
    return normalized, commands, {name: rendered[name] for name in query.filter_slots if name in rendered}


def is_read_sequence(platform: str, query_name: str) -> bool:
    return isinstance(READ_QUERIES.get(normalize_platform(platform), {}).get(query_name), SequenceQuery)


def public_query_catalog() -> dict[str, dict[str, list[str]]]:
    return {
        platform: {
            name: sorted(slot.inventory for slot in query.slots.values() if slot.inventory is not None)
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
                **({"requires_device_permission": query.requires_device_permission,
                    "read_only_account": query.read_only_account} if query.requires_device_permission else {}),
                "parameters": {
                    slot_name: {
                        "inventory": slot.inventory,
                        "kind": slot.kind,
                        **({"optional": True} if slot_name in query.optional_slots else {}),
                        **({"lookup_only": True} if slot.lookup_only else {}),
                    }
                    for slot_name, slot in sorted(query.slots.items())
                },
            }
            for name, query in sorted(queries.items())
        }
        for platform, queries in sorted(READ_QUERIES.items())
    }
