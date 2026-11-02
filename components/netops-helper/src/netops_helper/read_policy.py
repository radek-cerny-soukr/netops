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


def _canonical_cisco_ios_interface(value: str, physical_only: bool) -> str | None:
    if value.casefold() in _CISCO_IOS_RESERVED:
        return None
    ethernet = _canonical_cisco_ethernet(value)
    if ethernet is not None:
        return ethernet
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
    "fortiadc_interface": lambda value: (
        _canonical_fortios_interface(value) if value[:1].isalnum() else None
    ),
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

SAFE_FORTIADC_OBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,34}")
_TOKEN_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "interface": SAFE_INTERFACE,
    "service": SAFE_SERVICE,
    "switch": SAFE_SWITCH,
    "vlan_name": re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}"),
    "certificate_name": re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,78}"),
    "fortios_address_object": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}"),
    "fortios_station_mac": re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"),
    "flow_port": re.compile(r"(?:0|[1-9][0-9]{0,4})"),
    "ip_protocol": re.compile(r"(?:0|[1-9][0-9]{0,2})"),
    "fortios_policy_type": re.compile(r"(?:policy|proxy)"),
    "fortios_nat_pool": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}"),
    "managed_switch_serial": re.compile(r"S[A-Z0-9]{11,15}"),
    "managed_switch_port": re.compile(r"port[1-9][0-9]{0,2}"),
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
    "vlan_name": "vlans",
    "managed_switch_serial": "managed_switches",
    "managed_switch_port": "managed_switch_ports",
    "managed_switch_trunk": "managed_switch_trunks",
    "certificate_name": "certificates",
    "fortios_address_object": "firewall_addresses",
    "fortios_station_mac": "wireless_clients",
    "flow_port": "flow_ports",
    "ip_protocol": "ip_protocols",
    "fortios_policy_type": "policy_types",
    "fortios_nat_pool": "nat_pools",
    "fortios_sdwan_health_check": "sdwan_health_checks",
    "fortios_link_monitor": "link_monitors",
    "fortios_sdwan_member": "sdwan_members",
    "fortios_sdwan_rule": "sdwan_rules",
    "fortiadc_vdom": "adc_vdoms",
    "fortiadc_virtual_server": "adc_virtual_servers",
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
    "vlans": "vlan_name",
    "managed_switches": "managed_switch_serial",
    "managed_switch_ports": "managed_switch_port",
    "managed_switch_trunks": "managed_switch_trunk",
    "certificates": "certificate_name",
    "firewall_addresses": "fortios_address_object",
    "wireless_clients": "fortios_station_mac",
    "flow_ports": "flow_port",
    "ip_protocols": "ip_protocol",
    "policy_types": "fortios_policy_type",
    "nat_pools": "fortios_nat_pool",
    "sdwan_health_checks": "fortios_sdwan_health_check",
    "link_monitors": "fortios_link_monitor",
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
    "execute ping-options view-settings",
    "execute traceroute-options view-settings",
    "diagnose debug info",
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
    "get system interface physical",
    "diagnose netlink aggregate name {aggregate} show",
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
    "diagnose sys sdwan intf-sla-log {interface}",
    "diagnose sys sdwan sla-log {health_check} {member}",
    "diagnose sys link-monitor status {monitor}",
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
_FORTIADC_COMMANDS = frozenset({
    "get system status",
    "get system performance",
    "diagnose system vm",
    "diagnose netlink interface list {interface}",
    "diagnose netlink device",
    "get router info routing-table all",
    "diagnose netlink neighbor list",
    "get firewall global",
    "diagnose server-load-balance slb_load",
    "get security waf-signature-status",
    "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server}",
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


def _validate_slot(value: str, kind: str) -> str:
    if not isinstance(value, str):
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
        if value in {"ping", "traceroute", "sniffer", "sessions", "flow", "nslookup", "http_probe", "health_check_verify",
                     "logs", "system_event_logs", "waf_attack_logs", "session_list", "persistence_list"}:
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
    if kind == "diagnostic_dns_name":
        if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            return value
        raise ValueError("invalid diagnostic DNS name")
    if kind == "fortios_config_path":
        if len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*(?: [A-Za-z0-9][A-Za-z0-9_.+-]*){0,31}",value):
            return value
        raise ValueError("invalid measured configuration path")
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
        "fortiadc": {"ping", "traceroute", "nslookup", "http_probe", "health_check_verify",
                     "system_event_logs", "waf_attack_logs", "session_list", "persistence_list"},
    }
    allowed_recipes = recipe_allowlists.get(normalized, set())
    if not set(inventory.get("diagnostic_recipes", ())) <= allowed_recipes:
        raise ValueError("enrolled diagnostic recipe does not exist on this platform")
    if inventory.get("diagnostic_names") and normalized != "fortiadc":
        raise ValueError("enrolled diagnostic DNS names exist only on FortiADC")
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
    if platform == "fortiadc":
        if inspected not in _FORTIADC_COMMANDS:
            raise RuntimeError("FortiADC query is outside the reviewed templates")
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
            if type(query.pty) is not bool or (query.pty and platform not in ("fortiadc", "fortinet")):
                raise RuntimeError("query pty is reserved for FortiADC and FortiOS")
            if type(query.empty_allowed) is not bool:
                raise RuntimeError("query empty_allowed must be a boolean")
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
