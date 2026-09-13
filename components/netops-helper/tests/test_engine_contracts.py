#!/usr/bin/env python3
"""Dependency-free authentication and phase-1 query-boundary tests."""

from __future__ import annotations

from base64 import urlsafe_b64encode
import ast
from contextlib import contextmanager
import importlib
import ipaddress
import json
from pathlib import Path
import sys
import types

from netops_helper.auth import (
    AuthenticationContextError,
    AuthenticationMaterialError,
    EgressScopeError,
    PolicyScopeError,
    TargetAuth,
)
from netops_helper.query_catalog import (
    ARISTA_EOS_QUERIES,
    EXTREME_EXOS_QUERIES,
    FORTINET_QUERIES,
    IOS_QUERIES,
    IOS_XE_QUERIES,
    JUNIPER_JUNOS_ELS_QUERIES,
    JUNIPER_JUNOS_QUERIES,
    LINUX_QUERIES,
    NXOS_QUERIES,
    READ_QUERIES as AUTHORITY_READ_QUERIES,
)
from netops_helper.query_catalog.model import Query, Slot
from netops_helper.read_policy import (
    PLATFORM_MAP,
    READ_QUERIES,
    _validate_query_catalogs,
    normalize_platform,
    public_query_catalog,
    public_query_metadata,
    render_read_query,
    validate_inventory_item,
)


TEST_ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 10))
TEST_IPV6_ADDRESS = str(ipaddress.IPv6Address((0x20010DB8 << 96) | 10))
_MISSING = object()


def _context(**overrides: object) -> str:
    envelope: dict[str, object] = {
        "alias": "device-a",
        "host": TEST_ADDRESS,
        "port": 22,
        "login": "reader",
        "password": "ssh-secret",
        "account_role": "read-only",
        "ssh_platform": None,
        "enabled_queries": [],
        "egress": {
            "addresses": [TEST_ADDRESS],
            "tcp_ports": [],
            "udp_ports": [161],
            "tcp_port_ranges": [],
            "udp_port_ranges": [],
            "allow_icmp": False,
            "allow_dns": False,
            "tls_server_names": [],
        },
    }
    for name, value in overrides.items():
        if value is _MISSING:
            envelope.pop(name, None)
        else:
            envelope[name] = value
    raw = json.dumps(envelope).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_snmp_community_is_optional_for_non_snmp_tools() -> None:
    auth = TargetAuth.decode("device-a", _context())
    assert auth.snmp_community is None
    try:
        auth.require_snmp_community()
    except AuthenticationMaterialError as exc:
        assert exc.error_code == "auth_material"
    else:
        raise AssertionError("missing SNMP community was accepted")


def test_snmp_community_is_distinct_and_part_of_secret_set() -> None:
    auth = TargetAuth.decode("device-a", _context(snmp_community="snmp-secret"))
    assert auth.require_snmp_community() == "snmp-secret"
    assert auth.secrets == ("ssh-secret", "snmp-secret")


def test_equal_snmp_and_ssh_secrets_are_rejected() -> None:
    try:
        TargetAuth.decode("device-a", _context(snmp_community="ssh-secret"))
    except AuthenticationMaterialError as exc:
        assert exc.error_code == "auth_material"
        assert "ssh-secret" not in str(exc)
    else:
        raise AssertionError("SNMP community reused the SSH password")


def test_non_ascii_snmp_and_ssh_secrets_compare_as_utf8() -> None:
    auth = TargetAuth.decode(
        "device-a",
        _context(password="ssh-heslo-ž", snmp_community="snmp-komunita-č"),
    )
    assert auth.require_snmp_community() == "snmp-komunita-č"
    try:
        TargetAuth.decode(
            "device-a",
            _context(password="stejné-heslo", snmp_community="stejné-heslo"),
        )
    except AuthenticationMaterialError:
        pass
    else:
        raise AssertionError("equal non-ASCII secrets were accepted")


def test_direct_snmp_accessor_rejects_malformed_material_cleanly() -> None:
    malformed = (
        (7, "account-secret"),
        (chr(0xD800), "account-secret"),
        ("snmp-secret", 7),
        ("snmp-secret", chr(0xD800)),
    )
    for community, password in malformed:
        auth = TargetAuth(
            "device-a",
            TEST_ADDRESS,
            22,
            "reader",
            password,
            "",
            snmp_community=community,
        )
        try:
            auth.require_snmp_community()
        except AuthenticationMaterialError as exc:
            assert exc.error_code == "auth_material"
        except (AttributeError, TypeError, UnicodeError) as exc:
            raise AssertionError(
                "malformed direct SNMP material escaped as a raw exception"
            ) from exc
        else:
            raise AssertionError("malformed direct SNMP material was accepted")


def test_unsafe_snmp_community_is_invalid() -> None:
    for value in (None, "ab", "bad\nvalue"):
        try:
            TargetAuth.decode("device-a", _context(snmp_community=value))
        except AuthenticationContextError:
            pass
        else:
            raise AssertionError("unsafe SNMP community was accepted")


def test_identity_types_and_top_level_fields_fail_closed() -> None:
    invalid = (
        {"port": True},
        {"alias": 7},
        {"host": 7},
        {"login": ["reader"]},
        {"password": {"secret": True}},
        {"known_hosts": 7},
        {"account_role": ["read-only"]},
        {"fortios_output_standard_verified": 1},
        {"unexpected_field": True},
        {"https_endpoints": []},
    )
    for override in invalid:
        try:
            TargetAuth.decode("device-a", _context(**override))
        except AuthenticationContextError:
            pass
        else:
            raise AssertionError(f"unsafe identity envelope was accepted: {tuple(override)}")


def test_hostname_requires_dns_and_explicit_addresses_during_decode() -> None:
    base = {
        "addresses": [TEST_ADDRESS],
        "tcp_ports": [],
        "udp_ports": [],
        "tcp_port_ranges": [],
        "udp_port_ranges": [],
        "allow_icmp": False,
        "allow_dns": False,
        "tls_server_names": [],
    }
    for egress in (
        base,
        {**base, "addresses": [], "allow_dns": True},
    ):
        try:
            TargetAuth.decode("device-a", _context(host="device.invalid", egress=egress))
        except EgressScopeError:
            pass
        else:
            raise AssertionError("hostname without DNS/address scope was accepted")
    allowed = TargetAuth.decode(
        "device-a",
        _context(
            host="device.invalid",
            egress={**base, "allow_dns": True},
        ),
    )
    assert allowed.host == "device.invalid"


def test_policy_fields_are_mandatory_and_egress_shape_is_exact() -> None:
    for field in ("ssh_platform", "enabled_queries", "egress"):
        try:
            TargetAuth.decode("device-a", _context(**{field: _MISSING}))
        except AuthenticationContextError:
            pass
        else:
            raise AssertionError(f"missing {field} was accepted")

    egress = {
        "addresses": [TEST_ADDRESS],
        "tcp_ports": [],
        "udp_ports": [],
        "tcp_port_ranges": [],
        "udp_port_ranges": [],
        "allow_icmp": False,
        "allow_dns": False,
        "tls_server_names": [],
        "unexpected": [],
    }
    try:
        TargetAuth.decode("device-a", _context(egress=egress))
    except AuthenticationContextError:
        pass
    else:
        raise AssertionError("unexpected egress field was accepted")


def test_range_wire_shape_and_duplicates_fail_closed() -> None:
    base = {
        "addresses": [TEST_ADDRESS],
        "tcp_ports": [],
        "udp_ports": [],
        "tcp_port_ranges": [],
        "udp_port_ranges": [],
        "allow_icmp": False,
        "allow_dns": False,
        "tls_server_names": [],
    }
    invalid = (
        {**base, "tcp_port_ranges": [{"start": 1000, "end": 2000}]},
        {**base, "tcp_port_ranges": [[1000, 2000], [1500, 2500]]},
        {**base, "addresses": [TEST_ADDRESS, TEST_ADDRESS]},
        {**base, "udp_ports": [161, 161]},
        {
            **base,
            "tcp_ports": [1500],
            "tcp_port_ranges": [[1000, 2000]],
        },
        {
            **base,
            "udp_ports": [1500],
            "udp_port_ranges": [[1000, 2000]],
        },
    )
    for egress in invalid:
        try:
            TargetAuth.decode("device-a", _context(egress=egress))
        except AuthenticationContextError:
            pass
        else:
            raise AssertionError("malformed or duplicate egress value was accepted")


def test_envelope_collections_are_canonical_unique_and_control_free() -> None:
    invalid = (
        {"sftp_roots": ["/safe//log"]},
        {"sftp_roots": ["/safe", "/safe"]},
        {"read_inventory": {"interfaces": ["port3", "port3"]}},
        {"read_inventory": {"interfaces": ["port" + chr(0) + "3"]}},
        {"read_inventory": {"interfaces": ["Ethernet1/1;show"]}},
        {"read_inventory": {"services": ["service" + chr(127)]}},
        {"read_inventory": {"services": ["sshd --now"]}},
        {"read_inventory": {"addresses": [TEST_ADDRESS, TEST_ADDRESS]}},
        {"read_inventory": {"addresses": ["2001:0db8::10"]}},
        {"read_inventory": {"switches": ["switch" + chr(127)]}},
        {"read_inventory": {"switches": ["switch|show"]}},
    )
    for override in invalid:
        try:
            TargetAuth.decode("device-a", _context(**override))
        except AuthenticationContextError:
            pass
        else:
            raise AssertionError(f"unsafe collection was accepted: {tuple(override)}")


def test_auth_accepts_every_platform_alias_with_a_known_query() -> None:
    for alias, canonical in PLATFORM_MAP.items():
        query = next(iter(READ_QUERIES[canonical]))
        auth = TargetAuth.decode(
            "device-a",
            _context(ssh_platform=alias, enabled_queries=[query]),
        )
        assert auth.ssh_platform == canonical
        assert auth.enabled_queries == (query,)
        assert auth.require_ssh_query(alias, query) == canonical


def test_query_parameters_do_not_coerce_non_string_values() -> None:
    for platform, query, parameters in (
        (7, "interface_details", {"interface": "port3"}),
        ("fortios", 7, {"interface": "port3"}),
        ("fortios", "interface_details", {"interface": 3}),
        ("fortios", "interface_details", [("interface", "port3")]),
    ):
        try:
            render_read_query(
                platform, query, parameters, {"interfaces": ("port3",)},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("non-string query input was coerced")


def test_query_and_egress_capabilities_are_explicit() -> None:
    auth = TargetAuth.decode(
        "device-a",
        _context(ssh_platform="fortios", enabled_queries=["arp_table"]),
    )
    assert auth.require_ssh_query("fortios", "arp_table") == "fortinet"
    for platform, query in (("linux", "neighbors"), ("fortios", "routing_table")):
        try:
            auth.require_ssh_query(platform, query)
        except PolicyScopeError:
            pass
        else:
            raise AssertionError("unenrolled SSH capability was accepted")
    try:
        auth.require_tcp_port(443)
    except EgressScopeError:
        pass
    else:
        raise AssertionError("unenrolled TCP port was accepted")


def test_catalog_authority_and_platform_aliases_are_exact() -> None:
    expected_authorities = {
        "linux": LINUX_QUERIES,
        "fortinet": FORTINET_QUERIES,
        "extreme_exos": EXTREME_EXOS_QUERIES,
        "cisco_ios": IOS_QUERIES,
        "cisco_xe": IOS_XE_QUERIES,
        "cisco_nxos": NXOS_QUERIES,
        "arista_eos": ARISTA_EOS_QUERIES,
        "juniper_junos": JUNIPER_JUNOS_QUERIES,
        "juniper_junos_els": JUNIPER_JUNOS_ELS_QUERIES,
    }
    assert READ_QUERIES is AUTHORITY_READ_QUERIES
    assert set(READ_QUERIES) == set(expected_authorities)
    for platform, authority in expected_authorities.items():
        assert READ_QUERIES[platform] is authority

    expected_aliases = {
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
    }
    assert PLATFORM_MAP == expected_aliases
    for alias, canonical in expected_aliases.items():
        assert normalize_platform(alias) == canonical
    assert normalize_platform("FORTIOS") == "fortinet"
    for unsupported in ("extreme_switch", "junos_els", "nxos", 7):
        try:
            normalize_platform(unsupported)
        except ValueError:
            pass
        else:
            raise AssertionError("unsupported platform alias was accepted")


def test_ip_address_families_are_enforced_and_canonicalized() -> None:
    normalized, command = render_read_query(
        "cisco_ios",
        "route_lookup",
        {"address": TEST_ADDRESS},
        {"addresses": (TEST_ADDRESS,)},
    )
    assert (normalized, command) == (
        "cisco_ios",
        f"show ip route {TEST_ADDRESS}",
    )
    normalized, command = render_read_query(
        "cisco_nxos",
        "ipv6_route_lookup",
        {"address": TEST_IPV6_ADDRESS},
        {"addresses": (TEST_IPV6_ADDRESS,)},
    )
    assert (normalized, command) == (
        "cisco_nxos",
        f"show ipv6 route {TEST_IPV6_ADDRESS}",
    )

    wrong_family = (
        ("cisco_ios", "route_lookup", TEST_IPV6_ADDRESS),
        ("cisco_nxos", "ipv6_route_lookup", TEST_ADDRESS),
    )
    for platform, query, address in wrong_family:
        try:
            render_read_query(
                platform,
                query,
                {"address": address},
                {"addresses": (address,)},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("wrong IP address family was accepted")

    assert validate_inventory_item("addresses", TEST_ADDRESS) == TEST_ADDRESS
    assert (
        validate_inventory_item("addresses", TEST_IPV6_ADDRESS)
        == TEST_IPV6_ADDRESS
    )
    noncanonical = (
        "2001:0db8:0000:0000:0000:0000:0000:000a",
        "2001:DB8::A",
        "192.002.000.010",
    )
    for address in noncanonical:
        try:
            validate_inventory_item("addresses", address)
        except ValueError:
            pass
        else:
            raise AssertionError("noncanonical IP address was accepted")


def _render_interface(platform: str, query: str, value: str) -> str:
    _, command = render_read_query(
        platform,
        query,
        {"interface": value},
        {"interfaces": (value,)},
    )
    return command


def test_extreme_physical_port_kind_is_single_and_canonical() -> None:
    for value in ("1", "24", "1:1", "8:48", "1/47", "2:49:4"):
        assert value in _render_interface(
            "extreme_switch_engine",
            "interface_details",
            value,
        )

    invalid = (
        "all",
        "tag",
        "1:1-1:48",
        "1:1,1:2",
        "1:*",
        "*:1",
        "1:1 1:2",
        "port 1:1",
        "01",
        "0",
        "0:1",
        "1:0",
        "1:01",
        "1:1:0",
        "1000",
        "1:1000",
        "1:1:1000",
        "1/1/1",
        "1:1/1",
        "1/1:1",
        "1//1",
        "1::1",
        "1:1:1:1",
        "1:1 no-refresh",
    )
    for value in invalid:
        try:
            _render_interface(
                "extreme_switch_engine",
                "interface_details",
                value,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe Extreme physical port was accepted")


def test_eos_and_junos_slot_kinds_accept_only_canonical_forms() -> None:
    eos_positive = (
        ("interface_details", "Ethernet1"),
        ("interface_details", "Ethernet3/1"),
        ("interface_details", "Management1"),
        ("interface_details", "Port-Channel10"),
        ("interface_details", "Loopback0"),
        ("interface_details", "Vlan4094"),
        ("interface_optics", "Ethernet3/1"),
        ("lldp_neighbors_interface", "Management1"),
        ("lacp_peer_interface", "Port-Channel10"),
        ("stp_interface", "Ethernet1"),
        ("ospf_neighbors_interface", "Vlan4094"),
    )
    for query, value in eos_positive:
        assert value in _render_interface("arista_eos", query, value)

    junos_positive = (
        ("interface_details", "xe-0/0/1"),
        ("interface_details", "ge-1/0/47.0"),
        ("interface_details", "ae0"),
        ("interface_details", "ae0.0"),
        ("interface_details", "irb.500"),
        ("interface_details", "lo0.0"),
        ("interface_details", "reth1.0"),
        ("interface_optics", "xe-0/0/1"),
        ("arp_interface", "ge-1/0/47.0"),
        ("ipv6_neighbors_interface", "irb.500"),
        ("lacp_interface", "ae0"),
        ("lacp_interface", "et-0/0/0"),
        ("lacp_interface", "ge-1/0/47"),
    )
    for query, value in junos_positive:
        assert value in _render_interface("juniper_junos", query, value)

    invalid = (
        ("arista_eos", "interface_details", "Et1"),
        ("arista_eos", "interface_details", "ethernet1"),
        ("arista_eos", "interface_details", "Ethernet1;show"),
        ("arista_eos", "interface_details", "Ethernet 1"),
        ("arista_eos", "interface_details", "Port-Channel-1"),
        ("arista_eos", "interface_details", "Vlan0/1"),
        ("arista_eos", "interface_details", "../Ethernet1"),
        ("arista_eos", "interface_optics", "Port-Channel10"),
        ("arista_eos", "lldp_neighbors_interface", "Loopback0"),
        ("arista_eos", "lacp_peer_interface", "Vlan4094"),
        ("arista_eos", "stp_interface", "Loopback0"),
        ("juniper_junos", "interface_details", "GE-0/0/0"),
        ("juniper_junos", "interface_details", "../ge-0/0/0"),
        ("juniper_junos", "interface_details", "ge-0/0/0 terse"),
        ("juniper_junos", "interface_optics", "ge-0/0/0.0"),
        ("juniper_junos", "interface_optics", "ae0"),
        ("juniper_junos", "arp_interface", "ge-0/0/0"),
        ("juniper_junos", "arp_interface", "ae0"),
        ("juniper_junos", "lacp_interface", "ae0.0"),
        ("juniper_junos", "lacp_interface", "reth1"),
    )
    for platform, query, value in invalid:
        try:
            _render_interface(platform, query, value)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"unsafe {platform} interface was accepted for {query}"
            )


def test_public_inventory_validator_is_exact_and_fail_closed() -> None:
    accepted = (
        ("interfaces", "port3", "port3"),
        ("services", "sshd.service", "sshd.service"),
        ("addresses", TEST_ADDRESS, TEST_ADDRESS),
        ("switches", "switch-1", "switch-1"),
    )
    for category, value, expected in accepted:
        assert validate_inventory_item(category, value) == expected

    rejected = (
        ("unknown", "value"),
        ("interfaces", ""),
        ("interfaces", "port 3"),
        ("interfaces", "port3;show"),
        ("interfaces", "port3" + chr(0)),
        ("services", "sshd/service"),
        ("services", "service" + chr(127)),
        ("switches", "switch/1"),
        ("addresses", "192.0.2.999"),
        ("addresses", "fe80::1%eth0"),
        (7, "port3"),
        ("interfaces", 7),
    )
    for category, value in rejected:
        try:
            validate_inventory_item(category, value)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe inventory value was accepted")


def test_public_query_metadata_preserves_legacy_catalog_shape() -> None:
    legacy = public_query_catalog()
    metadata = public_query_metadata()
    assert set(legacy) == set(metadata) == set(READ_QUERIES)
    assert legacy["arista_eos"]["interface_optics"] == ["interfaces"]
    assert metadata["arista_eos"]["interface_optics"] == {
        "command_template": "show interfaces {interface} transceiver",
        "description": (
            "Show transceiver diagnostics for one enrolled physical interface."
        ),
        "high_volume": False,
        "parameters": {
            "interface": {
                "inventory": "interfaces",
                "kind": "eos_physical_interface",
            },
        },
    }
    assert metadata["cisco_ios"]["vlans"]["high_volume"] is True
    for platform in metadata.values():
        for query in platform.values():
            assert set(query) == {
                "command_template",
                "description",
                "high_volume",
                "parameters",
            }


def test_command_template_metadata_is_not_an_execution_input() -> None:
    metadata = public_query_metadata()
    for profile, queries in READ_QUERIES.items():
        assert set(metadata[profile]) == set(queries)
        for query_name, query in queries.items():
            assert metadata[profile][query_name]["command_template"] == query.command

    for profile, queries in READ_QUERIES.items():
        for query_name, query in queries.items():
            command_template = metadata[profile][query_name]["command_template"]
            if command_template in queries:
                assert command_template == query_name
                continue
            try:
                render_read_query(profile, command_template, {}, {})
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"command template was accepted as a query name: {profile}/{query_name}"
                )

    try:
        render_read_query(
            "cisco_ios",
            "version",
            {"command_template": "show version"},
            {},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("command template was accepted as a query parameter")


def test_import_time_catalog_invariant_rejects_invalid_corpus() -> None:
    valid = {
        "cisco_ios": {
            "version": Query("show version", {}, "Show version."),
        },
    }
    _validate_query_catalogs(valid)

    invalid = (
        {"cisco_ios": {"Bad-Name": Query("show version", {}, "Show version.")}},
        {"cisco_ios": {"bad": Query("show version", {}, "")}},
        {
            "cisco_ios": {
                "bad": Query("show version", {}, "Show version.", high_volume=1),
            },
        },
        {"cisco_ios": {"bad": Query("show  version", {}, "Show version.")}},
        {
            "cisco_ios": {
                "bad": Query("show version" + chr(10), {}, "Show version."),
            },
        },
        {
            "cisco_ios": {
                "bad": Query(
                    "show interfaces {missing}",
                    {"interface": Slot("interfaces", "interface")},
                    "Show interface.",
                ),
            },
        },
        {
            "cisco_ios": {
                "bad": Query(
                    "show interfaces {interface}",
                    {"interface": Slot("services", "interface")},
                    "Show interface.",
                ),
            },
        },
        {"linux": {"bad": Query("show version", {}, "Show version.")}},
        {"linux": {"bad": Query("ip link set dev eth0 down", {}, "Show link.")}},
        {
            "linux": {
                "bad": Query("ip route show table all", {}, "Show routes."),
            },
        },
        {
            "linux": {
                "bad": Query(
                    "systemctl --no-pager --full status {service} extra",
                    {"service": Slot("services", "service")},
                    "Show service.",
                ),
            },
        },
        {"fortinet": {"bad": Query("show version", {}, "Show version.")}},
        {
            "fortinet": {
                "bad": Query("diagnose debug enable", {}, "Show debug."),
            },
        },
        {
            "fortinet": {
                "bad": Query(
                    "diagnose sniffer packet any",
                    {},
                    "Show packets.",
                ),
            },
        },
        {
            "fortinet": {
                "bad": Query(
                    "get system full-configuration",
                    {},
                    "Show system.",
                ),
            },
        },
        {"cisco_ios": {"bad": Query("get system status", {}, "Show status.")}},
        {
            "cisco_ios": {
                "bad": Query("show running-config", {}, "Show system."),
            },
        },
        {
            "cisco_nxos": {
                "bad": Query("show key chain", {}, "Show keys."),
            },
        },
        {
            "arista_eos": {
                "bad": Query("show tech-support", {}, "Show system."),
            },
        },
        {"juniper_junos": {"bad": Query("show version", {}, "Show version.")}},
        {
            "juniper_junos": {
                "bad": Query(
                    "show version | match detail | no-more",
                    {},
                    "Show version.",
                ),
            },
        },
    )
    for catalogs in invalid:
        try:
            _validate_query_catalogs(catalogs)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid query catalogue was accepted")


def test_vendor_lldp_commands_use_supported_local_read_queries() -> None:
    assert (
        READ_QUERIES["fortinet"]["lldp_summary"].command
        == "diagnose lldp rx neighbor summary"
    )
    assert (
        READ_QUERIES["arista_eos"]["lldp_neighbors"].command
        == "show lldp neighbors"
    )


def test_phase1_catalog_has_no_configuration_export() -> None:
    forbidden = (
        "running-config",
        "startup-config",
        "full-configuration",
        "show configuration",
        "backup configuration",
        "execute backup",
    )
    for queries in READ_QUERIES.values():
        for name, query in queries.items():
            inspected = f"{name} {query.command}".lower()
            assert not any(marker in inspected for marker in forbidden), inspected


def test_ssh_continuation_cache_uses_absolute_capture_ttl() -> None:
    engine_was_loaded = "netops_helper.engine" in sys.modules
    injected_module_names: list[str] = []
    if not engine_was_loaded:
        icmplib_stub = types.ModuleType("icmplib")
        icmplib_stub.ping = lambda *args, **kwargs: None
        netmiko_stub = types.ModuleType("netmiko")
        netmiko_stub.ConnectHandler = lambda **kwargs: None
        fortinet_stub = types.ModuleType("netmiko.fortinet")
        fortinet_ssh_stub = types.ModuleType("netmiko.fortinet.fortinet_ssh")

        class StubFortinetSSH:
            pass

        fortinet_ssh_stub.FortinetSSH = StubFortinetSSH
        paramiko_stub = types.ModuleType("paramiko")
        paramiko_exceptions_stub = types.ModuleType("paramiko.ssh_exception")

        class StubIncompatiblePeer(Exception):
            pass

        paramiko_exceptions_stub.IncompatiblePeer = StubIncompatiblePeer
        dependency_stubs = {
            "icmplib": icmplib_stub,
            "netmiko": netmiko_stub,
            "netmiko.fortinet": fortinet_stub,
            "netmiko.fortinet.fortinet_ssh": fortinet_ssh_stub,
            "paramiko": paramiko_stub,
            "paramiko.ssh_exception": paramiko_exceptions_stub,
        }
        for name, module in dependency_stubs.items():
            if name not in sys.modules:
                sys.modules[name] = module
                injected_module_names.append(name)

    engine = importlib.import_module("netops_helper.engine")
    target = TargetAuth.decode(
        "device-a",
        _context(
            known_hosts="synthetic host key",
            read_inventory={"interfaces": ["port3"]},
            fortios_output_standard_verified=True,
            ssh_platform="fortios",
            enabled_queries=["interface_details"],
        ),
    )
    calls = {"connections": 0, "commands": 0}
    audit_events: list[dict[str, object]] = []

    class ControlledClock:
        now = 1_000.0

        def monotonic(self) -> float:
            return self.now

    class FakeConnection:
        def send_command(self, command: str, read_timeout: int) -> str:
            assert command == "diagnose netlink interface list port3"
            assert read_timeout == 60
            calls["commands"] += 1
            return "x" * 4_000

    @contextmanager
    def fake_connection(*args: object, **kwargs: object):
        calls["connections"] += 1
        yield FakeConnection()

    clock = ControlledClock()
    original_time = engine.time
    original_connection = engine.netmiko_connection
    original_record = engine.record
    engine.time = clock
    engine.netmiko_connection = fake_connection
    engine.record = lambda event, **fields: audit_events.append(
        {"event": event, **fields}
    )
    engine._SSH_PAGE_CACHE.clear()
    try:
        first = engine.ssh_read(
            target,
            "fortios",
            "interface_details",
            {"interface": "port3"},
            0,
            1_000,
        )
        cache_key = engine._ssh_cache_key(
            target, "fortinet", "interface_details", {"interface": "port3"},
        )
        original_deadline = engine._SSH_PAGE_CACHE[cache_key][0]
        assert original_deadline == clock.now + engine._SSH_CACHE_TTL_SECONDS

        clock.now = original_deadline - 1.0
        second = engine.ssh_read(
            target,
            "fortios",
            "interface_details",
            {"interface": "port3"},
            first["next_offset"],
            1_000,
        )
        assert engine._SSH_PAGE_CACHE[cache_key][0] == original_deadline
        assert first["pagination_source"] == "fresh"
        assert second["pagination_source"] == "cached"
        assert first["next_offset"] == second["offset"] == 1_000
        assert second["next_offset"] == 2_000
        assert first["content_sha256"] == second["content_sha256"]

        clock.now = original_deadline + 0.001
        try:
            engine.ssh_read(
                target,
                "fortios",
                "interface_details",
                {"interface": "port3"},
                second["next_offset"],
                1_000,
            )
        except ValueError as exc:
            assert str(exc) == "SSH pagination state expired; restart at offset 0"
        else:
            raise AssertionError("SSH continuation survived its original capture TTL")

        assert cache_key not in engine._SSH_PAGE_CACHE
        assert calls == {"connections": 1, "commands": 1}
        assert [event["status"] for event in audit_events] == [
            "started", "ok", "started", "ok", "started", "rejected",
        ]
    finally:
        engine._SSH_PAGE_CACHE.clear()
        engine.time = original_time
        engine.netmiko_connection = original_connection
        engine.record = original_record
        if not engine_was_loaded:
            sys.modules.pop("netops_helper.engine", None)
            package = sys.modules.get("netops_helper")
            if package is not None and getattr(package, "engine", None) is engine:
                delattr(package, "engine")
            for name in reversed(injected_module_names):
                sys.modules.pop(name, None)


def test_phase1_server_and_engine_expose_no_generic_body_reads() -> None:
    root = Path(__file__).resolve().parents[1]
    server_tree = ast.parse(
        (root / "src/netops_helper/server.py").read_text(encoding="utf-8")
    )
    engine_tree = ast.parse(
        (root / "src/netops_helper/engine.py").read_text(encoding="utf-8")
    )
    auth_tree = ast.parse(
        (root / "src/netops_helper/auth.py").read_text(encoding="utf-8")
    )

    registered_tools = {
        node.name
        for node in server_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(decorator, ast.Attribute)
            and isinstance(decorator.value, ast.Name)
            and decorator.value.id == "mcp"
            and decorator.attr == "tool"
            for decorator in node.decorator_list
        )
    }
    assert registered_tools == {
        "helper_status",
        "read_query_catalog",
        "dns_probe",
        "tcp_probe",
        "icmp_probe",
        "tls_probe",
        "ssh_read",
        "snmp_get",
        "sftp_stat",
        "ftp_list",
    }

    server_engine_imports = {
        alias.asname or alias.name
        for node in server_tree.body
        if isinstance(node, ast.ImportFrom)
        and node.level == 1
        and node.module == "engine"
        for alias in node.names
    }
    assert "engine_https_get" not in server_engine_imports
    assert "engine_sftp_read_text" not in server_engine_imports

    engine_functions = {
        node.name
        for node in engine_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"tls_probe", "sftp_stat"} <= engine_functions
    assert {
        "https_get",
        "sftp_read_text",
        "_read_https_snapshot",
        "_read_sftp_snapshot",
    }.isdisjoint(engine_functions)
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(alias.name == "httpx" for alias in node.names)
        for node in engine_tree.body
    )

    target_auth = next(
        node
        for node in auth_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TargetAuth"
    )
    auth_members = {
        node.target.id
        for node in target_auth.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    } | {
        node.name
        for node in target_auth.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "https_endpoints" not in auth_members
    assert "require_https_endpoint" not in auth_members


def main() -> int:
    test_snmp_community_is_optional_for_non_snmp_tools()
    test_snmp_community_is_distinct_and_part_of_secret_set()
    test_equal_snmp_and_ssh_secrets_are_rejected()
    test_non_ascii_snmp_and_ssh_secrets_compare_as_utf8()
    test_direct_snmp_accessor_rejects_malformed_material_cleanly()
    test_unsafe_snmp_community_is_invalid()
    test_identity_types_and_top_level_fields_fail_closed()
    test_hostname_requires_dns_and_explicit_addresses_during_decode()
    test_policy_fields_are_mandatory_and_egress_shape_is_exact()
    test_range_wire_shape_and_duplicates_fail_closed()
    test_envelope_collections_are_canonical_unique_and_control_free()
    test_auth_accepts_every_platform_alias_with_a_known_query()
    test_query_parameters_do_not_coerce_non_string_values()
    test_query_and_egress_capabilities_are_explicit()
    test_catalog_authority_and_platform_aliases_are_exact()
    test_ip_address_families_are_enforced_and_canonicalized()
    test_extreme_physical_port_kind_is_single_and_canonical()
    test_eos_and_junos_slot_kinds_accept_only_canonical_forms()
    test_public_inventory_validator_is_exact_and_fail_closed()
    test_public_query_metadata_preserves_legacy_catalog_shape()
    test_command_template_metadata_is_not_an_execution_input()
    test_import_time_catalog_invariant_rejects_invalid_corpus()
    test_vendor_lldp_commands_use_supported_local_read_queries()
    test_phase1_catalog_has_no_configuration_export()
    test_ssh_continuation_cache_uses_absolute_capture_ttl()
    test_phase1_server_and_engine_expose_no_generic_body_reads()
    print("engine_contract_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
