#!/usr/bin/env python3
"""Cross-component policy corpus using three independent production validators."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import generate_egress_rules as generator
import remote_mcp_proxy as proxy_module
from netops_helper.auth import TargetAuth
from netops_helper import read_policy


ALIAS = "device-a"
MASTER_ALIAS = "netops-runner"

REPRESENTATIVE_SLOT_VALUES = {
    "interface": "port5",
    "service": "sshd",
    "switch": "edge-a",
    "ipv4_address": "192.0.2.20",
    "ipv6_address": "2001:db8::1",
    "fortios_interface": "port1",
    "fortios_physical_interface": "wan1",
    "cisco_ios_interface": "GigabitEthernet1/0/1",
    "cisco_ios_physical_interface": "GigabitEthernet1/0/1",
    "cisco_xe_interface": "GigabitEthernet1/0/1",
    "cisco_xe_physical_interface": "GigabitEthernet1/0/1",
    "cisco_nxos_interface": "Ethernet1/1",
    "cisco_nxos_errors_interface": "Loopback0",
    "extreme_physical_port": "1:1",
    "eos_interface": "Ethernet1",
    "eos_physical_interface": "Ethernet3/1",
    "eos_lldp_interface": "Management1",
    "eos_lacp_interface": "Port-Channel10",
    "eos_stp_interface": "Port-Channel10",
    "eos_ospf_interface": "Vlan4094",
    "junos_interface": "ae0.0",
    "junos_physical_interface": "xe-0/0/1",
    "junos_logical_interface": "ge-1/0/47.0",
    "junos_lacp_interface": "et-0/0/0",
}


def canonical_record() -> dict[str, object]:
    return {
        "host": "192.0.2.10",
        "port": 2222,
        "login": "reader",
        "password": "account-secret",
        "snmp_community": "separate-community",
    }


def canonical_policy() -> dict[str, object]:
    return {
        "account_role": "read-only",
        "ssh_platform": "linux",
        "enabled_queries": ["hostname"],
        "read_inventory": {
            "interfaces": ["port5"],
            "services": ["sshd"],
            "addresses": ["192.0.2.20"],
            "switches": ["edge-a"],
        },
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": False,
        "legacy_ssh": None,
        "rate_limit": {"requests": 30, "window_seconds": 60},
        "egress": {
            "addresses": ["192.0.2.10"],
            "tcp_ports": [21, 443],
            "udp_ports": [161],
            "tcp_port_ranges": [[50000, 50010]],
            "udp_port_ranges": [],
            "allow_icmp": True,
            "allow_dns": False,
            "tls_server_names": ["device.example"],
        },
    }


def global_egress() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile": "strict-target",
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": ["192.0.2.53"],
        "lan_cidrs": [],
    }


def encode_envelope(record: dict[str, object], policy: dict[str, object]) -> str:
    # This is the documented proxy-to-engine envelope projection, not validation.
    envelope = {
        "alias": ALIAS,
        "host": record.get("host"),
        "port": record.get("port"),
        "login": record.get("login"),
        "password": record.get("password"),
        **{key: value for key, value in policy.items() if key != "rate_limit"},
    }
    if "snmp_community" in record:
        envelope["snmp_community"] = record["snmp_community"]
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def proxy_accepts(
    record: dict[str, object], policy: dict[str, object], *, ftp: bool = False,
) -> bool:
    try:
        checked_record = proxy_module.Proxy._validate_record(record)
        checked_policy = proxy_module.Proxy._validate_target_policy(policy)
        proxy_module.Proxy._validate_target_binding(checked_record, checked_policy)
        if ftp:
            proxy_module.Proxy._authorize_tool(
                "ftp_list", {"port": 21, "remote_path": "/safe"},
                checked_record, checked_policy,
            )
        return True
    except (ValueError, TypeError, KeyError):
        return False


def envelope_accepts(
    record: dict[str, object], policy: dict[str, object], *, ftp: bool = False,
) -> bool:
    try:
        target = TargetAuth.decode(ALIAS, encode_envelope(record, policy))
        if ftp:
            target.require_tcp_port(21)
            target.require_passive_tcp_range()
            target.require_passive_tcp_port(50005)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def generator_accepts(
    record: dict[str, object], policy: dict[str, object], *, ftp: bool = False,
) -> bool:
    try:
        bundle = generator.build_bundle(
            {ALIAS: record},
            {"_egress": global_egress(), ALIAS: policy},
            MASTER_ALIAS,
        )
        if ftp:
            generator.require_ftp_scope(bundle["manifest"]["targets"][0], 21, 50005)
        return True
    except (ValueError, TypeError, KeyError):
        return False


class PolicyParityTests(unittest.TestCase):
    def assert_all_accept(
        self, record: dict[str, object], policy: dict[str, object], *, ftp: bool = False,
    ) -> None:
        results = {
            "proxy": proxy_accepts(record, policy, ftp=ftp),
            "envelope": envelope_accepts(record, policy, ftp=ftp),
            "generator": generator_accepts(record, policy, ftp=ftp),
        }
        self.assertEqual(results, {name: True for name in results}, results)

    def assert_all_reject(
        self, record: dict[str, object], policy: dict[str, object], *, ftp: bool = False,
    ) -> None:
        results = {
            "proxy": proxy_accepts(record, policy, ftp=ftp),
            "envelope": envelope_accepts(record, policy, ftp=ftp),
            "generator": generator_accepts(record, policy, ftp=ftp),
        }
        self.assertEqual(results, {name: False for name in results}, results)

    def test_canonical_policy_and_ftp_scope_are_accepted(self) -> None:
        self.assert_all_accept(canonical_record(), canonical_policy(), ftp=True)

    def test_legacy_ssh_profile_is_accepted_by_every_validator(self) -> None:
        record, policy = canonical_record(), canonical_policy()
        policy["legacy_ssh"] = "rsa-sha1"
        self.assert_all_accept(record, policy)
        decoded = TargetAuth.decode(ALIAS, encode_envelope(record, policy))
        self.assertEqual(decoded.legacy_ssh, "rsa-sha1")
        self.assertEqual(
            proxy_module.Proxy._validate_target_policy(policy)["legacy_ssh"],
            "rsa-sha1",
        )

    def test_default_target_policy_has_no_legacy_ssh_profile(self) -> None:
        record, policy = canonical_record(), canonical_policy()
        del policy["legacy_ssh"]
        self.assert_all_accept(record, policy)
        self.assertIsNone(TargetAuth.decode(ALIAS, encode_envelope(record, policy)).legacy_ssh)
        self.assertIsNone(
            proxy_module.Proxy._validate_target_policy(policy)["legacy_ssh"],
        )

    def test_unknown_legacy_ssh_values_fail_closed_everywhere(self) -> None:
        for value in (
            "ssh-rsa", "rsa-sha1 ", "RSA-SHA1", "", True, 1, ["rsa-sha1"],
            {"profile": "rsa-sha1"}, "diffie-hellman-group1-sha1",
        ):
            with self.subTest(value=value):
                record, policy = canonical_record(), canonical_policy()
                policy["legacy_ssh"] = value
                self.assert_all_reject(record, policy)

    def test_proxy_vocabulary_matches_the_engine_vocabulary(self) -> None:
        from netops_helper.auth import LEGACY_SSH_PROFILES

        self.assertEqual(tuple(proxy_module.LEGACY_SSH_PROFILES), LEGACY_SSH_PROFILES)
        self.assertEqual(tuple(generator.LEGACY_SSH_PROFILES), LEGACY_SSH_PROFILES)
        self.assertIn("legacy_ssh", proxy_module.TARGET_POLICY_KEYS)
        self.assertIn("legacy_ssh", generator.TARGET_POLICY_KEYS)
        self.assertNotIn("legacy_ssh", generator.REQUIRED_TARGET_POLICY_KEYS)

    def test_fortios_alias_has_canonical_fortinet_meaning(self) -> None:
        record, policy = canonical_record(), canonical_policy()
        policy["ssh_platform"] = "fortios"
        policy["enabled_queries"] = ["system_status"]
        self.assert_all_accept(record, policy)
        decoded = TargetAuth.decode(ALIAS, encode_envelope(record, policy))
        self.assertEqual(decoded.ssh_platform, "fortinet")
        self.assertEqual(decoded.enabled_queries, ("system_status",))

    def test_complete_query_catalog_and_slot_maps_do_not_drift(self) -> None:
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
        expected_counts = {
            "linux": 16,
            "fortinet": 30,
            "extreme_exos": 32,
            "cisco_ios": 27,
            "cisco_xe": 27,
            "cisco_nxos": 30,
            "arista_eos": 33,
            "juniper_junos": 25,
            "juniper_junos_els": 29,
        }
        self.assertEqual(read_policy.PLATFORM_MAP, expected_aliases)
        self.assertEqual(
            {
                platform: len(queries)
                for platform, queries in read_policy.READ_QUERIES.items()
            },
            expected_counts,
        )
        self.assertEqual(sum(expected_counts.values()), 249)
        expected_names = {
            platform: frozenset(queries)
            for platform, queries in read_policy.READ_QUERIES.items()
        }
        expected_slots = {
            platform: {
                query_name: {
                    slot_name: {
                        "inventory": slot.inventory,
                        "kind": slot.kind,
                    }
                    for slot_name, slot in query.slots.items()
                }
                for query_name, query in queries.items()
                if query.slots
            }
            for platform, queries in read_policy.READ_QUERIES.items()
        }
        self.assertEqual(proxy_module.PLATFORM_MAP, read_policy.PLATFORM_MAP)
        self.assertEqual(proxy_module.READ_QUERY_NAMES, expected_names)
        self.assertEqual(proxy_module.READ_QUERY_SLOTS, expected_slots)
        self.assertEqual(set(generator.READ_QUERIES), set(expected_names))
        for alias, canonical in read_policy.PLATFORM_MAP.items():
            self.assertEqual(generator.normalize_platform(alias), canonical)
            self.assertEqual(
                frozenset(generator.READ_QUERIES[canonical]),
                expected_names[canonical],
            )

    def test_every_slot_query_has_cross_path_authorization_parity(self) -> None:
        actual_kinds = {
            slot.kind
            for queries in read_policy.READ_QUERIES.values()
            for query in queries.values()
            for slot in query.slots.values()
        }
        self.assertEqual(actual_kinds, set(REPRESENTATIVE_SLOT_VALUES))

        exercised = 0
        for platform, queries in read_policy.READ_QUERIES.items():
            for query_name, query in queries.items():
                if not query.slots:
                    continue
                with self.subTest(platform=platform, query=query_name):
                    parameters: dict[str, str] = {}
                    inventory = {
                        "interfaces": [],
                        "services": [],
                        "addresses": [],
                        "switches": [],
                    }
                    for slot_name, slot in query.slots.items():
                        value = REPRESENTATIVE_SLOT_VALUES[slot.kind]
                        parameters[slot_name] = value
                        if value not in inventory[slot.inventory]:
                            inventory[slot.inventory].append(value)

                    record, policy = canonical_record(), canonical_policy()
                    policy["ssh_platform"] = platform
                    policy["enabled_queries"] = [query_name]
                    policy["read_inventory"] = inventory

                    checked_record = proxy_module.Proxy._validate_record(record)
                    checked_policy = proxy_module.Proxy._validate_target_policy(policy)
                    proxy_module.Proxy._validate_target_binding(
                        checked_record, checked_policy,
                    )
                    proxy_module.Proxy._authorize_tool(
                        "ssh_read",
                        {
                            "platform": platform,
                            "query": query_name,
                            "parameters": parameters,
                        },
                        checked_record,
                        checked_policy,
                    )

                    target = TargetAuth.decode(
                        ALIAS, encode_envelope(record, policy),
                    )
                    self.assertEqual(
                        target.require_ssh_query(platform, query_name),
                        platform,
                    )
                    normalized, rendered = read_policy.render_read_query(
                        platform,
                        query_name,
                        parameters,
                        target.read_inventory,
                    )
                    self.assertEqual(normalized, platform)
                    self.assertEqual(
                        rendered,
                        query.command.format_map(parameters),
                    )

                    bundle = generator.build_bundle(
                        {ALIAS: record},
                        {"_egress": global_egress(), ALIAS: policy},
                        MASTER_ALIAS,
                    )
                    self.assertEqual(
                        bundle["manifest"]["targets"][0]["destinations"],
                        ["192.0.2.10"],
                    )
                    exercised += 1

        self.assertEqual(exercised, 62)

    def test_typed_query_rejections_have_proxy_render_parity(self) -> None:
        cases = (
            (
                "wrong IPv4 family",
                "cisco_ios", "route_lookup", "2001:db8::1",
            ),
            (
                "wrong IPv6 family",
                "cisco_nxos", "ipv6_route_lookup", "192.0.2.20",
            ),
            (
                "noncanonical IPv6",
                "cisco_nxos", "ipv6_route_lookup", "2001:0db8::1",
            ),
            (
                "Extreme all",
                "extreme_exos", "interface_details", "all",
            ),
            (
                "Extreme range",
                "extreme_exos", "interface_details", "1:1-1:48",
            ),
            (
                "Extreme list",
                "extreme_exos", "interface_details", "1:1,1:2",
            ),
            (
                "EOS shorthand",
                "arista_eos", "interface_details", "Et1",
            ),
            (
                "EOS wrong case",
                "arista_eos", "interface_details", "ethernet1",
            ),
            (
                "EOS physical subtype",
                "arista_eos", "interface_optics", "Port-Channel10",
            ),
            (
                "Junos physical subtype",
                "juniper_junos", "interface_optics", "ge-0/0/0.0",
            ),
            (
                "Junos logical subtype",
                "juniper_junos", "arp_interface", "ge-0/0/0",
            ),
            (
                "Junos LACP subtype",
                "juniper_junos", "lacp_interface", "ae0.0",
            ),
        )
        for label, platform, query_name, value in cases:
            with self.subTest(case=label):
                query = read_policy.READ_QUERIES[platform][query_name]
                self.assertEqual(len(query.slots), 1)
                slot_name, slot = next(iter(query.slots.items()))
                inventory = {
                    "interfaces": [],
                    "services": [],
                    "addresses": [],
                    "switches": [],
                }
                inventory[slot.inventory] = [value]
                policy = canonical_policy()
                policy["ssh_platform"] = platform
                policy["enabled_queries"] = [query_name]
                policy["read_inventory"] = inventory
                parameters = {slot_name: value}
                self.assertIn(value, policy["read_inventory"][slot.inventory])

                with self.assertRaises(proxy_module.PolicyScopeError):
                    proxy_module.Proxy._authorize_tool(
                        "ssh_read",
                        {
                            "platform": platform,
                            "query": query_name,
                            "parameters": parameters,
                        },
                        canonical_record(),
                        policy,
                    )
                with self.assertRaises(ValueError):
                    read_policy.render_read_query(
                        platform,
                        query_name,
                        parameters,
                        {
                            category: tuple(items)
                            for category, items in inventory.items()
                        },
                    )

    def test_vendor_interface_guard_positive_and_negative_corpus(self) -> None:
        positive_cases = (
            ("fortinet", "interface_details", "port1", "port1"),
            ("fortinet", "interface_details", "wan1", "wan1"),
            ("fortinet", "interface_details", "dmz", "dmz"),
            ("fortinet", "interface_details", "ha.1", "ha.1"),
            ("fortinet", "interface_hardware", "mgmt", "mgmt"),
            ("fortinet", "interface_hardware", "internal7", "internal7"),
            ("cisco_ios", "interface_details", "Gi0/1", "GigabitEthernet0/1"),
            (
                "cisco_ios", "interface_details",
                "GigabitEthernet1/0/48", "GigabitEthernet1/0/48",
            ),
            (
                "cisco_ios", "interface_details",
                "Gi8/0/99", "GigabitEthernet8/0/99",
            ),
            ("cisco_ios", "interface_details", "Po1", "Port-channel1"),
            (
                "cisco_ios", "interface_details",
                "Port-channel48", "Port-channel48",
            ),
            ("cisco_ios", "interface_details", "Vl1", "vlan 1"),
            ("cisco_ios", "interface_details", "Vlan4094", "vlan 4094"),
            (
                "cisco_ios", "interface_errors",
                "Gi1/0/1", "GigabitEthernet1/0/1",
            ),
            (
                "cisco_xe", "interface_details",
                "Gi0/0", "GigabitEthernet0/0",
            ),
            (
                "cisco_xe", "interface_details",
                "Gi1/0/48", "GigabitEthernet1/0/48",
            ),
            (
                "cisco_xe", "interface_details",
                "Tw8/0/36", "TwoGigabitEthernet8/0/36",
            ),
            (
                "cisco_xe", "interface_details",
                "Fi1/0/48", "FiveGigabitEthernet1/0/48",
            ),
            (
                "cisco_xe", "interface_details",
                "Te1/0/24", "TenGigabitEthernet1/0/24",
            ),
            (
                "cisco_xe", "interface_details",
                "Te1/1/37", "TenGigabitEthernet1/1/37",
            ),
            (
                "cisco_xe", "interface_details",
                "Twe8/1/2", "TwentyFiveGigE8/1/2",
            ),
            (
                "cisco_xe", "interface_details",
                "Fo1/1/1", "FortyGigabitEthernet1/1/1",
            ),
            (
                "cisco_xe", "interface_details",
                "Hu8/1/48", "HundredGigE8/1/48",
            ),
            ("cisco_xe", "interface_details", "Po128", "Port-channel128"),
            ("cisco_xe", "interface_details", "Vl4094", "vlan 4094"),
            (
                "cisco_xe", "interface_details",
                "Loopback2147483647", "Loopback2147483647",
            ),
            ("cisco_xe", "interface_details", "Tunnel0", "Tunnel0"),
            (
                "cisco_xe", "interface_errors",
                "GigabitEthernet0/0", "GigabitEthernet0/0",
            ),
            (
                "cisco_nxos", "interface_details",
                "Ethernet1/1", "Ethernet1/1",
            ),
            (
                "cisco_nxos", "interface_details",
                "Ethernet101/1/1", "Ethernet101/1/1",
            ),
            (
                "cisco_nxos", "interface_details",
                "Ethernet1/1.4094", "Ethernet1/1.4094",
            ),
            (
                "cisco_nxos", "interface_details",
                "Ethernet101/1/1.100", "Ethernet101/1/1.100",
            ),
            (
                "cisco_nxos", "interface_details",
                "Port-channel1", "Port-channel1",
            ),
            (
                "cisco_nxos", "interface_details",
                "Port-channel4096.4094", "Port-channel4096.4094",
            ),
            ("cisco_nxos", "interface_details", "Vlan4094", "Vlan4094"),
            ("cisco_nxos", "interface_details", "Loopback0", "Loopback0"),
            (
                "cisco_nxos", "interface_errors",
                "Loopback1023", "Loopback1023",
            ),
            ("cisco_nxos", "interface_details", "mgmt0", "mgmt0"),
            ("cisco_nxos", "interface_details", "Tunnel9999", "Tunnel9999"),
        )
        negative_cases = (
            # FortiOS reserved branches, grammar escapes, and length boundary.
            ("fortinet", "interface_details", "all"),
            ("fortinet", "interface_details", "ALL"),
            ("fortinet", "interface_details", "any"),
            ("fortinet", "interface_details", "none"),
            ("fortinet", "interface_details", "clear"),
            ("fortinet", "interface_details", "list"),
            ("fortinet", "interface_details", "packet-rate"),
            ("fortinet", "interface_details", "speed-test"),
            ("fortinet", "interface_details", "speed-test-result"),
            ("fortinet", "interface_details", "speed-test-result-clear"),
            ("fortinet", "interface_details", "speed-test-shaping-reset"),
            ("fortinet", "interface_details", "speed-test-tunnel"),
            ("fortinet", "interface_details", "_port1"),
            ("fortinet", "interface_details", "port/1"),
            ("fortinet", "interface_details", "port 1"),
            ("fortinet", "interface_details", "port1;show"),
            ("fortinet", "interface_details", "abcdefghijklmnop"),
            # IOS 2960-X global branches, bounds, range/list, and suffixes.
            ("cisco_ios", "interface_details", "all"),
            ("cisco_ios", "interface_details", "brief"),
            ("cisco_ios", "interface_details", "status"),
            ("cisco_ios", "interface_details", "description"),
            ("cisco_ios", "interface_details", "counters"),
            ("cisco_ios", "interface_details", "Gi0/0"),
            ("cisco_ios", "interface_details", "Gi9/0/1"),
            ("cisco_ios", "interface_details", "Gi1/1/1"),
            ("cisco_ios", "interface_details", "Gi1/0/100"),
            ("cisco_ios", "interface_details", "Gi01/0/1"),
            ("cisco_ios", "interface_details", "Gi1/0/01"),
            ("cisco_ios", "interface_details", "Gi1/0/1-4"),
            ("cisco_ios", "interface_details", "Gi1/0/1,Gi1/0/2"),
            ("cisco_ios", "interface_details", "Gi1/0/1 counters"),
            ("cisco_ios", "interface_details", "Gi1/0/1.10"),
            ("cisco_ios", "interface_details", "Po0"),
            ("cisco_ios", "interface_details", "Po49"),
            ("cisco_ios", "interface_details", "Vlan0"),
            ("cisco_ios", "interface_details", "Vlan4095"),
            ("cisco_ios", "interface_errors", "Port-channel1"),
            ("cisco_ios", "interface_errors", "Vlan10"),
            # IOS-XE C9300 global branches, platform bounds, and suffixes.
            ("cisco_xe", "interface_details", "status"),
            ("cisco_xe", "interface_details", "description"),
            ("cisco_xe", "interface_details", "counters"),
            ("cisco_xe", "interface_details", "Gi0/1"),
            ("cisco_xe", "interface_details", "Gi9/0/1"),
            ("cisco_xe", "interface_details", "Gi1/2/1"),
            ("cisco_xe", "interface_details", "Tw1/0/37"),
            ("cisco_xe", "interface_details", "Fi1/1/1"),
            ("cisco_xe", "interface_details", "Te1/0/25"),
            ("cisco_xe", "interface_details", "Te1/1/36"),
            ("cisco_xe", "interface_details", "Twe1/0/1"),
            ("cisco_xe", "interface_details", "Twe1/1/3"),
            ("cisco_xe", "interface_details", "Fo1/0/1"),
            ("cisco_xe", "interface_details", "Po129"),
            ("cisco_xe", "interface_details", "Vlan4095"),
            ("cisco_xe", "interface_details", "Loopback2147483648"),
            ("cisco_xe", "interface_details", "Tunnel2147483648"),
            ("cisco_xe", "interface_details", "Gi1/0/1-4"),
            ("cisco_xe", "interface_details", "Gi1/0/1,Gi1/0/2"),
            ("cisco_xe", "interface_details", "Gi1/0/1 counters"),
            ("cisco_xe", "interface_errors", "Loopback0"),
            ("cisco_xe", "interface_errors", "Port-channel1"),
            # NX-OS global branches, bounds, ranges/lists, and subtypes.
            ("cisco_nxos", "interface_details", "all"),
            ("cisco_nxos", "interface_details", "status"),
            ("cisco_nxos", "interface_details", "description"),
            ("cisco_nxos", "interface_details", "counters"),
            ("cisco_nxos", "interface_details", "quick"),
            ("cisco_nxos", "interface_details", "Ethernet0/1"),
            ("cisco_nxos", "interface_details", "Ethernet1/0"),
            ("cisco_nxos", "interface_details", "Ethernet1000/1"),
            ("cisco_nxos", "interface_details", "Ethernet1/1000"),
            ("cisco_nxos", "interface_details", "Ethernet01/1"),
            ("cisco_nxos", "interface_details", "Ethernet1/01"),
            ("cisco_nxos", "interface_details", "Ethernet1/1-4"),
            (
                "cisco_nxos", "interface_details",
                "Ethernet1/1,Ethernet1/2",
            ),
            ("cisco_nxos", "interface_details", "Eth1/1"),
            ("cisco_nxos", "interface_details", "Ethernet1/1 counters"),
            ("cisco_nxos", "interface_details", "Ethernet1/1.0"),
            ("cisco_nxos", "interface_details", "Ethernet1/1.4095"),
            ("cisco_nxos", "interface_details", "Port-channel0"),
            ("cisco_nxos", "interface_details", "Port-channel4097"),
            ("cisco_nxos", "interface_details", "Port-channel1.0"),
            ("cisco_nxos", "interface_details", "Vlan0"),
            ("cisco_nxos", "interface_details", "Vlan4095"),
            ("cisco_nxos", "interface_details", "Loopback1024"),
            ("cisco_nxos", "interface_details", "mgmt1"),
            ("cisco_nxos", "interface_details", "Tunnel10000"),
            (
                "cisco_nxos", "interface_errors",
                "Ethernet1/1.100",
            ),
            ("cisco_nxos", "interface_errors", "Port-channel1"),
            ("cisco_nxos", "interface_errors", "mgmt0"),
        )
        self.assertGreaterEqual(len(positive_cases), 34)
        self.assertGreaterEqual(len(negative_cases), 58)

        for platform, query_name, value, canonical in positive_cases:
            with self.subTest(outcome="accept", platform=platform, value=value):
                record, policy = canonical_record(), canonical_policy()
                policy["ssh_platform"] = platform
                policy["enabled_queries"] = [query_name]
                policy["read_inventory"] = {
                    "interfaces": [value],
                    "services": [],
                    "addresses": [],
                    "switches": [],
                }
                self.assert_all_accept(record, policy)
                query = read_policy.READ_QUERIES[platform][query_name]
                kind = query.slots["interface"].kind
                proxy_canonicalizer = (
                    proxy_module._VENDOR_INTERFACE_CANONICALIZERS[kind]
                )
                self.assertEqual(proxy_canonicalizer(value), canonical)

                checked_record = proxy_module.Proxy._validate_record(record)
                checked_policy = proxy_module.Proxy._validate_target_policy(policy)
                proxy_module.Proxy._validate_target_binding(
                    checked_record,
                    checked_policy,
                )
                proxy_module.Proxy._authorize_tool(
                    "ssh_read",
                    {
                        "platform": platform,
                        "query": query_name,
                        "parameters": {"interface": value},
                    },
                    checked_record,
                    checked_policy,
                )

                target = TargetAuth.decode(
                    ALIAS,
                    encode_envelope(record, policy),
                )
                normalized, rendered = read_policy.render_read_query(
                    platform,
                    query_name,
                    {"interface": value},
                    target.read_inventory,
                )
                self.assertEqual(normalized, platform)
                self.assertEqual(
                    rendered,
                    query.command.format_map({"interface": canonical}),
                )

        for platform, query_name, value in negative_cases:
            with self.subTest(outcome="reject", platform=platform, value=value):
                record, policy = canonical_record(), canonical_policy()
                policy["ssh_platform"] = platform
                policy["enabled_queries"] = [query_name]
                policy["read_inventory"] = {
                    "interfaces": [value],
                    "services": [],
                    "addresses": [],
                    "switches": [],
                }
                self.assert_all_reject(record, policy)
                query = read_policy.READ_QUERIES[platform][query_name]
                kind = query.slots["interface"].kind
                self.assertIsNone(
                    proxy_module._VENDOR_INTERFACE_CANONICALIZERS[kind](
                        value
                    )
                )
                with self.assertRaises(ValueError):
                    read_policy.render_read_query(
                        platform,
                        query_name,
                        {"interface": value},
                        {"interfaces": (value,)},
                    )

    def test_interface_inventory_profile_binding_and_raw_membership(self) -> None:
        record, policy = canonical_record(), canonical_policy()
        policy["read_inventory"]["interfaces"] = ["status"]
        self.assert_all_accept(record, policy)

        policy["ssh_platform"] = "cisco_ios"
        policy["enabled_queries"] = ["interface_details"]
        self.assert_all_reject(record, policy)

        policy["read_inventory"]["interfaces"] = [
            "GigabitEthernet1/0/1",
        ]
        self.assert_all_accept(record, policy)
        checked_record = proxy_module.Proxy._validate_record(record)
        checked_policy = proxy_module.Proxy._validate_target_policy(policy)
        with self.assertRaises(proxy_module.PolicyScopeError):
            proxy_module.Proxy._authorize_tool(
                "ssh_read",
                {
                    "platform": "cisco_ios",
                    "query": "interface_details",
                    "parameters": {"interface": "Gi1/0/1"},
                },
                checked_record,
                checked_policy,
            )
        target = TargetAuth.decode(
            ALIAS,
            encode_envelope(record, policy),
        )
        with self.assertRaises(ValueError):
            read_policy.render_read_query(
                "cisco_ios",
                "interface_details",
                {"interface": "Gi1/0/1"},
                target.read_inventory,
            )

    def test_standalone_cli_import_chain_needs_no_pythonpath(self) -> None:
        environment = {
            key: value for key, value in os.environ.items() if key != "PYTHONPATH"
        }
        environment["PYTHONNOUSERSITE"] = "1"
        with tempfile.TemporaryDirectory() as directory:
            for relative in (
                "scripts/generate_egress_rules.py",
                "scripts/check_egress_rules.py",
                "scripts/apply_egress_rules.py",
            ):
                with self.subTest(script=relative):
                    completed = subprocess.run(
                        [sys.executable, "-I", "-B", str(ROOT / relative), "--help"],
                        cwd=directory,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_client_vault_schema_is_exact_before_envelope_projection(self) -> None:
        record, policy = canonical_record(), canonical_policy()
        record["unexpected"] = "must-not-be-ignored"
        self.assertFalse(proxy_accepts(record, policy))
        self.assertFalse(generator_accepts(record, policy))
        # TargetAuth cannot validate a vault-only key that the wire envelope never carries.
        self.assertTrue(envelope_accepts(record, policy))

    def test_shared_invalid_credential_identity_corpus_is_rejected(self) -> None:
        cases = (
            ("empty host", lambda r: r.__setitem__("host", "")),
            ("long host", lambda r: r.__setitem__("host", "a" * 254)),
            ("host space", lambda r: r.__setitem__("host", "bad host")),
            ("host DEL", lambda r: r.__setitem__("host", "bad\x7fhost")),
            ("empty login", lambda r: r.__setitem__("login", "")),
            ("long login", lambda r: r.__setitem__("login", "a" * 513)),
            ("login NUL", lambda r: r.__setitem__("login", "bad\x00login")),
            ("login DEL", lambda r: r.__setitem__("login", "bad\x7flogin")),
            ("short password", lambda r: r.__setitem__("password", "ab")),
            ("long password", lambda r: r.__setitem__("password", "a" * 4097)),
            ("password NUL", lambda r: r.__setitem__("password", "abc\x00")),
            ("password DEL", lambda r: r.__setitem__("password", "abc\x7f")),
            ("password surrogate", lambda r: r.__setitem__("password", "abc\ud800")),
            ("short community", lambda r: r.__setitem__("snmp_community", "ab")),
            ("long community", lambda r: r.__setitem__("snmp_community", "a" * 256)),
            ("community C0", lambda r: r.__setitem__("snmp_community", "abc\n")),
            ("community DEL", lambda r: r.__setitem__("snmp_community", "abc\x7f")),
            ("community surrogate", lambda r: r.__setitem__("snmp_community", "abc\ud800")),
            ("community equals password", lambda r: r.__setitem__("snmp_community", r["password"])),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                record, policy = canonical_record(), canonical_policy()
                mutate(record)
                self.assert_all_reject(record, policy)

    def test_shared_invalid_policy_corpus_is_rejected(self) -> None:
        cases: list[tuple[str, dict[str, object], dict[str, object], bool]] = []

        def add(name: str, mutate, *, ftp: bool = False) -> None:
            record, policy = canonical_record(), canonical_policy()
            mutate(record, policy)
            cases.append((name, record, policy, ftp))

        add("unknown target key", lambda _r, p: p.__setitem__("unexpected", True))
        for key in ("account_role", "ssh_platform", "enabled_queries", "egress"):
            add(f"missing {key}", lambda _r, p, key=key: p.pop(key))
        add("bool credential port", lambda r, _p: r.__setitem__("port", True))
        add(
            "non-string query",
            lambda _r, p: p.__setitem__("enabled_queries", [7]),
        )
        add(
            "unknown platform query",
            lambda _r, p: p.__setitem__("enabled_queries", ["does_not_exist"]),
        )
        add("invalid hostname", lambda r, _p: r.__setitem__("host", "bad_name"))
        add(
            "hostname without DNS",
            lambda r, _p: r.__setitem__("host", "device.example"),
        )
        add(
            "literal host outside addresses",
            lambda _r, p: p["egress"].__setitem__("addresses", ["192.0.2.11"]),
        )
        add(
            "non-string address",
            lambda _r, p: p["egress"].__setitem__("addresses", [7]),
        )
        add(
            "overlapping ranges",
            lambda _r, p: p["egress"].__setitem__(
                "tcp_port_ranges", [[50000, 50010], [50010, 50020]],
            ),
        )
        add(
            "bool range endpoint",
            lambda _r, p: p["egress"].__setitem__("udp_port_ranges", [[True, 10]]),
        )
        add("root path", lambda _r, p: p.__setitem__("sftp_roots", ["/"]))
        add("double-slash root", lambda _r, p: p.__setitem__("sftp_roots", ["//safe"]))
        add(
            "duplicate SFTP root",
            lambda _r, p: p.__setitem__("sftp_roots", ["/safe", "/safe"]),
        )
        add(
            "legacy HTTPS body-read field",
            lambda _r, p: p.__setitem__(
                "https_endpoints",
                [{"path": "/export.conf", "port": 443, "use_basic_auth": False}],
            ),
        )
        add(
            "unknown inventory category",
            lambda _r, p: p.__setitem__("read_inventory", {"unknown": ["item"]}),
        )
        add(
            "inventory control character",
            lambda _r, p: p.__setitem__("read_inventory", {"interfaces": ["bad\nitem"]}),
        )
        add(
            "invalid inventory address",
            lambda _r, p: p.__setitem__("read_inventory", {"addresses": ["192.0.2.999"]}),
        )
        add(
            "duplicate inventory value",
            lambda _r, p: p.__setitem__("read_inventory", {"interfaces": ["port5", "port5"]}),
        )
        add(
            "egress missing field",
            lambda _r, p: p["egress"].pop("allow_icmp"),
        )
        add(
            "invalid TLS DNS name",
            lambda _r, p: p["egress"].__setitem__("tls_server_names", ["BAD_NAME"]),
        )
        add(
            "explicit port inside range",
            lambda _r, p: p["egress"].__setitem__("tcp_port_ranges", [[20, 30]]),
        )
        add(
            "FTP missing passive range",
            lambda _r, p: p["egress"].__setitem__("tcp_port_ranges", []),
            ftp=True,
        )
        add(
            "FTP control port outside scope",
            lambda _r, p: p["egress"].__setitem__("tcp_ports", [443]),
            ftp=True,
        )

        for name, record, policy, ftp in cases:
            with self.subTest(name=name):
                self.assert_all_reject(record, policy, ftp=ftp)

    def test_corpus_adapters_are_independent_production_paths(self) -> None:
        self.assertIsNot(proxy_module.Proxy._validate_target_policy, TargetAuth.decode)
        self.assertIsNot(generator.build_bundle, proxy_module.Proxy._validate_target_policy)
        self.assertIsNot(generator.build_bundle, TargetAuth.decode)


if __name__ == "__main__":
    unittest.main()
