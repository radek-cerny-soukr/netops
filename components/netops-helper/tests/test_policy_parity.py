#!/usr/bin/env python3
"""Cross-component policy corpus using three independent production validators."""

from __future__ import annotations

from base64 import b64encode, urlsafe_b64encode
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "netops-core" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import generate_egress_rules as generator
from netops_core.hostkey import fingerprint_of
import remote_mcp_proxy as proxy_module
from netops_helper.auth import TargetAuth
from netops_helper import inventory as helper_inventory
from netops_helper import read_policy


ALIAS = "device-a"
CREDENTIAL = "device-a-account"
SNMP_CREDENTIAL = "device-a-community"
LOGIN = "reader"
SECRET = "account-secret"
COMMUNITY = "separate-community"
KINDS = {CREDENTIAL: "password", SNMP_CREDENTIAL: "snmp-community"}
CANONICAL_PLATFORMS = {"fortinet": "fortios", "extreme_exos": "exos"}
HOST_KEY_PIN = fingerprint_of(b64encode(b"policy-parity-host-key").decode("ascii"))

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


def canonical_device() -> dict[str, object]:
    return {
        "name": ALIAS,
        "platform": "linux",
        "address": "192.0.2.10",
        "port": 2222,
        "role": "interni",
        "credential": CREDENTIAL,
        "host_key_fingerprint": HOST_KEY_PIN,
        "legacy_ssh": None,
        "auditor": None,
        "helper": canonical_section(),
    }


def canonical_section() -> dict[str, object]:
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
        "snmp_credential": SNMP_CREDENTIAL,
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


def document(device: dict[str, object]) -> dict[str, object]:
    return {"version": 2, "devices": [device]}


def loaded(device: dict[str, object]):
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "inventory.json"
        path.write_text(json.dumps(document(device)), encoding="utf-8")
        return helper_inventory.load(path), generator.inventory_digest(path)


def encode_envelope(device: dict[str, object], section: dict[str, object]) -> str:
    # This is the documented proxy-to-engine envelope projection, not validation.
    envelope = {
        "alias": device.get("name"),
        "host": device.get("address"),
        "port": device.get("port"),
        "login": LOGIN,
        "credential_kind": "password",
        "secret": SECRET,
        "host_key_fingerprint": device.get("host_key_fingerprint"),
        "legacy_ssh": device.get("legacy_ssh"),
        **{
            key: value for key, value in section.items()
            if key not in {"rate_limit", "snmp_credential"}
        },
    }
    if section.get("snmp_credential") is not None:
        envelope["snmp_community"] = COMMUNITY
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unchecked_section(platform: str, query_name: str, inventory: dict):
    """The tool-time scope check must stand on its own, without section validation."""
    return helper_inventory.HelperSection(
        account_role="read-only",
        ssh_platform=CANONICAL_PLATFORMS.get(platform, platform),
        enabled_queries=(query_name,),
        read_inventory={
            category: tuple(items) for category, items in inventory.items()
        },
        sftp_roots=("/safe",),
        fortios_output_standard_verified=False,
        rate_limit={"requests": 30, "window_seconds": 60},
        egress=canonical_section()["egress"],
        snmp_credential=None,
    )


def section_accepts(device: dict[str, object], *, ftp: bool = False) -> bool:
    try:
        entries, _ = loaded(device)
        section = helper_inventory.section(entries[0], KINDS)
        if ftp:
            proxy_module.Proxy._authorize_tool(
                "ftp_list", {"port": 21, "remote_path": "/safe"}, entries[0], section,
            )
        return True
    except (helper_inventory.InventoryError, ValueError, TypeError, KeyError):
        return False


def envelope_accepts(device: dict[str, object], *, ftp: bool = False) -> bool:
    try:
        target = TargetAuth.decode(ALIAS, encode_envelope(device, device["helper"]))
        if ftp:
            target.require_tcp_port(21)
            target.require_passive_tcp_range()
            target.require_passive_tcp_port(50005)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def generator_accepts(device: dict[str, object], *, ftp: bool = False) -> bool:
    try:
        entries, digest = loaded(device)
        bundle = generator.build_bundle(entries, global_egress(), digest)
        if ftp:
            generator.require_ftp_scope(bundle["manifest"]["targets"][0], 21, 50005)
        return True
    except (helper_inventory.InventoryError, ValueError, TypeError, KeyError):
        return False


class PolicyParityTests(unittest.TestCase):
    def assert_all_accept(
        self, device: dict[str, object], *, ftp: bool = False,
    ) -> None:
        results = {
            "section": section_accepts(device, ftp=ftp),
            "envelope": envelope_accepts(device, ftp=ftp),
            "generator": generator_accepts(device, ftp=ftp),
        }
        self.assertEqual(results, {name: True for name in results}, results)

    def assert_all_reject(
        self, device: dict[str, object], *, ftp: bool = False,
    ) -> None:
        results = {
            "section": section_accepts(device, ftp=ftp),
            "envelope": envelope_accepts(device, ftp=ftp),
            "generator": generator_accepts(device, ftp=ftp),
        }
        self.assertEqual(results, {name: False for name in results}, results)

    def test_canonical_policy_and_ftp_scope_are_accepted(self) -> None:
        self.assert_all_accept(canonical_device(), ftp=True)

    def test_legacy_ssh_profile_is_accepted_by_every_validator(self) -> None:
        device = canonical_device()
        device["legacy_ssh"] = "rsa-sha1"
        self.assert_all_accept(device)
        decoded = TargetAuth.decode(ALIAS, encode_envelope(device, device["helper"]))
        self.assertEqual(decoded.legacy_ssh, "rsa-sha1")
        entries, _ = loaded(device)
        self.assertEqual(entries[0].legacy_ssh, "rsa-sha1")

    def test_default_device_has_no_legacy_ssh_profile(self) -> None:
        device = canonical_device()
        self.assert_all_accept(device)
        self.assertIsNone(
            TargetAuth.decode(ALIAS, encode_envelope(device, device["helper"])).legacy_ssh
        )
        entries, _ = loaded(device)
        self.assertIsNone(entries[0].legacy_ssh)

    def test_unknown_legacy_ssh_values_fail_closed_everywhere(self) -> None:
        for value in (
            "ssh-rsa", "rsa-sha1 ", "RSA-SHA1", "", True, 1, ["rsa-sha1"],
            {"profile": "rsa-sha1"}, "diffie-hellman-group1-sha1",
        ):
            with self.subTest(value=value):
                device = canonical_device()
                device["legacy_ssh"] = value
                self.assert_all_reject(device)

    def test_the_legacy_profile_vocabulary_is_the_one_of_the_shared_layer(self) -> None:
        from netops_core import legacy_ssh
        from netops_helper.auth import LEGACY_SSH_PROFILES

        self.assertEqual(legacy_ssh.PROFILES, LEGACY_SSH_PROFILES)
        self.assertNotIn("legacy_ssh", helper_inventory.SECTION_FIELDS)
        self.assertIn("legacy_ssh", helper_inventory.core.DEVICE_FIELDS)

    def test_the_canonical_platform_carries_its_catalogue_meaning(self) -> None:
        device = canonical_device()
        device["platform"] = "fortios"
        device["helper"]["ssh_platform"] = "fortios"
        device["helper"]["enabled_queries"] = ["system_status"]
        device["helper"]["read_inventory"] = {}
        self.assert_all_accept(device)
        decoded = TargetAuth.decode(ALIAS, encode_envelope(device, device["helper"]))
        self.assertEqual(decoded.ssh_platform, "fortinet")
        self.assertEqual(decoded.enabled_queries, ("system_status",))
        entries, _ = loaded(device)
        section = helper_inventory.section(entries[0], KINDS)
        self.assertEqual(section.ssh_platform, "fortios")
        self.assertEqual(section.catalog_platform(), "fortinet")

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
            "ruckus_unleashed": "ruckus_unleashed",
        }
        expected_counts = {
            "linux": 16,
            "fortinet": 40,
            "extreme_exos": 47,
            "cisco_ios": 27,
            "cisco_xe": 27,
            "cisco_nxos": 30,
            "arista_eos": 33,
            "juniper_junos": 25,
            "juniper_junos_els": 29,
            "ruckus_unleashed": 4,
        }
        self.assertEqual(read_policy.PLATFORM_MAP, expected_aliases)
        self.assertEqual(
            {
                platform: len(queries)
                for platform, queries in read_policy.READ_QUERIES.items()
            },
            expected_counts,
        )
        self.assertEqual(sum(expected_counts.values()), 278)
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
        self.assertEqual(set(helper_inventory.READ_QUERIES), set(expected_names))
        for canonical_name in helper_inventory.core.platforms.PLATFORMS:
            canonical = helper_inventory.catalog_platform(canonical_name)
            self.assertEqual(
                frozenset(helper_inventory.READ_QUERIES[canonical]),
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

                    device = canonical_device()
                    policy = device["helper"]
                    device["platform"] = CANONICAL_PLATFORMS.get(platform, platform)
                    policy["ssh_platform"] = device["platform"]
                    policy["enabled_queries"] = [query_name]
                    policy["read_inventory"] = inventory

                    entries, digest = loaded(device)
                    section = helper_inventory.section(entries[0], KINDS)
                    proxy_module.Proxy._authorize_tool(
                        "ssh_read",
                        {
                            "platform": platform,
                            "query": query_name,
                            "parameters": parameters,
                        },
                        entries[0],
                        section,
                    )

                    target = TargetAuth.decode(
                        ALIAS, encode_envelope(device, policy),
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
                        entries, global_egress(), digest,
                    )
                    self.assertEqual(
                        bundle["manifest"]["targets"][0]["destinations"],
                        ["192.0.2.10"],
                    )
                    exercised += 1

        self.assertEqual(exercised, 63)

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
                section = unchecked_section(platform, query_name, inventory)
                parameters = {slot_name: value}
                self.assertIn(value, section.read_inventory[slot.inventory])

                entries, _ = loaded(canonical_device())
                with self.assertRaises(proxy_module.PolicyScopeError):
                    proxy_module.Proxy._authorize_tool(
                        "ssh_read",
                        {
                            "platform": platform,
                            "query": query_name,
                            "parameters": parameters,
                        },
                        entries[0],
                        section,
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
                device = canonical_device()
                policy = device["helper"]
                device["platform"] = CANONICAL_PLATFORMS.get(platform, platform)
                policy["ssh_platform"] = device["platform"]
                policy["enabled_queries"] = [query_name]
                policy["read_inventory"] = {
                    "interfaces": [value],
                    "services": [],
                    "addresses": [],
                    "switches": [],
                }
                self.assert_all_accept(device)
                query = read_policy.READ_QUERIES[platform][query_name]
                kind = query.slots["interface"].kind
                proxy_canonicalizer = (
                    proxy_module._VENDOR_INTERFACE_CANONICALIZERS[kind]
                )
                self.assertEqual(proxy_canonicalizer(value), canonical)

                entries, _ = loaded(device)
                proxy_module.Proxy._authorize_tool(
                    "ssh_read",
                    {
                        "platform": platform,
                        "query": query_name,
                        "parameters": {"interface": value},
                    },
                    entries[0],
                    helper_inventory.section(entries[0], KINDS),
                )

                target = TargetAuth.decode(
                    ALIAS,
                    encode_envelope(device, policy),
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
                device = canonical_device()
                policy = device["helper"]
                device["platform"] = CANONICAL_PLATFORMS.get(platform, platform)
                policy["ssh_platform"] = device["platform"]
                policy["enabled_queries"] = [query_name]
                policy["read_inventory"] = {
                    "interfaces": [value],
                    "services": [],
                    "addresses": [],
                    "switches": [],
                }
                self.assert_all_reject(device)
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
        device = canonical_device()
        policy = device["helper"]
        policy["read_inventory"]["interfaces"] = ["status"]
        self.assert_all_accept(device)

        device["platform"] = "cisco_ios"
        policy["ssh_platform"] = "cisco_ios"
        policy["enabled_queries"] = ["interface_details"]
        self.assert_all_reject(device)

        policy["read_inventory"]["interfaces"] = [
            "GigabitEthernet1/0/1",
        ]
        self.assert_all_accept(device)
        entries, _ = loaded(device)
        section = helper_inventory.section(entries[0], KINDS)
        with self.assertRaises(proxy_module.PolicyScopeError):
            proxy_module.Proxy._authorize_tool(
                "ssh_read",
                {
                    "platform": "cisco_ios",
                    "query": "interface_details",
                    "parameters": {"interface": "Gi1/0/1"},
                },
                entries[0],
                section,
            )
        target = TargetAuth.decode(
            ALIAS,
            encode_envelope(device, policy),
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

    def test_common_device_field_is_exact_before_envelope_projection(self) -> None:
        for name, mutate in (
            ("role", lambda d: d.__setitem__("role", "must-not-be-ignored")),
            ("unknown field", lambda d: d.__setitem__("snmp_community", "abc")),
            ("credential", lambda d: d.__setitem__("credential", None)),
        ):
            with self.subTest(name=name):
                device = canonical_device()
                mutate(device)
                self.assertFalse(section_accepts(device))
                self.assertFalse(generator_accepts(device))
                # TargetAuth cannot validate a common field the envelope never carries.
                self.assertTrue(envelope_accepts(device))

    def test_shared_invalid_device_identity_corpus_is_rejected(self) -> None:
        cases = (
            ("null address", lambda d: d.__setitem__("address", None)),
            ("empty address", lambda d: d.__setitem__("address", "")),
            ("uppercase address", lambda d: d.__setitem__("address", "Device.Example")),
            ("trailing dot address", lambda d: d.__setitem__("address", "device.example.")),
            ("IPv6 address", lambda d: d.__setitem__("address", "2001:db8::1")),
            ("noncanonical address", lambda d: d.__setitem__("address", "192.0.2.010")),
            ("bool port", lambda d: d.__setitem__("port", True)),
            ("port out of range", lambda d: d.__setitem__("port", 65_536)),
            ("null port", lambda d: d.__setitem__("port", None)),
            ("null pin", lambda d: d.__setitem__("host_key_fingerprint", None)),
            ("short pin", lambda d: d.__setitem__("host_key_fingerprint", "SHA256:AAA")),
            (
                "pin without prefix",
                lambda d: d.__setitem__("host_key_fingerprint", "A" * 43),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                device = canonical_device()
                mutate(device)
                self.assert_all_reject(device)

    def test_credential_kinds_of_a_device_are_checked_against_the_store(self) -> None:
        for name, kinds in (
            ("account is a token", {CREDENTIAL: "api-token", SNMP_CREDENTIAL: "snmp-community"}),
            ("account is a community", {CREDENTIAL: "snmp-community", SNMP_CREDENTIAL: "snmp-community"}),
            ("community is a password", {CREDENTIAL: "password", SNMP_CREDENTIAL: "password"}),
            ("account is unknown", {SNMP_CREDENTIAL: "snmp-community"}),
            ("community is unknown", {CREDENTIAL: "password"}),
        ):
            with self.subTest(name=name):
                entries, _ = loaded(canonical_device())
                with self.assertRaises(helper_inventory.InventoryError):
                    helper_inventory.section(entries[0], kinds)
        entries, _ = loaded(canonical_device())
        self.assertEqual(
            helper_inventory.section(entries[0], KINDS).snmp_credential,
            SNMP_CREDENTIAL,
        )

    def test_shared_invalid_policy_corpus_is_rejected(self) -> None:
        cases: list[tuple[str, dict[str, object], bool]] = []

        def add(name: str, mutate, *, ftp: bool = False) -> None:
            device = canonical_device()
            mutate(device, device["helper"])
            cases.append((name, device, ftp))

        add("unknown target key", lambda _r, p: p.__setitem__("unexpected", True))
        for key in ("account_role", "ssh_platform", "enabled_queries", "egress"):
            add(f"missing {key}", lambda _r, p, key=key: p.pop(key))
        add("bool device port", lambda d, _p: d.__setitem__("port", True))
        add(
            "non-string query",
            lambda _r, p: p.__setitem__("enabled_queries", [7]),
        )
        add(
            "unknown platform query",
            lambda _r, p: p.__setitem__("enabled_queries", ["does_not_exist"]),
        )
        add("invalid hostname", lambda d, _p: d.__setitem__("address", "bad_name"))
        add(
            "hostname without DNS",
            lambda d, _p: d.__setitem__("address", "device.example"),
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

        for name, device, ftp in cases:
            with self.subTest(name=name):
                self.assert_all_reject(device, ftp=ftp)

    def test_corpus_adapters_are_independent_production_paths(self) -> None:
        self.assertIsNot(helper_inventory.section, TargetAuth.decode)
        self.assertIsNot(generator.build_bundle, helper_inventory.section)
        self.assertIsNot(generator.build_bundle, TargetAuth.decode)
        self.assertIs(proxy_module.helper_inventory.section, helper_inventory.section)


if __name__ == "__main__":
    unittest.main()
