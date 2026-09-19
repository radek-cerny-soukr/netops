from __future__ import annotations

import importlib.util
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate_egress_rules.py"
CHECKER_PATH = ROOT / "scripts" / "check_egress_rules.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generator = _load("generate_egress_rules", GENERATOR_PATH)
checker = _load("check_egress_rules", CHECKER_PATH)
RFC1918_TEST_LAN = str(ipaddress.ip_network((0x0A000000, 24)))

CGNAT_NETWORK_SAMPLE = str(ipaddress.ip_address(0x64400000))
RFC1918_TEST_ALPHA = str(ipaddress.ip_address(0x0A00000A))
RFC1918_TEST_BETA = str(ipaddress.ip_address(0x0A000014))
RFC1918_TEST_BLOCKS = tuple(ipaddress.ip_network(value) for value in (
    (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16),
))


PIN_ALPHA = "SHA256:" + "A" * 43
PIN_BETA = "SHA256:" + "B" * 43


def fixture(profile: str = "strict-target") -> tuple[dict, dict]:
    alpha_address = RFC1918_TEST_ALPHA if profile == "lan-constrained" else "192.0.2.10"
    beta_address = RFC1918_TEST_BETA if profile == "lan-constrained" else "192.0.2.20"
    document = {
        "version": 2,
        "devices": [
            {
                "name": "device-alpha",
                "platform": "fortios",
                "address": alpha_address,
                "port": 22,
                "role": "interni",
                "credential": "device-alpha-account",
                "host_key_fingerprint": PIN_ALPHA,
                "legacy_ssh": None,
                "auditor": None,
                "helper": {
                    "account_role": "read-only",
                    "ssh_platform": "fortios",
                    "enabled_queries": ["system_status"],
                    "sftp_roots": [],
                    "egress": {
                        "addresses": [alpha_address],
                        "tcp_ports": [8443],
                        "udp_ports": [161],
                        "tcp_port_ranges": [[50000, 50010]],
                        "udp_port_ranges": [],
                        "allow_icmp": True,
                        "allow_dns": False,
                        "tls_server_names": ["status.device.invalid"],
                    },
                },
            },
            {
                "name": "device-beta",
                "platform": "exos",
                "address": "switch.example.invalid",
                "port": 2222,
                "role": "interni",
                "credential": "device-beta-account",
                "host_key_fingerprint": PIN_BETA,
                "legacy_ssh": None,
                "auditor": None,
                "helper": {
                    "account_role": "read-only",
                    "ssh_platform": None,
                    "enabled_queries": [],
                    "sftp_roots": [],
                    "egress": {
                        "addresses": [beta_address],
                        "tcp_ports": [],
                        "udp_ports": [1161],
                        "tcp_port_ranges": [],
                        "udp_port_ranges": [],
                        "allow_icmp": False,
                        "allow_dns": True,
                        "tls_server_names": ["switch.example.invalid"],
                    },
                },
            },
        ],
    }
    policy = {
        "schema_version": 1,
        "profile": profile,
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": ["203.0.113.53", "203.0.113.5"],
        "lan_cidrs": [RFC1918_TEST_LAN] if profile == "lan-constrained" else [],
    }
    return document, policy


def device(document: dict, name: str) -> dict:
    return next(item for item in document["devices"] if item["name"] == name)


def helper(document: dict, name: str) -> dict:
    return device(document, name)["helper"]


def write_inventory(document: dict, directory: Path) -> Path:
    path = directory / "inventory.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def build(document: dict, policy: dict) -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        path = write_inventory(document, Path(temporary))
        return generator.build_bundle(
            generator._devices(path), policy, generator.inventory_digest(path),
        )


def observed_state(bundle: dict) -> dict:
    ruleset = bundle["ruleset"]
    ipv4 = "\n".join([
        "-A FORWARD -j DOCKER-USER",
        ruleset["ipv4"]["jump_rule"],
        *ruleset["ipv4"]["chain_rules"],
    ])
    return {
        "backend": "iptables",
        "network_name": "netops-helper",
        "network_driver": "bridge",
        "network_bridge": "nh-egress0",
        "network_ipv6_enabled": False,
        "bridge_names": ["lo", "nh-egress0"],
        "ipv4_save": ipv4,
    }


class GeneratorTests(unittest.TestCase):
    def test_icmp_rule_uses_iptables_save_numeric_type(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        icmp_rules = [rule for rule in rules if " -p icmp " in rule]
        self.assertEqual(
            icmp_rules,
            [f"-A {generator.CHAIN_NAME} -d 192.0.2.10/32 -p icmp -m icmp --icmp-type 8 -j ACCEPT"],
        )
        self.assertFalse(any("echo-request" in rule for rule in rules))
        self.assertEqual(checker.check(bundle, observed_state(bundle)), [])

    def test_strict_bundle_contains_only_non_secret_scope(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        encoded = generator.canonical_json(bundle).decode()
        for forbidden in (
            "device-alpha", "device-beta", "device-alpha-account",
            "device-beta-account", PIN_ALPHA, PIN_BETA, "example.invalid",
            "status.device.invalid", "switch.example.invalid", "tls_server_names",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertIn("192.0.2.10", encoded)
        self.assertIn("192.0.2.20", encoded)
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        self.assertTrue(any("--dport 22 " in rule and "192.0.2.10/32" in rule for rule in rules))
        self.assertTrue(any("--dport 8443 " in rule and "192.0.2.10/32" in rule for rule in rules))
        self.assertFalse(any("--dport 443 " in rule for rule in rules))
        self.assertTrue(any("--dport 50000:50010 " in rule for rule in rules))
        self.assertFalse(any("--dport 2222 " in rule for rule in rules))
        self.assertTrue(bundle["manifest"]["allow_dns"])
        self.assertEqual(bundle["bundle_schema"], 3)
        self.assertIs(bundle["manifest"]["network_ipv6_enabled"], False)
        self.assertEqual(
            bundle["manifest"]["ipv6_boundary"],
            "docker-network-disabled",
        )
        self.assertNotIn("ipv6_mode", bundle["manifest"])
        self.assertEqual(
            set(bundle["ruleset"]),
            {"backend", "chain", "ipv4"},
        )
        self.assertNotIn('"ipv6":', encoded)
        self.assertNotIn("ip6tables", encoded)

    def test_lan_profile_uses_union_only_inside_explicit_lan(self) -> None:
        document, policy = fixture("lan-constrained")
        bundle = build(document, policy)
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        self.assertFalse(any("--dport 2222 " in rule for rule in rules))
        self.assertTrue(any(f"-d {RFC1918_TEST_LAN}" in rule and "--dport 161 " in rule for rule in rules))
        self.assertFalse(any(f"{RFC1918_TEST_ALPHA}/32" in rule for rule in rules))

    def test_lan_profile_rejects_target_outside_each_declared_private_block(self) -> None:
        for index, declared_lan in enumerate(RFC1918_TEST_BLOCKS):
            outside_lan = RFC1918_TEST_BLOCKS[(index + 1) % len(RFC1918_TEST_BLOCKS)]
            enrolled_address = str(declared_lan.network_address + 1)
            outside_address = str(outside_lan.network_address + 1)
            document, policy = fixture("lan-constrained")
            policy["lan_cidrs"] = [str(declared_lan)]
            device(document, "device-alpha")["address"] = outside_address
            helper(document, "device-alpha")["egress"]["addresses"] = [outside_address]
            helper(document, "device-beta")["egress"]["addresses"] = [enrolled_address]
            with self.subTest(declared_lan=str(declared_lan)):
                with self.assertRaisesRegex(
                    generator.EgressContractError,
                    "target is outside the declared LAN scope",
                ):
                    build(document, policy)

    def test_lan_profile_rejects_every_non_rfc1918_scope(self) -> None:
        invalid = (
            "0.0.0.0/0", str(ipaddress.ip_network((0x0A000000, 7))),
            CGNAT_NETWORK_SAMPLE + "/10", "192.0.2.0/24", "224.0.0.0/4",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(generator.EgressContractError):
                    generator._ipv4_network(value)
        valid = tuple(str(ipaddress.ip_network(value)) for value in (
            (0x0A000000, 8), (0x0A141E00, 24), (0xAC100000, 12),
            (0xAC1FFF00, 24), (0xC0A80000, 16),
        ))
        for value in valid:
            with self.subTest(value=value):
                self.assertEqual(generator._ipv4_network(value), value)

    def test_compose_explicitly_disables_network_ipv6(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        network = compose.split("networks:\n", 2)[-1]
        self.assertIn("    enable_ipv6: false\n", network)
        self.assertIn("com.docker.network.bridge.name: nh-egress0", network)

    def test_authoritative_inventory_validation_fails_closed(self) -> None:
        invalid_inventory = (
            {"interfaces": ["Ethernet1/1;show"]},
            {"services": ["sshd --now"]},
            {"addresses": ["2001:0db8::10"]},
            {"addresses": ["192.0.002.10"]},
            {"switches": ["switch|show"]},
        )
        for inventory in invalid_inventory:
            document, policy = fixture()
            helper(document, "device-alpha")["read_inventory"] = inventory
            with self.subTest(category=next(iter(inventory))):
                with self.assertRaises(generator.EgressContractError):
                    build(document, policy)

        document, policy = fixture()
        helper(document, "device-alpha")["read_inventory"] = {
            "interfaces": ["Ethernet1/1"],
            "services": ["sshd.service"],
            "addresses": ["2001:db8::10"],
            "switches": ["switch-1"],
        }
        build(document, policy)

    def test_every_canonical_platform_accepts_a_known_authoritative_query(self) -> None:
        catalog = generator.helper_inventory
        for platform in catalog.core.platforms.PLATFORMS:
            canonical = catalog.catalog_platform(platform)
            document, policy = fixture()
            device(document, "device-alpha")["platform"] = platform
            helper(document, "device-alpha")["ssh_platform"] = platform
            helper(document, "device-alpha")["enabled_queries"] = [
                next(iter(catalog.READ_QUERIES[canonical]))
            ]
            with self.subTest(platform=platform, canonical=canonical):
                build(document, policy)

    def test_the_section_refuses_a_platform_alias_of_the_inventory(self) -> None:
        for alias in ("fortinet", "extreme_exos", "extreme_switch_engine"):
            document, policy = fixture()
            helper(document, "device-alpha")["ssh_platform"] = alias
            with self.subTest(alias=alias):
                with self.assertRaises(generator.EgressContractError):
                    build(document, policy)

    def test_ipv6_and_unscoped_hostname_fail_closed(self) -> None:
        document, policy = fixture()
        device(document, "device-alpha")["address"] = "2001:db8::10"
        helper(document, "device-alpha")["egress"]["addresses"] = ["192.0.2.10"]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        helper(document, "device-beta")["egress"]["addresses"] = []
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)

    def test_hostname_requires_addresses_dns_permission_and_resolver(self) -> None:
        document, policy = fixture()
        helper(document, "device-beta")["egress"]["allow_dns"] = False
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        policy["dns_resolvers"] = []
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)

    def test_credential_port_is_only_derived_for_active_ssh_or_sftp(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["enabled_queries"] = []
        bundle = build(document, policy)
        alpha = next(scope for scope in bundle["manifest"]["targets"] if "192.0.2.10" in scope["destinations"])
        self.assertNotIn(22, alpha["tcp_ports"])
        helper(document, "device-alpha")["sftp_roots"] = ["/safe"]
        bundle = build(document, policy)
        alpha = next(scope for scope in bundle["manifest"]["targets"] if "192.0.2.10" in scope["destinations"])
        self.assertIn(22, alpha["tcp_ports"])

    def test_dns_rules_require_an_enrolled_dns_consumer(self) -> None:
        document, policy = fixture()
        device(document, "device-beta")["address"] = "192.0.2.20"
        helper(document, "device-beta")["egress"]["allow_dns"] = False
        bundle = build(document, policy)
        self.assertFalse(bundle["manifest"]["allow_dns"])
        self.assertFalse(any("--dport 53 " in rule for rule in bundle["ruleset"]["ipv4"]["chain_rules"]))

    def test_exact_egress_and_global_contracts_fail_closed(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        del helper(document, "device-alpha")["egress"]["tls_server_names"]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["tls_server_names"] = ["*.device.invalid"]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        policy["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        del policy["ipv6_mode"]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)

    def test_helper_section_rejects_unknown_and_missing_required_keys(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        for required in ("account_role", "ssh_platform", "enabled_queries", "egress"):
            document, policy = fixture()
            del helper(document, "device-alpha")[required]
            with self.subTest(required=required):
                with self.assertRaises(generator.EgressContractError):
                    build(document, policy)

    def test_sftp_root_invalid_corpus_fails_before_credential_port_enrollment(self) -> None:
        invalid_roots = (
            "relative/path", "/", "//safe", "/safe/../etc", "/safe/\x00file",
            "/" + "x" * 2_000,
        )
        for root in invalid_roots:
            document, policy = fixture()
            helper(document, "device-alpha")["sftp_roots"] = [root]
            with self.subTest(root_length=len(root)):
                with self.assertRaises(generator.EgressContractError):
                    build(document, policy)

    def test_legacy_https_body_read_field_is_rejected_without_port_derivation(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["https_endpoints"] = [{
            "path": "/export.conf", "port": 443, "use_basic_auth": False,
        }]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)

    def test_explicit_and_effective_ports_must_not_overlap_ranges(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["tcp_port_ranges"] = [[8_000, 9_000]]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["udp_port_ranges"] = [[160, 162]]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["tcp_ports"] = []
        helper(document, "device-alpha")["egress"]["tcp_port_ranges"] = [[20, 30]]
        with self.assertRaises(generator.EgressContractError):
            build(document, policy)

    def test_generate_is_atomic_mode_600_and_does_not_replace_inputs(self) -> None:
        document, policy = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory_path = write_inventory(document, root)
            policy_path = root / "egress-policy.json"
            output_path = root / "egress.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output_path.write_text("old", encoding="utf-8")
            output_path.chmod(0o644)
            generator.generate(inventory_path, policy_path, output_path)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            checker.validate_bundle(bundle)
            self.assertEqual(
                bundle["manifest"]["inventory_sha256"],
                generator.inventory_digest(inventory_path),
            )
            with self.assertRaises(generator.EgressContractError):
                generator.generate(inventory_path, policy_path, inventory_path)

    def test_cli_failure_never_prints_input_values(self) -> None:
        document, policy = fixture()
        helper(document, "device-alpha")["egress"]["addresses"] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory_path = write_inventory(document, root)
            policy_path = root / "egress-policy.json"
            output_path = root / "egress.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-B", str(GENERATOR_PATH),
                 "--inventory", str(inventory_path),
                 "--policy", str(policy_path), "--output", str(output_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "egress_generation=failed\n")
            self.assertFalse(output_path.exists())


class CheckerTests(unittest.TestCase):
    def test_checker_requires_docker_user_jump_to_be_first_in_forward(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        state = observed_state(bundle)
        state["ipv4_save"] = "-A FORWARD -i nh-egress0 -j ACCEPT\n" + state["ipv4_save"]
        self.assertIn("ipv4_docker_user_unreachable", checker.check(bundle, state))
        state["ipv4_save"] = state["ipv4_save"].replace(
            "-A FORWARD -i nh-egress0 -j ACCEPT\n", "",
        ) + "\n-A FORWARD -j ACCEPT"
        self.assertNotIn("ipv4_docker_user_unreachable", checker.check(bundle, state))

    def test_checker_accepts_ipv6_disabled_network_and_ipv4_guard(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        self.assertEqual(checker.check(bundle, observed_state(bundle)), [])

    def test_live_inspection_reads_false_and_never_calls_ip6tables(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        commands: list[tuple[str, ...]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(tuple(command))
            if command[:3] == ["docker", "network", "inspect"]:
                return json.dumps([{
                    "Driver": "bridge",
                    "EnableIPv6": False,
                    "Options": {"com.docker.network.bridge.name": "nh-egress0"},
                }])
            if command[:3] == ["nft", "list", "tables"]:
                return "table inet filter"
            if command == ["iptables-save"]:
                return observed_state(bundle)["ipv4_save"]
            raise AssertionError(f"unexpected command: {command!r}")

        class FakePath:
            def __init__(self, _value: str) -> None:
                pass

            def iterdir(self):
                return [type("Interface", (), {"name": "nh-egress0"})()]

        with mock.patch.object(checker, "_run", side_effect=fake_run), mock.patch.object(
            checker, "Path", FakePath,
        ):
            inspected = checker.inspect_live_state(bundle)
        self.assertEqual(checker.check(bundle, inspected), [])
        self.assertFalse(any(command[0].startswith("ip6tables") for command in commands))

    def test_live_inspection_rejects_missing_enable_ipv6(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        with mock.patch.object(
            checker,
            "_run",
            return_value=json.dumps([{
                "Driver": "bridge",
                "Options": {"com.docker.network.bridge.name": "nh-egress0"},
            }]),
        ):
            with self.assertRaises(checker.EgressCheckError):
                checker.inspect_live_state(bundle)

    def test_live_inspection_does_not_fallback_when_nft_inspection_fails(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        commands: list[tuple[str, ...]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(tuple(command))
            if command[:3] == ["docker", "network", "inspect"]:
                return json.dumps([{
                    "Driver": "bridge",
                    "EnableIPv6": False,
                    "Options": {"com.docker.network.bridge.name": "nh-egress0"},
                }])
            if command[:3] == ["nft", "list", "tables"]:
                raise checker.EgressCheckError("host inspection command failed")
            raise AssertionError(f"unexpected command: {command!r}")

        class FakePath:
            def __init__(self, _value: str) -> None:
                pass

            def iterdir(self):
                return [type("Interface", (), {"name": "nh-egress0"})()]

        with mock.patch.object(checker, "_run", side_effect=fake_run), mock.patch.object(
            checker, "Path", FakePath,
        ):
            with self.assertRaises(checker.EgressCheckError):
                checker.inspect_live_state(bundle)
        self.assertNotIn(("iptables-save",), commands)

    def test_checker_detects_backend_bridge_and_rule_drift(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        state = observed_state(bundle)
        state["backend"] = "nftables"
        state["network_bridge"] = "br-changing"
        state["bridge_names"] = ["br-changing"]
        state["network_ipv6_enabled"] = True
        errors = checker.check(bundle, state)
        for expected in (
            "backend_mismatch", "network_bridge_mismatch", "bridge_missing",
            "network_ipv6_mismatch",
        ):
            self.assertIn(expected, errors)

    def test_checker_rejects_missing_or_ambiguous_ipv6_state(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        missing = observed_state(bundle)
        del missing["network_ipv6_enabled"]
        with self.assertRaises(checker.EgressCheckError):
            checker.check(bundle, missing)
        ambiguous = observed_state(bundle)
        ambiguous["network_ipv6_enabled"] = None
        with self.assertRaises(checker.EgressCheckError):
            checker.check(bundle, ambiguous)

    def test_checker_rejects_bundle_claiming_enabled_ipv6(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        bundle["manifest"]["network_ipv6_enabled"] = True
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_an_unapplied_ipv6_ruleset_claim(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        bundle["ruleset"]["ipv6"] = {
            "jump_rule": bundle["ruleset"]["ipv4"]["jump_rule"],
            "chain_rules": [f"-A {generator.CHAIN_NAME} -j DROP"],
        }
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_requires_jump_to_be_first(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        state = observed_state(bundle)
        state["ipv4_save"] = state["ipv4_save"].replace(
            "-A FORWARD -j DOCKER-USER\n",
            "-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -i nh-egress0 -j ACCEPT\n",
        )
        self.assertIn("ipv4_jump_missing_or_not_first", checker.check(bundle, state))

    def test_checker_rejects_near_name_or_comment_only_forward_jump(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        replacements = (
            "-A FORWARD -j DOCKER-USER-ALT",
            '-A FORWARD -m comment --comment "-j DOCKER-USER" -j ACCEPT',
        )
        for replacement in replacements:
            with self.subTest(rule=replacement):
                state = observed_state(bundle)
                state["ipv4_save"] = state["ipv4_save"].replace(
                    "-A FORWARD -j DOCKER-USER", replacement,
                )
                self.assertIn(
                    "ipv4_docker_user_unreachable", checker.check(bundle, state),
                )

    def test_checker_rejects_tampered_manifest_digest(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        bundle["manifest"]["dns_resolvers"] = []
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_port_range_overlap_even_with_recomputed_digest(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        scope = next(
            item for item in bundle["manifest"]["targets"]
            if "192.0.2.10" in item["destinations"]
        )
        scope["tcp_port_ranges"] = [[20, 30]]
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_lan_target_outside_scope_with_recomputed_contract(self) -> None:
        document, policy = fixture("lan-constrained")
        bundle = build(document, policy)
        outside_address = str(RFC1918_TEST_BLOCKS[1].network_address + 1)
        bundle["manifest"]["targets"][0]["destinations"] = [outside_address]
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaisesRegex(
            checker.EgressCheckError,
            "target is outside the declared LAN scope",
        ):
            checker.validate_bundle(bundle)

    def test_checker_rejects_alias_even_with_recomputed_digest(self) -> None:
        document, policy = fixture()
        bundle = build(document, policy)
        bundle["manifest"]["targets"][0]["alias"] = "device-alpha"
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
