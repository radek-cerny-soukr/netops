#!/usr/bin/env python3
"""Dependency-free, fake-subprocess tests for explicit egress application."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "netops-core" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import apply_egress_rules as apply_rules
import check_egress_rules as checker
import generate_egress_rules as generator


PIN = "SHA256:" + "A" * 43


def bundle_fixture() -> dict[str, object]:
    document = {
        "version": 2,
        "devices": [{
            "name": "device-a",
            "platform": "linux",
            "address": "192.0.2.10",
            "port": 2222,
            "role": "interni",
            "credential": "device-a-account",
            "host_key_fingerprint": PIN,
            "legacy_ssh": None,
            "auditor": None,
            "helper": {
                "account_role": "read-only",
                "ssh_platform": "linux",
                "enabled_queries": ["hostname"],
                "read_inventory": {},
                "sftp_roots": [],
                "egress": {
                    "addresses": ["192.0.2.10"],
                    "tcp_ports": [443],
                    "udp_ports": [161],
                    "tcp_port_ranges": [],
                    "udp_port_ranges": [],
                    "allow_icmp": True,
                    "allow_dns": False,
                    "tls_server_names": [],
                },
            },
        }],
    }
    policy = {
        "schema_version": 1,
        "profile": "strict-target",
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": [],
        "lan_cidrs": [],
    }
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw) / "inventory.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return generator.build_bundle(
            generator._devices(path), policy, generator.inventory_digest(path),
        )


def empty_save() -> str:
    return "\n".join([
        "*filter",
        ":FORWARD ACCEPT [0:0]",
        ":DOCKER-USER - [0:0]",
        "-A FORWARD -j DOCKER-USER",
        "COMMIT",
        "",
    ])


def installed_save(bundle: dict[str, object], family: str) -> str:
    expected = bundle["ruleset"][family]
    return "\n".join([
        "*filter",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD ACCEPT [0:0]",
        ":DOCKER-USER - [0:0]",
        f":{generator.CHAIN_NAME} - [0:0]",
        f":{generator.INPUT_CHAIN_NAME} - [0:0]",
        expected["input_jump_rule"],
        "-A FORWARD -j DOCKER-USER",
        expected["jump_rule"],
        *expected["chain_rules"],
        *expected["input_chain_rules"],
        "COMMIT",
        "",
    ])


class SimulatedFilterTable:
    """The filter table as iptables-restore --noflush changes it: one payload commits or nothing does."""

    def __init__(self, save: str) -> None:
        self.chains: dict[str, list[str]] = {}
        self.policies: dict[str, str] = {}
        for line in save.splitlines():
            if line.startswith(":"):
                name, policy = line[1:].split()[:2]
                self.chains[name] = []
                self.policies[name] = policy
            elif line.startswith("-A "):
                self.chains[line.split()[1]].append(line)

    def save(self) -> str:
        lines = ["*filter"]
        lines.extend(f":{name} {self.policies[name]} [0:0]" for name in self.chains)
        for rules in self.chains.values():
            lines.extend(rules)
        return "\n".join([*lines, "COMMIT", ""])

    def restore(self, payload: str) -> bool:
        lines = [line for line in payload.splitlines() if line]
        if not lines or lines[0] != "*filter" or lines[-1] != "COMMIT":
            return False
        chains = {name: list(rules) for name, rules in self.chains.items()}
        policies = dict(self.policies)
        for line in lines[1:-1]:
            tokens = line.split()
            operation, chain = tokens[0], tokens[1]
            body = " ".join(tokens[2:])
            if operation == "-N":
                if chain in chains:
                    return False
                chains[chain] = []
                policies[chain] = "-"
                continue
            if chain not in chains:
                return False
            if operation == "-F":
                chains[chain] = []
            elif operation == "-X":
                referenced = any(
                    rule.split()[-2:] == ["-j", chain]
                    for rules in chains.values() for rule in rules
                )
                if chains[chain] or referenced:
                    return False
                del chains[chain]
                del policies[chain]
            elif operation in {"-A", "-I"}:
                position = len(chains[chain]) + 1
                if operation == "-I":
                    if not tokens[2].isdigit() or not 1 <= int(tokens[2]) <= position:
                        return False
                    position = int(tokens[2])
                    body = " ".join(tokens[3:])
                target = body.split()[-1]
                if target not in {"ACCEPT", "DROP", "RETURN"} and target not in chains:
                    return False
                chains[chain].insert(position - 1, f"-A {chain} {body}")
            elif operation == "-D":
                rule = f"-A {chain} {body}"
                if rule not in chains[chain]:
                    return False
                chains[chain].remove(rule)
            else:
                return False
        self.chains, self.policies = chains, policies
        return True


class SimulatedRunner:
    def __init__(self, save: str, *, after_apply=None, refuse=None) -> None:
        self.table = SimulatedFilterTable(save)
        self.after_apply = after_apply
        self.refuse = refuse
        self.restores: list[str] = []

    def __call__(self, command: list[str], **kwargs):
        if command[:3] == ["docker", "network", "inspect"]:
            network = {
                "Driver": "bridge",
                "Options": {"com.docker.network.bridge.name": "nh-egress0"},
                "EnableIPv6": False,
            }
            return SimpleNamespace(returncode=0, stdout=json.dumps([network]), stderr="")
        if command[:4] == ["ip", "link", "show", "dev"]:
            return SimpleNamespace(returncode=0, stdout="bridge", stderr="")
        if command[:3] == ["nft", "list", "tables"]:
            return SimpleNamespace(returncode=0, stdout="table inet filter", stderr="")
        if command == ["iptables-save"]:
            return SimpleNamespace(returncode=0, stdout=self.table.save(), stderr="")
        if command[0] == "iptables-restore":
            payload = kwargs["input"]
            self.restores.append(payload)
            if self.refuse is not None and self.refuse(payload):
                return SimpleNamespace(returncode=1, stdout="", stderr="hidden")
            if not self.table.restore(payload):
                return SimpleNamespace(returncode=1, stdout="", stderr="hidden")
            if self.after_apply is not None and len(self.restores) == 1:
                self.after_apply(self.table)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {command!r}")


def host_save() -> str:
    return "\n".join([
        "*filter",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        ":DOCKER-USER - [0:0]",
        "-A INPUT -i lo -j ACCEPT",
        "-A FORWARD -j DOCKER-USER",
        "-A DOCKER-USER -j RETURN",
        "COMMIT",
        "",
    ])


def observed(runner: SimulatedRunner) -> dict[str, object]:
    return {
        "backend": "iptables",
        "network_name": "netops-helper",
        "network_driver": "bridge",
        "network_bridge": "nh-egress0",
        "network_ipv6_enabled": False,
        "bridge_names": ["nh-egress0"],
        "ipv4_save": runner.table.save(),
    }


class FakeRunner:
    def __init__(
        self,
        bundle: dict[str, object],
        *,
        native_nft: bool = False,
        nft_failure: bool = False,
        network_ipv6_enabled: object = False,
        omit_enable_ipv6: bool = False,
        fail_rollback: bool = False,
        post_drift: bool = False,
        initial_ipv4: str | None = None,
        initial_ipv6: str | None = None,
    ) -> None:
        self.bundle = bundle
        self.native_nft = native_nft
        self.nft_failure = nft_failure
        self.network_ipv6_enabled = network_ipv6_enabled
        self.omit_enable_ipv6 = omit_enable_ipv6
        self.fail_rollback = fail_rollback
        self.post_drift = post_drift
        self.commands: list[tuple[list[str], str | None]] = []
        self.initial = {
            "ip": initial_ipv4 if initial_ipv4 is not None else empty_save(),
            "ip6": initial_ipv6 if initial_ipv6 is not None else empty_save(),
        }
        self.current = dict(self.initial)
        self.restore_counts = {"ip": 0, "ip6": 0}

    def __call__(self, command: list[str], **kwargs):
        payload = kwargs.get("input")
        self.commands.append((list(command), payload))
        executable = command[0]
        if command[:3] == ["docker", "network", "inspect"]:
            network = {
                "Driver": "bridge",
                "Options": {"com.docker.network.bridge.name": "nh-egress0"},
            }
            if not self.omit_enable_ipv6:
                network["EnableIPv6"] = self.network_ipv6_enabled
            return SimpleNamespace(
                returncode=0, stdout=json.dumps([network]), stderr="",
            )
        if command[:4] == ["ip", "link", "show", "dev"]:
            return SimpleNamespace(returncode=0, stdout="bridge", stderr="")
        if command[:3] == ["nft", "list", "tables"]:
            if self.nft_failure:
                return SimpleNamespace(returncode=1, stdout="", stderr="hidden")
            output = "table ip docker-bridges" if self.native_nft else "table inet filter"
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if executable in {"iptables-save", "ip6tables-save"}:
            unsupported = [
                option for option in command[1:]
                if option in {"--wait", "-w"} or option.isdigit()
            ]
            if unsupported:
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="%s: unrecognized option '%s'\n" % (executable, unsupported[0]),
                )
            family = "ip6" if executable.startswith("ip6") else "ip"
            output = self.current[family]
            if self.post_drift and self.restore_counts[family] and family == "ip":
                output = output.replace(
                    f"-A {generator.CHAIN_NAME} -j DROP\n", "",
                )
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if executable in {"iptables-restore", "ip6tables-restore"}:
            family = "ip6" if executable.startswith("ip6") else "ip"
            self.restore_counts[family] += 1
            if payload is None:
                raise AssertionError("firewall restore did not use stdin")
            if self.fail_rollback and f"-X {generator.CHAIN_NAME}" in payload:
                return SimpleNamespace(returncode=1, stdout="", stderr="hidden")
            if f"-X {generator.CHAIN_NAME}" in payload:
                self.current[family] = self.initial[family]
            elif f"netops-helper-egress:{self.bundle['manifest_sha256']}" in payload:
                key = "ipv4" if family == "ip" else "ipv6"
                self.current[family] = installed_save(self.bundle, key)
            else:
                raise AssertionError("unexpected restore payload")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {command!r}")


class ApplyEgressTests(unittest.TestCase):
    def test_apply_uses_stdin_and_skips_ip6tables_when_network_is_disabled(self) -> None:
        bundle = bundle_fixture()
        runner = FakeRunner(bundle)
        self.assertEqual(set(bundle["ruleset"]), {"backend", "chain", "input_chain", "ipv4"})
        apply_rules.apply_bundle(bundle, runner)
        restores = [(args, payload) for args, payload in runner.commands if "restore" in args[0]]
        self.assertEqual([item[0][0] for item in restores], ["iptables-restore"])
        self.assertTrue(all(payload for _args, payload in restores))
        self.assertFalse(any(args[0].startswith("ip6tables") for args, _ in runner.commands))
        argv = " ".join(part for args, _payload in runner.commands for part in args)
        self.assertNotIn("192.0.2.", argv)
        self.assertNotIn("account-secret", argv)
        self.assertIn("192.0.2.10", restores[0][1])

    def test_enabled_missing_or_ambiguous_ipv6_state_fails_before_firewall(self) -> None:
        bundle = bundle_fixture()
        cases = (
            ("enabled", {"network_ipv6_enabled": True}),
            ("missing", {"omit_enable_ipv6": True}),
            ("ambiguous", {"network_ipv6_enabled": None}),
        )
        for name, options in cases:
            with self.subTest(name=name):
                runner = FakeRunner(bundle, **options)
                with self.assertRaisesRegex(apply_rules.EgressApplyError, "network_invalid"):
                    apply_rules.apply_bundle(bundle, runner)
                self.assertFalse(any(
                    args[0].startswith(("iptables", "ip6tables"))
                    for args, _ in runner.commands
                ))
                self.assertEqual(
                    [args for args, _payload in runner.commands],
                    [["docker", "network", "inspect", "netops-helper"]],
                )

    def test_rollback_failure_has_distinct_fail_closed_code(self) -> None:
        bundle = bundle_fixture()
        runner = FakeRunner(bundle, post_drift=True, fail_rollback=True)
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "rollback_failed"):
            apply_rules.apply_bundle(bundle, runner)

    def test_post_check_failure_rolls_back_ipv4_chain(self) -> None:
        bundle = bundle_fixture()
        runner = FakeRunner(bundle, post_drift=True)
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "post_check_failed"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.current, runner.initial)
        self.assertEqual(runner.restore_counts, {"ip": 2, "ip6": 0})

    def test_near_name_or_comment_only_forward_jump_fails_before_restore(self) -> None:
        bundle = bundle_fixture()
        replacements = (
            "-A FORWARD -j DOCKER-USER-ALT",
            '-A FORWARD -m comment --comment "-j DOCKER-USER" -j ACCEPT',
        )
        for replacement in replacements:
            with self.subTest(rule=replacement):
                initial = empty_save().replace(
                    "-A FORWARD -j DOCKER-USER", replacement,
                )
                runner = FakeRunner(bundle, initial_ipv4=initial)
                with self.assertRaisesRegex(
                    apply_rules.EgressApplyError, "docker_user_unreachable",
                ):
                    apply_rules.apply_bundle(bundle, runner)
                self.assertFalse(any(
                    "restore" in args[0] for args, _ in runner.commands
                ))

    def test_foreign_chain_collision_fails_before_restore(self) -> None:
        bundle = bundle_fixture()
        foreign = "\n".join([
            "*filter", ":FORWARD ACCEPT [0:0]", ":DOCKER-USER - [0:0]",
            f":{generator.CHAIN_NAME} - [0:0]",
            "-A FORWARD -j DOCKER-USER",
            f"-A DOCKER-USER -i nh-egress0 -j {generator.CHAIN_NAME}",
            f"-A {generator.CHAIN_NAME} -j DROP", "COMMIT", "",
        ])
        runner = FakeRunner(bundle, initial_ipv4=foreign)
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "foreign_chain_collision"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertFalse(any("restore" in args[0] for args, _ in runner.commands))

    def test_foreign_reuse_of_owned_marker_fails_closed(self) -> None:
        bundle = bundle_fixture()
        save = installed_save(bundle, "ipv4").replace(
            "COMMIT\n",
            f'-A INPUT -m comment --comment "netops-helper-egress:{bundle["manifest_sha256"]}" -j ACCEPT\nCOMMIT\n',
        )
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "foreign_marker_collision"):
            apply_rules.snapshot_owned(save)

    def test_native_nftables_and_unknown_backend_fail_closed(self) -> None:
        bundle = bundle_fixture()
        for runner, code in (
            (FakeRunner(bundle, native_nft=True), "native_nftables_unsupported"),
            (FakeRunner(bundle, nft_failure=True), "backend_indeterminate"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(apply_rules.EgressApplyError, code):
                    apply_rules.apply_bundle(bundle, runner)
                self.assertFalse(any("restore" in args[0] for args, _ in runner.commands))

    def test_tampered_digest_fails_before_host_inspection(self) -> None:
        bundle = bundle_fixture()
        bundle["manifest_sha256"] = "0" * 64
        runner = FakeRunner(bundle)
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "bundle_invalid"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.commands, [])

    def test_load_bundle_requires_mode_600(self) -> None:
        bundle = bundle_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(apply_rules.EgressApplyError, "bundle_permissions"):
                apply_rules.load_bundle(path)
            os.chmod(path, 0o600)
            self.assertEqual(apply_rules.load_bundle(path), bundle)

    def test_main_requires_explicit_apply_and_root(self) -> None:
        for argv, uid, expected in (
            (["apply_egress_rules.py", "--bundle", "/missing"], 0, "explicit_apply_required"),
            (["apply_egress_rules.py", "--bundle", "/missing", "--apply"], 1000, "root_required"),
        ):
            with self.subTest(expected=expected), mock.patch.object(sys, "argv", argv), mock.patch.object(
                apply_rules.os, "geteuid", return_value=uid,
            ), redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                self.assertEqual(apply_rules.main(), 2)
                self.assertIn(expected, stderr.getvalue())

    def test_owned_snapshot_accepts_only_marked_first_jump(self) -> None:
        bundle = bundle_fixture()
        save = installed_save(bundle, "ipv4")
        snapshot = apply_rules.snapshot_owned(save)
        self.assertTrue(snapshot["exists"])
        marker = f"netops-helper-egress:{bundle['manifest_sha256']}"
        unquoted = save.replace(f'--comment "{marker}"', f"--comment {marker}")
        self.assertTrue(apply_rules.snapshot_owned(unquoted)["exists"])
        altered = save.replace(
            bundle["ruleset"]["ipv4"]["jump_rule"],
            bundle["ruleset"]["ipv4"]["jump_rule"].replace("netops-helper", "other"),
        )
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "foreign_chain_collision"):
            apply_rules.snapshot_owned(altered)


class HostInputGuardTests(unittest.TestCase):
    def test_apply_installs_the_input_guard_first_and_a_reapply_changes_nothing(self) -> None:
        bundle = bundle_fixture()
        ipv4 = bundle["ruleset"]["ipv4"]
        runner = SimulatedRunner(host_save())
        self.assertIn("ipv4_input_jump_missing_or_not_first", checker.check(bundle, observed(runner)))
        apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(checker.check(bundle, observed(runner)), [])
        table = runner.table.chains
        self.assertEqual(table["INPUT"], [ipv4["input_jump_rule"], "-A INPUT -i lo -j ACCEPT"])
        self.assertEqual(table[generator.INPUT_CHAIN_NAME], ipv4["input_chain_rules"])
        self.assertEqual(table["DOCKER-USER"][0], ipv4["jump_rule"])
        self.assertEqual(len(runner.restores), 1)
        installed = runner.table.save()
        apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.table.save(), installed)
        self.assertEqual(checker.check(bundle, observed(runner)), [])

    def test_apply_adds_the_input_guard_to_a_forward_only_installation(self) -> None:
        bundle = bundle_fixture()
        ipv4 = bundle["ruleset"]["ipv4"]
        old_marker = "netops-helper-egress:" + "0" * 64
        runner = SimulatedRunner(host_save())
        runner.table.chains[generator.CHAIN_NAME] = list(ipv4["chain_rules"])
        runner.table.policies[generator.CHAIN_NAME] = "-"
        runner.table.chains["DOCKER-USER"].insert(0, ipv4["jump_rule"].replace(
            f"netops-helper-egress:{bundle['manifest_sha256']}", old_marker,
        ))
        apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(checker.check(bundle, observed(runner)), [])
        self.assertNotIn(old_marker, runner.table.save())
        self.assertEqual(runner.table.chains["DOCKER-USER"], [ipv4["jump_rule"], "-A DOCKER-USER -j RETURN"])

    def test_apply_moves_a_displaced_input_jump_back_to_the_first_position(self) -> None:
        bundle = bundle_fixture()
        runner = SimulatedRunner(host_save())
        apply_rules.apply_bundle(bundle, runner)
        runner.table.chains["INPUT"].insert(0, "-A INPUT -j ACCEPT")
        self.assertEqual(
            checker.check(bundle, observed(runner)), ["ipv4_input_jump_missing_or_not_first"],
        )
        apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(checker.check(bundle, observed(runner)), [])
        self.assertEqual(runner.table.chains["INPUT"][1:], [
            "-A INPUT -j ACCEPT", "-A INPUT -i lo -j ACCEPT",
        ])

    def test_failed_post_check_restores_both_chains_exactly(self) -> None:
        bundle = bundle_fixture()
        drop = f"-A {generator.INPUT_CHAIN_NAME} -j DROP"
        for name, initial in (("fresh host", host_save()), ("installed", None)):
            with self.subTest(name=name):
                if initial is None:
                    seeded = SimulatedRunner(host_save())
                    apply_rules.apply_bundle(bundle, seeded)
                    initial = seeded.table.save()
                runner = SimulatedRunner(
                    initial,
                    after_apply=lambda table: table.chains[generator.INPUT_CHAIN_NAME].remove(drop),
                )
                with self.assertRaisesRegex(apply_rules.EgressApplyError, "post_check_failed"):
                    apply_rules.apply_bundle(bundle, runner)
                self.assertEqual(len(runner.restores), 2)
                self.assertEqual(runner.table.save(), SimulatedFilterTable(initial).save())

    def test_rollback_puts_a_displaced_input_jump_back_where_it_was(self) -> None:
        bundle = bundle_fixture()
        seeded = SimulatedRunner(host_save())
        apply_rules.apply_bundle(bundle, seeded)
        seeded.table.chains["INPUT"].insert(0, "-A INPUT -j ACCEPT")
        initial = seeded.table.save()
        drop = f"-A {generator.INPUT_CHAIN_NAME} -j DROP"
        runner = SimulatedRunner(
            initial,
            after_apply=lambda table: table.chains[generator.INPUT_CHAIN_NAME].remove(drop),
        )
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "post_check_failed"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.table.save(), initial)

    def test_a_refused_restore_leaves_the_host_unchanged(self) -> None:
        bundle = bundle_fixture()
        runner = SimulatedRunner(
            host_save(), refuse=lambda payload: generator.INPUT_CHAIN_NAME in payload,
        )
        before = runner.table.save()
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "host_command_failed"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.table.save(), before)

    def test_a_foreign_input_chain_or_marker_fails_before_restore(self) -> None:
        bundle = bundle_fixture()
        marker = f"netops-helper-egress:{bundle['manifest_sha256']}"
        foreign_rules = (
            [f"-A {generator.INPUT_CHAIN_NAME} -j ACCEPT"],
            [f"-A {generator.INPUT_CHAIN_NAME} -p tcp -m tcp --dport 22 -j ACCEPT",
             f"-A {generator.INPUT_CHAIN_NAME} -j DROP"],
        )
        for rules in foreign_rules:
            with self.subTest(rules=rules):
                runner = SimulatedRunner(host_save())
                runner.table.chains[generator.INPUT_CHAIN_NAME] = list(rules)
                runner.table.policies[generator.INPUT_CHAIN_NAME] = "-"
                runner.table.chains["INPUT"].insert(0, bundle["ruleset"]["ipv4"]["input_jump_rule"])
                with self.assertRaisesRegex(apply_rules.EgressApplyError, "foreign_chain_collision"):
                    apply_rules.apply_bundle(bundle, runner)
                self.assertEqual(runner.restores, [])
        runner = SimulatedRunner(host_save())
        runner.table.chains["INPUT"].insert(
            0, f'-A INPUT -i nh-egress0 -m comment --comment "{marker}" -j ACCEPT',
        )
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "foreign_marker_collision"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.restores, [])

    def test_a_bundle_without_the_input_guard_is_refused_by_name(self) -> None:
        bundle = bundle_fixture()
        bundle["bundle_schema"] = 3
        runner = SimulatedRunner(host_save())
        with self.assertRaisesRegex(apply_rules.EgressApplyError, "bundle_schema_outdated"):
            apply_rules.apply_bundle(bundle, runner)
        self.assertEqual(runner.restores, [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(apply_rules.EgressApplyError, "bundle_schema_outdated"):
                apply_rules.load_bundle(path)


if __name__ == "__main__":
    unittest.main()
