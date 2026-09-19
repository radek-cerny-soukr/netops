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
        ":FORWARD ACCEPT [0:0]",
        ":DOCKER-USER - [0:0]",
        f":{generator.CHAIN_NAME} - [0:0]",
        "-A FORWARD -j DOCKER-USER",
        expected["jump_rule"],
        *expected["chain_rules"],
        "COMMIT",
        "",
    ])


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
        self.assertEqual(set(bundle["ruleset"]), {"backend", "chain", "ipv4"})
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


if __name__ == "__main__":
    unittest.main()
