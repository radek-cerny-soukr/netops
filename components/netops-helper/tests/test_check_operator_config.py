from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
import ipaddress
import json
from io import StringIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_operator_config.py"


def _load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


checker = _load("check_operator_config", SCRIPT_PATH)

PIN_A = "SHA256:" + "A" * 43
PIN_B = "SHA256:" + "B" * 43
LAN_CIDR_SAMPLE = str(ipaddress.ip_network((0x0A000000, 24)))
LAN_ADDRESS_INSIDE = str(ipaddress.ip_address(0x0A000005))
LAN_ADDRESS_OUTSIDE = str(ipaddress.ip_address(0xAC100005))
SECRET_MARKER = "unit-test-marker-never-printed"

GOOD_INVENTORY = {
    "version": 2,
    "devices": [{
        "name": "device-a",
        "platform": "linux",
        "address": "192.0.2.10",
        "port": 22,
        "role": "interni",
        "credential": "device-a-account",
        "host_key_fingerprint": PIN_A,
        "legacy_ssh": None,
        "auditor": None,
        "helper": {
            "account_role": "read-only",
            "ssh_platform": "linux",
            "enabled_queries": ["hostname"],
            "read_inventory": {},
            "sftp_roots": [],
            "fortios_output_standard_verified": False,
            "rate_limit": {"requests": 30, "window_seconds": 60},
            "egress": {
                "addresses": ["192.0.2.10"],
                "tcp_ports": [],
                "udp_ports": [],
                "tcp_port_ranges": [],
                "udp_port_ranges": [],
                "allow_icmp": False,
                "allow_dns": False,
                "tls_server_names": [],
            },
        },
    }],
}
GOOD_VAULT = {
    "version": 2,
    "credentials": {
        "device-a-account": {
            "kind": "ssh-key",
            "login": "reader",
            "value": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + SECRET_MARKER
                + "\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
        },
        "runner-account": {"kind": "password", "login": "reader", "value": SECRET_MARKER},
    },
}
GOOD_RUNNER = {
    "version": 1,
    "host": "runner.example.invalid",
    "port": 22,
    "credential": "runner-account",
    "host_key_fingerprint": PIN_B,
}
GOOD_EGRESS_POLICY = {
    "schema_version": 1,
    "profile": "strict-target",
    "backend": "iptables",
    "bridge_name": "nh-egress0",
    "network_name": "netops-helper",
    "ipv6_mode": "deny",
    "dns_resolvers": [],
    "lan_cidrs": [],
}


def _write(directory: Path, name: str, document: dict, mode: int) -> Path:
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(mode)
    return path


def _good_paths(directory: Path) -> dict:
    return {
        "inventory.json": _write(directory, "inventory.json", copy.deepcopy(GOOD_INVENTORY), 0o644),
        "vault.json": _write(directory, "vault.json", copy.deepcopy(GOOD_VAULT), 0o600),
        "egress-policy.json": _write(
            directory, "egress-policy.json", copy.deepcopy(GOOD_EGRESS_POLICY), 0o644,
        ),
        "runner.json": _write(directory, "runner.json", copy.deepcopy(GOOD_RUNNER), 0o644),
    }


class GoodConfigurationTests(unittest.TestCase):
    def test_a_good_configuration_passes_and_reports_no_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _good_paths(Path(directory))
            summary = checker.check(paths)
            self.assertEqual(summary, {"devices": 1, "credentials": 2})

    def test_a_lan_constrained_policy_that_covers_every_device_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["address"] = LAN_ADDRESS_INSIDE
            document["devices"][0]["helper"]["egress"]["addresses"] = [LAN_ADDRESS_INSIDE]
            _write(directory_path, "inventory.json", document, 0o644)
            policy = copy.deepcopy(GOOD_EGRESS_POLICY)
            policy["profile"] = "lan-constrained"
            policy["lan_cidrs"] = [LAN_CIDR_SAMPLE]
            _write(directory_path, "egress-policy.json", policy, 0o644)
            summary = checker.check(paths)
            self.assertEqual(summary, {"devices": 1, "credentials": 2})


class BrokenConfigurationTests(unittest.TestCase):
    def test_a_missing_file_names_the_file_and_exits_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _good_paths(Path(directory))
            paths["inventory.json"].unlink()
            with self.assertRaisesRegex(checker.PreflightError, r"^inventory\.json: does not exist"):
                checker.check(paths)

    def test_a_symlinked_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            outside = directory_path.parent / "outside-runner.json"
            paths["runner.json"].replace(outside)
            paths["runner.json"].symlink_to(outside)
            with self.assertRaisesRegex(checker.PreflightError, r"^runner\.json: must not be a symbolic link"):
                checker.check(paths)

    def test_a_bad_vault_mode_names_vault_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _good_paths(Path(directory))
            paths["vault.json"].chmod(0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^vault\.json: .*mode 0644"):
                checker.check(paths)

    def test_an_old_inventory_schema_version_names_inventory_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["version"] = 1
            _write(directory_path, "inventory.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^inventory\.json: .*version 1, expected 2"):
                checker.check(paths)

    def test_an_old_vault_schema_version_names_vault_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_VAULT)
            document["version"] = 1
            _write(directory_path, "vault.json", document, 0o600)
            with self.assertRaisesRegex(checker.PreflightError, r"^vault\.json: "):
                checker.check(paths)

    def test_a_helper_section_missing_a_required_field_names_inventory_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            del document["devices"][0]["helper"]["egress"]
            _write(directory_path, "inventory.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^inventory\.json: .*missing fields: egress"):
                checker.check(paths)

    def test_a_device_credential_absent_from_the_vault_names_inventory_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["credential"] = "no-such-credential"
            _write(directory_path, "inventory.json", document, 0o644)
            with self.assertRaisesRegex(
                checker.PreflightError, r"^inventory\.json: .*no-such-credential.*not a record",
            ):
                checker.check(paths)

    def test_no_helper_enrolled_device_names_inventory_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["helper"] = None
            document["devices"][0]["auditor"] = {}
            _write(directory_path, "inventory.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^inventory\.json: no device carries"):
                checker.check(paths)

    def test_an_unknown_runner_credential_names_runner_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_RUNNER)
            document["credential"] = "no-such-credential"
            _write(directory_path, "runner.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^runner\.json: .*not a record"):
                checker.check(paths)

    def test_a_runner_credential_of_the_wrong_kind_names_runner_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            vault_document = copy.deepcopy(GOOD_VAULT)
            vault_document["credentials"]["runner-account"] = {
                "kind": "snmp-community", "value": SECRET_MARKER,
            }
            _write(directory_path, "vault.json", vault_document, 0o600)
            with self.assertRaisesRegex(checker.PreflightError, r"^runner\.json: .*kind snmp-community"):
                checker.check(paths)

    def test_a_malformed_host_key_pin_names_runner_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_RUNNER)
            document["host_key_fingerprint"] = "not-a-pin"
            _write(directory_path, "runner.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^runner\.json: .*host_key_fingerprint"):
                checker.check(paths)

    def test_an_unknown_egress_schema_version_names_egress_policy_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_EGRESS_POLICY)
            document["schema_version"] = 2
            _write(directory_path, "egress-policy.json", document, 0o644)
            with self.assertRaisesRegex(checker.PreflightError, r"^egress-policy\.json: "):
                checker.check(paths)

    def test_a_device_outside_the_declared_lan_scope_names_egress_policy_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["address"] = LAN_ADDRESS_OUTSIDE
            document["devices"][0]["helper"]["egress"]["addresses"] = [LAN_ADDRESS_OUTSIDE]
            _write(directory_path, "inventory.json", document, 0o644)
            policy = copy.deepcopy(GOOD_EGRESS_POLICY)
            policy["profile"] = "lan-constrained"
            policy["lan_cidrs"] = [LAN_CIDR_SAMPLE]
            _write(directory_path, "egress-policy.json", policy, 0o644)
            with self.assertRaisesRegex(
                checker.PreflightError,
                r"^egress-policy\.json: .*is not covered by any lan_cidrs entry",
            ):
                checker.check(paths)


class NoSecretLeaksThroughFindingsTests(unittest.TestCase):
    def test_a_broken_login_never_echoes_the_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_VAULT)
            document["credentials"]["runner-account"]["login"] = None
            _write(directory_path, "vault.json", document, 0o600)
            with self.assertRaises(checker.PreflightError) as caught:
                checker.check(paths)
            self.assertNotIn(SECRET_MARKER, str(caught.exception))

    def test_an_empty_secret_never_echoes_the_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_VAULT)
            document["credentials"]["device-a-account"]["value"] = ""
            _write(directory_path, "vault.json", document, 0o600)
            with self.assertRaises(checker.PreflightError) as caught:
                checker.check(paths)
            self.assertNotIn(SECRET_MARKER, str(caught.exception))


class MainCliTests(unittest.TestCase):
    def test_main_reports_a_passing_configuration_on_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            argv = [
                "check_operator_config.py",
                "--inventory", str(paths["inventory.json"]),
                "--vault", str(paths["vault.json"]),
                "--egress-policy", str(paths["egress-policy.json"]),
                "--runner", str(paths["runner.json"]),
            ]
            with mock.patch.object(sys, "argv", argv), redirect_stdout(StringIO()) as stdout:
                self.assertEqual(checker.main(), 0)
            self.assertIn("operator_config_check=passed devices=1 credentials=2", stdout.getvalue())

    def test_main_reports_a_failing_configuration_on_stderr_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            paths["vault.json"].chmod(0o644)
            argv = [
                "check_operator_config.py",
                "--inventory", str(paths["inventory.json"]),
                "--vault", str(paths["vault.json"]),
                "--egress-policy", str(paths["egress-policy.json"]),
                "--runner", str(paths["runner.json"]),
            ]
            with mock.patch.object(sys, "argv", argv), redirect_stdout(StringIO()) as stdout, redirect_stderr(
                StringIO()
            ) as stderr:
                self.assertEqual(checker.main(), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("operator_config_check=failed detail=vault.json:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
