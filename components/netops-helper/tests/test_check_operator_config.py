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
                checker.PreflightError,
                r"^inventory\.json: device device-a: .*credential names no record",
            ) as caught:
                checker.check(paths)
            self.assertNotIn("no-such-credential", str(caught.exception))

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
            with self.assertRaisesRegex(
                checker.PreflightError, r"^runner\.json: credential names no record",
            ) as caught:
                checker.check(paths)
            self.assertNotIn("no-such-credential", str(caught.exception))

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


    def test_a_device_port_inside_a_tcp_range_names_inventory_json_and_the_port(self) -> None:
        for name, helper in (
            ("ssh queries", {}),
            ("sftp roots only", {"ssh_platform": None, "enabled_queries": [], "sftp_roots": ["/srv"]}),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                directory_path = Path(directory)
                paths = _good_paths(directory_path)
                document = copy.deepcopy(GOOD_INVENTORY)
                document["devices"][0]["helper"].update(helper)
                document["devices"][0]["helper"]["egress"]["tcp_port_ranges"] = [[20, 30]]
                _write(directory_path, "inventory.json", document, 0o644)
                with self.assertRaises(checker.PreflightError) as caught:
                    checker.check(paths)
                message = str(caught.exception)
                self.assertTrue(message.startswith("inventory.json: device device-a"), message)
                self.assertIn("port 22 of the device lies inside egress tcp_port_ranges [20, 30]", message)
                self.assertNotIn(SECRET_MARKER, message)

    def test_a_device_port_inside_a_tcp_range_passes_when_the_helper_never_uses_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["helper"].update({
                "ssh_platform": None, "enabled_queries": [], "sftp_roots": [],
            })
            document["devices"][0]["helper"]["egress"]["tcp_port_ranges"] = [[20, 30]]
            _write(directory_path, "inventory.json", document, 0o644)
            self.assertEqual(checker.check(paths), {"devices": 1, "credentials": 2})

    def test_an_enrollment_the_egress_generator_refuses_fails_the_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            document = copy.deepcopy(GOOD_INVENTORY)
            document["devices"][0]["helper"]["egress"]["allow_dns"] = True
            _write(directory_path, "inventory.json", document, 0o644)
            with self.assertRaises(checker.PreflightError) as caught:
                checker.check(paths)
            self.assertEqual(
                str(caught.exception),
                "egress-policy.json: the egress rule generator refuses this enrollment:"
                " DNS enrollment requires DNS resolvers",
            )


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


CANARY = "canary-pasted-where-a-name-belongs"


def _inventory_with(change) -> dict:
    document = copy.deepcopy(GOOD_INVENTORY)
    change(document["devices"][0])
    return document


def _helper_with(name, value):
    return lambda device: device["helper"].__setitem__(name, value)


def _egress_with(name, value):
    return lambda device: device["helper"]["egress"].__setitem__(name, value)


CANARY_CASES = (
    ("credential", "inventory.json", _inventory_with(lambda device: device.__setitem__("credential", CANARY))),
    ("credential-list", "inventory.json",
     _inventory_with(lambda device: device.__setitem__("credential", [CANARY]))),
    ("device-password", "inventory.json",
     _inventory_with(lambda device: device.__setitem__("password", CANARY))),
    ("snmp_credential", "inventory.json", _inventory_with(_helper_with("snmp_credential", CANARY))),
    ("helper-password", "inventory.json", _inventory_with(_helper_with("password", CANARY))),
    ("egress-psk", "inventory.json", _inventory_with(_egress_with("psk", CANARY))),
    ("egress-addresses", "inventory.json", _inventory_with(_egress_with("addresses", {"secret": CANARY}))),
    ("egress-tcp_ports", "inventory.json", _inventory_with(_egress_with("tcp_ports", {"token": CANARY}))),
    ("rate_limit-token", "inventory.json", _inventory_with(_helper_with(
        "rate_limit", {"requests": 30, "window_seconds": 60, "token": CANARY}))),
    ("read_inventory", "inventory.json", _inventory_with(_helper_with("read_inventory", [CANARY]))),
    ("read_inventory-text", "inventory.json", _inventory_with(_helper_with("read_inventory", CANARY))),
    ("egress-text", "inventory.json", _inventory_with(_helper_with("egress", CANARY))),
    ("sftp_roots-text", "inventory.json", _inventory_with(_helper_with("sftp_roots", CANARY))),
    ("sftp_roots", "inventory.json", _inventory_with(_helper_with("sftp_roots", {"password": CANARY}))),
    ("enabled_queries", "inventory.json", _inventory_with(_helper_with("enabled_queries", {"key": CANARY}))),
    ("vault-login", "vault.json", None),
    ("runner-credential", "runner.json", dict(GOOD_RUNNER, credential=CANARY)),
    ("egress-policy-secret", "egress-policy.json", dict(GOOD_EGRESS_POLICY, secret=CANARY)),
    ("egress-policy-lan_cidrs", "egress-policy.json", dict(
        GOOD_EGRESS_POLICY, profile="lan-constrained", lan_cidrs={"psk": CANARY})),
)


class CanaryInEveryReferenceFieldTests(unittest.TestCase):
    def test_a_canary_in_a_reference_or_secret_like_field_never_reaches_the_output(self) -> None:
        for name, label, document in CANARY_CASES:
            with self.subTest(field=name), tempfile.TemporaryDirectory() as directory:
                directory_path = Path(directory)
                paths = _good_paths(directory_path)
                if name == "vault-login":
                    document = copy.deepcopy(GOOD_VAULT)
                    document["credentials"]["runner-account"]["login"] = "reader:" + CANARY
                _write(directory_path, label, document, 0o600 if label == "vault.json" else 0o644)
                argv = [
                    "check_operator_config.py",
                    "--inventory", str(paths["inventory.json"]),
                    "--vault", str(paths["vault.json"]),
                    "--egress-policy", str(paths["egress-policy.json"]),
                    "--runner", str(paths["runner.json"]),
                ]
                with mock.patch.object(sys, "argv", argv), redirect_stdout(
                    StringIO()
                ) as stdout, redirect_stderr(StringIO()) as stderr:
                    self.assertEqual(checker.main(), 1)
                self.assertIn("operator_config_check=failed detail=%s:" % label, stderr.getvalue())
                self.assertNotIn(CANARY, stdout.getvalue() + stderr.getvalue())


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


class LegacyConfigurationTests(unittest.TestCase):
    def test_a_leftover_target_policy_file_fails_preflight_and_names_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = _good_paths(directory_path)
            (directory_path / "target-policy.json").write_text("{}", encoding="utf-8")
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
            self.assertIn("operator_config_check=failed detail=target-policy.json:", stderr.getvalue())

    def test_a_removed_environment_variable_fails_preflight_the_same_way_as_the_proxy(self) -> None:
        for variable in checker.legacy_configuration.REMOVED_VARIABLES:
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
                with mock.patch.dict("os.environ", {variable: "set-by-an-old-deployment"}):
                    with mock.patch.object(sys, "argv", argv), redirect_stdout(
                        StringIO()
                    ) as stdout, redirect_stderr(StringIO()) as stderr:
                        self.assertEqual(checker.main(), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "operator_config_check=failed detail=%s:" % variable, stderr.getvalue(),
                )
                self.assertIn(
                    checker.legacy_configuration.LEGACY_CONFIGURATION_MESSAGE, stderr.getvalue(),
                )


if __name__ == "__main__":
    unittest.main()
