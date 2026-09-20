#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for SOURCE_ROOT in (
    COMPONENT_ROOT / "src", COMPONENT_ROOT.parent / "netops-core" / "src",
):
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))

from netops_core import hostkey
from netops_core import inventory as core_inventory
from netops_core import vault as core_vault
from netops_helper import inventory as helper_inventory
from netops_helper import legacy_configuration

FILES = ("inventory.json", "vault.json", "egress-policy.json", "runner.json")
RUNNER_VERSION = 1
RUNNER_FIELDS = ("version", "host", "port", "credential", "host_key_fingerprint")


class PreflightError(Exception):
    pass


def _error(label: str, detail: str) -> PreflightError:
    return PreflightError("%s: %s" % (label, detail))


def _configured_path(variable: str, default: Path) -> Path:
    return Path(os.environ.get(variable, default)).expanduser()


def default_paths() -> dict:
    config_home = _configured_path("XDG_CONFIG_HOME", Path.home() / ".config") / "netops-helper"
    inventory = _configured_path("NETOPS_INVENTORY_PATH", config_home / "inventory.json")
    return {
        "inventory.json": inventory,
        "vault.json": _configured_path("NETOPS_VAULT_PATH", config_home / "vault.json"),
        "egress-policy.json": _configured_path(
            "NETOPS_EGRESS_POLICY_PATH", inventory.parent / "egress-policy.json",
        ),
        "runner.json": _configured_path(
            "NETOPS_RUNNER_PATH", inventory.parent / "runner.json",
        ),
    }


def _require_regular_file(label: str, path: Path) -> None:
    try:
        information = path.lstat()
    except OSError:
        raise _error(label, "does not exist at the configured path") from None
    if stat.S_ISLNK(information.st_mode):
        raise _error(label, "must not be a symbolic link")
    if not stat.S_ISREG(information.st_mode):
        raise _error(label, "must be a regular file")


def _read_text(label: str, path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise _error(label, "is not valid UTF-8") from None
    except OSError as error:
        raise _error(label, "cannot be read (%s)" % (error.strerror or error)) from None


def _parsed_json(label: str, path: Path) -> dict:
    text = _read_text(label, path)
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise _error(label, "is not valid JSON (%s)" % error.msg) from None
    if not isinstance(document, dict):
        raise _error(label, "must hold a JSON object")
    return document


def _runner_document(label: str, path: Path) -> dict:
    document = _parsed_json(label, path)
    if set(document) != set(RUNNER_FIELDS):
        raise _error(label, "must hold exactly the fields %s" % ", ".join(RUNNER_FIELDS))
    version = document["version"]
    if isinstance(version, bool) or version != RUNNER_VERSION:
        raise _error(label, "version must be %d" % RUNNER_VERSION)
    host = document["host"]
    if (
        not isinstance(host, str) or not 0 < len(host) <= 253
        or host.startswith("-") or "@" in host
        or any(ord(character) < 33 or ord(character) == 127 for character in host)
    ):
        raise _error(label, "host must be a bare host name or address")
    port = document["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise _error(label, "port must be a whole number between 1 and 65535")
    credential = document["credential"]
    if not isinstance(credential, str) or not credential.strip():
        raise _error(label, "credential must name a record in the credential store")
    try:
        pin = hostkey.checked_pin(document["host_key_fingerprint"])
    except hostkey.HostKeyError as error:
        raise _error(label, str(error)) from None
    return {"host": host, "port": port, "credential": credential, "host_key_fingerprint": pin}


def _vault(label: str, path: Path) -> core_vault.Vault:
    try:
        return core_vault.load(path)
    except core_vault.VaultError as error:
        raise _error(label, str(error)) from None


def _devices(label: str, path: Path) -> tuple:
    try:
        return core_inventory.load(path)
    except core_inventory.InventoryError as error:
        raise _error(label, str(error)) from None


def _section(label: str, entry, kinds: dict):
    try:
        return helper_inventory.section(entry, kinds)
    except helper_inventory.InventoryError as error:
        raise _error(label, str(error)) from None


def _egress_policy(label: str, document: dict) -> dict:
    try:
        return helper_inventory.egress_policy(document)
    except helper_inventory.InventoryError as error:
        raise _error(label, str(error)) from None


def _checked_coverage(label: str, enrolled: list, policy: dict) -> None:
    if policy["profile"] != "lan-constrained":
        return
    networks = [ipaddress.ip_network(item) for item in policy["lan_cidrs"]]
    for entry, section in enrolled:
        for destination in section.egress["addresses"]:
            address = ipaddress.ip_address(destination)
            if not any(address in network for network in networks):
                raise _error(
                    label,
                    "device %r egress address %s is not covered by any lan_cidrs entry"
                    % (entry.name, destination),
                )


def check(paths: dict) -> dict:
    for label in FILES:
        _require_regular_file(label, paths[label])

    vault = _vault("vault.json", paths["vault.json"])
    devices = _devices("inventory.json", paths["inventory.json"])
    helper_devices = helper_inventory.devices(devices)
    if not helper_devices:
        raise _error("inventory.json", "no device carries a helper section")

    kinds = {name: vault.credential(name).kind for name in vault.names()}
    enrolled = [(entry, _section("inventory.json", entry, kinds)) for entry in helper_devices]

    runner = _runner_document("runner.json", paths["runner.json"])
    runner_kind = kinds.get(runner["credential"])
    if runner_kind is None:
        raise _error(
            "runner.json",
            "credential %r is not a record of the credential store" % runner["credential"],
        )
    if runner_kind not in helper_inventory.CREDENTIAL_KINDS:
        raise _error(
            "runner.json",
            "credential %r has kind %s, the runner needs one of: %s"
            % (runner["credential"], runner_kind, ", ".join(helper_inventory.CREDENTIAL_KINDS)),
        )

    policy_document = _parsed_json("egress-policy.json", paths["egress-policy.json"])
    policy = _egress_policy("egress-policy.json", policy_document)
    _checked_coverage("egress-policy.json", enrolled, policy)

    return {"devices": len(helper_devices), "credentials": len(vault.names())}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the four NetOps Helper operator files (inventory, vault, egress policy,"
            " runner) without contacting a device or printing a secret."
        ),
    )
    defaults = default_paths()
    parser.add_argument("--inventory", type=Path, default=defaults["inventory.json"])
    parser.add_argument("--vault", type=Path, default=defaults["vault.json"])
    parser.add_argument("--egress-policy", type=Path, default=defaults["egress-policy.json"])
    parser.add_argument("--runner", type=Path, default=defaults["runner.json"])
    arguments = parser.parse_args()
    paths = {
        "inventory.json": arguments.inventory,
        "vault.json": arguments.vault,
        "egress-policy.json": arguments.egress_policy,
        "runner.json": arguments.runner,
    }
    legacy = legacy_configuration.legacy_configuration_detail(paths["inventory.json"].parent)
    if legacy is not None:
        print(
            "operator_config_check=failed detail=%s: %s"
            % (legacy, legacy_configuration.LEGACY_CONFIGURATION_MESSAGE),
            file=sys.stderr,
        )
        return 1
    try:
        summary = check(paths)
    except PreflightError as error:
        print("operator_config_check=failed detail=%s" % error, file=sys.stderr)
        return 1
    print(
        "operator_config_check=passed devices=%d credentials=%d"
        % (summary["devices"], summary["credentials"])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
