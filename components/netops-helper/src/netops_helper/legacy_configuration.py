"""Detection of retired configuration inputs, shared by the proxy and the preflight."""

from __future__ import annotations

import os
from pathlib import Path

REMOVED_VARIABLES = (
    "NETOPS_TARGET_POLICY_PATH", "NETOPS_KNOWN_HOSTS_PATH", "NETOPS_MASTER_ALIAS",
)
REMOVED_FILES = ("target-policy.json",)
LEGACY_CONFIGURATION_MESSAGE = (
    "Enroll the devices in inventory.json, the runner in runner.json and the firewall"
    " inputs in egress-policy.json; target-policy.json, NETOPS_TARGET_POLICY_PATH,"
    " NETOPS_KNOWN_HOSTS_PATH and NETOPS_MASTER_ALIAS are gone."
)


def legacy_configuration_detail(inventory_directory: Path) -> str | None:
    for variable in REMOVED_VARIABLES:
        if variable in os.environ:
            return variable
    for name in REMOVED_FILES:
        if (inventory_directory / name).exists():
            return name
    return None
