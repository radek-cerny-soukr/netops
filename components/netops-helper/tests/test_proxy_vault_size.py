from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from netops_core import vault as core_vault
from netops_helper import proxy as MODULE

CHILD = r"""
import resource, sys
from pathlib import Path
from netops_helper import proxy

proxy.VAULT = Path(sys.argv[1])
with open("/proc/self/status") as status:
    size = next(int(line.split()[1]) * 1024 for line in status if line.startswith("VmSize:"))
resource.setrlimit(resource.RLIMIT_AS, (size + 256 * 1024 * 1024, resource.getrlimit(resource.RLIMIT_AS)[1]))
try:
    proxy.Proxy()._vault()
    print("loaded")
except proxy.ProxyError as error:
    print(error.category)
except MemoryError:
    print("MemoryError")
"""


def _write_vault(path: Path) -> None:
    path.write_text(json.dumps({
        "version": 2,
        "credentials": {"device-a-account": {"kind": "password", "login": "user", "value": "secret"}},
    }) + "\n")
    path.chmod(0o600)


@pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="needs /proc/self/status")
def test_a_huge_vault_is_refused_without_reading_it_whole(tmp_path: Path) -> None:
    vault = tmp_path / "vault.json"
    with open(vault, "wb") as handle:
        handle.truncate(4 * 1024 * 1024 * 1024)
    vault.chmod(0o600)
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    finished = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, str(vault)],
        capture_output=True, text=True, timeout=60, env=environment,
    )
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.strip() == "vault_schema"


def test_a_vault_over_the_store_limit_is_a_schema_error(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    vault.write_bytes(b" " * (core_vault.VAULT_MAX_BYTES + 1))
    vault.chmod(0o600)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    with pytest.raises(MODULE.VaultSchemaError):
        MODULE.Proxy()._vault()


def test_a_vault_at_the_store_limit_still_loads(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    _write_vault(vault)
    body = vault.read_bytes()
    vault.write_bytes(body + b" " * (core_vault.VAULT_MAX_BYTES - len(body)))
    assert vault.stat().st_size == core_vault.VAULT_MAX_BYTES
    monkeypatch.setattr(MODULE, "VAULT", vault)
    assert MODULE.Proxy()._vault().credential("device-a-account").login == "user"
