from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
from pathlib import Path

import pytest

from netops_core import inventory, vault

SOURCE = Path(__file__).resolve().parents[1] / "src"
INVENTORY_LIMIT = 4 * 1024 * 1024
VAULT_LIMIT = 1024 * 1024
MEMORY_CAP = 768 * 1024 * 1024
SECONDS = 30
ZERO = "/dev/zero"

PROBE = """
import sys
from netops_core import inventory
try:
    inventory.load(sys.argv[1])
except inventory.InventoryError as error:
    print(error)
    sys.exit(2)
"""


def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_CAP, MEMORY_CAP))


def _load_inventory(path):
    environment = dict(os.environ, PYTHONPATH=str(SOURCE))
    try:
        return subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(path)],
            capture_output=True, text=True, timeout=SECONDS, env=environment, preexec_fn=_limited,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the inventory was still being read after %d seconds: %s" % (SECONDS, path))


def _padded(document, size):
    text = json.dumps(document)
    return text + " " * (size - len(text))


@pytest.mark.skipif(not Path(ZERO).exists(), reason="needs /dev/zero")
def test_inventory_from_dev_zero_is_refused():
    result = _load_inventory(ZERO)
    assert result.returncode == 2, result.stderr[-400:]
    assert "not a regular file" in result.stdout
    assert "Traceback" not in result.stderr


def test_inventory_from_a_fifo_without_a_writer_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "inventory.fifo"
    os.mkfifo(fifo)
    result = _load_inventory(fifo)
    assert result.returncode == 2, result.stderr[-400:]
    assert "not a regular file" in result.stdout


def test_inventory_over_the_limit_is_refused(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(_padded({"version": 2, "devices": []}, INVENTORY_LIMIT + 1), encoding="utf-8")
    with pytest.raises(inventory.InventoryError) as error:
        inventory.load(path)
    assert "larger than %d bytes" % INVENTORY_LIMIT in str(error.value)


def test_inventory_at_the_limit_is_read(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(_padded({"version": 2, "devices": []}, INVENTORY_LIMIT), encoding="utf-8")
    assert inventory.load(path) == ()


def test_vault_over_the_limit_is_refused(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text(_padded({"version": 2, "credentials": {}}, VAULT_LIMIT + 1), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(vault.VaultError) as error:
        vault.load(path)
    assert "larger than %d bytes" % VAULT_LIMIT in str(error.value)


def test_vault_at_the_limit_is_read(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text(_padded({"version": 2, "credentials": {}}, VAULT_LIMIT), encoding="utf-8")
    os.chmod(path, 0o600)
    vault.load(path)


def test_inventory_that_is_not_utf_8_is_refused(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_bytes(b'{"version": 2, "devices": [], "x": "' + bytes([0xFF]) + b'"}')
    with pytest.raises(inventory.InventoryError) as error:
        inventory.load(path)
    assert "is not valid UTF-8" in str(error.value)
