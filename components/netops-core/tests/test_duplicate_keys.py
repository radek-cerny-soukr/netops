from __future__ import annotations

import json
import os

import pytest

from netops_core import inventory, vault

CANARY = "KANARCI-DUPLIKAT-NESMI-UNIKNOUT"
DEVICE = {
    "name": "fw-a.example.invalid",
    "platform": "fortios",
    "address": "192.0.2.10",
    "port": 22,
    "role": "perimetr",
    "credential": "fw-a-ro",
    "host_key_fingerprint": "SHA256:" + "A" * 43,
    "legacy_ssh": None,
    "auditor": {"channel": "ssh", "required_sections": ["system global"]},
    "helper": None,
}


def write_vault(tmp_path, text):
    path = tmp_path / "vault.json"
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def write_inventory(tmp_path, text):
    path = tmp_path / "inventory.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_a9_vault_entry_with_a_repeated_field_is_refused_without_its_values(tmp_path):
    text = ('{"version": 2, "credentials": {"fw-a-api": {"kind": "api-token", "value": "%s", "value": "%s-2"}}}'
            % (CANARY, CANARY))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(write_vault(tmp_path, text))
    assert "duplicate key" in str(caught.value)
    assert CANARY not in str(caught.value)


def test_a9_vault_with_a_repeated_credential_name_is_refused(tmp_path):
    entry = json.dumps({"kind": "api-token", "value": CANARY})
    text = '{"version": 2, "credentials": {"fw-a-api": %s, "fw-a-api": %s}}' % (entry, entry)
    with pytest.raises(vault.VaultError, match="duplicate key"):
        vault.load(write_vault(tmp_path, text))


def test_a9_vault_without_a_repeated_key_still_loads(tmp_path):
    text = json.dumps({"version": 2, "credentials": {"fw-a-api": {"kind": "api-token", "value": CANARY}}})
    assert vault.load(write_vault(tmp_path, text)).credential("fw-a-api").kind == "api-token"


def test_a9_inventory_device_with_a_repeated_field_is_refused(tmp_path):
    body = json.dumps(DEVICE)
    assert body.count('"port": 22') == 1
    body = body.replace('"port": 22', '"port": 22, "port": 2222')
    with pytest.raises(inventory.InventoryError, match="duplicate key"):
        inventory.load(write_inventory(tmp_path, '{"version": 2, "devices": [%s]}' % body))
    top = '{"version": 2, "devices": [], "devices": [%s]}' % json.dumps(DEVICE)
    with pytest.raises(inventory.InventoryError, match="duplicate key"):
        inventory.load(write_inventory(tmp_path, top))
    assert inventory.load(write_inventory(tmp_path, json.dumps({"version": 2, "devices": [DEVICE]})))[0].port == 22


def test_a9_deep_nesting_is_a_controlled_error(tmp_path):
    with pytest.raises(vault.VaultError):
        vault.load(write_vault(tmp_path, "[" * 100000))
    with pytest.raises(inventory.InventoryError):
        inventory.load(write_inventory(tmp_path, "[" * 100000))
