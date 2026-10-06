from __future__ import annotations

import json
import os
import traceback

import pytest

from netops_core import inventory, vault

CANARY = "KANAREK-OMYLEM-VLOZENE-HESLO"
PIN = "SHA256:" + "A" * 43
DEVICE = {
    "name": "fw-a.example.invalid",
    "platform": "fortios",
    "address": "192.0.2.10",
    "port": 22,
    "role": "perimetr",
    "credential": "fw-a-ro",
    "host_key_fingerprint": PIN,
    "legacy_ssh": None,
    "auditor": {"channel": "ssh"},
    "helper": None,
}


def _shown(error) -> tuple:
    return (
        str(error),
        repr(error),
        "".join(traceback.format_exception(type(error), error, error.__traceback__)),
    )


def _vault(tmp_path, credentials):
    path = tmp_path / "vault.json"
    path.write_text(json.dumps({"version": 2, "credentials": credentials}), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _inventory(tmp_path, document):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _device(**overrides):
    entry = dict(DEVICE)
    entry.update(overrides)
    return entry


def test_a_secret_given_as_a_credential_reference_is_not_repeated(tmp_path):
    loaded = vault.load(_vault(tmp_path, {"fw-a-ro": {"kind": "api-token", "value": "replace-me"}}))
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential(CANARY)
    for text in _shown(caught.value):
        assert CANARY not in text
    assert "names no record of the credential store" in str(caught.value)
    assert "fw-a-ro" in str(caught.value)


def test_the_caller_names_the_position_of_an_unknown_reference(tmp_path):
    loaded = vault.load(_vault(tmp_path, {}))
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential(CANARY, where="device fw-a.example.invalid: credential")
    assert "device fw-a.example.invalid: credential names no record" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("login", ["audit-ro:" + CANARY, CANARY + "@host", "-" + CANARY, "audit ro " + CANARY])
def test_a_secret_pasted_into_a_login_is_not_repeated(tmp_path, login):
    path = _vault(tmp_path, {"fw-a-ro": {"kind": "password", "login": login, "value": "replace-me"}})
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "login must be a plain user name" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("document,expected", [
    ({"version": 2, "devices": [_device(credential=[CANARY])]}, "device 0: credential must be null"),
    ({"version": 2, "devices": [_device(credential={"password": CANARY})]}, "device 0: credential must be null"),
    ({"version": 2, "devices": [[CANARY]]}, "device 0: must be an object"),
    ({"version": 2, "devices": [CANARY]}, "device 0: must be an object"),
    ({"version": 2, "devices": {"fw-a": _device(credential=CANARY)}}, "devices must be a list"),
    ([_device(credential=CANARY)], "must hold an object"),
    ({"version": 2, "devices": [_device(auditor=[CANARY])]}, "device 0: auditor must be null or an object"),
    ({"version": 2, "devices": [_device(helper=CANARY)]}, "device 0: helper must be null or an object"),
])
def test_an_inventory_error_does_not_repeat_a_value_that_may_be_a_secret(tmp_path, document, expected):
    with pytest.raises(inventory.InventoryError) as caught:
        inventory.load(_inventory(tmp_path, document))
    assert expected in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_a_secret_as_credential_reference_loads_and_fails_only_at_the_vault(tmp_path):
    devices = inventory.load(_inventory(tmp_path, {"version": 2, "devices": [_device(credential=CANARY)]}))
    loaded = vault.load(_vault(tmp_path, {}))
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential(devices[0].credential)
    for text in _shown(caught.value):
        assert CANARY not in text
