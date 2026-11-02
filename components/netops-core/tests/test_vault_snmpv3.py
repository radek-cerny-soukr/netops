from __future__ import annotations

import json
import os
import traceback

import pytest

from netops_core import vault

AUTH_KEY = "fixture-auth-key-1"
PRIV_KEY = "fixture-priv-key-1"
NAME = "fw-a-snmpv3"
USER = "usm-reader"


def _record(**overrides):
    record = {
        "kind": "snmpv3-authpriv",
        "login": USER,
        "value": AUTH_KEY,
        "priv_value": PRIV_KEY,
        "auth_protocol": "sha256",
        "priv_protocol": "aes128",
    }
    for key, value in overrides.items():
        if value is None and key in ("login", "priv_value", "value"):
            record.pop(key, None)
        else:
            record[key] = value
    return record


def _write(tmp_path, credentials):
    path = tmp_path / "vault.json"
    path.write_text(json.dumps({"version": 2, "credentials": credentials}), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _load(tmp_path, record=None, **extra):
    credentials = {NAME: _record() if record is None else record}
    credentials.update(extra)
    return vault.load(_write(tmp_path, credentials))


def _shown(error) -> str:
    return "\n".join((
        str(error), repr(error),
        "".join(traceback.format_exception(type(error), error, error.__traceback__)),
    ))


def test_kind_is_known_and_file_version_is_unchanged():
    assert vault.FILE_VERSION == 2
    assert "snmpv3-authpriv" in vault.KINDS
    assert vault.LOGIN_KINDS == ("password", "ssh-key")


def test_authpriv_record_loads_with_user_and_both_keys(tmp_path):
    credential = _load(tmp_path).credential(NAME)
    assert credential.kind == "snmpv3-authpriv"
    assert credential.login == USER
    assert credential.use() == AUTH_KEY
    assert credential.use_priv() == PRIV_KEY


def test_keys_never_appear_in_repr_or_str(tmp_path):
    credential = _load(tmp_path).credential(NAME)
    text = repr(credential) + str(credential) + repr(vault.load(tmp_path / "vault.json"))
    assert AUTH_KEY not in text
    assert PRIV_KEY not in text


def test_equal_auth_and_priv_keys_are_accepted(tmp_path):
    credential = _load(tmp_path, _record(priv_value=AUTH_KEY)).credential(NAME)
    assert credential.use() == credential.use_priv() == AUTH_KEY


@pytest.mark.parametrize("login", ["u", "u" * 32, "ž" * 16, "monitor@example.net"])
def test_user_of_one_to_32_utf8_bytes_is_accepted(tmp_path, login):
    assert _load(tmp_path, _record(login=login)).credential(NAME).login == login


@pytest.mark.parametrize("login", ["u" * 33, "ž" * 17, ""])
def test_user_outside_1_to_32_utf8_bytes_is_rejected(tmp_path, login):
    with pytest.raises(vault.VaultError):
        _load(tmp_path, _record(login=login))


def test_user_is_required(tmp_path):
    with pytest.raises(vault.VaultError):
        _load(tmp_path, _record(login=None))


@pytest.mark.parametrize("key", ["x" * 8, "žžžž"])
def test_keys_of_at_least_8_utf8_bytes_are_accepted(tmp_path, key):
    credential = _load(tmp_path, _record(value=key, priv_value=key)).credential(NAME)
    assert credential.use() == key


@pytest.mark.parametrize("field", ["value", "priv_value"])
@pytest.mark.parametrize("key", ["short-7", "žžž"])
def test_keys_shorter_than_8_utf8_bytes_are_rejected_without_the_value(tmp_path, field, key):
    with pytest.raises(vault.VaultError) as caught:
        _load(tmp_path, _record(**{field: key}))
    shown = _shown(caught.value)
    assert key not in shown
    assert AUTH_KEY not in shown and PRIV_KEY not in shown


def test_missing_priv_key_is_rejected_without_the_auth_key(tmp_path):
    with pytest.raises(vault.VaultError) as caught:
        _load(tmp_path, _record(priv_value=None))
    assert AUTH_KEY not in _shown(caught.value)


@pytest.mark.parametrize("field,value", [
    ("auth_protocol", "md5"), ("auth_protocol", "sha1"),
    ("priv_protocol", "des"), ("priv_protocol", "3des"), ("priv_protocol", "aes256"),
])
def test_other_protocols_are_rejected(tmp_path, field, value):
    with pytest.raises(vault.VaultError):
        _load(tmp_path, _record(**{field: value}))


def test_priv_value_is_not_allowed_on_other_kinds(tmp_path):
    record = {"kind": "api-token", "value": "fixture-token-12345", "priv_value": PRIV_KEY}
    with pytest.raises(vault.VaultError):
        _load(tmp_path, record)


def test_ssh_records_are_unchanged_next_to_an_authpriv_record(tmp_path):
    loaded = _load(
        tmp_path,
        **{"fw-a-ro": {"kind": "password", "login": "audit-ro", "value": "fixture-pass-1"}},
    )
    assert loaded.credential("fw-a-ro").login == "audit-ro"
    assert loaded.credential("fw-a-ro").use() == "fixture-pass-1"
    assert loaded.names() == ("fw-a-ro", NAME)


def test_legacy_community_record_still_loads_and_does_not_break_ssh_records(tmp_path):
    loaded = _load(
        tmp_path,
        **{
            "fw-a-community": {"kind": "snmp-community", "value": "fixture-community"},
            "fw-a-ro": {"kind": "password", "login": "audit-ro", "value": "fixture-pass-1"},
        },
    )
    assert loaded.credential("fw-a-community").kind == "snmp-community"
    assert loaded.credential("fw-a-ro").use() == "fixture-pass-1"
