from __future__ import annotations

import dataclasses
import json
import os
import traceback

import pytest

from netops_core import vault

CANARY = "KANARCI-TOKEN-NESMI-UNIKNOUT"
NAME = "fw-a-api"
DUMMY = "replace-me"
LOGIN = "audit-ro"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % CANARY
EXAMPLE = {
    "version": 2,
    "credentials": {
        "fw-a-ro": {"kind": "password", "login": LOGIN, "value": DUMMY},
        "sw-a-ro": {
            "kind": "ssh-key",
            "login": LOGIN,
            "value": "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
        },
        "fw-a-api": {"kind": "api-token", "value": DUMMY},
        "fw-a-snmp": {"kind": "snmp-community", "value": DUMMY},
    },
}


def _entry(kind="api-token", value=CANARY, login=None):
    entry = {"kind": kind, "value": value}
    if login is not None:
        entry["login"] = login
    return entry


def _doc(entry=None, name=NAME, version=2):
    return {"version": version, "credentials": {name: _entry() if entry is None else entry}}


def _write(tmp_path, document, mode=0o600, filename="vault.json"):
    path = tmp_path / filename
    if isinstance(document, bytes):
        path.write_bytes(document)
    elif isinstance(document, str):
        path.write_text(document, encoding="utf-8")
    else:
        path.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _loaded(tmp_path, document=None):
    return vault.load(_write(tmp_path, _doc() if document is None else document))


def _shown(error) -> tuple:
    return (
        str(error),
        repr(error),
        "".join(traceback.format_exception(type(error), error, error.__traceback__)),
    )


def test_file_version_is_two():
    assert vault.FILE_VERSION == 2


def test_kinds_and_login_kinds_agree():
    assert vault.KINDS == ("password", "ssh-key", "api-token", "snmp-community")
    assert vault.LOGIN_KINDS == ("password", "ssh-key")
    for kind in vault.LOGIN_KINDS:
        assert kind in vault.KINDS


def test_load_returns_vault_with_credential(tmp_path):
    loaded = _loaded(tmp_path)
    assert isinstance(loaded, vault.Vault)
    credential = loaded.credential(NAME)
    assert isinstance(credential, vault.Credential)
    assert credential.name == NAME
    assert credential.kind == "api-token"
    assert credential.login is None


def test_use_is_the_way_to_the_value(tmp_path):
    assert _loaded(tmp_path).credential(NAME).use() == CANARY


def test_example_document_from_the_specification_loads(tmp_path):
    loaded = vault.load(_write(tmp_path, EXAMPLE))
    assert loaded.names() == ("fw-a-api", "fw-a-ro", "fw-a-snmp", "sw-a-ro")
    assert loaded.credential("fw-a-ro").login == LOGIN
    assert loaded.credential("sw-a-ro").kind == "ssh-key"
    assert loaded.credential("sw-a-ro").use().startswith("-----BEGIN ")
    assert loaded.credential("fw-a-api").login is None
    assert loaded.credential("fw-a-snmp").login is None


def test_names_are_sorted(tmp_path):
    document = {
        "version": 2,
        "credentials": {
            "zeta": _entry(value=DUMMY),
            "alfa": _entry(value=DUMMY),
            "mezi": _entry(value=DUMMY),
        },
    }
    assert vault.load(_write(tmp_path, document)).names() == ("alfa", "mezi", "zeta")


def test_names_of_empty_vault(tmp_path):
    loaded = vault.load(_write(tmp_path, {"version": 2, "credentials": {}}))
    assert loaded.names() == ()


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_strict_mode_is_accepted(tmp_path, mode):
    assert vault.load(_write(tmp_path, _doc(), mode=mode)).names() == (NAME,)


@pytest.mark.parametrize(
    "mode", [0o644, 0o640, 0o604, 0o660, 0o606, 0o666, 0o700, 0o755, 0o777, 0o602]
)
def test_loose_mode_is_refused(tmp_path, mode):
    path = _write(tmp_path, _doc(), mode=mode)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "mode" in message
    assert str(path) in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_symlink_is_refused_even_when_the_target_is_strict(tmp_path):
    target = _write(tmp_path, _doc(), mode=0o600, filename="target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(link)
    message = str(caught.value)
    assert "symbolic link" in message
    assert str(link) in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_symlink_is_refused_before_the_mode_is_judged(tmp_path):
    target = _write(tmp_path, _doc(), mode=0o644, filename="target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(link)
    message = str(caught.value)
    assert "symbolic link" in message
    assert "mode 0644" not in message


def test_broken_symlink_is_refused_as_a_link(tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(tmp_path / "chybi.json")
    with pytest.raises(vault.VaultError) as caught:
        vault.load(link)
    assert str(link) in str(caught.value)
    assert "symbolic link" in str(caught.value)


def test_directory_is_not_a_vault(tmp_path):
    with pytest.raises(vault.VaultError) as caught:
        vault.load(tmp_path)
    assert "regular file" in str(caught.value)


def test_missing_file_names_the_path(tmp_path):
    path = tmp_path / "chybi.json"
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert str(path) in str(caught.value)
    assert "does not exist" in str(caught.value)


@pytest.mark.parametrize("kind", ["password", "ssh-key"])
def test_login_is_required_for_a_login_kind(tmp_path, kind):
    value = KEY if kind == "ssh-key" else CANARY
    path = _write(tmp_path, _doc(_entry(kind=kind, value=value)))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "login is required for kind %s" % kind in message
    assert NAME in message
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("kind", ["api-token", "snmp-community"])
def test_login_is_forbidden_for_a_kind_that_does_not_log_in(tmp_path, kind):
    path = _write(tmp_path, _doc(_entry(kind=kind, login=LOGIN)))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "login must be null for kind %s" % kind in message
    assert NAME in message
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize(
    "login",
    ["-rf", "audit-ro@example.invalid", "root:x", "a/b", "audit ro", "audit\tro", "audit\nro"],
)
def test_login_must_be_a_plain_user_name(tmp_path, login):
    path = _write(tmp_path, _doc(_entry(kind="password", login=login)))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "login must be a plain user name" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("login", ["", "   ", 1, True, [], {}])
def test_login_must_be_a_non_empty_string(tmp_path, login):
    path = _write(tmp_path, _doc(_entry(kind="password", login=login)))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "login" in message
    assert CANARY not in message


def test_login_is_stripped(tmp_path):
    loaded = vault.load(_write(tmp_path, _doc(_entry(kind="password", login="  %s  " % LOGIN))))
    assert loaded.credential(NAME).login == LOGIN


def test_ssh_key_value_must_be_private_key_text(tmp_path):
    path = _write(tmp_path, _doc(_entry(kind="ssh-key", login=LOGIN, value=CANARY)))
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "must hold the private key text" in message
    assert "-----BEGIN " in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_ssh_key_value_that_begins_the_right_way_loads(tmp_path):
    loaded = vault.load(_write(tmp_path, _doc(_entry(kind="ssh-key", login=LOGIN, value=KEY))))
    assert loaded.credential(NAME).use() == KEY


@pytest.mark.parametrize("kind", ["password", "api-token", "snmp-community"])
def test_only_ssh_key_demands_the_private_key_header(tmp_path, kind):
    login = LOGIN if kind in vault.LOGIN_KINDS else None
    loaded = vault.load(_write(tmp_path, _doc(_entry(kind=kind, login=login))))
    assert loaded.credential(NAME).use() == CANARY


def test_repr_and_str_hide_the_value(tmp_path):
    loaded = _loaded(tmp_path, _doc(_entry(kind="password", login=LOGIN)))
    credential = loaded.credential(NAME)
    holder = credential.__dict__["_secret"]
    rendered = (
        repr(credential),
        str(credential),
        format(credential),
        "%s" % (credential,),
        f"{credential}",
        repr(loaded),
        str(loaded),
        repr([credential]),
        repr({NAME: credential}),
        repr(credential.__dict__),
        repr(vars(credential)),
        repr(loaded.__dict__),
        repr(holder),
        str(holder),
        repr(dataclasses.asdict(credential)),
        json.dumps(dataclasses.asdict(credential)),
    )
    for text in rendered:
        assert CANARY not in text
    assert NAME in repr(credential)
    assert "password" in repr(credential)
    assert LOGIN in repr(credential)
    assert NAME in repr(loaded)
    assert vault.HIDDEN in repr(credential.__dict__)


def test_value_is_not_a_dataclass_field():
    assert tuple(item.name for item in dataclasses.fields(vault.Credential)) == (
        "name",
        "kind",
        "login",
    )


def test_no_public_attribute_holds_the_value(tmp_path):
    credential = _loaded(tmp_path).credential(NAME)
    for attribute in dir(credential):
        if attribute.startswith("_"):
            continue
        assert getattr(credential, attribute) != CANARY


def test_asdict_does_not_carry_the_value(tmp_path):
    credential = _loaded(tmp_path).credential(NAME)
    assert dataclasses.asdict(credential) == {"name": NAME, "kind": "api-token", "login": None}


def test_credential_is_immutable(tmp_path):
    credential = _loaded(tmp_path).credential(NAME)
    with pytest.raises(AttributeError):
        credential.kind = "password"


def _broken():
    return {
        "version-one": _doc(version=1),
        "bad-version": _doc(version=3),
        "version-as-text": _doc(version="2"),
        "version-as-bool": _doc(version=True),
        "unknown-document-field": dict(_doc(), extra=True),
        "missing-credentials": {"version": 2},
        "missing-version": {"credentials": {}},
        "document-not-object": [_doc()],
        "credentials-not-object": {"version": 2, "credentials": [_entry()]},
        "entry-not-object": {"version": 2, "credentials": {NAME: CANARY}},
        "entry-unknown-field": {
            "version": 2,
            "credentials": {NAME: dict(_entry(), token=CANARY)},
        },
        "entry-missing-kind": {"version": 2, "credentials": {NAME: {"value": CANARY}}},
        "entry-missing-value": {"version": 2, "credentials": {NAME: {"kind": "api-token"}}},
        "unknown-kind": _doc(_entry(kind="ssh-password")),
        "kind-holds-the-value": _doc(_entry(kind=CANARY)),
        "empty-name": _doc(name=""),
        "blank-name": _doc(name="   "),
        "empty-value": _doc(_entry(value="")),
        "blank-value": _doc(_entry(value="   ")),
        "value-as-int": _doc(_entry(value=12345)),
        "value-as-bool": _doc(_entry(value=True)),
        "value-as-null": _doc(_entry(value=None)),
        "value-as-list": _doc(_entry(value=[CANARY])),
        "value-as-object": _doc(_entry(value={"token": CANARY})),
        "login-on-api-token": _doc(_entry(login=LOGIN)),
        "password-without-login": _doc(_entry(kind="password")),
        "ssh-key-without-header": _doc(_entry(kind="ssh-key", login=LOGIN)),
    }


@pytest.mark.parametrize("case", sorted(_broken()))
def test_document_error_paths_hide_the_value(tmp_path, case):
    path = _write(tmp_path, _broken()[case])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize(
    "case, fragment",
    [
        ("version-one", "version must be 2"),
        ("bad-version", "version must be 2"),
        ("version-as-text", "version must be 2"),
        ("version-as-bool", "version must be 2"),
        ("unknown-document-field", "unknown document fields: extra"),
        ("missing-credentials", "missing document fields: credentials"),
        ("document-not-object", "must hold an object, got list"),
        ("credentials-not-object", "credentials must be an object, got list"),
        ("entry-not-object", "must be an object, got str"),
        ("entry-unknown-field", "unknown fields: token"),
        ("entry-missing-kind", "missing fields: kind"),
        ("entry-missing-value", "missing fields: value"),
        ("unknown-kind", "kind must be one of: password, ssh-key, api-token, snmp-community"),
        ("kind-holds-the-value", "kind must be one of: password"),
        ("empty-value", "value must be a non-empty string, got str"),
        ("value-as-int", "value must be a non-empty string, got int"),
        ("value-as-null", "value must be a non-empty string, got NoneType"),
        ("empty-name", "credential names must be non-empty strings"),
        ("login-on-api-token", "login must be null for kind api-token"),
        ("password-without-login", "login is required for kind password"),
        ("ssh-key-without-header", "must hold the private key text"),
    ],
)
def test_document_error_messages_are_explicit(tmp_path, case, fragment):
    path = _write(tmp_path, _broken()[case])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert fragment in str(caught.value)
    assert str(path) in str(caught.value)


def test_version_one_document_is_refused_by_name(tmp_path):
    document = {"version": 1, "credentials": {NAME: {"kind": "api-token", "value": DUMMY}}}
    path = _write(tmp_path, document)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "version must be 2" in str(caught.value)


def test_invalid_json_hides_the_value(tmp_path):
    path = _write(tmp_path, json.dumps(_doc())[:-2])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "not valid JSON" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_not_utf8_hides_the_value(tmp_path):
    path = _write(tmp_path, json.dumps(_doc()).encode("utf-8") + b"\xff")
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "not valid UTF-8" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_unknown_credential_lists_known_names(tmp_path):
    loaded = _loaded(tmp_path)
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential("neznamy")
    message = str(caught.value)
    assert "unknown credential" in message
    assert "neznamy" in message
    assert NAME in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_unknown_credential_in_empty_vault(tmp_path):
    loaded = vault.load(_write(tmp_path, {"version": 2, "credentials": {}}))
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential("neznamy")
    assert "known names: none" in str(caught.value)


@pytest.mark.parametrize("name", [None, 1, b"fw-a-api", ["fw-a-api"]])
def test_credential_name_must_be_string(tmp_path, name):
    loaded = _loaded(tmp_path)
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential(name)
    assert "must be a string" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("bad", ["", "   ", 1, None, True, [], {}])
def test_credential_rejects_bad_value(bad):
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="api-token", value=bad)
    assert "value must be a non-empty string" in str(caught.value)


def test_credential_rejects_unknown_kind():
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="ssh-password", value=DUMMY)
    assert "kind must be one of: password, ssh-key, api-token, snmp-community" in str(caught.value)


@pytest.mark.parametrize("bad", ["", "   ", None, 7])
def test_credential_rejects_bad_name(bad):
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=bad, kind="api-token", value=DUMMY)
    assert "credential name must be a non-empty string" in str(caught.value)


def test_credential_error_hides_the_value():
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="ssh-password", value=CANARY)
    for text in _shown(caught.value):
        assert CANARY not in text
