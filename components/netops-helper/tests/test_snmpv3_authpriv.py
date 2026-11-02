from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

from netops_core import vault as core_vault
from netops_helper import inventory as helper_inventory
from netops_helper import proxy as MODULE
from netops_helper.auth import (
    AuthenticationContextError,
    AuthenticationMaterialError,
    TargetAuth,
)

from test_check_operator_config import (
    GOOD_INVENTORY,
    GOOD_VAULT,
    _good_paths,
    _write,
    checker,
)
from test_engine_contracts import _context
from test_proxy import (
    _decode_context,
    _paths,
    _rewrite,
    _tool_call,
    _write_test_inventory,
)

ROOT = Path(__file__).parents[1]
AUTH_KEY = "fixture-auth-key-1"
PRIV_KEY = "fixture-priv-key-1"
LEGACY_COMMUNITY = "fixture-legacy-community"
RECORD = "device-a-community"
USER = "usm-reader"
OIDS = {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]}
USM = {
    "user": USER, "auth_protocol": "sha256", "auth_key": AUTH_KEY,
    "priv_protocol": "aes128", "priv_key": PRIV_KEY,
}
V3_RECORD = {
    "kind": "snmpv3-authpriv", "login": USER, "value": AUTH_KEY, "priv_value": PRIV_KEY,
    "auth_protocol": "sha256", "priv_protocol": "aes128",
}
LEGACY_RECORD = {"kind": "snmp-community", "value": LEGACY_COMMUNITY}


def _vault_with(path: Path, record: dict) -> None:
    path.write_text(json.dumps({
        "version": 2,
        "credentials": {
            "runner-account": {"kind": "password", "login": "runner-user", "value": "runner-secret"},
            "device-a-account": {"kind": "password", "login": "selected-user", "value": "selected-secret"},
            RECORD: record,
        },
    }))
    path.chmod(0o600)


def _enroll(tmp_path: Path, monkeypatch, record: dict):
    inventory, vault, _, _ = _paths(tmp_path, monkeypatch)
    _vault_with(vault, record)
    return inventory, vault


def _emitting(proxy, monkeypatch) -> list:
    emitted: list = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    return emitted


# ---- inventory ---------------------------------------------------------

def _entries(tmp_path: Path):
    path = tmp_path / "inventory.json"
    _write_test_inventory(path)
    return helper_inventory.load(path)


def test_inventory_accepts_authpriv_record_for_snmp_credential(tmp_path):
    entries = _entries(tmp_path)
    kinds = {"device-a-account": "password", RECORD: "snmpv3-authpriv"}
    assert helper_inventory.section(entries[0], kinds).snmp_credential == RECORD


def test_inventory_still_loads_a_section_that_points_at_a_legacy_community(tmp_path):
    entries = _entries(tmp_path)
    kinds = {"device-a-account": "password", RECORD: "snmp-community"}
    assert helper_inventory.section(entries[0], kinds).snmp_credential == RECORD


def test_inventory_rejects_a_password_record_as_snmp_credential(tmp_path):
    entries = _entries(tmp_path)
    kinds = {"device-a-account": "password", RECORD: "password"}
    with pytest.raises(helper_inventory.InventoryError):
        helper_inventory.section(entries[0], kinds)


# ---- proxy: positive authPriv path --------------------------------------

def test_snmp_get_envelope_carries_snmp_usm_and_no_community(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, V3_RECORD)
    proxy = MODULE.Proxy()
    transformed = proxy.request(_tool_call(70, "snmp_get", OIDS))
    assert transformed is not None
    context = _decode_context(transformed)
    assert context["snmp_usm"] == USM
    assert "snmp_community" not in context
    assert context["secret"] == "selected-secret"
    assert AUTH_KEY in proxy.response_secrets[70] and PRIV_KEY in proxy.response_secrets[70]


def test_other_tools_get_no_snmp_usm(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, V3_RECORD)
    transformed = MODULE.Proxy().request(_tool_call(71, "tcp_probe", {"target": "device-a", "port": 443}))
    assert transformed is not None
    context = _decode_context(transformed)
    assert "snmp_usm" not in context and "snmp_community" not in context


def test_snmp_get_without_enrolled_credential_is_refused(tmp_path, monkeypatch):
    inventory, _ = _enroll(tmp_path, monkeypatch, V3_RECORD)
    document = json.loads(inventory.read_text())
    del document["devices"][0]["helper"]["snmp_credential"]
    _rewrite(inventory, document)
    proxy = MODULE.Proxy()
    emitted = _emitting(proxy, monkeypatch)
    assert proxy.request(_tool_call(72, "snmp_get", OIDS)) is None
    assert emitted[-1]["error"]["data"]["category"] == "auth_material"


def test_keys_are_redacted_from_a_response_and_absent_from_scope(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, V3_RECORD)
    proxy = MODULE.Proxy()
    assert proxy.request(_tool_call(73, "snmp_get", OIDS)) is not None
    response = {"jsonrpc": "2.0", "id": 73, "result": {"structuredContent": {
        "text": "echo %s and %s" % (AUTH_KEY, PRIV_KEY)}}}
    shown = proxy.response(json.dumps(response).encode()).decode()
    assert AUTH_KEY not in shown and PRIV_KEY not in shown

    fresh = MODULE.Proxy()
    emitted = _emitting(fresh, monkeypatch)
    assert fresh.request(_tool_call(74, "target_scope", {"target": "device-a"})) is None
    scope = emitted[-1]["result"]["structuredContent"]
    assert scope["snmp_enrolled"] is True
    assert scope["snmp_security"] == "authPriv"
    serialized = json.dumps(scope)
    assert AUTH_KEY not in serialized and PRIV_KEY not in serialized and USER not in serialized


def test_target_scope_snmp_security_is_null_without_enrolment(tmp_path, monkeypatch):
    inventory, _ = _enroll(tmp_path, monkeypatch, V3_RECORD)
    document = json.loads(inventory.read_text())
    document["devices"][0]["helper"]["snmp_credential"] = None
    _rewrite(inventory, document)
    proxy = MODULE.Proxy()
    emitted = _emitting(proxy, monkeypatch)
    proxy.request(_tool_call(75, "target_scope", {"target": "device-a"}))
    scope = emitted[-1]["result"]["structuredContent"]
    assert scope["snmp_enrolled"] is False
    assert scope["snmp_security"] is None


# ---- proxy: legacy community --------------------------------------------

def test_snmp_get_with_legacy_community_is_refused_with_v3_guidance(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, LEGACY_RECORD)
    proxy = MODULE.Proxy()
    emitted = _emitting(proxy, monkeypatch)
    assert proxy.request(_tool_call(76, "snmp_get", OIDS)) is None
    shown = json.dumps(emitted[-1]["error"])
    assert "snmpv3-authpriv" in shown
    assert LEGACY_COMMUNITY not in shown


def test_legacy_community_does_not_break_other_tools(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, LEGACY_RECORD)
    transformed = MODULE.Proxy().request(_tool_call(77, "tcp_probe", {"target": "device-a", "port": 443}))
    assert transformed is not None
    context = _decode_context(transformed)
    assert "snmp_community" not in context and "snmp_usm" not in context
    assert LEGACY_COMMUNITY not in json.dumps(context)


def test_legacy_community_target_scope_is_not_authpriv(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch, LEGACY_RECORD)
    proxy = MODULE.Proxy()
    emitted = _emitting(proxy, monkeypatch)
    proxy.request(_tool_call(78, "target_scope", {"target": "device-a"}))
    scope = emitted[-1]["result"]["structuredContent"]
    assert scope["snmp_security"] is None
    assert scope["snmp_enrolled"] is False
    assert LEGACY_COMMUNITY not in json.dumps(scope)


# ---- envelope (TargetAuth.decode) ---------------------------------------

def test_decode_accepts_snmp_usm_and_secrets_hold_both_keys():
    auth = TargetAuth.decode("device-a", _context(snmp_usm=dict(USM)))
    assert AUTH_KEY in auth.secrets and PRIV_KEY in auth.secrets
    assert "ssh-secret" in auth.secrets


def test_decode_rejects_the_old_snmp_community_key():
    with pytest.raises((AuthenticationContextError, AuthenticationMaterialError)):
        TargetAuth.decode("device-a", _context(snmp_community="fixture-legacy-community"))


def _without(*names):
    return {key: value for key, value in USM.items() if key not in names}


@pytest.mark.parametrize("usm", [
    pytest.param(_without("auth_protocol", "auth_key", "priv_protocol", "priv_key"), id="noAuthNoPriv"),
    pytest.param(_without("priv_protocol", "priv_key"), id="authNoPriv"),
    pytest.param(_without("priv_key"), id="priv-key-missing"),
    pytest.param(dict(USM, auth_protocol="md5"), id="md5"),
    pytest.param(dict(USM, auth_protocol="sha1"), id="sha1"),
    pytest.param(dict(USM, priv_protocol="des"), id="des"),
    pytest.param(dict(USM, priv_protocol="3des"), id="3des"),
    pytest.param(dict(USM, priv_protocol="aes256"), id="aes256"),
])
def test_decode_rejects_weaker_or_incomplete_modes_before_any_network(usm):
    with pytest.raises((AuthenticationContextError, AuthenticationMaterialError)) as caught:
        TargetAuth.decode("device-a", _context(snmp_usm=usm))
    assert AUTH_KEY not in str(caught.value) and PRIV_KEY not in str(caught.value)


def test_snmp_usm_is_optional_for_non_snmp_tools():
    auth = TargetAuth.decode("device-a", _context())
    with pytest.raises(AuthenticationMaterialError):
        auth.require_snmp_usm()


# ---- server -------------------------------------------------------------

def test_server_snmp_get_signature_is_unchanged_and_documents_authpriv_only():
    tree = ast.parse((ROOT / "src/netops_helper/server.py").read_text(encoding="utf-8"))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "snmp_get"
    )
    assert [argument.arg for argument in function.args.args] == ["target", "oids", "port", "auth_context"]
    doc = ast.get_docstring(function)
    assert "SNMPv3" in doc and "authPriv" in doc
    assert "v2c" not in doc


# ---- check_operator_config ----------------------------------------------

def _config_with(directory: Path, record: dict):
    paths = _good_paths(directory)
    inventory = copy.deepcopy(GOOD_INVENTORY)
    inventory["devices"][0]["helper"]["snmp_credential"] = RECORD
    vault = copy.deepcopy(GOOD_VAULT)
    vault["credentials"][RECORD] = record
    _write(directory, "inventory.json", inventory, 0o644)
    _write(directory, "vault.json", vault, 0o600)
    return paths


class SnmpV3ConfigurationTests(unittest.TestCase):
    def test_an_authpriv_record_passes_and_no_key_is_printed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = checker.check(_config_with(Path(directory), V3_RECORD))
            self.assertEqual(summary, {"devices": 1, "credentials": 3})
            self.assertNotIn(AUTH_KEY, json.dumps(summary))

    def test_a_legacy_community_record_is_reported_with_the_v3_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _config_with(Path(directory), LEGACY_RECORD)
            with self.assertRaises(checker.PreflightError) as caught:
                checker.check(paths)
            message = str(caught.exception)
            self.assertIn("snmpv3-authpriv", message)
            self.assertIn(RECORD, message)
            self.assertNotIn(LEGACY_COMMUNITY, message)

    def test_a_short_key_is_rejected_without_printing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _config_with(Path(directory), dict(V3_RECORD, priv_value="short-7"))
            with self.assertRaisesRegex(checker.PreflightError, r"^vault\.json: ") as caught:
                checker.check(paths)
            self.assertNotIn("short-7", str(caught.exception))
            self.assertNotIn(AUTH_KEY, str(caught.exception))
