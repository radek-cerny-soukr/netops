from __future__ import annotations

from base64 import b64encode, urlsafe_b64decode
import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "remote_mcp_proxy.py"
SPEC = importlib.util.spec_from_file_location("remote_mcp_proxy", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_schema_hides_internal_auth_field() -> None:
    proxy = MODULE.Proxy(); proxy.pending[7] = "tools/list"
    response = {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{
        "name": "tcp_probe",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "auth_context": {"type": "string"}},
            "required": ["target", "auth_context"],
        },
    }]}}
    schema = json.loads(proxy.response(json.dumps(response).encode()))["result"]["tools"][0]["inputSchema"]
    assert "auth_context" not in schema["properties"]
    assert "auth_context" not in schema["required"]


def _write_test_vault(path: Path) -> None:
    path.write_text(json.dumps({
        "other": {
            "host": "unrelated-host", "port": 22,
            "login": "unrelated-user", "password": "unrelated-secret",
        },
        "device-a": {
            "host": "selected-host", "port": 22,
            "login": "selected-user", "password": "selected-secret",
            "snmp_community": "separate-community",
        },
    }, indent=2) + "\n")
    path.chmod(0o600)


def _policy(path: Path) -> None:
    path.write_text(json.dumps({"device-a": {
        "account_role": "read-only",
        "ssh_platform": "fortios",
        "enabled_queries": ["system_status", "interface_details"],
        "egress": {
            "addresses": ["192.0.2.10"],
            "tcp_ports": [21, 22, 443],
            "udp_ports": [161],
            "tcp_port_ranges": [],
            "udp_port_ranges": [],
            "allow_icmp": True,
            "allow_dns": True,
            "tls_server_names": [],
        },
        "read_inventory": {"interfaces": ["eth0"], "services": [], "addresses": []},
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": True,
        "rate_limit": {"requests": 2, "window_seconds": 60},
    }}))


def test_load_record_accepts_pretty_printed_json(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    _write_test_vault(vault)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    assert MODULE.Proxy()._load_record("device-a")["login"] == "selected-user"
    with pytest.raises(ValueError):
        MODULE.Proxy()._load_record("missing")


def test_load_record_rejects_loose_permissions(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    _write_test_vault(vault)
    vault.chmod(0o644)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    with pytest.raises(ValueError):
        MODULE.Proxy()._load_record("device-a")


def test_request_injects_read_only_scope_and_target_host_key(tmp_path: Path, monkeypatch) -> None:
    vault=tmp_path/"vault.json"; known=tmp_path/"known_hosts"; policy=tmp_path/"target-policy.json"
    _write_test_vault(vault); known.write_text("selected-host ssh-ed25519 QUJD\nother-host ssh-ed25519 REVG\n"); _policy(policy)
    monkeypatch.setattr(MODULE,"VAULT",vault); monkeypatch.setattr(MODULE,"KNOWN_HOSTS",known); monkeypatch.setattr(MODULE,"TARGET_POLICY",policy)
    proxy=MODULE.Proxy()
    transformed=proxy.request(json.dumps({
        "jsonrpc":"2.0","id":21,"method":"tools/call",
        "params":{"name":"ssh_read","arguments":{"target":"device-a","platform":"fortios","query":"system_status"}},
    }).encode())
    assert transformed is not None
    assert proxy.response_secrets[21][:2] == ("selected-secret", "separate-community")
    assert proxy.response_secrets[21][2] == json.loads(transformed)["params"]["arguments"]["auth_context"]
    encoded=json.loads(transformed)["params"]["arguments"]["auth_context"]
    scope=json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert scope["account_role"] == "read-only"
    assert scope["read_inventory"]["interfaces"] == ["eth0"]
    assert scope["sftp_roots"] == ["/safe"]
    assert "https_endpoints" not in scope
    assert scope["fortios_output_standard_verified"] is True
    assert scope["known_hosts"] == "selected-host ssh-ed25519 QUJD\n"
    assert "snmp_community" not in scope
    assert "rate_limit" not in scope


def test_missing_read_only_enrollment_fails_closed(tmp_path: Path, monkeypatch) -> None:
    policy=tmp_path/"target-policy.json"; policy.write_text("{}")
    monkeypatch.setattr(MODULE,"TARGET_POLICY",policy)
    with pytest.raises(ValueError): MODULE.Proxy()._load_target_policy("device-a")


def test_response_preserves_identifiers_redacts_secret_and_marks_untrusted() -> None:
    proxy=MODULE.Proxy(); proxy.pending[22]="tools/call"; proxy.response_secrets[22]=("credential-value",)
    raw=json.dumps({
        "jsonrpc":"2.0","id":22,
        "result":{"content":[{"type":"text","text":"Sep 9 10:23:45 host ip=192.0.2.10 mac=aa:bb:cc:dd:ee:ff credential-value"}]},
    }).encode()
    transformed=json.loads(proxy.response(raw)); output=transformed["result"]["content"][0]["text"]
    assert output.startswith("UNTRUSTED DEVICE DATA")
    for visible in ("10:23:45", "host", "192.0.2.10", "aa:bb:cc:dd:ee:ff"): assert visible in output
    assert "credential-value" not in output
    assert transformed["result"]["_meta"]["netops/device-output-trust"] == "untrusted"


def test_tools_list_error_response_does_not_crash() -> None:
    proxy = MODULE.Proxy(); proxy.pending[23] = "tools/list"
    response = {"jsonrpc": "2.0", "id": 23, "error": {"code": -32603, "message": "failed"}}
    assert json.loads(proxy.response(json.dumps(response).encode())) == response
    assert 23 not in proxy.pending


def test_server_request_id_collision_does_not_consume_pending_response() -> None:
    proxy = MODULE.Proxy(); proxy.pending[1] = "tools/call"
    proxy.response_secrets[1] = ("credential-value",)
    server_request = {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}}
    assert json.loads(proxy.response(json.dumps(server_request).encode())) == server_request
    assert proxy.pending[1] == "tools/call"
    actual = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "credential-value"}]}}
    transformed = json.loads(proxy.response(json.dumps(actual).encode()))
    assert "credential-value" not in transformed["result"]["content"][0]["text"]
    assert 1 not in proxy.pending


def test_batch_is_rejected_without_crashing(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(b"[]") is None
    assert emitted[0]["error"]["code"] == -32600


def test_master_alias_is_never_addressable(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    monkeypatch.setattr(proxy, "_load_record", lambda alias: (_ for _ in ()).throw(AssertionError()))
    request = {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {
        "name": "tcp_probe", "arguments": {"target": MODULE.MASTER_ALIAS, "port": 22},
    }}
    assert proxy.request(json.dumps(request).encode()) is None
    assert emitted[0]["error"]["code"] == -32602


def test_per_target_rate_limit_fails_closed(monkeypatch) -> None:
    proxy = MODULE.Proxy()
    ticks = iter((100.0, 101.0, 102.0, 200.0))
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: next(ticks))
    policy = {"requests": 2, "window_seconds": 60}
    proxy._consume_rate_limit("device-a", policy)
    proxy._consume_rate_limit("device-a", policy)
    with pytest.raises(ValueError, match="rate limit"):
        proxy._consume_rate_limit("device-a", policy)
    proxy._consume_rate_limit("device-a", policy)


def test_malformed_tool_params_and_request_id_are_rejected(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    malformed = {"jsonrpc": "2.0", "id": 40, "method": "tools/call", "params": []}
    assert proxy.request(json.dumps(malformed).encode()) is None
    assert emitted[-1]["error"]["code"] == -32602
    bad_id = {"jsonrpc": "2.0", "id": [], "method": "tools/list"}
    assert proxy.request(json.dumps(bad_id).encode()) is None
    assert emitted[-1]["error"]["code"] == -32600


def test_duplicate_pending_request_id_is_rejected(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []; proxy.pending[41] = "tools/list"
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    duplicate = {"jsonrpc": "2.0", "id": 41, "method": "tools/list"}
    assert proxy.request(json.dumps(duplicate).encode()) is None
    assert emitted[-1]["error"]["code"] == -32600
    assert proxy.pending[41] == "tools/list"


def test_batched_server_responses_are_sanitized() -> None:
    proxy = MODULE.Proxy(); proxy.pending[50] = "tools/call"; proxy.pending[51] = "tools/list"
    proxy.response_secrets[50] = ("credential-value",)
    batch = [
        {"jsonrpc": "2.0", "id": 50, "result": {
            "structuredContent": {"snmp_community": "private-value"},
            "content": [{"type": "text", "text": "credential-value"}],
        }},
        {"jsonrpc": "2.0", "id": 51, "error": {"code": -32603, "message": "failed"}},
    ]
    transformed = json.loads(proxy.response(json.dumps(batch).encode()))
    assert transformed[0]["result"]["structuredContent"]["snmp_community"] == "<REDACTED>"
    assert "credential-value" not in transformed[0]["result"]["content"][0]["text"]
    assert transformed[1] == batch[1]
    assert not proxy.pending


def test_every_server_message_is_sanitized_with_session_secrets() -> None:
    proxy = MODULE.Proxy(); proxy.pending[60] = "tools/call"
    proxy.response_secrets[60] = ("credential-value",)
    proxy.session_secrets.update(dict.fromkeys(("credential-value",)))
    for message in (
        {"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "credential-value"}},
        {"jsonrpc": "2.0", "id": 61, "method": "sampling/createMessage", "params": {"text": "credential-value"}},
        {"jsonrpc": "2.0", "id": 62, "result": {"content": [{"type": "text", "text": "credential-value"}]}},
    ):
        transformed = proxy.response(json.dumps(message).encode()).decode()
        assert "credential-value" not in transformed
        assert "<REDACTED>" in transformed
    assert proxy.pending == {60: "tools/call"}


def test_auth_context_envelope_is_redacted_from_server_messages() -> None:
    envelope = MODULE.urlsafe_b64encode(b'{"password":"credential-value"}').decode().rstrip("=")
    proxy = MODULE.Proxy(); proxy.pending[70] = "tools/call"
    proxy.response_secrets[70] = ("credential-value", envelope)
    proxy.session_secrets.update(dict.fromkeys(("credential-value", envelope)))
    echoed = {"jsonrpc": "2.0", "id": 70, "error": {"code": -32602, "message": "bad", "data": {
        "input": {"auth_context": "anything", "target": "edge-a"}, "text": "echo=" + envelope,
    }}}
    transformed = proxy.response(json.dumps(echoed).encode()).decode()
    assert envelope not in transformed
    assert '"auth_context":"<REDACTED>"' in transformed
    notification = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": envelope}}
    assert envelope not in proxy.response(json.dumps(notification).encode()).decode()


def test_malformed_or_oversized_requests_do_not_crash_the_proxy(capsys) -> None:
    proxy = MODULE.Proxy()
    for raw in (b"[" * 100_000 + b"]" * 100_000 + b"\n", b"\xff\xfe\n", b"x" * (MODULE.MAX_REQUEST_BYTES + 1)):
        assert proxy.request(raw) is None
        assert json.loads(capsys.readouterr().out)["error"]["code"] == -32700
    assert proxy.request(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n') is not None


def test_configured_paths_expand_home_and_symlinked_vault_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NETOPS_VAULT_PATH", "~/vault.json")
    assert MODULE._configured_path("NETOPS_VAULT_PATH", tmp_path / "x") == tmp_path / "vault.json"
    real = tmp_path / "real-vault.json"
    real.write_text("{}", encoding="utf-8"); real.chmod(0o600)
    link = tmp_path / "vault-link.json"
    link.symlink_to(real)
    monkeypatch.setattr(MODULE, "VAULT", link)
    with pytest.raises(MODULE.VaultPermissionError):
        MODULE.Proxy()._load_vault_document()
    monkeypatch.setattr(MODULE, "VAULT", real)
    assert MODULE.Proxy()._load_vault_document() == {}


def _paths(tmp_path: Path, monkeypatch):
    vault = tmp_path / "vault.json"
    known = tmp_path / "known_hosts"
    policy = tmp_path / "target-policy.json"
    _write_test_vault(vault)
    known.write_text("selected-host ssh-ed25519 QUJD\n")
    _policy(policy)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    monkeypatch.setattr(MODULE, "KNOWN_HOSTS", known)
    monkeypatch.setattr(MODULE, "TARGET_POLICY", policy)
    return vault, known, policy


def _tool_call(request_id, name: str, arguments: dict):
    message = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    if request_id is not ...:
        message["id"] = request_id
    return json.dumps(message).encode()


def _decode_context(transformed: bytes) -> dict:
    encoded = json.loads(transformed)["params"]["arguments"]["auth_context"]
    return json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def test_proxy_error_taxonomy_has_distinct_safe_categories() -> None:
    expected = {
        MODULE.UnknownAliasError: "unknown_alias",
        MODULE.PolicyRejectedError: "policy_rejected",
        MODULE.RoleRejectedError: "role_rejected",
        MODULE.VaultPermissionError: "vault_permission",
        MODULE.VaultSchemaError: "vault_schema",
        MODULE.AuthenticationMaterialError: "auth_material",
        MODULE.RateLimitError: "rate_limit",
        MODULE.PolicySchemaError: "policy_schema",
        MODULE.PolicyScopeError: "policy_scope",
    }
    assert {error.category for error in expected} == set(expected.values())
    assert len({error.code for error in expected}) == len(expected)


def test_request_reports_unknown_alias_and_rate_limit_separately(tmp_path: Path, monkeypatch) -> None:
    _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(60, "tcp_probe", {"target": "missing", "port": 22})) is None
    assert emitted[-1]["error"]["data"]["category"] == "unknown_alias"

    assert proxy.request(_tool_call(61, "tcp_probe", {"target": "device-a", "port": 22}))
    assert proxy.request(_tool_call(62, "tcp_probe", {"target": "device-a", "port": 22}))
    assert proxy.request(_tool_call(63, "tcp_probe", {"target": "device-a", "port": 22})) is None
    error = emitted[-1]["error"]
    assert error["data"]["category"] == "rate_limit"
    assert error["data"]["retry_after_seconds"] > 0
    assert "credential" not in error["message"].lower()


def test_policy_schema_and_role_fail_with_distinct_types(tmp_path: Path, monkeypatch) -> None:
    _, _, policy = _paths(tmp_path, monkeypatch)
    data = json.loads(policy.read_text())
    del data["device-a"]["ssh_platform"]
    policy.write_text(json.dumps(data))
    with pytest.raises(MODULE.PolicySchemaError):
        MODULE.Proxy()._load_target_policy("device-a")

    data["device-a"]["ssh_platform"] = "fortios"
    data["device-a"]["account_role"] = "administrator"
    policy.write_text(json.dumps(data))
    with pytest.raises(MODULE.RoleRejectedError):
        MODULE.Proxy()._load_target_policy("device-a")


def test_vault_schema_permissions_and_auth_material_are_distinct(
    tmp_path: Path, monkeypatch,
) -> None:
    vault, _, _ = _paths(tmp_path, monkeypatch)
    vault.chmod(0o644)
    with pytest.raises(MODULE.VaultPermissionError):
        MODULE.Proxy()._load_record("device-a")
    vault.chmod(0o600)
    vault.write_text("[]")
    with pytest.raises(MODULE.VaultSchemaError):
        MODULE.Proxy()._load_record("device-a")
    vault.write_text(json.dumps({"device-a": {
        "host": "host", "port": 22, "login": "user", "password": "abc",
        "snmp_community": "abc",
    }}))
    with pytest.raises(MODULE.AuthenticationMaterialError):
        MODULE.Proxy()._load_record("device-a")


def test_snmp_community_is_separate_injected_secret_without_fallback(
    tmp_path: Path, monkeypatch,
) -> None:
    vault, _, _ = _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    transformed = proxy.request(_tool_call(
        70, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]},
    ))
    assert transformed is not None
    context = _decode_context(transformed)
    assert context["snmp_community"] == "separate-community"
    assert context["password"] == "selected-secret"
    assert proxy.response_secrets[70][:2] == ("selected-secret", "separate-community")
    assert proxy.response_secrets[70][2] == json.loads(transformed)["params"]["arguments"]["auth_context"]

    data = json.loads(vault.read_text())
    del data["device-a"]["snmp_community"]
    vault.write_text(json.dumps(data))
    emitted = []
    proxy = MODULE.Proxy()
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(
        71, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]},
    )) is None
    assert emitted[-1]["error"]["data"]["category"] == "auth_material"


def _hashed_host(value: str) -> str:
    salt = b"0123456789abcdefghij"
    digest = hmac.new(salt, value.encode(), hashlib.sha1).digest()
    return "|1|" + b64encode(salt).decode() + "|" + b64encode(digest).decode()


def test_known_hosts_filters_plaintext_markers_and_comma_hostlists(
    tmp_path: Path, monkeypatch,
) -> None:
    _, known, _ = _paths(tmp_path, monkeypatch)
    known.write_text(
        "other-host,selected-host ssh-ed25519 QUJD comment-leak\n"
        "@cert-authority selected-host,third-host ssh-ed25519 REVG other-comment\n"
    )
    selected = MODULE.Proxy()._select_known_hosts({
        "host": "selected-host", "port": 22,
    })
    assert selected == (
        "selected-host ssh-ed25519 QUJD\n"
        "@cert-authority selected-host ssh-ed25519 REVG\n"
    )
    for hidden in ("other-host", "third-host", "comment-leak", "other-comment"):
        assert hidden not in selected


@pytest.mark.parametrize(
    ("host", "port", "known_name"),
    [
        ("device.example", 2222, "[device.example]:2222"),
        ("2001:db8::10", 22, "2001:db8::10"),
        ("2001:db8::10", 2222, "[2001:db8::10]:2222"),
    ],
)
def test_known_hosts_supports_custom_ports_and_ipv6(
    host: str, port: int, known_name: str, tmp_path: Path, monkeypatch,
) -> None:
    known = tmp_path / "known_hosts"
    known.write_text(f"{known_name} ssh-ed25519 QUJD\n")
    monkeypatch.setattr(MODULE, "KNOWN_HOSTS", known)
    selected = MODULE.Proxy()._select_known_hosts({"host": host, "port": port})
    assert selected == f"{known_name} ssh-ed25519 QUJD\n"


def test_known_hosts_supports_hashed_names_and_fails_closed(
    tmp_path: Path, monkeypatch,
) -> None:
    known = tmp_path / "known_hosts"
    token = _hashed_host("[device.example]:2222")
    known.write_text(f"{token} ssh-ed25519 QUJD\n")
    monkeypatch.setattr(MODULE, "KNOWN_HOSTS", known)
    assert MODULE.Proxy()._select_known_hosts({
        "host": "device.example", "port": 2222,
    }).startswith(token)
    with pytest.raises(MODULE.AuthenticationMaterialError):
        MODULE.Proxy()._select_known_hosts({"host": "other.example", "port": 2222})


def test_helper_status_lists_only_valid_non_master_aliases_with_rate_state(
    tmp_path: Path, monkeypatch,
) -> None:
    vault, _, policy = _paths(tmp_path, monkeypatch)
    vault_data = json.loads(vault.read_text())
    vault_data[MODULE.MASTER_ALIAS] = {
        "host": "runner", "port": 22, "login": "runner", "password": "runner-secret",
    }
    vault.write_text(json.dumps(vault_data))
    policy_data = json.loads(policy.read_text())
    policy_data["invalid-only-policy"] = dict(policy_data["device-a"])
    policy.write_text(json.dumps(policy_data))
    proxy = MODULE.Proxy()
    forwarded = proxy.request(_tool_call(80, "helper_status", {}))
    assert forwarded is not None
    remote = {
        "jsonrpc": "2.0", "id": 80,
        "result": {"content": [{"type": "text", "text": '{"ok":true}'}]},
    }
    result = json.loads(proxy.response(json.dumps(remote).encode()))["result"]
    assert result["structuredContent"]["target_aliases"] == ["device-a"]
    assert result["structuredContent"]["target_rate_limits"][0]["rate_limit"]["remaining"] == 2
    assert MODULE.MASTER_ALIAS not in result["structuredContent"]["target_aliases"]
    assert result["structuredContent"]["invalid_target_count"] == 2


def test_target_scope_reports_the_enrolled_legacy_ssh_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    _, _, policy = _paths(tmp_path, monkeypatch)
    emitted = []
    proxy = MODULE.Proxy()
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(91, "target_scope", {"target": "device-a"})) is None
    assert emitted[-1]["result"]["structuredContent"]["legacy_ssh"] is None

    document = json.loads(policy.read_text())
    document["device-a"]["legacy_ssh"] = "rsa-sha1"
    policy.write_text(json.dumps(document))
    enrolled = MODULE.Proxy()
    monkeypatch.setattr(enrolled, "_emit", emitted.append)
    assert enrolled.request(_tool_call(92, "target_scope", {"target": "device-a"})) is None
    assert emitted[-1]["result"]["structuredContent"]["legacy_ssh"] == "rsa-sha1"


def test_target_scope_is_local_non_secret_and_tools_list_advertises_it(
    tmp_path: Path, monkeypatch,
) -> None:
    _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(81, "target_scope", {"target": "device-a"})) is None
    scope = emitted[-1]["result"]["structuredContent"]
    assert scope["ssh_platform"] == "fortinet"
    assert scope["enabled_queries"] == ["system_status", "interface_details"]
    assert scope["read_inventory"]["interfaces"] == ["eth0"]
    assert "https_endpoints" not in scope
    assert scope["ssh_host_key_enrolled"] is True
    assert scope["snmp_configured"] is True
    serialized = json.dumps(scope)
    for secret in ("selected-secret", "separate-community", "selected-user", "selected-host"):
        assert secret not in serialized

    proxy.pending[82] = "tools/list"
    listed = {"jsonrpc": "2.0", "id": 82, "result": {"tools": []}}
    tools = json.loads(proxy.response(json.dumps(listed).encode()))["result"]["tools"]
    assert [item["name"] for item in tools] == ["target_scope"]


def test_ssh_platform_and_enabled_query_are_enforced_before_forwarding(
    tmp_path: Path, monkeypatch,
) -> None:
    _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(83, "ssh_read", {
        "target": "device-a", "platform": "fortios", "query": "routing_table",
    })) is None
    assert emitted[-1]["error"]["data"]["category"] == "policy_scope"


def test_json_rpc_notifications_never_emit_responses(tmp_path: Path, monkeypatch) -> None:
    _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(..., "target_scope", {"target": "device-a"})) is None
    assert proxy.request(_tool_call(..., "tcp_probe", {"target": MODULE.MASTER_ALIAS})) is None
    forwarded = proxy.request(_tool_call(
        ..., "tcp_probe", {"target": "device-a", "port": 22},
    ))
    assert forwarded is not None
    assert emitted == []
    assert not proxy.pending
    assert not proxy.response_secrets


def test_stderr_is_classified_without_raw_topology_or_secrets(
    monkeypatch, capsys,
) -> None:
    state = {"emitted": False}
    MODULE._drain_stderr(
        io.BytesIO(
            b"Permission denied for selected-user at selected-host selected-secret\n"
        ),
        ("selected-secret",),
        state,
    )
    output = capsys.readouterr().err
    assert "category=ssh_authentication" in output
    for hidden in ("selected-user", "selected-host", "selected-secret", "Permission denied"):
        assert hidden not in output
    assert state["emitted"] is True


def test_redaction_does_not_consume_log_words_and_hides_real_community() -> None:
    first = (
        "Sep 9 sshd[2211]: Failed password for invalid user admin "
        "from 203.0.113.9"
    )
    assert MODULE.sanitize_text(first) == first
    second = MODULE.sanitize_text("SNMP community string configured: public")
    assert second == "SNMP community string configured: <REDACTED>"


def test_askpass_uses_self_reexec_without_temporary_file(monkeypatch, capsys) -> None:
    source = SCRIPT.read_text()
    assert "mkstemp" not in source
    assert "tempfile" not in source
    assert MODULE.ASKPASS_SOCKET_ENV in source
    assert "_NETOPS_HELPER_ASKPASS_SECRET" not in source
    child = MODULE.subprocess.Popen(["sleep", "30"])
    try:
        handoff = MODULE._AskpassHandoff("askpass-secret")
        handoff.serve(child)
        monkeypatch.setenv(MODULE.ASKPASS_SOCKET_ENV, handoff.name)
        assert MODULE._run_askpass() == 0
        assert capsys.readouterr().out == "askpass-secret\n"
        assert MODULE._run_askpass() == 1
        assert handoff._secret == ""
    finally:
        child.kill()
        child.wait()
