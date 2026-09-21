from __future__ import annotations

from base64 import urlsafe_b64decode
import importlib.util
import io
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "src" / "netops_helper" / "proxy.py"
from netops_helper import proxy as MODULE

DEVICE_PIN = "SHA256:" + "A" * 43
RUNNER_PIN = "SHA256:" + "B" * 43


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


def _section() -> dict:
    return {
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
        "read_inventory": {"interfaces": ["port1"], "services": [], "addresses": []},
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": True,
        "snmp_credential": "device-a-community",
        "rate_limit": {"requests": 2, "window_seconds": 60},
    }


def _write_test_inventory(path: Path) -> None:
    path.write_text(json.dumps({
        "version": 2,
        "devices": [{
            "name": "device-a",
            "platform": "fortios",
            "address": "192.0.2.10",
            "port": 22,
            "role": "interni",
            "credential": "device-a-account",
            "host_key_fingerprint": DEVICE_PIN,
            "legacy_ssh": None,
            "auditor": None,
            "helper": _section(),
        }],
    }, indent=2) + "\n")


def _write_test_vault(path: Path) -> None:
    path.write_text(json.dumps({
        "version": 2,
        "credentials": {
            "runner-account": {
                "kind": "password", "login": "runner-user", "value": "runner-secret",
            },
            "device-a-account": {
                "kind": "password", "login": "selected-user", "value": "selected-secret",
            },
            "device-a-community": {
                "kind": "snmp-community", "value": "separate-community",
            },
        },
    }, indent=2) + "\n")
    path.chmod(0o600)


def _write_test_policy(path: Path) -> None:
    path.write_text(json.dumps({
        "schema_version": 1,
        "profile": "strict-target",
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": ["192.0.2.53"],
        "lan_cidrs": [],
    }))


def _write_test_runner(path: Path) -> None:
    path.write_text(json.dumps({
        "version": 1,
        "host": "runner.example.invalid",
        "port": 22,
        "credential": "runner-account",
        "host_key_fingerprint": RUNNER_PIN,
    }))


def _paths(tmp_path: Path, monkeypatch):
    inventory = tmp_path / "inventory.json"
    vault = tmp_path / "vault.json"
    policy = tmp_path / "egress-policy.json"
    runner = tmp_path / "runner.json"
    _write_test_inventory(inventory)
    _write_test_vault(vault)
    _write_test_policy(policy)
    _write_test_runner(runner)
    monkeypatch.setattr(MODULE, "INVENTORY", inventory)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    monkeypatch.setattr(MODULE, "EGRESS_POLICY", policy)
    monkeypatch.setattr(MODULE, "RUNNER", runner)
    return inventory, vault, policy, runner


def _section_of(inventory: Path) -> dict:
    return json.loads(inventory.read_text())["devices"][0]["helper"]


def _rewrite(inventory: Path, document: dict) -> None:
    inventory.write_text(json.dumps(document))


def test_vault_is_read_through_the_shared_credential_store(tmp_path: Path, monkeypatch) -> None:
    _, vault, _, _ = _paths(tmp_path, monkeypatch)
    assert MODULE.Proxy()._vault().credential("device-a-account").login == "selected-user"
    with pytest.raises(MODULE.AuthenticationMaterialError):
        MODULE.Proxy()._credential(MODULE.Proxy()._vault(), "missing")


def test_vault_rejects_loose_permissions(tmp_path: Path, monkeypatch) -> None:
    _, vault, _, _ = _paths(tmp_path, monkeypatch)
    vault.chmod(0o644)
    with pytest.raises(MODULE.VaultPermissionError):
        MODULE.Proxy()._vault()


def test_request_injects_the_read_only_scope_and_the_pinned_host_key(
    tmp_path: Path, monkeypatch,
) -> None:
    _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    transformed = proxy.request(json.dumps({
        "jsonrpc": "2.0", "id": 21, "method": "tools/call",
        "params": {"name": "ssh_read", "arguments": {
            "target": "device-a", "platform": "fortios", "query": "system_status",
        }},
    }).encode())
    assert transformed is not None
    assert proxy.response_secrets[21][0] == "selected-secret"
    assert proxy.response_secrets[21][1] == json.loads(
        transformed,
    )["params"]["arguments"]["auth_context"]
    scope = _decode_context(transformed)
    assert set(scope) == {
        "alias", "host", "port", "login", "credential_kind", "secret",
        "host_key_fingerprint", "legacy_ssh", "account_role", "ssh_platform",
        "enabled_queries", "read_inventory", "sftp_roots",
        "fortios_output_standard_verified", "egress",
    }
    assert scope["account_role"] == "read-only"
    assert scope["credential_kind"] == "password"
    assert scope["host_key_fingerprint"] == DEVICE_PIN
    assert scope["ssh_platform"] == "fortios"
    assert scope["read_inventory"]["interfaces"] == ["port1"]
    assert scope["sftp_roots"] == ["/safe"]
    assert scope["fortios_output_standard_verified"] is True
    assert "known_hosts" not in scope
    assert "password" not in scope
    assert "rate_limit" not in scope


def test_a_device_without_a_helper_section_is_not_a_target(
    tmp_path: Path, monkeypatch,
) -> None:
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    document = json.loads(inventory.read_text())
    document["devices"][0]["helper"] = None
    document["devices"][0]["auditor"] = {"channel": "ssh"}
    _rewrite(inventory, document)
    with pytest.raises(MODULE.PolicyRejectedError):
        MODULE.Proxy()._target("device-a")
    with pytest.raises(MODULE.UnknownAliasError):
        MODULE.Proxy()._target("device-b")


def test_response_preserves_identifiers_redacts_secret_and_marks_untrusted() -> None:
    proxy = MODULE.Proxy(); proxy.pending[22] = "tools/call"
    proxy.response_secrets[22] = ("credential-value",)
    raw = json.dumps({
        "jsonrpc": "2.0", "id": 22,
        "result": {"content": [{"type": "text", "text": "Sep 9 10:23:45 host ip=192.0.2.10 mac=aa:bb:cc:dd:ee:ff credential-value"}]},
    }).encode()
    transformed = json.loads(proxy.response(raw)); output = transformed["result"]["content"][0]["text"]
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
    envelope = MODULE.urlsafe_b64encode(b'{"secret":"credential-value"}').decode().rstrip("=")
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
    _write_test_vault(real)
    link = tmp_path / "vault-link.json"
    link.symlink_to(real)
    monkeypatch.setattr(MODULE, "VAULT", link)
    with pytest.raises(MODULE.VaultPermissionError):
        MODULE.Proxy()._vault()
    monkeypatch.setattr(MODULE, "VAULT", real)
    assert MODULE.Proxy()._vault().names() == (
        "device-a-account", "device-a-community", "runner-account",
    )


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
        MODULE.RunnerFileError: "runner_file",
        MODULE.LegacyConfigurationError: "legacy_configuration",
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


def test_section_schema_and_role_fail_with_distinct_types(tmp_path: Path, monkeypatch) -> None:
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    document = json.loads(inventory.read_text())
    del document["devices"][0]["helper"]["ssh_platform"]
    _rewrite(inventory, document)
    with pytest.raises(MODULE.PolicySchemaError):
        MODULE.Proxy()._target("device-a")

    document["devices"][0]["helper"]["ssh_platform"] = "fortios"
    document["devices"][0]["helper"]["account_role"] = "administrator"
    _rewrite(inventory, document)
    with pytest.raises(MODULE.RoleRejectedError):
        MODULE.Proxy()._target("device-a")


def test_inventory_and_egress_policy_failures_are_policy_schema(
    tmp_path: Path, monkeypatch,
) -> None:
    inventory, _, policy, _ = _paths(tmp_path, monkeypatch)
    inventory.write_text("[]")
    with pytest.raises(MODULE.PolicySchemaError):
        MODULE.Proxy()._load_inventory()
    _write_test_inventory(inventory)
    policy.write_text(json.dumps({"schema_version": 1}))
    with pytest.raises(MODULE.PolicySchemaError):
        MODULE.Proxy()._load_egress_policy()
    _write_test_policy(policy)
    document = json.loads(policy.read_text())
    document["dns_resolvers"] = []
    policy.write_text(json.dumps(document))
    with pytest.raises(MODULE.PolicySchemaError):
        MODULE.Proxy()._target("device-a")


def test_vault_schema_permissions_and_auth_material_are_distinct(
    tmp_path: Path, monkeypatch,
) -> None:
    _, vault, _, _ = _paths(tmp_path, monkeypatch)
    vault.chmod(0o644)
    with pytest.raises(MODULE.VaultPermissionError):
        MODULE.Proxy()._vault()
    vault.chmod(0o600)
    vault.write_text("[]")
    with pytest.raises(MODULE.VaultSchemaError):
        MODULE.Proxy()._vault()
    vault.write_text(json.dumps({
        "version": 2,
        "credentials": {"device-a-account": {"kind": "password", "value": "abc"}},
    }))
    with pytest.raises(MODULE.VaultSchemaError):
        MODULE.Proxy()._vault()


def test_snmp_community_is_a_separate_enrolled_record_without_fallback(
    tmp_path: Path, monkeypatch,
) -> None:
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    proxy = MODULE.Proxy()
    transformed = proxy.request(_tool_call(
        70, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]},
    ))
    assert transformed is not None
    context = _decode_context(transformed)
    assert context["snmp_community"] == "separate-community"
    assert context["secret"] == "selected-secret"
    assert proxy.response_secrets[70][:2] == ("selected-secret", "separate-community")
    assert proxy.response_secrets[70][2] == json.loads(
        transformed,
    )["params"]["arguments"]["auth_context"]

    document = json.loads(inventory.read_text())
    del document["devices"][0]["helper"]["snmp_credential"]
    _rewrite(inventory, document)
    emitted = []
    proxy = MODULE.Proxy()
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(
        71, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"]},
    )) is None
    assert emitted[-1]["error"]["data"]["category"] == "auth_material"


def test_helper_status_lists_only_valid_aliases_with_rate_state(
    tmp_path: Path, monkeypatch,
) -> None:
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    document = json.loads(inventory.read_text())
    invalid = json.loads(json.dumps(document["devices"][0]))
    invalid["name"] = "invalid-section"
    invalid["helper"]["enabled_queries"] = ["does_not_exist"]
    auditor_only = json.loads(json.dumps(document["devices"][0]))
    auditor_only["name"] = "auditor-only"
    auditor_only["helper"] = None
    auditor_only["auditor"] = {"channel": "ssh"}
    document["devices"].extend((invalid, auditor_only))
    _rewrite(inventory, document)
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
    assert result["structuredContent"]["invalid_target_count"] == 1


def test_target_scope_reports_the_enrolled_legacy_ssh_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    inventory, _, _, _ = _paths(tmp_path, monkeypatch)
    emitted = []
    proxy = MODULE.Proxy()
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(_tool_call(91, "target_scope", {"target": "device-a"})) is None
    assert emitted[-1]["result"]["structuredContent"]["legacy_ssh"] is None

    document = json.loads(inventory.read_text())
    document["devices"][0]["legacy_ssh"] = "rsa-sha1"
    _rewrite(inventory, document)
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
    assert scope["read_inventory"]["interfaces"] == ["port1"]
    assert scope["host_key_pinned"] is True
    assert scope["snmp_enrolled"] is True
    assert "snmp_configured" not in scope
    assert "ssh_host_key_enrolled" not in scope
    serialized = json.dumps(scope)
    for secret in (
        "selected-secret", "separate-community", "selected-user", DEVICE_PIN,
    ):
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
    assert proxy.request(_tool_call(..., "tcp_probe", {"target": "device" + chr(127)})) is None
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
    assert capsys.readouterr().err == ""
    assert "selected-secret" not in state["captured"]
    MODULE._exit_diagnostic(255, False, state)
    output = capsys.readouterr().err
    assert "category=ssh_authentication" in output
    for hidden in ("selected-user", "selected-host", "selected-secret", "Permission denied"):
        assert hidden not in output
    assert state["emitted"] is True


def test_a_clean_exit_with_stderr_noise_reports_no_transport_failure(capsys) -> None:
    state = {"emitted": False}
    MODULE._drain_stderr(
        io.BytesIO(b"FastMCP 4.0.3\nINFO Starting MCP server with transport 'stdio'\n"),
        (),
        state,
    )
    MODULE._exit_diagnostic(0, False, state)
    assert capsys.readouterr().err == ""
    assert state["emitted"] is False

    MODULE._exit_diagnostic(255, False, {"emitted": False})
    assert "category=ssh_transport" in capsys.readouterr().err

    MODULE._exit_diagnostic(0, True, {"emitted": False})
    assert "category=ssh_timeout" in capsys.readouterr().err


def test_redaction_does_not_consume_log_words_and_hides_real_community() -> None:
    first = (
        "Sep 9 sshd[2211]: Failed password for invalid user admin "
        "from 203.0.113.9"
    )
    assert MODULE.sanitize_text(first) == first
    second = MODULE.sanitize_text("SNMP community string configured: public")
    assert second == "SNMP community string configured: <REDACTED>"


def test_askpass_uses_self_reexec_without_writing_the_password(monkeypatch, capsys) -> None:
    source = SCRIPT.read_text()
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


def test_the_private_identity_file_is_written_0600_and_is_the_only_copy(
    tmp_path: Path,
) -> None:
    directory = MODULE._private_directory()
    try:
        path = MODULE._identity_file(directory, "-----BEGIN OPENSSH PRIVATE KEY-----")
        assert MODULE.stat.S_IMODE(MODULE.os.stat(path).st_mode) == 0o600
        assert MODULE.os.listdir(directory) == [MODULE.IDENTITY_NAME]
        command = MODULE._ssh_command(
            {"host": "runner.example.invalid", "port": 22}, "runner-user",
            directory + "/known_hosts", path,
        )
        assert f"IdentityFile={path}" in command
        assert "PubkeyAuthentication=yes" in command
        assert "PasswordAuthentication=no" in command
        assert not any("-----BEGIN" in item for item in command)
    finally:
        MODULE.shutil.rmtree(directory, ignore_errors=True)



def test_target_vault_materializes_only_its_enrolled_credentials(tmp_path, monkeypatch):
    _paths(tmp_path, monkeypatch)
    created = []
    original = MODULE.core_vault._credential

    def observe(path, name, entry):
        created.append(name)
        return original(path, name, entry)

    monkeypatch.setattr(MODULE.core_vault, "_credential", observe)
    proxy = MODULE.Proxy()
    entry, section, selected = proxy._target("device-a")
    assert selected.names() == ("device-a-account", "device-a-community")
    assert set(created) == set(selected.names())
    with pytest.raises(MODULE.AuthenticationMaterialError):
        proxy._credential(selected, "runner-account")
    transformed = proxy.request(_tool_call(991, "snmp_get", {"target": "device-a", "oids": ["1.3.6.1.2.1.1.3.0"]}))
    context = _decode_context(transformed)
    assert context["secret"] == "selected-secret"
    assert context["snmp_community"] == "separate-community"
    assert "runner-secret" not in json.dumps(context)
    assert "runner-secret" not in repr(proxy.response_secrets)
