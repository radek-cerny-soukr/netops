#!/usr/bin/env python3
"""Dependency-free proxy policy and JSON-RPC contract tests."""

from __future__ import annotations

from base64 import b64encode, urlsafe_b64decode
import ast
import copy
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import threading
import sys
import tempfile


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "src" / "netops_helper" / "proxy.py"
LAUNCHER = ROOT / "scripts" / "remote_mcp_proxy.py"
DEVICE_PIN = "SHA256:" + "A" * 43
RUNNER_PIN = "SHA256:" + "B" * 43
DEVICE_SECRET = "ssh-password"
RUNNER_SECRET = "runner-password"
COMMUNITY = "snmp-community-value"
RUNNER_HOST_KEY = b64encode(b"runner-host-key-material").decode("ascii")


def _load_proxy():
    spec = importlib.util.spec_from_file_location("netops_helper.proxy", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _egress() -> dict:
    return {
        "addresses": ["192.0.2.10"],
        "tcp_ports": [21, 444],
        "udp_ports": [161],
        "tcp_port_ranges": [[8000, 8010]],
        "udp_port_ranges": [[5000, 5010]],
        "allow_icmp": False,
        "allow_dns": False,
        "tls_server_names": ["alternate.example"],
    }


def _section() -> dict:
    return {
        "account_role": "read-only",
        "ssh_platform": "fortios",
        "enabled_queries": ["system_status"],
        "read_inventory": {
            "interfaces": [], "services": [],
            "addresses": ["192.0.2.20", "2001:db8::1"], "switches": ["sw1"],
        },
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": True,
        "snmp_credential": "device-a-community",
        "rate_limit": {"requests": 30, "window_seconds": 60},
        "egress": _egress(),
    }


def _device(section: dict, platform: str = "fortios") -> dict:
    return {
        "name": "device-a",
        "platform": platform,
        "address": "192.0.2.10",
        "port": 22,
        "role": "interni",
        "credential": "device-a-account",
        "host_key_fingerprint": DEVICE_PIN,
        "legacy_ssh": None,
        "auditor": None,
        "helper": section,
    }


def _inventory(*devices: dict) -> dict:
    return {"version": 2, "devices": list(devices)}


def _egress_policy() -> dict:
    return {
        "schema_version": 1,
        "profile": "strict-target",
        "backend": "iptables",
        "bridge_name": "nh-egress0",
        "network_name": "netops-helper",
        "ipv6_mode": "deny",
        "dns_resolvers": ["192.0.2.53"],
        "lan_cidrs": [],
    }


def _runner(pin: str = RUNNER_PIN) -> dict:
    return {
        "version": 1,
        "host": "runner.example.invalid",
        "port": 22,
        "credential": "runner-account",
        "host_key_fingerprint": pin,
    }


def _vault_document() -> dict:
    return {
        "version": 2,
        "credentials": {
            "runner-account": {
                "kind": "password", "login": "runner-user", "value": RUNNER_SECRET,
            },
            "device-a-account": {
                "kind": "password", "login": "reader", "value": DEVICE_SECRET,
            },
            "device-a-community": {
                "kind": "snmp-community", "value": COMMUNITY,
            },
        },
    }


def _write(path: Path, document: dict, mode: int | None = None) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    return path


def _configure(module, directory: Path):
    inventory = _write(directory / "inventory.json", _inventory(_device(_section())))
    vault = _write(directory / "vault.json", _vault_document(), 0o600)
    policy = _write(directory / "egress-policy.json", _egress_policy())
    runner = _write(directory / "runner.json", _runner())
    module.INVENTORY = inventory
    module.VAULT = vault
    module.EGRESS_POLICY = policy
    module.RUNNER = runner
    return inventory, vault, policy, runner


def _request(identifier, tool: str, arguments: dict) -> bytes:
    value = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    if identifier is not ...:
        value["id"] = identifier
    return json.dumps(value).encode()


def _envelope(forwarded: bytes) -> dict:
    encoded = json.loads(forwarded)["params"]["arguments"]["auth_context"]
    padding = "=" * (-len(encoded) % 4)
    return json.loads(urlsafe_b64decode(encoded + padding))


def _assert_policy_error(proxy, payload: bytes) -> None:
    emitted = []
    proxy._emit = emitted.append
    before = {key: len(value) for key, value in proxy.rate_history.items()}
    assert proxy.request(payload) is None
    assert emitted[-1]["error"]["data"]["category"] == "policy_scope"
    after = {key: len(value) for key, value in proxy.rate_history.items()}
    assert after == before


def _assert_invalid_params(proxy, payload: bytes) -> None:
    emitted = []
    proxy._emit = emitted.append
    before = {key: tuple(value) for key, value in proxy.rate_history.items()}
    assert proxy.request(payload) is None
    assert emitted[-1]["error"]["code"] == -32602
    assert emitted[-1]["error"]["data"]["category"] == "invalid_params"
    after = {key: tuple(value) for key, value in proxy.rate_history.items()}
    assert after == before
    assert not proxy.pending
    assert not proxy.pending_tools
    assert not proxy.response_secrets


def check_section_schema_and_consumer_binding(module, directory: Path) -> None:
    inventory, vault, policy, _ = _configure(module, directory)
    proxy = module.Proxy()
    _, section, _ = proxy._target("device-a")
    assert section.egress["tcp_port_ranges"] == [[8000, 8010]]
    assert section.read_inventory["switches"] == ("sw1",)
    assert section.ssh_platform == "fortios"
    assert section.catalog_platform() == "fortinet"

    _write(inventory, _inventory(dict(_device(_section()), helper=None, auditor={})))
    try:
        module.Proxy()._target("device-a")
    except module.PolicyRejectedError:
        pass
    else:
        raise AssertionError("a device without a helper section became a target")

    invalid = _section()
    invalid["typo"] = True
    _write(inventory, _inventory(_device(invalid)))
    try:
        module.Proxy()._target("device-a")
    except module.PolicySchemaError:
        pass
    else:
        raise AssertionError("unknown section key was accepted")

    for mutate in (
        lambda value: value["egress"].update(addresses=["192.0.2.010"]),
        lambda value: value["egress"].update(addresses=["2001:db8::1"]),
        lambda value: value["egress"].update(tcp_port_ranges=[{"start": 1, "end": 2}]),
        lambda value: value["egress"].update(tcp_port_ranges=[[10, 1]]),
        lambda value: value["egress"].update(tls_server_names=["*.example"]),
        lambda value: value["egress"].update(tcp_ports=[True]),
    ):
        candidate = _section()
        mutate(candidate)
        _write(inventory, _inventory(_device(candidate)))
        try:
            module.Proxy()._target("device-a")
        except module.PolicySchemaError:
            pass
        else:
            raise AssertionError("invalid egress contract was accepted")

    hostname_section = copy.deepcopy(_section())
    hostname_section["egress"]["allow_dns"] = True
    hostname_section["egress"]["addresses"] = []
    hostname = dict(_device(hostname_section), address="target.example", port=22)
    _write(inventory, _inventory(hostname))
    try:
        module.Proxy()._target("device-a")
    except module.PolicySchemaError:
        pass
    else:
        raise AssertionError("hostname target without explicit addresses was accepted")
    hostname_section["egress"]["addresses"] = ["192.0.2.10"]
    _write(inventory, _inventory(hostname))
    module.Proxy()._target("device-a")

    document = _egress_policy()
    document["dns_resolvers"] = []
    _write(policy, document)
    try:
        module.Proxy()._target("device-a")
    except module.PolicySchemaError:
        pass
    else:
        raise AssertionError("a DNS target without a resolver scope was accepted")
    _write(policy, _egress_policy())
    _write(inventory, _inventory(_device(_section())))

    vault.write_bytes(b"\xff")
    try:
        module.Proxy()._vault()
    except module.VaultSchemaError:
        pass
    else:
        raise AssertionError("invalid UTF-8 vault was not classified as vault_schema")


def check_credential_kinds_and_discovery_survive(module, directory: Path) -> None:
    inventory, vault, _, _ = _configure(module, directory)
    document = _vault_document()
    document["credentials"]["device-a-community"]["kind"] = "api-token"
    _write(vault, document, 0o600)

    proxy = module.Proxy()
    emitted = []
    proxy._emit = emitted.append
    assert proxy.request(_request(98, "snmp_get", {
        "target": "device-a",
        "oids": ["1.3.6.1.2.1.1.1.0"],
    })) is None
    assert emitted[-1]["error"]["data"]["category"] == "policy_schema"
    assert not proxy.pending
    assert not proxy.pending_tools
    assert not proxy.response_secrets
    assert proxy.rate_history == {}

    discovery = module.Proxy()
    status = discovery._helper_status_payload()
    assert status["target_aliases"] == []
    assert status["invalid_target_count"] == 1

    _write(vault, _vault_document(), 0o600)
    second = _device(_section())
    second["name"] = "device-b"
    second["helper"] = dict(_section(), enabled_queries=["does_not_exist"])
    _write(inventory, _inventory(_device(_section()), second))
    discovery = module.Proxy()
    forwarded = discovery.request(_request(99, "helper_status", {}))
    assert forwarded is not None
    response = discovery.response(json.dumps({
        "jsonrpc": "2.0",
        "id": 99,
        "result": {"content": [{"type": "text", "text": "{\"ok\":true}"}]},
    }).encode())
    status = json.loads(response)["result"]["structuredContent"]
    assert status["target_aliases"] == ["device-a"]
    assert status["invalid_target_count"] == 1
    assert [item["alias"] for item in status["target_rate_limits"]] == [
        "device-a"
    ]


def check_policy_parity_invalid_corpus(module, directory: Path) -> None:
    inventory, _, _, _ = _configure(module, directory)
    mutations = (
        (
            "legacy HTTPS body-read field",
            lambda value: value.update(https_endpoints=[{
                "path": "/export.conf", "port": 443, "use_basic_auth": False,
            }]),
        ),
        ("legacy per-target profile", lambda value: value.update(legacy_ssh="rsa-sha1")),
        ("SFTP relative", lambda value: value.update(sftp_roots=["relative"])),
        ("SFTP root", lambda value: value.update(sftp_roots=["/"])),
        ("SFTP parent", lambda value: value.update(sftp_roots=["/safe/../escape"])),
        ("SFTP noncanonical", lambda value: value.update(sftp_roots=["/safe//log"])),
        ("SFTP double slash", lambda value: value.update(sftp_roots=["//safe"])),
        ("SFTP NUL", lambda value: value.update(sftp_roots=["/safe\x00log"])),
        ("SFTP oversized", lambda value: value.update(sftp_roots=["/" + "a" * 2_000])),
        ("inventory control", lambda value: value["read_inventory"].update(services=["bad\nservice"])),
        ("inventory DEL", lambda value: value["read_inventory"].update(interfaces=["bad\x7finterface"])),
        ("inventory address text", lambda value: value["read_inventory"].update(addresses=["not-an-address"])),
        ("inventory IPv4 canonical", lambda value: value["read_inventory"].update(addresses=["192.0.2.010"])),
        ("inventory IPv6 canonical", lambda value: value["read_inventory"].update(addresses=["2001:0db8::1"])),
        ("inventory interface syntax", lambda value: value["read_inventory"].update(interfaces=["port3;show"])),
        ("inventory service syntax", lambda value: value["read_inventory"].update(services=["sshd/service"])),
        ("inventory switch syntax", lambda value: value["read_inventory"].update(switches=["switch/1"])),
        ("platform alias", lambda value: value.update(ssh_platform="fortinet")),
        ("unknown snmp record", lambda value: value.update(snmp_credential="missing")),
        ("TCP port/range overlap", lambda value: value["egress"].update(tcp_ports=[8_005])),
        ("UDP port/range overlap", lambda value: value["egress"].update(udp_ports=[5_005])),
    )
    for index, (label, mutate) in enumerate(mutations, start=100):
        candidate = _section()
        mutate(candidate)
        _write(inventory, _inventory(_device(candidate)))
        proxy = module.Proxy()
        try:
            proxy._target("device-a")
        except module.PolicySchemaError:
            pass
        else:
            raise AssertionError(f"invalid section accepted: {label}")

        status = proxy._helper_status_payload()
        assert status["target_aliases"] == [], label
        assert status["invalid_target_count"] == 1, label

        emitted = []
        proxy._emit = emitted.append
        assert proxy.request(_request(
            index, "target_scope", {"target": "device-a"},
        )) is None
        assert emitted[-1]["error"]["data"]["category"] == "policy_schema", label


def check_scope_and_no_overinjection(module, directory: Path) -> None:
    inventory, _, _, _ = _configure(module, directory)
    assert 22 not in _egress()["tcp_ports"]
    assert 443 not in _egress()["tcp_ports"]
    proxy = module.Proxy()
    ssh = proxy.request(_request(1, "ssh_read", {
        "target": "device-a", "platform": "fortios",
        "query": "system_status", "offset": 0,
    }))
    assert ssh is not None
    forwarded_ssh = json.loads(ssh)
    assert forwarded_ssh["params"]["arguments"]["platform"] == "fortinet"
    auth = _envelope(ssh)
    assert auth["ssh_platform"] == "fortios"
    assert auth["egress"] == _egress()
    assert auth["host_key_fingerprint"] == DEVICE_PIN
    assert auth["credential_kind"] == "password"
    assert auth["secret"] == DEVICE_SECRET
    assert auth["legacy_ssh"] is None
    assert "known_hosts" not in auth
    assert "password" not in auth
    assert "snmp_community" not in auth

    snmp = proxy.request(_request(2, "snmp_get", {
        "target": "device-a", "oids": ["1.3.6.1.2.1.1.1.0"], "port": 161,
    }))
    assert snmp is not None
    auth = _envelope(snmp)
    assert auth["snmp_community"] == COMMUNITY

    proxy = module.Proxy()
    _assert_policy_error(proxy, _request(3, "tcp_probe", {
        "target": "device-a", "port": 80,
    }))
    _assert_policy_error(proxy, _request(4, "icmp_probe", {
        "target": "device-a",
    }))
    _assert_policy_error(proxy, _request(5, "dns_probe", {
        "target": "device-a",
    }))
    _assert_policy_error(proxy, _request(6, "tls_probe", {
        "target": "device-a", "port": 444, "server_name": "other.example",
    }))
    _assert_policy_error(proxy, _request(7, "snmp_get", {
        "target": "device-a", "port": 162, "oids": ["1.3.6.1"],
    }))
    _assert_invalid_params(module.Proxy(), _request(8, "route_trace", {
        "target": "device-a",
    }))

    assert proxy.request(_request(9, "tcp_probe", {
        "target": "device-a", "port": 8005,
    })) is not None
    assert proxy.request(_request(10, "tls_probe", {
        "target": "device-a", "port": 444, "server_name": "alternate.example",
    })) is not None
    assert proxy.request(_request(13, "sftp_stat", {
        "target": "device-a", "remote_path": "/safe/log",
    })) is not None
    assert proxy.request(_request(14, "ftp_list", {
        "target": "device-a", "remote_path": "/safe", "port": 21,
        "use_tls": True,
    })) is not None

    section = _section()
    section["egress"]["tcp_port_ranges"] = []
    _write(inventory, _inventory(_device(section)))
    _assert_policy_error(module.Proxy(), _request(15, "ftp_list", {
        "target": "device-a", "remote_path": "/safe", "port": 21,
        "use_tls": True,
    }))

    section = _section()
    section["sftp_roots"] = []
    _write(inventory, _inventory(_device(section)))
    _assert_policy_error(module.Proxy(), _request(16, "sftp_stat", {
        "target": "device-a", "remote_path": "/safe/log",
    }))


def check_discovery_notifications_and_rate_cost(module, directory: Path) -> None:
    _configure(module, directory)
    proxy = module.Proxy()
    emitted = []
    proxy._emit = emitted.append

    status_call = proxy.request(_request(20, "helper_status", {}))
    assert status_call is not None
    status_response = proxy.response(json.dumps({
        "jsonrpc": "2.0",
        "id": 20,
        "result": {"content": [{"type": "text", "text": "{\"ok\":true}"}]},
    }).encode())
    status = json.loads(status_response)["result"]["structuredContent"]
    assert status["target_aliases"] == ["device-a"]
    assert status["target_rate_limits"][0]["rate_limit"]["requests"] == 30

    emitted.clear()
    assert proxy.request(_request(21, "target_scope", {"target": "device-a"})) is None
    scope = emitted[-1]["result"]["structuredContent"]
    assert scope["ssh_platform"] == "fortinet"
    assert scope["egress"] == _egress()
    assert scope["read_inventory"]["switches"] == ["sw1"]
    assert scope["host_key_pinned"] is True
    assert scope["snmp_enrolled"] is True
    assert "https_endpoints" not in scope
    visible = json.dumps(scope)
    for secret in (DEVICE_SECRET, COMMUNITY, "reader", RUNNER_SECRET, DEVICE_PIN):
        assert secret not in visible

    emitted.clear()
    assert proxy.request(_request(..., "tcp_probe", {
        "target": "device-a", "port": 80,
    })) is None
    assert emitted == []

    rate_proxy = module.Proxy()
    calls = (
        ("ssh_read", {
            "target": "device-a", "platform": "fortios",
            "query": "system_status", "offset": 0,
        }),
        ("ssh_read", {
            "target": "device-a", "platform": "fortios",
            "query": "system_status", "offset": 100,
        }),
        ("tcp_probe", {"target": "device-a", "port": 444}),
    )
    for index, (tool, arguments) in enumerate(calls, start=30):
        assert rate_proxy.request(_request(index, tool, arguments)) is not None
    rate = rate_proxy._rate_status("device-a", _section()["rate_limit"])
    assert rate["used"] == 2
    assert rate["remaining"] == 28


def check_exact_argument_schema_precedes_auth_rate_and_forward(
    module, directory: Path,
) -> None:
    _configure(module, directory)
    invalid_calls = (
        ("helper_status", {"unexpected": True}),
        ("read_query_catalog", {"target": "device-a"}),
        ("target_scope", {"target": "device-a", "extra": 1}),
        ("dns_probe", {"target": "device-a", "timeout": 1}),
        ("tcp_probe", {"target": "device-a"}),
        ("tcp_probe", {"target": "device-a", "port": True}),
        ("tcp_probe", {"target": "device-a", "port": 444, "timeout": float("nan")}),
        ("icmp_probe", {"target": "device-a", "count": True}),
        ("tls_probe", {"target": "device-a", "server_name": 7}),
        ("https_get", {
            "target": "device-a", "path": "/export.conf", "port": 443,
            "use_basic_auth": False, "offset": 0, "max_bytes": 24_000,
        }),
        ("ssh_read", {
            "target": "device-a", "platform": "fortios", "query": "system_status",
            "auth_context": "client-controlled",
        }),
        ("ssh_read", {
            "target": "device-a", "platform": "fortios", "query": "system_status",
            "parameters": {"interface": 7},
        }),
        ("snmp_get", {"target": "device-a", "oids": [7]}),
        ("sftp_stat", {"target": "device-a", "remote_path": 7}),
        ("sftp_read_text", {
            "target": "device-a", "remote_path": "/safe/export.conf",
            "offset": 0, "max_bytes": 24_000,
        }),
        ("ftp_list", {"target": "device-a", "remote_path": "/safe", "use_tls": 1}),
        ("route_trace", {"target": "device-a"}),
    )
    for index, (tool, arguments) in enumerate(invalid_calls, start=200):
        proxy = module.Proxy()
        proxy._target = lambda alias: (_ for _ in ()).throw(
            AssertionError("authentication lookup must not start")
        )
        proxy._consume_rate_limit = lambda *args: (_ for _ in ()).throw(
            AssertionError("rate slot must not be consumed")
        )
        _assert_invalid_params(proxy, _request(index, tool, arguments))
        assert proxy.rate_history == {}


def check_pre_auth_scope_for_query_slots_paths_and_alias(
    module, directory: Path,
) -> None:
    inventory, _, _, _ = _configure(module, directory)
    section = _section()
    section["enabled_queries"].append("interface_details")
    section["read_inventory"]["interfaces"] = ["port3"]
    _write(inventory, _inventory(_device(section)))

    def assert_scope_rejected(payload: bytes) -> None:
        proxy = module.Proxy()
        proxy._auth_context = lambda *args: (_ for _ in ()).throw(
            AssertionError("auth context must not be constructed")
        )
        proxy._consume_rate_limit = lambda *args: (_ for _ in ()).throw(
            AssertionError("rate slot must not be consumed")
        )
        emitted = []
        proxy._emit = emitted.append
        before = dict(proxy.rate_history)
        assert proxy.request(payload) is None
        assert emitted[-1]["error"]["data"]["category"] == "policy_scope"
        assert proxy.rate_history == before == {}
        assert not proxy.pending
        assert not proxy.response_secrets

    ssh_arguments = {
        "target": "device-a",
        "platform": "fortios",
        "query": "interface_details",
    }
    invalid_ssh_parameters = (
        None,
        {"wrong": "port3"},
        {"interface": "port3", "extra": "port3"},
        {"interface": "port4"},
    )
    for index, parameters in enumerate(invalid_ssh_parameters, start=300):
        arguments = dict(ssh_arguments)
        if parameters is not None:
            arguments["parameters"] = parameters
        assert_scope_rejected(_request(index, "ssh_read", arguments))

    invalid_paths = (
        ("sftp_stat", "/outside/log"),
        ("sftp_stat", "/safe/../escape"),
        ("ftp_list", "/outside"),
        ("ftp_list", "/safe//log"),
        ("ftp_list", "/safe/../escape"),
        ("ftp_list", "/safeish/log"),
    )
    for index, (tool, remote_path) in enumerate(invalid_paths, start=310):
        arguments = {"target": "device-a", "remote_path": remote_path}
        if tool == "ftp_list":
            arguments.update({"port": 21, "use_tls": True})
        assert_scope_rejected(_request(index, tool, arguments))

    assert module.Proxy._valid_alias("device" + chr(127)) is False
    proxy = module.Proxy()
    proxy._target = lambda alias: (_ for _ in ()).throw(
        AssertionError("vault lookup must not start for invalid alias")
    )
    _assert_invalid_params(proxy, _request(
        320, "dns_probe", {"target": "device" + chr(127)},
    ))


def check_query_authority_and_typed_pre_auth(
    module, directory: Path,
) -> None:
    inventory, _, _, _ = _configure(module, directory)
    expected_aliases = {
        "linux": "linux",
        "fortinet": "fortinet",
        "fortios": "fortinet",
        "extreme_exos": "extreme_exos",
        "extreme_switch_engine": "extreme_exos",
        "cisco_ios": "cisco_ios",
        "cisco_xe": "cisco_xe",
        "cisco_nxos": "cisco_nxos",
        "arista_eos": "arista_eos",
        "juniper_junos": "juniper_junos",
        "juniper_junos_els": "juniper_junos_els",
        "ruckus_unleashed": "ruckus_unleashed",
    }
    expected_counts = {
        "linux": 16,
        "fortinet": 40,
        "extreme_exos": 47,
        "cisco_ios": 27,
        "cisco_xe": 27,
        "cisco_nxos": 30,
        "arista_eos": 33,
        "juniper_junos": 25,
        "juniper_junos_els": 29,
        "ruckus_unleashed": 4,
    }
    assert module.PLATFORM_MAP == expected_aliases
    assert {
        platform: len(names)
        for platform, names in module.READ_QUERY_NAMES.items()
    } == expected_counts
    name_contract = "\n".join(
        f"{platform}:{name}"
        for platform, names in sorted(module.READ_QUERY_NAMES.items())
        for name in sorted(names)
    )
    assert hashlib.sha256(name_contract.encode()).hexdigest() == (
        "86bcc88f4f031239a732d223c7f49c98d90a2b8450d4f3a32c0935f906bb40b2"
    )
    assert sum(expected_counts.values()) == 278

    expected_kind_inventory = {
        "address": "addresses",
        "ipv4_address": "addresses",
        "ipv6_address": "addresses",
        "interface": "interfaces",
        "service": "services",
        "switch": "switches",
        "fortios_interface": "interfaces",
        "fortios_physical_interface": "interfaces",
        "cisco_ios_interface": "interfaces",
        "cisco_ios_physical_interface": "interfaces",
        "cisco_xe_interface": "interfaces",
        "cisco_xe_physical_interface": "interfaces",
        "cisco_nxos_interface": "interfaces",
        "cisco_nxos_errors_interface": "interfaces",
        "extreme_physical_port": "interfaces",
        "eos_interface": "interfaces",
        "eos_physical_interface": "interfaces",
        "eos_lldp_interface": "interfaces",
        "eos_lacp_interface": "interfaces",
        "eos_stp_interface": "interfaces",
        "eos_ospf_interface": "interfaces",
        "junos_interface": "interfaces",
        "junos_physical_interface": "interfaces",
        "junos_logical_interface": "interfaces",
        "junos_lacp_interface": "interfaces",
    }
    assert set(module.READ_QUERY_SLOTS) == set(module.READ_QUERY_NAMES)
    for platform, query_slots in module.READ_QUERY_SLOTS.items():
        for query, slots in query_slots.items():
            assert query in module.READ_QUERY_NAMES[platform]
            for slot_name, slot in slots.items():
                assert slot_name
                assert set(slot) == {"inventory", "kind"}
                assert slot["inventory"] == expected_kind_inventory[slot["kind"]]
    assert "ports_configuration" in module.READ_QUERY_NAMES["extreme_exos"]
    assert "ports_configuration" not in module.READ_QUERY_SLOTS["extreme_exos"]

    query_by_platform = {
        "linux": "hostname",
        "fortinet": "system_status",
        "extreme_exos": "version",
        "cisco_ios": "version",
        "cisco_xe": "version",
        "cisco_nxos": "version",
        "arista_eos": "version",
        "juniper_junos": "version",
        "juniper_junos_els": "version",
        "ruckus_unleashed": "system_info",
    }
    for canonical_name in module.helper_inventory.core.platforms.PLATFORMS:
        canonical = module.helper_inventory.catalog_platform(canonical_name)
        candidate = _section()
        candidate["ssh_platform"] = canonical_name
        candidate["enabled_queries"] = [query_by_platform[canonical]]
        candidate["read_inventory"] = {}
        _write(inventory, _inventory(_device(candidate, canonical_name)))
        _, section, _ = module.Proxy()._target("device-a")
        assert section.ssh_platform == canonical_name
        assert section.catalog_platform() == canonical

    expected_slots = {
        ("linux", "interface_link"): (
            "interfaces", "interface",
        ),
        ("linux", "service_status"): (
            "services", "service",
        ),
        ("fortinet", "bridge_mac_table"): (
            "switches", "switch",
        ),
        ("fortinet", "interface_details"): (
            "interfaces", "fortios_interface",
        ),
        ("fortinet", "interface_hardware"): (
            "interfaces", "fortios_physical_interface",
        ),
        ("cisco_ios", "interface_details"): (
            "interfaces", "cisco_ios_interface",
        ),
        ("cisco_ios", "interface_errors"): (
            "interfaces", "cisco_ios_physical_interface",
        ),
        ("cisco_xe", "interface_details"): (
            "interfaces", "cisco_xe_interface",
        ),
        ("cisco_xe", "interface_errors"): (
            "interfaces", "cisco_xe_physical_interface",
        ),
        ("cisco_nxos", "interface_details"): (
            "interfaces", "cisco_nxos_interface",
        ),
        ("cisco_nxos", "interface_errors"): (
            "interfaces", "cisco_nxos_errors_interface",
        ),
        ("cisco_ios", "route_lookup"): (
            "addresses", "ipv4_address",
        ),
        ("cisco_nxos", "ipv6_route_lookup"): (
            "addresses", "ipv6_address",
        ),
        ("extreme_exos", "interface_details"): (
            "interfaces", "extreme_physical_port",
        ),
        ("arista_eos", "interface_details"): (
            "interfaces", "eos_interface",
        ),
        ("arista_eos", "interface_optics"): (
            "interfaces", "eos_physical_interface",
        ),
        ("arista_eos", "lldp_neighbors_interface"): (
            "interfaces", "eos_lldp_interface",
        ),
        ("arista_eos", "lacp_peer_interface"): (
            "interfaces", "eos_lacp_interface",
        ),
        ("arista_eos", "stp_interface"): (
            "interfaces", "eos_stp_interface",
        ),
        ("arista_eos", "ospf_neighbors_interface"): (
            "interfaces", "eos_ospf_interface",
        ),
        ("juniper_junos", "interface_details"): (
            "interfaces", "junos_interface",
        ),
        ("juniper_junos", "interface_optics"): (
            "interfaces", "junos_physical_interface",
        ),
        ("juniper_junos", "arp_interface"): (
            "interfaces", "junos_logical_interface",
        ),
        ("juniper_junos", "lacp_interface"): (
            "interfaces", "junos_lacp_interface",
        ),
    }
    for (platform, query), expected in expected_slots.items():
        slots = module.READ_QUERY_SLOTS[platform][query]
        assert len(slots) == 1
        slot = next(iter(slots.values()))
        assert set(slot) == {"inventory", "kind"}
        assert (slot["inventory"], slot["kind"]) == expected

    valid_queries = (
        ("fortinet", "interface_details", "port1"),
        ("fortinet", "interface_hardware", "wan1"),
        ("cisco_ios", "interface_details", "Gi1/0/1"),
        ("cisco_ios", "interface_errors", "GigabitEthernet1/0/1"),
        ("cisco_xe", "interface_details", "Vl4094"),
        ("cisco_xe", "interface_errors", "Te1/0/24"),
        ("cisco_nxos", "interface_details", "Port-channel4096.4094"),
        ("cisco_nxos", "interface_errors", "Loopback1023"),
        ("cisco_ios", "route_lookup", "192.0.2.20"),
        ("cisco_nxos", "ipv6_route_lookup", "2001:db8::1"),
        ("extreme_exos", "interface_details", "1:1"),
        ("extreme_exos", "interface_details", "1/47"),
        ("extreme_exos", "interface_details", "49:4"),
        ("extreme_exos", "interface_details", "2:49:4"),
        ("arista_eos", "interface_details", "Ethernet1"),
        ("arista_eos", "interface_optics", "Ethernet3/1"),
        ("arista_eos", "lldp_neighbors_interface", "Management1"),
        ("arista_eos", "lacp_peer_interface", "Port-Channel10"),
        ("arista_eos", "stp_interface", "Ethernet1"),
        ("arista_eos", "ospf_neighbors_interface", "Vlan4094"),
        ("juniper_junos", "interface_details", "ae0.0"),
        ("juniper_junos", "interface_optics", "xe-0/0/1"),
        ("juniper_junos", "arp_interface", "ge-1/0/47.0"),
        ("juniper_junos", "lacp_interface", "et-0/0/0"),
    )

    canonical_of = {
        catalog: name
        for name in module.helper_inventory.core.platforms.PLATFORMS
        for catalog in (module.helper_inventory.catalog_platform(name),)
    }

    def install_section(
        platform: str,
        query: str,
        inventory_value: str,
    ) -> tuple[str, str]:
        slot_name, slot = next(iter(
            module.READ_QUERY_SLOTS[platform][query].items()
        ))
        candidate = _section()
        candidate["ssh_platform"] = canonical_of[platform]
        candidate["enabled_queries"] = [query]
        candidate["read_inventory"] = {
            "interfaces": [],
            "services": [],
            "addresses": [],
            "switches": [],
        }
        candidate["read_inventory"][slot["inventory"]] = [inventory_value]
        _write(inventory, _inventory(_device(candidate, canonical_of[platform])))
        return slot_name, slot["inventory"]

    candidate = _section()
    candidate["ssh_platform"] = "exos"
    candidate["enabled_queries"] = ["ports_configuration"]
    candidate["read_inventory"] = {}
    _write(inventory, _inventory(_device(candidate, "exos")))
    assert module.Proxy().request(_request(399, "ssh_read", {
        "target": "device-a",
        "platform": "extreme_exos",
        "query": "ports_configuration",
    })) is not None

    for index, (platform, query, value) in enumerate(valid_queries, start=400):
        slot_name, _ = install_section(platform, query, value)
        forwarded = module.Proxy().request(_request(index, "ssh_read", {
            "target": "device-a",
            "platform": platform,
            "query": query,
            "parameters": {slot_name: value},
        }))
        assert forwarded is not None, (platform, query, value)

    invalid_queries = (
        (
            "cisco_ios", "route_lookup",
            "2001:db8::1", "2001:db8::1",
        ),
        (
            "cisco_nxos", "ipv6_route_lookup",
            "2001:0db8::1", "2001:db8::1",
        ),
        ("extreme_exos", "interface_details", "all", "all"),
        (
            "extreme_exos", "interface_details",
            "1:1-1:48", "1:1-1:48",
        ),
        (
            "extreme_exos", "interface_details",
            "1:1,1:2", "1:1,1:2",
        ),
        (
            "extreme_exos", "interface_details",
            "1:1 1:2", "1:1 1:2",
        ),
        (
            "extreme_exos", "interface_details",
            "1:*", "1:*",
        ),
        ("arista_eos", "interface_details", "Et1", "Et1"),
        (
            "arista_eos", "interface_details",
            "ethernet1", "ethernet1",
        ),
        (
            "juniper_junos", "interface_optics",
            "ge-0/0/0.0", "ge-0/0/0.0",
        ),
        (
            "juniper_junos", "arp_interface",
            "ge-0/0/0", "ge-0/0/0",
        ),
        (
            "juniper_junos", "lacp_interface",
            "ae0.0", "ae0.0",
        ),
    )
    for index, (
        platform, query, parameter_value, inventory_value,
    ) in enumerate(invalid_queries, start=450):
        slot_name, _ = install_section(platform, query, inventory_value)
        proxy = module.Proxy()
        auth_calls = []
        rate_calls = []
        proxy._auth_context = (
            lambda *args: auth_calls.append(args) or "unexpected"
        )
        proxy._consume_rate_limit = (
            lambda *args: rate_calls.append(args)
        )
        emitted = []
        proxy._emit = emitted.append
        before = dict(proxy.rate_history)
        result = proxy.request(_request(index, "ssh_read", {
            "target": "device-a",
            "platform": platform,
            "query": query,
            "parameters": {slot_name: parameter_value},
        }))
        assert result is None, (platform, query, parameter_value)
        category = emitted[-1]["error"]["data"]["category"]
        if platform in {"cisco_ios", "cisco_nxos"} and query.endswith(
            "route_lookup"
        ):
            assert category == "policy_scope"
        else:
            assert category == "policy_schema"
        assert auth_calls == []
        assert rate_calls == []
        assert proxy.rate_history == before == {}
        assert not proxy.pending
        assert not proxy.response_secrets


def check_standalone_isolated_help(directory: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "PYTHONPATH"
    }
    environment["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(LAUNCHER), "--help"],
        cwd=directory,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout


def check_batch_and_tools_list(module, directory: Path) -> None:
    _configure(module, directory)
    proxy = module.Proxy()
    proxy.pending[40] = "tools/call"
    proxy.pending_tools[40] = "tcp_probe"
    proxy.response_secrets[40] = ("response-secret",)
    proxy.pending[41] = "tools/list"
    batch = [
        {
            "jsonrpc": "2.0", "id": 40,
            "result": {"content": [{"type": "text", "text": "response-secret"}]},
        },
        {"jsonrpc": "2.0", "id": 41, "result": {"tools": [{
            "name": "tcp_probe",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "auth_context": {"type": "string"},
                },
                "required": ["target", "auth_context"],
            },
        }]}},
    ]
    rejected_schema = {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    }
    batch[1]["result"]["tools"].extend(
        {"name": name, "inputSchema": dict(rejected_schema)}
        for name in ("write_tool", "https_get", "sftp_read_text", "target_scope")
    )
    transformed = json.loads(proxy.response(json.dumps(batch).encode()))
    assert "response-secret" not in transformed[0]["result"]["content"][0]["text"]
    tools = transformed[1]["result"]["tools"]
    assert [item["name"] for item in tools] == ["tcp_probe", "target_scope"]
    schema = tools[0]["inputSchema"]
    assert "auth_context" not in schema["properties"]
    assert "auth_context" not in schema["required"]


def check_ssh_stderr_classification(module) -> None:
    remote_exec_message = "The fixed remote container command could not start."
    remote_exec_cases = (
        "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
        "dial unix /run/user/1000/docker.sock: connect: permission denied",
        "/bin/sh: line 1: docker: not found",
        "sh: 1: docker: not found",
        "docker: command not found",
        "-bash: docker: command not found",
    )
    for value in remote_exec_cases:
        category, message = module._classify_ssh_stderr(value)
        assert (category, message) == ("remote_exec", remote_exec_message)
        assert value not in message
        assert "docker.sock" not in message.lower()

    negative_cases = (
        (
            "Permission denied (publickey,password).",
            "ssh_authentication",
            "SSH authentication to the runner failed.",
        ),
        (
            "Permission denied while reading /srv/docker/config.json",
            "ssh_authentication",
            "SSH authentication to the runner failed.",
        ),
        (
            "permission denied while invoking a container runtime",
            "ssh_authentication",
            "SSH authentication to the runner failed.",
        ),
        (
            "sh: 1: podman: not found",
            "ssh_transport",
            module.SSH_TRANSPORT_FAILURE_MESSAGE,
        ),
        (
            "unrelated text: docker: command not found",
            "ssh_transport",
            module.SSH_TRANSPORT_FAILURE_MESSAGE,
        ),
    )
    for value, expected_category, expected_message in negative_cases:
        assert module._classify_ssh_stderr(value) == (
            expected_category, expected_message,
        )


def check_runner_startup_preflight_categories(module, directory: Path) -> None:
    original_popen = module.subprocess.Popen
    original_diagnostic = module._write_transport_diagnostic
    original_argv = module.sys.argv
    askpass_mode = module.os.environ.pop(module.ASKPASS_MODE_ENV, None)
    popen_called = []
    diagnostics = []

    def forbidden_popen(*args, **kwargs):
        popen_called.append(True)
        raise AssertionError("failed startup preflight reached Popen")

    def run_case(expected: tuple[str, str]) -> None:
        diagnostics.clear()
        assert module.main() == 2
        assert diagnostics == [expected]
        assert popen_called == []

    try:
        module.subprocess.Popen = forbidden_popen
        module._write_transport_diagnostic = (
            lambda category, message: diagnostics.append((category, message))
        )
        module.sys.argv = [str(SCRIPT)]

        _, _, _, runner = _configure(module, directory)
        runner.unlink()
        run_case((
            module.RunnerFileError.category,
            module.RunnerFileError.public_message,
        ))

        _, _, _, runner = _configure(module, directory)
        for invalid in (
            dict(_runner(), version=2),
            dict(_runner(), host="-oProxyCommand=malicious"),
            dict(_runner(), port=0),
            dict(_runner(), host_key_fingerprint="SHA256:short"),
            {key: value for key, value in _runner().items() if key != "credential"},
        ):
            _write(runner, invalid)
            run_case((
                module.RunnerFileError.category,
                module.RunnerFileError.public_message,
            ))

        _, vault, _, runner = _configure(module, directory)
        _write(runner, dict(_runner(), credential="missing"))
        run_case((
            module.AuthenticationMaterialError.category,
            module.AuthenticationMaterialError.public_message,
        ))

        _, vault, _, _ = _configure(module, directory)
        document = _vault_document()
        document["credentials"]["runner-account"] = {
            "kind": "api-token", "value": RUNNER_SECRET,
        }
        _write(vault, document, 0o600)
        run_case((
            module.AuthenticationMaterialError.category,
            module.AuthenticationMaterialError.public_message,
        ))

        _, vault, _, _ = _configure(module, directory)
        vault.chmod(0o644)
        run_case((
            module.VaultPermissionError.category,
            module.VaultPermissionError.public_message,
        ))

        _, vault, _, _ = _configure(module, directory)
        vault.write_text("{invalid-json", encoding="utf-8")
        run_case((
            module.VaultSchemaError.category,
            module.VaultSchemaError.public_message,
        ))

        _configure(module, directory)
        for variable in module.REMOVED_VARIABLES:
            module.os.environ[variable] = "set-by-an-old-deployment"
            try:
                run_case((
                    module.LegacyConfigurationError.category,
                    module.LegacyConfigurationError.public_message,
                ))
            finally:
                del module.os.environ[variable]
        for name in module.REMOVED_FILES:
            legacy = directory / name
            legacy.write_text("{}", encoding="utf-8")
            try:
                run_case((
                    module.LegacyConfigurationError.category,
                    module.LegacyConfigurationError.public_message,
                ))
            finally:
                legacy.unlink()
    finally:
        module.subprocess.Popen = original_popen
        module._write_transport_diagnostic = original_diagnostic
        module.sys.argv = original_argv
        if askpass_mode is not None:
            module.os.environ[module.ASKPASS_MODE_ENV] = askpass_mode


def check_ssh_launch_hardening(module, directory: Path) -> None:
    _configure(module, directory)
    known_hosts = str(directory / "known_hosts")
    runner = {"host": "runner.example", "port": 2222}
    command = module._ssh_command(runner, "runner-user", known_hosts, None)
    assert command[:4] == ["ssh", "-T", "-F", "/dev/null"]
    assert command[-8:] == [
        "runner.example", "docker", "exec", "-i", "netops-helper",
        "python", "-m", "netops_helper.server",
    ]
    destination_index = len(command) - 8
    assert command[destination_index - 2:destination_index] == ["-l", "runner-user"]
    assert command[destination_index - 4:destination_index - 2] == ["-p", "2222"]
    assert "runner-user@runner.example" not in command

    options = {}
    index = 4
    while index < destination_index - 4:
        assert command[index] == "-o"
        key, separator, value = command[index + 1].partition("=")
        assert separator == "="
        assert key not in options
        options[key] = value
        index += 2
    assert options == {
        "BatchMode": "no",
        "NumberOfPasswordPrompts": "1",
        "PreferredAuthentications": "keyboard-interactive,password",
        "PasswordAuthentication": "yes",
        "KbdInteractiveAuthentication": "yes",
        "PubkeyAuthentication": "no",
        "HostbasedAuthentication": "no",
        "GSSAPIAuthentication": "no",
        "IdentitiesOnly": "yes",
        "IdentityAgent": "none",
        "ForwardAgent": "no",
        "ForwardX11": "no",
        "ForwardX11Trusted": "no",
        "ClearAllForwardings": "yes",
        "PermitLocalCommand": "no",
        "EscapeChar": "none",
        "Tunnel": "no",
        "ProxyCommand": "none",
        "ProxyJump": "none",
        "ControlMaster": "no",
        "ControlPath": "none",
        "ControlPersist": "no",
        "SendEnv": "-*",
        "UpdateHostKeys": "no",
        "StrictHostKeyChecking": "yes",
        "UserKnownHostsFile": known_hosts,
        "GlobalKnownHostsFile": "/dev/null",
        "VerifyHostKeyDNS": "no",
        "CanonicalizeHostname": "no",
        "LogLevel": "ERROR",
        "ConnectTimeout": "10",
    }
    assert not any(
        item in command[:destination_index]
        for item in ("-A", "-X", "-Y", "-L", "-R", "-D", "-J", "-S")
    )

    identity = str(directory / "runner-identity")
    keyed = module._ssh_command(runner, "runner-user", known_hosts, identity)
    keyed_options = dict(
        item.partition("=")[::2]
        for item in keyed[:len(keyed) - 8] if "=" in item
    )
    assert keyed_options["PubkeyAuthentication"] == "yes"
    assert keyed_options["PasswordAuthentication"] == "no"
    assert keyed_options["KbdInteractiveAuthentication"] == "no"
    assert keyed_options["PreferredAuthentications"] == "publickey"
    assert keyed_options["BatchMode"] == "yes"
    assert keyed_options["NumberOfPasswordPrompts"] == "0"
    assert keyed_options["IdentityFile"] == identity
    assert keyed_options["IdentitiesOnly"] == "yes"

    parsed = module.subprocess.run(
        [command[0], "-G", *command[1:destination_index + 1]],
        stdout=module.subprocess.PIPE,
        stderr=module.subprocess.PIPE,
        check=False,
        text=True,
    )
    assert parsed.returncode == 0, parsed.stderr
    effective = {}
    for line in parsed.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            effective.setdefault(key, value)
    assert effective["host"] == "runner.example"
    assert effective["hostname"] == "runner.example"
    assert effective["user"] == "runner-user"
    assert effective["port"] == "2222"
    assert effective["requesttty"] == "false"
    assert effective["clearallforwardings"] == "yes"
    assert effective["forwardagent"] == "no"
    assert effective["forwardx11"] == "no"
    assert effective["identityagent"] == "none"
    assert effective["permitlocalcommand"] == "no"
    assert effective["escapechar"] == "none"
    assert effective["tunnel"] == "false"
    assert effective["controlmaster"] == "false"
    assert effective["pubkeyauthentication"] == "false"
    assert effective["kbdinteractiveauthentication"] == "yes"
    assert effective["passwordauthentication"] == "yes"
    assert effective["stricthostkeychecking"] == "true"
    assert effective["updatehostkeys"] == "false"
    assert effective["verifyhostkeydns"] == "false"
    assert effective["canonicalizehostname"] == "false"
    assert effective["globalknownhostsfile"] == "/dev/null"
    assert effective["userknownhostsfile"] == known_hosts
    assert "proxycommand" not in effective
    assert "controlpath" not in effective
    assert "localcommand" not in effective
    assert "sendenv" not in effective
    assert "setenv" not in effective



FAKE_SSH = """#!%s
import json, os, sys

record = {"argv": sys.argv[1:], "env": dict(os.environ), "requests": []}
sys.stderr.write("FastMCP banner on standard error" + chr(10))
sys.stderr.flush()
for item in sys.argv[1:]:
    if item.startswith("UserKnownHostsFile="):
        with open(item.split("=", 1)[1], "r", encoding="utf-8") as handle:
            record["known_hosts"] = handle.read()
for raw in sys.stdin.buffer:
    record["requests"].append(raw.decode("utf-8"))
    message = json.loads(raw)
    sys.stdout.write(json.dumps({
        "jsonrpc": "2.0", "id": message.get("id"),
        "result": {"content": [{"type": "text", "text": "{\\"ok\\":true}"}]},
    }) + chr(10))
    sys.stdout.flush()
with open(os.environ["NETOPS_FAKE_SSH_RECORD"], "w", encoding="utf-8") as handle:
    json.dump(record, handle)
"""

FAKE_KEYSCAN = """#!%s
import sys

sys.stdout.write("%%s ssh-ed25519 %%s" %% (sys.argv[-1], %r) + chr(10))
"""


def _fake_tools(directory: Path) -> Path:
    binaries = directory / "bin"
    binaries.mkdir(exist_ok=True)
    for name, source in (
        ("ssh", FAKE_SSH % sys.executable),
        ("ssh-keyscan", FAKE_KEYSCAN % (sys.executable, RUNNER_HOST_KEY)),
    ):
        path = binaries / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
    return binaries


def _proxy_environment(module, directory: Path, binaries: Path, record: Path) -> dict:
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"PYTHONPATH"} | set(module.REMOVED_VARIABLES)
    }
    environment.update({
        "PATH": "%s:%s" % (binaries, os.environ.get("PATH", "/usr/bin:/bin")),
        "HOME": str(directory),
        "NETOPS_INVENTORY_PATH": str(directory / "inventory.json"),
        "NETOPS_VAULT_PATH": str(directory / "vault.json"),
        "NETOPS_EGRESS_POLICY_PATH": str(directory / "egress-policy.json"),
        "NETOPS_RUNNER_PATH": str(directory / "runner.json"),
        "NETOPS_FAKE_SSH_RECORD": str(record),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return environment


def check_end_to_end_over_a_fake_ssh(module, directory: Path) -> None:
    _, _, _, runner_path = _configure(module, directory)
    pin = module.hostkey.fingerprint_of(RUNNER_HOST_KEY)
    _write(runner_path, _runner(pin))
    binaries = _fake_tools(directory)
    record = directory / "fake-ssh-record.json"
    calls = b"".join((
        _request(1, "helper_status", {}) + b"\n",
        _request(2, "target_scope", {"target": "device-a"}) + b"\n",
        _request(3, "ssh_read", {
            "target": "device-a", "platform": "fortios", "query": "system_status",
        }) + b"\n",
    ))
    completed = subprocess.run(
        [sys.executable, "-B", str(LAUNCHER)],
        cwd=directory,
        env=_proxy_environment(module, directory, binaries, record),
        input=calls,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    assert completed.stderr == b""
    answers = [
        json.loads(line) for line in completed.stdout.splitlines() if line.strip()
    ]
    status = next(
        item["result"]["structuredContent"] for item in answers if item["id"] == 1
    )
    assert status["target_aliases"] == ["device-a"]
    scope = next(
        item["result"]["structuredContent"] for item in answers if item["id"] == 2
    )
    assert scope["host_key_pinned"] is True
    assert scope["snmp_enrolled"] is True
    assert scope["ssh_platform"] == "fortinet"

    observed = json.loads(record.read_text(encoding="utf-8"))
    assert observed["known_hosts"] == (
        "runner.example.invalid ssh-ed25519 %s\n" % RUNNER_HOST_KEY
    )
    forwarded = [json.loads(item) for item in observed["requests"]]
    envelope = _envelope(observed["requests"][-1].encode())
    assert forwarded[-1]["params"]["name"] == "ssh_read"
    assert set(envelope) == {
        "alias", "host", "port", "login", "credential_kind", "secret",
        "host_key_fingerprint", "legacy_ssh", "account_role", "ssh_platform",
        "enabled_queries", "read_inventory", "sftp_roots",
        "fortios_output_standard_verified", "egress",
    }
    assert envelope["host_key_fingerprint"] == DEVICE_PIN
    assert envelope["credential_kind"] == "password"
    assert envelope["secret"] == DEVICE_SECRET
    for item in observed["argv"]:
        assert RUNNER_SECRET not in item
        assert DEVICE_SECRET not in item
    for value in observed["env"].values():
        assert RUNNER_SECRET not in value
        assert DEVICE_SECRET not in value
    assert observed["env"]["SSH_ASKPASS_REQUIRE"] == "force"

    record.unlink()
    _write(runner_path, _runner())
    refused = subprocess.run(
        [sys.executable, "-B", str(LAUNCHER)],
        cwd=directory,
        env=_proxy_environment(module, directory, binaries, record),
        input=calls,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert refused.returncode == 2
    assert refused.stdout == b""
    assert refused.stderr.decode() == (
        "netops_proxy_transport category=ssh_host_key message=%s\n"
        % module.SSH_HOST_KEY_FAILURE_MESSAGE
    )
    assert not record.exists()



FAKE_DEAD_SSH = """#!%s
import sys

sys.stderr.write("Error response from daemon: No such container: netops-helper" + chr(10))
sys.stderr.flush()
sys.exit(1)
"""


def check_a_dead_child_is_reported_while_stdin_stays_open(module, directory: Path) -> None:
    _, _, _, runner_path = _configure(module, directory)
    pin = module.hostkey.fingerprint_of(RUNNER_HOST_KEY)
    _write(runner_path, _runner(pin))
    binaries = _fake_tools(directory)
    dead = binaries / "ssh"
    dead.write_text(FAKE_DEAD_SSH % sys.executable, encoding="utf-8")
    dead.chmod(0o755)
    record = directory / "fake-ssh-record.json"
    process = subprocess.Popen(
        [sys.executable, "-B", str(LAUNCHER)],
        cwd=directory,
        env=_proxy_environment(module, directory, binaries, record),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        process.stdin.write(_request(1, "helper_status", {}) + b"\n")
        process.stdin.flush()
        lines: list[bytes] = []
        reader = threading.Thread(target=lambda: lines.append(process.stderr.readline()))
        reader.start()
        reader.join(timeout=10)
        assert not reader.is_alive(), "no diagnostic while the client kept stdin open"
        assert lines[0] == (
            "netops_proxy_transport category=remote_exec message=%s\n"
            % "The fixed remote container command could not start."
        ).encode()
    finally:
        process.stdin.close()
        code = process.wait(timeout=10)
    assert code != 0
    remaining = process.stderr.read()
    assert b"netops_proxy_transport" not in remaining


def _main_function_call_names(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    main_function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    names: set[str] = set()
    for node in ast.walk(main_function):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Attribute):
            names.add(target.attr)
        elif isinstance(target, ast.Name):
            names.add(target.id)
    return names


def check_shared_legacy_configuration_detection() -> None:
    proxy_calls = _main_function_call_names(SCRIPT)
    preflight_calls = _main_function_call_names(ROOT / "scripts" / "check_operator_config.py")
    assert "legacy_configuration_detail" in proxy_calls
    assert "legacy_configuration_detail" in preflight_calls


def main() -> int:
    module = _load_proxy()
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755
    assert module.DEFAULT_RATE_REQUESTS == 30
    expected_control = {"helper_status", "read_query_catalog", "target_scope"}
    expected_device = {
        "dns_probe", "tcp_probe", "icmp_probe", "tls_probe", "ssh_read",
        "snmp_get", "sftp_stat", "ftp_list",
    }
    assert module.CONTROL_TOOLS == expected_control
    assert module.DEVICE_TOOLS == expected_device
    assert set(module.TOOL_ARGUMENT_SCHEMAS) == expected_control | expected_device
    assert module.REMOTE_SERVER_TOOLS == (
        expected_control | expected_device
    ) - {"target_scope"}
    assert module.SSH_TOOLS == {"ssh_read", "sftp_stat"}
    assert len(module.TOOL_ARGUMENT_SCHEMAS) == 11
    assert module.SSH_TRANSPORT_FAILURE_MESSAGE == (
        "The remote MCP SSH transport failed."
    )
    assert module.RunnerFileError.public_message == (
        "The runner file is unavailable or invalid."
    )
    assert module.SSH_HOST_KEY_FAILURE_MESSAGE == (
        "SSH host-key verification failed."
    )
    assert module.REMOVED_VARIABLES == (
        "NETOPS_TARGET_POLICY_PATH", "NETOPS_KNOWN_HOSTS_PATH", "NETOPS_MASTER_ALIAS",
    )
    assert module.REMOVED_FILES == ("target-policy.json",)
    assert module._classify_ssh_stderr("unclassified failure") == (
        "ssh_transport", module.SSH_TRANSPORT_FAILURE_MESSAGE,
    )
    categories = {
        module.UnknownAliasError.category,
        module.PolicyRejectedError.category,
        module.RoleRejectedError.category,
        module.VaultPermissionError.category,
        module.VaultSchemaError.category,
        module.AuthenticationMaterialError.category,
        module.RateLimitError.category,
        module.PolicySchemaError.category,
        module.PolicyScopeError.category,
        module.RunnerFileError.category,
        module.LegacyConfigurationError.category,
    }
    assert len(categories) == 11
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        check_section_schema_and_consumer_binding(module, directory)
        check_credential_kinds_and_discovery_survive(module, directory)
        check_policy_parity_invalid_corpus(module, directory)
        check_scope_and_no_overinjection(module, directory)
        check_discovery_notifications_and_rate_cost(module, directory)
        check_exact_argument_schema_precedes_auth_rate_and_forward(module, directory)
        check_pre_auth_scope_for_query_slots_paths_and_alias(module, directory)
        check_query_authority_and_typed_pre_auth(module, directory)
        check_standalone_isolated_help(directory)
        check_batch_and_tools_list(module, directory)
        check_ssh_stderr_classification(module)
        check_runner_startup_preflight_categories(module, directory)
        check_ssh_launch_hardening(module, directory)
        check_end_to_end_over_a_fake_ssh(module, directory)
        check_a_dead_child_is_reported_while_stdin_stays_open(module, directory)
    check_shared_legacy_configuration_detection()
    print("proxy_contract_tests=passed")
    return 0


def test_dependency_free_proxy_contracts() -> None:
    assert main() == 0


if __name__ == "__main__":
    raise SystemExit(main())

