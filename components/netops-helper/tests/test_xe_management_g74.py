"""G56/G74 public reads with IOS and IOS XE CLI captures and only SSH replaced."""

import asyncio
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

from fastmcp import Client
import pytest

from netops_helper import engine, server
import test_proxy_contracts as contracts

FIXTURES = Path(__file__).parent / "fixtures/real/cisco_xe/g74"
G56 = FIXTURES.parents[1] / "cisco_ios" / "g56"
DEVICES = {path.stem: json.loads(path.read_text()) for path in (
    FIXTURES / "iolxe.json", FIXTURES / "iolxe-l2.json", *sorted(G56.glob("*.json")),
)}
LAB = {name: device["captures"] for name, device in DEVICES.items()}
PLATFORMS = {name: device.get("profile", "cisco_xe") for name, device in DEVICES.items()}
CASES = {
    "aaa_servers": ("show aaa servers", "empty", ""),
    "radius_statistics": ("show radius statistics", "ok", "Maximum inQ length:"),
    "tacacs_statistics": ("show tacacs", "empty", ""),
    "snmp_statistics": ("show snmp", "not_applicable", "%SNMP agent not enabled"),
    "snmp_engine_id": ("show snmp engineID", "not_applicable", "%SNMP agent not enabled"),
    "dns_hosts": ("show hosts", "ok", "Name servers are"),
    "users": ("show users", "ok", "Host(s)"),
    "ssh_sessions": ("show ssh", "ok", "Session started"),
    "lines": ("show line", "ok", "Overruns"),
}


@pytest.fixture
def device(tmp_path, monkeypatch):
    proxy = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(proxy, tmp_path)

    def setup(node, query, *, role="RO", body=None, version=None, stderr="", rc=0, expect_suppressed_banner=False):
        calls = []
        command = CASES[query][0]
        output = {row["command"]: row["stdout"] for row in LAB[node] if row["role"] == role}
        if body is not None:
            output[command] = body
        if version is not None:
            output["show version"] = output["show version"].replace("17.18.2", version)

        def ssh(address, port, login, credential, key, sent, **options):
            calls.append(sent)
            if expect_suppressed_banner:
                assert options.get("suppress_login_banner") is True
            command_rc, command_stderr = (rc, stderr.encode()) if sent == command else (0, b"")
            return engine.core_ssh.Result(rc=command_rc, stdout=output[sent].encode(), stderr=command_stderr,
                                          said="", started_at="", finished_at="")

        monkeypatch.setattr(engine.core_ssh, "run_command", ssh)
        monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
        monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
        monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
        platform = PLATFORMS[node]
        section = dict(contracts._section(), ssh_platform=platform, snmp_credential=None,
                       enabled_queries=[query])
        section["egress"]["tcp_ports"].append(22)
        if role == "ADMIN":
            section.update(account_role="admin-bounded", role_boundary="catalogue")
            if platform == "cisco_ios":
                section.update(read_inventory={}, sftp_roots=[])
        contracts._write(inventory, contracts._inventory(contracts._device(section, platform)))
        return proxy.Proxy(), calls

    return setup


def read(relay, query, *, platform="cisco_xe", **options):
    async def run():
        async with Client(server.mcp) as client:
            arguments = {"target": "device-a", "platform": platform, "query": query, **options}
            forwarded = relay.request(contracts._request(1, "ssh_read", arguments))
            assert forwarded is not None
            message = json.loads(forwarded)
            result = await client.call_tool("ssh_read", message["params"]["arguments"])
            assert not result.is_error
            wire = relay.response(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {
                "structuredContent": result.data, "isError": False,
                "content": [{"type": "text", "text": json.dumps(result.data)}],
            }}).encode())
            return json.loads(wire)["result"]["structuredContent"]

    return asyncio.run(run())


@pytest.mark.parametrize("node", LAB)
@pytest.mark.parametrize("query", CASES)
def test_management_capture(device, node, query):
    command, status, expected = CASES[query]
    relay, calls = device(node, query, role="ADMIN" if query == "snmp_engine_id" else "RO")
    reply = read(relay, query, platform=PLATFORMS[node])
    assert calls == ["show version", command]
    assert reply["ok"] and reply["status"] == status and reply["next_offset"] is None
    assert reply["firmware_support"]["status"] == "tested"
    output = reply["untrusted_device_output"].lower()
    if query == "dns_hosts" and PLATFORMS[node] == "cisco_ios":
        assert "address(es)" in output and "static mappings" in output
    else:
        assert expected.lower() in output
    if status == "empty":
        assert not reply["untrusted_device_output"].strip()
    assert reply["normalized"]["coverage"]["complete"]


@pytest.mark.parametrize("node", LAB)
def test_engine_id_is_refused_for_read_only_account(device, node):
    relay, calls = device(node, "snmp_engine_id")
    reply = read(relay, "snmp_engine_id", platform=PLATFORMS[node])
    assert calls == ["show version", "show snmp engineID"]
    assert not reply["ok"] and reply["status"] == "permission_denied"
    assert not reply["normalized"]["coverage"]["complete"]


@pytest.mark.parametrize("query", ["aaa_servers", "tacacs_statistics"])
@pytest.mark.parametrize("rc,extra,expected", [
    (0, "", True),
    (0, "AAA command interrupted\n", False),
    (1, "", False),
])
def test_empty_aaa_checks_exit_and_ssh_diagnostics(device, query, rc, extra, expected):
    notice = "Connection to 192.0.2.10 closed by remote host.\n"
    relay, _ = device("iolxe", query, stderr=notice + extra, rc=rc, expect_suppressed_banner=True)
    reply = read(relay, query)
    assert reply["ok"] is expected
    if expected:
        assert reply["status"] == "empty" and reply["untrusted_device_output"].strip() == ""
    else:
        assert reply["error_code"] == "device_cli_error"


@pytest.mark.parametrize("node", ["iolxe", "d-iosv"])
@pytest.mark.parametrize("query", CASES)
def test_incomplete_management_capture(device, node, query):
    command = CASES[query][0]
    body = next(row["stdout"] for row in LAB[node] if row["command"] == command and row["role"] == "ADMIN")
    relay, _ = device(node, query, body=body.rstrip() + "\n--More--\n")
    reply = read(relay, query, platform=PLATFORMS[node])
    assert reply["status"] == "truncated"
    assert not reply["complete"] and not reply["normalized"]["coverage"]["complete"]


@pytest.mark.parametrize("query,field", [
    ("aaa_servers", "State: current UP"),
    ("tacacs_statistics", "Socket errors:"),
    ("snmp_statistics", "13 Trap PDUs"),
    ("snmp_engine_id", "123456789ABCDEF000000000"),
])
def test_documented_operational_fields(device, query, field):
    role = "ADMIN" if query == "snmp_engine_id" else "RO"
    relay, _ = device("iolxe", query, role=role, body=(FIXTURES / f"{query}.out").read_text())
    reply = read(relay, query)
    assert reply["ok"] and field in reply["untrusted_device_output"]


def test_untested_firmware_warns_without_blocking(device):
    relay, calls = device("iolxe", "dns_hosts", version="17.99.1")
    reply = read(relay, "dns_hosts")
    assert calls == ["show version", "show hosts"]
    assert reply["ok"] and "Name servers are" in reply["untrusted_device_output"]
    assert reply["firmware_support"]["status"] == "untested"
    assert [warning["code"] for warning in reply["warnings"]] == ["firmware_untested"]


@pytest.mark.parametrize("query,label", [
    ("aaa_servers", "RADIUS shared key:"),
    ("tacacs_statistics", "Key ="),
    ("snmp_statistics", "SNMP community name:"),
])
def test_credentials_are_hidden_before_paging_and_hashing(device, query, label):
    text = (FIXTURES / f"{query}.out").read_text()
    # Derived from the documented excerpt and long enough for a continuation.
    prefix = text * (1000 // len(text))
    first = "g74-canary-fragment remaining-credential"
    second = "g74-another-fragment another-credential"
    replies = []
    for value in (first, second):
        relay, calls = device("iolxe", query, body=f'{prefix}{label} "{value}"\n{text}')
        page = read(relay, query, max_bytes=1000)
        tail = read(relay, query, max_bytes=1000, offset=page["next_offset"],
                    content_sha256=page["content_sha256"])
        assert calls == ["show version", CASES[query][0]]
        wire = json.dumps([page, tail])
        assert not any(part in wire for part in value.split())
        body = page["untrusted_device_output"] + tail["untrusted_device_output"]
        assert body.endswith(text) or ("13 Trap PDUs" in body and query == "snmp_statistics")
        assert page["content_sha256"] == hashlib.sha256(body.encode()).hexdigest()
        replies.append(body)
    assert replies[0] == replies[1]


@pytest.mark.parametrize("query,credential,field", [
    ("tacacs_statistics", "Key: qZ", "Socket errors:"),
    ("snmp_statistics", "SNMP community name: qZ", "13 Trap PDUs"),
    ("snmp_statistics", "Destination: 192.0.2.80, V2C community: qZ", "Destination: 192.0.2.80"),
])
def test_short_secret_and_pager_keep_their_meaning(device, query, credential, field):
    text = (FIXTURES / f"{query}.out").read_text()
    relay, _ = device("iolxe", query, body=f"{text}{credential} --More--")
    result = read(relay, query)
    assert result["status"] == "truncated" and not result["complete"]
    assert "qZ" not in json.dumps(result) and field in result["untrusted_device_output"]


@pytest.mark.parametrize("node", ["d-iosv", "d-iolxe"])
@pytest.mark.parametrize("query,secret_row", [
    ("aaa_servers", 'radius server UDP key 7 "qZ wrapped secret value"'),
    ("radius_statistics", "server-key 7 qZ"),
    ("tacacs_statistics", "TACACS+ Server: 192.0.2.50/49, pac key qZ"),
    ("snmp_statistics", "private-read qZ RW"),
    ("snmp_statistics", "snmp-server user myuser grp v3 auth sha qZ priv aes 128 pZ"),
    ("snmp_engine_id", "deadbeefdeaf 192.0.2.80 162"),
    ("dns_hosts", "username user01 secret 5 qZ"),
    ("users", "netops-ro password 7 qZ"),
    ("ssh_sessions", "0 2.0 IN chacha20-polqZ Session started remote"),
    ("lines", " password 7 qZ"),
])
def test_unknown_management_rows_fail_closed(device, node, query, secret_row):
    command = CASES[query][0]
    if query in {"snmp_statistics", "snmp_engine_id"}:
        baseline = (FIXTURES / f"{query}.out").read_text()
    else:
        baseline = next(row["stdout"] for row in LAB[node] if row["command"] == command and row["role"] == "RO")
    relay, calls = device(node, query, body=secret_row + "\n" + baseline)
    reply = read(relay, query, platform=PLATFORMS[node])
    assert calls == ["show version", command]
    assert reply["ok"] and reply["status"] == "unparsed" and not reply["complete"]
    assert "[redacted]" in reply["untrusted_device_output"]
    assert all(canary not in json.dumps(reply) for canary in ("qZ", "pZ", "deadbeefdeaf", "wrapped secret value"))


def test_ios_privileged_snmp_alias_refuses_other_tools(device, capsys):
    relay, calls = device("d-iosv", "snmp_engine_id", role="ADMIN")
    for tool, args in [
        ("ssh_read", {"platform": "cisco_ios", "query": "users"}),
        ("config_read", {"platform": "cisco_ios"}),
        ("dns_probe", {"hostname": "example.test"}),
    ]:
        raw = relay.request(contracts._request(10, tool, {"target": "device-a", **args}))
        returned = raw or capsys.readouterr().out
        assert "error" in json.loads(returned)
    assert calls == []


def test_populated_dns_cache_keeps_static_and_wrapped_addresses(device):
    body = (G56 / "dns_hosts_populated.out").read_text()
    relay, _ = device("d-iosv", "dns_hosts", body=body)
    reply = read(relay, "dns_hosts", platform="cisco_ios")
    assert reply["status"] == "ok" and reply["complete"]
    for value in ("192.0.2.220", "192.0.2.111", "192.0.2.112", "host02.example"):
        assert value in reply["untrusted_device_output"]


@pytest.mark.parametrize("query", ["aaa_servers", "tacacs_statistics"])
def test_ios_requires_complete_fields_for_each_aaa_server(device, query):
    fixture = (FIXTURES / f"{query}.out").read_text()
    header = next(line for line in fixture.splitlines() if line.startswith(("RADIUS: id", "Tacacs+ Server")))
    relay, _ = device("d-iosv", query, body=fixture.rstrip() + "\n\n" + header + "\n")
    reply = read(relay, query, platform="cisco_ios")
    assert reply["ok"] and not reply["complete"]
    assert reply["status"] == "unparsed" and header in reply["untrusted_device_output"]


@pytest.mark.parametrize("node", ["d-iosv", "iolxe"])
def test_management_classifies_zero_exit_permission_refusal_before_projection(device, node):
    captured = next(row["stdout"] for row in LAB[node]
                    if row["command"] == "show aaa servers" and row["role"] == "RO")
    relay, calls = device(node, "aaa_servers", body="Error: Permission denied\n" + captured, rc=0)
    reply = read(relay, "aaa_servers", platform=PLATFORMS[node])
    assert calls == ["show version", "show aaa servers"]
    assert reply["ok"] is False and reply["status"] == "permission_denied"
    assert reply["normalized"]["status"] == "permission_denied"
    assert not reply["complete"]
