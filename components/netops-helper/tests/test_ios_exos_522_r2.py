"""Run the real Helper read path against fake SSH replies with separate streams."""

import json
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine
from netops_helper.query_catalog import READ_QUERIES


FIXTURES = Path(__file__).parent / "fixtures"
DOCS = FIXTURES / "docs/cisco_ios/ios-exos-522-r2"
PLATFORMS = ("cisco_ios", "cisco_xe", "extreme_exos")
PQ_WARNING = (FIXTURES / "transport/openssh_pq_warning.stderr").read_bytes()
HOST_KEY_WARNING = b"Warning: Permanently added '192.0.2.10' (ED25519) to the list of known hosts.\n"


def ssh_read(monkeypatch, platform, query, stdout, *, stderr=b"", rc=0, version=None, table=None):
    identity = (FIXTURES / "identity" / f"{platform}.txt").read_bytes()
    if version is not None:
        # DERIVED from the IOS identity fixture. The model is deliberately left unchanged.
        identity = identity.replace(b"12.2(0.0.16)FX", version.encode())
    command = READ_QUERIES[platform][query].command
    calls = []

    def run_command(address, port, login, credential, known_hosts, sent, **options):
        calls.append(sent)
        if sent == "show version":
            return engine.core_ssh.Result(0, identity, "", "", "")
        assert sent == command
        return engine.core_ssh.Result(rc, stdout, "", "", "", stderr=stderr)

    monkeypatch.setattr(engine.core_ssh, "run_command", run_command)
    auth = _target(platform, query)
    if table is None:
        result = engine.ssh_read(auth, platform, query, {}, 0, 48000)
    else:
        result = engine.normalized_query(auth, platform, query, table)
    assert calls == ["show version", command]
    return result


@pytest.mark.parametrize(("platform", "refusal"), [
    ("extreme_exos", (FIXTURES / "real/g02_20261117/x440-show_configuration.out").read_bytes()),
    ("cisco_ios", b"% Invalid input detected at '^' marker.\n"),
    ("cisco_xe", b"% Authorization failed.\n"),
])
@pytest.mark.parametrize("with_stdout", [False, True], ids=["stderr-only", "both-streams"])
def test_empty_allowed_refusal_on_stderr(wire, monkeypatch, platform, refusal, with_stdout):
    # DERIVED stream placement and rc from the review reproduction. The EXOS denial
    # text comes from a real RO capture. IOS notices use the shapes in test_refusal_semantics.
    table = json.loads((FIXTURES / "tables" / f"{platform}.json").read_text())
    stdout = table["mac_entry"].encode() if with_stdout else b""
    result = ssh_read(monkeypatch, platform, "mac_table", stdout, stderr=refusal + b"SSH diagnostic\n")
    assert result["rc"] == 0
    assert result["ok"] is False and result["error_code"] == "device_cli_error"
    assert result["status"] == "permission_denied"
    assert "SSH diagnostic" not in result.get("untrusted_device_output", "")


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_xe"])
@pytest.mark.parametrize("table", [None, "mac_entry"], ids=["raw", "normalized"])
def test_tacacs_refusal_on_stderr(wire, monkeypatch, platform, table):
    stderr = (DOCS / "tacacs_denied.out").read_bytes()
    result = ssh_read(monkeypatch, platform, "mac_table", b"", stderr=stderr, table=table)
    assert result["ok"] is False
    assert result["error_code"] == "device_cli_error"
    assert result["status"] == "permission_denied"


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("stderr", [b"", PQ_WARNING + HOST_KEY_WARNING], ids=["silent", "ssh-warnings"])
def test_empty_allowed_accepts_only_known_ssh_warnings(wire, monkeypatch, platform, stderr):
    result = ssh_read(monkeypatch, platform, "mac_table", b"", stderr=stderr)
    assert result["ok"] is True and result["status"] == "empty"
    assert result["normalized"]["records"] == []
    assert result["untrusted_device_output"] == ""


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("stderr", [b"SSH diagnostic\n", PQ_WARNING + b"Warning: command failed\n", b"\n"],
                         ids=["unknown", "mixed", "nonempty-whitespace"])
def test_empty_allowed_fails_on_unknown_stderr(wire, monkeypatch, platform, stderr):
    result = ssh_read(monkeypatch, platform, "mac_table", b"", stderr=stderr)
    assert result["rc"] == 0
    assert result["ok"] is False
    assert result["status"] == "unparsed" and result["error_code"] == "device_cli_error"
    assert not result.get("untrusted_device_output")


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("stderr", [PQ_WARNING, b"SSH diagnostic\n"], ids=["ssh-warning", "unknown"])
def test_empty_normalized_table_checks_stderr(wire, monkeypatch, platform, stderr):
    table = json.loads((FIXTURES / "tables" / f"{platform}.json").read_text())["mac_entry"]
    # DERIVED from the corresponding platform capture by retaining only the MAC table headings.
    header = "\n".join(table.splitlines()[:2 if platform == "extreme_exos" else 5]) + "\n"
    result = ssh_read(monkeypatch, platform, "mac_table", header.encode(), stderr=stderr, table="mac_entry")
    assert result["records"] == []
    if stderr == PQ_WARNING:
        assert result["ok"] is True and result["status"] == "empty"
    else:
        assert result["ok"] is False
        assert result["status"] == "unparsed" and result["error_code"] == "device_cli_error"
        assert result["coverage"]["complete"] is False


@pytest.mark.parametrize("stderr", [PQ_WARNING, b"SSH diagnostic\n"], ids=["ssh-warning", "unknown"])
def test_empty_table_in_raw_read_checks_stderr(wire, monkeypatch, stderr):
    # DERIVED by retaining just the legend and headings from Cisco's LACP example.
    body = (FIXTURES / "docs/cisco_ios/g53/lacp_internal.out").read_bytes()
    header = body.split(b"Gi2/0/1", 1)[0]
    result = ssh_read(monkeypatch, "cisco_ios", "lacp_internal", header, stderr=stderr)
    if stderr == PQ_WARNING:
        assert result["ok"] is True and result["status"] == "empty"
    else:
        assert result["ok"] is False
        assert result["status"] == "unparsed" and result["error_code"] == "device_cli_error"


@pytest.mark.parametrize("complete", [False, True], ids=["missing-bridged", "both-rows"])
def test_asr901_ipv6_requires_both_rows(wire, monkeypatch, complete):
    body = (DOCS / "asr901_load_balance.out").read_bytes()
    if not complete:
        body = b"".join(body.splitlines(keepends=True)[:-1])
    result = ssh_read(monkeypatch, "cisco_ios", "etherchannel_load_balance", body, version="15.1(2)SNG")
    assert result["status"] == ("ok" if complete else "unparsed")
    assert result["normalized"]["coverage"]["complete"] is complete
    assert result["load_balance"]["method"] == "src-dst-mac"
    assert "(routed packets)" in result["load_balance"]["ipv6"]
    assert ("(bridged packets)" in result["load_balance"]["ipv6"]) is complete


@pytest.mark.parametrize(("version", "terminated", "method"), [
    ("12.1(6)EA2c", True, "Source MAC address"),
    ("12.1(6)EA2c", False, "Source MAC address"),
    ("12.1(9)EA1", True, "Destination MAC address"),
    ("12.1(6)EA2c", True, "Source MAC"),
])
def test_legacy_single_line_method(wire, monkeypatch, version, terminated, method):
    body = (DOCS / "catalyst2950_load_balance.out").read_bytes()
    body = body.replace(b"Source MAC address", method.encode())
    if not terminated:
        body = body.removesuffix(b"\n")
    complete = terminated and method.endswith(" address")
    result = ssh_read(monkeypatch, "cisco_ios", "etherchannel_load_balance", body, version=version)
    assert result["status"] == ("ok" if complete else "unparsed")
    assert result["normalized"]["coverage"]["complete"] is complete
    if complete:
        assert result["load_balance"]["method"] == method
        assert all(result["load_balance"][key] is None for key in ("non_ip", "ipv4", "ipv6"))
