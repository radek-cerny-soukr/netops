"""Error branches of the engine, each entered by a real failure.

The device side is the substituted OpenSSH client of tests/conftest.py, the
SNMP stack is pysnmp itself, the FTP peer is the loopback server of
tests/test_ftp_wire_safety.py, the FTPS pin is read from real files and the FTP
watchdog shuts down a real socket. Where the standard library itself has to fail
(closing an FTP client), the failure is injected into ftplib, never into the engine. Each test checks what the operator finds in
the written audit log and what the caller receives after the failure.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import errno
from hashlib import sha256
import json
from pathlib import Path
import socket
from types import SimpleNamespace

from netops_core.audit import Recorder
import pytest

from conftest import EXEC_CLIENT, HOST_KEY_PIN, LOOPBACK, PASSWORD, _calls, _target, _write_client
import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper.auth import EgressPolicy, EgressScopeError
from test_ftp_wire_safety import _FTPServer, _target as _ftp_target

SNAPSHOT = "a" * 64


@pytest.fixture()
def audit_log(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    return path


def _written(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_audit(path: Path, event: str, statuses: list[str], detail: str | None = None) -> list[dict]:
    written = _written(path)
    assert [item["event"] for item in written] == [event] * len(statuses)
    assert [item["status"] for item in written] == statuses
    assert len({item["operation_id"] for item in written}) == 1
    if detail is not None:
        assert written[-1]["detail"] == detail
    assert PASSWORD not in path.read_text(encoding="utf-8")
    return written


def _device_output(wire, output: str, code: int = 0) -> None:
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=output, code=code))


def test_a_page_offset_inside_a_character_is_refused_and_audited(wire, audit_log) -> None:
    _device_output(wire, "é" * 1500)
    target = _target("fortinet", "system_status")
    first = engine.ssh_read(target, "fortinet", "system_status", None, 0, 1000)
    assert first["ok"] is True and first["next_offset"] == 1000
    assert first["untrusted_device_output"] == "é" * 500
    connections = len(_calls(wire))
    with pytest.raises(ValueError, match="offset is not a UTF-8 boundary; use next_offset"):
        engine.ssh_read(target, "fortinet", "system_status", None, 1001, 1000, first["content_sha256"])
    assert len(_calls(wire)) == connections
    written = _written(audit_log)
    assert [item["status"] for item in written] == ["started", "ok", "started", "failed"]
    assert written[-1]["detail"] == "ValueError"
    second = engine.ssh_read(target, "fortinet", "system_status", None, 1000, 1000, first["content_sha256"])
    assert second["pagination_source"] == "cached" and second["untrusted_device_output"] == "é" * 500


def test_a_continuation_with_an_invalid_page_size_is_audited_before_it_is_refused(wire, audit_log) -> None:
    target = _target("fortinet", "system_status")
    with pytest.raises(ValueError, match="max_bytes must be an integer between 1000 and 48000"):
        engine.ssh_read(target, "fortinet", "system_status", None, 5, 10, SNAPSHOT)
    written = _assert_audit(audit_log, "ssh_read", ["started", "failed"], "ValueError")
    assert written[0]["offset"] == 5 and written[0]["max_bytes"] == 10
    assert _calls(wire) == []


def _diagnostic_target() -> object:
    target = _target("fortinet", "system_status")
    return replace(target, read_inventory={
        "diagnostic_recipes": ("ping",), "addresses": ("192.0.2.183",), "interfaces": ("port2",),
    })


def _schema_registry(directory: Path, monkeypatch) -> None:
    library = directory / "library.json"
    library.write_text(json.dumps({
        "format": 1, "platform": "fortios", "hardware": "FortiGate-VM64-KVM", "os_version": "8.0.0",
        "build": "0167", "config": {"firewall address": {
            "kind": "table", "scope": "vdom", "available": True, "attrs": {"comment": {"type": "string"}},
        }},
    }))
    registry = directory / "registry.json"
    registry.write_text(json.dumps({"format": 1, "targets": {"wire-test": {
        "schema": "library.json", "sha256": sha256(library.read_bytes()).hexdigest(),
        "host_key_fingerprint": HOST_KEY_PIN,
    }}}))
    monkeypatch.setenv("NETOPS_SCHEMA_REGISTRY", str(registry))


def test_a_diagnostic_session_that_the_device_ends_is_a_closed_failure(wire, audit_log, tmp_path, monkeypatch) -> None:
    _schema_registry(tmp_path, monkeypatch)
    _device_output(wire, "Permission denied, please try again.\n", code=255)
    target = _diagnostic_target()
    with pytest.raises(ValueError) as refused:
        engine.fortios_diagnostics(target, "ping", "192.0.2.183", "port2", 1, 1, 1000)
    assert str(refused.value) == "bounded FortiOS diagnostic failed; the session was closed"
    assert refused.value.__cause__ is None and refused.value.__suppress_context__
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "failed"], "ValueError")
    calls = _calls(wire)
    assert len(calls) == 2 and calls[-1]["stdin_isatty"] is True


SCHEMA_DEVICE = """#!/usr/bin/env python3
import json, sys

with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:]}}) + "\\n")
command = sys.argv[-1]
if command == {failing!r}:
    sys.stderr.write("Connection to 127.0.0.1 closed by remote host.\\n")
    sys.exit(255)
if command == "get system status":
    sys.stdout.write("Version: FortiGate-VM64-KVM v8.0.0,build0167,release\\nCurrent virtual domain: root\\n")
sys.exit(0)
"""


@pytest.mark.parametrize(("failing", "message"), [
    ("get system status", "SSH schema identity read failed"),
    ("show full-configuration", "SSH schema snapshot read failed"),
])
def test_a_schema_read_whose_device_connection_fails_names_only_the_stage(
    wire, audit_log, tmp_path, monkeypatch, failing, message,
) -> None:
    _schema_registry(tmp_path, monkeypatch)
    _write_client(wire["binaries"], "ssh", SCHEMA_DEVICE.format(log=str(wire["log"]), failing=failing))
    target = replace(_target("fortinet", "system_status"), read_inventory={"schema_paths": ("firewall address",)})
    with pytest.raises(ValueError) as refused:
        engine.schema_read(target, "firewall address", "get", None, None, 0, 1000)
    assert str(refused.value) == message
    assert refused.value.__cause__ is None and refused.value.__suppress_context__
    _assert_audit(audit_log, "schema_read", ["started", "failed"], "ValueError")
    sent = [call["argv"][-1] for call in _calls(wire) if "-t" not in call["argv"]]
    assert sent[-1] == failing
    assert "show full-configuration" not in sent[:-1]


def _snmp_target() -> object:
    return replace(
        _target("fortinet", "system_status"), snmp_community="wire-community",
        egress=EgressPolicy(addresses=(LOOPBACK,), udp_ports=(161,)),
    )


def test_an_oid_the_snmp_stack_cannot_resolve_is_a_failed_answer(audit_log) -> None:
    target = _snmp_target()
    result = asyncio.run(engine.snmp_get(target, ["1.3.6.x"], 161))
    assert result["ok"] is False and result["target"] == "wire-test"
    assert result["error"].startswith("NoSuchObjectError: ")
    assert "wire-community" not in json.dumps(result)
    written = _assert_audit(audit_log, "snmp_get", ["started", "failed"])
    assert "wire-community" not in json.dumps(written)
    assert written[0]["item_count"] == 1


def test_an_ftps_pin_certificate_that_is_not_a_certificate_is_unreadable(tmp_path, monkeypatch) -> None:
    certificates = tmp_path / "certs"
    certificates.mkdir()
    certificate = certificates / "pinned.crt"
    certificate.write_text("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")
    pins = tmp_path / "tls-pins.json"
    pins.write_text(json.dumps({"device-a": {"sha256": "0" * 64, "certificate": str(certificate)}}))
    monkeypatch.setattr(engine, "TLS_PINS_PATH", pins)
    monkeypatch.setattr(engine, "TLS_CERT_DIR", certificates)
    with pytest.raises(engine.FtpsPinError, match="^FTPS pin certificate is unreadable$") as refused:
        engine._ftps_context("device-a")
    assert isinstance(refused.value.__cause__, OSError)


def test_an_ftps_pin_certificate_path_that_cannot_be_resolved_is_unavailable(tmp_path, monkeypatch) -> None:
    certificates = tmp_path / "certs"
    certificates.mkdir()
    pins = tmp_path / "tls-pins.json"
    pins.write_text(json.dumps({"device-a": {"sha256": "0" * 64, "certificate": str(certificates) + "/pin\u0000.crt"}}))
    monkeypatch.setattr(engine, "TLS_PINS_PATH", pins)
    monkeypatch.setattr(engine, "TLS_CERT_DIR", certificates)
    with pytest.raises(engine.FtpsPinError, match="^FTPS pin certificate is unavailable$"):
        engine._ftps_context("device-a")


def test_the_ftp_watchdog_survives_a_control_socket_that_was_never_connected(monkeypatch) -> None:
    monkeypatch.setattr(engine, "_FTP_TOTAL_TIMEOUT_SECONDS", 30)
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    budget = engine._FTPBudget(SimpleNamespace(sock=control))
    try:
        with pytest.raises(OSError) as unconnected:
            control.shutdown(socket.SHUT_RDWR)
        assert unconnected.value.errno == errno.ENOTCONN
        budget.data = control
        budget._expire()
        assert budget.expired is True
        with pytest.raises(TimeoutError, match="total time budget"):
            budget.remaining()
    finally:
        budget.close()
        control.close()


def _closing_fails(monkeypatch) -> list:
    closed: list = []
    original = engine.ftplib.FTP.close

    def close(client) -> None:
        original(client)
        closed.append(type(client).__name__)
        raise OSError(errno.EBADF, "Bad file descriptor")

    monkeypatch.setattr(engine.ftplib.FTP, "close", close)
    return closed


def _free_loopback_port() -> int:
    probe = socket.socket()
    probe.bind((LOOPBACK, 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_a_refused_ftp_connection_is_reported_when_closing_the_client_fails(audit_log, monkeypatch) -> None:
    closed = _closing_fails(monkeypatch)
    port = _free_loopback_port()
    target = _ftp_target("plain-device", port, port)
    result = engine.ftp_list(target, "/safe", use_tls=False, port=port, acknowledge_unencrypted=True)
    assert closed == ["FTP"]
    assert result["ok"] is False and result["failure_stage"] == "connect"
    assert result["error_type"] == "ConnectionRefusedError"
    assert "credential" not in json.dumps(result)
    _assert_audit(audit_log, "ftp_list", ["started", "failed"])


def test_a_passive_port_outside_the_allowlist_is_refused_when_closing_the_client_fails(
    audit_log, monkeypatch,
) -> None:
    closed = _closing_fails(monkeypatch)
    server = _FTPServer()
    target = _ftp_target("plain-device", server.port, server.data_port + 1)
    try:
        with pytest.raises(EgressScopeError, match="FTP passive port is outside the target egress allowlist"):
            engine.ftp_list(target, "/safe", use_tls=False, port=server.port, acknowledge_unencrypted=True)
    finally:
        server.close()
    assert closed == ["FTP"]
    assert server.data_failures == []
    _assert_audit(audit_log, "ftp_list", ["started", "failed"], "EgressScopeError")
