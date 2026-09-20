from __future__ import annotations

import asyncio
from base64 import b64encode
from dataclasses import replace
import ipaddress
import json
import os
import re
import stat
import sys
import types

from netops_core.audit import Recorder
from netops_core.hostkey import fingerprint_of
import pytest

import netops_helper.audit as audit
from netops_helper.audit import AuditPostOperationError, AuditPreflightError

from netops_helper.auth import (
    LEGACY_SSH_PROFILES, AuthenticationContextError, AuthenticationMaterialError,
    EgressPolicy, EgressScopeError, LegacySshProfileRequired, PolicyScopeError, TargetAuth,
)
import netops_helper.engine as engine
from netops_helper.read_policy import READ_QUERIES


TEST_ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 20))
HOST_KEY_BLOB = b64encode(b"offered-host-key-material").decode("ascii")
HOST_KEY_PIN = fingerprint_of(HOST_KEY_BLOB)
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "replace-me\n" * 4 + "-----END OPENSSH PRIVATE KEY-----\n"


HOST_KEY_LINE = f"{TEST_ADDRESS} ssh-ed25519 {HOST_KEY_BLOB}"


def known_hosts_line(host: str, port: int) -> str:
    name = host if port == 22 else f"[{host}]:{port}"
    return f"{name} ssh-ed25519 {HOST_KEY_BLOB}"


def offered_scan(scanned: list | None = None):
    def scan(host, port, pin, timeout_seconds, run=None):
        if scanned is not None:
            scanned.append((host, port, pin, timeout_seconds))
        return known_hosts_line(host, port)

    return scan


def refusing_scan(message: str = "no offered host key matches the pinned fingerprint"):
    def scan(host, port, pin, timeout_seconds, run=None):
        raise engine.core_hostkey.HostKeyError(message)

    return scan


@pytest.fixture(autouse=True)
def pinned_host_key(monkeypatch) -> None:
    monkeypatch.setattr(engine.core_hostkey, "scan", offered_scan())


class FakeSshResult:
    def __init__(self, rc: int = 0, stdout: bytes = b"") -> None:
        self.rc = rc
        self.stdout = stdout
        self.said = ""
        self.started_at = "2026-09-17T08:00:00Z"
        self.finished_at = "2026-09-17T08:00:01Z"


def recording_run_command(captured: list, answer=None, error=None):
    def run_command(host, port, login, credential, host_key_line, command, **options):
        captured.append({
            "host": host, "port": port, "login": login, "command": command,
            "credential_kind": credential.kind, "secret": credential.use(),
            "host_key_line": host_key_line, **options,
        })
        if error is not None:
            raise error
        return FakeSshResult() if answer is None else answer

    return run_command


def auth(
    *,
    fortios_verified: bool = True,
    legacy_ssh: str | None = None,
    credential_kind: str = "password",
    secret: str = "credential",
) -> TargetAuth:
    return TargetAuth(
        alias="device-a",
        host=TEST_ADDRESS,
        port=22,
        login="reader",
        secret=secret,
        host_key_fingerprint=HOST_KEY_PIN,
        credential_kind=credential_kind,
        sftp_roots=("/safe",),
        read_inventory={"interfaces": ("port3",)},
        account_role="read-only",
        fortios_output_standard_verified=fortios_verified,
        ssh_platform="fortinet",
        enabled_queries=("interface_details",),
        egress=EgressPolicy(
            addresses=(TEST_ADDRESS,),
            tcp_ports=(21, 443),
            udp_ports=(161,),
            tcp_port_ranges=((50_000, 50_010),),
            allow_icmp=True,
        ),
        legacy_ssh=legacy_ssh,
    )


def test_ssh_cache_key_binds_the_credential_and_audit_platform_is_canonical() -> None:
    base = auth()
    assert engine._ssh_cache_key(base, "fortinet", "q", None) != engine._ssh_cache_key(
        replace(base, secret="other-credential"), "fortinet", "q", None,
    )
    fields = engine._audit_fields({"platform": "fortios", "query": "system_status"}, {})
    assert fields["platform"] == "fortinet"
    assert engine._audit_fields({"platform": "not-a-platform"}, {})["platform"] == "not-a-platform"


def test_exec_read_scans_and_connects_to_the_resolved_address(monkeypatch) -> None:
    scanned: list = []
    captured: list = []
    named = replace(
        auth(), host="device.example.invalid", egress=replace(auth().egress, allow_dns=True),
    )
    monkeypatch.setattr(
        engine.socket, "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, (TEST_ADDRESS, 0))],
    )
    monkeypatch.setattr(engine.core_hostkey, "scan", offered_scan(scanned))
    monkeypatch.setattr(
        engine.core_ssh, "run_command",
        recording_run_command(captured, FakeSshResult(0, b"answer")),
    )
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("the exec transport opens no socket of its own")
        ),
    )
    assert engine.read_from_device(named, "fortinet", "get system status") == (0, "answer")
    assert scanned == [(TEST_ADDRESS, 22, HOST_KEY_PIN, engine._HOST_KEY_SCAN_TIMEOUT_SECONDS)]
    assert [call["host"] for call in captured] == [TEST_ADDRESS]
    assert captured[0]["host_key_line"] == HOST_KEY_LINE
    assert captured[0]["login"] == "reader"
    assert captured[0]["legacy_ssh"] is None
    assert captured[0]["timeout_seconds"] == engine._SSH_READ_TIMEOUT_SECONDS


def test_exec_read_returns_the_output_of_a_nonzero_exit_status(monkeypatch) -> None:
    monkeypatch.setattr(
        engine.core_ssh, "run_command",
        recording_run_command([], FakeSshResult(250, b"Port: 1\n")),
    )
    assert engine.read_from_device(auth(), "extreme_exos", "show sharing") == (
        250, "Port: 1\n",
    )


def test_a_transport_failure_of_the_client_still_refuses(monkeypatch) -> None:
    monkeypatch.setattr(
        engine.core_ssh, "run_command",
        recording_run_command([], error=engine.core_ssh.SshError("ssh failed", 255, "denied")),
    )
    with pytest.raises(engine.core_ssh.SshError):
        engine.read_from_device(auth(), "linux", "hostname")


def test_the_extreme_exos_read_sends_only_the_query(monkeypatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    engine.read_from_device(auth(), "extreme_exos", "show version")
    assert [call["command"] for call in captured] == ["show version"]
    assert {call["host_key_line"] for call in captured} == {HOST_KEY_LINE}


def test_a_populated_platform_preamble_is_still_sent_before_the_query(monkeypatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    monkeypatch.setattr(engine, "_PLATFORM_PREAMBLE", {"fortinet": ("terminal length 0",)})
    engine.read_from_device(auth(), "fortinet", "get system status")
    assert [call["command"] for call in captured] == [
        "terminal length 0", "get system status",
    ]
    assert {call["host_key_line"] for call in captured} == {HOST_KEY_LINE}


def test_transport_table_matches_the_canonical_authority() -> None:
    assert set(engine._SSH_TRANSPORTS) == set(READ_QUERIES)
    assert engine._SSH_TRANSPORTS["ruckus_unleashed"] == "pty"
    assert all(
        transport == "exec"
        for platform, transport in engine._SSH_TRANSPORTS.items()
        if platform != "ruckus_unleashed"
    )
    assert engine._PLATFORM_PREAMBLE == {}


@pytest.mark.parametrize(
    "platform",
    (
        "linux", "fortinet", "extreme_exos", "cisco_ios", "cisco_xe", "cisco_nxos",
        "arista_eos", "juniper_junos", "juniper_junos_els",
    ),
)
def test_every_exec_platform_sends_only_its_preamble_and_the_query(
    monkeypatch, platform,
) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    engine.read_from_device(auth(), platform, "show version")
    assert [call["command"] for call in captured] == [
        *engine._PLATFORM_PREAMBLE.get(platform, ()), "show version",
    ]


def test_fortios_read_requires_verified_output_standard(monkeypatch) -> None:
    monkeypatch.setattr(
        engine.core_ssh, "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("the client must not start")
        ),
    )
    with pytest.raises(ValueError, match="output standard"):
        engine.read_from_device(auth(fortios_verified=False), "fortios", "get system status")


def test_ssh_continuation_uses_cache_without_second_login(monkeypatch) -> None:
    calls = []

    def fake_read(target, platform, command):
        calls.append(command)
        return 0, "x" * 1500

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    first = engine.ssh_read(auth(), "fortios", "interface_details", {"interface": "port3"}, 0, 1000)
    second = engine.ssh_read(
        auth(), "fortios", "interface_details", {"interface": "port3"}, first["next_offset"], 1000,
    )
    assert first["pagination_source"] == "fresh"
    assert second["pagination_source"] == "cached"
    assert second["complete"] is True
    assert len(calls) == 1


def test_every_device_function_has_audit_wrapper() -> None:
    names = (
        "dns_probe", "tcp_probe", "icmp_probe", "tls_probe",
        "ssh_read", "snmp_get", "sftp_stat", "ftp_list",
    )
    assert all(hasattr(getattr(engine, name), "__wrapped__") for name in names)


def test_generic_body_read_functions_are_absent_from_phase1_engine() -> None:
    for name in ("https_get", "sftp_read_text", "_read_https_snapshot", "_read_sftp_snapshot"):
        assert not hasattr(engine, name)


def test_route_trace_is_absent_from_phase1_engine() -> None:
    assert not hasattr(engine, "route_trace")


def test_ssh_query_policy_rejects_before_connection_with_audit_names(monkeypatch) -> None:
    events = []
    monkeypatch.setattr(
        engine, "record",
        lambda event, **kwargs: events.append({"event": event, **kwargs}),
    )
    monkeypatch.setattr(
        engine, "read_from_device",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("SSH connection must not open")
        ),
    )
    with pytest.raises(PolicyScopeError):
        engine.ssh_read(auth(), "fortios", "routing_table", None, 0, 1000)
    assert [(item["status"], item["platform"], item["query"]) for item in events] == [
        ("started", "fortinet", "routing_table"),
        ("failed", "fortinet", "routing_table"),
    ]
    assert all("parameters" not in item and "path" not in item for item in events)


def test_public_argument_types_fail_before_transport(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        engine, "_resolve_target_ipv4",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("transport resolution must not start")
        ),
    )
    target = replace(auth(), snmp_community="snmp-secret")
    calls = (
        lambda: engine.tcp_probe(target, 443, True),
        lambda: engine.tcp_probe(target, 443, float("nan")),
        lambda: engine.icmp_probe(target, "4"),
        lambda: engine.tls_probe(target, 443, 7),
        lambda: engine.ssh_read(
            target, "fortios", "interface_details", {"interface": 3}, 0, 1000,
        ),
        lambda: asyncio.run(engine.snmp_get(target, ("1.3.6",), 161)),
        lambda: asyncio.run(engine.sftp_stat(target, "/safe//log")),
        lambda: engine.ftp_list(target, "/safe", 1, 21, False),
    )
    for call in calls:
        with pytest.raises(ValueError):
            call()


def test_tcp_scope_rejects_before_socket(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("socket must not open")
        ),
    )
    with pytest.raises(EgressScopeError):
        engine.tcp_probe(auth(), 444, 1)


def test_tls_name_scope_rejects_before_socket(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("socket must not open")
        ),
    )
    with pytest.raises(EgressScopeError):
        engine.tls_probe(auth(), 443, "other.invalid")


def test_protocol_flags_reject_before_transport(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    target = auth()
    denied = replace(
        target,
        egress=replace(target.egress, allow_dns=False, allow_icmp=False),
    )
    monkeypatch.setattr(
        engine.socket, "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("DNS must not start")
        ),
    )
    monkeypatch.setattr(
        engine, "ping",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("ICMP must not start")
        ),
    )
    with pytest.raises(EgressScopeError):
        engine.dns_probe(denied)
    with pytest.raises(EgressScopeError):
        engine.icmp_probe(denied, 1)


def test_snmp_udp_scope_rejects_before_backend_import(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    target = replace(auth(), snmp_community="snmp-secret")
    with pytest.raises(EgressScopeError):
        asyncio.run(engine.snmp_get(target, ["1.3.6"], 162))


def test_ftp_paths_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(ValueError):
        engine.ftp_list(auth(), "/outside", True, 21)


def test_audit_preflight_failure_prevents_operation(monkeypatch) -> None:
    touched = []

    @engine._audit_device_call
    def fake_device_call(target_auth):
        touched.append(True)
        return {"ok": True}

    monkeypatch.setattr(
        engine, "record",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("audit unavailable")),
    )
    with pytest.raises(AuditPreflightError) as captured:
        fake_device_call(auth())
    assert captured.value.operation_started is False
    assert touched == []


def test_operation_id_generation_failure_is_typed_preflight(monkeypatch) -> None:
    touched = []

    @engine._audit_device_call
    def fake_device_call(target_auth):
        touched.append(True)
        return {"ok": True}

    monkeypatch.setattr(
        engine.secrets, "token_hex",
        lambda *args: (_ for _ in ()).throw(OSError("random source unavailable")),
    )
    with pytest.raises(AuditPreflightError) as captured:
        fake_device_call(auth())
    assert captured.value.operation_started is False
    assert touched == []


def test_audit_completion_failure_is_explicit_after_operation(monkeypatch) -> None:
    touched = []
    statuses = []

    @engine._audit_device_call
    def fake_device_call(target_auth):
        touched.append(True)
        return {"ok": True}

    def record_then_fail(*args, **kwargs):
        statuses.append(kwargs["status"])
        if len(statuses) == 2:
            raise OSError("audit unavailable")

    monkeypatch.setattr(engine, "record", record_then_fail)
    with pytest.raises(AuditPostOperationError) as captured:
        fake_device_call(auth())
    assert captured.value.operation_started is True
    assert touched == [True]
    assert statuses == ["started", "ok"]


def test_async_audit_records_started_and_failed(monkeypatch) -> None:
    statuses = []

    @engine._audit_device_call
    async def fake_device_call(target_auth):
        raise ValueError("rejected")

    monkeypatch.setattr(
        engine, "record",
        lambda *args, **kwargs: statuses.append((
            kwargs["status"], kwargs.get("detail"), kwargs["operation_id"],
        )),
    )
    with pytest.raises(ValueError, match="rejected"):
        asyncio.run(fake_device_call(auth()))
    assert [(status, detail) for status, detail, _ in statuses] == [
        ("started", None), ("failed", "ValueError"),
    ]
    assert statuses[0][2] == statuses[1][2]
    assert re.fullmatch(r"op_[0-9a-f]{32}", statuses[0][2])


def test_interleaved_audit_calls_have_unique_pairable_operation_ids(monkeypatch) -> None:
    events = []
    entered = []
    release = asyncio.Event()

    @engine._audit_device_call
    async def fake_device_call(target_auth, marker):
        entered.append(marker)
        if len(entered) == 8:
            release.set()
        await release.wait()
        await asyncio.sleep(0)
        return {"ok": True}

    monkeypatch.setattr(
        engine, "record",
        lambda event, **kwargs: events.append({"event": event, **kwargs}),
    )

    async def scenario():
        return await asyncio.gather(*(
            fake_device_call(auth(), f"secret-marker-{index}")
            for index in range(8)
        ))

    results = asyncio.run(scenario())
    assert all(result == {"ok": True} for result in results)
    assert len(events) == 16

    grouped = {}
    for event in events:
        operation_id = event["operation_id"]
        assert re.fullmatch(r"op_[0-9a-f]{32}", operation_id)
        grouped.setdefault(operation_id, []).append(event["status"])
        assert "marker" not in event
        assert "secret-marker" not in operation_id
    assert len(grouped) == 8
    assert all(statuses == ["started", "ok"] for statuses in grouped.values())


def test_snmp_requires_separate_community_before_backend_import(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(AuthenticationMaterialError) as captured:
        asyncio.run(engine.snmp_get(auth(), ["1.3.6"], 161))
    assert captured.value.error_code == "auth_material"


def test_snmp_backend_receives_only_the_separate_community(monkeypatch) -> None:
    captured = {}

    class CommunityData:
        def __init__(self, value, mpModel):
            captured["community"] = value
            captured["model"] = mpModel

    class Transport:
        @classmethod
        async def create(cls, *args, **kwargs):
            captured["transport_created"] = True
            return object()

    class Engine:
        def close_dispatcher(self):
            captured["closed"] = True

    class Placeholder:
        def __init__(self, *args):
            pass

    async def get_cmd(*args, **kwargs):
        return None, False, 0, []

    backend = types.ModuleType("pysnmp.hlapi.v3arch.asyncio")
    backend.CommunityData = CommunityData
    backend.ContextData = Placeholder
    backend.ObjectIdentity = Placeholder
    backend.ObjectType = Placeholder
    backend.SnmpEngine = Engine
    backend.UdpTransportTarget = Transport
    backend.get_cmd = get_cmd
    monkeypatch.setitem(sys.modules, "pysnmp.hlapi.v3arch.asyncio", backend)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    target_auth = replace(
        auth(), secret="ssh-secret", snmp_community="snmp-secret",
    )
    result = asyncio.run(engine.snmp_get(target_auth, ["1.3.6"], 161))
    assert result["ok"] is True
    assert captured == {
        "community": "snmp-secret",
        "model": 1,
        "transport_created": True,
        "closed": True,
    }


def test_the_legacy_profile_is_the_only_thing_the_transport_forwards(monkeypatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    engine.read_from_device(auth(), "linux", "hostname")
    engine.read_from_device(auth(legacy_ssh="rsa-sha1"), "linux", "hostname")
    assert [call["legacy_ssh"] for call in captured] == [None, "rsa-sha1"]
    assert engine._refused_host_key_algorithms(auth()) == ["ssh-rsa"]
    assert engine._refused_host_key_algorithms(auth(legacy_ssh="rsa-sha1")) == []


def test_legacy_ssh_profile_tables_share_one_vocabulary() -> None:
    from netops_core import legacy_ssh as core_legacy

    assert LEGACY_SSH_PROFILES == ("rsa-sha1",)
    assert tuple(core_legacy.PROFILES) == LEGACY_SSH_PROFILES
    assert set(engine._SSH_LEGACY_PROFILES) == {None, *LEGACY_SSH_PROFILES}
    assert engine._SSH_LEGACY_PROFILES[None] == ()
    assert engine._SSH_LEGACY_PROFILES["rsa-sha1"] == engine._LEGACY_SSH_HOST_KEY_ALGS
    assert core_legacy.openssh_options(None) == ()
    assert core_legacy.openssh_options("rsa-sha1") == (
        "HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    )


def test_a_refused_negotiation_names_the_target_and_the_profile(monkeypatch) -> None:
    refusal = engine.core_ssh.SshError(
        "ssh to the device failed with exit code 255",
        255,
        "Unable to negotiate: no matching host key type found. Their offer: ssh-rsa",
    )
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command([], error=refusal),
    )
    with pytest.raises(LegacySshProfileRequired) as failure:
        engine.read_from_device(auth(), "linux", "hostname")
    message = str(failure.value)
    assert '"device-a"' in message
    assert '"legacy_ssh": "rsa-sha1"' in message
    assert "ssh-rsa" in message

    with pytest.raises(engine.core_ssh.SshError) as plain:
        engine.read_from_device(auth(legacy_ssh="rsa-sha1"), "linux", "hostname")
    assert not isinstance(plain.value, LegacySshProfileRequired)


def test_a_legacy_profile_is_refused_without_a_host_key_pin() -> None:
    from base64 import urlsafe_b64encode

    payload = {
        "alias": "device-a",
        "host": TEST_ADDRESS,
        "port": 22,
        "login": "reader",
        "credential_kind": "password",
        "secret": "credential",
        "host_key_fingerprint": HOST_KEY_PIN,
        "account_role": "read-only",
        "legacy_ssh": "rsa-sha1",
        "ssh_platform": "linux",
        "enabled_queries": ["hostname"],
        "read_inventory": {},
        "egress": {
            "addresses": [TEST_ADDRESS],
            "tcp_ports": [],
            "udp_ports": [],
            "tcp_port_ranges": [],
            "udp_port_ranges": [],
            "allow_icmp": False,
            "allow_dns": False,
            "tls_server_names": [],
        },
    }

    def decode(document):
        raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
        return TargetAuth.decode(
            "device-a", urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        )

    assert decode(payload).legacy_ssh == "rsa-sha1"
    for pin in (None, "", "SHA256:short", "not-a-pin"):
        unpinned = dict(payload, host_key_fingerprint=pin)
        with pytest.raises(AuthenticationContextError):
            decode(unpinned)
    without = {name: value for name, value in payload.items() if name != "host_key_fingerprint"}
    with pytest.raises(AuthenticationContextError):
        decode(without)


FAKE_SFTP = '''#!/usr/bin/env python3
import hashlib, json, os, sys

record = {{"argv": sys.argv[1:], "env": dict(os.environ), "batch": sys.stdin.read()}}
for item in sys.argv:
    if item.startswith("UserKnownHostsFile="):
        record["known_hosts"] = open(item.split("=", 1)[1]).read()
askpass = os.environ.get("SSH_ASKPASS")
if askpass:
    import subprocess
    answer = subprocess.run([askpass], capture_output=True, env=dict(os.environ)).stdout
    record["askpass_sha256"] = hashlib.sha256(answer.strip()).hexdigest()
if "-i" in sys.argv:
    identity = sys.argv[sys.argv.index("-i") + 1]
    record["identity_sha256"] = hashlib.sha256(open(identity, "rb").read()).hexdigest()
    record["identity_mode"] = oct(os.stat(identity).st_mode & 0o777)
with open({log!r}, "a") as handle:
    handle.write(json.dumps(record) + "\\n")
sys.stderr.write({said!r})
sys.stdout.write({answer!r})
sys.exit({code})
'''

SFTP_PROGRESS = "Connected to 192.0.2.20.\n"
SFTP_FILE_ANSWER = (
    'sftp> ls -ln "/safe/log"\n'
    "-rw-r-----    ? 0        0            1234 Sep 10 02:26 /safe/log\n"
)
SFTP_DIRECTORY_ANSWER = (
    'sftp> ls -ln "/safe"\n'
    "-rw-------    ? 0        0              11 Sep 10 02:26 /safe/a.conf\n"
    "-rw-------    ? 0        0              22 Sep 10 02:26 /safe/b.conf\n"
    "drwx------    ? 0        0            4096 Sep 10 02:26 /safe/sub\n"
)
SFTP_NEGOTIATION = (
    "Unable to negotiate with 192.0.2.20 port 22:"
    " no matching host key type found. Their offer: ssh-rsa\n"
)


def _fake_sftp(
    tmp_path, monkeypatch, answer=SFTP_FILE_ANSWER, said=SFTP_PROGRESS, code=0,
):
    binaries = tmp_path / "bin"
    binaries.mkdir(exist_ok=True)
    log = tmp_path / "sftp-calls.jsonl"
    client = binaries / "sftp"
    client.write_text(
        FAKE_SFTP.format(log=str(log), answer=answer, said=said, code=code),
        encoding="utf-8",
    )
    client.chmod(0o700)
    monkeypatch.setenv("PATH", f"{binaries}:{os.environ['PATH']}")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def calls() -> list:
        if not log.exists():
            return []
        return [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    return calls


def _sftp_options(argv: list) -> list:
    return [argv[index + 1] for index, item in enumerate(argv) if item == "-o"]


def test_sftp_stat_runs_the_hardened_client_with_a_single_command_batch(
    tmp_path, monkeypatch,
) -> None:
    import hashlib

    calls = _fake_sftp(tmp_path, monkeypatch)
    result = asyncio.run(engine.sftp_stat(auth(), "/safe/log"))
    assert result == {
        "ok": True,
        "target": "device-a",
        "path_sha256": engine.digest_text("/safe/log"),
        "kind": "file",
        "size": 1234,
        "mode": "0o640",
        "modified_ls": "Sep 10 02:26",
    }

    call = calls()[-1]
    assert call["argv"][:2] == ["-F", "/dev/null"]
    assert "-b" not in call["argv"]
    assert call["batch"] == 'ls -ln "/safe/log"\n'
    assert call["batch"].count("\n") == 1
    assert call["argv"][-3:-1] == ["-P", "22"]
    assert call["argv"][-1] == f"reader@{TEST_ADDRESS}"
    assert call["known_hosts"] == HOST_KEY_LINE + "\n"
    options = _sftp_options(call["argv"])
    for option in (
        "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "ClearAllForwardings=yes",
        "ProxyCommand=none", "PermitLocalCommand=no", "ControlMaster=no",
        "ControlPath=none", "BatchMode=no", "NumberOfPasswordPrompts=1",
    ):
        assert option in options, option
    assert call["askpass_sha256"] == hashlib.sha256(b"credential").hexdigest()
    assert all("credential" not in item for item in call["argv"]), call["argv"]
    assert all("credential" not in str(value) for value in call["env"].values())
    assert set(call["env"]) >= {"PATH", "HOME", "LC_ALL"}
    assert "credential" not in json.dumps(result)


def test_sftp_stat_of_a_directory_answers_with_a_count_and_no_names(
    tmp_path, monkeypatch,
) -> None:
    _fake_sftp(tmp_path, monkeypatch, answer=SFTP_DIRECTORY_ANSWER)
    result = asyncio.run(engine.sftp_stat(auth(), "/safe"))
    assert result == {
        "ok": True,
        "target": "device-a",
        "path_sha256": engine.digest_text("/safe"),
        "kind": "directory",
        "entry_count": 3,
    }
    for name in ("a.conf", "b.conf", "sub"):
        assert name not in json.dumps(result), name


def test_sftp_legacy_options_appear_only_with_the_enrolled_profile(
    tmp_path, monkeypatch,
) -> None:
    calls = _fake_sftp(tmp_path, monkeypatch)
    asyncio.run(engine.sftp_stat(auth(), "/safe/log"))
    options = _sftp_options(calls()[-1]["argv"])
    assert "HostKeyAlgorithms=+ssh-rsa" not in options

    asyncio.run(engine.sftp_stat(auth(legacy_ssh="rsa-sha1"), "/safe/log"))
    options = _sftp_options(calls()[-1]["argv"])
    assert options.index("StrictHostKeyChecking=yes") < options.index(
        "HostKeyAlgorithms=+ssh-rsa"
    )
    assert "PubkeyAcceptedAlgorithms=+ssh-rsa" in options


def test_sftp_host_key_negotiation_failure_names_the_profile(
    tmp_path, monkeypatch,
) -> None:
    _fake_sftp(tmp_path, monkeypatch, answer="", said=SFTP_NEGOTIATION, code=255)
    result = asyncio.run(engine.sftp_stat(auth(), "/safe/log"))
    assert result["ok"] is False
    assert LegacySshProfileRequired.__name__ in result["error"]
    assert '"legacy_ssh": "rsa-sha1"' in result["error"]

    enrolled = asyncio.run(engine.sftp_stat(auth(legacy_ssh="rsa-sha1"), "/safe/log"))
    assert enrolled["ok"] is False
    assert LegacySshProfileRequired.__name__ not in enrolled["error"]


def test_sftp_reports_a_closed_connection_without_inventing_a_cause(
    tmp_path, monkeypatch,
) -> None:
    _fake_sftp(
        tmp_path, monkeypatch, answer="",
        said="Connection closed by 192.0.2.20 port 22\n", code=255,
    )
    result = asyncio.run(engine.sftp_stat(auth(), "/safe/log"))
    assert result["ok"] is False
    assert LegacySshProfileRequired.__name__ not in result["error"]
    assert "the device closed the connection" in result["error"]
    assert "192.0.2.20 port 22" not in result["error"]


def test_written_audit_log_shows_an_enrolled_legacy_profile(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    assert engine.record is audit.record
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    engine.tcp_probe(auth(legacy_ssh="rsa-sha1"), 443, 1.0)
    written = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [item["status"] for item in written] == ["started", "failed"]
    assert [item["device"] for item in written] == ["device-a", "device-a"]
    assert [item["component"] for item in written] == ["helper", "helper"]
    assert [item["legacy_ssh"] for item in written] == ["rsa-sha1", "rsa-sha1"]

    path.unlink()
    engine.tcp_probe(auth(), 443, 1.0)
    plain = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [item["status"] for item in plain] == ["started", "failed"]
    assert all("legacy_ssh" not in item for item in plain)


def test_the_matching_pin_becomes_the_known_hosts_line_of_that_call(monkeypatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    assert engine.host_key_line(auth()) == HOST_KEY_LINE
    assert engine.host_key_line(replace(auth(), port=2222)) == (
        f"[{TEST_ADDRESS}]:2222 ssh-ed25519 {HOST_KEY_BLOB}"
    )
    engine.read_from_device(auth(), "linux", "hostname")
    assert captured[0]["host_key_line"] == HOST_KEY_LINE
    assert captured[0]["secret"] == "credential"


def test_the_pin_is_read_with_one_keyscan_of_the_enrolled_address(monkeypatch) -> None:
    scanned: list = []
    monkeypatch.setattr(engine.core_hostkey, "scan", offered_scan(scanned))
    engine.host_key_line(auth())
    assert scanned == [(TEST_ADDRESS, 22, HOST_KEY_PIN, engine._HOST_KEY_SCAN_TIMEOUT_SECONDS)]

    outside = replace(
        auth(), host="device.example.invalid", egress=replace(auth().egress, allow_dns=True),
    )
    monkeypatch.setattr(
        engine.socket, "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("198.51.100.99", 0))],
    )
    scanned.clear()
    with pytest.raises(EgressScopeError):
        engine.host_key_line(outside)
    assert scanned == []


def test_wrong_pin_refuses_before_any_transport_or_credential(monkeypatch) -> None:
    other = b64encode(b"a-different-host-key").decode("ascii")
    monkeypatch.setattr(
        engine.core_hostkey, "scan",
        refusing_scan(f"no offered host key matches the pinned fingerprint, saw {other}"),
    )
    monkeypatch.setattr(
        engine.core_ssh, "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("transport must not open")
        ),
    )
    with pytest.raises(AuthenticationContextError) as failure:
        engine.read_from_device(auth(), "linux", "hostname")
    assert '"device-a"' in str(failure.value)
    assert other not in str(failure.value)
    assert HOST_KEY_BLOB not in str(failure.value)


def test_unreachable_host_key_probe_names_the_target_without_the_key(monkeypatch) -> None:
    monkeypatch.setattr(
        engine.core_hostkey, "scan", refusing_scan("cannot read the host key (OSError)"),
    )
    with pytest.raises(AuthenticationContextError) as failure:
        engine.host_key_line(auth())
    assert '"device-a"' in str(failure.value)
    assert "did not offer the pinned SSH host key" in str(failure.value)


def test_key_authentication_hands_the_transport_a_handle_not_the_text(monkeypatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        engine.core_ssh, "run_command", recording_run_command(captured),
    )
    target = auth(credential_kind="ssh-key", secret=PRIVATE_KEY)
    credential = engine.DeviceCredential(target)
    assert credential.kind == "ssh-key"
    assert credential.login == "reader"
    assert credential.use() == PRIVATE_KEY
    assert PRIVATE_KEY not in repr(credential)
    assert PRIVATE_KEY not in str(credential)
    assert "replace-me" not in repr(credential)

    engine.read_from_device(target, "linux", "hostname")
    assert captured[0]["credential_kind"] == "ssh-key"
    assert captured[0]["secret"] == PRIVATE_KEY
    assert PRIVATE_KEY not in captured[0]["command"]
    assert PRIVATE_KEY not in captured[0]["host_key_line"]


def test_key_authentication_hands_the_sftp_client_a_private_file_and_removes_it(
    tmp_path, monkeypatch,
) -> None:
    import hashlib

    calls = _fake_sftp(tmp_path, monkeypatch)
    target = auth(credential_kind="ssh-key", secret=PRIVATE_KEY)
    assert asyncio.run(engine.sftp_stat(target, "/safe/log"))["ok"] is True
    call = calls()[-1]
    assert call["identity_sha256"] == hashlib.sha256(PRIVATE_KEY.encode("utf-8")).hexdigest()
    assert call["identity_mode"] == "0o600"
    assert "SSH_ASKPASS" not in call["env"]
    assert "BatchMode=yes" in _sftp_options(call["argv"])
    assert not os.path.exists(call["argv"][call["argv"].index("-i") + 1])
    assert PRIVATE_KEY not in json.dumps(call)


def test_audited_key_operation_never_writes_the_key(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    result = engine.tcp_probe(auth(credential_kind="ssh-key", secret=PRIVATE_KEY), 443, 1.0)
    written = path.read_text(encoding="utf-8")
    assert "BEGIN OPENSSH PRIVATE KEY" not in written
    assert "replace-me" not in written
    assert "replace-me" not in json.dumps(result)
