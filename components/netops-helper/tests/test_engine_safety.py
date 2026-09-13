from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
import ipaddress
import json
import re
import sys
import types

import pytest

import netops_helper.audit as audit
from netops_helper.audit import AuditPostOperationError, AuditPreflightError
from paramiko.ssh_exception import IncompatiblePeer

from netops_helper.auth import (
    LEGACY_SSH_PROFILES, AuthenticationMaterialError, EgressPolicy, EgressScopeError,
    LegacySshProfileRequired, PolicyScopeError, TargetAuth,
)
import netops_helper.engine as engine
from netops_helper.read_policy import READ_QUERIES


TEST_ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 20))


def auth(*, fortios_verified: bool = True, legacy_ssh: str | None = None) -> TargetAuth:
    return TargetAuth(
        alias="device-a",
        host=TEST_ADDRESS,
        port=22,
        login="reader",
        password="credential",
        known_hosts="known-key",
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
        replace(base, password="other-credential"), "fortinet", "q", None,
    )
    fields = engine._audit_fields({"platform": "fortios", "query": "system_status"}, {})
    assert fields["platform"] == "fortinet"
    assert engine._audit_fields({"platform": "not-a-platform"}, {})["platform"] == "not-a-platform"


class FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_verified_socket_connects_to_resolved_address_not_hostname(monkeypatch) -> None:
    captured = {}
    named = replace(auth(), host="device.example.invalid", egress=replace(auth().egress, allow_dns=True))
    monkeypatch.setattr(
        engine.socket, "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, (TEST_ADDRESS, 0))],
    )

    def fake_create_connection(address, timeout=None):
        captured["address"] = address
        captured["timeout"] = timeout
        return FakeSocket()

    monkeypatch.setattr(engine.socket, "create_connection", fake_create_connection)
    assert isinstance(engine._open_verified_socket(named), FakeSocket)
    assert captured["address"] == (TEST_ADDRESS, 22)
    assert captured["timeout"] == 10.0


def test_verified_socket_refuses_address_outside_egress(monkeypatch) -> None:
    named = replace(auth(), host="device.example.invalid", egress=replace(auth().egress, allow_dns=True))
    monkeypatch.setattr(
        engine.socket, "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("198.51.100.99", 0))],
    )
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not connect")),
    )
    with pytest.raises(EgressScopeError):
        engine._open_verified_socket(named)


def test_netmiko_connection_reuses_verified_socket_and_keeps_hostname_for_host_key(monkeypatch) -> None:
    captured = {}
    sock = FakeSocket()

    class FakeConnection:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def disconnect(self):
            captured["disconnected"] = True

    monkeypatch.setattr(engine, "ConnectHandler", FakeConnection)
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: sock)
    with engine.netmiko_connection(auth(), "linux"):
        assert sock.closed is False
    assert captured["sock"] is sock
    assert captured["host"] == auth().host
    assert captured["disconnected"] is True
    assert sock.closed is True


def test_netmiko_connection_closes_socket_when_driver_fails(monkeypatch) -> None:
    sock = FakeSocket()
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: sock)
    monkeypatch.setattr(
        engine, "ConnectHandler",
        lambda **kwargs: (_ for _ in ()).throw(OSError("handshake failed")),
    )
    with pytest.raises(OSError):
        with engine.netmiko_connection(auth(), "linux"):
            pass
    assert sock.closed is True


def test_fortios_connection_uses_read_only_driver_and_disables_sha1_kex(monkeypatch) -> None:
    captured = {}

    class FakeConnection:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def disconnect(self):
            captured["disconnected"] = True

    monkeypatch.setattr(engine, "ReadOnlyFortinetSSH", FakeConnection)
    monkeypatch.setattr(
        engine,
        "ConnectHandler",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("Fortinet must use the read-only connection class")
        ),
    )
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: FakeSocket())
    with engine.netmiko_connection(auth(), "fortios"):
        pass
    assert captured["device_type"] == "fortinet"
    assert captured["disabled_algorithms"]["kex"] == engine._WEAK_SSH_KEX
    assert all(name.endswith("sha1") for name in engine._WEAK_SSH_KEX)
    assert captured["disabled_algorithms"]["keys"] == ["ssh-rsa"]
    assert captured["disconnected"] is True


def test_netmiko_device_type_map_matches_canonical_authority() -> None:
    assert set(engine._NETMIKO_DEVICE_TYPES) == set(READ_QUERIES)
    assert all(
        isinstance(device_type, str) and device_type
        for device_type in engine._NETMIKO_DEVICE_TYPES.values()
    )
    assert engine._NETMIKO_DEVICE_TYPES["fortinet"] == "fortinet"
    assert engine._NETMIKO_DEVICE_TYPES["juniper_junos_els"] == "juniper_junos"


@pytest.mark.parametrize(
    ("platform", "expected_device_type"),
    (
        ("linux", "linux"),
        ("extreme_exos", "extreme_exos"),
        ("cisco_ios", "cisco_ios"),
        ("cisco_xe", "cisco_xe"),
        ("cisco_nxos", "cisco_nxos"),
        ("arista_eos", "arista_eos"),
        ("juniper_junos", "juniper_junos"),
        ("juniper_junos_els", "juniper_junos"),
    ),
)
def test_canonical_platform_uses_expected_netmiko_device_type(
    monkeypatch, platform, expected_device_type,
) -> None:
    captured = {}

    class FakeConnection:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def disconnect(self):
            captured["disconnected"] = True

    monkeypatch.setattr(engine, "ConnectHandler", FakeConnection)
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: FakeSocket())
    with engine.netmiko_connection(auth(), platform):
        pass
    assert captured["device_type"] == expected_device_type
    assert captured["disabled_algorithms"] == {
        "keys": ["ssh-rsa"], "kex": engine._WEAK_SSH_KEX,
    }
    assert captured["disconnected"] is True


def test_fortios_connection_requires_verified_output_standard(monkeypatch) -> None:
    monkeypatch.setattr(
        engine, "ReadOnlyFortinetSSH",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("connection must not open")),
    )
    with pytest.raises(ValueError, match="output standard"):
        with engine.netmiko_connection(auth(fortios_verified=False), "fortios"):
            pass


def test_ssh_continuation_uses_cache_without_second_login(monkeypatch) -> None:
    calls = []

    class FakeConnection:
        def send_command(self, command, read_timeout):
            calls.append(command)
            return "x" * 1500

    @contextmanager
    def fake_connection(*args, **kwargs):
        yield FakeConnection()

    monkeypatch.setattr(engine, "netmiko_connection", fake_connection)
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
        engine, "netmiko_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("SSH connection must not open")
        ),
    )
    with pytest.raises(PolicyScopeError):
        engine.ssh_read(auth(), "fortios", "routing_table", None, 0, 1000)
    assert [(item["status"], item["platform"], item["query"]) for item in events] == [
        ("started", "fortinet", "routing_table"),
        ("rejected", "fortinet", "routing_table"),
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


def test_async_audit_records_started_and_rejected(monkeypatch) -> None:
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
        ("started", None), ("rejected", "ValueError"),
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
        auth(), password="ssh-secret", snmp_community="snmp-secret",
    )
    result = asyncio.run(engine.snmp_get(target_auth, ["1.3.6"], 161))
    assert result["ok"] is True
    assert captured == {
        "community": "snmp-secret",
        "model": 1,
        "transport_created": True,
        "closed": True,
    }


def _fake_asyncssh(captured: dict, error: Exception | None = None):
    module = types.ModuleType("asyncssh")

    class KeyExchangeFailed(Exception):
        pass

    class FakeSftp:
        async def __aenter__(self):
            return "sftp-client"

        async def __aexit__(self, *args):
            return False

    class FakeConnection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def start_sftp_client(self, sftp_version=None):
            captured["sftp_version"] = sftp_version
            return FakeSftp()

    def connect(host, **kwargs):
        captured["host"] = host
        captured.update(kwargs)
        if error is not None:
            raise error
        return FakeConnection()

    module.connect = connect
    module.KeyExchangeFailed = KeyExchangeFailed
    return module


def _open_sftp(target: TargetAuth, monkeypatch, module) -> str:
    monkeypatch.setitem(sys.modules, "asyncssh", module)
    monkeypatch.setattr(engine, "_open_verified_socket", lambda item: FakeSocket())

    async def run() -> str:
        async with engine._sftp_client(target) as sftp:
            return sftp

    return asyncio.run(run())


def test_legacy_profile_is_the_only_way_to_reenable_the_sha1_host_key(monkeypatch) -> None:
    captured = {}

    class FakeConnection:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def disconnect(self):
            captured["disconnected"] = True

    monkeypatch.setattr(engine, "ConnectHandler", FakeConnection)
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: FakeSocket())
    with engine.netmiko_connection(auth(legacy_ssh="rsa-sha1"), "linux"):
        pass
    assert captured["disabled_algorithms"] == {"keys": [], "kex": engine._WEAK_SSH_KEX}


def test_legacy_ssh_profile_tables_share_one_vocabulary() -> None:
    assert LEGACY_SSH_PROFILES == ("rsa-sha1",)
    assert set(engine._SSH_LEGACY_PROFILES) == {None, *LEGACY_SSH_PROFILES}
    assert set(engine._ASYNCSSH_HOST_KEY_ALGS) == set(engine._SSH_LEGACY_PROFILES)
    assert engine._SSH_LEGACY_PROFILES[None] == ()
    assert engine._SSH_LEGACY_PROFILES["rsa-sha1"] == engine._LEGACY_SSH_HOST_KEY_ALGS
    assert engine._ASYNCSSH_HOST_KEY_ALGS[None] == "-ssh-rsa"
    assert engine._ASYNCSSH_HOST_KEY_ALGS["rsa-sha1"] == "+ssh-rsa"
    assert engine._ASYNCSSH_KEX_ALGS == "-" + ",".join(engine._WEAK_SSH_KEX)


def test_host_key_negotiation_failure_names_the_target_and_the_profile(monkeypatch) -> None:
    sock = FakeSocket()
    monkeypatch.setattr(engine, "_open_verified_socket", lambda target: sock)

    def wrapped_failure(**kwargs):
        try:
            raise IncompatiblePeer("Incompatible ssh peer (no acceptable host key)")
        except IncompatiblePeer as exc:
            raise OSError("A paramiko SSHException occurred") from exc

    monkeypatch.setattr(engine, "ConnectHandler", wrapped_failure)
    with pytest.raises(LegacySshProfileRequired) as failure:
        with engine.netmiko_connection(auth(), "linux"):
            pass
    message = str(failure.value)
    assert '"device-a"' in message
    assert '"legacy_ssh": "rsa-sha1"' in message
    assert "ssh-rsa" in message
    assert sock.closed is True

    with pytest.raises(OSError):
        with engine.netmiko_connection(auth(legacy_ssh="rsa-sha1"), "linux"):
            pass


def test_sftp_transport_uses_the_same_profile_as_the_netmiko_path(monkeypatch) -> None:
    captured = {}
    assert _open_sftp(auth(), monkeypatch, _fake_asyncssh(captured)) == "sftp-client"
    assert captured["server_host_key_algs"] == "-ssh-rsa"
    assert captured["kex_algs"] == engine._ASYNCSSH_KEX_ALGS
    assert captured["sftp_version"] == 3

    legacy = {}
    _open_sftp(auth(legacy_ssh="rsa-sha1"), monkeypatch, _fake_asyncssh(legacy))
    assert legacy["server_host_key_algs"] == "+ssh-rsa"
    assert legacy["kex_algs"] == engine._ASYNCSSH_KEX_ALGS


def test_sftp_host_key_negotiation_failure_names_the_profile(monkeypatch) -> None:
    module = _fake_asyncssh({})
    failing = _fake_asyncssh({}, error=module.KeyExchangeFailed("no host key"))
    failing.KeyExchangeFailed = module.KeyExchangeFailed
    with pytest.raises(LegacySshProfileRequired) as failure:
        _open_sftp(auth(), monkeypatch, failing)
    assert '"legacy_ssh": "rsa-sha1"' in str(failure.value)

    with pytest.raises(module.KeyExchangeFailed):
        _open_sftp(auth(legacy_ssh="rsa-sha1"), monkeypatch, failing)


def test_written_audit_log_shows_an_enrolled_legacy_profile(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    assert engine.record is audit.record
    monkeypatch.setattr(audit, "AUDIT_PATH", path)
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    engine.tcp_probe(auth(legacy_ssh="rsa-sha1"), 443, 1.0)
    written = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [item["status"] for item in written] == ["started", "failed"]
    assert [item["legacy_ssh"] for item in written] == ["rsa-sha1", "rsa-sha1"]

    path.unlink()
    engine.tcp_probe(auth(), 443, 1.0)
    plain = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [item["status"] for item in plain] == ["started", "failed"]
    assert all("legacy_ssh" not in item for item in plain)
