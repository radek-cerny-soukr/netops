from __future__ import annotations

from base64 import b64encode
from dataclasses import replace
import ipaddress

from netops_core.hostkey import fingerprint_of
import pytest

from netops_helper.auth import EgressPolicy, EgressScopeError, TargetAuth
import netops_helper.engine as engine


TEST_ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 30))
PIN = fingerprint_of(b64encode(b"plain-ftp-host-key").decode("ascii"))


def target_auth() -> TargetAuth:
    return TargetAuth(
        alias="legacy-device",
        host=TEST_ADDRESS,
        port=21,
        login="account",
        secret="credential",
        host_key_fingerprint=PIN,
        sftp_roots=("/safe",),
        egress=EgressPolicy(
            addresses=(TEST_ADDRESS,),
            tcp_ports=(21,),
            tcp_port_ranges=((50_000, 50_010),),
        ),
    )


def test_plain_ftp_is_rejected_before_client_creation_without_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_client(*args, **kwargs):
        raise AssertionError("plain FTP client must not be created without acknowledgement")

    monkeypatch.setattr(engine.ftplib, "FTP", forbidden_client)

    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="Plain FTP is unencrypted"):
        engine.ftp_list(target_auth(), "/safe", use_tls=False, port=21)


class FakePlainFTP:
    def __init__(self, timeout: int) -> None:
        assert timeout == 30
        self.connected = False
        self.logged_in = False
        self.closed = False
        self.encoding = "utf-8"
        self.sock = None

    def connect(self, host: str, port: int) -> None:
        assert host == TEST_ADDRESS and port == 21
        self.control_host = host
        self.connected = True

    def makepasv(self) -> tuple[str, int]:
        return self.control_host, 50_005

    def login(self, login: str, password: str) -> None:
        assert self.connected
        assert login == "account" and password == "credential"
        self.logged_in = True

    def nlst(self, remote_path: str) -> list[str]:
        assert self.logged_in and remote_path == "/safe"
        passive_host, passive_port = self.makepasv()
        assert passive_host == TEST_ADDRESS and passive_port == 50_005
        return ["/safe-file.txt"]

    def voidcmd(self, command):
        assert command == "TYPE A"

    def voidresp(self):
        return "226 done"

    def transfercmd(self, command):
        assert command == "NLST /safe"
        self.makepasv()
        return ListingSocket(b"/safe-file.txt\r\n")

    def quit(self) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True


def test_acknowledged_plain_ftp_returns_permanent_unencrypted_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine.ftplib, "FTP", FakePlainFTP)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    result = engine.ftp_list(
        target_auth(), "/safe", use_tls=False, port=21, acknowledge_unencrypted=True,
    )

    assert result["ok"]
    assert result["tls"] is False
    assert result["transport_encrypted"] is False
    assert result["plaintext_acknowledged"] is True
    assert result["security_warning"] == engine.PLAIN_FTP_WARNING
    assert "credentials" in result["security_warning"].lower()
    assert "directory listing" in result["security_warning"].lower()
    assert result["entries"] == ["safe-file.txt"]

def test_ftp_requires_passive_range_before_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = target_auth()
    target = replace(
        target,
        egress=replace(target.egress, tcp_port_ranges=()),
    )
    monkeypatch.setattr(
        engine.ftplib, "FTP",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("FTP client must not be created")
        ),
    )
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(EgressScopeError, match="passive TCP port range"):
        engine.ftp_list(
            target, "/safe", use_tls=False, port=21, acknowledge_unencrypted=True,
        )


def test_ftp_rejects_server_selected_passive_port_outside_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OutOfScopePassiveFTP(FakePlainFTP):
        def makepasv(self) -> tuple[str, int]:
            return self.control_host, 50_011

    monkeypatch.setattr(engine.ftplib, "FTP", OutOfScopePassiveFTP)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(EgressScopeError, match="passive port"):
        engine.ftp_list(
            target_auth(), "/safe", use_tls=False, port=21,
            acknowledge_unencrypted=True,
        )


class ListingSocket:
    def __init__(self, payload, tick=None):
        self.payload = payload
        self.received = 0
        self.closed = False
        self.tick = tick

    def recv(self, count):
        if self.tick:
            self.tick()
        data = self.payload[:min(count, 1024)]
        self.payload = self.payload[len(data):]
        self.received += len(data)
        return data

    def settimeout(self, timeout):
        assert timeout > 0

    def close(self):
        self.closed = True

    def shutdown(self, direction):
        self.closed = True


def listed(monkeypatch, payload, tick=None):
    data = ListingSocket(payload, tick)
    clients = []
    class StreamingFTP(FakePlainFTP):
        def __init__(self, timeout):
            super().__init__(timeout)
            clients.append(self)
        def transfercmd(self, command):
            self.makepasv()
            return data
        def nlst(self, remote_path):
            chunks = []
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    return b"".join(chunks).decode().splitlines()
                chunks.append(chunk)
    monkeypatch.setattr(engine.ftplib, "FTP", StreamingFTP)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    result = engine.ftp_list(target_auth(), "/safe", use_tls=False, port=21, acknowledge_unencrypted=True)
    return result, data, clients[0]


def test_reciprocal_ftp_caps_receive_before_full_listing(monkeypatch):
    payload = b"filename.txt\r\n" * 10000
    result, data, client = listed(monkeypatch, payload)
    assert result["ok"] and result["truncated"]
    assert len(result["entries"]) == 500
    assert data.received < len(payload)
    assert data.closed and client.closed


@pytest.mark.parametrize("count",[0,1,500])
def test_reciprocal_ftp_accepts_complete_bounded_listing(monkeypatch, count):
    result, data, client = listed(monkeypatch, b"filename.txt\r\n" * count)
    assert result["ok"] and not result["truncated"]
    assert len(result["entries"]) == count
    assert data.closed and client.closed


def test_reciprocal_ftp_rejects_byte_budget(monkeypatch):
    monkeypatch.setattr(engine, "_FTP_LIST_MAX_BYTES", 32, raising=False)
    result, data, client = listed(monkeypatch, b"x" * 64)
    assert not result["ok"]
    assert "budget" in result["error"].lower()
    assert data.received <= 33
    assert data.closed and client.closed


def test_reciprocal_ftp_rejects_slow_progress(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    def tick():
        now[0] += 31.0
    result, data, client = listed(monkeypatch, b"filename.txt\r\n", tick)
    assert not result["ok"]
    assert data.closed and client.closed


def test_reciprocal_ftp_deadline_after_transfer_closes_data_socket(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    data = ListingSocket(b"file\r\n")
    class LateFTP(FakePlainFTP):
        def transfercmd(self, command):
            now[0] = 31.0
            return data
    monkeypatch.setattr(engine.ftplib, "FTP", LateFTP)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    result = engine.ftp_list(target_auth(), "/safe", use_tls=False, port=21, acknowledge_unencrypted=True)
    assert not result["ok"] and data.closed


def test_reciprocal_ftp_watchdog_interrupts_blocked_control_read(monkeypatch):
    import socket
    import time
    from types import SimpleNamespace
    reader, writer = socket.socketpair()
    budget = None
    try:
        monkeypatch.setattr(engine, "_FTP_TOTAL_TIMEOUT_SECONDS", 0.1)
        budget = engine._FTPBudget(SimpleNamespace(sock=reader))
        started = time.monotonic()
        assert reader.recv(1) == b""
        assert time.monotonic() - started < 2.0
        with pytest.raises(TimeoutError):
            budget.remaining()
    finally:
        if budget is not None:
            budget.close()
        reader.close()
        writer.close()


@pytest.mark.parametrize("count", [1, 501])
def test_reciprocal_ftps_protects_and_closes_bounded_data(monkeypatch, count):
    events = []
    plain = ListingSocket(b"")
    class TLSData(ListingSocket):
        def unwrap(self):
            events.append("unwrap")
            return plain
    data = TLSData(b"file\r\n" * count)
    class TLSFTP(FakePlainFTP):
        def __init__(self, timeout, context):
            super().__init__(timeout)
        def auth(self):
            events.append("auth")
        def login(self, login, password):
            assert events == ["auth"]
            super().login(login, password)
        def prot_p(self):
            events.append("protect")
        def transfercmd(self, command):
            assert events == ["auth", "protect"]
            self.makepasv()
            return data
    monkeypatch.setattr(engine.ftplib, "FTP_TLS", TLSFTP)
    monkeypatch.setattr(engine.ssl, "SSLSocket", TLSData)
    monkeypatch.setattr(engine, "_ftps_context", lambda alias: (object(), None))
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    result = engine.ftp_list(target_auth(), "/safe", use_tls=True, port=21)
    assert result["ok"] and result["tls"] and data.closed
    assert result["truncated"] == (count > 500)
    assert plain.closed == (count <= 500)
