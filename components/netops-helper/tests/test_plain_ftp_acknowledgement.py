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
