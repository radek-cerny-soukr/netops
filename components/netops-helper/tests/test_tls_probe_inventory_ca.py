from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netops_helper import engine
from netops_helper import inventory as helper_inventory
from netops_helper import proxy as helper_proxy
from netops_helper.auth import AuthenticationContextError, EgressPolicy, TargetAuth
from test_engine_contracts import _context
from test_engine_safety import auth

LOOPBACK = "127.0.0.1"


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _usage(*, signer: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not signer, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=signer, crl_sign=signer,
        encipher_only=False, decipher_only=False,
    )


def _authority(common_name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name)).issuer_name(_name(common_name))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_usage(signer=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _leaf(authority, *, address: str | None = LOOPBACK, dns: str | None = None, expired: bool = False):
    authority_key, authority_certificate = authority
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    before, after = (now - timedelta(days=10), now - timedelta(days=1)) if expired else (
        now - timedelta(days=1), now + timedelta(days=10))
    names = [x509.IPAddress(ipaddress.ip_address(address))] if address else [x509.DNSName(dns)]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("fixture leaf")).issuer_name(authority_certificate.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_usage(signer=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
            critical=False,
        )
        .sign(authority_key, hashes.SHA256())
    )
    return key, certificate


def _pem(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class _TlsServer:
    def __init__(self, directory: Path, leaf) -> None:
        key, certificate = leaf
        (directory / "server.pem").write_bytes(_pem(certificate))
        (directory / "server.key").write_bytes(_key_pem(key))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(directory / "server.pem"), str(directory / "server.key"))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            connection.settimeout(5)
            try:
                with self.context.wrap_socket(connection, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    def close(self) -> None:
        self.listener.close()


@pytest.fixture
def trust(tmp_path, monkeypatch):
    directory = tmp_path / "certs"
    directory.mkdir()
    monkeypatch.setattr(engine, "TLS_CERT_DIR", directory)
    monkeypatch.setattr(helper_inventory, "TLS_CERT_DIR", directory)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    return directory


@pytest.fixture
def authority():
    return _authority("fixture private ca")


def _serve(tmp_path, leaf):
    work = tmp_path / "server"
    work.mkdir(exist_ok=True)
    return _TlsServer(work, leaf)


def _target(port: int, ca: Path | None) -> TargetAuth:
    return replace(
        auth(), host=LOOPBACK,
        egress=EgressPolicy(addresses=(LOOPBACK,), tcp_ports=(port,)),
        tls_ca_certificate=None if ca is None else str(ca),
    )


def _install(directory: Path, authority, name: str = "private-ca") -> Path:
    path = directory / name
    path.write_bytes(_pem(authority[1]))
    return path


def test_without_inventory_ca_a_private_chain_fails_under_system_trust(tmp_path, trust, authority):
    server = _serve(tmp_path, _leaf(authority))
    try:
        answer = engine.tls_probe(_target(server.port, None), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["trust"] == "system"


def test_with_inventory_ca_the_private_chain_is_verified_and_reported(tmp_path, trust, authority):
    ca = _install(trust, authority)
    server = _serve(tmp_path, _leaf(authority))
    try:
        answer = engine.tls_probe(_target(server.port, ca), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is True, answer
    assert answer["trust"] == "inventory_ca"
    assert answer["verified_by_system_trust"] is False
    assert str(trust) not in repr(answer) and "BEGIN" not in repr(answer)


def test_with_inventory_ca_a_wrong_san_still_fails(tmp_path, trust, authority):
    ca = _install(trust, authority)
    server = _serve(tmp_path, _leaf(authority, address=None, dns="other.example.invalid"))
    try:
        answer = engine.tls_probe(_target(server.port, ca), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["trust"] == "inventory_ca"
    assert "hostname" in answer["error"].lower() or "ip address mismatch" in answer["error"].lower()


def test_with_inventory_ca_a_chain_of_another_ca_fails(tmp_path, trust, authority):
    ca = _install(trust, authority)
    server = _serve(tmp_path, _leaf(_authority("fixture other ca")))
    try:
        answer = engine.tls_probe(_target(server.port, ca), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["trust"] == "inventory_ca"


def test_with_inventory_ca_an_expired_leaf_fails(tmp_path, trust, authority):
    ca = _install(trust, authority)
    server = _serve(tmp_path, _leaf(authority, expired=True))
    try:
        answer = engine.tls_probe(_target(server.port, ca), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert "expired" in answer["error"].lower()


def test_engine_refuses_a_ca_outside_the_trust_directory_before_the_socket(tmp_path, trust, authority, monkeypatch):
    outside = _install(tmp_path, authority, "outside-ca")
    monkeypatch.setattr(
        engine.socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("socket must not open")),
    )
    with pytest.raises(ValueError):
        engine.tls_probe(_target(443, outside), 443, None)


def test_the_tls_probe_signature_offers_no_way_to_skip_verification():
    import inspect
    assert list(inspect.signature(engine.tls_probe).parameters) == ["auth", "port", "server_name"]


def _device(**extra) -> helper_inventory.Device:
    helper = {
        "account_role": "read-only",
        "ssh_platform": "linux",
        "enabled_queries": ["kernel"],
        "egress": {
            "addresses": ["192.0.2.10"], "tcp_ports": [22, 443], "udp_ports": [],
            "tcp_port_ranges": [], "udp_port_ranges": [], "allow_icmp": False,
            "allow_dns": False, "tls_server_names": [],
        },
        **extra,
    }
    return helper_inventory.Device(
        name="linux-a.example.invalid", platform="linux", address="192.0.2.10", port=22,
        role="lab", credential="linux-a-ro",
        host_key_fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        legacy_ssh=None, auditor=None, helper=helper,
    )


def test_inventory_without_the_field_keeps_the_104_behaviour(trust):
    assert helper_inventory.section(_device()).tls_ca_certificate is None
    assert helper_inventory.section(_device(tls_ca_certificate=None)).tls_ca_certificate is None


def test_inventory_accepts_a_ca_pem_inside_the_trust_directory(trust, authority):
    ca = _install(trust, authority)
    assert helper_inventory.section(_device(tls_ca_certificate=str(ca))).tls_ca_certificate == str(ca)


def _refused(value) -> None:
    with pytest.raises(helper_inventory.InventoryError):
        helper_inventory.section(_device(tls_ca_certificate=value))


def test_inventory_refuses_a_missing_file(trust):
    _refused(str(trust / "absent"))


def test_inventory_refuses_a_directory(trust):
    (trust / "folder").mkdir()
    _refused(str(trust / "folder"))


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_inventory_refuses_an_unreadable_file(trust, authority):
    ca = _install(trust, authority)
    ca.chmod(0)
    try:
        _refused(str(ca))
    finally:
        ca.chmod(0o644)


def test_inventory_refuses_a_certificate_that_is_not_a_ca(trust, authority):
    path = trust / "leaf"
    path.write_bytes(_pem(_leaf(authority)[1]))
    _refused(str(path))


def test_inventory_refuses_a_file_that_is_not_pem(trust):
    path = trust / "garbage"
    path.write_bytes(b"not a certificate\n")
    _refused(str(path))


def test_inventory_refuses_a_ca_file_that_also_holds_a_private_key(trust, authority):
    path = trust / "with-key"
    path.write_bytes(_pem(authority[1]) + _key_pem(authority[0]))
    _refused(str(path))


def test_inventory_refuses_a_ca_outside_the_trust_directory(tmp_path, trust, authority):
    _refused(str(_install(tmp_path, authority, "outside-ca")))


def test_inventory_refuses_a_symlink_that_leaves_the_trust_directory(tmp_path, trust, authority):
    outside = _install(tmp_path, authority, "outside-ca")
    (trust / "link").symlink_to(outside)
    _refused(str(trust / "link"))


@pytest.mark.parametrize("value", ["certs/private-ca", "-----BEGIN CERTIFICATE-----", 7, "", "/a/../b"])
def test_inventory_refuses_inline_relative_or_non_string_values(trust, value):
    _refused(value)


def test_the_envelope_carries_the_ca_only_when_it_is_enrolled():
    assert TargetAuth.decode("device-a", _context()).tls_ca_certificate is None
    decoded = TargetAuth.decode("device-a", _context(tls_ca_certificate="/etc/netops-helper/certs/x"))
    assert decoded.tls_ca_certificate == "/etc/netops-helper/certs/x"
    for value in ("relative", 7, ""):
        with pytest.raises(AuthenticationContextError):
            TargetAuth.decode("device-a", _context(tls_ca_certificate=value))


def test_the_proxy_envelope_includes_the_enrolled_ca(trust, authority):
    import json
    from base64 import urlsafe_b64decode
    ca = _install(trust, authority)
    entry = _device(tls_ca_certificate=str(ca))
    section = helper_inventory.section(entry)
    credential = type("Credential", (), {"login": "reader", "kind": "password", "use": lambda self: "pw-123"})()
    encoded = helper_proxy.Proxy._auth_context(None, entry, section, credential, None, "tls_probe")
    data = json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert data["tls_ca_certificate"] == str(ca)
    plain = helper_proxy.Proxy._auth_context(None, entry, helper_inventory.section(_device()), credential, None, "tls_probe")
    assert "tls_ca_certificate" not in json.loads(urlsafe_b64decode(plain + "=" * (-len(plain) % 4)))
