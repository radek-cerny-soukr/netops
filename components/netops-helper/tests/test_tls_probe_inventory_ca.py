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


def _leaf(authority, *, address: str | None = LOOPBACK, dns: str | None = None, expired: bool = False,
          san: bool = True):
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
            critical=False,
        )
    )
    if san:
        certificate = certificate.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return key, certificate.sign(authority_key, hashes.SHA256())


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


@pytest.mark.parametrize("pin_mode", ["correct", "wrong", "absent"])
def test_untrusted_certificate_is_diagnostic_and_compared_to_enrolled_pin(tmp_path, trust, authority, monkeypatch, pin_mode):
    import hashlib
    leaf = _leaf(authority)
    fingerprint = hashlib.sha256(leaf[1].public_bytes(serialization.Encoding.DER)).hexdigest()
    server = _serve(tmp_path, leaf)
    pin = fingerprint if pin_mode == "correct" else "0" * 64 if pin_mode == "wrong" else None
    target = replace(_target(server.port, None), fortios_rest_certificate_sha256=pin, fortios_rest_port=server.port)
    try:
        answer = engine.tls_probe(target, server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["certificate_verified"] is False
    # nothing unverified sits at the level of the verified fields
    assert not {"certificate_sha256", "subject", "issuer", "san", "not_before", "not_after", "pin_match",
                "certificate_source"} & set(answer)
    details = answer["unverified_certificate"]
    assert details["source"] == "unverified diagnostic handshake"
    assert details["certificate_sha256"] == fingerprint
    assert details["pin_match"] == (None if pin is None else pin_mode == "correct")
    assert "fixture leaf" in details["subject"]
    assert LOOPBACK in details["san"]
    assert datetime.fromisoformat(details["not_before"]).utcoffset() is not None
    assert datetime.fromisoformat(details["not_after"]).utcoffset() is not None


def test_unverified_certificate_without_alternative_names_reports_an_empty_san(tmp_path, trust, authority):
    server = _serve(tmp_path, _leaf(authority, san=False))
    try:
        answer = engine.tls_probe(_target(server.port, None), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["unverified_certificate"]["san"] == []
    assert "certificate_details_error" not in answer


def test_failed_diagnostic_handshake_reports_details_unavailable(tmp_path, trust, authority, monkeypatch):
    def unreadable(*args):
        raise ValueError("certificate cannot be decoded")

    monkeypatch.setattr(engine, "_certificate_details", unreadable)
    server = _serve(tmp_path, _leaf(authority))
    try:
        answer = engine.tls_probe(_target(server.port, None), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is False and answer["certificate_verified"] is False
    assert answer["certificate_details_error"] == "unverified_certificate_unavailable"
    assert "unverified_certificate" not in answer


@pytest.mark.parametrize("pin_mode", ["correct", "wrong"])
def test_verified_certificate_reports_pin_match_on_the_pin_port(tmp_path, trust, authority, monkeypatch, pin_mode):
    import hashlib
    leaf = _leaf(authority)
    fingerprint = hashlib.sha256(leaf[1].public_bytes(serialization.Encoding.DER)).hexdigest()
    ca = _install(trust, authority)
    server = _serve(tmp_path, leaf)
    pin = fingerprint if pin_mode == "correct" else "0" * 64
    try:
        answer = engine.tls_probe(replace(_target(server.port, ca), fortios_rest_certificate_sha256=pin, fortios_rest_port=server.port), server.port, None)
    finally:
        server.close()
    assert answer["ok"] is True and answer["certificate_verified"] is True
    assert answer["certificate_sha256"] == fingerprint
    assert answer["pin_match"] is (pin_mode == "correct")
    assert "unverified_certificate" not in answer


def test_pin_match_is_null_off_the_rest_port_in_both_branches(tmp_path, trust, authority):
    leaf = _leaf(authority)
    ca = _install(trust, authority)
    server = _serve(tmp_path, leaf)  # random port, not 443: the REST pin does not apply
    try:
        verified = engine.tls_probe(replace(_target(server.port, ca), fortios_rest_certificate_sha256="0" * 64),
                                    server.port, None)
        unverified = engine.tls_probe(replace(_target(server.port, None), fortios_rest_certificate_sha256="0" * 64),
                                      server.port, None)
    finally:
        server.close()
    assert verified["ok"] is True and verified["pin_match"] is None
    assert unverified["ok"] is False and unverified["unverified_certificate"]["pin_match"] is None


def test_pin_match_is_null_for_a_non_default_server_name(tmp_path, trust, authority, monkeypatch):
    server = _serve(tmp_path, _leaf(authority))
    target = replace(_target(server.port, None), fortios_rest_certificate_sha256="0" * 64, fortios_rest_port=server.port,
                     egress=EgressPolicy(addresses=(LOOPBACK,), tcp_ports=(server.port,),
                                         tls_server_names=("other.example.invalid",)))
    try:
        answer = engine.tls_probe(target, server.port, "other.example.invalid")
    finally:
        server.close()
    assert answer["ok"] is False
    assert answer["unverified_certificate"]["pin_match"] is None


@pytest.mark.parametrize("rest_port", [443, 8443])
def test_tls_auth_context_includes_pin_without_rest_token(rest_port):
    from base64 import urlsafe_b64decode
    from types import SimpleNamespace
    section = helper_inventory.section(_device())
    section = replace(section, fortios_rest_certificate_sha256="a" * 64, fortios_rest_port=rest_port)
    credential = SimpleNamespace(login="reader", kind="password", use=lambda: "synthetic-password")
    entry = SimpleNamespace(name="device-a", address=LOOPBACK, port=22,
                            host_key_fingerprint="SHA256:synthetic", legacy_ssh=None)
    encoded = helper_proxy.Proxy._auth_context(None, entry, section, credential, None, "tls_probe")
    import json
    envelope = json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert envelope["fortios_rest_port"] == rest_port
    assert envelope["fortios_rest_certificate_sha256"] == "a" * 64
    assert "fortios_rest_token" not in envelope
