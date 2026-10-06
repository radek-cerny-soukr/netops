#!/usr/bin/env python3
"""FTP and FTPS limits against real loopback servers."""

from __future__ import annotations

from base64 import b64encode
import datetime
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import types

from netops_core.hostkey import fingerprint_of
from netops_helper.auth import EgressPolicy, TargetAuth


LOOPBACK = "127.0.0.1"
PIN = fingerprint_of(b64encode(b"ftp-wire-host-key").decode("ascii"))
LISTING = b"/safe/alpha\r\n/safe/beta\r\n"


def _engine():
    if "icmplib" not in sys.modules and importlib.util.find_spec("icmplib") is None:
        stub = types.ModuleType("icmplib")
        stub.ping = lambda *args, **kwargs: None
        sys.modules["icmplib"] = stub
    return importlib.import_module("netops_helper.engine")


def _listener() -> socket.socket:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LOOPBACK, 0))
    listener.listen(1)
    listener.settimeout(20)
    return listener


def _target(alias: str, control_port: int, data_port: int) -> TargetAuth:
    return TargetAuth(
        alias=alias,
        host=LOOPBACK,
        port=22,
        login="account",
        secret="credential",
        host_key_fingerprint=PIN,
        sftp_roots=("/safe",),
        egress=EgressPolicy(
            addresses=(LOOPBACK,),
            tcp_ports=(control_port,),
            tcp_port_ranges=((data_port, data_port),),
        ),
    )


def _list(engine, auth: TargetAuth, port: int, use_tls: bool) -> dict:
    original = engine.record
    engine.record = lambda *args, **kwargs: None
    try:
        return engine.ftp_list(
            auth, "/safe", use_tls=use_tls, port=port,
            acknowledge_unencrypted=not use_tls,
        )
    finally:
        engine.record = original


class _FTPServer:
    def __init__(
        self,
        control_context: ssl.SSLContext | None = None,
        data_context: ssl.SSLContext | None = None,
        banner: bytes = b"220 ready\r\n",
    ) -> None:
        self.control_context = control_context
        self.data_context = data_context
        self.banner = banner
        self.listener = _listener()
        self.data_listener = _listener()
        self.port = self.listener.getsockname()[1]
        self.data_port = self.data_listener.getsockname()[1]
        self.data_failures: list[str] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        connection = None
        try:
            connection, _ = self.listener.accept()
            connection.settimeout(20)
            self._session(connection)
        except (OSError, ValueError):
            pass
        finally:
            if connection is not None:
                connection.close()
            self.listener.close()
            self.data_listener.close()

    def _session(self, connection: socket.socket) -> None:
        stream = connection.makefile("rwb", buffering=0)
        stream.write(self.banner)
        protected = False
        while True:
            line = stream.readline()
            if not line:
                return
            command = line.decode("ascii").strip().split(" ")[0].upper()
            if command == "AUTH" and self.control_context is not None:
                stream.write(b"234 go\r\n")
                connection = self.control_context.wrap_socket(connection, server_side=True)
                stream = connection.makefile("rwb", buffering=0)
            elif command == "USER":
                stream.write(b"331 password\r\n")
            elif command == "PASS":
                stream.write(b"230 logged in\r\n")
            elif command == "PROT":
                protected = True
                stream.write(b"200 ok\r\n")
            elif command in ("PBSZ", "TYPE"):
                stream.write(b"200 ok\r\n")
            elif command == "PASV":
                high, low = divmod(self.data_port, 256)
                stream.write(b"227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n" % (high, low))
            elif command == "NLST":
                stream.write(b"150 listing\r\n")
                stream.write(self._listing(protected))
            elif command == "QUIT":
                stream.write(b"221 bye\r\n")
                return
            else:
                stream.write(b"502 no\r\n")

    def _listing(self, protected: bool) -> bytes:
        data, _ = self.data_listener.accept()
        data.settimeout(20)
        try:
            if protected:
                data = self.data_context.wrap_socket(data, server_side=True)
            data.sendall(LISTING)
            if protected:
                data = data.unwrap()
            return b"226 done\r\n"
        except (OSError, ValueError) as exc:
            self.data_failures.append(type(exc).__name__)
            return b"426 aborted\r\n"
        finally:
            data.close()

    def close(self) -> None:
        self.thread.join(timeout=20)
        assert not self.thread.is_alive(), "loopback FTP server did not finish"


def _certificates(directory: Path) -> dict[str, tuple[Path, Path]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def write(name: str, certificate, key) -> tuple[Path, Path]:
        certificate_path = directory / f"{name}.pem"
        key_path = directory / f"{name}.key"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return certificate_path, key_path

    def builder(subject: str, issuer: str, public_key):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )

    pinned_key = ec.generate_private_key(ec.SECP256R1())
    pinned = (
        builder("pinned-device", "pinned-device", pinned_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(pinned_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        builder("other-leaf", "pinned-device", leaf_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pinned_key.public_key()),
            critical=False,
        )
        .sign(pinned_key, hashes.SHA256())
    )
    return {"pinned": write("pinned", pinned, pinned_key), "leaf": write("leaf", leaf, leaf_key)}


def _server_context(pair: tuple[Path, Path]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pair[0]), str(pair[1]))
    return context


def _sha256(pair: tuple[Path, Path]) -> str:
    der = ssl.PEM_cert_to_DER_cert(pair[0].read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def test_plain_ftp_lists_names_after_a_multi_line_banner() -> None:
    engine = _engine()
    banner = b"".join(b"220-welcome line %d\r\n" % index for index in range(20)) + b"220 ready\r\n"
    server = _FTPServer(banner=banner)
    result = _list(engine, _target("plain-device", server.port, server.data_port), server.port, False)
    server.close()
    assert result["ok"] is True, result
    assert result["entries"] == ["alpha", "beta"]


def test_ftp_control_replies_have_a_total_byte_budget() -> None:
    engine = _engine()
    listener = _listener()
    port = listener.getsockname()[1]
    stop = threading.Event()
    sent = [0]

    def flood() -> None:
        connection = None
        try:
            connection, _ = listener.accept()
            connection.settimeout(20)
            line = b"220-" + b"A" * 8000 + b"\r\n"
            while not stop.is_set():
                connection.sendall(line)
                sent[0] += len(line)
        except OSError:
            pass
        finally:
            if connection is not None:
                connection.close()
            listener.close()

    thread = threading.Thread(target=flood, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        result = _list(engine, _target("flooding-device", port, 50_000), port, False)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
        thread.join(timeout=20)
    assert result["ok"] is False, result
    assert result["failure_stage"] == "connect", result
    assert result["error"] == "ValueError: FTP control replies exceed the receive byte budget", result
    assert elapsed < 10, elapsed


def test_ftps_pin_binds_the_exact_leaf_on_the_data_connection() -> None:
    engine = _engine()
    original_pins, original_directory = engine.TLS_PINS_PATH, engine.TLS_CERT_DIR
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        certificates = directory / "certs"
        certificates.mkdir()
        pairs = _certificates(certificates)
        assert _sha256(pairs["pinned"]) != _sha256(pairs["leaf"])
        pins = directory / "tls-pins.json"
        pins.write_text(json.dumps({"pinned-device": {
            "sha256": _sha256(pairs["pinned"]),
            "certificate": str(pairs["pinned"][0]),
        }}), encoding="utf-8")
        engine.TLS_PINS_PATH, engine.TLS_CERT_DIR = pins, certificates
        try:
            outcomes = {}
            for label, control, data in (
                ("same", "pinned", "pinned"),
                ("issued_by_pin", "pinned", "leaf"),
                ("control_issued_by_pin", "leaf", "pinned"),
            ):
                server = _FTPServer(
                    _server_context(pairs[control]), _server_context(pairs[data]),
                )
                outcomes[label] = _list(
                    engine, _target("pinned-device", server.port, server.data_port),
                    server.port, True,
                )
                server.close()
        finally:
            engine.TLS_PINS_PATH, engine.TLS_CERT_DIR = original_pins, original_directory
    same = outcomes["same"]
    assert same["ok"] is True, same
    assert same["certificate_pinned"] is True
    assert same["entries"] == ["alpha", "beta"]
    issued = outcomes["issued_by_pin"]
    assert issued["ok"] is False, issued
    assert issued["failure_stage"] == "directory_list", issued
    assert issued["error_type"] == "SSLCertVerificationError", issued
    assert "pinned FTPS certificate mismatch on the data connection" in issued["error"], issued
    assert "entries" not in issued
    control = outcomes["control_issued_by_pin"]
    assert control["ok"] is False, control
    assert control["failure_stage"] == "certificate_pin", control


def main() -> int:
    test_plain_ftp_lists_names_after_a_multi_line_banner()
    test_ftp_control_replies_have_a_total_byte_budget()
    test_ftps_pin_binds_the_exact_leaf_on_the_data_connection()
    print("ftp_wire_safety_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
