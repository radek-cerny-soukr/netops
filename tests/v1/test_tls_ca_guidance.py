from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from netops.files import write_private


def _certificate(*, ca):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic fixture")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


class TlsCaGuidance(unittest.TestCase):
    def refused(self, value, prepare=None):
        from netops.operator import _validate_helper_inventory
        from netops_core import vault
        from netops_helper import inventory
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            certs = directory / "certs"
            certs.mkdir()
            if prepare:
                prepare(directory, certs)
            write_private(directory / "vault.json", json.dumps({"version": 2, "credentials": {
                "fixture-ro": {"kind": "password", "login": "fixture-user", "value": "synthetic-only-value"}}}).encode())
            store = vault.load(directory / "vault.json")
            device = {"name": "linux-a.example.invalid", "platform": "linux",
                      "address": "192.0.2.10", "port": 22, "role": "lab", "credential": "fixture-ro",
                      "host_key_fingerprint": "SHA256:" + "A" * 43, "legacy_ssh": None, "auditor": None,
                      "helper": {"account_role": "read-only", "ssh_platform": "linux",
                                 "enabled_queries": ["kernel"],
                                 "egress": {"addresses": ["192.0.2.10"], "tcp_ports": [22, 443],
                                            "udp_ports": [], "tcp_port_ranges": [], "udp_port_ranges": [],
                                            "allow_icmp": False, "allow_dns": False, "tls_server_names": []},
                                 "tls_ca_certificate": value(certs) if callable(value) else value}}
            write_private(directory / "inventory.json", json.dumps({"version": 2, "devices": [device]}).encode())
            with patch.object(inventory, "TLS_CERT_DIR", certs), self.assertRaises(ValueError) as caught:
                _validate_helper_inventory(directory / "inventory.json", store)
        message = str(caught.exception)
        self.assertIn("inventory.devices[0].helper.tls_ca_certificate", message)
        self.assertNotIn("BEGIN", message)
        self.assertNotIn("synthetic-only-value", message)
        return message

    def test_path_outside_the_certs_directory(self):
        self.assertIn("under /etc/netops-helper/certs", self.refused("/etc/ssl/certs/ca.pem"))

    def test_non_canonical_path(self):
        self.assertIn("canonical absolute path", self.refused(lambda certs: str(certs) + "/../certs/ca.pem"))

    def test_inline_pem(self):
        self.assertIn("not inline PEM", self.refused("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"))

    def test_missing_file_or_mount(self):
        self.assertIn("is the certs directory mounted?", self.refused(lambda certs: str(certs / "absent.pem")))

    def test_leaf_that_is_not_a_ca(self):
        def prepare(directory, certs):
            (certs / "leaf.pem").write_bytes(_certificate(ca=False))
        self.assertIn("not a CA certificate", self.refused(lambda certs: str(certs / "leaf.pem"), prepare))

    def test_private_key(self):
        def prepare(directory, certs):
            (certs / "key.pem").write_bytes(_certificate(ca=True) + b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n")
        self.assertIn("contains a private key", self.refused(lambda certs: str(certs / "key.pem"), prepare))

    def test_symlink_leaving_the_certs_directory(self):
        def prepare(directory, certs):
            (directory / "outside.pem").write_bytes(_certificate(ca=True))
            (certs / "link.pem").symlink_to(directory / "outside.pem")
        self.assertIn("symlink leaves", self.refused(lambda certs: str(certs / "link.pem"), prepare))


if __name__ == "__main__":
    unittest.main()
