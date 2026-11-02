from base64 import b64encode, urlsafe_b64encode
from dataclasses import replace
import json
from unittest import TestCase

from netops_core.hostkey import fingerprint_of
from netops_core.snmp import validate_snmp_usm
from netops_helper.auth import (
    AuthenticationContextError, AuthenticationMaterialError, TargetAuth,
)
from netops_helper.sanitize import redact


def usm():
    return {
        "user": "monitor", "auth_protocol": "sha256",
        "auth_key": "SNMP-AUTH-fixture-91", "priv_protocol": "aes128",
        "priv_key": "SNMP-PRIV-fixture-92",
    }


def envelope():
    return {
        "alias": "fixture", "host": "192.0.2.20", "port": 22,
        "login": "reader", "credential_kind": "password",
        "secret": "SSH-fixture-password",
        "host_key_fingerprint": fingerprint_of(b64encode(b"fixture-host-key").decode()),
        "account_role": "read-only", "role_boundary": None,
        "ssh_platform": None, "enabled_queries": [],
        "egress": {
            "addresses": ["192.0.2.20"], "tcp_ports": [22], "udp_ports": [161],
            "tcp_port_ranges": [], "udp_port_ranges": [],
            "allow_icmp": False, "allow_dns": False, "tls_server_names": [],
        },
        "snmp_usm": usm(),
    }


def decode(data):
    encoded = urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return TargetAuth.decode("fixture", encoded)


class SnmpV3Auth(TestCase):
    def test_enrolled_authpriv_and_shared_passwords_are_valid(self):
        material = usm()
        checked = validate_snmp_usm(material)
        self.assertEqual(checked, material)
        self.assertIsNot(checked, material)
        auth = decode(envelope())
        self.assertEqual(auth.require_snmp_usm(), material)
        auth.require_udp_port(161)
        shared = envelope()
        shared["snmp_usm"]["auth_key"] = shared["secret"]
        shared["snmp_usm"]["priv_key"] = shared["secret"]
        same = decode(shared)
        self.assertEqual(same.require_snmp_usm()["priv_key"], same.secret)

    def test_weak_missing_privacy_and_legacy_envelopes_are_rejected(self):
        for changes in (
            {"auth_protocol": "none", "priv_protocol": "none"},
            {"auth_protocol": "sha256", "priv_protocol": "none"},
            {"auth_protocol": "md5"},
        ):
            data = envelope()
            data["snmp_usm"].update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(AuthenticationContextError):
                    decode(data)
        data = envelope()
        del data["snmp_usm"]["priv_key"]
        with self.assertRaises(AuthenticationContextError):
            decode(data)
        data = envelope()
        del data["snmp_usm"]
        data["snmp_community"] = "legacy-fixture-community"
        with self.assertRaises(AuthenticationContextError):
            decode(data)

    def test_utf8_printable_bounds_and_exact_fields(self):
        valid = usm()
        valid.update(user="é" * 16, auth_key="é" * 4, priv_key="x" * 4096)
        self.assertEqual(validate_snmp_usm(valid), valid)
        for changes in (
            {"user": "é" * 17}, {"auth_key": "short"},
            {"priv_key": "x" * 4097}, {"priv_key": "secret\nvalue"},
            {"security_level": "authPriv"},
        ):
            material = usm()
            material.update(changes)
            with self.subTest(fields=tuple(changes)):
                with self.assertRaisesRegex(ValueError, "^invalid SNMPv3 authPriv material$"):
                    validate_snmp_usm(material)

    def test_direct_constructor_material_is_revalidated(self):
        auth = decode(envelope())
        for material in (None, {}, dict(usm(), priv_protocol="none")):
            with self.subTest(absent=material is None):
                with self.assertRaises(AuthenticationMaterialError) as raised:
                    replace(auth, snmp_usm=material).require_snmp_usm()
                self.assertEqual(str(raised.exception),
                                 "SNMPv3 authPriv material is absent or invalid")
        direct = replace(auth, snmp_usm=usm())
        direct.snmp_usm.pop("priv_key")
        with self.assertRaises(AuthenticationMaterialError):
            direct.require_snmp_usm()

    def test_both_keys_are_redacted_without_hiding_identifiers(self):
        auth = decode(envelope())
        material = auth.require_snmp_usm()
        message = " ".join((auth.secret, material["auth_key"], material["priv_key"],
                            material["user"], material["auth_protocol"],
                            material["priv_protocol"]))
        safe = redact(message, auth.secrets)
        for value in (auth.secret, material["auth_key"], material["priv_key"]):
            self.assertNotIn(value, safe)
        for value in (material["auth_key"], material["priv_key"]):
            self.assertNotIn(value, repr(auth))
        for value in ("monitor", "sha256", "aes128"):
            self.assertIn(value, safe)
        self.assertEqual(set(auth.secrets),
                         {auth.secret, material["auth_key"], material["priv_key"]})
