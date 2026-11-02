"""SNMPv3 engine boundary: real USM objects, mocked DNS and UDP backend."""
from dataclasses import replace
import json
from unittest import IsolatedAsyncioTestCase, mock

from pysnmp.hlapi.v3arch import asyncio as snmp
from pysnmp.smi import builder, view
from netops_helper import engine
from netops_helper.auth import AuthenticationMaterialError, EgressPolicy, TargetAuth


ADDRESS = "192.0.2.20"
OID = "1.3.6.1.2.1.1.1.0"
USM = {
    "user": "fixture-monitor",
    "auth_protocol": "sha256",
    "auth_key": "fixture-auth-key-91",
    "priv_protocol": "aes128",
    "priv_key": "fixture-privacy-key-82",
}


def enrolled():
    return TargetAuth(
        alias="snmp-fixture", host="snmp.example.invalid", port=22,
        login="reader", secret="fixture-ssh-key-73",
        host_key_fingerprint="SHA256:fixture", ssh_platform="fortinet",
        snmp_usm=dict(USM),
        egress=EgressPolicy(addresses=(ADDRESS,), udp_ports=(161,), allow_dns=True),
    )


def printable(text):
    value = mock.Mock()
    value.prettyPrint.return_value = text
    value.get_oid.return_value = value
    return value


class SnmpV3Engine(IsolatedAsyncioTestCase):
    def setUp(self):
        self.audit = self.enterContext(mock.patch.object(engine, "record"))
        self.resolve = self.enterContext(
            mock.patch.object(engine, "_resolve_target_ipv4", return_value=(ADDRESS,)))
        self.backend_engine = self.enterContext(mock.patch.object(snmp, "SnmpEngine"))
        self.transport = object()
        self.create = self.enterContext(mock.patch.object(
            snmp.UdpTransportTarget, "create", new_callable=mock.AsyncMock,
            return_value=self.transport))
        self.get = self.enterContext(mock.patch.object(
            snmp, "get_cmd", new_callable=mock.AsyncMock,
            return_value=(None, False, 0, [])))

    def assert_private(self, result, auth):
        rendered = json.dumps(result) + repr(self.audit.call_args_list)
        for secret in (auth.secret, USM["auth_key"], USM["priv_key"]):
            self.assertNotIn(secret, rendered)

    async def test_get_uses_real_authpriv_sha256_aes128_and_redacts_values(self):
        auth = enrolled()
        self.assertTrue({auth.secret, USM["auth_key"], USM["priv_key"]} <= set(auth.secrets))
        raw_value = "public " + " ".join((auth.secret, USM["auth_key"], USM["priv_key"]))
        self.get.return_value = (
            None, False, 0, [(printable(OID), printable(raw_value))])
        result = await engine.snmp_get(auth, [OID], 161)

        self.assertTrue(result["ok"])
        self.assertEqual(result["values"][0]["oid"], OID)
        self.assertIn("public", result["values"][0]["value"])
        self.assert_private(result, auth)
        args = self.get.await_args.args
        actual = args[1]
        self.assertIsInstance(actual, snmp.UsmUserData)
        self.assertEqual(actual.security_level, "authPriv")
        self.assertEqual(actual.security_model, 3)
        self.assertEqual(actual.message_processing_model, 3)
        self.assertEqual(actual.authentication_protocol, snmp.USM_AUTH_HMAC192_SHA256)
        self.assertEqual(actual.privacy_protocol, snmp.USM_PRIV_CFB128_AES)
        self.assertEqual(actual.userName, USM["user"])
        self.assertEqual(actual.authentication_key, USM["auth_key"])
        self.assertEqual(actual.privacy_key, USM["priv_key"])
        self.assertIs(args[0], self.backend_engine.return_value)
        self.assertIs(args[2], self.transport)
        self.get.assert_awaited_once()
        self.create.assert_awaited_once_with((ADDRESS, 161), timeout=2, retries=1)
        self.backend_engine.return_value.close_dispatcher.assert_called_once_with()

    async def test_resolved_sysdescr_returns_numeric_oid_and_preserves_empty_value(self):
        mib_builder = builder.MibBuilder()
        mib_builder.load_modules("SNMPv2-MIB")
        mib_view = view.MibViewController(mib_builder)
        var_bind = snmp.ObjectType(
            snmp.ObjectIdentity("SNMPv2-MIB", "sysDescr", 0), ""
        ).resolve_with_mib(mib_view)
        name, value = var_bind
        self.assertEqual(name.get_mib_symbol()[:2], ("SNMPv2-MIB", "sysDescr"))
        self.assertNotEqual(name.prettyPrint(), OID)
        self.assertEqual(name.get_oid().prettyPrint(), OID)
        self.assertEqual(value.prettyPrint(), "")
        self.get.return_value = (None, False, 0, [var_bind])

        auth = enrolled()
        result = await engine.snmp_get(auth, [OID], 161)

        self.assertTrue(result["ok"])
        self.assertEqual(result["values"], [{"oid": OID, "value": ""}])
        self.assert_private(result, auth)
        self.get.assert_awaited_once()
        self.backend_engine.return_value.close_dispatcher.assert_called_once_with()

    async def test_missing_or_weak_usm_is_rejected_before_dns_or_udp(self):
        for usm in (None, {**USM, "auth_protocol": "md5"},
                    {**USM, "priv_protocol": "des"}):
            with self.subTest(usm=usm):
                with self.assertRaises(AuthenticationMaterialError):
                    await engine.snmp_get(replace(enrolled(), snmp_usm=usm), [OID], 161)
        self.resolve.assert_not_called()
        self.create.assert_not_awaited()
        self.get.assert_not_awaited()
        self.backend_engine.assert_not_called()

    async def test_backend_exception_redacts_credentials_and_closes(self):
        auth = enrolled()
        self.get.side_effect = RuntimeError("backend failed " + " ".join((auth.secret, USM["auth_key"], USM["priv_key"])))
        result = await engine.snmp_get(auth, [OID], 161)
        self.assertFalse(result["ok"])
        self.assertIn("backend failed", result["error"])
        self.assert_private(result, auth)
        self.backend_engine.return_value.close_dispatcher.assert_called_once_with()

    async def test_protocol_error_redacts_credentials_and_closes(self):
        auth = enrolled()
        self.get.return_value = ("reply failed " + " ".join((auth.secret, USM["auth_key"], USM["priv_key"])), False, 0, [])
        result = await engine.snmp_get(auth, [OID], 161)
        self.assertFalse(result["ok"])
        self.assertIn("reply failed", result["error"])
        self.assert_private(result, auth)
        self.backend_engine.return_value.close_dispatcher.assert_called_once_with()

    async def test_transport_failure_preserves_cleanup(self):
        auth = enrolled()
        self.create.side_effect = OSError("transport failed " + " ".join((auth.secret, USM["auth_key"], USM["priv_key"])))
        result = await engine.snmp_get(auth, [OID], 161)
        self.assertFalse(result["ok"])
        self.assert_private(result, auth)
        self.get.assert_not_awaited()
        self.backend_engine.return_value.close_dispatcher.assert_called_once_with()
