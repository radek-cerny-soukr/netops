import asyncio
import types
import unittest
from unittest import mock

from netops_helper import engine


class Egress:
    def allows_address(self, address):
        return True


def make_auth():
    return types.SimpleNamespace(
        alias="fw-1", host="192.0.2.1", port=22, ssh_platform="fortinet", legacy_ssh=None, secrets=(),
        egress=Egress(), tls_ca_certificate=None, fortios_rest_certificate_sha256=None, snmp_credential=None,
        require_snmp_usm=lambda: None, require_udp_port=lambda port: None, require_dns=lambda: None, require_icmp=lambda: None, require_tcp_port=lambda port: None,
        require_tls_server_name=lambda name: name or "fw-1.example.invalid")


class VantageTest(unittest.TestCase):
    """The decorated tools (audit wrapper included) return the vantage on success and on failure."""

    def setUp(self):
        patcher = mock.patch.object(engine, "record")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.auth = make_auth()

    def check(self, result):
        self.assertEqual(result["vantage"], "helper_host")
        return result

    def test_dns_probe(self):
        self.assertTrue(self.check(engine.dns_probe(self.auth))["ok"])
        with mock.patch.object(engine, "_resolve_target_ipv4", side_effect=OSError("boom")):
            self.assertFalse(self.check(engine.dns_probe(self.auth))["ok"])

    def test_tcp_probe(self):
        with mock.patch.object(engine.socket, "create_connection"):
            self.assertTrue(self.check(engine.tcp_probe(self.auth, 22, 1.0))["ok"])
        with mock.patch.object(engine.socket, "create_connection", side_effect=OSError("refused")):
            self.assertFalse(self.check(engine.tcp_probe(self.auth, 22, 1.0))["ok"])

    def test_icmp_probe(self):
        answer = types.SimpleNamespace(is_alive=True, packets_sent=1, packets_received=1, packet_loss=0.0,
                                       min_rtt=1.0, avg_rtt=1.0, max_rtt=1.0, jitter=0.0)
        with mock.patch.object(engine, "ping", return_value=answer):
            self.assertTrue(self.check(engine.icmp_probe(self.auth, 1))["ok"])
        with mock.patch.object(engine, "ping", side_effect=OSError("down")):
            self.assertFalse(self.check(engine.icmp_probe(self.auth, 1))["ok"])

    def test_tls_probe_failure_and_success(self):
        with mock.patch.object(engine.socket, "create_connection", side_effect=OSError("refused")):
            self.assertFalse(self.check(engine.tls_probe(self.auth, 443, None))["ok"])
        wrapped = mock.MagicMock()
        wrapped.getpeercert.side_effect = lambda binary_form=False: b"der" if binary_form else {"subject": (), "issuer": ()}
        wrapped.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        wrapped.version.return_value = "TLSv1.3"
        context = mock.MagicMock()
        context.minimum_version = engine.ssl.TLSVersion.TLSv1_2
        context.wrap_socket.return_value.__enter__.return_value = wrapped
        with mock.patch.object(engine.socket, "create_connection"), \
                mock.patch.object(engine.ssl, "create_default_context", return_value=context):
            self.assertTrue(self.check(engine.tls_probe(self.auth, 443, None))["ok"])

    def test_snmp_get_resolution_failure(self):
        with mock.patch.object(engine, "_resolve_target_ipv4", side_effect=OSError("boom")):
            result = asyncio.run(engine.snmp_get(self.auth, ["1.3.6.1.2.1.1.1.0"], 161))
        self.assertFalse(self.check(result)["ok"])
