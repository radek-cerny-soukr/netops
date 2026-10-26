import contextlib
import io
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from netops_helper import proxy


class ProxyNegotiationDiagnostics(unittest.TestCase):
    def test_runner_command_preserves_negotiation_diagnostics(self):
        command = proxy._ssh_command({"host": "127.0.0.1", "port": 2222}, "synthetic-fixture", "/tmp/synthetic-known-hosts", None)
        self.assertIn("LogLevel=INFO", command)
        self.assertNotIn("LogLevel=ERROR", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertFalse(any(arg.startswith("HostKeyAlgorithms=") or arg.startswith("KexAlgorithms=") for arg in command))

    def test_negotiation_category_is_safe_and_scoped_to_runner(self):
        raw = "Unable to negotiate with 192.0.2.99 port 22: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1"
        category, message = proxy._classify_ssh_stderr(raw)
        self.assertEqual(category, "ssh_negotiation")
        self.assertIn("runner", message)
        self.assertNotIn("192.0.2.99", message)
        self.assertNotIn("legacy_ssh", message)
        self.assertNotIn("diffie-hellman", message)

    def _runner_diagnostic(self, stderr, exit_code):
        command = proxy._ssh_command(
            {"host": "192.0.2.99", "port": 2222}, "synthetic-fixture",
            "/tmp/synthetic-known-hosts", None,
        )
        closed = mock.Mock()
        session = SimpleNamespace(
            stdout_lock=threading.Lock(), open_session=lambda: 1,
            accepting=lambda epoch: True, close_session=closed,
        )
        child = SimpleNamespace(
            stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO(stderr.encode()),
            wait=mock.Mock(return_value=exit_code),
        )
        output = io.StringIO()
        with mock.patch.object(proxy.subprocess, "Popen", return_value=child) as spawned:
            with contextlib.redirect_stderr(output):
                connection = proxy._ServerConnection(session, command, {}, (), None)
                self.assertTrue(connection.start())
                connection.response_thread.join(timeout=2)
                self.assertFalse(connection.response_thread.is_alive())
                self.assertEqual(connection.stop(), exit_code)
        spawned.assert_called_once()
        self.assertEqual(spawned.call_args.args[0], command)
        self.assertIn("LogLevel=INFO", spawned.call_args.args[0])
        closed.assert_called_once_with("transport_closed", 1)
        return output.getvalue()

    def test_runner_banner_preserves_real_failure_category(self):
        banner = "Authorized access only. No matching entries in this notice imply permission.\n"
        negotiation = (
            "Unable to negotiate with 192.0.2.99 port 2222: no matching key exchange method found. "
            "Their offer: diffie-hellman-group14-sha1\n"
        )
        cases = (
            (banner + negotiation, "ssh_negotiation",
             "SSH algorithm negotiation with the runner failed. Update the runner SSH service or review its allowed algorithms."),
            (banner + "Permission denied (publickey,password).\n", "ssh_authentication",
             "SSH authentication to the runner failed."),
            (banner, "ssh_transport", proxy.SSH_TRANSPORT_FAILURE_MESSAGE),
        )
        for stderr, category, message in cases:
            with self.subTest(category=category):
                output = self._runner_diagnostic(stderr, 255)
                self.assertEqual(
                    output, f"netops_proxy_transport category={category} message={message}\n",
                )
                self.assertNotIn("192.0.2.99", output)
                self.assertNotIn("diffie-hellman", output)
                self.assertNotIn("Authorized access", output)

    def test_successful_runner_banner_is_not_a_transport_failure(self):
        banner = "Authorized access only. Authentication failed is a policy-example phrase.\n"
        self.assertEqual(self._runner_diagnostic(banner, 0), "")


if __name__ == "__main__":
    unittest.main()
