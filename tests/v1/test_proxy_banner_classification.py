import contextlib
import io
import unittest

from netops_helper import proxy


NEGOTIATION = (
    "Unable to negotiate with 192.0.2.99 port 2222: no matching key exchange method found. "
    "Their offer: diffie-hellman-group14-sha1\n"
)


def _diagnostic(stderr, exit_code=255):
    state = {"emitted": False}
    proxy._drain_stderr(io.BytesIO(stderr.encode()), (), state)
    output = io.StringIO()
    with contextlib.redirect_stderr(output):
        proxy._exit_diagnostic(exit_code, False, state)
    return output.getvalue()


def _line(category, message):
    return f"netops_proxy_transport category={category} message={message}\n"


AUTH = _line("ssh_authentication", "SSH authentication to the runner failed.")
CONNECTION = _line("ssh_connection", "The SSH connection to the runner failed.")
NEGOTIATED = _line(
    "ssh_negotiation",
    "SSH algorithm negotiation with the runner failed. Update the runner SSH service or review its allowed algorithms.",
)


class RunnerBannerDoesNotSteerClassification(unittest.TestCase):
    def assertSafe(self, output):
        for hidden in ("Banner-Marker", "192.0.2.99", "diffie-hellman"):
            self.assertNotIn(hidden, output)

    def test_banner_permission_denied_does_not_hide_a_connection_reset(self):
        stderr = (
            "Banner-Marker: Permission denied to anyone without a contract.\n"
            "Permission denied unless authorised.\n"
            "Connection reset by 192.0.2.99 port 2222\n"
        )
        output = _diagnostic(stderr)
        self.assertEqual(output, CONNECTION)
        self.assertSafe(output)

    def test_banner_timed_out_does_not_turn_an_unknown_failure_into_connection(self):
        banner = "Banner-Marker: idle sessions are timed out after 5 minutes.\nConnection closed when idle.\n"
        for tail in ("", "remote helper ended without a reason\n"):
            with self.subTest(tail=tail):
                output = _diagnostic(banner + tail)
                self.assertEqual(output, _line("ssh_transport", proxy.SSH_TRANSPORT_FAILURE_MESSAGE))
                self.assertSafe(output)

    def test_banner_host_key_phrase_does_not_hide_authentication(self):
        stderr = (
            "Banner-Marker notice\nHost key verification failed.\n"
            "operator@192.0.2.99: Permission denied (publickey).\n"
        )
        self.assertEqual(_diagnostic(stderr), AUTH)

    def test_huge_banner_keeps_the_real_negotiation_line(self):
        banner = ("Banner-Marker " + "B" * 99 + "\n") * 1024
        self.assertGreater(len(banner), 100 * 1024)
        output = _diagnostic(banner + NEGOTIATION)
        self.assertEqual(output, NEGOTIATED)
        self.assertSafe(output)

    def test_huge_single_banner_line_is_dropped_whole(self):
        stderr = "Permission denied " + "B" * (100 * 1024) + "\nremote helper ended\n"
        state = {"emitted": False}
        proxy._drain_stderr(io.BytesIO(stderr.encode()), (), state)
        self.assertEqual(state["captured"], "remote helper ended\n")

    def test_banner_permission_denied_keeps_negotiation(self):
        stderr = "Banner-Marker: Permission denied for guests.\n" + NEGOTIATION
        self.assertEqual(_diagnostic(stderr), NEGOTIATED)

    def test_plain_openssh_lines_keep_their_categories(self):
        cases = (
            (NEGOTIATION, NEGOTIATED),
            ("operator@192.0.2.99: Permission denied (publickey,password).\n", AUTH),
            ("Received disconnect from 192.0.2.99 port 2222:2: Too many authentication failures\n", AUTH),
            ("ssh: connect to host 192.0.2.99 port 2222: Connection timed out\n", CONNECTION),
            ("ssh: connect to host 192.0.2.99 port 2222: Connection refused\n", CONNECTION),
            ("ssh: connect to host 192.0.2.99 port 2222: No route to host\n", CONNECTION),
            ("ssh: Could not resolve hostname runner.invalid: Name or service not known\n", CONNECTION),
            ("kex_exchange_identification: read: Connection reset by peer\n"
             "Connection reset by 192.0.2.99 port 2222\n", CONNECTION),
            ("Connection timed out during banner exchange\n"
             "Connection to 192.0.2.99 port 2222 timed out\n", CONNECTION),
            ("Connection closed by 192.0.2.99 port 2222\n", CONNECTION),
            ("No ED25519 host key is known for [192.0.2.99]:2222 and you have requested strict checking.\n"
             "Host key verification failed.\n", _line("ssh_host_key", "SSH host-key verification failed.")),
            ("Error response from daemon: No such container: netops-helper\n",
             _line("remote_exec", "The fixed remote container command could not start.")),
        )
        for stderr, expected in cases:
            with self.subTest(stderr=stderr):
                self.assertEqual(_diagnostic(stderr), expected)


    def test_real_openssh_disconnect_trailer_keeps_the_category(self):
        disconnect = (
            "Received disconnect from 192.0.2.99 port 2222:2: Too many authentication failures\n"
            "Disconnected from 192.0.2.99 port 2222\n"
        )
        host_key = _line("ssh_host_key", "SSH host-key verification failed.")
        remote_exec = _line("remote_exec", "The fixed remote container command could not start.")
        transport = _line("ssh_transport", proxy.SSH_TRANSPORT_FAILURE_MESSAGE)
        banner = "Banner-Marker: Permission denied to anyone.\n"
        cases = (
            (disconnect, AUTH),
            (banner + disconnect, AUTH),
            (banner + "operator@192.0.2.99: Permission denied (publickey,password,keyboard-interactive).\n", AUTH),
            ("No ED25519 host key is known for [192.0.2.99]:2222 and you have requested strict checking.\n"
             "Host key verification failed.\n", host_key),
            (NEGOTIATION, NEGOTIATED),
            ("ssh: connect to host 192.0.2.99 port 2222: Connection refused\n", CONNECTION),
            ("Connection closed by 192.0.2.99 port 2222\n", CONNECTION),
            (banner + "Error response from daemon: No such container: netops-helper\n", remote_exec),
            ("Received disconnect from 192.0.2.99 port 2222:11: Bye Bye\n"
             "Disconnected from 192.0.2.99 port 2222\n", transport),
            ("Banner-Marker: Received disconnect from 192.0.2.99 port 2222:2: Too many authentication failures\n"
             "Connection closed by 192.0.2.99 port 2222\n", CONNECTION),
            ("Banner-Marker: Too many authentication failures\n"
             "Received disconnect from 192.0.2.99 port 2222:11: Bye Bye\n"
             "Disconnected from 192.0.2.99 port 2222\n", transport),
            ("operator@192.0.2.99: Permission denied (publickey).\n"
             "Banner-Marker: Disconnected from 192.0.2.99 port 2222 at night\n", transport),
        )
        for stderr, expected in cases:
            with self.subTest(stderr=stderr):
                output = _diagnostic(stderr)
                self.assertEqual(output, expected)
                self.assertSafe(output)


class OnlyAnSshClientFailureHasAnSshCategory(unittest.TestCase):
    BANNERS = (
        "WARNING: Authentication failed attempts are logged.\n",
        "Notice: permission denied to unauthorised users\n",
    )
    TRANSPORT = _line("ssh_transport", proxy.SSH_TRANSPORT_FAILURE_MESSAGE)
    REMOTE_EXEC = _line("remote_exec", "The fixed remote container command could not start.")

    def test_banner_before_a_failed_remote_command_is_transport(self):
        for banner in self.BANNERS:
            for exit_code in (1, 137):
                with self.subTest(banner=banner, exit_code=exit_code):
                    self.assertEqual(_diagnostic(banner, exit_code), self.TRANSPORT)

    def test_remote_command_exit_never_takes_an_ssh_category(self):
        cases = (
            "operator@192.0.2.99: Permission denied (publickey).\n",
            "Host key verification failed.\n",
            NEGOTIATION,
            "ssh: connect to host 192.0.2.99 port 2222: Connection refused\n",
        )
        for stderr in cases:
            for exit_code in (1, 137):
                with self.subTest(stderr=stderr, exit_code=exit_code):
                    self.assertEqual(_diagnostic(stderr, exit_code), self.TRANSPORT)

    def test_remote_command_exit_keeps_the_remote_exec_category(self):
        for banner in ("",) + self.BANNERS:
            with self.subTest(banner=banner):
                self.assertEqual(
                    _diagnostic(banner + "Error response from daemon: No such container: netops-helper\n", 1),
                    self.REMOTE_EXEC,
                )

    def test_banner_alone_on_an_ssh_client_failure_is_transport(self):
        for banner in self.BANNERS:
            with self.subTest(banner=banner):
                self.assertEqual(_diagnostic(banner, 255), self.TRANSPORT)

    def test_banner_then_real_openssh_refusal_is_authentication(self):
        for banner in self.BANNERS:
            with self.subTest(banner=banner):
                self.assertEqual(
                    _diagnostic(banner + "operator@192.0.2.99: Permission denied (publickey).\n", 255),
                    AUTH,
                )

    def test_negotiation_needs_the_no_matching_message(self):
        for stderr in (
            "Unable to negotiate with 192.0.2.99 port 2222: invalid format\n",
            "Unable to negotiate with 192.0.2.99 port 2222\n",
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(_diagnostic(stderr, 255), self.TRANSPORT)


if __name__ == "__main__":
    unittest.main()
