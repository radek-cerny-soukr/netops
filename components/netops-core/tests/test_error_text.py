import subprocess

import pytest

from netops_core import sftp as sftp_module
from netops_core.ssh import REASONS, UNKNOWN_REASON, SshError, reason, run_command

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
COMMAND = "show"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
PEER_CANARY = "KANARCI-TAJEMSTVI-OD-PROTISTRANY"


class FakeCredential:
    kind = "ssh-key"
    login = LOGIN
    name = "fw-a-ro"

    def use(self):
        return "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n"


def _runner(code, stderr, stdout=b""):
    def run(call, **rest):
        return subprocess.CompletedProcess(call, code, stdout, stderr)

    return run


def _ssh_failure(stderr, code=255):
    with pytest.raises(SshError) as caught:
        run_command(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND,
            run=_runner(code, stderr),
        )
    return caught.value


def _sftp_failure(stderr, code=255):
    with pytest.raises(sftp_module.SftpError) as caught:
        sftp_module.stat(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, "/safe",
            run=_runner(code, stderr),
        )
    return caught.value


def test_what_a_device_writes_on_standard_error_never_reaches_the_ssh_message():
    banner = ("Permission denied. password=%s\n" % PEER_CANARY).encode("utf-8")
    error = _ssh_failure(banner)

    assert PEER_CANARY not in str(error)
    assert PEER_CANARY not in repr(error)
    assert "the device refused the credential" in str(error)
    assert PEER_CANARY in error.said


def test_what_a_device_writes_on_standard_error_never_reaches_the_sftp_message():
    banner = ("Connection closed. token=%s\n" % PEER_CANARY).encode("utf-8")
    error = _sftp_failure(banner)

    assert PEER_CANARY not in str(error)
    assert PEER_CANARY not in repr(error)
    assert "the device closed the connection" in str(error)
    assert PEER_CANARY in error.said


def test_a_failure_the_transport_does_not_know_says_so_and_echoes_nothing():
    error = _ssh_failure(("weird device noise %s\n" % PEER_CANARY).encode("utf-8"))

    assert UNKNOWN_REASON in str(error)
    assert PEER_CANARY not in str(error)
    assert "weird device noise" not in str(error)


def test_every_reason_is_a_fixed_sentence_of_this_module():
    meanings = {meaning for _, meaning in REASONS}

    assert UNKNOWN_REASON not in meanings
    for marker, meaning in REASONS:
        assert reason("prefix %s suffix" % marker) in meanings
        assert marker not in meaning


def test_a_client_that_said_nothing_gets_no_reason():
    assert reason("") == ""
    assert reason(None) == ""
    error = _ssh_failure(b"")
    assert "exit code 255" in str(error)
    assert error.said == ""
