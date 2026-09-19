import os
import stat
import subprocess

import pytest

from netops_core.hostkey import (
    DIGEST_LENGTH,
    PREFIX,
    HostKeyError,
    checked_pin,
    fingerprint_of,
    keyscan_argv,
    known_hosts_file,
    matching_line,
    scan,
)

HOST = "192.0.2.10"
PORT = 22
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
PIN = "SHA256:9M3h8iWlwyP5wyoVC6j2DSPB/1Cp4FZhaD1HXhhC7m8"
OTHER_BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1C"
OTHER_PIN = "SHA256:LRBl/IE0CKazz9wDBkd7JxgDeHlWIdPFK+bTByIFq4w"
LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
OTHER_LINE = "%s ssh-rsa %s" % (HOST, OTHER_BLOB)
BAD_PINS = (
    None,
    PIN[len(PREFIX):],
    PIN[:-1],
    PIN + "A",
    "sha256:" + PIN[len(PREFIX):],
    PREFIX + "!" * DIGEST_LENGTH,
    "",
    "   ",
    0,
    True,
    [PIN],
)


class FakeRun:
    def __init__(self, stdout=None, returncode=0, error=None):
        self.stdout = ("%s\n" % LINE).encode("utf-8") if stdout is None else stdout
        self.returncode = returncode
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


def test_pin_shape_is_the_one_ssh_keygen_prints():
    assert checked_pin(PIN) == PIN
    assert len(PIN) == len(PREFIX) + DIGEST_LENGTH


@pytest.mark.parametrize("pin", BAD_PINS)
def test_a_broken_pin_is_refused_with_the_shape_it_expects(pin):
    with pytest.raises(HostKeyError) as caught:
        checked_pin(pin)
    assert "host_key_fingerprint must hold the sha256 host key fingerprint" in str(caught.value)
    assert PREFIX in str(caught.value)
    assert repr(pin) in str(caught.value)


def test_fingerprint_is_base64_sha256_of_the_decoded_blob_without_padding():
    assert fingerprint_of(BLOB) == PIN
    assert fingerprint_of(OTHER_BLOB) == OTHER_PIN
    assert not fingerprint_of(BLOB).endswith("=")


@pytest.mark.parametrize("blob", ("", "   ", "not base64!!", None, 1, ["AAAA"]))
def test_fingerprint_refuses_something_that_is_not_a_blob(blob):
    with pytest.raises(HostKeyError):
        fingerprint_of(blob)


def test_keyscan_argv_is_bounded_and_targets_the_device():
    assert keyscan_argv(HOST, 2222, 17.0) == ["ssh-keyscan", "-T", "17", "-p", "2222", HOST]
    assert keyscan_argv(HOST, PORT, 0.5)[2] == "1"


@pytest.mark.parametrize(
    "host,port,seconds",
    (
        ("audit-ro@192.0.2.10", PORT, 17),
        ("-oProxyCommand=true", PORT, 17),
        ("192.0.2.10/x", PORT, 17),
        ("", PORT, 17),
        (HOST, 0, 17),
        (HOST, 65536, 17),
        (HOST, True, 17),
        (HOST, PORT, 0),
        (HOST, PORT, "17"),
    ),
)
def test_keyscan_argv_refuses_a_target_it_cannot_write_down(host, port, seconds):
    with pytest.raises(HostKeyError):
        keyscan_argv(host, port, seconds)


def test_matching_line_returns_the_line_whose_fingerprint_is_pinned():
    lines = ["# 192.0.2.10:22 SSH-2.0-OpenSSH", OTHER_LINE, LINE]
    assert matching_line(lines, PIN) == LINE


def test_matching_line_skips_comments_and_lines_that_are_not_a_key():
    lines = ["# comment", "", "192.0.2.10 ssh-ed25519", "192.0.2.10 ssh-ed25519 !!!", LINE]
    assert matching_line(lines, PIN) == LINE


def test_no_matching_key_names_the_pin_and_the_count_but_never_the_keys():
    with pytest.raises(HostKeyError) as caught:
        matching_line([OTHER_LINE, OTHER_LINE], PIN)
    said = str(caught.value)
    assert PIN in said
    assert "2 key(s) offered" in said
    assert OTHER_BLOB not in said
    assert OTHER_PIN not in said


def test_an_empty_scan_still_names_the_pin_and_zero_keys():
    with pytest.raises(HostKeyError) as caught:
        matching_line(["# only a banner"], PIN)
    assert PIN in str(caught.value)
    assert "0 key(s) offered" in str(caught.value)


def test_scan_calls_the_keyscan_binary_the_way_the_contract_says():
    run = FakeRun()
    assert scan(HOST, PORT, PIN, 17, run=run) == LINE
    call = run.calls[0]
    assert call["argv"] == ["ssh-keyscan", "-T", "17", "-p", "22", HOST]
    assert call["kwargs"]["capture_output"] is True
    assert call["kwargs"]["timeout"] == 17.0
    assert call["kwargs"]["check"] is False
    assert set(call["kwargs"]["env"]) == {"PATH", "LC_ALL"}
    assert call["kwargs"]["env"]["LC_ALL"] == "C"


@pytest.mark.parametrize(
    "run",
    (
        FakeRun(returncode=1),
        FakeRun(stdout=b""),
        FakeRun(returncode=255, stdout=b""),
    ),
)
def test_scan_refuses_a_failed_or_empty_answer(run):
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 17, run=run)
    assert "offered no host key" in str(caught.value)
    assert HOST in str(caught.value)


def test_scan_refuses_an_answer_that_is_not_bytes():
    class Answer:
        returncode = 0
        stdout = "not bytes"

    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 17, run=lambda argv, **kwargs: Answer())
    assert "must answer with bytes on stdout" in str(caught.value)


@pytest.mark.parametrize(
    "error",
    (OSError("ssh-keyscan not found"), subprocess.TimeoutExpired(["ssh-keyscan"], 1)),
)
def test_scan_turns_a_broken_call_into_a_refusal_naming_the_host(error):
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 17, run=FakeRun(error=error))
    assert "cannot read the host key of %s" % HOST in str(caught.value)


def test_scan_refuses_a_broken_pin_before_it_runs_anything():
    run = FakeRun()
    with pytest.raises(HostKeyError):
        scan(HOST, PORT, "SHA256:short", 17, run=run)
    assert run.calls == []


def test_known_hosts_file_is_written_once_with_mode_0600(tmp_path):
    path = known_hosts_file(str(tmp_path), LINE)
    assert os.path.dirname(path) == str(tmp_path)
    assert open(path, encoding="utf-8").read() == "%s\n" % LINE
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with pytest.raises(HostKeyError) as caught:
        known_hosts_file(str(tmp_path), LINE)
    assert "cannot write the known hosts file" in str(caught.value)


@pytest.mark.parametrize("line", ("", "   ", None, 1, "a b c\nd e f", "a b c\x00"))
def test_known_hosts_file_refuses_something_that_is_not_one_key_line(tmp_path, line):
    with pytest.raises(HostKeyError) as caught:
        known_hosts_file(str(tmp_path), line)
    assert "host key line must be" in str(caught.value)
