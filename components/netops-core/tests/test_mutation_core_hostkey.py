import os
import subprocess
import types

import pytest

from netops_core import hostkey as hostkey_module
from netops_core import ssh as ssh_module
from netops_core.hostkey import (
    KEY_TYPES,
    KEYSCAN_CAPTURE_MAX_BYTES,
    PROBE_LOGIN,
    HostKeyError,
    HostKeyUnavailable,
    fingerprint_of,
    keyscan_argv,
    known_hosts_file,
    matching_line,
    probe_argv,
    scan,
)

HOST = "192.0.2.10"
PORT = 22
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
PIN = "SHA256:9M3h8iWlwyP5wyoVC6j2DSPB/1Cp4FZhaD1HXhhC7m8"
OTHER_BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1C"
LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
OTHER_LINE = "%s ssh-rsa %s" % (HOST, OTHER_BLOB)
SHA1_PROFILE = "rsa-sha1-dh14"
BROKEN_UTF8 = b"# \xff\xfe broken banner\n"


class Answer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class Keyscan:
    def __init__(self, stdout=b"", returncode=0, clock=None, step=0.0):
        self.stdout = stdout
        self.returncode = returncode
        self.clock = clock
        self.step = step
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
        if self.clock is not None:
            self.clock.now += self.step
        stdout = self.stdout(argv) if callable(self.stdout) else self.stdout
        return subprocess.CompletedProcess(argv, self.returncode, stdout, b"")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class Probe:
    def __init__(self, content, returncode=255, error=None):
        self.content = content
        self.returncode = returncode
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
        if self.error is not None:
            raise self.error
        if self.content is not None:
            known = [option.split("=", 1)[1] for option in argv if option.startswith("UserKnownHostsFile=")]
            with open(known[0], "wb") as handle:
                handle.write(self.content)
        return subprocess.CompletedProcess(argv, self.returncode, b"", b"")


def message(caught):
    return str(caught.value)


def assert_sentence(caught, subject, received=None):
    text = message(caught)
    assert text.startswith(subject), text
    if received is not None:
        assert text.endswith(received), text


@pytest.fixture
def fake_clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(hostkey_module, "time", types.SimpleNamespace(monotonic=clock.monotonic))
    return clock


@pytest.mark.parametrize("value", (None, 5, b"host"))
def test_a_host_that_is_not_text_is_refused_naming_the_value(value):
    with pytest.raises(HostKeyError) as caught:
        keyscan_argv(value, PORT, 5.0)
    assert_sentence(caught, "host must be", repr(value))


@pytest.mark.parametrize("host", ("fw?a", "fw#a", "fw a", "fw\ta", "-oProxy", "a@b", "a/b", "ssh://a"))
def test_a_host_with_a_url_or_option_mark_is_refused_naming_the_value(host):
    with pytest.raises(HostKeyError) as caught:
        keyscan_argv(host, PORT, 5.0)
    assert_sentence(caught, "host must be", repr(host))
    with pytest.raises(HostKeyError):
        probe_argv(host, PORT, 5.0, "/w/known_hosts", None)


@pytest.mark.parametrize("port", (1, 65535))
def test_the_first_and_the_last_port_are_usable(port):
    assert keyscan_argv(HOST, port, 5.0)[-2:] == [str(port), HOST]
    line = probe_argv(HOST, port, 5.0, "/w/known_hosts", None)
    assert line[line.index("-p") + 1] == str(port)


@pytest.mark.parametrize("port", (0, 65536, -1, "22", 22.0, True))
def test_a_port_outside_the_range_is_refused_naming_the_value(port):
    with pytest.raises(HostKeyError) as caught:
        keyscan_argv(HOST, port, 5.0)
    assert_sentence(caught, "port must be", repr(port))


@pytest.mark.parametrize("seconds", (0, -1.0, float("inf"), float("nan"), "5", None, True))
def test_a_timeout_that_is_not_a_positive_number_is_refused_naming_the_value(seconds):
    with pytest.raises(HostKeyError) as caught:
        keyscan_argv(HOST, PORT, seconds)
    assert_sentence(caught, "timeout must be", repr(seconds))


def test_an_unknown_key_type_is_refused_listing_the_known_ones():
    with pytest.raises(HostKeyError) as caught:
        keyscan_argv(HOST, PORT, 5.0, "dsa")
    assert_sentence(caught, "key type must be one of ", repr("dsa"))
    assert ", ".join(KEY_TYPES) in message(caught)


def test_the_probe_argv_reads_no_config_and_opens_no_terminal():
    line = probe_argv(HOST, 2222, 1.0, "/w/known_hosts", None)
    assert line[:3] == [ssh_module.SSH_BINARY, "-F", ssh_module.CONFIG_FILE]
    assert line[-7:] == ["-T", "-p", "2222", "-l", PROBE_LOGIN, HOST, "exit"]
    assert "ConnectTimeout=1" in line
    assert line[line.index("ConnectTimeout=1") - 1] == "-o"


def test_a_blob_with_a_character_outside_base64_is_refused_not_cleaned_up():
    mangled = BLOB[:8] + "*" + BLOB[8:]
    with pytest.raises(HostKeyError) as caught:
        fingerprint_of(mangled)
    assert_sentence(caught, "host key blob is not valid base64")
    with pytest.raises(HostKeyError):
        matching_line(["%s ssh-ed25519 %s" % (HOST, mangled)], PIN)


@pytest.mark.parametrize("blob", (None, "", "   ", 7))
def test_a_blob_that_is_not_text_is_refused_naming_the_value(blob):
    with pytest.raises(HostKeyError) as caught:
        fingerprint_of(blob)
    assert_sentence(caught, "host key blob must be", repr(blob))


def test_a_pin_that_is_not_a_fingerprint_is_refused_with_the_field_name_first():
    with pytest.raises(HostKeyError) as caught:
        matching_line([LINE], "SHA256:short")
    assert_sentence(caught, "host_key_fingerprint must hold", repr("SHA256:short"))


def test_matching_line_counts_every_offered_key_that_did_not_match():
    with pytest.raises(HostKeyError) as caught:
        matching_line([OTHER_LINE, "# comment", OTHER_LINE], PIN)
    assert_sentence(caught, "no offered host key matches the pinned fingerprint %s" % PIN)
    assert ", 2 key(s) offered" in message(caught)


@pytest.mark.parametrize("lines, kind", ((5, "int"), ([LINE.encode("utf-8")], "bytes"), ([None], "NoneType")))
def test_an_answer_that_is_not_text_lines_is_refused_naming_its_type(lines, kind):
    with pytest.raises(HostKeyError) as caught:
        matching_line(lines, PIN)
    assert_sentence(caught, "the host key scan must answer with text lines", kind)


def test_scan_reads_past_a_banner_that_is_not_utf8():
    run = Keyscan(stdout=BROKEN_UTF8 + ("%s\n" % LINE).encode("utf-8"))
    assert scan(HOST, PORT, PIN, 5.0, run=run) == LINE


def test_scan_sums_the_offered_keys_of_every_type_it_asked_for():
    run = Keyscan(stdout=("%s\n" % OTHER_LINE).encode("utf-8"))
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 30.0, run=run)
    assert len(run.calls) == len(KEY_TYPES)
    assert_sentence(caught, "no offered host key matches the pinned fingerprint %s" % PIN)
    assert ", %d key(s) offered" % len(KEY_TYPES) in message(caught)


def test_scan_without_any_key_names_the_device_and_the_exit_code():
    run = Keyscan(stdout=b"", returncode=1)
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 30.0, run=run)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("%s: no host key could be obtained (exit code 1)" % HOST) + '; check reachability, SSH port and key negotiation before changing the pinned key'


def test_scan_with_a_key_and_a_failing_exit_code_names_the_device():
    run = Keyscan(stdout=("%s\n" % LINE).encode("utf-8"), returncode=3)
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 30.0, run=run)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("%s: the host-key scan did not complete (exit code 3)" % HOST) + '; check reachability, SSH port and key negotiation before changing the pinned key'


def test_scan_asks_for_the_first_type_even_with_less_than_a_second(fake_clock):
    run = Keyscan(stdout=("%s\n" % LINE).encode("utf-8"))
    assert scan(HOST, PORT, PIN, 0.5, run=run) == LINE
    assert len(run.calls) == 1


def test_scan_asks_for_the_next_type_while_a_whole_second_is_left(fake_clock):
    run = Keyscan(stdout=b"", clock=fake_clock, step=1.0)
    with pytest.raises(HostKeyError):
        scan(HOST, PORT, PIN, 3.0, run=run)
    assert len(run.calls) == 3
    assert [call["kwargs"]["timeout"] for call in run.calls] == [3.0, 2.0, 1.0]


def test_scan_stops_once_less_than_a_second_is_left(fake_clock):
    run = Keyscan(stdout=b"", clock=fake_clock, step=2.5)
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 3.0, run=run)
    assert len(run.calls) == 1
    assert_sentence(caught, "%s: no host key could be obtained" % HOST)


def test_scan_hands_the_keyscan_a_system_path_when_the_caller_has_none(monkeypatch):
    monkeypatch.delenv("PATH", raising=False)
    run = Keyscan(stdout=("%s\n" % LINE).encode("utf-8"))
    scan(HOST, PORT, PIN, 5.0, run=run)
    environment = run.calls[0]["kwargs"]["env"]
    assert environment["LC_ALL"] == "C"
    entries = environment["PATH"].split(":")
    assert entries and all(os.path.isabs(entry) and os.path.isdir(entry) for entry in entries)
    assert "/usr/bin" in entries


def test_scan_hands_the_keyscan_the_path_of_the_caller(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    run = Keyscan(stdout=("%s\n" % LINE).encode("utf-8"))
    scan(HOST, PORT, PIN, 5.0, run=run)
    assert run.calls[0]["kwargs"]["env"]["PATH"] == str(tmp_path)


def test_scan_refuses_a_legacy_profile_it_does_not_know_naming_the_device():
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Keyscan(), legacy="rsa-md5")
    assert_sentence(caught, "cannot read the host key of %s: " % HOST)


@pytest.mark.parametrize("budget", (0, -1, True, "1"))
def test_scan_refuses_a_capture_budget_that_is_not_a_size_naming_the_device(budget):
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Keyscan(), capture_max_bytes=budget)
    assert_sentence(caught, "cannot read the host key of %s: " % HOST)


def test_a_runner_that_fails_is_reported_with_the_device_and_the_error_type():
    def run(argv, **kwargs):
        raise PermissionError("denied")

    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=run)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("cannot read the host key of %s (PermissionError)" % HOST) + '; check reachability, SSH port and key negotiation'


def test_a_runner_that_refuses_is_reported_with_the_device_first():
    def run(argv, **kwargs):
        raise ssh_module.SshError("the client produced more than 1 bytes on stdout and was stopped")

    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=run)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("cannot read the host key of %s: the client produced more than 1 bytes on stdout and was stopped" % HOST) + '; check reachability, SSH port and key negotiation'


def test_a_runner_answer_without_stdout_is_a_refusal_not_a_crash():
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=lambda argv, **kwargs: Answer(returncode=0))
    assert_sentence(caught, "the host key scan must answer with bytes on stdout", "NoneType")


def test_a_runner_answer_with_text_on_stdout_is_refused_naming_its_type():
    answer = Answer(returncode=0, stdout=LINE)
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=lambda argv, **kwargs: answer)
    assert_sentence(caught, "the host key scan must answer with bytes on stdout", "str")


def test_a_runner_answer_without_an_exit_code_is_not_trusted():
    answer = Answer(stdout=("%s\n" % LINE).encode("utf-8"))
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=lambda argv, **kwargs: answer)
    assert_sentence(caught, "%s: the host-key scan did not complete (exit code None)" % HOST)


def test_the_probe_finds_the_pinned_key_past_a_line_that_is_not_utf8():
    run = Probe(BROKEN_UTF8 + ("%s\n" % LINE).encode("utf-8"))
    assert scan(HOST, PORT, PIN, 5.0, run=run, legacy=SHA1_PROFILE) == LINE
    assert run.calls[0]["kwargs"]["timeout"] == 5.0


def test_the_probe_without_a_key_names_the_device_and_the_exit_code():
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Probe(None, returncode=255), legacy=SHA1_PROFILE)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("%s: no host key could be obtained (exit code 255)" % HOST) + '; check reachability, SSH port and key negotiation before changing the pinned key'


def test_a_probe_that_cannot_run_names_the_device():
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Probe(None, error=OSError("gone")), legacy=SHA1_PROFILE)
    assert type(caught.value) is HostKeyUnavailable
    assert message(caught) == ("cannot read the host key of %s (OSError)" % HOST) + '; check reachability, SSH port and key negotiation'


def test_the_probe_names_how_many_keys_did_not_match():
    content = ("%s\n%s\n" % (OTHER_LINE, OTHER_LINE)).encode("utf-8")
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Probe(content), legacy=SHA1_PROFILE)
    assert_sentence(caught, "no offered host key matches the pinned fingerprint %s" % PIN)
    assert ", 2 key(s) offered" in message(caught)


def test_the_probe_refuses_a_known_hosts_file_beyond_the_cap_even_with_the_key_first():
    head = ("%s\n" % LINE).encode("utf-8")
    content = head + b"#" * (KEYSCAN_CAPTURE_MAX_BYTES + 100 - len(head))
    with pytest.raises(HostKeyError) as caught:
        scan(HOST, PORT, PIN, 5.0, run=Probe(content), legacy=SHA1_PROFILE)
    assert_sentence(caught, "%s offered more than %d bytes" % (HOST, KEYSCAN_CAPTURE_MAX_BYTES))


def test_the_probe_accepts_a_known_hosts_file_of_exactly_the_cap():
    head = ("%s\n" % LINE).encode("utf-8")
    content = head + b"#" * (KEYSCAN_CAPTURE_MAX_BYTES - len(head))
    assert len(content) == KEYSCAN_CAPTURE_MAX_BYTES
    assert scan(HOST, PORT, PIN, 5.0, run=Probe(content), legacy=SHA1_PROFILE) == LINE


@pytest.mark.parametrize("line", ("a\rb", "a\nb", "a\x00b"))
def test_a_host_key_line_that_carries_a_line_break_is_refused(tmp_path, line):
    with pytest.raises(HostKeyError) as caught:
        known_hosts_file(str(tmp_path), line)
    assert_sentence(caught, "host key line must be a single line", repr(line))
    assert not (tmp_path / "known_hosts").exists()


@pytest.mark.parametrize("line", ("", "  ", None))
def test_an_empty_host_key_line_is_refused_naming_the_value(tmp_path, line):
    with pytest.raises(HostKeyError) as caught:
        known_hosts_file(str(tmp_path), line)
    assert_sentence(caught, "host key line must be a non-empty single line", repr(line))


def test_a_known_hosts_file_that_exists_already_is_not_overwritten(tmp_path):
    (tmp_path / "known_hosts").write_text("other\n", encoding="utf-8")
    with pytest.raises(HostKeyError) as caught:
        known_hosts_file(str(tmp_path), LINE)
    assert_sentence(caught, "cannot write the known hosts file %s" % (tmp_path / "known_hosts"))
    assert (tmp_path / "known_hosts").read_text(encoding="utf-8") == "other\n"
