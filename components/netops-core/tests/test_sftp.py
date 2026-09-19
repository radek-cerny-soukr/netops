import os
import stat
import subprocess
from datetime import datetime, timezone

import pytest

from netops_core.sftp import (
    CONFIG_FILE,
    DEFAULT_TIMEOUT_SECONDS,
    LISTING_MAX_BYTES,
    SFTP_BINARY,
    Entry,
    SftpError,
    argv,
    stat as sftp_stat,
)
from netops_core.ssh import OPTIONS, PASSWORD_OPTIONS

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
PATH = "/safe/log"
CANARY_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-NESMI-UNIKNOUT\n"
CANARY_PASSWORD = "KANARCI-HESLO-NESMI-UNIKNOUT"
LEGACY_PROFILE = "rsa-sha1"
LEGACY_OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")
PROGRESS = b"Connected to 192.0.2.10.\n"
ECHO = b'sftp> ls -ln "/safe/log"\n'
FILE_LINE = b"-rw-r--r--    ? 0        0            1234 Sep 10 02:26 /safe/log\n"
FILE_OUTPUT = ECHO + FILE_LINE
DIRECTORY_OUTPUT = (
    b'sftp> ls -ln "/safe/dir"\n'
    b"-rw-------    ? 0        0              11 Sep 10 02:26 /safe/dir/a.conf\n"
    b"-rw-------    ? 0        0              22 Sep 10 02:26 /safe/dir/b.conf\n"
    b"drwx------    ? 0        0            4096 Sep 10 02:26 /safe/dir/sub\n"
)
ONE_ENTRY_OUTPUT = (
    b'sftp> ls -ln "/safe/one"\n'
    b"-rw-r--r--    ? 0        0               7 Sep 10 02:26 /safe/one/only.txt\n"
)
NEGOTIATION = (
    b"Unable to negotiate with 192.0.2.10 port 22:"
    b" no matching host key type found. Their offer: ssh-rsa\n"
)
MOMENT = datetime(2026, 9, 17, 8, 30, 0, tzinfo=timezone.utc)


class FakeCredential:
    def __init__(self, kind, secret, login=LOGIN):
        self.kind = kind
        self.login = login
        self._secret = secret

    def use(self):
        return self._secret

    def __repr__(self):
        return "<FakeCredential %s>" % self.kind

    __str__ = __repr__


class FakeRun:
    def __init__(self, returncode=0, stdout=FILE_OUTPUT, stderr=PROGRESS, error=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.calls = []
        self.workspace = None
        self.known_hosts = None
        self.identity_mode = None
        self.secret = None

    def __call__(self, call, **kwargs):
        environment = kwargs.get("env") or {}
        self.calls.append(
            {"argv": list(call), "kwargs": dict(kwargs), "env": dict(environment)}
        )
        for entry in call:
            if entry.startswith("UserKnownHostsFile="):
                path = entry.split("=", 1)[1]
                self.known_hosts = open(path, encoding="utf-8").read()
                self.workspace = os.path.dirname(path)
        if "-i" in call:
            path = call[call.index("-i") + 1]
            self.identity_mode = stat.S_IMODE(os.stat(path).st_mode)
        holder = environment.get("NETOPS_ASKPASS_FILE")
        if holder:
            self.secret = open(holder, "rb").read()
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(call, self.returncode, self.stdout, self.stderr)

    def argv(self, index=-1):
        return self.calls[index]["argv"]

    def batch(self, index=-1):
        return self.calls[index]["kwargs"]["input"]


def key_credential():
    return FakeCredential("ssh-key", CANARY_KEY)


def password_credential():
    return FakeCredential("password", CANARY_PASSWORD)


def call(run, credential=None, remote_path=PATH, **kwargs):
    holder = key_credential() if credential is None else credential
    return sftp_stat(
        HOST, PORT, LOGIN, holder, HOST_KEY_LINE, remote_path, run=run, **kwargs
    )


def failure(run, credential=None, remote_path=PATH, **kwargs):
    with pytest.raises(SftpError) as caught:
        call(run, credential=credential, remote_path=remote_path, **kwargs)
    return caught.value


def options_of(call_argv):
    return [call_argv[index] for index in range(len(call_argv)) if call_argv[index - 1] == "-o"]


def test_the_client_call_is_the_hardened_one_of_the_ssh_transport():
    run = FakeRun()
    call(run)
    line = run.argv()
    assert line[0] == SFTP_BINARY
    assert line[1:3] == ["-F", CONFIG_FILE]
    options = options_of(line)
    assert options[: len(OPTIONS)] == list(OPTIONS)
    assert any(option.startswith("UserKnownHostsFile=") for option in options)
    assert line[-3:-1] == ["-P", str(PORT)]
    assert line[-1] == "%s@%s" % (LOGIN, HOST)
    assert "ControlMaster=no" in options and "ControlPath=none" in options
    assert not any(option.startswith("ControlMaster=yes") for option in options)
    assert run.known_hosts == HOST_KEY_LINE + "\n"


def test_the_batch_is_never_a_file_and_never_more_than_one_command():
    run = FakeRun()
    call(run)
    assert "-b" not in run.argv()
    assert run.batch() == b'ls -ln "/safe/log"\n'
    assert run.batch().count(b"\n") == 1


def test_a_password_keeps_the_interactive_option_set_and_never_reaches_argv_or_env():
    run = FakeRun()
    call(run, credential=password_credential())
    assert options_of(run.argv())[: len(PASSWORD_OPTIONS)] == list(PASSWORD_OPTIONS)
    assert "BatchMode=no" in options_of(run.argv())
    assert all(CANARY_PASSWORD not in item for item in run.argv())
    assert all(CANARY_PASSWORD not in value for value in run.calls[-1]["env"].values())
    assert run.secret == CANARY_PASSWORD.encode("utf-8") + b"\n"


def test_a_key_is_a_private_file_and_the_workspace_is_gone_afterwards():
    run = FakeRun()
    call(run)
    assert run.identity_mode == 0o600
    assert all(CANARY_KEY not in item for item in run.argv())
    assert not os.path.exists(run.workspace)


def test_the_legacy_options_come_after_the_hardening_ones_and_only_with_a_profile():
    run = FakeRun()
    call(run)
    assert all(option not in options_of(run.argv()) for option in LEGACY_OPTIONS)

    legacy = FakeRun()
    call(legacy, legacy_ssh=LEGACY_PROFILE)
    options = options_of(legacy.argv())
    assert options[len(OPTIONS): len(OPTIONS) + len(LEGACY_OPTIONS)] == list(LEGACY_OPTIONS)


def test_a_file_answers_with_the_parsed_listing_line():
    run = FakeRun()
    entry = call(run, now=lambda: MOMENT)
    assert isinstance(entry, Entry)
    assert entry.kind == "file"
    assert entry.mode == 0o644
    assert entry.size == 1234
    assert entry.modified_ls == "Sep 10 02:26"
    assert entry.name == PATH
    assert entry.entry_count is None
    assert entry.started_at == entry.finished_at == "2026-09-17T08:30:00Z"


@pytest.mark.parametrize(
    "permissions,kind,mode",
    (
        (b"-rwsr-sr-t", "file", 0o7755),
        (b"drwxr-x---", "directory", 0o750),
        (b"lrwxrwxrwx", "symlink", 0o777),
        (b"prw-------", "other", 0o600),
    ),
)
def test_the_type_character_and_the_permission_string_become_kind_and_mode(
    permissions, kind, mode,
):
    run = FakeRun(stdout=ECHO + permissions + FILE_LINE[10:])
    entry = call(run)
    assert (entry.kind, entry.mode) == (kind, mode)


def test_a_directory_answers_with_a_count_and_never_with_a_name():
    run = FakeRun(stdout=DIRECTORY_OUTPUT)
    entry = call(run, remote_path="/safe/dir")
    assert entry.kind == "directory"
    assert entry.entry_count == 3
    assert (entry.name, entry.size, entry.mode, entry.modified_ls) == (None, None, None, None)
    for name in ("a.conf", "b.conf", "sub"):
        assert name not in repr(entry)


def test_a_directory_with_one_entry_is_still_a_directory():
    run = FakeRun(stdout=ONE_ENTRY_OUTPUT)
    entry = call(run, remote_path="/safe/one")
    assert (entry.kind, entry.entry_count, entry.name) == ("directory", 1, None)


def test_an_empty_listing_without_a_client_complaint_is_an_empty_directory():
    run = FakeRun(stdout=b'sftp> ls -ln "/safe/empty"\n')
    entry = call(run, remote_path="/safe/empty")
    assert (entry.kind, entry.entry_count) == ("directory", 0)


def test_an_empty_listing_with_a_client_complaint_is_a_refusal():
    run = FakeRun(
        stdout=b'sftp> ls -ln "/safe/missing"\n',
        stderr=PROGRESS + b'Can\'t ls: "/safe/missing" not found\n',
    )
    error = failure(run, remote_path="/safe/missing")
    assert "could not list the path" in str(error)
    assert "not found" in str(error)


def test_a_listing_larger_than_the_cap_is_refused_unparsed():
    run = FakeRun(stdout=ECHO + FILE_LINE * (LISTING_MAX_BYTES // len(FILE_LINE) + 1))
    error = failure(run)
    assert "larger than %d bytes" % LISTING_MAX_BYTES in str(error)


def test_a_client_failure_is_a_refusal_and_a_failed_negotiation_names_the_profile():
    plain = failure(FakeRun(returncode=255, stdout=b"", stderr=PROGRESS))
    assert "failed with exit code 255" in str(plain)
    assert "legacy_ssh" not in str(plain)

    refused = failure(FakeRun(returncode=255, stdout=b"", stderr=NEGOTIATION))
    assert "legacy_ssh" in str(refused)
    assert LEGACY_PROFILE in str(refused)

    enrolled = failure(
        FakeRun(returncode=255, stdout=b"", stderr=NEGOTIATION), legacy_ssh=LEGACY_PROFILE,
    )
    assert "legacy_ssh" not in str(enrolled)


def test_a_client_that_closes_early_carries_no_marker_and_no_remedy():
    closed = failure(
        FakeRun(returncode=255, stdout=b"", stderr=b"Connection closed by 192.0.2.10 port 22\n")
    )
    assert "legacy_ssh" not in str(closed)
    assert "Connection closed" in str(closed)


def test_a_timeout_names_the_host_and_the_limit():
    run = FakeRun(error=subprocess.TimeoutExpired(cmd="sftp", timeout=1.0))
    error = failure(run, timeout_seconds=1.0)
    assert "did not finish within 1.0 seconds" in str(error)
    assert not os.path.exists(run.workspace)


@pytest.mark.parametrize(
    "remote_path",
    (
        "relative/path",
        "/safe/../escape",
        '/safe/quote"mark',
        "/safe/line\nbreak",
        "/safe/return\rbreak",
        "/safe/nul\x00byte",
        " /safe/log",
        "/safe/log ",
        "",
        "   ",
        None,
        7,
        b"/safe/log",
    ),
)
def test_a_path_the_batch_line_could_not_carry_is_refused_before_the_client(remote_path):
    run = FakeRun()
    with pytest.raises(SftpError):
        call(run, remote_path=remote_path)
    assert run.calls == []


def test_a_credential_of_another_kind_is_refused_before_the_client():
    run = FakeRun()
    with pytest.raises(SftpError):
        call(run, credential=FakeCredential("snmp-community", "public"))
    assert run.calls == []


def test_the_default_timeout_is_the_one_of_this_module():
    run = FakeRun()
    call(run)
    assert run.calls[-1]["kwargs"]["timeout"] == DEFAULT_TIMEOUT_SECONDS


def test_the_argument_vector_is_available_on_its_own():
    line = argv(HOST, PORT, LOGIN, "/tmp/known_hosts", identity="/tmp/identity")
    assert line[:3] == [SFTP_BINARY, "-F", CONFIG_FILE]
    assert "-i" in line and line[line.index("-i") + 1] == "/tmp/identity"
    assert line[-1] == "%s@%s" % (LOGIN, HOST)
