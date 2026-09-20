import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from netops_core.legacy_ssh import LegacySshError
from netops_core.ssh import (
    CONFIG_FILE,
    DEFAULT_TIMEOUT_SECONDS,
    OPTIONS,
    PASSWORD_OPTIONS,
    Result,
    SshError,
    argv,
    run_command,
)

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
COMMAND = "show"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
PIN = "SHA256:9M3h8iWlwyP5wyoVC6j2DSPB/1Cp4FZhaD1HXhhC7m8"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
CANARY_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-NESMI-UNIKNOUT\n"
CANARY_PASSWORD = "KANARCI-HESLO-NESMI-UNIKNOUT"
CONFIG = b"config system global\nend\n"
LEGACY_PROFILE = "rsa-sha1"
LEGACY_OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")
ASKPASS_VARIABLES = ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "NETOPS_ASKPASS_FILE")
NEGOTIATION = (
    b"Unable to negotiate with 192.0.2.10 port 22:"
    b" no matching host key type found. Their offer: ssh-rsa\n"
)
MOMENT = datetime(2026, 9, 16, 8, 30, 0, tzinfo=timezone.utc)


class FakeCredential:
    def __init__(self, kind, secret, login=LOGIN, name="fw-a-ro"):
        self.name = name
        self.kind = kind
        self.login = login
        self._secret = secret
        self.uses = 0

    def use(self):
        self.uses += 1
        return self._secret

    def __repr__(self):
        return "<FakeCredential %s %s>" % (self.name, self.kind)

    def __str__(self):
        return repr(self)


class FakeRun:
    def __init__(self, returncode=0, stdout=CONFIG, stderr=b"", error=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.calls = []
        self.workspace = None
        self.known_hosts = None
        self.identity = None
        self.identity_mode = None
        self.secret = None
        self.secret_mode = None
        self.askpass = None
        self.askpass_mode = None

    def __call__(self, call, **kwargs):
        environment = kwargs.get("env")
        self.calls.append(
            {
                "argv": list(call),
                "kwargs": dict(kwargs),
                "env": None if environment is None else dict(environment),
            }
        )
        self._look(list(call), environment or {})
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(call, self.returncode, self.stdout, self.stderr)

    def _look(self, call, environment):
        for entry in call:
            if entry.startswith("UserKnownHostsFile="):
                path = entry.split("=", 1)[1]
                self.known_hosts = open(path, encoding="utf-8").read()
                self.workspace = os.path.dirname(path)
        if "-i" in call:
            path = call[call.index("-i") + 1]
            self.identity = open(path, "rb").read()
            self.identity_mode = stat.S_IMODE(os.stat(path).st_mode)
        secret = environment.get("NETOPS_ASKPASS_FILE")
        if secret:
            self.secret = open(secret, "rb").read()
            self.secret_mode = stat.S_IMODE(os.stat(secret).st_mode)
        askpass = environment.get("SSH_ASKPASS")
        if askpass:
            self.askpass = open(askpass, encoding="utf-8").read()
            self.askpass_mode = stat.S_IMODE(os.stat(askpass).st_mode)
            self.askpass_executable = os.access(askpass, os.X_OK)

    def argv(self, index=-1):
        return self.calls[index]["argv"]

    def env(self, index=-1):
        return self.calls[index]["env"]


def key_credential():
    return FakeCredential("ssh-key", CANARY_KEY)


def password_credential():
    return FakeCredential("password", CANARY_PASSWORD)


def call(run, credential=None, **kwargs):
    holder = key_credential() if credential is None else credential
    return run_command(HOST, PORT, LOGIN, holder, HOST_KEY_LINE, COMMAND, run=run, **kwargs)


def failure(run, credential=None, **kwargs):
    with pytest.raises(SshError) as caught:
        call(run, credential=credential, **kwargs)
    return caught.value


def options_of(call_argv):
    return [call_argv[index] for index in range(len(call_argv)) if call_argv[index - 1] == "-o"]


def test_the_hardening_options_are_written_down_in_this_module():
    assert OPTIONS == (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "ClearAllForwardings=yes",
        "ProxyCommand=none",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "ControlPath=none",
    )
    assert PASSWORD_OPTIONS[0] == "BatchMode=no"
    assert PASSWORD_OPTIONS[1:8] == OPTIONS[1:]
    assert PASSWORD_OPTIONS[8:] == ("NumberOfPasswordPrompts=1", "PubkeyAuthentication=no")
    assert DEFAULT_TIMEOUT_SECONDS == 120.0


def test_argv_binds_every_option_in_order_and_ends_with_the_command():
    line = argv(HOST, 2222, LOGIN, "/w/known_hosts", COMMAND, identity="/w/identity")
    assert line[0] == "ssh"
    assert line[1:3] == ["-F", CONFIG_FILE]
    assert options_of(line) == list(OPTIONS) + ["UserKnownHostsFile=/w/known_hosts"]
    assert line[-6:] == [
        "-i",
        "/w/identity",
        "-p",
        "2222",
        "%s@%s" % (LOGIN, HOST),
        COMMAND,
    ]
    for option in OPTIONS:
        assert line.count(option) == 1
        assert line[line.index(option) - 1] == "-o"


def test_argv_without_an_identity_switches_to_the_password_options():
    line = argv(HOST, PORT, LOGIN, "/w/known_hosts", COMMAND)
    assert "-i" not in line
    assert options_of(line) == list(PASSWORD_OPTIONS) + ["UserKnownHostsFile=/w/known_hosts"]
    assert "BatchMode=no" in line
    assert "BatchMode=yes" not in line


def test_argv_appends_the_legacy_options_behind_the_bound_ones():
    line = argv(
        HOST, PORT, LOGIN, "/w/known_hosts", COMMAND, identity="/w/identity",
        legacy=LEGACY_PROFILE,
    )
    assert options_of(line) == list(OPTIONS) + list(LEGACY_OPTIONS) + [
        "UserKnownHostsFile=/w/known_hosts"
    ]
    for option in LEGACY_OPTIONS:
        assert line.index(option) > line.index(OPTIONS[-1])


@pytest.mark.parametrize(
    "host,port,login,command",
    (
        ("audit-ro@192.0.2.10", PORT, LOGIN, COMMAND),
        ("-oProxyCommand=true", PORT, LOGIN, COMMAND),
        ("https://192.0.2.10", PORT, LOGIN, COMMAND),
        (HOST, 0, LOGIN, COMMAND),
        (HOST, True, LOGIN, COMMAND),
        (HOST, PORT, "-x", COMMAND),
        (HOST, PORT, "root@192.0.2.10", COMMAND),
        (HOST, PORT, "", COMMAND),
        (HOST, PORT, LOGIN, "show\nexecute reboot"),
        (HOST, PORT, LOGIN, ""),
    ),
)
def test_argv_refuses_a_target_it_cannot_write_down(host, port, login, command):
    with pytest.raises(SshError):
        argv(host, port, login, "/w/known_hosts", command, identity="/w/identity")


def test_a_key_call_writes_the_identity_0600_and_says_batchmode_yes():
    run = FakeRun()
    credential = key_credential()
    result = call(run, credential=credential)
    assert isinstance(result, Result)
    assert result.rc == 0
    assert result.stdout == CONFIG
    assert credential.uses == 1
    line = run.argv()
    assert line[1:3] == ["-F", CONFIG_FILE]
    assert options_of(line)[: len(OPTIONS)] == list(OPTIONS)
    assert run.identity == CANARY_KEY.encode("utf-8")
    assert run.identity_mode == 0o600
    assert run.known_hosts == "%s\n" % HOST_KEY_LINE
    assert set(run.env()) == {"PATH", "HOME", "LC_ALL"}
    assert run.env()["HOME"] == run.workspace
    assert run.env()["LC_ALL"] == "C"


def test_the_known_hosts_file_lives_in_the_workspace_and_carries_the_pinned_key():
    run = FakeRun()
    call(run)
    pointed = [entry for entry in run.argv() if entry.startswith("UserKnownHostsFile=")]
    assert len(pointed) == 1
    path = pointed[0].split("=", 1)[1]
    assert os.path.dirname(path) == run.workspace
    assert "netops-core-" in run.workspace
    assert BLOB in run.known_hosts


def test_a_password_call_hands_the_secret_over_through_a_file_and_askpass():
    run = FakeRun()
    credential = password_credential()
    call(run, credential=credential)
    assert credential.uses == 1
    environment = run.env()
    assert set(environment) == {"PATH", "HOME", "LC_ALL"} | set(ASKPASS_VARIABLES)
    assert environment["SSH_ASKPASS_REQUIRE"] == "force"
    assert environment["DISPLAY"] == "none"
    assert os.path.dirname(environment["NETOPS_ASKPASS_FILE"]) == run.workspace
    assert os.path.dirname(environment["SSH_ASKPASS"]) == run.workspace
    assert run.askpass == '#!/bin/sh\ncat "$NETOPS_ASKPASS_FILE"\n'
    assert run.askpass_mode == 0o700
    assert run.askpass_executable
    assert run.secret_mode == 0o600
    assert run.secret == ("%s\n" % CANARY_PASSWORD).encode("utf-8")


def test_a_password_call_says_batchmode_no_and_asks_exactly_once():
    run = FakeRun()
    call(run, credential=password_credential())
    line = run.argv()
    assert "BatchMode=no" in line
    assert "BatchMode=yes" not in line
    assert "NumberOfPasswordPrompts=1" in line
    assert "PubkeyAuthentication=no" in line
    assert "-i" not in line
    assert "StrictHostKeyChecking=yes" in line


@pytest.mark.parametrize("run", (FakeRun(), FakeRun(returncode=255, stderr=b"denied")))
def test_the_password_never_reaches_argv_or_the_environment(run):
    credential = password_credential()
    try:
        call(run, credential=credential)
    except SshError as error:
        assert CANARY_PASSWORD not in str(error)
    for entry in run.argv():
        assert CANARY_PASSWORD not in entry
    for value in run.env().values():
        assert CANARY_PASSWORD not in value
    assert CANARY_PASSWORD not in repr(credential)


def test_the_private_key_never_reaches_argv_or_the_environment():
    run = FakeRun()
    credential = key_credential()
    call(run, credential=credential)
    for entry in run.argv():
        assert CANARY_KEY not in entry
    for value in run.env().values():
        assert CANARY_KEY not in value


def test_the_workspace_is_gone_after_a_successful_call():
    run = FakeRun()
    call(run)
    assert run.workspace and not os.path.exists(run.workspace)


def test_the_workspace_is_gone_after_a_failed_call():
    run = FakeRun(returncode=255, stdout=b"", stderr=b"Permission denied (publickey).\n")
    failure(run)
    assert run.workspace and not os.path.exists(run.workspace)


def test_the_workspace_is_gone_after_a_timeout():
    run = FakeRun(error=subprocess.TimeoutExpired(["ssh"], 1))
    error = failure(run)
    assert HOST in str(error)
    assert "did not finish within" in str(error)
    assert run.workspace and not os.path.exists(run.workspace)


def test_a_password_workspace_is_gone_with_its_secret_and_askpass():
    run = FakeRun(returncode=255, stdout=b"", stderr=b"denied")
    failure(run, credential=password_credential())
    environment = run.env()
    assert not os.path.exists(environment["NETOPS_ASKPASS_FILE"])
    assert not os.path.exists(environment["SSH_ASKPASS"])
    assert not os.path.exists(run.workspace)


def test_the_call_passes_the_timeout_and_asks_for_captured_output():
    run = FakeRun()
    call(run, timeout_seconds=17)
    kwargs = run.calls[0]["kwargs"]
    assert kwargs["capture_output"] is True
    assert kwargs["timeout"] == 17.0
    assert kwargs["check"] is False


def test_the_result_carries_the_moments_of_the_call():
    moments = [MOMENT, MOMENT + timedelta(seconds=4)]
    result = call(FakeRun(), now=lambda: moments.pop(0))
    assert result.started_at == "2026-09-16T08:30:00Z"
    assert result.finished_at == "2026-09-16T08:30:04Z"
    assert result.said == ""


def test_a_nonzero_exit_names_the_code_and_a_recognized_reason():
    error = failure(FakeRun(returncode=255, stdout=b"", stderr=b"Permission denied (publickey).\n"))
    assert "failed with exit code 255" in str(error)
    assert "the device refused the credential" in str(error)
    assert "Permission denied (publickey)." not in str(error)
    assert error.rc == 255
    assert error.said == "Permission denied (publickey)."
    assert "legacy_ssh" not in str(error)


def test_what_the_client_said_is_trimmed_and_carries_no_control_characters():
    noise = b"\x1b[31mbanner\x1b[0m\r\n\x00second line\n" + b"x" * 400
    error = failure(FakeRun(returncode=255, stdout=b"", stderr=noise))
    assert error.said.endswith("...")
    assert len(error.said) == 203
    assert error.said.startswith("[31mbanner [0m second line")
    for character in error.said:
        assert character.isprintable()


def test_a_refused_negotiation_names_the_device_and_how_to_write_the_exception_down():
    error = failure(FakeRun(returncode=255, stdout=b"", stderr=NEGOTIATION))
    said = str(error)
    assert HOST in said
    assert "share no algorithm the client accepts" in said
    assert "Their offer: ssh-rsa" not in said
    assert "Their offer: ssh-rsa" in error.said
    assert "offers only algorithms this client refuses" in said
    assert "legacy_ssh" in said
    assert LEGACY_PROFILE in said
    assert "there is no global switch" in said


def test_the_remedy_stays_out_when_the_device_already_has_its_profile():
    error = failure(
        FakeRun(returncode=255, stdout=b"", stderr=NEGOTIATION), legacy_ssh=LEGACY_PROFILE
    )
    assert "share no algorithm the client accepts" in str(error)
    assert "legacy_ssh" not in str(error)


def test_a_profile_adds_its_options_behind_the_bound_ones_of_the_call():
    run = FakeRun()
    call(run, legacy_ssh=LEGACY_PROFILE)
    line = run.argv()
    assert options_of(line)[: len(OPTIONS)] == list(OPTIONS)
    assert options_of(line)[len(OPTIONS) : len(OPTIONS) + 2] == list(LEGACY_OPTIONS)


def test_a_profile_that_is_not_written_down_is_refused_before_anything_runs():
    run = FakeRun()
    with pytest.raises(LegacySshError) as caught:
        call(run, legacy_ssh="ssh-rsa")
    assert run.calls == []
    assert "no global switch" in str(caught.value)


@pytest.mark.parametrize("kind", ("api-token", "snmp-community", "", None, 1))
def test_a_credential_of_another_kind_is_refused_naming_the_kind(kind):
    run = FakeRun()
    error = failure(run, credential=FakeCredential(kind, CANARY_PASSWORD))
    assert run.calls == []
    assert "ssh authenticates with a credential of kind password or ssh-key" in str(error)
    assert repr(kind) in str(error)


@pytest.mark.parametrize("credential", ("replace-me", b"replace-me", None, 7))
def test_something_that_is_not_a_credential_record_is_refused(credential):
    run = FakeRun()
    with pytest.raises(SshError) as caught:
        run_command(HOST, PORT, LOGIN, credential, HOST_KEY_LINE, COMMAND, run=run)
    assert run.calls == []
    assert "credential must be a credential store record with use()" in str(caught.value)


def test_an_empty_or_broken_secret_is_refused_before_the_call():
    run = FakeRun()
    error = failure(run, credential=FakeCredential("ssh-key", ""))
    assert "empty" in str(error) or "text" in str(error)
    assert run.calls == []
    error = failure(run, credential=FakeCredential("password", 7))
    assert "must hand over the password as text" in str(error)


def test_the_login_falls_back_to_the_one_the_credential_carries():
    run = FakeRun()
    credential = FakeCredential("ssh-key", CANARY_KEY, login="other-ro")
    run_command(HOST, PORT, None, credential, HOST_KEY_LINE, COMMAND, run=run)
    assert run.argv()[-2] == "other-ro@%s" % HOST


def test_a_runner_answer_that_is_not_bytes_is_refused():
    class Answer:
        returncode = 0
        stdout = "not bytes"
        stderr = b""

    with pytest.raises(SshError) as caught:
        run_command(
            HOST, PORT, LOGIN, key_credential(), HOST_KEY_LINE, COMMAND,
            run=lambda call, **kwargs: Answer(),
        )
    assert "must answer with bytes on stdout" in str(caught.value)


@pytest.mark.parametrize("seconds", (0, -1, None, "30", float("inf"), True))
def test_a_timeout_that_is_not_a_positive_number_is_refused(seconds):
    run = FakeRun()
    error = failure(run, timeout_seconds=seconds)
    assert run.calls == []
    assert "timeout must be a positive number of seconds" in str(error)


EXOS_DETAIL = b"Port:\t1\nLink State:\tActive\n"


def test_a_command_that_ends_with_its_own_exit_status_returns_what_it_wrote():
    run = FakeRun(returncode=250, stdout=EXOS_DETAIL, stderr=b"")
    result = run_command(HOST, PORT, LOGIN, key_credential(), HOST_KEY_LINE, COMMAND, run=run)
    assert isinstance(result, Result)
    assert result.rc == 250
    assert result.stdout == EXOS_DETAIL
    assert result.said == ""


def test_the_client_failure_code_stays_a_refusal_even_with_output():
    error = failure(FakeRun(returncode=255, stdout=EXOS_DETAIL, stderr=b"denied"))
    assert "failed with exit code 255" in str(error)
    assert error.rc == 255


@pytest.mark.parametrize("code", (None, "0", True, 1.0))
def test_an_exit_status_that_is_not_a_whole_number_is_refused(code):
    class Answer:
        returncode = code
        stdout = CONFIG
        stderr = b""

    with pytest.raises(SshError) as caught:
        run_command(
            HOST, PORT, LOGIN, key_credential(), HOST_KEY_LINE, COMMAND,
            run=lambda call, **kwargs: Answer(),
        )
    assert "failed with exit code" in str(caught.value)
