import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from netops_core import legacy_ssh as legacy_module
from netops_core import ssh as ssh_module
from netops_core.ssh import (
    ASKPASS_PROGRAM_ENV,
    ASKPASS_REMEDY,
    OWNER_NAME,
    STDERR_MAX_BYTES,
    WORKSPACE_PREFIX,
    SshError,
    argv,
    run_command,
)

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
COMMAND = "show"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-NESMI-UNIKNOUT\n"
MOMENT = datetime(2026, 9, 16, 8, 30, 0, tzinfo=timezone.utc)
NEGOTIATION = b"Unable to negotiate with 192.0.2.10 port 22: no matching host key type found.\n"
SECONDS = 15.0


class Credential:
    kind = "ssh-key"
    login = LOGIN
    name = "fw-a-ro"

    def __init__(self, secret=KEY):
        self.secret = secret

    def use(self):
        return self.secret


class Nameless:
    kind = "ssh-key"

    def use(self):
        return KEY


class Answer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class Run:
    def __init__(self, answer=None, error=None, inspect=None):
        self.answer = answer
        self.error = error
        self.inspect = inspect
        self.calls = []

    def __call__(self, call, **kwargs):
        self.calls.append({"argv": list(call), "kwargs": dict(kwargs)})
        if self.inspect is not None:
            self.inspect(call, kwargs)
        if self.error is not None:
            raise self.error
        if self.answer is not None:
            return self.answer
        return subprocess.CompletedProcess(call, 0, b"ok\n", b"")


class Unknown(tzinfo):
    def utcoffset(self, moment):
        return None

    def dst(self, moment):
        return None


def failing(code, stderr=b""):
    return Run(subprocess.CompletedProcess(["ssh"], code, b"", stderr))


def command(run, **kwargs):
    options = {"run": run}
    options.update(kwargs)
    login = options.pop("login", LOGIN)
    credential = options.pop("credential", Credential())
    return run_command(HOST, PORT, login, credential, HOST_KEY_LINE, COMMAND, **options)


def refusal(run, **kwargs):
    with pytest.raises(SshError) as caught:
        command(run, **kwargs)
    return caught.value


def assert_sentence(error, subject, received=None):
    text = str(error)
    assert text.startswith(subject), text
    if received is not None:
        assert text.endswith(received), text


def python(program):
    return [sys.executable, "-I", "-c", program]


def ended_within(pid, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        try:
            with open("/proc/%d/stat" % pid, "rb") as handle:
                state = handle.read().rsplit(b")", 1)[1].split()[0]
        except OSError:
            return True
        if state == b"Z":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def pid_in(marker, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return int(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            time.sleep(0.02)
    raise AssertionError("no pid in %s" % marker)


def bounded(target, seconds, rescue):
    outcome = {}

    def body():
        try:
            outcome["value"] = target()
        except BaseException as error:
            outcome["error"] = error

    worker = threading.Thread(target=body, daemon=True)
    worker.start()
    worker.join(seconds)
    hung = worker.is_alive()
    if hung:
        rescue()
        worker.join(SECONDS)
    return hung, outcome


def kill_quietly(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    directory = tmp_path / "tmp"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    return directory


def abandoned(root, name, owner="file"):
    path = root / (WORKSPACE_PREFIX + name)
    path.mkdir(mode=0o700)
    if owner == "file":
        (path / OWNER_NAME).write_text("", encoding="utf-8")
    elif owner == "directory":
        (path / OWNER_NAME).mkdir()
    elif owner == "fifo":
        os.mkfifo(path / OWNER_NAME)
    return path


@pytest.mark.parametrize(
    "field, call",
    (
        ("known_hosts", lambda: argv(HOST, PORT, LOGIN, "", COMMAND)),
        ("identity", lambda: argv(HOST, PORT, LOGIN, "/w/known_hosts", COMMAND, identity=" ")),
        ("command", lambda: argv(HOST, PORT, LOGIN, "/w/known_hosts", "")),
        ("host", lambda: argv("", PORT, LOGIN, "/w/known_hosts", COMMAND)),
        ("login", lambda: argv(HOST, PORT, " ", "/w/known_hosts", COMMAND)),
    ),
)
def test_an_empty_field_is_refused_naming_the_field_first(field, call):
    with pytest.raises(SshError) as caught:
        call()
    assert_sentence(caught.value, "%s must be a non-empty string, got " % field)
    assert caught.value.said == ""
    assert caught.value.rc is None


@pytest.mark.parametrize("host", ("fw/a", "fw?a", "fw#a", "fw a", "fw\ta", "a@b", "-oProxy", "ssh://a"))
def test_a_host_with_a_path_query_or_space_is_refused_naming_the_value(host):
    with pytest.raises(SshError) as caught:
        argv(host, PORT, LOGIN, "/w/known_hosts", COMMAND)
    assert_sentence(caught.value, "host must be a bare host name or address", repr(host))


@pytest.mark.parametrize("login", ("a:b", "a/b", "a b", "a\tb", "a@b", "-l"))
def test_a_login_with_a_separator_is_refused_naming_the_value(login):
    with pytest.raises(SshError) as caught:
        argv(HOST, PORT, login, "/w/known_hosts", COMMAND)
    assert_sentence(caught.value, "login must be a plain user name", repr(login))


@pytest.mark.parametrize("port", (1, 65535))
def test_the_first_and_the_last_port_are_usable(port):
    line = argv(HOST, port, LOGIN, "/w/known_hosts", COMMAND)
    assert line[line.index("-p") + 1] == str(port)


@pytest.mark.parametrize("port", (0, 65536, -1, "22", True))
def test_a_port_outside_the_range_is_refused_naming_the_value(port):
    with pytest.raises(SshError) as caught:
        argv(HOST, port, LOGIN, "/w/known_hosts", COMMAND)
    assert_sentence(caught.value, "port must be a whole number between 1 and 65535", repr(port))


@pytest.mark.parametrize("line", ("show\x00all", "show\nall", "show\rall"))
def test_a_command_that_carries_a_second_line_or_a_nul_is_refused(line):
    with pytest.raises(SshError) as caught:
        argv(HOST, PORT, LOGIN, "/w/known_hosts", line)
    assert_sentence(caught.value, "command must be a single line", repr(line))


@pytest.mark.parametrize("seconds", ("5", None, 0, -1.0, float("inf")))
def test_a_timeout_that_is_not_a_positive_number_is_refused_naming_the_value(seconds):
    error = refusal(Run(), timeout_seconds=seconds)
    assert_sentence(error, "timeout must be a positive number of seconds", repr(seconds))


def test_a_capture_budget_of_one_byte_is_a_budget():
    result = command(Run(subprocess.CompletedProcess(["ssh"], 0, b"", b"")), capture_max_bytes=1)
    assert result.rc == 0


@pytest.mark.parametrize("budget", (0, -5, True, 1.5))
def test_a_capture_budget_that_is_not_a_size_is_refused_naming_the_value(budget):
    error = refusal(Run(), capture_max_bytes=budget)
    assert_sentence(error, "capture_max_bytes must be a whole number of at least 1", repr(budget))


def test_a_credential_that_is_text_is_refused_naming_its_type():
    error = refusal(Run(), credential="hunter2")
    assert_sentence(error, "credential must be a credential store record with use()", "str")


def test_a_credential_of_another_kind_is_refused_naming_the_kinds():
    holder = Credential()
    holder.kind = "token"
    error = refusal(Run(), credential=holder)
    assert_sentence(error, "ssh authenticates with a credential of kind password or ssh-key", repr("token"))


def test_a_clock_that_is_not_callable_is_refused_naming_it():
    error = refusal(Run(), now=5)
    assert_sentence(error, "now must be a callable returning an aware datetime", "5")


def test_a_clock_that_answers_no_datetime_is_refused_naming_the_answer():
    error = refusal(Run(), now=lambda: "08:30")
    assert_sentence(error, "clock must return a datetime", repr("08:30"))


@pytest.mark.parametrize("moment", (datetime(2026, 9, 16, 8, 30), datetime(2026, 9, 16, 8, 30, tzinfo=Unknown())))
def test_a_clock_without_a_usable_zone_is_refused_naming_the_answer(moment):
    error = refusal(Run(), now=lambda: moment)
    assert_sentence(error, "clock must return a timezone aware datetime", repr(moment))


def test_a_run_that_is_not_callable_is_refused_naming_its_type():
    error = refusal(5)
    assert_sentence(error, "run must be callable", "int")


def test_an_explicit_login_wins_over_the_login_of_the_credential():
    run = Run()
    command(run, login="operator")
    assert "operator@%s" % HOST in run.calls[0]["argv"]
    assert "%s@%s" % (LOGIN, HOST) not in run.calls[0]["argv"]


def test_a_credential_without_a_login_and_no_login_is_refused_as_a_login():
    error = refusal(Run(), login=None, credential=Nameless())
    assert_sentence(error, "login must be a non-empty string", "None")


def test_the_workspace_is_private_to_the_owner_while_the_client_runs():
    modes = []
    command(Run(inspect=lambda call, kwargs: modes.append(stat.S_IMODE(os.stat(kwargs["env"]["HOME"]).st_mode))))
    assert modes == [0o700]


def test_a_failing_claim_leaves_its_own_error_and_no_workspace(private_tmp, monkeypatch):
    def claimed(workspace):
        raise OSError("claim refused")

    monkeypatch.setattr(ssh_module, "_claimed", claimed)
    with pytest.raises(OSError, match="claim refused"):
        command(Run())
    assert os.listdir(private_tmp) == []


def test_a_client_that_overruns_its_time_is_reported_with_the_device_and_the_limit():
    error = refusal(Run(error=subprocess.TimeoutExpired(["ssh"], 3)), timeout_seconds=3)
    assert_sentence(error, "ssh to %s did not finish within 3.0 seconds" % HOST, "seconds")


def test_a_client_that_cannot_start_is_reported_with_the_device_and_the_error_type():
    error = refusal(Run(error=PermissionError("denied")))
    assert_sentence(error, "cannot run ssh to %s" % HOST, "(PermissionError)")


def test_a_clock_that_steps_back_never_finishes_before_it_started():
    moments = iter((MOMENT, MOMENT - timedelta(seconds=30)))
    result = command(Run(), now=lambda: next(moments))
    assert result.started_at == "2026-09-16T08:30:00Z"
    assert result.finished_at == result.started_at


def test_an_answer_without_stdout_is_a_refusal_not_a_crash():
    error = refusal(Run(Answer(returncode=0, stderr=b"")))
    assert_sentence(error, "the ssh runner must answer with bytes on stdout", "NoneType")


def test_an_answer_with_text_on_stdout_is_refused_naming_its_type():
    error = refusal(Run(Answer(returncode=0, stdout="ok", stderr=b"")))
    assert_sentence(error, "the ssh runner must answer with bytes on stdout", "str")


def test_an_answer_without_an_exit_code_is_a_failure_without_a_code():
    error = refusal(Run(Answer(stdout=b"ok", stderr=b"")))
    assert_sentence(error, "ssh to %s failed with exit code None" % HOST, "exit code None")
    assert error.rc is None


@pytest.mark.parametrize("code", (True, "0", 1.0))
def test_an_exit_code_that_is_not_a_whole_number_is_never_handed_on_as_one(code):
    error = refusal(Run(Answer(stdout=b"ok", stderr=b"", returncode=code)))
    assert error.rc is None
    assert_sentence(error, "ssh to %s failed with exit code %s" % (HOST, code))


def test_a_client_failure_without_a_word_ends_with_the_exit_code():
    error = refusal(failing(255))
    assert_sentence(error, "ssh to %s failed with exit code 255" % HOST, "exit code 255")
    assert error.rc == 255
    assert error.said == ""


def test_a_client_failure_names_the_reason_right_after_the_exit_code():
    error = refusal(failing(255, b"Permission denied (password).\r\n"))
    assert_sentence(error, "ssh to %s failed with exit code 255; the device refused the credential" % HOST,
                    "the device refused the credential")


def test_a_negotiation_failure_lists_the_legacy_profiles_by_name():
    error = refusal(failing(255, NEGOTIATION))
    assert ", ".join(legacy_module.PROFILES) in str(error)
    assert_sentence(error, "ssh to %s failed with exit code 255; " % HOST)


def test_an_answer_without_stderr_says_nothing():
    result = command(Run(Answer(stdout=b"ok", returncode=0)))
    assert result.said == ""


def test_an_answer_whose_stderr_is_not_bytes_says_nothing():
    result = command(Run(Answer(stdout=b"ok", returncode=0, stderr="Permission denied")))
    assert result.said == ""


def test_stderr_that_is_not_utf8_is_read_with_replacements():
    result = command(Run(subprocess.CompletedProcess(["ssh"], 0, b"ok", b"Warning: \xff\xfe banner\n")))
    assert result.said.startswith("Warning:")
    assert "�" in result.said
    assert result.said.endswith("banner")


def test_stderr_of_exactly_the_limit_is_kept_whole():
    text = "w" * ssh_module.SAID_CHARS
    result = command(Run(subprocess.CompletedProcess(["ssh"], 0, b"ok", text.encode("ascii"))))
    assert result.said == text
    longer = command(Run(subprocess.CompletedProcess(["ssh"], 0, b"ok", (text + "x").encode("ascii"))))
    assert longer.said == text + "..."


def test_a_private_key_handed_over_as_bytes_reaches_the_identity_file():
    seen = []

    def inspect(call, kwargs):
        with open(call[call.index("-i") + 1], "rb") as handle:
            seen.append(handle.read())

    command(Run(inspect=inspect), credential=Credential(KEY.encode("ascii")))
    assert seen == [KEY.encode("ascii")]


def test_a_private_key_that_is_not_text_is_refused_naming_the_secret_and_its_type():
    error = refusal(Run(), credential=Credential(5))
    assert_sentence(error, "credential must hand over the private key as text", "int")


def test_an_empty_private_key_is_refused_naming_the_secret():
    error = refusal(Run(), credential=Credential(""))
    assert_sentence(error, "credential handed over an empty private key")


def test_the_client_gets_a_system_path_when_the_caller_has_none(monkeypatch):
    monkeypatch.delenv("PATH", raising=False)
    run = Run()
    command(run)
    entries = run.calls[0]["kwargs"]["env"]["PATH"].split(":")
    assert entries and all(os.path.isabs(entry) and os.path.isdir(entry) for entry in entries)
    assert "/usr/bin" in entries


def test_the_client_gets_the_path_of_the_caller(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    run = Run()
    command(run)
    assert run.calls[0]["kwargs"]["env"]["PATH"] == str(tmp_path)


def test_a_client_that_leaves_an_unremovable_file_does_not_turn_success_into_an_error():
    if os.geteuid() == 0:
        pytest.skip("root removes read-only directories")
    left = []

    def inspect(call, kwargs):
        locked = os.path.join(kwargs["env"]["HOME"], ".ssh")
        os.mkdir(locked)
        with open(os.path.join(locked, "known_hosts"), "w", encoding="utf-8") as handle:
            handle.write("x\n")
        os.chmod(locked, 0o500)
        left.append(locked)

    try:
        result = command(Run(inspect=inspect))
        assert result.rc == 0
    finally:
        for locked in left:
            if os.path.isdir(locked):
                os.chmod(locked, 0o700)
                workspace = os.path.dirname(locked)
                for root, dirs, files in os.walk(workspace, topdown=False):
                    for name in files:
                        os.unlink(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(workspace)


def test_the_sweep_keeps_a_workspace_whose_owner_mark_is_not_a_file(private_tmp):
    keep = abandoned(private_tmp, "keep", owner="directory")
    command(Run())
    assert keep.is_dir()


def test_the_sweep_does_not_stop_at_the_first_foreign_name(private_tmp):
    stale = abandoned(private_tmp, "stale")
    for index in range(64):
        (private_tmp / ("other-%02d" % index)).write_text("", encoding="utf-8")
        names = os.listdir(private_tmp)
        if names.index(stale.name) > 0 and not names[0].startswith(WORKSPACE_PREFIX):
            break
    ssh_module._abandoned_removed()
    assert not stale.exists()


def test_the_sweep_never_waits_on_an_owner_mark_that_is_a_fifo(private_tmp):
    stale = abandoned(private_tmp, "fifo", owner="fifo")

    def rescue():
        handle = os.open(stale / OWNER_NAME, os.O_WRONLY | os.O_NONBLOCK)
        os.close(handle)

    hung, outcome = bounded(ssh_module._abandoned_removed, 5.0, rescue)
    assert not hung
    assert "error" not in outcome
    assert stale.is_dir()


def test_a_claim_that_cannot_rename_raises_its_own_error(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / OWNER_NAME).mkdir()
    (workspace / OWNER_NAME / "occupied").write_text("", encoding="utf-8")
    with pytest.raises(OSError):
        ssh_module._claimed(str(workspace))


@pytest.mark.parametrize("problem", ("missing", "directory", "writable", "inert"))
def test_a_named_askpass_program_that_is_unfit_is_refused_naming_it(tmp_path, monkeypatch, problem):
    path = tmp_path / "netops-askpass"
    if problem == "directory":
        path.mkdir()
    elif problem != "missing":
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod({"writable": 0o775, "inert": 0o644}[problem])
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(path))
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    holder = Credential("hunter2")
    holder.kind = "password"
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(str(workspace), "password", holder)
    ending = {
        "missing": "which is not a file this process can read",
        "directory": "which is not a regular file",
        "writable": "the program that is handed the password must not be",
        "inert": "which this process cannot execute",
    }[problem]
    assert_sentence(caught.value, "%s names %r, " % (ASKPASS_PROGRAM_ENV, str(path)), ending)


def test_an_askpass_program_that_cannot_execute_is_reported_with_the_remedy(tmp_path, monkeypatch):
    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    real = os.access
    monkeypatch.setattr(ssh_module.os, "access", lambda path, mode: False if str(path).endswith("/askpass") else real(path, mode))
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    holder = Credential("hunter2")
    holder.kind = "password"
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(str(workspace), "password", holder)
    assert_sentence(caught.value, "the askpass program written into %s cannot be executed" % workspace, ASKPASS_REMEDY)


def test_the_capped_runner_works_without_a_timeout():
    result = ssh_module._capped_runner(1024)(python("print('up')"))
    assert result.returncode == 0
    assert result.stdout == b"up\n"


def test_the_capped_runner_answers_like_subprocess_run():
    call = python("import sys; sys.stderr.write('e'); print('o')")
    result = ssh_module._capped_runner(1024)(call, timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert result.args == call
    assert (result.returncode, result.stdout, result.stderr) == (0, b"o\n", b"e")
    slow = python("import time; time.sleep(5)")
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        ssh_module._capped_runner(1024)(slow, timeout=0.3, env={"PATH": "/usr/bin:/bin"})
    assert caught.value.cmd == slow
    assert caught.value.timeout == 0.3


def test_the_client_without_input_reads_end_of_file_not_a_pipe_left_open():
    call = python("import sys; print(len(sys.stdin.buffer.read()))")
    result = ssh_module._capped_runner(1024)(call, timeout=5.0, env={"PATH": "/usr/bin:/bin"})
    assert result.stdout == b"0\n"


def test_the_client_reads_the_input_it_is_handed():
    call = python("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    result = ssh_module._capped_runner(1024)(call, timeout=SECONDS, env={"PATH": "/usr/bin:/bin"}, input=b"ls /\n")
    assert result.stdout == b"ls /\n"


def test_the_client_sees_only_the_environment_it_is_handed(monkeypatch):
    monkeypatch.setenv("W4_KANARCI_PROSTREDI", "nesmi-projit")
    call = python("import os; print(os.environ.get('W4_KANARCI_PROSTREDI'))")
    result = ssh_module._capped_runner(1024)(call, timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert result.stdout == b"None\n"


def test_stderr_written_in_pieces_is_kept_in_full():
    call = python(
        "import sys, time; sys.stderr.write('first'); sys.stderr.flush(); time.sleep(0.3);"
        " sys.stderr.write('second'); sys.stderr.flush()"
    )
    result = ssh_module._capped_runner(1024)(call, timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert result.stderr == b"firstsecond"


def test_stderr_never_grows_beyond_its_cap():
    call = python(
        "import sys, time; sys.stderr.write('a' * 1000); sys.stderr.flush(); time.sleep(0.3);"
        " sys.stderr.write('b' * 200000); sys.stderr.flush()"
    )
    result = ssh_module._capped_runner(1024)(call, timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert len(result.stderr) == STDERR_MAX_BYTES
    assert result.stderr.startswith(b"a" * 1000 + b"b")


def test_a_flooding_client_is_reported_as_stopped():
    with pytest.raises(SshError) as caught:
        ssh_module._capped_runner(10)(python("print('x' * 1000)"), timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert_sentence(caught.value, "the client produced more than 10 bytes on stdout", "was stopped")


def test_a_client_that_ignores_the_terminate_signal_is_still_stopped_on_time(tmp_path):
    marker = tmp_path / "pid"
    call = python(
        "import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        " open(%r, 'w').write(str(os.getpid())); time.sleep(30)" % str(marker)
    )

    def target():
        return ssh_module._capped_runner(1024)(call, timeout=1.0, env={"PATH": "/usr/bin:/bin"})

    def rescue():
        kill_quietly(pid_in(marker))

    hung, outcome = bounded(target, 10.0, rescue)
    assert not hung
    assert isinstance(outcome.get("error"), subprocess.TimeoutExpired)


def test_a_grandchild_that_ignores_the_terminate_signal_is_killed_without_a_hangup(tmp_path):
    marker = tmp_path / "pid"
    hangup = tmp_path / "hangup"
    grandchild = (
        "import os, signal, sys, time;"
        " signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        " signal.signal(signal.SIGHUP, lambda *_: open(%r, 'w').write('HUP'));"
        " open(%r, 'w').write(str(os.getpid()));"
        " time.sleep(30)" % (str(hangup), str(marker))
    )
    child = (
        "import os, subprocess, sys, time;"
        " subprocess.Popen([sys.executable, '-I', '-c', %r], stdin=subprocess.DEVNULL,"
        " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL);"
        " [time.sleep(0.02) for _ in range(500) if not os.path.exists(%r)];"
        " time.sleep(0.2); print('done')" % (grandchild, str(marker))
    )

    def target():
        return ssh_module._capped_runner(1024)(python(child), timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})

    def rescue():
        kill_quietly(pid_in(marker))

    try:
        hung, outcome = bounded(target, 10.0, rescue)
        assert not hung
        assert outcome["value"].stdout == b"done\n"
        assert ended_within(pid_in(marker), 2.0)
        assert not hangup.exists()
    finally:
        kill_quietly(pid_in(marker))


def test_a_client_whose_group_is_gone_costs_no_sweep_wait(monkeypatch):
    sleeps = []
    monkeypatch.setattr(
        ssh_module, "time",
        types.SimpleNamespace(monotonic=time.monotonic, sleep=lambda seconds: sleeps.append(seconds)),
    )
    result = ssh_module._capped_runner(1024)(python("print('x')"), timeout=SECONDS, env={"PATH": "/usr/bin:/bin"})
    assert result.stdout == b"x\n"
    assert sleeps == []
